//! The pluggable p2p fetch abstraction that sits UNDER the frozen `NarSource`
//! seam (task-38). iroh is ONE impl of it (task-39); BitTorrent a future one.
//!
//! ## Where this sits
//!
//! [`crate::source::NarSource`] resolves a NAR by its signed `NarHash`. This
//! module is what a wave-2 `NarSource` uses to actually GET the bytes once
//! discovery (task-40) has produced a [`Claim`]:
//!
//! ```text
//!   NarSource::resolve(NarKey::SignedNarHash{hash})   (frozen seam - UNCHANGED)
//!     -> discovery: hash -> Claim{ payload=blake3, transports=[offer,..] }
//!     -> fetch_via_offers(registry, blake3, offers)   (THIS module)
//!         -> pick a Transport impl by the offer's tag
//!         -> Transport::fetch(blake3, offer) -> raw NAR bytes
//! ```
//!
//! The addressed unit is the universal [`Blake3Digest`] (`BLAKE3(RawNarV1)`, the
//! task-48 freeze) - NOT a URL. A [`Transport`] is handed that content identity
//! plus a transport-specific locator (an iroh `NodeId`; a future BitTorrent
//! infohash, carried inside the [`KnownTransport`] offer) and returns the raw NAR
//! bytes for it. This module names no iroh crate (that lands in task-39); it is
//! deliberately transport-agnostic, exactly like [`crate::transport`] keeps the
//! locators transport-specific without an iroh dependency.
//!
//! ## The TWO gates (kept distinct on purpose)
//!
//! A p2p fetch passes through two INDEPENDENT verifications, and conflating them
//! is the classic trap this design guards against:
//!
//!   1. **Transport-integrity gate (BLAKE3)** - owned HERE. The bytes a holder
//!      hands back MUST hash to the requested [`Blake3Digest`] under the frozen
//!      plain-unkeyed recipe ([`verify_blake3`]). A corrupt/lying holder fails
//!      this gate and the daemon fails closed and tries the next offer. This is an
//!      integrity + fail-fast optimisation, NOT the trust anchor.
//!   2. **Trust gate (sha256 == NarHash)** - owned by NIX (wave-1 S1), NOT by this
//!      daemon. The Nix client re-verifies `sha256(nar) == NarHash` on every path
//!      it substitutes. The daemon is OUTSIDE the TCB: a transport serving wrong
//!      bytes that somehow slipped gate 1 yields a failed build + retry, never a
//!      poisoned store. That is why gate 1 can be a cheap integrity check and the
//!      real trust is Nix's signed-sha256 gate.
//!
//! The two identities come from the SAME `RawNarV1` bytes but are different values
//! addressing different things: the `sha256` NarHash is the LOOKUP/trust key a
//! claim is keyed on; the `blake3` digest is the FETCH/stream-verify key a
//! transport addresses. A claim binds them (see [`crate::claim`]). task-39 will
//! split the two gates with a corruption bite; this module is shaped so both are
//! independently checkable.
//!
//! ## Serve side
//!
//! The consumer (fetch) side is the trait below. The network PROVIDER side (a node
//! announcing and serving its held blobs over iroh-blobs) is task-39's iroh
//! provider; [`FakeTransport::seed`] models the content-addressed "put" a provider
//! does, which is all task-38 needs to prove the seam symmetric.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;
use http_body_util::{BodyExt, Full};

use crate::claim::{KnownTransport, NarHashKey};
use crate::content_id::Blake3Digest;
use crate::discovery::Discovery;
use crate::source::{NarKey, NarSource, SourceError, UpstreamResponse};

// -------------------------------------------------------------------------
// Transport selection tag.
// -------------------------------------------------------------------------

/// Which transport a [`KnownTransport`] offer selects. This is the dispatch key a
/// [`TransportRegistry`] maps to a [`Transport`] impl.
///
/// It mirrors the wire tags of [`KnownTransport`], but note the layering: the
/// claim decoder already DROPS genuinely-unknown wire transports (tolerated but
/// inert - see [`crate::claim`]), so by the time an offer reaches this module it
/// is always a KNOWN wire variant. "Unknown/unimplemented" AT THIS LAYER therefore
/// means a known wire transport with NO registered backend (e.g. `bittorrent`,
/// representable but not implemented until a backend exists) - that offer is
/// SKIPPED, never a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportTag {
    /// iroh whole-blob (Candidate B). The locator is a `NodeId`.
    Iroh,
    /// BitTorrent - representable, no backend yet. The locator is an infohash.
    BitTorrent,
}

impl TransportTag {
    /// The tag that dispatches a given offer.
    pub fn of(offer: &KnownTransport) -> Self {
        match offer {
            KnownTransport::Iroh { .. } => TransportTag::Iroh,
            KnownTransport::BitTorrent { .. } => TransportTag::BitTorrent,
        }
    }

    /// The wire-tag string (matches [`KnownTransport`]'s serde tags).
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportTag::Iroh => "iroh",
            TransportTag::BitTorrent => "bittorrent",
        }
    }
}

impl fmt::Display for TransportTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// -------------------------------------------------------------------------
// The transport-integrity gate (single source of truth).
// -------------------------------------------------------------------------

/// Gate 1: verify that `raw_nar` hashes to `expected` under the frozen
/// plain-unkeyed BLAKE3 recipe ([`Blake3Digest::from_raw_nar`]). The ONE place the
/// transport-integrity check lives, so every [`Transport`] enforces the identical
/// recipe rather than re-deriving it. A mismatch is a fail-closed error; it is NOT
/// the sha256 trust gate (Nix owns that - see the module docs).
pub fn verify_blake3(expected: &Blake3Digest, raw_nar: &[u8]) -> Result<(), TransportError> {
    let actual = Blake3Digest::from_raw_nar(raw_nar);
    if &actual == expected {
        Ok(())
    } else {
        Err(TransportError::IntegrityMismatch {
            expected: *expected,
            actual,
        })
    }
}

// -------------------------------------------------------------------------
// Errors.
// -------------------------------------------------------------------------

/// Why one [`Transport::fetch`] attempt did not yield verified bytes. These are
/// per-OFFER failures: the driver ([`fetch_via_offers`]) records them and moves to
/// the next offer rather than aborting the whole resolution.
#[derive(Debug)]
pub enum TransportError {
    /// The holder does not have this content identity.
    NotHeld(Blake3Digest),
    /// Gate 1 fired: the transferred bytes do not hash to the requested identity.
    /// A corrupt or lying holder. Fail closed - never hand these bytes upward.
    IntegrityMismatch {
        expected: Blake3Digest,
        actual: Blake3Digest,
    },
    /// The offer handed to this transport is not the variant it services (a
    /// registry-dispatch bug; guarded defensively rather than assumed away).
    WrongOffer {
        expected: TransportTag,
        got: TransportTag,
    },
    /// A transport-specific failure (dial refused, timeout, reset). Real backends
    /// (task-39) produce this; it means "this holder is unusable, try the next".
    Unavailable(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::NotHeld(id) => write!(f, "holder does not hold {id}"),
            TransportError::IntegrityMismatch { expected, actual } => write!(
                f,
                "transport-integrity gate failed: got bytes hashing to {actual}, expected {expected}"
            ),
            TransportError::WrongOffer { expected, got } => write!(
                f,
                "offer is a {got} locator but this transport services {expected}"
            ),
            TransportError::Unavailable(why) => write!(f, "transport unavailable: {why}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Why [`fetch_via_offers`] produced no bytes from a claim's offers.
#[derive(Debug)]
pub enum FetchError {
    /// The claim carries no usable content identity (its payload kind is unknown
    /// to this build, so [`Claim::content_id`] is `None`). Nothing to fetch.
    NoContentId,
    /// Every offer was exhausted without success: each was either SKIPPED (no
    /// registered backend for its transport) or FAILED (a per-offer
    /// [`TransportError`]). Carries both lists so a log line is diagnosable.
    Exhausted {
        skipped: Vec<TransportTag>,
        failed: Vec<(TransportTag, String)>,
    },
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::NoContentId => {
                f.write_str("claim has no usable content id (unknown payload kind)")
            }
            FetchError::Exhausted { skipped, failed } => {
                write!(
                    f,
                    "no offer yielded the content: {} skipped (no backend), {} failed",
                    skipped.len(),
                    failed.len()
                )?;
                for (tag, why) in failed {
                    write!(f, "; {tag}: {why}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for FetchError {}

// -------------------------------------------------------------------------
// The Transport trait: fetch the addressed unit by content identity.
// -------------------------------------------------------------------------

/// A p2p transport that fetches the addressed unit ([`Blake3Digest`]) by content
/// identity and returns BLAKE3-verified raw NAR bytes.
///
/// CONTRACT: an impl MUST return only bytes that pass [`verify_blake3`] against the
/// requested `content` (gate 1). A streaming backend (iroh-blobs via bao, task-39)
/// gets this incrementally and fail-fast, so it never buffers a whole lying blob
/// before rejecting it (the S8 "lying claim" row); a non-streaming impl calls
/// [`verify_blake3`] before returning. Returning unverified bytes is a contract
/// violation - the daemon trusts this contract for gate 1 and leans on Nix's
/// sha256 gate (gate 2) as the ultimate arbiter.
///
/// The trait is object-safe (`dyn Transport`) so a [`TransportRegistry`] can
/// dispatch offers decoded at runtime.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Which offer variant this transport services. Its registration key.
    fn tag(&self) -> TransportTag;

    /// Fetch `content` using `offer`'s locator, returning gate-1-verified raw NAR
    /// bytes. `offer` is guaranteed by the registry to be the variant matching
    /// [`Transport::tag`]; an impl may still guard with
    /// [`TransportError::WrongOffer`].
    async fn fetch(
        &self,
        content: &Blake3Digest,
        offer: &KnownTransport,
    ) -> Result<Vec<u8>, TransportError>;
}

// -------------------------------------------------------------------------
// Registry: offer tag -> Transport impl.
// -------------------------------------------------------------------------

/// Maps a [`TransportTag`] to the [`Transport`] impl that services it. A lookup
/// MISS is the "unknown/unimplemented transport" case: the offer is skipped, not a
/// crash (see [`fetch_via_offers`]).
#[derive(Default)]
pub struct TransportRegistry {
    by_tag: HashMap<TransportTag, Box<dyn Transport>>,
}

impl TransportRegistry {
    /// An empty registry (no transports). Register impls with [`Self::register`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a transport under its own [`Transport::tag`]. Re-registering a tag
    /// replaces the previous impl.
    pub fn register(&mut self, transport: Box<dyn Transport>) -> &mut Self {
        self.by_tag.insert(transport.tag(), transport);
        self
    }

    /// The transport servicing `tag`, or `None` if none is registered
    /// (unknown/unimplemented - the caller skips such offers).
    pub fn get(&self, tag: TransportTag) -> Option<&dyn Transport> {
        self.by_tag.get(&tag).map(Box::as_ref)
    }

    /// Whether a backend is registered for `tag`.
    pub fn has(&self, tag: TransportTag) -> bool {
        self.by_tag.contains_key(&tag)
    }
}

// -------------------------------------------------------------------------
// The driver: try a claim's offers in order, skip the unimplemented ones.
// -------------------------------------------------------------------------

/// Fetch `content` by trying each of `offers` in order, returning the first
/// gate-1-verified bytes.
///
/// Selection + fail-closed policy (AC#2):
///   * An offer whose transport has NO registered backend is SKIPPED (recorded,
///     resolution continues) - never a crash.
///   * An offer whose fetch FAILS (holder absent, integrity gate fired, dial
///     failed) is recorded and the next offer is tried - fail closed, try next.
///   * If no offer yields bytes, returns [`FetchError::Exhausted`] with both lists
///     so the failure is diagnosable and the caller can fall back to the cache.
pub async fn fetch_via_offers(
    registry: &TransportRegistry,
    content: &Blake3Digest,
    offers: &[KnownTransport],
) -> Result<Vec<u8>, FetchError> {
    let mut skipped = Vec::new();
    let mut failed = Vec::new();
    for offer in offers {
        let tag = TransportTag::of(offer);
        match registry.get(tag) {
            None => {
                // Unknown/unimplemented transport: skip, do not crash.
                skipped.push(tag);
            }
            Some(transport) => match transport.fetch(content, offer).await {
                Ok(bytes) => return Ok(bytes),
                Err(err) => failed.push((tag, err.to_string())),
            },
        }
    }
    Err(FetchError::Exhausted { skipped, failed })
}

// -------------------------------------------------------------------------
// The wave-2 NarSource skeleton: resolve a signed NarHash via transports.
// -------------------------------------------------------------------------

/// A [`NarSource`] that resolves a signed `NarHash` by fetching over the transport
/// layer - URL-less, keyed on content identity. task-39 registers the real iroh
/// [`Transport`]; task-40 supplies the [`Discovery`] layer that maps a `NarHash`
/// to a holder's complete claim. Neither touches the frozen [`NarSource`] seam.
///
/// Composition (task-40): `resolve` converts the seam's loose [`crate::source::NarHash`]
/// to the canonical [`NarHashKey`] (so discovery, the index and the claim all agree
/// on ONE key), asks [`Discovery::resolve`] for the holder's claim, then hands its
/// content id + offers to [`fetch_via_offers`]. A discovery MISS is a
/// [`SourceError::Unreachable`] - the fast, clean signal a [`crate::discovery::FallbackNarSource`]
/// (or the wave-1 serving layer's 502) turns into upstream fallback (S2).
pub struct TransportNarSource {
    registry: TransportRegistry,
    discovery: Arc<dyn Discovery>,
}

impl TransportNarSource {
    /// A source that fetches over `registry`, resolving holders via `discovery`.
    pub fn new(registry: TransportRegistry, discovery: Arc<dyn Discovery>) -> Self {
        Self {
            registry,
            discovery,
        }
    }
}

#[async_trait]
impl NarSource for TransportNarSource {
    /// `_expected_size` (the signed NarSize bound, risk-6 abort) is accepted but
    /// NOT enforced here yet: the bound must be enforced DURING streaming inside
    /// the transport (task-25), not post-hoc in this driver, or a lying holder
    /// could stream a huge blob before a late check - defeating the bound. Left as
    /// a forward-carry so the enforcement lands at the streaming boundary.
    async fn resolve(
        &self,
        key: &NarKey,
        _expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        // The p2p path resolves ONLY the signed-NarHash key. An UpstreamPath is the
        // wave-1 cold-start fallback (a raw URL) that a URL-less p2p source cannot
        // serve - reject it so the serving layer falls back to HTTP.
        let hash = match key {
            NarKey::SignedNarHash { hash, .. } => hash,
            NarKey::UpstreamPath(_) => {
                return Err(SourceError::Unreachable(
                    "a p2p transport source cannot resolve an UpstreamPath (no URL)".to_string(),
                ));
            }
        };

        // Canonicalise the loose seam hash to the strict wire key, so discovery,
        // the availability index and the claim all agree on ONE key. A genuine
        // narinfo NarHash always canonicalises; a non-canonical seam value cannot
        // be a p2p key, so it is a miss the caller falls back on (never a panic).
        let canonical = NarHashKey::try_from(hash).map_err(|e| {
            SourceError::Unreachable(format!(
                "NarHash {} is not a canonical p2p key: {e}",
                hash.as_str()
            ))
        })?;

        // Discovery: signed NarHash -> a holder's complete claim, or a bounded MISS.
        let claim = self.discovery.resolve(&canonical).await.ok_or_else(|| {
            SourceError::Unreachable(format!("no peer holds {canonical} (discovery miss)"))
        })?;

        // The addressed unit: the claim's single BLAKE3 content identity.
        let content = claim
            .content_id()
            .ok_or_else(|| SourceError::Upstream(FetchError::NoContentId.to_string()))?;

        // Gate 1 lives inside the transports; the driver picks an offer and returns
        // the verified bytes (or fails closed for HTTP fallback).
        let bytes = fetch_via_offers(&self.registry, content, &claim.transports)
            .await
            .map_err(|err| SourceError::Unreachable(err.to_string()))?;

        // Hand the raw NAR upward. Gate 2 (sha256 == NarHash) is Nix's, downstream:
        // the bytes are byte-identical to what the NarHash addresses, so that gate
        // passes; this daemon does not re-implement it (wave-1 S1).
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, bytes.len().into());
        Ok(UpstreamResponse {
            status: 200,
            headers,
            body: Full::new(Bytes::from(bytes))
                .map_err(|never| match never {})
                .boxed(),
        })
    }
}

// -------------------------------------------------------------------------
// FakeTransport: an in-memory, URL-less, content-addressed Transport for tests.
// task-39 replaces it with the real iroh backend under the SAME trait + registry.
// -------------------------------------------------------------------------

/// An in-memory [`Transport`] keyed PURELY on [`Blake3Digest`] - URL-less,
/// content-addressed. It stands in for iroh (task-39) to prove the seam: fetch
/// looks content up by identity ALONE, ignoring the offer's locator (a `NodeId`),
/// which is exactly the "keyed only on Blake3Digest" property.
pub struct FakeTransport {
    tag: TransportTag,
    by_content: HashMap<Blake3Digest, Vec<u8>>,
}

impl FakeTransport {
    /// A fake serving offers of `tag` (usually [`TransportTag::Iroh`], since it
    /// stands in for the iroh backend).
    pub fn new(tag: TransportTag) -> Self {
        Self {
            tag,
            by_content: HashMap::new(),
        }
    }

    /// Serve side (content-addressed "put"): store raw NAR bytes under their BLAKE3
    /// address and return that address. This is the honest holder path and models
    /// what a real iroh provider does when it adds a blob.
    pub fn seed(&mut self, raw_nar: Vec<u8>) -> Blake3Digest {
        let digest = Blake3Digest::from_raw_nar(&raw_nar);
        self.by_content.insert(digest, raw_nar);
        digest
    }

    /// Fault injection (a lying/corrupt holder): store `bytes` under a CHOSEN
    /// `claimed` digest they need not hash to, so a fetch for `claimed` returns
    /// bytes the transport-integrity gate ([`verify_blake3`]) must reject. Used to
    /// bite gate 1 - a real holder cannot make this bypass the gate.
    pub fn seed_corrupt(&mut self, claimed: Blake3Digest, bytes: Vec<u8>) {
        self.by_content.insert(claimed, bytes);
    }
}

#[async_trait]
impl Transport for FakeTransport {
    fn tag(&self) -> TransportTag {
        self.tag
    }

    async fn fetch(
        &self,
        content: &Blake3Digest,
        offer: &KnownTransport,
    ) -> Result<Vec<u8>, TransportError> {
        // Defensive: the registry dispatches by tag, but a wrong variant is a bug
        // worth surfacing rather than silently mis-serving.
        let got = TransportTag::of(offer);
        if got != self.tag {
            return Err(TransportError::WrongOffer {
                expected: self.tag,
                got,
            });
        }
        // URL-less: look content up PURELY by its identity, ignoring the locator.
        let bytes = self
            .by_content
            .get(content)
            .cloned()
            .ok_or(TransportError::NotHeld(*content))?;
        // Gate 1: the bytes we return MUST hash to the requested identity.
        verify_blake3(content, &bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::claim::{CLAIM_SCHEMA_VERSION, Claim, KnownPayload, NarHashKey};
    use crate::discovery::InMemoryDiscovery;
    use crate::source::{NarHash, NarPathToken};
    use crate::transport::{BitTorrentInfoHash, NodeId};

    /// A `TransportNarSource` over `registry` whose discovery already knows
    /// `claims` (the task-40 `InMemoryDiscovery` stand-in replacing the old inline
    /// map). With no claims it resolves every key to a miss.
    fn source_with(registry: TransportRegistry, claims: Vec<Claim>) -> TransportNarSource {
        let discovery = InMemoryDiscovery::new();
        for claim in claims {
            discovery.announce(claim);
        }
        TransportNarSource::new(registry, Arc::new(discovery))
    }

    // A canonical signed NarHash (borrowed from the claim.rs fixtures) and a
    // holder NodeId. The raw NAR is arbitrary bytes - BLAKE3 addresses whatever
    // they are.
    const KEY_HEX: &str = "sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb";
    const RAW_NAR: &[u8] = b"nix-archive-1 (fake raw NAR payload for the transport seam)";

    fn key() -> NarHashKey {
        KEY_HEX.parse().expect("canonical NarHash")
    }
    fn node() -> NodeId {
        NodeId::from_bytes([0x11; 32])
    }
    fn signed_key() -> NarKey {
        NarKey::SignedNarHash {
            hash: NarHash::new(KEY_HEX),
            // The transport hint is a URL token a p2p source must IGNORE.
            upstream_hint: NarPathToken::new("nar/1irrelevant.nar.xz"),
        }
    }

    /// A whole-NAR claim addressing `blake3`, offering the given transports.
    fn claim_with(blake3: Blake3Digest, transports: Vec<KnownTransport>) -> Claim {
        Claim {
            schema_version: CLAIM_SCHEMA_VERSION,
            key: key(),
            payload: Some(KnownPayload::WholeNar { blake3 }),
            holders: vec![node()],
            transports,
            relay: None,
            signatures: vec![],
        }
    }

    async fn collect(resp: UpstreamResponse) -> Vec<u8> {
        resp.body.collect().await.expect("body").to_bytes().to_vec()
    }

    // --- Gate 1 (transport integrity) is a real, checkable function -----------

    #[test]
    fn verify_blake3_accepts_matching_and_rejects_tampered() {
        let good = Blake3Digest::from_raw_nar(RAW_NAR);
        assert!(verify_blake3(&good, RAW_NAR).is_ok());
        // A different digest (of other bytes) does NOT match - the gate bites.
        let wrong = Blake3Digest::from_raw_nar(b"tampered");
        match verify_blake3(&wrong, RAW_NAR) {
            Err(TransportError::IntegrityMismatch { expected, actual }) => {
                assert_eq!(expected, wrong);
                assert_eq!(actual, good);
            }
            other => panic!("expected IntegrityMismatch, got {other:?}"),
        }
    }

    // --- AC#1: a fake in-memory transport satisfies NarSource, URL-less, keyed on
    // Blake3Digest, and the resolved NAR is byte-identical to the addressed unit
    // (so Nix's sha256==NarHash trust gate passes) - the TWO gates, both present.

    #[tokio::test]
    async fn fake_transport_satisfies_narsource_and_passes_both_gates() {
        let mut fake = FakeTransport::new(TransportTag::Iroh);
        // Serve side: content-addressed put. The digest is derived from the bytes.
        let content = fake.seed(RAW_NAR.to_vec());
        assert_eq!(content, Blake3Digest::from_raw_nar(RAW_NAR));

        // The two identities of the SAME bytes are DISTINCT: the sha256 NarHash key
        // (lookup/trust) is not the blake3 content id (fetch/stream-verify).
        assert_ne!(
            content.as_bytes().as_slice(),
            key().as_bytes().as_slice(),
            "the two gates key on two different identities of the same NAR"
        );

        let mut registry = TransportRegistry::new();
        registry.register(Box::new(fake));
        let source = source_with(
            registry,
            vec![claim_with(
                content,
                vec![KnownTransport::Iroh { node: node() }],
            )],
        );

        // resolve() takes the signed NarHash (NOT a URL). The fake fetched purely
        // by content id, ignoring the iroh NodeId locator.
        let resp = source
            .resolve(&signed_key(), Some(RAW_NAR.len() as u64))
            .await
            .expect("resolve the signed NarHash via the fake transport");
        assert_eq!(resp.status, 200);
        let got = collect(resp).await;

        // Gate 1 (BLAKE3) ran inside the transport. Re-check it explicitly here so
        // the assertion is not vacuous: the returned bytes address `content`.
        assert!(
            verify_blake3(&content, &got).is_ok(),
            "gate 1 holds on the output"
        );
        // Gate 2 (trust): the bytes are byte-identical to the addressed NAR, which
        // is exactly what makes Nix's downstream sha256==NarHash gate pass. The
        // daemon does not re-implement that gate (wave-1 S1 owns it).
        assert_eq!(
            got, RAW_NAR,
            "resolved NAR is byte-identical to the addressed unit"
        );
    }

    // --- AC#1 bite: gate 1 rejects a corrupt holder (fails-before/passes-after).

    #[tokio::test]
    async fn a_corrupt_holder_is_rejected_by_the_integrity_gate() {
        let content = Blake3Digest::from_raw_nar(RAW_NAR);
        let mut fake = FakeTransport::new(TransportTag::Iroh);
        // The holder LIES: it stores tampered bytes under the requested identity.
        // fails-before (no gate 1): resolve would return these wrong bytes.
        fake.seed_corrupt(content, b"WRONG bytes a lying peer serves".to_vec());

        let mut registry = TransportRegistry::new();
        registry.register(Box::new(fake));
        let source = source_with(
            registry,
            vec![claim_with(
                content,
                vec![KnownTransport::Iroh { node: node() }],
            )],
        );

        // passes-after: gate 1 fires, the offer fails, resolution is exhausted and
        // fails closed (Nix falls back) - the wrong bytes NEVER reach the client.
        match source.resolve(&signed_key(), None).await {
            Err(SourceError::Unreachable(why)) => {
                assert!(
                    why.contains("integrity"),
                    "the failure must be the integrity gate, got: {why}"
                );
            }
            Err(other) => panic!("expected a fail-closed Unreachable, got {other:?}"),
            Ok(_) => panic!("a corrupt holder must fail closed, not serve wrong bytes"),
        }
    }

    // --- AC#2: an unknown/unimplemented transport tag is SKIPPED, not a crash ---

    #[tokio::test]
    async fn an_unimplemented_transport_offer_is_skipped_not_a_crash() {
        let content = Blake3Digest::from_raw_nar(RAW_NAR);
        // Only iroh is registered; there is NO bittorrent backend.
        let mut fake = FakeTransport::new(TransportTag::Iroh);
        fake.seed(RAW_NAR.to_vec());
        let mut registry = TransportRegistry::new();
        registry.register(Box::new(fake));
        assert!(!registry.has(TransportTag::BitTorrent));

        let bt_offer = KnownTransport::BitTorrent {
            infohash: BitTorrentInfoHash::v2([0xbb; 32]),
        };

        // A claim offering ONLY bittorrent: the offer is skipped (no backend) and
        // resolution is cleanly exhausted - NOT a panic.
        match fetch_via_offers(&registry, &content, std::slice::from_ref(&bt_offer)).await {
            Err(FetchError::Exhausted { skipped, failed }) => {
                assert_eq!(skipped, vec![TransportTag::BitTorrent]);
                assert!(failed.is_empty());
            }
            other => panic!("an unimplemented-only offer must be exhausted, got {other:?}"),
        }

        // A claim offering [bittorrent, iroh]: bittorrent is skipped, iroh serves.
        // This is "resolution continues to the next offer".
        let bytes = fetch_via_offers(
            &registry,
            &content,
            &[bt_offer, KnownTransport::Iroh { node: node() }],
        )
        .await
        .expect("bittorrent skipped, iroh fetches");
        assert_eq!(bytes, RAW_NAR);
    }

    // --- Dispatch + fail-closed corner cases ---------------------------------

    #[test]
    fn transport_tag_maps_each_offer_variant() {
        assert_eq!(
            TransportTag::of(&KnownTransport::Iroh { node: node() }),
            TransportTag::Iroh
        );
        assert_eq!(
            TransportTag::of(&KnownTransport::BitTorrent {
                infohash: BitTorrentInfoHash::v1([0xaa; 20]),
            }),
            TransportTag::BitTorrent
        );
    }

    #[tokio::test]
    async fn an_offer_whose_holder_lacks_the_content_fails_then_exhausts() {
        // iroh is registered but holds NOTHING for this content: the offer FAILS
        // (NotHeld), is recorded, and resolution exhausts - fail closed, no crash.
        let content = Blake3Digest::from_raw_nar(RAW_NAR);
        let mut registry = TransportRegistry::new();
        registry.register(Box::new(FakeTransport::new(TransportTag::Iroh)));
        match fetch_via_offers(
            &registry,
            &content,
            &[KnownTransport::Iroh { node: node() }],
        )
        .await
        {
            Err(FetchError::Exhausted { skipped, failed }) => {
                assert!(skipped.is_empty());
                assert_eq!(failed.len(), 1);
                assert_eq!(failed[0].0, TransportTag::Iroh);
                assert!(failed[0].1.contains("does not hold"));
            }
            other => panic!("expected exhaustion after a failed offer, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upstream_path_is_rejected_by_the_p2p_source() {
        // Mirror of the nar_source_seam contract: a URL-less p2p source cannot
        // resolve the cold-start UpstreamPath fallback.
        let source = source_with(TransportRegistry::new(), vec![]);
        let key = NarKey::UpstreamPath(NarPathToken::new("nar/1abc.nar.xz"));
        match source.resolve(&key, None).await {
            Err(SourceError::Unreachable(why)) => assert!(why.contains("UpstreamPath")),
            Err(other) => panic!("expected an Unreachable rejection, got {other:?}"),
            Ok(_) => panic!("a p2p source must reject an UpstreamPath, not serve it"),
        }
    }

    #[tokio::test]
    async fn a_claim_with_no_usable_content_id_is_a_clean_error() {
        // An unknown payload kind -> content_id() is None -> resolve errors cleanly
        // (never a panic, never a fetch of nothing).
        let mut claim = claim_with(
            Blake3Digest::from_raw_nar(RAW_NAR),
            vec![KnownTransport::Iroh { node: node() }],
        );
        claim.payload = None; // as if decoded from an unknown-kind wire payload
        let source = source_with(TransportRegistry::new(), vec![claim]);
        match source.resolve(&signed_key(), None).await {
            Err(SourceError::Upstream(why)) => assert!(why.contains("content id")),
            Err(other) => panic!("expected a clean content-id error, got {other:?}"),
            Ok(_) => panic!("a no-content-id claim must error cleanly, not serve"),
        }
    }
}
