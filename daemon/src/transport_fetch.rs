//! The pluggable p2p fetch abstraction that sits UNDER the frozen `NarSource`
//! seam (task-38). iroh is ONE impl of it (task-39); BitTorrent a future one.
//!
//! ## Where this sits
//!
//! [`daemon_core::source::NarSource`] resolves a NAR by its signed `NarHash`. This
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
//! deliberately transport-agnostic, exactly like [`daemon_core::transport`] keeps the
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
//! transport addresses. A claim binds them (see [`daemon_core::claim`]). task-39 will
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

use daemon_core::claim::{KnownTransport, NarHashKey};
use daemon_core::content_id::Blake3Digest;
use daemon_core::discovery::Discovery;
use daemon_core::source::{NarKey, NarSource, SourceError, UpstreamResponse};

// -------------------------------------------------------------------------
// Transport selection tag.
// -------------------------------------------------------------------------

// The dispatch key a [`TransportRegistry`] maps to a [`Transport`] impl now lives
// in `peer-fabric` (the canonical home of every value type that crosses the P2P
// seam; TASK-141 deleted the daemon's former duplicate). Re-exported so this
// module's use-sites (`TransportTag::Iroh`, ...) are unchanged.
//
// Note the layering, unchanged: the claim decoder already DROPS genuinely-unknown
// wire transports (tolerated but inert - see [`daemon_core::claim`]), so by the time an
// offer reaches this module it is always a KNOWN wire variant. "Unknown" AT THIS
// LAYER means a known wire transport with NO registered backend (e.g. `bittorrent`,
// representable but not implemented) - that offer is SKIPPED, never a crash.
//
// The seam's `TransportTag::of` maps the SEAM's offer type (`TransportOffer`); the
// daemon's own wire offer enum maps to the tag via [`KnownTransport::tag`], since
// the two offer representations differ. Both agree on the frozen `"iroh"` /
// `"bittorrent"` wire tags.
pub use peer_fabric::TransportTag;

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
    /// The risk-6 SIZE ABORT (task-51): the holder streamed MORE than the signed
    /// NarSize bound. `streamed` is the byte count when the cap tripped (at least
    /// `limit`): a lower bound on the true blob size, since the stream is aborted
    /// early rather than drained. The bound is the SIGNED NarSize (uncompressed raw
    /// NAR),
    /// NEVER the compressed FileSize (the unit trap). Unlike [`Self::Unavailable`],
    /// this is a DELIBERATE abort of a lying claim, not a "try the next holder"
    /// signal: every offer in the claim addresses the SAME oversized BLAKE3, so the
    /// driver short-circuits it (see [`fetch_via_offers`]) into a propagating
    /// [`daemon_core::source::SourceError::TooLarge`] rather than falling back.
    TooLarge { limit: u64, streamed: u64 },
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
            TransportError::TooLarge { limit, streamed } => write!(
                f,
                "size abort: holder streamed {streamed} bytes, over the signed NarSize bound {limit}"
            ),
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
    /// The risk-6 SIZE ABORT short-circuited the offer loop (task-51): a holder
    /// streamed more than the signed NarSize bound. This is NOT "try the next
    /// offer" - every offer in the claim addresses the SAME oversized BLAKE3 - so
    /// the driver stops immediately and the caller maps this to a PROPAGATING
    /// [`daemon_core::source::SourceError::TooLarge`] (never an upstream fallback, which
    /// would paper over a deliberate abort).
    TooLarge { limit: u64, streamed: u64 },
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
            FetchError::TooLarge { limit, streamed } => write!(
                f,
                "size abort: a holder streamed {streamed} bytes, over the signed NarSize bound {limit}"
            ),
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
///
/// ## `expected_size`: the signed-NarSize safety bound (task-51)
///
/// task-39 deliberately left this trait size-less and carried the per-request
/// bound forward to here. `expected_size` is the SIGNED NarSize from the narinfo
/// (`Some` on the normal correlated path, `None` on the cold-start fallback where
/// no signed bound is known). It is the UNCOMPRESSED raw-NAR byte count - the same
/// unit as the transferred `RawNarV1` for a peer-served path - NEVER the compressed
/// FileSize (the recurring unit trap). A streaming impl MUST enforce it DURING the
/// transfer (abort the moment cumulative bytes exceed it), so a lying holder that
/// claims a small NarSize but serves a huge blob is cut off at ~NarSize rather than
/// buffered whole (risk 6 / OOM). `None` disables the size abort but not the
/// transport's own time/idle envelope.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Which offer variant this transport services. Its registration key.
    fn tag(&self) -> TransportTag;

    /// Fetch `content` using `offer`'s locator, returning gate-1-verified raw NAR
    /// bytes, aborting if the transfer exceeds `expected_size` (the signed NarSize;
    /// see the trait docs). `offer` is guaranteed by the registry to be the variant
    /// matching [`Transport::tag`]; an impl may still guard with
    /// [`TransportError::WrongOffer`].
    async fn fetch(
        &self,
        content: &Blake3Digest,
        offer: &KnownTransport,
        expected_size: Option<u64>,
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
/// `expected_size` is the signed NarSize bound (task-51), threaded to each
/// [`Transport::fetch`] so the risk-6 abort fires at the streaming boundary.
///
/// Selection + fail-closed policy (AC#2):
///   * An offer whose transport has NO registered backend is SKIPPED (recorded,
///     resolution continues) - never a crash.
///   * An offer whose fetch FAILS (holder absent, integrity gate fired, dial
///     failed) is recorded and the next offer is tried - fail closed, try next.
///   * An offer that trips the SIZE ABORT ([`TransportError::TooLarge`]) SHORT-
///     CIRCUITS the loop: every offer in the claim addresses the same oversized
///     BLAKE3, so trying the next is pointless, and falling back would paper over a
///     deliberate abort. Returns [`FetchError::TooLarge`] straight away.
///   * If no offer yields bytes, returns [`FetchError::Exhausted`] with both lists
///     so the failure is diagnosable and the caller can fall back to the cache.
pub async fn fetch_via_offers(
    registry: &TransportRegistry,
    content: &Blake3Digest,
    offers: &[KnownTransport],
    expected_size: Option<u64>,
) -> Result<Vec<u8>, FetchError> {
    let mut skipped = Vec::new();
    let mut failed = Vec::new();
    for offer in offers {
        let tag = offer.tag();
        match registry.get(tag) {
            None => {
                // Unknown/unimplemented transport: skip, do not crash.
                skipped.push(tag);
            }
            Some(transport) => match transport.fetch(content, offer, expected_size).await {
                Ok(bytes) => return Ok(bytes),
                // A deliberate size abort is not "try the next holder": short-circuit.
                Err(TransportError::TooLarge { limit, streamed }) => {
                    return Err(FetchError::TooLarge { limit, streamed });
                }
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
/// Composition (task-40): `resolve` converts the seam's loose [`daemon_core::source::NarHash`]
/// to the canonical [`NarHashKey`] (so discovery, the index and the claim all agree
/// on ONE key), asks [`Discovery::resolve`] for the holder's claim, then hands its
/// content id + offers to [`fetch_via_offers`]. A discovery MISS is a
/// [`SourceError::Unreachable`] - the fast, clean signal a [`daemon_core::discovery::FallbackNarSource`]
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
    /// `expected_size` (the signed NarSize bound, risk-6 abort) is threaded through
    /// [`fetch_via_offers`] to [`Transport::fetch`], where a streaming impl enforces
    /// it DURING the transfer (task-51) - never post-hoc in this driver, which would
    /// let a lying holder stream a huge blob before a late check and defeat the
    /// bound. A trip returns [`FetchError::TooLarge`], which this maps to the
    /// PROPAGATING [`SourceError::TooLarge`] (a [`daemon_core::discovery::FallbackNarSource`]
    /// does NOT paper it over with an upstream fetch).
    async fn resolve(
        &self,
        key: &NarKey,
        expected_size: Option<u64>,
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
        // the verified bytes (or fails closed for HTTP fallback). The signed NarSize
        // bound rides along so the risk-6 abort fires at the streaming boundary.
        let bytes = fetch_via_offers(&self.registry, content, &claim.transports, expected_size)
            .await
            .map_err(|err| match err {
                // A deliberate size abort PROPAGATES (no upstream fallback):
                FetchError::TooLarge { limit, streamed } => SourceError::TooLarge {
                    limit,
                    declared: streamed,
                },
                // A miss / exhausted offer set folds to a fast, clean miss the
                // FallbackNarSource turns into upstream fallback (S2).
                other => SourceError::Unreachable(other.to_string()),
            })?;

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
        // Deliberately IGNORED: this is a whole-in-memory stand-in, not a streaming
        // transport, so it has no streaming boundary to enforce the risk-6 NarSize
        // abort at. Enforcing it post-hoc here (buffer-then-check) would model the
        // exact anti-pattern task-51 fixes, so the real abort lives in IrohTransport
        // (the streaming path) and this fake stays a pure content-addressed lookup.
        _expected_size: Option<u64>,
    ) -> Result<Vec<u8>, TransportError> {
        // Defensive: the registry dispatches by tag, but a wrong variant is a bug
        // worth surfacing rather than silently mis-serving.
        let got = offer.tag();
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

    use daemon_core::claim::{CLAIM_SCHEMA_VERSION, Claim, KnownPayload, NarHashKey};
    use daemon_core::discovery::InMemoryDiscovery;
    use daemon_core::source::{NarHash, NarPathToken};
    use daemon_core::transport::{BitTorrentInfoHash, NodeId};

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
        match fetch_via_offers(&registry, &content, std::slice::from_ref(&bt_offer), None).await {
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
            None,
        )
        .await
        .expect("bittorrent skipped, iroh fetches");
        assert_eq!(bytes, RAW_NAR);
    }

    // --- Dispatch + fail-closed corner cases ---------------------------------

    #[test]
    fn transport_tag_maps_each_offer_variant() {
        assert_eq!(
            KnownTransport::Iroh { node: node() }.tag(),
            TransportTag::Iroh
        );
        assert_eq!(
            KnownTransport::BitTorrent {
                infohash: BitTorrentInfoHash::v1([0xaa; 20]),
            }
            .tag(),
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
            None,
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

    /// A transport that always trips the risk-6 size abort (models a streaming
    /// backend that cut a lying oversized blob off at the signed NarSize). Used to
    /// prove the SHORT-CIRCUIT + error mapping without a real network - the REAL
    /// streaming abort over iroh is `iroh_transport.rs`.
    struct AbortingTransport {
        limit: u64,
        streamed: u64,
    }
    #[async_trait]
    impl Transport for AbortingTransport {
        fn tag(&self) -> TransportTag {
            TransportTag::Iroh
        }
        async fn fetch(
            &self,
            _content: &Blake3Digest,
            _offer: &KnownTransport,
            _expected_size: Option<u64>,
        ) -> Result<Vec<u8>, TransportError> {
            Err(TransportError::TooLarge {
                limit: self.limit,
                streamed: self.streamed,
            })
        }
    }

    #[tokio::test]
    async fn a_size_abort_short_circuits_offers_and_does_not_try_the_next() {
        // Two offers, both iroh. The first trips TooLarge; the loop must NOT try the
        // second (every offer addresses the same oversized BLAKE3) - it short-
        // circuits into FetchError::TooLarge, carrying the bound through.
        let content = Blake3Digest::from_raw_nar(RAW_NAR);
        let mut registry = TransportRegistry::new();
        registry.register(Box::new(AbortingTransport {
            limit: 1024,
            streamed: 1040,
        }));
        let offers = [
            KnownTransport::Iroh { node: node() },
            KnownTransport::Iroh { node: node() },
        ];
        match fetch_via_offers(&registry, &content, &offers, Some(1024)).await {
            Err(FetchError::TooLarge { limit, streamed }) => {
                assert_eq!((limit, streamed), (1024, 1040));
            }
            other => panic!("a size abort must short-circuit into TooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_size_abort_maps_to_propagating_source_too_large() {
        // Through the NarSource: TransportError::TooLarge -> FetchError::TooLarge ->
        // SourceError::TooLarge (which FallbackNarSource propagates, never papers
        // over - proven in discovery.rs). This wires the seam end to end.
        let content = Blake3Digest::from_raw_nar(RAW_NAR);
        let mut registry = TransportRegistry::new();
        registry.register(Box::new(AbortingTransport {
            limit: 1024,
            streamed: 999_999,
        }));
        let source = source_with(
            registry,
            vec![claim_with(
                content,
                vec![KnownTransport::Iroh { node: node() }],
            )],
        );
        match source.resolve(&signed_key(), Some(1024)).await {
            Err(SourceError::TooLarge { limit, declared }) => {
                assert_eq!(limit, 1024);
                assert_eq!(declared, 999_999);
            }
            Err(other) => panic!("expected a propagating SourceError::TooLarge, got {other}"),
            Ok(_) => panic!("a size abort must NOT resolve to bytes"),
        }
    }

    // --- task-66: genuine MULTI-HOLDER failover (holder -> next holder) -------

    /// A content-addressed transport that is AWARE of which holder it is dialing
    /// (unlike [`FakeTransport`], which ignores the locator). It serves the seeded
    /// bytes for a LIVE holder and refuses for a DEAD one, and COUNTS attempts per
    /// holder - so a test can prove the fetch reached the SECOND holder only after
    /// the FIRST (dead) one was tried. This is what distinguishes real
    /// holder->holder failover from "the last announce happened to work".
    struct NodeAwareTransport {
        content: Blake3Digest,
        bytes: Vec<u8>,
        /// Holders whose dial is refused (a dead holder → try the next offer).
        dead: Vec<NodeId>,
        /// Holders that SERVE but serve tampered bytes not hashing to `content`
        /// (a lying holder → gate-1 fails closed → try the next offer).
        liars: Vec<NodeId>,
        attempts: Arc<std::sync::Mutex<Vec<NodeId>>>,
    }

    #[async_trait]
    impl Transport for NodeAwareTransport {
        fn tag(&self) -> TransportTag {
            TransportTag::Iroh
        }
        async fn fetch(
            &self,
            content: &Blake3Digest,
            offer: &KnownTransport,
            _expected_size: Option<u64>,
        ) -> Result<Vec<u8>, TransportError> {
            let node = match offer {
                KnownTransport::Iroh { node } => *node,
                other => {
                    return Err(TransportError::WrongOffer {
                        expected: TransportTag::Iroh,
                        got: other.tag(),
                    });
                }
            };
            // Record the dial so the test can see the ORDER holders were tried in.
            self.attempts.lock().expect("attempts").push(node);
            if self.dead.contains(&node) {
                // A dead holder: dial refused. The driver must try the NEXT offer.
                return Err(TransportError::Unavailable(format!(
                    "holder {node} is dead"
                )));
            }
            if self.liars.contains(&node) {
                // A lying holder serves bytes that do NOT hash to the requested
                // identity; gate-1 (verify_blake3) rejects them, fails closed, and
                // the driver moves to the next offer - a lying offer never yields
                // wrong bytes (the daemon is outside the TCB).
                verify_blake3(content, b"WRONG bytes a lying holder serves")?;
                unreachable!("gate-1 must reject the lying holder's bytes");
            }
            if content != &self.content {
                return Err(TransportError::NotHeld(*content));
            }
            verify_blake3(content, &self.bytes)?;
            Ok(self.bytes.clone())
        }
    }

    #[tokio::test]
    async fn a_dead_first_holder_fails_over_to_the_second_holder() {
        // The task-66 acceptance signal. TWO holders announce the SAME NarHash;
        // holder A (announced first) is DEAD, holder B is live. The resolve path
        // accumulates BOTH (multimap) and the fetch driver tries A, fails, and
        // reaches B - a genuine holder->holder failover, NOT the peer->upstream S6.
        //
        // Bite by mutation: revert `announce` to the old replace-on-key and only
        // B's claim survives, so A is NEVER dialed - `attempts == [A, B]` becomes
        // `[B]` and this fails. (The bytes would still arrive from B, which is
        // exactly why asserting only success is vacuous; the attempt ORDER is the
        // oracle that bites.)
        let content = Blake3Digest::from_raw_nar(RAW_NAR);
        let a = NodeId::from_bytes([0xaa; 32]);
        let b = NodeId::from_bytes([0xbb; 32]);
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut registry = TransportRegistry::new();
        registry.register(Box::new(NodeAwareTransport {
            content,
            bytes: RAW_NAR.to_vec(),
            dead: vec![a],
            liars: vec![],
            attempts: attempts.clone(),
        }));

        // A announces FIRST (so it is the dead holder tried first), then B.
        let holder_claim = |holder: NodeId| Claim {
            schema_version: CLAIM_SCHEMA_VERSION,
            key: key(),
            payload: Some(KnownPayload::WholeNar { blake3: content }),
            holders: vec![holder],
            transports: vec![KnownTransport::Iroh { node: holder }],
            relay: None,
            signatures: vec![],
        };
        let source = source_with(registry, vec![holder_claim(a), holder_claim(b)]);

        let resp = source
            .resolve(&signed_key(), Some(RAW_NAR.len() as u64))
            .await
            .expect("the dead first holder fails over to the live second holder");
        assert_eq!(
            collect(resp).await,
            RAW_NAR,
            "the second holder served the NAR"
        );

        // The oracle: A was dialed FIRST (and failed), THEN B - real failover.
        assert_eq!(
            *attempts.lock().expect("attempts"),
            vec![a, b],
            "the fetch must try the dead first holder, then fail over to the second"
        );
    }

    #[tokio::test]
    async fn a_lying_holder_in_the_merged_set_fails_gate1_and_an_honest_holder_serves() {
        // The safety claim the multi-holder MERGE rests on, pinned by a test (it was
        // prose-only before): when several holders are accumulated under one key and
        // merged into one claim, a holder that SERVES WRONG BYTES cannot poison the
        // result - gate-1 (BLAKE3) rejects it and the driver fails over to an honest
        // holder. So the union of offers is sound: a lying offer only costs a bounded
        // retry, never wrong bytes (the daemon is outside the TCB).
        //
        // Order: honest-but-DEAD A (tried first, dial refused) -> LIAR B (serves
        // tampered bytes, gate-1 rejects) -> honest live C (serves). Proven by the
        // attempt order [A, B, C] AND by the honest bytes coming back from C.
        let content = Blake3Digest::from_raw_nar(RAW_NAR);
        let a = NodeId::from_bytes([0xaa; 32]);
        let b = NodeId::from_bytes([0xbb; 32]);
        let c = NodeId::from_bytes([0xcc; 32]);
        let attempts = Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut registry = TransportRegistry::new();
        registry.register(Box::new(NodeAwareTransport {
            content,
            bytes: RAW_NAR.to_vec(),
            dead: vec![a],
            liars: vec![b],
            attempts: attempts.clone(),
        }));

        let holder_claim = |holder: NodeId| Claim {
            schema_version: CLAIM_SCHEMA_VERSION,
            key: key(),
            payload: Some(KnownPayload::WholeNar { blake3: content }),
            holders: vec![holder],
            transports: vec![KnownTransport::Iroh { node: holder }],
            relay: None,
            signatures: vec![],
        };
        let source = source_with(
            registry,
            vec![holder_claim(a), holder_claim(b), holder_claim(c)],
        );

        let resp = source
            .resolve(&signed_key(), Some(RAW_NAR.len() as u64))
            .await
            .expect("the honest holder still serves despite a liar in the merged set");
        assert_eq!(
            collect(resp).await,
            RAW_NAR,
            "the bytes are the honest NAR - the liar contributed nothing"
        );
        assert_eq!(
            *attempts.lock().expect("attempts"),
            vec![a, b, c],
            "dead A, then liar B (rejected by gate-1), then honest C served"
        );
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
