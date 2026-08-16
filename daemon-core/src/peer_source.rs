//! [`PeerFabricNarSource`] - a [`NarSource`] that resolves a NAR through ANY
//! [`PeerFabric`]: DISCOVER a provider via the fabric's [`ProviderDirectory`], then FETCH
//! the raw NAR from it over the fabric's [`NarTransfer`], gate-1 BLAKE3-verified, URL-less
//! and keyed on the signed content identity.
//!
//! ## Stack-neutral by construction (TASK-146)
//!
//! This is the generalization of the former `daemon::source_libp2p::Libp2pNarSource`. That
//! type was ALREADY generic over `Arc<dyn PeerFabric>` - only its *construction* named
//! `fabric_libp2p`. Moving the type here (into the peer-fabric-only `daemon-core`) makes the
//! decentralized content path a property of the SEAM, not of any one backend: a
//! `daemon-libp2p` binary constructs a `Libp2pFabric` and a `daemon-iroh` binary an
//! `IrohFabric`, and both wrap the running fabric in the SAME source. The per-backend
//! connectivity/bootstrap wiring stays in each binary; only the intention (discover, then
//! fetch behind the frozen [`NarSource`] seam) lives here.
//!
//! ## The flow (matching the FROZEN recipe)
//!
//! ```text
//!   NarSource::resolve(NarKey::SignedNarHash{ hash })
//!     -> NarHashKey::try_from(hash)                 (canonical 32-byte sha256 NarHash)
//!     -> ContentKey::derive_from_signed_nar_hash    (FROZEN peer-fabric content.rs recipe)
//!     -> fabric.provider_directory().find_providers(ContentKey)   (the DHT, NOT injected)
//!     -> pick a ProviderRecord: its provider NodeId, content Blake3Digest + offers
//!     -> for each offer: fabric.transfer(offer.tag()).fetch(content, offer, size, envelope)
//!         (WHERE the provider is dialable is resolved INSIDE the fabric before dialing;
//!         DialInfo never reaches this serving layer; gate-1 BLAKE3 verify lives INSIDE the
//!         transfer, so a lying holder fails closed and the next offer/record is tried)
//!     -> hand the raw NAR up; Nix re-verifies sig + sha256==NarHash (gate 2, the TCB)
//! ```
//!
//! ## The two gates (unchanged from the seam's contract)
//!
//!   1. Transport-integrity gate (BLAKE3) - owned by the [`NarTransfer`] impl: the bytes
//!      MUST hash to the record's `content` [`Blake3Digest`] or the fetch fails closed and
//!      the next offer/record is tried. This layer re-checks nothing the transfer checked.
//!   2. Trust gate (sha256 == NarHash) - owned by NIX, downstream. The daemon stays OUTSIDE
//!      the TCB: wrong bytes that somehow slipped gate 1 yield a failed build + retry.
//!
//! ## Miss / fallback discipline (S2)
//!
//! A discovery [`Lookup::Miss`]/[`Lookup::Unavailable`], and an exhausted offer set, all
//! fold to a fast [`SourceError::Unreachable`] - the clean signal a
//! [`crate::discovery::FallbackNarSource`] turns into an upstream fetch. A deliberate size
//! abort ([`TransferError::TooLarge`]) is the ONE exception: it PROPAGATES as
//! [`SourceError::TooLarge`] (never papered over by upstream fallback).

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;
use http_body_util::{BodyExt, Full};
use peer_fabric::{ContentKey, DiscoveryBudget, Lookup, PeerFabric, SafetyEnvelope, TransferError};

use crate::claim::NarHashKey;
use crate::rewrite::RawServeDecision;
use crate::source::{NarKey, NarSource, SourceError, UpstreamResponse};

/// A [`NarSource`] backed by any [`PeerFabric`]: discover via the directory, fetch over the
/// fabric's NAR transfer. Holds the fabric as `Arc<dyn PeerFabric>` (the seam, not a
/// concrete backend) plus the mechanism bounds the two consultations run under.
pub struct PeerFabricNarSource {
    fabric: Arc<dyn PeerFabric>,
    /// The bound on a `find_providers` consultation (deadline + peer cap).
    discovery_budget: DiscoveryBudget,
    /// The fetch time envelope (dial / body-idle / total) handed to each transfer.
    envelope: SafetyEnvelope,
}

impl PeerFabricNarSource {
    /// A source discovering + fetching through `fabric`, under the given bounds. The
    /// composition root (TASK-120) owns the numbers; this only enforces them.
    pub fn new(
        fabric: Arc<dyn PeerFabric>,
        discovery_budget: DiscoveryBudget,
        envelope: SafetyEnvelope,
    ) -> Self {
        PeerFabricNarSource {
            fabric,
            discovery_budget,
            envelope,
        }
    }
}

/// Wrap already-verified raw NAR bytes in the uniform seam response (200 + a truthful
/// Content-Length). Gate 2 (sha256==NarHash) is Nix's, downstream.
fn ok_response(bytes: Vec<u8>) -> UpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, bytes.len().into());
    UpstreamResponse {
        status: 200,
        headers,
        body: Full::new(Bytes::from(bytes))
            .map_err(|never| match never {})
            .boxed(),
    }
}

#[async_trait]
impl NarSource for PeerFabricNarSource {
    async fn resolve(
        &self,
        key: &NarKey,
        expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        // The p2p path resolves ONLY the signed-NarHash key. An UpstreamPath is the
        // wave-1 cold-start fallback (a raw URL) a URL-less p2p source cannot serve -
        // reject it so the serving layer falls back to HTTP.
        let hash = match key {
            NarKey::SignedNarHash { hash, .. } => hash,
            NarKey::UpstreamPath(_) => {
                return Err(SourceError::Unreachable(
                    "a p2p source cannot resolve an UpstreamPath (no URL)".to_string(),
                ));
            }
        };

        // Canonicalise the loose seam NarHash to its 32 raw sha256 bytes, then derive the
        // FROZEN discovery ContentKey. A non-canonical seam value cannot be a p2p key, so
        // it is a clean miss the caller falls back on (never a panic).
        let canonical = NarHashKey::try_from(hash).map_err(|e| {
            SourceError::Unreachable(format!(
                "NarHash {} is not a canonical p2p key: {e}",
                hash.as_str()
            ))
        })?;
        let content_key = ContentKey::derive_from_signed_nar_hash(canonical.as_bytes());

        // Discovery must come from the directory: no directory axis means this fabric cannot
        // answer (a misconfiguration), not a healthy miss - fail closed to fallback.
        let directory = self.fabric.provider_directory().ok_or_else(|| {
            SourceError::Unreachable(
                "fabric exposes no provider directory (discovery axis disabled)".to_string(),
            )
        })?;

        // Exact-key directory lookup, through the BOUND choke-point (TASK-100 AC#4): a
        // record whose own key is not the queried `content_key` is DROPPED, so a hostile
        // adapter cannot hand this direct caller holders of a key it did not name.
        let records = match peer_fabric::find_providers_bound(
            directory.as_ref(),
            &content_key,
            &self.discovery_budget,
        )
        .await
        {
            Lookup::Found(records) => records,
            // A healthy authoritative absence: fast, clean miss -> upstream fallback (S2).
            Lookup::Miss => {
                return Err(SourceError::Unreachable(format!(
                    "no provider holds {content_key} (directory miss)"
                )));
            }
            // Could-not-consult: NOT absence, but from the serving layer's view it is the
            // same fast fallback signal (never cached as a negative here).
            Lookup::Unavailable(why) => {
                return Err(SourceError::Unreachable(format!(
                    "directory unavailable for {content_key}: {why}"
                )));
            }
        };

        // Observability (fail-verbosely): the DHT answered with >= 1 record, so log the
        // DISCOVERY outcome BEFORE any fetch attempt - discovery is thus observable
        // independent of whether a subsequent fetch succeeds or misses (the miss diagnostic
        // below only fires on failure, so a clean success would otherwise leave discovery
        // unobserved). `records` is non-empty here (a `Found` with an empty vec never occurs).
        eprintln!(
            "daemon: discovered {} provider record(s) for {content_key} via kad",
            records.len()
        );

        // Try each discovered provider's offers in order, returning the first gate-1
        // verified bytes. A per-offer failure (holder absent, integrity gate fired, dial
        // failed) is recorded and the next offer/record is tried - fail closed, try next.
        let mut last_failure: Option<String> = None;
        for record in &records {
            let content = &record.content;

            // WHERE this provider is dialable is resolved INSIDE the fabric, by the transfer
            // itself: the transport resolves the provider's address before dialing, so this
            // layer needs NO injected dial address and the `DialInfo` never crosses the
            // `NodeLocator` seam into this serving layer. A provider whose address cannot be
            // resolved surfaces here as an ordinary per-offer `TransferError::Unavailable`.
            for offer in &record.offers {
                let tag = offer.tag();
                let Some(transfer) = self.fabric.transfer(tag) else {
                    // No backend registered for this offer's transport: skip it, do not
                    // crash (an unimplemented/foreign transport, e.g. a bittorrent offer in
                    // a libp2p-only build).
                    last_failure = Some(format!("no transfer backend for offer tag {tag}"));
                    continue;
                };
                match transfer
                    .fetch(content, offer, expected_size, &self.envelope)
                    .await
                {
                    // Gate 1 already passed inside the transfer; hand the bytes up.
                    Ok(bytes) => return Ok(ok_response(bytes)),
                    // A deliberate size abort PROPAGATES (never an upstream fallback): every
                    // offer addresses the same oversized content, so trying more is pointless
                    // and falling back would paper over a deliberate abort.
                    Err(TransferError::TooLarge { limit, streamed }) => {
                        return Err(SourceError::TooLarge {
                            limit,
                            declared: streamed,
                        });
                    }
                    // Any other per-offer failure: record it and try the next offer.
                    Err(err) => last_failure = Some(err.to_string()),
                }
            }
        }

        // No discovered provider yielded verified bytes: a clean miss the FallbackNarSource
        // turns into upstream fallback (S2). `last_failure` carries the specific cause.
        Err(SourceError::Unreachable(format!(
            "discovered {} provider record(s) for {content_key} but none yielded verified bytes \
             (unlocatable provider or offer failure): {}",
            records.len(),
            last_failure.unwrap_or_else(|| "no usable offer".to_string())
        )))
    }
}

/// A [`RawServeDecision`] that DYNAMICALLY probes the provider directory: the daemon will
/// serve `nar_hash`'s RAW nar IFF a provider is discoverable for it right now (TASK-164).
///
/// ## Why this exists (the correctness gap it closes)
///
/// A dynamic-discovery backend (the directory `find_providers`) has no static claim, so
/// without this a discovery HIT under a COMPRESSED (xz) upstream narinfo would serve RAW
/// bytes while the narinfo still declared `Compression: xz` -> a real Nix client rejects on
/// the `FileHash`/`Compression` gate. This answers the rewrite decision with the SAME probe
/// [`PeerFabricNarSource::resolve`] uses, so `serves-raw(h) <=> narinfo-rewritten-to-raw(h)`
/// holds by construction.
///
/// ## Fail-safe on ambiguity, fail-closed on a stale hit
///
/// A NarHash that is not a canonical p2p key, a fabric with no directory axis, and a
/// `Miss`/`Unavailable` all return `false`: the narinfo is served VERBATIM (compressed) and
/// its NAR request fetches the actual compressed bytes over HTTP - a safe non-regression,
/// never a raw narinfo the daemon cannot back. A found-then-vanished provider (TOCTOU)
/// leaves the rewrite-to-raw standing but the NAR fetch misses -> a fast clean fallback,
/// never wrong bytes.
pub struct PeerFabricRawServe {
    fabric: Arc<dyn PeerFabric>,
    /// The bound on the narinfo-time `find_providers` probe. Same budget the paired
    /// [`PeerFabricNarSource`] uses, so the decision and the fetch cannot drift.
    discovery_budget: DiscoveryBudget,
}

impl PeerFabricRawServe {
    /// A decision probing `fabric` under `discovery_budget`.
    pub fn new(fabric: Arc<dyn PeerFabric>, discovery_budget: DiscoveryBudget) -> Self {
        PeerFabricRawServe {
            fabric,
            discovery_budget,
        }
    }
}

#[async_trait]
impl RawServeDecision for PeerFabricRawServe {
    async fn will_serve_raw(&self, nar_hash: &str) -> bool {
        // Not a canonical NarHash -> cannot be a p2p key -> never rewrite to raw.
        let Ok(canonical) = NarHashKey::from_str(nar_hash) else {
            return false;
        };
        let content_key = ContentKey::derive_from_signed_nar_hash(canonical.as_bytes());
        // No directory axis: this fabric cannot answer, so do NOT rewrite (serve the
        // verbatim compressed narinfo, which the HTTP path can still back).
        let Some(directory) = self.fabric.provider_directory() else {
            return false;
        };
        // The SAME probe the paired PeerFabricNarSource fetch uses, through the BOUND
        // choke-point (AC#4): records for an un-asked key are dropped, so a hostile
        // adapter cannot make us rewrite-to-raw on holdings of a different key. Only an
        // authoritative, non-empty Found rewrites; a Miss/Unavailable leaves it verbatim.
        match peer_fabric::find_providers_bound(
            directory.as_ref(),
            &content_key,
            &self.discovery_budget,
        )
        .await
        {
            Lookup::Found(records) => !records.is_empty(),
            Lookup::Miss | Lookup::Unavailable(_) => false,
        }
    }
}

#[cfg(test)]
mod shipped_path_tests {
    //! TASK-232 AC#3 on the GENUINELY-SHIPPED decentralized path. `PeerFabricNarSource` is
    //! the production p2p NAR source; it consults the directory through
    //! [`peer_fabric::find_providers_bound`] (the bound choke-point, AC#3's direct-caller
    //! requirement), and the TYPED `Lookup::Miss` vs `Lookup::Unavailable` distinction that
    //! keeps a fault from becoming a false absence is proven load-bearing by peer-fabric's
    //! own `classify_lookup` / `KeyResolution` tests and rides in here.
    //!
    //! At THIS layer both a directory MISS and a directory FAULT deliberately fold to the
    //! same fast `SourceError::Unreachable` (S2 upstream fallback): a decentralized miss and
    //! a decentralized outage are both "p2p cannot serve it here". The property that MUST
    //! hold, and that this test bites, is the SAFE direction - a fault must never become a
    //! false SERVE or a hang, and is never cached as a negative (structural: this source
    //! holds no negative cache).

    use std::sync::Arc;

    use peer_fabric::{
        DiscoveryBudget, ExposureLedger, ExposureSurface, FakeFabric, FakeProviderDirectory,
        Lookup, NodeId, SafetyEnvelope, Unavailable,
    };

    use super::PeerFabricNarSource;
    use crate::claim::NarHashKey;
    use crate::source::{NarHash, NarKey, NarPathToken, NarSource, NarinfoTransport, SourceError};

    fn signed_key() -> NarKey {
        NarKey::SignedNarHash {
            hash: NarHash::new(NarHashKey::from_sha256_bytes([0x11; 32]).to_string()),
            upstream_hint: NarPathToken::new("nar/deadbeef.nar.xz"),
            transport: NarinfoTransport::default(),
        }
    }

    fn source_over(directory: FakeProviderDirectory) -> PeerFabricNarSource {
        let node = NodeId::from_bytes([0x01; 32]);
        let fabric = FakeFabric::upstream_only(node).with_provider_directory(Arc::new(directory));
        PeerFabricNarSource::new(
            Arc::new(fabric),
            DiscoveryBudget::default(),
            SafetyEnvelope::default(),
        )
    }

    fn fake_directory(result: Lookup<Vec<peer_fabric::ProviderRecord>>) -> FakeProviderDirectory {
        FakeProviderDirectory::new(
            result,
            Vec::new(),
            ExposureSurface::none(),
            Arc::new(ExposureLedger::new()),
        )
    }

    #[tokio::test]
    async fn a_directory_fault_folds_to_fallback_never_a_false_serve() {
        // A directory that FAULTS (Unavailable) must NOT be served as authoritative content
        // and must NOT hang: it folds to a fast Unreachable that the FallbackNarSource turns
        // into an upstream fetch. Crucially it is NEVER an Ok(bytes) (a false serve).
        let source = source_over(fake_directory(Lookup::Unavailable(
            Unavailable::BootstrapOutage,
        )));
        match source.resolve(&signed_key(), None).await {
            Err(SourceError::Unreachable(_)) => {}
            Ok(_) => panic!("a directory fault must NEVER become a false serve"),
            Err(other) => panic!("a directory fault must fold to a fast Unreachable, got {other}"),
        }
    }

    #[tokio::test]
    async fn a_directory_miss_folds_to_fallback_too() {
        // The deliberate collapse: a genuine decentralized MISS folds the same way, so the
        // fault case above is not distinguishable at THIS output BY DESIGN - the typed
        // distinction that matters lives in peer-fabric (classify_lookup) upstream of here,
        // and this source never caches either as a negative (no negative cache exists).
        let source = source_over(fake_directory(Lookup::Miss));
        assert!(
            matches!(
                source.resolve(&signed_key(), None).await,
                Err(SourceError::Unreachable(_))
            ),
            "a directory miss folds to a fast Unreachable (upstream fallback), never a serve"
        );
    }
}
