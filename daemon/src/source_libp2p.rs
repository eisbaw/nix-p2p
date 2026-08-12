//! [`Libp2pNarSource`] - a [`NarSource`] that resolves a NAR through a libp2p
//! [`PeerFabric`]: DISCOVER a provider via libp2p-kad, then FETCH the raw NAR from it,
//! gate-1 BLAKE3-verified, all URL-less and keyed on the signed content identity.
//!
//! ## Where this sits (TASK-160, the interim both-backends path)
//!
//! This is the functionality-first wiring that makes the daemon actually run a
//! decentralized content path, ahead of the clean daemon-core / two-binary split
//! (TASK-145/146). It is the libp2p sibling of [`crate::transport_fetch::TransportNarSource`]
//! (which drives the daemon's own iroh `Transport`/`Discovery`): both live behind the
//! FROZEN [`NarSource`] seam, so the serving layer is unchanged and the iroh path stays
//! intact (this is purely additive).
//!
//! It deliberately drives the `peer-fabric` seam types END TO END rather than adapting
//! them into the daemon's parallel `Claim`/`KnownTransport`/`Discovery` shapes. The two
//! type families are distinct (the daemon's `discovery::Discovery` yields a daemon
//! `Claim`; the fabric's [`ProviderDirectory`] yields a `peer_fabric::ProviderRecord`),
//! so bolting the fabric transfer into the daemon `TransportRegistry` would need a bridge
//! for every value crossing the seam. Talking to the fabric directly behind the ONE
//! `NarSource::resolve` method is the cleaner fit (option (b) in the task) and keeps the
//! fabric a swappable dependency (`Arc<dyn PeerFabric>`), not a hard-wired backend.
//!
//! ## The flow (matching the FROZEN recipe)
//!
//! ```text
//!   NarSource::resolve(NarKey::SignedNarHash{ hash })
//!     -> NarHashKey::try_from(hash)                 (canonical 32-byte sha256 NarHash)
//!     -> ContentKey::derive_from_signed_nar_hash    (FROZEN peer-fabric content.rs recipe)
//!     -> fabric.provider_directory().find_providers(ContentKey)   (libp2p-kad, NOT injected)
//!     -> pick a ProviderRecord: its content Blake3Digest + offers
//!     -> for each offer: fabric.transfer(offer.tag()).fetch(content, offer, size, envelope)
//!         (gate-1 BLAKE3 verify lives INSIDE the transfer; a lying holder fails closed)
//!     -> hand the raw NAR up; Nix re-verifies sig + sha256==NarHash (gate 2, the TCB)
//! ```
//!
//! ## The two gates (unchanged from the seam's contract)
//!
//!   1. Transport-integrity gate (BLAKE3) - owned by the [`NarTransfer`] impl: the bytes
//!      MUST hash to the record's `content` [`Blake3Digest`] or the fetch fails closed
//!      and the next offer/record is tried. This daemon does NOT re-implement it here;
//!      it trusts the trait contract and re-checks nothing the transfer already checked.
//!   2. Trust gate (sha256 == NarHash) - owned by NIX, downstream. The daemon stays
//!      OUTSIDE the TCB: wrong bytes that somehow slipped gate 1 yield a failed build +
//!      retry, never a poisoned store.
//!
//! ## Miss / fallback discipline (S2)
//!
//! A discovery [`Lookup::Miss`] or [`Lookup::Unavailable`], and an exhausted offer set,
//! all fold to a fast [`SourceError::Unreachable`] - the clean signal a
//! [`crate::discovery::FallbackNarSource`] turns into an upstream fetch, so an
//! un-discoverable NAR never hangs the build path. A deliberate size abort
//! ([`TransferError::TooLarge`]) is the ONE exception: it PROPAGATES as
//! [`SourceError::TooLarge`] (never papered over by upstream fallback), because every
//! offer addresses the same oversized content.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;
use http_body_util::{BodyExt, Full};

use peer_fabric::{ContentKey, DiscoveryBudget, Lookup, PeerFabric, SafetyEnvelope, TransferError};

use crate::claim::NarHashKey;
use crate::source::{NarKey, NarSource, SourceError, UpstreamResponse};

/// A [`NarSource`] backed by a libp2p [`PeerFabric`]: discover via kad, fetch over the
/// libp2p NAR transfer. Holds the fabric as `Arc<dyn PeerFabric>` (the seam, not the
/// concrete backend) plus the mechanism bounds the two consultations run under.
pub struct Libp2pNarSource {
    fabric: Arc<dyn PeerFabric>,
    /// The bound on a `find_providers` consultation (deadline + peer cap).
    discovery_budget: DiscoveryBudget,
    /// The fetch time envelope (dial / body-idle / total) handed to each transfer.
    envelope: SafetyEnvelope,
}

impl Libp2pNarSource {
    /// A source discovering + fetching through `fabric`, under the given bounds. The
    /// daemon (composition root / TASK-120) owns the numbers; this only enforces them.
    pub fn new(
        fabric: Arc<dyn PeerFabric>,
        discovery_budget: DiscoveryBudget,
        envelope: SafetyEnvelope,
    ) -> Self {
        Libp2pNarSource {
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
impl NarSource for Libp2pNarSource {
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
                    "a libp2p p2p source cannot resolve an UpstreamPath (no URL)".to_string(),
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

        // Discovery must come from the DHT: no directory axis means this fabric cannot
        // answer (a misconfiguration), not a healthy miss - fail closed to fallback.
        let directory = self.fabric.provider_directory().ok_or_else(|| {
            SourceError::Unreachable(
                "libp2p fabric exposes no provider directory (discovery axis disabled)".to_string(),
            )
        })?;

        // libp2p-kad exact-key lookup. The answer (signed ProviderRecord: content digest
        // + offers) is produced by Kademlia, NOT injected.
        let records = match directory
            .find_providers(&content_key, &self.discovery_budget)
            .await
        {
            Lookup::Found(records) => records,
            // A healthy authoritative absence: fast, clean miss -> upstream fallback (S2).
            Lookup::Miss => {
                return Err(SourceError::Unreachable(format!(
                    "no provider holds {content_key} (libp2p-kad miss)"
                )));
            }
            // Could-not-consult: NOT absence, but from the serving layer's view it is the
            // same fast fallback signal (never cached as a negative here - the daemon does
            // not cache discovery outcomes this cycle).
            Lookup::Unavailable(why) => {
                return Err(SourceError::Unreachable(format!(
                    "libp2p-kad directory unavailable for {content_key}: {why}"
                )));
            }
        };

        // Try each discovered provider's offers in order, returning the first gate-1
        // verified bytes. A per-offer failure (holder absent, integrity gate fired, dial
        // failed) is recorded and the next offer/record is tried - fail closed, try next.
        let mut last_failure: Option<String> = None;
        for record in &records {
            let content = &record.content;
            for offer in &record.offers {
                let tag = offer.tag();
                let Some(transfer) = self.fabric.transfer(tag) else {
                    // No backend registered for this offer's transport: skip it, do not
                    // crash (an unimplemented/foreign transport, e.g. a bittorrent offer
                    // in a libp2p-only build).
                    last_failure = Some(format!("no transfer backend for offer tag {tag}"));
                    continue;
                };
                match transfer
                    .fetch(content, offer, expected_size, &self.envelope)
                    .await
                {
                    // Gate 1 already passed inside the transfer; hand the bytes up.
                    Ok(bytes) => return Ok(ok_response(bytes)),
                    // A deliberate size abort PROPAGATES (never an upstream fallback):
                    // every offer addresses the same oversized content, so trying more is
                    // pointless and falling back would paper over a deliberate abort.
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

        // Every offer of every discovered provider was skipped or failed: a clean miss the
        // FallbackNarSource turns into upstream fallback (S2).
        Err(SourceError::Unreachable(format!(
            "discovered {} provider record(s) for {content_key} but no offer yielded verified bytes: {}",
            records.len(),
            last_failure.unwrap_or_else(|| "no usable offer".to_string())
        )))
    }
}
