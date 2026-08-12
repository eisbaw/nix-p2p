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
use fabric_libp2p::{Libp2pFabric, Multiaddr, NodeConfig, PeerId};
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

/// The composition-root numbers for the PRODUCTION libp2p `NarSource` (TASK-162).
///
/// The daemon binary parses its CLI flags (`--libp2p-bootstrap`, `--libp2p-listen`,
/// `--libp2p-scope`, `--libp2p-provider-addr`, `--libp2p-identity-seed`) into this
/// shape and hands it to [`build_libp2p_nar_source`]; the in-process production-path
/// integration test drives the SAME builder from an equivalent config, so the two
/// exercise one construction path (the CLI parse is unit-tested separately in the
/// binary). This is the interim both-backends wiring ahead of the clean daemon-core
/// split (TASK-145/146); the numbers are owned here (the composition root), not baked
/// into the seam types.
#[derive(Debug, Clone)]
pub struct Libp2pSourceConfig {
    /// 32-byte ed25519 identity seed for this node.
    pub identity_seed: [u8; 32],
    /// The kad/identify protocol network scope (`/nix-p2p/<scope>/kad/1.0.0`).
    pub network_scope: String,
    /// The multiaddr to listen on, if any (a pure dial-out consumer may omit it).
    pub listen: Option<Multiaddr>,
    /// kad bootstrap/entry peers (`PeerId` + dial `Multiaddr`). MUST be non-empty for
    /// discovery to work - an empty set is a consumer that can never find anyone.
    pub bootstrap: Vec<(PeerId, Multiaddr)>,
    /// TASK-159 basic-dial shim: provider byte-transfer dial addresses fed into the
    /// swarm out of band (`Libp2pFabric::node_locator()` is still `None`). The
    /// DISCOVERY leg stays a real kad lookup; this only supplies the dial.
    pub provider_addrs: Vec<(PeerId, Multiaddr)>,
    /// The bound on each `find_providers` consultation.
    pub discovery_budget: DiscoveryBudget,
    /// The fetch time envelope handed to each transfer.
    pub envelope: SafetyEnvelope,
}

/// Build the PRODUCTION libp2p [`NarSource`] from `cfg`: start a [`Libp2pFabric`],
/// bind the listener, join the DHT through the configured bootstrap peers (kad
/// self-lookup), teach the swarm the provider dial addresses (TASK-159 shim), and
/// wrap the running fabric in a [`Libp2pNarSource`].
///
/// Returns BOTH the `Arc<Libp2pFabric>` and the `NarSource`. In production the binary
/// keeps only the source (which itself holds an `Arc` clone of the fabric, so the
/// node stays alive); the returned fabric handle lets a test poll discovery readiness
/// before serving. Connectivity setup is fail-fast: a listen or bootstrap-dial error
/// is a loud startup error, never a silent degrade to upstream-only.
pub async fn build_libp2p_nar_source(
    cfg: Libp2pSourceConfig,
) -> Result<(Arc<Libp2pFabric>, Arc<dyn NarSource>), String> {
    let fabric = Libp2pFabric::start(NodeConfig {
        identity_seed: cfg.identity_seed,
        network_scope: cfg.network_scope,
    })
    .map_err(|e| format!("libp2p fabric start failed: {e}"))?;
    let fabric = Arc::new(fabric);

    if let Some(listen) = &cfg.listen {
        fabric
            .handle()
            .listen(listen.clone())
            .await
            .map_err(|e| format!("libp2p listen on {listen} failed: {e}"))?;
    }

    // Join the DHT through the bootstrap peers: add_address seeds kad's routing table
    // (so the subsequent bootstrap self-lookup has a peer to query) and dial opens the
    // connection. A bootstrap SET is plural for RESILIENCE - the invariant is "at least
    // one dial succeeds", not "all succeed": a single mistyped/down entry among several
    // must not brick startup. So dial errors are collected and only fatal when EVERY
    // bootstrap dial failed (then it is a loud startup error, not a silent no-discovery).
    if !cfg.bootstrap.is_empty() {
        let mut dial_errors = Vec::new();
        for (peer, addr) in &cfg.bootstrap {
            fabric.handle().add_address(*peer, addr.clone()).await;
            if let Err(e) = fabric.handle().dial(addr.clone()).await {
                dial_errors.push(format!("{peer} @ {addr}: {e}"));
            }
        }
        if dial_errors.len() == cfg.bootstrap.len() {
            return Err(format!(
                "libp2p: every bootstrap dial failed ({} peer(s)); cannot join the DHT: {}",
                cfg.bootstrap.len(),
                dial_errors.join("; ")
            ));
        }
        if !dial_errors.is_empty() {
            eprintln!(
                "daemon: libp2p {}/{} bootstrap dial(s) failed (continuing on the rest): {}",
                dial_errors.len(),
                cfg.bootstrap.len(),
                dial_errors.join("; ")
            );
        }
        // The kad self-lookup that populates the routing table. Not fatal on error:
        // add_address already seeded routing; a transient self-lookup error must not
        // brick startup. NOTE: this returns before discovery has CONVERGED - the daemon
        // starts serving immediately and early requests simply miss libp2p and fall back
        // to HTTP until the routing table fills (a benign cold-start window). A gate-able
        // readiness signal on the source seam is a follow-up (TASK-163).
        if let Err(e) = fabric.handle().bootstrap().await {
            eprintln!("daemon: libp2p kad bootstrap self-lookup returned: {e}");
        }
    }

    // TASK-159 basic-dial shim: teach the swarm each provider's byte-transfer dial
    // address out of band (discovery above is still a real kad lookup).
    for (peer, addr) in &cfg.provider_addrs {
        fabric.handle().add_address(*peer, addr.clone()).await;
    }

    let source: Arc<dyn NarSource> = Arc::new(Libp2pNarSource::new(
        fabric.clone() as Arc<dyn PeerFabric>,
        cfg.discovery_budget,
        cfg.envelope,
    ));
    Ok((fabric, source))
}
