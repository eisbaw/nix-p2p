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
//!     -> pick a ProviderRecord: its provider NodeId, content Blake3Digest + offers
//!     -> fabric.node_locator().locate(record.provider, PublicInfrastructure)   (kad
//!         peer-routing resolves WHERE the provider is dialable, THROUGH the DHT - no
//!         injected address; a Miss/Unavailable skips this record to upstream fallback)
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

use peer_fabric::{
    ContentKey, DiscoveryBudget, Lookup, PeerFabric, ResolutionPolicy, SafetyEnvelope,
    TransferError,
};

use std::str::FromStr;

use crate::claim::NarHashKey;
use crate::rewrite::RawServeDecision;
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

            // Resolve WHERE this provider is dialable THROUGH the DHT (kad peer-routing),
            // so the production path needs NO injected dial address (the TASK-159 shim is
            // gone). `locate` is the side-effecting consult: an iterative `get_closest_peers`
            // teaches THIS node's shared kad routing table the provider's address (which a
            // shared bootstrap learned via identify), so the request-response `fetch` below -
            // driven off the SAME swarm - dials the provider with nothing injected out of
            // band. A `Miss` (healthy query, no address known) or `Unavailable`
            // (could-not-consult / empty routing) means we cannot learn a dial address for
            // THIS provider right now: record it and try the next record, ultimately folding
            // to a clean upstream fallback (S2). A fabric with no locator axis
            // (`node_locator() == None`) proceeds unchanged - it must have its dial address
            // supplied another way (the optional `provider_addrs` override hint), so this is
            // a no-op for it rather than a hard skip.
            if let Some(locator) = self.fabric.node_locator() {
                match locator
                    .locate(&record.provider, &ResolutionPolicy::PublicInfrastructure)
                    .await
                {
                    // The routing table now knows an address for the provider; the fetch
                    // below can dial it. We do NOT feed the returned Multiaddr strings to the
                    // swarm explicitly (no `add_address`): they arrived via the DHT as a
                    // side effect of this query, which is exactly the no-injection property.
                    Lookup::Found(_dial_info) => {}
                    Lookup::Miss => {
                        last_failure = Some(format!(
                            "node_locator: no DHT-known dial address for provider {} (kad miss)",
                            record.provider
                        ));
                        continue;
                    }
                    Lookup::Unavailable(why) => {
                        last_failure = Some(format!(
                            "node_locator: could not resolve provider {}: {why}",
                            record.provider
                        ));
                        continue;
                    }
                }
            }

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

        // No discovered provider yielded verified bytes: every record was either
        // UNLOCATABLE (node_locator Miss/Unavailable -> the record loop never reached its
        // offers) or had all offers skipped/failed. `last_failure` carries the specific
        // cause (a `node_locator: ...` prefix means the dial address could not be resolved,
        // distinct from an offer/transfer failure), so the summary stays truthful either
        // way. A clean miss the FallbackNarSource turns into upstream fallback (S2).
        Err(SourceError::Unreachable(format!(
            "discovered {} provider record(s) for {content_key} but none yielded verified bytes \
             (unlocatable provider or offer failure): {}",
            records.len(),
            last_failure.unwrap_or_else(|| "no usable offer".to_string())
        )))
    }
}

/// A [`RawServeDecision`] that DYNAMICALLY probes the libp2p provider directory:
/// the daemon will serve `nar_hash`'s RAW nar IFF a libp2p provider is discoverable
/// for it right now (TASK-164).
///
/// ## Why this exists (the correctness gap it closes)
///
/// The iroh path seeds its discovery AND its raw-serve allowlist from ONE static
/// `--p2p-claim` set, so a discovery HIT implies an allowlist HIT and the narinfo is
/// rewritten to raw (`Compression: none`, `FileHash`/`FileSize` = the raw NAR's
/// hash/size) before a Nix client validates the served bytes. libp2p discovery is
/// DYNAMIC (kad `find_providers`) with no static claim, so without this a libp2p HIT
/// under a COMPRESSED (xz) upstream narinfo would serve RAW bytes while the narinfo
/// still declared `Compression: xz` -> a real Nix client rejects on the
/// `FileHash`/`Compression` gate (TASK-162 finding).
///
/// This closes the gap by answering the rewrite decision with the SAME kad probe
/// [`Libp2pNarSource::resolve`] uses for the fetch. So the invariant
/// `libp2p-serves-raw(h) <=> narinfo-rewritten-to-raw(h)` holds by construction, the
/// dynamic mirror of the iroh path's static coupling.
///
/// ## Fail-safe on ambiguity, fail-closed on a stale hit
///
/// A NarHash that is not a canonical p2p key, a fabric with no directory axis, and a
/// kad `Miss`/`Unavailable` all return `false`: the narinfo is served VERBATIM
/// (compressed) and its NAR request fetches the actual compressed bytes over HTTP - a
/// safe non-regression, never a raw narinfo the daemon cannot back. If a provider is
/// found here but has VANISHED by the time the correlated NAR request runs (TOCTOU),
/// the rewrite-to-raw stands but the NAR fetch misses -> a fast clean 502 -> Nix falls
/// back to the next substituter (S2), exactly the documented dead-holder behaviour of
/// [`crate::rewrite::AllowlistRawServe`]. Never wrong bytes.
///
/// COST (documented, not hidden): this runs a kad `find_providers` at narinfo time, and
/// the correlated NAR request runs it AGAIN at fetch time - two lookups per served path.
/// Caching a discovery outcome across the two is deferred (TASK-163); correctness, not
/// probe economy, is what this type buys.
pub struct Libp2pRawServe {
    fabric: Arc<dyn PeerFabric>,
    /// The bound on the narinfo-time `find_providers` probe. The daemon (composition
    /// root) owns the numbers; the same budget the paired [`Libp2pNarSource`] uses.
    discovery_budget: DiscoveryBudget,
}

impl Libp2pRawServe {
    /// A decision probing `fabric` under `discovery_budget`.
    pub fn new(fabric: Arc<dyn PeerFabric>, discovery_budget: DiscoveryBudget) -> Self {
        Libp2pRawServe {
            fabric,
            discovery_budget,
        }
    }
}

#[async_trait]
impl RawServeDecision for Libp2pRawServe {
    async fn will_serve_raw(&self, nar_hash: &str) -> bool {
        // Not a canonical NarHash -> cannot be a libp2p key -> never rewrite to raw.
        let Ok(canonical) = NarHashKey::from_str(nar_hash) else {
            return false;
        };
        let content_key = ContentKey::derive_from_signed_nar_hash(canonical.as_bytes());
        // No directory axis: this fabric cannot answer, so do NOT rewrite (serve the
        // verbatim compressed narinfo, which the HTTP path can still back).
        let Some(directory) = self.fabric.provider_directory() else {
            return false;
        };
        // The SAME kad probe the paired Libp2pNarSource fetch uses. Only an
        // authoritative, non-empty Found rewrites to raw; a Miss (healthy absence) or
        // an Unavailable (could-not-consult) both leave the narinfo verbatim.
        match directory
            .find_providers(&content_key, &self.discovery_budget)
            .await
        {
            Lookup::Found(records) => !records.is_empty(),
            Lookup::Miss | Lookup::Unavailable(_) => false,
        }
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
    /// OPTIONAL provider dial-address override hint (TASK-169). The production path no
    /// longer needs this: `Libp2pNarSource::resolve` resolves a discovered provider's
    /// dial address THROUGH kad peer-routing (`Libp2pFabric::node_locator()`, TASK-159),
    /// so BOTH legs are decentralized (discover WHO via kad get_providers, resolve WHERE
    /// via kad peer-routing) with zero injection. Any entries here are still seeded into
    /// the swarm's address book as an explicit out-of-band hint (e.g. to reach a peer the
    /// DHT has not yet propagated, or in a test), but an EMPTY set is the normal
    /// production shape. Keep it empty to prove no-injection.
    pub provider_addrs: Vec<(PeerId, Multiaddr)>,
    /// The bound on each `find_providers` consultation.
    pub discovery_budget: DiscoveryBudget,
    /// The fetch time envelope handed to each transfer.
    pub envelope: SafetyEnvelope,
}

/// Build the PRODUCTION libp2p [`NarSource`] from `cfg`: start a [`Libp2pFabric`],
/// bind the listener, join the DHT through the configured bootstrap peers (kad
/// self-lookup), seed any OPTIONAL provider dial-address override hints (normally none -
/// the fetch path resolves dial addresses via kad peer-routing, TASK-169), and wrap the
/// running fabric in a [`Libp2pNarSource`].
///
/// Returns the `Arc<Libp2pFabric>`, the `NarSource`, AND its paired
/// [`Libp2pRawServe`] decision. Building all three from the ONE running fabric and the
/// ONE `discovery_budget` here is deliberate: it makes the narinfo-rewrite decision and
/// the NAR fetch impossible to drift apart (they share the exact discovery mechanism),
/// the libp2p analogue of the iroh path seeding discovery + allowlist from one claim
/// set (TASK-164). In production the binary keeps the source and the raw-serve; the
/// returned fabric handle lets a test poll discovery readiness before serving.
/// Connectivity setup is fail-fast: a listen or bootstrap-dial error is a loud startup
/// error, never a silent degrade to upstream-only.
pub async fn build_libp2p_nar_source(
    cfg: Libp2pSourceConfig,
) -> Result<
    (
        Arc<Libp2pFabric>,
        Arc<dyn NarSource>,
        Arc<dyn RawServeDecision>,
    ),
    String,
> {
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

    // OPTIONAL dial-address override hint (TASK-169): normally EMPTY. The production
    // fetch path resolves a discovered provider's dial address through kad peer-routing
    // (`Libp2pNarSource::resolve` -> `node_locator().locate()`), so no address needs
    // injecting here. Any entries are an explicit out-of-band override (e.g. reach a peer
    // the DHT has not yet propagated) - legitimate, but not required for a dial.
    for (peer, addr) in &cfg.provider_addrs {
        fabric.handle().add_address(*peer, addr.clone()).await;
    }

    // Both the fetch source and the raw-serve decision hold the SAME running fabric and
    // the SAME discovery budget, so a rewrite-to-raw decision and the fetch that backs it
    // consult one mechanism (DiscoveryBudget is Copy).
    let raw_serve: Arc<dyn RawServeDecision> = Arc::new(Libp2pRawServe::new(
        fabric.clone() as Arc<dyn PeerFabric>,
        cfg.discovery_budget,
    ));
    let source: Arc<dyn NarSource> = Arc::new(Libp2pNarSource::new(
        fabric.clone() as Arc<dyn PeerFabric>,
        cfg.discovery_budget,
        cfg.envelope,
    ));
    Ok((fabric, source, raw_serve))
}
