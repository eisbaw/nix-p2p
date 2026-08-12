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
//!     -> for each offer: fabric.transfer(offer.tag()).fetch(content, offer, size, envelope)
//!         (the transfer resolves WHERE the provider is dialable THROUGH kad peer-routing
//!         INSIDE the fabric before dialing - TASK-169, no injected address, DialInfo never
//!         reaches this serving layer; gate-1 BLAKE3 verify also lives INSIDE the transfer,
//!         so a lying holder fails closed and the next offer/record is tried)
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
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use fabric_libp2p::{Libp2pFabric, Libp2pNarSupplier, Multiaddr, NodeConfig, PeerId};
use http::HeaderMap;
use http_body_util::{BodyExt, Full};

use ed25519_dalek::SigningKey;
use peer_fabric::{
    Blake3Digest, ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric, ProviderRecord,
    SafetyEnvelope, TransferError, TransportOffer, sign_provider_record,
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

            // WHERE this provider is dialable is resolved INSIDE the fabric, by the transfer
            // itself (TASK-169): the libp2p transport runs kad peer-routing and seeds the
            // DHT-resolved address before dialing, so the daemon needs NO injected dial
            // address and the `DialInfo` never crosses the `NodeLocator` seam into this
            // serving layer (peer-fabric/src/capabilities.rs). This layer therefore just
            // discovers WHO holds the NAR (above) and hands each offer to its transfer; a
            // provider whose address cannot be resolved surfaces here as an ordinary
            // per-offer `TransferError::Unavailable` (recorded in `last_failure`, next
            // record tried), folding to a clean upstream fallback (S2). The daemon does not
            // consult `node_locator()` directly - it holds only `Arc<dyn PeerFabric>` and
            // must not lean on a routing-table side effect to dial.
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

        // No discovered provider yielded verified bytes: every record's offers were all
        // skipped or failed (a transfer that could not resolve the provider's dial address
        // surfaces here as a per-offer `Unavailable`, an integrity gate fired, the holder
        // was absent, etc.). `last_failure` carries the specific cause, so the summary stays
        // truthful. A clean miss the FallbackNarSource turns into upstream fallback (S2).
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
    /// OPTIONAL address-book seed for the swarm's kad routing table (TASK-169). The
    /// production path does NOT need this: the libp2p transfer resolves a discovered
    /// provider's dial address THROUGH kad peer-routing INSIDE the fabric
    /// (`Libp2pFabric::node_locator()`, TASK-159) and dials off that resolution, so BOTH
    /// legs are decentralized (discover WHO via kad get_providers, resolve WHERE via kad
    /// peer-routing) with zero injection. Keep it EMPTY - that is the normal production
    /// shape and it proves no-injection.
    ///
    /// HONEST LIMIT (do not overclaim): since TASK-169 the transport DIALS only off a
    /// successful peer-routing resolution, so entries here do NOT independently enable a
    /// dial to a provider the DHT cannot resolve - `add_address` only seeds the local kad
    /// routing table (a bootstrap/entry hint), and kad `get_closest_peers` will not report
    /// a target's address unless a SHARED peer learned it via identify. A real static
    /// per-peer address book that the transfer honours for a dial (the `ExplicitPeersOnly`
    /// policy) is the locator's job and is TASK-168; until then these entries only help kad
    /// converge, they are not a per-provider dial override.
    pub provider_addrs: Vec<(PeerId, Multiaddr)>,
    /// The bound on each `find_providers` consultation.
    pub discovery_budget: DiscoveryBudget,
    /// The fetch time envelope handed to each transfer.
    pub envelope: SafetyEnvelope,
}

/// Build the PRODUCTION libp2p [`NarSource`] from `cfg`: start a [`Libp2pFabric`],
/// bind the listener, join the DHT through the configured bootstrap peers (kad
/// self-lookup), seed any OPTIONAL `provider_addrs` into the kad routing table (normally
/// none - the fetch path resolves dial addresses via kad peer-routing INSIDE the transfer,
/// TASK-169; these seeds only help kad converge, they are not a per-provider dial
/// override - see the field doc), and wrap the running fabric in a [`Libp2pNarSource`].
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
    let fabric = start_and_join_libp2p(&cfg, None).await?;
    Ok(wrap_consumer_source(fabric, &cfg))
}

/// The SERVING sibling of [`build_libp2p_nar_source`] (TASK-178): start the fabric WITH
/// a `supplier`, so the fabric exposes the serve axis (`server()` is `Some`) and can
/// answer inbound NAR requests. It runs the SAME connectivity join as the consumer
/// builder ([`start_and_join_libp2p`]), so a serving node is reachable in the DHT, and
/// returns the running fabric PLUS its own consumer source/raw-serve (a provider is also
/// a consumer - it can discover+fetch what it does not hold). The composition root then
/// installs the serve gate (`fabric.server().serve(budget)`) and announces the signed
/// provider records; that stays in the caller because the records are minted from the
/// caller's seed catalog (raw NAR + its NarHash), which the fabric does not know.
///
/// ONE fabric serves AND consumes on ONE identity/listen, so there is no second
/// same-identity swarm to collide with (the footgun a separate provider node would
/// create). The returned `Arc<Libp2pFabric>` is what the caller drives to serve/announce
/// and MUST keep alive for the process (the source holds its own clone too).
pub async fn build_libp2p_provider_source(
    cfg: Libp2pSourceConfig,
    supplier: Arc<dyn Libp2pNarSupplier>,
) -> Result<
    (
        Arc<Libp2pFabric>,
        Arc<dyn NarSource>,
        Arc<dyn RawServeDecision>,
    ),
    String,
> {
    let fabric = start_and_join_libp2p(&cfg, Some(supplier)).await?;

    // Unlike a CONSUMER (whose find_providers RETRIES until the routing table fills), a
    // provider's announce is a ONE-SHOT at startup and needs a non-empty kad routing table
    // to reach the k-closest nodes - an announce against an empty table fails
    // `Unavailable(InsufficientRouting)`. So WAIT (bounded) for the bootstrap join to
    // populate at least one routing peer before the caller announces. Fail-fast with a
    // clear message on timeout rather than letting the caller's announce fail obscurely.
    // Only relevant when a bootstrap set was configured (the join target).
    if !cfg.bootstrap.is_empty() {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if fabric.handle().routing_peers().await >= 1 {
                break;
            }
            if Instant::now() >= deadline {
                return Err(
                    "libp2p provider: kad routing table stayed empty after joining the \
                     bootstrap peer(s); cannot announce into an unreachable DHT"
                        .to_string(),
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    Ok(wrap_consumer_source(fabric, &cfg))
}

/// Build + SIGN a [`ProviderRecord`] for one seeded NAR (TASK-178), signed by the node's
/// ed25519 identity `seed`. SELF-SERVE v1: the record's `provider` is `NodeId(verifying
/// key of seed)`, which equals the fabric's own `node_id` (both derive from the same
/// seed) - the announcer REJECTS a record it did not sign, so this identity match is
/// load-bearing. The discovery [`ContentKey`] is derived from the Nix `NarHash`, so a
/// consumer that derived the SAME key from a narinfo discovers this provider; the
/// `content` [`Blake3Digest`] is the raw NAR's hash, the axis the transfer/serve keys on
/// and gate-1 BLAKE3-verifies. The lone offer carries the libp2p NAR transport (registered
/// under [`TransportOffer::Iroh`], per fabric-libp2p's ADR).
///
/// This is the SINGLE SOURCE OF TRUTH for a provider record's construction: the daemon
/// binary's `--libp2p-provider` path and the integration test both mint records here, so
/// the two cannot drift on the key-derivation / signing recipe.
pub fn sign_libp2p_provider_record(
    seed: [u8; 32],
    nar_hash: &NarHashKey,
    nar_bytes: &[u8],
    ttl_secs: u64,
    now: u64,
) -> ProviderRecord {
    let signing_key = SigningKey::from_bytes(&seed);
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    let key = ContentKey::derive_from_signed_nar_hash(nar_hash.as_bytes());
    let content = Blake3Digest::from_raw_nar(nar_bytes);
    let record = ProviderRecord {
        key,
        content,
        provider,
        offers: vec![TransportOffer::Iroh { node: provider }],
        sequence: 1,
        issued_at: now,
        expiry: now + ttl_secs,
        signature: [0u8; 64],
    };
    sign_provider_record(&signing_key, &record)
}

/// Wrap a running `fabric` in the consumer [`Libp2pNarSource`] + its paired
/// [`Libp2pRawServe`], both holding the SAME fabric and discovery budget so the
/// rewrite-to-raw decision and the fetch can never drift (TASK-164). Shared by the
/// consumer and provider builders (single source of truth for the wrapping).
fn wrap_consumer_source(
    fabric: Arc<Libp2pFabric>,
    cfg: &Libp2pSourceConfig,
) -> (
    Arc<Libp2pFabric>,
    Arc<dyn NarSource>,
    Arc<dyn RawServeDecision>,
) {
    let raw_serve: Arc<dyn RawServeDecision> = Arc::new(Libp2pRawServe::new(
        fabric.clone() as Arc<dyn PeerFabric>,
        cfg.discovery_budget,
    ));
    let source: Arc<dyn NarSource> = Arc::new(Libp2pNarSource::new(
        fabric.clone() as Arc<dyn PeerFabric>,
        cfg.discovery_budget,
        cfg.envelope,
    ));
    (fabric, source, raw_serve)
}

/// Start a [`Libp2pFabric`] for `cfg` and JOIN the DHT: bind the listener, dial the
/// bootstrap peers (fatal only if EVERY dial fails), run the kad self-lookup, and seed
/// any optional `provider_addrs` into the routing table. With `supplier` `Some` the
/// fabric ALSO serves (`start_with_supplier`); `None` is a pure consumer. This is the
/// ONE connectivity sequence both [`build_libp2p_nar_source`] and
/// [`build_libp2p_provider_source`] run - extracted so the join discipline (fail-fast on
/// a total bootstrap outage, tolerant of a partial one) has a single source of truth.
async fn start_and_join_libp2p(
    cfg: &Libp2pSourceConfig,
    supplier: Option<Arc<dyn Libp2pNarSupplier>>,
) -> Result<Arc<Libp2pFabric>, String> {
    let node_config = NodeConfig {
        identity_seed: cfg.identity_seed,
        network_scope: cfg.network_scope.clone(),
    };
    let fabric = match supplier {
        Some(supplier) => Libp2pFabric::start_with_supplier(node_config, supplier),
        None => Libp2pFabric::start(node_config),
    }
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

    // OPTIONAL kad routing-table seed (TASK-169): normally EMPTY. The production fetch
    // path resolves a discovered provider's dial address through kad peer-routing INSIDE
    // the transfer and dials off that resolution, so no address needs injecting here.
    // HONEST LIMIT (see the `provider_addrs` field doc): these `add_address` seeds only
    // populate the local kad routing table (a bootstrap/entry hint); since the transport
    // dials only off a successful resolution, they do NOT independently enable a dial to a
    // provider the DHT cannot resolve. A transfer-honoured static per-peer dial override
    // (`ExplicitPeersOnly`) is the locator's job, TASK-168.
    for (peer, addr) in &cfg.provider_addrs {
        fabric.handle().add_address(*peer, addr.clone()).await;
    }

    Ok(fabric)
}
