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

use fabric_libp2p::{Libp2pFabric, Libp2pNarSupplier, Multiaddr, NodeConfig, PeerId};

use ed25519_dalek::SigningKey;
use peer_fabric::{
    Axis, Blake3Digest, ContentKey, DiscoveryBudget, NodeId, PeerFabric, ProviderRecord,
    SafetyEnvelope, TransportOffer, TransportTag, require_axes, sign_provider_record,
};

use daemon_core::claim::NarHashKey;
use daemon_core::rewrite::RawServeDecision;
use daemon_core::source::NarSource;

// The generic PeerFabric-backed NarSource + raw-serve decision moved into `daemon-core`
// (TASK-146): they were ALREADY generic over `Arc<dyn PeerFabric>` - only their
// CONSTRUCTION named `fabric_libp2p`. Re-export them under the daemon's historical libp2p
// names so `daemon::Libp2pNarSource` / `daemon::Libp2pRawServe` and the flat re-exports keep
// resolving; this module now holds ONLY the libp2p-specific construction (start + join +
// wrap), which the daemon-libp2p binary shares via the same daemon-core source.
pub use daemon_core::peer_source::{
    PeerFabricNarSource as Libp2pNarSource, PeerFabricRawServe as Libp2pRawServe,
};

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
    let serving = supplier.is_some();
    let fabric = match supplier {
        Some(supplier) => Libp2pFabric::start_with_supplier(node_config, supplier),
        None => Libp2pFabric::start(node_config),
    }
    .map_err(|e| format!("libp2p fabric start failed: {e}"))?;
    let fabric = Arc::new(fabric);

    // Composition-root REQUIRED-axis assertion (TASK-144 AC#4, the "Unsupported-axis
    // dilemma" resolution): fail fast HERE, at construction, if the selected profile needs
    // an axis this fabric does not offer - never a silent runtime degrade (a fetch that
    // always falls back, a provider that announces then cannot serve). A libp2p CONSUMER
    // needs content discovery, node-address resolution and the fetch transport (registered
    // under the Iroh tag per the fabric-libp2p ADR); a PROVIDER additionally needs the
    // serve + announce axes. The single check lives in `peer_fabric::require_axes`, shared
    // with the iroh composition root so the two cannot drift on what "required" means.
    let mut required = vec![
        Axis::ProviderDirectory,
        Axis::NodeLocator,
        Axis::Transfer(TransportTag::Iroh),
    ];
    if serving {
        required.push(Axis::Server);
        required.push(Axis::Announcer);
    }
    require_axes(fabric.as_ref(), &required).map_err(|missing| {
        format!("libp2p fabric does not satisfy the required axes for this profile: {missing}")
    })?;

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
