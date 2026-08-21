//! `daemon-libp2p` (lib) - the libp2p CONSTRUCTION over the stack-neutral `daemon-core`.
//!
//! The generic discover-then-fetch [`NarSource`] and dynamic raw-serve decision live in
//! `daemon-core` (`PeerFabricNarSource`/`PeerFabricRawServe`, generic over
//! `Arc<dyn PeerFabric>`); this lib holds only what needs `fabric_libp2p`: the
//! [`Libp2pSourceConfig`] the CLI parses into, and the builders that START a
//! [`Libp2pFabric`], JOIN the DHT (listen + bootstrap-dial + the composition-root
//! `require_axes` gate), and WRAP the running fabric in the daemon-core source. It re-exports
//! the daemon-core source types under their historical `Libp2p*` names.
//!
//! It is the single source of truth for the libp2p construction: BOTH the `daemon-libp2p`
//! BINARY (the clean primary, `daemon_core::run(Libp2pFabric::…)`) and the interim `daemon`
//! composite (which re-exports these) build the libp2p path through here, so they cannot
//! drift. The binary's dependency closure contains NO iroh (a build guard proves it); the
//! `daemon` composite additionally links `fabric-iroh` for its retained iroh path.
//!
//! ## The flow (matching the FROZEN recipe)
//!
//! ```text
//!   NarSource::resolve(NarKey::SignedNarHash{ hash })
//!     -> ContentKey::derive_from_signed_nar_hash    (FROZEN peer-fabric content.rs recipe)
//!     -> fabric.provider_directory().find_providers(ContentKey)   (libp2p-kad, NOT injected)
//!     -> for each offer: fabric.transfer(tag).fetch(content, offer, size, envelope)
//!         (dial address resolved via kad peer-routing INSIDE the fabric - TASK-169; gate-1
//!         BLAKE3 verify INSIDE the transfer, so a lying holder fails closed, next offer tried)
//!     -> hand the raw NAR up; Nix re-verifies sig + sha256==NarHash (gate 2, the TCB)
//! ```
//!
//! A discovery miss / exhausted offer set folds to a fast fallback to HTTP upstream (S2); a
//! deliberate size abort propagates (every offer addresses the same oversized content).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use fabric_libp2p::{
    ANNOUNCE_SEQ_FILENAME, ConnPath, DEFAULT_LISTEN_READY_TIMEOUT, Libp2pNarSupplier, Multiaddr,
    NodeConfig, PROVIDER_FLOOR_FILENAME, PeerId, SwarmHandle, relay_hints_from_circuit_addresses,
};
// `Libp2pFabric` is used in several places under its bare name; keep it a separate line so the
// status-facts wiring above can re-order without churn.
use fabric_libp2p::Libp2pFabric;

use ed25519_dalek::SigningKey;
use peer_fabric::{
    AdmitAllPublication, AnnounceBudget, AnnounceError, AvailabilityAnnouncer, Axis, Blake3Digest,
    ContentKey, DiscoveryBudget, IneligibleReason, NodeId, PeerFabric, ProviderRecord,
    PublicationEligibility, RefusePublication, RelayHints, SafetyEnvelope, TransportOffer,
    TransportTag, require_axes, sign_provider_record,
};

use daemon_core::claim::NarHashKey;
use daemon_core::rewrite::RawServeDecision;
use daemon_core::source::{NarHash, NarSource};
use daemon_core::{
    AvailabilityIndex, HoldAnswer, LearnOutcome, PeerDeriveLedger, PostFetchAnnounce,
    PublicNarAllowlist, PublicNarClaim, PublicationRejected, StoreHash, StorePath, TrustedNarKeys,
    derive_allowlist_mac_key,
};

mod store_probe;
pub use store_probe::Libp2pCatalogProbe;

/// The composition-root adapter (TASK-297) that lets the shipped libp2p serve path charge a
/// hostile peer's repeated cold `nix-store --dump` regenerates against the daemon's
/// [`PeerDeriveLedger`] (TASK-229's enforced per-peer + global amplification ledger), keyed by
/// the AUTHENTICATED libp2p [`PeerId`] the serve accept loop observed.
///
/// It bridges a layering gap: the charge point is `fabric_libp2p::ServeGate` (a crate that
/// deliberately does NOT depend on the daemon), and the enforcing ledger lives in `daemon_core`.
/// `fabric_libp2p` exposes the [`ServeDeriveAdmission`](fabric_libp2p::ServeDeriveAdmission) seam
/// keyed by `PeerId`; this composition-root type (which sees BOTH crates) implements it over the
/// real ledger.
///
/// KEYING: the ledger keys by [`daemon_core::NodeId`] (32 raw bytes), while the authenticated
/// serve identity is a libp2p [`PeerId`] (a multihash whose length/algorithm varies by key type).
/// We derive the ledger key as `BLAKE3(PeerId::to_bytes())` - a collision-resistant, therefore
/// injective-in-practice, per-authenticated-identity mapping. This is deliberately NOT a claim
/// that the key equals the peer's ed25519 `NodeId` (a bare `PeerId` does not always yield the raw
/// public key); it only needs to be a STABLE per-peer key so distinct authenticated peers get
/// distinct budgets and one peer can never spend another's (nor the global) allowance. The charge
/// is seeded by the DECLARED uncompressed-NAR size, the same unit the ledger enforces.
pub struct Libp2pServeDeriveAdmission {
    ledger: Arc<PeerDeriveLedger>,
}

impl Libp2pServeDeriveAdmission {
    /// Adapt `ledger` (constructed from the operator contract's `ResourceCaps::derive_budget()`)
    /// to the libp2p serve seam.
    pub fn new(ledger: Arc<PeerDeriveLedger>) -> Self {
        Self { ledger }
    }

    /// The stable per-authenticated-peer ledger key: `BLAKE3(PeerId::to_bytes())`. See the type
    /// docs for why this is a hash, not the ed25519 `NodeId`.
    fn ledger_key(peer: &PeerId) -> NodeId {
        NodeId::from_bytes(*Blake3Digest::from_raw_nar(&peer.to_bytes()).as_bytes())
    }
}

impl fabric_libp2p::ServeDeriveAdmission for Libp2pServeDeriveAdmission {
    fn admit_regenerate(&self, peer: &PeerId, nar_size: u64) -> bool {
        self.ledger
            .try_admit(&Self::ledger_key(peer), nar_size)
            .is_admitted()
    }
}

// TASK-284: the opt-in Mainline (BEP5) peer-address rendezvous bootstrap wiring. Its
// `*mainline*`/`*rendezvous*`-named functions feed the libp2p DIAL path only (never content
// discovery); `scripts/check-discovery-no-shortcut.py` scans this file structurally.
pub mod mainline_bootstrap;

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
    /// Additional listeners installed in the same shared startup transaction as [`Self::listen`].
    /// All listener registrations are issued before awaiting any readiness event and share one
    /// absolute timeout, so multiple relay reservations do not serialize their startup budgets.
    pub additional_listens: Vec<Multiaddr>,
    /// Addresses this node explicitly advertises as externally reachable. These are applied by
    /// the shared construction path for both binaries before any provider readiness token exists.
    pub external_addresses: Vec<Multiaddr>,
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
    /// PER-NODE durable state directory (TASK-185, AC#1). When `Some`, the fabric is started
    /// through [`Libp2pFabric::start_durable`] / `start_with_supplier_durable`, so the
    /// consumer's anti-rollback FLOOR and the provider's per-key announce SEQUENCE are
    /// persisted here and re-seeded on restart - the shipped daemon then genuinely runs in the
    /// restart-durable mode the README describes. When `None` the fabric is session-scoped
    /// (the historical non-durable behaviour), for a throwaway/ephemeral node.
    ///
    /// EACH NODE NEEDS ITS OWN DIRECTORY: the files are keyed by directory, not by identity,
    /// so two nodes sharing one `state_dir` corrupt each other's floor/sequence. A fail-loud
    /// advisory lock is the TASK-185 hardening follow-up.
    pub state_dir: Option<PathBuf>,
    /// Whether this node runs the circuit-v2 relay SERVER (TASK-207/208). Default `true`
    /// (the permissionless-swarm intent: any public node helps NAT'd peers). Set `false`
    /// for a node that must be kad-only - e.g. a dedicated bootstrap that offers NO
    /// reservation service, so it can never be an ALTERNATIVE relay path. Threads straight to
    /// [`NodeConfig::with_relay_server`]: the relay-client / autonat / dcutr behaviours stay
    /// intact, only the server (which accepts reservations + forwards circuits) is dropped.
    pub relay_server_enabled: bool,
    /// Whether this node runs Kademlia in SERVER mode (TASK-120 fix A). Threads straight to
    /// [`NodeConfig::with_kad_server`]. The operator contract sets it from the participation
    /// profile: a PROVIDER (lan-share/public-share) is a kad SERVER (stores + answers DHT
    /// queries for others - real DHT participation); a CONSUMER (consume-only) is a kad CLIENT
    /// (issues queries, answers none). An upstream-only node runs no participating swarm at all
    /// and never builds this config. Default `true` (server); a consumer sets `false`.
    pub kad_server: bool,
    /// Whether this node runs LAN mDNS peer-ADDRESS discovery (TASK-257). Threads straight to
    /// [`NodeConfig::with_mdns`]. Set from the default-OFF `--libp2p-mdns` flag by any
    /// swarm-participating profile; upstream-only never builds this config (it refuses the flag).
    /// mDNS supplies peer ADDRESSES into the kad bootstrap path only - never content discovery -
    /// and is TASK-120 axis-1 (local discovery) only. Default `false` (emits zero multicast).
    pub mdns_enabled: bool,
    /// Whether this node confines its egress + serving to LAN peers (TASK-280). Threads straight to
    /// [`NodeConfig::with_lan_confinement`]. Set `true` by the composition root ONLY for a
    /// no-allowlist `lan-share` node ([`PublicationPlan::Lan`]), whose public-isolation GUARANTEE it
    /// holds end-to-end: the [`fabric_libp2p`] dial VETO + `add_address` LAN filtering + NAR
    /// serve-provenance gate. `public-share` (allowlist-gated) and `consume-only` leave it `false`
    /// (unrestricted). Default `false`.
    pub lan_confinement: bool,
}

/// Proof that a provider was built through the shared listener configuration path. Fields are
/// private so callers cannot mint or alter the configured reservation set. Every initial batch
/// announce door requires this token and captures one live snapshot through it after content /
/// allowlist verification, immediately before signing the batch.
#[derive(Debug, Clone)]
pub struct ProviderRelayReadiness {
    provider: NodeId,
    requested: RelayHints,
}

/// Immutable inputs shared by every initial provider-record batch. Grouping the signing identity,
/// validity window, observation time, and announce budget keeps the four readiness-gated doors on
/// one data contract as their capabilities evolve.
#[derive(Debug, Clone, Copy)]
pub struct InitialAnnounceConfig<'a> {
    identity_seed: [u8; 32],
    ttl_secs: u64,
    now: u64,
    budget: &'a AnnounceBudget,
}

impl<'a> InitialAnnounceConfig<'a> {
    pub fn new(
        identity_seed: [u8; 32],
        ttl_secs: u64,
        now: u64,
        budget: &'a AnnounceBudget,
    ) -> Self {
        Self {
            identity_seed,
            ttl_secs,
            now,
            budget,
        }
    }
}

impl ProviderRelayReadiness {
    fn from_config(fabric: &Libp2pFabric, cfg: &Libp2pSourceConfig) -> Result<Self, String> {
        let listeners: Vec<Multiaddr> = cfg
            .listen
            .iter()
            .chain(cfg.additional_listens.iter())
            .cloned()
            .collect();
        let requested = relay_hints_from_circuit_addresses(fabric.node_id(), &listeners)
            .map_err(|error| format!("invalid configured libp2p circuit listener set: {error}"))?;
        Ok(Self {
            provider: fabric.node_id(),
            requested,
        })
    }

    async fn capture(&self, fabric: &Libp2pFabric) -> Result<RelayHints, String> {
        if fabric.node_id() != self.provider {
            return Err(format!(
                "provider relay-readiness token belongs to {}, not {}",
                self.provider,
                fabric.node_id()
            ));
        }
        fabric
            .wait_for_live_relay_hints(self.requested, DEFAULT_LISTEN_READY_TIMEOUT)
            .await
            .map_err(|error| {
                format!(
                    "relay reservation readiness failed before initial announce: {error}; \
                     refusing to announce configured/attempted relays as live"
                )
            })
    }
}

/// Build the PRODUCTION libp2p [`NarSource`] from `cfg`: start a [`Libp2pFabric`],
/// bind the listener, join the DHT through the configured bootstrap peers (kad
/// self-lookup), seed any OPTIONAL `provider_addrs` into the kad routing table (normally
/// none - the fetch path resolves dial addresses via kad peer-routing INSIDE the transfer,
/// TASK-169; these seeds only help kad converge, they are not a per-provider dial
/// override - see the field doc), and wrap the running fabric in a [`Libp2pNarSource`].
///
/// Install a stderr `tracing` subscriber when `RUST_LOG` is set, so the fabric's NAT-traversal
/// diagnostics (autonat reachability verdict, relay circuit-v2 reservation, dcutr hole-punch
/// outcome, plus provider dial-address resolution - all emitted at info/debug by `fabric-libp2p`)
/// are visible for diagnosing a "works in the harness, fails behind NAT" incident. Coarse level
/// mapping (no `env-filter` dependency): `RUST_LOG=debug|trace` -> DEBUG
/// (also shows the relay SERVER's per-circuit forwarding), anything else -> INFO. Unset
/// `RUST_LOG` installs no subscriber - the daemon stays quiet and its existing `println!` status
/// lines are unchanged, so no test or deployment behaviour shifts.
///
/// SINGLE SOURCE OF TRUTH: this is the one wiring, called by BOTH the thin `daemon-libp2p`
/// binary AND the interim `daemon` composite (which links this lib), so the composite cannot
/// silently swallow `RUST_LOG` while the thin binary honours it (the TASK-272 divergence). The
/// `try_init` is idempotent: a second call is a no-op, never a panic.
pub fn init_tracing() {
    if let Ok(v) = std::env::var("RUST_LOG") {
        let level = if v.eq_ignore_ascii_case("debug") || v.eq_ignore_ascii_case("trace") {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        };
        let _ = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_writer(std::io::stderr)
            .try_init();
    }
}

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
    // A pure consumer never announces, so its announcer authority is the fail-closed default.
    let fabric = start_and_join_libp2p(&cfg, None, Arc::new(RefusePublication)).await?;
    Ok(wrap_consumer_source(fabric, &cfg))
}

/// The SERVING sibling of [`build_libp2p_nar_source`] (TASK-178): start the fabric WITH
/// a `supplier`, so the fabric exposes the serve axis (`server()` is `Some`) and can
/// answer inbound NAR requests. It runs the SAME connectivity join as the consumer
/// builder ([`start_and_join_libp2p`]), so a serving node is reachable in the DHT, and
/// returns the running fabric PLUS its own consumer source/raw-serve (a provider is also
/// a consumer - it can discover+fetch what it does not hold) and a fourth
/// [`ProviderRelayReadiness`] token. All initial announce doors require that private-field token,
/// revalidate requested reservations, and capture one live relay-hint snapshot immediately before
/// signing their batch. The composition root installs the serve gate
/// (`fabric.server().serve(budget)`) and announces the signed provider records; that stays in the
/// caller because the records are minted from the caller's seed catalog (raw NAR + its NarHash),
/// which the fabric does not know.
///
/// ONE fabric serves AND consumes on ONE identity/listen, so there is no second
/// same-identity swarm to collide with (the footgun a separate provider node would
/// create). The returned `Arc<Libp2pFabric>` is what the caller drives to serve/announce
/// and MUST keep alive for the process (the source holds its own clone too).
pub async fn build_libp2p_provider_source(
    cfg: Libp2pSourceConfig,
    supplier: Arc<dyn Libp2pNarSupplier>,
    publication_eligibility: Arc<dyn PublicationEligibility>,
) -> Result<
    (
        Arc<Libp2pFabric>,
        Arc<dyn NarSource>,
        Arc<dyn RawServeDecision>,
        ProviderRelayReadiness,
    ),
    String,
> {
    let fabric = start_and_join_libp2p(&cfg, Some(supplier), publication_eligibility).await?;

    // Unlike a CONSUMER (whose find_providers RETRIES until the routing table fills), a
    // provider's announce is a ONE-SHOT at startup and needs a non-empty kad routing table
    // to reach the k-closest nodes - an announce against an empty table fails
    // `Unavailable(InsufficientRouting)`. So WAIT (bounded) for the bootstrap join to
    // populate at least one routing peer before the caller announces. Fail-fast with a
    // clear message on timeout rather than letting the caller's announce fail obscurely.
    // Relevant when a bootstrap set was configured (the join target) OR when mDNS is enabled
    // (TASK-257 F-4: a same-scope LAN neighbour is the zero-config join target). For mDNS the
    // window is a touch longer (link-local discovery + a dial handshake), and a timeout is NOT
    // fatal: a lone-genesis mDNS provider that has not yet seen a LAN peer proceeds to announce
    // under the BOUNDED in-daemon retry below (announce_seed_records), so the feature needs no
    // external supervisor restart.
    if !cfg.bootstrap.is_empty() || cfg.mdns_enabled {
        let window_secs = if cfg.bootstrap.is_empty() { 30 } else { 20 };
        let deadline = Instant::now() + Duration::from_secs(window_secs);
        loop {
            if fabric.handle().routing_peers().await >= 1 {
                break;
            }
            if Instant::now() >= deadline {
                if cfg.bootstrap.is_empty() {
                    // mDNS-only lone genesis: no same-scope LAN peer has appeared YET. Do NOT fail
                    // startup - the bounded announce retry re-attempts once mDNS brings a put-quorum
                    // peer. Warn and proceed.
                    tracing::warn!(
                        "libp2p provider: no same-scope mDNS LAN peer joined the routing table \
                         within the discovery window; announcing lone-genesis under a bounded \
                         retry (it will land once a same-scope LAN peer appears)"
                    );
                    break;
                }
                return Err(
                    "libp2p provider: kad routing table stayed empty after joining the \
                     bootstrap peer(s); cannot announce into an unreachable DHT"
                        .to_string(),
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    let readiness = ProviderRelayReadiness::from_config(&fabric, &cfg)?;
    let (fabric, source, raw_serve) = wrap_consumer_source(fabric, &cfg);
    Ok((fabric, source, raw_serve, readiness))
}

/// Build + SIGN a [`ProviderRecord`] for one seeded NAR (TASK-178), signed by the node's
/// ed25519 identity `seed`. SELF-SERVE v1: the record's `provider` is `NodeId(verifying
/// key of seed)`, which equals the fabric's own `node_id` (both derive from the same
/// seed) - the announcer REJECTS a record it did not sign, so this identity match is
/// load-bearing. The discovery [`ContentKey`] is derived from the Nix `NarHash`, so a
/// consumer that derived the SAME key from a narinfo discovers this provider; the
/// `content` [`Blake3Digest`] is the raw NAR's hash, the axis the transfer/serve keys on
/// and gate-1 BLAKE3-verifies. The lone offer carries the native libp2p tag and the
/// caller's canonical `relay_hints`, derived from the fabric's live listener set immediately
/// before this function is called.
///
/// This is the SINGLE SOURCE OF TRUTH for a provider record's construction: the daemon
/// binary's `--libp2p-provider` path and the integration test both mint records here, so
/// the two cannot drift on the key-derivation / signing recipe.
///
/// `sequence` is DURABLY ALLOCATED by the caller from the fabric's announcer
/// ([`Libp2pFabric::next_announce_sequence`]) - NOT a hardcoded `1` (TASK-185, AC#2). Because
/// the record is signed above the seam (the sequence is inside the signed bytes, and the
/// frozen wire/codec forbids the backend clamping it), the sequence must be chosen BEFORE
/// signing; the durable announcer is the monotonic source, so a restarted provider mints
/// `last + 1` and its record is strictly newer than every record it previously published.
/// The frozen record recipe is otherwise untouched: same `provider`/`content`/`offers`/expiry
/// derivation, only the sequence field now comes from durable state instead of the constant.
pub fn sign_libp2p_provider_record(
    seed: [u8; 32],
    nar_hash: &NarHashKey,
    nar_bytes: &[u8],
    relay_hints: RelayHints,
    ttl_secs: u64,
    now: u64,
    sequence: u64,
) -> ProviderRecord {
    // The `--libp2p-seed-nar` (Memory) path holds the raw NAR bytes, so it derives the content
    // digest FROM those bytes. The store-supply path (TASK-191) has no bytes at announce time;
    // it takes the VERIFIED digest straight from the availability index (see
    // [`sign_libp2p_store_record`]). Both funnel through the ONE record recipe below.
    sign_libp2p_record_for_content(
        seed,
        nar_hash,
        Blake3Digest::from_raw_nar(nar_bytes),
        relay_hints,
        ttl_secs,
        now,
        sequence,
    )
}

/// Build + SIGN a [`ProviderRecord`] for a store path this node serves on demand (TASK-191),
/// taking the raw-NAR `content` [`Blake3Digest`] DIRECTLY rather than re-hashing bytes it does
/// not hold. The `content` MUST be the availability index's VERIFIED
/// (`sha256(--dump) == nar_hash`, TASK-56) `Blake3Digest` for `nar_hash` - see
/// [`verify_store_provisions`], the store analogue of [`verify_provider_seeds`], which is the
/// only sanctioned source of a `(nar_hash, content)` provision. This is the store-supply
/// sign-site: it never mints a record from the operator's word, only from a verified binding.
pub fn sign_libp2p_store_record(
    seed: [u8; 32],
    nar_hash: &NarHashKey,
    content: Blake3Digest,
    relay_hints: RelayHints,
    ttl_secs: u64,
    now: u64,
    sequence: u64,
) -> ProviderRecord {
    sign_libp2p_record_for_content(
        seed,
        nar_hash,
        content,
        relay_hints,
        ttl_secs,
        now,
        sequence,
    )
}

/// The SINGLE record recipe both the seed (Memory) and store (dump-on-demand) announce paths
/// share: derive the discovery [`ContentKey`] from the Nix `nar_hash`, carry the raw-NAR
/// `content` digest the transfer/serve keys on and gate-1 BLAKE3-verifies, and self-serve under
/// this node's own identity. Keeping it in one place means the two paths cannot drift on the
/// key-derivation / signing / offer recipe.
fn sign_libp2p_record_for_content(
    seed: [u8; 32],
    nar_hash: &NarHashKey,
    content: Blake3Digest,
    relay_hints: RelayHints,
    ttl_secs: u64,
    now: u64,
    sequence: u64,
) -> ProviderRecord {
    let signing_key = SigningKey::from_bytes(&seed);
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    let key = ContentKey::derive_from_signed_nar_hash(nar_hash.as_bytes());
    let record = ProviderRecord {
        key,
        content,
        provider,
        offers: vec![TransportOffer::Libp2p {
            node: provider,
            relay_hints,
        }],
        sequence,
        issued_at: now,
        expiry: now + ttl_secs,
        signature: [0u8; 64],
    };
    sign_provider_record(&signing_key, &record)
}

/// Derive the discovery [`ContentKey`] for `nar_hash` exactly as
/// [`sign_libp2p_provider_record`] does, so the provider path can look up the durable
/// announce sequence for the record it is about to mint (TASK-185, AC#2). Kept here, next to
/// the record construction, so the two cannot drift on the derivation recipe.
/// Wall-clock UNIX seconds, the `now` an announced record's `issued_at`/`expiry` are stamped
/// from. Saturates to 0 before the epoch (an unreachable clock skew), never a float.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn provider_content_key(nar_hash: &NarHashKey) -> ContentKey {
    ContentKey::derive_from_signed_nar_hash(nar_hash.as_bytes())
}

/// A provider seed whose DECLARED Nix NarHash does not match its bytes: the operator
/// gave `--libp2p-seed-nar <declared>=/path/to/bytes.nar` where
/// `sha256(bytes) != declared`. Signing/announcing a [`ProviderRecord`] for `declared`
/// over those bytes would mint a FALSE CLAIM - a consumer discovers this provider by
/// `declared`, fetches, then rejects it at its OWN NarHash gate: a wasted dial that
/// pollutes honest offload accounting (the very thing TASK-56 forbids, here on the
/// path that actually ships). Refused at the announce SSOT BEFORE any record is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedNarHashMismatch {
    /// The NarHash the operator DECLARED for this seed (the discovery key a consumer
    /// would look this provider up by).
    pub declared: NarHashKey,
    /// The NarHash the seed BYTES actually hash to (`sha256` of the raw NAR).
    pub actual: NarHashKey,
}

impl std::fmt::Display for SeedNarHashMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "provider seed NarHash mismatch: declared {} but the seed bytes hash to {}; \
             refusing to sign or announce a false provider record",
            self.declared, self.actual
        )
    }
}

impl std::error::Error for SeedNarHashMismatch {}

/// Verify that every provider seed's bytes hash to its DECLARED NarHash BEFORE any
/// record is signed (TASK-56): `NarHashKey::from_raw_nar(bytes) == declared`, reusing
/// the EXACT `daemon-core` helper the availability index uses to close the same gap on
/// the index-backed path. This is the site where a provider CLAIM is minted, so it is
/// the architecturally correct place to assert the bytes match the identity the claim
/// will advertise - regardless of whether the supply source is `--libp2p-seed-nar` or a
/// future index-backed dump (TASK-158). The WHOLE batch is refused on the first
/// mismatch (fail-fast), so a mis-specified seed fails the provider loudly at startup
/// rather than announcing a false claim.
pub fn verify_provider_seeds(seeds: &[(NarHashKey, Vec<u8>)]) -> Result<(), SeedNarHashMismatch> {
    for (declared, bytes) in seeds {
        let actual = NarHashKey::from_raw_nar(bytes);
        if actual != *declared {
            return Err(SeedNarHashMismatch {
                declared: *declared,
                actual,
            });
        }
    }
    Ok(())
}

/// The file under a `state_dir` that durably anchors this node's libp2p IDENTITY seed
/// (TASK-185 GB1), the companion to the `announce-seq-v1.txt` / `provider-floor-v1.txt` the
/// fabric writes there. A STABLE identity is what makes the durable sequence floor matter at
/// all: the anti-rollback floor and the record's `provider` are keyed by `NodeId(seed)`, so a
/// fresh random seed on every restart would announce in a DIFFERENT namespace and permanently
/// orphan every pre-restart record (it could neither supersede nor withdraw them). Persisting
/// the seed next to the sequence floor makes a plain identical-argv restart with only
/// `--libp2p-state-dir` come back as the SAME node.
pub const IDENTITY_SEED_FILENAME: &str = "identity-seed-v1";

/// Generate a fresh 32-byte libp2p identity seed from `/dev/urandom`.
fn random_identity_seed() -> Result<[u8; 32], String> {
    use std::io::Read;
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|e| format!("generating libp2p identity seed from /dev/urandom: {e}"))?;
    Ok(seed)
}

/// Parse 64 lowercase-hex chars into a 32-byte seed (the `--libp2p-identity-seed` wire form).
fn parse_seed_hex(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!(
            "expected 64 hex chars (32 bytes), got {}",
            hex.len()
        ));
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|e| format!("bad hex at byte {i}: {e}"))?;
    }
    Ok(seed)
}

/// Load the seed persisted at `path`, or `None` if the file does not exist. A file that
/// exists but is MALFORMED is a hard error, NOT a silent regenerate: regenerating a different
/// random identity here would orphan this state dir's anti-rollback floor (the exact GB1
/// hazard), so we refuse and make the operator fix or remove the file.
fn load_identity_seed(path: &Path) -> Result<Option<[u8; 32]>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_seed_hex(text.trim()).map(Some).map_err(|e| {
            format!(
                "the persisted libp2p identity seed {} is malformed ({e}); refusing to start \
                 with a DIFFERENT random identity that would orphan this state dir's \
                 anti-rollback floor - fix or remove the file",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "reading persisted libp2p identity seed {}: {e}",
            path.display()
        )),
    }
}

/// Persist `seed` to `path` as 64 lowercase-hex chars, mode 0600, with the SAME atomic +
/// fsync discipline the sequence floor uses (write a sibling temp, fsync it, rename, fsync the
/// parent directory) so a crash right after first announce cannot leave a torn or lost
/// identity file.
fn save_identity_seed(path: &Path, seed: &[u8; 32]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent();
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating libp2p state dir {}: {e}", parent.display()))?;
    }
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("creating identity-seed temp {}: {e}", tmp.display()))?;
        f.write_all(hex.as_bytes())
            .and_then(|()| f.write_all(b"\n"))
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("writing identity-seed temp {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("renaming identity-seed into place {}: {e}", path.display()))?;
    if let Some(parent) = parent {
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("fsync libp2p state dir {}: {e}", parent.display()))?;
    }
    Ok(())
}

/// The durable floor/sequence sidecars a fabric writes under a state dir - the pieces that,
/// if present while the identity file is ABSENT, mean the state dir is inconsistent (see
/// [`resolve_durable_identity_seed`]). Returns which of them exist under `dir`.
fn orphaned_floor_sidecars(dir: &Path) -> Vec<&'static str> {
    [ANNOUNCE_SEQ_FILENAME, PROVIDER_FLOOR_FILENAME]
        .into_iter()
        .filter(|name| dir.join(name).exists())
        .collect()
}

/// Resolve this node's 32-byte libp2p identity seed, anchoring it to `state_dir` when given
/// (TASK-185 GB1) so a plain identical-argv restart with only `--libp2p-state-dir` yields a
/// STABLE identity - and therefore a usable durable sequence floor (both are keyed to the
/// same directory). Precedence, fail-safe:
///   * No `state_dir`: `explicit` if given, else a fresh `/dev/urandom` seed - the historical
///     session-scoped behaviour (the caller warns that a provider here is non-durable).
///   * `state_dir`, no `explicit`: load the persisted seed if present, else generate one and
///     PERSIST it so the next restart reloads the SAME identity.
///   * `state_dir` AND `explicit`: the explicit seed WINS but must be CONSISTENT with any
///     persisted seed - a mismatch is a hard ERROR (fail-safe), because an explicit seed that
///     disagrees with the dir's identity would silently orphan that dir's floor. When nothing
///     is persisted yet, the explicit seed is persisted so later state-dir-only restarts match.
///
/// STATE-DIR CONSISTENCY (TASK-185 re-gate): the identity file is created EAGERLY (before any
/// floor/sequence file), so a floor/sequence sidecar present while the identity is ABSENT can
/// ONLY mean the identity was lost under partial corruption. Generating a fresh identity there
/// would silently REKEY this node and orphan the records the surviving floor is bound to - the
/// GB1 failure class, re-opened via partial loss. That direction is fail-closed here.
///
/// HONEST LIMIT (the symmetric direction is NOT cleanly detectable, and is deliberately NOT
/// special-cased here - TASK-189): the floor/sequence files are created LAZILY (a pure consumer
/// never writes an announce-seq file; a provider writes it only on its first announce), so
/// "identity present, floor absent" is INDISTINGUISHABLE from a legitimate first boot / pure
/// consumer / pre-first-announce provider. Fail-closing on it would break normal operation.
/// Fully closing that direction (and the whole partial-corruption space) needs a single atomic
/// durable-state file with an init marker, tracked as TASK-189.
pub fn resolve_durable_identity_seed(
    state_dir: Option<&Path>,
    explicit: Option<[u8; 32]>,
) -> Result<[u8; 32], String> {
    let Some(dir) = state_dir else {
        return match explicit {
            Some(seed) => Ok(seed),
            None => random_identity_seed(),
        };
    };
    let path = dir.join(IDENTITY_SEED_FILENAME);
    let persisted = load_identity_seed(&path)?;
    if persisted.is_none() {
        // Identity absent: refuse to (re)generate one while a durable floor it would NOT own
        // survives on disk. A false positive is impossible - the identity is written before any
        // floor, so a floor without an identity is always loss, never a legitimate first boot.
        let orphaned = orphaned_floor_sidecars(dir);
        if !orphaned.is_empty() {
            return Err(format!(
                "libp2p state dir {} is INCONSISTENT: durable floor/sequence file(s) {orphaned:?} \
                 exist but the identity file {IDENTITY_SEED_FILENAME} is missing. Regenerating an \
                 identity would silently rekey this node and orphan its existing records. Refusing \
                 to start: restore {IDENTITY_SEED_FILENAME}, or wipe the state dir to start fresh.",
                dir.display()
            ));
        }
    }
    match (explicit, persisted) {
        (Some(seed), Some(disk)) if seed != disk => Err(format!(
            "--libp2p-identity-seed disagrees with the identity already persisted in {}; \
             refusing to start (an explicit seed that differs from the state dir's identity \
             would orphan its anti-rollback floor). Remove the flag to use the persisted \
             identity, or point --libp2p-state-dir at a fresh directory.",
            path.display()
        )),
        (Some(seed), Some(_consistent)) => Ok(seed),
        (Some(seed), None) => {
            save_identity_seed(&path, &seed)?;
            Ok(seed)
        }
        (None, Some(disk)) => Ok(disk),
        (None, None) => {
            let seed = random_identity_seed()?;
            save_identity_seed(&path, &seed)?;
            Ok(seed)
        }
    }
}

/// Announce a signed provider record for each `(nar_hash, nar_bytes)` seed through `fabric`,
/// DURABLY allocating each record's sequence (TASK-185 AC#2) from the fabric's announcer floor,
/// signing with `identity_seed` (self-serve: must be the fabric's own identity), and
/// publishing under `budget`. Returns the announced records (index-aligned with `seeds`) so a
/// caller can log their keys/sequences.
///
/// This is THE shipped provider announce path (SSOT): BOTH thin binaries' `--libp2p-provider`
/// install AND the TASK-185 restart-durability integration test call this exact function, so a
/// mutation here (e.g. a hardcoded `sequence`) is caught by the test rather than hiding in a
/// binary `fn main` no test exercises.
///
/// It is a PRIVATE / LAN announce (requires a [`LanShare`] witness): the operator-named seed bytes
/// are content-verified (TASK-56) but NOT publication-authorized. Announcing them to a gated PUBLIC
/// DHT must go through the allowlist door (TASK-102/103); the shipped modes assert `LanShare` only
/// after the bootstrap guard refuses a bootstrapped announce without a configured allowlist.
pub async fn announce_provider_seeds(
    fabric: &Libp2pFabric,
    readiness: &ProviderRelayReadiness,
    config: InitialAnnounceConfig<'_>,
    seeds: &[(NarHashKey, Vec<u8>)],
    _lan: LanShare,
) -> Result<Vec<ProviderRecord>, String> {
    // LAN door (AC#3): the witness is minted via an EXPLICIT AdmitAllPublication - NOT
    // allowlist-gated. On a PUBLIC-reachable node the fabric's OWN authority (allowlist or
    // RefusePublication) still refuses at the adapter, so this permissive witness does not open a
    // bypass; on a no-allowlist LAN-witnessed node the fabric's AdmitAll authority admits.
    announce_seed_records(fabric, readiness, config, seeds, &AdmitAllPublication).await
}

/// The shared raw-seed announce loop: TASK-56-verify every seed, then per key
/// durably-allocate the sequence, sign, and announce. PRIVATE to this module - BOTH the
/// substrate-neutral LAN door ([`announce_provider_seeds`]) and the allowlist-gated PUBLIC
/// door ([`announce_public_seeds`]) funnel through it, so the verify-then-sign SSOT (the
/// site where a provider CLAIM is minted) is single-sourced and a public seed announce
/// signs the exact same record a LAN one would.
/// The BOUNDED total window (INTEGER seconds) for retrying a lone-genesis provider's announce
/// while a same-scope LAN peer joins the routing table via mDNS (TASK-257 F-4). Finite, so a
/// genuinely-alone provider fails with a clear error rather than hanging; long enough to absorb
/// link-local discovery + a dial handshake. No float enters the bound.
const ANNOUNCE_QUORUM_RETRY_WINDOW_SECS: u64 = 30;

async fn announce_seed_records(
    fabric: &Libp2pFabric,
    readiness: &ProviderRelayReadiness,
    config: InitialAnnounceConfig<'_>,
    seeds: &[(NarHashKey, Vec<u8>)],
    witness_authority: &dyn PublicationEligibility,
) -> Result<Vec<ProviderRecord>, String> {
    // TASK-56: verify every seed's bytes hash to its declared NarHash BEFORE signing or
    // announcing ANY record. This is the shipped SSOT where the provider CLAIM is minted
    // (both thin binaries and the composite daemon call this exact loop), so a
    // mis-specified `--libp2p-seed-nar <X>=/path/to/Y.nar` is refused here instead of
    // advertising a false claim. Refusing the whole batch up front means no partial
    // announce leaves a false record behind a later mismatch.
    verify_provider_seeds(seeds).map_err(|e| e.to_string())?;
    let announcer = fabric
        .announcer()
        .ok_or_else(|| "internal: libp2p provider fabric exposes no announcer".to_string())?;
    // Capture exactly once, after the all-or-nothing content verification and immediately before
    // the initial signing loop. Every record in this batch therefore states the same verified
    // startup route set, including an empty batch (which still crosses the readiness barrier).
    let relay_hints = readiness.capture(fabric).await?;
    let mut records = Vec::with_capacity(seeds.len());
    for (nar_hash, bytes) in seeds {
        // INITIAL announce is all-or-nothing (fail-fast): a `?` on the first failure. The periodic
        // RE-SIGN path deliberately does NOT reuse this batch loop - it isolates per seed (HIGH-2)
        // so one persistently-failing seed cannot starve the others of their refresh.
        records.push(
            announce_one_verified_seed(
                fabric,
                &**announcer,
                relay_hints,
                &config,
                nar_hash,
                bytes,
                witness_authority,
            )
            .await?,
        );
    }
    Ok(records)
}

/// Allocate the durable sequence, sign, mint the eligibility witness, and announce ONE
/// already-content-verified seed - the shared per-seed body of both the INITIAL announce
/// ([`announce_seed_records`], all-or-nothing) and the periodic RE-SIGN
/// ([`resign_seed_records_once`], per-seed isolated). Keeping it in one place means the two paths
/// cannot drift on the allocate -> sign -> witness -> announce recipe or the bounded put-quorum retry.
///
/// The caller MUST have TASK-56-verified `bytes` against `nar_hash` first (this does not re-verify).
async fn announce_one_verified_seed(
    fabric: &Libp2pFabric,
    announcer: &dyn AvailabilityAnnouncer,
    relay_hints: RelayHints,
    config: &InitialAnnounceConfig<'_>,
    nar_hash: &NarHashKey,
    bytes: &[u8],
    witness_authority: &dyn PublicationEligibility,
) -> Result<ProviderRecord, String> {
    // Allocate the durable sequence, then sign, then announce - in that order, per key
    // (the allocation is a non-reserving read finalised by announce's save-before-publish).
    let sequence = fabric.next_announce_sequence(&provider_content_key(nar_hash));
    let record = sign_libp2p_provider_record(
        config.identity_seed,
        nar_hash,
        bytes,
        relay_hints,
        config.ttl_secs,
        config.now,
        sequence,
    );
    // TASK-231 (AC#1): mint the eligibility witness for THIS path's authority (AdmitAll for
    // the LAN door, the allowlist for the public door), then hand it to `announce`. The
    // announcer ALSO re-checks with its own per-fabric authority, so a public node still
    // refuses an unallowlisted record even if this witness is permissive.
    let witness = witness_authority.authorize(record.clone()).map_err(|e| {
        format!("publication eligibility refused libp2p seed record for {nar_hash}: {e}")
    })?;
    // TASK-257 F-4: a lone GENESIS provider (zero-bootstrap / mDNS) can lose the startup
    // put-quorum race - its first announce fails `Unreachable` because no same-scope peer is in
    // the routing table YET. Retry within a BOUNDED integer window, WAITING for a routing peer
    // to appear (via mDNS) between attempts, so the zero-bootstrap feature does not depend on an
    // external supervisor restart. Only `Unreachable` (no-quorum) is retried; a record-level
    // fault (Rejected/Ineligible/Persist) or a budget DeadlineExceeded returns immediately (a
    // retry cannot help and must not mask it). Each attempt still respects the caller's announce
    // budget - the retry adds a bounded WAIT, never an unbounded or un-budgeted publish.
    let retry_deadline = Instant::now() + Duration::from_secs(ANNOUNCE_QUORUM_RETRY_WINDOW_SECS);
    loop {
        match announcer.announce(&witness, config.budget).await {
            Ok(_receipt) => break,
            Err(AnnounceError::Unreachable(why)) => {
                if Instant::now() >= retry_deadline {
                    return Err(format!(
                        "announcing libp2p provider record for {nar_hash}: publication \
                         substrate unreachable after a bounded retry: {why}"
                    ));
                }
                // Wait (bounded) for a routing peer to appear, then retry the announce.
                while fabric.handle().routing_peers().await == 0 && Instant::now() < retry_deadline
                {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
            Err(e) => {
                return Err(format!(
                    "announcing libp2p provider record for {nar_hash}: {e}"
                ));
            }
        }
    }
    Ok(record)
}

/// One VERIFIED store-supply provision: a `nar_hash` this node will announce, the availability
/// index's VERIFIED raw-NAR [`Blake3Digest`] for it, and its declared (uncompressed) `NarSize`.
///
/// It is a CAPABILITY, not a plain record: its fields are private and it has NO public
/// constructor, so the ONLY way to obtain one is [`verify_store_provisions`], which mints it
/// only after the availability index's TASK-56 `sha256(--dump) == nar_hash` check passed.
/// [`announce_store_provisions`] consumes `&[StoreProvision]`, so - by the type system - the
/// SHIPPED store-announce path can never announce a record for a store path that was not
/// verification-gated. This is the store analogue of the
/// `verify_provider_seeds`-before-`announce_provider_seeds` discipline, made gated-by-construction
/// on the shipped path rather than merely conventional. NOTE (not absolute): the lower-level
/// [`sign_libp2p_store_record`] takes a raw caller-supplied digest and is NOT itself
/// `StoreProvision`-gated - a direct library caller could sign an unverified record (a footgun no
/// shipped call site uses). Generic record-signing makes library-wide prevention impossible; the
/// guarantee is that the `--libp2p-provide-store` announce path is type-gated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreProvision {
    nar_hash: NarHashKey,
    content: Blake3Digest,
    declared_size: u64,
}

impl StoreProvision {
    /// The Nix NarHash the store path was registered under (the discovery key a consumer looks
    /// this provider up by).
    pub fn nar_hash(&self) -> &NarHashKey {
        &self.nar_hash
    }

    /// The raw-NAR `BLAKE3(RawNarV1)` the index VERIFIED this path dumps to (TASK-56) - the
    /// `content` the announced record advertises and the serve path gate-1 BLAKE3-verifies.
    pub fn content(&self) -> Blake3Digest {
        self.content
    }

    /// The declared UNCOMPRESSED NAR size (the index's persisted `NarSize`, NOT a compressed
    /// FileSize), learned WITHOUT re-dumping - the admission size a serve budget checks. A
    /// caller refuses to announce a provision over its per-NAR serve bound with this, so it does
    /// not publish a claim it would then decline (the store analogue of the seed-size guard).
    pub fn declared_size(&self) -> u64 {
        self.declared_size
    }
}

/// The STORE analogue of [`verify_provider_seeds`] (AC#2, TASK-191): gate the store-supply
/// announce on the TASK-56 verification, deriving each provision's advertised content FROM the
/// availability index's verified binding rather than the operator's word.
///
/// For each `nar_hash`, [`AvailabilityIndex::hold`] runs the TASK-56 index-side check - dump the
/// store path, assert `sha256(--dump) == nar_hash`, QUARANTINE a mismatch - and, on success,
/// publishes the reverse-map record into the supply catalog (so the [`Libp2pCatalogProbe`]-backed
/// [`fabric_libp2p::CatalogNarSupplier`] can then serve it) and returns the VERIFIED
/// `Blake3Digest`. The whole batch is refused (fail-fast, BEFORE any record is signed or
/// announced) if ANY key:
///   * QUARANTINED - the store path dumps to a different NarHash (a mis-registration); or
///   * `Absent` - the store path is not materialised (never registered here, or GC'd); or
///   * errors in the dump/persist.
///
/// So a store path the index quarantined or never verified is NEVER announced, and there is no
/// parallel unverified announce path: the ONLY way to obtain a [`StoreProvision`] is through this
/// gate. The returned provisions carry the verified digest, which [`sign_libp2p_store_record`]
/// advertises as the record `content`.
///
/// BLOCKING NOTE: `hold` shells out to `nix-store --dump` under a per-entry lock (a blocking
/// dump). This runs at provider STARTUP, once per provided path, before the serve loop begins,
/// so the brief block is acceptable; a large provided set on an async runtime should drive this
/// via `spawn_blocking` (a follow-up, not a correctness gap).
pub fn verify_store_provisions(
    index: &AvailabilityIndex,
    nar_hashes: &[NarHashKey],
) -> Result<Vec<StoreProvision>, String> {
    let catalog = index.supply_catalog();
    let mut provisions = Vec::with_capacity(nar_hashes.len());
    for nar_hash in nar_hashes {
        match index.hold(nar_hash).map_err(|e| {
            format!(
                "verifying store provision {nar_hash} against the availability index: {e}; \
                 refusing to announce a store path the index has not verified"
            )
        })? {
            HoldAnswer::Have { blake3, .. } => {
                // `hold` just PUBLISHED the reverse-map record (verified digest -> store path)
                // into the supply catalog, so its declared NarSize is now readable here without
                // a re-dump. Its absence would mean the record was retired between hold and now
                // (a concurrent unregister) - fail loud rather than announce a size we cannot
                // confirm.
                let declared_size = catalog
                    .probe_record(&blake3)
                    .map(|r| r.declared_size)
                    .ok_or_else(|| {
                        format!(
                            "store provision {nar_hash} verified to {blake3} but its supply record \
                         vanished before its size could be read; refusing to announce"
                        )
                    })?;
                provisions.push(StoreProvision {
                    nar_hash: *nar_hash,
                    content: blake3,
                    declared_size,
                });
            }
            HoldAnswer::Absent => {
                return Err(format!(
                    "store provision {nar_hash} is not held by the availability index (the store \
                     path is unregistered or no longer materialised); refusing to announce a \
                     claim this node cannot serve"
                ));
            }
        }
    }
    Ok(provisions)
}

/// A WITNESS that an announce targets a PRIVATE / LAN / operator-assembled substrate, NOT a
/// gated PUBLIC DHT. [`announce_provider_seeds`] and [`announce_store_provisions`] require one, so
/// a call site must EXPLICITLY declare "this is a private announce" - it can never be confused
/// with the PUBLIC door, which instead consumes an allowlist-minted [`ApprovedPublicProvision`].
///
/// Publicness is a property of the SUBSTRATE (does this DHT reach strangers?), which the LIBRARY
/// cannot know; the composition root asserts it. The two guarantees are ORTHOGONAL: the private
/// loop still content-verifies every provision (TASK-56), so no bad store path is ever published;
/// what it does NOT assert is publication AUTHORIZATION (the allowlist). The shipped provider modes
/// construct this only AFTER refusing any bootstrapped (potentially public) announce without a
/// configured allowlist (the TASK-102 bootstrap guard; see `daemon-libp2p::main`/`daemon::main`).
#[derive(Debug, Clone, Copy)]
pub struct LanShare(());

impl LanShare {
    /// Assert this announce targets a private / LAN / operator-assembled substrate. The caller
    /// (the composition root) owns the assertion; the type only makes it EXPLICIT and greppable so
    /// a bare provision can never be handed to a PUBLIC announce API by accident.
    pub fn operator_assembled() -> Self {
        LanShare(())
    }
}

/// The FULL node-reachability configuration the LAN-isolation witness inspects (TASK-102 fix
/// cycle #2). Borrowed from the composition root's parsed CLI so the guard sees EVERY public-reach
/// signal the shipped config can express - not just the bootstrap vector, which was the residual
/// hole: a provider started with `--libp2p-provider-addr` (a dial-addr override) but EMPTY
/// `--libp2p-bootstrap` STILL joins the public kad DHT (the provider-addr enters the routing table),
/// yet a bootstrap-only guard minted a `LanShare` and announced UNGATED. `bootstrap-empty` is NOT
/// `isolated-LAN`; the witness must require POSITIVE proof the node is LAN-only (loopback,
/// link-local, or RFC1918/ULA private per TASK-276), never merely absence-of-bootstrap.
pub struct LanReachability<'a> {
    /// `--libp2p-bootstrap` peers. ANY entry means the node is joining a kad DHT it did not
    /// assemble; whatever that bootstrap peer bridges to (potentially the public DHT) receives the
    /// announced records. Presence alone is a public-reach signal, regardless of the peer's address.
    pub bootstrap: &'a [(PeerId, Multiaddr)],
    /// `--libp2p-provider-addr` seeds. ANY entry is `add_address`-ed into the kad routing table (a
    /// dial-addr override / entry hint), giving an otherwise-empty-bootstrap provider a peer to
    /// `start_providing`/`put_record` against - the EXACT residual that let an ungated announce
    /// reach a public substrate. Presence alone is a public-reach signal, like a bootstrap peer.
    pub provider_addrs: &'a [(PeerId, Multiaddr)],
    /// `--libp2p-listen` bind address, if any. A listen address that is NOT provably-private (a
    /// GLOBAL/routable public IP, a wildcard `0.0.0.0`/`::`, or a DNS name) makes the node reachable
    /// by strangers on the public internet, so it is a public-reach signal. A loopback, link-local,
    /// or RFC1918/ULA private listen is not globally routable (TASK-276), so it is not a public-reach
    /// signal on the LISTEN axis — it is reachable via that private address (same-segment LAN peers,
    /// plus any VPN/NAT/forward the operator routes to it). This is a LISTEN-address check only; it
    /// does not by itself confine same-scope Kademlia publication end-to-end (see TASK-280).
    pub listen: Option<&'a Multiaddr>,
}

// The IP-literal PROVABLY-PRIVATE classifier is single-sourced DOWN in `fabric-libp2p` (TASK-280)
// so the fabric-internal LAN guards (dial veto, serve provenance) and this crate's strict LISTEN
// grammar cannot drift on what "private" means. Re-exported here so `multiaddr_is_lan_only` and the
// existing callers/tests keep referring to `ip_is_provably_private` unqualified and the public
// `daemon_libp2p::ip_is_provably_private` API is preserved. See `fabric_libp2p::ip_is_provably_private`
// for the RFC1918/ULA definition and the exclusions (loopback/link-local classified separately,
// wildcard/CGNAT refused).
pub use fabric_libp2p::ip_is_provably_private;

/// The FROZEN `lan-share` protocol scope, re-exported from `fabric-libp2p` (single source of truth,
/// TASK-280 wire freeze) so the binaries and their tests name the constant, never a bare string.
pub use fabric_libp2p::LAN_SHARE_NETWORK_SCOPE;

/// The default PUBLIC network scope for every non-`lan-share` profile (`public-share`,
/// `consume-only`, `router`) when the operator gives no explicit `--libp2p-scope`. Matches
/// `fabric_libp2p::NodeConfig::new`'s default; changing it is out of TASK-280's scope.
pub const DEFAULT_NETWORK_SCOPE: &str = "v1";

/// Select the effective kad/identify/nar network scope for a node — the ONE decision both thin
/// binaries call, so a `lan-share` PROVIDER and a `lan-share` CONSUMER derive the SAME scope from
/// the SAME constant and cannot silently diverge (TASK-280 AC#5 consumer/provider parity):
///
///   * an explicit `--libp2p-scope <scope>` ALWAYS wins (the advanced escape hatch — e.g. to join a
///     deliberately-shared scope), for every profile;
///   * else a `lan-share` node (`lan_share == true`, i.e. [`PublicationPlan::Lan`]-equivalent) gets
///     [`LAN_SHARE_NETWORK_SCOPE`], namespacing its kad/identify/nar away from the public `v1` DHT so
///     a same-`v1` dual-homed bridge is cross-scope on all three protocols and cannot relay its
///     records to the public DHT;
///   * else the public [`DEFAULT_NETWORK_SCOPE`] (`v1`).
///
/// Taking a plain `bool` (not `SharingProfile`) keeps `daemon-libp2p` free of the operator-contract
/// type; each binary passes `profile == SharingProfile::LanShare`, which is exactly the condition
/// under which the provider decision mints [`PublicationPlan::Lan`].
pub fn effective_network_scope(explicit: Option<&str>, lan_share: bool) -> String {
    match explicit {
        Some(scope) => scope.to_string(),
        None if lan_share => LAN_SHARE_NETWORK_SCOPE.to_string(),
        None => DEFAULT_NETWORK_SCOPE.to_string(),
    }
}

/// The human-readable startup hint a consume-capable node should print when it is probably trying to
/// join a LAN `lan-share` pool but sits on the PUBLIC default scope (TASK-280 #3). A `lan-share`
/// cache runs on [`LAN_SHARE_NETWORK_SCOPE`]; a consumer that defaults to [`DEFAULT_NETWORK_SCOPE`]
/// silently finds nothing there. Named so the message is identical across both binaries.
pub const LAN_SHARE_SCOPE_HINT: &str = "on the public \"v1\" scope, but a LAN lan-share cache runs on \
     \"lan-share.v1\" — pass --libp2p-scope lan-share.v1 to join it as a consumer. (--profile \
     lan-share would make this a PROVIDER, not what a leech wants.)";

/// TASK-280 #3: whether to emit [`LAN_SHARE_SCOPE_HINT`] at startup. A node lands on the PUBLIC
/// default scope unless told otherwise, but a LAN `lan-share` cache is on `lan-share.v1`, so a
/// consume-capable node whose ONLY peer reach is a LAN-oriented bootstrap mechanism (mDNS, or a
/// configured bootstrap peer) is likely trying to join a LAN pool and will silently find nothing on
/// `v1`. Warn iff ALL hold:
///   * the EFFECTIVE scope is the public default (no explicit `--libp2p-scope`, not a lan-share node);
///   * the node CONSUMES (a leech/consumer — the party that silently misses the pool);
///   * its reach is LAN-bootstrap-only (`--libp2p-mdns` on, or a bootstrap peer present).
///
/// TRADEOFF (self-critical): a genuinely PUBLIC consumer on `v1` with a public bootstrap peer also
/// trips this, so the hint is ADVISORY (a one-line startup note, never fatal). mDNS is the
/// high-precision signal ("I am looking on the LAN"); a bootstrap peer alone is included per the
/// spec but is the weaker signal. Pure so the decision is unit-mutation-provable.
pub fn should_hint_lan_share_scope(
    effective_scope: &str,
    consume_capable: bool,
    mdns_enabled: bool,
    has_bootstrap_peer: bool,
) -> bool {
    effective_scope == DEFAULT_NETWORK_SCOPE
        && consume_capable
        && (mdns_enabled || has_bootstrap_peer)
}

/// TASK-282 (e): whether the LIBP2P leg participates as a CONSUMER — the `consume_capable` signal
/// [`should_hint_lan_share_scope`] must key on. It is a property of the LIBP2P flags ALONE (a leech /
/// bare mDNS / bootstrap consumer that is not itself a libp2p give-side provider), NOT the AGGREGATE
/// operator profile.
///
/// THE BUG this closes (codex TASK-282 (e)): the COMPOSITE `/bin/daemon` derives ONE aggregate
/// `contract.profile` from BOTH transports, so an iroh give-side (`--iroh-provider`) inflates the
/// aggregate to a PROVIDER mode (`LanShare`/`PublicShare`). A call site that reads
/// `matches!(contract.profile, ConsumeOnly)` then reads `false` and SUPPRESSES the scope hint —
/// even though the node's libp2p consumer leg (`--libp2p-leech` / bare `--libp2p-mdns`) sits on the
/// public `v1` scope and silently misses a `lan-share.v1` pool. Keying on the libp2p leg directly
/// restores the warning for that mixed-mode node.
///
/// Excludes ONLY a libp2p give-side provider (`is_libp2p_provider`) — a provider serves/announces,
/// it is not a leech that would silently miss a pool. A ROUTER is DELIBERATELY NOT excluded (codex
/// re-gate): a router still retains the directory/locator/transfer consume axes (it is wrapped in
/// `LeechFabric`, and `daemon_core::run` builds a `PeerFabricNarSource` for it), so a bootstrapped or
/// mDNS router that lands on the public `v1` scope CAN consume and silently miss a `lan-share.v1`
/// pool — exactly the silent misconfiguration this hint exists to surface. This therefore FIXES a
/// pre-existing gap: the old `matches!(profile, ConsumeOnly)` gave a router NO warning; keying on the
/// libp2p leg makes a misconfigured router warn. Pure so the decision is unit-mutation-provable.
pub fn libp2p_leg_consume_capable(
    is_libp2p_provider: bool,
    libp2p_leech: bool,
    mdns_enabled: bool,
    has_bootstrap_peer: bool,
) -> bool {
    !is_libp2p_provider && (libp2p_leech || mdns_enabled || has_bootstrap_peer)
}

/// Whether a multiaddr is PROVABLY LAN-only AND a plain DIRECT listen: it must be EXACTLY one IP
/// literal — loopback, link-local, or provably-private (RFC1918/ULA, see [`ip_is_provably_private`])
/// — followed by exactly one recognized direct transport the shipped swarm actually builds. The
/// shipped swarm (`fabric-libp2p/src/swarm.rs`, `.with_tcp(...).with_quic()`) speaks TCP and QUIC-v1,
/// so the ONLY admissible listen shapes are:
///   * `/ip4|ip6/<literal>/tcp/<port>`
///   * `/ip4|ip6/<literal>/udp/<port>/quic-v1`
///
/// EVERYTHING ELSE is REFUSED (fail-CLOSED, positive grammar). Critically this rejects a relay hop
/// (`.../p2p/<id>` or `.../p2p-circuit`): the earlier fail-OPEN `_ => {}` ignored every non-IP
/// protocol, so a `/ip4/<rfc1918>/tcp/<port>/p2p/<relay>/p2p-circuit` classified LAN-only and a
/// no-allowlist provider could reserve a slot on a DUAL-HOMED relay, letting an INTERNET peer reach
/// it through the circuit (codex CRITICAL #1). It also rejects DNS names (`/dns*`, resolve to
/// who-knows-what), the `0.0.0.0`/`::` wildcard (binds every interface, including public ones),
/// `/ws`, `/wss`, `/memory`, and any bare or over-long multiaddr.
///
/// TASK-276 relaxed the IP-literal check from loopback/link-local-only to ALSO admit RFC1918/ULA.
/// Rationale: the TASK-102 guard over-coupled Publication (the allowlist axis) with
/// Serving/reachability (the listen axis). A bare `lan-share` does not itself dial a public DHT (no
/// bootstrap and no provider-addr — [`lan_isolation_or_refuse`] refuses those), so relaxing only the
/// LISTEN check to private ranges restores the PRD's axis separation (#4 Publication vs #5 Serving)
/// without a new leak class here: same-pin content is public nixpkgs, no holdings are enumerated, and
/// Nix re-verifies every fetched path. This is a LISTEN-address predicate ONLY — it does NOT
/// guarantee end-to-end public-internet isolation, because a dual-homed same-scope peer could still
/// re-propagate content keys beyond the LAN (that confinement is TASK-280). Reached ONLY on the
/// no-allowlist `lan-share` path; `public-share` uses the allowlist door and never calls it.
fn multiaddr_is_lan_only(addr: &Multiaddr) -> bool {
    use fabric_libp2p::Protocol;
    // Positive grammar: EXACTLY one IP literal + one direct transport the swarm builds. Collecting
    // to a slice lets us match the whole shape (and its LENGTH) at once, so a trailing `/p2p`,
    // `/p2p-circuit`, `/ws`, or any extra protocol falls through to the `_ => false` reject.
    let protos: Vec<Protocol> = addr.iter().collect();
    let ip = match protos.as_slice() {
        [Protocol::Ip4(ip), Protocol::Tcp(_)] => IpAddr::V4(*ip),
        [Protocol::Ip6(ip), Protocol::Tcp(_)] => IpAddr::V6(*ip),
        [Protocol::Ip4(ip), Protocol::Udp(_), Protocol::QuicV1] => IpAddr::V4(*ip),
        [Protocol::Ip6(ip), Protocol::Udp(_), Protocol::QuicV1] => IpAddr::V6(*ip),
        _ => return false,
    };
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || ip_is_provably_private(&ip),
        IpAddr::V6(v6) => {
            // `Ipv6Addr::is_unicast_link_local` is unstable, so test the `fe80::/10` prefix
            // directly. Loopback `::1` is covered by `is_loopback`; ULA `fc00::/7` by
            // `ip_is_provably_private`.
            let link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            v6.is_loopback() || link_local || ip_is_provably_private(&ip)
        }
    }
}

/// The TASK-102 LAN-reachability witness (fix cycle #2): mint a [`LanShare`] ONLY when this node
/// exposes no direct public-reach signal — no bootstrap, no provider-addr, and a provably-private (or
/// loopback/link-local) listen — else REFUSE (fail-closed, naming TASK-103). This constrains what
/// THIS node directly reaches; it does NOT by itself guarantee end-to-end LAN isolation, because a
/// dual-homed same-scope peer could re-propagate content keys beyond the LAN (that confinement is
/// TASK-280). This is the ONE place the shipped provider modes turn a reachability config into the
/// private-announce witness, so both thin binaries share exactly one policy (no per-binary drift).
///
/// It refuses on ANY public-reach signal in `reach`:
///   1. a non-empty `--libp2p-bootstrap` (joining a DHT we did not assemble);
///   2. a non-empty `--libp2p-provider-addr` (an external entry seeded into the kad routing table -
///      the residual that let an empty-bootstrap provider still announce to the public DHT); or
///   3. a `--libp2p-listen` address that is not provably LAN-only (loopback, link-local, or
///      RFC1918/ULA private — TASK-276); a GLOBAL/routable/wildcard/DNS listen still refuses.
///
/// A relay is NOT a shipped-config signal (the thin binaries expose no relay flag), so there is
/// nothing to check for it here; were a relay flag added, it would be a fourth refusal.
///
/// Only a node with NO bootstrap, NO provider-addr, and (if listening at all) a
/// loopback/link-local/private-LAN (RFC1918/ULA, TASK-276) listen is `LanShare`-eligible - the
/// genuinely-LAN-isolated single-host / same-segment case. The real allowlist-gated PUBLIC announce
/// door that lifts the bootstrap/provider-addr restriction is TASK-103's hard blocker.
pub fn lan_isolation_or_refuse(reach: LanReachability<'_>) -> Result<LanShare, String> {
    if !reach.bootstrap.is_empty() {
        return Err(
            "refusing to announce provider records: --libp2p-bootstrap joins a (potentially \
             PUBLIC) kad DHT and there is no configured public-NAR allowlist, so this would publish \
             operator-named local content to strangers. The allowlist-gated public announce door is \
             wired by TASK-103; run with NO --libp2p-bootstrap, NO --libp2p-provider-addr, and a \
             loopback/link-local --libp2p-listen for a no-allowlist LAN announce."
                .to_string(),
        );
    }
    if !reach.provider_addrs.is_empty() {
        return Err(
            "refusing to announce provider records: --libp2p-provider-addr seeds an external peer \
             into the kad routing table, so even with an empty --libp2p-bootstrap the node can reach \
             a (potentially PUBLIC) DHT to store its records - and there is no configured public-NAR \
             allowlist, so this would publish operator-named local content to strangers. The \
             allowlist-gated public announce door is wired by TASK-103; run with NO \
             --libp2p-provider-addr for a no-allowlist LAN announce."
                .to_string(),
        );
    }
    if let Some(listen) = reach.listen
        && !multiaddr_is_lan_only(listen)
    {
        return Err(format!(
            "refusing to announce provider records: --libp2p-listen {listen} is not provably \
             LAN-only (loopback, link-local, or RFC1918/ULA private), so the node is reachable by \
             strangers on the public internet and its announce could reach a public substrate - and \
             there is no configured public-NAR allowlist. The allowlist-gated public announce door \
             is wired by TASK-103; listen on a loopback/link-local/private-LAN address for a \
             no-allowlist LAN announce."
        ));
    }
    Ok(LanShare::operator_assembled())
}

/// The SINGLE publication decision for a PROVIDER node, taken ONCE before any fabric or listener is
/// constructed (TASK-276 FIX #2). It binds the witness a no-allowlist provider needs UP FRONT so the
/// refusal path aborts BEFORE `build_libp2p_provider_source` registers a single listener — closing
/// the codex CRITICAL #2 window where a wildcard/global+seed provider momentarily bound every
/// interface (and a queued exact-key request could be admitted) before the guard, run per-announce,
/// finally refused. Held and threaded into every announce branch so the guard is consulted exactly
/// once per provider start, not re-derived per leg.
///
/// There is deliberately NO "public-reachable, no allowlist" degraded variant: that config now
/// aborts at the decision (via [`lan_isolation_or_refuse`]) instead of building a fabric that serves
/// while refusing to announce.
pub enum PublicationPlan {
    /// A configured public allowlist gates each announce (the allowlist door mints + re-checks).
    Allowlist,
    /// No allowlist, but the node passed the LAN-reachability witness (no bootstrap/provider-addr, a
    /// provably-private listen) — the held [`LanShare`] authorises the no-allowlist LAN announce. Not
    /// a claim of end-to-end public-internet isolation (see TASK-280).
    Lan(LanShare),
}

impl PublicationPlan {
    /// The announcer's per-fabric publication-eligibility authority matching this plan (TASK-231
    /// AC#2), so the announcer's re-check and the announce door agree by construction: an allowlist
    /// plan -> the [`AllowlistEligibility`] backed by the SAME allowlist; a LAN plan -> the explicit
    /// [`AdmitAllPublication`] (safe because a LAN plan only exists when the isolation guard passed).
    pub fn announce_authority(
        &self,
        allowlist: &Arc<PublicNarAllowlist>,
    ) -> Arc<dyn PublicationEligibility> {
        match self {
            PublicationPlan::Allowlist => Arc::new(AllowlistEligibility::new(allowlist.clone())),
            PublicationPlan::Lan(_) => Arc::new(AdmitAllPublication),
        }
    }
}

/// Whether a bound listen [`Multiaddr`] carries a provably-private (RFC1918/ULA) IP literal — the
/// addresses a same-segment LAN peer actually reaches. Returns `false` for loopback/link-local/
/// global/wildcard binds so the "LOCAL NETWORK" serving disclosure never mislabels them, and works
/// for EVERY admitted transport (TCP and QUIC) since it inspects only the IP literal.
pub fn listen_addr_is_private_lan(addr: &Multiaddr) -> bool {
    use fabric_libp2p::Protocol;
    addr.iter().any(|proto| match proto {
        Protocol::Ip4(v4) => ip_is_provably_private(&IpAddr::V4(v4)),
        Protocol::Ip6(v6) => ip_is_provably_private(&IpAddr::V6(v6)),
        _ => false,
    })
}

/// Build the operator SERVING disclosure lines for a `lan-share` provider (TASK-276 FIX #3), one per
/// bound listener whose IP literal is provably-private (RFC1918/ULA — see [`listen_addr_is_private_lan`]).
/// SHARED by both thin binaries so the operator-facing honesty is single-sourced.
///
/// Each line prints the FULL bound multiaddr (correct for v6, covers QUIC) and is deliberately
/// NON-categorical: it does NOT claim "not reachable from the internet" (false the moment an operator
/// DNATs/port-forwards or routes a VPN to the port), and it names the STILL-OPEN isolation gap —
/// nix-p2p does not yet confine same-scope Kademlia publication to the LAN, so a dual-homed
/// same-network peer could propagate content keys beyond it (TASK-280). Under announce-after-fetch the
/// served set is not a fixed operator-chosen set, so the served-scope clause says so.
pub fn lan_serving_disclosures(
    announce_after_fetch: bool,
    network_scope: &str,
    listen_addrs: &[Multiaddr],
) -> Vec<String> {
    let served_scope = if announce_after_fetch {
        "The paths you chose to share, plus ELIGIBLE, successfully-verified paths this node fetches \
         while running — up to the configured announce budget, NOT every fetched path \
         (announce-after-fetch) — may be announced and served; no holdings are listed."
    } else {
        "Only paths you chose to share are served; no holdings are listed."
    };
    // Print the EFFECTIVE scope, not a hardcoded string (TASK-280 #6). The default lan-share scope is
    // distinct from the public DHT; but an operator who OVERRODE the scope to the public
    // `DEFAULT_NETWORK_SCOPE` (`--libp2p-scope v1`) has deliberately joined the public DHT namespace,
    // and the disclosure must say so honestly (the dial veto + serve provenance still confine it, but
    // the DHT is no longer separate). This is the deliberate insider-bridge case.
    let scope_clause = if network_scope == DEFAULT_NETWORK_SCOPE {
        format!(
            "This node is LAN-CONFINED (TASK-280): it dials and serves only LAN-provenance peers. But \
             you have OVERRIDDEN its DHT scope to the PUBLIC \"{DEFAULT_NETWORK_SCOPE}\" scope, so its \
             DHT namespace is SHARED WITH the public DHT (NOT isolated) — the dial veto and serve \
             provenance still confine dialing and serving, but this is the deliberate shared-scope case."
        )
    } else {
        format!(
            "This node is LAN-CONFINED (TASK-280): it dials and serves only LAN-provenance peers and \
             runs a distinct \"{network_scope}\" DHT scope separate from the public \
             \"{DEFAULT_NETWORK_SCOPE}\" DHT, so an ordinary public peer cannot join it or fetch \
             from it."
        )
    };
    listen_addrs
        .iter()
        .filter(|addr| listen_addr_is_private_lan(addr))
        .map(|addr| {
            format!(
                "SERVING on {addr} to devices that can route to this address (your LAN — plus any \
                 VPN/NAT/port-forward you configured to it). {served_scope} {scope_clause} A residual \
                 remains — a DELIBERATELY-BRIDGED same-scope peer, or a public source you DNAT to \
                 this port — so keep it on the LAN: Do not DNAT/port-forward this port."
            )
        })
        .collect()
}

/// Emit the operator disclosure(s) FIRST, then activate the `/nar` serve gate (TASK-276 FIX #3). The
/// ordering is a security property, not cosmetics: the disclosure must precede serve activation so an
/// exact-key peer cannot be served before the operator has been told the port is open, and a
/// serve-gate failure cannot suppress the disclosure. `disclose` runs unconditionally and to
/// completion; only then is `activate` awaited (constructing the serve future does not open the gate —
/// awaiting it does), and its `Result` propagates. SHARED by both binaries; unit-orderable via the
/// two effects.
pub async fn disclose_then_activate_serve<F, T, E>(
    disclose: impl FnOnce(),
    activate: F,
) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    disclose();
    activate.await
}

/// A verified store [`StoreProvision`] PAIRED with the allowlist [`PublicNarClaim`] that
/// authorises announcing it PUBLICLY. Private fields, minted ONLY by
/// [`approve_provisions_for_public`], so a public announce CANNOT be represented without an
/// allowlist-minted claim - the claim is LOAD-BEARING (held through the announce), not cosmetic.
#[derive(Debug, Clone)]
pub struct ApprovedPublicProvision {
    provision: StoreProvision,
    /// The unforgeable proof the allowlist approved this NAR for public announce. Held (never
    /// discarded) so this capability cannot exist without it.
    claim: PublicNarClaim,
}

impl ApprovedPublicProvision {
    /// The verified provision to announce (its `content` is the TASK-56-verified digest).
    pub fn provision(&self) -> &StoreProvision {
        &self.provision
    }

    /// The allowlist claim authorising the PUBLIC announce of this provision's NAR.
    pub fn claim(&self) -> &PublicNarClaim {
        &self.claim
    }
}

/// The single TASK-102 publication-eligibility decision as a PER-FABRIC authority the shipped
/// announcer HOLDS (TASK-231, AC#2): it ADMITS exactly the derived [`ContentKey`]s of the NARs the
/// [`PublicNarAllowlist`] proved public. The public provider path injects this so the announcer
/// refuses - fail-closed, AT THE ADAPTER, before any `start_providing`/`put_record` - any record the
/// allowlist did not approve. This is what structurally closes the bypass where a freely-minted LAN
/// witness reached `announce` carrying an unallowlisted-but-signed record.
pub struct AllowlistEligibility {
    allowlist: Arc<PublicNarAllowlist>,
}

impl AllowlistEligibility {
    /// An authority backed by `allowlist` - the SAME instance the public door consults, so the
    /// announcer's re-check and the door's approve gate are ONE decision (single source of truth).
    pub fn new(allowlist: Arc<PublicNarAllowlist>) -> Self {
        AllowlistEligibility { allowlist }
    }
}

impl PublicationEligibility for AllowlistEligibility {
    fn admit(&self, record: &ProviderRecord) -> Result<(), IneligibleReason> {
        allowlist_admits(&self.allowlist, record)
    }
}

/// A BORROWED allowlist authority used only to MINT a public-announce witness at the door
/// (transient): the public path's witness is thus genuinely allowlist-gated (AC#3), distinct from
/// the LAN path's [`AdmitAllPublication`] witness. Never stored; `authorize` returns an owned witness
/// and the borrow ends with the call.
struct AllowlistWitnessAuthority<'a> {
    allowlist: &'a PublicNarAllowlist,
}

impl PublicationEligibility for AllowlistWitnessAuthority<'_> {
    fn admit(&self, record: &ProviderRecord) -> Result<(), IneligibleReason> {
        allowlist_admits(self.allowlist, record)
    }
}

/// The ONE admit rule both allowlist authorities share: a record is admitted iff its derived
/// [`ContentKey`] matches an allowlisted NAR. The frozen `ProviderRecord` carries no `NarHash`
/// preimage, so the allowlist reverse-derives each entry's key (see
/// [`PublicNarAllowlist::contains_content_key`]). Fail-closed: no match -> refuse.
fn allowlist_admits(
    allowlist: &PublicNarAllowlist,
    record: &ProviderRecord,
) -> Result<(), IneligibleReason> {
    if allowlist.contains_content_key(&record.key) {
        Ok(())
    } else {
        Err(IneligibleReason::NotAllowlisted)
    }
}

/// The shared record-signing announce loop. PRIVATE to this module: neither the public nor the
/// private door is a bare-provision entry point reachable from outside. For each provision it
/// durably allocates the announce sequence, signs a record whose `content` is the verified digest
/// (via [`sign_libp2p_store_record`]), and publishes it under `budget`.
async fn announce_store_records(
    fabric: &Libp2pFabric,
    readiness: &ProviderRelayReadiness,
    config: InitialAnnounceConfig<'_>,
    provisions: &[StoreProvision],
    witness_authority: &dyn PublicationEligibility,
) -> Result<Vec<ProviderRecord>, String> {
    let announcer = fabric
        .announcer()
        .ok_or_else(|| "internal: libp2p provider fabric exposes no announcer".to_string())?;
    // StoreProvision is already the verified capability. Capture one live startup snapshot before
    // entering the initial batch loop; do this even for an empty provision batch.
    let relay_hints = readiness.capture(fabric).await?;
    let mut records = Vec::with_capacity(provisions.len());
    for provision in provisions {
        let sequence = fabric.next_announce_sequence(&provider_content_key(&provision.nar_hash));
        let record = sign_libp2p_store_record(
            config.identity_seed,
            &provision.nar_hash,
            provision.content,
            relay_hints,
            config.ttl_secs,
            config.now,
            sequence,
        );
        // TASK-231 (AC#1): mint this path's eligibility witness (see `announce_seed_records`).
        let witness = witness_authority.authorize(record.clone()).map_err(|e| {
            format!(
                "publication eligibility refused libp2p store record for {}: {e}",
                provision.nar_hash
            )
        })?;
        announcer
            .announce(&witness, config.budget)
            .await
            .map_err(|e| {
                format!(
                    "announcing libp2p store provider record for {}: {e}",
                    provision.nar_hash
                )
            })?;
        records.push(record);
    }
    Ok(records)
}

/// Announce a signed [`ProviderRecord`] for each VERIFIED store [`StoreProvision`] this node serves
/// on demand over a PRIVATE / LAN substrate (AC#1/#2, TASK-191), the store analogue of
/// [`announce_provider_seeds`]. It requires a [`LanShare`] witness, so the call site EXPLICITLY
/// declares the substrate is not a gated public DHT (the PUBLIC analogue is
/// [`announce_public_provisions`], which instead demands allowlist claims).
///
/// It consumes only [`StoreProvision`]s, which - being an un-forgeable capability minted solely by
/// [`verify_store_provisions`] - GUARANTEES every announced `content` came from the index's
/// TASK-56-verified binding, never the operator's word. The `fabric-libp2p` serve path re-runs the
/// len + BLAKE3 recheck (TASK-158/193) as the last-line integrity anchor.
pub async fn announce_store_provisions(
    fabric: &Libp2pFabric,
    readiness: &ProviderRelayReadiness,
    config: InitialAnnounceConfig<'_>,
    provisions: &[StoreProvision],
    _lan: LanShare,
) -> Result<Vec<ProviderRecord>, String> {
    // LAN door (AC#3): AdmitAll witness, as `announce_provider_seeds`.
    announce_store_records(fabric, readiness, config, provisions, &AdmitAllPublication).await
}

// -------------------------------------------------------------------------
// The TYPED PUBLIC-ANNOUNCE door (TASK-102): the ONLY announce path gated on the
// public-NAR allowlist. Closed-by-construction, so a PUBLIC announce cannot bypass it.
// -------------------------------------------------------------------------

/// CONSULT the public-NAR allowlist for a batch of verified store provisions a node
/// intends to announce PUBLICLY, minting one [`PublicNarClaim`] per provision. FAIL-CLOSED
/// and ALL-OR-NOTHING: if ANY provision is not allowlisted (never proven public via a
/// trusted cache.nixos.org signature), the WHOLE batch is refused and NO claim is minted,
/// so no partial announce can leak an un-approved NAR.
///
/// This is the single consult point (AC#1) the PUBLIC announce door goes through. It is a
/// PURE function of `(provisions, allowlist)`, so the closed-by-construction gate is
/// unit-testable without a live DHT: an operator-seeded LOCAL fixture (absent from the
/// allowlist) yields a NAMED [`PublicationRejected`] and mints nothing. The size the
/// allowlist proved must equal the provision's declared NarSize, or the claim is refused
/// (a NAR can be announced only at exactly the size a trusted signature covered).
///
/// It is deliberately SEPARATE from [`announce_provider_seeds`] / [`announce_store_provisions`],
/// which are SUBSTRATE-NEUTRAL (they legitimately serve LAN / private / test announces where
/// operator-named local content is fine). Publicness is a property of the SUBSTRATE, so the
/// allowlist gate belongs only at the PUBLIC boundary - this door - not inside the neutral loops.
pub fn approve_provisions_for_public(
    provisions: &[StoreProvision],
    allowlist: &PublicNarAllowlist,
) -> Result<Vec<ApprovedPublicProvision>, PublicationRejected> {
    let mut approved = Vec::with_capacity(provisions.len());
    for provision in provisions {
        // `approve` mints an UNFORGEABLE PublicNarClaim iff the NarHash is allowlisted AND its
        // approved size matches what this node would advertise. Absence -> fail-closed. The claim
        // is PAIRED with the provision into the capability and HELD through the announce, so a
        // public announce cannot be represented without it.
        let claim = allowlist.approve(provision.nar_hash(), Some(provision.declared_size()))?;
        approved.push(ApprovedPublicProvision {
            provision: provision.clone(),
            claim,
        });
    }
    Ok(approved)
}

/// Announce a signed [`ProviderRecord`] for each verified store [`StoreProvision`], but
/// ONLY after the public-NAR allowlist has PROVEN every one publishable (TASK-102). This is
/// the PUBLIC analogue of [`announce_store_provisions`]: it FIRST runs
/// [`approve_provisions_for_public`] (fail-closed, all-or-nothing) and announces nothing if
/// any provision is un-allowlisted, then reuses the same verified-content announce loop.
///
/// STATUS: this typed door exists so that - by construction - the only way to PUBLICLY announce
/// store content is through the allowlist gate. It takes `provisions + allowlist` and CONSUMES the
/// minted [`ApprovedPublicProvision`]s (claim held through the announce), so a public announce with
/// no allowlist-minted claim is UNREPRESENTABLE - there is no bare-provision public entry point.
/// It is not yet wired to a shipped binary: TASK-103 (the DHT discovery-announce driver) is the
/// integration that routes public participation through this door and populates the allowlist for
/// operator-provided paths by proving each public via the same narinfo-signature gate.
pub async fn announce_public_provisions(
    fabric: &Libp2pFabric,
    readiness: &ProviderRelayReadiness,
    config: InitialAnnounceConfig<'_>,
    provisions: &[StoreProvision],
    allowlist: &PublicNarAllowlist,
) -> Result<Vec<ProviderRecord>, String> {
    // THE GATE (fail-closed, before any record is signed or announced): every provision must be
    // allowlisted, minting a claim-bearing capability, or the whole public announce is refused.
    let approved = approve_provisions_for_public(provisions, allowlist)
        .map_err(|rejected| format!("public announce refused by the allowlist gate: {rejected}"))?;
    announce_approved_public(fabric, readiness, config, &approved, allowlist).await
}

/// Announce a record per [`ApprovedPublicProvision`], the PUBLIC counterpart of
/// [`announce_store_records`]. Consuming the capability (claim held) is what makes a public
/// announce impossible without an allowlist-minted claim. The witness is minted from the SAME
/// `allowlist` (AC#2/#3): allowlist-gated, distinct from the LAN path's AdmitAll witness.
async fn announce_approved_public(
    fabric: &Libp2pFabric,
    readiness: &ProviderRelayReadiness,
    config: InitialAnnounceConfig<'_>,
    approved: &[ApprovedPublicProvision],
    allowlist: &PublicNarAllowlist,
) -> Result<Vec<ProviderRecord>, String> {
    let provisions: Vec<StoreProvision> = approved
        .iter()
        .map(|a| {
            // The claim is load-bearing: its NarHash must match the provision it authorises.
            debug_assert_eq!(a.claim().nar_hash(), a.provision().nar_hash());
            a.provision().clone()
        })
        .collect();
    announce_store_records(
        fabric,
        readiness,
        config,
        &provisions,
        &AllowlistWitnessAuthority { allowlist },
    )
    .await
}

// -------------------------------------------------------------------------
// ANNOUNCE-AFTER-FETCH (TASK-77): the swarm-GROWTH hook. A node that just fetched a
// NAR becomes a discoverable holder for it, so popular paths acquire holders naturally.
// It REUSES the verified announce doors above (verify_store_provisions ->
// announce_store_provisions / announce_public_provisions) - there is deliberately NO
// second announce path that could bypass the TASK-231 eligibility authority.
// -------------------------------------------------------------------------

/// The publication door an announce-after-fetch node uses, mirroring the two shipped
/// provider doors (the substrate's publicness is a composition-root fact - see [`LanShare`] /
/// the allowlist - so the binary picks the door, never the library).
#[derive(Clone)]
pub enum AnnounceAfterFetchDoor {
    /// A PUBLIC (bootstrapped) substrate: announce ONLY allowlisted content. The allowlist is
    /// the SAME instance the fabric's `AllowlistEligibility` authority holds and that
    /// `respond_narinfo` keeps learning from the trusted-signed narinfos this node fetches, so a
    /// fetched path is announced iff a trusted narinfo proved it public - and the announcer
    /// re-checks that authority fail-closed (TASK-231). An unallowlisted fetched path is REFUSED
    /// here (nothing reaches the DHT).
    Public(Arc<PublicNarAllowlist>),
    /// The no-allowlist LAN path (the node passed the LAN-reachability witness — no
    /// bootstrap/provider-addr, a provably-private listen; NOT a claim of end-to-end public-internet
    /// isolation, see TASK-280): a fetched path may be announced without the public-allowlist gate
    /// (the fabric's `AdmitAll` authority admits), still TASK-56 verification-gated. The witness is
    /// the composition root's [`LanShare`].
    Lan(LanShare),
}

/// The integer announce BUDGET + the dedup state (TASK-77 AC#2). One `Mutex` guards all three so
/// the reserve/dedup/refund decisions are atomic under concurrent fetches.
///
/// The budget is spent on RESERVE and REFUNDED if the grow does not actually announce (TASK-77
/// FIX 2): a fetch that fails eligibility, never materialises, or fails to publish must NOT
/// permanently consume a node's growth budget - only a real announce does. So a stream of invalid
/// fetches cannot exhaust the budget.
struct AnnounceLedger {
    /// Remaining announce-after-fetch announces this process may still make. An INTEGER (no
    /// float). At zero, announcing STOPS (not degrades) - the guardrail against unbounded
    /// self-DoS + the privacy surface (every announce reveals a path you fetched).
    remaining: u64,
    /// Keys whose grow is IN FLIGHT (reserved, not yet committed). Prevents a concurrent duplicate
    /// grow for the same key, and is where a refund returns the unit from on failure.
    inflight: HashSet<NarHashKey>,
    /// Keys SUCCESSFULLY announced (budget spent for good). Dedup: a re-fetch of an already-
    /// announced path is a no-op (this node is already a holder).
    announced: HashSet<NarHashKey>,
    /// The still-advertised holdings, `nar_hash -> (announced ContentKey, store path)` (TASK-77
    /// FIX 3b/D). [`reconcile`] walks this to WITHDRAW any holding whose store path was GC'd, so the
    /// node self-heals a record it can no longer serve. This is EVENTUALLY consistent, not
    /// instantaneous: between a GC (or an ambiguous announce) and the next successful reconcile, the
    /// node CAN transiently keep advertising a record it cannot serve - bounded by reconcile-on-
    /// dispatch and the record's kad TTL (a stale record costs a querier one clean-declined retry,
    /// within the TCB; see the module doc's eventually-consistent residual). A withdrawn holding is
    /// dropped from here ONLY on a SUCCESSFUL withdraw (a failed one is KEPT for retry); it stays in
    /// `announced` for dedup, so its one budget unit is not re-spent.
    held: HashMap<NarHashKey, (ContentKey, String)>,
    /// The NarHashes owned by the DURABLE, memory-resident `--libp2p-seed-nar` leg (TASK-279 AC#1).
    /// This hook is a strict NO-OP for any key in here: it never reserves a budget unit, never
    /// announces, and — the load-bearing part — never TRACKS it in `held`, so [`reconcile`] can never
    /// WITHDRAW it.
    ///
    /// Why: the seed leg is a `MemoryNarSupplier` that is NEVER GC'd, and it announced the key ONCE at
    /// startup (`announce_provider_seeds`). If the announce-after-fetch hook ALSO announced the same
    /// key (a self-fetch that self-realises it into `/nix/store`) and later a store-path GC drove
    /// `reconcile` to withdraw it, the minted tombstone would SUPERSEDE the seed leg's still-valid
    /// announce — tombstoning discovery for a NAR the node can STILL serve from memory (served-but-not-
    /// announced), and unrepairably so (the key stays in `announced`, so a re-fetch is `AlreadyHandled`
    /// and never re-announces). The durable seed leg OWNS discovery for these keys; the hook must not
    /// touch them.
    seed_owned: HashSet<NarHashKey>,
}

/// The outcome of [`begin`]: whether `on_fetched` should proceed to spawn a grow.
#[derive(Debug, PartialEq, Eq)]
enum Begin {
    /// A budget unit was reserved and the key marked in-flight; spawn the grow.
    Proceed,
    /// The key is already announced or a grow for it is in flight; do nothing (not a failure).
    AlreadyHandled,
    /// The key is owned by the DURABLE, memory-resident seed leg (TASK-279 AC#1). The hook is a strict
    /// NO-OP: never reserve, never announce, never track (so `reconcile` can never withdraw it and
    /// tombstone the seed leg's own never-GC'd announce). Distinct from `AlreadyHandled` (which is
    /// same-key dedup within the hook's own grows) so the state machine — and the mutation that would
    /// re-introduce the tombstone — is legible.
    SeedOwned,
    /// The budget is spent; announcing STOPS. This is the AC#2 enforcement point that `on_fetched`
    /// consults - the mutation that removes the guard (or the `begin` CALL in `on_fetched`) makes
    /// the announce count grow unbounded.
    Exhausted,
}

/// The pure AC#2 reserve: atomically dedup + reserve one budget unit for `key`, marking it
/// in-flight. Past the budget this returns [`Begin::Exhausted`] and `on_fetched` spawns NOTHING.
/// Pure over the ledger, so the production bite (drive `on_fetched`, count spawns) needs no
/// runtime/fabric. Removing the `remaining == 0` guard here - or the `begin` call in `on_fetched`
/// - lets the announce count grow unbounded (both mutations reddened by the budget bite).
fn begin(ledger: &Mutex<AnnounceLedger>, key: &NarHashKey) -> Begin {
    let mut led = ledger.lock().expect("announce ledger poisoned");
    // TASK-279 AC#1 (STATE MACHINE, checked FIRST): a key the durable memory-resident seed leg owns
    // is never touched by this hook — no reserve, no announce, no `held` track. This is what prevents
    // a later store-path GC from withdrawing (tombstoning) the seed leg's own never-GC'd announce.
    // MUST precede the dedup/budget arms: a seed-owned key must never enter `inflight`/`held`.
    if led.seed_owned.contains(key) {
        return Begin::SeedOwned;
    }
    if led.announced.contains(key) || led.inflight.contains(key) {
        return Begin::AlreadyHandled;
    }
    if led.remaining == 0 {
        return Begin::Exhausted;
    }
    led.remaining -= 1;
    led.inflight.insert(*key);
    Begin::Proceed
}

/// Commit a grow that DID announce: the reservation becomes permanent (budget stays spent), the
/// key moves to `announced` (dedup), and the holding is tracked in `held` (`content_key` +
/// `store_path`) so [`reconcile`] can withdraw it if the path is later GC'd (FIX 3b).
fn commit_success(
    ledger: &Mutex<AnnounceLedger>,
    key: &NarHashKey,
    content_key: ContentKey,
    store_path: String,
) {
    let mut led = ledger.lock().expect("announce ledger poisoned");
    led.inflight.remove(key);
    led.announced.insert(*key);
    led.held.insert(*key, (content_key, store_path));
}

/// Commit a grow that did NOT announce (ineligible / never-materialised / publish failed): REFUND
/// the reserved unit (TASK-77 FIX 2) so an invalid fetch does not consume growth budget, and drop
/// the in-flight mark so a later fetch of the same path may retry. Removing the `remaining += 1`
/// refund is the mutation the exhaustion bite catches (invalid fetches would then drain the budget).
fn commit_failure(ledger: &Mutex<AnnounceLedger>, key: &NarHashKey) {
    let mut led = ledger.lock().expect("announce ledger poisoned");
    if led.inflight.remove(key) {
        led.remaining += 1;
    }
}

/// Retract a provider record this node published (TASK-77 FIX 3b). Returns `true` iff the
/// withdrawal was published, so [`reconcile`] KEEPS a holding whose withdraw FAILED and retries it
/// on a later dispatch (FIX B). Decoupled from the fabric so the GC-withdraw bite needs no live
/// swarm: the production impl drives `fabric.announcer().withdraw` (the existing TASK-231 self-serve
/// tombstone path), the test double scripts success/failure.
#[async_trait]
trait Withdrawer: Send + Sync {
    async fn withdraw(&self, key: &ContentKey) -> bool;
}

/// The production [`Withdrawer`]: withdraw through the fabric's own announcer (the SAME announcer
/// that published the record, so the self-serve tombstone is signed by this node - TASK-231/152).
struct FabricWithdrawer {
    fabric: Arc<Libp2pFabric>,
}

#[async_trait]
impl Withdrawer for FabricWithdrawer {
    async fn withdraw(&self, key: &ContentKey) -> bool {
        let Some(announcer) = self.fabric.announcer() else {
            eprintln!("LIBP2P-ANNOUNCE-AFTER-FETCH withdraw skipped: fabric exposes no announcer");
            return false;
        };
        match announcer.withdraw(key).await {
            Ok(_) => {
                println!("LIBP2P-ANNOUNCE-AFTER-FETCH withdrew content_key={key} (GC'd path)");
                true
            }
            Err(e) => {
                eprintln!(
                    "LIBP2P-ANNOUNCE-AFTER-FETCH withdraw of {key} failed: {e} (retained; retried \
                     on the next fetch, and it expires by TTL regardless)"
                );
                false
            }
        }
    }
}

/// GC-serveability reconcile (TASK-77 FIX 3b, AC#3 / TASK-72): WITHDRAW every held record whose
/// store path is no longer materialised (GC'd since the announce), self-healing toward
/// index==provider coverage. This is EVENTUALLY consistent, not instantaneous: it runs
/// OPPORTUNISTICALLY (on the next dispatch), so between a GC and the next successful reconcile the
/// node CAN transiently keep advertising a record it cannot serve - bounded by that reconcile and
/// the record's kad TTL. Self-correcting, no disk growth, reuses the existing TASK-231 withdraw.
/// `path.exists()` is the GC signal (the store GC unlinks the path); the serve side ALSO fails
/// cleanly on a vanished path (fabric-libp2p re-dumps + BLAKE3-re-verifies before emitting a byte,
/// so a stale holding costs a peer a clean Declined retry, never a wrong byte - the transient
/// window is within the TCB), so this is the ACTIVE self-heal on top of that passive safety. A
/// holding is dropped from `held` ONLY on a SUCCESSFUL withdraw (FIX B): a failed withdraw is KEPT
/// so the next dispatch retries it. Removing the `withdraw` call - the mutation the production GC
/// bite catches - leaves a lasting false holding on the DHT.
async fn reconcile(ledger: &Mutex<AnnounceLedger>, withdrawer: &dyn Withdrawer) {
    // Snapshot the GC'd holdings under the lock (do not hold it across the async withdraw).
    let gone: Vec<(NarHashKey, ContentKey)> = {
        let led = ledger.lock().expect("announce ledger poisoned");
        led.held
            .iter()
            .filter(|(_, (_, store_path))| !Path::new(store_path).exists())
            .map(|(key, (content_key, _))| (*key, *content_key))
            .collect()
    };
    for (key, content_key) in gone {
        if withdrawer.withdraw(&content_key).await {
            // Drop it from `held` (stop tracking) ONLY on success; it stays in `announced` so its
            // budget unit is not re-spent by a later re-fetch of the same path. A FAILED withdraw is
            // KEPT in `held` so the next dispatch retries it (FIX B).
            ledger
                .lock()
                .expect("announce ledger poisoned")
                .held
                .remove(&key);
        }
    }
}

/// The nix-base32 alphabet (`0-9a-z` minus `e o u t`), the encoding of a store path's `<hash>`
/// component. Used by [`validate_store_path`] to reject a non-store-shaped path shape.
const NIXBASE32_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Structural validation (TASK-77 FIX 3a, tightened per FIX C) that `store_path` is a well-formed
/// Nix store path DIRECTLY under this node's REAL store directory - `<store_dir>/<32-char
/// nix-base32 hash>-<name>` - BEFORE the node registers/dumps it. It requires the path's PARENT to
/// be exactly `store_dir` (the daemon's `--store-dir`, `/nix/store` in production), so a merely
/// store-SHAPED path elsewhere (e.g. `/tmp/store/<validhash>-x`) is refused rather than dumped.
/// The narinfo `StorePath` is signature-covered for allowlisted content and the TASK-56
/// `sha256(nix-store --dump) == NarHash` check is the ULTIMATE integrity gate; this is cheap
/// defense-in-depth so a hostile/odd path can never make the node shell `nix-store --dump` at an
/// arbitrary filesystem path (e.g. `/etc/shadow`). It checks the SHAPE + LOCATION, not the hash
/// (that is nix's job at dump time).
fn validate_store_path(store_path: &str, store_dir: &str) -> Result<(), String> {
    let path = Path::new(store_path);
    if !path.is_absolute() {
        return Err(format!("store path {store_path:?} is not absolute"));
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("store path {store_path:?} has no valid final component"))?;
    let (hash, rest) = name
        .split_once('-')
        .ok_or_else(|| format!("store path basename {name:?} is not <hash>-<name>"))?;
    if hash.len() != 32 || !hash.bytes().all(|b| NIXBASE32_ALPHABET.contains(&b)) {
        return Err(format!(
            "store path basename {name:?} has a non-nix-base32 32-char <hash> component"
        ));
    }
    if rest.is_empty() {
        return Err(format!(
            "store path basename {name:?} has an empty <name> component"
        ));
    }
    // The immediate parent must be EXACTLY the node's real store dir, so a store-shaped path
    // outside `/nix/store` (a decoy `/tmp/store/<hash>-x`) is refused rather than dumped (FIX C).
    match path.parent() {
        Some(parent) if parent == Path::new(store_dir) => Ok(()),
        _ => Err(format!(
            "store path {store_path:?} is not directly under the store dir {store_dir:?}"
        )),
    }
}

/// The pure AC#3 core: STRUCTURALLY validate `store_path` (FIX 3a), register `key -> store_path`
/// in `index` and VERIFY it is servable (TASK-56 `sha256(--dump)==NarHash`, quarantine on
/// mismatch), enforce the per-NAR serve-size guard, and - for a PUBLIC door - approve it against
/// the allowlist (refuse an unallowlisted fetched path BEFORE any DHT touch). Returns the verified
/// provisions ready to announce, or a typed refusal. This is where "never announce what you cannot
/// serve" is enforced independently of the announcer's own TASK-231 re-check; removing the allowlist
/// approval (the mutation the eligibility bite catches) lets an unallowlisted fetched path become a
/// provision that would reach the DHT. Free + fabric-free so the bite needs no live swarm; the
/// blocking dump runs on the caller thread.
fn eligible_provisions(
    index: &AvailabilityIndex,
    serve_budget: &peer_fabric::ServeBudget,
    door: &AnnounceAfterFetchDoor,
    store_dir: &str,
    key: &NarHashKey,
    store_path: &str,
) -> Result<Vec<StoreProvision>, String> {
    validate_store_path(store_path, store_dir)?;
    index
        .register(*key, StorePath::new(store_path))
        .map_err(|e| format!("registering fetched store path {store_path:?} under {key}: {e}"))?;
    // verify_store_provisions runs the index's TASK-56 dump+sha256==NarHash gate and refuses (Err)
    // an Absent/quarantined/undumpable path - so index-coverage == provider-coverage.
    let provisions = verify_store_provisions(index, std::slice::from_ref(key))?;
    // Size guard: never announce a NAR the serve gate would then decline (TooLarge).
    for provision in &provisions {
        if provision.declared_size() > serve_budget.max_nar_bytes_uncompressed_nar {
            return Err(format!(
                "fetched NAR {} dumps to {} B but the per-NAR serve bound is {}: not announcing a \
                 claim this node would decline to serve",
                provision.nar_hash(),
                provision.declared_size(),
                serve_budget.max_nar_bytes_uncompressed_nar
            ));
        }
    }
    // PUBLIC door (AC#3): announce a fetched path iff a trusted narinfo proved it public (it is in
    // the allowlist). Refuses BEFORE any DHT touch; the announcer's TASK-231 authority is the
    // second, independent gate. A LAN door skips this (publicness asserted by the composition
    // root's LanShare), still TASK-56-gated.
    if let AnnounceAfterFetchDoor::Public(allowlist) = door {
        approve_provisions_for_public(&provisions, allowlist).map_err(|rejected| {
            format!("announce-after-fetch refused by the allowlist gate: {rejected}")
        })?;
    }
    Ok(provisions)
}

/// A bounded wait for the LOCAL nix to MATERIALISE a fetched path into `/nix/store` (TASK-77).
///
/// The daemon RELAYS the NAR bytes; the local nix imports+registers the store path a moment
/// AFTER the serve completes (nix builds into a temp dir then renames the finished tree into
/// place atomically). So announce-after-fetch waits (bounded, cheap `exists()` polls) for the
/// path to appear before it dumps + announces - you announce only once you can actually serve
/// (TASK-72). If it never materialises (a truncated body the client rejected, a pure relay with
/// no local store), the wait times out and NOTHING is announced: fail-safe, never a claim this
/// node cannot back. The bound is an integer count of polls at an integer interval (no float).
#[derive(Debug, Clone, Copy)]
struct MaterialiseWait {
    poll_interval: Duration,
    max_polls: u32,
}

impl Default for MaterialiseWait {
    fn default() -> Self {
        // 250 ms x 240 = up to 60 s: generous headroom for a large-closure import, while a
        // never-materialising path gives up promptly enough not to pile up tasks. Tunable
        // integers, not wire constants.
        MaterialiseWait {
            poll_interval: Duration::from_millis(250),
            max_polls: 240,
        }
    }
}

/// The clonable WORKER that does the actual grow (verify + announce) for one fetched path. It
/// holds only cheap-to-clone handles (Arcs + Copy budgets), so [`PostFetchAnnounce::on_fetched`]
/// can clone it into a detached task without needing `Arc<Self>`. The stateful ledger stays on
/// [`Libp2pAnnounceAfterFetch`]; the worker is stateless over the ledger.
#[derive(Clone)]
struct GrowWorker {
    fabric: Arc<Libp2pFabric>,
    identity_seed: [u8; 32],
    /// The SHARED availability index: the provider serve path (`CatalogNarSupplier`) reads its
    /// reverse-map, so a path THIS worker registers+verifies is immediately servable to a peer.
    index: Arc<AvailabilityIndex>,
    door: AnnounceAfterFetchDoor,
    /// The per-NAR serve bound: a fetched NAR larger than this is NOT announced (announcing it
    /// would publish a claim the serve gate would then decline - the same guard the provider
    /// applies at startup).
    serve_budget: peer_fabric::ServeBudget,
    /// The DHT publish bound (deadline + replica fan-out) each announce runs under.
    announce_budget: AnnounceBudget,
    /// The record TTL (seconds) an announced record carries, matching the provider's.
    ttl_secs: u64,
    /// This node's REAL store dir (`--store-dir`, `/nix/store` in production): a fetched path must
    /// be DIRECTLY under it or it is refused before any dump (FIX C).
    store_dir: String,
    materialise: MaterialiseWait,
}

impl GrowWorker {
    /// Register + VERIFY + (public) approve one fetched path (delegates to the pure, fabric-free
    /// [`eligible_provisions`]). See there for the "never announce what you cannot serve" argument.
    fn eligible_provisions(
        &self,
        key: &NarHashKey,
        store_path: &str,
    ) -> Result<Vec<StoreProvision>, String> {
        eligible_provisions(
            &self.index,
            &self.serve_budget,
            &self.door,
            &self.store_dir,
            key,
            store_path,
        )
    }

    /// Announce ONE verified provision through the fabric's announcer, returning the outcome
    /// CLASSIFIED (FIX D) by whether a DHT side-effect could have occurred. This drives
    /// `announcer.announce` DIRECTLY (rather than the String-collapsing door) so the typed
    /// [`AnnounceError`] survives for classification. It does NOT bypass the eligibility gate: the
    /// witness is minted by THIS door's authority (Public: allowlist-gated; Lan: AdmitAll) AND the
    /// announcer re-checks with the FABRIC'S OWN per-fabric authority fail-closed (TASK-231), the
    /// same allowlist `eligible_provisions` already approved - three independent gates, no bypass.
    async fn announce_one(&self, provision: &StoreProvision) -> AnnounceAttempt {
        let Some(announcer) = self.fabric.announcer() else {
            // No announcer -> nothing published -> clean pre-publication failure.
            return AnnounceAttempt::CleanFailure("fabric exposes no announcer".to_string());
        };
        let now = now_unix_secs();
        let sequence = self
            .fabric
            .next_announce_sequence(&provider_content_key(provision.nar_hash()));
        let relay_hints = match self.fabric.live_relay_hints().await {
            Ok(hints) => hints,
            Err(error) => {
                return AnnounceAttempt::CleanFailure(format!(
                    "cannot derive live relay hints before signing: {error}"
                ));
            }
        };
        let record = sign_libp2p_store_record(
            self.identity_seed,
            provision.nar_hash(),
            provision.content(),
            relay_hints,
            self.ttl_secs,
            now,
            sequence,
        );
        let content_key = record.key;
        // Mint the witness via THIS door's authority (a witness-authorize refusal is a CLEAN
        // pre-publication failure - nothing reached the announcer).
        let witness = match &self.door {
            AnnounceAfterFetchDoor::Public(allowlist) => AllowlistWitnessAuthority {
                allowlist: allowlist.as_ref(),
            }
            .authorize(record.clone()),
            AnnounceAfterFetchDoor::Lan(_) => AdmitAllPublication.authorize(record.clone()),
        };
        let witness = match witness {
            Ok(w) => w,
            Err(reason) => {
                return AnnounceAttempt::CleanFailure(format!(
                    "witness refused (not published): {reason}"
                ));
            }
        };
        let attempt = classify_announce(
            announcer
                .announce(&witness, &self.announce_budget)
                .await
                .map(|_| ()),
            content_key,
        );
        match &attempt {
            AnnounceAttempt::Published(_) => println!(
                "LIBP2P-ANNOUNCE-AFTER-FETCH narhash={} content={} content_key={content_key} nar_size={}",
                provision.nar_hash(),
                provision.content().to_hex(),
                provision.declared_size(),
            ),
            AnnounceAttempt::Ambiguous(_) => eprintln!(
                "LIBP2P-ANNOUNCE-AFTER-FETCH narhash={} reason=announce-ambiguous \
                 (record may be live; tracked for withdraw, budget spent)",
                provision.nar_hash()
            ),
            AnnounceAttempt::CleanFailure(why) => eprintln!(
                "LIBP2P-ANNOUNCE-AFTER-FETCH narhash={} reason=announce-clean-fail: {why} \
                 (guaranteed not published; budget refunded)",
                provision.nar_hash()
            ),
        }
        attempt
    }
}

/// The outcome of announcing one provision, classified for FIX D accounting.
#[derive(Debug)]
enum AnnounceAttempt {
    /// The announcer returned `Ok`: the record was published. Track + keep budget spent.
    Published(ContentKey),
    /// The announce could have taken effect (an [`AnnounceError`] raised DURING/AROUND the publish
    /// future). The record MAY be live, so track it for `reconcile` + keep the budget SPENT.
    Ambiguous(ContentKey),
    /// A CLEAN pre-publication failure (no announcer / witness refused / an [`AnnounceError`]
    /// raised BEFORE the publish future - GUARANTEED not published). Refund the budget, track nothing.
    CleanFailure(String),
}

impl AnnounceAttempt {
    /// The FIX D ledger decision: `Some(content_key)` for Published OR Ambiguous (the caller
    /// `commit_success`es - SPENDS the budget + TRACKS the holding for `reconcile`), `None` for a
    /// CleanFailure (the caller `commit_failure`s - REFUNDS the budget + tracks nothing). Pure, so
    /// the discriminating FIX D bite chains `classify_announce` -> here -> the ledger without a swarm.
    fn into_grow_result(self) -> Option<ContentKey> {
        match self {
            AnnounceAttempt::Published(ck) | AnnounceAttempt::Ambiguous(ck) => Some(ck),
            AnnounceAttempt::CleanFailure(_) => None,
        }
    }
}

/// Classify one announce result into the FIX D accounting outcome (PURE, so the discriminating bite
/// needs no live swarm). `Ok` -> published (spend + track); an AMBIGUOUS error -> the record may be
/// live (spend + track for `reconcile`); a CLEAN error -> guaranteed not published (refund).
fn classify_announce(
    result: Result<(), AnnounceError>,
    content_key: ContentKey,
) -> AnnounceAttempt {
    match result {
        Ok(()) => AnnounceAttempt::Published(content_key),
        Err(e) if announce_error_is_ambiguous(&e) => AnnounceAttempt::Ambiguous(content_key),
        Err(e) => AnnounceAttempt::CleanFailure(e.to_string()),
    }
}

/// Classify an [`AnnounceError`] (FIX D): is it AMBIGUOUS (a DHT side-effect could have occurred) or
/// a CLEAN pre-publication failure (guaranteed not published)? Per `fabric-libp2p/src/announcer.rs`:
/// `Persist` is raised in save-before-publish BEFORE the `publish` future (announcer.rs:459), and
/// `Rejected` (record encode/decode/expiry/TTL) and `Ineligible` before it too - all GUARANTEED not
/// on the wire. Only `Unreachable` (raised inside `publish`'s `start_providing`/`put_record`) and
/// `DeadlineExceeded` (the `publish` future timed out, possibly after `start_providing`) can have a
/// side-effect. Exhaustive (no wildcard), so a NEW `AnnounceError` variant forces a conscious
/// clean-vs-ambiguous classification here rather than defaulting silently.
fn announce_error_is_ambiguous(err: &AnnounceError) -> bool {
    match err {
        AnnounceError::Unreachable(_) | AnnounceError::DeadlineExceeded => true,
        AnnounceError::Rejected(_) | AnnounceError::Persist(_) | AnnounceError::Ineligible(_) => {
            false
        }
    }
}

/// The announce side-effect for one fetched path, DECOUPLED from the ledger/spawn wiring so the
/// production-wired GC/retry bites can drive the real dispatch body ([`WorkerSpawner::run`]) with a
/// fake. The production impl is [`GrowWorker`].
#[async_trait]
trait Grower: Send + Sync {
    /// Bounded materialisation wait -> validate/verify -> announce for one reserved key. Returns
    /// `Some(content_key)` iff the record was PUBLISHED, OR the publish was AMBIGUOUSLY attempted
    /// (the announce call may have taken effect before erroring/timing out) - in both cases the
    /// caller TRACKS the holding (so `reconcile` can withdraw it) and keeps the budget SPENT.
    /// Returns `None` only on a CLEAN pre-publication failure (never materialised / ineligible /
    /// verify failed - no DHT side-effect), where the caller REFUNDS the budget (FIX 2/D).
    async fn grow(&self, key: &NarHashKey, store_path: &str) -> Option<ContentKey>;
}

#[async_trait]
impl Grower for GrowWorker {
    async fn grow(&self, key: &NarHashKey, store_path: &str) -> Option<ContentKey> {
        // Bounded wait for the local store to materialise the path (the daemon relayed the bytes;
        // nix imports them a moment later). A never-materialising path times out -> CLEAN failure.
        let mut materialised = false;
        for _ in 0..self.materialise.max_polls {
            if Path::new(store_path).exists() {
                materialised = true;
                break;
            }
            tokio::time::sleep(self.materialise.poll_interval).await;
        }
        if !materialised {
            eprintln!(
                "LIBP2P-ANNOUNCE-AFTER-FETCH skipped narhash={key} reason=not-materialised \
                 (store path {store_path:?} did not appear within the wait bound; not announced)"
            );
            return None; // clean pre-publication failure -> refund
        }

        // The validate+dump+verify is blocking; run it off the async worker. All failures here are
        // CLEAN (no DHT side-effect yet) -> refund.
        let worker = self.clone();
        let k = *key;
        let sp = store_path.to_string();
        let verified =
            tokio::task::spawn_blocking(move || worker.eligible_provisions(&k, &sp)).await;
        let provisions = match verified {
            Ok(Ok(p)) => p,
            Ok(Err(why)) => {
                eprintln!(
                    "LIBP2P-ANNOUNCE-AFTER-FETCH skipped narhash={key} reason=ineligible: {why}"
                );
                return None;
            }
            Err(join) => {
                eprintln!(
                    "LIBP2P-ANNOUNCE-AFTER-FETCH skipped narhash={key} reason=verify-panicked: {join}"
                );
                return None;
            }
        };

        // Announce each verified provision (one per fetched key). FIX D: `announce_one` classifies
        // the announce outcome by whether a DHT side-effect could have occurred, so a CLEAN
        // pre-publication failure (e.g. `AnnounceError::Persist`, raised BEFORE `start_providing`)
        // REFUNDS (returns `None`) while a Published/Ambiguous outcome SPENDS + tracks (returns
        // `Some`). A CleanFailure short-circuits: no `Some` was set, so the caller refunds.
        let mut content_key = None;
        for provision in &provisions {
            match self.announce_one(provision).await.into_grow_result() {
                Some(ck) => content_key = Some(ck),
                None => return None, // clean pre-publication failure -> refund
            }
        }
        content_key
    }
}

/// The seam that turns a reserved fetch into a spawned dispatch (TASK-77 FIX 1). It DECOUPLES the
/// announce side-effect from `on_fetched`'s budget gate, so the production budget bite - drive
/// `on_fetched` and count grows - needs no live swarm. The production impl also RECONCILES GC'd
/// holdings on every fetch (FIX 3b).
trait GrowSpawner: Send + Sync {
    /// On EVERY fetch: reconcile GC'd holdings (FIX 3b), and - iff `grow` is `Some` (the fetch was
    /// admitted by the budget gate) - run the grow for that reserved key, committing the outcome
    /// back to `ledger`. Running reconcile on every fetch (not only on a grow) means a
    /// budget-exhausted node still self-heals its stale holdings.
    fn dispatch(&self, ledger: Arc<Mutex<AnnounceLedger>>, grow: Option<(NarHashKey, String)>);
}

/// The production [`GrowSpawner`]. Its [`run`](WorkerSpawner::run) body - self-heal GC'd holdings,
/// then (if admitted) grow + commit - is async over its `Arc<dyn>` deps, so the production-wired
/// GC/retry bites drive `run` DIRECTLY with fakes (removing the `reconcile` call in `run` reddens
/// the GC bite). `dispatch` is the thin `tokio::spawn(run(..))` fire-and-forget wrapper.
struct WorkerSpawner {
    grower: Arc<dyn Grower>,
    withdrawer: Arc<dyn Withdrawer>,
}

impl WorkerSpawner {
    /// The production dispatch BODY (what `dispatch` spawns): reconcile GC'd holdings, then (if
    /// admitted) grow + commit its outcome. `commit_success` on a published/ambiguous grow (track +
    /// keep budget spent); `commit_failure` (REFUND) on a clean pre-publication failure.
    async fn run(
        ledger: Arc<Mutex<AnnounceLedger>>,
        grower: Arc<dyn Grower>,
        withdrawer: Arc<dyn Withdrawer>,
        grow: Option<(NarHashKey, String)>,
    ) {
        // FIX 3b: WITHDRAW any holding whose store path was GC'd since we announced it. Runs on
        // EVERY fetch, so an exhausted-budget node still reconciles. Timer-free; an IDLE node
        // relies on the clean serve-fail + record TTL (the documented eventually-consistent
        // residual - see the module doc).
        reconcile(&ledger, &*withdrawer).await;
        if let Some((key, store_path)) = grow {
            match grower.grow(&key, &store_path).await {
                Some(content_key) => commit_success(&ledger, &key, content_key, store_path),
                None => commit_failure(&ledger, &key),
            }
        }
    }
}

impl GrowSpawner for WorkerSpawner {
    fn dispatch(&self, ledger: Arc<Mutex<AnnounceLedger>>, grow: Option<(NarHashKey, String)>) {
        let grower = Arc::clone(&self.grower);
        let withdrawer = Arc::clone(&self.withdrawer);
        // Fire-and-forget: never blocks the serve path. Honest limit: a detached task is not tied to
        // a shutdown supervisor, so an in-flight announce is dropped on process exit - acceptable
        // for a best-effort growth announce (kad republish / TTL cover it).
        tokio::spawn(WorkerSpawner::run(ledger, grower, withdrawer, grow));
    }
}

/// The libp2p ANNOUNCE-AFTER-FETCH authority (TASK-77): the backend impl of the fabric-neutral
/// [`PostFetchAnnounce`] seam. It shares the provider's [`AvailabilityIndex`] (so a path it
/// registers becomes servable through the same `CatalogNarSupplier` reverse-map) and the
/// fabric's announcer (so every announce goes through the TASK-231 eligibility authority - no
/// bypass). On a successful fetch it: reserves a budget unit (AC#2), waits for the local store to
/// materialise the path, VALIDATES + verifies `sha256(--dump)==NarHash` (AC#3 / TASK-72:
/// index-coverage == provider-coverage), announces via the SAME verified door the shipped provider
/// uses, and reconciles/withdraws GC'd holdings (FIX 3b). An ineligible/failed fetch REFUNDS its
/// budget unit (FIX 2).
pub struct Libp2pAnnounceAfterFetch {
    ledger: Arc<Mutex<AnnounceLedger>>,
    spawner: Arc<dyn GrowSpawner>,
    /// The configured announce budget CAP (TASK-77 AC#2), retained so the live status surface can
    /// report `used = cap - remaining` (TASK-240 AC#4) from the SAME ledger the gate enforces.
    budget_cap: u64,
}

impl Libp2pAnnounceAfterFetch {
    /// Build the hook. `announce_budget_count` is the INTEGER number of distinct fetched paths this
    /// process may announce (AC#2); `index`/`fabric`/`identity_seed` MUST be the SAME ones the
    /// provider serve path + announcer use, so a registered path is servable and every announce (and
    /// withdrawal) is signed by this node and re-checked by its eligibility authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fabric: Arc<Libp2pFabric>,
        identity_seed: [u8; 32],
        index: Arc<AvailabilityIndex>,
        door: AnnounceAfterFetchDoor,
        serve_budget: peer_fabric::ServeBudget,
        announce_budget: AnnounceBudget,
        ttl_secs: u64,
        store_dir: String,
        announce_budget_count: u64,
        // TASK-279 AC#1: the NarHashes the DURABLE memory-resident seed leg owns. The hook is a strict
        // no-op for these (never grows/tracks/withdraws them), so a store-path GC can never tombstone
        // the seed leg's own never-GC'd announce. Empty when there is no seed leg.
        seed_owned: HashSet<NarHashKey>,
    ) -> Self {
        let worker = GrowWorker {
            fabric: Arc::clone(&fabric),
            identity_seed,
            index,
            door,
            serve_budget,
            announce_budget,
            ttl_secs,
            store_dir,
            materialise: MaterialiseWait::default(),
        };
        let grower: Arc<dyn Grower> = Arc::new(worker);
        let withdrawer: Arc<dyn Withdrawer> = Arc::new(FabricWithdrawer { fabric });
        Libp2pAnnounceAfterFetch {
            ledger: Arc::new(Mutex::new(AnnounceLedger {
                remaining: announce_budget_count,
                inflight: HashSet::new(),
                announced: HashSet::new(),
                held: HashMap::new(),
                seed_owned,
            })),
            spawner: Arc::new(WorkerSpawner { grower, withdrawer }),
            budget_cap: announce_budget_count,
        }
    }

    /// The remaining budget (test/observability).
    pub fn remaining_budget(&self) -> u64 {
        self.ledger
            .lock()
            .expect("announce ledger poisoned")
            .remaining
    }
}

impl PostFetchAnnounce for Libp2pAnnounceAfterFetch {
    fn on_fetched(&self, nar_hash: &NarHash, store_path: &str) {
        let key = match NarHashKey::from_str(nar_hash.as_str()) {
            Ok(k) => k,
            // A NarHash that is not a canonical p2p key can never be a discovery key; nothing to
            // announce (the UpstreamPath cold-start path never reaches here anyway).
            Err(_) => return,
        };
        // AC#2 (FIX 1): the budget gate the PRODUCTION path consults. Only a `Proceed` carries a
        // grow; removing this `begin` CALL - or the `remaining == 0` guard inside it - makes the
        // grow/announce count grow unbounded, which the production budget bite (drive on_fetched,
        // count grows) catches. `dispatch` ALSO reconciles GC'd holdings on every fetch (FIX 3b),
        // so it is called regardless of the budget outcome.
        let grow = match begin(&self.ledger, &key) {
            Begin::Proceed => Some((key, store_path.to_string())),
            Begin::AlreadyHandled => None,
            // TASK-279 AC#1: the durable seed leg OWNS discovery for this key (it announced it once at
            // startup and never GCs). The hook must not grow/track/withdraw it, or a later store-path
            // GC would tombstone the seed leg's still-valid announce (served-but-not-announced). No
            // grow; `dispatch` still runs reconcile for the OTHER (genuinely grown) holdings.
            Begin::SeedOwned => None,
            Begin::Exhausted => {
                eprintln!(
                    "LIBP2P-ANNOUNCE-AFTER-FETCH budget-exhausted narhash={key} \
                     (announce budget spent; not announcing - swarm growth is capped here)"
                );
                None
            }
        };
        self.spawner.dispatch(Arc::clone(&self.ledger), grow);
    }

    /// TASK-240 AC#4: the announce budget CONSUMED so far, read from the SAME ledger the gate
    /// enforces — `cap - remaining`, saturating (a reseeded-from-disk remaining can never exceed
    /// the cap in practice, but saturate rather than underflow).
    fn budget_used(&self) -> Option<u64> {
        Some(self.budget_cap.saturating_sub(self.remaining_budget()))
    }
}

// -------------------------------------------------------------------------
// The PUBLIC-ANNOUNCE door for raw SEEDS (`--libp2p-seed-nar`): the seed
// counterpart of the StoreProvision public door above. The shipped seed-supply
// provider (`daemon`/`daemon-libp2p`) uses it to announce over a PUBLIC (bootstrapped)
// substrate, gated on the same public-NAR allowlist. Seeds and store provisions are
// DISTINCT capabilities (a seed carries raw bytes; a provision carries an index-verified
// digest), so publicness is gated by a parallel typed door rather than by fabricating a
// `StoreProvision` from a byte string.
// -------------------------------------------------------------------------

/// A TASK-56-verified raw seed PAIRED with the allowlist [`PublicNarClaim`] that authorises
/// announcing it PUBLICLY. Private fields, minted ONLY by [`approve_seeds_for_public`], so a
/// public seed announce CANNOT be represented without an allowlist-minted claim - the claim is
/// LOAD-BEARING (held through the announce), the seed analogue of [`ApprovedPublicProvision`].
#[derive(Debug, Clone)]
pub struct ApprovedPublicSeed {
    nar_hash: NarHashKey,
    bytes: Vec<u8>,
    /// The unforgeable proof the allowlist approved this NAR for public announce. Held (never
    /// discarded) so this capability cannot exist without it.
    claim: PublicNarClaim,
}

impl ApprovedPublicSeed {
    /// The NAR identity this seed will announce.
    pub fn nar_hash(&self) -> &NarHashKey {
        &self.nar_hash
    }

    /// The allowlist claim authorising the PUBLIC announce of this seed's NAR.
    pub fn claim(&self) -> &PublicNarClaim {
        &self.claim
    }
}

/// CONSULT the public-NAR allowlist for a batch of raw seeds a node intends to announce
/// PUBLICLY, minting one [`PublicNarClaim`] per seed. FAIL-CLOSED and ALL-OR-NOTHING: if ANY
/// seed is not allowlisted (never proven public via a trusted narinfo signature), the WHOLE
/// batch is refused and NO claim is minted, so no partial announce can leak an un-approved NAR.
///
/// The size the allowlist gates on is `bytes.len()` - the raw UNCOMPRESSED NAR length, which is
/// exactly the signed NarSize a trusted narinfo proved. A wrong-length seed is refused as a
/// [`PublicationRejected::SizeMismatch`] here; a right-length-but-wrong-CONTENT seed is refused
/// by the TASK-56 `verify_provider_seeds` check inside the shared announce loop. The seed analogue
/// of [`approve_provisions_for_public`]; a PURE function of `(seeds, allowlist)`, so the
/// closed-by-construction gate is unit-testable without a DHT.
pub fn approve_seeds_for_public(
    seeds: &[(NarHashKey, Vec<u8>)],
    allowlist: &PublicNarAllowlist,
) -> Result<Vec<ApprovedPublicSeed>, PublicationRejected> {
    let mut approved = Vec::with_capacity(seeds.len());
    for (nar_hash, bytes) in seeds {
        // `approve` mints an UNFORGEABLE PublicNarClaim iff the NarHash is allowlisted AND its
        // approved size equals this seed's byte length. Absence -> fail-closed. The claim is
        // PAIRED with the seed and HELD through the announce.
        let claim = allowlist.approve(nar_hash, Some(bytes.len() as u64))?;
        approved.push(ApprovedPublicSeed {
            nar_hash: *nar_hash,
            bytes: bytes.clone(),
            claim,
        });
    }
    Ok(approved)
}

/// Announce a signed [`ProviderRecord`] for each raw seed, but ONLY after the public-NAR
/// allowlist has PROVEN every one publishable (TASK-102). The PUBLIC analogue of
/// [`announce_provider_seeds`] and the seed counterpart of [`announce_public_provisions`]: it
/// FIRST runs [`approve_seeds_for_public`] (fail-closed, all-or-nothing) and announces nothing
/// if any seed is un-allowlisted, then reuses the SAME verified-content announce loop
/// ([`announce_seed_records`]) a LAN announce uses. CONSUMING the minted [`ApprovedPublicSeed`]s
/// (claim held to the announce) is what makes a public seed announce with no allowlist-minted
/// claim UNREPRESENTABLE - there is no bare-seed public entry point.
pub async fn announce_public_seeds(
    fabric: &Libp2pFabric,
    readiness: &ProviderRelayReadiness,
    config: InitialAnnounceConfig<'_>,
    seeds: &[(NarHashKey, Vec<u8>)],
    allowlist: &PublicNarAllowlist,
) -> Result<Vec<ProviderRecord>, String> {
    // THE GATE (fail-closed, before any record is signed or announced): every seed must be
    // allowlisted, minting a claim-bearing capability, or the whole public announce is refused.
    let approved = approve_seeds_for_public(seeds, allowlist)
        .map_err(|rejected| format!("public announce refused by the allowlist gate: {rejected}"))?;
    announce_approved_seeds(fabric, readiness, config, &approved, allowlist).await
}

/// Announce a record per ALREADY-APPROVED [`ApprovedPublicSeed`] (the public-seed counterpart of
/// [`announce_approved_public`]). Split out of [`announce_public_seeds`] so a caller that has ALREADY
/// authorized the seed leg (TASK-279 AC#2 authorize-all-first) announces WITHOUT re-approving. The
/// claim is held to HERE, so a public seed announce is unrepresentable without an allowlist-minted
/// claim; the witness is minted from the SAME allowlist (allowlist-gated), distinct from the LAN
/// door's AdmitAll witness.
async fn announce_approved_seeds(
    fabric: &Libp2pFabric,
    readiness: &ProviderRelayReadiness,
    config: InitialAnnounceConfig<'_>,
    approved: &[ApprovedPublicSeed],
    allowlist: &PublicNarAllowlist,
) -> Result<Vec<ProviderRecord>, String> {
    // Reconstruct the (already-verified) seeds for the shared loop.
    let approved_seeds: Vec<(NarHashKey, Vec<u8>)> = approved
        .iter()
        .map(|a| {
            debug_assert_eq!(a.claim().nar_hash(), &a.nar_hash);
            (a.nar_hash, a.bytes.clone())
        })
        .collect();
    announce_seed_records(
        fabric,
        readiness,
        config,
        &approved_seeds,
        &AllowlistWitnessAuthority { allowlist },
    )
    .await
}

/// TASK-279 AC#2 (TRANSACTION — authorize-all-first): authorize EVERY public leg (seeds AND
/// provisions) against the allowlist BEFORE any record is announced. ALL-OR-NOTHING: `?` short-
/// circuits on the FIRST refusal from EITHER leg, so a refusal returns `Err` with NO partial
/// approval — the caller then announces nothing.
///
/// This closes the non-atomic publish window: the provider install path used to
/// `announce_public_seeds` (which PUBLISHES the seed records to the DHT) and only THEN
/// `announce_public_provisions` (which authorizes the provision leg). An un-allowlisted provision
/// would `Err` the whole startup AFTER the seed records were already on the wire, leaving them to
/// linger to their TTL. Authorizing both legs up front means one refused leg publishes zero records.
pub fn authorize_public_supply(
    seeds: &[(NarHashKey, Vec<u8>)],
    provisions: &[StoreProvision],
    allowlist: &PublicNarAllowlist,
) -> Result<(Vec<ApprovedPublicSeed>, Vec<ApprovedPublicProvision>), PublicationRejected> {
    let approved_seeds = approve_seeds_for_public(seeds, allowlist)?;
    let approved_provisions = approve_provisions_for_public(provisions, allowlist)?;
    Ok((approved_seeds, approved_provisions))
}

/// TASK-279 AC#2: announce a PUBLIC provider's WHOLE additive supply ATOMICALLY w.r.t. allowlist
/// authorization — authorize every leg FIRST ([`authorize_public_supply`]), and only then announce
/// the approved seeds AND provisions. On ANY allowlist refusal, NO record is published (authorize
/// fails before the first announce). Returns `(seed_records, provision_records)`, index-aligned with
/// `seeds` / `provisions`.
///
/// It REPLACES the previous per-leg `announce_public_seeds` + `announce_public_provisions` call
/// sequence in the provider install path, whose ordering published the seed records before the
/// provision leg was authorized (the non-atomic window this closes). A PHASE-2 (post-authorization)
/// failure is NOT an allowlist refusal (authorization already passed in phase 1); beyond that it can
/// be ANY of the announce path's error kinds — a relay-readiness capture failure, the TASK-56 seed
/// content re-verification, the announcer's TASK-231 fail-closed eligibility re-check, a save-before-
/// publish persistence error, an unreachable/network error, or a deadline — not "only a network
/// error". Because the two legs announce in SEQUENCE, a failure on the LATER leg cannot roll back the
/// EARLIER leg already on the wire; the empty-leg guard below removes the specific footgun where an
/// EMPTY later leg's (unconditional) readiness capture fails AFTER the earlier leg published, leaving
/// it to linger to TTL with no rollback.
pub async fn announce_public_supply(
    fabric: &Libp2pFabric,
    readiness: &ProviderRelayReadiness,
    config: InitialAnnounceConfig<'_>,
    seeds: &[(NarHashKey, Vec<u8>)],
    provisions: &[StoreProvision],
    allowlist: &PublicNarAllowlist,
) -> Result<(Vec<ProviderRecord>, Vec<ProviderRecord>), String> {
    // PHASE 1 — authorize EVERY leg before announcing ANY record (fail-closed, all-or-nothing).
    let (approved_seeds, approved_provisions) =
        authorize_public_supply(seeds, provisions, allowlist).map_err(|rejected| {
            format!("public announce refused by the allowlist gate: {rejected}")
        })?;
    // PHASE 2 — every leg is authorized; announce each NON-EMPTY leg (config is Copy, reused per leg).
    //
    // EMPTY-LEG GUARD (codex MED): announce_approved_seeds/public capture relay-readiness
    // UNCONDITIONALLY — even for an empty batch (`readiness.capture(fabric).await?` runs before the
    // per-record loop) — and that capture is FALLIBLE. Announcing the empty leg would therefore do
    // fallible work for nothing; worse, for an EMPTY PROVISION leg that failure fires AFTER seed S is
    // already on the wire, and phase-2's sequential legs give NO rollback, so S lingers to TTL. So an
    // empty approved leg is SKIPPED (its records are trivially empty), never announced.
    let seed_records = if approved_seeds.is_empty() {
        Vec::new()
    } else {
        announce_approved_seeds(fabric, readiness, config, &approved_seeds, allowlist).await?
    };
    let provision_records = if approved_provisions.is_empty() {
        Vec::new()
    } else {
        announce_approved_public(fabric, readiness, config, &approved_provisions, allowlist).await?
    };
    Ok((seed_records, provision_records))
}

// -------------------------------------------------------------------------
// TASK-285: PERIODIC RE-SIGN of the durable seed leg's provider records.
//
// The durable `--libp2p-seed-nar` leg announces its provider records ONCE at startup with an
// absolute SIGNED expiry (`now + ttl_secs`, capped at MAX_RECORD_TTL_SECS). libp2p-kad's native
// republishing re-provides the SAME signed bytes but CANNOT extend that signed expiry, so past the
// TTL a consumer's decode rejects the record (`RecordDecodeError::Stale`) and the seed goes
// UNDISCOVERABLE until the daemon restarts. This background task re-SIGNS a FRESH record (new
// issued_at/expiry, the NEXT monotonic sequence) BEFORE the signed expiry, so a continuously-running
// seeding node stays discoverable for its seeded NarHashes indefinitely (AC#1).
// -------------------------------------------------------------------------

/// The interval (INTEGER seconds) between seed re-sign cycles for a record TTL of `ttl_secs`: half
/// the TTL by integer division, floored at 1s. Re-announcing at `ttl/2` mints a fresh record while
/// the prior one still has ~half its TTL left, so a continuously-running seed never lapses — for
/// `ttl_secs >= 2`, `ttl/2` is STRICTLY less than `ttl_secs`. NO float: pure integer halving. (For a
/// degenerate `ttl_secs < 2` — never a production value, the CLI rejects it — the floor makes the
/// interval 1s, which is not strictly inside a 1s TTL; the lapse-free guarantee is stated for
/// `ttl_secs >= 2`.)
fn seed_resign_interval_secs(ttl_secs: u64) -> u64 {
    (ttl_secs / 2).max(1)
}

/// The publication authority a periodic seed RE-SIGN cycle re-announces under (TASK-285). It MIRRORS
/// the initial seed announce door so a re-signed record passes the SAME eligibility gate, never a
/// weaker one:
///   * [`Lan`](Self::Lan) — the AdmitAll LAN door ([`announce_provider_seeds`]).
///   * [`Public`](Self::Public) — the allowlist-gated public door ([`announce_public_seeds`]); the
///     allowlist is HELD so each cycle RE-PROVES every seed publishable (fail-closed if a NAR were
///     ever de-allowlisted), exactly as the initial public announce.
pub enum SeedResignAuthority {
    /// A no-allowlist lan-share provider: re-sign under the AdmitAll LAN witness.
    Lan,
    /// A public (allowlist-gated) provider: re-sign under the allowlist witness authority.
    Public(Arc<PublicNarAllowlist>),
}

/// A running seed RE-SIGN task (TASK-285 AC#1). Owning it keeps the SUPERVISOR loop alive; the
/// provider install path stores it in its guard so the loop lives as long as the serving process.
///
/// DROP aborts the SUPERVISOR JoinHandle so no further cycles are scheduled. It does NOT cancel a
/// cycle that is ALREADY IN FLIGHT: the supervisor `await`s each cycle in its own `tokio::spawn`
/// child, and aborting the supervisor at that await DETACHES the child rather than cancelling it, so
/// an in-flight re-sign runs to completion and can still publish AFTER the drop. That is harmless
/// under the TCB — a late but signed, strictly-monotonic positive SUPERSEDE (never a rollback, never
/// a tombstone) — but it means "no leaked in-flight work" is not guaranteed at the drop instant.
pub struct SeedResignTask {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for SeedResignTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The result of ONE seed re-sign cycle (TASK-285). Per-seed isolation (HIGH-2): a seed that fails
/// this cycle lands in `failed` (logged, retried next cycle) WITHOUT aborting the others' refresh, so
/// one persistently-unreachable seed can never starve a healthy seed into permanent expiry.
#[derive(Debug, Default)]
pub struct SeedResignOutcome {
    /// The seeds freshly re-signed + announced this cycle (each a strictly-superseding record).
    pub records: Vec<ProviderRecord>,
    /// The seeds that FAILED this cycle (per-seed verify or announce), isolated from the rest. Each
    /// retries next cycle; its prior record stays valid until its own signed expiry regardless.
    pub failed: Vec<(NarHashKey, String)>,
}

/// Run ONE seed re-sign cycle (TASK-285): for EACH durable seed INDEPENDENTLY, allocate the NEXT
/// monotonic sequence, sign a FRESH record (new `issued_at`/`expiry` from a fresh `now`), and announce
/// it through the SAME anti-rollback + save-before-publish path the initial announce uses
/// ([`announce_one_verified_seed`] → [`Libp2pFabric::next_announce_sequence`] →
/// `Libp2pAvailabilityAnnouncer::announce`). Reusing that SSOT is what makes the re-sign monotonic
/// (strictly-higher sequence, never a rollback/reuse) AND fail-closed (the advanced floor is persisted
/// BEFORE the DHT publish) — AC#3 — with NO second announce path to drift. A re-sign is always a
/// SUPERSEDE (a strictly-newer positive record), never a tombstone/withdraw.
///
/// HIGH-2 (per-seed isolation): unlike the initial [`announce_seed_records`] (all-or-nothing), this
/// isolates each seed - a verify/announce failure for one seed is collected into
/// [`SeedResignOutcome::failed`] and the loop CONTINUES, so a persistently-failing seed cannot starve
/// the healthy ones out of their refresh. A NODE-LEVEL fault (no announcer, relay-readiness capture)
/// returns `Err` (the whole cycle retries next interval); only PER-SEED faults are isolated.
///
/// Exposed so the loop, an operator-triggered manual refresh, and the AC#3 test can drive exactly ONE
/// re-sign cycle deterministically (the loop just calls it on a timer).
pub async fn resign_seed_records_once(
    fabric: &Libp2pFabric,
    readiness: &ProviderRelayReadiness,
    identity_seed: [u8; 32],
    seeds: &[(NarHashKey, Vec<u8>)],
    ttl_secs: u64,
    budget: &AnnounceBudget,
    authority: &SeedResignAuthority,
) -> Result<SeedResignOutcome, String> {
    let announcer = fabric
        .announcer()
        .ok_or_else(|| "internal: libp2p provider fabric exposes no announcer".to_string())?;
    // NODE-LEVEL capture (fail the whole cycle, retry next interval): one live route snapshot every
    // re-signed record in this cycle states, exactly as the initial announce.
    let relay_hints = readiness.capture(fabric).await?;
    // Bind the witness authority so its borrow outlives the loop (the Public arm borrows the
    // allowlist). It MIRRORS the initial announce door so a re-signed record passes the SAME gate.
    let admit_all = AdmitAllPublication;
    let allow_auth = match authority {
        SeedResignAuthority::Public(allowlist) => Some(AllowlistWitnessAuthority {
            allowlist: allowlist.as_ref(),
        }),
        SeedResignAuthority::Lan => None,
    };
    let witness_authority: &dyn PublicationEligibility = match &allow_auth {
        Some(auth) => auth,
        None => &admit_all,
    };
    let mut outcome = SeedResignOutcome::default();
    for seed in seeds {
        let (nar_hash, bytes) = seed;
        // Per-seed TASK-56 re-verify (isolated): a corrupted seed is refused WITHOUT blocking the
        // others - it never announces a false claim, and a healthy sibling still refreshes.
        if let Err(e) = verify_provider_seeds(std::slice::from_ref(seed)) {
            outcome.failed.push((*nar_hash, e.to_string()));
            continue;
        }
        // FIX 1: re-time PER SEED. Each seed signs from its OWN fresh `now`, so its `expiry =
        // now + ttl_secs` is fresh at sign time. Because the seeds are signed SEQUENTIALLY and a
        // slow earlier seed can burn up to ANNOUNCE_QUORUM_RETRY_WINDOW_SECS (30s) in its bounded
        // put-quorum retry, one shared `now` captured before the loop could leave a LATER seed
        // signed with an already-elapsed `now + ttl` at a small TTL — which `announce` then rejects
        // as `record.expiry <= now`. A fresh `now` per seed keeps every record's validity window
        // forward at the moment it is minted. (Integer seconds, no float.)
        let config = InitialAnnounceConfig::new(identity_seed, ttl_secs, now_unix_secs(), budget);
        match announce_one_verified_seed(
            fabric,
            &**announcer,
            relay_hints,
            &config,
            nar_hash,
            bytes,
            witness_authority,
        )
        .await
        {
            Ok(record) => outcome.records.push(record),
            Err(e) => outcome.failed.push((*nar_hash, e)),
        }
    }
    Ok(outcome)
}

/// The SUPERVISED re-sign loop (TASK-285 HIGH-3): sleep one interval, then run ONE cycle IN A CHILD
/// TASK so a panic inside the cycle is caught as a `JoinError`, logged at ERROR, and the loop
/// CONTINUES - the durability task can never silently die from a cycle panic. All logging is
/// `tracing` (never `println!`/`eprintln!`, which PANIC on a closed output pipe (EPIPE) - the other
/// silent-death vector). Generic over the cycle so the supervision (panic isolation + continue) is
/// unit-testable without a live fabric. Never returns (the caller aborts it on shutdown).
async fn run_resign_supervised<F, Fut>(interval: Duration, mut cycle: F)
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<SeedResignOutcome, String>> + Send + 'static,
{
    loop {
        // Sleep FIRST: the initial announce already published; the earliest a record needs a refresh
        // is one interval later.
        tokio::time::sleep(interval).await;
        match tokio::spawn(cycle()).await {
            Ok(Ok(outcome)) => {
                if outcome.failed.is_empty() {
                    tracing::info!(
                        re_signed = outcome.records.len(),
                        next_secs = interval.as_secs(),
                        "LIBP2P-SEED-RESIGN cycle re-signed all seeds"
                    );
                } else {
                    tracing::warn!(
                        re_signed = outcome.records.len(),
                        failed = outcome.failed.len(),
                        "LIBP2P-SEED-RESIGN cycle: some seeds failed this cycle (isolated; each \
                         retried next cycle; their prior records stay valid until signed expiry)"
                    );
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    "LIBP2P-SEED-RESIGN cycle fault (whole cycle retried next interval; prior \
                     records valid until their signed expiry)"
                );
            }
            Err(join_err) => {
                // The cycle PANICKED: the child task died, but the supervisor loop continues, so the
                // durability feature is NOT silently dead. Loud ERROR so an operator notices.
                tracing::error!(
                    error = %join_err,
                    "LIBP2P-SEED-RESIGN cycle PANICKED; supervisor loop continues (durability task \
                     is NOT dead) - the next interval retries"
                );
            }
        }
    }
}

/// Spawn the periodic seed RE-SIGN background task (TASK-285 AC#1): a supervised loop, OFF the swarm
/// poll loop (a `tokio::spawn`, like the announce-after-fetch dispatch), that re-signs + re-announces
/// every durable `--libp2p-seed-nar` record BEFORE its signed expiry, so a continuously-running
/// seeding node stays discoverable for its seeded NarHashes INDEFINITELY (no 24h TTL cliff, no
/// restart).
///
/// Cadence: [`seed_resign_interval_secs`] = `ttl_secs / 2` (integer), strictly inside the TTL for
/// `ttl_secs >= 2`, so a record never lapses. Each cycle mints the NEXT monotonic sequence and
/// persists the advanced floor BEFORE publishing (AC#3), via the shared SSOT
/// [`resign_seed_records_once`] — never a parallel announce path.
///
/// OWNERSHIP (TASK-279 discipline, non-overlapping): this task owns the SEED keys; the
/// announce-after-fetch hook owns GROWN keys (its `seed_owned` set makes it a strict no-op on these),
/// so the two never both mint a record for the same key.
///
/// SUPERVISION (HIGH-3): the loop runs each cycle in a child task and survives a cycle panic (logged
/// ERROR, loop continues); a per-seed failure is isolated (HIGH-2); a whole-cycle fault retries next
/// interval. Returns `None` for an EMPTY seed set (nothing to re-sign).
pub fn spawn_seed_resign(
    fabric: Arc<Libp2pFabric>,
    readiness: ProviderRelayReadiness,
    identity_seed: [u8; 32],
    seeds: Vec<(NarHashKey, Vec<u8>)>,
    ttl_secs: u64,
    budget: AnnounceBudget,
    authority: SeedResignAuthority,
) -> Option<SeedResignTask> {
    if seeds.is_empty() {
        return None;
    }
    let interval = Duration::from_secs(seed_resign_interval_secs(ttl_secs));
    let key_count = seeds.len();
    tracing::info!(
        seeds = key_count,
        ttl_secs,
        interval_secs = interval.as_secs(),
        "LIBP2P-SEED-RESIGN enabled"
    );
    // Share the immutable inputs so each cycle spins up a fresh future in its own child task.
    let seeds = Arc::new(seeds);
    let authority = Arc::new(authority);
    let task = tokio::spawn(run_resign_supervised(interval, move || {
        let fabric = Arc::clone(&fabric);
        let readiness = readiness.clone();
        let seeds = Arc::clone(&seeds);
        let authority = Arc::clone(&authority);
        async move {
            resign_seed_records_once(
                &fabric,
                &readiness,
                identity_seed,
                seeds.as_slice(),
                ttl_secs,
                &budget,
                &authority,
            )
            .await
        }
    }));
    Some(SeedResignTask { task })
}

#[cfg(test)]
mod seed_resign_supervision_tests {
    //! TASK-285 HIGH-3: the supervised re-sign loop must SURVIVE a panicking cycle (never silently
    //! die), so the durability feature keeps refreshing. Driven through the REAL supervision body
    //! [`run_resign_supervised`], no live fabric needed.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::{SeedResignOutcome, run_resign_supervised};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn supervisor_survives_a_panicking_cycle() {
        // The FIRST cycle PANICS; the supervisor must catch it and keep running, so the counter
        // advances well past the panic. BITE: run the cycle INLINE (`cycle().await`) instead of in a
        // child task and the panic kills the whole loop -> the counter sticks at 1 and this times out.
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let handle = tokio::spawn(run_resign_supervised(
            Duration::from_millis(20),
            move || {
                let c = Arc::clone(&c);
                async move {
                    let n = c.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        panic!("cycle 0 panics on purpose");
                    }
                    Ok(SeedResignOutcome::default())
                }
            },
        ));

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if count.load(Ordering::SeqCst) >= 4 {
                break; // it ran the panicking cycle AND several more -> the supervisor survived.
            }
            assert!(
                Instant::now() < deadline,
                "the supervisor did not keep running past the panicking cycle (count={})",
                count.load(Ordering::SeqCst)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        handle.abort();
    }
}

/// Build the node's ONE public-NAR allowlist (TASK-103), the single authority the PUBLIC announce
/// door ([`announce_public_seeds`] / [`announce_public_provisions`]) consults AND the serving
/// daemon learns into (`App::public_allowlist`). This is the SINGLE SOURCE OF TRUTH for the
/// config->allowlist wiring: BOTH the composite `daemon` binary and the thin `daemon-libp2p`
/// binary call it from their parsed CLI, so their publication policy cannot drift (TASK-204).
///
/// Without `allowlist_path` this returns a DISABLED allowlist (no trusted keys, in-memory,
/// `contains` always false) - the pre-TASK-103 behaviour, so a non-public node is unchanged. WITH
/// a path it opens the MAC-integrity-protected file (key derived from the durable identity seed via
/// [`derive_allowlist_mac_key`]) and POPULATES it by PROVING each `prove_public_narinfo` public
/// through the trusted-key signature gate: the operator NAMING a seed/store path never makes it
/// public - only a trusted narinfo signature does. A narinfo that does not prove public,
/// mis-correlates to its requested store hash, or fails to persist is a LOUD startup error
/// (fail-closed), never a silently-empty allowlist.
///
/// `prove_public_narinfo` is a slice of `(requested-store-hash, path-to-narinfo)`: the store hash
/// the narinfo must correlate to (its signed `StorePath`'s `<hash>`) and the narinfo file to prove.
pub fn open_public_allowlist(
    allowlist_path: Option<&Path>,
    trusted_public_keys: &[String],
    identity_seed: &[u8; 32],
    prove_public_narinfo: &[(String, String)],
) -> Result<Arc<PublicNarAllowlist>, String> {
    let Some(path) = allowlist_path else {
        return Ok(Arc::new(PublicNarAllowlist::disabled()));
    };
    let trusted = TrustedNarKeys::from_lines(trusted_public_keys)
        .map_err(|e| format!("--libp2p-trusted-public-key: {e}"))?;
    // Guard here too (the CLI layer also rejects this) so the function is safe to call in
    // isolation: a disabled-by-emptiness allowlist proves nothing, a silent no-op public provider.
    if trusted.is_empty() {
        return Err(
            "internal: public allowlist path set with no trusted keys (the CLI should have rejected this)".into(),
        );
    }
    let mac_key = derive_allowlist_mac_key(identity_seed);
    let allowlist = PublicNarAllowlist::open_file(trusted, path.to_path_buf(), mac_key)
        .map_err(|e| format!("opening the public-NAR allowlist at {path:?}: {e}"))?;
    for (store_hash, narinfo_path) in prove_public_narinfo {
        let bytes = std::fs::read(narinfo_path)
            .map_err(|e| format!("reading --libp2p-prove-public-narinfo {narinfo_path:?}: {e}"))?;
        match allowlist.learn(&StoreHash::new(store_hash.clone()), &bytes) {
            LearnOutcome::Appended { nar_hash, nar_size } => {
                // Machine-readable proof line: which NAR identity was proven public + its size.
                println!(
                    "LIBP2P-PUBLIC-LEARN store_hash={store_hash} nar_hash={nar_hash} nar_size={nar_size}"
                );
            }
            LearnOutcome::AlreadyPresent { nar_hash } => {
                println!(
                    "LIBP2P-PUBLIC-LEARN store_hash={store_hash} nar_hash={nar_hash} already_present"
                );
            }
            LearnOutcome::Rejected(reject) => {
                return Err(format!(
                    "--libp2p-prove-public-narinfo {store_hash}: narinfo did not prove public: {reject}"
                ));
            }
            LearnOutcome::RequestMismatch { requested, signed } => {
                return Err(format!(
                    "--libp2p-prove-public-narinfo {store_hash}: the signed narinfo is for store hash {signed}, not the requested {requested} (mis-correlated response)"
                ));
            }
            LearnOutcome::PersistFailed(e) => {
                return Err(format!(
                    "--libp2p-prove-public-narinfo {store_hash}: persisting the allowlist failed: {e}"
                ));
            }
        }
    }
    Ok(Arc::new(allowlist))
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
    publication_eligibility: Arc<dyn PublicationEligibility>,
) -> Result<Arc<Libp2pFabric>, String> {
    let mut node_config = NodeConfig::new(cfg.identity_seed)
        .with_network_scope(cfg.network_scope.clone())
        .with_relay_server(cfg.relay_server_enabled)
        // TASK-120 fix A: kad server/client mode from the participation profile.
        .with_kad_server(cfg.kad_server)
        // TASK-257: LAN mDNS peer-ADDRESS discovery (default OFF). When on, mDNS-discovered
        // neighbours feed the same kad bootstrap/address path, so a node with no configured
        // bootstrap converges from a same-scope LAN peer. Never a content-discovery route.
        .with_mdns(cfg.mdns_enabled)
        // TASK-280: LAN CONFINEMENT for a no-allowlist lan-share node — the dial VETO + add_address
        // LAN filtering + NAR serve-provenance gate that hold the public-isolation guarantee
        // end-to-end. `false` for every other profile (unrestricted dialing/serving).
        .with_lan_confinement(cfg.lan_confinement)
        // TASK-231 (AC#2): the announcer's per-fabric publication-eligibility authority. A pure
        // CONSUMER passes RefusePublication (it never announces); a PROVIDER injects the
        // allowlist-backed (public) or AdmitAll (isolated-LAN) decision from the composition root.
        .with_publication_eligibility(publication_eligibility);
    // TASK-218 rollout fallback: keep bootstrap relays as a flat, provider-independent set.
    // TASK-219's primary path instead takes the provider->relay binding from the exact signed
    // offer and resolves that relay's direct address through raw kad. This config is consulted
    // only for an actually empty legacy hint set; it is not an out-of-band provider-address map.
    for (peer, addr) in &cfg.bootstrap {
        node_config = node_config.with_known_relay(*peer, addr.clone());
    }
    let serving = supplier.is_some();
    // TASK-185, AC#1: a configured `state_dir` routes to the DURABLE constructors, so the
    // shipped daemon reloads its anti-rollback floor + per-key announce sequence on restart.
    // Without a `state_dir` the historical session-scoped (non-durable) path is used.
    let fabric = match (supplier, &cfg.state_dir) {
        (Some(supplier), Some(dir)) => {
            Libp2pFabric::start_with_supplier_durable(node_config, supplier, dir.clone())
        }
        (Some(supplier), None) => Libp2pFabric::start_with_supplier(node_config, supplier),
        (None, Some(dir)) => Libp2pFabric::start_durable(node_config, dir.clone()),
        (None, None) => Libp2pFabric::start(node_config),
    }
    .map_err(|e| format!("libp2p fabric start failed: {e}"))?;
    let fabric = Arc::new(fabric);

    // Composition-root REQUIRED-axis assertion (TASK-144 AC#4, the "Unsupported-axis
    // dilemma" resolution): fail fast HERE, at construction, if the selected profile needs
    // an axis this fabric does not offer - never a silent runtime degrade (a fetch that
    // always falls back, a provider that announces then cannot serve). A libp2p CONSUMER
    // needs content discovery, node-address resolution and the native libp2p fetch
    // transport; a PROVIDER additionally needs the
    // serve + announce axes. The single check lives in `peer_fabric::require_axes`, shared
    // with the iroh composition root so the two cannot drift on what "required" means.
    let mut required = vec![
        Axis::ProviderDirectory,
        Axis::NodeLocator,
        Axis::Transfer(TransportTag::Libp2p),
    ];
    if serving {
        required.push(Axis::Server);
        required.push(Axis::Announcer);
    }
    require_axes(fabric.as_ref(), &required).map_err(|missing| {
        format!("libp2p fabric does not satisfy the required axes for this profile: {missing}")
    })?;

    configure_swarm_addresses(fabric.as_ref(), cfg, DEFAULT_LISTEN_READY_TIMEOUT).await?;

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

/// Apply the complete listener/external-address set shared by both binaries. Factored only so a
/// fast test can inject a short integer bound; production always passes
/// [`DEFAULT_LISTEN_READY_TIMEOUT`].
async fn configure_swarm_addresses(
    fabric: &Libp2pFabric,
    cfg: &Libp2pSourceConfig,
    timeout: Duration,
) -> Result<(), String> {
    // Apply external self-advertisements before listener registration, then register EVERY
    // listener before waiting for any one. `listen_many` correlates readiness by ListenerId and
    // uses one absolute timeout, including circuit reservation acceptance.
    for external in &cfg.external_addresses {
        fabric.handle().add_external_address(external.clone()).await;
    }
    let listeners: Vec<Multiaddr> = cfg
        .listen
        .iter()
        .chain(cfg.additional_listens.iter())
        .cloned()
        .collect();
    if !listeners.is_empty() {
        fabric
            .handle()
            .listen_many(listeners.clone(), timeout)
            .await
            .map_err(|error| {
                let requested = listeners
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("libp2p listener readiness failed for [{requested}]: {error}")
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod provider_relay_readiness_tests {
    use super::*;
    use fabric_libp2p::Protocol;

    /// Shared-construction negative: a circuit listener pointed at a peer with its relay server
    /// disabled never becomes publication truth. A correlated terminal close may fail immediately;
    /// otherwise the one absolute injected bound stops startup promptly. Both binaries are covered
    /// because both call `start_and_join_libp2p`, whose sole address path is this helper.
    #[tokio::test]
    async fn provider_startup_refuses_a_requested_but_unaccepted_reservation() {
        let scope = "task219-shared-provider-readiness-refusal";
        let relay = Libp2pFabric::start(
            NodeConfig::new([201u8; 32])
                .with_network_scope(scope)
                .with_relay_server(false),
        )
        .expect("non-relaying kad node starts");
        relay
            .handle()
            .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .await
            .expect("non-relaying peer binds a direct address");
        let relay_address = relay
            .handle()
            .listen_addrs()
            .await
            .into_iter()
            .find(|address| address.iter().any(|part| matches!(part, Protocol::Tcp(_))))
            .expect("direct listener has a concrete TCP address");

        let provider = Libp2pFabric::start(NodeConfig::new([202u8; 32]).with_network_scope(scope))
            .expect("provider fabric starts");
        let circuit_listener = relay_address
            .with(Protocol::P2p(relay.peer_id()))
            .with(Protocol::P2pCircuit);
        let cfg = Libp2pSourceConfig {
            identity_seed: [202u8; 32],
            network_scope: scope.to_string(),
            listen: Some(circuit_listener),
            additional_listens: Vec::new(),
            external_addresses: Vec::new(),
            bootstrap: Vec::new(),
            provider_addrs: Vec::new(),
            discovery_budget: DiscoveryBudget::default(),
            envelope: SafetyEnvelope::default(),
            state_dir: None,
            relay_server_enabled: true,
            kad_server: true,
            mdns_enabled: false,
            lan_confinement: false,
        };

        let bound = Duration::from_millis(250);
        let started = tokio::time::Instant::now();
        let error = configure_swarm_addresses(&provider, &cfg, bound)
            .await
            .expect_err("startup must refuse an unaccepted reservation");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "readiness refusal exceeded its injected bound: {:?}",
            started.elapsed()
        );
        let correlated_terminal_close = error.contains("closed before NewListenAddr");
        let bounded_timeout = error.contains("did not emit NewListenAddr");
        assert!(
            error.contains("listener readiness failed")
                && (correlated_terminal_close || bounded_timeout),
            "failure must identify either the correlated terminal close or readiness timeout: {error}"
        );
    }

    /// TASK-279 AC#2 EMPTY-LEG GUARD (codex MED): `announce_public_supply` must NOT enter the fallible
    /// phase-2 announce for an EMPTY approved leg. `announce_approved_seeds`/`announce_approved_public`
    /// capture relay-readiness UNCONDITIONALLY - `readiness.capture(fabric).await?` runs BEFORE the
    /// per-record loop, even for an empty batch - and that capture is FALLIBLE. For an EMPTY provision
    /// leg that failure would fire AFTER seed S is already on the wire, and phase-2's sequential legs
    /// give no rollback, so S lingers to TTL.
    ///
    /// BITE: drive an ALL-EMPTY supply with a readiness token whose `provider` is a DIFFERENT node, so
    /// `capture()` returns Err at its FIRST (identity) check the instant ANY empty leg reaches it -
    /// deterministic, no relay wait. WITH the guards no leg is announced, so the would-fail capture is
    /// never reached -> Ok. Removing EITHER `if !approved_*.is_empty()` skip lets that leg reach capture
    /// -> Err. RED-without-guard / GREEN-with.
    #[tokio::test]
    async fn empty_legs_skip_the_fallible_phase2_readiness_capture() {
        let fabric = Libp2pFabric::start(
            NodeConfig::new([0x11u8; 32]).with_network_scope("task279-empty-leg-guard"),
        )
        .expect("provider fabric starts");
        // A readiness token whose provider is a DIFFERENT node than `fabric`, so `capture()` fails at
        // its identity check the instant any empty leg reaches it (no relay wait, no timeout).
        let mismatched = ProviderRelayReadiness {
            provider: NodeId::from_bytes([0x99u8; 32]),
            requested: RelayHints::empty(),
        };
        let budget = AnnounceBudget::new(Duration::from_secs(10), 20);
        let config = InitialAnnounceConfig::new([0x11u8; 32], 3600, 1_000, &budget);
        let allowlist = open_public_allowlist(None, &[], &[0x11u8; 32], &[])
            .expect("a disabled allowlist opens");

        // Both legs empty: WITH the guards neither leg is announced, so the mismatched (would-fail)
        // capture is NEVER reached. Removing either guard makes that empty leg call capture -> Err.
        let (seed_records, provision_records) =
            announce_public_supply(&fabric, &mismatched, config, &[], &[], &allowlist)
                .await
                .expect(
                    "an all-empty public supply must skip the fallible phase-2 announce (empty-leg \
                     guard); without it the empty leg's readiness capture fires and errors",
                );
        assert!(
            seed_records.is_empty() && provision_records.is_empty(),
            "an empty supply announces nothing"
        );
    }
}

/// The LIVE swarm-facts provider for the operator status surface (TASK-240/242). It answers the
/// two connectivity facts the stack-neutral frontend cannot compute itself (they live in the
/// backend's swarm):
///
/// * **bootstrap health** — how many of the configured bootstrap/entry peers the running swarm
///   holds an established connection to right now, via [`SwarmHandle::is_connected`]. A genuinely
///   live signal: it degrades the instant a bootstrap dies (the dependency-outage drill keys on it).
/// * **peer path** — direct vs relayed, via [`SwarmHandle::connection_path`], which reads the same
///   connection ledger `is_connected` does. `Direct` if ANY bootstrap connection is direct, else
///   `Relay` if a bootstrap is reachable only over a `/p2p-circuit`, else `Unknown` (a running swarm
///   with no classified live bootstrap connection — NEVER `None`, which is reserved for an
///   upstream-only node with no swarm at all; see [`daemon_core::PeerPath`]).
///
/// HONEST SCOPE (TASK-242): `peer_path` classifies the path to the CONFIGURED BOOTSTRAP peers (the
/// same peer set `bootstrap_healthy` counts), not a NAT-reachability verdict. A NAT'd node's
/// OUTBOUND dial to a bootstrap is typically direct even when the node itself is only reachable
/// INBOUND via a relay; the "am I publicly reachable" verdict is autonat's, surfaced separately.
/// What this reports is truthful and load-bearing: it is `relay` exactly when the only live path to
/// a bootstrap is a circuit, and `direct` when a direct connection exists.
pub struct SwarmStatusFacts {
    handle: SwarmHandle,
    bootstrap: Vec<PeerId>,
}

impl SwarmStatusFacts {
    /// Wire the live-facts provider over a running swarm's [`SwarmHandle`] and the configured
    /// bootstrap peer set (the same set `--libp2p-bootstrap` parsed).
    pub fn new(handle: SwarmHandle, bootstrap: Vec<PeerId>) -> Self {
        SwarmStatusFacts { handle, bootstrap }
    }
}

#[async_trait]
impl daemon_core::StatusFacts for SwarmStatusFacts {
    async fn snapshot(&self) -> daemon_core::StatusFactSnapshot {
        let mut healthy = 0u32;
        let mut any_direct = false;
        let mut any_relay = false;
        for peer in &self.bootstrap {
            // Bootstrap health is read from the ACTUAL connection state (is_connected), so a dead
            // bootstrap drops the count — the drill's load-bearing signal.
            if self.handle.is_connected(*peer).await {
                healthy += 1;
            }
            // Path classification reads the SAME connection ledger, so it can never disagree with
            // is_connected about whether the peer is connected.
            match self.handle.connection_path(*peer).await {
                ConnPath::Direct => any_direct = true,
                ConnPath::Relay => any_relay = true,
                ConnPath::None => {}
            }
        }
        // Direct dominates (a hole-punched peer reports direct even while a stale circuit lingers);
        // a swarm with no classified live bootstrap connection reports Unknown, never None.
        let path = if any_direct {
            daemon_core::PeerPath::Direct
        } else if any_relay {
            daemon_core::PeerPath::Relay
        } else {
            daemon_core::PeerPath::Unknown
        };
        daemon_core::StatusFactSnapshot {
            bootstrap_total: self.bootstrap.len() as u32,
            bootstrap_healthy: healthy,
            path,
            // TASK-257 F-2: the live routing-table size, read from the running swarm. NOTE: a
            // cross-scope mDNS neighbour IS inserted here (kad.add_address inserts it as Disconnected
            // BEFORE any handshake; ProtocolNotSupported only updates status, never removes) and IS
            // counted by routing_peers(). It occupies at most the F-1 admission cap of slots as a
            // decaying dead-end, never resolves scoped content (the scoped protocol name isolates it,
            // proven by the 7/7 e2e content-isolation control), and is a bounded cost inside "a cross
            // peer costs a retry". Deterministic event-driven eviction is deferred to TASK-262.
            kad_routing_peers: Some(self.handle.routing_peers().await as u32),
        }
    }
}

#[cfg(test)]
mod identity_seed_tests {
    //! TASK-185 GB1: `resolve_durable_identity_seed` is the anchor that makes durability real -
    //! a state-dir-only restart must come back as the SAME node. These are fast, network-free
    //! unit tests of that contract (the end-to-end restart bite is
    //! `tests/restart_durable_sequence_through_run.rs`).
    use super::{IDENTITY_SEED_FILENAME, resolve_durable_identity_seed};

    /// A unique, empty temp dir for one test (process + thread + counter keyed).
    fn fresh_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "nix-p2p-identtest-{tag}-{}-{:?}-{}",
            std::process::id(),
            std::thread::current().id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn state_dir_only_is_stable_across_boots() {
        // The GB1 property: two boots with only a state dir resolve the SAME identity, and it
        // is persisted. If persistence were a no-op these would differ.
        let dir = fresh_dir("stable");
        let first = resolve_durable_identity_seed(Some(&dir), None).expect("first boot");
        assert!(
            dir.join(IDENTITY_SEED_FILENAME).exists(),
            "the identity seed must be persisted under the state dir"
        );
        let second = resolve_durable_identity_seed(Some(&dir), None).expect("second boot");
        assert_eq!(
            first, second,
            "a state-dir-only restart is the SAME identity"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_state_dir_honours_explicit_and_is_session_scoped_otherwise() {
        // Without a state dir: explicit wins verbatim; None is random (session-scoped) - two
        // calls need not agree (and almost never will).
        let seed = [9u8; 32];
        assert_eq!(
            resolve_durable_identity_seed(None, Some(seed)).unwrap(),
            seed
        );
        let a = resolve_durable_identity_seed(None, None).unwrap();
        let b = resolve_durable_identity_seed(None, None).unwrap();
        assert_ne!(
            a, b,
            "session-scoped random seeds are (overwhelmingly) distinct"
        );
    }

    #[test]
    fn explicit_seed_is_persisted_then_reused_by_a_state_dir_only_restart() {
        let dir = fresh_dir("explicit-persist");
        let seed = [7u8; 32];
        assert_eq!(
            resolve_durable_identity_seed(Some(&dir), Some(seed)).unwrap(),
            seed
        );
        // A later state-dir-only boot reuses the persisted explicit seed.
        assert_eq!(
            resolve_durable_identity_seed(Some(&dir), None).unwrap(),
            seed,
            "the explicit seed was persisted and is reused on a state-dir-only restart"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explicit_seed_conflicting_with_persisted_is_fail_closed() {
        // Fail-safe: an explicit seed that disagrees with the state dir's persisted identity is
        // a hard error (else it would orphan the dir's anti-rollback floor).
        let dir = fresh_dir("conflict");
        resolve_durable_identity_seed(Some(&dir), None).expect("persist a random identity");
        let err = resolve_durable_identity_seed(Some(&dir), Some([0xAB; 32]))
            .expect_err("a conflicting explicit seed must be rejected");
        assert!(
            err.contains("disagrees"),
            "error must name the conflict: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_persisted_seed_is_fail_closed_not_silently_regenerated() {
        // A corrupt identity file must NOT be silently replaced with a fresh random identity
        // (that would orphan the floor) - it is a hard error the operator must resolve.
        let dir = fresh_dir("malformed");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(IDENTITY_SEED_FILENAME), b"not-hex\n").unwrap();
        assert!(
            resolve_durable_identity_seed(Some(&dir), None).is_err(),
            "a malformed persisted identity must fail closed, not regenerate a new one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_floor_without_its_identity_is_fail_closed_corruption() {
        // TASK-185 re-gate, case 1 (GB1 re-opened via PARTIAL loss): a floor/sequence file
        // present while the identity file is GONE must FAIL-CLOSED, not silently regenerate a
        // fresh identity (which would rekey the node and orphan the records the floor is bound
        // to). BITE: remove the consistency check in resolve and this returns a fresh seed -> the
        // expect_err goes red. Covered for BOTH floor sidecars.
        use fabric_libp2p::{ANNOUNCE_SEQ_FILENAME, PROVIDER_FLOOR_FILENAME};
        for orphan in [ANNOUNCE_SEQ_FILENAME, PROVIDER_FLOOR_FILENAME] {
            let dir = fresh_dir("orphan-floor");
            std::fs::create_dir_all(&dir).unwrap();
            // A floor file exists but NO identity file (partial corruption).
            std::fs::write(dir.join(orphan), b"# surviving floor state\n").unwrap();
            let err = resolve_durable_identity_seed(Some(&dir), None).expect_err(
                "a durable floor without its identity must fail closed, not silently rekey",
            );
            assert!(
                err.contains("INCONSISTENT"),
                "error must name the inconsistency (orphan {orphan}): {err}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn identity_present_without_a_floor_is_a_normal_boot_not_corruption() {
        // The AMBIGUOUS direction is deliberately NOT fail-closed (TASK-189): a pure consumer or
        // a pre-first-announce provider legitimately has an identity but no floor file yet, so a
        // restart there is a normal SAME-identity boot, not corruption.
        let dir = fresh_dir("ident-no-floor");
        let first = resolve_durable_identity_seed(Some(&dir), None).expect("first boot");
        let second =
            resolve_durable_identity_seed(Some(&dir), None).expect("restart with no floor yet");
        assert_eq!(
            first, second,
            "identity-present + floor-absent is a normal boot, not corruption"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod public_announce_gate_tests {
    //! TASK-102: the PUBLIC announce door is closed-by-construction on the allowlist.
    //! These are network-free unit tests of [`approve_provisions_for_public`] - the single
    //! consult point every public announce goes through. StoreProvision has private fields,
    //! but this test lives in the SAME crate, so it can mint one directly (the shipped path
    //! mints it only via `verify_store_provisions`; here we only need the gate's decision).
    use super::{StoreProvision, approve_provisions_for_public, approve_seeds_for_public};
    use daemon_core::content_id::Blake3Digest;
    use daemon_core::{
        NarHashKey, PublicNarAllowlist, PublicationRejected, StoreHash, TrustedNarKeys,
    };

    const FIXTURE_PUBKEY: &str = "nix-p2p-test-1:empdFBu9wVZG12rPKToHMOTsU1qzWzeCcLdq/KQH0JQ=";
    // The real `app` narinfo (NarHash sha256:0pgsb9..., NarSize 408), trusted-signed.
    const APP_NARINFO: &[u8] = b"StorePath: /nix/store/l30jg5xg904s62jvw5znmr682xpr993c-nix-p2p-fixture-app\n\
URL: nar/15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7.nar.xz\n\
Compression: xz\n\
FileHash: sha256:15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7\n\
FileSize: 260\n\
NarHash: sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm\n\
NarSize: 408\n\
References: 0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib\n\
Deriver: 3135ldqj1kl5wxkrrdnf4dfxiqakjz0z-nix-p2p-fixture-app.drv\n\
Sig: nix-p2p-test-1:Xqf1bjNJ1ReFahm86zY+hv80+7QeJer5V/HjlEAvP39yJEK8w8jHG9WH5lM7mN9WCIbdH/DDx81dmsjVObMqAQ==\n";

    fn allowlist_with_app() -> PublicNarAllowlist {
        let trusted = TrustedNarKeys::from_lines([FIXTURE_PUBKEY]).unwrap();
        let list = PublicNarAllowlist::in_memory(trusted);
        list.learn(
            &StoreHash::new("l30jg5xg904s62jvw5znmr682xpr993c"),
            APP_NARINFO,
        );
        list
    }

    fn provision(nar_hash: &str, declared_size: u64) -> StoreProvision {
        StoreProvision {
            nar_hash: nar_hash.parse::<NarHashKey>().unwrap(),
            content: Blake3Digest::from_bytes([0u8; 32]),
            declared_size,
        }
    }

    #[test]
    fn allowlisted_provision_is_approved() {
        let list = allowlist_with_app();
        let provisions = vec![provision(
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm",
            408,
        )];
        let approved = approve_provisions_for_public(&provisions, &list).expect("approved");
        assert_eq!(approved.len(), 1);
        assert_eq!(approved[0].claim().nar_size(), 408);
        // The claim is load-bearing: it authorises exactly the provision's NarHash.
        assert_eq!(
            approved[0].claim().nar_hash(),
            approved[0].provision().nar_hash()
        );
    }

    #[test]
    fn an_operator_seeded_local_fixture_is_refused_from_public_announce() {
        // THE BITE (mped-architect must-have #2): a purely-local NAR the operator named is
        // NOT allowlisted, so the public door refuses the whole batch and mints NO claim.
        // Neuter the `approve` consult inside `approve_provisions_for_public` and this goes
        // green (claims minted) -> the guard bites. This is the closed-by-construction gate:
        // without a PublicNarClaim, `announce_public_provisions` cannot announce it.
        let list = allowlist_with_app();
        let local_only = provision(
            "sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa",
            524808,
        );
        match approve_provisions_for_public(&[local_only], &list) {
            Err(PublicationRejected::NotAllowlisted(_)) => {}
            other => panic!("expected NotAllowlisted, got {other:?}"),
        }
    }

    #[test]
    fn all_or_nothing_one_unapproved_refuses_the_whole_batch() {
        // Fail-closed batch semantics: an approved provision alongside an un-allowlisted one
        // refuses BOTH, so no partial public announce can leak the un-approved NAR.
        let list = allowlist_with_app();
        let provisions = vec![
            provision(
                "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm",
                408,
            ),
            provision(
                "sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa",
                524808,
            ),
        ];
        assert!(approve_provisions_for_public(&provisions, &list).is_err());
    }

    #[test]
    fn a_size_that_disagrees_with_the_proof_is_refused() {
        // A NarHash allowlisted at 408 announced at a different size is refused: a NAR may be
        // announced only at exactly the size a trusted signature covered (defensive guard).
        let list = allowlist_with_app();
        let wrong_size = provision(
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm",
            999,
        );
        match approve_provisions_for_public(&[wrong_size], &list) {
            Err(PublicationRejected::SizeMismatch { .. }) => {}
            other => panic!("expected SizeMismatch, got {other:?}"),
        }
    }

    // ---- the SEED public door (announce_public_seeds), the path the s7-libp2p e2e drives ----

    const APP_NAR_HASH: &str = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";

    fn seed(nar_hash: &str, len: usize) -> (NarHashKey, Vec<u8>) {
        // The GATE (approve_seeds_for_public) checks only the allowlist membership + byte length;
        // the raw-content->NarHash TASK-56 check lives in the shared announce loop, so these
        // fixture bytes need only the right length to exercise the gate.
        (nar_hash.parse::<NarHashKey>().unwrap(), vec![0u8; len])
    }

    #[test]
    fn allowlisted_seed_is_approved() {
        let list = allowlist_with_app();
        let approved =
            approve_seeds_for_public(&[seed(APP_NAR_HASH, 408)], &list).expect("approved");
        assert_eq!(approved.len(), 1);
        assert_eq!(approved[0].claim().nar_size(), 408);
        assert_eq!(approved[0].claim().nar_hash(), approved[0].nar_hash());
    }

    #[test]
    fn an_operator_named_local_seed_is_refused_from_public_announce() {
        // THE SEED BITE: a purely-local NAR the operator named via --libp2p-seed-nar is NOT
        // allowlisted (never proven public via a trusted narinfo signature), so the public seed
        // door refuses the whole batch and mints NO claim. Neuter the `approve` consult and this
        // goes green -> the guard bites. Without a claim, announce_public_seeds cannot announce it.
        let list = allowlist_with_app();
        let local = seed(
            "sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa",
            1234,
        );
        match approve_seeds_for_public(&[local], &list) {
            Err(PublicationRejected::NotAllowlisted(_)) => {}
            other => panic!("expected NotAllowlisted, got {other:?}"),
        }
    }

    #[test]
    fn seed_all_or_nothing_one_unapproved_refuses_the_whole_batch() {
        let list = allowlist_with_app();
        let seeds = vec![
            seed(APP_NAR_HASH, 408),
            seed(
                "sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa",
                1234,
            ),
        ];
        assert!(approve_seeds_for_public(&seeds, &list).is_err());
    }

    #[test]
    fn a_seed_length_that_disagrees_with_the_proof_is_refused() {
        // A NarHash allowlisted at 408 B announced from a seed of a DIFFERENT length is refused:
        // the raw NAR length must equal the NarSize the trusted signature covered.
        let list = allowlist_with_app();
        match approve_seeds_for_public(&[seed(APP_NAR_HASH, 999)], &list) {
            Err(PublicationRejected::SizeMismatch { .. }) => {}
            other => panic!("expected SizeMismatch, got {other:?}"),
        }
    }

    // ---- TASK-279 AC#2: the WHOLE-supply authorize-all-first transaction ----

    /// AC#2 TRANSACTION BITE: a public provider authorizes its WHOLE additive supply (seeds AND
    /// provisions) BEFORE announcing ANY record. With an ALLOWLISTED seed S and an UN-ALLOWLISTED
    /// provision P, [`authorize_public_supply`] REFUSES the whole supply (Err) and approves NOTHING —
    /// so `announce_public_supply` announces nothing and S is never published to the DHT. This closes
    /// the non-atomic window where the seed leg was announced (published) before the provision leg was
    /// even authorized, leaving S to linger to its TTL on a P-refusal.
    ///
    /// MUTATION (reopens the window): make `authorize_public_supply` return the approved seed leg even
    /// when the provision leg is refused (e.g. `.unwrap_or_default()` on the provision arm instead of
    /// `?`) and the `NotAllowlisted` assertion below flips to an Ok(S approved) — the exact leak.
    #[test]
    fn authorize_public_supply_refuses_the_whole_supply_on_one_unallowlisted_leg() {
        use super::authorize_public_supply;
        let list = allowlist_with_app();
        const UNALLOWLISTED: &str = "sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa";

        // S allowlisted, P NOT allowlisted -> the WHOLE supply is refused (S is never approved to
        // announce). Attribute the refusal to the provision leg's allowlist decision.
        match authorize_public_supply(
            &[seed(APP_NAR_HASH, 408)],
            &[provision(UNALLOWLISTED, 524_808)],
            &list,
        ) {
            Err(PublicationRejected::NotAllowlisted(_)) => {}
            other => panic!(
                "an un-allowlisted provision must refuse the WHOLE supply (so the allowlisted seed \
                 S is never announced), got {other:?}"
            ),
        }

        // Symmetric: an un-allowlisted SEED alongside an allowlisted provision also refuses the whole.
        assert!(
            authorize_public_supply(
                &[seed(UNALLOWLISTED, 524_808)],
                &[provision(APP_NAR_HASH, 408)],
                &list,
            )
            .is_err(),
            "an un-allowlisted seed must refuse the whole supply too"
        );

        // NON-VACUOUS: a fully-allowlisted supply authorizes BOTH legs (both use the APP proof here),
        // so the refusal above is the allowlist decision, not an always-Err primitive.
        let (approved_seeds, approved_provisions) = authorize_public_supply(
            &[seed(APP_NAR_HASH, 408)],
            &[provision(APP_NAR_HASH, 408)],
            &list,
        )
        .expect("a fully-allowlisted supply authorizes both legs");
        assert_eq!(approved_seeds.len(), 1, "the seed leg is approved");
        assert_eq!(
            approved_provisions.len(),
            1,
            "the provision leg is approved"
        );
    }
}

#[cfg(test)]
mod lan_isolation_tests {
    //! TASK-102 fix cycle #2: the LAN-isolation witness must require POSITIVE loopback/link-local
    //! isolation, not merely absence-of-bootstrap. Each public-reach signal must make
    //! [`lan_isolation_or_refuse`] REFUSE; only a node with no public-reach signal mints a [`LanShare`].
    use super::{LanReachability, lan_isolation_or_refuse, multiaddr_is_lan_only};
    use fabric_libp2p::{Multiaddr, PeerId};

    fn peer() -> PeerId {
        "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
            .parse()
            .unwrap()
    }

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    // ============ TASK-280 scope selection + consumer/provider parity (AC#3/#5/#6) ============

    #[test]
    fn effective_scope_lan_share_uses_the_frozen_constant() {
        use super::{DEFAULT_NETWORK_SCOPE, LAN_SHARE_NETWORK_SCOPE, effective_network_scope};
        // No explicit --libp2p-scope: a lan-share node derives the FROZEN lan-share scope; every
        // other profile derives the public default. MUTATION: swap the `lan_share` branch and the
        // first two assertions flip.
        assert_eq!(
            effective_network_scope(None, true),
            LAN_SHARE_NETWORK_SCOPE,
            "a lan-share node with no explicit scope must use the frozen lan-share.v1 scope"
        );
        assert_eq!(
            effective_network_scope(None, false),
            DEFAULT_NETWORK_SCOPE,
            "a non-lan-share node with no explicit scope stays on public v1"
        );
        // The wire freeze: the constant is exactly lan-share.v1 (a compatibility surface).
        assert_eq!(LAN_SHARE_NETWORK_SCOPE, "lan-share.v1");
        assert_eq!(DEFAULT_NETWORK_SCOPE, "v1");
    }

    #[test]
    fn effective_scope_explicit_override_always_wins() {
        use super::effective_network_scope;
        // --libp2p-scope is the advanced escape hatch: it overrides for EVERY profile, including a
        // lan-share node deliberately joining a shared scope.
        assert_eq!(effective_network_scope(Some("custom"), true), "custom");
        assert_eq!(effective_network_scope(Some("custom"), false), "custom");
    }

    #[test]
    fn lan_share_scope_hint_fires_only_for_a_lan_oriented_consumer_on_public_v1() {
        use super::{DEFAULT_NETWORK_SCOPE, LAN_SHARE_NETWORK_SCOPE, should_hint_lan_share_scope};
        // Consume-capable + public v1 + mDNS on -> HINT (the target case: a LAN leech that will miss
        // the lan-share pool). MUTATION: drop the `consume_capable` conjunct, or invert the
        // `== DEFAULT_NETWORK_SCOPE` check, and an assertion below flips.
        assert!(should_hint_lan_share_scope(
            DEFAULT_NETWORK_SCOPE,
            true,
            true,
            false
        ));
        // Public v1 + bootstrap peer (no mDNS) + consuming -> HINT (weaker signal, per spec).
        assert!(should_hint_lan_share_scope(
            DEFAULT_NETWORK_SCOPE,
            true,
            false,
            true
        ));
        // Already on lan-share.v1 -> NO hint (already joined the pool).
        assert!(!should_hint_lan_share_scope(
            LAN_SHARE_NETWORK_SCOPE,
            true,
            true,
            true
        ));
        // Not consuming (e.g. a pure public provider) -> NO hint.
        assert!(!should_hint_lan_share_scope(
            DEFAULT_NETWORK_SCOPE,
            false,
            true,
            true
        ));
        // Consuming on v1 but NO LAN-bootstrap reach (no mDNS, no bootstrap) -> NO hint (nothing to
        // suggest it is LAN-oriented).
        assert!(!should_hint_lan_share_scope(
            DEFAULT_NETWORK_SCOPE,
            true,
            false,
            false
        ));
    }

    #[test]
    fn mixed_mode_libp2p_consumer_leg_still_warns_despite_a_provider_aggregate_profile() {
        // codex TASK-282 (e): the composite derives ONE aggregate profile from BOTH transports, so an
        // iroh give-side inflates it to a PROVIDER mode. The OLD `consume_capable =
        // matches!(contract.profile, ConsumeOnly)` then read `false` for a node whose LIBP2P leg is a
        // pure consumer (leech / bare mDNS) and SUPPRESSED the scope hint. `libp2p_leg_consume_capable`
        // keys on the libp2p flags directly so the hint fires. MUTATION: revert the call sites to
        // `matches!(contract.profile, ConsumeOnly)` for this mixed node -> `false` -> the first
        // assertion (hint fires) reddens.
        use super::{
            DEFAULT_NETWORK_SCOPE, libp2p_leg_consume_capable, should_hint_lan_share_scope,
        };

        // Mixed node: iroh PROVIDER (aggregate profile is NOT ConsumeOnly) + a libp2p leech leg on
        // mDNS. The libp2p leg IS consume-capable, so the hint MUST fire.
        let leg = libp2p_leg_consume_capable(
            /* is_libp2p_provider */ false, /* libp2p_leech */ true,
            /* mdns_enabled */ true, /* has_bootstrap_peer */ false,
        );
        assert!(
            leg,
            "a libp2p leech/mDNS leg is consume-capable regardless of the aggregate profile"
        );
        assert!(
            should_hint_lan_share_scope(DEFAULT_NETWORK_SCOPE, leg, true, false),
            "a mixed-mode node whose libp2p leg is a consumer must still get the lan-share scope hint"
        );

        // A libp2p PROVIDER leg is NOT a consumer wanting to join — excluded. MUTATION: drop the
        // `!is_libp2p_provider` guard -> this flips to consume-capable -> the assertion reddens.
        assert!(
            !libp2p_leg_consume_capable(true, true, true, true),
            "a libp2p give-side provider is not the leech the consumer-specific hint targets"
        );

        // A bootstrapped ROUTER IS consume-capable and MUST warn (codex re-gate): a router retains the
        // consume axes (LeechFabric + PeerFabricNarSource) so on public v1 it silently misses a
        // lan-share.v1 pool. This is the FIX vs the old `matches!(profile, ConsumeOnly)`, which gave a
        // router no warning. MUTATION: re-add a `!is_router`-style exclusion (or revert the callsite to
        // aggregate-profile logic) -> a router reads not-consume-capable -> this assertion reddens.
        assert!(
            libp2p_leg_consume_capable(
                /* is_libp2p_provider */ false, /* libp2p_leech */ false,
                /* mdns_enabled */ false, /* has_bootstrap_peer */ true,
            ),
            "a bootstrapped router consumes (retains the consume axes) and must get the scope hint"
        );

        // No libp2p leg at all (pure iroh consumer): no libp2p reach -> not libp2p-consume-capable, so
        // the LIBP2P scope hint is correctly irrelevant.
        assert!(
            !libp2p_leg_consume_capable(false, false, false, false),
            "a node with no libp2p consumer reach has no libp2p leg to warn about"
        );
    }

    #[test]
    fn effective_scope_is_audience_across_roles() {
        use super::{DEFAULT_NETWORK_SCOPE, LAN_SHARE_NETWORK_SCOPE, effective_network_scope};
        // TASK-280 #3 (SCOPE = AUDIENCE, de-vacuumed): scope names the POOL, not the role. Assert
        // DISTINCT inputs across roles, not `effective_network_scope(None, true)` twice:
        //   * a lan-share PROVIDER (lan_share = true, no explicit scope) -> lan-share.v1;
        //   * a consume-only LEECH that OPTS IN (lan_share = false, explicit lan-share.v1) -> the SAME
        //     pool as the provider (the explicit scope is the audience it chose to join);
        //   * a BARE consume-only (lan_share = false, no explicit scope) -> the public v1 pool, which
        //     is a DIFFERENT audience from the provider (so the leech must opt in to find it).
        let provider = effective_network_scope(None, true);
        let opt_in_leech = effective_network_scope(Some(LAN_SHARE_NETWORK_SCOPE), false);
        let bare_leech = effective_network_scope(None, false);
        assert_eq!(provider, LAN_SHARE_NETWORK_SCOPE);
        assert_eq!(
            opt_in_leech, provider,
            "a consume-only leech that passes --libp2p-scope lan-share.v1 joins the provider's pool"
        );
        assert_eq!(bare_leech, DEFAULT_NETWORK_SCOPE);
        assert_ne!(
            bare_leech, provider,
            "a BARE consume-only leech is on a DIFFERENT audience than the lan-share provider"
        );
    }

    fn none() -> LanReachability<'static> {
        LanReachability {
            bootstrap: &[],
            provider_addrs: &[],
            listen: None,
        }
    }

    #[test]
    fn isolated_node_with_no_reach_signals_is_permitted() {
        // No bootstrap, no provider-addr, no listen: a node with no public-reach signal -> LanShare.
        assert!(lan_isolation_or_refuse(none()).is_ok());
    }

    #[test]
    fn a_loopback_listen_only_node_is_permitted() {
        let listen = addr("/ip4/127.0.0.1/tcp/0");
        let reach = LanReachability {
            listen: Some(&listen),
            ..none()
        };
        assert!(
            lan_isolation_or_refuse(reach).is_ok(),
            "a loopback-listen isolated node is a valid LAN announce"
        );
    }

    #[test]
    fn a_link_local_listen_only_node_is_permitted() {
        for a in ["/ip4/169.254.10.10/tcp/0", "/ip6/fe80::1/tcp/0"] {
            let listen = addr(a);
            let reach = LanReachability {
                listen: Some(&listen),
                ..none()
            };
            assert!(
                lan_isolation_or_refuse(reach).is_ok(),
                "a link-local listen ({a}) is LAN-only"
            );
        }
    }

    #[test]
    fn a_bootstrapped_announce_is_refused() {
        // Presence of ANY bootstrap peer refuses, regardless of its address (even loopback).
        let bootstrap = [(peer(), addr("/ip4/127.0.0.1/tcp/4001"))];
        let reach = LanReachability {
            bootstrap: &bootstrap,
            ..none()
        };
        let err = lan_isolation_or_refuse(reach).expect_err("bootstrap must refuse");
        assert!(err.contains("TASK-103"), "must name TASK-103: {err}");
        assert!(
            err.contains("--libp2p-bootstrap"),
            "must name the signal: {err}"
        );
    }

    #[test]
    fn a_provider_addr_with_empty_bootstrap_is_refused() {
        // THE residual bite (fix cycle #2): a --libp2p-provider-addr with EMPTY bootstrap still
        // seeds the kad routing table and reaches the public DHT, so it must REFUSE. Before the fix
        // (bootstrap-only guard) this MINTED a LanShare and announced ungated. Loopback addr proves
        // the refusal is on PRESENCE, not the address literal.
        let provider_addrs = [(peer(), addr("/ip4/127.0.0.1/tcp/4001"))];
        let reach = LanReachability {
            provider_addrs: &provider_addrs,
            ..none()
        };
        let err = lan_isolation_or_refuse(reach)
            .expect_err("a provider-addr with empty bootstrap must be refused");
        assert!(err.contains("TASK-103"), "must name TASK-103: {err}");
        assert!(
            err.contains("--libp2p-provider-addr"),
            "must name the provider-addr signal: {err}"
        );
    }

    #[test]
    fn a_global_or_wildcard_or_dns_listen_still_refuses() {
        // TASK-276: a GLOBAL/routable IP, the 0.0.0.0/:: wildcard (binds public interfaces too on a
        // dual-homed host), a DNS name (uninspectable), and CGNAT 100.64/10 (RFC6598 carrier-shared,
        // not a trusted single LAN) must ALL still refuse under a no-allowlist lan-share. Only the
        // provably-private/loopback/link-local relax landed; the public-reach boundary still bites.
        for a in [
            "/ip4/203.0.113.7/tcp/4001",
            "/ip4/8.8.8.8/tcp/4001",
            "/ip4/0.0.0.0/tcp/4001",
            "/ip6/::/tcp/4001",
            "/ip6/2606:4700:4700::1111/tcp/4001",
            "/dns4/example.com/tcp/4001",
            "/ip4/100.64.0.1/tcp/4001",
        ] {
            let listen = addr(a);
            let reach = LanReachability {
                listen: Some(&listen),
                ..none()
            };
            assert!(
                lan_isolation_or_refuse(reach).is_err(),
                "listen {a} is not provably LAN-only; must refuse"
            );
        }
    }

    #[test]
    fn a_private_lan_listen_is_now_permitted() {
        // TASK-276 AC#1 (the relaxation): a bare no-allowlist lan-share MAY serve on an RFC1918 or
        // ULA private address so two same-pin machines serve each other cross-host on the LAN.
        for a in [
            "/ip4/10.0.0.5/tcp/4001",
            "/ip4/172.16.9.9/tcp/4001",
            "/ip4/172.31.255.254/tcp/4001",
            "/ip4/192.168.1.5/tcp/4001",
            "/ip6/fc00::1/tcp/4001",
            "/ip6/fd12:3456:789a::1/tcp/4001",
        ] {
            let listen = addr(a);
            let reach = LanReachability {
                listen: Some(&listen),
                ..none()
            };
            assert!(
                lan_isolation_or_refuse(reach).is_ok(),
                "a private-LAN listen ({a}) is LAN-only and must be permitted"
            );
        }
    }

    #[test]
    fn circuit_listen_is_refused() {
        // FIX #1 (codex CRITICAL #1): a /p2p-circuit listen on a PRIVATE literal must be refused. The
        // old fail-open `_ => {}` classified this LAN-only (it only inspected the Ip4), letting a
        // no-allowlist provider reserve a slot on a dual-homed relay so an INTERNET peer could reach
        // it through the circuit. Both the predicate and the guard must reject it.
        let circuit = addr(
            "/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit",
        );
        assert!(
            !multiaddr_is_lan_only(&circuit),
            "a /p2p-circuit listen must NOT classify as LAN-only"
        );
        let reach = LanReachability {
            listen: Some(&circuit),
            ..none()
        };
        assert!(
            lan_isolation_or_refuse(reach).is_err(),
            "a /p2p-circuit listen must be refused by the isolation guard"
        );
    }

    #[test]
    fn relay_hop_listen_is_refused() {
        // FIX #1: a private literal with a trailing /p2p/<relay> hop (not yet a circuit, but a relay
        // dial hint) is likewise not a plain direct listen and must be refused.
        let hop = addr(
            "/ip4/192.168.1.5/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
        );
        assert!(
            !multiaddr_is_lan_only(&hop),
            "a /p2p relay-hop listen must NOT classify as LAN-only"
        );
        let reach = LanReachability {
            listen: Some(&hop),
            ..none()
        };
        assert!(
            lan_isolation_or_refuse(reach).is_err(),
            "a /p2p relay-hop listen must be refused by the isolation guard"
        );
    }

    #[test]
    fn multiaddr_is_lan_only_classifies_correctly() {
        // Admitted (TCP): loopback, link-local, and (TASK-276) RFC1918/ULA private.
        assert!(multiaddr_is_lan_only(&addr("/ip4/127.0.0.1/tcp/0")));
        assert!(multiaddr_is_lan_only(&addr("/ip6/::1/tcp/0")));
        assert!(multiaddr_is_lan_only(&addr("/ip4/169.254.1.1/tcp/0")));
        assert!(multiaddr_is_lan_only(&addr("/ip6/fe80::abcd/tcp/0")));
        assert!(multiaddr_is_lan_only(&addr("/ip4/192.168.0.1/tcp/0")));
        assert!(multiaddr_is_lan_only(&addr("/ip4/10.1.2.3/tcp/0")));
        assert!(multiaddr_is_lan_only(&addr("/ip4/172.20.0.1/tcp/0")));
        assert!(multiaddr_is_lan_only(&addr("/ip6/fd00::1/tcp/0")));
        // Admitted (QUIC-v1): the shipped swarm builds a QUIC transport, so /udp/<port>/quic-v1 on a
        // private literal is a real direct-listen shape.
        assert!(multiaddr_is_lan_only(&addr(
            "/ip4/192.168.0.1/udp/4001/quic-v1"
        )));
        assert!(multiaddr_is_lan_only(&addr(
            "/ip6/fd00::1/udp/4001/quic-v1"
        )));
        // Refused: wildcard, global, CGNAT, DNS, and the 172.16/12 boundary neighbours.
        assert!(!multiaddr_is_lan_only(&addr("/ip4/0.0.0.0/tcp/0")));
        assert!(!multiaddr_is_lan_only(&addr("/ip4/8.8.8.8/tcp/0")));
        assert!(!multiaddr_is_lan_only(&addr("/ip4/100.64.0.1/tcp/0")));
        assert!(!multiaddr_is_lan_only(&addr("/ip4/172.15.0.1/tcp/0")));
        assert!(!multiaddr_is_lan_only(&addr("/ip4/172.32.0.1/tcp/0")));
        assert!(!multiaddr_is_lan_only(&addr("/dns4/example.com/tcp/0")));
        // A multiaddr with no IP literal at all is not provably local.
        assert!(!multiaddr_is_lan_only(&addr(
            "/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        )));
        // FIX #1 positive-grammar rejects: a private IP does NOT launder a non-direct suffix. A relay
        // hop (/p2p/<id>), a relay circuit (/p2p-circuit), a websocket wrapper (/ws, /wss), the
        // draft-29 /quic (not quic-v1), a bare /udp with no stream transport, and the 0.0.0.0 wildcard
        // are ALL refused even on an RFC1918 literal.
        assert!(!multiaddr_is_lan_only(&addr(
            "/ip4/192.168.1.5/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        )));
        assert!(!multiaddr_is_lan_only(&addr(
            "/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit"
        )));
        assert!(!multiaddr_is_lan_only(&addr(
            "/ip4/192.168.1.5/tcp/4001/ws"
        )));
        assert!(!multiaddr_is_lan_only(&addr(
            "/ip4/192.168.1.5/tcp/4001/wss"
        )));
        assert!(!multiaddr_is_lan_only(&addr(
            "/ip4/192.168.1.5/udp/4001/quic"
        )));
        assert!(!multiaddr_is_lan_only(&addr("/ip4/192.168.1.5/udp/4001")));
    }

    #[test]
    fn ip_is_provably_private_boundaries() {
        use super::ip_is_provably_private;
        use std::net::IpAddr;
        let p = |s: &str| ip_is_provably_private(&s.parse::<IpAddr>().unwrap());
        // RFC1918 in-range.
        assert!(p("10.0.0.0") && p("10.255.255.255"));
        assert!(p("172.16.0.0") && p("172.31.255.255"));
        assert!(p("192.168.0.0") && p("192.168.255.255"));
        // RFC1918 just-out-of-range and other non-private.
        assert!(!p("9.255.255.255") && !p("11.0.0.0"));
        assert!(!p("172.15.255.255") && !p("172.32.0.0"));
        assert!(!p("192.167.255.255") && !p("192.169.0.0"));
        assert!(!p("100.64.0.1")); // CGNAT
        assert!(!p("169.254.1.1")); // link-local (classified separately, not "private")
        assert!(!p("127.0.0.1")); // loopback (classified separately)
        assert!(!p("0.0.0.0")); // wildcard/unspecified
        assert!(!p("8.8.8.8")); // global
        // IPv6 ULA fc00::/7 boundary.
        assert!(p("fc00::") && p("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert!(!p("fbff::") && !p("fe00::"));
        assert!(!p("2606:4700:4700::1111")); // global
        assert!(!p("fe80::1")); // link-local
        assert!(!p("::1")); // loopback
    }

    #[test]
    fn lan_serving_disclosures_are_honest_and_full_multiaddr() {
        use super::{lan_serving_disclosures, listen_addr_is_private_lan};
        let a = |s: &str| s.parse::<super::Multiaddr>().unwrap();

        // Only provably-private listens are disclosed; loopback/link-local/global/wildcard are not.
        assert!(listen_addr_is_private_lan(&a("/ip4/192.168.1.5/tcp/4001")));
        assert!(listen_addr_is_private_lan(&a(
            "/ip6/fd00::1/udp/4001/quic-v1"
        )));
        assert!(!listen_addr_is_private_lan(&a("/ip4/127.0.0.1/tcp/4001")));
        assert!(!listen_addr_is_private_lan(&a("/ip4/8.8.8.8/tcp/4001")));
        assert!(!listen_addr_is_private_lan(&a("/ip4/0.0.0.0/tcp/4001")));

        let listens = [
            a("/ip4/127.0.0.1/tcp/9"),          // loopback: filtered out
            a("/ip4/192.168.1.5/tcp/4001"),     // private v4: disclosed
            a("/ip6/fd00::1/udp/4001/quic-v1"), // private v6 QUIC: disclosed (full multiaddr)
        ];
        let lines = lan_serving_disclosures(false, super::LAN_SHARE_NETWORK_SCOPE, &listens);
        assert_eq!(lines.len(), 2, "only the two private listens are disclosed");
        // FULL bound multiaddr (fixes malformed v6), for every admitted transport.
        assert!(lines[0].contains("/ip4/192.168.1.5/tcp/4001"));
        assert!(lines[1].contains("/ip6/fd00::1/udp/4001/quic-v1"));
        for line in &lines {
            // NON-categorical: NO "not reachable from the public internet" claim.
            assert!(
                !line.to_lowercase().contains("not reachable"),
                "disclosure must not make the categorical not-reachable claim: {line}"
            );
            // Names the still-open isolation gap (TASK-280) and warns against forwarding.
            assert!(line.contains("TASK-280"), "must name the open gap: {line}");
            assert!(
                line.contains("Do not DNAT/port-forward"),
                "must warn against forwarding: {line}"
            );
            assert!(line.contains("Only paths you chose to share"));
            // The EFFECTIVE scope is printed, not hardcoded — the distinct lan-share scope with a
            // "separate from the public" claim (TASK-280 #6).
            assert!(
                line.contains(super::LAN_SHARE_NETWORK_SCOPE) && line.contains("separate from the"),
                "distinct-scope disclosure must name the effective scope and claim separation: {line}"
            );
        }

        // #6 HONESTY: an operator who OVERRODE the scope to the public default gets a disclosure that
        // does NOT claim DHT separation — it names the deliberate shared-scope case. MUTATION: revert
        // the disclosure to a hardcoded "distinct lan-share.v1" string and this assertion flips RED.
        let overridden = lan_serving_disclosures(
            false,
            super::DEFAULT_NETWORK_SCOPE,
            &[a("/ip4/10.0.0.5/tcp/4001")],
        );
        assert_eq!(overridden.len(), 1);
        assert!(
            !overridden[0].contains("separate from the public"),
            "a public-scope override must NOT claim DHT separation: {}",
            overridden[0]
        );
        assert!(
            overridden[0].contains("OVERRIDDEN") && overridden[0].contains("shared-scope"),
            "a public-scope override must disclose the deliberate shared-scope case: {}",
            overridden[0]
        );

        // announce-after-fetch: the served-scope clause is ACCURATE about the actual guarantee —
        // publication is budget-limited and skips on materialization/validation failure, so it is
        // NOT "every fetched path".
        let grow = lan_serving_disclosures(
            true,
            super::LAN_SHARE_NETWORK_SCOPE,
            &[a("/ip4/10.0.0.5/tcp/4001")],
        );
        assert_eq!(grow.len(), 1);
        assert!(grow[0].contains("announce-after-fetch"));
        assert!(grow[0].contains("announce budget"));
        assert!(grow[0].contains("NOT every fetched path"));
        assert!(grow[0].contains("successfully-verified"));
        // The overclaim ("every store path this node fetches") must be gone.
        assert!(!grow[0].contains("every store path this node fetches"));
        assert!(!grow[0].contains("Only paths you chose to share"));
    }

    #[tokio::test]
    async fn disclosure_precedes_serve_gate() {
        // FIX #3 sequencer: the disclosure MUST run before the serve gate activates. This bites by
        // recording call order through the two effects; swapping the two lines inside
        // `disclose_then_activate_serve` flips the recorded order RED.
        use super::disclose_then_activate_serve;
        use std::sync::Mutex;
        let order: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
        let out: Result<u8, ()> =
            disclose_then_activate_serve(|| order.lock().unwrap().push("disclose"), async {
                order.lock().unwrap().push("serve-gate");
                Ok(7u8)
            })
            .await;
        assert_eq!(out, Ok(7u8));
        assert_eq!(
            *order.lock().unwrap(),
            vec!["disclose", "serve-gate"],
            "the operator disclosure must be emitted BEFORE the serve gate activates"
        );
    }
}

#[cfg(test)]
mod announce_after_fetch_tests {
    //! Mutation-proven bites for the TASK-77 announce-after-fetch invariants. Each targets a pure
    //! core / seam (no live swarm); end-to-end swarm growth is proven in the e2e `s9-libp2p-grow`.
    //!
    //! - AC#2 FIX 1: budget enforced through the PRODUCTION `on_fetched` path (fake `GrowSpawner`
    //!   counts grows; neutering the `begin` call in `on_fetched` reddens it).
    //! - AC#2 FIX 2 / FIX D: the PRODUCTION dispatch body `WorkerSpawner::run` REFUNDS a clean
    //!   pre-publication failure and SPENDS + TRACKS an announced/ambiguous grow.
    //! - AC#3 / TASK-72 FIX 3b: `WorkerSpawner::run` reconciles + WITHDRAWS a GC'd holding (the
    //!   production wiring; removing the `reconcile` call in `run` reddens it).
    //! - AC#3 FIX B: a FAILED withdraw is retained + retried, dropped only on success.
    //! - AC#3 FIX C: `validate_store_path` rejects a store-shaped path outside the real store dir.

    use super::{
        AnnounceAfterFetchDoor, AnnounceLedger, Begin, GrowSpawner, Grower,
        Libp2pAnnounceAfterFetch, Withdrawer, WorkerSpawner, begin, classify_announce,
        eligible_provisions, validate_store_path,
    };
    use async_trait::async_trait;
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use daemon_core::{
        AvailabilityIndex, NarDumper, NarHash, NarHashKey, NodeId, NullAnnounce, NullStore,
        PublicNarAllowlist, RegularFileNarDumper,
    };
    use peer_fabric::{AnnounceError, ContentKey, IneligibleReason, ServeBudget};

    const HASH32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
    const STORE_DIR: &str = "/nix/store";

    fn unique_temp(stem: &str) -> PathBuf {
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(format!("nix-p2p-task77-{stem}-{suffix}"))
    }
    fn nar_hash(seed: u8) -> NarHash {
        NarHash::new(NarHashKey::from_sha256_bytes([seed; 32]).to_string())
    }
    fn key(seed: u8) -> NarHashKey {
        NarHashKey::from_sha256_bytes([seed; 32])
    }
    fn content_key(seed: u8) -> ContentKey {
        ContentKey::from_bytes([seed; 32])
    }
    fn store_path_str(seed: u8) -> String {
        format!("/nix/store/{HASH32}-pkg-{seed}")
    }
    fn empty_ledger(budget: u64) -> Arc<Mutex<AnnounceLedger>> {
        ledger_with_seed_owned(budget, HashSet::new())
    }
    fn ledger_with_seed_owned(
        budget: u64,
        seed_owned: HashSet<NarHashKey>,
    ) -> Arc<Mutex<AnnounceLedger>> {
        Arc::new(Mutex::new(AnnounceLedger {
            remaining: budget,
            inflight: HashSet::new(),
            announced: HashSet::new(),
            held: HashMap::new(),
            seed_owned,
        }))
    }

    // ---- FIX 1: budget enforced through on_fetched (fake GrowSpawner counts dispatched grows) ----

    struct FakeSpawner {
        grows: Arc<Mutex<Vec<NarHashKey>>>,
    }
    impl GrowSpawner for FakeSpawner {
        fn dispatch(
            &self,
            _ledger: Arc<Mutex<AnnounceLedger>>,
            grow: Option<(NarHashKey, String)>,
        ) {
            if let Some((k, _)) = grow {
                self.grows.lock().unwrap().push(k);
            }
        }
    }
    fn hook_with_fake(budget: u64, grows: Arc<Mutex<Vec<NarHashKey>>>) -> Libp2pAnnounceAfterFetch {
        hook_over(empty_ledger(budget), budget, grows)
    }
    /// A hook over an EXPLICIT ledger (so a test can pre-seed `seed_owned`) whose FakeSpawner records
    /// the keys it is asked to grow.
    fn hook_over(
        ledger: Arc<Mutex<AnnounceLedger>>,
        budget_cap: u64,
        grows: Arc<Mutex<Vec<NarHashKey>>>,
    ) -> Libp2pAnnounceAfterFetch {
        Libp2pAnnounceAfterFetch {
            ledger,
            spawner: Arc::new(FakeSpawner { grows }),
            budget_cap,
        }
    }

    #[test]
    fn budget_is_enforced_through_the_production_on_fetched_path() {
        use daemon_core::PostFetchAnnounce;
        let grows = Arc::new(Mutex::new(Vec::new()));
        let hook = hook_with_fake(2, Arc::clone(&grows));
        for seed in [1u8, 2, 3] {
            hook.on_fetched(&nar_hash(seed), &store_path_str(seed));
        }
        assert_eq!(
            grows.lock().unwrap().len(),
            2,
            "on_fetched must STOP dispatching grows past the integer budget"
        );
        assert_eq!(hook.remaining_budget(), 0);
        // A re-fetch of an already-handled path is a no-op (dedup), not a new grow.
        hook.on_fetched(&nar_hash(1), &store_path_str(1));
        assert_eq!(
            grows.lock().unwrap().len(),
            2,
            "a re-fetch does not re-dispatch"
        );
    }

    /// TASK-240 AC#4: the LIVE announce-budget figure the status surface reports is read from the
    /// SAME ledger the gate enforces — `cap - remaining` — so it cannot drift from what is spent.
    /// MUTATION: reporting a constant (e.g. `Some(0)`) reddens the `== 2` after the budget is spent;
    /// reading a second, non-enforcing counter would not track the exhaustion here.
    #[test]
    fn budget_used_tracks_the_enforced_ledger() {
        use daemon_core::PostFetchAnnounce;
        let grows = Arc::new(Mutex::new(Vec::new()));
        let hook = hook_with_fake(2, Arc::clone(&grows));
        assert_eq!(hook.budget_used(), Some(0), "fresh: nothing spent yet");
        for seed in [1u8, 2, 3] {
            hook.on_fetched(&nar_hash(seed), &store_path_str(seed));
        }
        // Two distinct paths announced under a cap of 2 -> the surface reports 2/2 (exhausted).
        assert_eq!(hook.remaining_budget(), 0);
        assert_eq!(
            hook.budget_used(),
            Some(2),
            "budget_used = cap - remaining, read from the enforced ledger"
        );
    }

    // ---- TASK-279 AC#1: the seed-owned key STATE MACHINE (never grown/tracked/withdrawn) ----

    /// AC#1 BITE (production `on_fetched` + ledger): a NarHash the durable memory-resident seed leg
    /// owns is classified `SeedOwned` — NOT `Proceed` — so `on_fetched` dispatches NO grow, reserves
    /// no budget, and never marks it in-flight (the reserve that would later become a `held` track).
    /// A key that is NOT seed-owned still grows, proving the guard is the seed-ownership, not a blanket
    /// no-op. MUTATION: drop the `seed_owned` arm in `begin` and the seed-owned key returns `Proceed`
    /// -> a grow is dispatched, budget is spent, and it is marked in-flight -> every assertion below
    /// reddens.
    #[test]
    fn a_seed_owned_key_is_classified_seedowned_and_never_reserved() {
        use daemon_core::PostFetchAnnounce;
        let seed_key = key(1); // owned by the durable seed leg
        let grown_key = key(2); // an ordinary fetched path
        let ledger = ledger_with_seed_owned(10, [seed_key].into_iter().collect());

        // begin classifies the two keys differently at the ledger boundary.
        assert_eq!(
            begin(&ledger, &seed_key),
            Begin::SeedOwned,
            "a seed-owned key is SeedOwned (the durable seed leg owns discovery for it)"
        );
        {
            let led = ledger.lock().unwrap();
            assert_eq!(led.remaining, 10, "a seed-owned key reserves no budget");
            assert!(
                led.inflight.is_empty(),
                "a seed-owned key is never in-flight"
            );
            assert!(
                led.held.is_empty(),
                "a seed-owned key is never tracked/held"
            );
        }

        // Through the PRODUCTION on_fetched path: the seed-owned key dispatches NO grow; the ordinary
        // key does (non-vacuous — the two differ only by seed-ownership).
        let grows = Arc::new(Mutex::new(Vec::new()));
        let hook = hook_over(Arc::clone(&ledger), 10, Arc::clone(&grows));
        hook.on_fetched(&nar_hash(1), &store_path_str(1)); // seed-owned -> no grow
        assert!(
            grows.lock().unwrap().is_empty(),
            "on_fetched must dispatch NO grow for a seed-owned key"
        );
        hook.on_fetched(&nar_hash(2), &store_path_str(2)); // ordinary -> grows
        assert_eq!(
            *grows.lock().unwrap(),
            vec![grown_key],
            "an ordinary (non-seed-owned) fetched path still grows"
        );
    }

    /// AC#1 END-TO-END BITE (the tombstone hazard): a seed-owned key that the node self-fetches and
    /// self-realises into `/nix/store`, then GCs, must NEVER be withdrawn by the hook — else the minted
    /// tombstone would SUPERSEDE the seed leg's own never-GC'd announce, making the NAR served-but-not-
    /// announced (and unrepairably so). Drive the production reserve (`begin`, mapped exactly as
    /// `on_fetched` does) + the production dispatch body (`WorkerSpawner::run`) across the self-fetch
    /// and a post-GC reconcile: the withdrawer is called ZERO times and nothing is tracked.
    /// MUTATION: drop the `seed_owned` arm in `begin` -> the self-fetch reserves + the FakeGrower's
    /// announce commit_success-TRACKS the key in `held` -> the post-GC reconcile WITHDRAWS it
    /// (tombstone) -> `withdrawn` is non-empty. RED.
    #[tokio::test]
    async fn a_seed_owned_key_is_never_withdrawn_after_a_store_gc() {
        let seed_key = key(1);
        // A store path that never exists on disk == a GC'd path (reconcile's `!exists()` signal).
        let gc_path = format!("/nix/store/{HASH32}-gc-d-seed");
        let ledger = ledger_with_seed_owned(10, [seed_key].into_iter().collect());

        // The self-fetch of the seed-owned key. `on_fetched` maps begin's outcome to a grow exactly
        // this way (Proceed -> Some, everything else -> None); replicate that mapping, then run the
        // production dispatch body. Under the fix this is None (SeedOwned) -> no announce, no track.
        let grow = match begin(&ledger, &seed_key) {
            Begin::Proceed => Some((seed_key, gc_path.clone())),
            _ => None,
        };
        let withdrawn = Arc::new(Mutex::new(Vec::new()));
        let wd: Arc<dyn Withdrawer> = Arc::new(FakeWithdrawer {
            result: Arc::new(Mutex::new(true)),
            withdrawn: Arc::clone(&withdrawn),
        });
        // A grower that WOULD announce (Some) if it were ever handed a grow — so the only thing keeping
        // the key out of `held` is the SeedOwned classification, not a failing announce.
        WorkerSpawner::run(
            Arc::clone(&ledger),
            Arc::new(FakeGrower {
                outcome: Arc::new(Mutex::new(Some(content_key(1)))),
            }),
            Arc::clone(&wd),
            grow,
        )
        .await;
        // A later fetch (budget-exhausted / any) drives reconcile over the (now GC'd) path.
        WorkerSpawner::run(
            Arc::clone(&ledger),
            Arc::new(NoopGrower),
            Arc::clone(&wd),
            None,
        )
        .await;

        assert!(
            withdrawn.lock().unwrap().is_empty(),
            "a seed-owned key must NEVER be withdrawn (no tombstone over the seed leg's announce)"
        );
        let led = ledger.lock().unwrap();
        assert!(
            led.held.is_empty(),
            "a seed-owned key is never tracked in `held`"
        );
        assert!(
            !led.announced.contains(&seed_key),
            "a seed-owned key never enters the hook's `announced` dedup set"
        );
        assert_eq!(
            led.remaining, 10,
            "no budget was ever spent on the seed-owned key"
        );
    }

    // ---- the production dispatch body (WorkerSpawner::run) with fakes ----

    struct FakeGrower {
        outcome: Arc<Mutex<Option<ContentKey>>>,
    }
    #[async_trait]
    impl Grower for FakeGrower {
        async fn grow(&self, _key: &NarHashKey, _store_path: &str) -> Option<ContentKey> {
            *self.outcome.lock().unwrap()
        }
    }
    /// A grower that is never called (used when driving `run` with `grow == None`).
    struct NoopGrower;
    #[async_trait]
    impl Grower for NoopGrower {
        async fn grow(&self, _key: &NarHashKey, _store_path: &str) -> Option<ContentKey> {
            None
        }
    }
    struct FakeWithdrawer {
        result: Arc<Mutex<bool>>,
        withdrawn: Arc<Mutex<Vec<ContentKey>>>,
    }
    #[async_trait]
    impl Withdrawer for FakeWithdrawer {
        async fn withdraw(&self, k: &ContentKey) -> bool {
            self.withdrawn.lock().unwrap().push(*k);
            *self.result.lock().unwrap()
        }
    }
    fn noop_withdrawer() -> Arc<dyn Withdrawer> {
        Arc::new(FakeWithdrawer {
            result: Arc::new(Mutex::new(true)),
            withdrawn: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// AC#2 FIX 2 + FIX D BITE: a CLEAN pre-publication failure (grow -> None) REFUNDS the budget
    /// and tracks nothing; an announced/AMBIGUOUS grow (grow -> Some) SPENDS the budget and TRACKS
    /// the holding for reconcile. MUTATION: flip either arm in `WorkerSpawner::run` (None ->
    /// commit_success, or Some -> commit_failure) and one of these assertions reddens.
    #[tokio::test]
    async fn run_refunds_clean_failures_and_spends_plus_tracks_announced() {
        // Clean failure: reserve, then grow returns None -> refund, not tracked.
        let ledger = empty_ledger(1);
        assert_eq!(begin(&ledger, &key(1)), Begin::Proceed);
        assert_eq!(ledger.lock().unwrap().remaining, 0, "reserved");
        WorkerSpawner::run(
            Arc::clone(&ledger),
            Arc::new(FakeGrower {
                outcome: Arc::new(Mutex::new(None)),
            }),
            noop_withdrawer(),
            Some((key(1), store_path_str(1))),
        )
        .await;
        {
            let led = ledger.lock().unwrap();
            assert_eq!(led.remaining, 1, "a clean failure REFUNDS the budget");
            assert!(led.held.is_empty(), "a clean failure tracks nothing");
            assert!(led.announced.is_empty());
        }

        // Announced/ambiguous: reserve, grow returns Some -> spend + track.
        assert_eq!(begin(&ledger, &key(2)), Begin::Proceed);
        WorkerSpawner::run(
            Arc::clone(&ledger),
            Arc::new(FakeGrower {
                outcome: Arc::new(Mutex::new(Some(content_key(2)))),
            }),
            noop_withdrawer(),
            Some((key(2), store_path_str(2))),
        )
        .await;
        let led = ledger.lock().unwrap();
        assert_eq!(
            led.remaining, 0,
            "an announced/ambiguous grow SPENDS the budget"
        );
        assert!(led.announced.contains(&key(2)));
        assert!(
            led.held.contains_key(&key(2)),
            "the holding is TRACKED for reconcile"
        );
    }

    /// AC#3 FIX D BITE (discriminating): the announce-error classification drives the ledger. A
    /// CLEAN pre-publication error (`Persist`/`Rejected`/`Ineligible` - GUARANTEED not published)
    /// maps to `None` -> `commit_failure` REFUNDS + tracks nothing; an AMBIGUOUS error
    /// (`Unreachable`/`DeadlineExceeded` - may be live) or `Ok` maps to `Some` -> `commit_success`
    /// SPENDS + TRACKS for `reconcile`. (The `None`->refund / `Some`->spend+track half is proven by
    /// `run_refunds_clean_failures_and_spends_plus_tracks_announced`.) MUTATION: making `Persist`
    /// ambiguous (or an ambiguous variant clean) in `announce_error_is_ambiguous` flips the mapped
    /// result - this reddens, discriminating the exact error the announcer raises BEFORE vs
    /// during/after `start_providing`/`put_record`.
    #[test]
    fn announce_error_classification_discriminates_clean_pre_publication_from_ambiguous() {
        let ck = content_key(9);
        // CLEAN pre-publication (announcer.rs: raised BEFORE the publish future) -> None -> refund.
        for clean in [
            AnnounceError::Persist("save-before-publish failed".into()),
            AnnounceError::Rejected("bad record".into()),
            AnnounceError::Ineligible(IneligibleReason::NotAllowlisted),
        ] {
            assert_eq!(
                classify_announce(Err(clean), ck).into_grow_result(),
                None,
                "a clean pre-publication announce error must REFUND (guaranteed not published)"
            );
        }
        // AMBIGUOUS (raised inside/around the publish future - may be live) -> Some -> spend + track.
        for ambiguous in [
            AnnounceError::Unreachable("partition".into()),
            AnnounceError::DeadlineExceeded,
        ] {
            assert_eq!(
                classify_announce(Err(ambiguous), ck).into_grow_result(),
                Some(ck),
                "an ambiguous announce error must SPEND + TRACK (reconcile may need to withdraw)"
            );
        }
        // Ok -> published -> Some (spend + track).
        assert_eq!(classify_announce(Ok(()), ck).into_grow_result(), Some(ck));
    }

    /// AC#3 / TASK-72 FIX 3b BITE (production-wired): `WorkerSpawner::run` reconciles + WITHDRAWS a
    /// GC'd holding and leaves a present one. MUTATION: delete the `reconcile(&ledger, ...)` call in
    /// `run` and the GC'd holding is never withdrawn - this reddens (this is the exact production
    /// dispatch body, not a directly-called `reconcile`).
    #[tokio::test]
    async fn run_reconciles_and_withdraws_a_gc_d_holding_through_the_production_path() {
        let present = unique_temp("present").join("store");
        std::fs::create_dir_all(&present).unwrap();
        let present_path = present
            .join(format!("{HASH32}-present"))
            .to_string_lossy()
            .into_owned();
        std::fs::write(&present_path, b"here").unwrap();
        let gone_path = format!("/nix/store/{HASH32}-gc-d");

        let mut held = HashMap::new();
        held.insert(key(1), (content_key(1), present_path));
        held.insert(key(2), (content_key(2), gone_path));
        let ledger = Arc::new(Mutex::new(AnnounceLedger {
            remaining: 0,
            inflight: HashSet::new(),
            announced: [key(1), key(2)].into_iter().collect(),
            held,
            seed_owned: HashSet::new(),
        }));
        let withdrawn = Arc::new(Mutex::new(Vec::new()));
        let wd: Arc<dyn Withdrawer> = Arc::new(FakeWithdrawer {
            result: Arc::new(Mutex::new(true)),
            withdrawn: Arc::clone(&withdrawn),
        });
        // Drive the production dispatch body with grow == None (a budget-exhausted fetch): reconcile
        // still runs.
        WorkerSpawner::run(Arc::clone(&ledger), Arc::new(NoopGrower), wd, None).await;

        assert_eq!(
            *withdrawn.lock().unwrap(),
            vec![content_key(2)],
            "only the GC'd record withdrawn"
        );
        let led = ledger.lock().unwrap();
        assert!(led.held.contains_key(&key(1)), "present holding kept");
        assert!(
            !led.held.contains_key(&key(2)),
            "GC'd holding dropped on success"
        );
    }

    /// AC#3 FIX B BITE: a FAILED withdraw is RETAINED in `held` and RETRIED on the next dispatch;
    /// only a SUCCESSFUL withdraw drops it. MUTATION: drop-on-failure in `reconcile` and the
    /// "retained after a failed withdraw" assertion reddens.
    #[tokio::test]
    async fn a_failed_withdraw_is_retained_and_retried() {
        let gone_path = format!("/nix/store/{HASH32}-gc-d");
        let mut held = HashMap::new();
        held.insert(key(5), (content_key(5), gone_path));
        let ledger = Arc::new(Mutex::new(AnnounceLedger {
            remaining: 0,
            inflight: HashSet::new(),
            announced: [key(5)].into_iter().collect(),
            held,
            seed_owned: HashSet::new(),
        }));
        let result = Arc::new(Mutex::new(false)); // fail the first withdraw
        let withdrawn = Arc::new(Mutex::new(Vec::new()));
        let wd: Arc<dyn Withdrawer> = Arc::new(FakeWithdrawer {
            result: Arc::clone(&result),
            withdrawn: Arc::clone(&withdrawn),
        });
        WorkerSpawner::run(
            Arc::clone(&ledger),
            Arc::new(NoopGrower),
            Arc::clone(&wd),
            None,
        )
        .await;
        assert_eq!(withdrawn.lock().unwrap().len(), 1, "one withdraw attempted");
        assert!(
            ledger.lock().unwrap().held.contains_key(&key(5)),
            "a FAILED withdraw KEEPS the holding for retry"
        );

        *result.lock().unwrap() = true; // succeed on retry
        WorkerSpawner::run(Arc::clone(&ledger), Arc::new(NoopGrower), wd, None).await;
        assert_eq!(
            withdrawn.lock().unwrap().len(),
            2,
            "retried on the next dispatch"
        );
        assert!(
            !ledger.lock().unwrap().held.contains_key(&key(5)),
            "a SUCCESSFUL withdraw drops the holding"
        );
    }

    // ---- AC#3 / TASK-72 eligibility + FIX C store-path location (fabric-free) ----

    fn verified_index() -> (Arc<AvailabilityIndex>, NarHashKey, String, String) {
        let body = b"a raw NAR regenerated on demand from a fetched store path (TASK-77)".to_vec();
        let true_key = NarHashKey::from_raw_nar(&body);
        // A well-formed path DIRECTLY under a temp store dir; eligible_provisions is told that same
        // store dir, so validate_store_path (FIX C) accepts it.
        let store_dir = unique_temp("root").join("store");
        std::fs::create_dir_all(&store_dir).unwrap();
        let nar_path = store_dir.join(format!("{HASH32}-fetched"));
        std::fs::write(&nar_path, &body).unwrap();
        let index = AvailabilityIndex::open(
            NodeId::from_bytes([0u8; 32]),
            Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("index opens");
        (
            Arc::new(index),
            true_key,
            store_dir.to_string_lossy().into_owned(),
            nar_path.to_string_lossy().into_owned(),
        )
    }
    fn big_serve_budget() -> ServeBudget {
        ServeBudget {
            max_nar_bytes_uncompressed_nar: 1 << 30,
            max_inflight_bytes_uncompressed_nar: 1 << 30,
            max_serve_duration: std::time::Duration::from_secs(30),
        }
    }

    #[test]
    fn public_door_refuses_an_unallowlisted_fetched_path_lan_admits_it() {
        let (index, true_key, store_dir, store_path) = verified_index();
        let public = eligible_provisions(
            &index,
            &big_serve_budget(),
            &AnnounceAfterFetchDoor::Public(Arc::new(PublicNarAllowlist::disabled())),
            &store_dir,
            &true_key,
            &store_path,
        );
        assert!(
            public.is_err() && public.as_ref().unwrap_err().contains("allowlist"),
            "a PUBLIC node must not announce a fetched path it is not allowlisted to publish; got {public:?}"
        );

        let (index2, true_key2, store_dir2, store_path2) = verified_index();
        let lan = eligible_provisions(
            &index2,
            &big_serve_budget(),
            &AnnounceAfterFetchDoor::Lan(super::LanShare::operator_assembled()),
            &store_dir2,
            &true_key2,
            &store_path2,
        )
        .expect("a LAN door admits a verified-servable fetched path");
        assert_eq!(*lan[0].nar_hash(), true_key2);
    }

    #[test]
    fn a_mis_registered_fetched_path_is_never_announced() {
        let (index, _true_key, store_dir, store_path) = verified_index();
        let refused = eligible_provisions(
            &index,
            &big_serve_budget(),
            &AnnounceAfterFetchDoor::Lan(super::LanShare::operator_assembled()),
            &store_dir,
            &NarHashKey::from_sha256_bytes([0xAB; 32]),
            &store_path,
        );
        assert!(
            refused.is_err(),
            "a fetched path whose bytes do not hash to the registered NarHash must never be \
             announced; got {refused:?}"
        );
    }

    /// AC#3 FIX C BITE: `validate_store_path` requires the path DIRECTLY under the real store dir -
    /// a store-SHAPED decoy elsewhere (`/tmp/store/<validhash>-x`) is rejected before any dump.
    #[test]
    fn validate_store_path_requires_the_real_store_dir() {
        assert!(validate_store_path(&format!("/nix/store/{HASH32}-ok"), STORE_DIR).is_ok());
        assert!(
            validate_store_path("relative/path", STORE_DIR).is_err(),
            "not absolute"
        );
        assert!(
            validate_store_path("/etc/shadow", STORE_DIR).is_err(),
            "not a store path"
        );
        assert!(
            validate_store_path(&format!("/nix/store/{HASH32}-x/nested"), STORE_DIR).is_err(),
            "not directly under the store dir"
        );
        assert!(
            validate_store_path("/nix/store/tooshorthash-x", STORE_DIR).is_err(),
            "hash not 32 nix-base32 chars"
        );
        assert!(
            validate_store_path("/nix/store/0123456789abcdefghijklmnpqrsvwxy-x", STORE_DIR)
                .is_err(),
            "'e' is not in the nix-base32 alphabet"
        );
        // FIX C: a store-shaped path under a DIFFERENT parent (a decoy) is rejected.
        assert!(
            validate_store_path(&format!("/tmp/store/{HASH32}-x"), STORE_DIR).is_err(),
            "a /tmp/store decoy is not the real /nix/store"
        );
    }
}
