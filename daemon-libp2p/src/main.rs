//! `daemon-libp2p` - the PRIMARY per-backend thin binary (docs/peer-fabric-seam.md).
//!
//! `daemon-libp2p = daemon-core + fabric-libp2p`: a pure single-stack libp2p node (libp2p-kad
//! discovery + libp2p NAR transfer) with an HTTP-upstream fallback. The binary IS the backend
//! choice - no features, no `cfg`: `fn main` constructs a `Libp2pFabric` (started + DHT-joined
//! by the shared construction in this crate's lib), then calls [`daemon_core::run`]. Its
//! dependency closure contains NO iroh; `tests/no_iroh_closure_guard.rs` proves it from
//! `cargo metadata`, which is the DEFINITIVE de-weld guarantee (a real crate graph, not a
//! content ratchet).

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use daemon_core::cacheinfo::DEFAULT_PRIORITY;
use daemon_core::{
    AvailabilityIndex, CommandNarDumper, NarDumper, NodeId, NullAnnounce, NullStore,
    RegularFileNarDumper, StorePath,
};
use daemon_core::{
    CacheInfo, ContractRequest, CorrelationStore, DhtRole, METRICS_PATH, Mechanism,
    NARINFO_CACHE_FLAG_CONFLICT, NarSource, NarinfoLayer, NarinfoSource, NullStatusFacts,
    Observability, OperatorContract, PassThroughReason, PrivacyPolicy, PublicNarAllowlist,
    RawUpstream, ResourceCaps, RunConfig, RuntimeMetrics, STATUS_PATH, SharingProfile, StatusFacts,
    SystemClock, UpstreamHttp, build_narinfo_layer, resolve_narinfo_cache_dir, run,
};
use daemon_libp2p::{
    AnnounceAfterFetchDoor, InitialAnnounceConfig, LAN_SHARE_SCOPE_HINT, LanReachability, LanShare,
    Libp2pAnnounceAfterFetch, Libp2pCatalogProbe, Libp2pSourceConfig, PublicationPlan,
    SeedResignAuthority, SeedResignTask, StoreProvision, SwarmStatusFacts, announce_provider_seeds,
    announce_public_supply, announce_store_provisions, build_libp2p_nar_source,
    build_libp2p_provider_source, disclose_then_activate_serve, effective_network_scope,
    lan_isolation_or_refuse, lan_serving_disclosures, open_public_allowlist,
    resolve_durable_identity_seed, should_hint_lan_share_scope, spawn_seed_resign,
    verify_store_provisions,
};
use ed25519_dalek::SigningKey;
use fabric_libp2p::{
    CatalogNarSupplier, Libp2pFabric, Libp2pNarSupplier, MAX_RECORD_TTL_SECS, MemoryNarSupplier,
    Multiaddr, PeerId, UnionNarSupplier, raw_nar_helper_authorized,
};
use peer_fabric::{
    AnnounceBudget, Axis, DiscoveryBudget, LeechFabric, PeerFabric, SafetyEnvelope, ServeBudget,
    ServeHandle, TransportTag,
};
use tokio::net::TcpListener;

// The serve/announce bounds are NO LONGER local constants: they are DERIVED from the ONE
// authoritative `daemon_core::ResourceCaps` (TASK-120 AC#3/#9), so this binary cannot silently
// disagree with the documented operator contract. `provider_serve_budget()` and
// `DEFAULT_LIBP2P_ANNOUNCE_BUDGET` read `ResourceCaps::default()`; a parity test asserts it.

struct Config {
    listen: SocketAddr,
    upstream: String,
    header_timeout_ms: u64,
    narinfo_cache_dir: Option<String>,
    /// Explicit opt-out of the (default-on, TASK-29) narinfo disk cache.
    no_narinfo_cache: bool,
    store_dir: String,
    priority: u32,
    want_mass_query: bool,
    libp2p_bootstrap: Vec<(PeerId, Multiaddr)>,
    libp2p_provider_addrs: Vec<(PeerId, Multiaddr)>,
    /// `--libp2p-listen` bind multiaddrs, REPEATABLE (TASK-207). Every address is handed to the
    /// shared construction and registered before one bounded readiness wait. A NAT'd provider
    /// needs two: a real transport bind (so the relay-client can
    /// open its reservation connection) AND a relay `/…/p2p-circuit` address (the reservation
    /// request) - the two `listen()` calls `fabric-libp2p/tests/nat_traversal.rs` makes.
    libp2p_listen: Vec<Multiaddr>,
    /// `--libp2p-external-address` self-advertised reachable multiaddrs, REPEATABLE (TASK-207).
    /// Wired to the existing `SwarmHandle::add_external_address` so identify propagates them and,
    /// on a relay node, the circuit-v2 SERVER can cite them in reservation vouchers (without a
    /// known external address a relay answers reservations with `NoAddressesInReservation`). This
    /// advertises the node's OWN address (like autonat/identify), never a third-party dial hint.
    libp2p_external_addresses: Vec<Multiaddr>,
    libp2p_scope: Option<String>,
    /// TASK-257: `--libp2p-mdns` opts into LAN mDNS peer-ADDRESS discovery. DEFAULT OFF. When set,
    /// the swarm installs the mDNS behaviour (link-local multicast) so a same-scope LAN neighbour is
    /// discovered with NO `--libp2p-bootstrap`; discovered addresses feed the SAME kad bootstrap
    /// path an explicit bootstrap uses and NEVER content discovery. It is TASK-120 axis-1 (local
    /// discovery) only - it implies NOTHING about serving/announcing/public participation - and is
    /// REFUSED under upstream-only (which runs no swarm at all). Scope isolation is orthogonal and
    /// already enforced by the scoped kad/identify protocol names.
    ///
    /// TASK-273: TRI-STATE. `None` = operator made NO choice, follow the profile default
    /// ([`SharingProfile::default_lan_mdns`]: ON for lan-share, OFF otherwise); `Some(true)` =
    /// explicit `--libp2p-mdns`; `Some(false)` = explicit `--libp2p-no-mdns` opt-out. This RAW
    /// opt-in is what the profile-DERIVATION `has_bootstrap` inference consumes (only `Some(true)`
    /// counts, never the resolved default — that would be circular); the RESOLVED value lives in
    /// [`Config::mdns_active`].
    libp2p_mdns: Option<bool>,
    /// TASK-273: the RESOLVED mDNS decision, `libp2p_mdns.unwrap_or(profile.default_lan_mdns())`,
    /// computed ONCE in `parse_config` AFTER the profile is derived. Every RUNTIME site (the
    /// contract's `lan_mdns_enabled`, the selected-mechanism registry, the swarm's `mdns_enabled`,
    /// and the undiscoverable-provider guard) reads THIS, never the raw opt-in, so the reported and
    /// wired mDNS state cannot drift from the profile default.
    mdns_active: bool,
    /// TASK-258 SPIKE: `--libp2p-mainline-rendezvous` opts into using the BitTorrent Mainline
    /// DHT as a peer-ADDRESS RENDEZVOUS (announce membership under one well-known infohash;
    /// `get_peers` it to learn member addresses that feed the SAME kad bootstrap path). DEFAULT
    /// OFF. It is PUBLIC-network participation (unlike LAN mDNS), so it is REFUSED fail-closed
    /// under `upstream-only` AND `lan-share` (the two zero-egress profiles — the Wave-2c privacy
    /// contract says lan-share emits ZERO packets to public DHT/Mainline infrastructure). Under
    /// `consume-only` it is surfaced as public participation. There is NO default bootstrap (we
    /// never contact router.bittorrent.com), so it REQUIRES at least one
    /// `--libp2p-mainline-bootstrap`. NB (spike honesty): this binary does NOT itself run the
    /// Mainline DHT yet — the flag is the operator-contract scaffold (refusal + surfacing);
    /// live Mainline execution lives in the `rendezvous-spike` bin and is the deferred
    /// adoption productionization (AC#9/#10/#11). It supplies ADDRESSES only, never content
    /// discovery (scripts/check-discovery-no-shortcut.py enforces that structurally).
    libp2p_mainline_rendezvous: bool,
    /// TASK-258: the LOCAL Mainline DHT entry point(s) `host:port` the rendezvous bootstraps
    /// against. REPEATABLE. There is deliberately NO default (no public router), so an enabled
    /// rendezvous with an empty list fails closed.
    libp2p_mainline_bootstrap: Vec<String>,
    libp2p_identity_seed: Option<[u8; 32]>,
    libp2p_provider: bool,
    libp2p_seed_nar: Vec<(daemon_core::NarHashKey, String)>,
    /// TASK-191: real `/nix/store` paths served on demand via `nix-store --dump`, holding no
    /// .nar at rest (`<narhash>=<storepath>`). Verification-gated by the availability index
    /// (TASK-56) before announce.
    libp2p_provide_store: Vec<(daemon_core::NarHashKey, String)>,
    libp2p_print_peer_address: bool,
    /// Per-node durable state directory (TASK-185): when set, the fabric persists its
    /// anti-rollback floor + per-key announce sequence here and re-seeds them on restart.
    libp2p_state_dir: Option<std::path::PathBuf>,
    // ---- libp2p PUBLIC-announce allowlist config (TASK-103/204) --------------
    // Setting `--libp2p-public-allowlist-path` puts a PROVIDER into PUBLIC-announce mode: its
    // seeds/store paths are announced over a (bootstrapped) public substrate ONLY after each is
    // proven public through a trusted narinfo signature. The allowlist IS the enforcement,
    // replacing the isolated-LAN `lan_share_or_refuse` stopgap for the bootstrapped case. This
    // mirrors the composite `daemon` binary's wiring (TASK-204: parity, one policy source).
    /// Trusted narinfo-signing keys in the Nix `trusted-public-keys` format
    /// (`name:<base64 ed25519 pubkey>`, repeatable). A NAR is proven public ONLY by a signature
    /// from one of THESE keys; the operator naming a path does not make it public.
    libp2p_trusted_public_keys: Vec<String>,
    /// The on-disk, MAC-integrity-protected public-NAR allowlist file. Its presence switches a
    /// provider to PUBLIC-announce mode. The MAC key is derived from the durable identity seed.
    libp2p_public_allowlist_path: Option<std::path::PathBuf>,
    /// Narinfos to PROVE public at startup (`<requested-store-hash>=<path/to/narinfo>`,
    /// repeatable): each is verified against the trusted keys and correlated to its store hash,
    /// then its `(NarHash, NarSize)` is appended to the allowlist so the announce gate can approve
    /// the matching seed/store path.
    libp2p_prove_public_narinfo: Vec<(String, String)>,
    /// Whether this node runs the circuit-v2 relay SERVER (TASK-207). Default `true` (a public
    /// node helps NAT'd peers with no dedicated relay). `--libp2p-no-relay-server` sets it
    /// `false` for a kad-only node (a dedicated bootstrap that offers NO reservation service),
    /// leaving relay-client/autonat/dcutr intact. Threads to `NodeConfig::with_relay_server`.
    libp2p_relay_server_enabled: bool,
    /// ANNOUNCE-AFTER-FETCH (TASK-77): a successful peer/upstream fetch makes this node a
    /// discoverable HOLDER (register the realised store path, then announce it through the
    /// verification-gated + eligibility-gated door). Puts the node into provider mode (serve axis
    /// and announcer) even with an EMPTY initial supply set. DEFAULT OFF = consume-only / leech
    /// (TASK-78). Mirrors the composite `daemon` binary.
    libp2p_announce_after_fetch: bool,
    /// The INTEGER announce-after-fetch BUDGET (TASK-77 AC#2): max DISTINCT fetched paths this
    /// process announces. Past it, announcing STOPS. Never a float.
    libp2p_announce_budget: u64,
    /// The SIGNED provider-record TTL in seconds (TASK-285): every announced record is stamped with
    /// `expiry = now + this`, and the durable seed leg is periodically RE-SIGNED at `ttl/2` before it
    /// lapses. DEFAULT 3600 (1h); the `--libp2p-record-ttl-secs` flag drives a SHORT TTL so an e2e can
    /// prove the re-sign keeps a seed discoverable past a full TTL window without waiting hours.
    /// Bounded `2 ..= MAX_RECORD_TTL_SECS` (a `<2` TTL cannot be kept lapse-free by a `ttl/2` refresh;
    /// an over-cap TTL the announcer would reject anyway). Never a float.
    libp2p_record_ttl_secs: u64,
    /// TASK-120 AC#7: `--preflight` renders the one-command operator preflight (the selected
    /// [`SharingProfile`], the enabled/pending mechanism registry, external dependencies, and the
    /// effective integer resource + privacy controls) to stdout and EXITS before any socket is
    /// bound or any P2P traffic is emitted. A pure static read of the authoritative contract.
    preflight: bool,
    /// TASK-120 AC#5: `--diagnostics` opts into verbose diagnostics that MAY include otherwise
    /// redacted identifiers (StorePath / NarHash / peer IP / full NodeId). DEFAULT OFF; when set
    /// the node prints the mandatory [`daemon_core::DIAGNOSTICS_WARNING`] banner.
    diagnostics: bool,
    /// TASK-120 (authority inversion): the operator's EXPLICIT `--profile <token>` declaration, if
    /// given. The legacy give/consume flags are a validated COMPAT SHIM: the profile DERIVED from
    /// them must EQUAL this declaration, else `parse_config` fails closed (so
    /// `--profile upstream-only --libp2p-provider` can never pass silently).
    explicit_profile: Option<String>,
    /// The AUTHORITATIVE participation MODE, derived from the flags (and cross-checked against
    /// `explicit_profile`). This - NOT the raw `libp2p_provider`/`libp2p_leech` booleans - is what
    /// the RUNTIME branches on: the serve gate is installed IFF `profile.serves()`, and the
    /// consume-only [`LeechFabric`] mask is applied IFF `!profile.serves()`.
    profile: SharingProfile,
    /// LEECH / consume-only mode (TASK-78): an affirmative opt-out of contributing uplink. A leech
    /// still FETCHES from peers, but its fabric is wrapped in a [`peer_fabric::LeechFabric`] so the
    /// SERVE and ANNOUNCE axes are masked to `None` at the transport-agnostic capability seam - it
    /// serves nothing and announces nothing. Mutually exclusive with every provider/serve flag (a
    /// leech gives nothing back), enforced fail-fast in `parse_config`. HONEST LIMIT: a leech still
    /// SENDS its discovery lookups (get_record / peer-routing), so it hides what it serves and
    /// announces, NOT what it looks up.
    libp2p_leech: bool,
    /// ROUTER / bootstrap-relay mode (TASK-241): an EXPLICIT request to run as a kad SERVER (a
    /// bootstrap/entry root that answers FIND_NODE/GET_PROVIDERS) plus, by default, a
    /// circuit-v2 relay server — carrying NO content (serves + announces NOTHING). It is the
    /// DHT-infrastructure role the give/consume modes cannot express: `consume-only` is a kad
    /// CLIENT (cannot be a bootstrap root) and the provider modes require content to serve.
    /// Derives [`SharingProfile::Router`]; mutually exclusive with every give-side flag (a router
    /// that serves would be a backdoor), enforced fail-fast in `parse_config` and again by
    /// `SharingProfile::derive`. Threads to `NodeConfig::with_kad_server(true)` + the relay server.
    libp2p_router: bool,
    /// TASK-240 AC#4/#5: the DEDICATED admin listener address for the operator observability
    /// surfaces (`/nix-p2p/status`, `/nix-p2p/metrics`). `None` (the DEFAULT) = no admin surface at
    /// all — the fail-safe posture. An operator opts in with `--status-listen <addr>` and SHOULD
    /// bind a loopback address (`127.0.0.1:<port>`): the surface is served on its OWN listener, NEVER
    /// on the peer-facing cache listener, so the trust boundary is structural, not redaction alone.
    status_listen: Option<std::net::SocketAddr>,
}

/// TASK-273 (#8): `--libp2p-mdns` and `--libp2p-no-mdns` are contradictory; passing both is
/// ambiguous, so `parse_config` fails closed with this message rather than silently last-wins.
const LIBP2P_MDNS_FLAG_CONTRADICTION: &str =
    "pass exactly one of --libp2p-mdns / --libp2p-no-mdns, not both (contradictory mDNS intent)";

/// The default announce-after-fetch budget (distinct paths announced before growth stops). An
/// integer; the operator raises it with `--libp2p-announce-budget`. Sourced from the ONE
/// authoritative [`ResourceCaps`] so it cannot drift from the documented contract (TASK-120).
fn default_libp2p_announce_budget() -> u64 {
    ResourceCaps::default().announce_distinct_paths_budget
}

/// The default SIGNED provider-record TTL, in seconds (TASK-285): 1h, a generous refresh cadence
/// well below the `MAX_RECORD_TTL_SECS` (24h) announcer cap. The durable seed leg is re-signed at
/// half this before it lapses. `--libp2p-record-ttl-secs` overrides it (bounded) so an e2e can use a
/// short TTL. Kept equal to the composite `daemon` binary's default so the two do not drift.
const DEFAULT_LIBP2P_RECORD_TTL_SECS: u64 = 3600;

/// TASK-240: if invoked as `daemon-libp2p --status <addr>` / `--metrics <addr>`, QUERY a running
/// instance's admin surface over HTTP and print the (already-redacted) response, then exit. Returns
/// `None` for the normal daemon path (so `fn main` proceeds to build a node). Handled BEFORE
/// `parse_config` so the client flags never collide with the daemon flag grammar.
async fn maybe_run_admin_query() -> Option<ExitCode> {
    let mut args = std::env::args().skip(1);
    let first = args.next()?;
    let path = match first.as_str() {
        "--status" => STATUS_PATH,
        "--metrics" => METRICS_PATH,
        _ => return None,
    };
    let Some(addr) = args.next() else {
        eprintln!(
            "daemon-libp2p: {first} requires an <addr> (the host:port of a running --status-listen)"
        );
        return Some(ExitCode::from(2));
    };
    match admin_get(&addr, path).await {
        Ok(body) => {
            print!("{body}");
            Some(ExitCode::SUCCESS)
        }
        Err(err) => {
            eprintln!("daemon-libp2p: {first} query to {addr} failed: {err}");
            Some(ExitCode::FAILURE)
        }
    }
}

/// A minimal loopback HTTP/1.0 GET of an admin endpoint: connect, request `Connection: close`, read
/// to EOF, return the body (everything after the blank line). HTTP/1.0 + close makes read-to-EOF
/// unambiguous, so no chunked/length parsing is needed — and this is a client of our OWN loopback
/// admin server, not a parser behind a trust boundary.
async fn admin_get(addr: &str, path: &str) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| format!("read: {e}"))?;
    let text = String::from_utf8_lossy(&raw);
    match text.split_once("\r\n\r\n") {
        Some((head, body)) => {
            let status_line = head.lines().next().unwrap_or("");
            if !status_line.contains(" 200 ") {
                return Err(format!("admin endpoint returned: {status_line}"));
            }
            Ok(body.to_string())
        }
        None => Err("malformed HTTP response (no header/body separator)".to_string()),
    }
}

/// Build the ONE authoritative [`OperatorContract`] from the parsed [`Config`] (TASK-120 AC#9).
/// The [`SharingProfile`] was ALREADY derived + cross-checked against `--profile` in
/// `parse_config` (and stored in `cfg.profile`); this attaches the authoritative caps + privacy
/// stance and validates. daemon-libp2p is the libp2p-primary binary, so it selects no deferred
/// reference mechanism (no iroh give-side here); `active_reference_mechanisms` is empty.
fn build_contract(cfg: &Config) -> Result<OperatorContract, String> {
    // FIX A: the reported DHT role is what the swarm ACTUALLY runs, derived from the SAME profile
    // that drives the kad mode in `source_config` (upstream-only builds no swarm, consume-only is a
    // kad CLIENT, a provider is a kad SERVER) - so the report cannot drift from the wire.
    let dht_role = match cfg.profile {
        SharingProfile::UpstreamOnly => DhtRole::None,
        SharingProfile::ConsumeOnly => DhtRole::Client,
        // A provider AND a router both run a kad SERVER (a router IS the infrastructure role).
        SharingProfile::LanShare | SharingProfile::PublicShare | SharingProfile::Router => {
            DhtRole::Server
        }
    };
    // TASK-240 (SSOT): the contract's announce-budget cap is the EFFECTIVE one the operator chose
    // (`--libp2p-announce-budget`, default = the authoritative `ResourceCaps` value), so the LIVE
    // status/preflight denominator (`announce_budget=used/CAP`) equals the cap the announce gate
    // actually enforces — the flag drives BOTH, never a stale default alongside an overridden gate.
    let caps = ResourceCaps {
        announce_distinct_paths_budget: cfg.libp2p_announce_budget,
        ..ResourceCaps::default()
    };
    // TASK-257: when --libp2p-mdns is set, the operator has SELECTED the shipped LAN mDNS
    // peer-address mechanism. Naming it in `selected_mechanisms` puts it through the fail-closed
    // `validate` gate (it is Enabled, so it passes) and surfaces it as an operator override; the
    // per-node `lan_mdns_enabled` flag is what drives the status/preflight active+exposure report.
    let selected_mechanisms = if cfg.mdns_active {
        vec![Mechanism::LanMdns]
    } else {
        Vec::new()
    };
    let contract = OperatorContract {
        profile: cfg.profile,
        caps,
        privacy: PrivacyPolicy {
            diagnostics_opt_in: cfg.diagnostics,
        },
        selected_mechanisms,
        active_reference_mechanisms: Vec::new(),
        dht_role,
        lan_mdns_enabled: cfg.mdns_active,
        // TASK-241: does this node advertise a PUBLIC/reachable self-address? `--libp2p-external-address`
        // is the operator's explicit "I am reachable here" declaration (a relay/bootstrap sets it so
        // peers can dial it). This makes a PUBLIC router's `public_dht_participation` report the honest
        // `true` (a publicly-reachable kad-server + relay) while a LAN-isolated router reports `false` -
        // the report matches the wire. Inert for the give/consume modes (their public participation is
        // intrinsic).
        advertises_public_reachability: !cfg.libp2p_external_addresses.is_empty(),
    };
    contract.validate().map_err(|e| e.to_string())?;
    Ok(contract)
}

fn parse_libp2p_peer(flag: &str, raw: &str) -> Result<(PeerId, Multiaddr), String> {
    let (peer_str, addr_str) = raw
        .split_once('@')
        .ok_or_else(|| format!("bad {flag} {raw:?}: expected <PeerId>@<multiaddr>"))?;
    let peer: PeerId = peer_str
        .parse()
        .map_err(|e| format!("bad {flag} PeerId {peer_str:?}: {e}"))?;
    let addr: Multiaddr = addr_str
        .parse()
        .map_err(|e| format!("bad {flag} multiaddr {addr_str:?}: {e}"))?;
    Ok((peer, addr))
}

fn parse_libp2p_seed(raw: &str) -> Result<[u8; 32], String> {
    if raw.len() != 64 {
        return Err(format!(
            "bad --libp2p-identity-seed: expected 64 hex chars (32 bytes), got {}",
            raw.len()
        ));
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[2 * i..2 * i + 2], 16)
            .map_err(|e| format!("bad --libp2p-identity-seed hex at byte {i}: {e}"))?;
    }
    Ok(seed)
}

fn parse_libp2p_seed_nar(raw: &str) -> Result<(daemon_core::NarHashKey, String), String> {
    let (nar_hash, path) = raw.split_once('=').ok_or_else(|| {
        format!("bad --libp2p-seed-nar {raw:?}: expected <narhash>=<path/to/raw.nar>")
    })?;
    let key: daemon_core::NarHashKey = nar_hash
        .parse()
        .map_err(|e| format!("bad --libp2p-seed-nar NarHash {nar_hash:?}: {e}"))?;
    if path.is_empty() {
        return Err(format!("bad --libp2p-seed-nar {raw:?}: empty file path"));
    }
    Ok((key, path.to_string()))
}

/// Parse `--libp2p-prove-public-narinfo <requested-store-hash>=<path/to/narinfo>`: the store hash
/// the narinfo must correlate to (its signed StorePath's `<hash>`) and the narinfo file to prove
/// public. The store hash is an opaque correlation token the allowlist compares against the signed
/// StorePath; only its non-emptiness is checked here. Mirrors the composite `daemon` binary.
fn parse_prove_public_narinfo(raw: &str) -> Result<(String, String), String> {
    let (store_hash, path) = raw.split_once('=').ok_or_else(|| {
        format!(
            "bad --libp2p-prove-public-narinfo {raw:?}: expected <store-hash>=<path/to/narinfo>"
        )
    })?;
    if store_hash.is_empty() {
        return Err(format!(
            "bad --libp2p-prove-public-narinfo {raw:?}: empty store hash"
        ));
    }
    if path.is_empty() {
        return Err(format!(
            "bad --libp2p-prove-public-narinfo {raw:?}: empty narinfo path"
        ));
    }
    Ok((store_hash.to_string(), path.to_string()))
}

fn parse_config<I: IntoIterator<Item = String>>(args: I) -> Result<Config, String> {
    let mut cfg = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: "https://cache.nixos.org".to_string(),
        header_timeout_ms: 30_000,
        narinfo_cache_dir: None,
        no_narinfo_cache: false,
        store_dir: "/nix/store".to_string(),
        priority: DEFAULT_PRIORITY,
        want_mass_query: true,
        libp2p_bootstrap: Vec::new(),
        libp2p_provider_addrs: Vec::new(),
        libp2p_listen: Vec::new(),
        libp2p_external_addresses: Vec::new(),
        libp2p_scope: None,
        libp2p_mdns: None,
        // Provisional; parse_config recomputes it from the RAW opt-in + derived profile below.
        mdns_active: false,
        libp2p_mainline_rendezvous: false,
        libp2p_mainline_bootstrap: Vec::new(),
        libp2p_identity_seed: None,
        libp2p_provider: false,
        libp2p_seed_nar: Vec::new(),
        libp2p_provide_store: Vec::new(),
        libp2p_print_peer_address: false,
        libp2p_state_dir: None,
        libp2p_trusted_public_keys: Vec::new(),
        libp2p_public_allowlist_path: None,
        libp2p_prove_public_narinfo: Vec::new(),
        libp2p_relay_server_enabled: true,
        libp2p_announce_after_fetch: false,
        libp2p_announce_budget: default_libp2p_announce_budget(),
        libp2p_record_ttl_secs: DEFAULT_LIBP2P_RECORD_TTL_SECS,
        libp2p_leech: false,
        libp2p_router: false,
        status_listen: None,
        preflight: false,
        diagnostics: false,
        explicit_profile: None,
        // Provisional; parse_config recomputes it from the flags (+ cross-checks explicit_profile)
        // before returning. UpstreamOnly is the fail-safe placeholder.
        profile: SharingProfile::UpstreamOnly,
    };
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .ok_or_else(|| format!("flag {flag} requires a value"))
        };
        match flag.as_str() {
            "--listen" => {
                cfg.listen = value()?.parse().map_err(|e| format!("bad --listen: {e}"))?
            }
            "--upstream" => cfg.upstream = value()?,
            "--header-timeout-ms" => {
                cfg.header_timeout_ms = value()?
                    .parse()
                    .map_err(|e| format!("bad --header-timeout-ms: {e}"))?;
                if cfg.header_timeout_ms == 0 {
                    return Err("--header-timeout-ms must be positive".into());
                }
            }
            "--narinfo-cache-dir" => cfg.narinfo_cache_dir = Some(value()?),
            "--no-narinfo-cache" => cfg.no_narinfo_cache = true,
            "--store-dir" => cfg.store_dir = value()?,
            "--priority" => {
                cfg.priority = value()?
                    .parse()
                    .map_err(|e| format!("bad --priority: {e}"))?
            }
            "--libp2p-bootstrap" => cfg
                .libp2p_bootstrap
                .push(parse_libp2p_peer("--libp2p-bootstrap", &value()?)?),
            "--libp2p-provider-addr" => cfg
                .libp2p_provider_addrs
                .push(parse_libp2p_peer("--libp2p-provider-addr", &value()?)?),
            "--libp2p-listen" => cfg.libp2p_listen.push(
                value()?
                    .parse()
                    .map_err(|e| format!("bad --libp2p-listen multiaddr: {e}"))?,
            ),
            "--libp2p-external-address" => cfg.libp2p_external_addresses.push(
                value()?
                    .parse()
                    .map_err(|e| format!("bad --libp2p-external-address multiaddr: {e}"))?,
            ),
            "--libp2p-scope" => cfg.libp2p_scope = Some(value()?),
            // TASK-273: tri-state opt-in. Explicit ON, and an explicit opt-out that must REACH the
            // daemon (so a lan-share operator can decline LAN discovery and get the fail-loud guard
            // instead of a silent default-on). `None` (neither flag) follows the profile default.
            // FAIL-CLOSED (#8): the two are CONTRADICTORY — passing both (either order) is ambiguous
            // intent, so reject it rather than silently last-wins.
            "--libp2p-mdns" => {
                if cfg.libp2p_mdns == Some(false) {
                    return Err(LIBP2P_MDNS_FLAG_CONTRADICTION.into());
                }
                cfg.libp2p_mdns = Some(true);
            }
            "--libp2p-no-mdns" => {
                if cfg.libp2p_mdns == Some(true) {
                    return Err(LIBP2P_MDNS_FLAG_CONTRADICTION.into());
                }
                cfg.libp2p_mdns = Some(false);
            }
            "--libp2p-mainline-rendezvous" => cfg.libp2p_mainline_rendezvous = true,
            "--libp2p-mainline-bootstrap" => {
                let raw = value()?;
                // Validate as SocketAddrV4 at parse time (fail fast, no silent bad address).
                raw.parse::<std::net::SocketAddrV4>().map_err(|e| {
                    format!("bad --libp2p-mainline-bootstrap host:port {raw:?}: {e}")
                })?;
                cfg.libp2p_mainline_bootstrap.push(raw);
            }
            "--libp2p-identity-seed" => {
                cfg.libp2p_identity_seed = Some(parse_libp2p_seed(&value()?)?)
            }
            "--libp2p-provider" => cfg.libp2p_provider = true,
            "--libp2p-state-dir" => cfg.libp2p_state_dir = Some(value()?.into()),
            "--libp2p-seed-nar" => cfg.libp2p_seed_nar.push(parse_libp2p_seed_nar(&value()?)?),
            "--libp2p-provide-store" => cfg
                .libp2p_provide_store
                .push(parse_libp2p_seed_nar(&value()?)?),
            "--libp2p-print-peer-address" => cfg.libp2p_print_peer_address = true,
            "--libp2p-no-relay-server" => cfg.libp2p_relay_server_enabled = false,
            "--libp2p-trusted-public-key" => cfg.libp2p_trusted_public_keys.push(value()?),
            "--libp2p-public-allowlist-path" => {
                cfg.libp2p_public_allowlist_path = Some(value()?.into())
            }
            "--libp2p-prove-public-narinfo" => cfg
                .libp2p_prove_public_narinfo
                .push(parse_prove_public_narinfo(&value()?)?),
            "--libp2p-announce-after-fetch" => cfg.libp2p_announce_after_fetch = true,
            "--libp2p-leech" => cfg.libp2p_leech = true,
            "--libp2p-router" => cfg.libp2p_router = true,
            "--status-listen" => {
                cfg.status_listen = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("bad --status-listen: {e}"))?,
                )
            }
            "--preflight" => cfg.preflight = true,
            "--diagnostics" => cfg.diagnostics = true,
            "--profile" => cfg.explicit_profile = Some(value()?),
            "--libp2p-announce-budget" => {
                let raw = value()?;
                cfg.libp2p_announce_budget = raw.parse::<u64>().map_err(|e| {
                    format!("--libp2p-announce-budget {raw:?} is not a non-negative integer: {e}")
                })?;
            }
            "--libp2p-record-ttl-secs" => {
                let raw = value()?;
                let ttl = raw.parse::<u64>().map_err(|e| {
                    format!("--libp2p-record-ttl-secs {raw:?} is not a non-negative integer: {e}")
                })?;
                // A `<2` TTL cannot be kept lapse-free by a `ttl/2` refresh, and an over-cap TTL the
                // announcer would reject at publish — so bound it fail-fast here (TASK-285).
                if !(2..=MAX_RECORD_TTL_SECS).contains(&ttl) {
                    return Err(format!(
                        "--libp2p-record-ttl-secs must be in 2..={MAX_RECORD_TTL_SECS} seconds, got {ttl}"
                    ));
                }
                cfg.libp2p_record_ttl_secs = ttl;
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    // TASK-29: naming a narinfo cache dir AND opting out is contradictory; reject
    // it at parse time (shares the error string with the composite `daemon` binary
    // via NARINFO_CACHE_FLAG_CONFLICT so the two cannot drift).
    if cfg.narinfo_cache_dir.is_some() && cfg.no_narinfo_cache {
        return Err(NARINFO_CACHE_FLAG_CONFLICT.into());
    }
    // TASK-78 LEECH mode is consume-only: it masks the SERVE + ANNOUNCE axes at the seam, so it is
    // contradictory with every flag that makes this node GIVE content back. Reject the combination
    // fail-fast rather than silently mask a provider the operator asked for (a leech that serves
    // would be a lie). This is the one authoritative check; the give-side flags below
    // (`--libp2p-provider` and its allowlist companions) additionally guard themselves.
    if cfg.libp2p_leech {
        let give_side = [
            ("--libp2p-provider", cfg.libp2p_provider),
            (
                "--libp2p-announce-after-fetch",
                cfg.libp2p_announce_after_fetch,
            ),
            ("--libp2p-seed-nar", !cfg.libp2p_seed_nar.is_empty()),
            (
                "--libp2p-provide-store",
                !cfg.libp2p_provide_store.is_empty(),
            ),
            (
                "--libp2p-public-allowlist-path",
                cfg.libp2p_public_allowlist_path.is_some(),
            ),
            (
                "--libp2p-trusted-public-key",
                !cfg.libp2p_trusted_public_keys.is_empty(),
            ),
            (
                "--libp2p-prove-public-narinfo",
                !cfg.libp2p_prove_public_narinfo.is_empty(),
            ),
        ];
        if let Some((flag, _)) = give_side.iter().find(|(_, present)| *present) {
            return Err(format!(
                "--libp2p-leech is consume-only (it serves nothing and announces nothing); it \
                 cannot be combined with {flag}. Drop the give-side flag or drop --libp2p-leech."
            ));
        }
    }
    // TASK-241 ROUTER mode is a kad-server + relay that carries NO content: like a leech it must
    // GIVE nothing back, so it is contradictory with every give-side flag (and with --libp2p-leech,
    // which is the OTHER non-serving mode - a node is one or the other, not both). Reject fail-fast
    // rather than silently drop the flag; `SharingProfile::derive` re-checks this transport-agnostically.
    if cfg.libp2p_router {
        let incompatible = [
            ("--libp2p-provider", cfg.libp2p_provider),
            (
                "--libp2p-announce-after-fetch",
                cfg.libp2p_announce_after_fetch,
            ),
            ("--libp2p-seed-nar", !cfg.libp2p_seed_nar.is_empty()),
            (
                "--libp2p-provide-store",
                !cfg.libp2p_provide_store.is_empty(),
            ),
            (
                "--libp2p-public-allowlist-path",
                cfg.libp2p_public_allowlist_path.is_some(),
            ),
            (
                "--libp2p-trusted-public-key",
                !cfg.libp2p_trusted_public_keys.is_empty(),
            ),
            (
                "--libp2p-prove-public-narinfo",
                !cfg.libp2p_prove_public_narinfo.is_empty(),
            ),
            ("--libp2p-leech", cfg.libp2p_leech),
        ];
        if let Some((flag, _)) = incompatible.iter().find(|(_, present)| *present) {
            return Err(format!(
                "--libp2p-router is a pure kad-server + relay that carries NO content (serves \
                 nothing, announces nothing); it cannot be combined with {flag}. Drop it, or drop \
                 --libp2p-router."
            ));
        }
    }
    // TASK-273: an explicit provider `--profile lan-share` IS the give-side intent, so it back-fills
    // the provider axis. Without this a bare `--profile lan-share` (no `--libp2p-provider`) would
    // derive UPSTREAM-ONLY and then fail the compat-shim cross-check below — the exact "lan-share is
    // not zero-config" gap. lan-share is a PROVIDER (is_provider, no public allowlist), so setting
    // the flag makes the derivation AGREE with the declaration while keeping the cross-check honest
    // (e.g. `--profile lan-share --libp2p-leech` still fails closed as LeechServes). public-share is
    // intentionally NOT back-filled: it additionally requires its allowlist flags, so `--profile
    // public-share` alone must still fail loud (declared public-share != derived lan-share).
    //
    // TASK-279 AC#3 (parse ordering): this back-fill MUST run BEFORE the `--libp2p-announce-after-
    // fetch` PROVIDER-companion check below. `--profile lan-share --libp2p-seed-nar S
    // --libp2p-announce-after-fetch` (NO explicit `--libp2p-provider`) is the NORTH-STAR zero-config
    // combo: the back-fill makes `libp2p_provider` true so the companion check sees a provider and
    // the config parses, instead of rejecting the operator's own declared give-side intent. It is
    // placed AFTER the leech/router give-side checks so `--profile lan-share --libp2p-leech` still
    // fails closed at derivation (LeechServes), not with a confusing "leech + --libp2p-provider"
    // message for a flag the operator never passed.
    if cfg.explicit_profile.as_deref() == Some(SharingProfile::LanShare.as_str()) {
        cfg.libp2p_provider = true;
    }

    // --libp2p-announce-after-fetch is a PROVIDER companion (it needs the serve axis + announcer):
    // reject it on a consumer rather than silently ignore it.
    if cfg.libp2p_announce_after_fetch && !cfg.libp2p_provider {
        return Err(
            "--libp2p-announce-after-fetch requires --libp2p-provider (announcing what you fetched \
             needs the serve axis + announcer)"
                .into(),
        );
    }
    // TASK-278: `--libp2p-seed-nar` + `--libp2p-announce-after-fetch` is now VALID - `install_provider`
    // builds an ADDITIVE union (seed leg + store leg), so the seed is served AND the node grows via
    // announce-after-fetch. The old interim fail-closed that refused this combo is removed.
    // TASK-278 #3 (fail-loud, NOT silent dedup): a NarHash may appear at most ONCE across the whole
    // static supply set. A provider serves + announces each NarHash EXACTLY once (it keys the
    // supplier), so a repeat within --libp2p-seed-nar, within --libp2p-provide-store, or ACROSS the
    // two would make the startup count (raw .len()) over-state the distinct served set. Reject rather
    // than silently dedup, matching the `--iroh-*` duplicate rejects above, so `.len() == distinct ==
    // served` holds by construction.
    {
        let mut seen = std::collections::HashSet::new();
        for (nar_hash, _) in cfg
            .libp2p_seed_nar
            .iter()
            .chain(cfg.libp2p_provide_store.iter())
        {
            if !seen.insert(*nar_hash) {
                return Err(format!(
                    "--libp2p-seed-nar / --libp2p-provide-store lists NarHash {nar_hash} more than \
                     once (or in both): a provider serves and announces each NarHash exactly once; \
                     pass it a single time"
                ));
            }
        }
    }
    // TASK-278 #4: announce-after-fetch with a ZERO growth budget grows nothing - the hook would
    // reject every fetch while the startup report claims "grows on demand". `--libp2p-announce-budget`
    // is the DISTINCT-PATHS growth budget the announce-after-fetch hook consumes (static seed/provision
    // announces use a separate rate limiter), so this guard cannot catch a static-only provider.
    if cfg.libp2p_announce_after_fetch && cfg.libp2p_announce_budget == 0 {
        return Err(
            "--libp2p-announce-after-fetch with --libp2p-announce-budget 0 grows nothing: the hook \
             would reject every fetch while the startup report claims \"grows on demand\". Raise the \
             budget or drop --libp2p-announce-after-fetch"
                .into(),
        );
    }
    // TASK-207 fail-closed CONTRADICTION (safety): on a PROVIDER, an external address advertises
    // PUBLIC reachability, and without the public-NAR allowlist door that is an isolated-LAN
    // announce over a self-declared public address - refuse rather than leak local content. A
    // NON-serving node (a consumer, or a relay/bootstrap that carries no content) advertising its
    // OWN reachable address is legitimate (a relay's whole job), so the check is provider-scoped;
    // `SharingProfile::derive` enforces the same rule transport-agnostically (gated on the give side).
    if cfg.libp2p_provider
        && !cfg.libp2p_external_addresses.is_empty()
        && cfg.libp2p_public_allowlist_path.is_none()
    {
        return Err(
            "--libp2p-external-address on a provider requires --libp2p-public-allowlist-path: \
             advertising a public self-address is incompatible with an isolated-LAN announce"
                .into(),
        );
    }
    // TASK-103/204 PUBLIC-announce allowlist companion validation, MIRRORING the composite `daemon`
    // binary so the two cannot drift. Setting the allowlist path switches a provider into
    // PUBLIC-announce mode (the allowlist gates each announce), so its companions are inert without
    // it, and it is inert without a provider - fail fast rather than silently ignore. A public
    // allowlist with no trusted key can prove NOTHING public (every announce would refuse), so
    // reject that dead-on-arrival config up front.
    let public_allowlist_companion =
        !cfg.libp2p_trusted_public_keys.is_empty() || !cfg.libp2p_prove_public_narinfo.is_empty();
    if cfg.libp2p_public_allowlist_path.is_some() && !cfg.libp2p_provider {
        return Err(
            "--libp2p-public-allowlist-path requires --libp2p-provider; the allowlist gates a PROVIDER's public announce".into(),
        );
    }
    if public_allowlist_companion && cfg.libp2p_public_allowlist_path.is_none() {
        return Err(
            "--libp2p-trusted-public-key / --libp2p-prove-public-narinfo require --libp2p-public-allowlist-path (they populate the on-disk public-NAR allowlist)".into(),
        );
    }
    if cfg.libp2p_public_allowlist_path.is_some() && cfg.libp2p_trusted_public_keys.is_empty() {
        return Err(
            "--libp2p-public-allowlist-path requires at least one --libp2p-trusted-public-key; without a trusted narinfo-signing key nothing can be proven public and every announce would be refused".into(),
        );
    }

    // AUTHORITY INVERSION (TASK-120): derive the AUTHORITATIVE profile from the flags, then
    // cross-check it against any explicit `--profile`. The legacy flags are a validated COMPAT
    // SHIM - the derived profile MUST equal the declared one, else fail closed. This is what makes
    // `--profile upstream-only --libp2p-provider ...` impossible to pass silently.
    let derived = SharingProfile::derive(contract_request(&cfg)).map_err(|e| e.to_string())?;
    if let Some(token) = &cfg.explicit_profile {
        let declared = SharingProfile::parse(token).map_err(|e| e.to_string())?;
        if declared != derived {
            return Err(format!(
                "--profile {} disagrees with the profile the flags imply ({}): the flags are the \
                 compat shim and must MATCH the declared profile. Fix the flags or the --profile.",
                declared, derived
            ));
        }
    }
    cfg.profile = derived;

    // TASK-273: resolve the tri-state mDNS opt-in AGAINST the derived profile. Explicit
    // `--libp2p-mdns` / `--libp2p-no-mdns` wins; otherwise lan-share defaults mDNS ON (zero-config
    // LAN discovery) and every other profile OFF. Computed AFTER derivation so it can never feed
    // back into WHICH profile was derived (the `has_bootstrap` inference above consumed only the raw
    // `Some(true)` opt-in). Every runtime site reads `cfg.mdns_active` from here on.
    cfg.mdns_active = cfg.libp2p_mdns.unwrap_or(cfg.profile.default_lan_mdns());

    // TASK-273 (DISCOVERY-ONLY, Option B): under lan-share we default mDNS ON (above) so a bare
    // `--profile lan-share` gets zero-config LAN DISCOVERY, and we back-fill the provider axis (below,
    // before derivation) so it DERIVES lan-share. We deliberately do NOT force a listen or
    // announce-after-fetch: SUPPLY + REACHABILITY stay the operator's explicit choice, so a bare
    // `--profile lan-share` fails LOUD (the honest "saw your intent, here's what's missing" path) at
    // the provider preconditions rather than silently pretending to serve. Auto-defaulting the supply
    // set + listen is deferred to TASK-278.

    // TASK-258 SPIKE — Mainline rendezvous fail-closed refusals (AC#5/#6). These are
    // CONTRADICTION checks (enforced even under `--preflight`, not just the live path) so the
    // operator cannot even DESCRIBE a zero-egress profile as also doing public Mainline traffic.
    if cfg.libp2p_mainline_rendezvous {
        // (1) NO default public router: the rendezvous has no entry point without an explicit
        // LOCAL Mainline bootstrap, so an enabled rendezvous with none fails closed.
        if cfg.libp2p_mainline_bootstrap.is_empty() {
            return Err(
                "--libp2p-mainline-rendezvous requires at least one --libp2p-mainline-bootstrap \
                 <host:port>: there is NO default (we never contact router.bittorrent.com), so a \
                 rendezvous with no local Mainline entry point can reach nobody"
                    .into(),
            );
        }
        // (2) Wave-2c HARD CONSTRAINT: lan-share (and upstream-only) emit ZERO packets to public
        // DHT/Mainline infrastructure. The Mainline rendezvous IS public-network participation, so
        // it is REFUSED fail-closed under both — never a silent no-op. (upstream-only is normally
        // unreachable here because the flag implies consume-only via has_bootstrap, but an explicit
        // `--profile upstream-only --libp2p-mainline-rendezvous` reaches this after the cross-check
        // only if the derivation ever changes; the guard is kept explicit and belt-and-braces.)
        if matches!(
            cfg.profile,
            SharingProfile::LanShare | SharingProfile::UpstreamOnly
        ) {
            return Err(format!(
                "--libp2p-mainline-rendezvous is PUBLIC-network participation and is refused under \
                 {} (the Wave-2c privacy contract requires {} to emit ZERO packets to public \
                 DHT/Mainline infrastructure). Use --profile consume-only to fetch from peers over \
                 the public network, or drop the flag.",
                cfg.profile, cfg.profile
            ));
        }
    }

    Ok(cfg)
}

/// Distil the parsed [`Config`]'s give/consume flags into the transport-agnostic
/// [`ContractRequest`] the ONE authority ([`SharingProfile::derive`]) consumes. The SINGLE place
/// the flags map to intent, so the derived MODE cannot diverge between parse-time and runtime.
fn contract_request(cfg: &Config) -> ContractRequest {
    ContractRequest {
        is_leech: cfg.libp2p_leech,
        is_provider: cfg.libp2p_provider,
        announces: cfg.libp2p_announce_after_fetch
            || !cfg.libp2p_seed_nar.is_empty()
            || !cfg.libp2p_provide_store.is_empty(),
        is_router: cfg.libp2p_router,
        has_public_allowlist: cfg.libp2p_public_allowlist_path.is_some(),
        advertises_public_address: !cfg.libp2p_external_addresses.is_empty(),
        // TASK-257 (DEEP minor a): "reaches a peer substrate" - an explicit `--libp2p-bootstrap` OR
        // `--libp2p-mdns`. mDNS IS a consumer's DHT ENTRY PATH (a same-scope LAN neighbour is
        // discovered with zero config), exactly like a bootstrap peer, so a bare `--libp2p-mdns`
        // node derives CONSUME-ONLY (not upstream-only) - consistent with the composite `daemon` and
        // with the LIVE path (the swarm opens the mDNS socket). This also makes `--preflight
        // --libp2p-mdns` report consume-only instead of the old upstream-only/mDNS-active
        // inconsistency. An explicit `--profile upstream-only --libp2p-mdns` still fails CLOSED at
        // the compat-shim cross-check above (declared upstream-only != implied consume-only).
        // TASK-258: the Mainline rendezvous is ALSO a DHT ENTRY PATH (it learns member addresses
        // and feeds them to bootstrap), so a bare `--libp2p-mainline-rendezvous` derives
        // CONSUME-ONLY exactly like `--libp2p-mdns` — and `--profile upstream-only
        // --libp2p-mainline-rendezvous` therefore fails CLOSED at the compat-shim cross-check
        // (declared upstream-only != implied consume-only), the same mechanism mDNS relies on.
        // TASK-273 ORDERING TRAP: consume the RAW opt-in ONLY (`Some(true)`), NEVER the resolved
        // `mdns_active`. `mdns_active` depends on the derived profile, so feeding it back here would
        // be circular. A bare `--libp2p-mdns` still derives consume-only; a profile-defaulted mDNS
        // (lan-share) never reaches this branch because lan-share is a provider (is_provider short-
        // circuits `derive` before `has_bootstrap`).
        has_bootstrap: !cfg.libp2p_bootstrap.is_empty()
            || cfg.libp2p_mdns == Some(true)
            || cfg.libp2p_mainline_rendezvous,
    }
}

/// NETWORK-PRECONDITION checks, keyed off the AUTHORITATIVE [`SharingProfile`] (TASK-120 fix #1 +
/// #3). Distinct from the CONTRADICTION checks in `parse_config` (which fail even a `--preflight`):
/// these say a node is not yet WIRED to do what its profile asks, so `main` runs them ONLY on the
/// live path, AFTER the `--preflight` early-return. Crucially, a CONSUME-ONLY node requires a
/// bootstrap (it intends to fetch from peers), but an UPSTREAM-ONLY node does NOT - a fresh
/// `daemon-libp2p` with no flags is upstream-only and must run.
fn check_runtime_preconditions(cfg: &Config) -> Result<(), String> {
    if cfg.profile.serves() {
        // A provider must have SOMETHING to serve: a static supply set OR announce-after-fetch
        // (TASK-77), which grows the supply set from what it fetches.
        if cfg.libp2p_seed_nar.is_empty()
            && cfg.libp2p_provide_store.is_empty()
            && !cfg.libp2p_announce_after_fetch
        {
            return Err(
                "a provider profile (lan-share/public-share) requires at least one --libp2p-seed-nar, --libp2p-provide-store, or --libp2p-announce-after-fetch"
                    .into(),
            );
        }
        // TASK-278: `--libp2p-seed-nar` and `--libp2p-provide-store` CAN now be combined - the
        // provider builds an ADDITIVE union supplier serving both. The old TASK-191-MVP refusal is
        // removed.
        // TASK-276 FIX #B: a bare cross-host `lan-share` NO LONGER auto-resolves a private-LAN listen
        // (the interface heuristic was defeated twice in review). The operator must name their LAN
        // address explicitly; we NEVER silently guess a bind. An explicit provably-private listen is
        // admitted by the isolation guard and serves cross-host.
        if cfg.libp2p_listen.is_empty() {
            let msg = if cfg.profile == SharingProfile::LanShare {
                "a cross-host --profile lan-share needs its LAN address; pass --libp2p-listen \
                 /ip4/<your-LAN-ip>/tcp/0"
            } else {
                "a provider profile (lan-share/public-share) requires --libp2p-listen"
            };
            return Err(msg.into());
        }
        // TASK-273 AC#1: a provider that HAS something to serve and a listen but NO way to be
        // DISCOVERED runs silently dark — it joins no DHT, is found by no one, and announces into
        // the void with no error. This mirrors the consume-only entry-path guard below. The REAL Kad
        // entry paths (each seeds the routing table / joins a DHT where our provider records become
        // findable): LAN mDNS (multicasts presence AND feeds discovered addresses into bootstrap), an
        // explicit `--libp2p-bootstrap` peer, OR a `--libp2p-provider-addr` dial hint (also
        // `add_address`'d into Kad, lib.rs). A self-advertised `--libp2p-external-address` is NOT an
        // entry path: it only propagates identify SELF-metadata AFTER a connection already exists
        // (fabric-libp2p/src/swarm.rs), never dialing or seeding Kad — so it is EXCLUDED here.
        let discoverable = cfg.mdns_active
            || !cfg.libp2p_bootstrap.is_empty()
            || !cfg.libp2p_provider_addrs.is_empty();
        if !discoverable {
            // Profile-aware remedy. A no-allowlist LanShare announces through the TASK-102
            // isolated-LAN stopgap (`lan_isolation_or_refuse`, lib.rs), which REFUSES any
            // `--libp2p-bootstrap`/`--libp2p-provider-addr`, so LAN mDNS is its ONLY entry path —
            // don't suggest paths it would then reject. PublicShare (allowlist door) may use any.
            return Err(if cfg.profile == SharingProfile::LanShare {
                "lan-share has no way to be discovered: it announces over the isolated-LAN stopgap, \
                 which accepts NO --libp2p-bootstrap or --libp2p-provider-addr, so LAN mDNS is its \
                 ONLY entry path — do not pass --libp2p-no-mdns (NixOS: services.nix-p2p.libp2p.mdns \
                 = true)".into()
            } else {
                // public-share defaults mDNS OFF, so the operator must ADD --libp2p-mdns (not "drop
                // --libp2p-no-mdns"), OR give a real Kad entry hint.
                "public-share has no way to be discovered: add --libp2p-mdns for LAN discovery, OR \
                 give a --libp2p-bootstrap <PeerId>@<multiaddr>, OR a --libp2p-provider-addr \
                 <PeerId>@<multiaddr> dial hint. A self-advertised --libp2p-external-address is NOT \
                 an entry path (it only propagates identify metadata after a connection, never dials \
                 or seeds Kad)".into()
            });
        }
    } else if cfg.profile == SharingProfile::ConsumeOnly
        && cfg.libp2p_bootstrap.is_empty()
        && !cfg.mdns_active
        && !cfg.libp2p_mainline_rendezvous
    {
        // CONSUME-ONLY intends to fetch from peers, so it needs an ENTRY PATH to the DHT.
        // TASK-257: `--libp2p-mdns` IS such an entry path (a same-scope LAN neighbour is
        // discovered with zero configuration), so it satisfies this requirement exactly as an
        // explicit `--libp2p-bootstrap` does - the whole point of mDNS is to remove the mandatory
        // bootstrap for the LAN case. Without EITHER, a consumer can never find anyone; UPSTREAM-ONLY
        // needs neither (it is pure HTTP fallback) - the guard keys off the profile, not "non-provider".
        return Err(
            "consume-only requires an entry path to the DHT: at least one --libp2p-bootstrap <PeerId>@<multiaddr>, OR --libp2p-mdns for zero-config LAN discovery, OR --libp2p-mainline-rendezvous (with --libp2p-mainline-bootstrap) for public Mainline rendezvous. For pure HTTP fallback use --profile upstream-only with none".into(),
        );
    } else if cfg.profile == SharingProfile::Router && cfg.libp2p_listen.is_empty() {
        // TASK-241: a router is a kad-server + relay OTHERS reach - it must BIND a transport, so a
        // listen is mandatory. (A bootstrap is optional: a genesis router seeds the DHT itself.)
        return Err(
            "a router (--libp2p-router) requires at least one --libp2p-listen: it binds a kad-server + relay that others dial as a bootstrap/relay root".into(),
        );
    } else if cfg.profile == SharingProfile::UpstreamOnly {
        // TASK-120 fix A: upstream-only runs NO participating libp2p swarm - it is a pure HTTP
        // node. Refuse any flag that would start/participate a swarm (listen, bootstrap, provider
        // address, external address), so an upstream-only node can NEVER bind a kad server / relay
        // and then report `public_dht_participation=false`. The report matches the wire because
        // there is no swarm at all.
        let swarm_flag = [
            ("--libp2p-listen", !cfg.libp2p_listen.is_empty()),
            ("--libp2p-bootstrap", !cfg.libp2p_bootstrap.is_empty()),
            (
                "--libp2p-provider-addr",
                !cfg.libp2p_provider_addrs.is_empty(),
            ),
            (
                "--libp2p-external-address",
                !cfg.libp2p_external_addresses.is_empty(),
            ),
            // TASK-257 (DEEP minor a): `--libp2p-mdns` is NOT listed here. mDNS is a DHT ENTRY PATH,
            // so it derives CONSUME-ONLY (never upstream-only) - this branch is unreachable with
            // mDNS. An explicit `--profile upstream-only --libp2p-mdns` is refused earlier by the
            // compat-shim cross-check (declared upstream-only != implied consume-only), so the
            // zero-P2P guarantee still holds without a dead entry here.
        ];
        if let Some((flag, _)) = swarm_flag.iter().find(|(_, present)| *present) {
            return Err(format!(
                "upstream-only runs NO libp2p swarm (pure HTTP fallback); it cannot be combined \
                 with {flag}. Drop it, or select --profile consume-only (to fetch from peers) or a \
                 provider profile."
            ));
        }
    }
    Ok(())
}

/// Build the fabric construction config for a SWARM-PARTICIPATING profile (consume-only or a
/// provider). TASK-120 fix A: the swarm's PARTICIPATION MODE derives from the profile. A PROVIDER
/// (lan-share/public-share) runs kad SERVER + the relay server as configured (it participates in
/// the DHT infrastructure); a CONSUMER (consume-only) runs kad CLIENT + relay server OFF (it issues
/// queries and fetches, but answers no DHT queries and relays for nobody - no infrastructure).
/// upstream-only never calls this: it runs no participating swarm at all (a pure HTTP node).
fn source_config(
    cfg: &Config,
    profile: SharingProfile,
    identity_seed: [u8; 32],
    lan_share: bool,
) -> Libp2pSourceConfig {
    // TASK-241: the DHT-infrastructure axis (kad SERVER + the relay server) is run by a PROVIDER
    // AND by a ROUTER; a CONSUMER is a kad CLIENT that relays for nobody. `runs_dht_server()` is
    // that axis, distinct from `serves()` (which is content-serving, false for a router).
    let dht_server = profile.runs_dht_server();
    // TASK-280 #3 single-source: a no-allowlist lan-share node is LAN-CONFINED (dial veto + serve
    // provenance) AND scoped away from the public v1 DHT. `lan_share` is DECIDED BY THE CALLER, not
    // recomputed here from the profile: the provider path passes `matches!(plan,
    // PublicationPlan::Lan(_))` from the ONE `provider_publication_decision` mint, and the
    // non-provider path passes `false` (confinement is a PROVIDER egress control; a consumer dials
    // the pool it was told to join). Threading BOTH the scope and the confinement flag from that
    // SINGLE authority is what stops them drifting from the publication decision.
    Libp2pSourceConfig {
        identity_seed,
        network_scope: effective_network_scope(cfg.libp2p_scope.as_deref(), lan_share),
        listen: cfg.libp2p_listen.first().cloned(),
        additional_listens: cfg.libp2p_listen.iter().skip(1).cloned().collect(),
        external_addresses: cfg.libp2p_external_addresses.clone(),
        bootstrap: cfg.libp2p_bootstrap.clone(),
        provider_addrs: cfg.libp2p_provider_addrs.clone(),
        discovery_budget: DiscoveryBudget::default(),
        envelope: SafetyEnvelope::default(),
        state_dir: cfg.libp2p_state_dir.clone(),
        // A PROVIDER or ROUTER runs the relay server (unless --libp2p-no-relay-server); a CONSUMER
        // relays for nobody (relay server OFF).
        relay_server_enabled: dht_server && cfg.libp2p_relay_server_enabled,
        // A PROVIDER or ROUTER is a kad SERVER (DHT infrastructure); a CONSUMER is a kad CLIENT.
        kad_server: dht_server,
        // TASK-257: LAN mDNS peer-ADDRESS discovery, straight from the default-OFF flag. Any
        // swarm-participating profile (consume-only / provider / router) may opt in; upstream-only
        // never reaches here (it builds no swarm and refuses --libp2p-mdns in parse_config).
        // TASK-273: the RESOLVED decision (profile default folded in), not the raw opt-in.
        mdns_enabled: cfg.mdns_active,
        // TASK-280: LAN confinement for a no-allowlist lan-share node only.
        lan_confinement: lan_share,
    }
}

/// What keeps a libp2p PROVIDER serving for the process. Dropping the [`ServeHandle`] stops
/// admission; the optional [`AvailabilityIndex`] is present in the STORE-supply mode (TASK-191)
/// because the [`CatalogNarSupplier`] serves through the index's supply catalog and the index's
/// `Drop` retires every registration - so the served reverse-map must outlive the process.
struct ProviderGuard {
    _serve: ServeHandle,
    _index: Option<Arc<AvailabilityIndex>>,
    /// The ANNOUNCE-AFTER-FETCH hook (TASK-77), present with `--libp2p-announce-after-fetch`. It
    /// shares `_index` above, so a fetched path it registers is servable through the same supply
    /// catalog. `RunConfig` clones this `Arc` so the serving frontend grows the swarm.
    post_fetch_announce: Option<Arc<dyn daemon_core::PostFetchAnnounce>>,
    /// The periodic seed RE-SIGN task (TASK-285), present when a durable seed leg was announced. Held
    /// so the loop lives for the process; dropping the guard aborts it.
    _seed_resign: Option<SeedResignTask>,
}

/// The provider serve budget, DERIVED from the ONE authoritative [`ResourceCaps`] (TASK-120
/// AC#3/#9) so the shipped bounds cannot drift from the documented operator contract; shared by
/// both supply modes.
fn provider_serve_budget() -> ServeBudget {
    ResourceCaps::default().serve_budget()
}

/// UNIX seconds now (0 on a pre-epoch clock, matching the seed path).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Warn loudly (not fail-closed) that a PROVIDER without a durable state dir re-enables the F3
/// self-rollback. Shared by both supply modes; fail-closed is deferred to TASK-188.
fn warn_if_non_durable_provider(source_cfg: &Libp2pSourceConfig) {
    if source_cfg.state_dir.is_none() {
        eprintln!(
            "daemon-libp2p: WARNING: --libp2p-state-dir is not set; this PROVIDER runs \
             NON-DURABLE. Its identity is regenerated each start and its announce sequences \
             and withdrawals will NOT survive a restart (a restarted provider announces under a \
             NEW identity at sequence 1 and cannot supersede or withdraw its old records). Set \
             --libp2p-state-dir <dir> for restart-durable operation."
        );
    }
}

/// The TASK-102 LAN-isolation guard for the shipped provider modes (fix cycle #2). These announce
/// over a PRIVATE / LAN (operator-assembled) substrate: the seed/store bytes are content-verified
/// (TASK-56) but NOT publication-authorized by the public-NAR allowlist (config not wired until
/// TASK-103). This thin wrapper maps the binary's parsed [`Config`] to the FULL reachability the
/// shared [`lan_isolation_or_refuse`] policy inspects - bootstrap, provider-addr, AND listen - so a
/// provider that can reach ANY public substrate (not just one with a non-empty bootstrap) is
/// refused. Keeping the Config->reachability mapping in ONE tested place is what closes the residual
/// hole where `--libp2p-provider-addr` + empty bootstrap slipped through a bootstrap-only check.
fn lan_share_or_refuse(cfg: &Config) -> Result<LanShare, String> {
    // --libp2p-listen is repeatable (TASK-207), so EVERY listen must pass the isolation witness:
    // one non-loopback/non-link-local listen makes the node publicly reachable regardless of the
    // others. Refuse on the first that fails; the bootstrap/provider-addr signals refuse up front
    // (they are listen-independent). A node with no listen at all still runs the witness once.
    fn witness(cfg: &Config, listen: Option<&Multiaddr>) -> Result<LanShare, String> {
        lan_isolation_or_refuse(LanReachability {
            bootstrap: &cfg.libp2p_bootstrap,
            provider_addrs: &cfg.libp2p_provider_addrs,
            listen,
        })
    }
    if cfg.libp2p_listen.is_empty() {
        return witness(cfg, None);
    }
    let mut share = None;
    for listen in &cfg.libp2p_listen {
        share = Some(witness(cfg, Some(listen))?);
    }
    Ok(share.expect("non-empty listen set yields a LanShare"))
}

/// The SINGLE publication decision for this PROVIDER node (TASK-276 FIX #2), taken ONCE before any
/// fabric/listener is built: a configured public allowlist -> [`PublicationPlan::Allowlist`]; no
/// allowlist -> the isolation guard runs HERE ([`lan_share_or_refuse`]) and either binds the
/// [`LanShare`] witness into [`PublicationPlan::Lan`] or ABORTS. A public-reachable no-allowlist
/// provider therefore fails before a listener registers, rather than degrading to a serve-but-refuse
/// state that momentarily bound every interface (codex CRITICAL #2).
fn provider_publication_decision(cfg: &Config) -> Result<PublicationPlan, String> {
    if cfg.libp2p_public_allowlist_path.is_some() {
        Ok(PublicationPlan::Allowlist)
    } else {
        Ok(PublicationPlan::Lan(lan_share_or_refuse(cfg)?))
    }
}

/// The ADDITIVE provider supply (TASK-278), built SYNCHRONOUSLY so it is unit-testable without a
/// fabric: the union [`Libp2pNarSupplier`] the fabric will serve, plus the per-leg announce inputs
/// and the human-readable served-set report. The two supply legs are NOT mutually exclusive - a
/// provider can seed in-memory NARs AND serve `/nix/store` paths on demand AND grow via
/// announce-after-fetch, all from ONE fabric/identity.
struct ProviderSupply {
    /// The union of every built leg; drives the ONE serving fabric.
    supplier: Arc<dyn Libp2pNarSupplier>,
    /// The in-memory `--libp2p-seed-nar` set (empty iff the seed leg was not built), announced by
    /// the seed door and reported as `S`.
    seeds: Vec<(daemon_core::NarHashKey, Vec<u8>)>,
    /// The store-supply availability index; `Some` iff the store leg was built
    /// (`--libp2p-provide-store` non-empty OR `--libp2p-announce-after-fetch`). The
    /// announce-after-fetch hook grows THIS index, so it must exist for the hook.
    index: Option<Arc<AvailabilityIndex>>,
    /// The TASK-56-verified `--libp2p-provide-store` provisions (empty iff none provided),
    /// announced by the store door and reported as `P`.
    provisions: Vec<StoreProvision>,
    /// The ACTUAL served set, reported at startup with NO false count.
    report: String,
}

/// Build the additive [`ProviderSupply`] from the CLI (TASK-278 AC#1) WITHOUT touching the network:
/// read + size-guard the seed leg, register + verify + size-guard the store leg, and UNION them.
/// `dumper` is the store-path NAR producer (production: `CommandNarDumper`; tests inject a
/// `RegularFileNarDumper` so `verify_store_provisions` runs a real dump without a `/nix/store`).
///
/// Leg selection is ADDITIVE, not a mode-select: the seed leg is built iff there are seeds, the
/// store leg iff there is a provide-store set OR announce-after-fetch (which needs the index even
/// with an empty initial set). Both legs empty is a "provider with nothing to serve" fail-closed.
fn build_provider_supply(
    cfg: &Config,
    serve_budget: &ServeBudget,
    dumper: Arc<dyn NarDumper>,
    node_id: NodeId,
) -> Result<ProviderSupply, String> {
    let mut legs: Vec<Arc<dyn Libp2pNarSupplier>> = Vec::new();

    // SEED leg: read every `--libp2p-seed-nar`, size-guard it, and hold it in memory.
    let mut seeds: Vec<(daemon_core::NarHashKey, Vec<u8>)> =
        Vec::with_capacity(cfg.libp2p_seed_nar.len());
    for (nar_hash, path) in &cfg.libp2p_seed_nar {
        let bytes =
            std::fs::read(path).map_err(|e| format!("reading --libp2p-seed-nar {path:?}: {e}"))?;
        seeds.push((*nar_hash, bytes));
    }
    for (nar_hash, bytes) in &seeds {
        if bytes.len() as u64 > serve_budget.max_nar_bytes_uncompressed_nar {
            return Err(format!(
                "seeded NAR {nar_hash} is {} B but the per-NAR serve bound is {}: announcing it \
                 would publish a claim this node would then decline to serve",
                bytes.len(),
                serve_budget.max_nar_bytes_uncompressed_nar
            ));
        }
    }
    if !seeds.is_empty() {
        legs.push(Arc::new(MemoryNarSupplier::new(
            seeds.iter().map(|(_, b)| b.clone()),
        )));
    }

    // STORE leg: built iff there is a provide-store set OR announce-after-fetch (the hook grows
    // this index, so it must exist even for an empty initial provide set).
    let mut index = None;
    let mut provisions = Vec::new();
    if !cfg.libp2p_provide_store.is_empty() || cfg.libp2p_announce_after_fetch {
        // NullStore/NullAnnounce: the provided set is the CLI SSOT (re-registered + re-verified each
        // boot); claims announce through the libp2p announcer, not the index's iroh sink.
        let store_index =
            AvailabilityIndex::open(node_id, dumper, Arc::new(NullStore), Arc::new(NullAnnounce))
                .map_err(|e| format!("opening the availability index for store supply: {e}"))?;
        let mut nar_hashes = Vec::with_capacity(cfg.libp2p_provide_store.len());
        for (nar_hash, path) in &cfg.libp2p_provide_store {
            store_index
                .register(*nar_hash, StorePath::new(path))
                .map_err(|e| format!("registering store path {path:?} under {nar_hash}: {e}"))?;
            nar_hashes.push(*nar_hash);
        }
        let store_index = Arc::new(store_index);

        // The supplier reads the index's inert reverse-map. The helper program is THIS binary's
        // `__dump-raw-nar` mode, spawned ONLY for a ProbedSource::RegularFile; a real store path is
        // a ProbedSource::Process (nix-store --dump) and never invokes it.
        let helper_program = std::env::current_exe().map_err(|e| {
            format!("resolving daemon-libp2p executable for the raw-NAR helper: {e}")
        })?;
        legs.push(Arc::new(CatalogNarSupplier::new(
            Libp2pCatalogProbe::new(store_index.supply_catalog()),
            helper_program,
        )));

        // AC#2 gate: verify EVERY provided store path (dump + sha256==NarHash + quarantine) before
        // any announce; a quarantined/absent path fails the whole batch here.
        provisions = verify_store_provisions(&store_index, &nar_hashes)?;
        // Store analogue of the seed-size guard: refuse to announce a path whose verified NarSize is
        // over the per-NAR serve bound (it would publish a claim this node then declines TooLarge).
        for provision in &provisions {
            if provision.declared_size() > serve_budget.max_nar_bytes_uncompressed_nar {
                return Err(format!(
                    "store path for {} dumps to {} B (uncompressed NAR) but the per-NAR serve bound \
                     is {}: announcing it would publish a claim this node would then decline to serve",
                    provision.nar_hash(),
                    provision.declared_size(),
                    serve_budget.max_nar_bytes_uncompressed_nar
                ));
            }
        }
        index = Some(store_index);
    }

    if legs.is_empty() {
        return Err(
            "provider has nothing to serve: pass --libp2p-seed-nar, --libp2p-provide-store, or \
             --libp2p-announce-after-fetch"
                .into(),
        );
    }

    // The report reflects the ACTUAL served set (no false count): S seeds + P store paths, plus the
    // announce-after-fetch clause when the growing hook is on. Each count is computed independently.
    let report = provider_supply_report(
        seeds.len(),
        provisions.len(),
        cfg.libp2p_announce_after_fetch,
    );

    Ok(ProviderSupply {
        supplier: Arc::new(UnionNarSupplier::new(legs)),
        seeds,
        index,
        provisions,
        report,
    })
}

/// The startup served-set line (TASK-278 AC#1): S seeded NARs + P `/nix/store` paths served on
/// demand, plus an announce-after-fetch clause iff the growing hook is installed. Counts are
/// INDEPENDENT (never one-or-the-other), so the line never over- or under-states what is served.
fn provider_supply_report(seeds: usize, provisions: usize, announce_after_fetch: bool) -> String {
    let hook = if announce_after_fetch {
        " + announce-after-fetch (grows on demand)"
    } else {
        ""
    };
    format!("{seeds} seeded NAR(s) + {provisions} /nix/store path(s) on demand{hook}")
}

/// Node B (PROVIDER): build the ADDITIVE supply (TASK-278), start ONE fabric over the union
/// supplier, install ONE serve gate, and announce EVERY built leg (seeds AND store provisions) plus
/// install the announce-after-fetch hook. Every announced NarHash is distinct (the parse-time #3
/// dedup rejects a repeat within or across the two lists), so the per-ContentKey durable-sequence
/// allocator the two announce loops share cannot collide. Returns the fabric + the [`ProviderGuard`]
/// the caller must keep alive for the process.
async fn install_provider(
    cfg: &Config,
    contract: &OperatorContract,
    source_cfg: Libp2pSourceConfig,
    plan: PublicationPlan,
    allowlist: &Arc<PublicNarAllowlist>,
) -> Result<(Arc<Libp2pFabric>, ProviderGuard), String> {
    warn_if_non_durable_provider(&source_cfg);
    // TASK-276 FIX #2 / TASK-280 #3 single-source: publication eligibility is decided ONCE by the
    // caller (`provider_publication_decision`, BEFORE any fabric or listener is built) and the taken
    // `plan` is threaded in here — the SAME decision that produced this `plan` also drove
    // `source_cfg`'s scope + confinement (`matches!(plan, PublicationPlan::Lan(_))`), so they cannot
    // drift. A no-allowlist non-LAN-isolated provider already aborted at the mint, so no listener
    // ever binds in a bind-before-guard window. The bound witness is threaded into every announce
    // branch below (no per-leg re-derivation of the guard).
    let privacy = &contract.privacy;
    let serve_budget = provider_serve_budget();
    let identity_seed = source_cfg.identity_seed;

    // The index's `node_id` is this node's ed25519 identity for completeness; the libp2p
    // ProviderRecord carries its OWN provider identity, so the index's iroh offer is never consulted.
    let node_id = NodeId::from_bytes(
        SigningKey::from_bytes(&identity_seed)
            .verifying_key()
            .to_bytes(),
    );
    let supply = build_provider_supply(
        cfg,
        &serve_budget,
        Arc::new(CommandNarDumper::from_path()) as Arc<dyn NarDumper>,
        node_id,
    )?;
    let ProviderSupply {
        supplier,
        seeds,
        index,
        provisions,
        report,
    } = supply;

    // ONE fabric over the union supplier, ONE serve gate under the one serve budget. The publication
    // authority is derived from the ALREADY-TAKEN plan (guard consulted once, above).
    let authority = plan.announce_authority(allowlist);
    let (fabric, _source, _raw, readiness) =
        build_libp2p_provider_source(source_cfg, supplier, authority).await?;

    // TASK-276 FIX #3: SEQUENCE guard(done) -> bind(done above) -> DISCLOSE -> activate serve gate.
    // Read the bound listeners first (the OS assigned any `/tcp/0` port), build the lan-share
    // disclosure, then emit it BEFORE the `/nar` serve gate accepts. Ordering is a security property:
    // an exact-key peer must not be served before the operator is told the port is open, and a
    // serve-gate failure must not suppress the disclosure.
    let listen_addrs = fabric.handle().listen_addrs().await;
    let disclosures = if cfg.profile == SharingProfile::LanShare {
        // The EFFECTIVE scope this lan-share node runs (the canonical decision function, so the
        // disclosed scope matches the scope the fabric was built with; TASK-280 #6).
        let effective_scope = effective_network_scope(cfg.libp2p_scope.as_deref(), true);
        lan_serving_disclosures(
            cfg.libp2p_announce_after_fetch,
            &effective_scope,
            &listen_addrs,
        )
    } else {
        Vec::new()
    };
    let server = fabric
        .server()
        .ok_or_else(|| "internal: libp2p provider fabric has no serve axis".to_string())?;
    let serve = disclose_then_activate_serve(
        || {
            for line in &disclosures {
                println!("{line}");
            }
        },
        server.serve(serve_budget),
    )
    .await
    .map_err(|e| format!("libp2p serve gate failed to install: {e}"))?;
    println!("daemon-libp2p: /nar serve gate active");

    let announce_budget = AnnounceBudget::new(Duration::from_secs(10), 20);
    let ttl_secs = cfg.libp2p_record_ttl_secs;
    let announce_config =
        InitialAnnounceConfig::new(identity_seed, ttl_secs, now_secs(), &announce_budget);

    // Announce the SEED leg (if built). The announce door mirrors the store leg's: PUBLIC-announce
    // mode (a configured allowlist) gates each record on a trusted narinfo signature; ISOLATED-LAN
    // mode keeps the TASK-102 `lan_share_or_refuse` stopgap.
    //
    // TASK-279 AC#2 (TRANSACTION — atomic public publish): for a PUBLIC (allowlist) plan, authorize
    // EVERY leg (seeds AND provisions) BEFORE announcing ANY record via `announce_public_supply`
    // (authorize-all-then-announce-all). An un-allowlisted provision therefore publishes ZERO seed
    // records, instead of the old ordering that announced the seed leg to the DHT and only then
    // authorized the provision leg (leaving seed records to linger to TTL on a provision refusal).
    // The LAN plan has no allowlist refusal (AdmitAll) and each leg's only announce-time failure is a
    // network error, so it stays per-leg (nothing to be non-atomic about).
    let (seed_records, provision_records) = match &plan {
        PublicationPlan::Allowlist => {
            announce_public_supply(
                &fabric,
                &readiness,
                announce_config,
                &seeds,
                &provisions,
                allowlist,
            )
            .await?
        }
        PublicationPlan::Lan(lan) => {
            let seed_records = if seeds.is_empty() {
                Vec::new()
            } else {
                announce_provider_seeds(&fabric, &readiness, announce_config, &seeds, *lan).await?
            };
            // The parse-time #3 dedup guarantees every provision's NarHash differs from every seed's,
            // so no per-ContentKey durable-sequence collision against the same fabric/identity.
            let provision_records = if provisions.is_empty() {
                Vec::new()
            } else {
                announce_store_provisions(&fabric, &readiness, announce_config, &provisions, *lan)
                    .await?
            };
            (seed_records, provision_records)
        }
    };
    for (record, (nar_hash, bytes)) in seed_records.iter().zip(&seeds) {
        // TASK-120 fix #6: content-identity fields routed through the privacy policy (marker +
        // keys stay for machine oracles; secret values masked unless --diagnostics).
        println!(
            "LIBP2P-SEED narhash={} content={} content_key={} bytes={}",
            privacy.content_id(&nar_hash.to_string()),
            privacy.content_id(&record.content.to_hex()),
            privacy.content_id(&record.key.to_string()),
            bytes.len()
        );
    }
    for (record, provision) in provision_records.iter().zip(&provisions) {
        println!(
            "LIBP2P-PROVIDE-STORE narhash={} content={} content_key={} nar_size={}",
            privacy.content_id(&provision.nar_hash().to_string()),
            privacy.content_id(&record.content.to_hex()),
            privacy.content_id(&record.key.to_string()),
            provision.declared_size(),
        );
    }

    // ANNOUNCE-AFTER-FETCH (TASK-77): build the hook over the SAME store index + fabric + identity so
    // a fetched path it registers is servable and every announce it makes goes through this node's
    // eligibility authority (no second announce path). The store leg guarantees `index` is `Some`
    // whenever the flag is set.
    let post_fetch_announce: Option<Arc<dyn daemon_core::PostFetchAnnounce>> =
        if cfg.libp2p_announce_after_fetch {
            let index = index.clone().ok_or_else(|| {
                "internal: --libp2p-announce-after-fetch set but the store leg built no index"
                    .to_string()
            })?;
            let door = match &plan {
                PublicationPlan::Allowlist => AnnounceAfterFetchDoor::Public(allowlist.clone()),
                PublicationPlan::Lan(lan) => AnnounceAfterFetchDoor::Lan(*lan),
            };
            // TASK-279 AC#1: hand the hook the NarHashes the durable memory-resident seed leg owns, so
            // it never grows/tracks/withdraws a seed-owned key (a store-path GC would otherwise
            // tombstone the seed leg's own never-GC'd announce). Empty when there is no seed leg.
            let seed_owned: std::collections::HashSet<daemon_core::NarHashKey> =
                seeds.iter().map(|(nar_hash, _)| *nar_hash).collect();
            let hook = Libp2pAnnounceAfterFetch::new(
                Arc::clone(&fabric),
                identity_seed,
                index,
                door,
                serve_budget,
                announce_budget,
                ttl_secs,
                cfg.store_dir.clone(),
                cfg.libp2p_announce_budget,
                seed_owned,
            );
            println!(
                "LIBP2P-ANNOUNCE-AFTER-FETCH enabled budget={}",
                cfg.libp2p_announce_budget
            );
            Some(Arc::new(hook) as Arc<dyn daemon_core::PostFetchAnnounce>)
        } else {
            None
        };

    // TASK-285: the durable seed leg's records carry an ABSOLUTE signed expiry that kad's native
    // republish cannot extend, so without this a seed goes undiscoverable one TTL after boot. Spawn a
    // background task that re-signs each seed record at `ttl/2` under the SAME announce door/authority
    // (so it passes the same eligibility gate) via the same monotonic + save-before-publish path. It
    // owns SEED keys; the announce-after-fetch hook owns GROWN keys (non-overlapping, TASK-279). No
    // seeds ⇒ no task.
    let seed_resign = if seeds.is_empty() {
        None
    } else {
        let authority = match &plan {
            PublicationPlan::Allowlist => SeedResignAuthority::Public(allowlist.clone()),
            PublicationPlan::Lan(_) => SeedResignAuthority::Lan,
        };
        spawn_seed_resign(
            Arc::clone(&fabric),
            readiness.clone(),
            identity_seed,
            seeds,
            ttl_secs,
            announce_budget,
            authority,
        )
    };

    println!("daemon-libp2p: PROVIDER serving + announcing {report} (kad SERVER mode)");

    // NOTE: the lan-share SERVING disclosure was already emitted ABOVE, BEFORE the serve gate
    // activated (TASK-276 FIX #3 sequencing) — not here.

    if cfg.libp2p_print_peer_address {
        let listen_addrs = fabric.handle().listen_addrs().await;
        if listen_addrs.is_empty() {
            return Err(
                "--libp2p-print-peer-address requested but the provider bound no address".into(),
            );
        }
        let addrs = listen_addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "LIBP2P-PROVIDER-ADDR peer_id={} addrs={addrs}",
            fabric.peer_id()
        );
    }

    Ok((
        fabric,
        ProviderGuard {
            _serve: serve,
            _index: index,
            post_fetch_announce,
            _seed_resign: seed_resign,
        },
    ))
}

/// A never-cancelling [`daemon_core::availability::CancellationCheck`] for the one-shot
/// `__dump-raw-nar` helper: the parent process owns the timeout/kill via the supervised process
/// group, so the in-process read itself does not self-cancel.
struct NeverCancel;

impl daemon_core::availability::CancellationCheck for NeverCancel {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// The internal raw-NAR helper subprocess mode (`daemon-libp2p __dump-raw-nar <path>`): dump a
/// raw-NAR REGULAR FILE to stdout for a [`fabric_libp2p::ProbedSource::RegularFile`] serve, run in
/// an owned, killable, stdout-capped process group by the [`CatalogNarSupplier`]'s supervisor. It
/// is authorized ONLY by the env guard that supply path sets (`raw_nar_helper_authorized`), so it
/// is not a user-invokable mode. Store paths are served by `nix-store --dump` (a Process source)
/// and never reach this. Handled before any flag parsing, mirroring the `daemon` binary.
fn run_raw_nar_helper() -> Option<ExitCode> {
    use std::io::Write;
    let mut raw = std::env::args_os().skip(1);
    if raw.next().as_deref() != Some(std::ffi::OsStr::new(fabric_libp2p::RAW_NAR_HELPER_ARG)) {
        return None;
    }
    if !raw_nar_helper_authorized() {
        eprintln!("daemon-libp2p: __dump-raw-nar is an internal supervised subprocess mode");
        return Some(ExitCode::from(2));
    }
    let Some(path) = raw.next() else {
        eprintln!("daemon-libp2p: __dump-raw-nar requires exactly one path");
        return Some(ExitCode::from(2));
    };
    if raw.next().is_some() {
        eprintln!("daemon-libp2p: __dump-raw-nar accepts exactly one path");
        return Some(ExitCode::from(2));
    }
    let bytes = match RegularFileNarDumper.dump(&StorePath::new(path), &NeverCancel) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("daemon-libp2p: __dump-raw-nar failed: {error}");
            return Some(ExitCode::FAILURE);
        }
    };
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    match locked.write_all(&bytes).and_then(|()| locked.flush()) {
        Ok(()) => Some(ExitCode::SUCCESS),
        Err(error) => {
            eprintln!("daemon-libp2p: __dump-raw-nar failed writing stdout: {error}");
            Some(ExitCode::FAILURE)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    // Internal process-isolation boundary for raw-file supply, handled before configuration:
    // the parent owns this process group, caps stdout, and kills/reaps it on cancel/shutdown.
    if let Some(code) = run_raw_nar_helper() {
        return code;
    }

    daemon_libp2p::init_tracing();

    // TASK-240: the `--status <addr>` / `--metrics <addr>` CLIENT subcommands query a RUNNING
    // instance's admin surface and exit; handled before parse_config so they never collide with the
    // daemon flag grammar.
    if let Some(code) = maybe_run_admin_query().await {
        return code;
    }

    let cfg = match parse_config(std::env::args().skip(1)) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("daemon-libp2p: {err}");
            return ExitCode::from(2);
        }
    };

    // TASK-120: build the ONE authoritative operator contract and validate it FAIL-CLOSED. The
    // profile was already derived + cross-checked against `--profile` in parse_config.
    let contract = match build_contract(&cfg) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("daemon-libp2p: operator contract rejected: {err}");
            return ExitCode::from(2);
        }
    };

    // TASK-280 #3: hint a LAN-oriented consumer that is on the public v1 scope (it would silently
    // miss a lan-share.v1 pool). Consume-capable here = the consume-only leech profile; the effective
    // scope is the SAME canonical decision the fabric uses.
    let consume_capable = cfg.profile == SharingProfile::ConsumeOnly;
    let effective_scope = effective_network_scope(
        cfg.libp2p_scope.as_deref(),
        cfg.profile == SharingProfile::LanShare,
    );
    if should_hint_lan_share_scope(
        &effective_scope,
        consume_capable,
        cfg.mdns_active,
        !cfg.libp2p_bootstrap.is_empty(),
    ) {
        eprintln!("daemon-libp2p: NOTE — this consume-only node is {LAN_SHARE_SCOPE_HINT}");
    }

    // TASK-120 AC#10 (+ codex #1/#5b): the full fail-closed budget contract — the frozen artifact
    // verify (hash/identity + normative envelope + parity) AND the EFFECTIVE serve-budget ceiling
    // (an override may only tighten the envelope). This binary's serve budget is the fixed
    // `provider_serve_budget()` (= `ResourceCaps::default().serve_budget()`, no serve-size CLI
    // override), so the ceiling check is a guard-rail today, not a live gate — but it makes the
    // invariant "whatever reaches ServeBudget is within the envelope" hold structurally here too,
    // and it bites if a future flag ever loosens it.
    let budget_check = || -> Result<(), String> {
        daemon_core::profile_budget::verify(contract.profile, &contract.caps)
            .map_err(|e| e.to_string())?;
        let sb = provider_serve_budget();
        daemon_core::profile_budget::check_serve_ms_within_envelope(
            sb.max_nar_bytes_uncompressed_nar,
            sb.max_inflight_bytes_uncompressed_nar,
            sb.max_serve_duration.as_millis() as u64,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    };

    // TASK-120 AC#7 + fix #3: `--preflight` renders the contract and EXITS BEFORE any
    // network-precondition guard (a pure static read of the INTENDED profile), so e.g.
    // `daemon-libp2p --preflight` shows the upstream-only preflight without demanding a bootstrap.
    // codex #5b: preflight must EXIT NONZERO when the budget contract fails, so automation that
    // checks only preflight's status cannot accept a drifted/over-envelope budget (fail-OPEN).
    if cfg.preflight {
        println!("{}", contract.preflight());
        if let Err(err) = budget_check() {
            eprintln!("daemon-libp2p: profile-budget contract rejected: {err}");
            return ExitCode::from(2);
        }
        return ExitCode::SUCCESS;
    }

    // TASK-276 FIX #B: a bare `--profile lan-share` does NOT auto-resolve a private-LAN listen (the
    // interface heuristic was defeated twice in review). A cross-host lan-share must name its LAN
    // address via --libp2p-listen; `check_runtime_preconditions` (below) fails LOUD when it is empty.

    // TASK-120 fix #1/#3: the network-precondition guards run ONLY on the live path, AFTER the
    // preflight early-return, keyed off the AUTHORITATIVE profile - so a fresh upstream-only node
    // with no bootstrap runs, while a consume-only node still requires one.
    if let Err(err) = check_runtime_preconditions(&cfg) {
        eprintln!("daemon-libp2p: {err}");
        return ExitCode::from(2);
    }

    // TASK-120 AC#10: fail-closed on the frozen per-profile budget contract BEFORE serving (the same
    // `budget_check` preflight ran): content hash (freeze/identity), normative envelope, parity vs
    // the running caps, and the effective serve-budget ceiling. A drifted/exceeded/diverged budget
    // BLOCKS startup with a precise reason — never a silent zero/unbounded default. (A genuinely
    // MISSING artifact is caught earlier, at BUILD time: the artifact is `include_str!`'d, so its
    // absence is a compile error; PROFILE_BUDGET_ARTIFACT_MISSING has no production caller today — it
    // is the fail-closed contract a future filesystem/Stage-B loader would use.)
    if let Err(err) = budget_check() {
        eprintln!("daemon-libp2p: profile-budget contract rejected: {err}");
        return ExitCode::from(2);
    }

    // TASK-120 AC#4 (startup surface): always announce the derived operator MODE so the running
    // node's participation is legible from its first log line; AC#5: print the mandatory privacy
    // banner when opt-in diagnostics are enabled.
    println!(
        "daemon-libp2p: operator profile={} ({})",
        contract.profile,
        contract.profile.describe()
    );
    if contract.privacy.diagnostics_opt_in {
        eprintln!("daemon-libp2p: {}", daemon_core::DIAGNOSTICS_WARNING);
    }
    // TASK-273 AC#4: when LAN mDNS is ACTIVE, disclose the presence EXPOSURE on the first log line
    // so the operator can tell it is working — and what it discloses — without RUST_LOG surgery.
    // This is the sensitive privacy default made legible.
    if cfg.mdns_active {
        // #6: label mDNS honestly by HOW it was enabled — the lan-share PROFILE DEFAULT (raw opt-in
        // unset + profile is lan-share) vs an EXPLICIT `--libp2p-mdns` (e.g. under consume-only /
        // public-share / router). Only the former is a "default".
        let how = if cfg.libp2p_mdns.is_none() && cfg.profile == SharingProfile::LanShare {
            "lan-share default"
        } else {
            "explicitly enabled via --libp2p-mdns"
        };
        // A SEPARATE exposure, disclosed in the SAME line only when it is actually ON:
        // `--libp2p-announce-after-fetch` makes the node advertise the content-keys of what it
        // fetches to same-pin DHT peers (disclosing WHAT it fetched), on top of the mDNS presence
        // exposure. It is an explicit opt-in (NOT a lan-share default), so name the accurate way to
        // avoid it: don't pass the flag — or `--profile consume-only` to fetch without serving.
        let announce_clause = if cfg.libp2p_announce_after_fetch {
            " It ALSO announces the content-keys of the store paths it fetches to same-pin DHT \
             peers (--libp2p-announce-after-fetch) — disclosing WHAT you have fetched; drop that \
             flag, or use --profile consume-only to fetch without serving/announcing."
        } else {
            ""
        };
        println!(
            "daemon-libp2p: LAN discovery ACTIVE via mDNS ({how}). This host multicasts its \
             presence, NodeId, and libp2p listen multiaddrs to the local link and answers any LAN \
             querier — this is how same-pin peers find you with zero config. Opt out: \
             --libp2p-no-mdns (NixOS: services.nix-p2p.libp2p.mdns = false).{announce_clause}"
        );
    }

    // Resolve the durable identity seed ONCE (TASK-185 GB1: anchor to the state dir so a plain
    // `--libp2p-state-dir` restart is the SAME node). Shared by the public-NAR allowlist MAC key,
    // the (participating) fabric construction, and the upstream-only FakeFabric's NodeId.
    let identity_seed = match resolve_durable_identity_seed(
        cfg.libp2p_state_dir.as_deref(),
        cfg.libp2p_identity_seed,
    ) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("daemon-libp2p: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Build the node's ONE public-NAR allowlist (TASK-103/204) through the SHARED wiring the
    // composite `daemon` binary also uses, so the two binaries' publication policy cannot drift.
    // Without `--libp2p-public-allowlist-path` this is a DISABLED allowlist (learns nothing,
    // `contains` always false) - the pre-TASK-103 behaviour. WITH a path it opens the
    // MAC-integrity-protected file (key from the durable identity seed) and proves each
    // `--libp2p-prove-public-narinfo` public via the trusted-key signature gate. It is BOTH the
    // provider announce gate (below) and the serving daemon's learn sink (RunConfig), one instance.
    let public_allowlist = match open_public_allowlist(
        cfg.libp2p_public_allowlist_path.as_deref(),
        &cfg.libp2p_trusted_public_keys,
        &identity_seed,
        &cfg.libp2p_prove_public_narinfo,
    ) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("daemon-libp2p: {err}");
            return ExitCode::FAILURE;
        }
    };

    let upstream = match UpstreamHttp::new(&cfg.upstream) {
        Ok(u) => Arc::new(u.with_header_timeout(Duration::from_millis(cfg.header_timeout_ms))),
        Err(err) => {
            eprintln!("daemon-libp2p: bad --upstream: {err}");
            return ExitCode::from(2);
        }
    };
    // TASK-29: narinfo disk cache ON BY DEFAULT (a default XDG state dir is resolved
    // when no `--narinfo-cache-dir` is given; `--no-narinfo-cache` opts out). The
    // choice→source policy (soft-fail default vs fatal explicit) lives ONCE in
    // `daemon_core::build_narinfo_layer`, shared with the composite `daemon` binary;
    // here we only log the outcome and decide whether to abort.
    let choice = resolve_narinfo_cache_dir(
        cfg.narinfo_cache_dir.as_deref(),
        cfg.no_narinfo_cache,
        |k| std::env::var(k).ok(),
    );
    let (narinfo, correlation): (Arc<dyn NarinfoSource>, Arc<dyn CorrelationStore>) =
        match build_narinfo_layer(choice, upstream.clone(), Arc::new(SystemClock)) {
            NarinfoLayer::Cached {
                narinfo,
                correlation,
                dir,
            } => {
                println!("daemon-libp2p: narinfo disk cache at {}", dir.display());
                (narinfo, correlation)
            }
            NarinfoLayer::PassThrough {
                narinfo,
                correlation,
                reason,
            } => {
                match reason {
                    PassThroughReason::Disabled => {
                        println!("daemon-libp2p: narinfo disk cache disabled (--no-narinfo-cache)")
                    }
                    PassThroughReason::NoDefault => eprintln!(
                        "daemon-libp2p: WARNING: no --narinfo-cache-dir and neither HOME nor \
                         XDG_STATE_HOME is set; running WITHOUT a persistent narinfo cache"
                    ),
                    PassThroughReason::DefaultOpenFailed { dir, err } => eprintln!(
                        "daemon-libp2p: WARNING: default narinfo cache dir {dir:?} is unusable \
                         ({err}); running WITHOUT a persistent narinfo cache"
                    ),
                }
                (narinfo, correlation)
            }
            NarinfoLayer::ExplicitOpenFailed { dir, err } => {
                eprintln!("daemon-libp2p: cannot open narinfo cache dir {dir:?}: {err}");
                return ExitCode::FAILURE;
            }
        };

    // Consumer axes; a provider additionally needs the serve + announce axes. `run` re-asserts
    // these, and the construction already asserted them at start (belt and braces).
    // AUTHORITY INVERSION (TASK-120 fix #3 + fix A): BOTH the serve/announce axes AND the SWARM
    // PARTICIPATION derive from the AUTHORITATIVE profile, so a node's reported participation
    // matches what it does on the wire:
    //   * UPSTREAM-ONLY: NO participating swarm at all - a pure HTTP node backed by a FakeFabric
    //     (every P2P axis None). No kad (server OR client), no relay, no listen. required_axes is
    //     EMPTY. This is why `public_dht_participation=false` is honest: there is no swarm.
    //   * CONSUME-ONLY: a Libp2pFabric in kad CLIENT mode + relay-server OFF (source_config), masked
    //     with LeechFabric (serve+announce None). It fetches but provides no DHT infrastructure.
    //   * PROVIDER (lan-share/public-share): a Libp2pFabric in kad SERVER mode + relay as configured,
    //     with the serve gate + announcer installed.
    let mut required_axes = vec![
        Axis::ProviderDirectory,
        Axis::NodeLocator,
        Axis::Transfer(TransportTag::Libp2p),
    ];
    let _serve_guard: Option<ProviderGuard>;
    let fabric_dyn: Arc<dyn PeerFabric>;
    // TASK-240: the LIVE status-facts provider and this node's identity, captured per branch so the
    // status surface reports the ACTUAL running node (its swarm's bootstrap health, its NodeId).
    let status_facts: Arc<dyn StatusFacts>;
    let observ_node_id: String;

    if contract.profile == SharingProfile::UpstreamOnly {
        // FIX A: a pure HTTP node. No libp2p swarm is constructed, so it stores nothing, answers no
        // DHT query, and relays for nobody. required_axes is emptied (the FakeFabric exposes no P2P
        // axis and `run` asserts only what is required).
        required_axes.clear();
        _serve_guard = None;
        let node_id = NodeId::from_bytes(
            SigningKey::from_bytes(&identity_seed)
                .verifying_key()
                .to_bytes(),
        );
        // No swarm: the status surface has no bootstrap health / peer path to report (NullFacts),
        // but the node still has a stable identity to show.
        observ_node_id = node_id.to_string();
        status_facts = Arc::new(NullStatusFacts);
        fabric_dyn = Arc::new(peer_fabric::FakeFabric::upstream_only(node_id));
        println!(
            "daemon-libp2p: UPSTREAM-ONLY started - pure HTTP fallback, NO libp2p swarm (no DHT \
             participation: no kad server/client, no relay, no serving, no announce)"
        );
    } else if contract.profile.serves() {
        required_axes.push(Axis::Server);
        required_axes.push(Axis::Announcer);
        // TASK-280 #3 single-source: mint the publication plan ONCE here. The SAME decision that
        // produces PublicationPlan::Lan (no allowlist + LAN-isolation witness) drives the fabric's
        // scope + confinement, so the two cannot drift. A public-reachable no-allowlist provider
        // aborts HERE, before any fabric/listener is built.
        let plan = match provider_publication_decision(&cfg) {
            Ok(plan) => plan,
            Err(err) => {
                eprintln!("daemon-libp2p: provider setup failed: {err}");
                return ExitCode::FAILURE;
            }
        };
        let lan_share = matches!(plan, PublicationPlan::Lan(_));
        let source_cfg = source_config(&cfg, contract.profile, identity_seed, lan_share);
        let fabric =
            match install_provider(&cfg, &contract, source_cfg, plan, &public_allowlist).await {
                Ok((fabric, guard)) => {
                    // The accurate served-set report line (S seeds + P store paths + hook) is printed
                    // INSIDE `install_provider`, from the ACTUAL built legs (TASK-278) - never a
                    // one-or-the-other count derived from the CLI flags here.
                    _serve_guard = Some(guard);
                    fabric
                }
                Err(err) => {
                    eprintln!("daemon-libp2p: provider setup failed: {err}");
                    return ExitCode::FAILURE;
                }
            };
        // TASK-240: capture the live-facts provider (bootstrap health via the swarm handle) + the
        // node identity BEFORE the fabric is moved into `fabric_dyn`.
        observ_node_id = fabric.peer_id().to_string();
        status_facts = Arc::new(SwarmStatusFacts::new(
            fabric.handle().clone(),
            cfg.libp2p_bootstrap.iter().map(|(p, _)| *p).collect(),
        ));
        // A serving profile uses the concrete fabric (its serve gate is installed).
        fabric_dyn = fabric;
    } else {
        // Non-serving participating swarm: either CONSUME-ONLY (kad CLIENT + relay OFF) or a ROUTER
        // (kad SERVER + relay as configured, TASK-241). Both are masked with LeechFabric below so
        // the serve + announce axes are structurally None - a router carries NO content just like a
        // leech. `source_config` already set kad_server + the relay server from the profile.
        _serve_guard = None;
        // A non-serving participant (CONSUME-ONLY or ROUTER) is never LAN-confined: confinement is a
        // PROVIDER egress control, and there is no PublicationPlan on this path (`lan_share = false`).
        // A consumer that wants to join a lan-share pool passes `--libp2p-scope lan-share.v1`.
        let source_cfg = source_config(&cfg, contract.profile, identity_seed, false);
        let fabric = match build_libp2p_nar_source(source_cfg).await {
            Ok((fabric, _source, _raw)) => {
                if contract.profile == SharingProfile::Router {
                    let relay = if cfg.libp2p_relay_server_enabled {
                        "relay server ON"
                    } else {
                        "relay server OFF (--libp2p-no-relay-server)"
                    };
                    println!(
                        "daemon-libp2p: ROUTER started (kad SERVER mode, {relay}) - a bootstrap/relay \
                         root for others; carries NO content (serves NOTHING, announces NOTHING), \
                         {} bootstrap peer(s)",
                        cfg.libp2p_bootstrap.len()
                    );
                } else {
                    println!(
                        "daemon-libp2p: CONSUMER started (kad CLIENT mode, relay OFF), discovery \
                         converging ({} bootstrap peer(s))",
                        cfg.libp2p_bootstrap.len()
                    );
                }
                if cfg.libp2p_leech {
                    // TASK-78 exposure honesty (AC#5): state EXACTLY what a leech hides vs reveals.
                    println!(
                        "daemon-libp2p: LIBP2P-LEECH consume-only: serves NOTHING + announces \
                         NOTHING (serve/announce axes masked at the capability seam). HONEST \
                         LIMIT: it STILL SENDS discovery lookups (kad get_record + peer-routing), \
                         disclosing what it looks up to the DHT nodes it queries - a leech hides \
                         what it SERVES/ANNOUNCES, not what it LOOKS UP."
                    );
                }
                fabric
            }
            Err(err) => {
                eprintln!("daemon-libp2p: consumer setup failed: {err}");
                return ExitCode::FAILURE;
            }
        };
        // TASK-240: capture the live-facts provider + node identity BEFORE the fabric is wrapped in
        // the LeechFabric mask (a router/consumer still has a real swarm with bootstrap health).
        observ_node_id = fabric.peer_id().to_string();
        status_facts = Arc::new(SwarmStatusFacts::new(
            fabric.handle().clone(),
            cfg.libp2p_bootstrap.iter().map(|(p, _)| *p).collect(),
        ));
        // AUTHORITY INVERSION (fix #3): a non-serving profile is wrapped in the LeechFabric mask so
        // serve + announce are structurally None at the seam.
        fabric_dyn = Arc::new(LeechFabric::new(fabric));
    }

    let listener = match TcpListener::bind(cfg.listen).await {
        Ok(l) => l,
        Err(err) => {
            eprintln!("daemon-libp2p: cannot bind {}: {err}", cfg.listen);
            return ExitCode::FAILURE;
        }
    };
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| cfg.listen.to_string());
    println!(
        "daemon-libp2p: listening on {local} -> upstream {}",
        cfg.upstream
    );

    // TASK-240: the announce hook (its budget feeds the LIVE status figure), computed ONCE and
    // shared by the observability bundle and the RunConfig (one source of truth).
    let post_fetch = _serve_guard
        .as_ref()
        .and_then(|g| g.post_fetch_announce.clone());

    // TASK-240: the runtime observability bundle (metrics SSOT + live facts + announce hook). The
    // metrics are ALWAYS recorded (cheap); the operator `--status`/`--metrics` surface is served
    // only when the operator opts in with `--status-listen`, on its OWN loopback socket — never on
    // the peer-facing cache listener. No `--status-listen` = no introspection surface (fail-safe).
    let observability = Arc::new(Observability {
        contract: contract.clone(),
        node_id_full: observ_node_id,
        metrics: Arc::new(RuntimeMetrics::new()),
        facts: status_facts,
        announce: post_fetch.clone(),
        // TASK-229: no LIVE derive-budget figure yet - this binary runs no over-libp2p
        // hold-query RESPONDER, so there is no `PeerDeriveLedger` charging on a wire path
        // to report. The contract's derive_budget() CAP is still visible in --preflight
        // via `effective_lines`. When the libp2p hold-responder lands (its own task), it
        // constructs `PeerDeriveLedger::new(contract.caps.derive_budget())`, threads it
        // into the answer path, and passes `Some(ledger)` here for the live used/CAP.
        derive_ledger: None,
    });
    let admin_listener = match cfg.status_listen {
        Some(addr) => match TcpListener::bind(addr).await {
            Ok(l) => {
                let admin_local = l
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| addr.to_string());
                println!(
                    "daemon-libp2p: operator admin surface on {admin_local} \
                     (GET {STATUS_PATH}, {METRICS_PATH}; redacted unless --diagnostics)"
                );
                Some(l)
            }
            Err(err) => {
                eprintln!("daemon-libp2p: cannot bind --status-listen {addr}: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    let run_cfg = RunConfig {
        listener,
        upstream: upstream.clone() as Arc<dyn NarSource>,
        narinfo,
        passthrough: upstream.clone() as Arc<dyn RawUpstream>,
        correlation,
        cache_info: CacheInfo {
            store_dir: cfg.store_dir.clone(),
            priority: cfg.priority,
            want_mass_query: cfg.want_mass_query,
        },
        upstream_label: cfg.upstream.clone(),
        discovery_budget: DiscoveryBudget::default(),
        envelope: SafetyEnvelope::default(),
        required_axes,
        extra_raw_serve: Vec::new(),
        // TASK-103/204: the SAME allowlist instance the provider announce gate consulted above -
        // one source of truth (a disabled allowlist without `--libp2p-public-allowlist-path`, a
        // populated file-backed one with it), matching the composite `daemon` binary.
        public_allowlist,
        // TASK-77: the announce-after-fetch hook the provider install built (present only with
        // `--libp2p-announce-after-fetch`); `None` = consume-only (leech). Shared with the
        // observability bundle above so the reported budget is the enforced one.
        post_fetch_announce: post_fetch,
        // TASK-240: the observability bundle + the OPT-IN admin listener.
        observability: Some(observability),
        admin_listener,
    };

    // `fabric_dyn` was built above per the AUTHORITATIVE profile: a FakeFabric (no swarm) for
    // upstream-only, a LeechFabric-masked consumer for consume-only, or the concrete serving fabric
    // for a provider profile.
    let mut success = true;
    tokio::select! {
        result = run(fabric_dyn, run_cfg) => {
            if let Err(err) = result {
                eprintln!("daemon-libp2p: serve error: {err}");
                success = false;
            }
        }
        signal = wait_for_shutdown() => {
            match signal {
                Ok(name) => println!("daemon-libp2p: received {name}; shutting down"),
                Err(err) => {
                    eprintln!("daemon-libp2p: shutdown signal error: {err}");
                    success = false;
                }
            }
        }
    }
    // `fabric` (its swarm worker) and `_serve_guard` drop here, stopping the node.
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Resolve when a SIGINT or SIGTERM arrives, so the serve loop is cancelled and the fabric /
/// serve gate are dropped (their teardown).
async fn wait_for_shutdown() -> Result<&'static str, String> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
    let mut sigterm = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    tokio::select! {
        _ = sigint.recv() => Ok("SIGINT"),
        _ = sigterm.recv() => Ok("SIGTERM"),
    }
}

#[cfg(test)]
mod bootstrap_guard_tests {
    //! TASK-102 LAN-isolation guard bite (fix cycle #2): the shipped provider modes must REFUSE
    //! announcing whenever the node can reach ANY public substrate without a configured allowlist -
    //! a non-empty `--libp2p-bootstrap`, a non-empty `--libp2p-provider-addr` (the residual), or a
    //! non-loopback/non-link-local `--libp2p-listen` - and still permit a no-public-reach-signal
    //! (loopback-listen, no bootstrap, no provider-addr) LAN announce. This drives the binary's
    //! Config->reachability wrapper, so a call site that FORGOT to pass provider-addr/listen (the
    //! original hole) is caught here, not only in the lib-level policy test.
    use super::{Config, SharingProfile, lan_share_or_refuse, source_config};
    use fabric_libp2p::{Libp2pFabric, Multiaddr, NodeConfig, PeerId};
    use std::time::Duration;

    fn peer() -> PeerId {
        "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
            .parse()
            .unwrap()
    }

    #[test]
    fn source_config_wires_lan_confinement_and_scope_by_profile() {
        // TASK-280 #3 single-source: `source_config` faithfully applies the caller's ONE `lan_share`
        // decision (derived at the production callsite from `matches!(plan, PublicationPlan::Lan(_))`)
        // to BOTH the frozen lan-share.v1 scope AND `lan_confinement`; `lan_share == false` stays on
        // public v1 and unconfined. Threading the SAME bool into both fields is what stops the scope
        // and the confinement drifting from the publication decision. MUTATION: drop
        // `lan_confinement: lan_share` or the `effective_network_scope` call and the corresponding
        // assertion flips. (The plan -> lan_share derivation itself is covered by the
        // `provider_publication_decision` tests.)
        let base = provider_cfg(
            Vec::new(),
            Vec::new(),
            Some(addr("/ip4/192.168.1.7/tcp/4001")),
        );

        let lan = source_config(&base, SharingProfile::LanShare, [9u8; 32], true);
        assert_eq!(
            lan.network_scope,
            daemon_libp2p::LAN_SHARE_NETWORK_SCOPE,
            "a lan-share node scopes to the frozen lan-share.v1"
        );
        assert!(lan.lan_confinement, "a lan-share node is LAN-confined");

        for other in [SharingProfile::PublicShare, SharingProfile::ConsumeOnly] {
            let sc = source_config(&base, other, [9u8; 32], false);
            assert_eq!(sc.network_scope, "v1", "{other:?} stays on public v1");
            assert!(!sc.lan_confinement, "{other:?} is NOT LAN-confined");
        }

        // An explicit --libp2p-scope overrides even for lan-share (advanced shared-scope escape).
        let mut explicit = provider_cfg(
            Vec::new(),
            Vec::new(),
            Some(addr("/ip4/192.168.1.7/tcp/4001")),
        );
        explicit.libp2p_scope = Some("deliberately-shared".to_string());
        let overridden = source_config(&explicit, SharingProfile::LanShare, [9u8; 32], true);
        assert_eq!(overridden.network_scope, "deliberately-shared");
        assert!(
            overridden.lan_confinement,
            "confinement still applies to a lan-share node on an explicit shared scope"
        );
    }

    #[test]
    fn scope_is_audience_lan_leech_joins_the_pool_by_explicit_scope() {
        // TASK-280 #3 (SCOPE = AUDIENCE, de-vacuumed): scope names the POOL a node joins, independent
        // of its role. A REAL LanShare PROVIDER and a REAL ConsumeOnly LEECH that passes
        // `--libp2p-scope lan-share.v1` BOTH land on lan-share.v1 (so the leech finds the provider);
        // a BARE ConsumeOnly (no override) lands on the PUBLIC v1 — it would NOT find the lan-share
        // pool, which is exactly why the leech must opt in. This asserts REAL source_config outputs
        // across DIFFERENT profiles, not `effective_network_scope(None, true)` twice (the prior
        // vacuous parity check). MUTATION: make the explicit --libp2p-scope NOT win in
        // effective_network_scope and the leech-joins assertion flips RED.
        let provider = source_config(
            &provider_cfg(
                Vec::new(),
                Vec::new(),
                Some(addr("/ip4/192.168.1.7/tcp/4001")),
            ),
            SharingProfile::LanShare,
            [1u8; 32],
            true,
        );
        assert_eq!(
            provider.network_scope,
            daemon_libp2p::LAN_SHARE_NETWORK_SCOPE
        );

        // A bare consume-only leech: no explicit scope -> public v1 (does NOT join the lan-share pool).
        let bare_leech = source_config(
            &provider_cfg(Vec::new(), Vec::new(), None),
            SharingProfile::ConsumeOnly,
            [2u8; 32],
            false,
        );
        assert_eq!(
            bare_leech.network_scope, "v1",
            "a bare consume-only leech defaults to the PUBLIC v1 pool"
        );

        // A consume-only leech that OPTS IN with --libp2p-scope lan-share.v1: joins the SAME pool as
        // the provider (scope = audience, role-independent).
        let mut opt_in = provider_cfg(Vec::new(), Vec::new(), None);
        opt_in.libp2p_scope = Some(daemon_libp2p::LAN_SHARE_NETWORK_SCOPE.to_string());
        let joined_leech = source_config(&opt_in, SharingProfile::ConsumeOnly, [3u8; 32], false);
        assert_eq!(
            joined_leech.network_scope, provider.network_scope,
            "a consume-only leech that passes --libp2p-scope lan-share.v1 joins the provider's pool"
        );
        assert!(
            !joined_leech.lan_confinement,
            "a consume-only leech is NOT LAN-confined (it dials the pool it was told to join); \
             confinement is a PROVIDER egress control, not a consumer one"
        );
    }

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    /// A minimal PROVIDER config with the reachability fields set from the args and safe defaults
    /// elsewhere. The wrapper only reads `libp2p_bootstrap` / `libp2p_provider_addrs` /
    /// `libp2p_listen`, so the other fields are immaterial to the guard.
    fn provider_cfg(
        bootstrap: Vec<(PeerId, Multiaddr)>,
        provider_addrs: Vec<(PeerId, Multiaddr)>,
        listen: Option<Multiaddr>,
    ) -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream: "https://cache.nixos.org".to_string(),
            header_timeout_ms: 30_000,
            narinfo_cache_dir: None,
            no_narinfo_cache: false,
            store_dir: "/nix/store".to_string(),
            priority: 0,
            want_mass_query: true,
            libp2p_bootstrap: bootstrap,
            libp2p_provider_addrs: provider_addrs,
            libp2p_listen: listen.into_iter().collect(),
            libp2p_external_addresses: Vec::new(),
            libp2p_scope: None,
            libp2p_mdns: None,
            mdns_active: false,
            libp2p_mainline_rendezvous: false,
            libp2p_mainline_bootstrap: Vec::new(),
            libp2p_identity_seed: None,
            libp2p_provider: true,
            libp2p_seed_nar: Vec::new(),
            libp2p_provide_store: Vec::new(),
            libp2p_print_peer_address: false,
            libp2p_state_dir: None,
            libp2p_trusted_public_keys: Vec::new(),
            libp2p_public_allowlist_path: None,
            libp2p_prove_public_narinfo: Vec::new(),
            libp2p_relay_server_enabled: true,
            libp2p_announce_after_fetch: false,
            libp2p_announce_budget: crate::default_libp2p_announce_budget(),
            libp2p_record_ttl_secs: crate::DEFAULT_LIBP2P_RECORD_TTL_SECS,
            libp2p_leech: false,
            libp2p_router: false,
            preflight: false,
            diagnostics: false,
            explicit_profile: None,
            status_listen: None,
            // This helper constructs a PROVIDER config directly for the lan_share_or_refuse guard
            // tests; those tests never consult `profile`, so lan-share is a faithful placeholder.
            profile: SharingProfile::LanShare,
        }
    }

    #[test]
    fn isolated_loopback_provider_is_permitted_as_a_lan_announce() {
        let cfg = provider_cfg(Vec::new(), Vec::new(), Some(addr("/ip4/127.0.0.1/tcp/0")));
        assert!(
            lan_share_or_refuse(&cfg).is_ok(),
            "a no-public-reach-signal (loopback-listen, no bootstrap/provider-addr) announce is permitted"
        );
    }

    #[test]
    fn a_bootstrapped_announce_without_an_allowlist_is_refused() {
        let cfg = provider_cfg(
            vec![(peer(), addr("/ip4/127.0.0.1/tcp/4001"))],
            Vec::new(),
            Some(addr("/ip4/127.0.0.1/tcp/0")),
        );
        let err = lan_share_or_refuse(&cfg)
            .expect_err("a bootstrapped announce without an allowlist must be refused");
        assert!(
            err.contains("TASK-103"),
            "the refusal must name TASK-103 (the wiring that makes this safe): {err}"
        );
    }

    #[test]
    fn a_provider_addr_with_empty_bootstrap_is_refused() {
        // THE residual bite (fix cycle #2): before the fix the guard checked ONLY the bootstrap
        // vector, so this provider (empty bootstrap, a provider-addr seeded into kad) MINTED a
        // LanShare and announced UNGATED to the public DHT. It must now REFUSE.
        let cfg = provider_cfg(
            Vec::new(),
            vec![(peer(), addr("/ip4/127.0.0.1/tcp/4001"))],
            Some(addr("/ip4/127.0.0.1/tcp/0")),
        );
        let err = lan_share_or_refuse(&cfg)
            .expect_err("a provider-addr with empty bootstrap must be refused");
        assert!(
            err.contains("--libp2p-provider-addr") && err.contains("TASK-103"),
            "the refusal must name the provider-addr signal and TASK-103: {err}"
        );
    }

    #[test]
    fn a_public_listen_provider_is_refused() {
        let cfg = provider_cfg(Vec::new(), Vec::new(), Some(addr("/ip4/0.0.0.0/tcp/4001")));
        let err = lan_share_or_refuse(&cfg).expect_err("a wildcard/public listen must be refused");
        assert!(err.contains("TASK-103"), "must name TASK-103: {err}");
    }

    #[test]
    fn publication_decision_aborts_before_any_fabric_for_a_public_no_allowlist_provider() {
        // FIX #2: the SINGLE publication decision is what install_provider calls BEFORE building the
        // fabric. For a no-allowlist provider it must Err on a wildcard, a global, OR a circuit
        // listen — so `?` aborts before `build_libp2p_provider_source` registers a listener. No fabric
        // is constructed in this test: it drives the pure decision directly.
        use super::provider_publication_decision;
        for bad in [
            "/ip4/0.0.0.0/tcp/4001",
            "/ip4/8.8.8.8/tcp/4001",
            "/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit",
        ] {
            let cfg = provider_cfg(Vec::new(), Vec::new(), Some(addr(bad)));
            assert!(
                provider_publication_decision(&cfg).is_err(),
                "a no-allowlist provider with listen {bad} must abort at the decision (before fabric)"
            );
        }
        // A provably-private listen yields a LAN plan (the decision does NOT abort).
        let ok = provider_cfg(
            Vec::new(),
            Vec::new(),
            Some(addr("/ip4/192.168.1.7/tcp/4001")),
        );
        assert!(
            matches!(
                provider_publication_decision(&ok),
                Ok(super::PublicationPlan::Lan(_))
            ),
            "a provably-private no-allowlist provider yields a LAN publication plan"
        );
    }

    #[test]
    fn bare_lan_share_without_listen_fails_loud() {
        // FIX #B: the auto-resolve is GONE — a bare cross-host lan-share with NO --libp2p-listen must
        // fail loud (never silently guess a bind). A lan-share WITH supply (announce-after-fetch) but
        // empty listen reaches the listen precondition, which refuses with a lan-share-specific
        // remedy. MUTATION: re-adding any silent listen default (or weakening this precondition) makes
        // this Err assertion RED.
        use super::check_runtime_preconditions;
        let mut cfg = provider_cfg(Vec::new(), Vec::new(), None);
        cfg.libp2p_announce_after_fetch = true; // give it something to serve -> reach the listen check
        let err = check_runtime_preconditions(&cfg)
            .expect_err("a bare lan-share with empty --libp2p-listen must fail loud");
        assert!(
            err.contains("--libp2p-listen") && err.contains("lan-share"),
            "the refusal must name --libp2p-listen and be lan-share-specific: {err}"
        );
    }

    /// Listener startup is event-correlated and bounded: a direct ephemeral TCP listener must emit
    /// its concrete `NewListenAddr` promptly rather than leaving startup in an unbounded poll loop.
    #[tokio::test]
    async fn direct_listener_readiness_wait_is_bounded() {
        let fabric = Libp2pFabric::start(
            NodeConfig::new([202u8; 32]).with_network_scope("task219-listener-ready"),
        )
        .expect("fabric starts");
        tokio::time::timeout(
            Duration::from_secs(2),
            fabric.handle().listen(addr("/ip4/127.0.0.1/tcp/0")),
        )
        .await
        .expect("direct listener readiness must not wait indefinitely")
        .expect("direct listener emits NewListenAddr");
        assert!(
            !fabric.handle().listen_addrs().await.is_empty(),
            "successful readiness corresponds to a concrete live listener"
        );
    }
}

#[cfg(test)]
mod public_allowlist_parity_tests {
    //! TASK-204: the thin `daemon-libp2p` binary must expose the SAME public-NAR allowlist door
    //! config surface + fail-closed companion validation as the composite `daemon` binary, so the
    //! two cannot drift into two divergent publication policies. These drive the binary's OWN
    //! `parse_config` (not a lib helper), so a missing flag or a dropped validation is caught here.
    use super::parse_config;

    const APP_NAR_HASH: &str = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";
    const FIXTURE_PUBKEY: &str = "nix-p2p-test-1:empdFBu9wVZG12rPKToHMOTsU1qzWzeCcLdq/KQH0JQ=";

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    /// A valid PUBLIC-announce seed provider: `--libp2p-provider` + a seed + a listener + the
    /// allowlist path + a trusted key. Parses cleanly and carries all three door fields.
    #[test]
    fn a_public_provider_parses_with_the_door_flags() {
        let cfg = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-public-allowlist-path",
            "/tmp/nix-p2p-allowlist",
            "--libp2p-trusted-public-key",
            FIXTURE_PUBKEY,
            "--libp2p-prove-public-narinfo",
            "l30jg5xg904s62jvw5znmr682xpr993c=/tmp/app.narinfo",
        ]))
        .expect("a public seed provider with the allowlist door flags parses");
        assert_eq!(
            cfg.libp2p_public_allowlist_path.as_deref(),
            Some(std::path::Path::new("/tmp/nix-p2p-allowlist"))
        );
        assert_eq!(
            cfg.libp2p_trusted_public_keys,
            vec![FIXTURE_PUBKEY.to_string()]
        );
        assert_eq!(cfg.libp2p_prove_public_narinfo.len(), 1);
    }

    /// TASK-285: `--libp2p-record-ttl-secs` defaults to 1h, accepts an in-bounds value, and is
    /// REJECTED fail-fast below 2s (a `ttl/2` refresh cannot keep it lapse-free) or above the
    /// announcer's 24h cap (the announcer would reject it at publish). Bites a dropped bound check.
    #[test]
    fn record_ttl_secs_defaults_and_is_bounded() {
        let default_cfg = parse_config(args(&["--libp2p-leech"]))
            .expect("a bare leech config parses with the default TTL");
        assert_eq!(
            default_cfg.libp2p_record_ttl_secs, super::DEFAULT_LIBP2P_RECORD_TTL_SECS,
            "the record TTL defaults to 1h when the flag is absent"
        );

        let short = parse_config(args(&["--libp2p-record-ttl-secs", "10", "--libp2p-leech"]))
            .expect("an in-bounds short TTL parses (the e2e test hook)");
        assert_eq!(short.libp2p_record_ttl_secs, 10);

        for bad in ["0", "1", &format!("{}", super::MAX_RECORD_TTL_SECS + 1)] {
            let Err(err) = parse_config(args(&["--libp2p-record-ttl-secs", bad])) else {
                panic!("a TTL of {bad} outside the accepted bound must be refused");
            };
            assert!(
                err.contains("--libp2p-record-ttl-secs"),
                "the refusal must name the flag: {err}"
            );
        }
    }

    /// The allowlist path gates a PROVIDER's public announce, so it is inert (and rejected) without
    /// `--libp2p-provider` - exactly the composite binary's rule.
    #[test]
    fn allowlist_path_without_provider_is_refused() {
        let Err(err) = parse_config(args(&[
            "--libp2p-bootstrap",
            "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN@/ip4/127.0.0.1/tcp/4001",
            "--libp2p-public-allowlist-path",
            "/tmp/nix-p2p-allowlist",
        ])) else {
            panic!("an allowlist path without a provider must be refused");
        };
        assert!(
            err.contains("--libp2p-public-allowlist-path") && err.contains("--libp2p-provider"),
            "the refusal must name the path flag and require --libp2p-provider: {err}"
        );
    }

    /// The trusted-key / prove-narinfo companions POPULATE the on-disk allowlist, so they are inert
    /// (and rejected) without the path - the composite binary's rule.
    #[test]
    fn companions_without_the_allowlist_path_are_refused() {
        let Err(err) = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-trusted-public-key",
            FIXTURE_PUBKEY,
        ])) else {
            panic!("a trusted key without the allowlist path must be refused");
        };
        assert!(
            err.contains("--libp2p-public-allowlist-path"),
            "the refusal must require the allowlist path: {err}"
        );
    }

    /// A public allowlist with no trusted key can prove NOTHING public (every announce would
    /// refuse), so it is rejected up front - fail-closed, matching the composite binary.
    #[test]
    fn allowlist_path_without_a_trusted_key_is_refused() {
        let Err(err) = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-public-allowlist-path",
            "/tmp/nix-p2p-allowlist",
        ])) else {
            panic!("an allowlist path with no trusted key must be refused");
        };
        assert!(
            err.contains("--libp2p-trusted-public-key"),
            "the refusal must require at least one trusted key: {err}"
        );
    }
}

#[cfg(test)]
mod operator_contract_tests {
    //! TASK-120 authority inversion: the RUNTIME derives its participation from `cfg.profile`, and
    //! `cfg.profile` is derived from the flags (cross-checked against `--profile`) in `parse_config`.
    //! These drive the binary's OWN `parse_config` + `build_contract` + `check_runtime_preconditions`,
    //! so a wiring gap (a flag that fails to move the MODE, a `--profile` that disagrees silently, a
    //! serve budget that drifts from the caps, or a fresh node that cannot start) is caught here.
    use super::{
        build_contract, check_runtime_preconditions, default_libp2p_announce_budget, parse_config,
        provider_serve_budget, source_config,
    };
    use daemon_core::{ResourceCaps, SharingProfile};

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    const APP_NAR_HASH: &str = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";
    const FIXTURE_PUBKEY: &str = "nix-p2p-test-1:empdFBu9wVZG12rPKToHMOTsU1qzWzeCcLdq/KQH0JQ=";
    const BOOT: &str =
        "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN@/ip4/127.0.0.1/tcp/4001";

    /// TASK-240 (SSOT): the contract's announce-budget CAP follows the operator's
    /// `--libp2p-announce-budget` flag, so the LIVE status/preflight denominator
    /// (`announce_budget=used/CAP`) equals the cap the announce gate actually enforces — not a stale
    /// `ResourceCaps::default()` alongside an overridden gate. MUTATION: pinning `build_contract`'s
    /// caps back to `ResourceCaps::default()` reddens the `== 10` (it would report 256).
    #[test]
    fn announce_budget_cap_follows_the_flag_for_the_surface() {
        let cfg = parse_config(args(&["--libp2p-announce-budget", "10"])).expect("parses");
        let contract = build_contract(&cfg).expect("valid contract");
        assert_eq!(
            contract.caps.announce_distinct_paths_budget, 10,
            "the contract cap must be the effective flag value, not the default"
        );
        // The preflight surface renders that cap (the status denominator derives from the same).
        assert!(
            contract
                .preflight()
                .contains("announce_distinct_paths_budget=10"),
            "the surface must report the effective announce cap:\n{}",
            contract.preflight()
        );
        // A fresh node (no flag) still reports the authoritative default.
        let fresh = build_contract(&parse_config(args(&[])).unwrap()).unwrap();
        assert_eq!(
            fresh.caps.announce_distinct_paths_budget,
            ResourceCaps::default().announce_distinct_paths_budget
        );
    }

    /// AC#9 parity: the shipped serve/announce bounds are the authoritative `ResourceCaps`, not a
    /// second hardcoded set. If a local constant were reintroduced and drifted, this bites.
    #[test]
    fn shipped_budgets_equal_the_authoritative_caps() {
        let caps = ResourceCaps::default();
        assert_eq!(provider_serve_budget(), caps.serve_budget());
        assert_eq!(
            default_libp2p_announce_budget(),
            caps.announce_distinct_paths_budget
        );
    }

    /// fix #1 (fail-safe default): a fresh `daemon-libp2p` with NO flags is UPSTREAM-ONLY and STARTS
    /// (no bootstrap demanded). It serves + announces nothing. This is the mutation-target of the
    /// authority inversion: the runtime keys the serve gate off `profile.serves()`, which is false.
    #[test]
    fn fresh_no_flag_node_is_upstream_only_and_starts() {
        let cfg = parse_config(args(&[])).expect("a fresh no-flag node parses");
        assert_eq!(cfg.profile, SharingProfile::UpstreamOnly);
        assert!(!cfg.profile.serves(), "upstream-only must not serve");
        assert!(!cfg.profile.announces(), "upstream-only must not announce");
        // fix #1: upstream-only does NOT require a bootstrap - it must start.
        check_runtime_preconditions(&cfg)
            .expect("a fresh upstream-only node must start with no bootstrap");
        build_contract(&cfg).expect("upstream-only contract is valid");
    }

    /// fix #3 (consume-only still requires a bootstrap): the guard keys off CONSUME-ONLY, not
    /// "non-provider" - so upstream-only is exempt but consume-only is not.
    #[test]
    fn consume_only_requires_a_bootstrap_upstream_only_does_not() {
        // A leech with no bootstrap is consume-only and MUST be rejected at runtime preconditions.
        let leech = parse_config(args(&["--libp2p-leech"])).expect("leech parses");
        assert_eq!(leech.profile, SharingProfile::ConsumeOnly);
        let err = check_runtime_preconditions(&leech)
            .expect_err("consume-only with no bootstrap must be rejected");
        assert!(err.contains("consume-only requires"), "{err}");
        // The same node WITH a bootstrap starts.
        let leech_ok =
            parse_config(args(&["--libp2p-leech", "--libp2p-bootstrap", BOOT])).expect("parses");
        check_runtime_preconditions(&leech_ok).expect("consume-only with a bootstrap starts");
    }

    /// A plain consumer (a bootstrap, no give-side flag) is consume-only - serves + announces
    /// nothing. The mode never silently becomes a give-side one.
    #[test]
    fn a_plain_consumer_is_consume_only() {
        let cfg = parse_config(args(&["--libp2p-bootstrap", BOOT])).expect("consumer parses");
        assert_eq!(cfg.profile, SharingProfile::ConsumeOnly);
        assert!(!cfg.profile.serves());
        assert!(!cfg.profile.announces());
    }

    /// TASK-241: `--libp2p-router` derives the ROUTER profile - a kad SERVER + relay that carries
    /// NO content. The load-bearing bite (mirroring the leech serve-side proof): a router serves
    /// NOTHING and announces NOTHING, yet is a kad SERVER (so it is a usable bootstrap root), and
    /// `source_config` puts kad in SERVER mode with the relay server engaged - the exact wire a
    /// content-less bootstrap/relay root needs, without any give-side capability.
    #[test]
    fn router_is_kad_server_relay_serving_nothing() {
        let cfg = parse_config(args(&[
            "--libp2p-router",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-bootstrap",
            BOOT,
        ]))
        .expect("a router parses");
        assert_eq!(cfg.profile, SharingProfile::Router);
        // GIVE-SIDE BACKDOOR BITE: a router must serve + announce NOTHING.
        assert!(!cfg.profile.serves(), "a router must serve NOTHING");
        assert!(!cfg.profile.announces(), "a router must announce NOTHING");
        // ...yet it IS the DHT infrastructure (a kad server + relay), unlike a consume-only client.
        assert!(
            cfg.profile.runs_dht_server(),
            "a router must be a kad SERVER (a bootstrap/entry root)"
        );
        check_runtime_preconditions(&cfg).expect("a router with a listen starts");
        // The wire the swarm actually runs: kad SERVER + relay server ON.
        let src = source_config(
            &cfg,
            cfg.profile,
            [7u8; 32],
            cfg.profile == SharingProfile::LanShare,
        );
        assert!(src.kad_server, "router swarm must be a kad SERVER");
        assert!(
            src.relay_server_enabled,
            "router runs the relay server by default"
        );
        // The reported DHT role matches the wire.
        let contract = build_contract(&cfg).expect("router contract is valid");
        assert_eq!(contract.dht_role, daemon_core::DhtRole::Server);
        // TASK-241 (codex item 4): this router advertises NO external address, so it is LAN-isolated
        // and must report public_dht_participation=false - NOT the intrinsic-profile hardcode.
        assert!(
            !contract.advertises_public_reachability && !contract.public_dht_participation(),
            "a router with no --libp2p-external-address must report public_dht_participation=false"
        );

        // A PUBLIC router - same flags PLUS a self-advertised external address - runs a
        // publicly-reachable kad-server + relay, so it MUST report public_dht_participation=true
        // (the honesty gap codex caught: a public router mislabelled false). It still serves +
        // announces NOTHING.
        let public_router = parse_config(args(&[
            "--libp2p-router",
            "--libp2p-listen",
            "/ip4/0.0.0.0/tcp/0",
            "--libp2p-external-address",
            "/ip4/203.0.113.7/tcp/4001",
            "--libp2p-bootstrap",
            BOOT,
        ]))
        .expect("a public router parses");
        assert_eq!(public_router.profile, SharingProfile::Router);
        let pub_contract = build_contract(&public_router).expect("public router contract is valid");
        assert!(
            pub_contract.advertises_public_reachability && pub_contract.public_dht_participation(),
            "a router advertising a public external address must report public_dht_participation=true"
        );
        assert!(
            pub_contract
                .preflight()
                .contains("public_dht_participation: true"),
            "the preflight must print public_dht_participation: true for a public router"
        );
        // ...and it STILL serves + announces NOTHING (public reachability is not a give side).
        assert!(!public_router.profile.serves() && !public_router.profile.announces());

        // `--libp2p-no-relay-server` drops ONLY the relay server (a kad-only bootstrap like zboot):
        // still a kad SERVER, but relays for nobody, so it can never be an alternative relay path.
        let kad_only = parse_config(args(&[
            "--libp2p-router",
            "--libp2p-no-relay-server",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
        ]))
        .expect("a kad-only router parses");
        assert_eq!(kad_only.profile, SharingProfile::Router);
        let kad_only_src = source_config(
            &kad_only,
            kad_only.profile,
            [7u8; 32],
            kad_only.profile == SharingProfile::LanShare,
        );
        assert!(kad_only_src.kad_server, "still a kad SERVER");
        assert!(
            !kad_only_src.relay_server_enabled,
            "--libp2p-no-relay-server drops the relay server"
        );

        // A router with NO listen fails fast (it must bind a transport to be reachable).
        let no_listen = parse_config(args(&["--libp2p-router"])).expect("parses");
        let err = check_runtime_preconditions(&no_listen)
            .expect_err("a router with no listen must be rejected");
        assert!(err.contains("router"), "{err}");

        // FAIL-CLOSED: a router combined with a give-side flag is rejected at parse time.
        let backdoor = parse_config(args(&[
            "--libp2p-router",
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
        ]))
        .err()
        .expect("router + provider must fail closed");
        assert!(backdoor.contains("router"), "{backdoor}");

        // The explicit `--profile router` agrees with the flag (the compat-shim cross-check).
        parse_config(args(&[
            "--profile",
            "router",
            "--libp2p-router",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
        ]))
        .expect("--profile router agrees with --libp2p-router");
    }

    /// AC#2: a provider WITHOUT a public allowlist is lan-share; WITH one it is public-share.
    #[test]
    fn provider_modes_map_to_lan_and_public_share() {
        let lan = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
        ]))
        .expect("lan provider parses");
        assert_eq!(lan.profile, SharingProfile::LanShare);
        assert!(lan.profile.serves());

        let public = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-public-allowlist-path",
            "/tmp/nix-p2p-allowlist",
            "--libp2p-trusted-public-key",
            FIXTURE_PUBKEY,
        ]))
        .expect("public provider parses");
        assert_eq!(public.profile, SharingProfile::PublicShare);
        assert!(public.profile.serves());
        assert!(public.profile.public_participation());
    }

    /// fix #4 / #2 (the compat shim): an explicit `--profile` that AGREES with the flags passes; one
    /// that DISAGREES fails closed - `--profile upstream-only --libp2p-provider ...` can never run.
    #[test]
    fn explicit_profile_must_agree_with_the_flags() {
        // Agreement: --profile lan-share + provider flags.
        parse_config(args(&[
            "--profile",
            "lan-share",
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
        ]))
        .expect("--profile lan-share agrees with provider flags");

        // Disagreement: --profile upstream-only but the flags make it a provider. FAIL CLOSED.
        let err = parse_config(args(&[
            "--profile",
            "upstream-only",
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
        ]))
        .err()
        .expect("--profile upstream-only + provider flags must fail closed");
        assert!(err.contains("disagrees"), "{err}");

        // Disagreement the other way: --profile consume-only but no bootstrap-only intent (a bare
        // node is upstream-only). FAIL CLOSED.
        let err2 = parse_config(args(&["--profile", "consume-only"]))
            .err()
            .expect("--profile consume-only on a bare (upstream-only) node must fail closed");
        assert!(err2.contains("disagrees"), "{err2}");
    }

    /// FIX A: the swarm PARTICIPATION MODE derives from the profile. A CONSUMER is a kad CLIENT +
    /// relay-server OFF (provides no DHT infrastructure); a PROVIDER is a kad SERVER + relay on.
    /// This is what makes `public_dht_participation` honest against the wire. Mutation: flip either
    /// mapping and the mismatch reddens.
    #[test]
    fn swarm_participation_mode_derives_from_the_profile() {
        let consumer = parse_config(args(&["--libp2p-bootstrap", BOOT])).expect("consumer parses");
        assert_eq!(consumer.profile, SharingProfile::ConsumeOnly);
        let sc = source_config(
            &consumer,
            consumer.profile,
            [7u8; 32],
            consumer.profile == SharingProfile::LanShare,
        );
        assert!(
            !sc.kad_server,
            "consume-only must be a kad CLIENT, not a server"
        );
        assert!(
            !sc.relay_server_enabled,
            "consume-only must relay for nobody (relay-server OFF)"
        );

        let provider = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
        ]))
        .expect("provider parses");
        let sc2 = source_config(
            &provider,
            provider.profile,
            [7u8; 32],
            provider.profile == SharingProfile::LanShare,
        );
        assert!(
            sc2.kad_server,
            "a provider must be a kad SERVER (DHT participation)"
        );
        assert!(
            sc2.relay_server_enabled,
            "a provider relays by default (relay-server ON)"
        );
    }

    /// FIX A: an UPSTREAM-ONLY node runs NO participating swarm, so any swarm-starting flag
    /// (--libp2p-listen/bootstrap/provider-addr/external-address) is REFUSED at runtime - it can
    /// never bind a kad server/relay and then report public_dht_participation=false.
    #[test]
    fn upstream_only_refuses_swarm_flags() {
        let cfg = parse_config(args(&["--libp2p-listen", "/ip4/127.0.0.1/tcp/0"]))
            .expect("upstream-only + a stray listen parses (contract is valid)");
        assert_eq!(cfg.profile, SharingProfile::UpstreamOnly);
        let err = check_runtime_preconditions(&cfg)
            .expect_err("upstream-only must refuse --libp2p-listen (no participating swarm)");
        assert!(err.contains("NO libp2p swarm"), "{err}");
    }

    /// TASK-257 (DEEP minor a): `--libp2p-mdns` is a consumer's DHT ENTRY PATH, so a bare
    /// `--libp2p-mdns` node derives CONSUME-ONLY (report matches the LIVE path, which opens the
    /// mDNS socket) - NOT upstream-only. `--preflight --libp2p-mdns` therefore reports consume-only
    /// with active mDNS consistently. MUTATION: dropping `cfg.libp2p_mdns` from `has_bootstrap`
    /// re-derives upstream-only (the old dry-run/live inconsistency) - the profile assertion reddens.
    #[test]
    fn bare_mdns_is_consume_only_and_preflight_matches() {
        let cfg = parse_config(args(&["--libp2p-mdns"])).expect("bare --libp2p-mdns parses");
        assert_eq!(
            cfg.profile,
            SharingProfile::ConsumeOnly,
            "mDNS is a DHT entry path, so bare --libp2p-mdns is consume-only, not upstream-only"
        );
        check_runtime_preconditions(&cfg)
            .expect("consume-only with --libp2p-mdns and no bootstrap must be accepted");
        let p = build_contract(&cfg).unwrap().preflight();
        assert!(
            p.contains("consume-only"),
            "preflight must report consume-only for --libp2p-mdns: {p}"
        );
        assert!(
            p.contains("lan-mdns = ENABLED (active on this node)"),
            "preflight must show mDNS active: {p}"
        );
    }

    /// TASK-257 (DEEP minor a): the explicit contradiction `--profile upstream-only --libp2p-mdns`
    /// still fails CLOSED - upstream-only is zero-P2P and cannot carry an mDNS socket. Caught at the
    /// compat-shim cross-check (declared upstream-only != implied consume-only).
    #[test]
    fn explicit_upstream_only_plus_mdns_is_refused() {
        let Err(err) = parse_config(args(&["--profile", "upstream-only", "--libp2p-mdns"])) else {
            panic!("--profile upstream-only + --libp2p-mdns must fail closed");
        };
        assert!(
            err.contains("disagrees") && err.contains("consume-only"),
            "the refusal must name the upstream-only/consume-only disagreement: {err}"
        );
    }

    /// TASK-258 SPIKE: a bare `--libp2p-mainline-rendezvous` (with a local Mainline bootstrap) is a
    /// DHT ENTRY PATH, so it derives CONSUME-ONLY (public-network participation), not upstream-only.
    /// MUTATION: dropping `cfg.libp2p_mainline_rendezvous` from `has_bootstrap` re-derives
    /// upstream-only and this assertion reddens.
    #[test]
    fn bare_mainline_rendezvous_is_consume_only() {
        let cfg = parse_config(args(&[
            "--libp2p-mainline-rendezvous",
            "--libp2p-mainline-bootstrap",
            "127.0.0.1:16881",
        ]))
        .expect("bare --libp2p-mainline-rendezvous parses");
        assert_eq!(
            cfg.profile,
            SharingProfile::ConsumeOnly,
            "the Mainline rendezvous is a DHT entry path => consume-only, not upstream-only"
        );
        check_runtime_preconditions(&cfg)
            .expect("consume-only with the rendezvous and no --libp2p-bootstrap must be accepted");
    }

    /// TASK-258: there is NO default public router, so an enabled rendezvous with no local Mainline
    /// bootstrap fails CLOSED. MUTATION: removing the requires-bootstrap check lets it parse.
    #[test]
    fn mainline_rendezvous_requires_local_bootstrap() {
        let Err(err) = parse_config(args(&["--libp2p-mainline-rendezvous"])) else {
            panic!(
                "--libp2p-mainline-rendezvous with no --libp2p-mainline-bootstrap must fail closed"
            );
        };
        assert!(
            err.contains("requires at least one --libp2p-mainline-bootstrap"),
            "the refusal must name the missing local Mainline entry point: {err}"
        );
    }

    /// TASK-258 AC#5: the Mainline rendezvous is PUBLIC-network participation and is REFUSED
    /// fail-closed under lan-share (a give-side zero-egress profile). MUTATION: removing the
    /// LanShare arm of the refusal lets a lan-share node also do public Mainline traffic — the
    /// exact zero-egress violation the Wave-2c contract forbids — and this reddens.
    #[test]
    fn mainline_rendezvous_refused_under_lan_share() {
        let Err(err) = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-mainline-rendezvous",
            "--libp2p-mainline-bootstrap",
            "127.0.0.1:16881",
        ])) else {
            panic!("lan-share + --libp2p-mainline-rendezvous must fail closed");
        };
        assert!(
            err.contains("refused under lan-share") && err.contains("ZERO packets"),
            "the refusal must name the lan-share zero-egress contract: {err}"
        );
    }

    /// TASK-258 AC#5: the explicit contradiction `--profile upstream-only
    /// --libp2p-mainline-rendezvous` fails CLOSED — caught at the compat-shim cross-check (declared
    /// upstream-only != implied consume-only), the same mechanism that guards mDNS.
    #[test]
    fn explicit_upstream_only_plus_mainline_rendezvous_is_refused() {
        let Err(err) = parse_config(args(&[
            "--profile",
            "upstream-only",
            "--libp2p-mainline-rendezvous",
            "--libp2p-mainline-bootstrap",
            "127.0.0.1:16881",
        ])) else {
            panic!("--profile upstream-only + the rendezvous must fail closed");
        };
        assert!(
            err.contains("disagrees") && err.contains("consume-only"),
            "the refusal must name the upstream-only/consume-only disagreement: {err}"
        );
    }

    /// TASK-257: `--libp2p-mdns` is an ENTRY PATH to the DHT, so a consume-only node with mDNS and
    /// NO `--libp2p-bootstrap` is ACCEPTED (the whole point: zero-config LAN discovery). MUTATION:
    /// dropping the `!cfg.libp2p_mdns` relaxation re-imposes the bootstrap requirement and this
    /// reddens. The contract also surfaces mDNS as active with its LAN exposure.
    #[test]
    fn consume_only_with_mdns_needs_no_bootstrap() {
        let cfg = parse_config(args(&["--libp2p-leech", "--libp2p-mdns"]))
            .expect("leech + mdns parses as consume-only");
        assert_eq!(cfg.profile, SharingProfile::ConsumeOnly);
        check_runtime_preconditions(&cfg).expect(
            "a consume-only node with --libp2p-mdns and no --libp2p-bootstrap must be accepted \
             (mDNS is its DHT entry path)",
        );
        let contract = build_contract(&cfg).expect("leech+mdns contract is valid");
        assert!(contract.lan_mdns_enabled, "mDNS must be reported active");
        assert!(
            contract.preflight().contains("EXPOSURE (lan-mdns)"),
            "the LAN mDNS exposure must be surfaced in preflight"
        );
    }

    /// TASK-257 negative control: WITHOUT mDNS (and without a bootstrap), a consume-only node is
    /// still refused - proving the relaxation above is scoped to mDNS, not a blanket drop of the
    /// entry-path requirement.
    #[test]
    fn consume_only_without_mdns_or_bootstrap_still_refused() {
        let cfg =
            parse_config(args(&["--libp2p-leech"])).expect("bare leech parses (consume-only)");
        let err = check_runtime_preconditions(&cfg)
            .expect_err("consume-only with neither bootstrap nor mdns must be refused");
        assert!(
            err.contains("entry path") && err.contains("--libp2p-mdns"),
            "{err}"
        );
    }

    /// TASK-273 (DISCOVERY-ONLY, Option B): a BARE `--profile lan-share` still DERIVES lan-share and
    /// defaults mDNS ON (zero-config DISCOVERY + provider back-fill), but SUPPLY + a listen stay the
    /// operator's EXPLICIT choice — so it FAILS LOUD on the missing supply (the honest "saw your
    /// intent, here's what's missing" path), never silently pretending to serve. Auto-defaulting
    /// supply/listen is deferred to TASK-278. MUTATION: were the reverted AC#5 forcing restored, this
    /// `expect_err` would flip to a start (the silent-serve regression) — the assertions pin both
    /// that NOTHING is forced and that it fails loud.
    #[test]
    fn bare_profile_lan_share_derives_but_fails_loud_on_missing_supply() {
        let cfg = parse_config(args(&["--profile", "lan-share"]))
            .expect("a bare --profile lan-share must still PARSE + derive lan-share");
        assert_eq!(
            cfg.profile,
            SharingProfile::LanShare,
            "an explicit --profile lan-share must derive lan-share, not upstream-only"
        );
        assert!(
            cfg.mdns_active,
            "lan-share still defaults mDNS ON (DISCOVERY is zero-config)"
        );
        assert!(
            cfg.libp2p_listen.is_empty(),
            "no listen is forced (supply/reachability reverted -> TASK-278)"
        );
        assert!(
            !cfg.libp2p_announce_after_fetch,
            "no announce-after-fetch is forced (reverted -> TASK-278)"
        );
        let err = check_runtime_preconditions(&cfg)
            .expect_err("a bare lan-share has nothing to serve -> must fail LOUD, not run dark");
        assert!(
            err.contains("--libp2p-seed-nar") || err.contains("--libp2p-provide-store"),
            "the failure must name the missing supply set: {err}"
        );
    }

    /// TASK-279 AC#3 (parse ordering; NORTH-STAR zero-config combo): the exact argv
    /// `--profile lan-share --libp2p-seed-nar S --libp2p-announce-after-fetch` with NO explicit
    /// `--libp2p-provider` MUST PARSE — the lan-share provider back-fill runs BEFORE the
    /// announce-after-fetch PROVIDER-companion check, so the operator's declared give-side intent is
    /// honoured instead of rejected. It carries the seed leg (S) AND the growing hook.
    ///
    /// MUTATION (restores the ordering bug): move the `explicit_profile == lan-share` back-fill back
    /// to after the `libp2p_announce_after_fetch && !libp2p_provider` check and this `expect` flips to
    /// an Err ("--libp2p-announce-after-fetch requires --libp2p-provider"), because the check would
    /// see `libp2p_provider` still false.
    #[test]
    fn lan_share_seed_plus_announce_after_fetch_parses_without_explicit_provider() {
        let cfg = parse_config(args(&[
            "--profile",
            "lan-share",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-announce-after-fetch",
        ]))
        .expect(
            "the NORTH-STAR combo (lan-share + seed + announce-after-fetch, no explicit provider) \
             must parse: the back-fill precedes the announce-after-fetch companion check",
        );
        assert_eq!(
            cfg.profile,
            SharingProfile::LanShare,
            "the declared lan-share must derive lan-share"
        );
        assert!(
            cfg.libp2p_provider,
            "the lan-share back-fill must set the provider axis (else the companion check rejects it)"
        );
        assert!(
            cfg.libp2p_announce_after_fetch,
            "announce-after-fetch stays on (the growing hook)"
        );
        assert_eq!(
            cfg.libp2p_seed_nar.len(),
            1,
            "the seed leg S is carried through"
        );
    }

    /// TASK-273 ORDERING TRAP: the profile-DERIVATION must consume only the RAW mDNS opt-in, never
    /// the profile-defaulted resolved value. A bare `--libp2p-mdns` still derives CONSUME-ONLY (mDNS
    /// is a consumer's DHT entry path), and a bare `--profile lan-share` (which defaults mdns_active
    /// ON) does NOT let that default feed back to spuriously re-derive the profile — it stays
    /// lan-share via the explicit declaration + provider back-fill, not via has_bootstrap.
    #[test]
    fn mdns_default_does_not_feed_back_into_derivation() {
        // Raw opt-in => consume-only (entry-path inference fires on Some(true)).
        let raw = parse_config(args(&["--libp2p-mdns"])).expect("bare --libp2p-mdns parses");
        assert_eq!(raw.profile, SharingProfile::ConsumeOnly);
        assert_eq!(raw.libp2p_mdns, Some(true), "the raw opt-in is preserved");
        // Profile-defaulted mDNS (lan-share) is NOT a raw opt-in: the raw field stays None even
        // though the resolved mdns_active is true.
        let lan = parse_config(args(&["--profile", "lan-share"])).expect("bare lan-share parses");
        assert_eq!(lan.profile, SharingProfile::LanShare);
        assert_eq!(
            lan.libp2p_mdns, None,
            "lan-share's mDNS default must NOT masquerade as a raw opt-in (would be circular)"
        );
        assert!(lan.mdns_active, "but the RESOLVED value is on");
    }

    /// TASK-273 AC#1 (guard #2/#5): a no-path LAN-SHARE provider (mDNS off, no bootstrap, no
    /// provider-addr) has NO way to be discovered and MUST fail loud — and the remedy names mDNS as
    /// its ONLY entry (bootstrap/provider-addr are refused by the isolated-LAN stopgap for a
    /// no-allowlist lan-share, so suggesting them would be false advice). It carries a supply + a
    /// listen so it reaches the discoverability guard (past the nothing-to-serve/no-listen guards).
    #[test]
    fn lan_share_no_discovery_path_fails_loud_naming_mdns_only() {
        let cfg = parse_config(args(&[
            "--profile",
            "lan-share",
            "--libp2p-no-mdns",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
        ]))
        .expect("--profile lan-share --libp2p-no-mdns + supply + listen parses");
        assert!(
            !cfg.mdns_active,
            "--libp2p-no-mdns must turn the default OFF"
        );
        let err = check_runtime_preconditions(&cfg)
            .expect_err("an undiscoverable lan-share provider must be refused");
        assert!(
            err.contains("no way to be discovered") && err.contains("mDNS is its ONLY entry path"),
            "the lan-share remedy must name mDNS as the only entry path (no false bootstrap advice): {err}"
        );
    }

    /// TASK-273 AC#1 (guard #2): a self-advertised `--libp2p-external-address` is NOT a Kad entry
    /// path (it only propagates identify metadata AFTER a connection, never dialing or seeding Kad),
    /// so a provider whose ONLY reachability signal is an external-address must still be refused. Uses
    /// PUBLIC-SHARE because a lan-share with an external-address is rejected earlier at derive
    /// (PublicAddressWithoutAllowlist). MUTATION: adding `external_addresses` back to `discoverable`
    /// makes this node PERMITTED (the guard stops biting) — proving the exclusion is load-bearing.
    #[test]
    fn external_address_only_provider_is_refused() {
        let cfg = parse_config(args(&[
            "--profile",
            "public-share",
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/0.0.0.0/tcp/0",
            "--libp2p-external-address",
            "/ip4/203.0.113.7/tcp/4001",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-public-allowlist-path",
            "/tmp/nix-p2p-allowlist",
            "--libp2p-trusted-public-key",
            FIXTURE_PUBKEY,
        ]))
        .expect("public-share with an external-address (allowlist door) parses");
        assert_eq!(cfg.profile, SharingProfile::PublicShare);
        assert!(!cfg.mdns_active);
        let err = check_runtime_preconditions(&cfg)
            .expect_err("external-address is NOT an entry path -> provider must be refused");
        assert!(
            err.contains("no way to be discovered")
                && err.contains("--libp2p-external-address is NOT"),
            "the public-share remedy must state external-address is not an entry path: {err}"
        );
    }

    /// TASK-273 AC#1 (guard #5): the undiscoverable-provider guard is SATISFIED by a real Kad entry
    /// hint. A PUBLIC-SHARE provider with a `--libp2p-provider-addr` (a dial hint `add_address`'d into
    /// Kad) and no mDNS is discoverable, so it must PASS — proving the guard is scoped to "no real
    /// entry at all", not a blanket mDNS requirement, and that provider-addr counts while
    /// external-address does not.
    #[test]
    fn provider_addr_only_public_share_is_permitted() {
        let cfg = parse_config(args(&[
            "--profile",
            "public-share",
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/0.0.0.0/tcp/0",
            "--libp2p-provider-addr",
            "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN@/ip4/127.0.0.1/tcp/4001",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-public-allowlist-path",
            "/tmp/nix-p2p-allowlist",
            "--libp2p-trusted-public-key",
            FIXTURE_PUBKEY,
        ]))
        .expect("public-share + provider-addr parses");
        assert_eq!(cfg.profile, SharingProfile::PublicShare);
        assert!(!cfg.mdns_active);
        check_runtime_preconditions(&cfg)
            .expect("a provider-addr dial hint IS a Kad entry path -> must pass");
    }

    /// TASK-273 (#8): `--libp2p-mdns` and `--libp2p-no-mdns` are contradictory — passing both (either
    /// order) fails closed rather than silently last-wins.
    #[test]
    fn contradictory_mdns_flags_fail_closed() {
        let Err(err) = parse_config(args(&["--libp2p-mdns", "--libp2p-no-mdns"])) else {
            panic!("--libp2p-mdns then --libp2p-no-mdns must fail closed");
        };
        assert!(err.contains("exactly one"), "{err}");
        let Err(err2) = parse_config(args(&["--libp2p-no-mdns", "--libp2p-mdns"])) else {
            panic!("--libp2p-no-mdns then --libp2p-mdns must fail closed");
        };
        assert!(err2.contains("exactly one"), "{err2}");
    }

    /// TASK-278: `--libp2p-seed-nar` + `--libp2p-announce-after-fetch` is now a VALID additive
    /// provider (seed leg + growth store leg from ONE fabric). The old interim fail-closed is gone;
    /// `install_provider` unions the two. MUTATION: reinstating the interim guard makes this parse RED.
    #[test]
    fn seed_nar_with_announce_after_fetch_is_accepted_as_additive() {
        let cfg = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-mdns",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-announce-after-fetch",
        ]))
        .expect("--libp2p-seed-nar + --libp2p-announce-after-fetch is a valid additive provider");
        assert_eq!(
            cfg.libp2p_seed_nar.len(),
            1,
            "the seed is retained, not dropped"
        );
        assert!(
            cfg.libp2p_announce_after_fetch,
            "announce-after-fetch stays on alongside the seed"
        );
    }

    /// TASK-278 #3: the SAME NarHash as both a --libp2p-seed-nar AND a --libp2p-provide-store is
    /// rejected fail-loud (a provider serves + announces each NarHash exactly once). MUTATION: delete
    /// the dedup guard -> parses Ok and the report counts 2 while the supplier answers one digest.
    #[test]
    fn duplicate_narhash_across_seed_and_store_is_rejected() {
        let Err(err) = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-mdns",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-provide-store",
            &format!("{APP_NAR_HASH}=/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-app"),
        ])) else {
            panic!("a NarHash appearing as both a seed and a store path must be rejected");
        };
        assert!(
            err.contains(APP_NAR_HASH) && err.contains("more than once"),
            "the refusal must name the duplicated NarHash: {err}"
        );
    }

    /// TASK-278 #4: announce-after-fetch with a ZERO growth budget is rejected (it would grow nothing
    /// while the report claims "grows on demand"). MUTATION: remove the guard -> parses and the
    /// report's "grows on demand" clause is falsified with remaining==0.
    #[test]
    fn announce_after_fetch_with_zero_growth_budget_is_rejected() {
        let Err(err) = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-mdns",
            "--libp2p-announce-after-fetch",
            "--libp2p-announce-budget",
            "0",
        ])) else {
            panic!("announce-after-fetch with a zero growth budget must be rejected");
        };
        assert!(
            err.contains("grows nothing") && err.contains("--libp2p-announce-budget 0"),
            "the refusal must name the zero growth budget: {err}"
        );
    }

    /// TASK-278 #4 precision: a STATIC-only provider (no announce-after-fetch) with
    /// --libp2p-announce-budget 0 is NOT caught - the growth-budget guard keys off the hook, and a
    /// static seed/provision announce uses a separate rate limiter.
    #[test]
    fn static_provider_with_zero_announce_budget_is_accepted() {
        parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-mdns",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-announce-budget",
            "0",
        ]))
        .expect(
            "a static-only provider with announce-budget 0 is valid (growth guard must not fire)",
        );
    }

    /// AC#7 + fix #3: `--preflight` renders the INTENDED profile with NO network-precondition
    /// demanded (a bare `--preflight` shows the upstream-only preflight - no bootstrap needed).
    #[test]
    fn preflight_needs_no_network_precondition() {
        let cfg = parse_config(args(&["--preflight"])).expect("bare --preflight parses");
        assert!(cfg.preflight);
        assert_eq!(cfg.profile, SharingProfile::UpstreamOnly);
        let p = build_contract(&cfg).unwrap().preflight();
        assert!(p.contains("iroh-transport = PENDING"));
        assert!(p.contains("max_nar_bytes_uncompressed=268435456"));
        // TASK-120 AC#10: the frozen profile-budget artifact is surfaced + verified in preflight.
        assert!(p.contains("frozen profile-budget artifact"));
        assert!(p.contains("serves_bytes: false"));
    }
}

#[cfg(test)]
mod nat_flags_tests {
    //! TASK-207: `--libp2p-listen` is REPEATABLE and `--libp2p-external-address` is NEW - the two
    //! additive knobs that let the shipped binary drive the relay circuit-v2 path (a provider binds
    //! a real transport AND a `/…/p2p-circuit` reservation; a relay advertises its public address so
    //! reservation vouchers are not empty). These drive the binary's OWN `parse_config`, so a
    //! regression in the repeatable-listen or external-address wiring is caught here.
    use super::{parse_config, source_config};
    use daemon_core::SharingProfile;

    const APP_NAR_HASH: &str = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";
    const FIXTURE_PUBKEY: &str = "nix-p2p-test-1:empdFBu9wVZG12rPKToHMOTsU1qzWzeCcLdq/KQH0JQ=";
    const RELAY_ID: &str = "12D3KooWBr7cTGxmMhdiGNcbesEusWMR1VG26jEQQgFr6wwZkNNf";

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    /// A NAT'd provider binds TWO listens: a direct transport bind AND a relay `/p2p-circuit`
    /// reservation address. Both must be retained IN ORDER and passed through shared construction.
    #[test]
    fn libp2p_listen_is_repeatable_and_ordered() {
        let circuit = format!("/ip4/10.0.0.1/tcp/4001/p2p/{RELAY_ID}/p2p-circuit");
        let cfg = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/192.168.2.3/tcp/4001",
            "--libp2p-listen",
            &circuit,
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-public-allowlist-path",
            "/tmp/nix-p2p-allowlist",
            "--libp2p-trusted-public-key",
            FIXTURE_PUBKEY,
        ]))
        .expect("a provider with two --libp2p-listen addresses parses");
        assert_eq!(cfg.libp2p_listen.len(), 2, "both listens retained");
        assert_eq!(
            cfg.libp2p_listen[0].to_string(),
            "/ip4/192.168.2.3/tcp/4001",
            "the direct transport bind is first"
        );
        assert!(
            cfg.libp2p_listen[1].to_string().contains("p2p-circuit"),
            "the circuit reservation address is second: {}",
            cfg.libp2p_listen[1]
        );

        let shared = source_config(&cfg, SharingProfile::LanShare, [9u8; 32], true);
        assert_eq!(
            shared.listen.as_ref(),
            cfg.libp2p_listen.first(),
            "the first listen reaches shared startup configuration"
        );
        assert_eq!(
            shared.additional_listens,
            cfg.libp2p_listen[1..],
            "every remaining listen reaches shared startup configuration in order"
        );
    }

    /// A relay/bootstrap node (a consumer-shaped node) advertises its public address via
    /// `--libp2p-external-address`; repeatable, and it parses into the external-address vec.
    #[test]
    fn external_address_is_repeatable_on_a_consumer() {
        let cfg = parse_config(args(&[
            "--libp2p-bootstrap",
            &format!("{RELAY_ID}@/ip4/10.0.0.9/tcp/1"),
            "--libp2p-listen",
            "/ip4/192.168.1.5/tcp/4001",
            "--libp2p-external-address",
            "/ip4/192.168.1.5/tcp/4001",
        ]))
        .expect("a consumer/relay with an external address parses");
        assert_eq!(cfg.libp2p_external_addresses.len(), 1);
        assert_eq!(
            cfg.libp2p_external_addresses[0].to_string(),
            "/ip4/192.168.1.5/tcp/4001"
        );

        let shared = source_config(&cfg, SharingProfile::ConsumeOnly, [10u8; 32], false);
        assert_eq!(
            shared.external_addresses, cfg.libp2p_external_addresses,
            "external addresses reach shared startup configuration"
        );
    }

    /// TASK-207 B2: the relay SERVER is ON by default (a public node helps NAT'd peers) and
    /// `--libp2p-no-relay-server` turns it OFF for a kad-only node (a dedicated bootstrap that
    /// offers NO reservation service, so it can never be an ALTERNATIVE relay). The bite: drop the
    /// flag wiring and a kad-only node silently keeps serving reservations.
    #[test]
    fn relay_server_defaults_on_and_no_relay_server_disables_it() {
        let bootstrap = format!("{RELAY_ID}@/ip4/10.0.0.9/tcp/1");
        let base: [&str; 4] = [
            "--libp2p-bootstrap",
            &bootstrap,
            "--libp2p-listen",
            "/ip4/192.168.1.6/tcp/4001",
        ];
        let on =
            parse_config(args(&base)).expect("a kad node with the relay server default parses");
        assert!(
            on.libp2p_relay_server_enabled,
            "the relay server is ON by default"
        );
        let mut off_args: Vec<&str> = base.to_vec();
        off_args.push("--libp2p-no-relay-server");
        let off = parse_config(args(&off_args))
            .expect("a kad-only node with --libp2p-no-relay-server parses");
        assert!(
            !off.libp2p_relay_server_enabled,
            "--libp2p-no-relay-server disables the relay server"
        );
    }

    /// Fail-closed: an external address on a provider WITHOUT the public-allowlist door is refused
    /// (it would advertise a public self-address for an isolated-LAN announce). The bite: drop the
    /// validation and this config is silently accepted.
    #[test]
    fn external_address_on_a_provider_without_allowlist_is_refused() {
        let Err(err) = parse_config(args(&[
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
            "--libp2p-external-address",
            "/ip4/1.2.3.4/tcp/4001",
        ])) else {
            panic!("an external address on an isolated-LAN provider must be refused");
        };
        assert!(
            err.contains("--libp2p-external-address")
                && err.contains("--libp2p-public-allowlist-path"),
            "the refusal must name the external-address flag and require the allowlist door: {err}"
        );
    }

    /// A bad multiaddr on either new flag fails fast (never a silently-ignored knob).
    #[test]
    fn bad_external_address_multiaddr_fails_fast() {
        let Err(err) = parse_config(args(&[
            "--libp2p-bootstrap",
            &format!("{RELAY_ID}@/ip4/10.0.0.9/tcp/1"),
            "--libp2p-external-address",
            "not-a-multiaddr",
        ])) else {
            panic!("a malformed --libp2p-external-address must be refused");
        };
        assert!(
            err.contains("--libp2p-external-address"),
            "the parse error must name the flag: {err}"
        );
    }
}

#[cfg(test)]
mod leech_flag_tests {
    //! TASK-78: `--libp2p-leech` is an affirmative consume-only opt-out. A leech is a CONSUMER
    //! (it still needs a bootstrap) whose fabric is wrapped in `peer_fabric::LeechFabric` so the
    //! serve and announce axes are masked at the seam. These drive the binary's OWN `parse_config`,
    //! so the fail-fast mutual-exclusion with every give-side flag is caught here (a dropped check
    //! would silently accept "a leech that also serves", which is exactly the lie the flag forbids).
    use super::{check_runtime_preconditions, parse_config};

    const APP_NAR_HASH: &str = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";
    const FIXTURE_PUBKEY: &str = "nix-p2p-test-1:empdFBu9wVZG12rPKToHMOTsU1qzWzeCcLdq/KQH0JQ=";
    const BOOT: &str =
        "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN@/ip4/127.0.0.1/tcp/4001";

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    /// A leech consumer parses: it carries a bootstrap (a consumer must) and `libp2p_leech` is set.
    #[test]
    fn a_leech_consumer_parses() {
        let cfg = parse_config(args(&["--libp2p-leech", "--libp2p-bootstrap", BOOT]))
            .expect("a leech consumer with a bootstrap parses");
        assert!(cfg.libp2p_leech, "the leech flag is recorded");
        assert!(!cfg.libp2p_provider, "a leech is not a provider");
    }

    /// A leech (consume-only) still needs a bootstrap - it fetches from peers. TASK-120 moved this
    /// NETWORK-PRECONDITION out of `parse_config` (so `--preflight` can render without it) into
    /// `check_runtime_preconditions`, keyed off the consume-only profile.
    #[test]
    fn a_leech_without_a_bootstrap_is_refused() {
        let cfg = parse_config(args(&["--libp2p-leech"])).expect(
            "a bootstrap-less leech PARSES (upstream-only exempt; consume-only checked at runtime)",
        );
        let err = check_runtime_preconditions(&cfg)
            .expect_err("a consume-only leech with no bootstrap must be refused at runtime");
        assert!(
            err.contains("--libp2p-bootstrap"),
            "the refusal must require a bootstrap: {err}"
        );
    }

    /// `--libp2p-leech` + `--libp2p-provider` is contradictory (a leech gives nothing back).
    #[test]
    fn leech_with_provider_is_refused() {
        let Err(err) = parse_config(args(&[
            "--libp2p-leech",
            "--libp2p-provider",
            "--libp2p-listen",
            "/ip4/127.0.0.1/tcp/0",
            "--libp2p-seed-nar",
            &format!("{APP_NAR_HASH}=/tmp/app.nar"),
        ])) else {
            panic!("a leech that is also a provider must be refused");
        };
        assert!(
            err.contains("--libp2p-leech") && err.contains("--libp2p-provider"),
            "the refusal must name both conflicting flags: {err}"
        );
    }

    /// `--libp2p-leech` + `--libp2p-announce-after-fetch` is contradictory (announcing is giving).
    #[test]
    fn leech_with_announce_after_fetch_is_refused() {
        let Err(err) = parse_config(args(&[
            "--libp2p-leech",
            "--libp2p-bootstrap",
            BOOT,
            "--libp2p-announce-after-fetch",
        ])) else {
            panic!("a leech that announces-after-fetch must be refused");
        };
        assert!(
            err.contains("--libp2p-leech") && err.contains("--libp2p-announce-after-fetch"),
            "the refusal must name both conflicting flags: {err}"
        );
    }

    /// `--libp2p-leech` + a give-side supply/allowlist flag is contradictory. The leech check runs
    /// BEFORE the provider-companion validation, so it names the leech conflict specifically. Each
    /// flag value is PARSE-VALID (a bad narhash would error earlier), so the loop reaches the check.
    #[test]
    fn leech_with_a_give_side_flag_is_refused() {
        let seed = format!("{APP_NAR_HASH}=/tmp/app.nar");
        let store = format!("{APP_NAR_HASH}=/nix/store/p");
        let cases: [(&str, &str); 4] = [
            ("--libp2p-seed-nar", seed.as_str()),
            ("--libp2p-provide-store", store.as_str()),
            ("--libp2p-public-allowlist-path", "/tmp/allow"),
            ("--libp2p-trusted-public-key", FIXTURE_PUBKEY),
        ];
        for (flag, value) in cases {
            let Err(err) = parse_config(args(&[
                "--libp2p-leech",
                "--libp2p-bootstrap",
                BOOT,
                flag,
                value,
            ])) else {
                panic!("a leech with {flag} must be refused");
            };
            assert!(
                err.contains("--libp2p-leech") && err.contains(flag),
                "the refusal must name the leech conflict with {flag}: {err}"
            );
        }
    }
}

#[cfg(test)]
mod additive_supply_tests {
    //! TASK-278 AC#3 (unit, biting): `build_provider_supply` UNIONS the in-memory seed leg with the
    //! store-supply leg, so a provider passing `--libp2p-seed-nar S` + `--libp2p-provide-store P` +
    //! `--libp2p-announce-after-fetch` serves BOTH S's and P's content digest and reports both
    //! counts honestly.
    //!
    //! MUTATION (proves the fix is load-bearing): restore the pre-278 mode-select in
    //! `build_provider_supply` (build the store leg XOR the seed leg on `announce_after_fetch`)
    //! and the `plan(S)` assertion goes RED - the seed is silently dropped, exactly finding #1.
    use super::{Config, build_provider_supply, provider_serve_budget};
    use daemon_core::content_id::Blake3Digest;
    use daemon_core::{NarDumper, NarHashKey, NodeId, RegularFileNarDumper, SharingProfile};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn unique_temp(stem: &str) -> PathBuf {
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(format!("nix-p2p-task278-{stem}-{suffix}"))
    }

    /// A PROVIDER config carrying the seed + provide-store + announce-after-fetch fields under test;
    /// every other field is an immaterial safe default (`build_provider_supply` reads only the three
    /// supply fields).
    fn supply_cfg(
        seed_nar: Vec<(NarHashKey, String)>,
        provide_store: Vec<(NarHashKey, String)>,
        announce_after_fetch: bool,
    ) -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream: "https://cache.nixos.org".to_string(),
            header_timeout_ms: 30_000,
            narinfo_cache_dir: None,
            no_narinfo_cache: false,
            store_dir: "/nix/store".to_string(),
            priority: 0,
            want_mass_query: true,
            libp2p_bootstrap: Vec::new(),
            libp2p_provider_addrs: Vec::new(),
            libp2p_listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            libp2p_external_addresses: Vec::new(),
            libp2p_scope: None,
            libp2p_mdns: None,
            mdns_active: false,
            libp2p_mainline_rendezvous: false,
            libp2p_mainline_bootstrap: Vec::new(),
            libp2p_identity_seed: None,
            libp2p_provider: true,
            libp2p_seed_nar: seed_nar,
            libp2p_provide_store: provide_store,
            libp2p_print_peer_address: false,
            libp2p_state_dir: None,
            libp2p_trusted_public_keys: Vec::new(),
            libp2p_public_allowlist_path: None,
            libp2p_prove_public_narinfo: Vec::new(),
            libp2p_relay_server_enabled: true,
            libp2p_announce_after_fetch: announce_after_fetch,
            libp2p_announce_budget: crate::default_libp2p_announce_budget(),
            libp2p_record_ttl_secs: crate::DEFAULT_LIBP2P_RECORD_TTL_SECS,
            libp2p_leech: false,
            libp2p_router: false,
            preflight: false,
            diagnostics: false,
            explicit_profile: None,
            status_listen: None,
            profile: SharingProfile::LanShare,
        }
    }

    /// AC#1/AC#3: seed S + provide-store P + announce-after-fetch builds a UNION whose `plan` answers
    /// for BOTH content digests, the store index exists (so the growth hook can register), and the
    /// report counts both legs.
    #[test]
    fn union_serves_seed_and_store_and_reports_both() {
        // Distinct bytes -> distinct content digests, so plan(P) can only be answered by the STORE
        // leg (never smuggled by the seed leg).
        let seed_bytes = b"nix-archive-1 SEED nar bytes for TASK-278 union".to_vec();
        let store_bytes = b"nix-archive-1 STORE nar bytes for TASK-278 union".to_vec();
        let seed_content = Blake3Digest::from_raw_nar(&seed_bytes);
        let store_content = Blake3Digest::from_raw_nar(&store_bytes);
        let seed_key = NarHashKey::from_raw_nar(&seed_bytes);
        let store_key = NarHashKey::from_raw_nar(&store_bytes);

        let seed_path = unique_temp("seed.nar");
        let store_path = unique_temp("store.nar");
        std::fs::write(&seed_path, &seed_bytes).unwrap();
        std::fs::write(&store_path, &store_bytes).unwrap();

        let cfg = supply_cfg(
            vec![(seed_key, seed_path.to_string_lossy().into_owned())],
            vec![(store_key, store_path.to_string_lossy().into_owned())],
            true,
        );
        let serve_budget = provider_serve_budget();
        // RegularFileNarDumper lets verify_store_provisions run a real dump+verify WITHOUT a
        // /nix/store (the store-dump analogue used across the daemon-side unit tests).
        let supply = build_provider_supply(
            &cfg,
            &serve_budget,
            Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
            NodeId::from_bytes([0u8; 32]),
        )
        .expect("additive supply builds from seed + provide-store + announce-after-fetch");

        // The union answers for the SEED content (would be None under the pre-278 mode-select).
        assert!(
            supply.supplier.plan(&seed_content).is_some(),
            "the union must serve the seeded NAR S (mode-select would DROP it)"
        );
        // ...and for the STORE content, from the verified provide-store leg.
        assert!(
            supply.supplier.plan(&store_content).is_some(),
            "the union must serve the provide-store path P from the store leg"
        );
        // A digest neither seeded nor provided is not servable (no enumeration/over-answer).
        let unknown = Blake3Digest::from_raw_nar(b"never seeded, never provided");
        assert!(supply.supplier.plan(&unknown).is_none());

        assert_eq!(supply.seeds.len(), 1, "the seed leg was built");
        assert_eq!(supply.provisions.len(), 1, "the store leg verified P");
        assert!(
            supply.index.is_some(),
            "announce-after-fetch requires the store index to exist for growth"
        );
        assert!(
            supply.report.contains("1 seeded NAR(s)")
                && supply.report.contains("1 /nix/store path(s)")
                && supply.report.contains("announce-after-fetch"),
            "the startup report must count BOTH legs and the growth hook, no false count: {}",
            supply.report
        );

        let _ = std::fs::remove_file(&seed_path);
        let _ = std::fs::remove_file(&store_path);
    }

    /// Seed S + announce-after-fetch WITHOUT a provide-store set is the zero-config growth case: the
    /// seed leg serves S, and the store leg exists (empty) so the hook can register fetched paths.
    /// This is the exact combo the old interim fail-closed refused.
    #[test]
    fn seed_plus_announce_after_fetch_serves_the_seed_and_opens_the_growth_index() {
        let seed_bytes = b"nix-archive-1 seed for the announce-after-fetch growth case".to_vec();
        let seed_content = Blake3Digest::from_raw_nar(&seed_bytes);
        let seed_key = NarHashKey::from_raw_nar(&seed_bytes);
        let seed_path = unique_temp("seed-grow.nar");
        std::fs::write(&seed_path, &seed_bytes).unwrap();

        let cfg = supply_cfg(
            vec![(seed_key, seed_path.to_string_lossy().into_owned())],
            Vec::new(),
            true,
        );
        let serve_budget = provider_serve_budget();
        let supply = build_provider_supply(
            &cfg,
            &serve_budget,
            Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
            NodeId::from_bytes([0u8; 32]),
        )
        .expect("seed + announce-after-fetch is a valid additive provider");

        assert!(
            supply.supplier.plan(&seed_content).is_some(),
            "the seed must be served even with announce-after-fetch (finding #1 regression)"
        );
        assert!(
            supply.index.is_some(),
            "announce-after-fetch opens the growth index even with an empty initial provide set"
        );
        assert_eq!(supply.provisions.len(), 0, "no static provide-store paths");
        assert!(
            supply.report.contains("1 seeded NAR(s)")
                && supply.report.contains("0 /nix/store path(s)")
                && supply.report.contains("announce-after-fetch"),
            "report: {}",
            supply.report
        );

        let _ = std::fs::remove_file(&seed_path);
    }
}
