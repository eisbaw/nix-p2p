//! nix-p2p product daemon - binary entrypoint.
//!
//! A thin wrapper over the `daemon` library: parse flags, wire the single
//! `UpstreamHttp` behind all three upstream traits, and serve. All behaviour
//! lives in the library so the integration tests drive the exact same stack.
//!
//! The near-identical `banner()` in `testproxy` is deliberate duplication, not
//! an oversight (task-1 note): factoring it into a shared crate is exactly the
//! coupling the PRD forbids until a second consumer genuinely earns it.

use std::future::pending;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;

use daemon::cacheinfo::DEFAULT_PRIORITY;
use daemon::claim::CLAIM_SCHEMA_VERSION;
use daemon::{
    AddressLookupCapability, AllowlistRawServe, AnyRawServe, App, Blake3Digest, CacheInfo, Claim,
    CorrelationStore, DEFAULT_MAX_INFLIGHT_NAR_BYTES, DEFAULT_MAX_SERVE_DURATION,
    DEFAULT_MAX_SERVE_NAR_BYTES, EndpointProfile, EndpointScope, FallbackNarSource,
    FileNarSupplier, IdentitySource, InMemoryDiscovery, IrohNode, IrohNodeBuilder, IrohPeerAddr,
    IrohProviderConfig, IrohTransport, KnownPayload, KnownTransport, Libp2pSourceConfig,
    NarCatalog, NarHashKey, NarSource, NarinfoDiskCache, NarinfoSource, NoRawServe, NodeId,
    NodeLocation, NodeLookupAuthorityAuthorization, NodeLookupConfig, NodePublicationCapability,
    NodePublicationConfig, NodePublicationHandle, NullCorrelation,
    PublicationAuthorityAuthorization, RawServeDecision, RelayCapability, ServeBudget, SystemClock,
    TaskSupervisor, TransportNarSource, TransportRegistry, UpstreamHttp, announce_provider_seeds,
    build_libp2p_nar_source, build_libp2p_provider_source, resolve_durable_identity_seed, serve,
};
use fabric_libp2p::{Libp2pFabric, MemoryNarSupplier, Multiaddr, PeerId};
use peer_fabric::{AnnounceBudget, PeerFabric, ServeHandle};
use tokio::net::TcpListener;

/// A configured peer's iroh address: its `NodeId` and one-or-more direct sockets
/// the daemon can dial it on. In the wave-2a container topology the harness reads
/// node B's `IROH-PROVIDER-ADDR` line and passes it here via `--iroh-peer`; a real
/// discovery/DHT (task-47) replaces this configured resolution.
#[derive(Debug, Clone)]
struct PeerSpec {
    node: NodeId,
    sockets: Vec<SocketAddr>,
}

/// A configured p2p claim: "this signed `NarHash` is held by `node` as the raw NAR
/// whose content id is `blake3`". Seeds the daemon's discovery AND its raw-serve
/// allowlist from ONE datum, so the two can never drift (a `will_serve_raw(true)`
/// always has a claim - hence a raw NAR source - behind it). The harness builds it
/// from node B's `IROH-SEED` line (blake3) + the fixture manifest (NarHash).
#[derive(Debug, Clone)]
struct ClaimSpec {
    /// The full signed NarHash string, `sha256:<base32>` (the exact form the
    /// narinfo carries and [`daemon::catalog::parse_correlation`] emits). KEPT as
    /// the original string for the raw-serve allowlist, so allowlist matching is
    /// byte-equal to what the narinfo carries (no re-encode round-trip risk).
    nar_hash: String,
    /// The SAME NarHash canonicalised once at parse time, for the discovery claim.
    /// Parsing here (not again at wiring) is the single canonicalisation.
    key: NarHashKey,
    blake3: Blake3Digest,
    node: NodeId,
}

/// Parse `--iroh-peer <nodeid_hex>@<socket>[,<socket>...]`.
fn parse_peer_spec(raw: &str) -> Result<PeerSpec, String> {
    let (node_hex, sockets_csv) = raw
        .split_once('@')
        .ok_or_else(|| format!("bad --iroh-peer {raw:?}: expected <nodeid_hex>@<socket>[,...]"))?;
    let node: NodeId = node_hex
        .parse()
        .map_err(|e| format!("bad --iroh-peer node id {node_hex:?}: {e}"))?;
    let mut sockets = Vec::new();
    for s in sockets_csv.split(',').filter(|s| !s.is_empty()) {
        sockets.push(
            s.parse::<SocketAddr>()
                .map_err(|e| format!("bad --iroh-peer socket {s:?}: {e}"))?,
        );
    }
    if sockets.is_empty() {
        return Err(format!("bad --iroh-peer {raw:?}: no sockets after '@'"));
    }
    Ok(PeerSpec { node, sockets })
}

/// Parse `--p2p-claim <narhash>=<blake3_hex>@<nodeid_hex>`. `<narhash>` is the full
/// `sha256:<base32>` NarHash; `<blake3_hex>` is the 64-hex raw-NAR content id.
fn parse_claim_spec(raw: &str) -> Result<ClaimSpec, String> {
    let (nar_hash, rest) = raw.split_once('=').ok_or_else(|| {
        format!("bad --p2p-claim {raw:?}: expected <narhash>=<blake3hex>@<nodeid>")
    })?;
    let (blake3_hex, node_hex) = rest.split_once('@').ok_or_else(|| {
        format!("bad --p2p-claim {raw:?}: expected <narhash>=<blake3hex>@<nodeid>")
    })?;
    // Canonicalise the NarHash ONCE, here (fail fast at config time, not at the
    // first request); the allowlist still keys on the original string form.
    let key = NarHashKey::from_str(nar_hash)
        .map_err(|e| format!("bad --p2p-claim NarHash {nar_hash:?}: {e}"))?;
    let blake3: Blake3Digest = format!("blake3:{blake3_hex}")
        .parse()
        .map_err(|e| format!("bad --p2p-claim blake3 {blake3_hex:?}: {e}"))?;
    let node: NodeId = node_hex
        .parse()
        .map_err(|e| format!("bad --p2p-claim node id {node_hex:?}: {e}"))?;
    Ok(ClaimSpec {
        nar_hash: nar_hash.to_string(),
        key,
        blake3,
        node,
    })
}

/// Parse a libp2p `<PeerId>@<multiaddr>` pair, used by both `--libp2p-bootstrap`
/// (a REQUIRED kad entry peer) and `--libp2p-provider-addr` (an OPTIONAL provider
/// dial-address override hint, TASK-169). The production path no longer needs the latter:
/// the daemon resolves a discovered provider's dial address THROUGH kad peer-routing
/// (`Libp2pFabric::node_locator()`, TASK-159), so both the discovery and the dial legs are
/// injection-free. `--libp2p-provider-addr` only seeds an explicit out-of-band override
/// (e.g. reach a peer the DHT has not yet propagated); it is not required to dial.
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

/// Parse a 32-byte libp2p identity seed as exactly 64 lowercase/uppercase hex chars.
/// The seed is the node's ed25519 identity material; a fixed default is deliberately
/// NOT provided (two consumers sharing an identity is a footgun) - when absent the
/// composition root generates a fresh one from `/dev/urandom`.
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

/// Parse a `--libp2p-seed-nar <narhash>=<path>` pair: the Nix `NarHash` (canonical
/// `sha256:<nix-base32>`) of a raw NAR and the FILE holding those raw NAR bytes. The
/// NarHash is REQUIRED because the discovery [`ContentKey`](peer_fabric::ContentKey) a
/// consumer derives from a narinfo is
/// `ContentKey::derive_from_signed_nar_hash(NarHash)`; the provider must ANNOUNCE under
/// that same key, and the raw file's own `BLAKE3` content id is a DIFFERENT axis (it
/// keys the transfer/serve, not discovery). So both halves are needed and neither is
/// derivable from the other.
fn parse_libp2p_seed_nar(raw: &str) -> Result<(NarHashKey, String), String> {
    let (nar_hash, path) = raw.split_once('=').ok_or_else(|| {
        format!("bad --libp2p-seed-nar {raw:?}: expected <narhash>=<path/to/raw.nar>")
    })?;
    let key: NarHashKey = nar_hash
        .parse()
        .map_err(|e| format!("bad --libp2p-seed-nar NarHash {nar_hash:?}: {e}"))?;
    if path.is_empty() {
        return Err(format!("bad --libp2p-seed-nar {raw:?}: empty file path"));
    }
    Ok((key, path.to_string()))
}

/// Parse a byte/millisecond budget that must be POSITIVE.
///
/// Zero is rejected for the same reason `--header-timeout-ms 0` is: a zero serve
/// budget declines every peer, and a zero sweep interval spins the collector - both
/// are daemons that look healthy and do nothing. There is deliberately NO
/// "unlimited" spelling: an operator who wants no practical bound writes a large
/// number, and has then written the number they chose.
fn parse_positive_u64(flag: &str, raw: &str) -> Result<u64, String> {
    let value: u64 = raw
        .parse()
        .map_err(|e| format!("bad {flag} {raw:?}: {e}"))?;
    if value == 0 {
        return Err(format!("bad {flag} 0: must be positive"));
    }
    Ok(value)
}

/// Parse the lower-level bind scope. This selects sockets only; it never turns
/// on relay or address lookup. Public discovery/participation remains owned by
/// later capability tasks.
fn parse_iroh_endpoint_scope(raw: &str) -> Result<EndpointScope, String> {
    match raw {
        "offline-test" => Ok(EndpointScope::OfflineTest { port: 0 }),
        "global" => Ok(EndpointScope::Global { port: 0 }),
        _ => {
            let addresses = raw.strip_prefix("lan:").ok_or_else(|| {
                format!(
                    "bad --iroh-endpoint-scope {raw:?}: expected offline-test, global, or lan:<ipv4>[,<ipv6>]"
                )
            })?;
            let mut parts = addresses.split(',');
            let ipv4 = parts
                .next()
                .filter(|part| !part.is_empty())
                .ok_or_else(|| format!("bad LAN scope {raw:?}: missing IPv4 address"))?
                .parse::<Ipv4Addr>()
                .map_err(|error| format!("bad LAN IPv4 in {raw:?}: {error}"))?;
            let ipv6 = parts
                .next()
                .filter(|part| !part.is_empty())
                .map(|part| {
                    part.parse::<Ipv6Addr>()
                        .map_err(|error| format!("bad LAN IPv6 in {raw:?}: {error}"))
                })
                .transpose()?;
            if parts.next().is_some() {
                return Err(format!("bad LAN scope {raw:?}: too many addresses"));
            }
            Ok(EndpointScope::Lan {
                ipv4,
                ipv6,
                port: 0,
            })
        }
    }
}

fn endpoint_scope_with_port(scope: EndpointScope, port: u16) -> EndpointScope {
    match scope {
        EndpointScope::OfflineTest { .. } => EndpointScope::OfflineTest { port },
        EndpointScope::Lan { ipv4, ipv6, .. } => EndpointScope::Lan { ipv4, ipv6, port },
        EndpointScope::Global { .. } => EndpointScope::Global { port },
    }
}

/// Human- and machine-readable identity of this build.
fn banner() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// Startup configuration. Hand-rolled flag parsing, like the fixture - a CLI
/// crate is a dependency a five-flag binary does not need.
#[derive(Debug, Clone)]
struct Config {
    listen: SocketAddr,
    upstream: String,
    store_dir: String,
    priority: u32,
    want_mass_query: bool,
    /// Directory for the persistent narinfo disk cache (task-8). When unset the
    /// daemon runs pure-upstream (pre-task-8 behaviour); when set it layers
    /// disk-cache-over-upstream and persists the NAR correlation across restarts.
    /// Opt-in in wave 1 so enabling it in the container/NixOS paths is a separate,
    /// reviewable change (filed: wire a default cache dir into the module + e2e).
    narinfo_cache_dir: Option<String>,
    /// Per-hop upstream header timeout in milliseconds (default 1000). Exposed so
    /// the fault x depth matrix (task-13) can move the 200->502 latency ceiling
    /// deliberately and so an operator fronting a slow upstream can widen it. It
    /// is a FIXED per-hop deadline that does NOT compose across a daemon chain
    /// (task-33); see `UpstreamHttp::with_header_timeout`.
    header_timeout_ms: u64,
    /// Node B (provider) mode: run an iroh-blobs provider seeded with the raw NARs
    /// named by `iroh_seed_nar`, in ADDITION to the normal HTTP daemon (so the node
    /// stays readiness-pollable and is a real peer). Off by default. The S6 harness
    /// sets it on node B only.
    iroh_provider: bool,
    /// Explicit status/test output capability. Stable NodeIds are not written to
    /// routine logs; the container harness opts into the machine-readable peer
    /// address it needs to wire its second process.
    iroh_print_peer_address: bool,
    /// Persistent identity state. Required whenever any Iroh provider/fetch
    /// capability is configured; absence fails startup rather than generating an
    /// ephemeral NodeId that invalidates discovery records after restart.
    iroh_state_dir: Option<PathBuf>,
    /// Closed lower-level socket scope. Also required for Iroh startup so a
    /// daemon never inherits a public bind from a library preset.
    iroh_endpoint_scope: Option<EndpointScope>,
    /// Fixed UDP port for the persistent Iroh identity. Required whenever Iroh
    /// is enabled so restart and discovery records describe the same endpoint.
    iroh_port: Option<u16>,
    /// Explicit node-address publication capability. Every companion field is
    /// inert and rejected unless this switch is present.
    iroh_publish_node: bool,
    iroh_publication_namespace: Option<String>,
    iroh_publication_recipient: Option<String>,
    iroh_publication_authority_socket: Option<SocketAddr>,
    iroh_publication_authority_host: Option<String>,
    iroh_publication_owner: Option<String>,
    iroh_publication_external_authorization: Option<String>,
    iroh_publication_locations: Vec<NodeLocation>,
    iroh_publication_ttl_seconds: Option<u64>,
    iroh_publication_refresh_seconds: Option<u64>,
    /// Explicit resolve-only NodeId lookup capability. Companion fields are
    /// rejected unless this switch is present, and enabling it performs no GET.
    iroh_enable_node_lookup: bool,
    iroh_lookup_namespace: Option<String>,
    iroh_lookup_recipient: Option<String>,
    iroh_lookup_authority_socket: Option<SocketAddr>,
    iroh_lookup_authority_host: Option<String>,
    iroh_lookup_owner: Option<String>,
    iroh_lookup_external_authorization: Option<String>,
    /// Raw-NAR files this node ANNOUNCES it can serve (node B). Each is served by
    /// its `BLAKE3(RawNarV1)` content id, printed on startup so the harness can
    /// wire node A's claim to it. Under the task-61 supply model the file is
    /// stream-hashed once to learn that id and then NOT held: the bytes are
    /// regenerated from the file when a peer asks.
    iroh_seed_nar: Vec<String>,
    /// Largest single NAR this node agrees to serve, in UNCOMPRESSED NAR bytes
    /// (NarSize - never the compressed FileSize). Above it a peer is DECLINED
    /// rather than the node allocating. The bound exists because the daemon is
    /// outside the trust base: without it any peer can pick the largest NAR we
    /// announce and make us allocate it (task-72 gap 1).
    iroh_max_serve_nar_bytes: u64,
    /// Largest TOTAL across concurrently-admitted serves, same units. Bounds a
    /// swarm of peers each asking for something individually acceptable.
    iroh_max_inflight_nar_bytes: u64,
    /// How long ONE admitted serve may hold its slice of the in-flight budget
    /// before the reservation is reclaimed, in milliseconds. A peer that opens a
    /// get-request and then never reads would otherwise hold its share for the life
    /// of the process; the fetch-side safety envelope bounds a stalled HOLDER, not
    /// a stalled READER.
    iroh_max_serve_duration_ms: u64,
    /// How often the provider's collector may reclaim what is no longer being
    /// served, in milliseconds. It is the LATENCY of the release, not its
    /// correctness: a sweep only runs from quiescence (see `StoreRetention`).
    iroh_sweep_interval_ms: u64,
    /// Node A (client) mode: peer iroh addresses to dial (`NodeId -> sockets`), the
    /// discovery stand-in for the fetch layer (task-40's in-memory address book).
    iroh_peers: Vec<PeerSpec>,
    /// Node A (client) mode: configured claims (signed NarHash -> raw-NAR blake3 +
    /// holder). Seeds BOTH the in-memory discovery and the raw-serve allowlist, so a
    /// peer-served path both resolves over iroh and gets the task-49 raw rewrite.
    p2p_claims: Vec<ClaimSpec>,
    // ---- libp2p Node A (consumer) config (TASK-162) -------------------------
    // The libp2p decentralized discovery+transfer path, wired ADDITIVELY in front
    // of iroh/HTTP. Distinct from the iroh flags above: iroh resolves from a
    // configured address book (`--iroh-peer`/`--p2p-claim`), libp2p DISCOVERS the
    // provider via libp2p-kad given only a bootstrap entry peer.
    /// libp2p kad bootstrap/entry peers (`<PeerId>@<multiaddr>`, repeatable). At
    /// least one is REQUIRED for libp2p (kad cannot discover without an entry point).
    libp2p_bootstrap: Vec<(PeerId, Multiaddr)>,
    /// TASK-159 basic-dial shim: provider byte-transfer dial addresses fed into the
    /// swarm out of band (`<PeerId>@<multiaddr>`, repeatable). DISCOVERY is still the
    /// decentralized kad lookup; this only supplies the dial leg until the gate-able
    /// libp2p NodeLocator/NAT axis lands (TASK-159).
    libp2p_provider_addrs: Vec<(PeerId, Multiaddr)>,
    /// The multiaddr this node listens on (e.g. `/ip4/0.0.0.0/tcp/0`). Optional; a
    /// pure consumer that only dials out may omit it, but kad connectivity is more
    /// robust with a bound listener.
    libp2p_listen: Option<Multiaddr>,
    /// The kad/identify protocol network scope (`/nix-p2p/<scope>/kad/1.0.0`).
    /// Defaults to `v1` (matching `NodeConfig::new`).
    libp2p_scope: Option<String>,
    /// Optional 32-byte ed25519 identity seed (64 hex chars). When omitted the
    /// composition root generates a fresh one from `/dev/urandom`.
    libp2p_identity_seed: Option<[u8; 32]>,
    // ---- libp2p Node B (SERVING/provider) config (TASK-178) -----------------
    // The SERVING half of the libp2p primary path: this node ANNOUNCES + SERVES
    // NARs over libp2p so a consumer daemon can discover it via kad. Mirrors the
    // iroh `--iroh-provider`/`--iroh-seed-nar`/`--iroh-print-peer-address` mode.
    /// libp2p PROVIDER mode: start the libp2p fabric WITH a supplier serving the
    /// `--libp2p-seed-nar` NARs, install the serve gate, and announce a signed
    /// `ProviderRecord` for each. Off by default (a bare consumer/HTTP node).
    libp2p_provider: bool,
    /// Raw-NAR files this node SERVES + ANNOUNCES over libp2p, each paired with its
    /// Nix `NarHash` (`<narhash>=<path>`, repeatable). The NarHash is REQUIRED because
    /// the discovery key a consumer derives from a narinfo is
    /// `ContentKey::derive_from_signed_nar_hash(NarHash)`; the provider must announce
    /// under that SAME key, and the raw file alone does not carry it (unlike the iroh
    /// `--iroh-seed-nar`, whose NarHash is supplied out of band by node A's `--p2p-claim`).
    libp2p_seed_nar: Vec<(NarHashKey, String)>,
    /// Print the provider's `PeerId` + bound listen multiaddr(s) on startup
    /// (`LIBP2P-PROVIDER-ADDR ...`), so a harness can wire another daemon's
    /// `--libp2p-bootstrap <PeerId>@<multiaddr>` to this provider. Like
    /// `--iroh-print-peer-address`.
    libp2p_print_peer_address: bool,
    /// Per-node durable state directory (TASK-185): when set, the libp2p fabric persists its
    /// anti-rollback floor + per-key announce sequence here and re-seeds them on restart.
    libp2p_state_dir: Option<std::path::PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            // 8082: clear of the fixture upstream (8080) and the testproxy (8081).
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8082)),
            upstream: "http://127.0.0.1:8081".to_string(),
            store_dir: "/nix/store".to_string(),
            priority: DEFAULT_PRIORITY,
            want_mass_query: true,
            narinfo_cache_dir: None,
            header_timeout_ms: 1000,
            iroh_provider: false,
            iroh_print_peer_address: false,
            iroh_state_dir: None,
            iroh_endpoint_scope: None,
            iroh_port: None,
            iroh_publish_node: false,
            iroh_publication_namespace: None,
            iroh_publication_recipient: None,
            iroh_publication_authority_socket: None,
            iroh_publication_authority_host: None,
            iroh_publication_owner: None,
            iroh_publication_external_authorization: None,
            iroh_publication_locations: Vec::new(),
            iroh_publication_ttl_seconds: None,
            iroh_publication_refresh_seconds: None,
            iroh_enable_node_lookup: false,
            iroh_lookup_namespace: None,
            iroh_lookup_recipient: None,
            iroh_lookup_authority_socket: None,
            iroh_lookup_authority_host: None,
            iroh_lookup_owner: None,
            iroh_lookup_external_authorization: None,
            iroh_seed_nar: Vec::new(),
            iroh_max_serve_nar_bytes: DEFAULT_MAX_SERVE_NAR_BYTES,
            iroh_max_inflight_nar_bytes: DEFAULT_MAX_INFLIGHT_NAR_BYTES,
            iroh_max_serve_duration_ms: DEFAULT_MAX_SERVE_DURATION.as_millis() as u64,
            // 500 ms: comfortably inside the profiler's 3 s post-transfer settle
            // window, so an idle node's residency reading is the released one and
            // not a race; and long enough that a burst of serves does not spend the
            // process's time sweeping an empty store.
            iroh_sweep_interval_ms: 500,
            iroh_peers: Vec::new(),
            p2p_claims: Vec::new(),
            libp2p_bootstrap: Vec::new(),
            libp2p_provider_addrs: Vec::new(),
            libp2p_listen: None,
            libp2p_scope: None,
            libp2p_identity_seed: None,
            libp2p_provider: false,
            libp2p_seed_nar: Vec::new(),
            libp2p_print_peer_address: false,
            libp2p_state_dir: None,
        }
    }
}

impl Config {
    fn from_args<I: IntoIterator<Item = String>>(args: I) -> Result<Config, String> {
        let mut config = Config::default();
        let mut args = args.into_iter();
        while let Some(flag) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| format!("flag {flag} needs a value"))
            };
            match flag.as_str() {
                "--listen" => {
                    let raw = value()?;
                    config.listen = raw
                        .parse()
                        .map_err(|e| format!("bad --listen {raw:?}: {e}"))?;
                }
                "--upstream" => config.upstream = value()?,
                "--narinfo-cache-dir" => config.narinfo_cache_dir = Some(value()?),
                "--header-timeout-ms" => {
                    let raw = value()?;
                    let ms: u64 = raw
                        .parse()
                        .map_err(|e| format!("bad --header-timeout-ms {raw:?}: {e}"))?;
                    // Reject 0 (codex, task-13): a 0 ms header timeout fires before
                    // any upstream can answer, so EVERY request 502s - a bricked-
                    // but-superficially-healthy daemon. Require a positive, sane
                    // value; the upper bound catches a units typo (e.g. seconds).
                    if !(1..=600_000).contains(&ms) {
                        return Err(format!(
                            "bad --header-timeout-ms {ms}: must be 1..=600000 (0 bricks the daemon)"
                        ));
                    }
                    config.header_timeout_ms = ms;
                }
                "--store-dir" => config.store_dir = value()?,
                "--priority" => {
                    let raw = value()?;
                    config.priority = raw
                        .parse()
                        .map_err(|e| format!("bad --priority {raw:?}: {e}"))?;
                }
                "--want-mass-query" => {
                    let raw = value()?;
                    config.want_mass_query = match raw.as_str() {
                        "1" | "true" | "yes" => true,
                        "0" | "false" | "no" => false,
                        other => return Err(format!("bad --want-mass-query {other:?}")),
                    };
                }
                "--iroh-provider" => config.iroh_provider = true,
                "--iroh-print-peer-address" => config.iroh_print_peer_address = true,
                "--iroh-state-dir" => config.iroh_state_dir = Some(PathBuf::from(value()?)),
                "--iroh-endpoint-scope" => {
                    config.iroh_endpoint_scope = Some(parse_iroh_endpoint_scope(&value()?)?);
                }
                "--iroh-port" => {
                    let raw = value()?;
                    let port = raw
                        .parse::<u16>()
                        .map_err(|error| format!("bad --iroh-port {raw:?}: {error}"))?;
                    if port == 0 {
                        return Err("bad --iroh-port 0: must be 1..=65535".into());
                    }
                    config.iroh_port = Some(port);
                }
                "--iroh-publish-node" => {
                    if config.iroh_publish_node {
                        return Err("duplicate --iroh-publish-node".into());
                    }
                    config.iroh_publish_node = true;
                }
                "--iroh-publication-namespace" => {
                    let parsed = value()?;
                    if config.iroh_publication_namespace.replace(parsed).is_some() {
                        return Err("duplicate --iroh-publication-namespace".into());
                    }
                }
                "--iroh-publication-recipient" => {
                    let parsed = value()?;
                    if config.iroh_publication_recipient.replace(parsed).is_some() {
                        return Err("duplicate --iroh-publication-recipient".into());
                    }
                }
                "--iroh-publication-authority-socket" => {
                    let raw = value()?;
                    let parsed = raw.parse().map_err(|error| {
                        format!("bad --iroh-publication-authority-socket {raw:?}: {error}")
                    })?;
                    if config
                        .iroh_publication_authority_socket
                        .replace(parsed)
                        .is_some()
                    {
                        return Err("duplicate --iroh-publication-authority-socket".into());
                    }
                }
                "--iroh-publication-authority-host" => {
                    let parsed = value()?;
                    if config
                        .iroh_publication_authority_host
                        .replace(parsed)
                        .is_some()
                    {
                        return Err("duplicate --iroh-publication-authority-host".into());
                    }
                }
                "--iroh-publication-owner" => {
                    let parsed = value()?;
                    if config.iroh_publication_owner.replace(parsed).is_some() {
                        return Err("duplicate --iroh-publication-owner".into());
                    }
                }
                "--iroh-publication-external-authorization" => {
                    let parsed = value()?;
                    if config
                        .iroh_publication_external_authorization
                        .replace(parsed)
                        .is_some()
                    {
                        return Err("duplicate --iroh-publication-external-authorization".into());
                    }
                }
                "--iroh-publication-address" => {
                    let raw = value()?;
                    let address = raw.parse::<SocketAddr>().map_err(|error| {
                        format!("bad --iroh-publication-address {raw:?}: {error}")
                    })?;
                    config
                        .iroh_publication_locations
                        .push(NodeLocation::direct(address).map_err(|error| {
                            format!("bad --iroh-publication-address {raw:?}: {error}")
                        })?);
                }
                "--iroh-publication-relay" => {
                    let raw = value()?;
                    config.iroh_publication_locations.push(
                        NodeLocation::relay(raw.clone()).map_err(|error| {
                            format!("bad --iroh-publication-relay {raw:?}: {error}")
                        })?,
                    );
                }
                "--iroh-publication-ttl-seconds" => {
                    let parsed = parse_positive_u64("--iroh-publication-ttl-seconds", &value()?)?;
                    if config
                        .iroh_publication_ttl_seconds
                        .replace(parsed)
                        .is_some()
                    {
                        return Err("duplicate --iroh-publication-ttl-seconds".into());
                    }
                }
                "--iroh-publication-refresh-seconds" => {
                    let parsed =
                        parse_positive_u64("--iroh-publication-refresh-seconds", &value()?)?;
                    if config
                        .iroh_publication_refresh_seconds
                        .replace(parsed)
                        .is_some()
                    {
                        return Err("duplicate --iroh-publication-refresh-seconds".into());
                    }
                }
                "--iroh-enable-node-lookup" => {
                    if config.iroh_enable_node_lookup {
                        return Err("duplicate --iroh-enable-node-lookup".into());
                    }
                    config.iroh_enable_node_lookup = true;
                }
                "--iroh-lookup-namespace" => {
                    if config.iroh_lookup_namespace.replace(value()?).is_some() {
                        return Err("duplicate --iroh-lookup-namespace".into());
                    }
                }
                "--iroh-lookup-recipient" => {
                    if config.iroh_lookup_recipient.replace(value()?).is_some() {
                        return Err("duplicate --iroh-lookup-recipient".into());
                    }
                }
                "--iroh-lookup-authority-socket" => {
                    let raw = value()?;
                    let parsed = raw.parse().map_err(|error| {
                        format!("bad --iroh-lookup-authority-socket {raw:?}: {error}")
                    })?;
                    if config
                        .iroh_lookup_authority_socket
                        .replace(parsed)
                        .is_some()
                    {
                        return Err("duplicate --iroh-lookup-authority-socket".into());
                    }
                }
                "--iroh-lookup-authority-host" => {
                    if config
                        .iroh_lookup_authority_host
                        .replace(value()?)
                        .is_some()
                    {
                        return Err("duplicate --iroh-lookup-authority-host".into());
                    }
                }
                "--iroh-lookup-owner" => {
                    if config.iroh_lookup_owner.replace(value()?).is_some() {
                        return Err("duplicate --iroh-lookup-owner".into());
                    }
                }
                "--iroh-lookup-external-authorization" => {
                    if config
                        .iroh_lookup_external_authorization
                        .replace(value()?)
                        .is_some()
                    {
                        return Err("duplicate --iroh-lookup-external-authorization".into());
                    }
                }
                "--iroh-seed-nar" => config.iroh_seed_nar.push(value()?),
                "--iroh-max-serve-nar-bytes" => {
                    config.iroh_max_serve_nar_bytes =
                        parse_positive_u64("--iroh-max-serve-nar-bytes", &value()?)?;
                }
                "--iroh-max-inflight-nar-bytes" => {
                    config.iroh_max_inflight_nar_bytes =
                        parse_positive_u64("--iroh-max-inflight-nar-bytes", &value()?)?;
                }
                "--iroh-max-serve-duration-ms" => {
                    config.iroh_max_serve_duration_ms =
                        parse_positive_u64("--iroh-max-serve-duration-ms", &value()?)?;
                }
                "--iroh-sweep-interval-ms" => {
                    config.iroh_sweep_interval_ms =
                        parse_positive_u64("--iroh-sweep-interval-ms", &value()?)?;
                }
                "--iroh-peer" => config.iroh_peers.push(parse_peer_spec(&value()?)?),
                "--p2p-claim" => config.p2p_claims.push(parse_claim_spec(&value()?)?),
                "--libp2p-bootstrap" => config
                    .libp2p_bootstrap
                    .push(parse_libp2p_peer("--libp2p-bootstrap", &value()?)?),
                "--libp2p-provider-addr" => config
                    .libp2p_provider_addrs
                    .push(parse_libp2p_peer("--libp2p-provider-addr", &value()?)?),
                "--libp2p-listen" => {
                    let raw = value()?;
                    config.libp2p_listen = Some(
                        raw.parse()
                            .map_err(|e| format!("bad --libp2p-listen {raw:?}: {e}"))?,
                    );
                }
                "--libp2p-scope" => config.libp2p_scope = Some(value()?),
                "--libp2p-state-dir" => config.libp2p_state_dir = Some(value()?.into()),
                "--libp2p-identity-seed" => {
                    config.libp2p_identity_seed = Some(parse_libp2p_seed(&value()?)?)
                }
                "--libp2p-provider" => config.libp2p_provider = true,
                "--libp2p-seed-nar" => config
                    .libp2p_seed_nar
                    .push(parse_libp2p_seed_nar(&value()?)?),
                "--libp2p-print-peer-address" => config.libp2p_print_peer_address = true,
                other => return Err(format!("unknown flag {other:?}")),
            }
        }
        let publication_companion_configured = config.iroh_publication_namespace.is_some()
            || config.iroh_publication_recipient.is_some()
            || config.iroh_publication_authority_socket.is_some()
            || config.iroh_publication_authority_host.is_some()
            || config.iroh_publication_owner.is_some()
            || config.iroh_publication_external_authorization.is_some()
            || !config.iroh_publication_locations.is_empty()
            || config.iroh_publication_ttl_seconds.is_some()
            || config.iroh_publication_refresh_seconds.is_some();
        if publication_companion_configured && !config.iroh_publish_node {
            return Err(
                "Iroh publication companion flags require explicit --iroh-publish-node".into(),
            );
        }
        let lookup_companion_configured = config.iroh_lookup_namespace.is_some()
            || config.iroh_lookup_recipient.is_some()
            || config.iroh_lookup_authority_socket.is_some()
            || config.iroh_lookup_authority_host.is_some()
            || config.iroh_lookup_owner.is_some()
            || config.iroh_lookup_external_authorization.is_some();
        if lookup_companion_configured && !config.iroh_enable_node_lookup {
            return Err(
                "Iroh node-lookup companion flags require explicit --iroh-enable-node-lookup"
                    .into(),
            );
        }
        let iroh_enabled = config.iroh_provider
            || config.iroh_publish_node
            || config.iroh_enable_node_lookup
            || !config.iroh_peers.is_empty()
            || !config.p2p_claims.is_empty();
        if iroh_enabled && config.iroh_port.is_none() {
            return Err("Iroh is configured but --iroh-port is missing; refusing an ephemeral discovery address".into());
        }
        // libp2p PROVIDER companion validation (TASK-178), mirroring the iroh provider
        // companions. `--libp2p-seed-nar` / `--libp2p-print-peer-address` are inert
        // without the mode switch, so reject them without `--libp2p-provider` rather than
        // silently ignoring. And a provider with nothing to serve, or with no listener to
        // be dialed on, is a node that announces then cannot deliver - fail fast naming
        // the missing flag rather than shipping a dead-on-arrival provider.
        if (!config.libp2p_seed_nar.is_empty() || config.libp2p_print_peer_address)
            && !config.libp2p_provider
        {
            return Err(
                "libp2p provider companion flags (--libp2p-seed-nar / --libp2p-print-peer-address) require explicit --libp2p-provider".into(),
            );
        }
        if config.libp2p_provider && config.libp2p_seed_nar.is_empty() {
            return Err(
                "--libp2p-provider requires at least one --libp2p-seed-nar <narhash>=<path>; a provider with nothing to serve is a no-op".into(),
            );
        }
        if config.libp2p_provider && config.libp2p_listen.is_none() {
            return Err(
                "--libp2p-provider requires --libp2p-listen <multiaddr>; a provider that binds no listener cannot be dialed by a consumer".into(),
            );
        }
        // libp2p companion validation: any libp2p flag REQUIRES a bootstrap entry
        // peer (kad cannot discover a provider without one). A `--libp2p-listen`/
        // `--libp2p-provider-addr` with no bootstrap would be a consumer that can
        // never find anyone - a silently-useless config, so fail fast. A PROVIDER
        // equally needs one: its announce only propagates once it has joined the DHT.
        if config.libp2p_requested() && config.libp2p_bootstrap.is_empty() {
            return Err(
                "libp2p is configured but --libp2p-bootstrap is missing; kad cannot discover a provider without an entry peer".into(),
            );
        }
        // Resolve the libp2p identity seed ONCE, here, so `libp2p_source_config()` is a pure,
        // idempotent read (two calls -> one identity). TASK-185 GB1: anchor it to the state dir
        // when `--libp2p-state-dir` is given, so a plain identical-argv restart comes back as
        // the SAME node (stable identity + stable sequence floor); an explicit
        // `--libp2p-identity-seed` still wins but must agree with any persisted one. Without a
        // state dir this is a fresh `/dev/urandom` seed, session-scoped as before.
        if config.libp2p_requested() {
            config.libp2p_identity_seed = Some(resolve_durable_identity_seed(
                config.libp2p_state_dir.as_deref(),
                config.libp2p_identity_seed,
            )?);
        }
        Ok(config)
    }

    /// Any libp2p flag present (so the daemon should wire the libp2p node). Covers BOTH
    /// the Node-A consumer flags and the Node-B provider flags (TASK-178): a
    /// provider-only invocation still needs the identity seed resolved and the fabric
    /// started, so it must count as "requested". `--libp2p-state-dir` counts too (TASK-185
    /// GB4): a state-dir-only invocation must be honored - it is the durable-identity anchor,
    /// not an inert flag to be silently dropped into the upstream-only branch.
    fn libp2p_requested(&self) -> bool {
        !self.libp2p_bootstrap.is_empty()
            || !self.libp2p_provider_addrs.is_empty()
            || self.libp2p_listen.is_some()
            || self.libp2p_scope.is_some()
            || self.libp2p_identity_seed.is_some()
            || self.libp2p_state_dir.is_some()
            || self.libp2p_provider
            || !self.libp2p_seed_nar.is_empty()
            || self.libp2p_print_peer_address
    }

    /// Build the production [`Libp2pSourceConfig`] this `Config` describes. PURE and
    /// idempotent: the identity seed was resolved once in [`Config::from_args`] (a fresh
    /// `/dev/urandom` one when `--libp2p-identity-seed` was omitted), so this only reads
    /// it. The network scope defaults to `v1`; the discovery budget and fetch envelope
    /// use the peer-fabric v1 defaults; per-flag budget knobs are a follow-up (TASK-162
    /// note) once the podman e2e (TASK-161) pins the operating numbers.
    fn libp2p_source_config(&self) -> Result<Libp2pSourceConfig, String> {
        let identity_seed = self.libp2p_identity_seed.ok_or_else(|| {
            "internal: libp2p identity seed unresolved (from_args resolves it when libp2p is requested)".to_string()
        })?;
        Ok(Libp2pSourceConfig {
            identity_seed,
            network_scope: self
                .libp2p_scope
                .clone()
                .unwrap_or_else(|| "v1".to_string()),
            listen: self.libp2p_listen.clone(),
            bootstrap: self.libp2p_bootstrap.clone(),
            provider_addrs: self.libp2p_provider_addrs.clone(),
            discovery_budget: peer_fabric::DiscoveryBudget::default(),
            envelope: peer_fabric::SafetyEnvelope::default(),
            state_dir: self.libp2p_state_dir.clone(),
        })
    }

    fn cache_info(&self) -> CacheInfo {
        CacheInfo {
            store_dir: self.store_dir.clone(),
            priority: self.priority,
            want_mass_query: self.want_mass_query,
        }
    }
}

/// Build the daemon's one Iroh node runtime. Provider and fetch capabilities
/// attach to the same persistent identity, endpoint and router.
///
/// Node B: attach an iroh-blobs provider under the TASK-61 SUPPLY MODEL, ANNOUNCE
/// each configured raw NAR without holding it, print the dialable identity + each
/// blob's content id (machine-readable lines the harness parses), and start a
/// monitor that logs the ground-truth served-bytes counter as it changes. Returns
/// the node owner so `main` keeps every attached capability and its router alive.
///
/// WHAT CHANGED IN TASK-72, and why the flag name still says "seed": the flag
/// names raw-NAR FILES this node can serve, and it still does. What no longer
/// happens is the eager `std::fs::read` + `provider.seed()` that put every one of
/// them in RAM at startup and kept them there for the process lifetime. Announcing
/// now costs one streamed BLAKE3 pass in 64 KiB slices; the bytes are produced
/// only when a peer actually asks, inside the serve budget, and released after.
/// The `IROH-SEED` line is byte-identical, so the harness contract is unchanged.
#[cfg(test)]
async fn setup_iroh_node(config: &Config) -> Result<Option<IrohNode>, String> {
    setup_iroh_node_with_deadline(
        config,
        tokio::time::Instant::now() + daemon::PUBLICATION_STARTUP_DEADLINE,
    )
    .await
}

async fn setup_iroh_node_with_deadline(
    config: &Config,
    publication_startup_deadline: tokio::time::Instant,
) -> Result<Option<IrohNode>, String> {
    let enabled = config.iroh_provider
        || config.iroh_publish_node
        || config.iroh_enable_node_lookup
        || !config.iroh_peers.is_empty()
        || !config.p2p_claims.is_empty();
    if !enabled {
        return Ok(None);
    }
    let state_dir = config.iroh_state_dir.clone().ok_or_else(|| {
        "Iroh is configured but --iroh-state-dir is missing; refusing an ephemeral daemon identity"
            .to_string()
    })?;
    let scope = config.iroh_endpoint_scope.ok_or_else(|| {
        "Iroh is configured but --iroh-endpoint-scope is missing; refusing an implicit network bind"
            .to_string()
    })?;
    let port = config.iroh_port.ok_or_else(|| {
        "Iroh is configured but --iroh-port is missing; refusing an ephemeral discovery address"
            .to_string()
    })?;
    let scope = endpoint_scope_with_port(scope, port);
    let address_lookup = if config.iroh_enable_node_lookup {
        let namespace = config.iroh_lookup_namespace.clone().ok_or_else(|| {
            "--iroh-enable-node-lookup requires --iroh-lookup-namespace".to_string()
        })?;
        let signed_recipient = config.iroh_lookup_recipient.clone().ok_or_else(|| {
            "--iroh-enable-node-lookup requires --iroh-lookup-recipient".to_string()
        })?;
        let authority_socket = config.iroh_lookup_authority_socket.ok_or_else(|| {
            "--iroh-enable-node-lookup requires --iroh-lookup-authority-socket".to_string()
        })?;
        let authority_host = config.iroh_lookup_authority_host.clone().ok_or_else(|| {
            "--iroh-enable-node-lookup requires --iroh-lookup-authority-host".to_string()
        })?;
        let owner = config
            .iroh_lookup_owner
            .clone()
            .ok_or_else(|| "--iroh-enable-node-lookup requires --iroh-lookup-owner".to_string())?;
        let authorization = match &config.iroh_lookup_external_authorization {
            Some(reference) => NodeLookupAuthorityAuthorization::ExternalAuthorized {
                owner: owner.clone(),
                authorization_reference: reference.clone(),
            },
            None => NodeLookupAuthorityAuthorization::LocalProductionShaped {
                owner: owner.clone(),
            },
        };
        let lookup = NodeLookupConfig::new(
            namespace,
            signed_recipient.clone(),
            authority_socket,
            authority_host,
            authorization.clone(),
        )
        .map_err(|error| error.to_string())?;
        println!(
            "IROH-NODE-LOOKUP-CONFIG enabled=true authority_class={} owner_json={} recipient_label={} requests=0",
            authorization.evidence_label(),
            serde_json::to_string(&owner).expect("a String always serializes as JSON"),
            signed_recipient,
        );
        AddressLookupCapability::PinnedPkarr(lookup)
    } else {
        AddressLookupCapability::Disabled
    };
    let mut builder = IrohNodeBuilder::new(
        EndpointProfile { scope },
        IdentitySource::Persistent {
            state_dir: state_dir.clone(),
        },
        RelayCapability::Disabled,
        address_lookup,
    )
    .map_err(|error| error.to_string())?;

    if config.iroh_publish_node {
        let namespace = config.iroh_publication_namespace.clone().ok_or_else(|| {
            "--iroh-publish-node requires --iroh-publication-namespace".to_string()
        })?;
        let signed_recipient = config.iroh_publication_recipient.clone().ok_or_else(|| {
            "--iroh-publish-node requires --iroh-publication-recipient".to_string()
        })?;
        let authority_socket = config.iroh_publication_authority_socket.ok_or_else(|| {
            "--iroh-publish-node requires --iroh-publication-authority-socket".to_string()
        })?;
        let authority_host = config
            .iroh_publication_authority_host
            .clone()
            .ok_or_else(|| {
                "--iroh-publish-node requires --iroh-publication-authority-host".to_string()
            })?;
        let owner = config
            .iroh_publication_owner
            .clone()
            .ok_or_else(|| "--iroh-publish-node requires --iroh-publication-owner".to_string())?;
        if config.iroh_publication_locations.is_empty() {
            return Err(
                "--iroh-publish-node requires at least one --iroh-publication-address or --iroh-publication-relay"
                    .into(),
            );
        }
        // Direct locations are an operator allowlist, not sufficient proof of
        // reachability by themselves. Runtime publication intersects them with
        // addresses actually observed on the endpoint. Static NAT provenance is
        // not a v1 capability, so unobserved declarations never become records.
        // Relay declarations are rejected below while relay transport is off.
        let authorization = match &config.iroh_publication_external_authorization {
            Some(reference) => PublicationAuthorityAuthorization::ExternalAuthorized {
                owner: owner.clone(),
                authorization_reference: reference.clone(),
            },
            None => PublicationAuthorityAuthorization::LocalProductionShaped {
                owner: owner.clone(),
            },
        };
        let publication_ttl_seconds = config.iroh_publication_ttl_seconds.unwrap_or(30);
        let publication_refresh_seconds = config.iroh_publication_refresh_seconds.unwrap_or(10);
        let publication = NodePublicationConfig::new(
            namespace,
            signed_recipient.clone(),
            authority_socket,
            authority_host,
            authorization.clone(),
            std::time::Duration::from_secs(publication_ttl_seconds),
            std::time::Duration::from_secs(publication_refresh_seconds),
            std::time::Duration::from_secs(2),
            config.iroh_publication_locations.clone(),
        )
        .map_err(|error| error.to_string())?;
        println!(
            "IROH-NODE-PUBLICATION-CONFIG enabled=true authority_class={} owner_json={} recipient_label={} locations={} ttl_seconds={} refresh_seconds={}",
            authorization.evidence_label(),
            serde_json::to_string(&owner).expect("a String always serializes as JSON"),
            signed_recipient,
            config.iroh_publication_locations.len(),
            publication_ttl_seconds,
            publication_refresh_seconds,
        );
        builder = builder
            .publication_startup_deadline(publication_startup_deadline)
            .map_err(|error| error.to_string())?
            .node_publication(NodePublicationCapability::Enabled(publication))
            .map_err(|error| error.to_string())?;
    }

    if !config.iroh_provider {
        let node = builder.spawn().await.map_err(|error| error.to_string());
        let node = node?;
        if let Err(error) = log_publication_status(&node).await {
            return Err(shutdown_after_setup_error(node, error).await);
        }
        return Ok(Some(node));
    }

    // FILE-BACKED, not store-backed. `IndexNarSupplier` (an inert supply-catalog
    // reader) is the supplier a real node wants and is proven in
    // `daemon/tests/serve_budget_and_supply.rs`, but nothing here opens an index
    // yet - so the shipped daemon regenerates from the raw-NAR files it was
    // pointed at, not from /nix/store. TASK-83 wires the real one.
    let helper_program = std::env::current_exe().map_err(|error| {
        format!("resolving daemon executable for supervised NAR reads: {error}")
    })?;
    let supplier = Arc::new(FileNarSupplier::new(helper_program));
    let budget = ServeBudget {
        max_nar_bytes_uncompressed_nar: config.iroh_max_serve_nar_bytes,
        max_inflight_bytes_uncompressed_nar: config.iroh_max_inflight_nar_bytes,
        max_serve_duration: std::time::Duration::from_millis(config.iroh_max_serve_duration_ms),
    };
    // S11: a node whose in-flight total is below its per-NAR bound declines EVERY
    // serve with `busy` - "a daemon that looks healthy and does nothing", the exact
    // failure `parse_positive_u64` rejects 0 for. Refuse at startup, naming both.
    if budget.max_inflight_bytes_uncompressed_nar < budget.max_nar_bytes_uncompressed_nar {
        return Err(format!(
            "--iroh-max-inflight-nar-bytes {} is below --iroh-max-serve-nar-bytes {}: \
             every serve at the per-NAR bound would be declined as busy",
            budget.max_inflight_bytes_uncompressed_nar, budget.max_nar_bytes_uncompressed_nar
        ));
    }
    for path in &config.iroh_seed_nar {
        // Fails fast at STARTUP: a raw NAR we cannot read is a configuration error,
        // not a node that quietly announces nothing and dial-then-fails later.
        let (blake3, nar_bytes) = supplier
            .announce(path)
            .map_err(|e| format!("announcing raw NAR {path:?}: {e}"))?;
        // Announcing something the budget would refuse to serve is exactly the
        // "index promises what the provider cannot deliver" defect task-72 exists
        // to remove - in a different disguise. Refuse at startup, naming both
        // numbers, rather than shipping a claim that is dead on arrival.
        if nar_bytes > budget.max_nar_bytes_uncompressed_nar {
            return Err(format!(
                "raw NAR {path:?} is {nar_bytes} B (uncompressed NAR) but \
                 --iroh-max-serve-nar-bytes is {}: announcing it would publish a \
                 claim this node would then decline to serve",
                budget.max_nar_bytes_uncompressed_nar
            ));
        }
        // Machine-readable: the harness maps path -> NarHash and builds node A's
        // --p2p-claim <narhash>=<this blake3>@<this node_id>.
        println!(
            "IROH-SEED path={path} bytes={nar_bytes} blake3={}",
            blake3.to_hex()
        );
    }
    println!(
        "IROH-SERVE-BUDGET max_nar_bytes_uncompressed_nar={} max_inflight_bytes_uncompressed_nar={} max_serve_duration_ms={} sweep_interval_ms={}",
        budget.max_nar_bytes_uncompressed_nar,
        budget.max_inflight_bytes_uncompressed_nar,
        config.iroh_max_serve_duration_ms,
        config.iroh_sweep_interval_ms
    );

    let node = builder
        .provider(IrohProviderConfig::supplying(
            supplier,
            budget,
            std::time::Duration::from_millis(config.iroh_sweep_interval_ms),
        ))
        .spawn()
        .await
        .map_err(|error| error.to_string())?;
    if let Err(error) = log_publication_status(&node).await {
        return Err(shutdown_after_setup_error(node, error).await);
    }
    let provider = node
        .provider_handle()
        .expect("provider configuration installs the provider before spawn");

    if config.iroh_print_peer_address {
        let sockets = match provider.reachable_socket_addrs() {
            Ok(sockets) => sockets,
            Err(error) => {
                drop(provider);
                return Err(shutdown_after_setup_error(
                    node,
                    format!("reading provider's reachable sockets: {error}"),
                )
                .await);
            }
        };
        if sockets.is_empty() {
            drop(provider);
            let shutdown = node
                .shutdown()
                .await
                .map(|outcome| format!("shutdown outcome {outcome:?}"))
                .unwrap_or_else(|error| format!("shutdown also failed: {error}"));
            return Err(format!(
                "--iroh-print-peer-address requested but the provider has no concrete reachable sockets; {shutdown}"
            ));
        }
        let sockets_csv = sockets
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let node_id = match provider.node_id() {
            Ok(node_id) => node_id,
            Err(error) => {
                drop(provider);
                return Err(shutdown_after_setup_error(
                    node,
                    format!("reading provider identity: {error}"),
                )
                .await);
            }
        };
        println!(
            "IROH-PROVIDER-ADDR node_id={} sockets={sockets_csv}",
            node_id.to_hex()
        );
    }

    // Ground-truth served-bytes monitor: poll the provider's own byte counter and
    // log it whenever it advances, so the harness reads node B's SENT bytes (not
    // node A's self-report) as the peer-served oracle.
    //
    // Two more machine-readable lines ride the same loop (task-65):
    //
    //   IROH-STORE-RESIDENT - the RESIDENCY oracle. What the blob store says it
    //     holds, asked of the store itself. Peak RSS cannot answer this (VmHWM is
    //     monotone, and glibc need not return a freed arena), so a residency claim
    //     gated on RSS alone would fail on a correct fix and pass on a wrong one.
    //
    //   IROH-SERVE-WINDOW - one line per COMPLETED serve, with the holder-side
    //     start/end of the transfer. The concurrency precondition is measured from
    //     these, not from the fetching client's request windows, which would overlap
    //     even if the serves had taken turns.
    let monitor = {
        let provider = provider.clone();
        async move {
            let mut last = 0u64;
            let mut windows_logged = 0usize;
            let mut last_residency: Option<daemon::StoreResidency> = None;
            let mut last_counters: Option<daemon::ServeCounters> = None;
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                let served = provider.bytes_served();
                if served != last {
                    last = served;
                    println!(
                        "IROH-SERVED-TOTAL bytes={served} transfers={}",
                        provider.transfers_completed()
                    );
                }
                let windows = provider.serve_windows();
                for window in windows.iter().skip(windows_logged) {
                    println!(
                        "IROH-SERVE-WINDOW start_ms={:.3} end_ms={:.3} bytes_uncompressed_nar={}",
                        window.start_ms, window.end_ms, window.bytes_uncompressed_nar
                    );
                }
                windows_logged = windows.len();
                // FAIL VERBOSELY, never silently: a residency reading that could not
                // be taken is logged as an error line, so the harness sees "unknown"
                // rather than inferring "holds nothing" from a missing line.
                match provider.store_residency().await {
                    Ok(residency) => {
                        if last_residency != Some(residency) {
                            last_residency = Some(residency);
                            println!(
                                "IROH-STORE-RESIDENT blobs={} bytes_uncompressed_nar={}",
                                residency.blobs, residency.bytes_uncompressed_nar
                            );
                        }
                    }
                    Err(err) => eprintln!("IROH-STORE-RESIDENT-ERROR {err}"),
                }
                // The ADMISSION GATE's own story (task-72). A node that is
                // declining peers must say so and say WHY: "declined 12" is not
                // actionable, "declined 12 over the per-NAR bound" is. Logged only
                // when it moves, like the byte counter above.
                let counters = provider.serve_counters();
                if last_counters != Some(counters) {
                    last_counters = Some(counters);
                    println!(
                        "IROH-SERVE-COUNTERS admitted={} regenerated={} declined={} \
                         declined_too_large={} declined_busy={} declined_unknown={} \
                         declined_supply_failed={} declined_store_unreadable={} \
                         reservations_timed_out={}",
                        counters.admitted,
                        counters.regenerated,
                        counters.declined(),
                        counters.declined_too_large,
                        counters.declined_busy,
                        counters.declined_unknown,
                        counters.declined_supply_failed,
                        counters.declined_store_unreadable,
                        counters.reservations_timed_out,
                    );
                }
            }
        }
    };
    if let Err(error) = node.spawn_task("provider-observability", monitor) {
        drop(provider);
        return Err(shutdown_after_setup_error(
            node,
            format!("starting provider observability: {error}"),
        )
        .await);
    }

    Ok(Some(node))
}

async fn log_publication_status(node: &IrohNode) -> Result<(), String> {
    let Some(publication) = node.node_publication_handle() else {
        return Ok(());
    };
    let record = publication
        .current_record()
        .await
        .map_err(|error| format!("reading publication status: {error}"))?
        .ok_or_else(|| "publication startup returned without a committed record".to_string())?;
    if record.state != daemon::PublicationState::Live || record.locations.is_empty() {
        return Err(format!(
            "publication startup returned {:?} with {} locations; readiness requires a visible live record",
            record.state,
            record.locations.len()
        ));
    }
    println!(
        "IROH-NODE-PUBLICATION state={:?} sequence={} ttl_seconds={} expires_unix_micros={} locations={} recipient_label={}",
        record.state,
        record.sequence,
        record.ttl_seconds,
        record.expires_unix_micros,
        record.locations.len(),
        record.recipient,
    );
    Ok(())
}

async fn shutdown_after_setup_error(node: IrohNode, error: String) -> String {
    let cleanup = node
        .shutdown()
        .await
        .map(|outcome| format!("shutdown outcome {outcome:?}"))
        .unwrap_or_else(|cleanup_error| format!("shutdown failed: {cleanup_error}"));
    format!("{error}; cleanup={cleanup}")
}

/// Held for the process lifetime by `main`: keeps the libp2p PROVIDER fabric AND its
/// installed serve gate alive. Dropping the [`ServeHandle`] stops admitting new serves
/// (peer_fabric's teardown contract), and dropping the fabric stops its swarm worker - so
/// both MUST outlive the HTTP server. The libp2p NarSource layer holds its own
/// `Arc<Libp2pFabric>` clone, but the serve gate lives ONLY here, so this guard is what
/// keeps the node SERVING.
struct Libp2pProviderGuard {
    _fabric: Arc<Libp2pFabric>,
    _serve: ServeHandle,
}

/// Node B (libp2p PROVIDER, TASK-178): start the libp2p fabric WITH a supplier serving
/// the `--libp2p-seed-nar` NARs, install the serve gate under the daemon's serve budget,
/// and announce a signed [`ProviderRecord`] for each seed so a consumer discovers it via
/// kad. Returns the fabric's OWN consumer source/raw-serve (a provider also consumes -
/// ONE fabric/identity/listen does both) plus the [`Libp2pProviderGuard`] `main` holds.
///
/// Fail-fast: an unreadable seed file, a seed over the per-NAR budget, or a serve/announce
/// error is a loud startup error, never a provider that announces then cannot deliver.
async fn install_libp2p_provider(
    config: &Config,
    cfg: Libp2pSourceConfig,
) -> Result<
    (
        Arc<dyn NarSource>,
        Arc<dyn RawServeDecision>,
        Libp2pProviderGuard,
    ),
    String,
> {
    // Read every seeded raw NAR up front: a NAR we cannot read is a configuration error,
    // not a provider that quietly announces nothing and dial-then-fails at serve time.
    let mut seeds: Vec<(NarHashKey, Vec<u8>)> = Vec::with_capacity(config.libp2p_seed_nar.len());
    for (nar_hash, path) in &config.libp2p_seed_nar {
        let bytes =
            std::fs::read(path).map_err(|e| format!("reading --libp2p-seed-nar {path:?}: {e}"))?;
        seeds.push((*nar_hash, bytes));
    }

    // The serve budget REUSES the daemon's existing serve-budget knobs (the `--iroh-max-*`
    // flags), which are backend-neutral `ServeBudget` numbers in UNCOMPRESSED NAR bytes -
    // NOT a new unbounded serving path. Backend-specific `--libp2p-max-*` knobs are a
    // follow-up once TASK-161 pins the operating numbers. The two guards below are the
    // SAME "healthy but does nothing" footguns the iroh provider path rejects: an inflight
    // bound below the per-NAR bound declines every serve as busy, and announcing a NAR
    // larger than the per-NAR bound publishes a claim this node would then decline.
    // NOTE: the daemon's own `ServeBudget` (transport_iroh) and `peer_fabric::ServeBudget`
    // are DISTINCT types with the same fields; the libp2p `NarServer::serve` wants the
    // peer_fabric one, so build that explicitly.
    let serve_budget = peer_fabric::ServeBudget {
        max_nar_bytes_uncompressed_nar: config.iroh_max_serve_nar_bytes,
        max_inflight_bytes_uncompressed_nar: config.iroh_max_inflight_nar_bytes,
        max_serve_duration: std::time::Duration::from_millis(config.iroh_max_serve_duration_ms),
    };
    if serve_budget.max_inflight_bytes_uncompressed_nar
        < serve_budget.max_nar_bytes_uncompressed_nar
    {
        return Err(format!(
            "--iroh-max-inflight-nar-bytes {} is below --iroh-max-serve-nar-bytes {}: every \
             libp2p serve at the per-NAR bound would be declined as busy",
            serve_budget.max_inflight_bytes_uncompressed_nar,
            serve_budget.max_nar_bytes_uncompressed_nar
        ));
    }
    for (nar_hash, bytes) in &seeds {
        if bytes.len() as u64 > serve_budget.max_nar_bytes_uncompressed_nar {
            return Err(format!(
                "seeded NAR {nar_hash} is {} B (uncompressed NAR) but --iroh-max-serve-nar-bytes \
                 is {}: announcing it would publish a claim this node would then decline to serve",
                bytes.len(),
                serve_budget.max_nar_bytes_uncompressed_nar
            ));
        }
    }

    // A PROVIDER without a durable state dir re-enables the F3 self-rollback (fresh random
    // identity + sequence 1 after a restart). WARN loudly rather than silently - but this
    // warns-and-continues, it is NOT fail-closed (a hard refusal is arguably right now that GB1
    // makes the state dir load-bearing, but the podman/netns e2e harness starts providers
    // without --libp2p-state-dir, so fail-closed is deferred to TASK-188 with the harness fix).
    if cfg.state_dir.is_none() {
        eprintln!(
            "daemon: WARNING: --libp2p-state-dir is not set; this libp2p PROVIDER runs \
             NON-DURABLE. Its identity is regenerated each start and its announce sequences and \
             withdrawals will NOT survive a restart (a restarted provider announces under a NEW \
             identity at sequence 1 and cannot supersede or withdraw its old records). Set \
             --libp2p-state-dir <dir> for restart-durable operation."
        );
    }

    let identity_seed = cfg.identity_seed;
    let supplier = Arc::new(MemoryNarSupplier::new(seeds.iter().map(|(_, b)| b.clone())));

    // Start the fabric WITH the supplier (serve axis present) + join the DHT, and get its
    // consumer source/raw-serve from the SAME fabric (one identity, one listen).
    let (fabric, source, raw_serve) = build_libp2p_provider_source(cfg, supplier).await?;

    // Install the serve gate (bounded by the serve budget). The returned ServeHandle MUST
    // live for the process; it goes in the guard `main` holds.
    let serve = fabric
        .server()
        .ok_or_else(|| {
            "internal: libp2p provider fabric has no serve axis (start_with_supplier)".to_string()
        })?
        .serve(serve_budget)
        .await
        .map_err(|e| format!("libp2p serve gate failed to install: {e}"))?;

    // Announce a signed ProviderRecord for each seed (durable-allocate -> sign -> announce)
    // through the SSOT provider loop the restart-durability test also exercises (TASK-185 GB2),
    // so a consumer's kad get_providers finds this node under the ContentKey it derives from
    // the narinfo's NarHash.
    let announce_budget = AnnounceBudget::new(std::time::Duration::from_secs(10), 20);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let records =
        announce_provider_seeds(&fabric, identity_seed, &seeds, 3600, now, &announce_budget)
            .await?;
    for (record, (nar_hash, bytes)) in records.iter().zip(&seeds) {
        // Machine-readable: path/NarHash -> the derived ContentKey + raw BLAKE3 content id.
        println!(
            "LIBP2P-SEED narhash={nar_hash} content={} content_key={} bytes={}",
            record.content.to_hex(),
            record.key,
            bytes.len()
        );
    }
    println!(
        "LIBP2P-SERVE-BUDGET max_nar_bytes_uncompressed_nar={} max_inflight_bytes_uncompressed_nar={} max_serve_duration_ms={}",
        serve_budget.max_nar_bytes_uncompressed_nar,
        serve_budget.max_inflight_bytes_uncompressed_nar,
        config.iroh_max_serve_duration_ms
    );

    // The harness reads this to wire another daemon's `--libp2p-bootstrap <PeerId>@<addr>`.
    if config.libp2p_print_peer_address {
        let listen_addrs = fabric.handle().listen_addrs().await;
        if listen_addrs.is_empty() {
            return Err(
                "--libp2p-print-peer-address requested but the provider bound no listen address"
                    .into(),
            );
        }
        let addrs_csv = listen_addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "LIBP2P-PROVIDER-ADDR peer_id={} listen={addrs_csv}",
            fabric.peer_id()
        );
    }

    Ok((
        source,
        raw_serve,
        Libp2pProviderGuard {
            _fabric: fabric,
            _serve: serve,
        },
    ))
}

/// Node A: assemble the p2p `NarSource` (iroh transport wired to the configured
/// peers + an in-memory discovery seeded from the configured claims) IN FRONT of
/// the HTTP upstream, plus the matching raw-serve allowlist. Both are built from
/// the ONE `p2p_claims` set so discovery and raw-serve can never drift.
async fn setup_p2p_source(
    config: &Config,
    upstream: Arc<UpstreamHttp>,
    transport: Option<IrohTransport>,
) -> Result<
    (
        Arc<dyn NarSource>,
        Arc<dyn RawServeDecision>,
        Option<Libp2pProviderGuard>,
    ),
    String,
> {
    let iroh_configured = !config.iroh_peers.is_empty() || !config.p2p_claims.is_empty();

    // Build each p2p LAYER as an optional source; the pure `compose_nar_chain` helper
    // nests them in the documented precedence. Separating "build the layers" (I/O,
    // fallible) from "order the layers" (pure) makes the precedence a unit-testable
    // oracle (see `compose_nar_chain`'s tests) rather than an un-probed inline decision.
    let iroh_layer: Option<Arc<dyn NarSource>> = if iroh_configured {
        // Fail fast (config-time, not first-request): every claim's holder MUST have a
        // configured dialable address. Without this a typo'd/omitted `--iroh-peer`
        // node silently degrades to upstream fallback (raw paths) or a fail-closed 404
        // (compressed-rewritten paths) at the first request - a confusing runtime miss
        // instead of a loud startup error.
        let peer_nodes: std::collections::HashSet<NodeId> =
            config.iroh_peers.iter().map(|p| p.node).collect();
        for claim in &config.p2p_claims {
            if !peer_nodes.contains(&claim.node) {
                return Err(format!(
                    "claim for {} names holder {} but no --iroh-peer supplies its address",
                    claim.nar_hash,
                    claim.node.to_hex()
                ));
            }
        }

        let transport = transport.ok_or_else(|| {
            "iroh peers/claims configured but no Iroh transport was supplied".to_string()
        })?;
        for peer in &config.iroh_peers {
            transport.add_peer(&IrohPeerAddr::new(peer.node, peer.sockets.iter().copied()));
        }
        let mut registry = TransportRegistry::new();
        registry.register(Box::new(transport));

        let discovery = InMemoryDiscovery::new();
        for claim in &config.p2p_claims {
            // Reuse the key canonicalised once at parse time (SSOT for the parsed form).
            discovery.announce(Claim {
                schema_version: CLAIM_SCHEMA_VERSION,
                key: claim.key,
                payload: Some(KnownPayload::WholeNar {
                    blake3: claim.blake3,
                }),
                holders: vec![claim.node],
                transports: vec![KnownTransport::Iroh { node: claim.node }],
                relay: None,
                signatures: vec![],
            });
        }

        println!(
            "daemon: iroh p2p source wired ({} peer(s), {} claim(s))",
            config.iroh_peers.len(),
            config.p2p_claims.len()
        );
        Some(Arc::new(TransportNarSource::new(
            registry,
            Arc::new(discovery),
        )))
    } else {
        None
    };

    // Captured from the libp2p builder (when libp2p is requested): the DYNAMIC raw-serve
    // decision that probes kad provider discovery, paired with the fetch source so the
    // two consult one mechanism (TASK-164).
    let mut libp2p_raw_serve: Option<Arc<dyn RawServeDecision>> = None;
    // The PROVIDER guard (serve gate + fabric) when `--libp2p-provider` is set. `main`
    // keeps it alive for the process; here it rides out via the return value.
    let mut libp2p_provider_guard: Option<Libp2pProviderGuard> = None;
    let libp2p_layer: Option<Arc<dyn NarSource>> = if config.libp2p_requested() {
        if config.libp2p_provider {
            // Node B (SERVING, TASK-178): ONE fabric that SERVES + ANNOUNCES the seeded
            // NARs AND consumes (build_libp2p_provider_source returns the same fabric's
            // consumer source). The serve gate + fabric live in the guard `main` holds.
            let (libp2p_source, raw_serve, guard) =
                install_libp2p_provider(config, config.libp2p_source_config()?).await?;
            libp2p_raw_serve = Some(raw_serve);
            libp2p_provider_guard = Some(guard);
            println!(
                "daemon: libp2p PROVIDER started, serving + announcing {} seeded NAR(s) ({} bootstrap peer(s))",
                config.libp2p_seed_nar.len(),
                config.libp2p_bootstrap.len()
            );
            Some(libp2p_source)
        } else {
            // Node A (CONSUMER): build + START the libp2p fabric (listen/bootstrap/dial)
            // and wrap it in the Libp2pNarSource. The returned fabric handle is dropped
            // here: the source holds its own Arc clone, keeping the node alive for the
            // process lifetime. The raw-serve decision is captured so a libp2p HIT
            // rewrites its narinfo to raw (see below).
            let (_fabric, libp2p_source, raw_serve) =
                build_libp2p_nar_source(config.libp2p_source_config()?).await?;
            libp2p_raw_serve = Some(raw_serve);
            println!(
                "daemon: libp2p p2p source started, discovery converging ({} bootstrap peer(s), {} optional provider dial-addr override hint(s); dial addresses resolved via kad peer-routing)",
                config.libp2p_bootstrap.len(),
                config.libp2p_provider_addrs.len()
            );
            Some(libp2p_source)
        }
    } else {
        None
    };

    let chain = compose_nar_chain(libp2p_layer, iroh_layer, upstream.clone());

    // Compose the raw-serve decision so BOTH backends trigger the task-49 narinfo
    // rewrite (TASK-164):
    //   * iroh: the STATIC claim allowlist (discovery + allowlist seeded from one
    //     `--p2p-claim`, so a discovery HIT is already an allowlist HIT);
    //   * libp2p: the DYNAMIC provider probe (rewrite to raw iff kad discovers a
    //     provider for the NarHash right now), mirroring iroh's coupling but keyed on
    //     the live discovery result rather than a static claim.
    // `AnyRawServe` serves raw iff EITHER says so, so a libp2p HIT under a compressed
    // upstream narinfo is rewritten to raw (Compression: none, FileHash/FileSize = raw)
    // before a real Nix client validates the bytes - the gap TASK-164 closes. Iroh-only
    // and pure-HTTP nodes keep exactly their prior decision.
    let iroh_allowlist: Arc<dyn RawServeDecision> = Arc::new(AllowlistRawServe::new(
        config.p2p_claims.iter().map(|c| c.nar_hash.clone()),
    ));
    let raw_serve: Arc<dyn RawServeDecision> = match libp2p_raw_serve {
        Some(libp2p) => Arc::new(AnyRawServe::new(vec![iroh_allowlist, libp2p])),
        None => iroh_allowlist,
    };

    Ok((chain, raw_serve, libp2p_provider_guard))
}

/// Nest the optional p2p layers in front of `upstream` in the documented PRECEDENCE
/// (TASK-162): libp2p (decentralized kad discovery, PRD-primary) -> iroh (configured
/// address book) -> HTTP upstream. Each present layer wraps the one below via
/// [`FallbackNarSource`], so a clean miss/`Unreachable` at one layer falls through to
/// the next (a `TooLarge` abort still propagates). Built tail-first so the outermost
/// (primary) source is tried first.
///
/// This is a PURE function (no I/O) so the precedence is a unit-testable oracle: the
/// tests below drive it with fake sources and assert which layer answers, so swapping
/// the layer order (or dropping a layer) is caught by a failing test. Whether
/// libp2p-first is the RIGHT composition (vs. a transport tournament / dual-stack race)
/// is the open compose question deferred to the clean daemon-core split (TASK-145/146,
/// TASK-163).
fn compose_nar_chain(
    libp2p: Option<Arc<dyn NarSource>>,
    iroh: Option<Arc<dyn NarSource>>,
    upstream: Arc<dyn NarSource>,
) -> Arc<dyn NarSource> {
    let mut chain = upstream;
    if let Some(iroh) = iroh {
        chain = Arc::new(FallbackNarSource::new(iroh, chain));
    }
    if let Some(libp2p) = libp2p {
        chain = Arc::new(FallbackNarSource::new(libp2p, chain));
    }
    chain
}

/// The `rewrite-narinfo` filter subcommand: read a narinfo on stdin, apply the
/// task-49 transport rewrite (`to_raw`), write the rewritten narinfo on stdout.
/// Exits 0 on success, 3 on a `RewriteError` (an un-rewritable narinfo), 1 on an
/// I/O error. It is the exact serving-layer rewrite as a pure filter, so an
/// operator (and the real-nix e2e in scripts/) can see and verify precisely what
/// the daemon would hand a client for a peer-served path.
fn run_rewrite_narinfo_filter() -> ExitCode {
    use std::io::{Read, Write};
    let mut input = Vec::new();
    if let Err(err) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("daemon rewrite-narinfo: reading stdin: {err}");
        return ExitCode::FAILURE;
    }
    match daemon::to_raw(&input) {
        Ok(rewrite) => {
            if let Err(err) = std::io::stdout().write_all(&rewrite.body) {
                eprintln!("daemon rewrite-narinfo: writing stdout: {err}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("daemon rewrite-narinfo: {err}");
            ExitCode::from(3)
        }
    }
}

/// Installed synchronously before any readiness output, closing the startup
/// race where a supervisor could signal immediately after observing readiness.
#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
fn install_shutdown_signals() -> Result<ShutdownSignals, String> {
    let interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|error| format!("installing SIGINT handler: {error}"))?;
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| format!("installing SIGTERM handler: {error}"))?;
    Ok(ShutdownSignals {
        interrupt,
        terminate,
    })
}

#[cfg(unix)]
impl ShutdownSignals {
    async fn recv(mut self) -> Result<&'static str, String> {
        tokio::select! {
            received = self.interrupt.recv() => {
                received.ok_or_else(|| "SIGINT signal stream closed unexpectedly".to_string())?;
                Ok("SIGINT")
            }
            received = self.terminate.recv() => {
                received.ok_or_else(|| "SIGTERM signal stream closed unexpectedly".to_string())?;
                Ok("SIGTERM")
            }
        }
    }
}

#[cfg(not(unix))]
struct ShutdownSignals;

#[cfg(not(unix))]
fn install_shutdown_signals() -> Result<ShutdownSignals, String> {
    Ok(ShutdownSignals)
}

#[cfg(not(unix))]
impl ShutdownSignals {
    async fn recv(self) -> Result<&'static str, String> {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| format!("waiting for shutdown signal: {error}"))?;
        Ok("interrupt")
    }
}

/// Consume the sole runtime owner and report whether shutdown completed through
/// its bounded graceful/forced path.
async fn shutdown_iroh_node(node: Option<IrohNode>) -> bool {
    let Some(node) = node else {
        return true;
    };
    match node.shutdown().await {
        Ok(outcome) => {
            println!("IROH-NODE-SHUTDOWN outcome={outcome:?}");
            true
        }
        Err(error) => {
            eprintln!("IROH-NODE-SHUTDOWN-FAILED error={error}");
            false
        }
    }
}

async fn wait_for_publication_fatal(
    publication: Option<NodePublicationHandle>,
) -> daemon::PublicationError {
    match publication {
        Some(publication) => publication.wait_for_fatal().await,
        None => pending().await,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let process_started = tokio::time::Instant::now();
    let publication_startup_deadline = process_started + daemon::PUBLICATION_STARTUP_DEADLINE;
    // Internal process-isolation boundary for raw-file supply. It is intentionally
    // handled before normal configuration: the parent owns this process group,
    // caps stdout, and kills/reaps it on request cancellation or node shutdown.
    let mut raw_os_args = std::env::args_os().skip(1);
    if raw_os_args.next().as_deref() == Some(std::ffi::OsStr::new("__dump-raw-nar")) {
        if !daemon::raw_nar_helper_authorized() {
            eprintln!("daemon: __dump-raw-nar is an internal supervised subprocess mode");
            return ExitCode::from(2);
        }
        let Some(path) = raw_os_args.next() else {
            eprintln!("daemon: __dump-raw-nar requires exactly one path");
            return ExitCode::from(2);
        };
        if raw_os_args.next().is_some() {
            eprintln!("daemon: __dump-raw-nar accepts exactly one path");
            return ExitCode::from(2);
        }
        let stdout = std::io::stdout();
        let mut locked = stdout.lock();
        return match daemon::copy_regular_raw_nar(PathBuf::from(path), &mut locked) {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("daemon: __dump-raw-nar failed: {error}");
                ExitCode::FAILURE
            }
        };
    }

    // A tiny subcommand surface: `rewrite-narinfo` is a synchronous stdin->stdout
    // filter, handled before any flag parsing or the async serve loop.
    let mut raw_args = std::env::args().skip(1).peekable();
    if raw_args.peek().map(String::as_str) == Some("rewrite-narinfo") {
        return run_rewrite_narinfo_filter();
    }

    let config = match Config::from_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("daemon: {err}");
            return ExitCode::from(2);
        }
    };
    let shutdown_signals = match install_shutdown_signals() {
        Ok(signals) => signals,
        Err(error) => {
            eprintln!("daemon: shutdown signal setup failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("{}", banner());

    // The correlation catalog lives in the server only: it populates it as
    // narinfos pass through and reads it at NAR-request time. UpstreamHttp needs
    // no catalog - the request carries the exact URL token to fetch.
    let catalog = Arc::new(NarCatalog::new());
    let upstream = match UpstreamHttp::new(&config.upstream) {
        Ok(upstream) => Arc::new(
            upstream
                .with_header_timeout(std::time::Duration::from_millis(config.header_timeout_ms)),
        ),
        Err(err) => {
            eprintln!("daemon: bad --upstream: {err}");
            return ExitCode::from(2);
        }
    };

    // Layer the persistent narinfo cache over the upstream when a cache dir is
    // configured (task-8). The SAME instance is the narinfo source AND the
    // persistent correlation store, so a warm-on-disk daemon dispatches the
    // signed NarHash even after an in-memory-cold restart.
    let (narinfo, correlation): (Arc<dyn NarinfoSource>, Arc<dyn CorrelationStore>) = match &config
        .narinfo_cache_dir
    {
        Some(dir) => match NarinfoDiskCache::new(dir, upstream.clone(), Arc::new(SystemClock)) {
            Ok(cache) => {
                let cache = Arc::new(cache);
                println!("daemon: narinfo disk cache at {dir}");
                (cache.clone(), cache)
            }
            Err(err) => {
                eprintln!("daemon: cannot open narinfo cache dir {dir:?}: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => (upstream.clone(), Arc::new(NullCorrelation)),
    };

    // One persistent Iroh node owns provider and fetch capabilities. Keeping it
    // alive for the process lifetime keeps the shared router/socket alive.
    let iroh_node = match setup_iroh_node_with_deadline(&config, publication_startup_deadline).await
    {
        Ok(node) => node,
        Err(err) => {
            eprintln!("daemon: Iroh node setup failed: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Node A (client) mode: put the p2p NarSource (iroh transport + configured
    // discovery) IN FRONT of the HTTP upstream via FallbackNarSource, and pair it
    // with the raw-serve allowlist so a peer-served path is both resolved over iroh
    // AND gets the task-49 raw narinfo rewrite. Absent any peer/claim config the
    // node stays a pure HTTP substituter (the wave-1 S2 path, NoRawServe).
    let iroh_p2p = !config.iroh_peers.is_empty() || !config.p2p_claims.is_empty();
    // `_libp2p_provider` keeps the libp2p PROVIDER's serve gate + fabric alive for the
    // process (TASK-178); dropping it would stop serving. `None` for a non-provider node.
    let (nar, raw_serve, _libp2p_provider): (
        Arc<dyn NarSource>,
        Arc<dyn RawServeDecision>,
        Option<Libp2pProviderGuard>,
    ) = if !iroh_p2p && !config.libp2p_requested() {
        (upstream.clone(), Arc::new(NoRawServe), None)
    } else {
        // The Iroh transport is only needed for the iroh p2p layer; a libp2p-only
        // node runs with no Iroh node runtime (None here).
        let transport = if iroh_p2p {
            match &iroh_node {
                Some(node) => Some(node.transport_handle()),
                None => {
                    eprintln!("daemon: iroh p2p source requested without an Iroh node runtime");
                    return ExitCode::FAILURE;
                }
            }
        } else {
            None
        };
        match setup_p2p_source(&config, upstream.clone(), transport).await {
            Ok(triple) => triple,
            Err(err) => {
                eprintln!("daemon: p2p source setup failed: {err}");
                shutdown_iroh_node(iroh_node).await;
                return ExitCode::FAILURE;
            }
        }
    };

    let app = Arc::new(App {
        narinfo,
        nar,
        passthrough: upstream.clone(),
        cache_info: config.cache_info(),
        catalog,
        upstream_label: config.upstream.clone(),
        correlation,
        raw_serve,
    });

    let listener = match TcpListener::bind(config.listen).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("daemon: cannot bind {}: {err}", config.listen);
            shutdown_iroh_node(iroh_node).await;
            return ExitCode::FAILURE;
        }
    };
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| config.listen.to_string());
    println!(
        "daemon: listening on {local} -> upstream {}",
        config.upstream
    );

    // HTTP connection tasks share the Iroh node's supervisor when present, so
    // endpoint, inbound/outbound Iroh work and active HTTP responses all stop
    // inside the same absolute shutdown deadline. A pure HTTP daemon retains a
    // standalone RAII supervisor for the same no-detach property.
    let standalone_http_supervisor = iroh_node.is_none().then(TaskSupervisor::new);
    let http_supervisor = iroh_node
        .as_ref()
        .map(IrohNode::task_supervisor_handle)
        .or_else(|| {
            standalone_http_supervisor
                .as_ref()
                .map(TaskSupervisor::handle)
        })
        .expect("one HTTP task supervisor is always constructed");

    let mut success = true;
    let publication_health = iroh_node
        .as_ref()
        .and_then(IrohNode::node_publication_handle);
    tokio::select! {
        result = serve(listener, app, http_supervisor) => {
            match result {
                Ok(()) => println!("daemon: HTTP serve loop ended"),
                Err(error) => {
                    eprintln!("daemon: serve error: {error}");
                    success = false;
                }
            }
        }
        signal = shutdown_signals.recv() => {
            match signal {
                Ok(signal) => println!("daemon: received {signal}; shutting down"),
                Err(error) => {
                    eprintln!("daemon: shutdown signal error: {error}");
                    success = false;
                }
            }
        }
        error = wait_for_publication_fatal(publication_health) => {
            eprintln!("daemon: fatal Iroh node-publication health failure: {error}");
            success = false;
        }
    }
    if let Some(supervisor) = &standalone_http_supervisor {
        supervisor.cancel_now();
    }
    success &= shutdown_iroh_node(iroh_node).await;
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_names_this_crate_and_a_version() {
        let text = banner();
        assert!(
            text.starts_with("daemon "),
            "banner must lead with the crate name, got {text:?}"
        );
        let version = text.strip_prefix("daemon ").expect("prefix checked above");
        assert!(
            version.split('.').count() >= 3,
            "expected a semver-ish version, got {version:?}"
        );
    }

    #[test]
    fn parses_all_flags() {
        let config = Config::from_args(
            [
                "--listen",
                "127.0.0.1:9000",
                "--upstream",
                "http://example:80",
                "--store-dir",
                "/nix/store",
                "--priority",
                "25",
                "--want-mass-query",
                "0",
                "--header-timeout-ms",
                "250",
            ]
            .map(String::from),
        )
        .unwrap();
        assert_eq!(config.listen.port(), 9000);
        assert_eq!(config.upstream, "http://example:80");
        assert_eq!(config.priority, 25);
        assert!(!config.want_mass_query);
        assert_eq!(config.header_timeout_ms, 250);
    }

    #[test]
    fn unknown_flag_fails_fast() {
        assert!(Config::from_args(["--nope".to_string()]).is_err());
        assert!(Config::from_args(["--listen".to_string()]).is_err());
        assert!(Config::from_args(["--priority".to_string(), "abc".to_string()]).is_err());
    }

    #[test]
    fn header_timeout_zero_is_rejected() {
        // 0 ms bricks the daemon (every request 502s before any upstream answer);
        // reject at parse rather than start a bricked-but-healthy-looking daemon.
        assert!(
            Config::from_args(["--header-timeout-ms".to_string(), "0".to_string()]).is_err(),
            "0 must be rejected"
        );
        // Absurd (units typo) is rejected too; a sane value is accepted.
        assert!(
            Config::from_args(["--header-timeout-ms".to_string(), "9999999".to_string()]).is_err()
        );
        assert_eq!(
            Config::from_args(["--header-timeout-ms".to_string(), "500".to_string()])
                .unwrap()
                .header_timeout_ms,
            500
        );
    }

    #[test]
    fn default_config_advertises_a_preferred_priority() {
        assert!(Config::default().priority < 40);
    }

    // A valid 64-hex NodeId (parse is hex-only; the ed25519 curve check lives at
    // the dial boundary) and a 64-hex blake3, for the config-parse tests.
    const NODE_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BLAKE3_HEX: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NARHASH: &str = "sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb";

    #[test]
    fn parse_peer_spec_accepts_node_and_one_or_more_sockets() {
        let spec = parse_peer_spec(&format!("{NODE_HEX}@127.0.0.1:35766")).unwrap();
        assert_eq!(spec.sockets.len(), 1);
        let multi = parse_peer_spec(&format!("{NODE_HEX}@127.0.0.1:1,127.0.0.1:2")).unwrap();
        assert_eq!(multi.sockets.len(), 2);
        // The parsed node round-trips to the same 64-hex id.
        assert_eq!(spec.node.to_hex(), NODE_HEX);
    }

    #[test]
    fn parse_peer_spec_fails_fast_on_malformed_input() {
        // No '@'; a non-hex node; a garbage socket; an empty socket list.
        assert!(parse_peer_spec("no-at-sign").is_err());
        assert!(parse_peer_spec("zzzz@127.0.0.1:1").is_err());
        assert!(parse_peer_spec(&format!("{NODE_HEX}@not-a-socket")).is_err());
        assert!(parse_peer_spec(&format!("{NODE_HEX}@")).is_err());
    }

    #[test]
    fn parse_claim_spec_accepts_narhash_blake3_node() {
        let spec = parse_claim_spec(&format!("{NARHASH}={BLAKE3_HEX}@{NODE_HEX}")).unwrap();
        assert_eq!(spec.nar_hash, NARHASH);
        assert_eq!(spec.node.to_hex(), NODE_HEX);
        assert_eq!(spec.blake3.to_hex(), BLAKE3_HEX);
    }

    #[test]
    fn parse_claim_spec_fails_fast_on_malformed_input() {
        // Missing '='; missing '@'; a non-canonical NarHash; a short blake3; a bad node.
        assert!(parse_claim_spec("no-equals").is_err());
        assert!(parse_claim_spec(&format!("{NARHASH}={BLAKE3_HEX}")).is_err());
        assert!(parse_claim_spec(&format!("not-a-narhash={BLAKE3_HEX}@{NODE_HEX}")).is_err());
        assert!(parse_claim_spec(&format!("{NARHASH}=dead@{NODE_HEX}")).is_err());
        assert!(parse_claim_spec(&format!("{NARHASH}={BLAKE3_HEX}@zzzz")).is_err());
    }

    #[test]
    fn parse_libp2p_peer_round_trips_peerid_and_multiaddr() {
        let peer = PeerId::random();
        let raw = format!("{peer}@/ip4/127.0.0.1/tcp/4001");
        let (parsed_peer, addr) = parse_libp2p_peer("--libp2p-bootstrap", &raw).unwrap();
        assert_eq!(parsed_peer, peer, "PeerId round-trips through base58 parse");
        assert_eq!(addr.to_string(), "/ip4/127.0.0.1/tcp/4001");
    }

    #[test]
    fn parse_libp2p_peer_fails_fast_on_malformed_input() {
        // No '@'; a non-base58 PeerId; a garbage multiaddr.
        assert!(parse_libp2p_peer("--libp2p-bootstrap", "no-at-sign").is_err());
        assert!(parse_libp2p_peer("--libp2p-bootstrap", "notapeer@/ip4/127.0.0.1/tcp/1").is_err());
        let peer = PeerId::random();
        assert!(
            parse_libp2p_peer("--libp2p-bootstrap", &format!("{peer}@not-a-multiaddr")).is_err()
        );
    }

    #[test]
    fn parse_libp2p_seed_requires_exactly_64_hex() {
        assert_eq!(parse_libp2p_seed(&"ab".repeat(32)).unwrap(), [0xabu8; 32]);
        assert!(parse_libp2p_seed("abcd").is_err(), "short seed rejected");
        assert!(
            parse_libp2p_seed(&"zz".repeat(32)).is_err(),
            "non-hex rejected"
        );
    }

    #[test]
    fn parses_libp2p_flags_and_resolves_source_config() {
        let peer = PeerId::random();
        let prov = PeerId::random();
        let config = Config::from_args(vec![
            "--libp2p-bootstrap".to_string(),
            format!("{peer}@/ip4/127.0.0.1/tcp/4001"),
            "--libp2p-provider-addr".to_string(),
            format!("{prov}@/ip4/127.0.0.1/tcp/4002"),
            "--libp2p-listen".to_string(),
            "/ip4/0.0.0.0/tcp/0".to_string(),
            "--libp2p-scope".to_string(),
            "task162".to_string(),
            "--libp2p-identity-seed".to_string(),
            "11".repeat(32),
        ])
        .unwrap();
        assert!(config.libp2p_requested());
        assert_eq!(config.libp2p_bootstrap.len(), 1);
        assert_eq!(config.libp2p_provider_addrs.len(), 1);
        assert_eq!(config.libp2p_scope.as_deref(), Some("task162"));
        assert_eq!(config.libp2p_identity_seed, Some([0x11u8; 32]));

        // The production source config resolves the seed + scope the builder consumes.
        let src = config.libp2p_source_config().unwrap();
        assert_eq!(src.identity_seed, [0x11u8; 32]);
        assert_eq!(src.network_scope, "task162");
        assert_eq!(src.bootstrap.len(), 1);
        assert_eq!(src.provider_addrs.len(), 1);
        assert!(src.listen.is_some());
    }

    #[test]
    fn libp2p_flag_without_bootstrap_fails_fast() {
        // A consumer that can never discover anyone is a silently-useless config.
        let err = Config::from_args(vec![
            "--libp2p-listen".to_string(),
            "/ip4/0.0.0.0/tcp/0".to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("libp2p-bootstrap"), "got {err}");
    }

    #[test]
    fn parse_libp2p_seed_nar_splits_narhash_and_path() {
        // A canonical Nix NarHash (sha256:<nix-base32>) + a file path.
        let nar_hash = NarHashKey::from_sha256_bytes([0x33u8; 32]);
        let raw = format!("{nar_hash}=/srv/seed/a.nar");
        let (key, path) = parse_libp2p_seed_nar(&raw).unwrap();
        assert_eq!(key, nar_hash);
        assert_eq!(path, "/srv/seed/a.nar");
        // A path can legitimately contain '=' (only the FIRST '=' splits).
        let raw2 = format!("{nar_hash}=/srv/a=b.nar");
        assert_eq!(parse_libp2p_seed_nar(&raw2).unwrap().1, "/srv/a=b.nar");
        // Missing '=', a bad NarHash, and an empty path are all rejected (fail fast).
        assert!(parse_libp2p_seed_nar("no-equals").is_err());
        assert!(parse_libp2p_seed_nar("not-a-narhash=/x.nar").is_err());
        assert!(parse_libp2p_seed_nar(&format!("{nar_hash}=")).is_err());
    }

    #[test]
    fn parses_libp2p_provider_flags() {
        let peer = PeerId::random();
        let nar_hash = NarHashKey::from_sha256_bytes([0x33u8; 32]);
        let config = Config::from_args(vec![
            "--libp2p-provider".to_string(),
            "--libp2p-bootstrap".to_string(),
            format!("{peer}@/ip4/127.0.0.1/tcp/4001"),
            "--libp2p-listen".to_string(),
            "/ip4/0.0.0.0/tcp/0".to_string(),
            "--libp2p-seed-nar".to_string(),
            format!("{nar_hash}=/srv/seed/a.nar"),
            "--libp2p-print-peer-address".to_string(),
        ])
        .unwrap();
        assert!(config.libp2p_provider);
        assert!(config.libp2p_requested());
        assert!(config.libp2p_print_peer_address);
        assert_eq!(config.libp2p_seed_nar.len(), 1);
        assert_eq!(config.libp2p_seed_nar[0].0, nar_hash);
        assert_eq!(config.libp2p_seed_nar[0].1, "/srv/seed/a.nar");
    }

    #[test]
    fn libp2p_provider_companions_require_the_mode_switch() {
        // --libp2p-seed-nar without --libp2p-provider is inert -> rejected.
        let nar_hash = NarHashKey::from_sha256_bytes([0x33u8; 32]);
        let peer = PeerId::random();
        let err = Config::from_args(vec![
            "--libp2p-bootstrap".to_string(),
            format!("{peer}@/ip4/127.0.0.1/tcp/4001"),
            "--libp2p-seed-nar".to_string(),
            format!("{nar_hash}=/srv/seed/a.nar"),
        ])
        .unwrap_err();
        assert!(err.contains("--libp2p-provider"), "got {err}");
    }

    #[test]
    fn libp2p_provider_requires_a_seed_and_a_listener() {
        let peer = PeerId::random();
        // Provider with no seed: a no-op provider.
        let err = Config::from_args(vec![
            "--libp2p-provider".to_string(),
            "--libp2p-bootstrap".to_string(),
            format!("{peer}@/ip4/127.0.0.1/tcp/4001"),
            "--libp2p-listen".to_string(),
            "/ip4/0.0.0.0/tcp/0".to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("--libp2p-seed-nar"), "got {err}");

        // Provider with a seed but no listener: cannot be dialed.
        let nar_hash = NarHashKey::from_sha256_bytes([0x33u8; 32]);
        let err = Config::from_args(vec![
            "--libp2p-provider".to_string(),
            "--libp2p-bootstrap".to_string(),
            format!("{peer}@/ip4/127.0.0.1/tcp/4001"),
            "--libp2p-seed-nar".to_string(),
            format!("{nar_hash}=/srv/seed/a.nar"),
        ])
        .unwrap_err();
        assert!(err.contains("--libp2p-listen"), "got {err}");
    }

    #[test]
    fn libp2p_scope_defaults_to_v1_when_omitted() {
        let peer = PeerId::random();
        let config = Config::from_args(vec![
            "--libp2p-bootstrap".to_string(),
            format!("{peer}@/ip4/127.0.0.1/tcp/4001"),
        ])
        .unwrap();
        let src = config.libp2p_source_config().unwrap();
        assert_eq!(src.network_scope, "v1", "default scope");
        // Omitted seed is filled by a fresh /dev/urandom one (not a fixed default).
        assert_ne!(src.identity_seed, [0u8; 32]);
        // The PRODUCTION default budget/envelope must be non-degenerate (a zero deadline
        // or peer cap would make the binary's libp2p source silently answer nothing).
        assert!(src.discovery_budget.deadline > std::time::Duration::ZERO);
        assert!(src.discovery_budget.max_peers > 0);
        assert!(src.envelope.total_timeout > std::time::Duration::ZERO);
    }

    #[test]
    fn libp2p_source_config_is_idempotent_in_identity() {
        // Two builds of the config yield the SAME identity (the seed is resolved ONCE in
        // from_args, not minted per call) - the SSOT/idempotency fix.
        let peer = PeerId::random();
        let config = Config::from_args(vec![
            "--libp2p-bootstrap".to_string(),
            format!("{peer}@/ip4/127.0.0.1/tcp/4001"),
        ])
        .unwrap();
        let a = config.libp2p_source_config().unwrap();
        let b = config.libp2p_source_config().unwrap();
        assert_eq!(
            a.identity_seed, b.identity_seed,
            "one config -> one identity"
        );
    }

    // ---- compose_nar_chain precedence oracle (bites by mutation) -------------
    // A fake NarSource that either ANSWERS (Ok, body = its tag) or MISSES
    // (Unreachable, so FallbackNarSource falls through to the next layer).
    struct TaggedSource {
        tag: &'static str,
        answer: bool,
    }

    #[async_trait::async_trait]
    impl daemon::NarSource for TaggedSource {
        async fn resolve(
            &self,
            _key: &daemon::NarKey,
            _expected_size: Option<u64>,
        ) -> Result<daemon::UpstreamResponse, daemon::SourceError> {
            use http_body_util::{BodyExt, Full};
            if self.answer {
                Ok(daemon::UpstreamResponse {
                    status: 200,
                    headers: http::HeaderMap::new(),
                    body: Full::new(bytes::Bytes::from_static(self.tag.as_bytes()))
                        .map_err(|never| match never {})
                        .boxed(),
                })
            } else {
                Err(daemon::SourceError::Unreachable(format!(
                    "{} miss",
                    self.tag
                )))
            }
        }
    }

    async fn answering_layer(chain: &Arc<dyn NarSource>) -> String {
        let key = daemon::NarKey::UpstreamPath(daemon::NarPathToken::new("probe.nar"));
        let resp = chain.resolve(&key, None).await.expect("some layer answers");
        let bytes = http_body_util::BodyExt::collect(resp.body)
            .await
            .expect("body collects")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("tag is utf8")
    }

    fn tagged(tag: &'static str, answer: bool) -> Arc<dyn NarSource> {
        Arc::new(TaggedSource { tag, answer })
    }

    #[tokio::test]
    async fn compose_nar_chain_precedence_libp2p_then_iroh_then_upstream() {
        // All three present, all would answer: libp2p (primary) wins. Swapping the two
        // layer blocks in compose_nar_chain flips this to "iroh" - the mutation bites.
        let chain = compose_nar_chain(
            Some(tagged("libp2p", true)),
            Some(tagged("iroh", true)),
            tagged("upstream", true),
        );
        assert_eq!(answering_layer(&chain).await, "libp2p");

        // libp2p MISSES -> falls through to iroh (NOT straight to upstream).
        let chain = compose_nar_chain(
            Some(tagged("libp2p", false)),
            Some(tagged("iroh", true)),
            tagged("upstream", true),
        );
        assert_eq!(answering_layer(&chain).await, "iroh");

        // libp2p and iroh both MISS -> HTTP upstream (the S2 tail).
        let chain = compose_nar_chain(
            Some(tagged("libp2p", false)),
            Some(tagged("iroh", false)),
            tagged("upstream", true),
        );
        assert_eq!(answering_layer(&chain).await, "upstream");
    }

    #[tokio::test]
    async fn compose_nar_chain_each_layer_optional_and_additive() {
        // libp2p-only (no iroh): libp2p primary, upstream tail; iroh layer absent.
        let chain = compose_nar_chain(Some(tagged("libp2p", true)), None, tagged("upstream", true));
        assert_eq!(answering_layer(&chain).await, "libp2p");
        let chain = compose_nar_chain(
            Some(tagged("libp2p", false)),
            None,
            tagged("upstream", true),
        );
        assert_eq!(answering_layer(&chain).await, "upstream");

        // iroh-only (no libp2p): the pre-existing iroh path is untouched/additive.
        let chain = compose_nar_chain(None, Some(tagged("iroh", true)), tagged("upstream", true));
        assert_eq!(answering_layer(&chain).await, "iroh");

        // Neither: bare HTTP upstream.
        let chain = compose_nar_chain(None, None, tagged("upstream", true));
        assert_eq!(answering_layer(&chain).await, "upstream");
    }

    #[test]
    fn parses_p2p_flags() {
        let config = Config::from_args(
            [
                "--iroh-provider",
                "--iroh-state-dir",
                "/var/lib/nix-p2p/iroh",
                "--iroh-endpoint-scope",
                "offline-test",
                "--iroh-port",
                "41001",
                "--iroh-seed-nar",
                "/srv/seed/a.nar",
                "--iroh-peer",
                &format!("{NODE_HEX}@127.0.0.1:35766"),
                "--p2p-claim",
                &format!("{NARHASH}={BLAKE3_HEX}@{NODE_HEX}"),
            ]
            .map(String::from),
        )
        .unwrap();
        assert!(config.iroh_provider);
        assert_eq!(
            config.iroh_state_dir,
            Some(PathBuf::from("/var/lib/nix-p2p/iroh"))
        );
        assert_eq!(
            config.iroh_endpoint_scope,
            Some(EndpointScope::OfflineTest { port: 0 })
        );
        assert_eq!(config.iroh_port, Some(41001));
        assert_eq!(config.iroh_seed_nar, vec!["/srv/seed/a.nar".to_string()]);
        assert_eq!(config.iroh_peers.len(), 1);
        assert_eq!(config.p2p_claims.len(), 1);
    }

    #[test]
    fn endpoint_scope_parser_covers_closed_offline_lan_and_global_variants() {
        assert_eq!(
            parse_iroh_endpoint_scope("offline-test").unwrap(),
            EndpointScope::OfflineTest { port: 0 }
        );
        assert_eq!(
            parse_iroh_endpoint_scope("lan:192.0.2.4,2001:db8::4").unwrap(),
            EndpointScope::Lan {
                ipv4: "192.0.2.4".parse().unwrap(),
                ipv6: Some("2001:db8::4".parse().unwrap()),
                port: 0,
            }
        );
        assert_eq!(
            parse_iroh_endpoint_scope("global").unwrap(),
            EndpointScope::Global { port: 0 }
        );
        assert!(parse_iroh_endpoint_scope("lan:").is_err());
        assert!(parse_iroh_endpoint_scope("lan:127.0.0.1,::1,extra").is_err());
        assert!(parse_iroh_endpoint_scope("n0").is_err());
        assert_eq!(
            endpoint_scope_with_port(EndpointScope::Global { port: 0 }, 41002),
            EndpointScope::Global { port: 41002 }
        );
    }

    #[test]
    fn configured_iroh_requires_a_nonzero_fixed_port() {
        assert!(
            Config::from_args(["--iroh-provider".into(), "--iroh-port".into(), "0".into()])
                .unwrap_err()
                .contains("must be 1..=65535")
        );
        assert!(
            Config::from_args(["--iroh-provider".into()])
                .unwrap_err()
                .contains("--iroh-port")
        );
    }

    #[test]
    fn node_publication_is_default_off_and_companions_are_inert_without_switch() {
        let config = Config::from_args(Vec::<String>::new()).unwrap();
        assert!(!config.iroh_publish_node);
        assert!(config.iroh_publication_namespace.is_none());
        assert!(config.iroh_publication_recipient.is_none());
        assert!(config.iroh_publication_authority_socket.is_none());
        assert!(config.iroh_publication_authority_host.is_none());
        assert!(config.iroh_publication_owner.is_none());
        assert!(config.iroh_publication_locations.is_empty());

        for (flag, value) in [
            ("--iroh-publication-namespace", "run-1"),
            ("--iroh-publication-recipient", "authority.test:v1"),
            ("--iroh-publication-authority-socket", "127.0.0.1:8080"),
            ("--iroh-publication-authority-host", "authority.test"),
            ("--iroh-publication-owner", "operator"),
            ("--iroh-publication-external-authorization", "ticket-1"),
            ("--iroh-publication-address", "127.0.0.1:4433"),
            ("--iroh-publication-relay", "https://relay.example"),
            ("--iroh-publication-ttl-seconds", "30"),
            ("--iroh-publication-refresh-seconds", "10"),
        ] {
            let error = Config::from_args([flag.to_string(), value.to_string()]).unwrap_err();
            assert!(error.contains("require explicit --iroh-publish-node"));
        }
    }

    #[test]
    fn node_publication_flags_parse_only_as_an_explicit_complete_capability() {
        let config = Config::from_args(
            [
                "--iroh-publish-node",
                "--iroh-port",
                "41003",
                "--iroh-publication-namespace",
                "run-1",
                "--iroh-publication-recipient",
                "authority.test:v1",
                "--iroh-publication-authority-socket",
                "127.0.0.1:8080",
                "--iroh-publication-authority-host",
                "authority.test",
                "--iroh-publication-owner",
                "operator",
                "--iroh-publication-address",
                "127.0.0.1:4433",
                "--iroh-publication-ttl-seconds",
                "30",
                "--iroh-publication-refresh-seconds",
                "10",
            ]
            .map(String::from),
        )
        .unwrap();
        assert!(config.iroh_publish_node);
        assert_eq!(config.iroh_port, Some(41003));
        assert_eq!(config.iroh_publication_locations.len(), 1);
        assert_eq!(config.iroh_publication_ttl_seconds, Some(30));
        assert_eq!(config.iroh_publication_refresh_seconds, Some(10));

        assert!(
            Config::from_args(
                [
                    "--iroh-publish-node",
                    "--iroh-publish-node",
                    "--iroh-port",
                    "41003"
                ]
                .map(String::from)
            )
            .unwrap_err()
            .contains("duplicate --iroh-publish-node")
        );
    }

    #[test]
    fn node_lookup_is_default_off_and_companion_flags_are_inert_without_switch() {
        let config = Config::from_args(Vec::<String>::new()).unwrap();
        assert!(!config.iroh_enable_node_lookup);
        assert!(config.iroh_lookup_namespace.is_none());
        assert!(config.iroh_lookup_recipient.is_none());
        assert!(config.iroh_lookup_authority_socket.is_none());
        assert!(config.iroh_lookup_authority_host.is_none());
        assert!(config.iroh_lookup_owner.is_none());
        for (flag, value) in [
            ("--iroh-lookup-namespace", "run-1"),
            ("--iroh-lookup-recipient", "authority.test:v1"),
            ("--iroh-lookup-authority-socket", "127.0.0.1:8080"),
            ("--iroh-lookup-authority-host", "authority.test"),
            ("--iroh-lookup-owner", "operator"),
            ("--iroh-lookup-external-authorization", "ticket-1"),
        ] {
            let error = Config::from_args([flag.to_string(), value.to_string()]).unwrap_err();
            assert!(error.contains("require explicit --iroh-enable-node-lookup"));
        }
    }

    #[test]
    fn node_lookup_flags_parse_only_as_one_explicit_capability() {
        let config = Config::from_args(
            [
                "--iroh-enable-node-lookup",
                "--iroh-port",
                "41004",
                "--iroh-lookup-namespace",
                "run-1",
                "--iroh-lookup-recipient",
                "authority.test:v1",
                "--iroh-lookup-authority-socket",
                "127.0.0.1:8080",
                "--iroh-lookup-authority-host",
                "authority.test",
                "--iroh-lookup-owner",
                "operator",
            ]
            .map(String::from),
        )
        .unwrap();
        assert!(config.iroh_enable_node_lookup);
        assert_eq!(config.iroh_port, Some(41004));
        assert_eq!(config.iroh_lookup_namespace.as_deref(), Some("run-1"));
        assert_eq!(
            config.iroh_lookup_authority_socket,
            Some("127.0.0.1:8080".parse().unwrap())
        );
        assert!(
            Config::from_args(
                [
                    "--iroh-enable-node-lookup",
                    "--iroh-enable-node-lookup",
                    "--iroh-port",
                    "41004"
                ]
                .map(String::from)
            )
            .unwrap_err()
            .contains("duplicate --iroh-enable-node-lookup")
        );
    }

    #[tokio::test]
    async fn configured_iroh_refuses_implicit_identity_or_bind_scope() {
        let missing_both = Config {
            iroh_provider: true,
            ..Config::default()
        };
        let error = setup_iroh_node(&missing_both)
            .await
            .err()
            .expect("configured Iroh must reject an ephemeral identity");
        assert!(error.contains("--iroh-state-dir"), "got {error}");

        let missing_scope = Config {
            iroh_provider: true,
            iroh_state_dir: Some(PathBuf::from("/unused/identity/state")),
            ..Config::default()
        };
        let error = setup_iroh_node(&missing_scope)
            .await
            .err()
            .expect("configured Iroh must reject an implicit bind scope");
        assert!(error.contains("--iroh-endpoint-scope"), "got {error}");
    }

    #[test]
    fn the_serve_budget_defaults_are_the_library_constants() {
        // The daemon must not carry a SECOND copy of the numbers the library
        // documents and the tests reason about. If these ever diverge, an operator
        // reading the constants would be reading a different bound than the one
        // running.
        let config = Config::default();
        assert_eq!(config.iroh_max_serve_nar_bytes, DEFAULT_MAX_SERVE_NAR_BYTES);
        assert_eq!(
            config.iroh_max_inflight_nar_bytes,
            DEFAULT_MAX_INFLIGHT_NAR_BYTES
        );
        // The per-NAR default must fit under the in-flight default, or the second
        // bound could never bind and one of the two knobs would be decorative.
        assert!(config.iroh_max_serve_nar_bytes < config.iroh_max_inflight_nar_bytes);
    }

    #[test]
    fn serve_budget_flags_parse_and_reject_zero() {
        let config = Config::from_args(
            [
                "--iroh-max-serve-nar-bytes",
                "1048576",
                "--iroh-max-inflight-nar-bytes",
                "4194304",
                "--iroh-sweep-interval-ms",
                "250",
            ]
            .map(String::from),
        )
        .unwrap();
        assert_eq!(config.iroh_max_serve_nar_bytes, 1_048_576);
        assert_eq!(config.iroh_max_inflight_nar_bytes, 4_194_304);
        assert_eq!(config.iroh_sweep_interval_ms, 250);

        // 0 is rejected on every one of them. A zero serve budget declines every
        // peer and a zero sweep interval spins the collector: both are daemons
        // that look healthy and do nothing, the same failure `--header-timeout-ms
        // 0` is rejected for.
        for flag in [
            "--iroh-max-serve-nar-bytes",
            "--iroh-max-inflight-nar-bytes",
            "--iroh-sweep-interval-ms",
        ] {
            assert!(
                Config::from_args([flag.to_string(), "0".to_string()]).is_err(),
                "{flag} 0 must be rejected"
            );
            assert!(
                Config::from_args([flag.to_string(), "not-a-number".to_string()]).is_err(),
                "{flag} must fail fast on a non-number"
            );
        }
    }
}
