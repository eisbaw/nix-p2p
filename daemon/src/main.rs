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
    AddressLookupCapability, AllowlistRawServe, AnyRawServe, App, AvailabilityIndex, Blake3Digest,
    CONNECT_TIMEOUT_MS, CacheInfo, Claim, CommandNarDumper, ContractRequest, CorrelationStore,
    DEFAULT_MAX_INFLIGHT_NAR_BYTES, DEFAULT_MAX_SERVE_DURATION, DEFAULT_MAX_SERVE_NAR_BYTES,
    DhtRole, EndpointProfile, EndpointScope, FallbackNarSource, FileNarSupplier, HEADER_TIMEOUT_MS,
    IdentitySource, InMemoryDiscovery, InitialAnnounceConfig, IrohNode, IrohNodeBuilder,
    IrohPeerAddr, IrohProviderConfig, IrohTransport, KnownPayload, KnownTransport,
    LAN_SHARE_SCOPE_HINT, LanReachability, LanShare, Libp2pCatalogProbe, Libp2pSourceConfig,
    Mechanism, NARINFO_CACHE_FLAG_CONFLICT, NarCatalog, NarDumper, NarHashKey, NarSource,
    NarinfoLayer, NarinfoSource, NoRawServe, NodeId, NodeLocation,
    NodeLookupAuthorityAuthorization, NodeLookupConfig, NodePublicationCapability,
    NodePublicationConfig, NodePublicationHandle, NullAnnounce, NullStore, OperatorContract,
    PassThroughReason, PrivacyPolicy, PublicNarAllowlist, PublicationAuthorityAuthorization,
    PublicationPlan, RawServeDecision, RelayCapability, ResourceCaps, ServeBudget, SharingProfile,
    StorePath, StoreProvision, SystemClock, TaskSupervisor, TransportNarSource, TransportRegistry,
    UpstreamHttp, announce_provider_seeds, announce_public_provisions, announce_public_seeds,
    announce_store_provisions, build_libp2p_nar_source, build_libp2p_provider_source,
    build_narinfo_layer, disclose_then_activate_serve, effective_network_scope,
    lan_isolation_or_refuse, lan_serving_disclosures, resolve_durable_identity_seed,
    resolve_narinfo_cache_dir, serve, should_hint_lan_share_scope, verify_store_provisions,
};
use fabric_libp2p::{
    CatalogNarSupplier, Libp2pFabric, Libp2pNarSupplier, MemoryNarSupplier, Multiaddr, PeerId,
    UnionNarSupplier,
};
use peer_fabric::{AnnounceBudget, Axis, LeechFabric, PeerFabric, ServeHandle, require_axes};
use tokio::net::TcpListener;

/// TASK-273 (#8): `--libp2p-mdns` and `--libp2p-no-mdns` are contradictory; passing both is
/// ambiguous, so `Config::from_args` fails closed with this message rather than silently last-wins.
/// Kept verbatim-equal to daemon-libp2p's `LIBP2P_MDNS_FLAG_CONTRADICTION` so the two binaries speak
/// one operator surface.
const LIBP2P_MDNS_FLAG_CONTRADICTION: &str =
    "pass exactly one of --libp2p-mdns / --libp2p-no-mdns, not both (contradictory mDNS intent)";

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

/// Parse `--libp2p-prove-public-narinfo <requested-store-hash>=<path/to/narinfo>`: the store
/// hash the narinfo must correlate to (its signed StorePath's `<hash>`) and the narinfo file to
/// prove public. The store hash is not parsed to a strict type here (it is an opaque correlation
/// token the allowlist compares against the signed StorePath); only its non-emptiness is checked.
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
    /// Explicit opt-out of the narinfo disk cache (`--no-narinfo-cache`, TASK-29).
    /// The cache is ON BY DEFAULT (a default XDG state dir is resolved when
    /// `narinfo_cache_dir` is unset); this flag turns it fully off. Passing both
    /// `--narinfo-cache-dir` and `--no-narinfo-cache` is a contradictory-usage
    /// error, rejected before the cache is constructed.
    no_narinfo_cache: bool,
    /// Per-hop upstream header timeout in milliseconds (default
    /// [`HEADER_TIMEOUT_MS`] = 15000; TASK-111 raised it from a WAN-hostile 1000).
    /// Bounds the wait for RESPONSE HEADERS after connect - the upstream's own work
    /// (a cache-miss, a loaded/distant host) - so a slow-but-HEALTHY upstream is not
    /// 502'd as if dead. Exposed so the fault x depth matrix (task-13) can move the
    /// 200->502 latency ceiling deliberately and so an operator can tune it. It seeds
    /// a per-hop deadline that does NOT depth-compose across a daemon chain (task-33);
    /// see `UpstreamHttp::with_header_timeout`.
    header_timeout_ms: u64,
    /// Per-hop plaintext CONNECT timeout in milliseconds (default
    /// [`CONNECT_TIMEOUT_MS`] = 1000; TASK-111 AC#2). DISTINCT from the header
    /// timeout - this is the fast-fail-against-a-DEAD upstream bound (~1 RTT to reach
    /// the host), kept TIGHT so a down upstream 502s fast and Nix falls back. Governs
    /// ONLY the plaintext transport (the TLS connect stage is the frozen
    /// `tls-upstream-v1` budget). Newly operator-tunable; see
    /// `UpstreamHttp::with_connect_timeout`.
    connect_timeout_ms: u64,
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
    /// TASK-257: `--libp2p-mdns` opts into LAN mDNS peer-ADDRESS discovery (DEFAULT OFF). When set,
    /// a same-scope LAN neighbour is discovered with NO `--libp2p-bootstrap`; discovered addresses
    /// feed the SAME kad bootstrap path and NEVER content discovery. It is TASK-120 axis-1 (local
    /// discovery) only. As an entry path to the DHT it satisfies the bootstrap requirement for a
    /// consumer, exactly like an explicit bootstrap peer.
    libp2p_mdns: bool,
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
    /// Real `/nix/store` paths this node SERVES on demand via `nix-store --dump` and ANNOUNCES
    /// over libp2p (`<narhash>=<storepath>`, repeatable), holding NO .nar at rest (TASK-191).
    /// The announce is verification-gated by the availability index (TASK-56); mutually
    /// exclusive with `--libp2p-seed-nar` in one provider (MVP).
    libp2p_provide_store: Vec<(NarHashKey, String)>,
    /// Print the provider's `PeerId` + bound listen multiaddr(s) on startup
    /// (`LIBP2P-PROVIDER-ADDR ...`), so a harness can wire another daemon's
    /// `--libp2p-bootstrap <PeerId>@<multiaddr>` to this provider. Like
    /// `--iroh-print-peer-address`.
    libp2p_print_peer_address: bool,
    /// Per-node durable state directory (TASK-185): when set, the libp2p fabric persists its
    /// anti-rollback floor + per-key announce sequence here and re-seeds them on restart.
    libp2p_state_dir: Option<std::path::PathBuf>,
    // ---- libp2p PUBLIC-announce allowlist config (TASK-103) -----------------
    // Setting `--libp2p-public-allowlist-path` puts a PROVIDER into PUBLIC-announce mode: its
    // seeds/store paths are announced over a (bootstrapped) public substrate ONLY after each is
    // proven public through a trusted narinfo signature (the allowlist is the enforcement,
    // replacing the isolated-LAN `lan_share_or_refuse` stopgap for the bootstrapped case).
    /// Trusted narinfo-signing keys in the Nix `trusted-public-keys` format
    /// (`name:<base64 ed25519 pubkey>`, repeatable). A NAR is proven public only by a signature
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
    /// ANNOUNCE-AFTER-FETCH (TASK-77): when set, a successful peer/upstream fetch makes this node
    /// a discoverable HOLDER for that path (register the realised `/nix/store` path + announce it
    /// through the verification-gated + eligibility-gated provider door), so the swarm GROWS. It
    /// puts the node into provider mode (serve axis + announcer) even with an EMPTY initial supply
    /// set. DEFAULT OFF = consume-only / leech (TASK-78): fetch without ever revealing what you
    /// fetched. Public-substrate use REQUIRES `--libp2p-public-allowlist-path` (only allowlisted
    /// content is announced); an isolated-LAN node uses the `lan_share_or_refuse` witness.
    libp2p_announce_after_fetch: bool,
    /// The INTEGER announce-after-fetch BUDGET (TASK-77 AC#2): the maximum number of DISTINCT
    /// fetched paths this process announces. Past it, announcing STOPS (the guardrail against
    /// unbounded self-DoS + the privacy surface). A plain integer, never a float.
    libp2p_announce_budget: u64,
    /// LEECH / consume-only mode (TASK-78): an affirmative opt-out of contributing uplink. A leech
    /// still FETCHES from peers, but its fabric is wrapped in a [`peer_fabric::LeechFabric`] so the
    /// SERVE and ANNOUNCE axes are masked to `None` at the transport-agnostic capability seam - it
    /// serves nothing and announces nothing. Mutually exclusive with every provider/serve flag,
    /// enforced fail-fast. HONEST LIMIT: a leech still SENDS its discovery lookups (get_record /
    /// peer-routing), so it hides what it serves and announces, NOT what it looks up. Mirrors the
    /// thin `daemon-libp2p` binary so the two cannot drift.
    libp2p_leech: bool,
    /// TASK-120 AC#7: `--preflight` renders the one-command operator preflight (selected profile,
    /// enabled/pending mechanism registry, dependencies, effective integer resource + privacy
    /// controls) and EXITS before any socket bind or P2P traffic. A pure static contract read.
    preflight: bool,
    /// TASK-120 AC#5: `--diagnostics` opts into verbose diagnostics that MAY include otherwise
    /// redacted identifiers. DEFAULT OFF; when set the node prints the mandatory privacy banner.
    diagnostics: bool,
    /// TASK-120 (compat shim): the operator's EXPLICIT `--profile <token>` declaration, if given.
    /// The give/consume flags must DERIVE the same profile, else `derive_contract` fails closed.
    explicit_profile: Option<String>,
}

/// The default announce-after-fetch budget: distinct paths a process announces before growth
/// stops. Conservative (a swarm-growth cap, not a throughput target); an operator raises it with
/// `--libp2p-announce-budget`. Sourced from the ONE authoritative [`ResourceCaps`] (TASK-120
/// AC#9) so it cannot drift from the documented operator contract or the thin `daemon-libp2p`.
fn default_libp2p_announce_budget() -> u64 {
    ResourceCaps::default().announce_distinct_paths_budget
}

/// Is the composite daemon's legacy iroh GIVE-SIDE active (serving or publishing over iroh)?
/// The iroh transport is DEFERRED (prune-pending TASK-202); when it is active it is reported as an
/// ACTIVE deferred-reference mechanism, and its reachability is safety-gated (#3a).
fn iroh_give_side_active(config: &Config) -> bool {
    config.iroh_provider || config.iroh_publish_node
}

/// Is the composite daemon's legacy iroh CONSUME side active (fetching over iroh)? TASK-120 fix B:
/// a node given `--iroh-peer` and/or `--p2p-claim` starts an iroh transport and FETCHES over it -
/// it is NOT "HTTP-only/upstream-only". This makes the profile + the mechanism registry reflect
/// that the node reaches peers over iroh.
fn iroh_consume_active(config: &Config) -> bool {
    !config.iroh_peers.is_empty() || !config.p2p_claims.is_empty()
}

/// Is ANY iroh transport running on this node (give OR consume side)?
fn iroh_transport_active(config: &Config) -> bool {
    iroh_give_side_active(config) || iroh_consume_active(config)
}

/// Map the composite daemon's parsed [`Config`] onto the ONE authoritative [`OperatorContract`]
/// (TASK-120), on the libp2p-PRIMARY path with the legacy iroh transport modeled HONESTLY as a
/// deferred reference (the composite's FULL iroh contract is deferred to TASK-202).
///
/// * Give-side intent counts a libp2p provider OR the legacy iroh provider/publish, so a SERVING
///   node is never mislabeled upstream-only (#3b: `announces` reflects `iroh_publish_node`).
/// * #3a SAFETY: a GLOBAL-scope iroh endpoint is public-reachable (it binds/relays to the open
///   internet), so it is permitted ONLY under public-share (+ the allowlist door); a global iroh
///   give-side on any other profile is REFUSED rather than mislabeled lan-share. Offline-test / LAN
///   iroh scopes are genuinely isolated and map to lan-share honestly.
/// * #4: when the iroh give-side (or iroh node-lookup / pkarr) is active it is recorded in
///   `active_reference_mechanisms` so the preflight/status REPORT MATCHES THE WIRE.
fn derive_contract(config: &Config) -> Result<OperatorContract, String> {
    let req = ContractRequest {
        is_leech: config.libp2p_leech,
        // Give-side participants: a libp2p provider, an iroh content provider, OR an iroh node that
        // publishes its own address to be dialed (a give-side participation - publishing your
        // reachability so peers can fetch from you). Counting node-publish here keeps `is_provider`
        // consistent with `announces` below, so #3b never trips AnnounceWithoutProvider.
        is_provider: config.libp2p_provider || config.iroh_provider || config.iroh_publish_node,
        announces: config.libp2p_announce_after_fetch
            || !config.libp2p_seed_nar.is_empty()
            || !config.libp2p_provide_store.is_empty()
            || config.iroh_provider
            || config.iroh_publish_node,
        has_public_allowlist: config.libp2p_public_allowlist_path.is_some(),
        // The composite daemon has no `--libp2p-external-address`; libp2p public reachability is
        // governed by the allowlist door. Iroh public reachability is handled by the #3a scope
        // gate below (a global iroh endpoint is the iroh analogue of a public self-address).
        advertises_public_address: false,
        // "Reaches a peer substrate" - a libp2p bootstrap, `--libp2p-mdns`, OR an iroh consume side
        // (fix B). An iroh-consuming node with no give-side flag is CONSUME-ONLY (fetches from
        // peers), never upstream-only: it is a lie to report HTTP-only while an iroh transport
        // fetches. TASK-257 (F1): `--libp2p-mdns` IS a consumer's DHT ENTRY PATH exactly like an
        // explicit `--libp2p-bootstrap` (mDNS discovers a LAN neighbour's address with zero config),
        // so it must count here too. Without it, bare `--libp2p-mdns` would derive UPSTREAM-ONLY
        // while `libp2p_requested()` still opens the mDNS multicast socket - reporting HTTP-only
        // while the wire emits mDNS multicast and discloses presence+NodeId to the LAN (a
        // report-does-not-match-wire AC#4 violation). Folding it here makes bare `--libp2p-mdns`
        // derive CONSUME-ONLY (report matches wire), and an explicit `--profile upstream-only
        // --libp2p-mdns` fail CLOSED at the compat-shim cross-check below (declared upstream-only !=
        // implied consume-only).
        has_bootstrap: !config.libp2p_bootstrap.is_empty()
            || config.libp2p_mdns
            || iroh_consume_active(config),
        // The composite daemon exposes no `--libp2p-router`: the pure kad-server/relay ROUTER mode
        // (TASK-241) is a daemon-libp2p-primary surface. Never a router here.
        is_router: false,
    };
    let profile = SharingProfile::derive(req).map_err(|e| e.to_string())?;

    // #3a: a GLOBAL iroh endpoint scope is public-reachable. A serving node on it must be
    // public-share (allowlist-gated) - otherwise it would announce local content over a public
    // endpoint mislabeled as lan-share. Refuse rather than mislabel. (offline-test / LAN scopes are
    // isolated and legitimately lan-share; the e2e s6 provider uses offline-test.)
    if iroh_give_side_active(config)
        && matches!(
            config.iroh_endpoint_scope,
            Some(EndpointScope::Global { .. })
        )
        && profile != SharingProfile::PublicShare
    {
        return Err(format!(
            "an iroh give-side (provider/publish) on a GLOBAL endpoint scope is public-reachable \
             and may run ONLY under the public-share profile (with a public-NAR allowlist); the \
             flags imply {profile}. Use --iroh-endpoint-scope offline-test/lan for an isolated \
             substrate, or configure public-share."
        ));
    }

    // #4 + fix B: reflect the ACTIVE deferred-reference mechanisms so the report matches the wire.
    // ANY iroh transport (give OR consume) marks IrohTransport active - a node fetching over iroh
    // is not HTTP-only. Node publication via the pkarr path AND iroh node-lookup both mark DnsPkarr.
    let mut active_reference = Vec::new();
    if iroh_transport_active(config) {
        active_reference.push(Mechanism::IrohTransport);
    }
    if config.iroh_enable_node_lookup || config.iroh_publish_node {
        active_reference.push(Mechanism::DnsPkarr);
    }

    // FIX A / C-defer: the composite's libp2p give-side stays FLAG-AUTHORITATIVE (prune-pending
    // TASK-202) and always runs kad in SERVER mode when its libp2p swarm is engaged - so its
    // REPORTED dht_role reflects THAT reality (Server whenever the libp2p node is active), rather
    // than the profile-derived client/server mapping the PRIMARY binary uses. This keeps the
    // composite's report honest against its actual (unchanged) wire behaviour. A node with no
    // libp2p flags runs no libp2p swarm (iroh is a separate transport with no kad DHT) -> None.
    let libp2p_swarm_active = config.libp2p_provider
        || !config.libp2p_bootstrap.is_empty()
        || config.libp2p_listen.is_some()
        // TASK-257: --libp2p-mdns alone engages the libp2p swarm (zero-config LAN discovery).
        || config.libp2p_mdns;
    let dht_role = if libp2p_swarm_active {
        DhtRole::Server
    } else {
        DhtRole::None
    };
    // TASK-257: --libp2p-mdns SELECTS the shipped LAN mDNS mechanism (fail-closed validate admits
    // it; it is Enabled) and drives the per-node active+exposure report via `lan_mdns_enabled`.
    let selected_mechanisms = if config.libp2p_mdns {
        vec![Mechanism::LanMdns]
    } else {
        Vec::new()
    };
    // TASK-120 R2-1: `contract.caps` is the EFFECTIVE resource configuration the preflight displays.
    // The composite's serve budget is CLI-overridable (`--iroh-max-serve-*`), so reflect those
    // EFFECTIVE serve values here (an override that TIGHTENS the frozen ceiling must SHOW as the
    // tightened value, not the 256 MiB / 1 GiB / 120 s default). The frozen CEILING is still surfaced
    // separately by `profile_budget::preflight_lines`, and `enforce_budget_contract` guarantees these
    // effective values are within the envelope, so display and enforcement agree. The other caps
    // fields have no composite override and stay at their frozen defaults.
    let caps = ResourceCaps {
        max_nar_bytes_uncompressed: config.iroh_max_serve_nar_bytes,
        max_inflight_bytes_uncompressed: config.iroh_max_inflight_nar_bytes,
        serve_duration_ms: config.iroh_max_serve_duration_ms,
        ..ResourceCaps::default()
    };
    let contract = OperatorContract {
        profile,
        caps,
        privacy: PrivacyPolicy {
            diagnostics_opt_in: config.diagnostics,
        },
        selected_mechanisms,
        active_reference_mechanisms: active_reference,
        dht_role,
        // TASK-241: the composite exposes no `--libp2p-external-address` and no router mode, so it
        // advertises no libp2p public self-address here (iroh public reachability is governed by the
        // #3a endpoint-scope gate, not this field). Inert for every profile the composite derives.
        advertises_public_reachability: false,
        // TASK-257: LAN mDNS active on this node iff the default-OFF flag was passed.
        lan_mdns_enabled: config.libp2p_mdns,
    };
    contract.validate().map_err(|e| e.to_string())?;

    // The compat-shim cross-check (#2/#4): an explicit `--profile` must EQUAL the profile the flags
    // imply, else fail closed - `--profile upstream-only` with give-side flags can never run.
    if let Some(token) = &config.explicit_profile {
        let declared = SharingProfile::parse(token).map_err(|e| e.to_string())?;
        if declared != profile {
            return Err(format!(
                "--profile {declared} disagrees with the profile the flags imply ({profile}): the \
                 flags are the compat shim and must MATCH the declared profile."
            ));
        }
    }
    Ok(contract)
}

/// TASK-120 AC#10 (+ codex #1): the full fail-closed budget contract for the composite daemon,
/// extracted so it is unit-testable (the startup path AND a bite test call THIS). It runs the two
/// checks whose conjunction makes the frozen envelope binding on the running node:
///  1. the frozen artifact verify — content hash (freeze/identity), normative envelope, parity vs
///     the frozen `ResourceCaps::default()` SSOT (the tunable serve fields are separately
///     envelope-guarded in step 2, so parity must NOT use the effective `contract.caps`);
///  2. the EFFECTIVE serve-budget ceiling — the CLI-overridable values that actually reach
///     `ServeBudget` on BOTH serve paths (`config.iroh_max_*`) must be within the frozen envelope,
///     so an override can only TIGHTEN it. This is the check that closes the runtime bypass where
///     `--iroh-max-serve-nar-bytes 536870912` would serve 512 MiB while a defaults-only verify passed.
fn enforce_budget_contract(contract: &OperatorContract, config: &Config) -> Result<(), String> {
    // Parity is the artifact↔frozen-DEFAULT SSOT (that the code's frozen defaults match the frozen
    // artifact) — it uses `ResourceCaps::default()`, NOT `contract.caps`, because `contract.caps` now
    // carries the EFFECTIVE (possibly TIGHTENED) serve values and a tightening must not fail parity.
    daemon::profile_budget::verify(contract.profile, &ResourceCaps::default())
        .map_err(|e| e.to_string())?;
    // The EFFECTIVE serve budget (what actually reaches `ServeBudget` on both serve paths) must be
    // within the frozen envelope — an override may only tighten it.
    daemon::profile_budget::check_serve_ms_within_envelope(
        config.iroh_max_serve_nar_bytes,
        config.iroh_max_inflight_nar_bytes,
        config.iroh_max_serve_duration_ms,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
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
            no_narinfo_cache: false,
            header_timeout_ms: HEADER_TIMEOUT_MS,
            connect_timeout_ms: CONNECT_TIMEOUT_MS,
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
            // TASK-120 AC#10: the iroh serve budget is the fabric-iroh FROZEN values
            // (256 MiB / 1 GiB / 120 s). As of the AC#10 freeze the libp2p-primary `ResourceCaps`
            // ADOPT the SAME normative envelope, so the two now CONVERGE on the PRD.md:839-842
            // ceiling rather than diverging (the earlier 512 MiB / 300 s libp2p caps were the
            // divergence AC#10 eliminated). The test `iroh_budget_matches_the_normative_caps`
            // pins the convergence; the iroh give-side remains prune-pending TASK-202.
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
            libp2p_mdns: false,
            libp2p_identity_seed: None,
            libp2p_provider: false,
            libp2p_seed_nar: Vec::new(),
            libp2p_provide_store: Vec::new(),
            libp2p_print_peer_address: false,
            libp2p_state_dir: None,
            libp2p_trusted_public_keys: Vec::new(),
            libp2p_public_allowlist_path: None,
            libp2p_prove_public_narinfo: Vec::new(),
            libp2p_announce_after_fetch: false,
            libp2p_announce_budget: default_libp2p_announce_budget(),
            libp2p_leech: false,
            preflight: false,
            diagnostics: false,
            explicit_profile: None,
        }
    }
}

impl Config {
    fn from_args<I: IntoIterator<Item = String>>(args: I) -> Result<Config, String> {
        let mut config = Config::default();
        // TASK-273 (#8): track whether an mDNS flag was already seen so `--libp2p-mdns` and
        // `--libp2p-no-mdns` together fail closed (contradictory intent), not silently last-wins.
        let mut mdns_seen: Option<bool> = None;
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
                "--no-narinfo-cache" => config.no_narinfo_cache = true,
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
                "--connect-timeout-ms" => {
                    let raw = value()?;
                    let ms: u64 = raw
                        .parse()
                        .map_err(|e| format!("bad --connect-timeout-ms {raw:?}: {e}"))?;
                    // Reject 0 (mirrors --header-timeout-ms, TASK-111 AC#2): a 0 ms
                    // connect timeout fires before any TCP connect can complete, so
                    // EVERY request 502s - a bricked daemon. The upper bound catches a
                    // units typo. Range identical to the header timeout for symmetry.
                    if !(1..=600_000).contains(&ms) {
                        return Err(format!(
                            "bad --connect-timeout-ms {ms}: must be 1..=600000 (0 bricks the daemon)"
                        ));
                    }
                    config.connect_timeout_ms = ms;
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
                // TASK-273 FLAG-SURFACE PARITY: the NixOS module (nixos/nix-p2p.nix) resolves the
                // tri-state `libp2p.mdns` and emits `--libp2p-no-mdns` for an explicit opt-out. That
                // module drives THIS composite binary (`packages.<system>.daemon`), which fails fast
                // on unknown flags - so it must ACCEPT `--libp2p-no-mdns` or an explicit opt-out
                // crashes the daemon at startup. This binary has no lan-share mDNS-default (mDNS is
                // always default-OFF here), so `--libp2p-no-mdns` sets the already-default OFF state
                // explicitly. #8: passing BOTH flags is contradictory and fails closed. NOTE: this
                // binary does NOT run an undiscoverable provider silently dark — the pre-existing
                // entry-path guard below (search `no DHT entry path`) already fails a libp2p-requested
                // node loud when it has neither `--libp2p-bootstrap` nor `--libp2p-mdns`. The residual
                // vs daemon-libp2p's TASK-273 guard is narrow (external-address entry-path parity +
                // message unification), the deferred low-priority follow-up (TASK-277).
                "--libp2p-mdns" => {
                    if mdns_seen == Some(false) {
                        return Err(LIBP2P_MDNS_FLAG_CONTRADICTION.into());
                    }
                    mdns_seen = Some(true);
                    config.libp2p_mdns = true;
                }
                "--libp2p-no-mdns" => {
                    if mdns_seen == Some(true) {
                        return Err(LIBP2P_MDNS_FLAG_CONTRADICTION.into());
                    }
                    mdns_seen = Some(false);
                    config.libp2p_mdns = false;
                }
                "--libp2p-state-dir" => config.libp2p_state_dir = Some(value()?.into()),
                "--libp2p-identity-seed" => {
                    config.libp2p_identity_seed = Some(parse_libp2p_seed(&value()?)?)
                }
                "--libp2p-provider" => config.libp2p_provider = true,
                "--libp2p-seed-nar" => config
                    .libp2p_seed_nar
                    .push(parse_libp2p_seed_nar(&value()?)?),
                "--libp2p-provide-store" => config
                    .libp2p_provide_store
                    .push(parse_libp2p_seed_nar(&value()?)?),
                "--libp2p-print-peer-address" => config.libp2p_print_peer_address = true,
                "--libp2p-trusted-public-key" => config.libp2p_trusted_public_keys.push(value()?),
                "--libp2p-public-allowlist-path" => {
                    config.libp2p_public_allowlist_path = Some(value()?.into())
                }
                "--libp2p-prove-public-narinfo" => config
                    .libp2p_prove_public_narinfo
                    .push(parse_prove_public_narinfo(&value()?)?),
                "--libp2p-announce-after-fetch" => config.libp2p_announce_after_fetch = true,
                "--libp2p-leech" => config.libp2p_leech = true,
                "--preflight" => config.preflight = true,
                "--diagnostics" => config.diagnostics = true,
                "--profile" => config.explicit_profile = Some(value()?),
                "--libp2p-announce-budget" => {
                    let raw = value()?;
                    config.libp2p_announce_budget = raw.parse::<u64>().map_err(|e| {
                        format!(
                            "--libp2p-announce-budget {raw:?} is not a non-negative integer: {e}"
                        )
                    })?;
                }
                other => return Err(format!("unknown flag {other:?}")),
            }
        }
        // TASK-78 LEECH mode is consume-only: it masks the SERVE + ANNOUNCE axes at the seam, so it
        // is contradictory with every flag that makes this node GIVE content back. Reject the
        // combination fail-fast rather than silently mask a provider the operator asked for (a leech
        // that serves would be a lie). Mirrors the thin `daemon-libp2p` binary's check.
        if config.libp2p_leech {
            let give_side = [
                ("--libp2p-provider", config.libp2p_provider),
                (
                    "--libp2p-announce-after-fetch",
                    config.libp2p_announce_after_fetch,
                ),
                ("--libp2p-seed-nar", !config.libp2p_seed_nar.is_empty()),
                (
                    "--libp2p-provide-store",
                    !config.libp2p_provide_store.is_empty(),
                ),
                (
                    "--libp2p-public-allowlist-path",
                    config.libp2p_public_allowlist_path.is_some(),
                ),
                (
                    "--libp2p-trusted-public-key",
                    !config.libp2p_trusted_public_keys.is_empty(),
                ),
                (
                    "--libp2p-prove-public-narinfo",
                    !config.libp2p_prove_public_narinfo.is_empty(),
                ),
            ];
            if let Some((flag, _)) = give_side.iter().find(|(_, present)| *present) {
                return Err(format!(
                    "--libp2p-leech is consume-only (it serves nothing and announces nothing); it \
                     cannot be combined with {flag}. Drop the give-side flag or drop --libp2p-leech."
                ));
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
        if (!config.libp2p_seed_nar.is_empty()
            || !config.libp2p_provide_store.is_empty()
            || config.libp2p_print_peer_address
            || config.libp2p_announce_after_fetch)
            && !config.libp2p_provider
        {
            return Err(
                "libp2p provider companion flags (--libp2p-seed-nar / --libp2p-provide-store / --libp2p-print-peer-address / --libp2p-announce-after-fetch) require explicit --libp2p-provider".into(),
            );
        }
        // A provider must have SOMETHING to make it more than a no-op: a static supply set, OR
        // announce-after-fetch (TASK-77), which grows its supply set dynamically from what it
        // fetches (so an EMPTY initial set is legitimate - the node starts holding nothing and
        // becomes a holder as it fetches).
        if config.libp2p_provider
            && config.libp2p_seed_nar.is_empty()
            && config.libp2p_provide_store.is_empty()
            && !config.libp2p_announce_after_fetch
        {
            return Err(
                "--libp2p-provider requires at least one --libp2p-seed-nar <narhash>=<path>, --libp2p-provide-store <narhash>=<storepath>, or --libp2p-announce-after-fetch; a provider with nothing to serve and no way to acquire content is a no-op".into(),
            );
        }
        // TASK-278: `--libp2p-seed-nar` and `--libp2p-provide-store` CAN now be combined - the
        // provider builds an ADDITIVE union supplier serving both. The old TASK-191-MVP refusal is
        // removed.
        // TASK-278 #3 (fail-loud, NOT silent dedup): a NarHash may appear at most ONCE across the
        // whole static supply set (within --libp2p-seed-nar, within --libp2p-provide-store, or ACROSS
        // the two). A provider serves + announces each NarHash EXACTLY once, so a repeat would make
        // the startup count (raw .len()) over-state the distinct served set. Reject rather than
        // silently dedup, matching the `--iroh-*` duplicate rejects, so `.len() == distinct == served`.
        {
            let mut seen = std::collections::HashSet::new();
            for (nar_hash, _) in config
                .libp2p_seed_nar
                .iter()
                .chain(config.libp2p_provide_store.iter())
            {
                if !seen.insert(*nar_hash) {
                    return Err(format!(
                        "--libp2p-seed-nar / --libp2p-provide-store lists NarHash {nar_hash} more \
                         than once (or in both): a provider serves and announces each NarHash \
                         exactly once; pass it a single time"
                    ));
                }
            }
        }
        // TASK-278 #4: announce-after-fetch with a ZERO growth budget grows nothing - the hook would
        // reject every fetch while the startup report claims "grows on demand". `--libp2p-announce-
        // budget` is the DISTINCT-PATHS growth budget the announce-after-fetch hook consumes (static
        // seed/provision announces use a separate rate limiter), so it cannot catch a static-only
        // provider.
        if config.libp2p_announce_after_fetch && config.libp2p_announce_budget == 0 {
            return Err(
                "--libp2p-announce-after-fetch with --libp2p-announce-budget 0 grows nothing: the \
                 hook would reject every fetch while the startup report claims \"grows on demand\". \
                 Raise the budget or drop --libp2p-announce-after-fetch"
                    .into(),
            );
        }
        if config.libp2p_provider && config.libp2p_listen.is_none() {
            // TASK-276 FIX #B: nix-p2p never auto-resolves/guesses a bind. A cross-host lan-share
            // provider must name its LAN address explicitly.
            return Err(
                "--libp2p-provider requires --libp2p-listen <multiaddr>; a cross-host lan-share provider must name its LAN address (--libp2p-listen /ip4/<your-LAN-ip>/tcp/0) — nix-p2p never guesses a bind, and a provider that binds no listener cannot be dialed by a consumer".into(),
            );
        }
        // TASK-103 PUBLIC-announce allowlist companion validation. Setting the allowlist path is
        // what switches a provider into PUBLIC-announce mode (the allowlist gates each announce),
        // so its companions are inert without it, and it is inert without a provider - fail fast
        // rather than silently ignore. A public allowlist with no trusted key can prove NOTHING
        // public, so it would refuse every announce; reject that dead-on-arrival config up front.
        let public_allowlist_companion = !config.libp2p_trusted_public_keys.is_empty()
            || !config.libp2p_prove_public_narinfo.is_empty();
        if config.libp2p_public_allowlist_path.is_some() && !config.libp2p_provider {
            return Err(
                "--libp2p-public-allowlist-path requires --libp2p-provider; the allowlist gates a PROVIDER's public announce".into(),
            );
        }
        if public_allowlist_companion && config.libp2p_public_allowlist_path.is_none() {
            return Err(
                "--libp2p-trusted-public-key / --libp2p-prove-public-narinfo require --libp2p-public-allowlist-path (they populate the on-disk public-NAR allowlist)".into(),
            );
        }
        if config.libp2p_public_allowlist_path.is_some()
            && config.libp2p_trusted_public_keys.is_empty()
        {
            return Err(
                "--libp2p-public-allowlist-path requires at least one --libp2p-trusted-public-key; without a trusted narinfo-signing key nothing can be proven public and every announce would be refused".into(),
            );
        }
        // TASK-278: `--libp2p-seed-nar` + `--libp2p-announce-after-fetch` is now VALID -
        // `install_libp2p_provider` builds an ADDITIVE union (seed leg + store leg), so the seed is
        // served AND the node grows via announce-after-fetch. The old interim fail-closed is removed.
        // (The generic no-`--libp2p-provider` companion check above still fails-closed correctly for
        // provider flags passed without --libp2p-provider; with --libp2p-provider the combo reaches
        // the additive install, so codex-LOW-#2 is resolved by the hazard no longer existing.)
        // TASK-29: the narinfo cache is on by default; naming a dir AND opting out
        // at once is contradictory intent, so reject it at parse time (fail fast)
        // rather than silently pick one.
        if config.narinfo_cache_dir.is_some() && config.no_narinfo_cache {
            return Err(NARINFO_CACHE_FLAG_CONFLICT.into());
        }

        // libp2p companion validation: any libp2p flag REQUIRES a bootstrap entry peer (kad cannot
        // discover a provider without one). A `--libp2p-listen`/`--libp2p-provider-addr` with no
        // bootstrap would be a consumer that can never find anyone - a silently-useless config, so
        // fail fast. A PROVIDER equally needs one: its announce only propagates once it has joined
        // the DHT.
        if config.libp2p_requested() && config.libp2p_bootstrap.is_empty() && !config.libp2p_mdns {
            // TASK-257: --libp2p-mdns is an alternative ENTRY PATH to the DHT (zero-config LAN
            // discovery), so it satisfies the entry-peer requirement exactly as an explicit
            // --libp2p-bootstrap does. Without EITHER, kad cannot discover anyone.
            return Err(
                "libp2p is configured but no DHT entry path is given; add --libp2p-bootstrap <PeerId>@<multiaddr>, or --libp2p-mdns for zero-config LAN discovery".into(),
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
            || self.libp2p_mdns
            || self.libp2p_identity_seed.is_some()
            || self.libp2p_state_dir.is_some()
            || self.libp2p_provider
            || !self.libp2p_seed_nar.is_empty()
            || !self.libp2p_provide_store.is_empty()
            || self.libp2p_print_peer_address
            // TASK-78: a lone `--libp2p-leech` must not be silently ignored - it requests libp2p
            // (consume-only), so it trips the bootstrap requirement (a leech needs an entry peer).
            || self.libp2p_leech
    }

    /// Build the production [`Libp2pSourceConfig`] this `Config` describes. PURE and
    /// idempotent: the identity seed was resolved once in [`Config::from_args`] (a fresh
    /// `/dev/urandom` one when `--libp2p-identity-seed` was omitted), so this only reads
    /// it. The network scope defaults to `v1`; the discovery budget and fetch envelope
    /// use the peer-fabric v1 defaults; per-flag budget knobs are a follow-up (TASK-162
    /// note) once the podman e2e (TASK-161) pins the operating numbers.
    /// `lan_share` is DECIDED BY THE CALLER, not recomputed here (TASK-280 #6 single-source): the
    /// provider path passes `matches!(plan, PublicationPlan::Lan(_))` from the ONE
    /// [`provider_publication_decision`] mint, and the consumer path passes `false` (confinement is a
    /// PROVIDER egress control; a consumer dials the pool it was told to join). This threads BOTH the
    /// scope and the confinement flag from a SINGLE authority, so they cannot drift from the
    /// publication decision (the earlier `libp2p_provider && allowlist.is_none()` recomputation is
    /// gone).
    fn libp2p_source_config(&self, lan_share: bool) -> Result<Libp2pSourceConfig, String> {
        let identity_seed = self.libp2p_identity_seed.ok_or_else(|| {
            "internal: libp2p identity seed unresolved (from_args resolves it when libp2p is requested)".to_string()
        })?;
        Ok(Libp2pSourceConfig {
            identity_seed,
            network_scope: effective_network_scope(self.libp2p_scope.as_deref(), lan_share),
            listen: self.libp2p_listen.clone(),
            additional_listens: Vec::new(),
            external_addresses: Vec::new(),
            bootstrap: self.libp2p_bootstrap.clone(),
            provider_addrs: self.libp2p_provider_addrs.clone(),
            discovery_budget: peer_fabric::DiscoveryBudget::default(),
            envelope: peer_fabric::SafetyEnvelope::default(),
            state_dir: self.libp2p_state_dir.clone(),
            relay_server_enabled: true,
            // TASK-120 fix C is DEFERRED (prune-pending TASK-202): the composite daemon's libp2p
            // give-side remains FLAG-AUTHORITATIVE (it branches on config.libp2p_provider /
            // libp2p_leech, not on contract.profile) rather than deriving the swarm participation
            // mode from the profile as the PRIMARY daemon-libp2p does. Kept at kad SERVER (the
            // pre-TASK-120 behaviour) so this defer changes nothing; the profile-derived
            // kad-client/relay-off wiring is the primary binary's job and a filed 202 follow-up.
            kad_server: true,
            // TASK-257: LAN mDNS peer-ADDRESS discovery, straight from the default-OFF flag.
            mdns_enabled: self.libp2p_mdns,
            // TASK-280: LAN confinement for a no-allowlist lan-share node only.
            lan_confinement: lan_share,
        })
    }

    fn cache_info(&self) -> CacheInfo {
        CacheInfo {
            store_dir: self.store_dir.clone(),
            priority: self.priority,
            want_mass_query: self.want_mass_query,
        }
    }

    /// Build the node's ONE public-NAR allowlist (TASK-103), the single authority the PUBLIC
    /// announce gate consults AND the serving daemon learns into (`App::public_allowlist`).
    ///
    /// Without `--libp2p-public-allowlist-path` this returns a DISABLED allowlist (no trusted
    /// keys, in-memory, `contains` always false) - the pre-TASK-103 behaviour, so a non-public
    /// node is unchanged. WITH the path it opens the MAC-integrity-protected file (key derived
    /// from the durable identity seed) and POPULATES it by PROVING each
    /// `--libp2p-prove-public-narinfo` public through the trusted-key signature gate: the
    /// operator naming a seed/store path never makes it public - only a trusted narinfo signature
    /// does. A narinfo that does not prove public, mis-correlates to its requested store hash, or
    /// fails to persist is a LOUD startup error (fail-closed), never a silently-empty allowlist.
    fn build_public_allowlist(&self) -> Result<Arc<PublicNarAllowlist>, String> {
        // Delegate to the shared SSOT wiring in `daemon-libp2p` (TASK-204), so this composite
        // binary and the thin `daemon-libp2p` binary open + populate the allowlist through ONE
        // code path and their publication policy cannot drift. The identity seed is resolved when
        // the allowlist path is set (from_args resolves it whenever libp2p is requested); a bare
        // disabled allowlist needs none.
        let identity_seed = match &self.libp2p_public_allowlist_path {
            Some(_) => self.libp2p_identity_seed.ok_or_else(|| {
                "internal: public allowlist requires the resolved libp2p identity seed (from_args resolves it when libp2p is requested)".to_string()
            })?,
            None => [0u8; 32],
        };
        daemon::open_public_allowlist(
            self.libp2p_public_allowlist_path.as_deref(),
            &self.libp2p_trusted_public_keys,
            &identity_seed,
            &self.libp2p_prove_public_narinfo,
        )
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
    /// Present in the STORE-supply mode (TASK-191): the [`CatalogNarSupplier`] serves through
    /// this index's supply catalog, and the index's `Drop` retires every registration, so the
    /// served reverse-map must outlive the process.
    _index: Option<Arc<AvailabilityIndex>>,
    /// The ANNOUNCE-AFTER-FETCH hook (TASK-77), present when `--libp2p-announce-after-fetch` is
    /// set. `App` clones this `Arc` so a successful fetch on the serving frontend grows the swarm.
    /// It shares the SAME `_index` above, so a fetched path it registers is servable through the
    /// same supply catalog.
    post_fetch_announce: Option<Arc<dyn daemon_core::PostFetchAnnounce>>,
}

/// The TASK-102 LAN-isolation guard for the shipped libp2p provider modes (fix cycle #2). They
/// announce over a PRIVATE / LAN (operator-assembled) substrate: the seed/store bytes are
/// content-verified (TASK-56) but NOT publication-authorized by the public-NAR allowlist (config
/// not wired until TASK-103). This thin wrapper maps the daemon's parsed [`Config`] to the FULL
/// reachability the shared [`daemon_libp2p::lan_isolation_or_refuse`] policy inspects - bootstrap, provider-addr,
/// AND listen - so a provider that can reach ANY public substrate (not just one with a non-empty
/// bootstrap) is refused. Keeping the Config->reachability mapping in ONE tested place closes the
/// residual hole where `--libp2p-provider-addr` + empty bootstrap slipped through a bootstrap-only
/// check and announced ungated.
fn lan_share_or_refuse(config: &Config) -> Result<LanShare, String> {
    lan_isolation_or_refuse(LanReachability {
        bootstrap: &config.libp2p_bootstrap,
        provider_addrs: &config.libp2p_provider_addrs,
        listen: config.libp2p_listen.as_ref(),
    })
}

/// The SINGLE publication decision for this libp2p PROVIDER node (TASK-276 FIX #2), taken ONCE
/// before any fabric/listener is built: a configured public allowlist -> [`PublicationPlan::Allowlist`];
/// no allowlist -> the isolation guard runs HERE ([`lan_share_or_refuse`]) and either binds the
/// [`LanShare`] witness into [`PublicationPlan::Lan`] or ABORTS. A public-reachable no-allowlist
/// provider therefore fails before a listener registers, closing the bind-before-guard window (codex
/// CRITICAL #2).
fn provider_publication_decision(config: &Config) -> Result<PublicationPlan, String> {
    if config.libp2p_public_allowlist_path.is_some() {
        Ok(PublicationPlan::Allowlist)
    } else {
        Ok(PublicationPlan::Lan(lan_share_or_refuse(config)?))
    }
}

/// The ADDITIVE libp2p provider supply (TASK-278), built SYNCHRONOUSLY so it is unit-testable
/// without a fabric: the union [`Libp2pNarSupplier`] the fabric will serve, plus the per-leg
/// announce inputs and the human-readable served-set report. The two supply legs are NOT mutually
/// exclusive - a provider can seed in-memory NARs AND serve `/nix/store` paths on demand AND grow
/// via announce-after-fetch, all from ONE fabric/identity.
struct Libp2pProviderSupply {
    supplier: Arc<dyn Libp2pNarSupplier>,
    seeds: Vec<(NarHashKey, Vec<u8>)>,
    index: Option<Arc<AvailabilityIndex>>,
    provisions: Vec<StoreProvision>,
    report: String,
}

/// The libp2p provider serve budget, REUSING the daemon's backend-neutral serve-budget knobs (the
/// `--iroh-max-*` flags, in UNCOMPRESSED NAR bytes). Fail-fast if the in-flight bound is below the
/// per-NAR bound (every serve at the per-NAR bound would be declined busy).
fn libp2p_provider_serve_budget(config: &Config) -> Result<peer_fabric::ServeBudget, String> {
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
    Ok(serve_budget)
}

/// The startup served-set line (TASK-278 AC#1): S seeded NARs + P `/nix/store` paths served on
/// demand, plus an announce-after-fetch clause iff the growing hook is installed. Counts are
/// INDEPENDENT (never one-or-the-other), so the line never over- or under-states what is served.
/// Kept behaviourally identical to `daemon-libp2p`'s `provider_supply_report`.
fn libp2p_provider_supply_report(
    seeds: usize,
    provisions: usize,
    announce_after_fetch: bool,
) -> String {
    let hook = if announce_after_fetch {
        " + announce-after-fetch (grows on demand)"
    } else {
        ""
    };
    format!("{seeds} seeded NAR(s) + {provisions} /nix/store path(s) on demand{hook}")
}

/// Build the additive [`Libp2pProviderSupply`] from the CLI (TASK-278 AC#1) WITHOUT touching the
/// network: read + size-guard the seed leg, register + verify + size-guard the store leg, and UNION
/// them. `dumper` is the store-path NAR producer (production: `CommandNarDumper`; tests inject a
/// `RegularFileNarDumper` so `verify_store_provisions` runs a real dump without a `/nix/store`).
///
/// Leg selection is ADDITIVE, not a mode-select: the seed leg is built iff there are seeds, the
/// store leg iff there is a provide-store set OR announce-after-fetch (which needs the index even
/// with an empty initial set). Both legs empty is a "provider with nothing to serve" fail-closed.
fn build_libp2p_provider_supply(
    config: &Config,
    serve_budget: &peer_fabric::ServeBudget,
    dumper: Arc<dyn NarDumper>,
    node_id: NodeId,
) -> Result<Libp2pProviderSupply, String> {
    let mut legs: Vec<Arc<dyn Libp2pNarSupplier>> = Vec::new();

    // SEED leg: read every `--libp2p-seed-nar`, size-guard it, and hold it in memory.
    let mut seeds: Vec<(NarHashKey, Vec<u8>)> = Vec::with_capacity(config.libp2p_seed_nar.len());
    for (nar_hash, path) in &config.libp2p_seed_nar {
        let bytes =
            std::fs::read(path).map_err(|e| format!("reading --libp2p-seed-nar {path:?}: {e}"))?;
        seeds.push((*nar_hash, bytes));
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
    if !seeds.is_empty() {
        legs.push(Arc::new(MemoryNarSupplier::new(
            seeds.iter().map(|(_, b)| b.clone()),
        )));
    }

    // STORE leg: built iff there is a provide-store set OR announce-after-fetch (the hook grows this
    // index, so it must exist even for an empty initial provide set).
    let mut index = None;
    let mut provisions = Vec::new();
    if !config.libp2p_provide_store.is_empty() || config.libp2p_announce_after_fetch {
        // NullStore/NullAnnounce: the provided set is the CLI SSOT (re-registered + re-verified each
        // boot); claims announce through the libp2p announcer, not the index's iroh sink. The
        // `node_id` is a PLACEHOLDER (the composite has no ed25519 dep to derive the real one); the
        // libp2p ProviderRecord carries its OWN provider identity, so the iroh offer is never used.
        let store_index =
            AvailabilityIndex::open(node_id, dumper, Arc::new(NullStore), Arc::new(NullAnnounce))
                .map_err(|e| format!("opening the availability index for store supply: {e}"))?;
        let mut nar_hashes = Vec::with_capacity(config.libp2p_provide_store.len());
        for (nar_hash, path) in &config.libp2p_provide_store {
            store_index
                .register(*nar_hash, StorePath::new(path))
                .map_err(|e| format!("registering store path {path:?} under {nar_hash}: {e}"))?;
            nar_hashes.push(*nar_hash);
        }
        let store_index = Arc::new(store_index);

        // The supplier reads the index's inert reverse-map. The helper program is THIS binary's
        // `__dump-raw-nar` mode, spawned ONLY for a ProbedSource::RegularFile; a real store path is
        // a ProbedSource::Process (nix-store --dump) and never invokes it.
        let helper_program = std::env::current_exe()
            .map_err(|e| format!("resolving daemon executable for the raw-NAR helper: {e}"))?;
        legs.push(Arc::new(CatalogNarSupplier::new(
            Libp2pCatalogProbe::new(store_index.supply_catalog()),
            helper_program,
        )));

        // AC#2 gate: verify EVERY provided store path before any announce.
        provisions = verify_store_provisions(&store_index, &nar_hashes)?;
        for provision in &provisions {
            if provision.declared_size() > serve_budget.max_nar_bytes_uncompressed_nar {
                return Err(format!(
                    "store path for {} dumps to {} B (uncompressed NAR) but --iroh-max-serve-nar-bytes \
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

    let report = libp2p_provider_supply_report(
        seeds.len(),
        provisions.len(),
        config.libp2p_announce_after_fetch,
    );

    Ok(Libp2pProviderSupply {
        supplier: Arc::new(UnionNarSupplier::new(legs)),
        seeds,
        index,
        provisions,
        report,
    })
}

/// Node B (libp2p PROVIDER): build the ADDITIVE supply (TASK-278), start ONE libp2p fabric over the
/// union supplier, install ONE serve gate, and announce EVERY built leg (seeds AND store
/// provisions) plus install the announce-after-fetch hook. Seeds and provisions are DISTINCT
/// content keys, so the two announce loops share the one durable-sequence allocator without
/// collision. Returns the fabric's OWN consumer source/raw-serve (a provider also consumes - ONE
/// fabric/identity/listen does both) plus the [`Libp2pProviderGuard`] `main` holds.
///
/// Fail-fast: an unreadable seed file, a seed/provision over the per-NAR budget, or a serve/announce
/// error is a loud startup error, never a provider that announces then cannot deliver.
async fn install_libp2p_provider(
    config: &Config,
    cfg: Libp2pSourceConfig,
    plan: PublicationPlan,
    allowlist: &Arc<PublicNarAllowlist>,
) -> Result<
    (
        Arc<dyn NarSource>,
        Arc<dyn RawServeDecision>,
        Libp2pProviderGuard,
    ),
    String,
> {
    let serve_budget = libp2p_provider_serve_budget(config)?;
    let identity_seed = cfg.identity_seed;

    // TASK-276 FIX #2 / TASK-280 #6: the publication decision was taken ONCE by the CALLER (before any
    // fabric or listener is built, so a no-allowlist non-LAN-isolated provider aborts before a
    // listener binds) and threaded in here — the SAME `plan` that decided `cfg.lan_confinement` and
    // `cfg.network_scope`, so confinement and publication cannot drift. The bound witness is threaded
    // into every announce branch (guard consulted once, not per leg).

    // A PROVIDER without a durable state dir re-enables the F3 self-rollback (fresh random identity +
    // sequence 1 after a restart). WARN loudly rather than silently.
    if cfg.state_dir.is_none() {
        eprintln!(
            "daemon: WARNING: --libp2p-state-dir is not set; this libp2p PROVIDER runs \
             NON-DURABLE. Its identity is regenerated each start and its announce sequences and \
             withdrawals will NOT survive a restart (a restarted provider announces under a NEW \
             identity at sequence 1 and cannot supersede or withdraw its old records). Set \
             --libp2p-state-dir <dir> for restart-durable operation."
        );
    }

    let supply = build_libp2p_provider_supply(
        config,
        &serve_budget,
        Arc::new(CommandNarDumper::from_path()) as Arc<dyn NarDumper>,
        NodeId::from_bytes([0u8; 32]),
    )?;
    let Libp2pProviderSupply {
        supplier,
        seeds,
        index,
        provisions,
        report,
    } = supply;

    // ONE fabric over the union supplier, ONE serve gate under the one serve budget. The publication
    // authority is derived from the ALREADY-TAKEN plan (guard consulted once, above).
    let authority = plan.announce_authority(allowlist);
    let (fabric, source, raw_serve, readiness) =
        build_libp2p_provider_source(cfg, supplier, authority).await?;

    // TASK-276 FIX #3 (composite parity): SEQUENCE guard(done) -> bind(done) -> DISCLOSE -> activate
    // serve gate. Read the bound listeners, print the SAME bound-private-multiaddr disclosure the thin
    // binary prints (only for an isolated-LAN provider — a public/allowlist provider has no LAN
    // disclosure), THEN activate the `/nar` serve gate. Disclosure-before-serve is a security ordering,
    // not cosmetics.
    let listen_addrs = fabric.handle().listen_addrs().await;
    let disclosures = match &plan {
        PublicationPlan::Lan(_) => {
            // The EFFECTIVE scope this lan-share node runs (the canonical decision function; a
            // `PublicationPlan::Lan` node is `lan_share == true`), so the disclosed scope matches the
            // scope the fabric was built with (TASK-280 #6).
            let effective_scope = effective_network_scope(config.libp2p_scope.as_deref(), true);
            lan_serving_disclosures(
                config.libp2p_announce_after_fetch,
                &effective_scope,
                &listen_addrs,
            )
        }
        PublicationPlan::Allowlist => Vec::new(),
    };
    let server = fabric.server().ok_or_else(|| {
        "internal: libp2p provider fabric has no serve axis (start_with_supplier)".to_string()
    })?;
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
    println!("daemon: /nar serve gate active");

    let announce_budget = AnnounceBudget::new(std::time::Duration::from_secs(10), 20);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let announce_config = InitialAnnounceConfig::new(identity_seed, 3600, now, &announce_budget);
    let privacy = PrivacyPolicy {
        diagnostics_opt_in: config.diagnostics,
    };

    // Announce the SEED leg (if built). PUBLIC-announce mode (a configured allowlist) gates each
    // record; ISOLATED-LAN mode keeps the TASK-102 `lan_share_or_refuse` stopgap.
    if !seeds.is_empty() {
        let records = match &plan {
            PublicationPlan::Allowlist => {
                announce_public_seeds(&fabric, &readiness, announce_config, &seeds, allowlist)
                    .await?
            }
            PublicationPlan::Lan(lan) => {
                announce_provider_seeds(&fabric, &readiness, announce_config, &seeds, *lan).await?
            }
        };
        for (record, (nar_hash, bytes)) in records.iter().zip(&seeds) {
            println!(
                "LIBP2P-SEED narhash={} content={} content_key={} bytes={}",
                privacy.content_id(&nar_hash.to_string()),
                privacy.content_id(&record.content.to_hex()),
                privacy.content_id(&record.key.to_string()),
                bytes.len()
            );
        }
    }

    // Announce the STORE leg (if any provisions were verified). The parse-time #3 dedup guarantees
    // every provision's NarHash differs from every seed's, so no per-ContentKey durable-sequence
    // collision against the same fabric/identity.
    if !provisions.is_empty() {
        let records = match &plan {
            PublicationPlan::Allowlist => {
                announce_public_provisions(
                    &fabric,
                    &readiness,
                    announce_config,
                    &provisions,
                    allowlist,
                )
                .await?
            }
            PublicationPlan::Lan(lan) => {
                announce_store_provisions(&fabric, &readiness, announce_config, &provisions, *lan)
                    .await?
            }
        };
        for (record, provision) in records.iter().zip(&provisions) {
            println!(
                "LIBP2P-PROVIDE-STORE narhash={} content={} content_key={} nar_size={}",
                privacy.content_id(&provision.nar_hash().to_string()),
                privacy.content_id(&record.content.to_hex()),
                privacy.content_id(&record.key.to_string()),
                provision.declared_size(),
            );
        }
    }

    println!(
        "LIBP2P-SERVE-BUDGET max_nar_bytes_uncompressed_nar={} max_inflight_bytes_uncompressed_nar={} max_serve_duration_ms={}",
        serve_budget.max_nar_bytes_uncompressed_nar,
        serve_budget.max_inflight_bytes_uncompressed_nar,
        config.iroh_max_serve_duration_ms
    );

    // ANNOUNCE-AFTER-FETCH (TASK-77): build the hook over the SAME store index + fabric + identity so
    // a fetched path it registers is servable and every announce it makes is signed by this node and
    // re-checked by its eligibility authority (no second announce path). The store leg guarantees
    // `index` is `Some` whenever the flag is set.
    let post_fetch_announce: Option<Arc<dyn daemon_core::PostFetchAnnounce>> = if config
        .libp2p_announce_after_fetch
    {
        let index = index.clone().ok_or_else(|| {
            "internal: --libp2p-announce-after-fetch set but the store leg built no index"
                .to_string()
        })?;
        let door = match &plan {
            PublicationPlan::Allowlist => daemon::AnnounceAfterFetchDoor::Public(allowlist.clone()),
            PublicationPlan::Lan(lan) => daemon::AnnounceAfterFetchDoor::Lan(*lan),
        };
        let hook = daemon::Libp2pAnnounceAfterFetch::new(
            Arc::clone(&fabric),
            identity_seed,
            index,
            door,
            serve_budget,
            announce_budget,
            3600,
            config.store_dir.clone(),
            config.libp2p_announce_budget,
        );
        println!(
            "LIBP2P-ANNOUNCE-AFTER-FETCH enabled budget={}",
            config.libp2p_announce_budget
        );
        Some(Arc::new(hook) as Arc<dyn daemon_core::PostFetchAnnounce>)
    } else {
        None
    };

    println!(
        "daemon: libp2p PROVIDER started, serving + announcing {report} ({} bootstrap peer(s))",
        config.libp2p_bootstrap.len()
    );

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
            _index: index,
            post_fetch_announce,
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
    public_allowlist: &Arc<PublicNarAllowlist>,
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
            // TASK-280 #6: take the publication decision ONCE here (runs the isolation guard, so a
            // public-reachable no-allowlist provider aborts BEFORE any fabric/listener), derive the
            // lan-share confinement flag from it, and thread the SAME plan into
            // `install_libp2p_provider`. One authority for scope + confinement + announce eligibility.
            let plan = provider_publication_decision(config)?;
            let lan_share = matches!(plan, PublicationPlan::Lan(_));
            let (libp2p_source, raw_serve, guard) = install_libp2p_provider(
                config,
                config.libp2p_source_config(lan_share)?,
                plan,
                public_allowlist,
            )
            .await?;
            libp2p_raw_serve = Some(raw_serve);
            libp2p_provider_guard = Some(guard);
            // The accurate served-set report line (S seeds + P store paths + hook) is printed INSIDE
            // `install_libp2p_provider`, from the ACTUAL built legs (TASK-278) - never a
            // one-or-the-other count derived from the CLI flags here.
            Some(libp2p_source)
        } else {
            // Node A (CONSUMER): build + START the libp2p fabric (listen/bootstrap/dial)
            // and wrap it in the Libp2pNarSource. The returned fabric handle is dropped
            // here: the source holds its own Arc clone, keeping the node alive for the
            // process lifetime. The raw-serve decision is captured so a libp2p HIT
            // rewrites its narinfo to raw (see below).
            // A CONSUMER is never LAN-confined (confinement is a provider egress control), so
            // `lan_share = false` (TASK-280 #6): its scope is the default v1 unless the operator
            // opted into a pool with --libp2p-scope.
            let (fabric, libp2p_source, raw_serve) =
                build_libp2p_nar_source(config.libp2p_source_config(false)?).await?;
            libp2p_raw_serve = Some(raw_serve);
            // TASK-78: the non-provider path is CONSUME-ONLY by construction - it builds the fabric
            // WITHOUT a supplier, so the libp2p backend installs no serve gate (every inbound NAR
            // request is answered NotHeld) and runs no announce loop. When `--libp2p-leech` is set,
            // wrap the fabric in the SAME transport-agnostic seam mask the primary `daemon-libp2p`
            // binary uses (peer_fabric::LeechFabric) and ASSERT, fail-closed, that the give-side
            // axes are absent - so BOTH binaries enforce consume-only through the one capability
            // seam, not two divergent mechanisms. (The composite is iroh-native and consumes libp2p
            // as a `NarSource`, so the fetch rides `libp2p_source`; the wrapped fabric is the
            // seam-level guard. The behavioural end-to-end proof of the mask runs on daemon-libp2p,
            // which the leech e2e scenario launches.)
            if config.libp2p_leech {
                let leech: Arc<dyn PeerFabric> = Arc::new(LeechFabric::new(fabric));
                // Fail-closed: the mask MUST have removed serve + announce. If a future refactor
                // let either axis leak, refuse to start rather than run a leech that can give back.
                require_axes(leech.as_ref(), &[Axis::ProviderDirectory]).map_err(|e| {
                    format!("libp2p leech fabric lost a required consumer axis: {e}")
                })?;
                if leech.server().is_some() || leech.announcer().is_some() {
                    return Err(
                        "libp2p leech fabric still exposes a serve/announce axis after masking - \
                         refusing to start a leech that could give content back"
                            .into(),
                    );
                }
                println!(
                    "daemon: LIBP2P-LEECH consume-only (LeechFabric seam mask): serves NOTHING + \
                     announces NOTHING. HONEST LIMIT: it STILL SENDS discovery lookups (kad \
                     get_record + peer-routing), disclosing what it looks up to the DHT nodes it \
                     queries - a leech hides what it SERVES/ANNOUNCES, not what it LOOKS UP."
                );
            }
            println!(
                "daemon: libp2p {} source started, discovery converging ({} bootstrap peer(s), {} optional provider dial-addr override hint(s); dial addresses resolved via kad peer-routing)",
                if config.libp2p_leech { "LEECH" } else { "p2p" },
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

    // TASK-272: honour RUST_LOG on the SHIPPED composite binary. Without this the composite
    // linked `fabric-libp2p`'s `tracing::info!` diagnostics (autonat/relay/dcutr NAT verdicts +
    // provider dial-address resolution) but installed NO subscriber, so they were silently
    // swallowed even with RUST_LOG set. This is the SAME wiring the thin `daemon-libp2p` binary
    // uses (single source of truth in the daemon-libp2p lib), placed AFTER the two internal filter
    // subcommands (__dump-raw-nar / rewrite-narinfo) so those stdin->stdout subprocesses stay
    // quiet, and BEFORE config parse. Unset RUST_LOG installs nothing: unchanged behaviour.
    daemon_libp2p::init_tracing();

    let config = match Config::from_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("daemon: {err}");
            return ExitCode::from(2);
        }
    };

    // TASK-120: derive + validate the ONE authoritative operator contract (libp2p-primary path)
    // before touching the network; a contradictory mode blocks startup fail-closed.
    let contract = match derive_contract(&config) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("daemon: operator contract rejected: {err}");
            return ExitCode::from(2);
        }
    };
    // TASK-120 AC#10 (+ codex #1): the full fail-closed budget contract. TWO checks:
    //  (1) the frozen artifact verify — hash (freeze/identity), normative envelope, parity vs caps;
    //  (2) the EFFECTIVE serve-override ceiling — the values that ACTUALLY reach `ServeBudget`
    //      (`config.iroh_max_*`, CLI-overridable at :965) must be within the frozen envelope, so an
    //      override can only TIGHTEN it, never loosen it. Without (2) a `--iroh-max-serve-nar-bytes
    //      536870912` would serve 512 MiB while verify (which checks defaults) passed — the runtime
    //      bypass codex found. This guards BOTH serve paths (iroh :1496, libp2p :1995), which read
    //      the same config fields.
    let budget_check = || enforce_budget_contract(&contract, &config);

    // TASK-120 AC#7: `--preflight` is a static one-shot - render and EXIT. codex #5b: it must EXIT
    // NONZERO when the budget contract fails, so automation that checks only preflight's status
    // cannot accept a drifted/over-envelope budget (fail-OPEN).
    if config.preflight {
        println!("{}", contract.preflight());
        if let Err(err) = budget_check() {
            eprintln!("daemon: profile-budget contract rejected: {err}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    // Fail-closed BEFORE serving on the live path.
    if let Err(err) = budget_check() {
        eprintln!("daemon: profile-budget contract rejected: {err}");
        return ExitCode::FAILURE;
    }

    let shutdown_signals = match install_shutdown_signals() {
        Ok(signals) => signals,
        Err(error) => {
            eprintln!("daemon: shutdown signal setup failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("{}", banner());
    // TASK-120 AC#4 (startup surface) + AC#5: announce the derived operator MODE and the privacy
    // banner when diagnostics are opted in, so the running node's participation is legible.
    println!(
        "daemon: operator profile={} ({})",
        contract.profile,
        contract.profile.describe()
    );
    if contract.privacy.diagnostics_opt_in {
        eprintln!("daemon: {}", daemon::DIAGNOSTICS_WARNING);
    }
    // TASK-280 #3: hint a LAN-oriented consumer that defaults to the public v1 scope and would
    // silently miss a lan-share.v1 pool. Consume-capable = the DERIVED consume-only profile, NOT the
    // raw `--libp2p-leech` flag: a bare `--libp2p-mdns` (no `--libp2p-leech`) derives ConsumeOnly too
    // (has_bootstrap without a give-side), and without folding it here that node would discover a
    // lan-share.v1 provider, find NOTHING on v1, and get NO warning (codex HIGH). The effective scope
    // is the SAME canonical decision the fabric uses (a consumer is never a lan-share provider, so
    // `lan_share == false`).
    {
        let effective_scope = effective_network_scope(config.libp2p_scope.as_deref(), false);
        if should_hint_lan_share_scope(
            &effective_scope,
            matches!(contract.profile, SharingProfile::ConsumeOnly),
            config.libp2p_mdns,
            !config.libp2p_bootstrap.is_empty(),
        ) {
            eprintln!("daemon: NOTE — this consume-only node is {LAN_SHARE_SCOPE_HINT}");
        }
    }
    // TASK-273 AC#4 (disclosure parity): when LAN mDNS is active this NixOS-shipped binary
    // multicasts its presence + NodeId + listen multiaddrs to the link — disclose that on the first
    // log line, matching daemon-libp2p, so the operator sees the exposure without RUST_LOG surgery.
    if config.libp2p_mdns {
        println!(
            "daemon: LAN discovery ACTIVE via mDNS. This host multicasts its presence, NodeId, and \
             libp2p listen multiaddrs to the local link and answers any LAN querier — this is how \
             same-pin peers find you with zero config. Opt out: --libp2p-no-mdns (NixOS: \
             services.nix-p2p.libp2p.mdns = false)."
        );
    }

    // The correlation catalog lives in the server only: it populates it as
    // narinfos pass through and reads it at NAR-request time. UpstreamHttp needs
    // no catalog - the request carries the exact URL token to fetch.
    let catalog = Arc::new(NarCatalog::new());
    let upstream = match UpstreamHttp::new(&config.upstream) {
        Ok(upstream) => Arc::new(
            upstream
                .with_header_timeout(std::time::Duration::from_millis(config.header_timeout_ms))
                .with_connect_timeout(std::time::Duration::from_millis(config.connect_timeout_ms)),
        ),
        Err(err) => {
            eprintln!("daemon: bad --upstream: {err}");
            return ExitCode::from(2);
        }
    };
    // Fail-verbose UX (TASK-111, mped review): `connect_timeout` governs ONLY the
    // plaintext connect; on a `https://` upstream the connect+handshake is the frozen
    // `tls-upstream-v1` budget, so a NON-default --connect-timeout-ms is INERT there.
    // An operator who set it expecting effect must see that it did nothing, rather
    // than silently get no change (the primary production upstream, cache.nixos.org,
    // is https - exactly where this trap bites).
    if config.upstream.starts_with("https://") && config.connect_timeout_ms != CONNECT_TIMEOUT_MS {
        eprintln!(
            "daemon: WARNING: --connect-timeout-ms {} is INERT on an https:// upstream \
             (the TLS connect+handshake is the frozen tls-upstream-v1 budget, not \
             connect_timeout); it applies only to plaintext http:// upstreams",
            config.connect_timeout_ms
        );
    }

    // Layer the persistent narinfo cache over the upstream (task-8). The SAME
    // instance is the narinfo source AND the persistent correlation store, so a
    // warm-on-disk daemon dispatches the signed NarHash even after an in-memory-cold
    // restart. TASK-29: the cache is ON BY DEFAULT — a default XDG state dir is
    // resolved when no `--narinfo-cache-dir` is given (TASK-28 moved the fsync
    // off-worker, so default-enabling is safe). `--no-narinfo-cache` opts out; the
    // contradictory `--narinfo-cache-dir` + `--no-narinfo-cache` pair is already
    // rejected in `from_args`. The choice→source policy (soft-fail default vs fatal
    // explicit) lives ONCE in `daemon_core::build_narinfo_layer`, shared with
    // daemon-libp2p; here we only log the outcome and decide whether to abort.
    let choice = resolve_narinfo_cache_dir(
        config.narinfo_cache_dir.as_deref(),
        config.no_narinfo_cache,
        |k| std::env::var(k).ok(),
    );
    let (narinfo, correlation): (Arc<dyn NarinfoSource>, Arc<dyn CorrelationStore>) =
        match build_narinfo_layer(choice, upstream.clone(), Arc::new(SystemClock)) {
            NarinfoLayer::Cached {
                narinfo,
                correlation,
                dir,
            } => {
                println!("daemon: narinfo disk cache at {}", dir.display());
                (narinfo, correlation)
            }
            NarinfoLayer::PassThrough {
                narinfo,
                correlation,
                reason,
            } => {
                match reason {
                    PassThroughReason::Disabled => {
                        println!("daemon: narinfo disk cache disabled (--no-narinfo-cache)")
                    }
                    PassThroughReason::NoDefault => eprintln!(
                        "daemon: WARNING: no --narinfo-cache-dir and neither HOME nor \
                         XDG_STATE_HOME is set, so no default narinfo cache dir could be derived; \
                         running WITHOUT a persistent narinfo cache (pass --narinfo-cache-dir to \
                         enable it explicitly)"
                    ),
                    PassThroughReason::DefaultOpenFailed { dir, err } => eprintln!(
                        "daemon: WARNING: default narinfo cache dir {dir:?} is unusable ({err}); \
                         running WITHOUT a persistent narinfo cache"
                    ),
                }
                (narinfo, correlation)
            }
            NarinfoLayer::ExplicitOpenFailed { dir, err } => {
                eprintln!("daemon: cannot open narinfo cache dir {dir:?}: {err}");
                return ExitCode::FAILURE;
            }
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

    // The node's ONE public-NAR allowlist (TASK-103): opened + POPULATED here (proving each
    // `--libp2p-prove-public-narinfo` public through the trusted-key signature gate) BEFORE the
    // provider announce consults it, and shared into `App` so a serving daemon keeps learning into
    // the same authority. Disabled (nothing publishable) unless `--libp2p-public-allowlist-path`
    // is set - so a non-public node is unchanged.
    let public_allowlist = match config.build_public_allowlist() {
        Ok(allowlist) => allowlist,
        Err(err) => {
            eprintln!("daemon: public-NAR allowlist setup failed: {err}");
            shutdown_iroh_node(iroh_node).await;
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
        match setup_p2p_source(&config, upstream.clone(), transport, &public_allowlist).await {
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
        // TASK-103: the node's ONE public-NAR allowlist (the same instance the provider announce
        // gate consulted). Disabled when `--libp2p-public-allowlist-path` is unset (a non-public
        // node, unchanged); a configured one keeps learning as this daemon serves narinfos.
        public_allowlist,
        // TASK-77: the announce-after-fetch hook, present only when the libp2p provider install
        // built one (`--libp2p-announce-after-fetch`). `None` = consume-only (leech).
        post_fetch_announce: _libp2p_provider
            .as_ref()
            .and_then(|g| g.post_fetch_announce.clone()),
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

    fn guard_peer() -> PeerId {
        "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
            .parse()
            .unwrap()
    }

    fn guard_addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    // ---- TASK-120 composite safety fixes (#3a/#3b/#4/#5 + compat shim) ----

    /// #3a SAFETY: a GLOBAL-scope iroh provider is public-reachable, so it must NOT be labelled
    /// lan-share; without public-share (+ allowlist) it is REFUSED rather than mislabelled.
    #[test]
    fn iroh_global_scope_provider_without_public_share_is_refused() {
        let config = Config {
            iroh_provider: true,
            iroh_endpoint_scope: Some(EndpointScope::Global { port: 0 }),
            iroh_seed_nar: vec!["/srv/seed/x.nar".to_string()],
            ..Config::default()
        };
        let err = derive_contract(&config)
            .expect_err("a global-scope iroh provider without public-share must be refused");
        assert!(err.contains("GLOBAL endpoint scope"), "{err}");
    }

    /// #3a negative control + #4: an OFFLINE-scope iroh provider is genuinely isolated -> lan-share
    /// (honest), and the active iroh transport is reported as a deferred-reference mechanism so the
    /// preflight REPORT MATCHES THE WIRE (the e2e s6 provider uses exactly this scope).
    #[test]
    fn iroh_offline_scope_provider_is_lan_share_and_reports_iroh_active() {
        let config = Config {
            iroh_provider: true,
            iroh_endpoint_scope: Some(EndpointScope::OfflineTest { port: 0 }),
            iroh_seed_nar: vec!["/srv/seed/x.nar".to_string()],
            ..Config::default()
        };
        let contract =
            derive_contract(&config).expect("an offline-scope iroh provider is lan-share");
        assert_eq!(contract.profile, SharingProfile::LanShare);
        assert!(
            contract
                .active_reference_mechanisms
                .contains(&Mechanism::IrohTransport),
            "a running iroh give-side must be reported as an active deferred-reference mechanism"
        );
        // The preflight must SAY iroh is active (report matches wire), not report it merely pending.
        assert!(contract.preflight().contains("iroh-transport = ACTIVE"));
    }

    /// FIX B: an iroh CONSUMER (given `--iroh-peer` / `--p2p-claim`) fetches over iroh, so it is
    /// NOT upstream-only/HTTP-only - it is consume-only, and the preflight/registry mark iroh ACTIVE.
    /// A node reporting HTTP-only while an iroh transport fetches is the lie this fixes. Mutation:
    /// drop the iroh-consume inputs from the request and the node falsely reverts to upstream-only.
    #[test]
    fn iroh_consumer_is_not_upstream_only_and_reports_iroh_active() {
        let node_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let config = Config {
            iroh_peers: vec![parse_peer_spec(&format!("{node_hex}@127.0.0.1:35766")).unwrap()],
            ..Config::default()
        };
        let contract = derive_contract(&config).expect("an iroh consumer derives a profile");
        assert_ne!(
            contract.profile,
            SharingProfile::UpstreamOnly,
            "a node fetching over iroh must NOT report upstream-only/HTTP-only"
        );
        assert_eq!(contract.profile, SharingProfile::ConsumeOnly);
        assert!(
            contract
                .active_reference_mechanisms
                .contains(&Mechanism::IrohTransport),
            "an iroh-consuming node must report iroh ACTIVE"
        );
        assert!(contract.preflight().contains("iroh-transport = ACTIVE"));
    }

    /// TASK-257 (F1): the COMPOSITE daemon must never report upstream-only while its swarm opens
    /// the mDNS multicast socket. `--libp2p-mdns` IS a consumer's DHT ENTRY PATH (same as an
    /// explicit `--libp2p-bootstrap`), so a bare `--libp2p-mdns` node derives CONSUME-ONLY - and
    /// the WIRE really is mdns-active (the built source config opens the socket), so report matches
    /// wire. MUTATION: dropping `config.libp2p_mdns` from `has_bootstrap` re-derives UpstreamOnly
    /// while `libp2p_requested()` still opens the socket - the exact report-does-not-match-wire /
    /// AC#4 bug; the profile assertion reddens.
    #[test]
    fn composite_bare_mdns_is_consume_only_and_report_matches_wire() {
        let config = Config::from_args(vec!["--libp2p-mdns".to_string()])
            .expect("bare --libp2p-mdns parses");
        let contract = derive_contract(&config).expect("bare --libp2p-mdns derives a profile");
        assert_ne!(
            contract.profile,
            SharingProfile::UpstreamOnly,
            "a node opening the mDNS multicast socket must NOT report upstream-only (zero-P2P)"
        );
        assert_eq!(contract.profile, SharingProfile::ConsumeOnly);
        assert!(
            contract.lan_mdns_enabled,
            "the contract must report mDNS active"
        );
        // The WIRE the report must match: the swarm this config builds opens the mDNS socket.
        assert!(
            config.libp2p_requested(),
            "bare --libp2p-mdns must engage the libp2p swarm"
        );
        assert!(
            config
                .libp2p_source_config(false)
                .expect("bare --libp2p-mdns builds a source config")
                .mdns_enabled,
            "the swarm this config builds opens the mDNS socket - the report must match the wire"
        );
    }

    /// TASK-257 (F1): the explicit contradiction `--profile upstream-only --libp2p-mdns` must FAIL
    /// CLOSED (as daemon-libp2p does) - upstream-only is zero-P2P/zero-multicast and cannot carry an
    /// mDNS socket. Caught at parse OR at the compat-shim cross-check in derive_contract.
    #[test]
    fn composite_upstream_only_plus_mdns_is_refused() {
        let parsed = Config::from_args(vec![
            "--profile".to_string(),
            "upstream-only".to_string(),
            "--libp2p-mdns".to_string(),
        ]);
        let err = match parsed {
            Err(e) => e,
            Ok(cfg) => derive_contract(&cfg)
                .expect_err("--profile upstream-only + --libp2p-mdns must fail closed"),
        };
        assert!(
            err.contains("disagrees") || err.to_lowercase().contains("upstream"),
            "the refusal must name the upstream-only contradiction: {err}"
        );
    }

    /// #3b: `iroh_publish_node` is a give-side publication, so `publishes_records` must reflect it -
    /// never report `publishes_records=false` while an iroh publication capability is installed.
    #[test]
    fn iroh_publish_node_is_reflected_in_publishes_records() {
        let config = Config {
            iroh_publish_node: true,
            iroh_endpoint_scope: Some(EndpointScope::OfflineTest { port: 0 }),
            ..Config::default()
        };
        let contract = derive_contract(&config).expect("an iroh-publishing node derives a profile");
        assert!(
            contract.profile.announces(),
            "an iroh-publishing node must report publishes_records=true"
        );
    }

    /// The compat shim: an explicit `--profile` that disagrees with the flags fails closed.
    #[test]
    fn explicit_profile_disagreement_fails_closed() {
        let config = Config {
            explicit_profile: Some("upstream-only".to_string()),
            libp2p_provider: true,
            libp2p_seed_nar: vec![(
                "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm"
                    .parse()
                    .unwrap(),
                "/tmp/x.nar".to_string(),
            )],
            ..Config::default()
        };
        let err = derive_contract(&config)
            .expect_err("--profile upstream-only with provider flags must fail closed");
        assert!(err.contains("disagrees"), "{err}");
    }

    /// TASK-120 AC#10: the composite iroh serve budget is the FROZEN fabric-iroh reference
    /// (256 MiB / 1 GiB / 120 s), and after the AC#10 freeze the libp2p-primary `ResourceCaps`
    /// CONVERGE on the SAME normative envelope. What used to be a documented 512 MiB / 300 s
    /// divergence is now a single ceiling both paths honour.
    #[test]
    fn iroh_budget_matches_the_normative_caps() {
        assert_eq!(DEFAULT_MAX_SERVE_NAR_BYTES, 256 * 1024 * 1024);
        assert_eq!(
            DEFAULT_MAX_SERVE_DURATION,
            std::time::Duration::from_secs(120)
        );
        let caps = ResourceCaps::default();
        assert_eq!(
            DEFAULT_MAX_SERVE_NAR_BYTES, caps.max_nar_bytes_uncompressed,
            "AC#10: libp2p-primary caps must adopt the normative 256 MiB single-NAR envelope"
        );
        assert_eq!(
            DEFAULT_MAX_SERVE_DURATION.as_millis() as u64,
            caps.serve_duration_ms,
            "AC#10: libp2p-primary caps must adopt the normative 120 s serve duration"
        );
    }

    /// codex #1 BITE (composite binary wiring): an operator serve-override that LOOSENS the frozen
    /// 256 MiB / 1 GiB / 120 s envelope must fail the startup budget contract that the live path AND
    /// preflight call (`enforce_budget_contract`). Proves the runtime bypass is closed: verify alone
    /// (defaults) passed such an override before this fix.
    #[test]
    fn over_envelope_serve_override_is_rejected_at_startup() {
        let contract = OperatorContract::for_profile(SharingProfile::PublicShare);
        // Baseline: the shipped defaults (256 MiB / 1 GiB / 120 s) pass.
        enforce_budget_contract(&contract, &Config::default())
            .expect("the shipped defaults are within the envelope");
        // 512 MiB single-NAR override → rejected at startup.
        let over_single = Config {
            iroh_max_serve_nar_bytes: 512 * 1024 * 1024,
            ..Config::default()
        };
        let err = enforce_budget_contract(&contract, &over_single)
            .expect_err("a 512 MiB serve override must be rejected");
        assert!(
            err.contains("exceeds the frozen normative ceiling")
                && err.contains("single_nar_bytes_uncompressed_nar"),
            "{err}"
        );
        // >1 GiB inflight override → rejected.
        let over_inflight = Config {
            iroh_max_inflight_nar_bytes: 2 * 1024 * 1024 * 1024,
            ..Config::default()
        };
        assert!(
            enforce_budget_contract(&contract, &over_inflight).is_err(),
            "a >1 GiB inflight override must be rejected"
        );
        // 300 s serve-duration override → rejected.
        let over_dur = Config {
            iroh_max_serve_duration_ms: 300_000,
            ..Config::default()
        };
        assert!(
            enforce_budget_contract(&contract, &over_dur).is_err(),
            "a 300 s serve-duration override must be rejected"
        );
    }

    /// R2-1: a valid TIGHTENING serve override (64 MiB / 200 MiB inflight / 90 s, all below the
    /// frozen ceiling) must be REFLECTED in `contract.caps` and in preflight's "effective resource
    /// controls" — the display shows what is actually in force, not the frozen ceiling/default. The
    /// frozen CEILING (256 MiB) is still surfaced separately. `derive_contract` derives the profile
    /// from flags (default = upstream-only), which is enough to exercise the effective-caps wiring.
    #[test]
    fn tightened_serve_override_is_reflected_in_effective_controls() {
        let config = Config {
            iroh_max_serve_nar_bytes: 64 * 1024 * 1024, // 64 MiB — a valid tightening
            iroh_max_inflight_nar_bytes: 200 * 1024 * 1024, // 200 MiB
            iroh_max_serve_duration_ms: 90_000,         // 90 s
            ..Config::default()
        };
        let contract = derive_contract(&config).expect("contract derives");
        // The effective caps carry the tightened override, not the frozen default.
        assert_eq!(contract.caps.max_nar_bytes_uncompressed, 64 * 1024 * 1024);
        assert_eq!(
            contract.caps.max_inflight_bytes_uncompressed,
            200 * 1024 * 1024
        );
        assert_eq!(contract.caps.serve_duration_ms, 90_000);
        // A tightening is within the envelope, so startup passes.
        enforce_budget_contract(&contract, &config).expect("a tightening override passes");
        let preflight = contract.preflight();
        // Effective resource controls show the EFFECTIVE (tightened) value, not the 256 MiB default.
        assert!(
            preflight.contains("max_nar_bytes_uncompressed=67108864"),
            "effective controls must reflect the 64 MiB tightening:\n{preflight}"
        );
        assert!(
            !preflight.contains("max_nar_bytes_uncompressed=268435456"),
            "effective controls must NOT still show the 256 MiB default:\n{preflight}"
        );
        // The frozen artifact CEILING is still surfaced (256 MiB) as the separate normative envelope.
        assert!(
            preflight.contains("single_nar_bytes_uncompressed_nar=268435456"),
            "the frozen ceiling must still be surfaced:\n{preflight}"
        );
    }

    #[test]
    fn lan_isolation_guard_permits_a_provably_isolated_loopback_provider() {
        // TASK-102 fix cycle #2 (composite binary). A loopback-listen provider with NO bootstrap
        // and NO provider-addr has no public-reach signal -> permitted.
        let config = Config {
            libp2p_listen: Some(guard_addr("/ip4/127.0.0.1/tcp/0")),
            ..Config::default()
        };
        assert!(
            lan_share_or_refuse(&config).is_ok(),
            "a no-public-reach-signal loopback provider is permitted"
        );
    }

    #[test]
    fn lan_isolation_guard_refuses_a_bootstrapped_provider() {
        let config = Config {
            libp2p_bootstrap: vec![(guard_peer(), guard_addr("/ip4/127.0.0.1/tcp/4001"))],
            libp2p_listen: Some(guard_addr("/ip4/127.0.0.1/tcp/0")),
            ..Config::default()
        };
        let err = lan_share_or_refuse(&config)
            .expect_err("a bootstrapped announce without an allowlist must be refused");
        assert!(
            err.contains("TASK-103"),
            "the refusal must name TASK-103: {err}"
        );
    }

    #[test]
    fn lan_isolation_guard_refuses_a_provider_addr_with_empty_bootstrap() {
        // THE residual bite (fix cycle #2): before the fix the composite guard checked ONLY the
        // bootstrap vector, so this provider (empty bootstrap, a provider-addr seeded into kad)
        // MINTED a LanShare and announced UNGATED. It must now REFUSE.
        let config = Config {
            libp2p_provider_addrs: vec![(guard_peer(), guard_addr("/ip4/127.0.0.1/tcp/4001"))],
            libp2p_listen: Some(guard_addr("/ip4/127.0.0.1/tcp/0")),
            ..Config::default()
        };
        let err = lan_share_or_refuse(&config)
            .expect_err("a provider-addr with empty bootstrap must be refused");
        assert!(
            err.contains("--libp2p-provider-addr") && err.contains("TASK-103"),
            "the refusal must name the provider-addr signal and TASK-103: {err}"
        );
    }

    #[test]
    fn lan_isolation_guard_refuses_a_public_listen_provider() {
        let config = Config {
            libp2p_listen: Some(guard_addr("/ip4/0.0.0.0/tcp/4001")),
            ..Config::default()
        };
        let err =
            lan_share_or_refuse(&config).expect_err("a wildcard/public listen must be refused");
        assert!(err.contains("TASK-103"), "must name TASK-103: {err}");
    }

    #[test]
    fn lan_isolation_guard_permits_a_private_lan_listen_provider() {
        // TASK-276 PARITY (composite binary): the shared isolation predicate reached via this
        // crate's `lan_share_or_refuse` now admits RFC1918/ULA private listens for a no-allowlist
        // lan-share, so two same-pin machines serve each other cross-host. A GLOBAL/wildcard listen
        // (above) still refuses.
        for a in [
            "/ip4/10.0.0.5/tcp/4001",
            "/ip4/192.168.1.5/tcp/4001",
            "/ip4/172.16.9.9/tcp/4001",
            "/ip6/fd00::1/tcp/4001",
        ] {
            let config = Config {
                libp2p_listen: Some(guard_addr(a)),
                ..Config::default()
            };
            assert!(
                lan_share_or_refuse(&config).is_ok(),
                "a private-LAN listen ({a}) is LAN-only and must be permitted"
            );
        }
    }

    #[test]
    fn lan_isolation_guard_refuses_a_global_listen_provider() {
        // TASK-276: distinct from the wildcard test — a GLOBAL/routable unicast listen must still
        // refuse under a no-allowlist lan-share (the relax admits ONLY provably-private ranges).
        let config = Config {
            libp2p_listen: Some(guard_addr("/ip4/8.8.8.8/tcp/4001")),
            ..Config::default()
        };
        let err =
            lan_share_or_refuse(&config).expect_err("a global/routable listen must be refused");
        assert!(err.contains("TASK-103"), "must name TASK-103: {err}");
    }

    #[test]
    fn publication_decision_aborts_before_any_fabric_for_a_public_no_allowlist_provider() {
        // FIX #2 (composite binary): the single publication decision Err's on a wildcard, a global,
        // OR a circuit listen for a no-allowlist provider, so `?` aborts before the fabric is built.
        for bad in [
            "/ip4/0.0.0.0/tcp/4001",
            "/ip4/8.8.8.8/tcp/4001",
            "/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit",
        ] {
            let config = Config {
                libp2p_listen: Some(guard_addr(bad)),
                ..Config::default()
            };
            assert!(
                provider_publication_decision(&config).is_err(),
                "a no-allowlist provider with listen {bad} must abort at the decision (before fabric)"
            );
        }
        let ok = Config {
            libp2p_listen: Some(guard_addr("/ip4/192.168.1.7/tcp/4001")),
            ..Config::default()
        };
        assert!(
            matches!(
                provider_publication_decision(&ok),
                Ok(PublicationPlan::Lan(_))
            ),
            "a provably-private no-allowlist provider yields a LAN publication plan"
        );
    }

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
                "--connect-timeout-ms",
                "750",
            ]
            .map(String::from),
        )
        .unwrap();
        assert_eq!(config.listen.port(), 9000);
        assert_eq!(config.upstream, "http://example:80");
        assert_eq!(config.priority, 25);
        assert!(!config.want_mass_query);
        assert_eq!(config.header_timeout_ms, 250);
        assert_eq!(config.connect_timeout_ms, 750);
    }

    #[test]
    fn default_timeouts_are_distinct_connect_and_header_numbers() {
        // TASK-111 AC#1: the two are DIFFERENT physics and DIFFERENT defaults, not
        // one number. connect stays tight (fast-fail against dead); header is WAN-sane.
        let config = Config::default();
        assert_eq!(config.connect_timeout_ms, CONNECT_TIMEOUT_MS);
        assert_eq!(config.header_timeout_ms, HEADER_TIMEOUT_MS);
        assert_eq!(config.connect_timeout_ms, 1000);
        assert_eq!(config.header_timeout_ms, 15000);
        assert!(
            config.header_timeout_ms > config.connect_timeout_ms,
            "header (upstream's own work) must tolerate more than connect (~1 RTT)"
        );
    }

    #[test]
    fn connect_timeout_zero_is_rejected() {
        // 0 ms bricks the daemon (every connect fails before it can complete),
        // mirroring --header-timeout-ms; a units typo (seconds) is rejected too.
        assert!(
            Config::from_args(["--connect-timeout-ms".to_string(), "0".to_string()]).is_err(),
            "0 must be rejected"
        );
        assert!(
            Config::from_args(["--connect-timeout-ms".to_string(), "9999999".to_string()]).is_err()
        );
        assert_eq!(
            Config::from_args(["--connect-timeout-ms".to_string(), "500".to_string()])
                .unwrap()
                .connect_timeout_ms,
            500
        );
    }

    #[test]
    fn unknown_flag_fails_fast() {
        assert!(Config::from_args(["--nope".to_string()]).is_err());
        assert!(Config::from_args(["--listen".to_string()]).is_err());
        assert!(Config::from_args(["--priority".to_string(), "abc".to_string()]).is_err());
    }

    /// TASK-273 FLAG-SURFACE PARITY: the composite binary must ACCEPT `--libp2p-no-mdns` (the NixOS
    /// module emits it for an explicit tri-state opt-out) rather than fail-fast as an unknown flag,
    /// and it sets mDNS OFF. MUTATION: dropping the parse arm makes this an `unknown flag` error and
    /// the accept assertion reddens - proving the arm is what keeps a `libp2p.mdns = false` NixOS
    /// deployment from crashing the daemon at startup.
    #[test]
    fn libp2p_no_mdns_is_accepted_and_sets_mdns_off() {
        let cfg = Config::from_args(["--libp2p-no-mdns".to_string()])
            .expect("--libp2p-no-mdns must be accepted (the NixOS module emits it)");
        assert!(!cfg.libp2p_mdns, "--libp2p-no-mdns sets mDNS off");
        // ...and the affirmative flag still turns it on (the two are a legible pair).
        let on = Config::from_args(["--libp2p-mdns".to_string()]).expect("--libp2p-mdns parses");
        assert!(on.libp2p_mdns);
    }

    /// TASK-273 (#8) parity: passing BOTH `--libp2p-mdns` and `--libp2p-no-mdns` (either order) is
    /// contradictory and fails closed on the composite binary too, matching daemon-libp2p.
    #[test]
    fn contradictory_mdns_flags_fail_closed() {
        let err = Config::from_args(["--libp2p-mdns".to_string(), "--libp2p-no-mdns".to_string()])
            .expect_err("--libp2p-mdns then --libp2p-no-mdns must fail closed");
        assert!(err.contains("exactly one"), "{err}");
        let err2 = Config::from_args(["--libp2p-no-mdns".to_string(), "--libp2p-mdns".to_string()])
            .expect_err("--libp2p-no-mdns then --libp2p-mdns must fail closed");
        assert!(err2.contains("exactly one"), "{err2}");
    }

    /// TASK-278: `--libp2p-seed-nar` + `--libp2p-announce-after-fetch` is now a VALID additive
    /// provider on the composite binary (seed leg + growth store leg from ONE fabric), matching
    /// daemon-libp2p. The old interim fail-closed is gone; `install_libp2p_provider` unions the two.
    /// MUTATION: reinstating the interim guard makes this parse RED.
    #[test]
    fn seed_nar_with_announce_after_fetch_is_accepted_as_additive() {
        let cfg = Config::from_args([
            "--libp2p-provider".to_string(),
            "--libp2p-listen".to_string(),
            "/ip4/127.0.0.1/tcp/0".to_string(),
            "--libp2p-mdns".to_string(),
            "--libp2p-seed-nar".to_string(),
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm=/tmp/app.nar".to_string(),
            "--libp2p-announce-after-fetch".to_string(),
        ])
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
    /// rejected fail-loud. MUTATION: delete the dedup guard -> parses Ok and the report counts 2
    /// while the supplier answers one digest.
    #[test]
    fn duplicate_narhash_across_seed_and_store_is_rejected() {
        let err = Config::from_args([
            "--libp2p-provider".to_string(),
            "--libp2p-listen".to_string(),
            "/ip4/127.0.0.1/tcp/0".to_string(),
            "--libp2p-mdns".to_string(),
            "--libp2p-seed-nar".to_string(),
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm=/tmp/app.nar".to_string(),
            "--libp2p-provide-store".to_string(),
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm=/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-app".to_string(),
        ])
        .expect_err("a NarHash appearing as both a seed and a store path must be rejected");
        assert!(
            err.contains("0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm")
                && err.contains("more than once"),
            "the refusal must name the duplicated NarHash: {err}"
        );
    }

    /// TASK-278 #4: announce-after-fetch with a ZERO growth budget is rejected. MUTATION: remove the
    /// guard -> parses and the report's "grows on demand" clause is falsified with remaining==0.
    #[test]
    fn announce_after_fetch_with_zero_growth_budget_is_rejected() {
        let err = Config::from_args([
            "--libp2p-provider".to_string(),
            "--libp2p-listen".to_string(),
            "/ip4/127.0.0.1/tcp/0".to_string(),
            "--libp2p-mdns".to_string(),
            "--libp2p-announce-after-fetch".to_string(),
            "--libp2p-announce-budget".to_string(),
            "0".to_string(),
        ])
        .expect_err("announce-after-fetch with a zero growth budget must be rejected");
        assert!(
            err.contains("grows nothing") && err.contains("--libp2p-announce-budget 0"),
            "the refusal must name the zero growth budget: {err}"
        );
    }

    /// TASK-278 #4 precision: a STATIC-only provider with --libp2p-announce-budget 0 is NOT caught.
    #[test]
    fn static_provider_with_zero_announce_budget_is_accepted() {
        Config::from_args([
            "--libp2p-provider".to_string(),
            "--libp2p-listen".to_string(),
            "/ip4/127.0.0.1/tcp/0".to_string(),
            "--libp2p-mdns".to_string(),
            "--libp2p-seed-nar".to_string(),
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm=/tmp/app.nar".to_string(),
            "--libp2p-announce-budget".to_string(),
            "0".to_string(),
        ])
        .expect(
            "a static-only provider with announce-budget 0 is valid (growth guard must not fire)",
        );
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

    #[test]
    fn parse_narinfo_cache_flags() {
        // TASK-29: the cache defaults on (dir resolved later, not at parse), the
        // off-switch sets the bool, and the two together are a usage error.
        let default = Config::from_args(std::iter::empty()).unwrap();
        assert_eq!(default.narinfo_cache_dir, None);
        assert!(!default.no_narinfo_cache);

        let off = Config::from_args(["--no-narinfo-cache".to_string()]).unwrap();
        assert!(off.no_narinfo_cache);
        assert_eq!(off.narinfo_cache_dir, None);

        let explicit =
            Config::from_args(["--narinfo-cache-dir".to_string(), "/srv/nic".to_string()]).unwrap();
        assert_eq!(explicit.narinfo_cache_dir.as_deref(), Some("/srv/nic"));

        let contradiction = Config::from_args([
            "--narinfo-cache-dir".to_string(),
            "/srv/nic".to_string(),
            "--no-narinfo-cache".to_string(),
        ]);
        assert!(
            contradiction
                .as_ref()
                .is_err_and(|e| e.contains("contradictory")),
            "both flags must be rejected, got {contradiction:?}"
        );
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
        let src = config.libp2p_source_config(false).unwrap();
        assert_eq!(src.identity_seed, [0x11u8; 32]);
        assert_eq!(src.network_scope, "task162");
        assert_eq!(src.bootstrap.len(), 1);
        assert_eq!(src.provider_addrs.len(), 1);
        assert!(src.listen.is_some());
        assert!(
            src.additional_listens.is_empty(),
            "the composite CLI currently exposes one listen address"
        );
        assert!(
            src.external_addresses.is_empty(),
            "the composite CLI currently exposes no external-address flag"
        );
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
    fn libp2p_leech_is_consume_only_and_conflicts_with_give_side_flags() {
        // TASK-78 parity with the thin `daemon-libp2p` binary. A leech consumer with a bootstrap
        // parses and is consume-only (not a provider); it trips the bootstrap requirement on its
        // own; and it is refused fail-fast alongside any give-side flag.
        let peer = PeerId::random();
        let boot = format!("{peer}@/ip4/127.0.0.1/tcp/4001");
        let ok = Config::from_args(vec![
            "--libp2p-leech".to_string(),
            "--libp2p-bootstrap".to_string(),
            boot.clone(),
        ])
        .expect("a leech consumer with a bootstrap parses");
        assert!(ok.libp2p_leech && !ok.libp2p_provider && ok.libp2p_requested());

        // A lone --libp2p-leech requests libp2p, so the missing bootstrap is caught (not ignored).
        let err = Config::from_args(vec!["--libp2p-leech".to_string()]).unwrap_err();
        assert!(err.contains("libp2p-bootstrap"), "got {err}");

        // Conflict with a give-side flag is refused, naming both.
        let nar_hash = NarHashKey::from_sha256_bytes([0x33u8; 32]);
        let err = Config::from_args(vec![
            "--libp2p-leech".to_string(),
            "--libp2p-bootstrap".to_string(),
            boot.clone(),
            "--libp2p-provider".to_string(),
            "--libp2p-listen".to_string(),
            "/ip4/127.0.0.1/tcp/0".to_string(),
            "--libp2p-seed-nar".to_string(),
            format!("{nar_hash}=/srv/seed/a.nar"),
        ])
        .unwrap_err();
        assert!(
            err.contains("--libp2p-leech") && err.contains("--libp2p-provider"),
            "the refusal must name both conflicting flags: {err}"
        );
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
        let src = config.libp2p_source_config(false).unwrap();
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
        let a = config.libp2p_source_config(false).unwrap();
        let b = config.libp2p_source_config(false).unwrap();
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

#[cfg(test)]
mod additive_supply_tests {
    //! TASK-278 AC#3 (unit, biting) on the COMPOSITE binary: `build_libp2p_provider_supply` UNIONS
    //! the seed leg with the store-supply leg, so `--libp2p-seed-nar S` + `--libp2p-provide-store P`
    //! + `--libp2p-announce-after-fetch` serves BOTH content digests and reports both counts.
    //!
    //! MUTATION: restore the pre-278 mode-select (store leg XOR seed leg on `announce_after_fetch`)
    //! and the `plan(S)` assertion goes RED - the seed is silently dropped (finding #1).
    use super::{Config, build_libp2p_provider_supply, libp2p_provider_serve_budget};
    use daemon::{Blake3Digest, NarHashKey, NodeId};
    use daemon_core::{NarDumper, RegularFileNarDumper};
    use fabric_libp2p::Libp2pNarSupplier;
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
        std::env::temp_dir().join(format!("nix-p2p-task278-composite-{stem}-{suffix}"))
    }

    #[test]
    fn union_serves_seed_and_store_and_reports_both() {
        let seed_bytes = b"nix-archive-1 SEED nar bytes for TASK-278 composite union".to_vec();
        let store_bytes = b"nix-archive-1 STORE nar bytes for TASK-278 composite union".to_vec();
        let seed_content = Blake3Digest::from_raw_nar(&seed_bytes);
        let store_content = Blake3Digest::from_raw_nar(&store_bytes);
        let seed_key = NarHashKey::from_raw_nar(&seed_bytes);
        let store_key = NarHashKey::from_raw_nar(&store_bytes);

        let seed_path = unique_temp("seed.nar");
        let store_path = unique_temp("store.nar");
        std::fs::write(&seed_path, &seed_bytes).unwrap();
        std::fs::write(&store_path, &store_bytes).unwrap();

        let cfg = Config {
            libp2p_provider: true,
            libp2p_seed_nar: vec![(seed_key, seed_path.to_string_lossy().into_owned())],
            libp2p_provide_store: vec![(store_key, store_path.to_string_lossy().into_owned())],
            libp2p_announce_after_fetch: true,
            ..Config::default()
        };
        let serve_budget =
            libp2p_provider_serve_budget(&cfg).expect("default serve budget is well-formed");
        let supply = build_libp2p_provider_supply(
            &cfg,
            &serve_budget,
            Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
            NodeId::from_bytes([0u8; 32]),
        )
        .expect("additive supply builds from seed + provide-store + announce-after-fetch");

        assert!(
            supply.supplier.plan(&seed_content).is_some(),
            "the union must serve the seeded NAR S (mode-select would DROP it)"
        );
        assert!(
            supply.supplier.plan(&store_content).is_some(),
            "the union must serve the provide-store path P from the store leg"
        );
        let unknown = Blake3Digest::from_raw_nar(b"never seeded, never provided");
        assert!(supply.supplier.plan(&unknown).is_none());

        assert_eq!(supply.seeds.len(), 1);
        assert_eq!(supply.provisions.len(), 1);
        assert!(supply.index.is_some());
        assert!(
            supply.report.contains("1 seeded NAR(s)")
                && supply.report.contains("1 /nix/store path(s)")
                && supply.report.contains("announce-after-fetch"),
            "the startup report must count BOTH legs and the growth hook: {}",
            supply.report
        );

        let _ = std::fs::remove_file(&seed_path);
        let _ = std::fs::remove_file(&store_path);
    }

    #[test]
    fn seed_plus_announce_after_fetch_serves_the_seed_and_opens_the_growth_index() {
        let seed_bytes = b"nix-archive-1 composite seed for announce-after-fetch growth".to_vec();
        let seed_content = Blake3Digest::from_raw_nar(&seed_bytes);
        let seed_key = NarHashKey::from_raw_nar(&seed_bytes);
        let seed_path = unique_temp("seed-grow.nar");
        std::fs::write(&seed_path, &seed_bytes).unwrap();

        let cfg = Config {
            libp2p_provider: true,
            libp2p_seed_nar: vec![(seed_key, seed_path.to_string_lossy().into_owned())],
            libp2p_announce_after_fetch: true,
            ..Config::default()
        };
        let serve_budget = libp2p_provider_serve_budget(&cfg).expect("serve budget");
        let supply = build_libp2p_provider_supply(
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
        assert!(supply.index.is_some());
        assert_eq!(supply.provisions.len(), 0);

        let _ = std::fs::remove_file(&seed_path);
    }
}
