//! nix-p2p product daemon - binary entrypoint.
//!
//! A thin wrapper over the `daemon` library: parse flags, wire the single
//! `UpstreamHttp` behind all three upstream traits, and serve. All behaviour
//! lives in the library so the integration tests drive the exact same stack.
//!
//! The near-identical `banner()` in `testproxy` is deliberate duplication, not
//! an oversight (task-1 note): factoring it into a shared crate is exactly the
//! coupling the PRD forbids until a second consumer genuinely earns it.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;

use daemon::cacheinfo::DEFAULT_PRIORITY;
use daemon::claim::CLAIM_SCHEMA_VERSION;
use daemon::{
    AddressLookupCapability, AllowlistRawServe, App, Blake3Digest, CacheInfo, Claim,
    CorrelationStore, DEFAULT_MAX_INFLIGHT_NAR_BYTES, DEFAULT_MAX_SERVE_DURATION,
    DEFAULT_MAX_SERVE_NAR_BYTES, EndpointProfile, EndpointScope, FallbackNarSource,
    FileNarSupplier, IdentitySource, InMemoryDiscovery, IrohNode, IrohNodeBuilder, IrohPeerAddr,
    IrohProviderConfig, IrohTransport, KnownPayload, KnownTransport, NarCatalog, NarHashKey,
    NarSource, NarinfoDiskCache, NarinfoSource, NoRawServe, NodeId, NullCorrelation,
    RawServeDecision, RelayCapability, ServeBudget, SystemClock, TaskSupervisor,
    TransportNarSource, TransportRegistry, UpstreamHttp, serve,
};
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
                other => return Err(format!("unknown flag {other:?}")),
            }
        }
        let iroh_enabled =
            config.iroh_provider || !config.iroh_peers.is_empty() || !config.p2p_claims.is_empty();
        if iroh_enabled && config.iroh_port.is_none() {
            return Err("Iroh is configured but --iroh-port is missing; refusing an ephemeral discovery address".into());
        }
        Ok(config)
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
async fn setup_iroh_node(config: &Config) -> Result<Option<IrohNode>, String> {
    let enabled =
        config.iroh_provider || !config.iroh_peers.is_empty() || !config.p2p_claims.is_empty();
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
    let builder = IrohNodeBuilder::new(
        EndpointProfile { scope },
        IdentitySource::Persistent { state_dir },
        RelayCapability::Disabled,
        AddressLookupCapability::Disabled,
    )
    .map_err(|error| error.to_string())?;

    if !config.iroh_provider {
        return builder
            .spawn()
            .await
            .map(Some)
            .map_err(|error| error.to_string());
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

async fn shutdown_after_setup_error(node: IrohNode, error: String) -> String {
    let cleanup = node
        .shutdown()
        .await
        .map(|outcome| format!("shutdown outcome {outcome:?}"))
        .unwrap_or_else(|cleanup_error| format!("shutdown failed: {cleanup_error}"));
    format!("{error}; cleanup={cleanup}")
}

/// Node A: assemble the p2p `NarSource` (iroh transport wired to the configured
/// peers + an in-memory discovery seeded from the configured claims) IN FRONT of
/// the HTTP upstream, plus the matching raw-serve allowlist. Both are built from
/// the ONE `p2p_claims` set so discovery and raw-serve can never drift.
async fn setup_p2p_source(
    config: &Config,
    upstream: Arc<UpstreamHttp>,
    transport: IrohTransport,
) -> Result<(Arc<dyn NarSource>, Arc<dyn RawServeDecision>), String> {
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

    let transport_source = Arc::new(TransportNarSource::new(registry, Arc::new(discovery)));
    let nar: Arc<dyn NarSource> = Arc::new(FallbackNarSource::new(transport_source, upstream));
    let raw_serve: Arc<dyn RawServeDecision> = Arc::new(AllowlistRawServe::new(
        config.p2p_claims.iter().map(|c| c.nar_hash.clone()),
    ));

    println!(
        "daemon: p2p source wired ({} peer(s), {} claim(s))",
        config.iroh_peers.len(),
        config.p2p_claims.len()
    );
    Ok((nar, raw_serve))
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

#[tokio::main]
async fn main() -> ExitCode {
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
    let iroh_node = match setup_iroh_node(&config).await {
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
    let (nar, raw_serve): (Arc<dyn NarSource>, Arc<dyn RawServeDecision>) =
        if config.iroh_peers.is_empty() && config.p2p_claims.is_empty() {
            (upstream.clone(), Arc::new(NoRawServe))
        } else {
            let transport = match &iroh_node {
                Some(node) => node.transport_handle(),
                None => {
                    eprintln!("daemon: p2p source requested without an Iroh node runtime");
                    return ExitCode::FAILURE;
                }
            };
            match setup_p2p_source(&config, upstream.clone(), transport).await {
                Ok(pair) => pair,
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
