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
    CacheInfo, CorrelationStore, NarSource, NarinfoDiskCache, NarinfoSource, NullCorrelation,
    RawUpstream, RunConfig, SystemClock, UpstreamHttp, run,
};
use daemon_libp2p::{
    Libp2pSourceConfig, build_libp2p_nar_source, build_libp2p_provider_source,
    sign_libp2p_provider_record,
};
use fabric_libp2p::{Libp2pFabric, MemoryNarSupplier, Multiaddr, PeerId};
use peer_fabric::{
    AnnounceBudget, Axis, DiscoveryBudget, PeerFabric, SafetyEnvelope, ServeBudget, ServeHandle,
    TransportTag,
};
use tokio::net::TcpListener;

/// PROVISIONAL serve bounds (uncompressed NAR bytes / wall clock). Backend-neutral
/// `peer_fabric::ServeBudget` numbers; explicit `--libp2p-max-*` knobs are a follow-up once
/// the operating numbers are pinned. A large-but-finite default, never "unlimited".
const DEFAULT_MAX_SERVE_NAR_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_INFLIGHT_NAR_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_MAX_SERVE_DURATION_MS: u64 = 300_000;

struct Config {
    listen: SocketAddr,
    upstream: String,
    header_timeout_ms: u64,
    narinfo_cache_dir: Option<String>,
    store_dir: String,
    priority: u32,
    want_mass_query: bool,
    libp2p_bootstrap: Vec<(PeerId, Multiaddr)>,
    libp2p_provider_addrs: Vec<(PeerId, Multiaddr)>,
    libp2p_listen: Option<Multiaddr>,
    libp2p_scope: Option<String>,
    libp2p_identity_seed: Option<[u8; 32]>,
    libp2p_provider: bool,
    libp2p_seed_nar: Vec<(daemon_core::NarHashKey, String)>,
    libp2p_print_peer_address: bool,
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

fn random_identity_seed() -> Result<[u8; 32], String> {
    use std::io::Read;
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|e| format!("generating libp2p identity seed from /dev/urandom: {e}"))?;
    Ok(seed)
}

fn parse_config<I: IntoIterator<Item = String>>(args: I) -> Result<Config, String> {
    let mut cfg = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: "https://cache.nixos.org".to_string(),
        header_timeout_ms: 30_000,
        narinfo_cache_dir: None,
        store_dir: "/nix/store".to_string(),
        priority: DEFAULT_PRIORITY,
        want_mass_query: true,
        libp2p_bootstrap: Vec::new(),
        libp2p_provider_addrs: Vec::new(),
        libp2p_listen: None,
        libp2p_scope: None,
        libp2p_identity_seed: None,
        libp2p_provider: false,
        libp2p_seed_nar: Vec::new(),
        libp2p_print_peer_address: false,
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
            "--libp2p-listen" => {
                cfg.libp2p_listen = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("bad --libp2p-listen multiaddr: {e}"))?,
                )
            }
            "--libp2p-scope" => cfg.libp2p_scope = Some(value()?),
            "--libp2p-identity-seed" => {
                cfg.libp2p_identity_seed = Some(parse_libp2p_seed(&value()?)?)
            }
            "--libp2p-provider" => cfg.libp2p_provider = true,
            "--libp2p-seed-nar" => cfg.libp2p_seed_nar.push(parse_libp2p_seed_nar(&value()?)?),
            "--libp2p-print-peer-address" => cfg.libp2p_print_peer_address = true,
            other => return Err(format!("unknown flag {other}")),
        }
    }
    // A provider MUST have at least one seed and a listener; a consumer MUST have a bootstrap
    // peer (an empty bootstrap set can never discover anyone) - fail fast, never a silent
    // node that does nothing.
    if cfg.libp2p_provider {
        if cfg.libp2p_seed_nar.is_empty() {
            return Err("--libp2p-provider requires at least one --libp2p-seed-nar".into());
        }
        if cfg.libp2p_listen.is_none() {
            return Err("--libp2p-provider requires --libp2p-listen".into());
        }
    } else if cfg.libp2p_bootstrap.is_empty() {
        return Err(
            "a consumer requires at least one --libp2p-bootstrap <PeerId>@<multiaddr>".into(),
        );
    }
    Ok(cfg)
}

fn source_config(cfg: &Config) -> Result<Libp2pSourceConfig, String> {
    let identity_seed = match cfg.libp2p_identity_seed {
        Some(seed) => seed,
        None => random_identity_seed()?,
    };
    Ok(Libp2pSourceConfig {
        identity_seed,
        network_scope: cfg.libp2p_scope.clone().unwrap_or_else(|| "v1".to_string()),
        listen: cfg.libp2p_listen.clone(),
        bootstrap: cfg.libp2p_bootstrap.clone(),
        provider_addrs: cfg.libp2p_provider_addrs.clone(),
        discovery_budget: DiscoveryBudget::default(),
        envelope: SafetyEnvelope::default(),
    })
}

/// Node B (PROVIDER): start the fabric WITH a supplier for the seeded NARs, install the serve
/// gate under the serve budget, and announce a signed record per seed. Returns the fabric +
/// the ServeHandle the caller must keep alive for the process (dropping either stops serving).
async fn install_provider(
    cfg: &Config,
    source_cfg: Libp2pSourceConfig,
) -> Result<(Arc<Libp2pFabric>, ServeHandle), String> {
    let mut seeds: Vec<(daemon_core::NarHashKey, Vec<u8>)> =
        Vec::with_capacity(cfg.libp2p_seed_nar.len());
    for (nar_hash, path) in &cfg.libp2p_seed_nar {
        let bytes =
            std::fs::read(path).map_err(|e| format!("reading --libp2p-seed-nar {path:?}: {e}"))?;
        seeds.push((*nar_hash, bytes));
    }

    let serve_budget = ServeBudget {
        max_nar_bytes_uncompressed_nar: DEFAULT_MAX_SERVE_NAR_BYTES,
        max_inflight_bytes_uncompressed_nar: DEFAULT_MAX_INFLIGHT_NAR_BYTES,
        max_serve_duration: Duration::from_millis(DEFAULT_MAX_SERVE_DURATION_MS),
    };
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

    let identity_seed = source_cfg.identity_seed;
    let supplier = Arc::new(MemoryNarSupplier::new(seeds.iter().map(|(_, b)| b.clone())));
    let (fabric, _source, _raw) = build_libp2p_provider_source(source_cfg, supplier).await?;

    let serve = fabric
        .server()
        .ok_or_else(|| "internal: libp2p provider fabric has no serve axis".to_string())?
        .serve(serve_budget)
        .await
        .map_err(|e| format!("libp2p serve gate failed to install: {e}"))?;

    let announce_budget = AnnounceBudget::new(Duration::from_secs(10), 20);
    let announcer = fabric
        .announcer()
        .ok_or_else(|| "internal: libp2p provider fabric exposes no announcer".to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for (nar_hash, bytes) in &seeds {
        let record = sign_libp2p_provider_record(identity_seed, nar_hash, bytes, 3600, now);
        announcer
            .announce(&record, &announce_budget)
            .await
            .map_err(|e| format!("announcing libp2p provider record for {nar_hash}: {e}"))?;
        println!(
            "LIBP2P-SEED narhash={nar_hash} content={} content_key={} bytes={}",
            record.content.to_hex(),
            record.key,
            bytes.len()
        );
    }

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
    Ok((fabric, serve))
}

#[tokio::main]
async fn main() -> ExitCode {
    let cfg = match parse_config(std::env::args().skip(1)) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("daemon-libp2p: {err}");
            return ExitCode::from(2);
        }
    };
    let source_cfg = match source_config(&cfg) {
        Ok(sc) => sc,
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
    let (narinfo, correlation): (Arc<dyn NarinfoSource>, Arc<dyn CorrelationStore>) = match &cfg
        .narinfo_cache_dir
    {
        Some(dir) => match NarinfoDiskCache::new(dir, upstream.clone(), Arc::new(SystemClock)) {
            Ok(cache) => {
                let cache = Arc::new(cache);
                println!("daemon-libp2p: narinfo disk cache at {dir}");
                (cache.clone(), cache)
            }
            Err(err) => {
                eprintln!("daemon-libp2p: cannot open narinfo cache dir {dir:?}: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => (upstream.clone(), Arc::new(NullCorrelation)),
    };

    // Consumer axes; a provider additionally needs the serve + announce axes. `run` re-asserts
    // these, and the construction already asserted them at start (belt and braces).
    let mut required_axes = vec![
        Axis::ProviderDirectory,
        Axis::NodeLocator,
        Axis::Transfer(TransportTag::Iroh),
    ];

    // Keep the provider serve gate alive for the process (dropping it stops serving).
    let _serve_guard: Option<ServeHandle>;
    let fabric: Arc<Libp2pFabric> = if cfg.libp2p_provider {
        required_axes.push(Axis::Server);
        required_axes.push(Axis::Announcer);
        match install_provider(&cfg, source_cfg).await {
            Ok((fabric, serve)) => {
                _serve_guard = Some(serve);
                println!(
                    "daemon-libp2p: PROVIDER serving + announcing {} seeded NAR(s)",
                    cfg.libp2p_seed_nar.len()
                );
                fabric
            }
            Err(err) => {
                eprintln!("daemon-libp2p: provider setup failed: {err}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        match build_libp2p_nar_source(source_cfg).await {
            Ok((fabric, _source, _raw)) => {
                _serve_guard = None;
                println!(
                    "daemon-libp2p: CONSUMER started, discovery converging ({} bootstrap peer(s))",
                    cfg.libp2p_bootstrap.len()
                );
                fabric
            }
            Err(err) => {
                eprintln!("daemon-libp2p: consumer setup failed: {err}");
                return ExitCode::FAILURE;
            }
        }
    };

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
    };

    let fabric_dyn: Arc<dyn PeerFabric> = fabric.clone();
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
