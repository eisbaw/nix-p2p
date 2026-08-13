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
    CacheInfo, CorrelationStore, NarSource, NarinfoDiskCache, NarinfoSource, NullCorrelation,
    RawUpstream, RunConfig, SystemClock, UpstreamHttp, run,
};
use daemon_libp2p::{
    Libp2pCatalogProbe, Libp2pSourceConfig, announce_provider_seeds, announce_store_provisions,
    build_libp2p_nar_source, build_libp2p_provider_source, resolve_durable_identity_seed,
    verify_store_provisions,
};
use ed25519_dalek::SigningKey;
use fabric_libp2p::{
    CatalogNarSupplier, Libp2pFabric, MemoryNarSupplier, Multiaddr, PeerId,
    raw_nar_helper_authorized,
};
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
    /// TASK-191: real `/nix/store` paths served on demand via `nix-store --dump`, holding no
    /// .nar at rest (`<narhash>=<storepath>`). Verification-gated by the availability index
    /// (TASK-56) before announce.
    libp2p_provide_store: Vec<(daemon_core::NarHashKey, String)>,
    libp2p_print_peer_address: bool,
    /// Per-node durable state directory (TASK-185): when set, the fabric persists its
    /// anti-rollback floor + per-key announce sequence here and re-seeds them on restart.
    libp2p_state_dir: Option<std::path::PathBuf>,
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
        libp2p_provide_store: Vec::new(),
        libp2p_print_peer_address: false,
        libp2p_state_dir: None,
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
            "--libp2p-state-dir" => cfg.libp2p_state_dir = Some(value()?.into()),
            "--libp2p-seed-nar" => cfg.libp2p_seed_nar.push(parse_libp2p_seed_nar(&value()?)?),
            "--libp2p-provide-store" => cfg
                .libp2p_provide_store
                .push(parse_libp2p_seed_nar(&value()?)?),
            "--libp2p-print-peer-address" => cfg.libp2p_print_peer_address = true,
            other => return Err(format!("unknown flag {other}")),
        }
    }
    // A provider MUST have at least one seed and a listener; a consumer MUST have a bootstrap
    // peer (an empty bootstrap set can never discover anyone) - fail fast, never a silent
    // node that does nothing.
    if cfg.libp2p_provider {
        if cfg.libp2p_seed_nar.is_empty() && cfg.libp2p_provide_store.is_empty() {
            return Err(
                "--libp2p-provider requires at least one --libp2p-seed-nar or --libp2p-provide-store"
                    .into(),
            );
        }
        // MVP scope (TASK-191): one supplier drives the fabric, so the in-memory seed path and
        // the store-dump path are not combined in a single provider yet. Combining them (a union
        // supplier) is a filed follow-up; fail fast rather than silently serve only one.
        if !cfg.libp2p_seed_nar.is_empty() && !cfg.libp2p_provide_store.is_empty() {
            return Err(
                "--libp2p-seed-nar and --libp2p-provide-store cannot be combined in one provider \
                 yet (TASK-191 MVP): use one supply mode"
                    .into(),
            );
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
    // TASK-185 GB1: anchor the identity to the state dir so a plain `--libp2p-state-dir`-only
    // restart is the SAME node (stable identity + stable sequence floor). An explicit
    // --libp2p-identity-seed still wins but must agree with any persisted one.
    let identity_seed =
        resolve_durable_identity_seed(cfg.libp2p_state_dir.as_deref(), cfg.libp2p_identity_seed)?;
    Ok(Libp2pSourceConfig {
        identity_seed,
        network_scope: cfg.libp2p_scope.clone().unwrap_or_else(|| "v1".to_string()),
        listen: cfg.libp2p_listen.clone(),
        bootstrap: cfg.libp2p_bootstrap.clone(),
        provider_addrs: cfg.libp2p_provider_addrs.clone(),
        discovery_budget: DiscoveryBudget::default(),
        envelope: SafetyEnvelope::default(),
        state_dir: cfg.libp2p_state_dir.clone(),
    })
}

/// What keeps a libp2p PROVIDER serving for the process. Dropping the [`ServeHandle`] stops
/// admission; the optional [`AvailabilityIndex`] is present in the STORE-supply mode (TASK-191)
/// because the [`CatalogNarSupplier`] serves through the index's supply catalog and the index's
/// `Drop` retires every registration - so the served reverse-map must outlive the process.
struct ProviderGuard {
    _serve: ServeHandle,
    _index: Option<Arc<AvailabilityIndex>>,
}

/// The provider serve budget (PROVISIONAL defaults; shared by both supply modes).
fn provider_serve_budget() -> ServeBudget {
    ServeBudget {
        max_nar_bytes_uncompressed_nar: DEFAULT_MAX_SERVE_NAR_BYTES,
        max_inflight_bytes_uncompressed_nar: DEFAULT_MAX_INFLIGHT_NAR_BYTES,
        max_serve_duration: Duration::from_millis(DEFAULT_MAX_SERVE_DURATION_MS),
    }
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

/// Node B (PROVIDER): start the fabric WITH a supplier, install the serve gate, and announce.
/// Two supply modes (mutually exclusive at the CLI, TASK-191 MVP): the in-memory `--libp2p-seed-nar`
/// path (holds the .nar at rest) and the `--libp2p-provide-store` path (serves a real `/nix/store`
/// path via `nix-store --dump` on demand, holding no .nar at rest). Returns the fabric + the
/// [`ProviderGuard`] the caller must keep alive for the process.
async fn install_provider(
    cfg: &Config,
    source_cfg: Libp2pSourceConfig,
) -> Result<(Arc<Libp2pFabric>, ProviderGuard), String> {
    warn_if_non_durable_provider(&source_cfg);
    let (fabric, guard) = if !cfg.libp2p_provide_store.is_empty() {
        install_store_provider(cfg, source_cfg).await?
    } else {
        install_seed_provider(cfg, source_cfg).await?
    };

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
    Ok((fabric, guard))
}

/// The in-memory seed supply mode (TASK-178): serve the `--libp2p-seed-nar` raw NARs from a
/// [`MemoryNarSupplier`] (holding them at rest) and announce a signed record per seed.
async fn install_seed_provider(
    cfg: &Config,
    source_cfg: Libp2pSourceConfig,
) -> Result<(Arc<Libp2pFabric>, ProviderGuard), String> {
    let mut seeds: Vec<(daemon_core::NarHashKey, Vec<u8>)> =
        Vec::with_capacity(cfg.libp2p_seed_nar.len());
    for (nar_hash, path) in &cfg.libp2p_seed_nar {
        let bytes =
            std::fs::read(path).map_err(|e| format!("reading --libp2p-seed-nar {path:?}: {e}"))?;
        seeds.push((*nar_hash, bytes));
    }

    let serve_budget = provider_serve_budget();
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
    // The shared SSOT provider announce loop (durable-allocate -> sign -> announce), the same
    // one the restart-durability test exercises (TASK-185 GB2).
    let records = announce_provider_seeds(
        &fabric,
        identity_seed,
        &seeds,
        3600,
        now_secs(),
        &announce_budget,
    )
    .await?;
    for (record, (nar_hash, bytes)) in records.iter().zip(&seeds) {
        println!(
            "LIBP2P-SEED narhash={nar_hash} content={} content_key={} bytes={}",
            record.content.to_hex(),
            record.key,
            bytes.len()
        );
    }
    Ok((
        fabric,
        ProviderGuard {
            _serve: serve,
            _index: None,
        },
    ))
}

/// The STORE-supply mode (TASK-191, the store-supply MVP): serve real `/nix/store` paths from a
/// [`CatalogNarSupplier`] over the daemon's [`AvailabilityIndex`], regenerating each on demand
/// via `nix-store --dump` and holding NO .nar at rest. The announce is verification-gated
/// (AC#2): [`verify_store_provisions`] runs the index's TASK-56 `sha256(--dump) == NarHash`
/// check + quarantine for every path BEFORE any record is signed, and each announced `content`
/// is the index's VERIFIED digest, never the operator's word.
async fn install_store_provider(
    cfg: &Config,
    source_cfg: Libp2pSourceConfig,
) -> Result<(Arc<Libp2pFabric>, ProviderGuard), String> {
    let serve_budget = provider_serve_budget();
    let identity_seed = source_cfg.identity_seed;

    // The availability index over the REAL store: a `nix-store --dump` producer (CommandNarDumper
    // -> a ProbedSource::Process source, so the CatalogNarSupplier regenerates on demand and holds
    // nothing at rest). NullStore: the provided set is the CLI SSOT, re-registered + re-verified
    // each boot (persisting the store index across restarts is a TASK-82 follow-up). NullAnnounce:
    // claims are announced through the libp2p announcer below, not the index's iroh sink. The
    // `node_id` is this node's ed25519 identity for completeness; the libp2p ProviderRecord
    // carries its OWN provider identity, so the index's iroh offer is never consulted here.
    let node_id = NodeId::from_bytes(
        SigningKey::from_bytes(&identity_seed)
            .verifying_key()
            .to_bytes(),
    );
    let index = AvailabilityIndex::open(
        node_id,
        Arc::new(CommandNarDumper::from_path()) as Arc<dyn NarDumper>,
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .map_err(|e| format!("opening the availability index for store supply: {e}"))?;
    let mut nar_hashes = Vec::with_capacity(cfg.libp2p_provide_store.len());
    for (nar_hash, path) in &cfg.libp2p_provide_store {
        index
            .register(*nar_hash, StorePath::new(path))
            .map_err(|e| format!("registering store path {path:?} under {nar_hash}: {e}"))?;
        nar_hashes.push(*nar_hash);
    }
    let index = Arc::new(index);

    // The supplier reads the index's inert reverse-map (verified digest -> store path). The helper
    // program is THIS binary's `__dump-raw-nar` mode, spawned ONLY for a ProbedSource::RegularFile;
    // a real store path is a ProbedSource::Process (nix-store --dump) and never invokes it.
    let helper_program = std::env::current_exe()
        .map_err(|e| format!("resolving daemon-libp2p executable for the raw-NAR helper: {e}"))?;
    let supplier = Arc::new(CatalogNarSupplier::new(
        Libp2pCatalogProbe::new(index.supply_catalog()),
        helper_program,
    ));
    let (fabric, _source, _raw) = build_libp2p_provider_source(source_cfg, supplier).await?;

    let serve = fabric
        .server()
        .ok_or_else(|| "internal: libp2p provider fabric has no serve axis".to_string())?
        .serve(serve_budget)
        .await
        .map_err(|e| format!("libp2p serve gate failed to install: {e}"))?;

    // AC#2 gate: verify EVERY provided store path through the index (dump + sha256==NarHash +
    // quarantine) before any announce; a quarantined/absent path fails the whole batch here.
    let provisions = verify_store_provisions(&index, &nar_hashes)?;
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

    let announce_budget = AnnounceBudget::new(Duration::from_secs(10), 20);
    let records = announce_store_provisions(
        &fabric,
        identity_seed,
        &provisions,
        3600,
        now_secs(),
        &announce_budget,
    )
    .await?;
    for (record, provision) in records.iter().zip(&provisions) {
        println!(
            "LIBP2P-PROVIDE-STORE narhash={} content={} content_key={} nar_size={}",
            provision.nar_hash(),
            record.content.to_hex(),
            record.key,
            provision.declared_size(),
        );
    }
    Ok((
        fabric,
        ProviderGuard {
            _serve: serve,
            _index: Some(index),
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

    // Keep the provider serve gate (and, in store-supply mode, its availability index) alive for
    // the process (dropping the guard stops serving / retires the served reverse-map).
    let _serve_guard: Option<ProviderGuard>;
    let fabric: Arc<Libp2pFabric> = if cfg.libp2p_provider {
        required_axes.push(Axis::Server);
        required_axes.push(Axis::Announcer);
        match install_provider(&cfg, source_cfg).await {
            Ok((fabric, guard)) => {
                _serve_guard = Some(guard);
                let supplied = if cfg.libp2p_provide_store.is_empty() {
                    format!("{} seeded NAR(s)", cfg.libp2p_seed_nar.len())
                } else {
                    format!(
                        "{} /nix/store path(s) on demand",
                        cfg.libp2p_provide_store.len()
                    )
                };
                println!("daemon-libp2p: PROVIDER serving + announcing {supplied}");
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
