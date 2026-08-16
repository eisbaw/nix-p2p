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
    CacheInfo, CorrelationStore, NARINFO_CACHE_FLAG_CONFLICT, NarSource, NarinfoLayer,
    NarinfoSource, PassThroughReason, PublicNarAllowlist, RawUpstream, RunConfig, SystemClock,
    UpstreamHttp, build_narinfo_layer, resolve_narinfo_cache_dir, run,
};
use daemon_libp2p::{
    AllowlistEligibility, LanReachability, LanShare, Libp2pCatalogProbe, Libp2pSourceConfig,
    announce_provider_seeds, announce_public_provisions, announce_public_seeds,
    announce_store_provisions, build_libp2p_nar_source, build_libp2p_provider_source,
    lan_isolation_or_refuse, open_public_allowlist, resolve_durable_identity_seed,
    verify_store_provisions,
};
use ed25519_dalek::SigningKey;
use fabric_libp2p::{
    CatalogNarSupplier, Libp2pFabric, MemoryNarSupplier, Multiaddr, PeerId,
    raw_nar_helper_authorized,
};
use peer_fabric::{
    AdmitAllPublication, AnnounceBudget, Axis, DiscoveryBudget, PeerFabric, PublicationEligibility,
    RefusePublication, SafetyEnvelope, ServeBudget, ServeHandle, TransportTag,
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
    /// Explicit opt-out of the (default-on, TASK-29) narinfo disk cache.
    no_narinfo_cache: bool,
    store_dir: String,
    priority: u32,
    want_mass_query: bool,
    libp2p_bootstrap: Vec<(PeerId, Multiaddr)>,
    libp2p_provider_addrs: Vec<(PeerId, Multiaddr)>,
    /// `--libp2p-listen` bind multiaddrs, REPEATABLE (TASK-207). The FIRST is bound through the
    /// shared construction (`Libp2pSourceConfig.listen`); any EXTRA are applied post-build via the
    /// fabric handle. A NAT'd provider needs two: a real transport bind (so the relay-client can
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
            other => return Err(format!("unknown flag {other}")),
        }
    }
    // TASK-29: naming a narinfo cache dir AND opting out is contradictory; reject
    // it at parse time (shares the error string with the composite `daemon` binary
    // via NARINFO_CACHE_FLAG_CONFLICT so the two cannot drift).
    if cfg.narinfo_cache_dir.is_some() && cfg.no_narinfo_cache {
        return Err(NARINFO_CACHE_FLAG_CONFLICT.into());
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
        if cfg.libp2p_listen.is_empty() {
            return Err("--libp2p-provider requires --libp2p-listen".into());
        }
        // TASK-207 fail-closed: an external address advertises PUBLIC reachability. On a provider
        // WITHOUT the public-NAR allowlist door that is an isolated-LAN announce (lan_share_or_refuse),
        // where advertising a public self-address contradicts the isolation the announce relies on -
        // refuse rather than announce local content over a self-declared public address. With the
        // allowlist door set the announce is gated per-NAR, so external addresses are fine.
        if !cfg.libp2p_external_addresses.is_empty() && cfg.libp2p_public_allowlist_path.is_none() {
            return Err(
                "--libp2p-external-address on a provider requires --libp2p-public-allowlist-path: \
                 advertising a public self-address is incompatible with an isolated-LAN announce"
                    .into(),
            );
        }
    } else if cfg.libp2p_bootstrap.is_empty() {
        return Err(
            "a consumer requires at least one --libp2p-bootstrap <PeerId>@<multiaddr>".into(),
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
        // The FIRST --libp2p-listen is bound by the shared construction; any EXTRA listens (and all
        // external addresses) are applied post-build in `main` via the fabric handle (TASK-207).
        listen: cfg.libp2p_listen.first().cloned(),
        bootstrap: cfg.libp2p_bootstrap.clone(),
        provider_addrs: cfg.libp2p_provider_addrs.clone(),
        discovery_budget: DiscoveryBudget::default(),
        envelope: SafetyEnvelope::default(),
        state_dir: cfg.libp2p_state_dir.clone(),
        relay_server_enabled: cfg.libp2p_relay_server_enabled,
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

/// The announcer's per-fabric publication-eligibility authority for a PROVIDER node (TASK-231,
/// AC#2), matching the announce door it will use: a configured public allowlist -> the
/// [`AllowlistEligibility`] backed by that SAME allowlist (the announcer refuses any record the
/// allowlist did not approve); no allowlist but PROVABLY isolated -> an explicit
/// [`AdmitAllPublication`]; a public-reachable node with no allowlist -> fail-closed
/// [`RefusePublication`] (its LAN announce is also refused by `lan_share_or_refuse`, and now the
/// adapter refuses too, so no unallowlisted record reaches the DHT by any path).
fn provider_publication_authority(
    cfg: &Config,
    allowlist: &Arc<PublicNarAllowlist>,
) -> Arc<dyn PublicationEligibility> {
    if cfg.libp2p_public_allowlist_path.is_some() {
        Arc::new(AllowlistEligibility::new(allowlist.clone()))
    } else if lan_share_or_refuse(cfg).is_ok() {
        Arc::new(AdmitAllPublication)
    } else {
        Arc::new(RefusePublication)
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
    allowlist: &Arc<PublicNarAllowlist>,
) -> Result<(Arc<Libp2pFabric>, ProviderGuard), String> {
    warn_if_non_durable_provider(&source_cfg);
    let (fabric, guard) = if !cfg.libp2p_provide_store.is_empty() {
        install_store_provider(cfg, source_cfg, allowlist).await?
    } else {
        install_seed_provider(cfg, source_cfg, allowlist).await?
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
    allowlist: &Arc<PublicNarAllowlist>,
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
    let authority = provider_publication_authority(cfg, allowlist);
    let (fabric, _source, _raw) =
        build_libp2p_provider_source(source_cfg, supplier, authority).await?;

    let serve = fabric
        .server()
        .ok_or_else(|| "internal: libp2p provider fabric has no serve axis".to_string())?
        .serve(serve_budget)
        .await
        .map_err(|e| format!("libp2p serve gate failed to install: {e}"))?;

    let announce_budget = AnnounceBudget::new(Duration::from_secs(10), 20);
    // The announce path (TASK-103/204, parity with the composite `daemon` binary): PUBLIC-announce
    // mode (a configured allowlist) gates each seed on a trusted narinfo signature via the typed
    // claim-consuming door and legitimately announces over a bootstrapped substrate; ISOLATED-LAN
    // mode (no allowlist) keeps the TASK-102 `lan_share_or_refuse` stopgap, which still refuses any
    // public-reach without a configured allowlist. The allowlist IS the enforcement for the
    // bootstrapped case, replacing the bootstrap-emptiness proxy.
    let records = if cfg.libp2p_public_allowlist_path.is_some() {
        announce_public_seeds(
            &fabric,
            identity_seed,
            &seeds,
            allowlist,
            3600,
            now_secs(),
            &announce_budget,
        )
        .await?
    } else {
        // The shared SSOT provider announce loop (durable-allocate -> sign -> announce), the same
        // one the restart-durability test exercises (TASK-185 GB2).
        let lan = lan_share_or_refuse(cfg)?;
        announce_provider_seeds(
            &fabric,
            identity_seed,
            &seeds,
            lan,
            3600,
            now_secs(),
            &announce_budget,
        )
        .await?
    };
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
    allowlist: &Arc<PublicNarAllowlist>,
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
    let authority = provider_publication_authority(cfg, allowlist);
    let (fabric, _source, _raw) =
        build_libp2p_provider_source(source_cfg, supplier, authority).await?;

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
    // The announce path (TASK-103/204, see install_seed_provider): PUBLIC-announce mode (a
    // configured allowlist) gates each provision on a trusted narinfo signature via the typed
    // claim-consuming door; ISOLATED-LAN mode keeps the TASK-102 `lan_share_or_refuse` stopgap.
    let records = if cfg.libp2p_public_allowlist_path.is_some() {
        announce_public_provisions(
            &fabric,
            identity_seed,
            &provisions,
            allowlist,
            3600,
            now_secs(),
            &announce_budget,
        )
        .await?
    } else {
        let lan = lan_share_or_refuse(cfg)?;
        announce_store_provisions(
            &fabric,
            identity_seed,
            &provisions,
            lan,
            3600,
            now_secs(),
            &announce_budget,
        )
        .await?
    };
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

/// Install a stderr `tracing` subscriber when `RUST_LOG` is set, so the fabric's NAT-traversal
/// diagnostics (autonat reachability verdict, relay circuit-v2 reservation, dcutr hole-punch
/// outcome - all emitted at info/debug by `fabric-libp2p`) are visible for diagnosing a "works in
/// the harness, fails behind NAT" incident. Coarse level mapping (no `env-filter` dependency):
/// `RUST_LOG=debug|trace` -> DEBUG (also shows the relay SERVER's per-circuit forwarding), anything
/// else -> INFO. Unset `RUST_LOG` installs no subscriber - the daemon stays quiet and its existing
/// `println!` status lines are unchanged, so no test or deployment behaviour shifts.
fn init_tracing() {
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

#[tokio::main]
async fn main() -> ExitCode {
    // Internal process-isolation boundary for raw-file supply, handled before configuration:
    // the parent owns this process group, caps stdout, and kills/reaps it on cancel/shutdown.
    if let Some(code) = run_raw_nar_helper() {
        return code;
    }

    init_tracing();

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
        &source_cfg.identity_seed,
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
        match install_provider(&cfg, source_cfg, &public_allowlist).await {
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

    // TASK-207: apply the EXTRA --libp2p-listen addresses (the first was bound by the shared
    // construction) and ALL --libp2p-external-address self-advertisements now that the fabric
    // exists. Extra listens carry a NAT'd provider's relay `/…/p2p-circuit` reservation; external
    // addresses let a relay node cite its public address in reservation vouchers. Fail-fast on a
    // listen error (a requested reservation address that cannot be registered is a config fault,
    // not something to serve around silently); add_external_address is a fire-and-forget hint.
    for extra in cfg.libp2p_listen.iter().skip(1) {
        if let Err(err) = fabric.handle().listen(extra.clone()).await {
            eprintln!("daemon-libp2p: cannot listen on {extra}: {err}");
            return ExitCode::FAILURE;
        }
        println!("daemon-libp2p: additional libp2p listen {extra}");
    }
    for ext in &cfg.libp2p_external_addresses {
        fabric.handle().add_external_address(ext.clone()).await;
        println!("daemon-libp2p: advertising external address {ext}");
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

#[cfg(test)]
mod bootstrap_guard_tests {
    //! TASK-102 LAN-isolation guard bite (fix cycle #2): the shipped provider modes must REFUSE
    //! announcing whenever the node can reach ANY public substrate without a configured allowlist -
    //! a non-empty `--libp2p-bootstrap`, a non-empty `--libp2p-provider-addr` (the residual), or a
    //! non-loopback/non-link-local `--libp2p-listen` - and still permit a provably-isolated
    //! (loopback-listen, no bootstrap, no provider-addr) LAN announce. This drives the binary's
    //! Config->reachability wrapper, so a call site that FORGOT to pass provider-addr/listen (the
    //! original hole) is caught here, not only in the lib-level policy test.
    use super::{Config, lan_share_or_refuse};
    use fabric_libp2p::{Multiaddr, PeerId};

    fn peer() -> PeerId {
        "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
            .parse()
            .unwrap()
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
        }
    }

    #[test]
    fn isolated_loopback_provider_is_permitted_as_a_lan_announce() {
        let cfg = provider_cfg(Vec::new(), Vec::new(), Some(addr("/ip4/127.0.0.1/tcp/0")));
        assert!(
            lan_share_or_refuse(&cfg).is_ok(),
            "a provably-isolated (loopback-listen, no bootstrap/provider-addr) announce is permitted"
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
mod nat_flags_tests {
    //! TASK-207: `--libp2p-listen` is REPEATABLE and `--libp2p-external-address` is NEW - the two
    //! additive knobs that let the shipped binary drive the relay circuit-v2 path (a provider binds
    //! a real transport AND a `/…/p2p-circuit` reservation; a relay advertises its public address so
    //! reservation vouchers are not empty). These drive the binary's OWN `parse_config`, so a
    //! regression in the repeatable-listen or external-address wiring is caught here.
    use super::parse_config;

    const APP_NAR_HASH: &str = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";
    const FIXTURE_PUBKEY: &str = "nix-p2p-test-1:empdFBu9wVZG12rPKToHMOTsU1qzWzeCcLdq/KQH0JQ=";
    const RELAY_ID: &str = "12D3KooWBr7cTGxmMhdiGNcbesEusWMR1VG26jEQQgFr6wwZkNNf";

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    /// A NAT'd provider binds TWO listens: a direct transport bind AND a relay `/p2p-circuit`
    /// reservation address. Both must be retained IN ORDER (the first flows through the shared
    /// construction, the rest are applied post-build).
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
