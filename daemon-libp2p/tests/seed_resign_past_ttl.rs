//! TASK-285 AC#2 — a node seeding S stays discoverable + fetchable for S PAST one full record-TTL
//! window, verified by a FRESH consumer built AFTER the original signed record would have expired.
//!
//! The defect: the durable `--libp2p-seed-nar` leg announces ONCE at startup with an absolute SIGNED
//! `expiry = now + ttl_secs`. libp2p-kad's native republish re-provides the SAME signed bytes but
//! cannot extend that signed expiry, so past the TTL a consumer's decode rejects the record
//! (`RecordDecodeError::Stale`) and the seed is undiscoverable until restart. The re-sign task mints
//! a FRESH record (new expiry, next monotonic sequence) at `ttl/2`, so a continuously-running seed
//! stays discoverable indefinitely.
//!
//! Both arms use a SHORT `ttl_secs` (so the test does not wait hours) and differ ONLY by whether the
//! re-sign task is spawned — that single toggle IS the mutation proof:
//!   * GREEN (with re-sign): [`seed_stays_discoverable_and_fetchable_past_ttl_with_resign`] — the
//!     fresh consumer (built AFTER the original expiry) discovers an UNEXPIRED, strictly-superseding
//!     record (sequence > 1) and FETCHES S byte-identically over libp2p, 0 upstream fallback.
//!   * RED-without (the negative control): [`seed_goes_undiscoverable_past_ttl_without_resign`] — the
//!     SAME setup with NO re-sign leaves only the original (now-expired) record, so the fresh
//!     consumer's discovery of S returns NOT-Found (the expired record is filtered at decode).
//!
//! Real loopback-TCP libp2p swarms (BOOT + a durable provider + a fresh consumer), the SHIPPED
//! production builders + announce loop + re-sign task — no containers, no mock DHT.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use daemon_core::{
    CacheInfo, NarHashKey, NarKey, NarSource, NarinfoSource, NullCorrelation, RawUpstream,
    RunConfig, SourceError, StoreHash, UpstreamResponse, run,
};
use daemon_libp2p::{
    InitialAnnounceConfig, LanShare, Libp2pSourceConfig, ProviderRelayReadiness,
    SeedResignAuthority, announce_provider_seeds, build_libp2p_nar_source,
    build_libp2p_provider_source, provider_content_key, resolve_durable_identity_seed,
    spawn_seed_resign,
};
use fabric_libp2p::{Libp2pFabric, MemoryNarSupplier, Multiaddr, NodeConfig, PeerId};
use http::HeaderMap;
use http_body_util::{BodyExt, Full};
use peer_fabric::{
    AnnounceBudget, Axis, DiscoveryBudget, Lookup, PeerFabric, SafetyEnvelope, ServeBudget,
    ServeHandle, TransportTag,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The SHORT record TTL both arms use (seconds). Re-sign fires at `ttl/2` = 5s; the fresh consumer
/// is built at `WAIT_PAST_TTL_S` (past the ORIGINAL expiry), where only a re-signed record can be
/// valid. Small enough to keep the test quick, large enough to give the loopback swarm headroom.
const SHORT_TTL_SECS: u64 = 10;
/// Wall-clock wait after the initial announce before building the fresh consumer: PAST the original
/// `SHORT_TTL_SECS` window, so the original signed record has certainly expired.
const WAIT_PAST_TTL_S: u64 = 12;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

async fn start_fabric(fabric: Libp2pFabric) -> (Arc<Libp2pFabric>, Multiaddr) {
    fabric
        .handle()
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("listen bound");
    let deadline = Instant::now() + Duration::from_secs(5);
    let addr = loop {
        if let Some(addr) = fabric.handle().listen_addrs().await.into_iter().next() {
            break addr;
        }
        assert!(Instant::now() < deadline, "no listen address bound in time");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    (Arc::new(fabric), addr)
}

fn durable_provider_cfg(
    scope: &str,
    boot: (PeerId, Multiaddr),
    state_dir: &std::path::Path,
) -> Libp2pSourceConfig {
    let identity_seed = resolve_durable_identity_seed(Some(state_dir), None)
        .expect("resolve the durable identity seed from the state dir");
    Libp2pSourceConfig {
        identity_seed,
        network_scope: scope.to_string(),
        listen: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        additional_listens: Vec::new(),
        external_addresses: Vec::new(),
        bootstrap: vec![boot],
        provider_addrs: vec![],
        discovery_budget: DiscoveryBudget::new(Duration::from_secs(10), 32),
        envelope: SafetyEnvelope::default(),
        state_dir: Some(state_dir.to_path_buf()),
        relay_server_enabled: true,
        kad_server: true,
        mdns_enabled: false,
        lan_confinement: false,
    }
}

fn consumer_cfg(scope: &str, boot: (PeerId, Multiaddr)) -> Libp2pSourceConfig {
    Libp2pSourceConfig {
        identity_seed: [7u8; 32],
        network_scope: scope.to_string(),
        listen: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        additional_listens: Vec::new(),
        external_addresses: Vec::new(),
        bootstrap: vec![boot],
        provider_addrs: vec![],
        discovery_budget: DiscoveryBudget::new(Duration::from_secs(10), 32),
        envelope: SafetyEnvelope::default(),
        state_dir: None,
        relay_server_enabled: true,
        kad_server: true,
        mdns_enabled: false,
        lan_confinement: false,
    }
}

/// Stand up a durable provider seeding `nar`, install its serve gate, and announce it ONCE through
/// the SHIPPED SSOT loop at `SHORT_TTL_SECS`. Returns the fabric + readiness + serve guard.
async fn start_provider(
    cfg: Libp2pSourceConfig,
    nar: &[u8],
    nar_hash: &NarHashKey,
) -> (Arc<Libp2pFabric>, ProviderRelayReadiness, ServeHandle) {
    let seed = cfg.identity_seed;
    let supplier = Arc::new(MemoryNarSupplier::new([nar.to_vec()]));
    let (fabric, _source, _raw, readiness) =
        build_libp2p_provider_source(cfg, supplier, Arc::new(peer_fabric::AdmitAllPublication))
            .await
            .expect("production provider builder starts a serving fabric joined to the DHT");
    let serve = fabric
        .server()
        .expect("provider fabric exposes a serve axis")
        .serve(ServeBudget::default())
        .await
        .expect("serve gate installs");
    let budget = AnnounceBudget::new(Duration::from_secs(10), 20);
    let records = announce_provider_seeds(
        &fabric,
        &readiness,
        InitialAnnounceConfig::new(seed, SHORT_TTL_SECS, unix_now(), &budget),
        &[(*nar_hash, nar.to_vec())],
        LanShare::operator_assembled(),
    )
    .await
    .expect("shipped announce loop admitted (provider is DHT-joined)");
    let first = records.into_iter().next().expect("one announced record");
    assert_eq!(first.sequence, 1, "the initial announce is sequence 1");
    (fabric, readiness, serve)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seed_stays_discoverable_and_fetchable_past_ttl_with_resign() {
    let scope = "task285-resign-past-ttl-green";
    let state_dir = std::env::temp_dir().join(format!(
        "nix-p2p-task285-green-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&state_dir);

    let nar = b"nix-archive-1 raw NAR kept discoverable past its TTL by periodic re-sign".to_vec();
    let nar_hash = NarHashKey::from_raw_nar(&nar);
    let content_key = provider_content_key(&nar_hash);

    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig::new([1u8; 32]).with_network_scope(scope))
            .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    let (provider, readiness, _serve) = start_provider(
        durable_provider_cfg(scope, (boot_peer, boot_addr.clone()), &state_dir),
        &nar,
        &nar_hash,
    )
    .await;
    let provider_id = provider.node_id();

    // Spawn the SHIPPED re-sign task: it re-signs the seed at ttl/2 before the original lapses.
    let identity_seed = resolve_durable_identity_seed(Some(&state_dir), None).unwrap();
    let budget = AnnounceBudget::new(Duration::from_secs(10), 20);
    let _resign = spawn_seed_resign(
        Arc::clone(&provider),
        readiness,
        identity_seed,
        vec![(nar_hash, nar.clone())],
        SHORT_TTL_SECS,
        budget,
        SeedResignAuthority::Lan,
    )
    .expect("a non-empty seed set spawns a re-sign task");

    // Wait PAST the original TTL window: the original record has expired; only re-signed records
    // (minted at ttl/2 and again at ttl) can now be valid.
    tokio::time::sleep(Duration::from_secs(WAIT_PAST_TTL_S)).await;

    // ---- FRESH consumer built AFTER the original expiry ----
    let discovery_budget = DiscoveryBudget::new(Duration::from_secs(10), 32);
    let (consumer, _c_source, _c_raw) =
        build_libp2p_nar_source(consumer_cfg(scope, (boot_peer, boot_addr.clone())))
            .await
            .expect("production consumer builder constructs a running libp2p fabric");

    // The fresh consumer must discover an UNEXPIRED record for S that STRICTLY SUPERSEDES the
    // original (sequence > 1) — proof the re-sign kept it alive, not a lingering original.
    let deadline = Instant::now() + Duration::from_secs(20);
    let discovered_sequence = loop {
        if let Lookup::Found(records) = consumer
            .provider_directory()
            .expect("consumer has a directory")
            .find_providers(&content_key, &discovery_budget)
            .await
            && let Some(r) = records.iter().find(|r| r.provider == provider_id)
        {
            break r.sequence;
        }
        assert!(
            Instant::now() < deadline,
            "the fresh consumer never discovered a valid (unexpired) record for S past the TTL — \
             the re-sign did not keep the seed alive"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert!(
        discovered_sequence > 1,
        "the record discovered past the TTL must be a RE-SIGNED one (sequence > 1), not the \
         original — got sequence {discovered_sequence}"
    );

    // ---- FETCH S byte-identically over libp2p through the exact `run` glue the binary uses ----
    let fallback_hits = Arc::new(AtomicUsize::new(0));
    let hit_token = "1hitnaaaaaaaaaaaaaaaaaaaaaaaaaaaa.nar.xz";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("run() binds");
    let addr = listener.local_addr().unwrap();
    let run_cfg = RunConfig {
        listener,
        upstream: Arc::new(CountingUpstreamNar {
            body: b"UPSTREAM FALLBACK (must not appear on a p2p hit)".to_vec(),
            hits: fallback_hits.clone(),
        }) as Arc<dyn NarSource>,
        narinfo: Arc::new(OneNarinfo(narinfo_body(
            hit_token,
            &nar_hash.to_string(),
            nar.len(),
        ))),
        passthrough: Arc::new(DeadPassthrough),
        correlation: Arc::new(NullCorrelation),
        cache_info: CacheInfo::default(),
        upstream_label: "task285-run-upstream".to_string(),
        discovery_budget,
        envelope: SafetyEnvelope::default(),
        required_axes: vec![
            Axis::ProviderDirectory,
            Axis::NodeLocator,
            Axis::Transfer(TransportTag::Libp2p),
        ],
        extra_raw_serve: Vec::new(),
        public_allowlist: Arc::new(daemon_core::PublicNarAllowlist::disabled()),
        post_fetch_announce: None,
        observability: None,
        admin_listener: None,
    };
    let fabric_dyn: Arc<dyn PeerFabric> = consumer.clone();
    let run_task = tokio::spawn(run(fabric_dyn, run_cfg));

    let narinfo = get(addr, "/hit.narinfo").await;
    assert_eq!(narinfo.status, Some(200), "narinfo served through run()");
    let hit_url = url_token(&narinfo.body);
    assert_ne!(
        hit_url,
        format!("nar/{hit_token}"),
        "run's production raw-serve must have REWRITTEN the announced narinfo to a raw URL"
    );
    let served = get(addr, &format!("/{hit_url}")).await;
    assert_eq!(
        served.status,
        Some(200),
        "run() served S over libp2p from the still-discoverable (re-signed) seed"
    );
    assert_eq!(
        served.body, nar,
        "run() served BYTE-IDENTICAL bytes for S past the original TTL"
    );
    assert_eq!(
        fallback_hits.load(Ordering::SeqCst),
        0,
        "S was served over p2p from the re-signed seed; the HTTP fallback was not consulted"
    );

    run_task.abort();
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seed_goes_undiscoverable_past_ttl_without_resign() {
    // The NEGATIVE CONTROL: identical setup, but NO re-sign task. Past the TTL the fresh consumer
    // must NOT discover a valid record for S — the exact failure the re-sign fixes (removing the
    // re-sign task ⇒ consumer discovery of S fails after the TTL).
    let scope = "task285-resign-past-ttl-red";
    let state_dir = std::env::temp_dir().join(format!(
        "nix-p2p-task285-red-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&state_dir);

    let nar = b"nix-archive-1 raw NAR that goes dark after its TTL with no re-sign".to_vec();
    let nar_hash = NarHashKey::from_raw_nar(&nar);
    let content_key = provider_content_key(&nar_hash);

    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig::new([1u8; 32]).with_network_scope(scope))
            .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    let (provider, _readiness, _serve) = start_provider(
        durable_provider_cfg(scope, (boot_peer, boot_addr.clone()), &state_dir),
        &nar,
        &nar_hash,
    )
    .await;
    let provider_id = provider.node_id();

    // NO spawn_seed_resign here — that is the mutation.

    tokio::time::sleep(Duration::from_secs(WAIT_PAST_TTL_S)).await;

    let discovery_budget = DiscoveryBudget::new(Duration::from_secs(10), 32);
    let (consumer, _c_source, _c_raw) =
        build_libp2p_nar_source(consumer_cfg(scope, (boot_peer, boot_addr.clone())))
            .await
            .expect("production consumer builder constructs a running libp2p fabric");

    // Confirm discovery of S FAILS across a bounded window: the only record was the original, now
    // expired, and it is filtered at decode — so the provider is never returned with a valid record.
    let confirm_until = Instant::now() + Duration::from_secs(6);
    while Instant::now() < confirm_until {
        let found_valid = matches!(
            consumer
                .provider_directory()
                .expect("consumer has a directory")
                .find_providers(&content_key, &discovery_budget)
                .await,
            Lookup::Found(records) if records.iter().any(|r| r.provider == provider_id)
        );
        assert!(
            !found_valid,
            "without re-sign, the fresh consumer must NOT discover a valid record for S past the \
             TTL (the original signed record has expired) — but it did"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    let _ = std::fs::remove_dir_all(&state_dir);
}

// ---- run()/serve plumbing (mirrors restart_durable_sequence_through_run.rs) ----

fn narinfo_body(token: &str, nar_hash: &str, nar_size: usize) -> Vec<u8> {
    format!(
        "StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
         URL: nar/{token}\n\
         Compression: xz\n\
         FileHash: sha256:0000000000000000000000000000000000000000000000000000\n\
         FileSize: 100\n\
         NarHash: {nar_hash}\n\
         NarSize: {nar_size}\n\
         References: \n\
         Sig: nix-p2p-test-1:AAAA==\n"
    )
    .into_bytes()
}

struct OneNarinfo(Vec<u8>);

#[async_trait]
impl NarinfoSource for OneNarinfo {
    async fn fetch(&self, hash: &StoreHash) -> Result<UpstreamResponse, SourceError> {
        if hash.as_str() != "hit" {
            return Err(SourceError::Unreachable(format!("no narinfo for {hash:?}")));
        }
        let body = self.0.clone();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "text/x-nix-narinfo".parse().unwrap(),
        );
        headers.insert(http::header::CONTENT_LENGTH, body.len().into());
        Ok(UpstreamResponse {
            status: 200,
            headers,
            body: Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        })
    }
}

struct CountingUpstreamNar {
    body: Vec<u8>,
    hits: Arc<AtomicUsize>,
}

#[async_trait]
impl NarSource for CountingUpstreamNar {
    async fn resolve(
        &self,
        _key: &NarKey,
        _expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        self.hits.fetch_add(1, Ordering::SeqCst);
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, self.body.len().into());
        Ok(UpstreamResponse {
            status: 200,
            headers,
            body: Full::new(Bytes::from(self.body.clone()))
                .map_err(|never| match never {})
                .boxed(),
        })
    }
}

struct DeadPassthrough;

#[async_trait]
impl RawUpstream for DeadPassthrough {
    async fn get(&self, _: &str) -> Result<UpstreamResponse, SourceError> {
        Err(SourceError::Unreachable("passthrough unused".into()))
    }
}

struct Resp {
    status: Option<u16>,
    body: Vec<u8>,
}

fn url_token(narinfo_body: &[u8]) -> String {
    let text = String::from_utf8_lossy(narinfo_body);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("URL:") {
            return rest.trim().to_string();
        }
    }
    panic!("served narinfo carried no URL line:\n{text}");
}

async fn get(addr: SocketAddr, path: &str) -> Resp {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to run() server");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    stream.flush().await.ok();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw).await;
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Resp {
            status: None,
            body: raw,
        };
    };
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head
        .split("\r\n")
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok());
    Resp {
        status,
        body: raw[split + 4..].to_vec(),
    }
}
