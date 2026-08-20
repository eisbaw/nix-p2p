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
//!     fresh consumer (built AFTER the original expiry) discovers a strictly-superseding record and,
//!     to prove CONTINUOUS re-signing (not a one-shot refresh), watches the discovered sequence
//!     STRICTLY INCREASE across ≥2 further refresh cycles past the original TTL, then FETCHES S
//!     byte-identically over libp2p with 0 upstream fallback. (A task that refreshed once and exited
//!     would plateau and fail this arm.)
//!   * RED-without (the negative control): [`seed_goes_undiscoverable_past_ttl_without_resign`] — the
//!     SAME setup with NO re-sign leaves only the original (now-expired) record. The fresh consumer's
//!     discovery of S settles to `Lookup::Miss` — the AUTHORITATIVE healthy-absence the directory
//!     returns when it REACHED the provider's record and skipped it as EXPIRED (the `Stale`
//!     decode-reject boundary in `directory.rs`), which is DISTINCT from `Unavailable` (a routing /
//!     consult failure). Asserting `Miss` (never `Found`, and specifically not accepting a transient
//!     `Unavailable` as success) attributes the failure to the expiry boundary, not a broken harness
//!     — and the GREEN arm proves the SAME setup IS discoverable when the re-sign runs.
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
    AnnounceBudget, Axis, ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric, SafetyEnvelope,
    ServeBudget, ServeHandle, TransportTag,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Poll `find_providers(key)` on `consumer` until it discovers a record for `provider_id` whose
/// sequence is STRICTLY GREATER than `min_exclusive`, returning that sequence. Bounded (panics on
/// timeout) so a PLATEAUED (one-shot) re-sign — which never produces a higher sequence — fails the
/// CONTINUOUS-refresh assertion in the positive arm.
async fn poll_discovered_sequence_above(
    consumer: &Arc<Libp2pFabric>,
    key: &ContentKey,
    provider_id: NodeId,
    budget: &DiscoveryBudget,
    min_exclusive: u64,
) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(SHORT_TTL_SECS * 3);
    loop {
        if let Lookup::Found(records) = consumer
            .provider_directory()
            .expect("consumer has a directory")
            .find_providers(key, budget)
            .await
            && let Some(seq) = records
                .iter()
                .find(|r| r.provider == provider_id)
                .map(|r| r.sequence)
            && seq > min_exclusive
        {
            return seq;
        }
        assert!(
            Instant::now() < deadline,
            "the consumer never discovered a re-signed record for S with sequence > {min_exclusive} \
             past the TTL — the re-sign is not continuously refreshing"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The SHORT record TTL both arms use (seconds). Re-sign fires at `ttl/2` = 4s; the fresh consumer
/// is built at `WAIT_PAST_TTL_S` (past the ORIGINAL expiry), where only a re-signed record can be
/// valid. Small enough to keep the test quick, large enough to give the loopback swarm headroom.
const SHORT_TTL_SECS: u64 = 8;
/// Wall-clock wait after the initial announce before building the fresh consumer: PAST the original
/// `SHORT_TTL_SECS` window, so the original signed record has certainly expired.
const WAIT_PAST_TTL_S: u64 = 10;

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

    // CONTINUOUS re-signing (not a one-shot refresh): the discovered sequence for S must STRICTLY
    // INCREASE across ≥2 further refresh cycles, ALL observed PAST the original TTL. A task that
    // re-signed once and exited would plateau here and fail. Every observed sequence is > 1 (a
    // re-signed supersede), and each strictly exceeds the previous — proof the seed keeps refreshing.
    let s1 =
        poll_discovered_sequence_above(&consumer, &content_key, provider_id, &discovery_budget, 1)
            .await;
    let s2 =
        poll_discovered_sequence_above(&consumer, &content_key, provider_id, &discovery_budget, s1)
            .await;
    let s3 =
        poll_discovered_sequence_above(&consumer, &content_key, provider_id, &discovery_budget, s2)
            .await;
    assert!(
        s1 > 1 && s1 < s2 && s2 < s3,
        "past the original TTL the seed must stay discoverable through CONTINUOUS re-signing: the \
         discovered sequence must strictly increase across ≥2 refresh cycles (got {s1} < {s2} < {s3})"
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

    // HIGH-5(b): the per-lookup budget (3s) is STRICTLY LESS than the confirmation window (8s), so
    // the window fits multiple independent lookups (a single 10s budget could swallow the whole
    // window in one call).
    let discovery_budget = DiscoveryBudget::new(Duration::from_secs(3), 32);
    let (consumer, _c_source, _c_raw) =
        build_libp2p_nar_source(consumer_cfg(scope, (boot_peer, boot_addr.clone())))
            .await
            .expect("production consumer builder constructs a running libp2p fabric");

    // HIGH-5(a): attribute the failure to the EXPIRY boundary, not a generic "not Found". Discovery
    // of S must SETTLE to `Lookup::Miss` — the AUTHORITATIVE healthy-absence the directory returns
    // ONLY when it reached the provider's record store and every candidate was skipped as EXPIRED /
    // withdrawn / absent (the `Stale` decode-reject in `directory.rs::classify`). That is DISTINCT
    // from `Unavailable` (a routing / consult failure), which we do NOT accept as success — we keep
    // polling toward the steady `Miss`. And it is NEVER `Found` for our provider. The GREEN arm
    // proves the SAME setup IS discoverable when the re-sign runs, so this `Miss` is the missing
    // re-sign (expiry), not a broken harness.
    let confirm_until = Instant::now() + Duration::from_secs(8);
    loop {
        match consumer
            .provider_directory()
            .expect("consumer has a directory")
            .find_providers(&content_key, &discovery_budget)
            .await
        {
            Lookup::Found(records) if records.iter().any(|r| r.provider == provider_id) => {
                panic!(
                    "without re-sign, S must NOT be discoverable past the TTL, but the fresh \
                     consumer FOUND a valid record for the provider"
                );
            }
            // Reached the record store; the only record was the expired original -> healthy,
            // AUTHORITATIVE absence. This is the expiry boundary, cleanly attributed (and DISTINCT
            // from `Unavailable`, which we do NOT accept as success). Breaking here IS the assertion
            // that discovery settled to `Miss`.
            Lookup::Miss => break,
            // A stray `Found` without our provider, or a transient `Unavailable` (consult/routing):
            // not success — keep polling toward the steady `Miss`.
            _ => {}
        }
        assert!(
            Instant::now() < confirm_until,
            "discovery of S never settled to the authoritative Miss (expired-record) boundary past \
             the TTL — it stayed Unavailable, which would not attribute the failure to expiry"
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
