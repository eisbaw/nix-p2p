//! The daemon-libp2p PRODUCTION PATH end to end THROUGH `daemon_core::run` (TASK-146
//! honesty gate). The binary's `fn main` is: parse CLI -> `build_libp2p_nar_source(cfg)` ->
//! `daemon_core::run(fabric, RunConfig)`. This test drives that exact seam (minus CLI
//! parsing, which is the argv-splitting in `main.rs`): it constructs the consumer fabric from
//! a `Libp2pSourceConfig` and then SERVES real HTTP through `run`, so the `run` glue -
//! require_axes gate -> `PeerFabricNarSource` + HTTP-upstream fallback -> `App` -> `serve` -
//! is genuinely exercised, not hand-assembled.
//!
//! Sibling `daemon/tests/libp2p_production_path.rs` proves the SAME discover/fetch topology
//! but hand-assembles `App`; it does NOT call `run`. This one closes that gap: the ~15 lines
//! of `run.rs` composition and the fetch-through-`run` byte path were previously unguarded.
//!
//! Topology (all in-process, real loopback-TCP libp2p swarms), mirroring the sibling:
//!   * `B` - bootstrap (the consumer's ONLY injected address).
//!   * `P` - a serving provider holding a raw NAR, announcing its signed record.
//!   * `C` - the CONSUMER, built by the production `build_libp2p_nar_source` from a config
//!     whose only injected address is `B`. Its fabric is handed to `run`, which wraps it in
//!     the generic `PeerFabricNarSource` with an HTTP-upstream fallback.
//!
//! Proves: a p2p HIT is served BYTE-IDENTICAL through `run` (0 upstream fallbacks); an
//! un-announced NarHash is a clean kad miss that `run`'s fallback turns into an upstream fetch
//! (exactly 1 fallback, upstream bytes). The no-injection / peer-routing oracle is the
//! sibling's job (and `fabric-libp2p/tests/node_locator_discovery.rs`); here the point is the
//! `run` composition serving the discovered content.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use daemon_core::{
    CacheInfo, NarKey, NarSource, NarinfoSource, NullCorrelation, RawUpstream, RunConfig,
    SourceError, StoreHash, UpstreamResponse, run,
};
use daemon_libp2p::{Libp2pSourceConfig, build_libp2p_nar_source};
use ed25519_dalek::SigningKey;
use fabric_libp2p::{Libp2pFabric, MemoryNarSupplier, Multiaddr, NodeConfig, PeerId};
use http::HeaderMap;
use http_body_util::{BodyExt, Full};
use peer_fabric::{
    AnnounceBudget, Axis, Blake3Digest, ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric,
    ProviderRecord, ResolutionPolicy, SafetyEnvelope, ServeBudget, TransportOffer, TransportTag,
    sign_provider_record,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// Bring a fabric up on an ephemeral loopback port; return it + its dial address.
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

/// Join `node` through the bootstrap peer, then wait for `min_peers` routing entries.
async fn join(node: &Libp2pFabric, boot_peer: PeerId, boot_addr: Multiaddr, min_peers: usize) {
    node.handle()
        .add_address(boot_peer, boot_addr.clone())
        .await;
    node.handle().dial(boot_addr).await.expect("dial bootstrap");
    let _ = node.handle().bootstrap().await;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if node.handle().routing_peers().await >= min_peers {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "routing table did not reach {min_peers} peers"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Build + SIGN P's self-serve ProviderRecord (signing key IS the node identity).
fn signed_record(
    seed: [u8; 32],
    nar_hash_bytes: [u8; 32],
    content: Blake3Digest,
) -> ProviderRecord {
    let signing_key = SigningKey::from_bytes(&seed);
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    let key = ContentKey::derive_from_signed_nar_hash(&nar_hash_bytes);
    let now = unix_now();
    let record = ProviderRecord {
        key,
        content,
        provider,
        offers: vec![TransportOffer::Iroh { node: provider }],
        sequence: 1,
        issued_at: now,
        expiry: now + 3600,
        signature: [0u8; 64],
    };
    sign_provider_record(&signing_key, &record)
}

/// Canonical NarHash string (sha256:<nix-base32>) via the daemon_core re-export.
fn nar_hash_string(bytes: [u8; 32]) -> String {
    daemon_core::NarHashKey::from_sha256_bytes(bytes).to_string()
}

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

/// A narinfo source that correlates two store hashes to two canned narinfos.
struct TwoNarinfos {
    hit: Vec<u8>,
    miss: Vec<u8>,
}

#[async_trait]
impl NarinfoSource for TwoNarinfos {
    async fn fetch(&self, hash: &StoreHash) -> Result<UpstreamResponse, SourceError> {
        let body = match hash.as_str() {
            "hit" => self.hit.clone(),
            "miss" => self.miss.clone(),
            other => return Err(SourceError::Unreachable(format!("no narinfo for {other}"))),
        };
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

/// The HTTP-upstream FALLBACK NAR source `run` layers behind the p2p source. Counts hits so
/// the test can assert the p2p HIT never touched it and the MISS did exactly once.
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

// ---- a minimal raw HTTP/1.1 GET client (run() is the server under test) ----
struct Resp {
    status: Option<u16>,
    body: Vec<u8>,
}

/// Extract the `URL: nar/<token>` the served narinfo advertises. `run` uses the PRODUCTION
/// dynamic raw-serve, so a narinfo whose NAR the provider announced is REWRITTEN to raw (a
/// different token, `Compression: none`); the client must follow the narinfo's own URL rather
/// than a hardcoded token. A narinfo whose NAR is NOT announced relays verbatim.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_serves_a_discovered_libp2p_nar_and_falls_back_on_miss() {
    let scope = "task146-run-production-path";

    let nar =
        b"nix-archive-1 raw NAR served THROUGH daemon_core::run over the libp2p path".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);

    let hit_nar_hash_bytes = [0x33u8; 32];
    let hit_nar_hash = nar_hash_string(hit_nar_hash_bytes);
    let hit_content_key = ContentKey::derive_from_signed_nar_hash(&hit_nar_hash_bytes);

    let miss_nar_hash_bytes = [0x44u8; 32];
    let miss_nar_hash = nar_hash_string(miss_nar_hash_bytes);

    // ---- B (bootstrap) + P (serving provider) via the raw fabric API ----
    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig::new([1u8; 32]).with_network_scope(scope))
            .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    let provider_seed = [3u8; 32];
    let (provider, provider_listen_addr) = start_fabric(
        Libp2pFabric::start_with_supplier(
            NodeConfig::new(provider_seed).with_network_scope(scope),
            Arc::new(MemoryNarSupplier::new([nar.clone()])),
        )
        .expect("provider starts"),
    )
    .await;
    join(&provider, boot_peer, boot_addr.clone(), 1).await;

    let record = signed_record(provider_seed, hit_nar_hash_bytes, content);
    assert_eq!(record.key, hit_content_key, "one NarHash -> one ContentKey");
    let _serve = provider
        .server()
        .expect("provider has a server axis")
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    provider
        .announcer()
        .expect("provider announces")
        .announce(&record, &AnnounceBudget::new(Duration::from_secs(10), 20))
        .await
        .expect("announce admitted");

    // ---- C: the CONSUMER, built by the PRODUCTION builder the binary calls ----
    let discovery_budget = DiscoveryBudget::new(Duration::from_secs(10), 32);
    let cfg = Libp2pSourceConfig {
        identity_seed: [4u8; 32],
        network_scope: scope.to_string(),
        listen: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        bootstrap: vec![(boot_peer, boot_addr.clone())],
        provider_addrs: vec![],
        discovery_budget,
        envelope: SafetyEnvelope::default(),
        state_dir: None,
        relay_server_enabled: true,
    };
    let (consumer, _libp2p_source, _raw) = build_libp2p_nar_source(cfg)
        .await
        .expect("production builder constructs a running libp2p fabric from config");

    // ---- Readiness: wait until C can DISCOVER P purely through kad ----
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        match consumer
            .provider_directory()
            .expect("consumer has a directory")
            .find_providers(&hit_content_key, &discovery_budget)
            .await
        {
            Lookup::Found(records) if records.iter().any(|r| r.provider == provider.node_id()) => {
                break;
            }
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never discovered P via kad (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    // And wait until the transfer can resolve P's REAL listen address via kad peer-routing -
    // the SAME resolution `run`'s fetch runs inside the transfer. A weaker "any Found" gate
    // can pass before the address propagates, letting run's first fetch dial a stale entry
    // and fall back; wait for P's actual listen address, as the sibling does.
    let locator = consumer
        .node_locator()
        .expect("consumer has a node_locator");
    let provider_listen = provider_listen_addr.to_string();
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        match locator
            .locate(&provider.node_id(), &ResolutionPolicy::PublicInfrastructure)
            .await
        {
            Lookup::Found(dial_info)
                if dial_info
                    .locations
                    .iter()
                    .any(|loc| loc.starts_with(&provider_listen)) =>
            {
                break;
            }
            _ => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never resolved P's real dial address via kad"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }

    // ---- SERVE THROUGH daemon_core::run (the exact glue the binary runs) ----
    let fallback_hits = Arc::new(AtomicUsize::new(0));
    let fallback_body = b"HTTP-UPSTREAM FALLBACK BYTES (must appear ONLY on the miss arm)".to_vec();
    let hit_token = "1hitnaaaaaaaaaaaaaaaaaaaaaaaaaaaa.nar.xz";
    let miss_token = "1missnaaaaaaaaaaaaaaaaaaaaaaaaaaa.nar.xz";

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("run() binds");
    let addr = listener.local_addr().unwrap();
    let run_cfg = RunConfig {
        listener,
        // `run` wraps the fabric in PeerFabricNarSource and puts THIS upstream behind it.
        upstream: Arc::new(CountingUpstreamNar {
            body: fallback_body.clone(),
            hits: fallback_hits.clone(),
        }) as Arc<dyn NarSource>,
        narinfo: Arc::new(TwoNarinfos {
            hit: narinfo_body(hit_token, &hit_nar_hash, nar.len()),
            miss: narinfo_body(miss_token, &miss_nar_hash, fallback_body.len()),
        }),
        passthrough: Arc::new(DeadPassthrough),
        correlation: Arc::new(NullCorrelation),
        cache_info: CacheInfo::default(),
        upstream_label: "task146-run-upstream".to_string(),
        discovery_budget,
        envelope: SafetyEnvelope::default(),
        required_axes: vec![
            Axis::ProviderDirectory,
            Axis::NodeLocator,
            Axis::Transfer(TransportTag::Iroh),
        ],
        extra_raw_serve: Vec::new(),
        public_allowlist: Arc::new(daemon_core::PublicNarAllowlist::disabled()),
    };
    let fabric_dyn: Arc<dyn PeerFabric> = consumer.clone();
    let run_task = tokio::spawn(run(fabric_dyn, run_cfg));

    // ---- HIT arm: served byte-identical through run(), no fallback ----
    // The provider ANNOUNCED this NAR, so run's dynamic raw-serve rewrites the narinfo to raw
    // (a new token, Compression: none); follow the narinfo's advertised URL, which the daemon
    // then serves from the p2p HIT byte-identically.
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
        "run() served the NAR discovered+fetched over the libp2p source"
    );
    assert_eq!(
        served.body, nar,
        "run() served BYTE-IDENTICAL bytes to the NAR P holds (gate-1 verified over libp2p)"
    );
    assert_eq!(
        fallback_hits.load(Ordering::SeqCst),
        0,
        "run()'s HTTP-upstream fallback must NOT be consulted on a p2p HIT"
    );

    // ---- MISS arm: clean kad miss -> run()'s fallback serves upstream bytes ----
    // This NAR is NOT announced, so raw-serve leaves the narinfo verbatim; the NAR request
    // then misses libp2p discovery and run falls back to the HTTP upstream.
    let miss_narinfo = get(addr, "/miss.narinfo").await;
    assert_eq!(
        miss_narinfo.status,
        Some(200),
        "miss narinfo served through run()"
    );
    let miss_url = url_token(&miss_narinfo.body);
    assert_eq!(
        miss_url,
        format!("nar/{miss_token}"),
        "an un-announced narinfo must relay verbatim (no raw rewrite)"
    );
    let miss_served = get(addr, &format!("/{miss_url}")).await;
    assert_eq!(
        miss_served.status,
        Some(200),
        "an un-announced NarHash: libp2p misses, run() falls back to upstream"
    );
    assert_eq!(
        miss_served.body, fallback_body,
        "the miss arm served run()'s HTTP-upstream fallback bytes (clean S2 fallback)"
    );
    assert_eq!(
        fallback_hits.load(Ordering::SeqCst),
        1,
        "exactly one fallback through run(): the miss arm, not the hit arm"
    );

    run_task.abort();
}
