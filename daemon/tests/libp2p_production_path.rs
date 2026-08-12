//! TASK-162 PASS BAR: the PRODUCTION libp2p wiring path constructs a working
//! decentralized `NarSource` FROM CONFIG and serves through the real serving stack.
//!
//! TASK-160 proved `Libp2pNarSource` discovers+fetches when the source is hand-built
//! in the test. This test instead drives the SAME construction the daemon binary runs:
//! a [`daemon::Libp2pSourceConfig`] fed to [`daemon::build_libp2p_nar_source`] (the lib
//! seam `main.rs::setup_p2p_source` calls). The binary's only extra step is parsing CLI
//! flags into that config, which is unit-tested in `main.rs`; together they cover the
//! production path (config -> running libp2p NarSource).
//!
//! Topology (all in-process, real loopback-TCP libp2p swarms), mirroring TASK-160:
//!   * `B` - a bootstrap node (the only address the consumer is CONFIGURED with).
//!   * `P` - a SERVING provider: holds a raw NAR, serves it over the libp2p NAR
//!     request-response protocol, announces its signed [`ProviderRecord`].
//!   * `C` - the CONSUMER: its p2p `NarSource` is built by the PRODUCTION builder from a
//!     `Libp2pSourceConfig` whose ONLY injected address is `B` (bootstrap) - `provider_addrs`
//!     is EMPTY, so `C` is NEVER told `P`'s dial address. Plus a listen addr and a scope.
//!     Then wrapped in a `FallbackNarSource` in front of a fake HTTP upstream behind the
//!     real `App` stack.
//!
//! What it proves (TASK-169): `C`, configured only with `B` as bootstrap and NO injected
//! provider address, DISCOVERS `P` via libp2p-kad (record kad-produced, NOT injected), then
//! its libp2p TRANSFER resolves `P`'s dial address THROUGH kad peer-routing INSIDE the
//! fabric (the `node_locator` machinery, no injection) and dials off that resolution before
//! fetching the raw NAR, gate-1 BLAKE3-verifies, and the daemon serves BYTE-IDENTICAL bytes
//! (0 upstream fallbacks); an un-announced NarHash is a clean kad miss that falls back to
//! HTTP (1 fallback). The daemon `resolve()` itself no longer calls `locate()` - the
//! resolve-then-dial lives inside the transfer, where the `DialInfo` is allowed to be (the
//! seam keeps it out of this serving layer).
//!
//! HONEST SCOPE (documented, not faked, carried from TASK-159's node_locator test): the
//! dial address is NOT injected - `provider_addrs` is empty and the test's readiness gate
//! asserts `locate()` independently returns `P`'s REAL listen address via the DHT. It does
//! NOT claim `locate()` is the SOLE connectivity path: in a small loopback kad network the
//! request-response fetch can reuse a connection an earlier kad query (bootstrap
//! self-lookup / get_providers) already opened to `P`, so isolating `locate()` as the only
//! dial path is not robust (whether an iterative query dials `P` depends on XOR distance).
//! What is proven is (a) NO provider address was injected out of band, and (b) the
//! production fetch transport consults `node_locator` inside the fabric and it resolves
//! `P`'s address independently. A full podman multi-daemon libp2p e2e is TASK-161.
//!
//! This test does NOT model the Nix client's transport gate. The consumer uses
//! `NoRawServe` and an `.nar.xz` token with `Compression: xz`, yet asserts the served
//! bytes equal the RAW NAR - because `common::get` is a plain HTTP client, not a Nix
//! client checking FileHash/Compression. A real Nix client would REJECT raw bytes under
//! a compressed narinfo. That mismatch (libp2p's dynamic kad discovery is decoupled from
//! the iroh-claim-keyed raw-serve allowlist, so a libp2p HIT under a compressed upstream
//! narinfo serves raw bytes without the narinfo being rewritten to raw) is a BLOCKING
//! correctness follow-up: TASK-164. What THIS test proves is the discover->fetch->serve
//! plumbing of the production config path, not real-Nix compression-domain correctness.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http::HeaderMap;
use http_body_util::{BodyExt, Full};

use daemon::{
    App, CacheInfo, FallbackNarSource, Libp2pSourceConfig, NarCatalog, NarHashKey, NarKey,
    NarSource, NarinfoSource, NullCorrelation, RawUpstream, SourceError, StoreHash,
    UpstreamResponse, build_libp2p_nar_source,
};
use fabric_libp2p::{Libp2pFabric, MemoryNarSupplier, Multiaddr, NodeConfig, PeerId};
use peer_fabric::{
    AnnounceBudget, Blake3Digest, ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric,
    ProviderRecord, ResolutionPolicy, SafetyEnvelope, ServeBudget, TransportOffer,
    sign_provider_record,
};

// -------------------------------------------------------------------------
// libp2p node plumbing for B and P (C is built by the production builder).
// -------------------------------------------------------------------------

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// Bring up a fabric listening on an ephemeral loopback TCP port; return it and its
/// dial address (used for B and P, which are stood up with the raw fabric API).
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

/// Join `node` to the network THROUGH the bootstrap peer only, then wait until its
/// routing table holds at least `min_peers` entries (used for P).
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
            "routing table did not reach {min_peers} peers in time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Build and SIGN a `ProviderRecord` (self-serve: the signing key IS the node identity).
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

// -------------------------------------------------------------------------
// Serving-stack doubles (a narinfo source keyed by store hash, a counting HTTP
// upstream, a dead passthrough) - the same shapes TASK-160's test uses.
// -------------------------------------------------------------------------

fn nar_hash_string(bytes: [u8; 32]) -> String {
    NarHashKey::from_sha256_bytes(bytes).to_string()
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

// -------------------------------------------------------------------------
// The pass-bar test.
// -------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_config_builds_libp2p_source_that_discovers_and_serves_with_clean_miss_fallback()
{
    let scope = "task162-production-path";

    let nar = b"nix-archive-1 raw NAR served via the PRODUCTION libp2p config path".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);

    let hit_nar_hash_bytes = [0x33u8; 32];
    let hit_nar_hash = nar_hash_string(hit_nar_hash_bytes);
    let hit_content_key = ContentKey::derive_from_signed_nar_hash(&hit_nar_hash_bytes);

    let miss_nar_hash_bytes = [0x44u8; 32];
    let miss_nar_hash = nar_hash_string(miss_nar_hash_bytes);

    // ---- Stand up B (bootstrap) and P (serving provider) with the raw fabric API ----
    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig {
            identity_seed: [1u8; 32],
            network_scope: scope.to_string(),
        })
        .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    let provider_seed = [3u8; 32];
    let (provider, provider_listen_addr) = start_fabric(
        Libp2pFabric::start_with_supplier(
            NodeConfig {
                identity_seed: provider_seed,
                network_scope: scope.to_string(),
            },
            Arc::new(MemoryNarSupplier::new([nar.clone()])),
        )
        .expect("provider starts"),
    )
    .await;

    join(&provider, boot_peer, boot_addr.clone(), 1).await;

    let record = signed_record(provider_seed, hit_nar_hash_bytes, content);
    assert_eq!(record.provider, provider.node_id(), "self-serve identity");
    assert_eq!(record.key, hit_content_key, "one NarHash -> one ContentKey");

    let _serve = provider
        .server()
        .expect("serving provider has a server axis")
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    provider
        .announcer()
        .expect("provider announces")
        .announce(&record, &AnnounceBudget::new(Duration::from_secs(10), 20))
        .await
        .expect("announce admitted");

    // ---- Build C through the PRODUCTION builder from a config ----
    // C is CONFIGURED with B as its ONLY injected address. `provider_addrs` is EMPTY:
    // C is NEVER told P's dial address - it must resolve it through kad peer-routing
    // (node_locator, TASK-169). This is exactly what main.rs::setup_p2p_source runs
    // after parsing --libp2p-bootstrap/--libp2p-listen/-scope (no --libp2p-provider-addr).
    let cfg = Libp2pSourceConfig {
        identity_seed: [4u8; 32],
        network_scope: scope.to_string(),
        listen: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        bootstrap: vec![(boot_peer, boot_addr.clone())],
        provider_addrs: vec![],
        discovery_budget: DiscoveryBudget::new(Duration::from_secs(10), 32),
        envelope: SafetyEnvelope::default(),
    };
    // The builder also returns a Libp2pRawServe (TASK-164); this NoRawServe test does
    // not wire it (the compression-domain correctness it enables is covered by
    // `libp2p_raw_serve.rs`), so it is intentionally dropped here.
    let (consumer, libp2p_source, _libp2p_raw_serve) = build_libp2p_nar_source(cfg)
        .await
        .expect("production builder constructs a running libp2p NarSource from config");

    // ---- Readiness: wait until C can DISCOVER P purely through kad ----
    // The builder returns the fabric so the test can poll the exact lookup the source
    // runs, absorbing DHT propagation without injecting the answer.
    let discovery_budget = DiscoveryBudget::new(Duration::from_secs(10), 32);
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        match consumer
            .provider_directory()
            .expect("consumer has a directory")
            .find_providers(&hit_content_key, &discovery_budget)
            .await
        {
            Lookup::Found(records) if records.iter().any(|r| r.provider == provider.node_id()) => {
                assert!(
                    records.contains(&record),
                    "the discovered record is P's exact signed record (kad-produced, not injected)"
                );
                break;
            }
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never discovered P through kad (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }

    // ---- Readiness + no-injection oracle: C resolves P's dial address via kad ----
    // The production fetch transport calls `node_locator().locate(record.provider, ..)`
    // INSIDE the fabric before dialing. Poll the SAME locate here so the subsequent served
    // request finds it Found (absorbing DHT propagation) AND assert the resolved address is
    // P's REAL listen address - which C was never told (provider_addrs empty). A resolver
    // that never learned P's address could only get it from the DHT, so this is the
    // no-injection proof (the same oracle as fabric-libp2p/tests/node_locator_discovery.rs).
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
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never resolved P's dial address via kad peer-routing \
                     (no injected address); last: {other:?}"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }

    // ---- Build the real daemon serving stack around C's PRODUCTION-built source ----
    let fallback_hits = Arc::new(AtomicUsize::new(0));
    let fallback_body = b"HTTP-UPSTREAM FALLBACK BYTES (must only appear on the miss arm)".to_vec();

    let upstream_secondary: Arc<dyn NarSource> = Arc::new(CountingUpstreamNar {
        body: fallback_body.clone(),
        hits: fallback_hits.clone(),
    });
    let nar_source: Arc<dyn NarSource> =
        Arc::new(FallbackNarSource::new(libp2p_source, upstream_secondary));

    let hit_token = "1hitnaaaaaaaaaaaaaaaaaaaaaaaaaaaa.nar.xz";
    let miss_token = "1missnaaaaaaaaaaaaaaaaaaaaaaaaaaa.nar.xz";
    let app = Arc::new(App {
        narinfo: Arc::new(TwoNarinfos {
            hit: narinfo_body(hit_token, &hit_nar_hash, nar.len()),
            miss: narinfo_body(miss_token, &miss_nar_hash, fallback_body.len()),
        }),
        nar: nar_source,
        passthrough: Arc::new(DeadPassthrough),
        cache_info: CacheInfo::default(),
        catalog: Arc::new(NarCatalog::new()),
        upstream_label: "task162-upstream".to_string(),
        correlation: Arc::new(NullCorrelation),
        raw_serve: Arc::new(daemon::NoRawServe),
    });
    let (addr, _daemon) = common::spawn_app(app).await;

    // ---- HIT arm ----
    let narinfo = common::get(addr, "/hit.narinfo").await;
    assert_eq!(
        narinfo.status,
        Some(200),
        "narinfo served (token correlated)"
    );

    // Snapshot C's exposure ledger around the served NAR request. A HIT discloses to the
    // DHT twice: `find_providers` (discover WHO, in `resolve`) records ContentKey+OurNodeId,
    // then the transport's `node_locator().locate` (resolve WHERE, inside the fetch) records
    // a further OurNodeId disclosure. The served request is synchronous and nothing else
    // drives the ledger, so this delta is attributable to those two DHT consultations. (See
    // the HIT-vs-MISS oracle below - this is why it bites the peer-routing consult.)
    let hit_ledger_before = consumer.exposure_ledger().len();
    let served = common::get(addr, &format!("/nar/{hit_token}")).await;
    let hit_ledger_delta = consumer.exposure_ledger().len() - hit_ledger_before;
    assert_eq!(
        served.status,
        Some(200),
        "the daemon served the NAR discovered+fetched over the production libp2p source"
    );
    assert_eq!(
        served.body, nar,
        "served bytes are BYTE-IDENTICAL to the NAR P holds (gate-1 verified over libp2p)"
    );
    assert_eq!(
        fallback_hits.load(Ordering::SeqCst),
        0,
        "the HTTP upstream fallback must NOT be consulted on a p2p HIT"
    );

    // ---- MISS arm ----
    let miss_narinfo = common::get(addr, "/miss.narinfo").await;
    assert_eq!(miss_narinfo.status, Some(200), "miss narinfo correlated");

    // Same ledger snapshot on the MISS path. Here `find_providers` returns `Miss`, so
    // `resolve` bails BEFORE the record loop and NEVER reaches the transfer (whose fetch is
    // where `node_locator().locate` now runs) - only the discovery disclosure is recorded,
    // not the peer-routing one.
    let miss_ledger_before = consumer.exposure_ledger().len();
    let miss_served = common::get(addr, &format!("/nar/{miss_token}")).await;
    let miss_ledger_delta = consumer.exposure_ledger().len() - miss_ledger_before;
    assert_eq!(
        miss_served.status,
        Some(200),
        "an un-announced NarHash: libp2p misses, the daemon falls back to upstream"
    );
    assert_eq!(
        miss_served.body, fallback_body,
        "the miss arm served the HTTP-upstream fallback bytes (clean S2 fallback)"
    );
    assert_eq!(
        fallback_hits.load(Ordering::SeqCst),
        1,
        "exactly one fallback: the miss arm, not the hit arm"
    );

    // ---- ORACLE: the fetch path CONSULTED node_locator on the HIT path ----
    // This is the robust proof (the byte-path arms alone do NOT bite it: a small loopback
    // kad lets the fetch reuse a connection an earlier discovery query opened to P, so the
    // HIT would serve byte-identical EVEN IF the transport skipped `locate` - verified by
    // mutation, TASK-169 notes). The peer-routing consult (now inside the transfer's fetch)
    // IS observable through the frozen exposure-ledger seam.
    //
    // LOAD-BEARING ASSUMPTION (pinned deliberately, per the TASK-169 mped review F2): the
    // directory's `find_providers` records a PROVIDER-COUNT-INDEPENDENT 2 disclosures
    // (ContentKey + OurNodeId, `fabric-libp2p/src/directory.rs`) up front on any DHT
    // consultation, and the transport's `node_locator().locate` records EXACTLY 1 more
    // (OurNodeId, `fabric-libp2p/src/locator.rs`) inside the fetch; the byte path itself
    // records none. So a HIT (discovery Found -> record loop -> transfer.fetch -> locate)
    // discloses `find_providers`(2) + `locate`(1) = 3, and a MISS (discovery Miss -> returns
    // BEFORE the record loop, no fetch, no locate) discloses only
    // `find_providers`(2). The EXACT `+1` form is intentional: were discovery ever changed
    // to record a per-provider disclosure, a HIT would out-disclose a MISS for the WRONG
    // reason (more providers, not a peer-routing consult) - a strict `>` would silently pass
    // and stop guarding the locate call. Exact equality trips loudly instead, forcing this
    // oracle to be revisited alongside any change to discovery's exposure accounting.
    assert_eq!(
        hit_ledger_delta,
        miss_ledger_delta + 1,
        "a p2p HIT must disclose to the DHT via peer-routing (node_locator) EXACTLY one \
         disclosure beyond the discovery lookup a MISS does; got hit_delta={hit_ledger_delta}, \
         miss_delta={miss_ledger_delta}. hit != miss+1 means either the transport did not \
         consult node_locator on the HIT, or discovery's exposure accounting changed (revisit \
         this oracle - see the load-bearing assumption above)"
    );
}
