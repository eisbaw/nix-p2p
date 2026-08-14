//! TASK-160 PASS BAR: the daemon runs a decentralized content path over libp2p,
//! THROUGH THE REAL SERVING STACK.
//!
//! Topology (all in-process, real loopback-TCP libp2p swarms):
//!   * `B` - a bootstrap node (the only address `P` and `C` are told).
//!   * `P` - a SERVING provider: holds a known raw NAR, serves it over the libp2p NAR
//!     request-response protocol, and announces its signed [`ProviderRecord`] for the
//!     `ContentKey` derived (FROZEN recipe) from the NAR's signed NarHash.
//!   * `C` - the CONSUMER daemon under test: its p2p `NarSource` is a
//!     [`Libp2pNarSource`] over `C`'s own [`Libp2pFabric`], wrapped in a
//!     [`FallbackNarSource`] in front of a fake HTTP upstream, behind the real `App`
//!     serving stack (`common::spawn_app` + `common::get`, the exact stack the binary
//!     runs).
//!
//! What it proves (the whole point - no shortcut):
//!   * HIT: given a NarHash (learned at narinfo time by the daemon, as in production),
//!     `C` DISCOVERS `P` via libp2p-kad - the [`ProviderRecord`] is produced by
//!     Kademlia, NOT injected into the source - fetches the raw NAR from `P` over
//!     libp2p, gate-1 BLAKE3-verifies it, and the daemon serves BYTE-IDENTICAL bytes.
//!     The HTTP-upstream fallback is never consulted.
//!   * MISS: for a NarHash nobody announced, `C`'s kad lookup is a healthy Miss, the
//!     libp2p source fails closed, and the daemon cleanly FALLS BACK to the HTTP
//!     upstream (S2) - proving the p2p source never hangs or poisons the miss path.
//!
//! HONEST SCOPE (documented, not faked):
//!   * DISCOVERY is genuinely decentralized: `C` knows only `B`; the answer is a real
//!     kad `get_providers` -> per-provider `get_record` -> frozen decode. NOT injected.
//!   * The byte-transfer DIAL address of `P` is fed into `C`'s swarm out of band (the
//!     TASK-159 basic-dial shim; the gate-able NodeLocator / NAT-traversal axis is not
//!     wired yet - `Libp2pFabric::node_locator()` is `None`). This mirrors the existing
//!     `fabric-libp2p` two-node transfer test; it is the DIAL, not the discovery.
//!   * A full podman multi-daemon libp2p e2e is the follow-up (TASK-161); this
//!     in-process integration test is TASK-160's bar.

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
    App, CacheInfo, FallbackNarSource, Libp2pNarSource, NarCatalog, NarHashKey, NarKey, NarSource,
    NarinfoSource, NullCorrelation, RawUpstream, SourceError, StoreHash, UpstreamResponse,
};
use fabric_libp2p::{Libp2pFabric, MemoryNarSupplier, Multiaddr, NodeConfig, PeerId};
use peer_fabric::{
    AnnounceBudget, Blake3Digest, ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric,
    ProviderRecord, SafetyEnvelope, ServeBudget, TransportOffer, sign_provider_record,
};

// -------------------------------------------------------------------------
// libp2p node plumbing (mirrors fabric-libp2p's own multi-node tests).
// -------------------------------------------------------------------------

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// Bring up a fabric listening on an ephemeral loopback TCP port; return it (as an
/// `Arc`, so the `NarSource` and the readiness probe can share it) and its dial address.
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
/// routing table holds at least `min_peers` entries.
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

/// Build and SIGN a `ProviderRecord` for `nar_hash_bytes` offering the raw NAR whose
/// content digest is `content`, signed by the ed25519 key `seed` (the SAME seed the
/// provider node's identity is built from, so `record.provider == node.node_id`).
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
// Serving-stack doubles (a fake narinfo source keyed by store hash, a fake HTTP
// upstream NAR source counting fallbacks, a dead passthrough).
// -------------------------------------------------------------------------

/// The canonical `sha256:<nix-base32>` string for 32 raw NarHash bytes, exactly what a
/// real narinfo's `NarHash:` carries and what the daemon canonicalises back to those
/// bytes to derive the discovery key.
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

/// Serves one of two canned narinfos by store hash, so the daemon can correlate each
/// request token to its signed NarHash (as it does in production at narinfo time).
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
            other => {
                return Err(SourceError::Unreachable(format!("no narinfo for {other}")));
            }
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

/// A fake HTTP upstream NAR source: the FallbackNarSource secondary. Serves fixed bytes
/// for any key and counts how many times it was consulted, so the test can prove the p2p
/// primary served the HIT (0 fallbacks) and the miss fell back (1 fallback).
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
async fn daemon_discovers_via_libp2p_kad_and_serves_byte_identical_nar_with_clean_miss_fallback() {
    let scope = "task160-daemon-libp2p";

    // The known NAR the provider serves, and its FROZEN content identity.
    let nar = b"nix-archive-1 raw NAR served decentrally through the daemon over libp2p".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);

    // The signed NarHash the daemon learns at narinfo time (any 32 sha256 bytes; Nix's
    // sha256==NarHash gate is out of scope here - the daemon is outside the TCB). The
    // provider derives its ContentKey from the SAME bytes via the frozen recipe.
    let hit_nar_hash_bytes = [0x11u8; 32];
    let hit_nar_hash = nar_hash_string(hit_nar_hash_bytes);
    let hit_content_key = ContentKey::derive_from_signed_nar_hash(&hit_nar_hash_bytes);

    // A DIFFERENT NarHash that nobody will announce - the MISS arm.
    let miss_nar_hash_bytes = [0x22u8; 32];
    let miss_nar_hash = nar_hash_string(miss_nar_hash_bytes);

    // ---- Stand up the libp2p network: bootstrap B, provider P, consumer C ----
    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig::new([1u8; 32]).with_network_scope(scope))
            .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    // P serves the NAR from an in-memory supplier and signs with its own identity seed.
    let provider_seed = [3u8; 32];
    let (provider, provider_addr) = start_fabric(
        Libp2pFabric::start_with_supplier(
            NodeConfig::new(provider_seed).with_network_scope(scope),
            Arc::new(MemoryNarSupplier::new([nar.clone()])),
        )
        .expect("provider starts"),
    )
    .await;
    let provider_peer = provider.peer_id();

    let (consumer, _consumer_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig::new([4u8; 32]).with_network_scope(scope))
            .expect("consumer starts"),
    )
    .await;

    // P and C join the DHT through B ONLY (they never learn each other out of band for
    // discovery). B needs no join (it is the entry point).
    join(&provider, boot_peer, boot_addr.clone(), 1).await;
    join(&consumer, boot_peer, boot_addr.clone(), 1).await;

    // Sanity: the record's provider (ed25519 verifying key) is P's node identity.
    let record = signed_record(provider_seed, hit_nar_hash_bytes, content);
    assert_eq!(
        record.provider,
        provider.node_id(),
        "self-serve: the signing key IS the node identity"
    );
    assert_eq!(record.key, hit_content_key, "one NarHash -> one ContentKey");

    // P starts serving (hold the handle for the whole test) and announces its record.
    let _serve = provider
        .server()
        .expect("a serving provider has a server axis")
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    provider
        .announcer()
        .expect("provider announces")
        .announce(&record, &AnnounceBudget::new(Duration::from_secs(10), 20))
        .await
        .expect("announce admitted");

    // Feed P's dial address into C's swarm for the byte-transfer leg (the TASK-159
    // basic-dial shim; discovery below is still a real, injection-free kad lookup).
    consumer
        .handle()
        .add_address(provider_peer, provider_addr)
        .await;

    // ---- Readiness: wait until C can DISCOVER P purely through kad ----
    // This is the SAME lookup the Libp2pNarSource will run; polling it here absorbs DHT
    // propagation without injecting the answer. It also asserts the discovered record is
    // exactly P's signed record (produced by Kademlia).
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

    // ---- Build the real daemon serving stack around C's libp2p source ----
    let fallback_hits = Arc::new(AtomicUsize::new(0));
    let fallback_body = b"HTTP-UPSTREAM FALLBACK BYTES (must only appear on the miss arm)".to_vec();

    let libp2p_source: Arc<dyn NarSource> = Arc::new(Libp2pNarSource::new(
        consumer.clone() as Arc<dyn PeerFabric>,
        discovery_budget,
        SafetyEnvelope::default(),
    ));
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
            // The HIT narinfo's NarSize is the served NAR's true byte length.
            hit: narinfo_body(hit_token, &hit_nar_hash, nar.len()),
            miss: narinfo_body(miss_token, &miss_nar_hash, fallback_body.len()),
        }),
        nar: nar_source,
        passthrough: Arc::new(DeadPassthrough),
        cache_info: CacheInfo::default(),
        catalog: Arc::new(NarCatalog::new()),
        upstream_label: "task160-upstream".to_string(),
        correlation: Arc::new(NullCorrelation),
        raw_serve: Arc::new(daemon::NoRawServe),
        public_allowlist: Arc::new(daemon::PublicNarAllowlist::disabled()),
    });
    let (addr, _daemon) = common::spawn_app(app).await;

    // ---- HIT arm: correlate the narinfo, then fetch the NAR over libp2p ----
    let narinfo = common::get(addr, "/hit.narinfo").await;
    assert_eq!(
        narinfo.status,
        Some(200),
        "narinfo served (token correlated)"
    );

    let served = common::get(addr, &format!("/nar/{hit_token}")).await;
    assert_eq!(
        served.status,
        Some(200),
        "the daemon served the NAR discovered+fetched over libp2p"
    );
    assert_eq!(
        served.body, nar,
        "served bytes are BYTE-IDENTICAL to the NAR P holds (fetched via libp2p, gate-1 verified)"
    );
    assert_eq!(
        fallback_hits.load(Ordering::SeqCst),
        0,
        "the HTTP upstream fallback must NOT be consulted on a p2p HIT"
    );

    // ---- MISS arm: an un-announced NarHash falls back cleanly to HTTP upstream ----
    let miss_narinfo = common::get(addr, "/miss.narinfo").await;
    assert_eq!(miss_narinfo.status, Some(200), "miss narinfo correlated");

    let miss_served = common::get(addr, &format!("/nar/{miss_token}")).await;
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
}
