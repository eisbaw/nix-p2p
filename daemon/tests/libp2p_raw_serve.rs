//! TASK-164 PASS BAR: a libp2p discovery HIT under a COMPRESSED upstream narinfo
//! triggers the SAME task-49 narinfo rewrite the iroh claim path gets, so a REAL Nix
//! client (which validates `FileHash`/`FileSize`/`Compression` against the served
//! bytes) ACCEPTS the raw NAR the daemon serves.
//!
//! ## The bug this closes (TASK-162 mped review, real not theoretical)
//!
//! The daemon serves the RAW NAR for a `SignedNarHash` correlation. For iroh a
//! discovery HIT implies an allowlist HIT (both seeded from `--p2p-claim`), so the
//! narinfo is rewritten to raw (`Compression: none`, `FileHash`/`FileSize` = the raw
//! NAR's hash/size) and a Nix client accepts. For libp2p, discovery is DYNAMIC (kad
//! `find_providers`) with no static claim, so BEFORE this fix a libp2p HIT under an xz
//! upstream narinfo served RAW bytes while the narinfo still declared `Compression: xz`
//! -> a real Nix client rejects on `FileHash`/`Compression`. TASK-160/162's in-process
//! test masked it: `NoRawServe` + a plain HTTP client asserting raw==raw.
//!
//! ## What THIS test proves (the fix, tested green)
//!
//! Topology is the production-path one (B bootstrap, P serving provider, C consumer
//! built by the PRODUCTION builder). The one thing that changes: C's `App` is wired
//! with the `Libp2pRawServe` the SAME builder returns (TASK-164), and the upstream
//! narinfo is COMPRESSED (xz, `FileHash != NarHash`), with `NarHash` set to the REAL
//! sha256 of the raw NAR so a modeled Nix client can actually verify it.
//!
//!   * HIT arm: C discovers P via kad; the narinfo the daemon returns is REWRITTEN to
//!     raw; the served NAR bytes pass a modeled Nix client's gate-1
//!     (`sha256(served) == FileHash`, `len == FileSize`) AND gate-2
//!     (decompress-none, `sha256(nar) == NarHash`, `len == NarSize`). ACCEPTED.
//!   * The oracle BITES BY MUTATION: the same modeled client REJECTS the identical raw
//!     bytes when validated against the ORIGINAL COMPRESSED narinfo - i.e. it would
//!     have caught the pre-fix bug. (AC#2.)
//!   * MISS arm: an un-announced NarHash is a clean kad miss; the narinfo is relayed
//!     BYTE-VERBATIM (still `Compression: xz`) - passthrough non-regression (S1).
//!
//! HONEST SCOPE (as TASK-160/162): discovery is genuinely decentralized; P's
//! byte-transfer DIAL address is supplied to C out of band (the TASK-159 basic-dial
//! shim). The modeled Nix client is exactly the transport+trust gate Nix applies, not
//! a real `nix` process (the real-nix acceptance oracle is scripts/check-rewrite-realnix.py
//! for the pure rewrite; a full podman libp2p e2e with compressed fixtures is TASK-161).

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http::HeaderMap;
use http_body_util::{BodyExt, Full};
use sha2::{Digest, Sha256};

use daemon::{
    App, CacheInfo, FallbackNarSource, Libp2pSourceConfig, NarCatalog, NarHashKey, NarKey,
    NarSource, NarinfoSource, NullCorrelation, RawUpstream, SourceError, StoreHash,
    UpstreamResponse, build_libp2p_nar_source,
};
use fabric_libp2p::{Libp2pFabric, MemoryNarSupplier, Multiaddr, NodeConfig, PeerId};
use peer_fabric::{
    AnnounceBudget, Blake3Digest, ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric,
    ProviderRecord, SafetyEnvelope, ServeBudget, TransportOffer, sign_provider_record,
};

// -------------------------------------------------------------------------
// libp2p node plumbing for B and P (C is built by the production builder).
// Same shapes as tests/libp2p_production_path.rs.
// -------------------------------------------------------------------------

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
        offers: vec![TransportOffer::libp2p(provider)],
        sequence: 1,
        issued_at: now,
        expiry: now + 3600,
        signature: [0u8; 64],
    };
    sign_provider_record(&signing_key, &record)
}

// -------------------------------------------------------------------------
// Serving-stack doubles.
// -------------------------------------------------------------------------

/// A COMPRESSED (xz) upstream narinfo: `FileHash`/`FileSize` describe the compressed
/// transfer and are DISTINCT from the raw `NarHash`/`NarSize`. `NarHash` is the REAL
/// sha256 of the raw NAR so a modeled Nix client can verify it end to end.
fn compressed_narinfo(token: &str, nar_hash: &str, nar_size: usize) -> Vec<u8> {
    format!(
        "StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
         URL: nar/{token}\n\
         Compression: xz\n\
         FileHash: sha256:00000000000000000000000000000000000000000000000000000\n\
         FileSize: 4242\n\
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
// The modeled Nix client: exactly the transport + trust gate Nix applies to a
// narinfo + the file it points at. This is the oracle the pass bar is about.
// -------------------------------------------------------------------------

fn field(body: &[u8], key: &str) -> Option<String> {
    String::from_utf8_lossy(body)
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")).map(str::to_string))
}

fn sha256_narhash_string(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    NarHashKey::from_sha256_bytes(digest).to_string()
}

/// Validate `served` against `narinfo` the way a real Nix client does:
///   gate 1 (transport): `sha256(served) == FileHash` AND `len == FileSize`;
///   gate 2 (trust): decompress per `Compression`, then `sha256(nar) == NarHash`
///   AND `len == NarSize`.
/// Only `Compression: none` is modeled (a peer-served raw NAR must be uncompressed);
/// any other coding is REJECTED, which is the point - it bites the pre-fix bug where
/// raw bytes were served under `Compression: xz`.
fn nix_client_accepts(narinfo: &[u8], served: &[u8]) -> Result<(), String> {
    let compression = field(narinfo, "Compression").ok_or("no Compression")?;
    let file_hash = field(narinfo, "FileHash").ok_or("no FileHash")?;
    let file_size: u64 = field(narinfo, "FileSize")
        .ok_or("no FileSize")?
        .parse()
        .map_err(|e| format!("bad FileSize: {e}"))?;
    let nar_hash = field(narinfo, "NarHash").ok_or("no NarHash")?;
    let nar_size: u64 = field(narinfo, "NarSize")
        .ok_or("no NarSize")?
        .parse()
        .map_err(|e| format!("bad NarSize: {e}"))?;

    // Gate 1: transport integrity of the downloaded file.
    if served.len() as u64 != file_size {
        return Err(format!(
            "gate-1 FileSize: served {} != FileSize {file_size}",
            served.len()
        ));
    }
    let served_hash = sha256_narhash_string(served);
    if served_hash != file_hash {
        return Err(format!(
            "gate-1 FileHash: sha256(served)={served_hash} != FileHash {file_hash}"
        ));
    }

    // Gate 2: decompress per Compression, then verify the raw NAR against the SIGNED
    // NarHash/NarSize. A peer serves the raw NAR, so only Compression: none is valid.
    let nar = match compression.as_str() {
        "none" => served.to_vec(),
        other => {
            return Err(format!(
                "gate-2 Compression: narinfo declares {other:?} but the served bytes \
                 are a raw NAR - a real Nix client cannot decompress raw bytes as {other}"
            ));
        }
    };
    if nar.len() as u64 != nar_size {
        return Err(format!(
            "gate-2 NarSize: nar {} != NarSize {nar_size}",
            nar.len()
        ));
    }
    let computed = sha256_narhash_string(&nar);
    if computed != nar_hash {
        return Err(format!(
            "gate-2 NarHash: sha256(nar)={computed} != NarHash {nar_hash}"
        ));
    }
    Ok(())
}

// -------------------------------------------------------------------------
// The pass-bar test.
// -------------------------------------------------------------------------

/// TASK-231: wrap a record for the witness-taking `announce`; provider uses AdmitAll test authority.
fn eligible(record: &peer_fabric::ProviderRecord) -> peer_fabric::PublicationWitness {
    use peer_fabric::PublicationEligibility;
    peer_fabric::AdmitAllPublication
        .authorize(record.clone())
        .expect("admit-all authorizes a test record")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn libp2p_hit_under_compressed_narinfo_is_rewritten_to_raw_and_a_nix_client_accepts() {
    let scope = "task164-raw-serve";

    // The raw NAR P serves. NarHash is the REAL sha256 of these bytes, so the fixture
    // is what a real cache would sign, and the modeled Nix client can verify it.
    let nar = b"nix-archive-1 raw NAR whose narinfo is xz upstream but served raw".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);
    let hit_nar_hash_bytes: [u8; 32] = Sha256::digest(&nar).into();
    let hit_nar_hash = NarHashKey::from_sha256_bytes(hit_nar_hash_bytes).to_string();
    let hit_content_key = ContentKey::derive_from_signed_nar_hash(&hit_nar_hash_bytes);

    // A DIFFERENT, un-announced NAR for the miss arm (kad will never find a provider).
    let miss_nar_hash_bytes = [0x44u8; 32];
    let miss_nar_hash = NarHashKey::from_sha256_bytes(miss_nar_hash_bytes).to_string();

    // ---- Stand up B (bootstrap) and P (serving provider) ----
    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig::new([1u8; 32]).with_network_scope(scope))
            .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    let provider_seed = [3u8; 32];
    let (provider, provider_addr) = start_fabric(
        Libp2pFabric::start_with_supplier(
            NodeConfig::new(provider_seed)
                .with_network_scope(scope)
                .with_admit_all_publication(),
            Arc::new(MemoryNarSupplier::new([nar.clone()])),
        )
        .expect("provider starts"),
    )
    .await;
    let provider_peer = provider.peer_id();

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
        .announce(
            &eligible(&record),
            &AnnounceBudget::new(Duration::from_secs(10), 20),
        )
        .await
        .expect("announce admitted");

    // ---- Build C through the PRODUCTION builder; capture its Libp2pRawServe ----
    let cfg = Libp2pSourceConfig {
        identity_seed: [4u8; 32],
        network_scope: scope.to_string(),
        listen: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        additional_listens: Vec::new(),
        external_addresses: Vec::new(),
        bootstrap: vec![(boot_peer, boot_addr.clone())],
        provider_addrs: vec![(provider_peer, provider_addr)],
        discovery_budget: DiscoveryBudget::new(Duration::from_secs(10), 32),
        envelope: SafetyEnvelope::default(),
        state_dir: None,
        relay_server_enabled: true,
        kad_server: true,
    };
    let (consumer, libp2p_source, libp2p_raw_serve) = build_libp2p_nar_source(cfg)
        .await
        .expect("production builder constructs a running libp2p NarSource + raw-serve");

    // ---- Readiness: wait until C can DISCOVER P purely through kad ----
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

    // ---- Build the real daemon serving stack, wiring the Libp2pRawServe ----
    let fallback_hits = Arc::new(AtomicUsize::new(0));
    let fallback_body = b"HTTP FALLBACK BYTES (must only appear on the miss arm)".to_vec();
    let upstream_secondary: Arc<dyn NarSource> = Arc::new(CountingUpstreamNar {
        body: fallback_body.clone(),
        hits: fallback_hits.clone(),
    });
    let nar_source: Arc<dyn NarSource> =
        Arc::new(FallbackNarSource::new(libp2p_source, upstream_secondary));

    // COMPRESSED upstream narinfos (xz). The hit arm's NarHash is the raw NAR's real
    // sha256; the miss arm's is an arbitrary un-announced hash.
    let hit_token = "1hitxaaaaaaaaaaaaaaaaaaaaaaaaaaaa.nar.xz";
    let miss_token = "1missxaaaaaaaaaaaaaaaaaaaaaaaaaaa.nar.xz";
    let hit_upstream_narinfo = compressed_narinfo(hit_token, &hit_nar_hash, nar.len());
    let miss_upstream_narinfo = compressed_narinfo(miss_token, &miss_nar_hash, fallback_body.len());

    let app = Arc::new(App {
        narinfo: Arc::new(TwoNarinfos {
            hit: hit_upstream_narinfo.clone(),
            miss: miss_upstream_narinfo.clone(),
        }),
        nar: nar_source,
        passthrough: Arc::new(DeadPassthrough),
        cache_info: CacheInfo::default(),
        catalog: Arc::new(NarCatalog::new()),
        upstream_label: "task164-upstream".to_string(),
        correlation: Arc::new(NullCorrelation),
        // The fix under test: the libp2p dynamic raw-serve decision, so a libp2p HIT
        // rewrites its compressed narinfo to raw.
        raw_serve: libp2p_raw_serve,
        public_allowlist: Arc::new(daemon::PublicNarAllowlist::disabled()),

        post_fetch_announce: None,
    });
    let (addr, _daemon) = common::spawn_app(app).await;

    // ---- HIT arm: the narinfo is REWRITTEN to raw ----
    let narinfo = common::get(addr, "/hit.narinfo").await;
    assert_eq!(narinfo.status, Some(200), "narinfo served");
    let body = &narinfo.body;
    assert_eq!(
        field(body, "Compression").as_deref(),
        Some("none"),
        "a libp2p HIT rewrites the xz narinfo to raw (Compression: none)"
    );
    assert_eq!(
        field(body, "FileHash").as_deref(),
        Some(hit_nar_hash.as_str()),
        "FileHash rewritten to the raw NarHash (sha256 of the raw NAR)"
    );
    assert_eq!(
        field(body, "FileSize").map(|s| s.parse::<u64>().unwrap()),
        Some(nar.len() as u64),
        "FileSize rewritten to the raw NarSize, not the compressed 4242"
    );
    // SIGNED fields survive byte-verbatim.
    for signed in ["StorePath", "NarHash", "NarSize", "References", "Sig"] {
        assert_eq!(
            field(body, signed),
            field(&hit_upstream_narinfo, signed),
            "signed field {signed} must be byte-identical through the rewrite"
        );
    }

    // ---- HIT arm: fetch the NAR at the URL the rewritten narinfo points at ----
    let url = field(body, "URL").expect("rewritten narinfo has a URL");
    let path = url.strip_prefix("nar/").expect("URL is nar/-relative");
    let served = common::get(addr, &format!("/nar/{path}")).await;
    assert_eq!(
        served.status,
        Some(200),
        "the raw NAR is served over libp2p"
    );
    assert_eq!(
        served.body, nar,
        "served bytes are the raw NAR P holds (gate-1 verified over libp2p)"
    );
    assert_eq!(
        fallback_hits.load(Ordering::SeqCst),
        0,
        "the HTTP upstream fallback must NOT be consulted on a p2p HIT"
    );

    // THE PASS BAR: a real Nix client validating FileHash/FileSize/Compression against
    // the served bytes ACCEPTS them.
    nix_client_accepts(body, &served.body)
        .expect("a real Nix client accepts the rewritten raw narinfo + raw NAR");

    // AC#2: the oracle BITES BY MUTATION. The SAME modeled client REJECTS the identical
    // raw bytes when validated against the ORIGINAL COMPRESSED narinfo - i.e. it would
    // have caught the pre-fix bug (raw bytes under Compression: xz).
    let rejection = nix_client_accepts(&hit_upstream_narinfo, &served.body)
        .expect_err("a Nix client MUST reject raw bytes under the compressed upstream narinfo");
    // The rejection must be a genuine transport/trust-gate failure (a real Nix client
    // rejecting the compression-domain mismatch), not an incidental parse error. The raw
    // bytes disagree with the compressed narinfo's FileSize/FileHash (gate 1) and its
    // Compression: xz (gate 2) - any of those is the bug being caught.
    assert!(
        rejection.starts_with("gate-1") || rejection.starts_with("gate-2"),
        "the mutation must be caught on a verification gate, got: {rejection}"
    );

    // ---- MISS arm: an un-announced NarHash -> byte-verbatim compressed narinfo ----
    let miss_narinfo = common::get(addr, "/miss.narinfo").await;
    assert_eq!(miss_narinfo.status, Some(200), "miss narinfo served");
    assert_eq!(
        miss_narinfo.body, miss_upstream_narinfo,
        "a libp2p MISS relays the upstream narinfo BYTE-VERBATIM (still Compression: xz), \
         the passthrough non-regression (S1)"
    );
    assert_eq!(
        field(&miss_narinfo.body, "Compression").as_deref(),
        Some("xz"),
        "the miss arm's narinfo is NOT rewritten"
    );

    // And the miss arm's NAR falls back to HTTP upstream (clean S2).
    let miss_served = common::get(addr, &format!("/nar/{miss_token}")).await;
    assert_eq!(
        miss_served.status,
        Some(200),
        "miss NAR served via fallback"
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
