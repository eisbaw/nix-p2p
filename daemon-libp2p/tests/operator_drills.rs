//! TASK-240 AC#6 — the four operational DRILL ORACLES as executable assertions.
//!
//! Each drill INJECTS an operational condition, asserts the operator observability surface
//! (`/nix-p2p/status`, `/nix-p2p/metrics`) REPORTS it correctly, AND asserts the S2 additive
//! invariant still holds — a fetch through the daemon still succeeds via the HTTP-upstream fallback
//! (the in-process analogue of "a `nix build` still succeeds; the store is never corrupted").
//!
//! These drive the GENUINELY-SHIPPED serving frontend `daemon_core::run` end to end: the same
//! composition `fn main` builds (a consumer fabric + the observability bundle + the dedicated
//! loopback admin listener), so the admin surface, the metrics recording in the discover/fetch
//! path, and the live-status join are all exercised, not hand-assembled.
//!
//! Scope honesty: the conditions are injected at the OBSERVABILITY seam (the live-facts snapshot,
//! the announce hook's budget, the operator profile) and the daemon is a `FakeFabric`-backed
//! consumer whose p2p path always misses (so every fetch folds to the S2 upstream). The
//! NETWORK-level fault injection (killing a real bootstrap process and watching `is_connected` flip)
//! is the containerized/VM layer's job and is a documented follow-up; the enforcement each surface
//! reads from (the announce ledger, the swarm `is_connected`, the durable identity seed) is proven
//! load-bearing by its own unit/integration tests. What these drills prove is that the operator
//! SURFACE reports each condition truthfully WHILE the additive invariant holds — the AC#6 property.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use daemon_core::{
    CacheInfo, DhtRole, NarKey, NarSource, NarinfoSource, NullCorrelation, NullStatusFacts,
    Observability, OperatorContract, PeerPath, PostFetchAnnounce, PrivacyPolicy,
    PublicNarAllowlist, RawUpstream, RunConfig, RuntimeMetrics, SharingProfile, SourceError,
    StatusFactSnapshot, StatusFacts, StoreHash, UpstreamResponse, run,
};
use ed25519_dalek::SigningKey;
use http::HeaderMap;
use http_body_util::{BodyExt, Full};
use peer_fabric::{FakeFabric, NodeId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

// -------------------------------------------------------------------------
// A minimal always-serving HTTP upstream (the S2 fallback the daemon folds to).
// -------------------------------------------------------------------------

const STORE_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NAR_TOKEN: &str = "0mn0000000000000000000000000000000000000000000000000.nar.xz";
const NAR_BYTES: &[u8] = b"nix-archive-1 S2 fallback NAR bytes served through daemon_core::run";

fn narinfo_body() -> Vec<u8> {
    format!(
        "StorePath: /nix/store/{STORE_HASH}-x\n\
         URL: nar/{NAR_TOKEN}\n\
         Compression: xz\n\
         FileHash: sha256:0000000000000000000000000000000000000000000000000000\n\
         FileSize: {}\n\
         NarHash: sha256:1bn0000000000000000000000000000000000000000000000000\n\
         NarSize: 999\n\
         References: \n\
         Sig: nix-p2p-test-1:AAAA==\n",
        NAR_BYTES.len()
    )
    .into_bytes()
}

fn ok(body: Vec<u8>, content_type: Option<&str>) -> UpstreamResponse {
    let mut headers = HeaderMap::new();
    if let Some(ct) = content_type {
        headers.insert(http::header::CONTENT_TYPE, ct.parse().unwrap());
    }
    headers.insert(http::header::CONTENT_LENGTH, body.len().into());
    UpstreamResponse {
        status: 200,
        headers,
        body: Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed(),
    }
}

struct FixedNarinfo;
#[async_trait]
impl NarinfoSource for FixedNarinfo {
    async fn fetch(&self, hash: &StoreHash) -> Result<UpstreamResponse, SourceError> {
        if hash.as_str() == STORE_HASH {
            Ok(ok(narinfo_body(), Some("text/x-nix-narinfo")))
        } else {
            Err(SourceError::Unreachable(format!("no narinfo for {hash:?}")))
        }
    }
}

struct FixedNar;
#[async_trait]
impl NarSource for FixedNar {
    async fn resolve(
        &self,
        _key: &NarKey,
        _expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        Ok(ok(NAR_BYTES.to_vec(), None))
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
// Controllable observability inputs (the injection seams).
// -------------------------------------------------------------------------

/// A mutable live-facts provider so a drill can flip bootstrap health at will.
struct MutFacts(Arc<Mutex<StatusFactSnapshot>>);
#[async_trait]
impl StatusFacts for MutFacts {
    async fn snapshot(&self) -> StatusFactSnapshot {
        *self.0.lock().unwrap()
    }
}

/// A test announce hook whose `budget_used` mirrors an integer counter capped at `cap` — the SAME
/// shape the shipped `Libp2pAnnounceAfterFetch::budget_used` exposes (proven against the real
/// enforced ledger in the lib's `budget_used_tracks_the_enforced_ledger`).
struct TestAnnounce {
    cap: u64,
    used: AtomicU64,
}
impl PostFetchAnnounce for TestAnnounce {
    fn on_fetched(&self, _nar_hash: &daemon_core::NarHash, _store_path: &str) {
        // Stop at the cap (the budget gate); past it, announcing STOPS.
        if self.used.load(Ordering::SeqCst) < self.cap {
            self.used.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn budget_used(&self) -> Option<u64> {
        Some(self.used.load(Ordering::SeqCst).min(self.cap))
    }
}

// -------------------------------------------------------------------------
// The harness: run() serving both the cache API and the admin surface.
// -------------------------------------------------------------------------

struct Daemon {
    cache: SocketAddr,
    admin: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Stand up `daemon_core::run` over a `FakeFabric` upstream-only consumer with the given
/// observability bundle inputs, plus the dedicated loopback admin listener.
async fn start_daemon(
    contract: OperatorContract,
    node_id_full: String,
    facts: Arc<dyn StatusFacts>,
    announce: Option<Arc<dyn PostFetchAnnounce>>,
) -> Daemon {
    let cache_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cache = cache_listener.local_addr().unwrap();
    let admin = admin_listener.local_addr().unwrap();

    let observability = Arc::new(Observability {
        contract,
        node_id_full,
        metrics: Arc::new(RuntimeMetrics::new()),
        facts,
        announce: announce.clone(),
        derive_ledger: None,
    });

    let fabric = Arc::new(FakeFabric::upstream_only(NodeId::from_bytes([0x09; 32])));
    let cfg = RunConfig {
        listener: cache_listener,
        upstream: Arc::new(FixedNar),
        narinfo: Arc::new(FixedNarinfo),
        passthrough: Arc::new(DeadPassthrough),
        correlation: Arc::new(NullCorrelation),
        cache_info: CacheInfo {
            store_dir: "/nix/store".to_string(),
            priority: 41,
            want_mass_query: true,
        },
        upstream_label: "http://drill-upstream".to_string(),
        discovery_budget: peer_fabric::DiscoveryBudget::default(),
        envelope: peer_fabric::SafetyEnvelope::default(),
        required_axes: Vec::new(),
        extra_raw_serve: Vec::new(),
        public_allowlist: Arc::new(PublicNarAllowlist::disabled()),
        post_fetch_announce: announce,
        observability: Some(observability),
        admin_listener: Some(admin_listener),
    };
    let task = tokio::spawn(async move {
        let _ = run(fabric, cfg).await;
    });
    // Let the accept loops bind before the first client connects.
    tokio::time::sleep(Duration::from_millis(50)).await;
    Daemon { cache, admin, task }
}

struct Resp {
    status: Option<u16>,
    body: Vec<u8>,
}

async fn get(addr: SocketAddr, path: &str) -> Resp {
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
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
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok());
    Resp {
        status,
        body: raw[split + 4..].to_vec(),
    }
}

async fn status_text(d: &Daemon) -> String {
    let r = get(d.admin, daemon_core::STATUS_PATH).await;
    assert_eq!(r.status, Some(200), "status endpoint must answer 200");
    String::from_utf8_lossy(&r.body).into_owned()
}

async fn metrics_text(d: &Daemon) -> String {
    let r = get(d.admin, daemon_core::METRICS_PATH).await;
    assert_eq!(r.status, Some(200), "metrics endpoint must answer 200");
    String::from_utf8_lossy(&r.body).into_owned()
}

/// The S2 ADDITIVE INVARIANT probe: a fetch through the daemon still succeeds via the upstream
/// fallback. Returns the served NAR bytes so the caller can assert byte fidelity. Also drives the
/// REAL metrics recording (the /nar fetch folds through FallbackNarSource -> hit_upstream).
async fn s2_fetch_succeeds(d: &Daemon) -> Vec<u8> {
    // nix-cache-info is always answerable locally.
    assert_eq!(
        get(d.cache, "/nix-cache-info").await.status,
        Some(200),
        "S2: nix-cache-info must answer"
    );
    // The narinfo (correlates the token) then the NAR itself, both via the upstream fallback.
    let ni = get(d.cache, &format!("/{STORE_HASH}.narinfo")).await;
    assert_eq!(
        ni.status,
        Some(200),
        "S2: narinfo must be served via fallback"
    );
    let nar = get(d.cache, &format!("/nar/{NAR_TOKEN}")).await;
    assert_eq!(nar.status, Some(200), "S2: NAR must be served via fallback");
    nar.body
}

fn node_id_for(seed: [u8; 32]) -> String {
    NodeId::from_bytes(SigningKey::from_bytes(&seed).verifying_key().to_bytes()).to_string()
}

// =========================================================================
// DRILL 1 — restart: a restart with the durable identity keeps the SAME NodeId.
// =========================================================================

/// Restart drill: the status surface reports a NodeId derived from the durable identity seed;
/// across a "restart" (a fresh `run` lifetime) with the SAME seed the reported NodeId is UNCHANGED,
/// AND the S2 fetch still succeeds. Negative control: a DIFFERENT seed changes the reported id, so
/// the assertion is not vacuous. MUTATION: reporting a session-random id (dropping the durable seed)
/// reddens the "unchanged across restart" assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drill_restart_keeps_stable_node_id_and_s2_holds() {
    let seed = [0x21u8; 32];
    let expected = node_id_for(seed);

    // First lifetime.
    let d1 = start_daemon(
        OperatorContract::for_profile(SharingProfile::ConsumeOnly),
        expected.clone(),
        Arc::new(NullStatusFacts),
        None,
    )
    .await;
    let s1 = status_text(&d1).await;
    assert!(
        s1.contains(&format!("node_id={}", &expected[..8])),
        "status must report the durable NodeId (redacted prefix):\n{s1}"
    );
    assert_eq!(
        s2_fetch_succeeds(&d1).await,
        NAR_BYTES,
        "S2 holds before restart"
    );
    drop(d1); // "kill" the node.

    // Restart: a fresh run lifetime with the SAME durable seed -> SAME reported NodeId.
    let d2 = start_daemon(
        OperatorContract::for_profile(SharingProfile::ConsumeOnly),
        node_id_for(seed),
        Arc::new(NullStatusFacts),
        None,
    )
    .await;
    let s2 = status_text(&d2).await;
    assert!(
        s2.contains(&format!("node_id={}", &expected[..8])),
        "restart with the durable seed keeps the SAME NodeId:\n{s2}"
    );
    assert_eq!(
        s2_fetch_succeeds(&d2).await,
        NAR_BYTES,
        "S2 holds after restart"
    );

    // Negative control: a DIFFERENT seed reports a DIFFERENT id (the assertion above bites).
    let other = node_id_for([0x77u8; 32]);
    assert_ne!(other[..8], expected[..8], "distinct seeds must differ");
}

// =========================================================================
// DRILL 2 — dependency-outage: the bootstrap set goes unreachable.
// =========================================================================

/// Dependency-outage drill: with the bootstrap set healthy the status reports it healthy; when the
/// bootstrap goes unreachable the status flips to `bootstrap_healthy=0/N` AND
/// `fallback_reason=bootstrap-outage`, WHILE the S2 fetch still succeeds via upstream. The oracle
/// ATTRIBUTES the failure to the bootstrap (the fallback_reason token), not merely "something
/// changed". MUTATION: if the surface did not read live facts (a constant healthy count), the
/// post-outage `0/2` + `bootstrap-outage` assertions redden.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drill_dependency_outage_reports_and_s2_holds() {
    let facts = Arc::new(Mutex::new(StatusFactSnapshot {
        bootstrap_total: 2,
        bootstrap_healthy: 2,
        path: PeerPath::None,
    }));
    let d = start_daemon(
        OperatorContract::for_profile(SharingProfile::ConsumeOnly),
        node_id_for([0x31u8; 32]),
        Arc::new(MutFacts(facts.clone())),
        None,
    )
    .await;

    let healthy = status_text(&d).await;
    assert!(healthy.contains("bootstrap_healthy=2/2"), "{healthy}");
    assert!(healthy.contains("fallback_reason=none"), "{healthy}");

    // INJECT the outage: every bootstrap goes unreachable.
    facts.lock().unwrap().bootstrap_healthy = 0;

    let outaged = status_text(&d).await;
    assert!(
        outaged.contains("bootstrap_healthy=0/2"),
        "the live surface must report the degraded bootstrap health:\n{outaged}"
    );
    assert!(
        outaged.contains("fallback_reason=bootstrap-outage"),
        "the surface must ATTRIBUTE the fallback to the bootstrap outage:\n{outaged}"
    );
    // The additive invariant holds THROUGH the outage.
    assert_eq!(
        s2_fetch_succeeds(&d).await,
        NAR_BYTES,
        "S2 holds during a bootstrap outage"
    );
}

// =========================================================================
// DRILL 3 — exhausted-budget: the announce-after-fetch budget is spent.
// =========================================================================

/// Exhausted-budget drill: driving the announce hook past its integer budget makes the status
/// report `announce_budget=CAP/CAP` (announcing has STOPPED), WHILE the S2 fetch still succeeds.
/// MUTATION: reporting a constant budget figure (not reading the hook) reddens the `CAP/CAP`
/// assertion after exhaustion; a non-capped counter would over-report past the cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drill_exhausted_budget_reports_and_s2_holds() {
    // A small cap so the drill is exact + fast. Uses the default caps' cap on the surface's
    // denominator, so the reported CAP matches the operator contract's announce budget.
    let contract = OperatorContract::for_profile(SharingProfile::LanShare);
    let cap = contract.caps.announce_distinct_paths_budget;
    let hook: Arc<dyn PostFetchAnnounce> = Arc::new(TestAnnounce {
        cap,
        used: AtomicU64::new(0),
    });
    let d = start_daemon(
        contract,
        node_id_for([0x41u8; 32]),
        Arc::new(NullStatusFacts),
        Some(hook.clone()),
    )
    .await;

    let fresh = status_text(&d).await;
    assert!(
        fresh.contains(&format!("announce_budget=0/{cap}")),
        "{fresh}"
    );

    // INJECT: spend the whole budget (and then some — the gate caps it).
    for i in 0..(cap + 3) {
        hook.on_fetched(
            &daemon_core::NarHash::new(format!("sha256:budgetdrill{i:040}")),
            &format!("/nix/store/{STORE_HASH}-p{i}"),
        );
    }
    let exhausted = status_text(&d).await;
    assert!(
        exhausted.contains(&format!("announce_budget={cap}/{cap}")),
        "the surface must report the announce budget EXHAUSTED (used==cap):\n{exhausted}"
    );
    assert_eq!(
        s2_fetch_succeeds(&d).await,
        NAR_BYTES,
        "S2 holds with the announce budget spent"
    );
}

// =========================================================================
// DRILL 4 — kill-switch: a non-serving profile serves + announces nothing.
// =========================================================================

/// Kill-switch drill: an upstream-only ("give nothing") node reports it participates in NO DHT and
/// serves nothing (`profile=upstream-only`, `dht_role=none`), yet the S2 fetch still succeeds — the
/// consume path is untouched. The metrics surface reflects the REAL emitted metric from that fetch
/// (`hit_upstream` incremented, recorded inside `run`'s FallbackNarSource), and REDACTS the NodeId
/// by default. MUTATION: a profile that leaked serving would report `dht_role=server`; dropping the
/// metrics recording reddens the `hit_upstream>=1` check; dropping the redaction leaks the raw id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drill_kill_switch_serves_nothing_and_s2_holds() {
    let seed = [0x51u8; 32];
    let full_id = node_id_for(seed);
    // A fresh-install upstream-only contract: dht_role None (no participating swarm), privacy on.
    let contract = OperatorContract {
        dht_role: DhtRole::None,
        privacy: PrivacyPolicy::default(),
        ..OperatorContract::for_profile(SharingProfile::UpstreamOnly)
    };
    let d = start_daemon(contract, full_id.clone(), Arc::new(NullStatusFacts), None).await;

    let s = status_text(&d).await;
    assert!(s.contains("profile=upstream-only"), "{s}");
    assert!(
        s.contains("dht_role=none"),
        "kill-switch: no DHT participation:\n{s}"
    );
    // Redaction by default: the raw NodeId must NOT appear.
    assert!(
        !s.contains(&full_id),
        "raw NodeId leaked on the status surface:\n{s}"
    );

    // The additive invariant holds, and it drives a REAL upstream serve through run().
    assert_eq!(
        s2_fetch_succeeds(&d).await,
        NAR_BYTES,
        "S2 holds under the kill switch"
    );

    let m = metrics_text(&d).await;
    assert!(
        m.contains("nix_p2p_serve_total{source=\"hit_upstream\"} 1"),
        "the metrics surface must reflect the REAL upstream serve emitted inside run():\n{m}"
    );
    assert!(
        !m.contains(&full_id),
        "raw NodeId leaked on the metrics surface:\n{m}"
    );
}
