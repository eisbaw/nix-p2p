//! TASK-185 AC#4 - RESTART-DURABILITY through the SHIPPED path, biting by mutation.
//!
//! The defect (F3): the durable floor + per-key announce sequence were built + unit-tested but
//! NOT wired into the shipped daemon, and positive records were minted at a hardcoded
//! `sequence: 1`. GB1 (found at the DEEP gate): the identity seed was ALSO ephemeral - a
//! restart with only `--libp2p-state-dir` came back a NEW random NodeId, so the durable
//! sequence floor was bound to an orphaned namespace and could not supersede or withdraw the
//! pre-restart records. This test exercises the PRODUCTION provider path the binary's
//! `--libp2p-provider` install runs - the identity resolved FROM the state dir
//! (`resolve_durable_identity_seed`), `build_libp2p_provider_source` with that `state_dir`, and
//! the SSOT announce loop `announce_provider_seeds` (NOT a hand-rolled reimplementation) -
//! across a restart, then serves the post-restart record through the exact `daemon_core::run`
//! glue the binary calls.
//!
//! Topology (all in-process, real loopback-TCP libp2p swarms):
//! - `B` - bootstrap (the only injected address for P and C).
//! - `P1` - a serving provider whose identity is RESOLVED FROM the `state_dir` (the shipped
//!   default: no explicit seed), built by the PRODUCTION `build_libp2p_provider_source`;
//!   announces its NAR through the shipped `announce_provider_seeds` loop at a durably-allocated
//!   sequence, then is DROPPED (== a process restart; the state dir persists).
//! - `P2` - the RESTART: a fresh fabric configured with ONLY the SAME `state_dir` (identity
//!   re-resolved from disk, not a seed passed twice), same production builder + announce loop;
//!   it comes back as the SAME provider and its allocator re-seeds from disk, so its record
//!   carries a STRICTLY-NEWER sequence. Stays up to serve.
//! - `C` - the CONSUMER built by the production `build_libp2p_nar_source`, handed to
//!   `daemon_core::run`, which serves P2's NAR byte-identical over the libp2p path.
//!
//! What BITES BY MUTATION:
//!   * GB1 (identity): stub the identity persistence in `resolve_durable_identity_seed` so P2
//!     resolves a fresh random seed -> a different NodeId -> `record2.provider != first_provider`
//!     -> the same-provider assertion fails. (Verified by the reviewer's requested stub.)
//!   * F3 wiring: revert the daemon routing to the NON-durable `start*` -> P2's re-seeded floor
//!     is EMPTY, `next_announce_sequence` returns 1, the announce-seq file is never written ->
//!     both the strict-monotonicity and the floor-survival assertions fail.
//!   * F3 sequence: hardcode `sequence: 1` in the shipped `announce_provider_seeds` /
//!     `sign_libp2p_provider_record` -> P2's record carries 1 -> the monotonicity assertion fails.
//!
//! HONEST COVERAGE: this exercises the shipped PROVIDER construction + announce loop + the
//! `run()` consumer serve; it does NOT spawn the actual binary process (argv parse ->
//! `source_config`/`from_args` is unit-tested separately). The CONSUMER floor RELOAD across a
//! restart is covered by the `FloorStore::durable` unit test, not here.

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
    IDENTITY_SEED_FILENAME, Libp2pSourceConfig, announce_provider_seeds, build_libp2p_nar_source,
    build_libp2p_provider_source, provider_content_key, resolve_durable_identity_seed,
};
use fabric_libp2p::{
    ANNOUNCE_SEQ_FILENAME, Libp2pFabric, MemoryNarSupplier, Multiaddr, NodeConfig, PeerId,
};
use http::HeaderMap;
use http_body_util::{BodyExt, Full};
use peer_fabric::{
    AnnounceBudget, Axis, DiscoveryBudget, PeerFabric, ProviderRecord, SafetyEnvelope, ServeBudget,
    TransportTag,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// Bring a raw fabric up on an ephemeral loopback port; return it + its dial address.
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

/// Build the SHIPPED durable provider config under `state_dir`, joined to `boot`. The identity
/// seed is resolved THE WAY THE BINARY DOES - from the state dir, no explicit seed
/// ([`resolve_durable_identity_seed`], TASK-185 GB1) - so two boots on the SAME state_dir come
/// back as the SAME node. This is the property the GB1 bite depends on: without durable
/// identity, the restart would come back a different provider. Panics if the identity cannot be
/// resolved (an unwritable state dir would be a test-setup bug).
fn durable_provider_cfg(
    scope: &str,
    boot: (PeerId, Multiaddr),
    state_dir: &std::path::Path,
) -> Libp2pSourceConfig {
    let identity_seed = resolve_durable_identity_seed(Some(state_dir), None)
        .expect("resolve the durable identity seed from the state dir (the shipped path)");
    Libp2pSourceConfig {
        identity_seed,
        network_scope: scope.to_string(),
        listen: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        bootstrap: vec![boot],
        provider_addrs: vec![],
        discovery_budget: DiscoveryBudget::new(Duration::from_secs(10), 32),
        envelope: SafetyEnvelope::default(),
        state_dir: Some(state_dir.to_path_buf()),
    }
}

/// Stand up a serving provider through the PRODUCTION builder, install its serve gate, and
/// announce `nar` through the SHIPPED SSOT announce loop ([`announce_provider_seeds`], the same
/// function the binary's `--libp2p-provider` install calls - NOT a hand-rolled allocate/sign/
/// announce, so a `sequence = 1` mutation in that shipped loop is caught here). Returns the
/// running fabric, the serve guard (kept alive by the caller), and the announced record.
async fn start_provider_and_announce(
    cfg: Libp2pSourceConfig,
    nar: &[u8],
    nar_hash: &NarHashKey,
) -> (Arc<Libp2pFabric>, peer_fabric::ServeHandle, ProviderRecord) {
    let seed = cfg.identity_seed;
    let supplier = Arc::new(MemoryNarSupplier::new([nar.to_vec()]));
    let (fabric, _source, _raw) = build_libp2p_provider_source(cfg, supplier)
        .await
        .expect("production provider builder starts a serving fabric joined to the DHT");
    let serve = fabric
        .server()
        .expect("provider fabric exposes a serve axis")
        .serve(ServeBudget::default())
        .await
        .expect("serve gate installs");

    let records = announce_provider_seeds(
        &fabric,
        seed,
        &[(*nar_hash, nar.to_vec())],
        3600,
        unix_now(),
        &AnnounceBudget::new(Duration::from_secs(10), 20),
    )
    .await
    .expect("shipped announce loop admitted (provider is DHT-joined)");
    let record = records.into_iter().next().expect("one announced record");
    (fabric, serve, record)
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

/// The HTTP-upstream fallback `run` layers behind the p2p source. Counts hits so the test
/// can assert the p2p HIT (the restarted provider's durably-sequenced record) never touched
/// it.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_durable_sequence_serves_through_run() {
    let scope = "task185-restart-durable";

    // A unique per-run state dir (process + thread keyed), removed up front.
    let state_dir = std::env::temp_dir().join(format!(
        "nix-p2p-task185-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&state_dir);

    let nar = b"nix-archive-1 raw NAR served post-restart at a durable sequence".to_vec();
    // TASK-56: the shipped announce path now verifies sha256(bytes)==declared NarHash,
    // so the seed must declare the NAR's TRUE NarHash (not an arbitrary key).
    let nar_hash = NarHashKey::from_raw_nar(&nar);
    let content_key = provider_content_key(&nar_hash);

    // ---- B (bootstrap) ----
    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig {
            identity_seed: [1u8; 32],
            network_scope: scope.to_string(),
        })
        .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    // ---- P1: provider whose identity is resolved FROM the state dir (the shipped way),
    // announces at the durable sequence. ----
    let first_sequence;
    let first_provider;
    {
        let (p1, _serve1, record1) = start_provider_and_announce(
            durable_provider_cfg(scope, (boot_peer, boot_addr.clone()), &state_dir),
            &nar,
            &nar_hash,
        )
        .await;
        first_sequence = record1.sequence;
        first_provider = record1.provider;
        assert_eq!(
            first_provider,
            p1.node_id(),
            "self-serve: the record's provider is the fabric's own identity"
        );
        assert_eq!(
            first_sequence, 1,
            "a first-ever announce on a fresh state dir allocates sequence 1"
        );
        assert_eq!(record1.key, content_key, "one NarHash -> one ContentKey");
        // Drop p1 (and its serve guard) == a process restart. The state dir persists.
        drop(p1);
    }

    // The floor SURVIVED to disk (proof of durable persistence, not just an in-memory map).
    // The persisted line keys on the lowercase hex of the ContentKey bytes (persist.rs), so
    // match that exactly rather than the Display form.
    let seq_file = state_dir.join("announce-seq-v1.txt");
    let seq_text = std::fs::read_to_string(&seq_file)
        .expect("the durable announce-sequence file must exist after the first announce");
    let key_hex: String = content_key
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        seq_text.contains(&key_hex),
        "the persisted announce-sequence file must record the announced key {key_hex}; \
         file was:\n{seq_text}"
    );

    // ---- P2: RESTART on the SAME state_dir ONLY (identity re-resolved from disk, no seed
    // passed twice), announces STRICTLY NEWER as the SAME provider. ----
    let (p2, _serve2, record2) = start_provider_and_announce(
        durable_provider_cfg(scope, (boot_peer, boot_addr.clone()), &state_dir),
        &nar,
        &nar_hash,
    )
    .await;
    // GB1 BITE: the restart must come back as the SAME provider identity. Without durable
    // identity (GB1), P2 would resolve a FRESH random seed -> a different NodeId -> a different
    // `provider` -> it could neither supersede nor withdraw P1's records. If identity
    // persistence is stubbed out, this assertion fails.
    assert_eq!(
        record2.provider, first_provider,
        "the restarted provider (state-dir only, no seed) must be the SAME identity as before \
         the restart - else its durable sequence is bound to an orphaned namespace"
    );
    assert_eq!(
        p2.node_id(),
        first_provider,
        "the restarted fabric's own node_id must also match the pre-restart identity"
    );
    // AC2/GB2 BITE: strictly-newer sequence across the restart. A revert to non-durable
    // start*, or a hardcoded sequence:1 in the shipped announce loop, makes this fail.
    assert!(
        record2.sequence > first_sequence,
        "the restarted provider must mint a STRICTLY NEWER sequence (got {} <= {})",
        record2.sequence,
        first_sequence
    );
    assert_eq!(
        record2.sequence, 2,
        "the durable allocator mints last+1 after exactly one prior announce"
    );

    // ---- C: consumer via the production builder, served through daemon_core::run ----
    let discovery_budget = DiscoveryBudget::new(Duration::from_secs(10), 32);
    let consumer_cfg = Libp2pSourceConfig {
        identity_seed: [4u8; 32],
        network_scope: scope.to_string(),
        listen: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        bootstrap: vec![(boot_peer, boot_addr.clone())],
        provider_addrs: vec![],
        discovery_budget,
        envelope: SafetyEnvelope::default(),
        state_dir: None,
    };
    let (consumer, _c_source, _c_raw) = build_libp2p_nar_source(consumer_cfg)
        .await
        .expect("production consumer builder constructs a running libp2p fabric");

    // Wait until C can DISCOVER the restarted provider P2 purely through kad.
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let found = matches!(
            consumer
                .provider_directory()
                .expect("consumer has a directory")
                .find_providers(&content_key, &discovery_budget)
                .await,
            peer_fabric::Lookup::Found(records)
                if records.iter().any(|r| r.provider == p2.node_id() && r.sequence == record2.sequence)
        );
        if found {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "consumer never discovered the restarted provider's durably-sequenced record"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // Serve the discovered NAR through the exact `run` glue the binary calls.
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
        upstream_label: "task185-run-upstream".to_string(),
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

    // The provider announced this NAR, so run's dynamic raw-serve rewrites the narinfo to raw;
    // follow the advertised URL, which the daemon serves from the p2p HIT byte-identically.
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
        "run() served the NAR discovered over the libp2p path from the RESTARTED provider"
    );
    assert_eq!(
        served.body, nar,
        "run() served BYTE-IDENTICAL bytes to the NAR the restarted provider holds"
    );
    assert_eq!(
        fallback_hits.load(Ordering::SeqCst),
        0,
        "the durably-sequenced record served over p2p; the HTTP fallback was not consulted"
    );

    run_task.abort();
    let _ = std::fs::remove_dir_all(&state_dir);
}

/// TASK-185 re-gate: PARTIAL state-dir corruption (identity file lost, floor/sequence survives)
/// must FAIL-CLOSED at the shipped identity resolution, not silently rekey the node. Driven
/// through the REAL durable path: a durable provider boot writes both `identity-seed-v1` and
/// `announce-seq-v1.txt`, then we delete ONLY the identity file and re-resolve the way the
/// binary's `source_config`/`from_args` does.
///
/// BITE: with the consistency check, this errors ("INCONSISTENT"); remove the check in
/// `resolve_durable_identity_seed` and it returns a FRESH seed (a different NodeId) -> the
/// `expect_err` goes red. (The symmetric case - identity kept, floor deleted - is NOT a
/// distinct fail-closed path: a fresh consumer / pre-first-announce provider legitimately has no
/// floor file, so it is left to TASK-189's atomic state-file, see the AC4 test's module doc.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partial_state_dir_with_lost_identity_fails_closed() {
    let scope = "task185-partial-corrupt";
    let state_dir = std::env::temp_dir().join(format!(
        "nix-p2p-task185-partial-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&state_dir);

    let nar = b"nix-archive-1 raw NAR for the partial-corruption oracle".to_vec();
    // TASK-56: declare the NAR's TRUE NarHash (the shipped announce path verifies it).
    let nar_hash = NarHashKey::from_raw_nar(&nar);

    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig {
            identity_seed: [1u8; 32],
            network_scope: scope.to_string(),
        })
        .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    // A real durable boot: identity + a genuine announce-seq (the sequence advanced on announce).
    {
        let (p1, _serve1, _record1) = start_provider_and_announce(
            durable_provider_cfg(scope, (boot_peer, boot_addr.clone()), &state_dir),
            &nar,
            &nar_hash,
        )
        .await;
        drop(p1);
    }
    assert!(
        state_dir.join(IDENTITY_SEED_FILENAME).exists(),
        "the durable boot must have persisted the identity"
    );
    assert!(
        state_dir.join(ANNOUNCE_SEQ_FILENAME).exists(),
        "the durable boot must have persisted the advanced announce sequence"
    );

    // PARTIAL CORRUPTION: lose ONLY the identity file; the sequence floor survives.
    std::fs::remove_file(state_dir.join(IDENTITY_SEED_FILENAME)).expect("delete identity file");

    // The shipped restart resolves identity from the state dir -> must FAIL CLOSED (not rekey).
    let err = resolve_durable_identity_seed(Some(&state_dir), None)
        .expect_err("a surviving floor with a lost identity must fail closed, not silently rekey");
    assert!(
        err.contains("INCONSISTENT"),
        "the corruption error must name the inconsistency, got: {err}"
    );

    let _ = std::fs::remove_dir_all(&state_dir);
}
