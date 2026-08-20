//! TASK-285 AC#3 — the periodic seed RE-SIGN allocates monotonic sequences through the SAME
//! anti-rollback path as the initial announce (no reuse/rollback) and, in `--libp2p-state-dir`
//! durable mode, PERSISTS the advanced floor BEFORE republishing (save-before-publish, fail-closed).
//!
//! Deterministic (no timers): it drives the re-sign cycle DIRECTLY via
//! [`daemon_libp2p::resign_seed_records_once`] — the exact body the background loop calls on its
//! timer — against a REAL durable provider joined to a bootstrap, and after each cycle asserts BOTH:
//!   * the freshly-signed record carries a STRICTLY-HIGHER sequence (1 → 2 → 3) — no reuse/rollback;
//!   * the on-disk `announce-seq-v1.txt` floor advanced to EXACTLY that sequence — the sequence was
//!     durably recorded (and, because `announce` persists BEFORE the DHT publish, it is recorded
//!     before the record is ever discoverable).
//!
//! What BITES BY MUTATION:
//!   * SEQUENCE REUSE/ROLLBACK: make the re-sign mint a fixed/stale sequence (e.g. sign at a
//!     hardcoded `1`, or skip `next_announce_sequence`) — the record's sequence stops strictly
//!     increasing and the on-disk floor stops advancing → both asserts below go RED.
//!   * PUBLISH-BEFORE-SAVE: reorder `Libp2pAvailabilityAnnouncer::announce` to publish before it
//!     persists the floor — the on-disk floor lags the just-published sequence → the floor assert
//!     goes RED (the re-sign would expose a record whose sequence is not durably recorded, the F3
//!     rollback hazard).
//!
//! NO FLOAT anywhere: sequences and expiries are integers throughout.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use daemon_core::NarHashKey;
use daemon_libp2p::{
    InitialAnnounceConfig, LanShare, Libp2pSourceConfig, ProviderRelayReadiness,
    SeedResignAuthority, announce_provider_seeds, build_libp2p_provider_source,
    provider_content_key, resign_seed_records_once, resolve_durable_identity_seed,
};
use fabric_libp2p::{
    ANNOUNCE_SEQ_FILENAME, Libp2pFabric, MemoryNarSupplier, Multiaddr, NodeConfig, PeerId,
};
use peer_fabric::{
    AnnounceBudget, ContentKey, DiscoveryBudget, PeerFabric, ProviderRecord, SafetyEnvelope,
    ServeBudget, ServeHandle,
};

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

/// The SHIPPED durable provider config under `state_dir`, joined to `boot`. Identity resolved FROM
/// the state dir (the shipped default), so the durable floor binds to a stable identity namespace.
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

/// Read the persisted per-key floor sequence for `content_key` from `announce-seq-v1.txt`
/// (`<key-hex> <seq> <expiry>` lines), or `None` if the key is not recorded.
fn on_disk_floor_sequence(state_dir: &std::path::Path, content_key: &ContentKey) -> Option<u64> {
    let text = std::fs::read_to_string(state_dir.join(ANNOUNCE_SEQ_FILENAME)).ok()?;
    let key_hex: String = content_key
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for line in text.lines() {
        let mut parts = line.split(' ');
        if parts.next() == Some(key_hex.as_str()) {
            return parts.next().and_then(|s| s.parse::<u64>().ok());
        }
    }
    None
}

/// Stand up a serving durable provider and announce `nar` ONCE through the SHIPPED SSOT loop
/// ([`announce_provider_seeds`]). Returns the running fabric, its readiness token, the serve guard,
/// and the first announced record.
async fn start_provider_and_announce(
    cfg: Libp2pSourceConfig,
    nar: &[u8],
    nar_hash: &NarHashKey,
) -> (
    Arc<Libp2pFabric>,
    ProviderRelayReadiness,
    ServeHandle,
    ProviderRecord,
) {
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
        InitialAnnounceConfig::new(seed, 3600, unix_now(), &budget),
        &[(*nar_hash, nar.to_vec())],
        LanShare::operator_assembled(),
    )
    .await
    .expect("shipped announce loop admitted (provider is DHT-joined)");
    let record = records.into_iter().next().expect("one announced record");
    (fabric, readiness, serve, record)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resign_allocates_monotonic_sequences_and_persists_floor_before_publish() {
    let scope = "task285-resign-durable-seq";
    let state_dir = std::env::temp_dir().join(format!(
        "nix-p2p-task285-seq-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&state_dir);

    let nar = b"nix-archive-1 raw NAR re-signed at a monotonic durable sequence".to_vec();
    let nar_hash = NarHashKey::from_raw_nar(&nar);
    let content_key = provider_content_key(&nar_hash);

    // ---- B (bootstrap) ----
    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig::new([1u8; 32]).with_network_scope(scope))
            .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    // ---- P: durable provider announces the seed ONCE at sequence 1 ----
    let (fabric, readiness, _serve, record1) = start_provider_and_announce(
        durable_provider_cfg(scope, (boot_peer, boot_addr.clone()), &state_dir),
        &nar,
        &nar_hash,
    )
    .await;
    let seed = fabric.node_id();
    assert_eq!(record1.provider, seed, "self-serve: record provider is us");
    assert_eq!(
        record1.sequence, 1,
        "a first-ever announce on a fresh state dir allocates sequence 1"
    );
    assert_eq!(
        on_disk_floor_sequence(&state_dir, &content_key),
        Some(1),
        "the initial announce persisted the floor at sequence 1"
    );

    let identity_seed = resolve_durable_identity_seed(Some(&state_dir), None).unwrap();
    let budget = AnnounceBudget::new(Duration::from_secs(10), 20);
    let seeds = vec![(nar_hash, nar.clone())];

    // ---- RE-SIGN cycle #1: must mint sequence 2 and persist the floor to 2 ----
    let records2 = resign_seed_records_once(
        &fabric,
        &readiness,
        identity_seed,
        &seeds,
        3600,
        &budget,
        &SeedResignAuthority::Lan,
    )
    .await
    .expect("re-sign cycle #1 announces through the durable path");
    let record2 = records2.into_iter().next().expect("one re-signed record");
    assert!(
        record2.sequence > record1.sequence,
        "re-sign must mint a STRICTLY-HIGHER sequence (no reuse/rollback): got {} <= {}",
        record2.sequence,
        record1.sequence
    );
    assert_eq!(
        record2.sequence, 2,
        "the durable allocator mints last+1 on the first re-sign"
    );
    assert_eq!(
        record2.provider, seed,
        "the re-signed record is still self-served under the SAME identity (supersede, not a new node)"
    );
    assert!(
        record2.expiry > record2.issued_at,
        "the re-signed record carries a fresh forward validity window"
    );
    assert_eq!(
        on_disk_floor_sequence(&state_dir, &content_key),
        Some(2),
        "re-sign #1 PERSISTED the advanced floor to 2 (save-before-publish): the on-disk floor must \
         track the just-published sequence, else a crash could re-mint an already-published sequence"
    );

    // ---- RE-SIGN cycle #2: must mint sequence 3 and persist the floor to 3 ----
    let records3 = resign_seed_records_once(
        &fabric,
        &readiness,
        identity_seed,
        &seeds,
        3600,
        &budget,
        &SeedResignAuthority::Lan,
    )
    .await
    .expect("re-sign cycle #2 announces through the durable path");
    let record3 = records3.into_iter().next().expect("one re-signed record");
    assert_eq!(
        record3.sequence, 3,
        "each re-sign strictly advances the monotonic sequence (never reused/rolled back)"
    );
    assert_eq!(
        on_disk_floor_sequence(&state_dir, &content_key),
        Some(3),
        "re-sign #2 PERSISTED the advanced floor to 3 before publishing"
    );

    let _ = std::fs::remove_dir_all(&state_dir);
}
