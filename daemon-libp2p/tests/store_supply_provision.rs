//! TASK-191 daemon-side wiring: the STORE-supply provider builds a `CatalogNarSupplier` over a
//! `Libp2pCatalogProbe` backed by the availability index (AC#1), and its announce is
//! VERIFICATION-GATED by the index's TASK-56 `sha256(--dump) == NarHash` check (AC#2).
//!
//! These are NO-NIX, no-network unit-level bites of the two properties the shipped binary depends
//! on. They use a `RegularFileNarDumper` over a temp raw-NAR file (a Process/file source, the
//! store-dump analogue) so `verify_store_provisions` runs a real dump + verify without needing a
//! `/nix/store`; the byte-identical two-swarm SERVE with a Process source is proven separately in
//! `fabric-libp2p/tests/nar_transport.rs`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use daemon_core::content_id::Blake3Digest;
use daemon_core::{
    AvailabilityIndex, NarDumper, NarHashKey, NodeId, NullAnnounce, NullStore,
    RegularFileNarDumper, StorePath,
};
use daemon_libp2p::{
    InitialAnnounceConfig, LanShare, Libp2pCatalogProbe, Libp2pSourceConfig,
    announce_store_provisions, build_libp2p_provider_source, verify_store_provisions,
};
use fabric_libp2p::{
    CatalogNarSupplier, Libp2pFabric, Libp2pNarSupplier, MemoryNarSupplier, Multiaddr, NodeConfig,
};
use peer_fabric::{AnnounceBudget, DiscoveryBudget, PeerFabric, SafetyEnvelope, ServeBudget};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// A unique-per-run temp path (no external tempdir dep; mirrors the fabric-libp2p tests).
fn unique_temp(stem: &str) -> PathBuf {
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    std::env::temp_dir().join(format!("nix-p2p-task191-{stem}-{suffix}"))
}

/// AC#2 (verification-gated announce): a store path registered under its TRUE NarHash is VERIFIED,
/// yielding a provision whose announced `content` is the index's verified BLAKE3 and whose
/// declared size is the real NAR length - and the reverse-map is now published so the supplier can
/// serve it. BITE: register it under a WRONG NarHash and `verify_store_provisions` REFUSES the
/// whole batch (the index quarantines the mismatch), so no unverified store path is ever announced.
#[test]
fn verify_store_provisions_accepts_verified_and_refuses_quarantined() {
    let body = b"a raw NAR regenerated on demand from a real store path".to_vec();
    let true_key = NarHashKey::from_raw_nar(&body);
    let expected_content = Blake3Digest::from_raw_nar(&body);

    // --- VERIFIED: registered under its true NarHash ---
    let nar_path = unique_temp("verified.nar");
    std::fs::write(&nar_path, &body).unwrap();
    let index = AvailabilityIndex::open(
        NodeId::from_bytes([0u8; 32]),
        Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("index opens");
    index
        .register(true_key, StorePath::new(&nar_path))
        .expect("register");

    let provisions = verify_store_provisions(&index, &[true_key])
        .expect("a store path under its true NarHash verifies");
    assert_eq!(provisions.len(), 1);
    assert_eq!(
        *provisions[0].nar_hash(),
        true_key,
        "the provision announces the registered NarHash"
    );
    assert_eq!(
        provisions[0].content(),
        expected_content,
        "the announced content is the index's VERIFIED digest, not the operator's word"
    );
    assert_eq!(
        provisions[0].declared_size(),
        body.len() as u64,
        "the declared size is the real uncompressed NAR length"
    );

    // --- QUARANTINE BITE: registered under a WRONG NarHash ---
    let wrong_key = NarHashKey::from_raw_nar(b"totally different bytes -> a different NarHash");
    assert_ne!(wrong_key, true_key);
    let mismatch_path = unique_temp("mismatch.nar");
    std::fs::write(&mismatch_path, &body).unwrap();
    let mismatch_index = AvailabilityIndex::open(
        NodeId::from_bytes([0u8; 32]),
        Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("index opens");
    mismatch_index
        .register(wrong_key, StorePath::new(&mismatch_path))
        .expect("register (the mis-binding is caught at verify, not register)");
    let refused = verify_store_provisions(&mismatch_index, &[wrong_key]);
    assert!(
        refused.is_err(),
        "a store path whose dump does not hash to its registered NarHash must be REFUSED \
         (quarantined), never announced: {refused:?}"
    );

    let _ = std::fs::remove_file(&nar_path);
    let _ = std::fs::remove_file(&mismatch_path);
}

/// AC#1 (store path served BY the supplier, nothing at rest): once a store path is registered +
/// verified, a `CatalogNarSupplier` over the `Libp2pCatalogProbe` bridge can PLAN its supply from
/// the index's reverse-map (verified digest -> store path). BITE: a digest that was never
/// registered/verified is NOT planned (the supplier has nothing to serve), and reverting to a
/// seed/MemoryNarSupplier would not reach the store path at all.
#[test]
fn catalog_supplier_serves_a_verified_store_path_and_only_that() {
    let body = b"raw NAR served on demand through the CatalogNarSupplier bridge".to_vec();
    let key = NarHashKey::from_raw_nar(&body);
    let content = Blake3Digest::from_raw_nar(&body);

    let nar_path = unique_temp("supplied.nar");
    std::fs::write(&nar_path, &body).unwrap();
    let index = AvailabilityIndex::open(
        NodeId::from_bytes([0u8; 32]),
        Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("index opens");
    index
        .register(key, StorePath::new(&nar_path))
        .expect("register");

    // The supplier the shipped provider builds: an inert probe over the index's supply catalog.
    let supplier = CatalogNarSupplier::new(
        Libp2pCatalogProbe::new(index.supply_catalog()),
        "unused-helper",
    );

    // BEFORE verification the reverse-map is empty, so the supplier cannot plan the content.
    assert!(
        supplier.plan(&content).is_none(),
        "an unverified store path is NOT servable (the reverse-map is empty until first verify)"
    );

    // Verification publishes the reverse-map (the store analogue of seeding), gating the announce.
    let provisions = verify_store_provisions(&index, &[key]).expect("verifies");
    assert_eq!(provisions[0].content(), content);

    // NOW the supplier plans the store path's supply from the index - served on demand, no .nar
    // held at rest by the provider.
    let plan = supplier
        .plan(&content)
        .expect("the verified store path is now servable via the supplier");
    assert_eq!(
        plan.declared_size(),
        body.len() as u64,
        "the plan's admission size is the index's declared NarSize"
    );

    // A digest never registered here is still not servable (the bite: no register+verify -> None).
    let unknown = Blake3Digest::from_raw_nar(b"a NAR this node was never asked to provide");
    assert!(
        supplier.plan(&unknown).is_none(),
        "the supplier serves ONLY what the index verified, never an arbitrary digest"
    );

    let _ = std::fs::remove_file(&nar_path);
}

/// Bring a raw fabric up on an ephemeral loopback port; return it + its dial address (mirrors the
/// seed-path shipped-announce test's helper).
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

/// SHIPPED-ANNOUNCE regression oracle (codex TASK-191 finding): drive the STORE announce SSOT
/// `announce_store_provisions` over a real DHT-joined provider and assert (a) a VERIFIED provision
/// announces exactly one record whose `content` is the index's TASK-56-verified digest - never the
/// operator's word - and (b) the verify->announce COMPOSITION mints NO record for a
/// mis-registered/quarantined key (the shape a refused `verify_store_provisions` yields). This
/// catches a future direct-sign regression in the announce path that the by-construction type gate
/// alone would not surface as a behaviour.
///
/// MUTATION bites: (a) make `announce_store_records` sign from a source other than the verified
/// `provision.content` -> the content assertion goes RED; (b) make `verify_store_provisions` return
/// `Ok` on a mismatch -> the `is_err()` assertion goes RED and the empty-announce becomes a false
/// record.
#[tokio::test(flavor = "multi_thread")]
async fn shipped_store_announce_carries_verified_content_and_refuses_quarantined() {
    let scope = "task194-store-announce-verify";

    // ---- boot node: the provider's DHT entry point (holds no content) ----
    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig::new([11u8; 32]).with_network_scope(scope))
            .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    // ---- provider fabric joined through the shipped builder (the supplier is irrelevant to the
    // announce; it only gives us an announcer-capable DHT-joined fabric, as the seed test does) ----
    let body = b"nix-archive-1 raw NAR regenerated on demand from a real store path".to_vec();
    let true_key = NarHashKey::from_raw_nar(&body);
    let expected_content = Blake3Digest::from_raw_nar(&body);

    let cfg = Libp2pSourceConfig {
        identity_seed: [12u8; 32],
        network_scope: scope.to_string(),
        listen: Some("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        additional_listens: Vec::new(),
        external_addresses: Vec::new(),
        bootstrap: vec![(boot_peer, boot_addr)],
        provider_addrs: vec![],
        discovery_budget: DiscoveryBudget::new(Duration::from_secs(10), 32),
        envelope: SafetyEnvelope::default(),
        state_dir: None,
        relay_server_enabled: true,
        kad_server: true,
    };
    let (fabric, _source, _raw, readiness) = build_libp2p_provider_source(
        cfg,
        Arc::new(MemoryNarSupplier::new([body.clone()])),
        Arc::new(peer_fabric::AdmitAllPublication),
    )
    .await
    .expect("production provider builder starts a serving fabric joined to the DHT");
    let _serve = fabric
        .server()
        .expect("provider fabric exposes a serve axis")
        .serve(ServeBudget::default())
        .await
        .expect("serve gate installs");
    let budget = AnnounceBudget::new(Duration::from_secs(10), 20);

    // --- HONEST: a store path registered under its TRUE NarHash verifies, and the shipped announce
    // path publishes ONE record whose content is the VERIFIED digest. ---
    let nar_path = unique_temp("announce-verified.nar");
    std::fs::write(&nar_path, &body).unwrap();
    let index = AvailabilityIndex::open(
        NodeId::from_bytes([0u8; 32]),
        Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("index opens");
    index
        .register(true_key, StorePath::new(&nar_path))
        .expect("register");
    let provisions = verify_store_provisions(&index, &[true_key]).expect("verifies");
    let records = announce_store_provisions(
        &fabric,
        &readiness,
        InitialAnnounceConfig::new([12u8; 32], 3600, unix_now(), &budget),
        &provisions,
        LanShare::operator_assembled(),
    )
    .await
    .expect("a verified provision announces on the shipped store path");
    assert_eq!(records.len(), 1, "one verified provision -> one record");
    assert_eq!(
        records[0].content, expected_content,
        "the announced record carries the index's VERIFIED digest, not the operator's word"
    );

    // --- QUARANTINE: a path registered under a WRONG key is refused by verify, so the shipped
    // verify->announce composition mints NO record (no false claim on the DHT). ---
    let wrong_key = NarHashKey::from_raw_nar(b"totally different bytes -> a different NarHash");
    assert_ne!(wrong_key, true_key);
    let mismatch_path = unique_temp("announce-mismatch.nar");
    std::fs::write(&mismatch_path, &body).unwrap();
    let mismatch_index = AvailabilityIndex::open(
        NodeId::from_bytes([0u8; 32]),
        Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("index opens");
    mismatch_index
        .register(wrong_key, StorePath::new(&mismatch_path))
        .expect("register (the mis-binding is caught at verify, not register)");
    let refused = verify_store_provisions(&mismatch_index, &[wrong_key]);
    assert!(
        refused.is_err(),
        "a mis-registered store path must be quarantined by verify, never announced: {refused:?}"
    );
    let none = refused.unwrap_or_default();
    let records = announce_store_provisions(
        &fabric,
        &readiness,
        InitialAnnounceConfig::new([12u8; 32], 3600, unix_now(), &budget),
        &none,
        LanShare::operator_assembled(),
    )
    .await
    .expect("announcing an empty (verify-refused) provision set is Ok");
    assert!(
        records.is_empty(),
        "a quarantined key mints NO ProviderRecord on the shipped store announce path"
    );

    // Fabrics clean up on drop; holding `bootstrap` kept the DHT entry point alive above.
    drop(fabric);
    drop(bootstrap);
    let _ = std::fs::remove_file(&nar_path);
    let _ = std::fs::remove_file(&mismatch_path);
}
