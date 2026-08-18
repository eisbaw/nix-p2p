//! TASK-56 (regate): the SHIPPED libp2p provider announce path must not mint a FALSE
//! CLAIM. `--libp2p-seed-nar <X>=/path/to/Y.nar` declares NarHash X for bytes Y; if
//! `sha256(Y) != X`, signing/announcing a ProviderRecord for X over Y would advertise
//! content this node cannot honestly serve - a consumer discovers it by X, fetches,
//! and rejects at its own NarHash gate: a wasted dial. The guard lives at the announce
//! SSOT (`announce_provider_seeds`, called by BOTH thin binaries and the composite
//! daemon), reusing `daemon_core::NarHashKey::from_raw_nar` - the exact helper the
//! availability index uses to close the same gap on the index-backed path.
//!
//! Two bites:
//!   * `verify_provider_seeds_*` - the pure guard, red-green: a mismatch is a typed
//!     `SeedNarHashMismatch(declared, actual)`; an honest seed passes. MUTATION to
//!     confirm the bite: make `verify_provider_seeds` return `Ok(())` unconditionally
//!     (delete the `if actual != *declared { .. }` refusal) -> the `is_err()`
//!     assertions here go RED.
//!   * `the_shipped_announce_path_refuses_a_mis_specified_seed` - PROVIDER level, over a
//!     real DHT-joined provider: the honest seed announces (Ok, a signed record), the
//!     mis-specified seed is REFUSED (Err naming declared vs actual) with NO record.
//!     MUTATION to confirm the bite: delete `verify_provider_seeds(seeds)?` from
//!     `announce_provider_seeds` -> the mis-specified seed is signed + announced as a
//!     false record and the call returns `Ok` -> the `is_err()` assertion goes RED.
//!     (The honest positive proves the DHT announce path genuinely works, so the
//!     mismatch's `Err` is attributable to the guard, not to a routing failure.)

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use daemon_core::NarHashKey;
use daemon_core::content_id::Blake3Digest;
use daemon_libp2p::{
    InitialAnnounceConfig, LanShare, Libp2pSourceConfig, SeedNarHashMismatch,
    announce_provider_seeds, build_libp2p_provider_source, verify_provider_seeds,
};
use fabric_libp2p::{Libp2pFabric, MemoryNarSupplier, Multiaddr, NodeConfig};
use peer_fabric::{AnnounceBudget, DiscoveryBudget, PeerFabric, SafetyEnvelope, ServeBudget};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

// ---------------------------------------------------------------- pure guard bite

#[test]
fn verify_provider_seeds_refuses_a_mismatch_and_admits_honest_seeds() {
    let bytes = b"nix-archive-1 raw NAR bytes for a provider seed".to_vec();
    let true_key = NarHashKey::from_raw_nar(&bytes);

    // Honest: declared == sha256(bytes) -> admitted.
    assert_eq!(
        verify_provider_seeds(&[(true_key, bytes.clone())]),
        Ok(()),
        "a seed whose declared NarHash equals sha256(bytes) must be admitted"
    );

    // Mis-specified: declared X != sha256(bytes) = Y -> typed refusal naming both.
    let lied = NarHashKey::from_sha256_bytes([0x42; 32]);
    assert_ne!(lied, true_key, "the test is only meaningful if X != Y");
    assert_eq!(
        verify_provider_seeds(&[(lied, bytes.clone())]),
        Err(SeedNarHashMismatch {
            declared: lied,
            actual: true_key,
        }),
        "a seed whose bytes hash to a DIFFERENT NarHash than declared must be refused"
    );

    // The WHOLE batch is refused on the first mismatch (fail-fast), so a good seed
    // ahead of a bad one does not slip an honest record out before the refusal.
    assert!(
        verify_provider_seeds(&[(true_key, bytes.clone()), (lied, bytes)]).is_err(),
        "a batch containing any mismatch is refused whole, before any announce"
    );
}

// -------------------------------------------------- shipped-path (provider) bite

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

#[tokio::test(flavor = "multi_thread")]
async fn the_shipped_announce_path_refuses_a_mis_specified_seed() {
    let scope = "task56-provider-seed-verify";

    // ---- boot node (the provider's DHT entry point) ----
    let (bootstrap, boot_addr) = start_fabric(
        Libp2pFabric::start(NodeConfig::new([1u8; 32]).with_network_scope(scope))
            .expect("bootstrap starts"),
    )
    .await;
    let boot_peer = bootstrap.peer_id();

    // ---- provider, joined to the DHT through the shipped builder ----
    let nar = b"nix-archive-1 the raw NAR this provider honestly holds".to_vec();
    let honest_key = NarHashKey::from_raw_nar(&nar);
    let expected_content = Blake3Digest::from_raw_nar(&nar);

    let cfg = Libp2pSourceConfig {
        identity_seed: [2u8; 32],
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
    let supplier = Arc::new(MemoryNarSupplier::new([nar.clone()]));
    let (fabric, _source, _raw, readiness) =
        build_libp2p_provider_source(cfg, supplier, Arc::new(peer_fabric::AdmitAllPublication))
            .await
            .expect("production provider builder starts a serving fabric joined to the DHT");
    let _serve = fabric
        .server()
        .expect("provider fabric exposes a serve axis")
        .serve(ServeBudget::default())
        .await
        .expect("serve gate installs");
    let budget = AnnounceBudget::new(Duration::from_secs(10), 20);

    // HONEST seed: sha256(nar) == honest_key -> the shipped path announces a record.
    // This also proves the DHT announce genuinely works, so the mismatch Err below is
    // the guard, not a routing failure.
    let records = announce_provider_seeds(
        &fabric,
        &readiness,
        InitialAnnounceConfig::new([2u8; 32], 3600, unix_now(), &budget),
        &[(honest_key, nar.clone())],
        LanShare::operator_assembled(),
    )
    .await
    .expect("an honest seed announces on the shipped path");
    assert_eq!(records.len(), 1, "one honest seed -> one announced record");
    assert_eq!(
        records[0].content, expected_content,
        "the announced record carries the raw NAR's real BLAKE3"
    );

    // MIS-SPECIFIED seed: declared X != sha256(nar) = Y. The shipped path must REFUSE
    // it before signing/announcing - no false record is minted.
    let lied = NarHashKey::from_sha256_bytes([0xee; 32]);
    assert_ne!(lied, honest_key);
    let refused = announce_provider_seeds(
        &fabric,
        &readiness,
        InitialAnnounceConfig::new([2u8; 32], 3600, unix_now(), &budget),
        &[(lied, nar.clone())],
        LanShare::operator_assembled(),
    )
    .await;
    let err = refused.expect_err(
        "a mis-specified seed must be REFUSED by the shipped announce path, not announced \
         as a false claim (delete verify_provider_seeds(seeds)? in announce_provider_seeds \
         and this becomes Ok - the bite)",
    );
    assert!(
        err.contains("NarHash mismatch") && err.contains(&lied.to_string()),
        "the refusal must be the SEED-HASH guard (naming the declared key), not some \
         other error: {err}"
    );

    // Fabrics clean up on drop (as the sibling restart/production tests do); keeping
    // `bootstrap` bound here holds the DHT entry point alive for the announces above.
    drop(fabric);
    drop(bootstrap);
}
