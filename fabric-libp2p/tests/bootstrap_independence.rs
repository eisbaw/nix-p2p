//! TASK-153: prove BOOTSTRAP INDEPENDENCE - the decentralized directory joins through a
//! SET of >=3 independently-operated bootstrap nodes, and an already-admitted network
//! keeps resolving announced content when ANY single bootstrap is lost. There is NO
//! single central service: killing one bootstrap neither breaks an existing resolve nor
//! stops the DHT from admitting a FRESH announcement and answering it.
//!
//! Topology: three bootstrap nodes `B1`, `B2`, `B3` (each a full kad server, none more
//! privileged than the others), a provider `P`, and a consumer `C`. `P` and `C` know
//! ONLY the bootstrap SET - they never learn each other's address out of band. They JOIN
//! THROUGH ALL THREE via [`SwarmHandle::join_bootstraps`]. `P` announces its OWN signed
//! `ProviderRecord`; `C` resolves it purely through the DHT.
//!
//! The oracle bites: after `C` is admitted, we DROP `B1` (its worker aborts and its
//! listener closes - a real loss, not a pause). If the join had funneled through a single
//! bootstrap, killing it would leave `C`'s routing table pointing only at a dead peer and
//! break resolution. Because the join used the SET, `C` still resolves the announced key,
//! AND `P` can announce a brand-new key that `C` then resolves - both with `B1` gone.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use fabric_libp2p::{Libp2pFabric, Multiaddr, NodeConfig, PeerId};
use peer_fabric::{
    AnnounceBudget, Blake3Digest, ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric,
    ProviderRecord, TransportOffer, sign_provider_record,
};

/// Bring up a node listening on an ephemeral loopback TCP port; returns the fabric and
/// its concrete dial address.
async fn start_node(seed_byte: u8, scope: &str) -> (Libp2pFabric, Multiaddr) {
    let fabric = Libp2pFabric::start(NodeConfig {
        identity_seed: [seed_byte; 32],
        network_scope: scope.to_string(),
    })
    .expect("swarm builds");

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
    (fabric, addr)
}

/// Build and SIGN a ProviderRecord for `nar_hash`, signed by the ed25519 key `seed`
/// (the same seed the provider node's identity was built from, so
/// `record.provider == node.node_id`). Returns the discovery key and the signed record.
fn signed_record(seed_byte: u8, nar_hash: [u8; 32]) -> (ContentKey, ProviderRecord) {
    let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    let key = ContentKey::derive_from_signed_nar_hash(&nar_hash);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let record = ProviderRecord {
        key,
        content: Blake3Digest::from_bytes([0x5a; 32]),
        provider,
        offers: vec![TransportOffer::Iroh { node: provider }],
        sequence: 1,
        issued_at: now,
        expiry: now + 3600,
        signature: [0u8; 64],
    };
    (key, sign_provider_record(&signing_key, &record))
}

/// Resolve `key` through `consumer`, retrying within a bounded window to absorb DHT
/// propagation, until at least one provider record comes back or the deadline elapses.
/// Each call is a real, injection-free lookup. Panics with the last outcome on timeout.
async fn resolve_found(
    consumer: &Libp2pFabric,
    key: &ContentKey,
    within: Duration,
    context: &str,
) -> Vec<ProviderRecord> {
    let budget = DiscoveryBudget::new(Duration::from_secs(10), 32);
    let deadline = Instant::now() + within;
    loop {
        match consumer
            .provider_directory()
            .unwrap()
            .find_providers(key, &budget)
            .await
        {
            Lookup::Found(records) if !records.is_empty() => return records,
            other => {
                assert!(
                    Instant::now() < deadline,
                    "{context}: consumer never resolved the announced key (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resolves_after_any_single_bootstrap_is_lost() {
    let _ = tracing_subscriber::fmt::try_init();
    let scope = "bootstrap-independence";

    // Three INDEPENDENT bootstrap nodes (>=3, AC#1). Each is a plain kad server; none is
    // more privileged than the others.
    let (boot1, addr1) = start_node(1, scope).await;
    let (boot2, addr2) = start_node(2, scope).await;
    let (boot3, addr3) = start_node(3, scope).await;
    let bootstraps: Vec<(PeerId, Multiaddr)> = vec![
        (boot1.peer_id(), addr1),
        (boot2.peer_id(), addr2),
        (boot3.peer_id(), addr3),
    ];
    assert!(bootstraps.len() >= 3, "the join uses a set of at least three");

    // Provider and consumer JOIN THROUGH ALL THREE bootstraps (AC#1: the set is used to
    // join). `min_peers = 3` requires the routing table to see all three bootstraps, so a
    // join that funneled through only one could not satisfy it.
    let (provider, _) = start_node(10, scope).await;
    let (consumer, _) = start_node(11, scope).await;
    provider
        .handle()
        .join_bootstraps(&bootstraps, 3, Duration::from_secs(20))
        .await
        .expect("provider joins through the bootstrap set");
    consumer
        .handle()
        .join_bootstraps(&bootstraps, 3, Duration::from_secs(20))
        .await
        .expect("consumer joins through the bootstrap set");

    // The provider announces its signed record for K1.
    let (key1, record1) = signed_record(10, [0x11u8; 32]);
    provider
        .announcer()
        .unwrap()
        .announce(&record1, &AnnounceBudget::new(Duration::from_secs(10), 20))
        .await
        .expect("provider announce admitted");

    // Baseline: the admitted network resolves K1 (confirms propagation + full admission).
    let found = resolve_found(&consumer, &key1, Duration::from_secs(20), "baseline pre-kill").await;
    assert!(
        found.iter().any(|r| r == &record1),
        "baseline resolve returns the exact signed record"
    );

    // ---- KILL any one bootstrap: drop B1. Its worker aborts (AbortOnDropHandle) and its
    // listener closes - a genuine loss of one of the three independent bootstraps. ----
    drop(boot1);
    // Give the swarm a moment to notice the closed connection; not required for
    // correctness (kad tolerates stale entries), only to make the loss concrete.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // AC#2: the ALREADY-ADMITTED network still resolves the announced key with B1 gone.
    // If the join had used a single (now-dead) bootstrap, this would fail.
    let still = resolve_found(&consumer, &key1, Duration::from_secs(20), "post-kill same key").await;
    assert!(
        still.iter().any(|r| r == &record1),
        "the announced record still resolves after a bootstrap is lost"
    );

    // AC#3 (no single central service): with B1 gone, the DHT still ADMITS a fresh
    // announcement and ANSWERS it. The provider announces a brand-new K2 AFTER the kill;
    // the consumer resolves it - proving the remaining bootstraps carry the network and no
    // single node was load-bearing for either writes or reads.
    let (key2, record2) = signed_record(10, [0x22u8; 32]);
    assert_ne!(key1, key2, "K2 is a genuinely different key");
    provider
        .announcer()
        .unwrap()
        .announce(&record2, &AnnounceBudget::new(Duration::from_secs(10), 20))
        .await
        .expect("fresh announce admitted with one bootstrap down");
    let fresh = resolve_found(&consumer, &key2, Duration::from_secs(20), "post-kill fresh key").await;
    assert!(
        fresh.iter().any(|r| r == &record2),
        "a key announced AFTER the bootstrap loss still resolves (no central service)"
    );
}
