//! The CORNERSTONE test: prove DECENTRALIZED, exact-key content discovery over a real
//! in-process libp2p-kad network, with NO out-of-band injection of the answer.
//!
//! Topology: a bootstrap node `B`, two provider nodes `P` and `Q`, and a consumer `C`.
//! `P`, `Q` and `C` know ONLY `B`'s address - they never learn each other's addresses
//! out of band. `P` and `Q` each announce their OWN signed `ProviderRecord` for one
//! `ContentKey` derived from a NarHash via the FROZEN `content.rs` recipe (the
//! MULTI-PROVIDER case); `C` resolves BOTH back purely through the DHT (get_providers ->
//! per-provider get_record -> frozen decode). The answer is produced by Kademlia, not
//! handed to `C`.
//!
//! Also exercises the two non-Found `Lookup` arms: `Miss` (a healthy empty lookup for
//! an un-announced key) and `Unavailable` (InsufficientRouting for a node not on the
//! network, and DeadlineExceeded for a zero budget).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use fabric_libp2p::{Libp2pFabric, Multiaddr, NodeConfig, PeerId};
use peer_fabric::{
    AnnounceBudget, Blake3Digest, ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric,
    ProviderRecord, TransportOffer, Unavailable, sign_provider_record,
};

/// Bring up a node listening on an ephemeral loopback TCP port; returns the fabric and
/// its concrete dial address.
async fn start_node(seed_byte: u8, scope: &str) -> (Libp2pFabric, Multiaddr) {
    let fabric = Libp2pFabric::start(NodeConfig::new([seed_byte; 32]).with_network_scope(scope))
        .expect("swarm builds");

    fabric
        .handle()
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("listen bound");

    // Wait for the concrete listen address to be reported.
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

/// Join `node` to the network THROUGH the bootstrap peer only, then wait until its
/// routing table has at least `min_peers` entries.
async fn join(node: &Libp2pFabric, boot_peer: PeerId, boot_addr: Multiaddr, min_peers: usize) {
    node.handle()
        .add_address(boot_peer, boot_addr.clone())
        .await;
    node.handle().dial(boot_addr).await.expect("dial bootstrap");
    // Bootstrap self-lookup populates the routing table; tolerate its result and rely
    // on the routing-population poll below as the real readiness signal.
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

/// Build and SIGN a ProviderRecord for `nar_hash`, signed by the ed25519 key `seed`
/// (which must be the same seed the provider node's identity was built from, so
/// `record.provider == node.node_id`). Returns the discovery key and the signed record.
fn signed_record(seed_byte: u8, nar_hash: [u8; 32]) -> (ContentKey, ProviderRecord, NodeId) {
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
    (key, sign_provider_record(&signing_key, &record), provider)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn decentralized_discovery_found_miss_and_unavailable() {
    let _ = tracing_subscriber::fmt::try_init();
    let scope = "found-miss-unavail";

    // Four in-process nodes. Only B is a bootstrap; R/P/C know ONLY B.
    let (bootstrap, boot_addr) = start_node(1, scope).await;
    let (router, _) = start_node(2, scope).await;
    let (provider, _) = start_node(3, scope).await;
    let (consumer, _) = start_node(4, scope).await;
    let boot_peer = bootstrap.peer_id();

    // Sanity: the libp2p identity's NodeId equals the ed25519 verifying key of the same
    // seed (self-serve identity == signing key). If this drifted, announce would reject.
    let (_k, _r, provider_node_from_seed) = signed_record(3, [0u8; 32]);
    assert_eq!(
        provider.node_id(),
        provider_node_from_seed,
        "libp2p identity must equal the ed25519 verifying key of the same seed"
    );

    // Everyone joins through B. B learns R/P/C as they connect; R/P/C discover each
    // other only via the DHT (bootstrap self-lookup), never by injected addresses.
    join(&router, boot_peer, boot_addr.clone(), 1).await;
    join(&provider, boot_peer, boot_addr.clone(), 1).await;
    join(&consumer, boot_peer, boot_addr.clone(), 1).await;

    // ---- UNAVAILABLE arm 1: a node not on the network (empty routing) ----
    let (loner, _) = start_node(9, scope).await;
    let unavailable = loner
        .provider_directory()
        .unwrap()
        .find_providers(&_k, &DiscoveryBudget::new(Duration::from_secs(5), 32))
        .await;
    assert!(
        matches!(
            unavailable,
            Lookup::Unavailable(Unavailable::InsufficientRouting)
        ),
        "a node with an empty routing table must be Unavailable(InsufficientRouting), got {unavailable:?}"
    );

    // ---- The Found arm: TWO providers announce the SAME key; C resolves BOTH ----
    // This is the MULTI-PROVIDER proof (AC#5): P (seed 3) and Q (seed 2, the "router")
    // each announce their OWN signed record for one ContentKey, and C - which knows only
    // B - resolves both through the DHT with no injected answer.
    let nar_hash = [0x11u8; 32];
    let (key, record_p, provider_p) = signed_record(3, nar_hash);
    let (key_q, record_q, provider_q) = signed_record(2, nar_hash);
    assert_eq!(key, key_q, "same NarHash derives to one ContentKey");
    assert_ne!(provider_p, provider_q, "two distinct providers");

    provider
        .announcer()
        .unwrap()
        .announce(&record_p, &AnnounceBudget::new(Duration::from_secs(10), 20))
        .await
        .expect("P announce admitted");
    router
        .announcer()
        .unwrap()
        .announce(&record_q, &AnnounceBudget::new(Duration::from_secs(10), 20))
        .await
        .expect("Q announce admitted");

    // C resolves the key. Retry within a bounded window to absorb DHT propagation; each
    // call is a real, injection-free lookup. Wait until BOTH providers are visible.
    let budget = DiscoveryBudget::new(Duration::from_secs(10), 32);
    let deadline = Instant::now() + Duration::from_secs(20);
    let found = loop {
        match consumer
            .provider_directory()
            .unwrap()
            .find_providers(&key, &budget)
            .await
        {
            Lookup::Found(records) if records.len() >= 2 => break records,
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never resolved both announced providers (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    };

    assert_eq!(found.len(), 2, "exactly the two announced providers");
    // Every resolved record answers the queried key (SSOT) and is one of the two exact
    // signed records that round-tripped the DHT - the answer was produced by Kademlia.
    for resolved in &found {
        assert_eq!(resolved.key, key, "record answers the queried key (SSOT)");
        assert!(
            resolved == &record_p || resolved == &record_q,
            "resolved record is one of the two exact signed records"
        );
    }
    let providers: std::collections::HashSet<_> = found.iter().map(|r| r.provider).collect();
    assert!(
        providers.contains(&provider_p) && providers.contains(&provider_q),
        "both P and Q resolved as distinct providers of the one key"
    );

    // ---- The Miss arm: a healthy lookup for a key nobody announced ----
    let (unannounced_key, _, _) = signed_record(3, [0x22u8; 32]);
    let miss = consumer
        .provider_directory()
        .unwrap()
        .find_providers(&unannounced_key, &budget)
        .await;
    assert!(
        matches!(miss, Lookup::Miss),
        "an un-announced key over a populated routing table must be a healthy Miss, got {miss:?}"
    );

    // ---- UNAVAILABLE arm 2: a zero deadline cuts the lookup short ----
    let deadlined = consumer
        .provider_directory()
        .unwrap()
        .find_providers(&key, &DiscoveryBudget::new(Duration::from_nanos(1), 32))
        .await;
    assert!(
        matches!(
            deadlined,
            Lookup::Unavailable(Unavailable::DeadlineExceeded)
        ),
        "a 1ns budget must surface Unavailable(DeadlineExceeded), got {deadlined:?}"
    );
}
