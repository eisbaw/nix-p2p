//! TASK-78 (fix cycle): prove the `peer_fabric::LeechFabric` seam mask is LOAD-BEARING for
//! EACH give-axis INDEPENDENTLY, over real in-process libp2p swarms, with a reddening mutation
//! per axis. These are the behavioural counterparts to the peer-fabric unit tests: they show a
//! peer actually observing the consequence of the mask, and that UNWRAPPING the exact same fabric
//! (re-enabling that one axis) reverses it.
//!
//!   * SERVE axis (over CONTENT): a CONTENT-BEARING fabric (a real supplier, so it COULD serve)
//!     wrapped in `LeechFabric` exposes `server() == None`, so the composition can never install a
//!     serve gate - and a reachable peer that dials it directly and asks for the content it holds
//!     gets `NotHeld`. MUTATION: install the gate through the UNWRAPPED inner fabric and the very
//!     same fetch returns the bytes. This is NOT "an empty node serves nothing" - the node HOLDS
//!     the content; the mask is the only thing standing between the peer and the bytes.
//!   * ANNOUNCE axis: a provider wrapped in `LeechFabric` exposes `announcer() == None`, so nothing
//!     can publish its record and a consumer's `find_providers` MISSES. MUTATION: announce through
//!     the UNWRAPPED inner announcer and the consumer now resolves the record (Found).
//!
//! Each mutation flips ONE axis: the serve test never announces (direct-address fetch, no DHT
//! record), and the announce test never serves - so a serve-only or announce-only re-enablement is
//! independently caught.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use fabric_libp2p::{Libp2pFabric, MemoryNarSupplier, Multiaddr, NodeConfig, PeerId};
use peer_fabric::{
    AnnounceBudget, Blake3Digest, ContentKey, DiscoveryBudget, LeechFabric, Lookup, NodeId,
    PeerFabric, ProviderRecord, PublicationWitness, ServeBudget, TransferError, TransportOffer,
    sign_provider_record,
};

/// Bring up a node listening on an ephemeral loopback TCP port; returns the fabric + dial addr.
async fn start_node(seed_byte: u8, scope: &str) -> (Libp2pFabric, Multiaddr) {
    let fabric = Libp2pFabric::start(
        NodeConfig::new([seed_byte; 32])
            .with_network_scope(scope)
            .with_admit_all_publication(),
    )
    .expect("swarm builds");
    let addr = listen_and_wait(&fabric).await;
    (fabric, addr)
}

/// Bring up a SERVING-CAPABLE node: it holds `content` via a real supplier, so `server()` is
/// `Some` - but no serve gate is installed until `serve()` is called. Returns the fabric + addr.
async fn start_supplier_node(
    seed_byte: u8,
    scope: &str,
    content: Vec<u8>,
) -> (Libp2pFabric, Multiaddr) {
    let supplier = Arc::new(MemoryNarSupplier::new([content]));
    let fabric = Libp2pFabric::start_with_supplier(
        NodeConfig::new([seed_byte; 32]).with_network_scope(scope),
        supplier,
    )
    .expect("supplier swarm builds");
    let addr = listen_and_wait(&fabric).await;
    (fabric, addr)
}

async fn listen_and_wait(fabric: &Libp2pFabric) -> Multiaddr {
    fabric
        .handle()
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("listen bound");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(addr) = fabric.handle().listen_addrs().await.into_iter().next() {
            return addr;
        }
        assert!(Instant::now() < deadline, "no listen address bound in time");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
            "routing table did not populate in time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

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
        offers: vec![TransportOffer::libp2p(provider)],
        sequence: 1,
        issued_at: now,
        expiry: now + 3600,
        signature: [0u8; 64],
    };
    (key, sign_provider_record(&signing_key, &record))
}

fn eligible(record: &ProviderRecord) -> PublicationWitness {
    use peer_fabric::PublicationEligibility;
    peer_fabric::AdmitAllPublication
        .authorize(record.clone())
        .expect("admit-all authorizes a test record")
}

/// FIX 3 (SERVE axis) + FIX 4 (over CONTENT): a content-bearing fabric wrapped in `LeechFabric`
/// serves NOTHING to a reachable peer that dials it directly and asks for the content it holds;
/// unwrapping to install the serve gate reverses it. Announce is never involved (direct-address
/// fetch), so this catches a SERVE-ONLY re-enablement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leech_over_content_serves_nothing_until_unwrapped() {
    let scope = "leech-serve";
    let content = b"a NAR the leech HOLDS in its supplier but must never serve".to_vec();
    let digest = Blake3Digest::from_raw_nar(&content);

    // The node HOLDS the content (server() is Some) but no serve gate is installed.
    let holder = Arc::new(start_supplier_node(70, scope, content.clone()).await.0);
    let holder_addr = holder
        .handle()
        .listen_addrs()
        .await
        .into_iter()
        .next()
        .unwrap();

    // The mask over the CONTENT-BEARING fabric removes the serve accessor entirely.
    let leech: Arc<dyn PeerFabric> = Arc::new(LeechFabric::new(holder.clone()));
    assert!(
        leech.server().is_none(),
        "LeechFabric over a content-bearing fabric exposes NO server (FIX 4)"
    );

    // A peer dials the holder DIRECTLY (told its address) and asks for the content it holds.
    let (consumer, _) = start_node(71, scope).await;
    consumer
        .handle()
        .add_address(holder.peer_id(), holder_addr.clone())
        .await;
    let _ = consumer.handle().dial(holder_addr.clone()).await;

    let before = consumer
        .handle()
        .fetch_nar_streaming(
            holder.peer_id(),
            digest,
            Some(content.len() as u64),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await;
    assert!(
        matches!(before, Err(TransferError::NotHeld(_))),
        "a reachable leech HOLDING the content still serves NOTHING (no gate installed); got {before:?}"
    );

    // MUTATION (unwrap): install the serve gate through the inner fabric's OWN server axis - the
    // only thing the mask was preventing - and the very same fetch now returns the bytes.
    let _serve = holder
        .server()
        .expect("the inner content-bearing fabric CAN serve once unwrapped")
        .serve(ServeBudget::default())
        .await
        .expect("serve gate installs");
    let after = consumer
        .handle()
        .fetch_nar_streaming(
            holder.peer_id(),
            digest,
            Some(content.len() as u64),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .expect("unwrapped + serving, the peer gets the content");
    assert_eq!(
        after, content,
        "unwrapping to install the gate reddens the NotHeld: serve was the ONLY masked axis"
    );
}

/// FIX 3 (ANNOUNCE axis): a provider wrapped in `LeechFabric` publishes NOTHING, so a consumer's
/// `find_providers` MISSES; announcing through the unwrapped inner announcer makes it resolvable.
/// Serving is never involved, so this catches an ANNOUNCE-ONLY re-enablement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leech_announces_nothing_until_unwrapped() {
    let scope = "leech-announce";
    let (bootstrap, boot_addr) = start_node(1, scope).await;
    let boot_peer = bootstrap.peer_id();
    // The provider identity (seed 3) MUST match the record's signing seed so record.provider == P.
    let provider = Arc::new(start_node(3, scope).await.0);
    let (consumer, _) = start_node(4, scope).await;

    join(&provider, boot_peer, boot_addr.clone(), 1).await;
    join(&consumer, boot_peer, boot_addr.clone(), 1).await;

    let (key, record) = signed_record(3, [0x22u8; 32]);
    let budget = DiscoveryBudget::new(Duration::from_secs(10), 32);

    // Wrap the provider: the mask removes the announce accessor, so NOTHING can publish.
    let leech: Arc<dyn PeerFabric> = Arc::new(LeechFabric::new(provider.clone()));
    assert!(
        leech.announcer().is_none(),
        "LeechFabric exposes NO announcer - a leech publishes nothing"
    );

    // With nothing announced, a healthy lookup over a populated routing table MISSES.
    let miss = consumer
        .provider_directory()
        .unwrap()
        .find_providers(&key, &budget)
        .await;
    assert!(
        matches!(miss, Lookup::Miss),
        "an un-announced key over a populated routing table is a healthy Miss; got {miss:?}"
    );

    // MUTATION (unwrap): announce through the inner announcer - the only masked axis - and the
    // consumer now resolves the exact signed record (Found).
    provider
        .announcer()
        .expect("the inner fabric CAN announce once unwrapped")
        .announce(
            &eligible(&record),
            &AnnounceBudget::new(Duration::from_secs(10), 20),
        )
        .await
        .expect("announce admitted");

    let deadline = Instant::now() + Duration::from_secs(20);
    let found = loop {
        match consumer
            .provider_directory()
            .unwrap()
            .find_providers(&key, &budget)
            .await
        {
            Lookup::Found(records) if !records.is_empty() => break records,
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never resolved the announced record after unwrapping (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    };
    assert_eq!(found.len(), 1, "exactly the one announced provider");
    assert_eq!(
        found[0], record,
        "the resolved record is the exact signed one"
    );
}
