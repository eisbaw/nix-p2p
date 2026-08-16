//! TASK-153: prove BOOTSTRAP INDEPENDENCE - the decentralized directory joins through a
//! SET of >=3 independently-operated bootstrap nodes, and the network keeps resolving
//! announced content when ANY single bootstrap is lost. There is NO single central
//! service: killing one bootstrap neither breaks an admitted consumer's resolve nor stops
//! the DHT from admitting a FRESH announcement and answering a BRAND-NEW consumer that
//! joins through only the survivors.
//!
//! Topology: three bootstrap nodes `B1`, `B2`, `B3` (each a full kad server, none more
//! privileged than the others), a provider `P`, an admitted consumer `C`, and - after the
//! kill - a fresh consumer `C2`. `P` and `C` know ONLY the bootstrap SET; they JOIN
//! THROUGH ALL THREE via [`SwarmHandle::join_bootstraps`]. `C2` joins through only the
//! SURVIVING bootstraps.
//!
//! Making the oracle bite is subtle, and the two tests below are honest about it. A
//! healthy kad DHT REPLICATES records across the k-closest peers, so once a provider that
//! joined the full set has pushed its records, they survive losing any single holder -
//! that robustness is the property under test, but it also means a bridging peer can mask
//! a single-bootstrap join. So:
//!   * `resolves_after_any_single_bootstrap_is_lost` (positive) uses a fresh post-kill
//!     consumer `C2` that joins ONLY the survivors and resolves a key announced AFTER the
//!     kill - a real DHT traversal over `B2`/`B3`, no injection, no pre-existing direct
//!     link. It proves the surviving mesh answers.
//!   * `single_bootstrap_join_does_not_survive_its_only_bootstrap` (the NEGATIVE CONTROL)
//!     builds the ISOLATING topology - a provider that joined ONLY the killed bootstrap,
//!     with NO bridging peer - and asserts resolution FAILS after the kill. That is the
//!     "the oracle can observe a break" proof: the harness is not vacuously green. The two
//!     together discriminate a >=3-bootstrap join (survives) from a single-bootstrap one
//!     (does not).

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
    let fabric = Libp2pFabric::start(
        NodeConfig::new([seed_byte; 32])
            .with_network_scope(scope)
            .with_admit_all_publication(),
    )
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
                    "{context}: consumer never resolved the key (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
}

/// TASK-231: wrap a record in a PublicationWitness for the witness-taking `announce`. A test
/// fabric is a genuinely-isolated in-process network built with the explicit
/// `with_admit_all_publication()` authority, so the announcer admits and the record reaches the
/// DHT exactly as before.
fn eligible(record: &peer_fabric::ProviderRecord) -> peer_fabric::PublicationWitness {
    use peer_fabric::PublicationEligibility;
    peer_fabric::AdmitAllPublication
        .authorize(record.clone())
        .expect("admit-all authorizes a test record")
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
    let boot2_entry = (boot2.peer_id(), addr2);
    let boot3_entry = (boot3.peer_id(), addr3);
    let all_three: Vec<(PeerId, Multiaddr)> = vec![
        (boot1.peer_id(), addr1),
        boot2_entry.clone(),
        boot3_entry.clone(),
    ];
    assert!(
        all_three.len() >= 3,
        "the join uses a set of at least three"
    );

    // Provider and the admitted consumer JOIN THROUGH ALL THREE bootstraps (AC#1: the set
    // is used to join). `min_peers = 3` requires the routing table to actually see all
    // three - a join that funneled through only one could not satisfy it (join returns
    // Err), so this line alone rejects a single-bootstrap join.
    let (provider, _) = start_node(10, scope).await;
    let (consumer, _) = start_node(11, scope).await;
    provider
        .handle()
        .join_bootstraps(&all_three, 3, Duration::from_secs(20))
        .await
        .expect("provider joins through the full bootstrap set");
    consumer
        .handle()
        .join_bootstraps(&all_three, 3, Duration::from_secs(20))
        .await
        .expect("consumer joins through the full bootstrap set");

    // The provider announces its signed record for K1.
    let (key1, record1) = signed_record(10, [0x11u8; 32]);
    provider
        .announcer()
        .unwrap()
        .announce(
            &eligible(&record1),
            &AnnounceBudget::new(Duration::from_secs(10), 20),
        )
        .await
        .expect("provider announce admitted");

    // Baseline: the admitted network resolves K1 (confirms propagation + full admission).
    let found = resolve_found(
        &consumer,
        &key1,
        Duration::from_secs(20),
        "baseline pre-kill",
    )
    .await;
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

    // AC#2 (literal): the ALREADY-ADMITTED consumer still resolves the announced key with
    // B1 gone.
    let still = resolve_found(
        &consumer,
        &key1,
        Duration::from_secs(20),
        "post-kill admitted consumer",
    )
    .await;
    assert!(
        still.iter().any(|r| r == &record1),
        "an admitted consumer still resolves after a bootstrap is lost"
    );

    // ---- The DISCRIMINATING oracle (AC#2/#3, no single central service). With B1 gone,
    // the provider announces a FRESH key K2, and a BRAND-NEW consumer C2 that never talked
    // to the provider joins THROUGH THE SURVIVORS ONLY (B2, B3) and resolves K2. No
    // pre-existing direct provider<->C2 link can shortcut this, so it genuinely traverses
    // the DHT over the surviving bootstraps. Had the provider joined through only the
    // now-dead B1, its fresh announcement could not reach B2/B3 and this resolve would
    // fail - the single-bootstrap regression this test exists to catch. ----
    let (key2, record2) = signed_record(10, [0x22u8; 32]);
    assert_ne!(key1, key2, "K2 is a genuinely different key");
    provider
        .announcer()
        .unwrap()
        .announce(
            &eligible(&record2),
            &AnnounceBudget::new(Duration::from_secs(10), 20),
        )
        .await
        .expect("fresh announce admitted with one bootstrap down");

    let survivors: Vec<(PeerId, Multiaddr)> = vec![boot2_entry, boot3_entry];
    let (fresh_consumer, _) = start_node(12, scope).await;
    fresh_consumer
        .handle()
        .join_bootstraps(&survivors, 2, Duration::from_secs(20))
        .await
        .expect("a fresh consumer joins through the SURVIVING bootstraps only");
    let fresh = resolve_found(
        &fresh_consumer,
        &key2,
        Duration::from_secs(20),
        "fresh consumer via survivors",
    )
    .await;
    assert!(
        fresh.iter().any(|r| r == &record2),
        "a fresh consumer joining only through the surviving bootstraps resolves a key \
         announced after the loss (no single central service)"
    );
}

/// THE NEGATIVE CONTROL: prove the harness can OBSERVE a break, so the positive test's
/// green is not vacuous. Here a provider joins ONLY the bootstrap that is later killed,
/// and NO other peer bridges to the survivors - the isolating topology a >=3-bootstrap
/// join avoids. After the kill, a fresh consumer joining only the surviving bootstraps
/// must NOT resolve the provider's key: its records lived only on the dead bootstrap.
/// This is exactly the single-bootstrap regression `resolves_after_any_single_bootstrap_is_lost`
/// exists to reject; asserting the failure here shows the two tests genuinely discriminate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_bootstrap_join_does_not_survive_its_only_bootstrap() {
    let _ = tracing_subscriber::fmt::try_init();
    let scope = "bootstrap-independence-negative";

    let (boot1, addr1) = start_node(21, scope).await;
    let (boot2, addr2) = start_node(22, scope).await;
    let (boot3, addr3) = start_node(23, scope).await;
    let only_boot1: Vec<(PeerId, Multiaddr)> = vec![(boot1.peer_id(), addr1)];
    let survivors: Vec<(PeerId, Multiaddr)> =
        vec![(boot2.peer_id(), addr2), (boot3.peer_id(), addr3)];

    // The provider joins ONLY B1 (the bootstrap we will kill). Crucially there is NO
    // admitted consumer to bridge the provider's records onto the survivors.
    let (provider, _) = start_node(30, scope).await;
    provider
        .handle()
        .join_bootstraps(&only_boot1, 1, Duration::from_secs(20))
        .await
        .expect("provider joins through its single bootstrap");

    // Announce while B1 is alive: the record lands on the provider's only known holder, B1.
    let (key, record) = signed_record(30, [0x33u8; 32]);
    provider
        .announcer()
        .unwrap()
        .announce(
            &eligible(&record),
            &AnnounceBudget::new(Duration::from_secs(10), 20),
        )
        .await
        .expect("announce admitted through the single bootstrap");

    // Kill the provider's only bootstrap. Its records go with it.
    drop(boot1);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A fresh consumer joins only the SURVIVORS (which never held the provider's records,
    // and which the provider never connected to). It must NOT resolve the key.
    let (fresh_consumer, _) = start_node(31, scope).await;
    fresh_consumer
        .handle()
        .join_bootstraps(&survivors, 2, Duration::from_secs(20))
        .await
        .expect("fresh consumer joins the surviving bootstraps");

    // Poll for a generous window; every attempt must be non-Found (the record is
    // unreachable now that its only holder died). A single Found would mean the harness
    // could not observe the break - which would invalidate the positive test's oracle.
    let budget = DiscoveryBudget::new(Duration::from_secs(5), 32);
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last = None;
    while Instant::now() < deadline {
        let lookup = fresh_consumer
            .provider_directory()
            .unwrap()
            .find_providers(&key, &budget)
            .await;
        assert!(
            !lookup.is_found(),
            "the record must be unreachable after its only bootstrap died, got {lookup:?}"
        );
        last = Some(lookup);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Sanity: we actually exercised the resolver (it returned a real non-Found verdict).
    assert!(
        last.is_some(),
        "the negative control must have run at least one real lookup"
    );
}
