//! TASK-152: DHT record-lifecycle hardening, END TO END over a real in-process
//! libp2p-kad network. Proves the frozen `peer_fabric` validation oracle - now WIRED into
//! the fabric-libp2p announcer + directory - holds across real DHT propagation:
//!
//!   * `withdrawal_retracts_one_of_two_concurrent_providers` (AC#1 + AC#5 concurrent +
//!     no-lost-update): two providers announce the SAME key, a consumer resolves BOTH,
//!     then one provider WITHDRAWS. The withdrawing provider's signed ProviderWithdrawal
//!     tombstone (put_record on the composite value key) retracts its record BEFORE the
//!     record's natural TTL, while the OTHER provider stays Found. The withdrawal happens
//!     long before the 1-hour record expiry, so a Miss for the withdrawn provider is the
//!     tombstone's doing, not TTL. MUTATION that bites: make `withdraw` a no-op (skip the
//!     put_record tombstone) and the withdrawn provider stays Found - the assertion fails.
//!
//!   * `a_rolled_back_record_is_rejected_by_the_durable_floor` (AC#3 replay/rollback + no
//!     resurrection): a provider announces a NEW sequence, a consumer resolves it (its
//!     durable per-(key,provider) floor advances), then the DHT value is ROLLED BACK to an
//!     OLDER signed record. The consumer's floor rejects the stale record, so it is never
//!     returned. MUTATION that bites: drop the record_store apply gate in the directory
//!     and the rolled-back record is served again.
//!
//! Both are timing-sensitive (real kad propagation), so each polls within a bounded
//! window; every resolve is a real, injection-free DHT lookup.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use fabric_libp2p::{Libp2pFabric, MAX_RECORD_TTL_SECS, Multiaddr, NodeConfig, PeerId};
use peer_fabric::{
    AnnounceBudget, AnnounceError, Blake3Digest, ContentKey, DiscoveryBudget, Lookup, NodeId,
    PeerFabric, ProviderRecord, TransportOffer, sign_provider_record,
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

/// Like [`start_node`] but with a DURABLE state directory (TASK-176 #1): the anti-rollback
/// floor and per-key announce sequence are persisted under `state_dir`, so a fabric
/// rebuilt on the SAME `state_dir` (a restart) re-seeds them.
async fn start_node_durable(
    seed_byte: u8,
    scope: &str,
    state_dir: std::path::PathBuf,
) -> (Libp2pFabric, Multiaddr) {
    let fabric = Libp2pFabric::start_durable(
        NodeConfig::new([seed_byte; 32]).with_network_scope(scope),
        state_dir,
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

/// Join `node` to the network through `boot` only, then wait for `min_peers` routing entries.
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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A signed record for `nar_hash` from the identity `seed`, at `sequence`, expiring
/// `ttl_secs` from now. The seed MUST match the provider node's identity seed so
/// `record.provider == node.node_id` (self-serve).
fn signed_record(
    seed_byte: u8,
    nar_hash: [u8; 32],
    sequence: u64,
    ttl_secs: u64,
) -> (ContentKey, ProviderRecord) {
    let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    let key = ContentKey::derive_from_signed_nar_hash(&nar_hash);
    let now = now_secs();
    let record = ProviderRecord {
        key,
        content: Blake3Digest::from_bytes([0x5a; 32]),
        provider,
        offers: vec![TransportOffer::Iroh { node: provider }],
        sequence,
        issued_at: now,
        expiry: now + ttl_secs,
        signature: [0u8; 64],
    };
    (key, sign_provider_record(&signing_key, &record))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn announce_rejects_an_over_cap_record_ttl() {
    // TASK-176 #2 BITE (announce-side policy): an over-cap record TTL is REJECTED on the
    // sender, fail-fast, BEFORE any network op (no bootstrap needed). This is what lets
    // the tombstone floor (>= the cap) guarantee it outlives any record. Mutation: remove
    // the announce TTL-cap check and this record announces (or reaches the network) rather
    // than being Rejected - the assertion fails.
    let _ = tracing_subscriber::fmt::try_init();
    let (node, _addr) = start_node(7, "lifecycle-ttl-cap").await;

    // A record whose TTL exceeds the cap by an hour. The seed matches the node identity so
    // it passes the self-serve provider check and reaches the TTL gate.
    let over_cap_ttl = MAX_RECORD_TTL_SECS + 3600;
    let (_key, record) = signed_record(7, [0x33u8; 32], 1, over_cap_ttl);
    let result = node
        .announcer()
        .unwrap()
        .announce(&record, &AnnounceBudget::new(Duration::from_secs(5), 20))
        .await;
    match result {
        Err(AnnounceError::Rejected(why)) => {
            assert!(
                why.contains("cap"),
                "the rejection must name the TTL cap, got: {why}"
            );
        }
        other => panic!("an over-cap record TTL must be Rejected, got: {other:?}"),
    }

    // Control: a record exactly AT the cap passes the TTL gate (it does not reach the
    // network here, but it is NOT rejected by the cap - it would proceed to publish). We
    // assert the cap is the ONLY thing that changed by checking a within-cap record does
    // not fail with the cap message.
    let (_k2, ok_record) = signed_record(7, [0x34u8; 32], 1, MAX_RECORD_TTL_SECS);
    if let Err(AnnounceError::Rejected(why)) = node
        .announcer()
        .unwrap()
        .announce(
            &ok_record,
            &AnnounceBudget::new(Duration::from_millis(300), 20),
        )
        .await
    {
        assert!(
            !why.contains("cap"),
            "a record AT the cap must not be rejected for exceeding it, got: {why}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn announce_fails_closed_when_the_sequence_cannot_be_persisted() {
    // TASK-185 AC#3 BITE (save-before-publish, fail-closed): if the durably-allocated
    // per-key sequence CANNOT be written, `announce` returns `AnnounceError::Persist` and
    // does NOT publish - so a crash can never expose a record whose sequence is not on disk
    // (the F3 rollback hazard). We force a persist failure by pointing the state dir UNDER a
    // REGULAR FILE, so `create_dir_all` for the sequence file fails. No network is needed:
    // the fail-closed check is BEFORE the DHT publish. Mutation: drop the fail-closed persist
    // check in `announce` and this announce proceeds (to a publish/deadline) instead of
    // returning `Persist` - the match below then panics.
    let _ = tracing_subscriber::fmt::try_init();

    // A regular file that cannot serve as a directory parent for the sequence file.
    let blocker = std::env::temp_dir().join(format!(
        "nix-p2p-persist-blocker-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&blocker);
    std::fs::write(&blocker, b"not a directory").unwrap();
    // state_dir's PARENT is a regular file -> any save's create_dir_all(parent) fails.
    let state_dir = blocker.join("state");

    let fabric = Libp2pFabric::start_durable(
        NodeConfig::new([7u8; 32]).with_network_scope("persist-failclosed"),
        state_dir,
    )
    .expect("fabric builds even with an unwritable state dir (load is best-effort)");

    // A valid, in-cap, self-serve record (seed 7 matches the node identity).
    let (_key, record) = signed_record(7, [0x55u8; 32], 1, 3600);
    let result = fabric
        .announcer()
        .unwrap()
        .announce(&record, &AnnounceBudget::new(Duration::from_secs(5), 20))
        .await;
    match result {
        Err(AnnounceError::Persist(_)) => {}
        other => panic!(
            "an announce whose sequence cannot be durably persisted must FAIL-CLOSED with \
             AnnounceError::Persist (no DHT publish), got: {other:?}"
        ),
    }

    let _ = std::fs::remove_file(&blocker);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withdrawal_retracts_one_of_two_concurrent_providers() {
    let _ = tracing_subscriber::fmt::try_init();
    let scope = "lifecycle-withdraw";

    let (bootstrap, boot_addr) = start_node(1, scope).await;
    let (provider_p, _) = start_node(3, scope).await;
    let (provider_q, _) = start_node(2, scope).await;
    let (consumer, _) = start_node(4, scope).await;
    let boot_peer = bootstrap.peer_id();

    join(&provider_p, boot_peer, boot_addr.clone(), 1).await;
    join(&provider_q, boot_peer, boot_addr.clone(), 1).await;
    join(&consumer, boot_peer, boot_addr.clone(), 1).await;

    // Both providers announce the SAME key with a LONG (1h) TTL, so any later retraction
    // is the withdrawal's doing, never expiry.
    let nar_hash = [0x11u8; 32];
    let (key, record_p) = signed_record(3, nar_hash, 1, 3600);
    let (key_q, record_q) = signed_record(2, nar_hash, 1, 3600);
    assert_eq!(key, key_q);
    let provider_p_id = record_p.provider;
    let provider_q_id = record_q.provider;

    provider_p
        .announcer()
        .unwrap()
        .announce(&record_p, &AnnounceBudget::new(Duration::from_secs(10), 20))
        .await
        .expect("P announce admitted");
    provider_q
        .announcer()
        .unwrap()
        .announce(&record_q, &AnnounceBudget::new(Duration::from_secs(10), 20))
        .await
        .expect("Q announce admitted");

    let budget = DiscoveryBudget::new(Duration::from_secs(10), 32);

    // The consumer resolves BOTH providers (concurrent-provider merge).
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match consumer
            .provider_directory()
            .unwrap()
            .find_providers(&key, &budget)
            .await
        {
            Lookup::Found(records) if records.len() >= 2 => break,
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never resolved both providers (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }

    // P WITHDRAWS: this publishes a signed ProviderWithdrawal tombstone on P's composite
    // value key (and stops P's index entry). The record's own TTL is still ~1h away.
    provider_p
        .announcer()
        .unwrap()
        .withdraw(&key)
        .await
        .expect("P withdraw admitted");

    // The consumer must converge to Q ONLY: P's record is actively retracted before its
    // TTL. Poll within a bounded window for the tombstone to propagate and P to drop.
    let deadline = Instant::now() + Duration::from_secs(25);
    let final_records = loop {
        let lookup = consumer
            .provider_directory()
            .unwrap()
            .find_providers(&key, &budget)
            .await;
        match lookup {
            Lookup::Found(records)
                if records.len() == 1 && records[0].provider == provider_q_id =>
            {
                break records;
            }
            // Still seeing P (tombstone not yet propagated) or a transient empty: keep
            // polling until the deadline.
            Lookup::Found(_) | Lookup::Miss | Lookup::Unavailable(_)
                if Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            other => panic!(
                "P was not retracted to leave Q as the sole provider before the deadline \
                 (last: {other:?})"
            ),
        }
    };
    assert_eq!(final_records.len(), 1);
    assert_eq!(
        final_records[0].provider, provider_q_id,
        "only Q remains after P's signed withdrawal"
    );
    assert_ne!(
        final_records[0].provider, provider_p_id,
        "the withdrawn provider P is gone before its record's natural TTL"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rolled_back_record_is_rejected_by_the_durable_floor() {
    let _ = tracing_subscriber::fmt::try_init();
    let scope = "lifecycle-rollback";

    let (bootstrap, boot_addr) = start_node(1, scope).await;
    let (provider, _) = start_node(3, scope).await;
    let (consumer, _) = start_node(4, scope).await;
    let boot_peer = bootstrap.peer_id();

    join(&provider, boot_peer, boot_addr.clone(), 1).await;
    join(&consumer, boot_peer, boot_addr.clone(), 1).await;

    let nar_hash = [0x22u8; 32];
    // The provider first publishes sequence 5 (the current, legitimate record).
    let (key, record_new) = signed_record(3, nar_hash, 5, 3600);
    let provider_id = record_new.provider;
    let budget = DiscoveryBudget::new(Duration::from_secs(10), 32);

    provider
        .announcer()
        .unwrap()
        .announce(
            &record_new,
            &AnnounceBudget::new(Duration::from_secs(10), 20),
        )
        .await
        .expect("seq-5 announce admitted");

    // The consumer resolves it - its DURABLE per-(key,provider) floor advances to seq 5.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match consumer
            .provider_directory()
            .unwrap()
            .find_providers(&key, &budget)
            .await
        {
            Lookup::Found(records)
                if records
                    .iter()
                    .any(|r| r.provider == provider_id && r.sequence == 5) =>
            {
                break;
            }
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never resolved the seq-5 record (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }

    // ROLLBACK: the DHT value is rewritten to an OLDER signed record (seq 3). This is a
    // real re-put over the network (re-announcing a stale, still-validly-signed record).
    let (_k, record_old) = signed_record(3, nar_hash, 3, 3600);
    provider
        .announcer()
        .unwrap()
        .announce(
            &record_old,
            &AnnounceBudget::new(Duration::from_secs(10), 20),
        )
        .await
        .expect("seq-3 re-put admitted by the substrate (unauthenticated at the wire)");

    // The consumer must NOT serve the rolled-back record: its floor (5) rejects seq 3.
    // Give the stale value time to propagate, then assert the consumer holds the line for
    // a sustained window (never returns the seq-3 record).
    tokio::time::sleep(Duration::from_secs(2)).await;
    let check_until = Instant::now() + Duration::from_secs(6);
    while Instant::now() < check_until {
        match consumer
            .provider_directory()
            .unwrap()
            .find_providers(&key, &budget)
            .await
        {
            Lookup::Found(records) => {
                for r in &records {
                    assert!(
                        !(r.provider == provider_id && r.sequence == 3),
                        "the rolled-back seq-3 record must never be served (durable floor)"
                    );
                }
            }
            // Miss (the stale value lost to the floor and P's slot has no live record) or a
            // transient Unavailable are both acceptable: neither serves the stale record.
            Lookup::Miss | Lookup::Unavailable(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Whether `consumer` currently returns `provider_id` as a live provider of `key`.
async fn provider_is_present(
    consumer: &Libp2pFabric,
    key: &ContentKey,
    provider_id: NodeId,
    budget: &DiscoveryBudget,
) -> bool {
    matches!(
        consumer.provider_directory().unwrap().find_providers(key, budget).await,
        Lookup::Found(records) if records.iter().any(|r| r.provider == provider_id)
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_provider_withdrawal_blocks_resurrection() {
    // TASK-176 #1 + #4 e2e: the DURABLE announce-sequence makes a RESTARTED provider's
    // withdrawal supersede the consumer's floor, so a later re-serve of the old record
    // cannot resurrect the provider.
    //
    // Timeline: provider announces seq 5 (its per-key floor persisted under a state dir),
    // consumer resolves it (its own floor advances to 5), provider RESTARTS (fresh fabric,
    // SAME identity + SAME state dir), WITHDRAWS (re-seeded floor -> tombstone seq 6), the
    // consumer observes the retraction (its floor advances to Withdrawn@6), then the OLD
    // seq-5 record is RE-SERVED (a stale cache / re-put). The durable seq-6 tombstone
    // rejects the seq-5 resurrection.
    //
    // MUTATION that bites: build the restarted provider with `Libp2pFabric::start`
    // (in-memory) instead of `start_durable`. Its re-seeded floor is empty, so the
    // withdrawal is minted at seq 1, which LOSES to the consumer's floor (5) - the
    // consumer's slot stays Active@5, so the re-served seq-5 record is Idempotent and the
    // provider RESURRECTS. The final sustained-absence assertion then fails.
    let _ = tracing_subscriber::fmt::try_init();
    let scope = "lifecycle-provider-restart";
    let state_dir = std::env::temp_dir().join(format!(
        "nix-p2p-provider-restart-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&state_dir);

    let (bootstrap, boot_addr) = start_node(1, scope).await;
    let (consumer, _) = start_node(4, scope).await;
    let boot_peer = bootstrap.peer_id();
    join(&consumer, boot_peer, boot_addr.clone(), 1).await;

    // Provider (seed 3, durable) announces seq 5 with a long TTL, so any later drop is the
    // withdrawal's doing, not expiry.
    let nar_hash = [0x44u8; 32];
    let (key, record) = signed_record(3, nar_hash, 5, 3600);
    let provider_id = record.provider;
    let budget = DiscoveryBudget::new(Duration::from_secs(10), 32);
    let announce_budget = AnnounceBudget::new(Duration::from_secs(10), 20);

    {
        let (provider, _) = start_node_durable(3, scope, state_dir.clone()).await;
        join(&provider, boot_peer, boot_addr.clone(), 1).await;
        provider
            .announcer()
            .unwrap()
            .announce(&record, &announce_budget)
            .await
            .expect("seq-5 announce admitted");

        // The consumer resolves it, advancing its durable floor to seq 5.
        let deadline = Instant::now() + Duration::from_secs(20);
        while !provider_is_present(&consumer, &key, provider_id, &budget).await {
            assert!(
                Instant::now() < deadline,
                "consumer never resolved the provider"
            );
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    } // the provider fabric is DROPPED here == a process restart (state dir persists)

    // RESTART: a fresh fabric, SAME identity + SAME state dir -> re-seeds the per-key
    // announce sequence floor from disk, then withdraws (mints seq 6, strictly newer).
    let (restarted, _) = start_node_durable(3, scope, state_dir.clone()).await;
    join(&restarted, boot_peer, boot_addr.clone(), 1).await;
    restarted
        .announcer()
        .unwrap()
        .withdraw(&key)
        .await
        .expect("restarted provider withdraw admitted");

    // Let the tombstone propagate, then require the consumer to observe the retraction for
    // a CONSECUTIVE streak (so its floor has reliably advanced to Withdrawn@6, not a
    // transient not-yet-fetched blip) before we test resurrection.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut absent_streak = 0;
    while absent_streak < 5 {
        if provider_is_present(&consumer, &key, provider_id, &budget).await {
            absent_streak = 0;
            assert!(
                Instant::now() < deadline,
                "the restarted provider's withdrawal never retracted the record"
            );
        } else {
            absent_streak += 1;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // RESURRECTION ATTEMPT: the OLD seq-5 record is re-served (a stale cache re-put). Only
    // a strictly-newer (durable seq-6) tombstone floor blocks it; a non-durable seq-1
    // tombstone that lost to the consumer's floor does NOT, so the provider would come back.
    restarted
        .announcer()
        .unwrap()
        .announce(&record, &announce_budget)
        .await
        .expect("seq-5 re-serve admitted by the substrate");

    // The provider must STAY gone for a sustained window: the durable floor rejects the
    // re-served seq-5 record.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let check_until = Instant::now() + Duration::from_secs(6);
    while Instant::now() < check_until {
        assert!(
            !provider_is_present(&consumer, &key, provider_id, &budget).await,
            "the durable seq-6 tombstone must block resurrection of the re-served \
             seq-5 record (a non-durable seq-1 tombstone would let it resurrect)"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let _ = std::fs::remove_dir_all(&state_dir);
}
