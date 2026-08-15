//! TASK-218: a consumer that did ONLY kad discovery must RESOLVE a NAT'd provider's
//! `/p2p-circuit` dial-address WITHOUT any injected address, and fetch the NAR through the
//! relay. `nat_traversal.rs` proves the relay DATA path when the circuit address is supplied
//! DIRECTLY; this file proves the RESOLUTION half - the discovery-only consumer CONSTRUCTS
//! the circuit dial-address (ROUTE 1, mped-architect-ruled) from the provider PeerId it got
//! via kad `get_providers` PLUS a relay it already knows from bootstrap config.
//!
//! DIAGNOSIS this pins (the TASK-218 miss): kad `get_closest_peers` for the NAT'd provider
//! returns ONLY the provider's DIRECT transport address, never its `/p2p-circuit` address (it
//! is dropped in the identify->kad->FIND_NODE path). On loopback the direct addr is 127.0.0.1
//! so a fetch incidentally works; behind a real NAT it is a PRIVATE unreachable addr and the
//! circuit is the only reachable one -> a "kad peer-routing miss" and upstream fallback.
//!
//! HONEST SCOPE / GENERALITY LIMIT: ROUTE 1 resolves a provider that reserved on a relay the
//! consumer ALREADY knows from config (the single shared-relay case - the harness, and the
//! common "a known public relay" deployment). The multi-relay case (consumer does not know
//! which relay a provider chose) needs the relay identity to propagate through the DHT and is
//! the filed follow-up TASK-219. These tests deliberately use ONE shared relay.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use fabric_libp2p::{
    Libp2pFabric, Libp2pNarSupplier, MemoryNarSupplier, Multiaddr, NodeConfig, PeerId, Protocol,
};
use peer_fabric::{
    AnnounceBudget, Blake3Digest, ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric,
    ProviderRecord, ResolutionPolicy, SafetyEnvelope, ServeBudget, TransportOffer, TransportTag,
    sign_provider_record,
};

fn is_direct_tcp(addr: &Multiaddr) -> bool {
    !addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
        && addr.iter().any(|p| matches!(p, Protocol::Tcp(_)))
}

fn is_circuit_str(loc: &str) -> bool {
    loc.contains("p2p-circuit")
}

async fn wait_for<T, Fut, F>(mut f: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    for _ in 0..400 {
        if let Some(v) = f().await {
            return Some(v);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// Bind `fabric` on an ephemeral loopback port and return its concrete direct address.
async fn bind_direct(fabric: &Libp2pFabric) -> Multiaddr {
    fabric
        .handle()
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("listen bound");
    wait_for(|| async {
        fabric
            .handle()
            .listen_addrs()
            .await
            .into_iter()
            .find(is_direct_tcp)
    })
    .await
    .expect("direct loopback listen address")
}

/// Join `fabric` to the DHT through `boot` only (adding the BOOTSTRAP address is legitimate),
/// then wait until its routing table has at least one entry.
async fn join(fabric: &Libp2pFabric, boot_peer: PeerId, boot_addr: Multiaddr) {
    fabric
        .handle()
        .add_address(boot_peer, boot_addr.clone())
        .await;
    fabric
        .handle()
        .dial(boot_addr)
        .await
        .expect("dial bootstrap");
    let _ = fabric.handle().bootstrap().await;
    let ok =
        wait_for(|| async { (fabric.handle().routing_peers().await >= 1).then_some(()) }).await;
    assert!(ok.is_some(), "routing table never reached 1 peer");
}

fn signed_record(
    seed_byte: u8,
    nar_hash: [u8; 32],
    content: Blake3Digest,
) -> (ContentKey, ProviderRecord) {
    let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    let key = ContentKey::derive_from_signed_nar_hash(&nar_hash);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let record = ProviderRecord {
        key,
        content,
        provider,
        offers: vec![TransportOffer::Iroh { node: provider }],
        sequence: 1,
        issued_at: now,
        expiry: now + 3600,
        signature: [0u8; 64],
    };
    (key, sign_provider_record(&signing_key, &record))
}

fn node_id_of(seed_byte: u8) -> NodeId {
    let sk = SigningKey::from_bytes(&[seed_byte; 32]);
    NodeId::from_bytes(sk.verifying_key().to_bytes())
}

fn envelope() -> SafetyEnvelope {
    SafetyEnvelope {
        dial_timeout: Duration::from_secs(8),
        body_idle_timeout: Duration::from_secs(8),
        total_timeout: Duration::from_secs(20),
    }
}

/// AC#1 (fabric level): a discovery-only consumer that knows the relay ONLY from bootstrap
/// config RESOLVES the NAT'd provider's `/p2p-circuit` dial-address (no injection) and fetches
/// the NAR byte-identical. THE BITE: the resolved `DialInfo` must carry a `/p2p-circuit`
/// location - the pre-TASK-218 locator returns only the provider's direct address, so this
/// assertion FAILS without the relay-circuit composition (RED), and passes with it (GREEN).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovery_only_consumer_resolves_and_fetches_via_constructed_circuit() {
    let _ = tracing_subscriber::fmt::try_init();
    let scope = "task218-construct";
    let nar =
        b"raw NAR bytes a discovery-only consumer fetches through a constructed circuit".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);
    let nar_hash = [0x21u8; 32];

    // R: public relay + kad bootstrap.
    let relay = Libp2pFabric::start(NodeConfig::new([211u8; 32]).with_network_scope(scope))
        .expect("relay fabric starts");
    let relay_addr = bind_direct(&relay).await;
    let relay_peer = relay.peer_id();
    relay
        .handle()
        .add_external_address(relay_addr.clone())
        .await;

    // P: the NAT'd provider. Serves the NAR; its REACHABLE address is the relay circuit.
    let supplier: Arc<dyn Libp2pNarSupplier> = Arc::new(MemoryNarSupplier::new([nar.clone()]));
    let provider = Libp2pFabric::start_with_supplier(
        NodeConfig::new([212u8; 32]).with_network_scope(scope),
        supplier,
    )
    .expect("provider fabric starts");
    let _p_direct = bind_direct(&provider).await;
    let provider_node: NodeId = provider.node_id();
    let _serve = provider
        .server()
        .expect("provider serves")
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    join(&provider, relay_peer, relay_addr.clone()).await;

    // P reserves on R by listening on its /p2p-circuit.
    let circuit_listen = relay_addr
        .clone()
        .with(Protocol::P2p(relay_peer))
        .with(Protocol::P2pCircuit);
    provider
        .handle()
        .listen(circuit_listen)
        .await
        .expect("provider requests a reservation");
    let reserved = wait_for(|| async {
        provider
            .handle()
            .listen_addrs()
            .await
            .into_iter()
            .find(|a| a.iter().any(|p| matches!(p, Protocol::P2pCircuit)))
    })
    .await;
    assert!(
        reserved.is_some(),
        "provider never obtained a relay reservation"
    );

    // P announces its signed record so C can discover WHO holds the NAR purely via kad.
    let (key, record) = signed_record(212, nar_hash, content);
    provider
        .announcer()
        .expect("announcer present")
        .announce(&record, &AnnounceBudget::new(Duration::from_secs(10), 20))
        .await
        .expect("provider announce admitted");

    // C: consumer that knows the relay ONLY from bootstrap config (known_relays), never P.
    let consumer = Libp2pFabric::start(
        NodeConfig::new([213u8; 32])
            .with_network_scope(scope)
            .with_known_relay(relay_peer, relay_addr.clone()),
    )
    .expect("consumer fabric starts");
    let _c_direct = bind_direct(&consumer).await;
    join(&consumer, relay_peer, relay_addr.clone()).await;

    // Step 1: DISCOVERY via kad get_providers (no injection).
    let budget = DiscoveryBudget::new(Duration::from_secs(10), 32);
    let deadline = Instant::now() + Duration::from_secs(25);
    let discovered = loop {
        match consumer
            .provider_directory()
            .expect("directory present")
            .find_providers(&key, &budget)
            .await
        {
            Lookup::Found(recs) => break recs,
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never discovered the provider ({other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    };
    assert_eq!(discovered.len(), 1);
    assert_eq!(
        discovered[0].provider, provider_node,
        "discovered provider is P"
    );

    // Step 2: RESOLUTION via kad peer-routing + relay-circuit CONSTRUCTION (the bite).
    let locator = consumer.node_locator().expect("locator present");
    let deadline = Instant::now() + Duration::from_secs(25);
    let dial_info = loop {
        match locator
            .locate(&provider_node, &ResolutionPolicy::PublicInfrastructure)
            .await
        {
            Lookup::Found(info) => break info,
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never resolved P ({other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    };
    let located: Vec<String> = dial_info.locations.clone();
    assert!(
        located.iter().any(|l| is_circuit_str(l)),
        "THE BITE: resolution must carry a /p2p-circuit dial-address constructed from the \
         bootstrap-known relay; got {located:?}"
    );
    // And it must be a circuit THROUGH the known relay TO this provider (not fabricated).
    let relay_peer_s = relay_peer.to_string();
    let provider_peer_s = provider.peer_id().to_string();
    assert!(
        located.iter().any(|l| is_circuit_str(l)
            && l.contains(&relay_peer_s)
            && l.contains(&provider_peer_s)),
        "the constructed circuit must go through the known relay {relay_peer_s} to provider \
         {provider_peer_s}; got {located:?}"
    );

    // Step 3: end-to-end byte-identical fetch off the resolved DialInfo (no injected address).
    let transport = consumer
        .transfer(TransportTag::Iroh)
        .expect("transport present");
    let offer = TransportOffer::Iroh {
        node: provider_node,
    };
    let bytes = transport
        .fetch(&content, &offer, Some(nar.len() as u64), &envelope())
        .await
        .expect("fetch succeeds off the resolved dial address (no injection)");
    assert_eq!(
        bytes, nar,
        "fetched bytes are byte-identical to the served NAR"
    );
    assert_eq!(Blake3Digest::from_raw_nar(&bytes), content);
}

/// Q3 provider-INDEPENDENCE bite (mped-architect must-fix #3): `known_relays` is a
/// CONFIG-LEVEL, provider-independent set, NOT a per-provider address channel. The SAME
/// known-relay set must compose a DISTINCT working circuit for two DIFFERENT providers. If a
/// future refactor keyed relays per-provider (injection under another name), one of these
/// would resolve empty - this bites.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn known_relays_compose_distinct_circuits_for_different_providers() {
    let _ = tracing_subscriber::fmt::try_init();
    let scope = "task218-independence";

    // R: a relay whose identity the consumer knows from config. It need not even be joined -
    // circuit CONSTRUCTION is a pure local operation from the provider PeerId + known relay.
    let relay = Libp2pFabric::start(NodeConfig::new([221u8; 32]).with_network_scope(scope))
        .expect("relay fabric starts");
    let relay_addr = bind_direct(&relay).await;
    let relay_peer = relay.peer_id();

    // C: consumer with ONE known relay, EMPTY routing table (never joined). Resolving over an
    // empty table records NO kad (DhtNode) disclosure, yet still composes the circuit.
    let consumer = Libp2pFabric::start(
        NodeConfig::new([222u8; 32])
            .with_network_scope(scope)
            .with_known_relay(relay_peer, relay_addr.clone()),
    )
    .expect("consumer fabric starts");
    let locator = consumer.node_locator().expect("locator present");

    let provider_a = node_id_of(231);
    let provider_b = node_id_of(232);

    let a = match locator
        .locate(&provider_a, &ResolutionPolicy::PublicInfrastructure)
        .await
    {
        Lookup::Found(info) => info.locations,
        other => panic!("expected a constructed circuit for provider A, got {other:?}"),
    };
    let b = match locator
        .locate(&provider_b, &ResolutionPolicy::PublicInfrastructure)
        .await
    {
        Lookup::Found(info) => info.locations,
        other => panic!("expected a constructed circuit for provider B, got {other:?}"),
    };

    let a_circuit: Vec<&String> = a.iter().filter(|l| l.contains("p2p-circuit")).collect();
    let b_circuit: Vec<&String> = b.iter().filter(|l| l.contains("p2p-circuit")).collect();
    assert!(
        !a_circuit.is_empty(),
        "provider A must get a constructed circuit; got {a:?}"
    );
    assert!(
        !b_circuit.is_empty(),
        "provider B must get a constructed circuit; got {b:?}"
    );
    // Same relay in both (the shared config-level relay), distinct provider suffix.
    let relay_peer_s = relay_peer.to_string();
    assert!(a_circuit.iter().all(|l| l.contains(&relay_peer_s)));
    assert!(b_circuit.iter().all(|l| l.contains(&relay_peer_s)));
    assert!(
        a_circuit != b_circuit,
        "distinct providers must yield DISTINCT circuits through the SAME relay set (not a \
         per-provider channel); A={a_circuit:?} B={b_circuit:?}"
    );
}
