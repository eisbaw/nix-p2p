//! TASK-159 AC#1 acceptance: prove the DIAL ADDRESS is now discovered THROUGH the DHT,
//! not injected. This is the peer-discovery cornerstone on the primary (libp2p) path.
//!
//! Topology: a bootstrap node `B`, a serving provider `P`, and a resolver `C`. `P` and `C`
//! know ONLY `B`'s address; they never learn each other's addresses out of band. `P`
//! serves a NAR and announces its signed `ProviderRecord`. `C`:
//!
//!   1. discovers WHO holds the NAR via kad `get_providers` (as today, TASK-103), then
//!   2. resolves that provider's PeerId to a Multiaddr via the NEW [`NodeLocator`] (kad
//!      peer-routing / `get_closest_peers`), and
//!   3. dials + fetches the NAR - WITHOUT ever calling `add_address` to inject `P`'s
//!      address on `C`.
//!
//! The address reaches `C` only through the DHT/identify via the shared bootstrap `B`.
//! The oracle asserts: the located address equals `P`'s real listen address (so the
//! resolution, not a guess, produced it); the fetch returns the exact served bytes; and
//! the three `Lookup` arms of `locate` are distinct (Found for `P`, Miss for an unknown
//! peer, Unavailable for a node not on the network).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use fabric_libp2p::{Libp2pFabric, Libp2pNarSupplier, MemoryNarSupplier, Multiaddr, NodeConfig};
use peer_fabric::{
    AnnounceBudget, Blake3Digest, ContentKey, DialInfo, DiscoveryBudget, Lookup, NodeId,
    PeerFabric, ProviderRecord, ResolutionPolicy, SafetyEnvelope, ServeBudget, TransportOffer,
    TransportTag, Unavailable, sign_provider_record,
};

/// Bring up a serving fabric (a supplier makes it a provider) listening on an ephemeral
/// loopback TCP port; returns the fabric and its concrete dial address.
async fn start_serving_node(
    seed_byte: u8,
    scope: &str,
    supplier: Arc<dyn Libp2pNarSupplier>,
) -> (Libp2pFabric, Multiaddr) {
    let fabric = Libp2pFabric::start_with_supplier(
        NodeConfig::new([seed_byte; 32])
            .with_network_scope(scope)
            .with_admit_all_publication(),
        supplier,
    )
    .expect("swarm builds");
    bind_and_addr(fabric).await
}

/// Bring up a pure consumer/bootstrap fabric (no supplier) listening on loopback.
async fn start_node(seed_byte: u8, scope: &str) -> (Libp2pFabric, Multiaddr) {
    let fabric = Libp2pFabric::start(
        NodeConfig::new([seed_byte; 32])
            .with_network_scope(scope)
            .with_admit_all_publication(),
    )
    .expect("swarm builds");
    bind_and_addr(fabric).await
}

async fn bind_and_addr(fabric: Libp2pFabric) -> (Libp2pFabric, Multiaddr) {
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

/// Join `node` to the network THROUGH the bootstrap peer only, then wait until its routing
/// table has at least `min_peers` entries. Adding the BOOTSTRAP address is legitimate (it
/// is the entry peer); the provider's address is what must NOT be injected.
async fn join(
    node: &Libp2pFabric,
    boot_peer: fabric_libp2p::PeerId,
    boot_addr: Multiaddr,
    min_peers: usize,
) {
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

/// Build and SIGN a ProviderRecord for `nar_hash` and `content`, signed by the ed25519 key
/// `seed` (which is the provider node's identity, so `record.provider == node.node_id`).
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

fn envelope() -> SafetyEnvelope {
    SafetyEnvelope {
        dial_timeout: Duration::from_secs(5),
        body_idle_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(10),
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
async fn node_locator_resolves_dial_address_via_kad_and_fetches_without_injection() {
    let _ = tracing_subscriber::fmt::try_init();
    let scope = "locator-no-injection";

    let nar = b"raw NAR bytes whose dial address is discovered through the DHT".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);
    let nar_hash = [0x11u8; 32];

    // Bootstrap B (the ONLY address P and C are told). Provider P serves + announces.
    let (bootstrap, boot_addr) = start_node(1, scope).await;
    let boot_peer = bootstrap.peer_id();
    let supplier = Arc::new(MemoryNarSupplier::new([nar.clone()]));
    let (provider, provider_listen_addr) = start_serving_node(3, scope, supplier).await;
    let provider_node: NodeId = provider.node_id();
    let (resolver, _c_addr) = start_node(4, scope).await;

    // Start serving on P (installs the serve gate).
    let _serve = provider
        .server()
        .expect("provider fabric serves")
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");

    // P and C join THROUGH B only. B learns P's and C's listen addresses via identify as
    // they connect; P and C never exchange addresses directly.
    join(&provider, boot_peer, boot_addr.clone(), 1).await;
    join(&resolver, boot_peer, boot_addr.clone(), 1).await;

    // ---- UNAVAILABLE arm: a node not on the network (empty routing) ----
    let (loner, _) = start_node(9, scope).await;
    let unavailable = loner
        .node_locator()
        .expect("locator present")
        .locate(&provider_node, &ResolutionPolicy::PublicInfrastructure)
        .await;
    assert!(
        matches!(
            unavailable,
            Lookup::Unavailable(Unavailable::InsufficientRouting)
        ),
        "a node with an empty routing table must be Unavailable(InsufficientRouting), got {unavailable:?}"
    );

    // ---- P announces its signed record (so C discovers WHO via get_providers) ----
    let (key, record_p) = signed_record(3, nar_hash, content);
    provider
        .announcer()
        .expect("announcer present")
        .announce(
            &eligible(&record_p),
            &AnnounceBudget::new(Duration::from_secs(10), 20),
        )
        .await
        .expect("P announce admitted");

    // ---- Step 1: C discovers WHO holds the NAR purely through the DHT ----
    let budget = DiscoveryBudget::new(Duration::from_secs(10), 32);
    let deadline = Instant::now() + Duration::from_secs(20);
    let discovered = loop {
        match resolver
            .provider_directory()
            .expect("directory present")
            .find_providers(&key, &budget)
            .await
        {
            Lookup::Found(records) => break records,
            other => {
                assert!(
                    Instant::now() < deadline,
                    "resolver never discovered the provider (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    };
    assert_eq!(discovered.len(), 1, "exactly the one announced provider");
    assert_eq!(
        discovered[0].provider, provider_node,
        "discovered provider is P"
    );

    // ---- Step 2: C resolves P's PeerId to a Multiaddr THROUGH kad peer-routing ----
    // C has NEVER been told P's address. The only path is the DHT/identify via B.
    let locator = resolver.node_locator().expect("locator present");
    let deadline = Instant::now() + Duration::from_secs(20);
    let dial_info = loop {
        match locator
            .locate(&provider_node, &ResolutionPolicy::PublicInfrastructure)
            .await
        {
            Lookup::Found(info) => break info,
            other => {
                assert!(
                    Instant::now() < deadline,
                    "resolver never resolved P's dial address via the DHT (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    };

    // THE ORACLE for "the resolution came from locate(), not a guess": the located address
    // must be P's real listen address (kad reports it with a trailing `/p2p/<PeerId>`
    // component appended, so we match on the listen address as a PREFIX). A resolver that
    // never learned P's address could not produce this - the only source was the DHT.
    let located: Vec<String> = dial_info.locations.clone();
    let listen = provider_listen_addr.to_string();
    assert!(
        located.iter().any(|loc| loc.starts_with(&listen)),
        "the DHT-resolved address {located:?} must carry P's real listen address {listen}"
    );

    // ---- Step 3: C fetches the NAR over a dial that used a DHT-learned address - C never
    // called add_address(P, ..) anywhere (only B's bootstrap address was ever injected).
    // HONEST NOTE: in a small loopback DHT the dial can reuse a connection an EARLIER kad
    // query (bootstrap self-lookup / get_providers) already opened to P, so this fetch's
    // connectivity is not exclusively attributable to the explicit locate() above; what is
    // proven is that NO address was injected out of band and that locate() independently
    // returns P's real address via peer-routing (the assertion above). Cleanly isolating
    // locate() as the SOLE connectivity path is not robust in a small kad network (whether
    // an iterative query dials P depends on XOR distance), so we do not assert it. ----
    let transport = resolver
        .transfer(TransportTag::Iroh)
        .expect("transport present");
    let offer = TransportOffer::Iroh {
        node: provider_node,
    };
    let bytes = transport
        .fetch(&content, &offer, Some(nar.len() as u64), &envelope())
        .await
        .expect("fetch succeeds using the DHT-resolved dial address (no injected address)");
    assert_eq!(
        bytes, nar,
        "fetched bytes must be byte-identical to the served NAR"
    );
    assert_eq!(Blake3Digest::from_raw_nar(&bytes), content);

    // ---- MISS arm: resolving a peer nobody on the network knows an address for ----
    // A distinct, un-joined identity: the query completes healthily but the DHT knows no
    // address for it, so locate is a Miss (distinct from the Unavailable and Found arms).
    let unknown_node = {
        let sk = SigningKey::from_bytes(&[0x7fu8; 32]);
        NodeId::from_bytes(sk.verifying_key().to_bytes())
    };
    let miss = locator
        .locate(&unknown_node, &ResolutionPolicy::PublicInfrastructure)
        .await;
    assert!(
        matches!(miss, Lookup::Miss),
        "a healthy peer-routing query for an address nobody knows must be Miss, got {miss:?}"
    );

    // The three arms are observably distinct (Found above, Miss and Unavailable here).
    assert!(matches!(miss, Lookup::Miss));

    // ---- Exposure oracle: the PublicInfrastructure path RECORDS a disclosure to the
    // ledger (AC: "recording exposure"); the ExplicitPeersOnly path discloses NOTHING. ----
    let before_public = resolver.exposure_ledger().len();
    let _ = locator
        .locate(&provider_node, &ResolutionPolicy::PublicInfrastructure)
        .await;
    let after_public = resolver.exposure_ledger().len();
    assert!(
        after_public > before_public,
        "a PublicInfrastructure locate that consulted the DHT must record a disclosure"
    );

    let explicit = locator
        .locate(&provider_node, &ResolutionPolicy::ExplicitPeersOnly)
        .await;
    assert!(
        matches!(explicit, Lookup::Miss),
        "ExplicitPeersOnly with no configured address book resolves Miss, got {explicit:?}"
    );
    assert_eq!(
        resolver.exposure_ledger().len(),
        after_public,
        "ExplicitPeersOnly must disclose nothing (no new ledger entries)"
    );
}

/// TASK-168 AC#2 acceptance: `ExplicitPeersOnly` resolves from a statically-configured peer
/// address book with ZERO third-party disclosure - a pure LOCAL lookup that makes NO network
/// query.
///
/// The oracle is a single node with an EMPTY routing table and NO peers/bootstrap: it is not
/// on any DHT. On such a node the kad (`PublicInfrastructure`) path CANNOT resolve - it
/// short-circuits to `Unavailable(InsufficientRouting)` because a peer-routing walk over an
/// empty table is not authoritative. So the fact that `ExplicitPeersOnly` still returns
/// `Found` for a book-configured peer PROVES the answer came from the local book, not from
/// the network. Two further bites: an unconfigured peer is a `Miss` (no fabricated address),
/// and the exposure ledger stays at ZERO across every explicit resolution (no disclosure -
/// the load-bearing property that separates this policy from the kad path, which records an
/// `OurNodeId -> DhtNode` disclosure on every consult).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_peers_only_resolves_from_static_book_with_zero_disclosure() {
    let _ = tracing_subscriber::fmt::try_init();
    let scope = "explicit-peers-static-book";

    // The peer whose address we STATICALLY configure. Its NodeId is a real ed25519 verifying
    // key (a dialable identity), distinct from this node's own identity.
    let configured_peer = {
        let sk = SigningKey::from_bytes(&[0x21u8; 32]);
        NodeId::from_bytes(sk.verifying_key().to_bytes())
    };
    let book_addr: Multiaddr = "/ip4/127.0.0.1/tcp/45999".parse().unwrap();

    // A peer we do NOT configure - its explicit resolution must Miss.
    let unconfigured_peer = {
        let sk = SigningKey::from_bytes(&[0x22u8; 32]);
        NodeId::from_bytes(sk.verifying_key().to_bytes())
    };

    // A single node holding the static book. It is NEVER joined to any network: no bootstrap,
    // no dial, no listen - so its kad routing table is empty. We do NOT even call listen().
    let node = Libp2pFabric::start(
        NodeConfig::new([0x20u8; 32])
            .with_network_scope(scope)
            .with_admit_all_publication()
            .with_explicit_peer(configured_peer, [book_addr.clone()]),
    )
    .expect("swarm builds");

    // PRECONDITION for the oracle: the node is genuinely off any DHT (empty routing table).
    assert_eq!(
        node.handle().routing_peers().await,
        0,
        "the node must have an EMPTY routing table so a kad resolve genuinely cannot answer - \
         only then does an ExplicitPeersOnly Found prove the book (not the DHT) produced it"
    );

    let locator = node.node_locator().expect("locator present");

    // ---- ZERO-DISCLOSURE baseline: nothing disclosed yet ----
    let ledger_before = node.exposure_ledger().len();

    // ---- FOUND arm: the book-configured peer resolves from the LOCAL book ----
    let found = locator
        .locate(&configured_peer, &ResolutionPolicy::ExplicitPeersOnly)
        .await;
    assert_eq!(
        found,
        Lookup::Found(DialInfo::new([book_addr.to_string()])),
        "ExplicitPeersOnly must resolve a book-configured peer to its configured address"
    );

    // ---- PROOF IT WAS NOT THE DHT: the SAME node, SAME peer, under PublicInfrastructure
    // cannot resolve at all (empty routing table). If the Found above had gone through kad it
    // would be Unavailable here too. The book path is independent of the network. ----
    let via_dht = locator
        .locate(&configured_peer, &ResolutionPolicy::PublicInfrastructure)
        .await;
    assert!(
        matches!(
            via_dht,
            Lookup::Unavailable(Unavailable::InsufficientRouting)
        ),
        "on an off-network node the kad path must be Unavailable(InsufficientRouting), \
         proving the ExplicitPeersOnly Found came from the local book, got {via_dht:?}"
    );

    // ---- MISS arm: an unconfigured peer has no book entry -> honest Miss (no fabrication) ----
    let miss = locator
        .locate(&unconfigured_peer, &ResolutionPolicy::ExplicitPeersOnly)
        .await;
    assert!(
        matches!(miss, Lookup::Miss),
        "ExplicitPeersOnly for an unconfigured peer must Miss, got {miss:?}"
    );

    // ---- ZERO-DISCLOSURE oracle: NOT ONE explicit resolution touched the ledger. Contrast
    // the PublicInfrastructure consult, which - had it reached the network - would record an
    // OurNodeId disclosure. The InsufficientRouting short-circuit above also records nothing
    // (it never touched the DHT), so the ledger must be exactly unchanged. ----
    assert_eq!(
        node.exposure_ledger().len(),
        ledger_before,
        "ExplicitPeersOnly resolution (Found or Miss) must disclose NOTHING - a static-book \
         lookup makes no network query and records no exposure"
    );
}
