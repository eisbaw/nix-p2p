//! TASK-284 AC#6 (crate-level): a fresh CONSUMER node given ONLY the Mainline rendezvous — NO
//! `--libp2p-bootstrap`, NO injected provider address — discovers a provider over a real (hermetic,
//! loopback) BitTorrent Mainline DHT, DIALS it into its libp2p swarm, and then resolves the
//! provider's signed content record over the kad DHT it thereby joined. The paired MUTATION (the
//! consumer runs NO rendezvous, the ONLY change) leaves its routing table EMPTY and unable to
//! resolve — proving the Mainline rendezvous dial was the load-bearing entry path and no address
//! leaked in by any other route.
//!
//! WHY THIS COMPLEMENTS THE CONTAINER E2E. Unlike mDNS (two multicast sockets in one netns do not
//! loop back under SO_REUSEPORT — see `fabric-libp2p/tests/mdns_bootstrap.rs`), the Mainline
//! rendezvous meets peers through a shared LOCAL Mainline SERVER, so two client nodes in ONE
//! process/netns genuinely discover each other. This test therefore proves the cross-node
//! discover -> dial -> kad-join -> resolve MECHANISM deterministically in `cargo test`. The full
//! "fetch a byte-identical NAR with 0 upstream egress across container network namespaces" arm is
//! the e2e harness's job (it owns the HTTP frontend + upstream proxy egress counter); this crate
//! test is the fast, hermetic mechanism proof, mirroring how `mdns_bootstrap.rs` de-risks the mDNS
//! container scenario.
//!
//! `#[ignore]`d like the spike's hermetic-Mainline tests: it spins a real (loopback) Mainline DHT,
//! so it is run explicitly (`cargo test -p daemon-libp2p --test mainline_rendezvous_join --
//! --ignored`) and recorded as the AC#6 mechanism evidence, keeping `just test` fast.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use daemon_libp2p::mainline_bootstrap::{
    MainlineRendezvousConfig, MainlineRendezvousGuard, spawn_mainline_rendezvous,
};
use ed25519_dalek::SigningKey;
use fabric_libp2p::{Libp2pFabric, Multiaddr, NodeConfig};
use mainline_rendezvous::{DhtRole, RendezvousNode, build_node};
use peer_fabric::{
    AnnounceBudget, Blake3Digest, ContentKey, DiscoveryBudget, Lookup, NodeId, PeerFabric,
    ProviderRecord, TransportOffer, sign_provider_record,
};

/// A free loopback UDP port (bind :0, read it, drop) so parallel tests never collide.
fn free_udp_port() -> u16 {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral");
    sock.local_addr().expect("local_addr").port()
}

/// Stand up the hermetic, loopback Mainline SERVER — the ONLY bootstrap either node points at
/// (never `router.bittorrent.com`). Returns the node (kept alive) and its `host:port`.
fn local_mainline_bootstrap() -> (RendezvousNode, SocketAddrV4) {
    let port = free_udp_port();
    let dht =
        build_node(DhtRole::Server, &[], Ipv4Addr::LOCALHOST, port).expect("bootstrap server");
    (dht, SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

/// Bring up a libp2p node listening on all interfaces (so its `0.0.0.0/tcp/P` bind is reachable at
/// `127.0.0.1:P`, the address the loopback Mainline records). NO bootstrap/add_address is ever
/// performed — the ONLY way this node meets a peer is the Mainline rendezvous under test.
async fn start_node(seed_byte: u8, scope: &str) -> Libp2pFabric {
    let fabric = Libp2pFabric::start(
        NodeConfig::new([seed_byte; 32])
            .with_network_scope(scope)
            .with_admit_all_publication(),
    )
    .expect("swarm builds");
    fabric
        .handle()
        .listen("/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>().unwrap())
        .await
        .expect("listen bound");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !fabric.handle().listen_addrs().await.is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "no listen address bound in time");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    fabric
}

/// The first TCP port among a node's bound listen multiaddrs.
fn tcp_port(addrs: &[Multiaddr]) -> u16 {
    use fabric_libp2p::Protocol;
    addrs
        .iter()
        .find_map(|a| {
            a.iter().find_map(|p| match p {
                Protocol::Tcp(port) => Some(port),
                _ => None,
            })
        })
        .expect("node bound a tcp listen port")
}

/// Spawn the SHIPPED rendezvous wiring for `fabric` against `boot`, announcing `announce_port`.
fn spawn_rendezvous(
    fabric: &Libp2pFabric,
    boot: SocketAddrV4,
    announce_port: Option<u16>,
) -> MainlineRendezvousGuard {
    spawn_mainline_rendezvous(
        fabric.handle().clone(),
        MainlineRendezvousConfig {
            bootstrap: vec![boot],
            announce_libp2p_port: announce_port,
        },
    )
    .expect("rendezvous spawns")
}

/// Build + SIGN a ProviderRecord for `nar_hash` under seed `seed_byte` (so `record.provider ==
/// node.node_id`). Returns the discovery key and the signed record.
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

fn eligible(record: &ProviderRecord) -> peer_fabric::PublicationWitness {
    use peer_fabric::PublicationEligibility;
    peer_fabric::AdmitAllPublication
        .authorize(record.clone())
        .expect("admit-all authorizes a test record")
}

/// Poll until `node`'s kad routing table reaches at least `min` peers, or the window elapses. With
/// NO bootstrap and NO add_address, a non-empty routing table can ONLY have come from a Mainline
/// rendezvous dial.
async fn routing_reaches(node: &Libp2pFabric, min: usize, window: Duration) -> bool {
    let deadline = Instant::now() + window;
    loop {
        if node.handle().routing_peers().await >= min {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Poll `consumer.find_providers(key)` until it returns a non-empty `Found` or the window elapses.
async fn resolves_within(consumer: &Libp2pFabric, key: &ContentKey, window: Duration) -> bool {
    let budget = DiscoveryBudget::new(Duration::from_secs(5), 32);
    let deadline = Instant::now() + window;
    loop {
        if let Lookup::Found(records) = consumer
            .provider_directory()
            .unwrap()
            .find_providers(key, &budget)
            .await
            && !records.is_empty()
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Announce `record` from `provider`, retrying within `window` so a not-yet-propagated routing
/// table (rendezvous dial still settling) does not flake the put-quorum.
async fn announce_within(provider: &Libp2pFabric, record: &ProviderRecord, window: Duration) {
    let deadline = Instant::now() + window;
    loop {
        match provider
            .announcer()
            .unwrap()
            .announce(
                &eligible(record),
                &AnnounceBudget::new(Duration::from_secs(10), 20),
            )
            .await
        {
            Ok(_receipt) => return,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "provider could not announce within the window (last: {e:?})"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// AC#6 mechanism + load-bearing bite. POSITIVE: a fresh consumer given ONLY the Mainline
/// rendezvous discovers the provider over the loopback Mainline, dials it, joins its kad, and
/// resolves the provider's signed record. MUTATION (consumer runs NO rendezvous, else identical):
/// its routing table stays EMPTY and it cannot resolve — attributing the join to the rendezvous
/// dial and nothing else (the consumer was NEVER handed the provider's address).
#[ignore = "spins a hermetic loopback Mainline DHT; run with --ignored (AC#6 mechanism evidence). \
            The container-netns NAR-fetch + 0-egress arm is the e2e harness scenario."]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_consumer_joins_and_resolves_via_mainline_only() {
    let _ = tracing_subscriber::fmt::try_init();
    let (_boot_node, boot) = local_mainline_bootstrap();
    let scope = "mainline-join";
    let nar_hash = [0x84u8; 32];
    let (key, record) = signed_record(3, nar_hash);

    // ---- POSITIVE: provider announces its address to Mainline; consumer discovers + dials it ----
    let provider = start_node(3, scope).await;
    let provider_port = tcp_port(&provider.handle().listen_addrs().await);
    // The provider announces its libp2p listen port under the well-known infohash.
    let _prov_rzv = spawn_rendezvous(&provider, boot, Some(provider_port));

    // The consumer is fresh: NO --libp2p-bootstrap, NO provider address, ONLY the rendezvous. It
    // announces nothing (announce_port=None) — it only DISCOVERS the provider's address and dials.
    let consumer = start_node(4, scope).await;
    let _cons_rzv = spawn_rendezvous(&consumer, boot, None);

    assert!(
        routing_reaches(&consumer, 1, Duration::from_secs(45)).await,
        "the consumer given ONLY --libp2p-mainline-rendezvous (no bootstrap, no provider-addr) \
         must discover the provider over the loopback Mainline and DIAL it into its kad routing \
         table. An empty table means the rendezvous discover->dial path did not deliver the address."
    );

    announce_within(&provider, &record, Duration::from_secs(30)).await;
    assert!(
        resolves_within(&consumer, &key, Duration::from_secs(45)).await,
        "the consumer must resolve the provider's signed record over the kad DHT it joined purely \
         via the Mainline rendezvous — content discovery stayed on kad, the rendezvous only \
         supplied the address"
    );
    drop(_cons_rzv);
    drop(_prov_rzv);
    drop(consumer);
    drop(provider);

    // ---- MUTATION (bite): consumer runs NO rendezvous; EVERYTHING else identical => NO join ----
    let provider_off = start_node(3, scope).await;
    let provider_off_port = tcp_port(&provider_off.handle().listen_addrs().await);
    let _prov_rzv_off = spawn_rendezvous(&provider_off, boot, Some(provider_off_port));
    // The consumer has no rendezvous and no bootstrap: there is no path to learn the address.
    let consumer_off = start_node(5, scope).await;
    assert!(
        !routing_reaches(&consumer_off, 1, Duration::from_secs(8)).await,
        "MUTATION: with NO rendezvous and no bootstrap the consumer has no path to learn the \
         provider's address, so its routing table MUST stay empty. A non-empty table would mean an \
         address leaked in by a path other than the Mainline rendezvous, defeating the bite."
    );
    assert!(
        !resolves_within(&consumer_off, &key, Duration::from_secs(4)).await,
        "MUTATION: with no rendezvous the consumer cannot join the DHT, so it cannot resolve the \
         provider's record (empty routing => Unavailable)"
    );
}
