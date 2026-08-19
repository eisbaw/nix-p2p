//! TASK-258 SPIKE — in-process oracles for the Mainline rendezvous.
//!
//! Fast/deterministic tests run in the default suite. The load-bearing tests that spin up
//! a real (hermetic, loopback) Mainline DHT are `#[ignore]` (mirroring
//! `fabric-libp2p/tests/mdns_bootstrap.rs`) so `just test` stays fast and non-flaky; they
//! are run explicitly by the spike (`cargo test -p mainline-rendezvous -- --ignored`) and
//! their results are recorded in the report. The AUTHORITATIVE enumeration + client-only
//! measurements are the RAW-WIRE ones in `scripts/mainline_spike_measure.py`; these
//! in-process tests are the API-level cross-checks.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use mainline::async_dht::AsyncDht;
use mainline_rendezvous::{
    DhtRole, LookupBound, announce, build_node, discover, rendezvous_infohash,
};

/// A free loopback UDP port (bind :0, read it, drop) so parallel tests never collide.
fn free_udp_port() -> u16 {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral");
    sock.local_addr().expect("local_addr").port()
}

fn local_bootstrap() -> (AsyncDht, SocketAddrV4) {
    let port = free_udp_port();
    let dht = build_node(DhtRole::Server, &[], Ipv4Addr::LOCALHOST, port).expect("bootstrap");
    (dht, SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

#[test]
fn rendezvous_infohash_is_deterministic_and_20_bytes() {
    let a = rendezvous_infohash();
    let b = rendezvous_infohash();
    assert_eq!(a, b, "the well-known infohash must be a stable constant");
    assert_eq!(a.as_bytes().len(), 20, "BEP5 infohash is 20 bytes");
}

/// Client-only self-report cross-check (the RAW-WIRE proof is the measure script): a node
/// built without `server_mode()` reports `server_mode() == false`; the bootstrap server
/// reports `true`. This is the API mirror of the packet-level bite (0 vs 44 outbound
/// responses).
#[tokio::test]
async fn client_and_server_self_report_serving_mode() {
    let (server, boot) = local_bootstrap();
    assert!(
        server.info().await.server_mode(),
        "a server_mode() node must report serving"
    );
    let client = build_node(
        DhtRole::Client,
        &[boot],
        Ipv4Addr::LOCALHOST,
        free_udp_port(),
    )
    .expect("client");
    assert!(
        !client.info().await.server_mode(),
        "a client (no server_mode) must NEVER report serving — the client-only guarantee"
    );
}

/// AC#3 core (in-process): a THIRD node B, never given A's address, discovers A via BEP5
/// `get_peers` on the well-known infohash. AC#13 is visible in the RETURN TYPE: `addrs` is
/// `Vec<SocketAddrV4>` — bare IP:port, NO PeerId to build a `/p2p-circuit` from.
#[tokio::test]
#[ignore = "spins a hermetic loopback Mainline DHT; run with --ignored"]
async fn rendezvous_discovery_across_local_dht() {
    let (_server, boot) = local_bootstrap();
    let libp2p_port = free_udp_port();

    let announcer = build_node(
        DhtRole::Client,
        &[boot],
        Ipv4Addr::LOCALHOST,
        free_udp_port(),
    )
    .expect("announcer");
    let _ = tokio::time::timeout(Duration::from_secs(10), announcer.bootstrapped()).await;
    announce(&announcer, libp2p_port).await.expect("announce");

    let seeker = build_node(
        DhtRole::Client,
        &[boot],
        Ipv4Addr::LOCALHOST,
        free_udp_port(),
    )
    .expect("seeker");
    let _ = tokio::time::timeout(Duration::from_secs(10), seeker.bootstrapped()).await;
    let found = discover(
        &seeker,
        LookupBound {
            deadline: Duration::from_secs(10),
            max_addrs: 64,
        },
    )
    .await;

    assert!(
        found.addrs.iter().any(|a| a.port() == libp2p_port),
        "B must discover A's announced libp2p port {libp2p_port} via BEP5; got {:?}",
        found.addrs
    );
    // AC#13 made concrete: the recovered address carries only IP:port. There is no PeerId
    // in `SocketAddrV4`, so B cannot build `/ip4/<relay>/.../p2p-circuit/p2p/<A-PeerId>`
    // from a BEP5 answer. Discovery of membership: yes. Reachability of a NAT'd A: no.
}

/// AC#4 BITE: with the rendezvous "disabled" on A (A never announces), B's SAME bounded
/// `get_peers` recovers NOTHING within the bound — proving no address arrived by another
/// path. If discovery still succeeded here, an out-of-band injection would be smuggling the
/// address (the no-injection discipline TASK-103/155 enforce).
#[tokio::test]
#[ignore = "spins a hermetic loopback Mainline DHT; run with --ignored"]
async fn disabling_rendezvous_makes_discovery_fail() {
    let (_server, boot) = local_bootstrap();
    // A node exists but does NOT announce (rendezvous disabled). B looks up the infohash.
    let seeker = build_node(
        DhtRole::Client,
        &[boot],
        Ipv4Addr::LOCALHOST,
        free_udp_port(),
    )
    .expect("seeker");
    let _ = tokio::time::timeout(Duration::from_secs(10), seeker.bootstrapped()).await;
    let found = discover(
        &seeker,
        LookupBound {
            deadline: Duration::from_secs(4),
            max_addrs: 64,
        },
    )
    .await;
    assert!(
        found.addrs.is_empty(),
        "with no announce, discovery MUST be empty within the bound (no out-of-band \
         injection); got {:?}",
        found.addrs
    );
}
