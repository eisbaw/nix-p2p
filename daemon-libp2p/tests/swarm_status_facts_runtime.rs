//! TASK-242 item 2: a RUNTIME test of [`daemon_libp2p::SwarmStatusFacts`] over a REAL libp2p
//! swarm (two live `fabric_libp2p::Node`s), not a controllable `MutFacts` stand-in.
//!
//! TASK-240 wired `SwarmStatusFacts` (the `is_connected` bootstrap-health loop) but only
//! COMPILE-tested it — the drills exercise a mutable snapshot, never the live path. This drives the
//! genuine query round-trip through the swarm worker and asserts:
//!
//!   * bootstrap health reads the ACTUAL `SwarmHandle::is_connected` state — a CONNECTED bootstrap
//!     counts healthy, an UNCONNECTED one does not (polarity), and the reported denominator equals
//!     the configured bootstrap-list length (mapping);
//!   * `peer_path` is classified LIVE from the swarm's connection ledger: a direct dial reports
//!     `Direct`, and a bootstrap set with no live connection reports `Unknown` (never `None`, which
//!     is the no-swarm/upstream-only sentinel);
//!   * killing the bootstrap flips a previously-healthy node to `0` healthy + `Unknown` path — the
//!     real dependency-outage, driven end to end through `ConnectionClosed`, not injected.
//!
//! MUTATION: hardwiring `is_connected` to `true` reddens every `healthy=0`/`bootstrap_healthy==0`
//! assertion; hardwiring `connection_path` to `Direct` reddens every `Unknown` assertion.

use std::time::Duration;

use daemon_core::{PeerPath, StatusFacts};
use daemon_libp2p::SwarmStatusFacts;
use fabric_libp2p::{Multiaddr, Node, NodeConfig, PeerId};

/// Start a node listening on a loopback TCP port; return it with its concrete bound address.
async fn start_listening(seed: [u8; 32], scope: &str) -> (Node, Multiaddr) {
    let node = Node::start(NodeConfig::new(seed).with_network_scope(scope)).expect("node starts");
    node.handle
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("listen binds");
    let addr = wait_for(|| async {
        node.handle
            .listen_addrs()
            .await
            .into_iter()
            .find(is_direct_tcp)
    })
    .await
    .expect("a direct loopback TCP listen address appeared");
    (node, addr)
}

/// A direct (non-circuit) TCP loopback address.
fn is_direct_tcp(addr: &Multiaddr) -> bool {
    use fabric_libp2p::Protocol;
    addr.iter().any(|p| matches!(p, Protocol::Tcp(_)))
        && !addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
}

/// Poll `f` up to ~10s (200 * 50ms); the first `Some`/`true` wins. Bounded so a genuine failure
/// fails the test rather than hanging (fail-fast, never a silent stall).
async fn wait_for<T, Fut, F>(mut f: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    for _ in 0..200 {
        if let Some(v) = f().await {
            return Some(v);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn swarm_status_facts_report_live_bootstrap_health_and_path() {
    let scope = "status-facts-runtime";

    // Two real nodes: A (the observed node) and B (its bootstrap). A dials B directly.
    let (node_a, _a_addr) = start_listening([0xA1; 32], scope).await;
    let (node_b, b_addr) = start_listening([0xB2; 32], scope).await;
    let b_peer = node_b.peer_id;

    node_a.handle.add_address(b_peer, b_addr.clone()).await;
    node_a.handle.dial(b_addr.clone()).await.expect("dial B");
    let connected =
        wait_for(|| async { node_a.handle.is_connected(b_peer).await.then_some(()) }).await;
    assert!(
        connected.is_some(),
        "A never established a connection to its bootstrap B"
    );

    // --- CONNECTED bootstrap: healthy=1/1, path=Direct (a direct dial). ---
    let facts_connected = SwarmStatusFacts::new(node_a.handle.clone(), vec![b_peer]);
    let snap = facts_connected.snapshot().await;
    assert_eq!(
        snap.bootstrap_total, 1,
        "denominator maps to the bootstrap list"
    );
    assert_eq!(
        snap.bootstrap_healthy, 1,
        "a live-connected bootstrap counts healthy (real is_connected)"
    );
    assert_eq!(
        snap.path,
        PeerPath::Direct,
        "a directly-dialed bootstrap classifies as Direct (not {:?})",
        snap.path
    );

    // --- UNCONNECTED bootstrap: healthy=0/1, path=Unknown (NOT None: a swarm IS running). ---
    // A random PeerId A never connected to — is_connected must be false, connection_path None,
    // so the aggregate path is Unknown. This is the polarity mutation guard.
    let never = PeerId::random();
    let facts_absent = SwarmStatusFacts::new(node_a.handle.clone(), vec![never]);
    let snap_absent = facts_absent.snapshot().await;
    assert_eq!(snap_absent.bootstrap_total, 1);
    assert_eq!(
        snap_absent.bootstrap_healthy, 0,
        "an unconnected bootstrap is NOT healthy (is_connected false)"
    );
    assert_eq!(
        snap_absent.path,
        PeerPath::Unknown,
        "a running swarm with no live bootstrap connection reports Unknown, never None: got {:?}",
        snap_absent.path
    );

    // --- MIXED list: one connected + one absent -> total=2, healthy=1, path=Direct. Proves the
    //     per-peer mapping over the whole configured set, not a single-peer shortcut. ---
    let facts_mixed = SwarmStatusFacts::new(node_a.handle.clone(), vec![b_peer, never]);
    let snap_mixed = facts_mixed.snapshot().await;
    assert_eq!(snap_mixed.bootstrap_total, 2);
    assert_eq!(snap_mixed.bootstrap_healthy, 1);
    assert_eq!(snap_mixed.path, PeerPath::Direct);

    // --- DEPENDENCY OUTAGE: kill B; A's connection closes; the SAME facts provider flips to
    //     0 healthy + Unknown path, driven end to end through the real ConnectionClosed event. ---
    drop(node_b);
    let dropped =
        wait_for(|| async { (!node_a.handle.is_connected(b_peer).await).then_some(()) }).await;
    assert!(
        dropped.is_some(),
        "A never observed the connection to B closing after B was dropped"
    );
    let snap_outage = facts_connected.snapshot().await;
    assert_eq!(
        snap_outage.bootstrap_healthy, 0,
        "after the bootstrap dies the live surface reports it unhealthy"
    );
    assert_eq!(
        snap_outage.path,
        PeerPath::Unknown,
        "with the only bootstrap gone the path returns to Unknown: got {:?}",
        snap_outage.path
    );
}
