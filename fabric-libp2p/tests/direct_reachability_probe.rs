//! TASK-221: the bounded DIRECT-reachability probe (`SwarmHandle::probe_direct_reachable`) is
//! the ground-truth signal the locator uses to tell a SAME-LAN private provider (directly
//! reachable — compose NO relay circuit, record NO Relay disclosure) from a CROSS-NAT one
//! (never reached directly — compose the circuit, the real-NAT cornerstone). This file proves
//! the probe MECHANISM hermetically with real in-process swarms:
//!
//!   * a provider we CAN reach directly -> the probe returns `true` (well within the budget),
//!     and the observed connection is `Direct` (never a relayed false positive);
//!   * a provider at an UNREACHABLE address -> the probe returns `false`, BOUNDED by the budget
//!     (it never hangs). This is the cross-NAT outcome that keeps the circuit composed.
//!
//! Address CLASSIFICATION (which providers even reach the probe) is unit-tested in
//! `src/locator.rs`; the DISCLOSURE invariant (reachable => no Relay record) is unit-tested
//! there too; and the full cross-NAT end-to-end (probe fails behind a real NAT -> circuit
//! carries the bytes) is `nixos/nat-vm-test.nix`.

use std::time::{Duration, Instant};

use fabric_libp2p::{ConnPath, Multiaddr, Node, NodeConfig, PeerId, Protocol};

/// Start a node listening on loopback TCP; return it with its concrete bound address.
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
    .expect("node reported a direct loopback listen address");
    (node, addr)
}

fn is_direct_tcp(addr: &Multiaddr) -> bool {
    !addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
        && addr.iter().any(|p| matches!(p, Protocol::Tcp(_)))
}

async fn wait_for<T, Fut, F>(mut f: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    for _ in 0..300 {
        if let Some(v) = f().await {
            return Some(v);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

fn with_peer(mut addr: Multiaddr, peer: PeerId) -> Multiaddr {
    addr.push(Protocol::P2p(peer));
    addr
}

/// A provider we CAN reach directly: the probe returns `true`, and quickly (well under the
/// budget), and the resulting connection is `Direct` — never a relayed false positive.
#[tokio::test]
async fn probe_returns_true_for_a_directly_reachable_provider() {
    let scope = "task221-probe-reachable";
    let (consumer, _c_addr) = start_listening([21u8; 32], scope).await;
    let (provider, p_addr) = start_listening([22u8; 32], scope).await;
    let provider_peer: PeerId = provider.peer_id;

    let budget = Duration::from_millis(2000);
    let started = Instant::now();
    let reachable = consumer
        .handle
        .probe_direct_reachable(provider_peer, &[with_peer(p_addr, provider_peer)], budget)
        .await;
    let elapsed = started.elapsed();

    assert!(
        reachable,
        "a directly-reachable (loopback) provider must probe as reachable"
    );
    assert!(
        elapsed < budget,
        "a reachable provider connects within a few RTT, not the full budget; took {elapsed:?}"
    );
    assert_eq!(
        consumer.handle.connection_path(provider_peer).await,
        ConnPath::Direct,
        "the observed path is a genuine DIRECT connection (not relayed)"
    );
}

/// A provider at an UNREACHABLE address (TEST-NET-1 192.0.2.0/24, reserved and never routed):
/// the probe returns `false`, BOUNDED by the budget. This is the cross-NAT outcome — the
/// locator then composes the relay circuit. The bound is the load-bearing property: the probe
/// must never stall discovery.
#[tokio::test]
async fn probe_returns_false_bounded_for_an_unreachable_provider() {
    let scope = "task221-probe-unreachable";
    let (consumer, _c_addr) = start_listening([23u8; 32], scope).await;
    // A random peer id never dialed, at a documentation address that MUST NOT be routed.
    let absent_peer = PeerId::random();
    let unreachable: Multiaddr = "/ip4/192.0.2.1/tcp/1".parse().unwrap();

    let budget = Duration::from_millis(400);
    let started = Instant::now();
    let reachable = consumer
        .handle
        .probe_direct_reachable(absent_peer, &[with_peer(unreachable, absent_peer)], budget)
        .await;
    let elapsed = started.elapsed();

    assert!(
        !reachable,
        "an unreachable provider must probe as NOT directly reachable (so the circuit composes)"
    );
    // BOUNDED: it waits ~budget then gives up — never the full 15s a naive dial-wait could take,
    // and never indefinitely. Allow generous slack for a loaded CI scheduler.
    assert!(
        elapsed >= budget,
        "the probe honoured its full budget before concluding unreachable; took {elapsed:?}"
    );
    assert!(
        elapsed < budget + Duration::from_secs(3),
        "the probe is BOUNDED — it must not hang past its budget; took {elapsed:?}"
    );
    assert_eq!(
        consumer.handle.connection_path(absent_peer).await,
        ConnPath::None,
        "no connection was ever established to the unreachable peer"
    );
}
