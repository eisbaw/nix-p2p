//! NAT traversal (TASK-168): the swarm now carries the dial-assistance trio - autonat
//! (reachability), relay (circuit-v2 client + server), dcutr (hole punch) - alongside the
//! unchanged kad + identify + stream. This is the LAST unproven half of "robust
//! connectivity" (the PRD's risk 8: works in the harness, fails behind real NAT).
//!
//! Two tests, two altitudes:
//!
//!   1. `swarm_builds_and_listens_with_nat_behaviours_active` - the composition of all seven
//!      behaviours builds and binds. A regression bite: if the relay-client TRANSPORT is not
//!      wired (`with_relay_client`), or a behaviour fails to construct, `Node::start` errors.
//!
//!   2. `provider_reachable_only_via_relay_circuit_fetches_byte_identical` - the LOAD-BEARING
//!      proof at the API level: a provider P that listens ONLY on a relay's `/p2p-circuit`
//!      address (it advertises NO directly-dialable address) is fetched byte-identical by a
//!      consumer C that possesses ONLY the circuit address - the NAR bytes flow THROUGH the
//!      relay's circuit-v2 connection. This exercises `relay` (server, on R) + `relay_client`
//!      (P's reservation, C's circuit dial) end to end over real libp2p streams.
//!
//! HONEST SCOPE (do not over-read): this is LOOPBACK, so there is NO NAT to hole-punch and
//! DCUtR is not exercised here - the true "peer behind a NAT is reachable ONLY via
//! hole-punch/relay, and undiallable when they are disabled" minimal-pair needs a real
//! containerized-NAT topology (the e2e harness). What THIS proves is that the relay
//! circuit-v2 data path is wired and load-bearing: a peer with no directly-reachable address
//! is fetched from purely through the relay. The remaining NAT-harness proof is tracked
//! separately (see the TASK-168 notes / follow-up).

use std::sync::Arc;
use std::time::Duration;

use fabric_libp2p::{
    ConnPath, Libp2pServer, MemoryNarSupplier, Multiaddr, Node, NodeConfig, PeerId, Protocol,
};
use peer_fabric::{Blake3Digest, NarServer, ServeBudget};
use proc_supervisor::TaskSupervisorHandle;

/// Start a node listening on loopback TCP; return it with its concrete bound address.
async fn start_listening(seed: [u8; 32], scope: &str) -> (Node, Multiaddr) {
    let node = Node::start(NodeConfig::new(seed).with_network_scope(scope))
        .expect("node starts (the 7-behaviour composition builds)");
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

/// A direct (non-circuit) TCP loopback address - the relay's own dialable address.
fn is_direct_tcp(addr: &Multiaddr) -> bool {
    !addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
        && addr.iter().any(|p| matches!(p, Protocol::Tcp(_)))
}

/// Poll `f` every 50ms up to ~15s until it yields `Some`.
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

#[tokio::test]
async fn swarm_builds_and_listens_with_nat_behaviours_active() {
    // The composition is kad + identify + stream + autonat + relay + relay_client + dcutr, and
    // the relay-client transport is installed (`with_relay_client`). If any of that regressed,
    // `Node::start` / `listen` would fail here.
    let (node, addr) = start_listening([170u8; 32], "nat-build").await;
    assert!(
        is_direct_tcp(&addr),
        "the node bound a direct loopback listen address: {addr}"
    );
    // The node is live and its worker is polling (a command round-trips).
    let addrs = node.handle.listen_addrs().await;
    assert!(!addrs.is_empty(), "listen addresses are reported");
}

#[tokio::test]
async fn provider_reachable_only_via_relay_circuit_fetches_byte_identical() {
    let scope = "nat-relay-circuit";
    let nar = b"raw NAR bytes served to a consumer THROUGH a relay circuit-v2 hop".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);

    // R: the public relay. Runs the relay SERVER (unconditional in the composition) so it will
    // accept P's reservation and forward C's circuit to P.
    let (relay, relay_addr) = start_listening([171u8; 32], scope).await;
    let relay_peer: PeerId = relay.peer_id;
    // The relay must advertise a reachable address of its own, or its reservation vouchers
    // carry no addresses and the client aborts with `NoAddressesInReservation`. On loopback
    // there is no autonat confirmation, so we tell the relay its address explicitly - exactly
    // what a public relay node does with its known-public address.
    relay.handle.add_external_address(relay_addr.clone()).await;

    // P: the provider. It serves the NAR but listens ONLY on the relay circuit - it advertises
    // NO directly-dialable address, so the ONLY way to reach it is through R.
    let (provider, _p_direct) = {
        // P still needs to bind SOMETHING to run identify/relay-client; it binds a loopback
        // port (the relay reservation is opened over a connection to R), but crucially C is
        // NEVER given this direct address - C only ever learns the circuit address below.
        start_listening([172u8; 32], scope).await
    };
    let provider_peer: PeerId = provider.peer_id;
    let server = Libp2pServer::new(
        provider.handle.clone(),
        Arc::new(MemoryNarSupplier::new([nar.clone()])),
        TaskSupervisorHandle::disconnected(),
    );
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("provider serve starts");

    // P establishes a reservation on R by LISTENING on R's `/p2p-circuit` address. The
    // relay-client transport dials the relay itself (the relay address is embedded in the
    // circuit multiaddr) and requests the reservation - so we do NOT pre-dial the relay here
    // (a competing bare dial races the relay-client's own connection and one gets reset).
    let circuit_listen = relay_addr
        .clone()
        .with(Protocol::P2p(relay_peer))
        .with(Protocol::P2pCircuit);
    provider
        .handle
        .listen(circuit_listen.clone())
        .await
        .expect("provider listens on the relay circuit (requests a reservation)");

    // Wait until P's reservation is live: a `/p2p-circuit` address appears among P's listen
    // addresses (the relay accepted the reservation and P now advertises the circuit).
    let have_reservation = wait_for(|| async {
        provider
            .handle
            .listen_addrs()
            .await
            .into_iter()
            .find(|a| a.iter().any(|p| matches!(p, Protocol::P2pCircuit)))
    })
    .await;
    assert!(
        have_reservation.is_some(),
        "provider never obtained a relay reservation (no /p2p-circuit listen address appeared)"
    );

    // C: the consumer. It is given ONLY the circuit address to P (relay addr + P2pCircuit +
    // P's PeerId). It has NO direct address for P. The fetch must succeed THROUGH the relay.
    let (consumer, _c_addr) = start_listening([173u8; 32], scope).await;
    let circuit_to_provider = relay_addr
        .clone()
        .with(Protocol::P2p(relay_peer))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(provider_peer));

    consumer
        .handle
        .add_address(provider_peer, circuit_to_provider.clone())
        .await;
    // Establish the relayed connection to P via the circuit before opening the NAR stream.
    let _ = consumer.handle.dial(circuit_to_provider.clone()).await;

    let bytes = consumer
        .handle
        .fetch_nar_streaming(
            provider_peer,
            content,
            Some(nar.len() as u64),
            Duration::from_secs(15),
            Duration::from_secs(15),
        )
        .await
        .expect("the NAR is fetched THROUGH the relay circuit (relay path is load-bearing)");

    assert_eq!(
        bytes, nar,
        "bytes fetched over the relay circuit are byte-identical to the served NAR"
    );
    assert_eq!(
        Blake3Digest::from_raw_nar(&bytes),
        content,
        "the relayed transfer preserves the frozen BLAKE3 blob id"
    );

    // TASK-242 relay-detection bite: C reaches P ONLY over the relay circuit, so the live
    // connection-path query (which reads `ConnectedPoint::is_relayed` off the swarm's own
    // ConnectionEstablished bookkeeping) MUST report `Relay` for P — this is exactly the signal
    // the operator status surface renders as `peer_path=relay` for a relayed fetch. MUTATION:
    // classifying a `/p2p-circuit` connection as `Direct` (dropping the `is_relayed` check)
    // reddens this. The SAME node's path to the relay R, which C dials directly, is `Direct` — so
    // the query is not a constant `Relay`, it discriminates by the actual connected endpoint.
    let path_to_provider = consumer.handle.connection_path(provider_peer).await;
    assert_eq!(
        path_to_provider,
        ConnPath::Relay,
        "the only live path to P is the relay circuit, so connection_path must be Relay (not {path_to_provider:?})"
    );
    let path_to_relay = consumer.handle.connection_path(relay_peer).await;
    assert_eq!(
        path_to_relay,
        ConnPath::Direct,
        "C dials the relay R directly, so its path to R is Direct (proves the query is not a constant Relay): got {path_to_relay:?}"
    );
}

/// TASK-208 opt-out: a node built with `with_relay_server(false)` does NOT run the circuit-v2
/// relay server, so it accepts NO reservation - a provider that tries to reserve on it never
/// obtains a `/p2p-circuit` listen address. The MINIMAL PAIR to
/// `provider_reachable_only_via_relay_circuit_fetches_byte_identical` above, which proves the
/// SAME reservation DOES appear against a default (server-ON) relay. This is the behavioral
/// bite that the opt-out truly REMOVES the server (a disabled `Toggle`), not merely reconfigures
/// it. The opted-out node keeps `relay_client`/`autonat`/`dcutr`, so it can still USE relays -
/// asserted here by confirming it still starts and binds with the NAT trio active.
#[tokio::test]
async fn relay_server_opt_out_declines_reservations() {
    let scope = "nat-relay-optout";

    // R: an opted-OUT relay. It binds and advertises an address like any node, but installs
    // NO relay server behaviour, so it cannot grant a reservation.
    let relay = Node::start(
        NodeConfig::new([181u8; 32])
            .with_network_scope(scope)
            .with_relay_server(false),
    )
    .expect("opted-out node still starts (relay_client/autonat/dcutr stay active)");
    relay
        .handle
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("opted-out node still binds a direct address (it can still USE relays)");
    let relay_addr = wait_for(|| async {
        relay
            .handle
            .listen_addrs()
            .await
            .into_iter()
            .find(is_direct_tcp)
    })
    .await
    .expect("opted-out relay reported a direct loopback address");
    let relay_peer: PeerId = relay.peer_id;
    relay.handle.add_external_address(relay_addr.clone()).await;

    // P: a provider that tries to reserve on R exactly as the positive test does.
    let (provider, _p_direct) = start_listening([182u8; 32], scope).await;
    let circuit_listen = relay_addr
        .clone()
        .with(Protocol::P2p(relay_peer))
        .with(Protocol::P2pCircuit);
    // Listener readiness is the exact ListenerId's first `NewListenAddr`, not mere registration.
    // An opted-out relay therefore fails this bounded wait with the correlated terminal listener
    // error. Reverting `listen` to registration-only success makes this assertion fail.
    let listen_error = tokio::time::timeout(
        Duration::from_secs(10),
        provider.handle.listen(circuit_listen.clone()),
    )
    .await
    .expect("reservation refusal must resolve inside the test's outer safety bound")
    .expect_err("an opted-out relay must refuse the circuit listener before it becomes ready");
    assert!(
        listen_error.contains("closed before NewListenAddr")
            && listen_error.contains("Failed to get Reservation")
            && listen_error.contains(&circuit_listen.to_string()),
        "reservation refusal must identify the requested listener and terminal readiness cause: {listen_error}"
    );

    let circuit_addr = provider
        .handle
        .listen_addrs()
        .await
        .into_iter()
        .find(|a| a.iter().any(|p| matches!(p, Protocol::P2pCircuit)));
    assert!(
        circuit_addr.is_none(),
        "opted-out relay must grant NO reservation, but the provider advertised a circuit \
         address: {circuit_addr:?}"
    );
}
