//! The libp2p analogue of the iroh `s6-p2p` multi-node transfer test (TASK-151 pass
//! bar): a SERVING node A and a CONSUMER node B, two independent libp2p swarms over real
//! loopback TCP, prove that:
//!
//!   * B fetches a NAR from A over the shared swarm's `/nix-p2p/<scope>/nar/1`
//!     request-response protocol and gets BYTE-IDENTICAL, BLAKE3-verified bytes;
//!   * a CORRUPT provider (bytes that do not hash to the requested digest) is rejected
//!     by the fetch-side gate-1 BLAKE3 verify (`IntegrityMismatch`), never trusted;
//!   * an OVERSIZED response (larger than the signed NarSize) trips the size abort
//!     (`TooLarge`);
//!   * a serve budget DECLINES an over-per-NAR request (task-72 admission), surfaced to
//!     the consumer as a declined fetch;
//!   * dropping the [`ServeHandle`] STOPS the session admitting new requests.
//!
//! These exercise the whole libp2p transfer/serve stack end to end across TWO nodes,
//! with NO in-process shortcut for the byte path.

use std::sync::Arc;
use std::time::Duration;

use fabric_libp2p::{Libp2pServer, Libp2pTransport, MemoryNarSupplier, Node, NodeConfig};
use peer_fabric::{
    Blake3Digest, NarServer, NarTransfer, SafetyEnvelope, ServeBudget, TransferError,
    TransportOffer,
};

/// A generous per-call envelope: loopback finishes in milliseconds, so a multi-second
/// total bound only guards against a hang.
fn envelope() -> SafetyEnvelope {
    SafetyEnvelope {
        dial_timeout: Duration::from_secs(5),
        body_idle_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(10),
    }
}

/// Start a node listening on loopback TCP and return it with its concrete listen addr.
async fn start_listening(seed: [u8; 32], scope: &str) -> (Node, fabric_libp2p::Multiaddr) {
    let node = Node::start(NodeConfig {
        identity_seed: seed,
        network_scope: scope.to_string(),
    })
    .expect("node starts");
    node.handle
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("listen binds");
    // Poll for the concrete bound address (the OS-assigned port arrives asynchronously
    // via NewListenAddr just after listen_on returns).
    let addr = wait_for_listen_addr(&node).await;
    (node, addr)
}

async fn wait_for_listen_addr(node: &Node) -> fabric_libp2p::Multiaddr {
    for _ in 0..200 {
        if let Some(addr) = node.handle.listen_addrs().await.into_iter().next() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("node never reported a listen address");
}

/// Build a consumer transport for `consumer` that can dial `provider` at `addr`.
async fn wire_consumer(
    consumer: &Node,
    provider_peer: fabric_libp2p::PeerId,
    addr: fabric_libp2p::Multiaddr,
) -> Libp2pTransport {
    // Teach the consumer's swarm how to reach the provider (request-response auto-dials
    // a peer whose address is known to the swarm). This is the basic dial the task
    // scopes in; kad peer-routing / NAT traversal is the TASK-159 follow-up.
    consumer.handle.add_address(provider_peer, addr).await;
    Libp2pTransport::new(consumer.handle.clone())
}

#[tokio::test]
async fn fetch_is_byte_identical_and_blake3_verified_across_two_nodes() {
    let scope = "nar-happy";
    let nar = b"raw NAR bytes served over a real libp2p swarm, byte for byte".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);

    // Node A: serve the NAR.
    let (node_a, addr_a) = start_listening([1u8; 32], scope).await;
    let supplier = Arc::new(MemoryNarSupplier::new([nar.clone()]));
    let server = Libp2pServer::new(node_a.handle.clone(), supplier);
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");

    // Node B: fetch it.
    let (node_b, _addr_b) = start_listening([2u8; 32], scope).await;
    let transport = wire_consumer(&node_b, node_a.peer_id, addr_a).await;
    let offer = TransportOffer::Iroh {
        node: node_a.node_id,
    };

    let bytes = transport
        .fetch(&content, &offer, Some(nar.len() as u64), &envelope())
        .await
        .expect("fetch succeeds");

    assert_eq!(
        bytes, nar,
        "fetched bytes must be byte-identical to the served NAR"
    );
    // The fetch already BLAKE3-verified; assert the identity independently too.
    assert_eq!(Blake3Digest::from_raw_nar(&bytes), content);
}

#[tokio::test]
async fn corrupt_provider_is_rejected_by_gate1_blake3_verify() {
    let scope = "nar-corrupt";
    // The consumer ASKS for the digest of the honest bytes...
    let honest = b"the bytes the consumer actually wants".to_vec();
    let requested = Blake3Digest::from_raw_nar(&honest);
    // ...but the provider is CORRUPT: it binds DIFFERENT bytes under that digest.
    let corrupt_bytes = b"totally different bytes that do not hash to the digest".to_vec();
    let mut supplier = MemoryNarSupplier::new([]);
    supplier.insert_raw(requested, corrupt_bytes);

    let (node_a, addr_a) = start_listening([3u8; 32], scope).await;
    let server = Libp2pServer::new(node_a.handle.clone(), Arc::new(supplier));
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");

    let (node_b, _addr_b) = start_listening([4u8; 32], scope).await;
    let transport = wire_consumer(&node_b, node_a.peer_id, addr_a).await;
    let offer = TransportOffer::Iroh {
        node: node_a.node_id,
    };

    let err = transport
        .fetch(&requested, &offer, None, &envelope())
        .await
        .expect_err("a corrupt provider must not yield trusted bytes");
    match err {
        TransferError::IntegrityMismatch { expected, actual } => {
            assert_eq!(expected, requested);
            assert_ne!(actual, requested);
        }
        other => panic!("expected IntegrityMismatch, got {other}"),
    }
}

#[tokio::test]
async fn oversized_response_trips_the_size_abort() {
    let scope = "nar-oversize";
    let nar = b"a NAR that is bigger than the size bound the consumer will allow".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);

    let (node_a, addr_a) = start_listening([5u8; 32], scope).await;
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(MemoryNarSupplier::new([nar.clone()])),
    );
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");

    let (node_b, _addr_b) = start_listening([6u8; 32], scope).await;
    let transport = wire_consumer(&node_b, node_a.peer_id, addr_a).await;
    let offer = TransportOffer::Iroh {
        node: node_a.node_id,
    };

    // Claim a signed NarSize SMALLER than the served bytes: the size abort must fire.
    let lying_bound = (nar.len() - 1) as u64;
    let err = transport
        .fetch(&content, &offer, Some(lying_bound), &envelope())
        .await
        .expect_err("an over-bound response must be aborted");
    match err {
        TransferError::TooLarge { limit, streamed } => {
            assert_eq!(limit, lying_bound);
            assert_eq!(streamed, nar.len() as u64);
        }
        other => panic!("expected TooLarge, got {other}"),
    }
}

#[tokio::test]
async fn serve_budget_declines_over_per_nar_request() {
    let scope = "nar-budget";
    let nar = vec![0xABu8; 4096]; // 4 KiB
    let content = Blake3Digest::from_raw_nar(&nar);

    let (node_a, addr_a) = start_listening([7u8; 32], scope).await;
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(MemoryNarSupplier::new([nar.clone()])),
    );
    // A per-NAR budget SMALLER than the NAR: admission must decline it (task-72).
    let tight = ServeBudget {
        max_nar_bytes_uncompressed_nar: 1024,
        max_inflight_bytes_uncompressed_nar: 1 << 30,
        max_serve_duration: Duration::from_secs(120),
    };
    let _serve = server.serve(tight).await.expect("serve starts");

    let (node_b, _addr_b) = start_listening([8u8; 32], scope).await;
    let transport = wire_consumer(&node_b, node_a.peer_id, addr_a).await;
    let offer = TransportOffer::Iroh {
        node: node_a.node_id,
    };

    let err = transport
        .fetch(&content, &offer, Some(nar.len() as u64), &envelope())
        .await
        .expect_err("an over-budget serve must be declined");
    match err {
        TransferError::Unavailable(why) => {
            assert!(why.contains("declined"), "expected a decline, got: {why}")
        }
        other => panic!("expected Unavailable(declined), got {other}"),
    }
}

#[tokio::test]
async fn dropping_the_serve_handle_stops_admission() {
    let scope = "nar-teardown";
    let nar = b"served only while the handle is held".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);

    let (node_a, addr_a) = start_listening([9u8; 32], scope).await;
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(MemoryNarSupplier::new([nar.clone()])),
    );

    let (node_b, _addr_b) = start_listening([10u8; 32], scope).await;
    let transport = wire_consumer(&node_b, node_a.peer_id, addr_a).await;
    let offer = TransportOffer::Iroh {
        node: node_a.node_id,
    };

    // While serving: the fetch succeeds.
    let serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    let ok = transport
        .fetch(&content, &offer, Some(nar.len() as u64), &envelope())
        .await
        .expect("fetch succeeds while serving");
    assert_eq!(ok, nar);

    // Drop the handle: the session stops admitting. The next fetch must see NotHeld.
    drop(serve);
    // The synchronous stop is via the gate's active flag; the worker uninstall is
    // best-effort/async, so give it a beat to settle before asserting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let err = transport
        .fetch(&content, &offer, Some(nar.len() as u64), &envelope())
        .await
        .expect_err("a torn-down session must not serve");
    assert!(
        matches!(err, TransferError::NotHeld(_)),
        "expected NotHeld after teardown, got {err}"
    );
}
