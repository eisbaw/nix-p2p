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
use std::time::{Duration, Instant};

use fabric_libp2p::{
    Libp2pNodeLocator, Libp2pServer, Libp2pTransport, MemoryNarSupplier, Node, NodeConfig,
};
use peer_fabric::{
    Blake3Digest, ExposureLedger, Lookup, NarServer, NarTransfer, NodeLocator, ResolutionPolicy,
    SafetyEnvelope, ServeBudget, TransferError, TransportOffer,
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

/// Stand up a shared bootstrap `B` for `scope`. Both the provider `A` and the consumer
/// `B'` join it. Why a bootstrap at all: since TASK-169 the transport drives its dial off
/// an EXPLICIT kad peer-routing resolution of the provider, and a bare two-node
/// `add_address` does NOT make the provider resolvable - kad `get_closest_peers` returns
/// the target with NO address unless a SHARED peer learned that address via identify. So
/// the consumer must reach the provider's address through the DHT via `B`, exactly the
/// production topology (`node_locator_discovery.rs`). The old "basic dial shim" (fetch
/// auto-dialing off an injected `add_address`) is precisely what this task removes.
async fn start_bootstrap(scope: &str) -> (Node, fabric_libp2p::Multiaddr) {
    start_listening([200u8; 32], scope).await
}

/// Join `node` to the DHT THROUGH `boot`, waiting until its routing table is non-empty (so
/// identify has run and the shared bootstrap has learned this node's listen address).
async fn join(node: &Node, boot_peer: fabric_libp2p::PeerId, boot_addr: fabric_libp2p::Multiaddr) {
    node.handle.add_address(boot_peer, boot_addr.clone()).await;
    let _ = node.handle.dial(boot_addr).await;
    let _ = node.handle.bootstrap().await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if node.handle.routing_peers().await >= 1 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "routing table never populated through the bootstrap"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Join `consumer` to the DHT through `boot` and build a transport that resolves + dials
/// `provider` through kad peer-routing. Polls `locate(provider)` until Found so the
/// byte-path assertions below are deterministic rather than racing DHT propagation.
async fn wire_consumer(
    consumer: &Node,
    provider: &Node,
    boot_peer: fabric_libp2p::PeerId,
    boot_addr: fabric_libp2p::Multiaddr,
) -> Libp2pTransport {
    join(consumer, boot_peer, boot_addr).await;

    // The transport drives its dial off an EXPLICIT in-fabric resolution (TASK-169), so it
    // holds the same kind of `Libp2pNodeLocator` the fabric wires it with. A standalone
    // ledger is fine here - these tests assert byte-path behaviour, not exposure counts.
    let ledger = Arc::new(ExposureLedger::new());
    let locator = Arc::new(Libp2pNodeLocator::new(consumer.handle.clone(), ledger));

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match locator
            .locate(&provider.node_id, &ResolutionPolicy::PublicInfrastructure)
            .await
        {
            Lookup::Found(_) => break,
            other => {
                assert!(
                    Instant::now() < deadline,
                    "consumer never resolved the provider's dial address via kad peer-routing \
                     (last: {other:?})"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    Libp2pTransport::new(consumer.handle.clone(), locator)
}

#[tokio::test]
async fn fetch_is_byte_identical_and_blake3_verified_across_two_nodes() {
    let scope = "nar-happy";
    let nar = b"raw NAR bytes served over a real libp2p swarm, byte for byte".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);

    // Shared bootstrap B; the serving provider A joins it so its address is DHT-resolvable.
    let (boot, boot_addr) = start_bootstrap(scope).await;
    let boot_peer = boot.peer_id;

    // Node A: serve the NAR.
    let (node_a, _addr_a) = start_listening([1u8; 32], scope).await;
    let supplier = Arc::new(MemoryNarSupplier::new([nar.clone()]));
    let server = Libp2pServer::new(node_a.handle.clone(), supplier);
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    join(&node_a, boot_peer, boot_addr.clone()).await;

    // Node B: fetch it (resolves A's dial address through the DHT via B).
    let (node_b, _addr_b) = start_listening([2u8; 32], scope).await;
    let transport = wire_consumer(&node_b, &node_a, boot_peer, boot_addr.clone()).await;
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

    let (boot, boot_addr) = start_bootstrap(scope).await;
    let boot_peer = boot.peer_id;

    let (node_a, _addr_a) = start_listening([3u8; 32], scope).await;
    let server = Libp2pServer::new(node_a.handle.clone(), Arc::new(supplier));
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    join(&node_a, boot_peer, boot_addr.clone()).await;

    let (node_b, _addr_b) = start_listening([4u8; 32], scope).await;
    let transport = wire_consumer(&node_b, &node_a, boot_peer, boot_addr.clone()).await;
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
async fn signed_bound_smaller_than_served_bytes_trips_size_abort() {
    let scope = "nar-oversize";
    let nar = b"a NAR that is bigger than the size bound the consumer will allow".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);

    let (boot, boot_addr) = start_bootstrap(scope).await;
    let boot_peer = boot.peer_id;

    let (node_a, _addr_a) = start_listening([5u8; 32], scope).await;
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(MemoryNarSupplier::new([nar.clone()])),
    );
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    join(&node_a, boot_peer, boot_addr.clone()).await;

    let (node_b, _addr_b) = start_listening([6u8; 32], scope).await;
    let transport = wire_consumer(&node_b, &node_a, boot_peer, boot_addr.clone()).await;
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

    let (boot, boot_addr) = start_bootstrap(scope).await;
    let boot_peer = boot.peer_id;

    let (node_a, _addr_a) = start_listening([7u8; 32], scope).await;
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
    join(&node_a, boot_peer, boot_addr.clone()).await;

    let (node_b, _addr_b) = start_listening([8u8; 32], scope).await;
    let transport = wire_consumer(&node_b, &node_a, boot_peer, boot_addr.clone()).await;
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

    let (boot, boot_addr) = start_bootstrap(scope).await;
    let boot_peer = boot.peer_id;

    let (node_a, _addr_a) = start_listening([9u8; 32], scope).await;
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(MemoryNarSupplier::new([nar.clone()])),
    );
    join(&node_a, boot_peer, boot_addr.clone()).await;

    let (node_b, _addr_b) = start_listening([10u8; 32], scope).await;
    let transport = wire_consumer(&node_b, &node_a, boot_peer, boot_addr.clone()).await;
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

#[tokio::test]
async fn a_stale_teardown_does_not_clobber_a_live_successor_session() {
    // Regression for the re-serve handoff race: install a SECOND serve session before
    // dropping the FIRST handle. The stale first-handle teardown must NOT uninstall the
    // live successor (the worker clears the slot only if it still holds THAT gate).
    let scope = "nar-reserve";
    let nar = b"served by the successor session".to_vec();
    let content = Blake3Digest::from_raw_nar(&nar);

    let (boot, boot_addr) = start_bootstrap(scope).await;
    let boot_peer = boot.peer_id;

    let (node_a, _addr_a) = start_listening([11u8; 32], scope).await;
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(MemoryNarSupplier::new([nar.clone()])),
    );
    join(&node_a, boot_peer, boot_addr.clone()).await;

    let (node_b, _addr_b) = start_listening([12u8; 32], scope).await;
    let transport = wire_consumer(&node_b, &node_a, boot_peer, boot_addr.clone()).await;
    let offer = TransportOffer::Iroh {
        node: node_a.node_id,
    };

    let handle1 = server.serve(ServeBudget::default()).await.expect("serve 1");
    // Install the successor BEFORE dropping handle1 (the exact handoff order the fix
    // guards): the worker command queue is [InstallServe(g2), UninstallServe(g1)].
    let _handle2 = server.serve(ServeBudget::default()).await.expect("serve 2");
    drop(handle1);
    // Let the stale UninstallServe(g1) be processed and ignored.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The successor session (handle2) is still held and must still serve.
    let bytes = transport
        .fetch(&content, &offer, Some(nar.len() as u64), &envelope())
        .await
        .expect("the live successor session must still serve after a stale teardown");
    assert_eq!(bytes, nar);
}
