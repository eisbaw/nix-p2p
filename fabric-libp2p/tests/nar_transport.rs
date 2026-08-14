//! The libp2p analogue of the iroh `s6-p2p` multi-node transfer test (TASK-151 pass
//! bar): a SERVING node A and a CONSUMER node B, two independent libp2p swarms over real
//! loopback TCP, prove that:
//!
//!   * B fetches a NAR from A over the shared swarm's `/nix-p2p/<scope>/nar/3` raw
//!     libp2p-stream protocol (TASK-157 + TASK-99 negotiated codec) and gets
//!     BYTE-IDENTICAL, BLAKE3-verified bytes - the default policy compresses the LINK
//!     with zstd, decoded back to the identical raw NAR on the fetch side;
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

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fabric_libp2p::{
    CatalogNarSupplier, CatalogProbe, Libp2pNodeLocator, Libp2pServer, Libp2pTransport,
    MemoryNarSupplier, Multiaddr, Node, NodeConfig, PeerId, ProbedSource, ProbedSupply, ServeGate,
};
use peer_fabric::{
    Blake3Digest, CODEC_ZSTD, ExposureLedger, Lookup, NarServer, NarTransfer, NodeLocator,
    ResolutionPolicy, SafetyEnvelope, ServeBudget, ServeCodecPolicy, TransferError, TransportOffer,
    compress_zstd,
};
use proc_supervisor::{TaskSupervisor, TaskSupervisorHandle};

// TASK-99 live-adversary imports: a MINIMAL bare libp2p-stream swarm stood up IN THE TEST that
// writes attacker-chosen `/nar/3` bytes (truncated frame / bogus codec byte) the honest serve
// loop never emits. No production seam is added (mped-architect judgment): the honest
// `serve_stream` stays the single always-installed inbound path; the codec-level unit tests in
// peer-fabric are the PRIMARY oracle for truncation/trailing/unknown-codec, and these live
// tests CONFIRM the adversarial bytes survive the real libp2p pipe and still hit the same
// rejection at the consumer's decoder boundary.
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::identity::Keypair;
use libp2p::swarm::SwarmEvent;
use libp2p::{StreamProtocol, SwarmBuilder, noise, tcp, yamux};
use tokio::sync::oneshot;

/// The `/nar/3` `STATUS_NAR` response byte (private to `nar.rs`; re-stated for the adversary).
const STATUS_NAR: u8 = 1;

/// Fetch `content` from a provider by its PeerId over the RAW-stream `/nar/3` path directly
/// (add its dial address, then open a stream) - no DHT round trip. This exercises the SAME
/// `serve_stream` + `read_response_streamed` byte path over real libp2p streams the transport
/// uses, but without the bootstrap/discovery machinery, so the compression tests stay cheap and
/// deterministic (mped-architect: route (b)/(c) through `fetch_nar_streaming`, not the DHT
/// transport path). The fetcher always offers raw+zstd (`ACCEPT_RAW_AND_ZSTD`).
async fn direct_fetch(
    consumer: &Node,
    provider_peer: PeerId,
    provider_addr: &Multiaddr,
    content: Blake3Digest,
    expected_size: Option<u64>,
) -> Result<Vec<u8>, TransferError> {
    // Teach the address book AND explicitly dial by multiaddr (the same add_address + dial idiom
    // `join_bootstraps` uses): the dial ESTABLISHES the connection so the subsequent open_stream
    // reuses it, rather than racing a kad-provided address (which is not reliably surfaced for a
    // bare-PeerId dial -> "no addresses for peer").
    consumer
        .handle
        .add_address(provider_peer, provider_addr.clone())
        .await;
    let _ = consumer.handle.dial(provider_addr.clone()).await;
    consumer
        .handle
        .fetch_nar_streaming(
            provider_peer,
            content,
            expected_size,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
}

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
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        supplier,
        TaskSupervisorHandle::disconnected(),
    );
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
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(supplier),
        TaskSupervisorHandle::disconnected(),
    );
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
        TaskSupervisorHandle::disconnected(),
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
async fn a_large_over_bound_serve_is_aborted_mid_stream_not_after_the_whole_nar() {
    // AC#1 over the REAL two-node transport: a provider holds a 1 MiB NAR but the consumer
    // signed a tiny 4 KiB bound. The streaming fetch must abort the INSTANT the running total
    // crosses the bound - after ~one 64 KiB chunk - NOT after receiving all 1 MiB and NOT at
    // the 256 MiB floor. BITE (pre-157): a post-receive buffer check reports streamed == the
    // whole 1 MiB. The mid-stream property is `streamed << served_size`.
    let scope = "nar-oversize-large";
    let nar = vec![0x5au8; 1024 * 1024]; // 1 MiB, honestly hashed
    let content = Blake3Digest::from_raw_nar(&nar);

    let (boot, boot_addr) = start_bootstrap(scope).await;
    let boot_peer = boot.peer_id;

    let (node_a, _addr_a) = start_listening([31u8; 32], scope).await;
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(MemoryNarSupplier::new([nar.clone()])),
        TaskSupervisorHandle::disconnected(),
    );
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    join(&node_a, boot_peer, boot_addr.clone()).await;

    let (node_b, _addr_b) = start_listening([32u8; 32], scope).await;
    let transport = wire_consumer(&node_b, &node_a, boot_peer, boot_addr.clone()).await;
    let offer = TransportOffer::Iroh {
        node: node_a.node_id,
    };

    let signed_bound: u64 = 4 * 1024; // 4 KiB
    let err = transport
        .fetch(&content, &offer, Some(signed_bound), &envelope())
        .await
        .expect_err("a 1 MiB serve under a 4 KiB signed bound must abort mid-stream");
    match err {
        TransferError::TooLarge { limit, streamed } => {
            assert_eq!(limit, signed_bound, "the abort limit is the signed bound");
            assert!(
                streamed > signed_bound,
                "streamed ({streamed}) crossed the bound ({signed_bound})"
            );
            // Decisive: aborted far below the served 1 MiB, proving the read stopped
            // mid-stream rather than buffering the whole NAR (or waiting for the 256 MiB cap).
            assert!(
                streamed < 256 * 1024,
                "streamed ({streamed}) must be far below the served 1 MiB - it aborted mid-stream"
            );
            assert!(
                (streamed as usize) < nar.len(),
                "streamed ({streamed}) must be less than the full NAR ({})",
                nar.len()
            );
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
        TaskSupervisorHandle::disconnected(),
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
        TaskSupervisorHandle::disconnected(),
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
        TaskSupervisorHandle::disconnected(),
    );
    join(&node_a, boot_peer, boot_addr.clone()).await;

    let (node_b, _addr_b) = start_listening([12u8; 32], scope).await;
    let transport = wire_consumer(&node_b, &node_a, boot_peer, boot_addr.clone()).await;
    let offer = TransportOffer::Iroh {
        node: node_a.node_id,
    };

    let handle1 = server.serve(ServeBudget::default()).await.expect("serve 1");
    // Install the successor BEFORE dropping handle1 (the exact handoff order the fix
    // guards): the shared serve slot is set to g2, then handle1's teardown does an
    // identity-checked uninstall of g1 that must NOT clear the live g2 (TASK-157).
    let _handle2 = server.serve(ServeBudget::default()).await.expect("serve 2");
    drop(handle1);
    // Let the stale identity-checked uninstall of g1 run and be ignored.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The successor session (handle2) is still held and must still serve.
    let bytes = transport
        .fetch(&content, &offer, Some(nar.len() as u64), &envelope())
        .await
        .expect("the live successor session must still serve after a stale teardown");
    assert_eq!(bytes, nar);
}

// -------------------------------------------------------------------------
// TASK-193: OFF-loop async serve production reachable from the swarm serve loop.
// A `NarSource::Process` (the store-dump analogue) is now SERVED end to end - before this
// task the synchronous serve loop Declined every Process source with SupplyFailed - and a
// slow Process serve in flight does NOT block the poll loop.
// -------------------------------------------------------------------------

/// A one-content [`CatalogProbe`] returning a fixed [`ProbedSupply`], so a test can drive a
/// Process-backed serve without the daemon catalog.
struct OneProbe {
    content: Blake3Digest,
    declared_size: u64,
    make: Box<dyn Fn() -> ProbedSource + Send + Sync>,
}

impl CatalogProbe for OneProbe {
    fn probe(&self, content: &Blake3Digest) -> Option<ProbedSupply> {
        (content == &self.content).then(|| ProbedSupply {
            declared_size: self.declared_size,
            source: (self.make)(),
        })
    }
}

/// A [`CatalogNarSupplier`] whose one digest regenerates `body` via `sh -c 'printf'` (a
/// [`ProbedSource::Process`], the store-dump analogue: nothing held at rest). `sleep_secs`
/// makes production deliberately SLOW so a test can prove the poll loop stays responsive.
/// `body` must contain no single quote.
fn process_supplier(content: Blake3Digest, body: &[u8], sleep_secs: u32) -> CatalogNarSupplier {
    let body_str = String::from_utf8(body.to_vec()).expect("ascii test body");
    let script = if sleep_secs > 0 {
        format!("sleep {sleep_secs}; printf %s '{body_str}'")
    } else {
        format!("printf %s '{body_str}'")
    };
    let probe = OneProbe {
        content,
        declared_size: body.len() as u64,
        make: Box::new(move || ProbedSource::Process {
            program: PathBuf::from("sh"),
            args: vec![OsString::from("-c"), OsString::from(script.clone())],
        }),
    };
    CatalogNarSupplier::new(probe, "unused-helper")
}

#[tokio::test]
async fn process_source_is_served_across_two_nodes() {
    let scope = "nar-process";
    let body = b"raw NAR regenerated on demand by a process source, served over libp2p".to_vec();
    let content = Blake3Digest::from_raw_nar(&body);

    let (boot, boot_addr) = start_bootstrap(scope).await;
    let boot_peer = boot.peer_id;

    // Node A serves via a Process source. A serving FABRIC would own its supervisor; here
    // the server is built directly, so the test owns one and threads its handle in.
    let (node_a, _addr_a) = start_listening([21u8; 32], scope).await;
    let supervisor = TaskSupervisor::new();
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(process_supplier(content, &body, 0)),
        supervisor.handle(),
    );
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    join(&node_a, boot_peer, boot_addr.clone()).await;

    let (node_b, _addr_b) = start_listening([22u8; 32], scope).await;
    let transport = wire_consumer(&node_b, &node_a, boot_peer, boot_addr.clone()).await;
    let offer = TransportOffer::Iroh {
        node: node_a.node_id,
    };

    let bytes = transport
        .fetch(&content, &offer, Some(body.len() as u64), &envelope())
        .await
        .expect("a Process source is now SERVED off the poll loop (was Declined pre-TASK-193)");
    assert_eq!(
        bytes, body,
        "the served bytes are the process source's output"
    );
    assert_eq!(
        Blake3Digest::from_raw_nar(&bytes),
        content,
        "the served bytes hash to the announced content"
    );
}

#[tokio::test]
async fn a_slow_process_serve_does_not_block_the_poll_loop() {
    let scope = "nar-liveness";
    let body = b"slowly regenerated NAR bytes".to_vec();
    let content = Blake3Digest::from_raw_nar(&body);
    let expected_len = body.len() as u64;

    let (boot, boot_addr) = start_bootstrap(scope).await;
    let boot_peer = boot.peer_id;

    // A ~2s production: long enough that an INLINE (poll-loop-blocking) serve would clearly
    // delay a concurrent poll-loop command.
    let (node_a, _addr_a) = start_listening([23u8; 32], scope).await;
    let supervisor = TaskSupervisor::new();
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(process_supplier(content, &body, 2)),
        supervisor.handle(),
    );
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    join(&node_a, boot_peer, boot_addr.clone()).await;

    let (node_b, _addr_b) = start_listening([24u8; 32], scope).await;
    let transport = wire_consumer(&node_b, &node_a, boot_peer, boot_addr.clone()).await;
    let offer = TransportOffer::Iroh {
        node: node_a.node_id,
    };

    // Kick off the SLOW fetch (drives the ~2s off-loop production on A) without awaiting it.
    let fetch = tokio::spawn(async move {
        transport
            .fetch(&content, &offer, Some(expected_len), &envelope())
            .await
    });

    // Wait until the off-loop dump is PROVABLY in flight on A (its process job is live), so
    // the responsiveness check below is not a false pass on a request that has not arrived.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if supervisor.process_jobs().active_len() >= 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the off-loop serve never started producing"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // With a serve provably in flight, A's poll loop must STILL answer a command promptly.
    // If production ran inline on the loop, this would block for ~2s (the sleep).
    let started = Instant::now();
    let _addrs = node_a.handle.listen_addrs().await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "poll loop was blocked by an in-flight serve: listen_addrs took {elapsed:?}"
    );

    // And the slow fetch still completes with correct, hash-verified bytes.
    let bytes = fetch
        .await
        .expect("fetch task joins")
        .expect("the slow off-loop serve completes");
    assert_eq!(bytes, body);
    assert_eq!(Blake3Digest::from_raw_nar(&bytes), content);
}

/// AC#3 (TASK-191) - the byte-identity bite for the STORE-supply serve, at the two-swarm level.
/// A Process source (the `nix-store --dump` analogue) whose bytes NO LONGER hash to the announced
/// content - a store path REBUILT since it was announced, emitting DIFFERENT bytes of the SAME
/// length so the declared-size admission passes and ONLY the serve-time BLAKE3 recheck can catch
/// it - must fail the serve LOUD (the provider Declines, `SupplyFailed`), so the consumer's fetch
/// FAILS and it NEVER receives the wrong bytes under the right name. BITE: drop the
/// `BLAKE3(RawNarV1) == content` recheck in `produce_supervised` and the provider ships the
/// rebuilt bytes; the fetch then either succeeds with wrong bytes or trips the consumer's gate-1
/// IntegrityMismatch instead of this provider-side `Unavailable` decline.
#[tokio::test]
async fn a_rebuilt_store_source_is_declined_and_never_ships_wrong_bytes() {
    let scope = "nar-process-rebuilt";
    let announced = b"the exact raw NAR bytes announced under this content digest".to_vec();
    let content = Blake3Digest::from_raw_nar(&announced);
    // Same LENGTH, different bytes (flip every 'a'->'e', still quote-free ASCII): the size guard
    // passes and ONLY the serve-time BLAKE3 recheck can catch the drift.
    let rebuilt: Vec<u8> = announced
        .iter()
        .map(|&b| if b == b'a' { b'e' } else { b })
        .collect();
    assert_eq!(
        announced.len(),
        rebuilt.len(),
        "same length so only BLAKE3 bites"
    );
    assert_ne!(announced, rebuilt, "the rebuilt bytes must actually differ");
    let rebuilt_str = String::from_utf8(rebuilt.clone()).unwrap();

    let (boot, boot_addr) = start_bootstrap(scope).await;
    let boot_peer = boot.peer_id;

    let (node_a, _addr_a) = start_listening([25u8; 32], scope).await;
    let supervisor = TaskSupervisor::new();
    // The probe declares the ANNOUNCED content + size, but its Process regenerates the REBUILT
    // bytes - exactly a store path whose content drifted since it was announced.
    let probe = OneProbe {
        content,
        declared_size: announced.len() as u64,
        make: Box::new(move || ProbedSource::Process {
            program: PathBuf::from("sh"),
            args: vec![
                OsString::from("-c"),
                OsString::from(format!("printf %s '{rebuilt_str}'")),
            ],
        }),
    };
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(CatalogNarSupplier::new(probe, "unused-helper")),
        supervisor.handle(),
    );
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");
    join(&node_a, boot_peer, boot_addr.clone()).await;

    let (node_b, _addr_b) = start_listening([26u8; 32], scope).await;
    let transport = wire_consumer(&node_b, &node_a, boot_peer, boot_addr.clone()).await;
    let offer = TransportOffer::Iroh {
        node: node_a.node_id,
    };

    let err = transport
        .fetch(&content, &offer, Some(announced.len() as u64), &envelope())
        .await
        .expect_err("a rebuilt store source must fail the fetch, never ship wrong bytes");
    // The PROVIDER refused before shipping (serve-time recheck), so this is an `Unavailable`
    // decline - NOT a consumer-side `IntegrityMismatch` (no bytes were shipped to verify) and
    // certainly not a success. That is the whole point: the wrong bytes never left node A.
    match err {
        TransferError::Unavailable(why) => assert!(
            why.contains("declined") || why.to_lowercase().contains("produce"),
            "expected a supply-failed decline, got: {why}"
        ),
        other => panic!("expected an Unavailable decline (provider refused to ship), got {other}"),
    }
}

// -------------------------------------------------------------------------
// TASK-99 (codex DEEP-gate fix #5): LIVE 2-node coverage of the COMPRESSED path with payloads
// OVER the 1 KiB compress threshold, so the zstd link is ACTUALLY exercised (the earlier
// happy/corrupt tests use ~60 B bodies that fall back to RAW and never touch the codec). These
// use the direct `/nar/3` fetch so the byte path - serve_stream negotiates zstd, the fetcher
// decodes it - is the real one, over real libp2p streams.
// -------------------------------------------------------------------------

/// A >1 KiB compressible NAR body: large enough to clear the compress threshold (so serve_stream
/// negotiates zstd) and repetitive enough that the zstd frame is much smaller than the raw nar.
fn compressible_nar(tag: &str) -> Vec<u8> {
    format!("raw NAR body for {tag} that repeats so zstd shrinks the link a lot; ")
        .repeat(64)
        .into_bytes()
}

#[tokio::test]
async fn compressed_fetch_is_byte_identical_over_the_link() {
    let scope = "nar99-happy-zstd";
    let nar = compressible_nar("happy");
    assert!(nar.len() > 1024, "must exceed the compress threshold");
    let content = Blake3Digest::from_raw_nar(&nar);

    // Provider A: default codec policy (zstd on, level 3) -> the >1 KiB body is served COMPRESSED.
    let (node_a, addr_a) = start_listening([41u8; 32], scope).await;
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(MemoryNarSupplier::new([nar.clone()])),
        TaskSupervisorHandle::disconnected(),
    );
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");

    let (node_b, _addr_b) = start_listening([42u8; 32], scope).await;
    let bytes = direct_fetch(
        &node_b,
        node_a.peer_id,
        &addr_a,
        content,
        Some(nar.len() as u64),
    )
    .await
    .expect("compressed fetch succeeds over the real link");
    assert_eq!(
        bytes, nar,
        "the zstd-compressed link must decode to the byte-identical raw NAR"
    );
    assert_eq!(
        Blake3Digest::from_raw_nar(&bytes),
        content,
        "the frozen blob id is unchanged by link compression (AC#1)"
    );
}

#[tokio::test]
async fn corrupt_compressed_provider_is_rejected_over_the_link() {
    // A CORRUPT provider binds >1 KiB bytes that do NOT hash to the requested digest; the server
    // COMPRESSES them (a valid zstd frame of the wrong bytes), and the consumer decodes a clean
    // frame whose BLAKE3 mismatches -> gate-1 IntegrityMismatch. Proves the compressed path
    // fails closed on wrong content (not only the tiny-RAW path the old test covered).
    let scope = "nar99-corrupt-zstd";
    let honest = compressible_nar("honest");
    let requested = Blake3Digest::from_raw_nar(&honest);
    let corrupt = compressible_nar("CORRUPT-different-bytes"); // same shape, different content
    assert_ne!(honest, corrupt);
    assert!(corrupt.len() > 1024);

    let mut supplier = MemoryNarSupplier::new([]);
    supplier.insert_raw(requested, corrupt);

    let (node_a, addr_a) = start_listening([43u8; 32], scope).await;
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(supplier),
        TaskSupervisorHandle::disconnected(),
    );
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");

    let (node_b, _addr_b) = start_listening([44u8; 32], scope).await;
    let err = direct_fetch(&node_b, node_a.peer_id, &addr_a, requested, None)
        .await
        .expect_err("a corrupt compressed provider must not yield trusted bytes");
    match err {
        TransferError::IntegrityMismatch { expected, actual } => {
            assert_eq!(expected, requested);
            assert_ne!(actual, requested);
        }
        other => panic!("expected IntegrityMismatch over the compressed link, got {other}"),
    }
}

#[tokio::test]
async fn two_servers_at_different_levels_serve_one_blob_id() {
    // AC#1 END TO END: two independent nodes compress the SAME raw NAR at DIFFERENT zstd levels
    // (3 vs 19) -> DIFFERENT wire bytes, but the consumer decodes EITHER to the byte-identical
    // raw NAR and the SAME BLAKE3 blob id. So two holders with different compressor settings are
    // interchangeable sources for one content id. Custom levels are set by installing a
    // ServeGate with a codec policy directly (the serve seam carries only the budget).
    let scope = "nar99-two-levels";
    let nar = compressible_nar("shared-across-two-levels");
    let content = Blake3Digest::from_raw_nar(&nar);

    async fn provider_at_level(seed: u8, scope: &str, nar: &[u8], level: i32) -> (Node, Multiaddr) {
        let (node, addr) = start_listening([seed; 32], scope).await;
        let gate = Arc::new(
            ServeGate::new(
                ServeBudget::default(),
                Arc::new(MemoryNarSupplier::new([nar.to_vec()])),
                TaskSupervisorHandle::disconnected(),
            )
            .with_codec_policy(ServeCodecPolicy {
                level,
                ..ServeCodecPolicy::default()
            }),
        );
        node.handle.install_serve(gate).await;
        (node, addr)
    }

    let (node_lo, addr_lo) = provider_at_level(45, scope, &nar, 3).await;
    let (node_hi, addr_hi) = provider_at_level(46, scope, &nar, 19).await;

    let (consumer, _addr_c) = start_listening([47u8; 32], scope).await;

    let from_lo = direct_fetch(
        &consumer,
        node_lo.peer_id,
        &addr_lo,
        content,
        Some(nar.len() as u64),
    )
    .await
    .expect("fetch from the level-3 holder");
    let from_hi = direct_fetch(
        &consumer,
        node_hi.peer_id,
        &addr_hi,
        content,
        Some(nar.len() as u64),
    )
    .await
    .expect("fetch from the level-19 holder");

    assert_eq!(from_lo, nar, "level-3 holder decodes to the raw NAR");
    assert_eq!(from_hi, nar, "level-19 holder decodes to the raw NAR");
    assert_eq!(
        Blake3Digest::from_raw_nar(&from_lo),
        content,
        "level-3 holder serves the frozen blob id"
    );
    assert_eq!(
        Blake3Digest::from_raw_nar(&from_hi),
        content,
        "level-19 holder serves the SAME frozen blob id (different settings, one id)"
    );
}

// -------------------------------------------------------------------------
// TASK-99 (codex DEEP-gate fix #1/#5): LIVE adversarial `/nar/3` responders. A minimal bare
// libp2p-stream swarm writes attacker-chosen wire bytes the honest server never emits - a
// TRUNCATED zstd frame (the P0 case) and an UNKNOWN codec byte - and the consumer's real
// fetch path must fail CLOSED. See the module-top import note for why this needs no production
// change.
// -------------------------------------------------------------------------

/// Stand up a MINIMAL bare libp2p swarm (tcp+noise+yamux + a `libp2p_stream::Behaviour`) that
/// accepts `/nix-p2p/<scope>/nar/3` and, per inbound stream, reads the 33-byte request then
/// writes `response` verbatim and closes. Returns its PeerId + concrete listen address. The
/// swarm + accept tasks are detached; the `#[tokio::test]` runtime aborts them at test end (no
/// leak). Deliberately carries NO kad/identify (a direct dial needs neither), keeping the
/// duplicated swarm construction - the maintenance cost of this approach - as small as possible.
async fn spawn_adversary(scope: &str, seed: u8, response: Vec<u8>) -> (PeerId, Multiaddr) {
    let keypair = Keypair::ed25519_from_bytes([seed; 32]).expect("adversary keypair");
    let peer_id = keypair.public().to_peer_id();
    let proto = StreamProtocol::try_from_owned(format!("/nix-p2p/{scope}/nar/3"))
        .expect("nar protocol name");

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("tcp transport")
        .with_behaviour(|_key| {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(libp2p_stream::Behaviour::new())
        })
        .expect("stream behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let mut control = swarm.behaviour().new_control();
    let mut incoming = control.accept(proto).expect("accept /nar/3");
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .expect("listen");

    // Drive the swarm (so connections/muxing progress) and capture the first listen address.
    let (addr_tx, addr_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut addr_tx = Some(addr_tx);
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await
                && let Some(tx) = addr_tx.take()
            {
                let _ = tx.send(address);
            }
        }
    });

    // Per inbound `/nar/3` stream: read the 33-byte request, then ship the crafted response.
    tokio::spawn(async move {
        while let Some((_peer, mut stream)) = incoming.next().await {
            let response = response.clone();
            tokio::spawn(async move {
                let mut request = [0u8; 33];
                let _ = stream.read_exact(&mut request).await;
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
                let _ = stream.close().await;
            });
        }
    });

    let addr = addr_rx.await.expect("adversary reported a listen address");
    (peer_id, addr)
}

#[tokio::test]
async fn adversarial_truncated_zstd_frame_fails_the_fetch() {
    // The P0 case OVER A REAL LINK: a well-formed `Nar` header + zstd codec byte, then a valid
    // zstd frame with its tail CUT OFF. The consumer must fail CLOSED (the codec's finish() sees
    // the frame is not complete -> Unavailable), never accept a short/wrong NAR. The payload is
    // >1 KiB so the zstd path is genuinely exercised.
    let scope = "nar99-adv-trunc";
    let nar = compressible_nar("adversarial-truncation");
    assert!(nar.len() > 1024);
    let content = Blake3Digest::from_raw_nar(&nar);

    let frame = compress_zstd(&nar, 3).expect("compress");
    let truncated = &frame[..frame.len() - 6]; // drop the frame tail
    let mut response = vec![STATUS_NAR, CODEC_ZSTD];
    response.extend_from_slice(truncated);

    let (adv_peer, adv_addr) = spawn_adversary(scope, 51, response).await;

    let (consumer, _addr) = start_listening([52u8; 32], scope).await;
    let err = direct_fetch(
        &consumer,
        adv_peer,
        &adv_addr,
        content,
        Some(nar.len() as u64),
    )
    .await
    .expect_err("a truncated zstd frame over the link must fail the fetch");
    // Truncation is now rejected AT THE CODEC (finish -> Truncated -> Unavailable), never a
    // silent short NAR. (Pre-fix it could return the correct-but-short bytes and lean on gate-1.)
    match err {
        TransferError::Unavailable(_) | TransferError::IntegrityMismatch { .. } => {}
        other => panic!("expected the truncated fetch to fail closed, got {other}"),
    }
}

#[tokio::test]
async fn adversarial_unknown_codec_byte_fails_the_fetch() {
    // A `Nar` header followed by a codec byte that is neither raw (0) nor zstd (1): the consumer
    // must fail rather than guess a framing (AC#5), over the real link.
    let scope = "nar99-adv-codec";
    let content = Blake3Digest::from_bytes([0x9c; 32]);
    let response = vec![STATUS_NAR, 0x7f]; // 0x7f is not a known codec byte

    let (adv_peer, adv_addr) = spawn_adversary(scope, 53, response).await;

    let (consumer, _addr) = start_listening([54u8; 32], scope).await;
    let err = direct_fetch(&consumer, adv_peer, &adv_addr, content, Some(4096))
        .await
        .expect_err("an unknown codec byte over the link must fail the fetch");
    match err {
        TransferError::Unavailable(why) => assert!(
            why.contains("unknown NAR codec"),
            "expected an unknown-codec failure, got: {why}"
        ),
        other => panic!("expected Unavailable(unknown codec), got {other}"),
    }
}
