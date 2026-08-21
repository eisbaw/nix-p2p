//! The libp2p analogue of the iroh `s6-p2p` multi-node transfer test (TASK-151 pass
//! bar): a SERVING node A and a CONSUMER node B, two independent libp2p swarms over real
//! loopback TCP, prove that:
//!
//!   * B fetches a NAR from A over the shared swarm's Bao-authenticated
//!     `/nix-p2p/<scope>/nar/4` protocol and gets BYTE-IDENTICAL bytes - the
//!     default policy compresses each leaf on the LINK with zstd, decoded and
//!     authenticated back to the identical raw NAR on the fetch side;
//!   * a CORRUPT provider (bytes that do not hash to the requested digest) is rejected
//!     by fetch-side Bao authentication (`AuthenticationFailed`), never trusted;
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fabric_libp2p::{
    CatalogNarSupplier, CatalogProbe, FetchOutcome, Libp2pNodeLocator, Libp2pServer,
    Libp2pTransport, MemoryNarSupplier, Multiaddr, Node, NodeConfig, PeerId, ProbedSource,
    ProbedSupply, ServeDeriveAdmission, ServeGate,
};
use peer_fabric::{
    Blake3Digest, CODEC_ZSTD, ExposureLedger, Lookup, NarServer, NarTransfer, NodeLocator,
    ResolutionPolicy, SafetyEnvelope, ServeBudget, ServeCodecPolicy, TransferError, TransportOffer,
    TransportTag, compress_zstd,
};
use proc_supervisor::{TaskSupervisor, TaskSupervisorHandle};

// Live-adversary imports: a MINIMAL bare libp2p-stream swarm stood up IN THE TEST that
// writes attacker-chosen `/nar/4` bytes (truncated frame / bogus codec byte) the honest serve
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

/// The `/nar/4` `STATUS_NAR` response byte (private to `nar.rs`; re-stated for the adversary).
const STATUS_NAR: u8 = 1;
const COMPLETE: &[u8; 4] = b"N4OK";

/// Fetch `content` from a provider by its PeerId over the `/nar/4` path directly
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
    let node = Node::start(NodeConfig::new(seed).with_network_scope(scope)).expect("node starts");
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
    // No explicit peers and no known relays configured: these tests drive the kad
    // (PublicInfrastructure) direct-address path with no relay-circuit composition.
    let locator = Arc::new(Libp2pNodeLocator::new(
        consumer.handle.clone(),
        ledger,
        std::collections::BTreeMap::new(),
        Vec::new(),
    ));

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

/// TASK-218 finding 1 (the load-bearing boundary): the streaming fetch must ATTRIBUTE a
/// failure to BEFORE vs AFTER the substream opened, because the transport logs "NAR fetch
/// UNREACHABLE" (which the B2 relay-down oracle greps) ONLY on the never-opened path. This
/// LOCKS IN that a REACHABLE provider replying `NotHeld` is `OpenedThenFailed` (relay/dial
/// WORKED — NOT unreachable), while a peer with NO dialable address is `NotOpened` (a genuine
/// dial failure). MUTATION: revert `fetch_nar_streaming_attributed` to return `NotOpened` (or
/// a bare Err the transport treats as unreachable) for the post-open NotHeld and this fails.
#[tokio::test]
async fn fetch_attribution_distinguishes_dial_failure_from_post_open_not_held() {
    let scope = "nar-attribution";
    let held = b"the NAR bytes the provider actually holds".to_vec();
    let held_content = Blake3Digest::from_raw_nar(&held);
    let unheld_content = Blake3Digest::from_raw_nar(b"a DIFFERENT NAR the provider does NOT hold");

    // Provider A serves ONLY `held`, and is directly reachable by the consumer.
    let (node_a, addr_a) = start_listening([61u8; 32], scope).await;
    let server = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(MemoryNarSupplier::new([held.clone()])),
        TaskSupervisorHandle::disconnected(),
    );
    let _serve = server
        .serve(ServeBudget::default())
        .await
        .expect("serve starts");

    // Consumer B connects DIRECTLY to A (add_address + dial) - no DHT needed for this boundary.
    let (node_b, _addr_b) = start_listening([62u8; 32], scope).await;
    node_b
        .handle
        .add_address(node_a.peer_id, addr_a.clone())
        .await;
    let _ = node_b.handle.dial(addr_a.clone()).await;

    // (1) POST-OPEN: fetch content the REACHABLE provider does NOT hold. The substream OPENS
    //     (the provider is reached, the /nar/4 protocol negotiates) and the reply is NotHeld ->
    //     `OpenedThenFailed(NotHeld)`. This must NOT be classified as unreachable.
    let after_open = node_b
        .handle
        .fetch_nar_streaming_attributed(
            node_a.peer_id,
            unheld_content,
            None,
            Duration::from_secs(5),
            Duration::from_secs(5),
            true,
        )
        .await;
    match after_open {
        FetchOutcome::OpenedThenFailed(TransferError::NotHeld(c)) => assert_eq!(c, unheld_content),
        other => panic!(
            "a REACHABLE NotHeld provider must be OpenedThenFailed(NotHeld) (relay/dial worked) \
             - the transport must NOT log UNREACHABLE here; got {other:?}"
        ),
    }

    // (2) DIAL FAILURE: fetch from a peer the consumer has NO dialable address for. The
    //     substream NEVER opens -> `NotOpened` (the "unreachable" attribution the transport
    //     logs UNREACHABLE for). This is what a relay-down circuit dial produces.
    let unreachable_peer = Keypair::ed25519_from_bytes([99u8; 32])
        .expect("keypair")
        .public()
        .to_peer_id();
    let never_opened = node_b
        .handle
        .fetch_nar_streaming_attributed(
            unreachable_peer,
            held_content,
            None,
            Duration::from_secs(2),
            Duration::from_secs(2),
            true,
        )
        .await;
    assert!(
        matches!(never_opened, FetchOutcome::NotOpened(_)),
        "a peer with NO dialable address must be NotOpened (the UNREACHABLE attribution); \
         got {never_opened:?}"
    );
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
    assert_eq!(transport.tag(), TransportTag::Libp2p);
    let offer = TransportOffer::libp2p(node_a.node_id);

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
async fn corrupt_memory_provider_fails_before_shipping_a_v4_status() {
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
    let offer = TransportOffer::libp2p(node_a.node_id);

    let err = transport
        .fetch(&requested, &offer, None, &envelope())
        .await
        .expect_err("a corrupt provider must not yield trusted bytes");
    assert!(
        matches!(err, TransferError::Unavailable(ref why) if why.contains("before its status byte")),
        "the provider must authenticate memory supply before STATUS_NAR, got {err}"
    );
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
    let offer = TransportOffer::libp2p(node_a.node_id);

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
async fn a_large_over_bound_v4_response_is_rejected_from_its_exact_size_header() {
    // `/nar/4` declares exact RawNarV1 geometry in its fixed header. A signed 4-KiB bound
    // rejects this 1-MiB response before allocating a tree or accepting any Bao body byte.
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
    let offer = TransportOffer::libp2p(node_a.node_id);

    let signed_bound: u64 = 4 * 1024; // 4 KiB
    let err = transport
        .fetch(&content, &offer, Some(signed_bound), &envelope())
        .await
        .expect_err("a 1 MiB serve under a 4 KiB signed bound must fail at the v4 header");
    match err {
        TransferError::TooLarge { limit, streamed } => {
            assert_eq!(limit, signed_bound, "the abort limit is the signed bound");
            assert_eq!(
                streamed,
                nar.len() as u64,
                "TooLarge reports the untrusted declared raw_size, not bytes buffered"
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
    let offer = TransportOffer::libp2p(node_a.node_id);

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
    let offer = TransportOffer::libp2p(node_a.node_id);

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

/// TASK-78 leech serve-barrier (the AIRTIGHT peer-side proof): a LEECH node is one on which
/// NO serve gate was ever installed (a pure consumer; on the seam, `PeerFabric::server()` is
/// `None`, so nothing can start the serve lifecycle). This test proves the peer-observable
/// consequence DIRECTLY, at the swarm boundary and INDEPENDENTLY of discovery: a consumer that
/// has the leech's exact dial address (the "told the leech is a provider" case - `add_address` +
/// `dial` in `direct_fetch`) and asks for content the leech holds gets `NotHeld` - the leech's
/// inbound `/nar/4` handler answers "not held" for EVERY request because its serve slot is empty
/// (`nar.rs`: `None => NarResponse::NotHeld`). So a peer cannot obtain bytes from a leech by ANY
/// path: not via the DHT (a leech never announces, so there is no record to find), and not via a
/// direct dial (this test). MUTATION: install a serve gate on the "leech" (make it serve) and the
/// `NotHeld` assertion reddens - the `dropping_the_serve_handle_stops_admission` test above is the
/// live proof that WITH a gate the very same fetch succeeds.
#[tokio::test]
async fn a_leech_serves_nothing_to_a_reachable_peer() {
    let scope = "nar-leech";
    // The leech has, in the field, FETCHED this content (it holds it in its nix store) - but it
    // installs no serve gate, so it cannot hand it out. We model "content the leech holds" by the
    // digest a peer would request; the leech's answer must be NotHeld regardless.
    let held = b"content a leech fetched but must never serve".to_vec();
    let held_content = Blake3Digest::from_raw_nar(&held);

    // The LEECH: a listening node with NO `Libp2pServer::serve()` ever called on it. Its inbound
    // serve slot stays empty for the whole test.
    let (leech, leech_addr) = start_listening([78u8; 32], scope).await;

    // A peer that is handed the leech's EXACT address (out-of-band "told it is a provider") and
    // asks for the content the leech holds.
    let (peer, _peer_addr) = start_listening([79u8; 32], scope).await;
    let outcome = direct_fetch(
        &peer,
        leech.peer_id,
        &leech_addr,
        held_content,
        Some(held.len() as u64),
    )
    .await;
    let err = outcome.expect_err("a leech must serve NOTHING even to a peer holding its address");
    assert!(
        matches!(err, TransferError::NotHeld(_)),
        "a reachable leech must answer NotHeld to every request (no serve gate installed); got {err}"
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
    let offer = TransportOffer::libp2p(node_a.node_id);

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
    let offer = TransportOffer::libp2p(node_a.node_id);

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

// -------------------------------------------------------------------------
// TASK-297: the per-authenticated-PeerId regenerate AMPLIFICATION cap on the shipped serve path.
// A Process-backed serve re-runs the expensive `nix-store --dump` regenerate on EVERY request
// (nothing held at rest, no produced-byte cache), so a hostile peer that opens repeated exact-key
// serve requests would otherwise drive UNBOUNDED regenerate work. The gate now charges each cold
// regenerate against a per-authenticated-PeerId budget (TASK-229's ledger, injected through the
// `ServeDeriveAdmission` seam) and DECLINES once a peer is over budget.
// -------------------------------------------------------------------------

/// A faithful stand-in for the per-authenticated-PeerId regenerate budget: it caps each distinct
/// [`PeerId`] to `per_peer_cap` admitted regenerates per process (the shipped
/// `daemon_core::PeerDeriveLedger` additionally enforces a BYTE ceiling, a global ceiling, and a
/// tumbling window; the per-peer COUNT cap is enough to bite this end-to-end oracle). It records
/// how often the gate consulted it, so a refusal can be ATTRIBUTED to the budget rather than to
/// some unrelated failure.
struct CountingDeriveAdmission {
    per_peer_cap: u32,
    charged: std::sync::Mutex<std::collections::HashMap<PeerId, u32>>,
    consulted: std::sync::atomic::AtomicU64,
    /// The dump-execution count of the most recent consultation, so the test can assert the gate
    /// charges [`fabric_libp2p::SERVE_DUMP_PASSES`] (2) per serve, not 1.
    last_dumps: std::sync::atomic::AtomicU32,
}

impl CountingDeriveAdmission {
    fn new(per_peer_cap: u32) -> Self {
        CountingDeriveAdmission {
            per_peer_cap,
            charged: std::sync::Mutex::new(std::collections::HashMap::new()),
            consulted: std::sync::atomic::AtomicU64::new(0),
            last_dumps: std::sync::atomic::AtomicU32::new(0),
        }
    }
    fn consultations(&self) -> u64 {
        self.consulted.load(Ordering::Relaxed)
    }
    fn last_dumps(&self) -> u32 {
        self.last_dumps.load(Ordering::Relaxed)
    }
}

impl ServeDeriveAdmission for CountingDeriveAdmission {
    fn admit_regenerate(&self, peer: &PeerId, _nar_bytes: u64, dumps: u32) -> bool {
        self.consulted.fetch_add(1, Ordering::Relaxed);
        self.last_dumps.store(dumps, Ordering::Relaxed);
        // Charge `dumps` executions against this peer's count budget (the real serve passes 2).
        let mut charged = self.charged.lock().expect("charged map");
        let count = charged.entry(*peer).or_insert(0);
        if count.saturating_add(dumps) > self.per_peer_cap {
            return false; // over this peer's per-peer regenerate budget: REFUSE, charge nothing
        }
        *count += dumps;
        true
    }
}

/// AC#2 (the adversarial, negative-control oracle): a hostile peer that floods a provider with
/// repeated exact-key REGENERATE requests is REFUSED once it exceeds its per-authenticated-PeerId
/// budget, the refusal is ATTRIBUTABLE to the budget (the gate consulted it and a DISTINCT peer is
/// unaffected), and the bound is LOAD-BEARING (the SAME flood against a provider with NO budget
/// wired serves unbounded). This exercises the WHOLE shipped serve path over two real libp2p nodes:
/// accept loop -> `serve_stream` -> `ServeGate::admit` -> the per-peer derive charge -> decline.
///
/// MUTATION (proven inline by the negative control below, not just documented): remove the
/// `set_derive_admission` wiring (or set the cap unbounded) and the second regenerate from the same
/// peer is served -> the `second.is_err()` assertion reddens. The charge is what makes it bite.
#[tokio::test]
async fn serve_declines_a_per_peer_regenerate_flood_and_the_bound_is_load_bearing() {
    let scope = "nar-derive-budget";
    let body = b"raw NAR regenerated on demand, charged against the per-peer amplification budget"
        .to_vec();
    let content = Blake3Digest::from_raw_nar(&body);
    let size = Some(body.len() as u64);

    // ---- ARMED provider A: a per-peer regenerate cap of 2 dump EXECUTIONS = exactly ONE serve
    // (each `/nar/4` serve is a two-pass regeneration, so it charges SERVE_DUMP_PASSES == 2). ----
    let (node_a, addr_a) = start_listening([41u8; 32], scope).await;
    let supervisor_a = TaskSupervisor::new();
    let admission = Arc::new(CountingDeriveAdmission::new(2));
    let server_a = Libp2pServer::new(
        node_a.handle.clone(),
        Arc::new(process_supplier(content, &body, 0)),
        supervisor_a.handle(),
    );
    server_a.set_derive_admission(admission.clone() as Arc<dyn ServeDeriveAdmission>);
    let _serve_a = server_a
        .serve(ServeBudget::default())
        .await
        .expect("armed serve starts");

    // Consumer B (ONE authenticated PeerId): first regenerate admitted, SECOND declined (over its
    // per-peer budget). Each `direct_fetch` opens a fresh `/nar/4` stream -> a fresh authenticated
    // admit -> a fresh charge, so B's two requests aggregate against B's single-regenerate budget.
    let (node_b, _addr_b) = start_listening([42u8; 32], scope).await;
    let first = direct_fetch(&node_b, node_a.peer_id, &addr_a, content, size).await;
    assert_eq!(
        first.expect("the FIRST regenerate is within the per-peer budget"),
        body,
        "the first regenerate serves the process source's bytes"
    );
    let second = direct_fetch(&node_b, node_a.peer_id, &addr_a, content, size).await;
    // The failure must be AT the budget boundary: a serve-side DECLINE (the gate refused the
    // regenerate), not an unrelated dial/transport error. A Declined(Busy) response surfaces to the
    // fetcher as `Unavailable(... "declined" ...)`, exactly as the per-NAR ServeBudget decline does.
    match second {
        Err(TransferError::Unavailable(why)) => assert!(
            why.contains("declined"),
            "the second regenerate must be refused by a serve DECLINE (the derive budget biting), \
             got Unavailable({why})"
        ),
        other => panic!(
            "the SECOND regenerate from the SAME authenticated peer must be DECLINED (over its \
             per-peer amplification budget), not served or failed otherwise; got {other:?}"
        ),
    }

    // Consumer C (a DISTINCT authenticated PeerId): its FIRST regenerate is admitted, proving the
    // budget is truly PER-PEER - B exhausting its own allowance cannot spend C's (nor a global one).
    let (node_c, _addr_c) = start_listening([43u8; 32], scope).await;
    let c_first = direct_fetch(&node_c, node_a.peer_id, &addr_a, content, size).await;
    assert_eq!(
        c_first.expect("a DISTINCT peer has its OWN budget"),
        body,
        "one peer's exhausted budget must NOT decline a different authenticated peer"
    );

    // Attribution: the gate consulted the derive budget on every cold regenerate (B's admitted
    // first + C's admitted first; B's second was refused by the fake before this counter... so at
    // least the two admitted serves consulted it), so the decline is the BUDGET biting - not an
    // unrelated transport/supply failure.
    assert!(
        admission.consultations() >= 2,
        "the serve gate must consult the per-peer derive budget on every regenerate; saw {}",
        admission.consultations()
    );
    // HIGH-3: each serve charges SERVE_DUMP_PASSES (2) dump executions, not 1 - the two-pass
    // regeneration is accounted at its real cost.
    assert_eq!(
        admission.last_dumps(),
        fabric_libp2p::SERVE_DUMP_PASSES,
        "a /nar serve must charge both regeneration passes (2), not one"
    );

    // ---- NEGATIVE CONTROL (the mutation, run inline): NO budget wired -> the SAME flood is served
    // unbounded, proving the charge above is what makes the bound bite. ----
    let (node_d, addr_d) = start_listening([44u8; 32], scope).await;
    let supervisor_d = TaskSupervisor::new();
    let server_d = Libp2pServer::new(
        node_d.handle.clone(),
        Arc::new(process_supplier(content, &body, 0)),
        supervisor_d.handle(),
    );
    // Deliberately NOT calling set_derive_admission: this is the "budget reverted / unbounded" arm.
    let _serve_d = server_d
        .serve(ServeBudget::default())
        .await
        .expect("unbounded serve starts");
    let (node_e, _addr_e) = start_listening([45u8; 32], scope).await;
    let e_first = direct_fetch(&node_e, node_d.peer_id, &addr_d, content, size).await;
    let e_second = direct_fetch(&node_e, node_d.peer_id, &addr_d, content, size).await;
    assert_eq!(
        e_first.expect("unbounded regenerate #1"),
        body,
        "with no budget wired the first regenerate serves"
    );
    assert_eq!(
        e_second.expect("unbounded regenerate #2 (the load-bearing control)"),
        body,
        "with NO per-peer budget the SAME peer's second regenerate is served unbounded - so the \
         armed provider's decline above is attributable to the budget, not to the workload"
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
    let offer = TransportOffer::libp2p(node_a.node_id);

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
/// length so declared-size admission passes and ONLY pass-1 root verification can catch it - must
/// fail the serve before `STATUS_NAR`, so the consumer NEVER receives wrong bytes under the right
/// name. BITE: drop pass-1 root verification and the provider starts an unauthenticatable v4
/// response, moving detection to the consumer after response status instead of failing at source.
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
    let offer = TransportOffer::libp2p(node_a.node_id);

    let err = transport
        .fetch(&content, &offer, Some(announced.len() as u64), &envelope())
        .await
        .expect_err("a rebuilt store source must fail the fetch, never ship wrong bytes");
    // Pass 1 checks the regenerated root before STATUS_NAR, so the wrong bytes never leave A.
    assert!(
        matches!(err, TransferError::Unavailable(ref why) if why.contains("before its status byte")),
        "rebuilt pass 1 must close before STATUS_NAR, got {err}"
    );
}

// -------------------------------------------------------------------------
// TASK-99 (codex DEEP-gate fix #5): LIVE 2-node coverage of the COMPRESSED path with payloads
// OVER the 1 KiB compress threshold, so the zstd link is ACTUALLY exercised (the earlier
// happy/corrupt tests use ~60 B bodies that fall back to RAW and never touch the codec). These
// use the direct `/nar/4` fetch so the byte path - serve_stream selects per-leaf zstd, the fetcher
// decodes and authenticates it - is the real one, over real libp2p streams.
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
async fn corrupt_compressed_memory_provider_fails_before_shipping_a_v4_status() {
    // A corrupt provider binds >1 KiB bytes under another digest. V4 prepares and checks its
    // Bao root before the status/codec decision, so not even a compressed leaf crosses the link.
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
    assert!(
        matches!(err, TransferError::Unavailable(ref why) if why.contains("before its status byte")),
        "the provider must reject the bad root before compressed v4 delivery, got {err}"
    );
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
// TASK-99/TASK-197: LIVE adversarial `/nar/4` responders. A minimal bare
// libp2p-stream swarm writes attacker-chosen wire bytes the honest server never emits - a
// TRUNCATED zstd frame (the P0 case) and an UNKNOWN codec byte - and the consumer's real
// fetch path must fail CLOSED. See the module-top import note for why this needs no production
// change.
// -------------------------------------------------------------------------

/// Stand up a MINIMAL bare libp2p swarm (tcp+noise+yamux + a `libp2p_stream::Behaviour`) that
/// accepts `/nix-p2p/<scope>/nar/4` and, per inbound stream, reads the 33-byte request then
/// writes `response` verbatim and closes. Returns its PeerId + concrete listen address. The
/// swarm + accept tasks are detached; the `#[tokio::test]` runtime aborts them at test end (no
/// leak). Deliberately carries NO kad/identify (a direct dial needs neither), keeping the
/// duplicated swarm construction - the maintenance cost of this approach - as small as possible.
async fn spawn_adversary(scope: &str, seed: u8, response: Vec<u8>) -> (PeerId, Multiaddr) {
    spawn_protocol_adversary(scope, seed, 4, response, Arc::new(AtomicUsize::new(0))).await
}

async fn spawn_protocol_adversary(
    scope: &str,
    seed: u8,
    version: u8,
    response: Vec<u8>,
    accepted: Arc<AtomicUsize>,
) -> (PeerId, Multiaddr) {
    let keypair = Keypair::ed25519_from_bytes([seed; 32]).expect("adversary keypair");
    let peer_id = keypair.public().to_peer_id();
    let proto = StreamProtocol::try_from_owned(format!("/nix-p2p/{scope}/nar/{version}"))
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
    let mut incoming = control
        .accept(proto)
        .expect("accept adversary NAR protocol");
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

    // Per inbound `/nar/4` stream: read the 33-byte request, then ship the crafted response.
    tokio::spawn(async move {
        while let Some((_peer, _conn, mut stream)) = incoming.next().await {
            accepted.fetch_add(1, Ordering::SeqCst);
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
    // The P0 case OVER A REAL LINK: a well-formed v4 header and one-leaf length prefix, then a
    // valid independent zstd leaf frame with its tail CUT OFF. The consumer must fail closed
    // before exposing that leaf. The payload is <64 KiB, so its Bao full-range proof is empty.
    let scope = "nar99-adv-trunc";
    let nar = compressible_nar("adversarial-truncation");
    assert!(nar.len() > 1024);
    let content = Blake3Digest::from_raw_nar(&nar);

    let frame = compress_zstd(&nar, 3).expect("compress");
    assert!(nar.len() < 64 * 1024, "one-leaf adversary fixture");
    let truncated = &frame[..frame.len() - 6];
    let mut response = vec![STATUS_NAR, CODEC_ZSTD];
    response.extend_from_slice(&(nar.len() as u64).to_le_bytes());
    response.extend_from_slice(&(frame.len() as u32).to_le_bytes());
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
    assert!(
        matches!(
            err,
            TransferError::AuthenticationFailed { .. } | TransferError::Unavailable(_)
        ),
        "truncated encoded leaf must fail at v4 framing/authentication, got {err}"
    );
}

#[tokio::test]
async fn adversarial_unknown_codec_byte_fails_the_fetch() {
    // A `Nar` header followed by a codec byte that is neither raw (0) nor zstd (1): the consumer
    // must fail rather than guess a framing (AC#5), over the real link.
    let scope = "nar99-adv-codec";
    let content = Blake3Digest::from_bytes([0x9c; 32]);
    let mut response = vec![STATUS_NAR, 0x7f]; // 0x7f is not a known codec byte
    response.extend_from_slice(&4096u64.to_le_bytes());

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

#[tokio::test]
async fn adversarial_provider_cannot_select_a_codec_the_request_did_not_offer() {
    let scope = "nar4-adv-unoffered-codec";
    let content = Blake3Digest::from_bytes([0x7b; 32]);
    let mut response = vec![STATUS_NAR, CODEC_ZSTD];
    response.extend_from_slice(&0u64.to_le_bytes());
    response.extend_from_slice(COMPLETE);
    let (adv_peer, adv_addr) = spawn_adversary(scope, 55, response).await;
    let (consumer, _addr) = start_listening([56u8; 32], scope).await;
    consumer
        .handle
        .add_address(adv_peer, adv_addr.clone())
        .await;
    consumer
        .handle
        .dial(adv_addr)
        .await
        .expect("dial adversary");

    let error = consumer
        .handle
        .fetch_nar_streaming_measured(
            adv_peer,
            content,
            Some(0),
            Duration::from_secs(5),
            Duration::from_secs(5),
            false,
        )
        .await
        .expect_err("raw-only request must reject a selected zstd response");
    assert!(
        matches!(error, TransferError::Unavailable(ref why) if why.contains("did not offer")),
        "selected codec outside the accept mask must fail explicitly, got {error}"
    );
}

#[tokio::test]
async fn v3_only_peer_is_protocol_incompatible_and_v3_is_never_opened() {
    let scope = "nar4-no-v3-downgrade";
    let accepted_v3 = Arc::new(AtomicUsize::new(0));
    let (old_peer, old_addr) =
        spawn_protocol_adversary(scope, 57, 3, vec![0], Arc::clone(&accepted_v3)).await;
    let (consumer, _addr) = start_listening([58u8; 32], scope).await;
    consumer
        .handle
        .add_address(old_peer, old_addr.clone())
        .await;
    consumer
        .handle
        .dial(old_addr)
        .await
        .expect("dial v3-only peer");

    let outcome = consumer
        .handle
        .fetch_nar_streaming_attributed(
            old_peer,
            Blake3Digest::from_bytes([0x4d; 32]),
            Some(1),
            Duration::from_secs(5),
            Duration::from_secs(5),
            false,
        )
        .await;
    assert!(
        matches!(outcome, FetchOutcome::ProtocolIncompatible(_)),
        "a reached v3-only peer must be classified as protocol-incompatible, got {outcome:?}"
    );
    tokio::task::yield_now().await;
    assert_eq!(
        accepted_v3.load(Ordering::SeqCst),
        0,
        "the consumer must never attempt a /nar/3 downgrade"
    );
}
