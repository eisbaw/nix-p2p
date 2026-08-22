//! TASK-297 HIGH-4 / HIGH-5 / HIGH-3 / HIGH-2: the PRODUCTION wiring + charge-at-spawn bites.
//!
//! `wire_disclose_serve_provider` is the ONE helper BOTH shipped provider binaries (the thin
//! `daemon-libp2p` and the composite `daemon`, the flake DEFAULT) call to run the ordered
//! wire -> disclose -> serve sequence that caps per-authenticated-PeerId serve amplification. These
//! tests drive a REAL two-node `/nar` serve through that helper over the REAL [`PeerDeriveLedger`]:
//!
//!   * HIGH-4: the helper snapshots the derive-admission `OnceLock` at serve activation, so the cap
//!     MUST be wired before serve. Driving the SHARED helper (not a bespoke wire-then-serve in the
//!     test) means SWAPPING its internal wire/serve order — exactly the reorder a callsite could make
//!     — leaves the provider uncapped and reddens the decline assertion. An inline NEGATIVE CONTROL
//!     (a provider wired with an UNBOUNDED budget) serves the same flood, so the armed provider's
//!     decline is attributable to the wired budget.
//!   * HIGH-5: the bound that bites is the per-peer BYTE ceiling (few large-ish serves), not a
//!     request count - a charge-0 / charge-wrong-size mutation reddens the `global_bytes_used`
//!     assertion.
//!   * HIGH-3: one serve charges BOTH regeneration passes, so `global_bytes_used() == 2 * declared`.
//!   * HIGH-2 (charge-at-spawn, never refund): a serve cancelled mid-dump STAYS charged; a node-side
//!     start-failure is charged at the spawn too (the only over-charge, harmless + not peer-inducible).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daemon_core::DeriveBudget;
use daemon_core::content_id::Blake3Digest;
use daemon_libp2p::wire_disclose_serve_provider;
use fabric_libp2p::{
    CatalogNarSupplier, CatalogProbe, Libp2pFabric, Multiaddr, Node, NodeConfig, PeerId,
    ProbedSource, ProbedSupply,
};
use peer_fabric::{ServeBudget, TransferError};

/// A one-content catalog probe returning a fixed [`ProbedSupply`] (mirrors nar_transport's helper).
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

/// A supplier whose one digest regenerates `body` via `sh -c printf` (a Process source, the
/// store-dump analogue: nothing held at rest, re-run on EVERY request - the amplification surface).
fn process_supplier(content: Blake3Digest, body: &[u8]) -> CatalogNarSupplier {
    let body_str = String::from_utf8(body.to_vec()).expect("ascii test body");
    let script = format!("printf %s '{body_str}'");
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

/// A supplier whose one digest declares `declared_size` bytes (so codec negotiation runs and the
/// SPAWN is reached) but whose Process source names a program that does NOT exist, so the serve fails
/// at process START. TASK-297 charge-at-spawn: the charge is taken at the spawn point (after the Bao
/// permit, before exec), so this is CHARGED - the node-side start-failure over-charge (harmless
/// self-limit; a missing binary is node misconfig, not peer-inducible).
fn failing_process_supplier(content: Blake3Digest, declared_size: u64) -> CatalogNarSupplier {
    let probe = OneProbe {
        content,
        declared_size,
        make: Box::new(|| ProbedSource::Process {
            program: PathBuf::from("nix-p2p-nonexistent-serve-program-for-charge-at-spawn"),
            args: Vec::new(),
        }),
    };
    CatalogNarSupplier::new(probe, "unused-helper")
}

/// A supplier whose one digest declares `declared_size` bytes but whose Process source emits ONE byte
/// then BLOCKS forever, so pass-1 never completes and the serve is CANCELLED at its absolute deadline
/// - AFTER the spawn charge. Models a serve cancelled mid-dump (incl. the small-NAR case).
fn blocking_process_supplier(content: Blake3Digest, declared_size: u64) -> CatalogNarSupplier {
    let probe = OneProbe {
        content,
        declared_size,
        make: Box::new(|| ProbedSource::Process {
            program: PathBuf::from("sh"),
            args: vec![OsString::from("-c"), OsString::from("printf x; sleep 30")],
        }),
    };
    CatalogNarSupplier::new(probe, "unused-helper")
}

/// A supplier that declares `requested` but whose Process source EMITS `emitted` (a DIFFERENT
/// content), so the dump runs but pass-1 rejects the root. Charged at the spawn (TASK-297), so the
/// charge STICKS even though the serve fails.
fn stale_root_process_supplier(requested: Blake3Digest, emitted: &[u8]) -> CatalogNarSupplier {
    let body_str = String::from_utf8(emitted.to_vec()).expect("ascii test body");
    let script = format!("printf %s '{body_str}'");
    let probe = OneProbe {
        content: requested,
        declared_size: emitted.len() as u64,
        make: Box::new(move || ProbedSource::Process {
            program: PathBuf::from("sh"),
            args: vec![OsString::from("-c"), OsString::from(script.clone())],
        }),
    };
    CatalogNarSupplier::new(probe, "unused-helper")
}

async fn provider_addr(fabric: &Libp2pFabric) -> Multiaddr {
    fabric
        .handle()
        .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .await
        .expect("listen bound");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(addr) = fabric.handle().listen_addrs().await.into_iter().next() {
            return addr;
        }
        assert!(Instant::now() < deadline, "no listen address bound in time");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// One direct `/nar/4` fetch from `provider` by PeerId (add_address + dial + fetch), no DHT.
async fn direct_fetch(
    consumer: &Node,
    provider_peer: PeerId,
    provider_addr: &Multiaddr,
    content: Blake3Digest,
    expected_size: u64,
) -> Result<Vec<u8>, TransferError> {
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
            Some(expected_size),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
}

fn budget(per_peer_bytes: u64) -> DeriveBudget {
    DeriveBudget {
        max_bytes_per_peer_uncompressed_nar: per_peer_bytes,
        max_dumps_per_peer: 1000, // generous: BYTES are the binding bound here
        max_bytes_global_uncompressed_nar: 1 << 40,
        max_dumps_global: u32::MAX,
        window: Duration::from_secs(60),
    }
}

/// The shipped production wiring caps a real two-node serve flood by the per-peer BYTE ceiling, the
/// charge is exactly two passes, and the bound is load-bearing (an unbounded-budget control serves
/// the same flood).
#[tokio::test]
async fn production_wiring_caps_a_real_serve_flood_by_the_byte_ceiling() {
    let scope = "task297-serve-wiring";
    let body =
        b"raw NAR regenerated on demand by a process source, charged against the real ledger"
            .to_vec();
    let content = Blake3Digest::from_raw_nar(&body);
    let declared = body.len() as u64;

    // ---- ARMED provider: wired via the REAL helper with a per-peer byte budget for ONE serve
    // (2*declared) plus slack, but less than TWO (4*declared). ----
    let provider = Libp2pFabric::start_with_supplier(
        NodeConfig::new([41u8; 32]).with_network_scope(scope),
        Arc::new(process_supplier(content, &body)),
    )
    .expect("armed provider starts");
    let addr = provider_addr(&provider).await;
    // Drive the SHARED wire -> disclose -> serve helper (the exact sequence both binaries run), so a
    // reorder of its internal wire/serve steps (which would ship an UNCAPPED provider) reddens here.
    let (ledger, _serve) = wire_disclose_serve_provider(
        &provider,
        budget(3 * declared),
        ServeBudget::default(),
        || {},
    )
    .await
    .expect("the production wire->disclose->serve helper caps the provider");

    // Consumer B (one authenticated PeerId): serve #1 admitted, serve #2 refused ON BYTES.
    let node_b = Node::start(NodeConfig::new([42u8; 32]).with_network_scope(scope))
        .expect("consumer starts");
    let first = direct_fetch(&node_b, provider.peer_id(), &addr, content, declared).await;
    assert_eq!(
        first.expect("the first serve is within the per-peer byte budget"),
        body,
        "the first serve regenerates the process source's bytes"
    );
    // HIGH-3: exactly ONE serve was admitted and it charged BOTH passes -> 2*declared, not declared.
    assert_eq!(
        ledger.global_bytes_used(),
        2 * declared,
        "one serve must charge BOTH regeneration passes (2*declared bytes); a value of `declared` \
         means the 2x amplification is under-counted (HIGH-3)"
    );
    let second = direct_fetch(&node_b, provider.peer_id(), &addr, content, declared).await;
    match second {
        Err(TransferError::Unavailable(why)) => assert!(
            why.contains("declined"),
            "the second serve must be refused by a serve DECLINE (the per-peer BYTE ceiling biting: \
             4*declared > 3*declared), got Unavailable({why})"
        ),
        other => panic!(
            "the second serve from the SAME peer must be DECLINED on the per-peer byte ceiling; \
             got {other:?}"
        ),
    }

    // Per-peer isolation: a DISTINCT authenticated peer still serves (its own window is untouched).
    let node_c = Node::start(NodeConfig::new([43u8; 32]).with_network_scope(scope))
        .expect("second consumer starts");
    let c_first = direct_fetch(&node_c, provider.peer_id(), &addr, content, declared).await;
    assert_eq!(
        c_first.expect("a distinct authenticated peer has its OWN per-peer byte window"),
        body,
        "one peer's exhausted byte budget must not decline a different authenticated peer"
    );

    // ---- NEGATIVE CONTROL (load-bearing): the SAME helper with an UNBOUNDED budget serves the same
    // peer's flood without limit -> the armed decline above is attributable to the wired budget, and
    // neutering the helper's set (leaving the fabric unwired) would likewise serve unbounded. ----
    let unbounded = Libp2pFabric::start_with_supplier(
        NodeConfig::new([44u8; 32]).with_network_scope(scope),
        Arc::new(process_supplier(content, &body)),
    )
    .expect("unbounded provider starts");
    let unbounded_addr = provider_addr(&unbounded).await;
    let (_unbounded_ledger, _unbounded_serve) =
        wire_disclose_serve_provider(&unbounded, budget(u64::MAX), ServeBudget::default(), || {})
            .await
            .expect("the helper wires + serves the unbounded provider");
    let node_e = Node::start(NodeConfig::new([45u8; 32]).with_network_scope(scope))
        .expect("control consumer starts");
    let e1 = direct_fetch(
        &node_e,
        unbounded.peer_id(),
        &unbounded_addr,
        content,
        declared,
    )
    .await;
    let e2 = direct_fetch(
        &node_e,
        unbounded.peer_id(),
        &unbounded_addr,
        content,
        declared,
    )
    .await;
    assert_eq!(e1.expect("unbounded serve #1"), body);
    assert_eq!(
        e2.expect("unbounded serve #2 (the load-bearing control)"),
        body,
        "with an unbounded per-peer budget the SAME peer's second serve is served - so the armed \
         provider's decline is attributable to the wired budget, not to the workload"
    );
}

/// TASK-297 charge-at-spawn (oracle 1, the exploit closer): a serve that is CANCELLED mid-dump STAYS
/// CHARGED over the REAL ledger. The child emits one byte then BLOCKS, so pass-1 never completes and
/// the serve is cancelled at its absolute deadline - but the charge was already taken at the SPAWN, so
/// `global_bytes_used()` stays 2*declared. There is no refund path, so cancellation timing (including
/// the 32 KiB in-child-buffer window that defeated the observe-output designs) is irrelevant.
///
/// MUTATION: add back ANY refund-on-cancel (reintroduce a reserve/commit/release lifecycle) and this
/// reddens - a cancelled serve would drop back to 0, re-opening the timed-cancel exploit.
#[tokio::test]
async fn a_serve_cancelled_mid_dump_stays_charged() {
    let scope = "task297-cancel-stays-charged";
    let declared: u64 = 64; // declared larger than the one byte emitted, so pass-1 blocks
    let content = Blake3Digest::from_raw_nar(b"a digest whose source emits one byte then blocks");

    let provider = Libp2pFabric::start_with_supplier(
        NodeConfig::new([51u8; 32]).with_network_scope(scope),
        Arc::new(blocking_process_supplier(content, declared)),
    )
    .expect("provider starts");
    let addr = provider_addr(&provider).await;
    // A short serve deadline so the blocked pass-1 is cancelled promptly, AFTER the spawn charge.
    let serve_budget = ServeBudget {
        max_serve_duration: Duration::from_millis(600),
        ..ServeBudget::default()
    };
    let (ledger, _serve) =
        wire_disclose_serve_provider(&provider, budget(1 << 40), serve_budget, || {})
            .await
            .expect("wire->disclose->serve helper installs");

    let consumer = Node::start(NodeConfig::new([52u8; 32]).with_network_scope(scope))
        .expect("consumer starts");

    // The serve spawns (CHARGED), then pass-1 blocks and the serve is cancelled at the deadline. The
    // fetch fails, but the charge STAYS - never refunded.
    let fetched = direct_fetch(&consumer, provider.peer_id(), &addr, content, declared).await;
    assert!(
        fetched.is_err(),
        "a serve cancelled mid-dump fails the fetch, but is still charged"
    );
    assert_eq!(
        ledger.global_bytes_used(),
        2 * declared,
        "a spawned regenerate cancelled mid-dump STAYS charged (2*declared); a drop to 0 would mean a          refund re-opened the timed-cancel exploit"
    );
}

/// TASK-297 charge-at-spawn: a NODE-SIDE start-failure (the program does not exist) reaches the spawn
/// point, so it is CHARGED. This is the design's only over-charge - a harmless self-limit, since a
/// missing `nix-store` binary is node misconfig (the node serves nothing anyway) and is not
/// peer-inducible for repeated free work. The point is the SYMMETRY with cancel: there is no refund.
#[tokio::test]
async fn a_node_side_start_failure_is_charged_at_spawn() {
    let scope = "task297-start-failure-charged";
    let declared: u64 = 4096;
    let content =
        Blake3Digest::from_raw_nar(b"known digest whose regenerate program does not exist");

    let provider = Libp2pFabric::start_with_supplier(
        NodeConfig::new([53u8; 32]).with_network_scope(scope),
        Arc::new(failing_process_supplier(content, declared)),
    )
    .expect("provider starts");
    let addr = provider_addr(&provider).await;
    let (ledger, _serve) =
        wire_disclose_serve_provider(&provider, budget(1 << 40), ServeBudget::default(), || {})
            .await
            .expect("wire->disclose->serve helper installs");

    let consumer = Node::start(NodeConfig::new([54u8; 32]).with_network_scope(scope))
        .expect("consumer starts");

    let fetched = direct_fetch(&consumer, provider.peer_id(), &addr, content, declared).await;
    assert!(
        fetched.is_err(),
        "a serve whose process cannot start fails the fetch"
    );
    assert_eq!(
        ledger.global_bytes_used(),
        2 * declared,
        "the spawn point was reached, so the charge is taken (node-side start-failure over-charge;          not refunded)"
    );
}

/// TASK-297 HIGH-2 (round-3, over-refund closer): a serve whose process EMITS real output but then
/// fails pass-1 (a stale/wrong-root source) is CHARGED over the REAL ledger, not refunded. The commit
/// point is the first real producer output, so the peer cannot drive unbounded uncharged regenerate
/// work by pointing at a source that produces then fails.
///
/// MUTATION: commit only after the full pass-1 root check (round-2) and global_bytes_used() drops to 0
/// here - the wrong-root work would be refunded and the exploit re-opens.
#[tokio::test]
async fn a_stale_root_serve_that_produced_output_is_charged_not_refunded() {
    let scope = "task297-stale-root-charge";
    let emitted =
        b"real bytes a stale source emits on demand; their root will not match the request";
    let requested =
        Blake3Digest::from_raw_nar(b"the DIFFERENT content digest the peer actually asked for");
    let declared = emitted.len() as u64;

    let provider = Libp2pFabric::start_with_supplier(
        NodeConfig::new([61u8; 32]).with_network_scope(scope),
        Arc::new(stale_root_process_supplier(requested, emitted)),
    )
    .expect("provider starts");
    let addr = provider_addr(&provider).await;
    // A per-peer byte budget for ONE serve (2*declared) plus slack.
    let (ledger, _serve) = wire_disclose_serve_provider(
        &provider,
        budget(3 * declared),
        ServeBudget::default(),
        || {},
    )
    .await
    .expect("wire->disclose->serve helper installs");

    let consumer = Node::start(NodeConfig::new([62u8; 32]).with_network_scope(scope))
        .expect("consumer starts");

    // The serve produces real output (pass-1 first chunk -> COMMIT), then rejects the root -> the
    // fetch fails, but the amplification charge STICKS (the dump genuinely ran).
    let fetched = direct_fetch(&consumer, provider.peer_id(), &addr, requested, declared).await;
    assert!(
        fetched.is_err(),
        "a stale-root serve must fail the fetch (the root does not match)"
    );
    assert_eq!(
        ledger.global_bytes_used(),
        2 * declared,
        "a serve that produced real regenerate output must be CHARGED both passes (2*declared) even \
         though pass-1 then rejected the root; 0 would mean the work was refunded (round-3 over-refund)"
    );
}
