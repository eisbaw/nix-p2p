//! TASK-297 HIGH-4 / HIGH-5 / HIGH-3: the PRODUCTION wiring bite.
//!
//! `wire_provider_derive_budget` is the ONE helper BOTH shipped provider binaries (the thin
//! `daemon-libp2p` and the composite `daemon`, the flake DEFAULT) call to cap per-authenticated-
//! PeerId serve amplification. This test drives a REAL two-node `/nar` serve through that helper
//! over the REAL [`PeerDeriveLedger`], with the per-peer BYTE ceiling as the binding constraint:
//!
//!   * HIGH-4: neutering the helper's `set_serve_derive_admission` call leaves BOTH binaries
//!     uncapped; here the inline NEGATIVE CONTROL (a provider wired with an UNBOUNDED budget) serves
//!     the same flood, so the armed provider's decline is attributable to the wired budget.
//!   * HIGH-5: the bound that bites is the per-peer BYTE ceiling (few large-ish serves), not a
//!     request count - a charge-0 / charge-wrong-size mutation reddens the `global_bytes_used`
//!     assertion.
//!   * HIGH-3: one serve charges BOTH regeneration passes, so `global_bytes_used() == 2 * declared`.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daemon_core::DeriveBudget;
use daemon_core::content_id::Blake3Digest;
use daemon_libp2p::wire_provider_derive_budget;
use fabric_libp2p::{
    CatalogNarSupplier, CatalogProbe, Libp2pFabric, Multiaddr, Node, NodeConfig, PeerId,
    ProbedSource, ProbedSupply,
};
use peer_fabric::{PeerFabric, ServeBudget, TransferError};

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
    let ledger = wire_provider_derive_budget(&provider, budget(3 * declared))
        .expect("the production helper wires the serve axis");
    let _serve = provider
        .server()
        .expect("provider fabric exposes a serve axis")
        .serve(ServeBudget::default())
        .await
        .expect("serve gate installs");

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
    let _unbounded_ledger = wire_provider_derive_budget(&unbounded, budget(u64::MAX))
        .expect("helper wires the unbounded provider");
    let _unbounded_serve = unbounded
        .server()
        .expect("serve axis")
        .serve(ServeBudget::default())
        .await
        .expect("serve gate installs");
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
