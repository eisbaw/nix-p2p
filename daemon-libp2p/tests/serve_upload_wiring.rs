//! TASK-299: the PRODUCTION upload-rate egress shaper bites through the SHIPPED wiring.
//!
//! `wire_disclose_serve_provider` is the ONE helper BOTH shipped provider binaries (the thin
//! `daemon-libp2p` and the composite `daemon`, the flake DEFAULT) call. This test drives a REAL
//! two-node `/nar` serve through it over the REAL [`UploadRateLedger`], so the shipped serve path
//! (`serve_stream` -> `ShapingWriter` charge + `admit_plan` decline) — not a unit mock — is what is
//! exercised:
//!
//!   * a provider wired with a TINY per-window egress cap serves the FIRST request (the window
//!     starts empty), whose real compressed-wire octets are CHARGED to the ledger, spending the
//!     window; the SECOND request from the same node is then DECLINED (coalesced `Busy`), attributed
//!     to the upload-rate bound — the sustained-egress cap biting.
//!   * an inline NEGATIVE CONTROL (a provider wired with an UNBOUNDED egress cap) serves the same
//!     two requests without limit, so the armed provider's decline is attributable to the wired
//!     upload budget, not the request. MUTATION: neuter the ledger's `admit_upload` (always true) or
//!     drop the `ShapingWriter` charge, and the armed second-serve decline no longer happens —
//!     reddening this test.
//!
//! The derive axis is held GENEROUS here (a huge per-peer/global byte+dump budget) so the ONLY bound
//! that can bite is the egress shaper — a clean single-axis oracle.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use daemon_core::content_id::Blake3Digest;
use daemon_core::{DeriveBudget, UploadBudget};
use daemon_libp2p::wire_disclose_serve_provider;
use fabric_libp2p::{
    CatalogNarSupplier, CatalogProbe, Libp2pFabric, Multiaddr, Node, NodeConfig, PeerId,
    ProbedSource, ProbedSupply,
};
use peer_fabric::{ServeBudget, TransferError};

/// A one-content catalog probe returning a fixed [`ProbedSupply`].
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

/// A supplier whose one digest regenerates `body` via `sh -c printf` (a Process source: nothing held
/// at rest, re-run on every request — the serve path that streams real wire octets).
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

/// A GENEROUS derive budget so the per-peer/global amplification cap never fires — the egress shaper
/// is the only bound under test.
fn derive_generous() -> DeriveBudget {
    DeriveBudget {
        max_bytes_per_peer_uncompressed_nar: u64::MAX,
        max_dumps_per_peer: u32::MAX,
        max_bytes_global_uncompressed_nar: u64::MAX,
        max_dumps_global: u32::MAX,
        window: Duration::from_secs(60),
    }
}

/// An upload budget of `cap` octets per 60 s window (long enough that it never rolls mid-test).
fn upload(cap: u64) -> UploadBudget {
    UploadBudget {
        max_bytes_per_window: cap,
        window: Duration::from_secs(60),
    }
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

/// The shipped upload-rate egress shaper: the first real serve charges its wire octets and spends a
/// tiny window; the next serve is DECLINED, attributable to the upload budget; an unbounded control
/// serves both.
#[tokio::test]
async fn production_wiring_shapes_real_serve_egress_by_the_upload_window() {
    let scope = "task299-upload-wiring";
    let body = b"raw NAR streamed to a peer and charged against the real egress shaper".to_vec();
    let content = Blake3Digest::from_raw_nar(&body);
    let declared = body.len() as u64;

    // ---- ARMED provider: a 1-octet upload window. The first serve (window empty) is admitted and
    // its real wire octets are charged, spending the window; the second is declined. ----
    let provider = Libp2pFabric::start_with_supplier(
        NodeConfig::new([81u8; 32]).with_network_scope(scope),
        Arc::new(process_supplier(content, &body)),
    )
    .expect("armed provider starts");
    let addr = provider_addr(&provider).await;
    let (_derive, upload_ledger, _serve) = wire_disclose_serve_provider(
        &provider,
        derive_generous(),
        upload(1),
        ServeBudget::default(),
        || {},
    )
    .await
    .expect("the production wire->disclose->serve helper wires the egress shaper");

    let node_b = Node::start(NodeConfig::new([82u8; 32]).with_network_scope(scope))
        .expect("consumer starts");
    let first = direct_fetch(&node_b, provider.peer_id(), &addr, content, declared).await;
    assert_eq!(
        first.expect("the first serve (empty window) is admitted"),
        body,
        "the first serve streams the process source's bytes"
    );
    // The real serve charged real compressed-wire octets to the ledger, spending the 1-octet window.
    let used = upload_ledger.window_bytes_used();
    assert!(
        used >= upload_ledger.window_bytes_cap() && used > 0,
        "the first serve must charge real wire octets and spend the window: used={used}, cap={}",
        upload_ledger.window_bytes_cap()
    );

    let second = direct_fetch(&node_b, provider.peer_id(), &addr, content, declared).await;
    match second {
        Err(TransferError::Unavailable(why)) => assert!(
            why.contains("declined"),
            "the second serve must be refused by a serve DECLINE (the spent upload window biting), \
             got Unavailable({why})"
        ),
        other => {
            panic!("the second serve must be DECLINED on the spent upload window; got {other:?}")
        }
    }

    // ---- NEGATIVE CONTROL (load-bearing): the SAME helper with an UNBOUNDED upload window serves
    // both requests, so the armed decline is attributable to the wired egress budget. ----
    let unbounded = Libp2pFabric::start_with_supplier(
        NodeConfig::new([83u8; 32]).with_network_scope(scope),
        Arc::new(process_supplier(content, &body)),
    )
    .expect("unbounded provider starts");
    let unbounded_addr = provider_addr(&unbounded).await;
    let (_d2, _u2, _serve2) = wire_disclose_serve_provider(
        &unbounded,
        derive_generous(),
        upload(u64::MAX),
        ServeBudget::default(),
        || {},
    )
    .await
    .expect("the helper wires + serves the unbounded-egress provider");
    let node_c = Node::start(NodeConfig::new([84u8; 32]).with_network_scope(scope))
        .expect("control consumer starts");
    let c1 = direct_fetch(
        &node_c,
        unbounded.peer_id(),
        &unbounded_addr,
        content,
        declared,
    )
    .await;
    let c2 = direct_fetch(
        &node_c,
        unbounded.peer_id(),
        &unbounded_addr,
        content,
        declared,
    )
    .await;
    assert_eq!(c1.expect("unbounded egress serves the first request"), body);
    assert_eq!(
        c2.expect("unbounded egress serves the second request too (no window to spend)"),
        body,
        "with an unbounded upload window the second serve is NOT declined — so the armed decline is \
         caused by the wired egress budget, not the request"
    );
}
