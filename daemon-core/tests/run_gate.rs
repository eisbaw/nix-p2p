//! [`daemon_core::run`]'s composition-root REQUIRED-axis gate (TASK-146): a profile that
//! needs an axis the constructed fabric does not offer is a LOUD startup error, before the
//! listener ever serves - never a silent runtime degrade.
//!
//! `run` composes already-tested pieces (`PeerFabricNarSource`, `FallbackNarSource`, `App` +
//! `serve`, `require_axes`); this test pins the axis-gate behaviour specifically - that the
//! assertion fires FIRST and names the gap, and that a satisfied profile gets PAST the gate.
//! It does NOT serve traffic. The `run` SERVING glue (gate -> PeerFabricNarSource + upstream
//! fallback -> App -> serve) is exercised end to end - a real HTTP GET served through `run`
//! from a discovered libp2p provider, byte-identical, plus the miss->upstream fallback - by
//! `daemon-libp2p/tests/production_path_through_run.rs`, which needs the libp2p backend this
//! stack-neutral crate deliberately does not depend on.

use std::sync::Arc;

use daemon_core::{
    CacheInfo, NarSource, NarinfoSource, NullCorrelation, RawUpstream, RunConfig, UpstreamHttp, run,
};
use peer_fabric::{
    Axis, DiscoveryBudget, FakeFabric, NodeId, PeerFabric, SafetyEnvelope, TransportTag,
};
use tokio::net::TcpListener;

fn cache_info() -> CacheInfo {
    CacheInfo {
        store_dir: "/nix/store".to_string(),
        priority: 41,
        want_mass_query: true,
    }
}

/// Build a `RunConfig` whose sources are a never-dialed upstream (the gate fails before any
/// request is served, so the URL is inert) requiring `required_axes`.
async fn run_config(required_axes: Vec<Axis>) -> RunConfig {
    let upstream = Arc::new(UpstreamHttp::new("http://127.0.0.1:9").expect("inert upstream"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    RunConfig {
        listener,
        upstream: upstream.clone() as Arc<dyn NarSource>,
        narinfo: upstream.clone() as Arc<dyn NarinfoSource>,
        passthrough: upstream as Arc<dyn RawUpstream>,
        correlation: Arc::new(NullCorrelation),
        cache_info: cache_info(),
        upstream_label: "http://127.0.0.1:9".to_string(),
        discovery_budget: DiscoveryBudget::default(),
        envelope: SafetyEnvelope::default(),
        required_axes,
        extra_raw_serve: Vec::new(),
        public_allowlist: Arc::new(daemon_core::PublicNarAllowlist::disabled()),
    }
}

#[tokio::test]
async fn run_fails_fast_naming_every_missing_required_axis() {
    // An `upstream_only` fake offers NO p2p axis; a profile requiring several must be refused
    // at the gate, naming ALL of them, before the HTTP loop starts.
    let fabric: Arc<dyn PeerFabric> =
        Arc::new(FakeFabric::upstream_only(NodeId::from_bytes([7; 32])));
    let cfg = run_config(vec![
        Axis::ProviderDirectory,
        Axis::NodeLocator,
        Axis::Transfer(TransportTag::Iroh),
    ])
    .await;

    let err = run(fabric, cfg)
        .await
        .expect_err("a fabric missing every required axis must fail the composition-root gate");
    // The error names the gap (actionable startup failure), not a generic serve error.
    assert!(err.contains("required axes"), "{err}");
    assert!(err.contains("provider_directory"), "{err}");
    assert!(err.contains("node_locator"), "{err}");
    assert!(err.contains("transfer(iroh)"), "{err}");
}

#[tokio::test]
async fn run_gate_passes_when_no_axes_are_required() {
    // With an empty required set the gate is satisfied even by an upstream-only fabric, so the
    // failure below can only be the serve loop - proving the gate itself did NOT reject. We do
    // not actually serve traffic here (that is the libp2p integration tests' job); we assert
    // the run gets PAST the axis gate by racing it against an immediate timeout.
    let fabric: Arc<dyn PeerFabric> =
        Arc::new(FakeFabric::upstream_only(NodeId::from_bytes([9; 32])));
    let cfg = run_config(Vec::new()).await;

    // The gate passes -> run proceeds to serve and blocks on accept(); a short timeout elapses
    // (Err) rather than run returning an axis-gate Err. If the gate had wrongly rejected, run
    // would return Ready(Err(..)) immediately and the timeout would NOT fire.
    let timed_out = tokio::time::timeout(std::time::Duration::from_millis(150), run(fabric, cfg))
        .await
        .is_err();
    assert!(
        timed_out,
        "with no required axes the gate must pass and run must proceed to serve (block on accept), \
         not return an axis-gate error"
    );
}
