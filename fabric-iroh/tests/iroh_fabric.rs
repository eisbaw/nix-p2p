//! TASK-144: [`IrohFabric`] wires the iroh axes behind the `peer_fabric` seam, symmetric
//! with `Libp2pFabric`, and the composition-root `require_axes` assertion bites on a
//! required-but-absent axis.
//!
//! These tests build a HERMETIC offline node (no network) and assert the axis map: the
//! transfer axis is always present, the content-discovery/announce/hold-query/LAN axes are
//! honestly absent (iroh offers no content-provider routing), the node-locator axis is
//! absent when pkarr lookup is disabled and the serve axis is present exactly when a
//! provider was built.

use std::time::Duration;

use fabric_iroh::IrohFabric;
use fabric_iroh::transport_iroh::{IrohNodeBuilder, IrohProviderConfig, StoreRetention};
use peer_fabric::{Axis, NarServer, PeerFabric, ServeBudget, TransportTag, require_axes};

/// A pure CONSUMER fabric (offline_ephemeral, no provider): transfer present, serve absent,
/// every content axis honestly `None`, and - because offline_ephemeral disables address
/// lookup - the node-locator axis `None` too.
#[tokio::test]
async fn consumer_fabric_axis_map_and_required_axis_gate() {
    let node = IrohNodeBuilder::offline_ephemeral()
        .expect("builder")
        .spawn()
        .await
        .expect("spawn offline consumer node");
    let fabric = IrohFabric::wrap(node).expect("wrap node as IrohFabric");

    // The fetch transport is always wired, under the Iroh tag.
    assert!(
        fabric.transfer(TransportTag::Iroh).is_some(),
        "the iroh NAR transfer must be registered under the Iroh tag"
    );
    // A consumer built with no provider does not serve.
    assert!(
        fabric.server().is_none(),
        "a consumer fabric (no provider) exposes no serve axis"
    );
    // iroh offers no content-provider routing / no content announcer / no hold-query / no
    // LAN discovery - all honestly None (the reason libp2p is primary).
    assert!(
        fabric.provider_directory().is_none(),
        "iroh has no content directory"
    );
    assert!(
        fabric.announcer().is_none(),
        "iroh has no content announcer"
    );
    assert!(fabric.hold_query().is_none(), "no over-iroh hold-query");
    assert!(fabric.local_peers().is_none(), "no mDNS wired");
    // offline_ephemeral disables address lookup, so the node runtime exposes no pkarr
    // handle and the locator axis is honestly absent (not a stub that always fails).
    assert!(
        fabric.node_locator().is_none(),
        "an offline node with address lookup disabled exposes no node-locator"
    );

    // The composition-root gate: the CONSUMER-required transfer axis passes.
    require_axes(&fabric, &[Axis::Transfer(TransportTag::Iroh)])
        .expect("the iroh consumer transfer axis is present");

    // ... and a profile that (wrongly) required axes iroh does not offer fails fast,
    // naming EVERY missing one - the Unsupported-axis dilemma resolved at construction.
    let err = require_axes(
        &fabric,
        &[
            Axis::Transfer(TransportTag::Iroh),
            Axis::ProviderDirectory,
            Axis::Server,
        ],
    )
    .expect_err("iroh offers neither a content directory nor (here) a server");
    assert_eq!(err.missing, vec![Axis::ProviderDirectory, Axis::Server]);

    fabric.into_node().shutdown().await.expect("clean shutdown");
}

/// A PROVIDER fabric (built with a deferred-serve provider): the serve axis is present, and
/// the exposed `NarServer` is the real, startable iroh provider.
#[tokio::test]
async fn provider_fabric_exposes_a_startable_serve_axis() {
    let node = IrohNodeBuilder::offline_ephemeral()
        .expect("builder")
        .provider(IrohProviderConfig::retaining(StoreRetention::RetainAll))
        .defer_serve()
        .spawn()
        .await
        .expect("spawn deferred-serve provider node");
    let fabric = IrohFabric::wrap(node).expect("wrap provider node as IrohFabric");

    // A provider serves AND consumes: both the transfer and the serve axis are present.
    assert!(fabric.transfer(TransportTag::Iroh).is_some());
    let server = fabric
        .server()
        .expect("a provider fabric exposes the serve axis");

    // The PROVIDER-required axes pass the gate.
    require_axes(&fabric, &[Axis::Transfer(TransportTag::Iroh), Axis::Server])
        .expect("a provider fabric offers both the transfer and serve axes");

    // The exposed NarServer is the real, startable provider: serving starts through the
    // seam and its ServeHandle tears the driver down on drop (TASK-150), all on the node
    // runtime the fabric owns.
    let handle = NarServer::serve(server.as_ref(), ServeBudget::default())
        .await
        .expect("the fabric's serve axis starts through the seam");
    drop(handle);

    // Give the abort a moment, then confirm the node runtime is untouched by serve teardown.
    tokio::time::sleep(Duration::from_millis(20)).await;
    fabric
        .node()
        .node_id()
        .expect("the node runtime survives serve teardown");
    fabric.into_node().shutdown().await.expect("clean shutdown");
}
