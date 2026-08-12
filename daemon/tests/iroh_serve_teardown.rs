//! TASK-150 AC#2: the DE-WELDED serve axis.
//!
//! [`IrohProvider`] implements `peer_fabric::NarServer`. Serving starts on an
//! ALREADY-RUNNING node runtime via `serve`, and the returned `ServeHandle`'s `Drop`
//! aborts JUST the serve driver task - leaving the node runtime (endpoint/router)
//! intact. That is the de-weld: the serve loop's lifetime is owned by the handle, not
//! by the shared runtime supervisor.
//!
//! The oracle for "the task was aborted" is the driver's own `MarkStopped` guard: the
//! event-driver loop otherwise blocks on `recv()` forever, so the only way its
//! lifecycle can leave the READY state is the task being dropped/aborted.

use std::time::Duration;

use daemon::{IrohNodeBuilder, IrohProviderConfig, StoreRetention};
use peer_fabric::{NarServer, ServeBudget};

async fn wait_until(mut cond: impl FnMut() -> bool, within: Duration, what: &str) {
    let deadline = tokio::time::Instant::now() + within;
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn deferred_serve_handle_drop_aborts_the_serve_task_but_not_the_runtime() {
    // Built with `defer_serve`: the provider handler is registered but its serve
    // driver is NOT started, so it is fail-closed until `NarServer::serve`.
    let node = IrohNodeBuilder::offline_ephemeral()
        .expect("builder")
        .provider(IrohProviderConfig::retaining(StoreRetention::RetainAll))
        .defer_serve()
        .spawn()
        .await
        .expect("spawn deferred-serve node");
    let provider = node.provider_handle().expect("provider installed");

    assert!(
        !provider.event_driver_ready(),
        "a deferred provider must not be serving before NarServer::serve"
    );

    // Start the serve session on the running runtime THROUGH the seam.
    let handle = NarServer::serve(provider.as_ref(), ServeBudget::default())
        .await
        .expect("deferred serve starts");
    assert!(
        provider.event_driver_ready(),
        "serve() must start the driver and enter the ready state"
    );

    // Dropping the handle aborts the serve driver task; its `MarkStopped` guard runs
    // on abort, so the lifecycle leaves READY.
    drop(handle);
    wait_until(
        || !provider.event_driver_ready(),
        Duration::from_secs(5),
        "serve driver aborted after ServeHandle drop",
    )
    .await;

    // The node RUNTIME is untouched by the serve teardown (the serve axis is
    // de-welded from it): its endpoint is still reachable and it shuts down cleanly.
    node.node_id()
        .expect("runtime endpoint still alive after serve teardown");
    node.shutdown()
        .await
        .expect("clean runtime shutdown after serve teardown");
}

#[tokio::test]
async fn serve_is_rejected_on_an_auto_serve_provider() {
    // The auto-serve constructor already started the driver on the runtime
    // supervisor, so there is no deferred driver for `NarServer::serve` to start: it
    // must refuse with a NAMED backend error, not panic or double-start.
    let node = IrohNodeBuilder::offline_ephemeral()
        .expect("builder")
        .provider(IrohProviderConfig::retaining(StoreRetention::RetainAll))
        .spawn()
        .await
        .expect("spawn auto-serve node");
    let provider = node.provider_handle().expect("provider installed");
    assert!(
        provider.event_driver_ready(),
        "auto-serve starts the driver at spawn"
    );

    let error = NarServer::serve(provider.as_ref(), ServeBudget::default())
        .await
        .expect_err("an auto-serve provider cannot also be served through the seam");
    assert!(
        error.to_string().contains("deferred serve"),
        "the refusal should name the deferred-serve requirement, got: {error}"
    );

    node.shutdown().await.expect("clean shutdown");
}
