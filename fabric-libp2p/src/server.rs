//! [`Libp2pServer`] - the libp2p [`NarServer`]: serve NARs to whoever asks over the
//! shared swarm's request-response protocol, admitting each request against a
//! [`ServeBudget`] BEFORE producing bytes, following TASK-150's serve-seam contract.
//!
//! ## The seam contract (TASK-150), realised on libp2p
//!
//!   * `serve(budget) -> ServeHandle`: the SUPPLIER is bound to this server at
//!     CONSTRUCTION (a substrate-internal [`Libp2pNarSupplier`], never crossing the
//!     `peer_fabric` seam), so `serve` carries only the budget. It installs a
//!     [`ServeGate`] on the running swarm worker and returns a [`ServeHandle`] whose
//!     `Drop` STOPS ADMITTING new requests.
//!   * Teardown is SYNCHRONOUS at the admission boundary: the handle's guard flips the
//!     gate's `active` flag on `Drop`, so the very next inbound request is answered
//!     `NotHeld` - independent of the (best-effort, async) worker uninstall command.
//!     The peer_fabric [`ServeHandle`] contract only promises "stops admitting new
//!     requests" (in-flight may drain); inline production this cycle means there is no
//!     lingering in-flight transfer to drain (TASK-157 adds off-worker streaming).
//!   * Admission (declared-size-before-produce, the task-72 GAP-1 peer-triggerable-OOM
//!     defense) lives in [`ServeGate::respond`], driven on the worker for each request.

use std::sync::Arc;

use async_trait::async_trait;

use peer_fabric::{NarServer, ServeBudget, ServeError, ServeHandle};

use crate::nar::{Libp2pNarSupplier, ServeGate};
use crate::swarm::SwarmHandle;

/// The libp2p [`NarServer`]. Holds the swarm handle and the substrate-internal supplier
/// (bound at construction); each [`serve`](Libp2pServer::serve) installs a fresh
/// [`ServeGate`] under the given budget.
pub struct Libp2pServer {
    handle: SwarmHandle,
    supplier: Arc<dyn Libp2pNarSupplier>,
}

impl Libp2pServer {
    /// A server driving `handle`, producing bytes through `supplier`.
    pub fn new(handle: SwarmHandle, supplier: Arc<dyn Libp2pNarSupplier>) -> Self {
        Libp2pServer { handle, supplier }
    }
}

/// The serve teardown guard: dropping it STOPS the session admitting new requests.
/// Flipping the shared gate's `active` flag is the synchronous stop; the best-effort
/// worker uninstall just lets the worker drop its `Arc<ServeGate>`.
struct ServeTeardown {
    gate: Arc<ServeGate>,
    handle: SwarmHandle,
}

impl Drop for ServeTeardown {
    fn drop(&mut self) {
        // Synchronous, authoritative stop: the next inbound request sees `active=false`
        // and is answered NotHeld.
        self.gate.stop();
        // Best-effort cleanup so a subsequent serve() replaces cleanly and the worker
        // drops its gate Arc. Non-blocking: safe to call from Drop. Carries THIS gate's
        // identity so a stale teardown cannot clobber a live successor session.
        self.handle
            .uninstall_serve_nonblocking(Arc::clone(&self.gate));
        tracing::debug!("fabric-libp2p: NAR serve session torn down (stopped admitting)");
    }
}

#[async_trait]
impl NarServer for Libp2pServer {
    async fn serve(&self, budget: ServeBudget) -> Result<ServeHandle, ServeError> {
        let gate = Arc::new(ServeGate::new(budget, Arc::clone(&self.supplier)));
        self.handle.install_serve(Arc::clone(&gate)).await;
        tracing::info!("fabric-libp2p: NAR serve session started");
        let guard = ServeTeardown {
            gate,
            handle: self.handle.clone(),
        };
        Ok(ServeHandle::with_teardown("libp2p-nar", Box::new(guard)))
    }
}
