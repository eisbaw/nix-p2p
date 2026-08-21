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

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use proc_supervisor::TaskSupervisorHandle;

use peer_fabric::{NarServer, ServeBudget, ServeError, ServeHandle};

use crate::nar::{Libp2pNarSupplier, ServeDeriveAdmission, ServeGate};
use crate::swarm::SwarmHandle;

/// The libp2p [`NarServer`]. Holds the swarm handle and the substrate-internal supplier
/// (bound at construction); each [`serve`](Libp2pServer::serve) installs a fresh
/// [`ServeGate`] under the given budget.
pub struct Libp2pServer {
    handle: SwarmHandle,
    supplier: Arc<dyn Libp2pNarSupplier>,
    /// The supervisor OFF-loop [`crate::nar::NarSource::Process`] production runs under
    /// (TASK-193). Threaded into each [`ServeGate`] so a `nix-store --dump` rides in a
    /// killable, reaped-on-shutdown process group. [`TaskSupervisorHandle::disconnected`]
    /// disables Process serving (Memory-only servers pass it).
    supervisor: TaskSupervisorHandle,
    /// The per-authenticated-PeerId regenerate AMPLIFICATION cap (TASK-297) each
    /// [`serve`](Self::serve) session installs on its [`ServeGate`]. Interior-mutable + set
    /// ONCE at startup ([`set_derive_admission`](Self::set_derive_admission)) by the
    /// composition root BEFORE the first `serve()`, because the substrate-neutral seam builds
    /// the server (bound to its supplier) inside the fabric, while the budget - a
    /// `daemon_core::PeerDeriveLedger` the daemon owns - is known only above the seam. Absent
    /// (`OnceLock` empty) for a server no budget was wired onto (e.g. every in-process test),
    /// exactly the pre-TASK-297 behaviour.
    derive_admission: OnceLock<Arc<dyn ServeDeriveAdmission>>,
}

impl Libp2pServer {
    /// A server driving `handle`, producing bytes through `supplier`. Off-loop supervised
    /// Process production runs under `supervisor`; pass
    /// [`TaskSupervisorHandle::disconnected`] for a Memory-only server (TASK-193).
    pub fn new(
        handle: SwarmHandle,
        supplier: Arc<dyn Libp2pNarSupplier>,
        supervisor: TaskSupervisorHandle,
    ) -> Self {
        Libp2pServer {
            handle,
            supplier,
            supervisor,
            derive_admission: OnceLock::new(),
        }
    }

    /// Wire the per-authenticated-PeerId regenerate AMPLIFICATION cap (TASK-297) every
    /// subsequent [`serve`](Self::serve) session installs on its [`ServeGate`]. Called ONCE by
    /// the composition root at startup (via [`crate::Libp2pFabric::set_serve_derive_admission`])
    /// BEFORE the serve gate is activated, so the shipped provider charges a hostile peer's
    /// repeated cold regenerates against the daemon's `PeerDeriveLedger`. Idempotent-safe: a
    /// second call is ignored (the first wiring wins), never a panic.
    pub fn set_derive_admission(&self, admission: Arc<dyn ServeDeriveAdmission>) {
        let _ = self.derive_admission.set(admission);
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
        let mut gate = ServeGate::new(budget, Arc::clone(&self.supplier), self.supervisor.clone());
        // TASK-297: install the per-authenticated-PeerId regenerate amplification cap the
        // composition root wired (if any) onto THIS session's gate, so every inbound Process
        // regenerate is charged against it. Absent on a server no budget was wired onto.
        if let Some(admission) = self.derive_admission.get() {
            gate = gate.with_derive_admission(Arc::clone(admission));
        }
        let gate = Arc::new(gate);
        self.handle.install_serve(Arc::clone(&gate)).await;
        tracing::info!("fabric-libp2p: NAR serve session started");
        let guard = ServeTeardown {
            gate,
            handle: self.handle.clone(),
        };
        Ok(ServeHandle::with_teardown("libp2p-nar", Box::new(guard)))
    }
}
