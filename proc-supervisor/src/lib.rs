//! `proc-supervisor` - stack-neutral supervision of daemon-owned work.
//!
//! Two coupled primitives, neither iroh- nor libp2p-specific, extracted from
//! `fabric_iroh::iroh_runtime` (TASK-146) so the stack-neutral `daemon-core`
//! frontend and the `fabric-iroh` backend can BOTH build on them without a crate
//! cycle (docs/peer-fabric-seam.md "Crate topology"):
//!
//!   * [`process_group`] - a non-abortable OS subprocess job on its own process
//!     group, owned by a dedicated waiter thread; the daemon's NAR producers and
//!     the iroh supervised-supplier both run their `nix`/helper subprocesses here.
//!   * [`task_supervisor`] - [`TaskSupervisor`], bounded ownership of async tasks
//!     (the daemon's HTTP accept loop, provider request handlers, node-lookup
//!     work) that must not outlive their runtime owner, plus a killable-subprocess
//!     bridge (`execute_process`) over `process_group`.
//!
//! This crate carries ZERO p2p dependencies (tokio + rustix only), so both the
//! frontend and either backend can link it.

pub mod process_group;
pub mod task_supervisor;

pub use task_supervisor::{
    MAX_OWNED_TASKS, SupervisedProcessOutput, SupervisorError, TaskSupervisor,
    TaskSupervisorHandle, TrackedTask,
};
