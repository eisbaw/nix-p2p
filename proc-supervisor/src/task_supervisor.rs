//! [`TaskSupervisor`] - bounded ownership of daemon-side asynchronous work and
//! killable subprocesses, extracted stack-neutral (TASK-146).
//!
//! This is the generic process/task supervisor that used to live inside
//! `fabric_iroh::iroh_runtime`. It is NOT iroh-specific: it owns async tasks and
//! OS process groups bounded to a runtime owner's lifetime, and it rode in
//! `fabric-iroh` only so `iroh_runtime` and the daemon's serving core could share
//! it while keeping the crate cut acyclic. It now lives in its own leaf crate so
//! BOTH the stack-neutral `daemon-core` frontend (its HTTP accept loop + NAR
//! production) and `fabric-iroh` (its endpoint runtime) depend on it WITHOUT
//! either depending on the other (docs/peer-fabric-seam.md crate topology).
//!
//! Handles ([`TaskSupervisorHandle`]) are weak capabilities: they register work
//! while the owner is alive but cannot keep the supervisor alive or detach work
//! from shutdown. Dropping the owner synchronously cancels and aborts every
//! registered task; explicit shutdown joins them inside the owner's deadline.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{AbortHandle, Id, JoinHandle, JoinSet};

use crate::process_group::{ProcessJobRegistry, ProcessJobSpec};

/// Provisional hard safety ceiling on queued plus running owned async tasks.
/// Remote peers can create HTTP connections and provider requests, so an
/// unbounded registry would merely move the memory leak from completed joins to
/// pending commands. This value establishes finite admission and recovery; it is
/// not a measured production optimum. TASK-120 owns resource-policy tuning.
pub const MAX_OWNED_TASKS: usize = 1024;

// One additional slot is reserved for the FIFO shutdown marker. Since accepted
// Spawn commands are bounded by MAX_OWNED_TASKS, shutdown cannot be starved by a
// full registration queue.
const TASK_COMMAND_CAPACITY: usize = MAX_OWNED_TASKS + 1;

/// Fail-fast supervisor admission / shutdown errors. Stack-neutral: it carries no
/// iroh (or any backend) type. `fabric_iroh::IrohRuntimeError` maps from this via
/// `From` so the endpoint runtime keeps its own richer error surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    /// The supervisor is shut down (or was never started / already dropped).
    Closed,
    /// The owned-task registry is at capacity: `active`/`limit` queued or running.
    Capacity { active: usize, limit: usize },
    /// An internal lock was poisoned, or a reserved shutdown marker could not be
    /// enqueued - a shutdown-path invariant broke. Carries the specific cause.
    Poisoned(String),
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("task supervisor is shut down"),
            Self::Capacity { active, limit } => write!(
                f,
                "task supervisor is busy: {active}/{limit} owned tasks are queued or running"
            ),
            Self::Poisoned(why) => {
                write!(f, "task supervisor shutdown-path invariant broke: {why}")
            }
        }
    }
}

impl std::error::Error for SupervisorError {}

impl SupervisorError {
    /// Whether this is the capacity-exhausted admission refusal (recoverable: the
    /// caller sheds this one unit of work and keeps serving), as opposed to a hard
    /// `Closed`/`Poisoned` fault.
    pub fn is_capacity_exhausted(&self) -> bool {
        matches!(self, Self::Capacity { .. })
    }
}

pub struct TrackedTask {
    pub name: String,
    pub join: JoinHandle<()>,
}

#[derive(Default)]
struct TaskFailureLatch {
    first: Option<String>,
    count: usize,
}

impl TaskFailureLatch {
    fn record(&mut self, failure: String) {
        self.count = self.count.saturating_add(1);
        if self.first.is_none() {
            self.first = Some(failure);
        }
    }

    fn summary(&self) -> Option<String> {
        self.first
            .as_ref()
            .map(|first| format!("{first} ({} owned-task failure(s) total)", self.count))
    }
}

struct TaskSupervisorInner {
    closing: AtomicBool,
    cancel: watch::Sender<bool>,
    commands: mpsc::Sender<SupervisorCommand>,
    command_receiver: Mutex<Option<mpsc::Receiver<SupervisorCommand>>>,
    manager: Mutex<Option<JoinHandle<()>>>,
    spawn_gate: Mutex<()>,
    abort_handles: Mutex<HashMap<Id, AbortHandle>>,
    active_tasks: AtomicUsize,
    failures: Mutex<TaskFailureLatch>,
    process_jobs: ProcessJobRegistry,
}

type BoxedTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

struct SpawnCommand {
    pub name: String,
    future: BoxedTask,
    cancel_on_shutdown: bool,
}

enum SupervisorCommand {
    Spawn(SpawnCommand),
    Shutdown,
}

/// Owns daemon-side asynchronous work that must not outlive a node runtime.
///
/// Handles are weak capabilities. They can register work while the owner is
/// alive, but cannot keep the supervisor alive or detach work from shutdown.
/// Dropping the owner synchronously cancels and aborts every registered task;
/// explicit runtime shutdown additionally joins them inside the node's single
/// absolute deadline.
pub struct TaskSupervisor {
    inner: Arc<TaskSupervisorInner>,
}

impl Default for TaskSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskSupervisor {
    pub fn new() -> Self {
        let (cancel, _receiver) = watch::channel(false);
        let (commands, command_receiver) = mpsc::channel(TASK_COMMAND_CAPACITY);
        Self {
            inner: Arc::new(TaskSupervisorInner {
                closing: AtomicBool::new(false),
                cancel,
                commands,
                command_receiver: Mutex::new(Some(command_receiver)),
                manager: Mutex::new(None),
                spawn_gate: Mutex::new(()),
                abort_handles: Mutex::new(HashMap::new()),
                active_tasks: AtomicUsize::new(0),
                failures: Mutex::new(TaskFailureLatch::default()),
                process_jobs: ProcessJobRegistry::default(),
            }),
        }
    }

    pub fn handle(&self) -> TaskSupervisorHandle {
        TaskSupervisorHandle {
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub fn begin_shutdown(&self) -> Result<Vec<TrackedTask>, SupervisorError> {
        let _gate = self.inner.spawn_gate.lock().map_err(|_| {
            SupervisorError::Poisoned("task-supervisor spawn gate was poisoned".to_string())
        })?;
        self.inner.closing.store(true, Ordering::Release);
        let _ = self.inner.cancel.send(true);
        self.inner
            .commands
            .try_send(SupervisorCommand::Shutdown)
            .map_err(|error| {
                SupervisorError::Poisoned(format!(
                    "task-supervisor could not enqueue its reserved shutdown marker: {error}"
                ))
            })?;
        let manager = self
            .inner
            .manager
            .lock()
            .map_err(|_| {
                SupervisorError::Poisoned("task-supervisor manager mutex was poisoned".into())
            })?
            .take();
        Ok(manager
            .into_iter()
            .map(|join| TrackedTask {
                name: "owned-task-registry".to_string(),
                join,
            })
            .collect())
    }

    /// Immediate RAII fallback for callers that omit explicit async shutdown.
    pub fn cancel_now(&self) {
        let _gate = match self.inner.spawn_gate.lock() {
            Ok(gate) => gate,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.inner.closing.store(true, Ordering::Release);
        let _ = self.inner.cancel.send(true);
        let _ = self.inner.commands.try_send(SupervisorCommand::Shutdown);
        let aborts = match self.inner.abort_handles.lock() {
            Ok(aborts) => aborts,
            Err(poisoned) => poisoned.into_inner(),
        };
        for abort in aborts.values() {
            abort.abort();
        }
        drop(aborts);
        self.inner.process_jobs.cancel_all();
        let mut manager = match self.inner.manager.lock() {
            Ok(manager) => manager,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(manager) = manager.take() {
            manager.abort();
        }
    }

    pub fn abort_active(&self) -> Result<(), SupervisorError> {
        let aborts = self.inner.abort_handles.lock().map_err(|_| {
            SupervisorError::Poisoned("task-supervisor abort registry mutex was poisoned".into())
        })?;
        for abort in aborts.values() {
            abort.abort();
        }
        drop(aborts);
        self.inner.process_jobs.cancel_all();
        Ok(())
    }

    pub fn process_jobs(&self) -> ProcessJobRegistry {
        self.inner.process_jobs.clone()
    }

    pub fn recorded_failures(&self) -> Result<Vec<String>, SupervisorError> {
        let failures = self.inner.failures.lock().map_err(|_| {
            SupervisorError::Poisoned("task-supervisor failure mutex was poisoned".into())
        })?;
        Ok(failures.summary().into_iter().collect())
    }

    #[doc(hidden)]
    pub fn active_task_count(&self) -> usize {
        self.inner.active_tasks.load(Ordering::Acquire)
    }
}

impl Drop for TaskSupervisor {
    fn drop(&mut self) {
        self.cancel_now();
    }
}

impl fmt::Debug for TaskSupervisor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskSupervisor")
            .field("closing", &self.inner.closing.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// Non-owning registration capability for [`TaskSupervisor`].
#[derive(Clone)]
pub struct TaskSupervisorHandle {
    inner: Weak<TaskSupervisorInner>,
}

impl fmt::Debug for TaskSupervisorHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskSupervisorHandle")
            .field("alive", &self.inner.strong_count().gt(&0))
            .finish()
    }
}

pub struct SupervisedProcessOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_exceeded_limit: bool,
}

async fn wait_for_supervisor_cancel(mut cancelled: watch::Receiver<bool>) {
    if *cancelled.borrow() {
        return;
    }
    let _ = cancelled.wait_for(|closing| *closing).await;
}

async fn task_registry_manager(
    inner: Weak<TaskSupervisorInner>,
    mut commands: mpsc::Receiver<SupervisorCommand>,
) {
    let mut tasks = JoinSet::new();
    let mut names = HashMap::<Id, String>::new();
    let mut shutting_down = false;

    loop {
        if shutting_down && tasks.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                let Some(joined) = joined else { continue };
                let (id, failure) = match joined {
                    Ok((id, ())) => (id, None),
                    Err(error) => {
                        let id = error.id();
                        let failure = (!error.is_cancelled()).then(|| format!("join_error={error}"));
                        (id, failure)
                    }
                };
                let name = names.remove(&id).unwrap_or_else(|| "unknown-owned-task".into());
                if let Some(inner) = inner.upgrade() {
                    if let Some(failure) = failure {
                        let failure = format!("task={name} {failure}");
                        eprintln!("IROH-OWNED-TASK-FAILED {failure}");
                        if let Ok(mut failures) = inner.failures.lock() {
                            failures.record(failure);
                        }
                    }
                    // Publish a panic before removing the task from the active
                    // registry. Shutdown can therefore never observe zero
                    // active work while its failure is still unlatched.
                    if let Ok(mut aborts) = inner.abort_handles.lock() {
                        aborts.remove(&id);
                    }
                    inner.active_tasks.fetch_sub(1, Ordering::AcqRel);
                }
            }
            command = commands.recv(), if !shutting_down => {
                match command {
                    Some(SupervisorCommand::Spawn(command)) => {
                        let Some(inner) = inner.upgrade() else { break };
                        let future: BoxedTask = if command.cancel_on_shutdown {
                            let cancelled = inner.cancel.subscribe();
                            Box::pin(async move {
                                tokio::select! {
                                    biased;
                                    _ = wait_for_supervisor_cancel(cancelled) => {}
                                    _ = command.future => {}
                                }
                            })
                        } else {
                            command.future
                        };
                        let abort = tasks.spawn(future);
                        let id = abort.id();
                        names.insert(id, command.name);
                        inner
                            .abort_handles
                            .lock()
                            .expect("task-supervisor abort registry mutex")
                            .insert(id, abort);
                    }
                    Some(SupervisorCommand::Shutdown) => shutting_down = true,
                    None => {
                        shutting_down = true;
                        tasks.abort_all();
                    }
                }
            }
        }
    }
}

impl TaskSupervisorHandle {
    /// A permanently-disconnected handle (its owner never existed / is already gone).
    /// Every registration on it fails `Closed`. Used where a runtime is built without a
    /// live supervisor (e.g. an endpoint runtime that owns no supervised work), so callers
    /// can hold a handle uniformly rather than an `Option`.
    pub fn disconnected() -> Self {
        TaskSupervisorHandle { inner: Weak::new() }
    }

    fn ensure_manager(inner: &Arc<TaskSupervisorInner>) -> Result<(), SupervisorError> {
        let mut manager = inner.manager.lock().map_err(|_| {
            SupervisorError::Poisoned("task-supervisor manager mutex was poisoned".into())
        })?;
        if manager.is_some() {
            return Ok(());
        }
        let receiver = inner
            .command_receiver
            .lock()
            .map_err(|_| {
                SupervisorError::Poisoned(
                    "task-supervisor command receiver mutex was poisoned".into(),
                )
            })?
            .take()
            .ok_or_else(|| {
                SupervisorError::Poisoned("task-supervisor manager stopped before shutdown".into())
            })?;
        let weak = Arc::downgrade(inner);
        *manager = Some(tokio::spawn(task_registry_manager(weak, receiver)));
        Ok(())
    }

    fn spawn_inner(
        &self,
        name: String,
        future: impl Future<Output = ()> + Send + 'static,
        cancel_on_shutdown: bool,
    ) -> Result<(), SupervisorError> {
        let inner = self.inner.upgrade().ok_or(SupervisorError::Closed)?;
        let _gate = inner.spawn_gate.lock().map_err(|_| {
            SupervisorError::Poisoned("task-supervisor spawn gate was poisoned".into())
        })?;
        if inner.closing.load(Ordering::Acquire) {
            return Err(SupervisorError::Closed);
        }
        Self::ensure_manager(&inner)?;
        let active = inner.active_tasks.load(Ordering::Acquire);
        if active >= MAX_OWNED_TASKS {
            return Err(SupervisorError::Capacity {
                active,
                limit: MAX_OWNED_TASKS,
            });
        }
        inner.active_tasks.fetch_add(1, Ordering::AcqRel);
        match inner
            .commands
            .try_send(SupervisorCommand::Spawn(SpawnCommand {
                name,
                future: Box::pin(future),
                cancel_on_shutdown,
            })) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                inner.active_tasks.fetch_sub(1, Ordering::AcqRel);
                Err(SupervisorError::Capacity {
                    active: MAX_OWNED_TASKS,
                    limit: MAX_OWNED_TASKS,
                })
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                inner.active_tasks.fetch_sub(1, Ordering::AcqRel);
                Err(SupervisorError::Closed)
            }
        }
    }

    #[doc(hidden)]
    pub fn active_task_count(&self) -> Result<usize, SupervisorError> {
        Ok(self
            .inner
            .upgrade()
            .ok_or(SupervisorError::Closed)?
            .active_tasks
            .load(Ordering::Acquire))
    }

    /// Register a task whose lifetime is bounded by its runtime owner.
    pub fn spawn(
        &self,
        name: impl Into<String>,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), SupervisorError> {
        self.spawn_inner(name.into(), future, true)
    }

    pub async fn execute<T>(
        &self,
        name: impl Into<String>,
        future: impl Future<Output = T> + Send + 'static,
    ) -> Result<T, SupervisorError>
    where
        T: Send + 'static,
    {
        let (result_tx, result_rx) = oneshot::channel();
        self.spawn(name, async move {
            let mut result_tx = result_tx;
            tokio::select! {
                biased;
                _ = result_tx.closed() => {}
                result = future => {
                    let _ = result_tx.send(result);
                }
            }
        })?;
        result_rx.await.map_err(|_| SupervisorError::Closed)
    }

    /// Execute one killable subprocess under node ownership.
    ///
    /// This deliberately accepts data, not an in-process callback. If the
    /// caller disappears or node shutdown begins, the whole process group is
    /// SIGKILLed and the direct child is waited/reaped before this tracked task
    /// completes. Stdout is capped while reading, so a replaced/growing source
    /// cannot allocate beyond the serve reservation before validation.
    pub async fn execute_process(
        &self,
        name: impl Into<String>,
        program: PathBuf,
        args: Vec<OsString>,
        environment: Vec<(OsString, OsString)>,
        stdout_limit: usize,
    ) -> Result<SupervisedProcessOutput, SupervisorError> {
        let inner = self.inner.upgrade().ok_or(SupervisorError::Closed)?;
        if inner.closing.load(Ordering::Acquire) {
            return Err(SupervisorError::Closed);
        }
        let cancelled = inner.cancel.subscribe();
        let process_jobs = inner.process_jobs.clone();
        let supervisor_inner = Arc::downgrade(&inner);

        let (mut result_tx, result_rx) = oneshot::channel();
        self.spawn_inner(
            name.into(),
            async move {
                let result = async {
                    let job = process_jobs
                        .start(
                            format!("{} (supervised supplier)", program.display()),
                            ProcessJobSpec {
                                program: program.clone(),
                                args,
                                environment,
                                stdout_limit: Some(stdout_limit),
                                stderr_limit: 64 * 1024,
                            },
                        )
                        .map_err(|error| {
                            SupervisorError::Poisoned(format!(
                                "starting supervised process {}: {error}",
                                program.display()
                            ))
                        })?;
                    if supervisor_inner
                        .upgrade()
                        .is_none_or(|inner| inner.closing.load(Ordering::Acquire))
                    {
                        job.cancel();
                    }
                    let cancellation = wait_for_supervisor_cancel(cancelled);
                    let caller_closed = result_tx.closed();
                    tokio::pin!(cancellation, caller_closed);
                    let mut cancelled_or_abandoned = false;
                    let output = loop {
                        if let Some(result) = job.try_take_result() {
                            break result.map_err(|error| {
                                SupervisorError::Poisoned(format!(
                                    "supervised process {} failed: {error}",
                                    program.display()
                                ))
                            })?;
                        }
                        tokio::select! {
                            () = &mut cancellation, if !cancelled_or_abandoned => {
                                cancelled_or_abandoned = true;
                                job.cancel();
                            }
                            () = &mut caller_closed, if !cancelled_or_abandoned => {
                                cancelled_or_abandoned = true;
                                job.cancel();
                            }
                            () = tokio::time::sleep(Duration::from_millis(1)) => {}
                        }
                    };

                    if cancelled_or_abandoned {
                        return Err(SupervisorError::Closed);
                    }
                    Ok(SupervisedProcessOutput {
                        status: output.status,
                        stdout: output.stdout,
                        stderr: output.stderr,
                        stdout_exceeded_limit: output.stdout_exceeded_limit,
                    })
                }
                .await;
                let _ = result_tx.send(result);
            },
            false,
        )?;
        result_rx.await.map_err(|_| SupervisorError::Closed)?
    }
}
