//! Non-abortable subprocess jobs used by every NAR producer.
//!
//! The control record is registered before a dedicated OS thread is launched.
//! That thread performs the spawn, owns [`std::process::Child`], drains both pipes,
//! and is the ONLY direct-child waiter. Async futures merely poll its completion;
//! aborting or dropping them requests cancellation but cannot detach the worker.
//!
//! The daemon is a child subreaper, so after the direct child exits the worker
//! kills its fresh process group and reaps adopted descendants to `ECHILD`.
//! Linux can keep a task forever in uninterruptible (`D`) state on broken kernel
//! IO. No userspace deadline can reap that task. Shutdown may therefore report a
//! still-owned job, but the worker and registry retain ownership and keep waiting
//! until the kernel makes it reapable.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use rustix::process::{Pid, Signal, WaitOptions};
use tokio::sync::mpsc;

static JOB_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessJobError {
    message: String,
    report_to_registry: bool,
}

impl ProcessJobError {
    fn operational(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            report_to_registry: true,
        }
    }

    fn cancelled(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            report_to_registry: false,
        }
    }
}

impl fmt::Display for ProcessJobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProcessJobError {}

#[derive(Debug)]
pub struct ProcessJobSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    /// Retain at most this limit plus one proof byte. `None` is the synchronous
    /// availability hash path, whose existing contract buffers the whole NAR.
    pub stdout_limit: Option<usize>,
    pub stderr_limit: usize,
}

#[derive(Debug)]
pub struct ProcessJobOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_exceeded_limit: bool,
    /// Number of stdout bytes observed, saturated at `stdout_limit + 1` when a
    /// limit is configured. This remains meaningful for streaming jobs, whose
    /// stdout is deliberately not retained in [`Self::stdout`].
    pub stdout_bytes_read: usize,
}

enum StdoutMode {
    Retain,
    /// Send at most one 64-KiB chunk at a time. The worker uses `try_send` and
    /// retains one pending chunk while continuing to drain stderr and poll
    /// cancellation/child exit, so a slow consumer cannot deadlock the sole
    /// process-group supervision loop.
    Stream {
        sender: mpsc::Sender<Vec<u8>>,
        /// Fired ONCE the instant the worker reads the child's FIRST real output byte (at the
        /// supervisor read, not when a downstream consumer accepts the buffered chunk). A caller
        /// that must charge for "the producer genuinely emitted output" (TASK-297 HIGH-2) hangs its
        /// commit here, so a consumer cancel in the read->send buffering gap cannot un-charge a dump
        /// that has already produced. Dropped WITHOUT firing (the child never emitted - start
        /// failure or a cancel before any output) if this worker ends with no output observed.
        on_first_output: Option<Box<dyn FnOnce() + Send>>,
    },
}

/// Enable process-global child adoption before any worker is allowed to spawn.
pub(crate) fn ensure_child_subreaper() -> Result<(), ProcessJobError> {
    static INITIALIZED: OnceLock<Result<(), String>> = OnceLock::new();
    INITIALIZED
        .get_or_init(|| {
            rustix::process::set_child_subreaper(Some(rustix::process::getpid())).map_err(|error| {
                format!("enabling child subreaper for supervised producers: {error}")
            })
        })
        .clone()
        .map_err(ProcessJobError::operational)
}

#[derive(Default)]
struct LaunchState {
    cancelled: bool,
    pgid: Option<Pid>,
}

struct CompletionState {
    result: Option<Result<ProcessJobOutput, ProcessJobError>>,
}

struct ProcessJobControl {
    id: u64,
    label: String,
    launch: Mutex<LaunchState>,
    completion: Mutex<CompletionState>,
    completion_changed: Condvar,
    #[cfg(test)]
    stream_backpressured: std::sync::atomic::AtomicBool,
}

impl ProcessJobControl {
    fn cancel(&self) {
        let pgid = {
            let mut launch = match self.launch.lock() {
                Ok(launch) => launch,
                Err(poisoned) => poisoned.into_inner(),
            };
            launch.cancelled = true;
            launch.pgid
        };
        if let Some(pgid) = pgid {
            let _ = rustix::process::kill_process_group(pgid, Signal::KILL);
        }
        self.completion_changed.notify_all();
    }

    fn is_cancelled(&self) -> bool {
        match self.launch.lock() {
            Ok(launch) => launch.cancelled,
            Err(poisoned) => poisoned.into_inner().cancelled,
        }
    }

    fn try_take_result(&self) -> Option<Result<ProcessJobOutput, ProcessJobError>> {
        match self.completion.lock() {
            Ok(mut completion) => completion.result.take(),
            Err(poisoned) => poisoned.into_inner().result.take(),
        }
    }
}

#[derive(Default)]
struct ProcessJobRegistryInner {
    jobs: Mutex<HashMap<u64, Arc<ProcessJobControl>>>,
    failures: Mutex<FailureLatch>,
}

/// Runtime-owned set of workers that have not yet proved child-free completion.
#[derive(Clone, Default)]
pub struct ProcessJobRegistry {
    inner: Arc<ProcessJobRegistryInner>,
}

impl ProcessJobRegistry {
    pub fn start(
        &self,
        label: impl Into<String>,
        spec: ProcessJobSpec,
    ) -> Result<ProcessJob, ProcessJobError> {
        let result = ProcessJob::start(
            label.into(),
            spec,
            StdoutMode::Retain,
            Some(Arc::clone(&self.inner)),
        );
        if let Err(error) = &result
            && error.report_to_registry
        {
            match self.inner.failures.lock() {
                Ok(mut failures) => failures.record(error.to_string()),
                Err(poisoned) => poisoned.into_inner().record(error.to_string()),
            }
        }
        result
    }

    /// Start a job whose stdout is delivered through a bounded channel instead
    /// of retained in memory. Closing `stdout` cancels and reaps the process
    /// group. The receiver capacity is chosen by the caller; the worker itself
    /// never accumulates more than one additional pending 64-KiB chunk.
    pub fn start_streaming(
        &self,
        label: impl Into<String>,
        spec: ProcessJobSpec,
        stdout: mpsc::Sender<Vec<u8>>,
        on_first_output: Option<Box<dyn FnOnce() + Send>>,
    ) -> Result<ProcessJob, ProcessJobError> {
        let result = ProcessJob::start(
            label.into(),
            spec,
            StdoutMode::Stream {
                sender: stdout,
                on_first_output,
            },
            Some(Arc::clone(&self.inner)),
        );
        if let Err(error) = &result
            && error.report_to_registry
        {
            match self.inner.failures.lock() {
                Ok(mut failures) => failures.record(error.to_string()),
                Err(poisoned) => poisoned.into_inner().record(error.to_string()),
            }
        }
        result
    }

    /// O(1) per live job: request kill without waiting. The workers remain the
    /// sole waiters and remove themselves only after actual cleanup.
    pub fn cancel_all(&self) {
        let jobs = match self.inner.jobs.lock() {
            Ok(jobs) => jobs.values().cloned().collect::<Vec<_>>(),
            Err(poisoned) => poisoned.into_inner().values().cloned().collect(),
        };
        for job in jobs {
            job.cancel();
        }
    }

    pub fn active_len(&self) -> usize {
        match self.inner.jobs.lock() {
            Ok(jobs) => jobs.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    pub fn active_labels(&self) -> Vec<String> {
        match self.inner.jobs.lock() {
            Ok(jobs) => jobs.values().map(|job| job.label.clone()).collect(),
            Err(poisoned) => poisoned
                .into_inner()
                .values()
                .map(|job| job.label.clone())
                .collect(),
        }
    }

    pub fn recorded_failures(&self) -> Vec<String> {
        let failures = match self.inner.failures.lock() {
            Ok(failures) => failures,
            Err(poisoned) => poisoned.into_inner(),
        };
        failures
            .summary("process-job registry")
            .into_iter()
            .collect()
    }
}

/// A control/observation ticket for one non-abortable worker.
pub struct ProcessJob {
    control: Arc<ProcessJobControl>,
}

impl ProcessJob {
    pub fn standalone(
        label: impl Into<String>,
        spec: ProcessJobSpec,
    ) -> Result<Self, ProcessJobError> {
        Self::start(label.into(), spec, StdoutMode::Retain, None)
    }

    fn start(
        label: String,
        spec: ProcessJobSpec,
        stdout_mode: StdoutMode,
        registry: Option<Arc<ProcessJobRegistryInner>>,
    ) -> Result<Self, ProcessJobError> {
        ensure_child_subreaper()?;
        let id = JOB_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let control = Arc::new(ProcessJobControl {
            id,
            label,
            launch: Mutex::new(LaunchState::default()),
            completion: Mutex::new(CompletionState { result: None }),
            completion_changed: Condvar::new(),
            #[cfg(test)]
            stream_backpressured: std::sync::atomic::AtomicBool::new(false),
        });
        if let Some(registry) = registry.as_ref() {
            registry
                .jobs
                .lock()
                .map_err(|_| ProcessJobError::operational("process-job registry mutex poisoned"))?
                .insert(id, Arc::clone(&control));
        }
        let worker_control = Arc::clone(&control);
        let worker_registry = registry.clone();
        if let Err(error) = std::thread::Builder::new()
            .name(format!("nix-p2p-process-{id}"))
            .spawn(move || run_worker(worker_control, spec, stdout_mode, worker_registry))
        {
            if let Some(registry) = registry.as_ref()
                && let Ok(mut jobs) = registry.jobs.lock()
            {
                jobs.remove(&id);
            }
            return Err(ProcessJobError::operational(format!(
                "starting non-abortable process worker: {error}"
            )));
        }
        Ok(Self { control })
    }

    pub fn cancel(&self) {
        self.control.cancel();
    }

    pub fn try_take_result(&self) -> Option<Result<ProcessJobOutput, ProcessJobError>> {
        self.control.try_take_result()
    }

    pub fn wait(self) -> Result<ProcessJobOutput, ProcessJobError> {
        loop {
            if let Some(result) = self.try_take_result() {
                return result;
            }
            let completion = self.control.completion.lock().map_err(|_| {
                ProcessJobError::operational("process-job completion mutex poisoned")
            })?;
            drop(
                self.control
                    .completion_changed
                    .wait_while(completion, |state| state.result.is_none())
                    .map_err(|_| {
                        ProcessJobError::operational(
                            "process-job completion mutex poisoned while waiting",
                        )
                    })?,
            );
        }
    }
}

impl Drop for ProcessJob {
    fn drop(&mut self) {
        self.control.cancel();
    }
}

#[derive(Default)]
struct FailureLatch {
    first: Option<String>,
    count: usize,
}

impl FailureLatch {
    fn record(&mut self, message: impl Into<String>) {
        self.count = self.count.saturating_add(1);
        if self.first.is_none() {
            self.first = Some(message.into());
        }
    }

    fn finish(self, label: &str) -> Option<ProcessJobError> {
        self.first.map(|first| {
            ProcessJobError::operational(format!(
                "{label}: {first} ({} process-worker error(s) total)",
                self.count
            ))
        })
    }

    fn summary(&self, label: &str) -> Option<String> {
        self.first.as_ref().map(|first| {
            format!(
                "{label}: {first} ({} process-worker error(s) total)",
                self.count
            )
        })
    }
}

/// Sole ownership of one spawned process and every descendant that remains in
/// its fresh process group.
///
/// `std::process::Child::drop` neither kills nor waits. Keeping this record
/// outside the post-spawn unwind boundary is therefore load-bearing: a panic in
/// pipe draining or supervision is caught while the live child is still
/// available for an explicit group kill and reap. `Drop` is the last-resort
/// fail-closed path if cleanup itself unwinds; it does not return while a direct
/// child or adopted same-PGID descendant remains waitable.
struct OwnedProcessGroup {
    child: Child,
    pgid: Pid,
    direct_status: Option<ExitStatus>,
    descendants_reaped: bool,
}

impl OwnedProcessGroup {
    fn new(child: Child) -> Self {
        let pgid = Pid::from_child(&child);
        Self {
            child,
            pgid,
            direct_status: None,
            descendants_reaped: false,
        }
    }

    fn is_child_free(&self) -> bool {
        self.direct_status.is_some() && self.descendants_reaped
    }

    /// Kill the exact process group, reap the direct child through its `Child`
    /// handle, then reap adopted same-PGID descendants to `ECHILD`.
    ///
    /// Errors are latched and returned only after child-free completion. A
    /// persistent kernel failure (including an unkillable D-state task) keeps
    /// this sole owner blocked here instead of falsely publishing completion.
    fn kill_and_reap(&mut self, label: &str) -> Result<(), ProcessJobError> {
        let mut failures = FailureLatch::default();
        let mut kill_error_recorded = false;
        let mut direct_wait_error_recorded = false;
        let mut descendant_wait_error_recorded = false;

        while self.direct_status.is_none() {
            if let Err(error) = kill_group(self.pgid)
                && !kill_error_recorded
            {
                failures.record(error.to_string());
                kill_error_recorded = true;
            }
            match self.child.try_wait() {
                Ok(Some(status)) => self.direct_status = Some(status),
                Ok(None) => {}
                Err(error) if !direct_wait_error_recorded => {
                    failures.record(format!("waiting direct child during cleanup: {error}"));
                    direct_wait_error_recorded = true;
                }
                Err(_) => {}
            }
            if self.direct_status.is_none() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        while !self.descendants_reaped {
            if let Err(error) = kill_group(self.pgid)
                && !kill_error_recorded
            {
                failures.record(error.to_string());
                kill_error_recorded = true;
            }
            match reap_descendants_once(self.pgid) {
                Ok(true) => self.descendants_reaped = true,
                Ok(false) => {}
                Err(error) if !descendant_wait_error_recorded => {
                    failures.record(error.to_string());
                    descendant_wait_error_recorded = true;
                }
                Err(_) => {}
            }
            if !self.descendants_reaped {
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        match failures.finish(label) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for OwnedProcessGroup {
    fn drop(&mut self) {
        if self.is_child_free() {
            return;
        }
        if let Err(error) = self.kill_and_reap("process-group unwind fallback") {
            eprintln!("daemon: {error}");
        }
    }
}

fn panic_detail(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".into())
}

#[cfg(test)]
struct PostSpawnPanicFailpoint {
    label: String,
    ready_file: PathBuf,
}

#[cfg(test)]
static POST_SPAWN_PANIC_FAILPOINT: Mutex<Option<PostSpawnPanicFailpoint>> = Mutex::new(None);

#[cfg(test)]
fn arm_post_spawn_panic(label: String, ready_file: PathBuf) {
    let mut failpoint = match POST_SPAWN_PANIC_FAILPOINT.lock() {
        Ok(failpoint) => failpoint,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert!(
        failpoint.is_none(),
        "post-spawn panic failpoint already armed"
    );
    *failpoint = Some(PostSpawnPanicFailpoint { label, ready_file });
}

#[cfg(test)]
fn maybe_panic_after_spawn(label: &str) {
    let ready_file = {
        let mut failpoint = match POST_SPAWN_PANIC_FAILPOINT.lock() {
            Ok(failpoint) => failpoint,
            Err(poisoned) => poisoned.into_inner(),
        };
        match failpoint.as_ref() {
            Some(armed) if armed.label == label => failpoint.take().map(|armed| armed.ready_file),
            _ => None,
        }
    };
    let Some(ready_file) = ready_file else {
        return;
    };

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if std::fs::read_to_string(&ready_file).is_ok_and(|raw| raw.split_whitespace().count() == 2)
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "post-spawn panic helper did not publish child and grandchild PIDs"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("deterministic panic after process-group publication");
}

fn run_worker(
    control: Arc<ProcessJobControl>,
    spec: ProcessJobSpec,
    stdout_mode: StdoutMode,
    registry: Option<Arc<ProcessJobRegistryInner>>,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_worker_inner(&control, spec, stdout_mode)
    }))
    .unwrap_or_else(|panic| {
        let detail = panic_detail(panic.as_ref());
        Err(ProcessJobError::operational(format!(
            "{} worker panicked: {detail}",
            control.label
        )))
    });
    // Clear the published PGID before making completion observable. A result
    // ticket is dropped by its waiter; leaving the numeric PGID behind would
    // let that harmless Drop signal an unrelated, newly-reused process group.
    match control.launch.lock() {
        Ok(mut launch) => launch.pgid = None,
        Err(poisoned) => poisoned.into_inner().pgid = None,
    }
    if let Some(registry) = registry.as_ref()
        && let Err(error) = &result
        && error.report_to_registry
    {
        match registry.failures.lock() {
            Ok(mut failures) => failures.record(error.to_string()),
            Err(poisoned) => poisoned.into_inner().record(error.to_string()),
        }
    }
    *match control.completion.lock() {
        Ok(completion) => completion,
        Err(poisoned) => poisoned.into_inner(),
    } = CompletionState {
        result: Some(result),
    };
    control.completion_changed.notify_all();
    if let Some(registry) = registry {
        match registry.jobs.lock() {
            Ok(mut jobs) => {
                jobs.remove(&control.id);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(&control.id);
            }
        }
    }
}

/// TASK-297 HIGH-2 (cancel-path drain): if `stdout` already has queued bytes, fire `on_first_output`
/// exactly once and return `true`. Called on the cancellation path BEFORE the pipe is discarded, so a
/// completed small-NAR dump the child wrote into the pipe during the poll gap is still CHARGED; an
/// empty pipe (a genuinely zero-output child, or a start failure) leaves the hook unfired -> the
/// caller's guard refunds, preserving "no-work requests cost nothing". The pipe is O_NONBLOCK (the
/// worker set it), so a `WouldBlock`/EOF read observes no output and fires nothing. Only the EXISTENCE
/// of output matters; the drained bytes are NOT served. One read of up to a scratch buffer is enough
/// to observe output exists.
fn drain_and_fire_first_output<R: Read>(
    stdout: &mut Option<R>,
    scratch: &mut Option<Vec<u8>>,
    on_first_output: &mut Option<Box<dyn FnOnce() + Send>>,
) -> bool {
    if on_first_output.is_some()
        && let Some(pipe) = stdout.as_mut()
        && let Some(scratch) = scratch.as_mut()
        && let Ok(read) = pipe.read(scratch)
        && read > 0
        && let Some(hook) = on_first_output.take()
    {
        hook();
        return true;
    }
    false
}

fn run_worker_inner(
    control: &Arc<ProcessJobControl>,
    spec: ProcessJobSpec,
    stdout_mode: StdoutMode,
) -> Result<ProcessJobOutput, ProcessJobError> {
    let mut command = std::process::Command::new(&spec.program);
    command
        .args(&spec.args)
        .envs(spec.environment.iter().map(|(key, value)| (key, value)))
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Serializes cancel-vs-spawn publication. A cancel before this lock prevents
    // spawn; a cancel after it observes the published PGID and sends SIGKILL.
    let mut owned = {
        let mut launch = control
            .launch
            .lock()
            .map_err(|_| ProcessJobError::operational("process-job launch mutex poisoned"))?;
        if launch.cancelled {
            return Err(ProcessJobError::cancelled(format!(
                "{} cancelled before subprocess spawn",
                control.label
            )));
        }
        let child = command.spawn().map_err(|error| {
            ProcessJobError::operational(format!(
                "spawning {} for {}: {error}",
                spec.program.display(),
                control.label
            ))
        })?;
        // Construct the owner before publishing the PGID. `from_child` is
        // infallible for an OS-spawned child, leaving no post-spawn error path
        // on which bare `Child::drop` could detach it.
        let owned = OwnedProcessGroup::new(child);
        launch.pgid = Some(owned.pgid);
        owned
    };

    // The live Child + PGID owner intentionally lives OUTSIDE this closure.
    // Any panic after publication returns here while the sole waiter is still
    // available for explicit cleanup; only then may run_worker clear the PGID,
    // publish completion, or remove the registry entry.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        #[cfg(test)]
        maybe_panic_after_spawn(&control.label);
        supervise_owned_process_group(control, spec, stdout_mode, &mut owned)
    })) {
        Ok(result) => result,
        Err(panic) => {
            let detail = panic_detail(panic.as_ref());
            let cleanup = owned.kill_and_reap(&control.label).err();
            let cleanup_detail = cleanup
                .map(|error| format!("; cleanup completed with errors: {error}"))
                .unwrap_or_default();
            Err(ProcessJobError::operational(format!(
                "{} worker panicked: {detail}{cleanup_detail}",
                control.label
            )))
        }
    }
}

fn supervise_owned_process_group(
    control: &Arc<ProcessJobControl>,
    spec: ProcessJobSpec,
    stdout_mode: StdoutMode,
    owned: &mut OwnedProcessGroup,
) -> Result<ProcessJobOutput, ProcessJobError> {
    let pgid = owned.pgid;
    let mut failures = FailureLatch::default();
    let mut stdout = owned.child.stdout.take();
    let mut stderr = owned.child.stderr.take();
    if stdout.is_none() {
        failures.record("subprocess stdout pipe was not created");
        control.cancel();
    }
    if stderr.is_none() {
        failures.record("subprocess stderr pipe was not created");
        control.cancel();
    }
    if let Some(pipe) = stdout.as_ref()
        && let Err(error) = make_nonblocking(pipe)
    {
        failures.record(format!("making subprocess stdout nonblocking: {error}"));
        stdout = None;
        control.cancel();
    }
    if let Some(pipe) = stderr.as_ref()
        && let Err(error) = make_nonblocking(pipe)
    {
        failures.record(format!("making subprocess stderr nonblocking: {error}"));
        stderr = None;
        control.cancel();
    }

    let mut stdout_bytes = Vec::new();
    let mut stdout_bytes_read = 0usize;
    let mut stderr_bytes = Vec::new();
    let mut stdout_exceeded_limit = false;
    let mut pending_stdout = None;
    let (stdout_sender, mut on_first_output) = match stdout_mode {
        StdoutMode::Retain => (None, None),
        StdoutMode::Stream {
            sender,
            on_first_output,
        } => (Some(sender), on_first_output),
    };
    // Reused across every WouldBlock poll. A fresh allocation is needed only
    // when an actual chunk transfers ownership into the bounded channel.
    let mut stdout_scratch = stdout_sender.as_ref().map(|_| vec![0u8; 64 * 1024]);
    let mut kill_sent = false;

    loop {
        // Cancellation must not depend on a streaming consumer making room.
        // Discard the one bounded pending chunk and close our stdout pipe before
        // trying the channel again; otherwise a cleanup-ticket/supervisor cancel
        // can leave the worker retrying `Full` forever after the child is dead.
        if control.is_cancelled() {
            // TASK-297 HIGH-2: before discarding the child's stdout pipe UNREAD, do a NON-BLOCKING
            // DRAIN. A small child can write its complete NAR into the kernel pipe during the 1ms
            // poll gap; if a peer then cancels, closing the pipe unread would leave the first-output
            // hook unfired and REFUND a completed dump - a calibratable, timed-retry exploit. So if
            // the pipe ALREADY has queued bytes (the child produced real output), FIRE the hook
            // (-> COMMIT) before discarding. An empty pipe (a genuinely zero-output child, or a start
            // failure) leaves the hook unfired -> the caller's guard refunds, preserving "no-work
            // requests cost nothing". Only the EXISTENCE of output matters here; these bytes are not
            // served. `on_first_output` is still `Some` only if no earlier read already fired it (a
            // read that produced `pending_stdout` fired it), so this drain is the ONE remaining place
            // a produced-but-unread dump can be observed.
            drain_and_fire_first_output(&mut stdout, &mut stdout_scratch, &mut on_first_output);
            pending_stdout = None;
            stdout = None;
        }
        if let Some(sender) = stdout_sender.as_ref() {
            if let Some(chunk) = pending_stdout.take() {
                match sender.try_send(chunk) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(chunk)) => {
                        #[cfg(test)]
                        control.stream_backpressured.store(true, Ordering::Release);
                        pending_stdout = Some(chunk);
                    }
                    Err(mpsc::error::TrySendError::Closed(_chunk)) => {
                        stdout = None;
                        control.cancel();
                    }
                }
            }
            // Read only when the previous chunk has been accepted. This is the
            // process-pipe backpressure point; stderr/cancel/wait handling below
            // continues even while `pending_stdout` occupies the one slot.
            if pending_stdout.is_none()
                && let Some(pipe) = stdout.as_mut()
            {
                let scratch = stdout_scratch
                    .as_mut()
                    .expect("streaming stdout always has one reusable scratch buffer");
                match pipe.read(scratch) {
                    Ok(0) => stdout = None,
                    Ok(read) => {
                        // FIRST real child output (this arm is only reached for read >= 1; `Ok(0)`
                        // is EOF above). Fire the first-output hook HERE - at the supervisor read,
                        // before the chunk is even staged for the downstream consumer - so a caller's
                        // "producer emitted output" commit cannot be undone by a consumer cancel in
                        // the read->send buffering gap (TASK-297 HIGH-2). Fires at most once.
                        if let Some(hook) = on_first_output.take() {
                            hook();
                        }
                        let previous = stdout_bytes_read;
                        stdout_bytes_read = match spec.stdout_limit {
                            Some(limit) => {
                                previous.saturating_add(read).min(limit.saturating_add(1))
                            }
                            None => previous.saturating_add(read),
                        };
                        let allowed = spec
                            .stdout_limit
                            .map(|limit| limit.saturating_sub(previous))
                            .unwrap_or(read)
                            .min(read);
                        if allowed != 0 {
                            let mut chunk = std::mem::replace(scratch, vec![0u8; 64 * 1024]);
                            chunk.truncate(allowed);
                            pending_stdout = Some(chunk);
                        }
                        if allowed != read {
                            stdout_exceeded_limit = true;
                            stdout = None;
                            control.cancel();
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        failures.record(format!("reading subprocess stdout: {error}"));
                        stdout = None;
                        control.cancel();
                    }
                }
            }
        } else if let Some(pipe) = stdout.as_mut() {
            match drain_pipe(pipe, &mut stdout_bytes, spec.stdout_limit, true) {
                Ok(DrainState::Open) => {}
                Ok(DrainState::Eof) => stdout = None,
                Ok(DrainState::Exceeded) => {
                    stdout_exceeded_limit = true;
                    stdout = None;
                    control.cancel();
                }
                Err(error) => {
                    failures.record(format!("reading subprocess stdout: {error}"));
                    stdout = None;
                    control.cancel();
                }
            }
            stdout_bytes_read = stdout_bytes.len();
        }
        if let Some(pipe) = stderr.as_mut() {
            match drain_pipe(pipe, &mut stderr_bytes, Some(spec.stderr_limit), false) {
                Ok(DrainState::Open | DrainState::Exceeded) => {}
                Ok(DrainState::Eof) => stderr = None,
                Err(error) => {
                    failures.record(format!("reading subprocess stderr: {error}"));
                    stderr = None;
                    control.cancel();
                }
            }
        }

        if control.is_cancelled() && !kill_sent {
            if let Err(error) = kill_group(pgid) {
                failures.record(error.to_string());
            } else {
                kill_sent = true;
            }
        }
        if owned.direct_status.is_none() {
            match owned.child.try_wait() {
                Ok(Some(status)) => {
                    owned.direct_status = Some(status);
                    if !kill_sent {
                        if let Err(error) = kill_group(pgid) {
                            failures.record(error.to_string());
                        } else {
                            kill_sent = true;
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    failures.record(format!("waiting direct child: {error}"));
                    control.cancel();
                }
            }
        }
        if owned.direct_status.is_some() && !owned.descendants_reaped {
            match reap_descendants_once(pgid) {
                Ok(true) => owned.descendants_reaped = true,
                Ok(false) => {}
                Err(error) => failures.record(error.to_string()),
            }
        }
        if owned.direct_status.is_some()
            && owned.descendants_reaped
            && stdout.is_none()
            && pending_stdout.is_none()
            && stderr.is_none()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    if let Some(error) = failures.finish(&control.label) {
        return Err(error);
    }
    Ok(ProcessJobOutput {
        status: owned.direct_status.ok_or_else(|| {
            ProcessJobError::operational(format!(
                "{} reached child-free completion without direct status",
                control.label
            ))
        })?,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
        stdout_exceeded_limit,
        stdout_bytes_read,
    })
}

enum DrainState {
    Open,
    Eof,
    Exceeded,
}

fn make_nonblocking(pipe: impl AsFd) -> Result<(), rustix::io::Errno> {
    let flags = rustix::fs::fcntl_getfl(pipe.as_fd())?;
    rustix::fs::fcntl_setfl(pipe.as_fd(), flags | rustix::fs::OFlags::NONBLOCK)
}

fn drain_pipe(
    pipe: &mut (impl Read + ?Sized),
    retained: &mut Vec<u8>,
    limit: Option<usize>,
    stop_on_exceeded: bool,
) -> std::io::Result<DrainState> {
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(DrainState::Eof),
            Ok(read) => {
                let retain_limit = limit
                    .and_then(|limit| limit.checked_add(usize::from(stop_on_exceeded)))
                    .unwrap_or(usize::MAX);
                let keep = read.min(retain_limit.saturating_sub(retained.len()));
                retained.extend_from_slice(&chunk[..keep]);
                if let Some(limit) = limit
                    && (retained.len() > limit || keep != read)
                    && stop_on_exceeded
                {
                    return Ok(DrainState::Exceeded);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(DrainState::Open);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn kill_group(pgid: Pid) -> Result<(), ProcessJobError> {
    match rustix::process::kill_process_group(pgid, Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(ProcessJobError::operational(format!(
            "killing supervised process group {}: {error}",
            pgid.as_raw_nonzero()
        ))),
    }
}

/// Reap everything currently waitable, returning true only at `ECHILD`.
fn reap_descendants_once(pgid: Pid) -> Result<bool, ProcessJobError> {
    loop {
        match rustix::process::waitpgid(pgid, WaitOptions::NOHANG) {
            Ok(Some((_pid, _status))) => continue,
            Ok(None) => return Ok(false),
            Err(rustix::io::Errno::CHILD) => return Ok(true),
            Err(error) => {
                return Err(ProcessJobError::operational(format!(
                    "reaping descendants from supervised process group {}: {error}",
                    pgid.as_raw_nonzero()
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TASK-297 HIGH-2 (round-5): the child-wrote / cancel-before-read interleaving. A REAL spawned
    /// child writes output into its stdout pipe, then the cancellation-path DRAIN runs (standing in
    /// for a cancel that lands before the worker's normal read poll). Because the child produced
    /// output, the drain fires the first-output hook -> the charge COMMITS. This is the completed
    /// small-NAR dump the 1ms-poll + discard-unread window would otherwise refund.
    ///
    /// MUTATION: no-op `drain_and_fire_first_output` (revert the drain) and this reddens - the
    /// produced-but-unread dump would leave the hook unfired and be refunded.
    #[test]
    fn drain_on_cancel_commits_a_spawned_child_that_already_wrote() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "printf OUTPUT; sleep 30"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child");
        let pipe = child.stdout.take().expect("child stdout");
        make_nonblocking(&pipe).expect("nonblocking");
        let mut stdout = Some(pipe);
        let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_fired = std::sync::Arc::clone(&fired);
        let mut on_first_output: Option<Box<dyn FnOnce() + Send>> = Some(Box::new(move || {
            hook_fired.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        let mut scratch = Some(vec![0u8; 64 * 1024]);
        // Retry the NON-BLOCKING drain until the child's bytes have reached the pipe; a
        // produced-but-unread dump MUST fire the hook on the cancel path.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !fired.load(std::sync::atomic::Ordering::SeqCst) {
            drain_and_fire_first_output(&mut stdout, &mut scratch, &mut on_first_output);
            assert!(
                std::time::Instant::now() < deadline,
                "the cancel-path drain must fire the first-output hook once a spawned child has \
                 written output"
            );
            if !fired.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The control (distinguish real-work from no-work): a REAL spawned child that produces NO output
    /// (an actually-spawned silent child, NOT a nonexistent-executable spawn failure) leaves the hook
    /// unfired on the cancel-path drain -> the caller's guard REFUNDS.
    #[test]
    fn drain_on_cancel_refunds_a_spawned_child_that_emitted_nothing() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child");
        let pipe = child.stdout.take().expect("child stdout");
        make_nonblocking(&pipe).expect("nonblocking");
        let mut stdout = Some(pipe);
        let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_fired = std::sync::Arc::clone(&fired);
        let mut on_first_output: Option<Box<dyn FnOnce() + Send>> = Some(Box::new(move || {
            hook_fired.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        let mut scratch = Some(vec![0u8; 64 * 1024]);
        // Give the silent child time to run; the pipe stays empty, so every drain fires nothing.
        for _ in 0..10 {
            assert!(
                !drain_and_fire_first_output(&mut stdout, &mut scratch, &mut on_first_output),
                "a spawned child that emits nothing must not fire the first-output hook"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !fired.load(std::sync::atomic::Ordering::SeqCst),
            "a zero-output child must leave the hook unfired on the cancel-path drain (it refunds)"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn cancellation_reaps_with_a_full_stream_receiver() {
        let registry = ProcessJobRegistry::default();
        let (stdout_tx, held_full_receiver) = mpsc::channel(1);
        let job = registry
            .start_streaming(
                "full-stream-cancel-regression",
                ProcessJobSpec {
                    program: PathBuf::from("sh"),
                    args: vec![
                        OsString::from("-c"),
                        OsString::from("dd if=/dev/zero bs=65536 count=8 2>/dev/null; sleep 60"),
                    ],
                    environment: Vec::new(),
                    stdout_limit: Some(1024 * 1024),
                    stderr_limit: 1024,
                },
                stdout_tx,
                None,
            )
            .expect("start streaming process");

        // Keep the receiver alive but deliberately never drain it. Prove both
        // preconditions rather than sleeping and hoping: the channel is full,
        // and the worker has hit `TrySendError::Full` while retaining its one
        // permitted pending chunk.
        let full_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while held_full_receiver.len() != held_full_receiver.max_capacity()
            || !job.control.stream_backpressured.load(Ordering::Acquire)
        {
            assert!(
                std::time::Instant::now() < full_deadline,
                "stream did not reach a proven full+pending state"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        job.cancel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done_tx.send(job.wait());
        });
        let result = done_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("cancellation must reap despite the full retained receiver");
        let output = result.expect("SIGKILL cleanup itself remains operational");
        assert!(
            !output.status.success(),
            "cancelled child must not report success"
        );
        assert_eq!(
            registry.active_len(),
            0,
            "child-free job unregisters exactly once"
        );
    }

    #[test]
    fn post_spawn_panic_reaps_child_and_grandchild_before_unregistering() {
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            JOB_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let pid_file = std::env::temp_dir().join(format!("nix-p2p-post-spawn-panic-{suffix}.pids"));
        let label = format!("post-spawn-panic-regression-{suffix}");
        arm_post_spawn_panic(label.clone(), pid_file.clone());

        let registry = ProcessJobRegistry::default();
        let job = registry
            .start(
                label,
                ProcessJobSpec {
                    program: PathBuf::from("sh"),
                    args: vec![
                        OsString::from("-c"),
                        OsString::from(
                            "(while :; do sleep 60; done) & grand=$!; \
                             printf '%s %s\\n' \"$$\" \"$grand\" > \"$1\"; wait",
                        ),
                        OsString::from("nix-p2p-post-spawn-panic-helper"),
                        pid_file.as_os_str().to_owned(),
                    ],
                    environment: Vec::new(),
                    stdout_limit: Some(1),
                    stderr_limit: 1024,
                },
            )
            .expect("registered panic-path process worker");
        assert_eq!(registry.active_len(), 1);

        let error = job
            .wait()
            .expect_err("deterministic post-spawn panic must fail loudly");
        assert!(
            error
                .to_string()
                .contains("deterministic panic after process-group publication"),
            "unexpected worker error: {error}"
        );

        let unregister_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while registry.active_len() != 0 {
            assert!(
                std::time::Instant::now() < unregister_deadline,
                "child-free worker did not unregister"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        let raw_pids = std::fs::read_to_string(&pid_file)
            .expect("helper published direct-child and grandchild PIDs");
        let pids = raw_pids
            .split_whitespace()
            .map(|raw| raw.parse::<i32>().expect("decimal helper PID"))
            .collect::<Vec<_>>();
        assert_eq!(pids.len(), 2);
        for pid in &pids {
            assert!(
                !PathBuf::from(format!("/proc/{pid}")).exists(),
                "panic-path supervised PID {pid} remains alive or zombie after unregister"
            );
        }

        let pgid = Pid::from_raw(pids[0]).expect("spawned shell PID is nonzero");
        assert!(
            reap_descendants_once(pgid).expect("postcondition waitpgid succeeds"),
            "same-PGID descendant remains waitable after registry removal"
        );
        let failures = registry.recorded_failures();
        assert_eq!(failures.len(), 1, "panic is latched exactly once");
        assert!(failures[0].contains("worker panicked"), "{failures:?}");
        let _ = std::fs::remove_file(pid_file);
    }
}
