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

static JOB_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessJobError {
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
pub(crate) struct ProcessJobSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    /// Retain at most this limit plus one proof byte. `None` is the synchronous
    /// availability hash path, whose existing contract buffers the whole NAR.
    pub stdout_limit: Option<usize>,
    pub stderr_limit: usize,
}

#[derive(Debug)]
pub(crate) struct ProcessJobOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_exceeded_limit: bool,
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
pub(crate) struct ProcessJobRegistry {
    inner: Arc<ProcessJobRegistryInner>,
}

impl ProcessJobRegistry {
    pub(crate) fn start(
        &self,
        label: impl Into<String>,
        spec: ProcessJobSpec,
    ) -> Result<ProcessJob, ProcessJobError> {
        let result = ProcessJob::start(label.into(), spec, Some(Arc::clone(&self.inner)));
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
    pub(crate) fn cancel_all(&self) {
        let jobs = match self.inner.jobs.lock() {
            Ok(jobs) => jobs.values().cloned().collect::<Vec<_>>(),
            Err(poisoned) => poisoned.into_inner().values().cloned().collect(),
        };
        for job in jobs {
            job.cancel();
        }
    }

    pub(crate) fn active_len(&self) -> usize {
        match self.inner.jobs.lock() {
            Ok(jobs) => jobs.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    pub(crate) fn active_labels(&self) -> Vec<String> {
        match self.inner.jobs.lock() {
            Ok(jobs) => jobs.values().map(|job| job.label.clone()).collect(),
            Err(poisoned) => poisoned
                .into_inner()
                .values()
                .map(|job| job.label.clone())
                .collect(),
        }
    }

    pub(crate) fn recorded_failures(&self) -> Vec<String> {
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
pub(crate) struct ProcessJob {
    control: Arc<ProcessJobControl>,
}

impl ProcessJob {
    pub(crate) fn standalone(
        label: impl Into<String>,
        spec: ProcessJobSpec,
    ) -> Result<Self, ProcessJobError> {
        Self::start(label.into(), spec, None)
    }

    fn start(
        label: String,
        spec: ProcessJobSpec,
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
            .spawn(move || run_worker(worker_control, spec, worker_registry))
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

    pub(crate) fn cancel(&self) {
        self.control.cancel();
    }

    pub(crate) fn try_take_result(&self) -> Option<Result<ProcessJobOutput, ProcessJobError>> {
        self.control.try_take_result()
    }

    pub(crate) fn wait(self) -> Result<ProcessJobOutput, ProcessJobError> {
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
    registry: Option<Arc<ProcessJobRegistryInner>>,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_worker_inner(&control, spec)
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

fn run_worker_inner(
    control: &Arc<ProcessJobControl>,
    spec: ProcessJobSpec,
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
        supervise_owned_process_group(control, spec, &mut owned)
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
    let mut stderr_bytes = Vec::new();
    let mut stdout_exceeded_limit = false;
    let mut kill_sent = false;

    loop {
        if let Some(pipe) = stdout.as_mut() {
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
