#![cfg(unix)]

//! The product binary, not only the library API, must route SIGTERM through the
//! named Iroh shutdown path.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use daemon::{
    Blake3Digest, IROH_IDENTITY_FILENAME, IrohClientNode, IrohPeerAddr, KnownTransport, NodeId,
    Transport,
};
use rustix::process::{Pid, Signal, kill_process, kill_process_group};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nix-p2p-task115-daemon-shutdown-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("unique test directory");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct RunningDaemon {
    child: Child,
    pid: u32,
    lines: mpsc::Receiver<String>,
    stdout_reader: std::thread::JoinHandle<String>,
    port: u16,
}

struct Startup {
    node_id: Option<String>,
    sockets: Vec<SocketAddr>,
    seed: Option<Blake3Digest>,
}

#[derive(Debug, Clone, Copy)]
struct ProcessOracle {
    pid: u32,
    pgid: u32,
}

fn unused_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn_daemon(
    state: &std::path::Path,
    port: u16,
    print_address: bool,
    seed: Option<&std::path::Path>,
) -> RunningDaemon {
    let mut command = Command::new(env!("CARGO_BIN_EXE_daemon"));
    let port_arg = port.to_string();
    command
        .args([
            "--listen",
            "127.0.0.1:0",
            "--upstream",
            "http://127.0.0.1:9",
            "--iroh-provider",
            "--iroh-state-dir",
            state.to_str().expect("UTF-8 test path"),
            "--iroh-endpoint-scope",
            "offline-test",
            "--iroh-port",
            &port_arg,
        ])
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if print_address {
        command.arg("--iroh-print-peer-address");
    }
    if let Some(seed) = seed {
        command.arg("--iroh-seed-nar").arg(seed);
    }
    let mut child = command.spawn().expect("spawn daemon binary");
    let pid = child.id();
    let stdout = child.stdout.take().expect("piped stdout");
    let (line_tx, line_rx) = mpsc::channel();
    let stdout_reader = std::thread::spawn(move || {
        let mut complete = String::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("read daemon stdout");
            complete.push_str(&line);
            complete.push('\n');
            let _ = line_tx.send(line);
        }
        complete
    });
    RunningDaemon {
        child,
        pid,
        lines: line_rx,
        stdout_reader,
        port,
    }
}

impl RunningDaemon {
    fn await_startup(&self, expect_address: bool, expect_seed: bool) -> Startup {
        let startup_deadline = Instant::now() + Duration::from_secs(5);
        let mut listening = false;
        let mut node_id = None;
        let mut sockets = Vec::new();
        let mut seed = None;
        while !listening || (expect_address && node_id.is_none()) || (expect_seed && seed.is_none())
        {
            let remaining = startup_deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "daemon did not reach its serve loop");
            let line = self
                .lines
                .recv_timeout(remaining)
                .expect("daemon did not complete startup");
            listening |= line.starts_with("daemon: listening on ");
            if line.starts_with("IROH-PROVIDER-ADDR ") {
                node_id = line
                    .split_whitespace()
                    .find_map(|field| field.strip_prefix("node_id="))
                    .map(str::to_owned);
                sockets = line
                    .split_whitespace()
                    .find_map(|field| field.strip_prefix("sockets="))
                    .into_iter()
                    .flat_map(|csv| csv.split(','))
                    .map(|socket| socket.parse::<SocketAddr>().expect("provider socket"))
                    .collect();
                assert!(!sockets.is_empty(), "provider published no fixed sockets");
                assert!(
                    sockets.iter().all(|socket| socket.port() == self.port),
                    "provider published a socket outside selected port {}: {sockets:?}",
                    self.port
                );
            }
            if line.starts_with("IROH-SEED ") {
                seed = line
                    .split_whitespace()
                    .find_map(|field| field.strip_prefix("blake3="))
                    .map(|hex| format!("blake3:{hex}").parse().expect("seed digest"));
            }
        }
        Startup {
            node_id,
            sockets,
            seed,
        }
    }

    fn terminate(mut self) -> (ExitStatus, String, String, Vec<ProcessOracle>) {
        let descendants = descendant_pids(self.pid)
            .into_iter()
            .map(|pid| ProcessOracle {
                pid,
                pgid: process_group_of(pid).unwrap_or(pid),
            })
            .collect();
        let pid = Pid::from_raw(self.pid as i32).expect("child PID is positive");
        kill_process(pid, Signal::TERM).expect("send SIGTERM to daemon");

        let exit_deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("poll daemon exit") {
                break status;
            }
            if Instant::now() >= exit_deadline {
                let _ = self.child.kill();
                panic!("daemon ignored SIGTERM or exceeded its shutdown deadline");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = self.stdout_reader.join().expect("stdout reader thread");
        let mut stderr = String::new();
        self.child
            .stderr
            .take()
            .expect("piped stderr")
            .read_to_string(&mut stderr)
            .expect("read daemon stderr");
        (status, stdout, stderr, descendants)
    }
}

fn descendant_pids(root: u32) -> Vec<u32> {
    let mut found = HashSet::new();
    let mut pending = vec![root];
    while let Some(pid) = pending.pop() {
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
            continue;
        };
        for task in tasks.flatten() {
            let children =
                std::fs::read_to_string(task.path().join("children")).unwrap_or_default();
            for child in children.split_whitespace() {
                if let Ok(child) = child.parse::<u32>()
                    && found.insert(child)
                {
                    pending.push(child);
                }
            }
        }
    }
    let mut found = found.into_iter().collect::<Vec<_>>();
    found.sort_unstable();
    found
}

fn process_group_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_name, fields) = stat.rsplit_once(") ")?;
    fields
        .split_whitespace()
        .nth(2)
        .and_then(|field| field.parse().ok())
}

fn process_group_members(group: u32) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| process_group_of(*pid) == Some(group))
        .collect()
}

fn process_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_name, fields) = stat.rsplit_once(") ")?;
    fields.chars().next()
}

fn is_raw_nar_helper(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .is_some_and(|cmdline| {
            cmdline
                .split(|byte| *byte == 0)
                .any(|argument| argument == b"__dump-raw-nar")
        })
}

fn stop_next_raw_nar_helper(daemon_pid: u32) -> Result<ProcessOracle, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        for pid in descendant_pids(daemon_pid) {
            if !is_raw_nar_helper(pid) {
                continue;
            }
            let Some(pgid) = process_group_of(pid) else {
                continue;
            };
            let group = Pid::from_raw(pgid as i32)
                .ok_or_else(|| format!("raw-NAR helper {pid} reported invalid PGID {pgid}"))?;
            if kill_process_group(group, Signal::STOP).is_err() {
                continue;
            }
            let stopped_deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < stopped_deadline {
                if matches!(process_state(pid), Some('T' | 't')) {
                    return Ok(ProcessOracle { pid, pgid });
                }
                if !PathBuf::from(format!("/proc/{pid}")).exists() {
                    break;
                }
                std::thread::yield_now();
            }
        }
        std::thread::yield_now();
    }
    Err(format!(
        "no live raw-NAR helper under daemon {daemon_pid} could be stopped within 5s"
    ))
}

fn assert_clean_shutdown(
    pid: u32,
    status: ExitStatus,
    stdout: &str,
    stderr: &str,
    descendants: &[ProcessOracle],
) {
    assert!(status.success(), "daemon exit={status}; stderr={stderr}");
    assert!(
        stdout.contains("daemon: received SIGTERM; shutting down"),
        "SIGTERM was not observed by the daemon:\n{stdout}"
    );
    assert!(
        stdout.contains("IROH-NODE-SHUTDOWN outcome=Graceful"),
        "daemon bypassed the explicit Iroh shutdown path:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
    for descendant in descendants {
        assert!(
            !PathBuf::from(format!("/proc/{}", descendant.pid)).exists(),
            "recorded daemon descendant {:?} survived shutdown",
            descendant
        );
        assert_eq!(
            process_group_members(descendant.pgid),
            Vec::<u32>::new(),
            "helper-owned process group {} survived shutdown",
            descendant.pgid
        );
    }
    assert_eq!(
        process_group_members(pid),
        Vec::<u32>::new(),
        "daemon process group retained a child/helper after shutdown"
    );
}

#[test]
fn sigterm_restarts_same_identity_and_fixed_port_without_descendants() {
    let temp = TempDir::new();
    let state = temp.0.join("iroh");
    let port = unused_port();

    let first = spawn_daemon(&state, port, true, None);
    let first_pid = first.pid;
    let first_id = first
        .await_startup(true, false)
        .node_id
        .expect("opt-in NodeId line");
    assert!(state.join(IROH_IDENTITY_FILENAME).is_file());
    let (status, stdout, stderr, descendants) = first.terminate();
    assert_clean_shutdown(first_pid, status, &stdout, &stderr, &descendants);

    let restarted = spawn_daemon(&state, port, true, None);
    let restarted_pid = restarted.pid;
    let restarted_id = restarted
        .await_startup(true, false)
        .node_id
        .expect("restart NodeId line");
    assert_eq!(
        restarted_id, first_id,
        "persistent identity changed on restart"
    );
    let (status, stdout, stderr, descendants) = restarted.terminate();
    assert_clean_shutdown(restarted_pid, status, &stdout, &stderr, &descendants);

    let quiet = spawn_daemon(&state, port, false, None);
    let quiet_pid = quiet.pid;
    assert_eq!(quiet.await_startup(false, false).node_id, None);
    let (status, stdout, stderr, descendants) = quiet.terminate();
    assert!(
        !stdout.contains("IROH-PROVIDER-ADDR"),
        "stable identity leaked without --iroh-print-peer-address: {stdout}"
    );
    assert_clean_shutdown(quiet_pid, status, &stdout, &stderr, &descendants);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_cancels_and_reaps_an_active_product_helper_before_restart() {
    let temp = TempDir::new();
    let state = temp.0.join("iroh-active");
    let seed = temp.0.join("active.raw-nar");
    // A large sparse regular file gives the external watcher enough time to
    // observe the real product helper without adding a test hook to production
    // code. The default per-NAR budget is 256 MiB, so this remains admissible.
    std::fs::File::create(&seed)
        .unwrap()
        .set_len(128 * 1024 * 1024)
        .unwrap();
    let port = unused_port();

    let daemon = spawn_daemon(&state, port, true, Some(&seed));
    let daemon_pid = daemon.pid;
    let startup = daemon.await_startup(true, true);
    let node_id: NodeId = startup
        .node_id
        .as_deref()
        .expect("provider NodeId")
        .parse()
        .unwrap();
    let digest = startup.seed.expect("seed digest");
    let client = IrohClientNode::spawn().await.unwrap();
    client.add_peer(&IrohPeerAddr::new(node_id, startup.sockets));
    let transport = client.transport_handle();
    let (helper_tx, helper_rx) = mpsc::sync_channel(1);
    let helper_watcher = std::thread::spawn(move || {
        let _ = helper_tx.send(stop_next_raw_nar_helper(daemon_pid));
    });
    let fetch = tokio::spawn(async move {
        transport
            .fetch(&digest, &KnownTransport::Iroh { node: node_id }, None)
            .await
    });

    let helper = tokio::task::spawn_blocking(move || {
        helper_rx
            .recv_timeout(Duration::from_secs(6))
            .map_err(|error| format!("raw-NAR helper watcher did not report: {error}"))?
    })
    .await
    .unwrap()
    .expect("real product helper was discovered and externally stopped");
    helper_watcher.join().expect("raw-NAR helper watcher");
    assert!(
        descendant_pids(daemon_pid).contains(&helper.pid),
        "stopped helper {} is not owned under daemon {daemon_pid}",
        helper.pid
    );
    assert_ne!(
        helper.pgid, daemon_pid,
        "supplier helper must own its fresh killable process group"
    );
    assert!(
        matches!(process_state(helper.pid), Some('T' | 't')),
        "raw-NAR helper {} was not stopped before SIGTERM",
        helper.pid
    );

    let (status, stdout, stderr, descendants) =
        tokio::task::spawn_blocking(move || daemon.terminate())
            .await
            .unwrap();
    assert!(
        descendants.iter().any(|process| process.pid == helper.pid),
        "active-helper oracle was not captured before SIGTERM: {descendants:?}"
    );
    assert_clean_shutdown(daemon_pid, status, &stdout, &stderr, &descendants);
    let fetch_result = tokio::time::timeout(Duration::from_secs(2), fetch)
        .await
        .expect("fetch observes daemon shutdown")
        .expect("fetch task joins");
    assert!(fetch_result.is_err());
    client.shutdown().await.unwrap();

    let restarted = spawn_daemon(&state, port, true, None);
    let restarted_pid = restarted.pid;
    let restarted_id = restarted
        .await_startup(true, false)
        .node_id
        .expect("restart NodeId");
    assert_eq!(restarted_id, node_id.to_hex());
    let (status, stdout, stderr, descendants) =
        tokio::task::spawn_blocking(move || restarted.terminate())
            .await
            .unwrap();
    assert_clean_shutdown(restarted_pid, status, &stdout, &stderr, &descendants);
}
