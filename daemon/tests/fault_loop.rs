//! AC#2: the in-process fault-mode loop - daemon -> REAL testproxy binary ->
//! in-process mock origin, all over loopback, no containers.
//!
//! The testproxy is the permanent fixture that OWNS fault injection (PRD); the
//! daemon must never contain adversarial logic. Crate independence forbids the
//! daemon linking the testproxy crate, so this test drives the testproxy as an
//! external process and pokes its fault admin endpoint over HTTP - exactly how
//! the container harness (task-5) will.
//!
//! Locating the binary: `TESTPROXY_BIN`, else the sibling of this test binary in
//! the cargo target dir (present under `just test` / `cargo test --workspace`
//! and in `nix flake check`'s workspace test). If neither exists - e.g. the
//! package-only `nix build .#daemon`, which does not build the fixture bin - the
//! test SKIPS loudly rather than failing or passing vacuously. Every other AC is
//! covered by the always-available in-process mock upstream, so this skip never
//! hides a regression.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::{MockResponse, MockUpstream, get, request, spawn_daemon};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

const NAR_LEN: usize = 4096;

/// Safety margin below the upstream header deadline for the fast-fallback bound.
///
/// A *fast* fallback - connection refused, a `connection_reset`, or the proxy's
/// own `unreachable` 502 with no upstream contacted - returns in MILLISECONDS; it
/// never waits on the daemon's upstream header timeout. So the "failed fast, did
/// not wait the deadline out" property is asserted as `elapsed <
/// HARNESS_HEADER_TIMEOUT - FAST_FALLBACK_MARGIN`, i.e. keyed off the real
/// upstream deadline rather than a tight absolute wall clock:
///
///   * Load-tolerant. The fast path is milliseconds, so a 10 s - 2 s = 8 s bound
///     leaves ~8 s of slack. Scheduler jitter on a loaded box moves the fast
///     path by milliseconds-to-hundreds-of-ms, nowhere near 8 s, so correct code
///     never trips it. (The pre-task-109 `< 2 s` form instead asserted the HOST
///     could schedule a loopback round-trip within 2 s - a claim about the
///     machine, not the daemon - and that is what flaked under load.)
///   * Still bites, with margin. A regression that WAITS OUT the deadline instead
///     of failing fast elapses to >= HARNESS_HEADER_TIMEOUT (10 s), which exceeds
///     the 8 s bound by the full 2 s margin. That is a robust bite, not the
///     photo-finish at the exact 10 s boundary that the previous `< 10 s` bound
///     gave (where a header-timeout firing a hair early could slip under).
const FAST_FALLBACK_MARGIN: Duration = Duration::from_secs(2);

fn nar_bytes() -> Vec<u8> {
    (0..NAR_LEN).map(|i| (i % 251) as u8).collect()
}

const NARINFO: &[u8] = b"StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
URL: nar/testnar.nar\n\
Compression: none\n\
FileHash: sha256:0000000000000000000000000000000000000000000000000000\n\
FileSize: 4096\n\
NarHash: sha256:1111111111111111111111111111111111111111111111111111\n\
NarSize: 4096\n\
References: \n\
Sig: nix-p2p-test-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n";

fn find_testproxy() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("TESTPROXY_BIN") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    // Sibling in target/<profile>/ (this test runs from target/<profile>/deps/).
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?;
    for name in ["testproxy", "testproxy.exe"] {
        let candidate = profile_dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// A running testproxy child; killed on drop. Owns its temp cache dir.
struct Testproxy {
    addr: SocketAddr,
    _child: Child,
    cache_dir: PathBuf,
}

impl Testproxy {
    async fn spawn(bin: &PathBuf, upstream: &str) -> Testproxy {
        static NONCE: AtomicU64 = AtomicU64::new(0);
        let cache_dir = std::env::temp_dir().join(format!(
            "daemon-faultloop-{}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&cache_dir).unwrap();

        let mut child = Command::new(bin)
            .arg("--listen")
            .arg("127.0.0.1:0")
            .arg("--upstream")
            .arg(upstream)
            .arg("--cache-dir")
            .arg(&cache_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn testproxy");

        let stderr = child.stderr.take().expect("piped stderr");
        let mut lines = BufReader::new(stderr).lines();
        let addr = timeout(Duration::from_secs(10), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                if let Some((_, rest)) = line.split_once("listening on ") {
                    let addr_str = rest.split(" ->").next().unwrap().trim();
                    return addr_str.parse::<SocketAddr>().expect("parse proxy addr");
                }
            }
            panic!("testproxy exited before announcing a listen address");
        })
        .await
        .expect("testproxy announced its address within 10s");

        // Drain remaining stderr so the pipe never fills and blocks the child.
        tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });

        Testproxy {
            addr,
            _child: child,
            cache_dir,
        }
    }
}

impl Drop for Testproxy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.cache_dir);
    }
}

async fn set_fault(proxy: SocketAddr, query: &str) {
    let resp = request(proxy, "POST", &format!("/__testproxy/faults?{query}")).await;
    assert_eq!(
        resp.status,
        Some(200),
        "fault {query:?} rejected: {}",
        resp.body_string()
    );
}

async fn clear_faults(proxy: SocketAddr) {
    let resp = request(proxy, "POST", "/__testproxy/faults/clear").await;
    assert_eq!(resp.status, Some(200));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fault_mode_loop() {
    let Some(bin) = find_testproxy() else {
        eprintln!(
            "SKIP fault_mode_loop: testproxy binary not found. Set TESTPROXY_BIN or run \
             via `just test` (cargo test --workspace builds it). Every other AC is \
             covered by the in-process mock upstream, so this skip hides no regression."
        );
        return;
    };

    // Mock origin behind the testproxy.
    let origin = MockUpstream::start(|_m, path| match path {
        "/nix-cache-info" => MockResponse::ok(
            "text/x-nix-cache-info",
            b"StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n".to_vec(),
        ),
        "/test.narinfo" => MockResponse::ok("text/x-nix-narinfo", NARINFO.to_vec()),
        "/nar/testnar.nar" => MockResponse::ok("application/x-nix-nar", nar_bytes()),
        _ => MockResponse::status(404),
    });
    let proxy = Testproxy::spawn(&bin, &origin.base_url()).await;
    let (daemon, _daemon) = spawn_daemon(&format!("http://{}", proxy.addr)).await;

    // ---- clean passthrough: warms the testproxy cache and proves S1 ----
    let narinfo = get(daemon, "/test.narinfo").await;
    assert_eq!(narinfo.status, Some(200));
    assert_eq!(narinfo.body, NARINFO, "clean narinfo is byte-identical");

    let nar = get(daemon, "/nar/testnar.nar").await;
    assert_eq!(nar.status, Some(200));
    assert_eq!(nar.body, nar_bytes(), "clean NAR is byte-identical");
    assert!(nar.complete, "clean NAR transfer is complete");

    // ---- fault 1: HTTP 503 on NAR -> forwarded verbatim ----
    set_fault(proxy.addr, "http_error=503&http_error_kind=nar").await;
    assert_eq!(get(daemon, "/nar/testnar.nar").await.status, Some(503));
    clear_faults(proxy.addr).await;

    // ---- fault 2: upstream unreachable -> fast clean 502 ----
    set_fault(proxy.addr, "unreachable=1").await;
    let start = Instant::now();
    let resp = get(daemon, "/nar/testnar.nar").await;
    assert_eq!(resp.status, Some(502));
    // Bounded by the harness's own upstream timeout MINUS a margin, not by a
    // wall-clock constant (task-109 introduced the timeout key; task-173 added
    // the margin). The property this guards is "the daemon failed FAST instead of
    // waiting out its upstream deadline". Stating it as `< 2s` also asserted the
    // HOST could schedule a loopback round-trip within two seconds - a claim about
    // the machine that fails on correct code under load. Keying the bound off
    // HARNESS_HEADER_TIMEOUT states the real invariant; subtracting
    // FAST_FALLBACK_MARGIN turns the bite from a photo-finish at the exact
    // deadline into a robust one: a regression that DID wait the timeout out takes
    // >= HARNESS_HEADER_TIMEOUT, exceeding this bound by the full margin, while a
    // millisecond-scale fast path clears it with ~8s of slack. See
    // FAST_FALLBACK_MARGIN.
    let elapsed = start.elapsed();
    assert!(
        elapsed < common::HARNESS_HEADER_TIMEOUT - FAST_FALLBACK_MARGIN,
        "must not hang: failed after {elapsed:?}, within {FAST_FALLBACK_MARGIN:?} \
         of the {:?} upstream header timeout - it waited the deadline out rather \
         than failing fast",
        common::HARNESS_HEADER_TIMEOUT
    );
    clear_faults(proxy.addr).await;

    // ---- fault 3: connection reset -> clean gateway error, no hang ----
    set_fault(proxy.addr, "connection_reset=nar").await;
    let start = Instant::now();
    let resp = get(daemon, "/nar/testnar.nar").await;
    assert!(
        resp.status == Some(502) || resp.status.is_none(),
        "reset yields a clean failure, got {:?}",
        resp.status
    );
    // Bounded by the harness's own upstream timeout MINUS a margin, not by a
    // wall-clock constant (task-109 introduced the timeout key; task-173 added
    // the margin). The property this guards is "the daemon failed FAST instead of
    // waiting out its upstream deadline". Stating it as `< 2s` also asserted the
    // HOST could schedule a loopback round-trip within two seconds - a claim about
    // the machine that fails on correct code under load. Keying the bound off
    // HARNESS_HEADER_TIMEOUT states the real invariant; subtracting
    // FAST_FALLBACK_MARGIN turns the bite from a photo-finish at the exact
    // deadline into a robust one: a regression that DID wait the timeout out takes
    // >= HARNESS_HEADER_TIMEOUT, exceeding this bound by the full margin, while a
    // millisecond-scale fast path clears it with ~8s of slack. See
    // FAST_FALLBACK_MARGIN.
    let elapsed = start.elapsed();
    assert!(
        elapsed < common::HARNESS_HEADER_TIMEOUT - FAST_FALLBACK_MARGIN,
        "must not hang: failed after {elapsed:?}, within {FAST_FALLBACK_MARGIN:?} \
         of the {:?} upstream header timeout - it waited the deadline out rather \
         than failing fast",
        common::HARNESS_HEADER_TIMEOUT
    );
    clear_faults(proxy.addr).await;

    // ---- fault 4: truncated NAR -> client sees a SHORT transfer ----
    set_fault(proxy.addr, "truncate_pct=50").await;
    let resp = get(daemon, "/nar/testnar.nar").await;
    assert!(
        !resp.complete,
        "a truncated upstream NAR must surface as an incomplete transfer, not padded"
    );
    assert!(
        (resp.body.len() as usize) < NAR_LEN,
        "truncated body ({}) must be shorter than the full NAR ({NAR_LEN})",
        resp.body.len()
    );
    clear_faults(proxy.addr).await;

    // ---- fault 5: corrupted NAR -> forwarded verbatim for the client's gate ----
    set_fault(proxy.addr, "corrupt_nar=1").await;
    let resp = get(daemon, "/nar/testnar.nar").await;
    assert_eq!(resp.status, Some(200));
    let corrupted: Vec<u8> = nar_bytes().iter().map(|b| !b).collect();
    assert_eq!(
        resp.body, corrupted,
        "daemon relays corrupted bytes unchanged"
    );
    assert_ne!(
        resp.body,
        nar_bytes(),
        "corruption is not masked by the daemon"
    );
    clear_faults(proxy.addr).await;

    // ---- fault 6: wrong/stale narinfo -> mutation forwarded verbatim ----
    set_fault(proxy.addr, "wrong_narinfo=1").await;
    let resp = get(daemon, "/test.narinfo").await;
    assert_eq!(resp.status, Some(200));
    assert_ne!(
        resp.body, NARINFO,
        "a mutated narinfo must reach the client changed (its sig then fails)"
    );
    clear_faults(proxy.addr).await;

    // ---- fault 7: added NAR latency -> daemon waits and stays correct ----
    set_fault(proxy.addr, "latency_nar_ms=200").await;
    let start = Instant::now();
    let resp = get(daemon, "/nar/testnar.nar").await;
    assert_eq!(resp.status, Some(200));
    assert_eq!(
        resp.body,
        nar_bytes(),
        "a slow-but-correct upstream still yields correct bytes"
    );
    assert!(
        start.elapsed() >= Duration::from_millis(150),
        "the injected latency should be observable"
    );
    clear_faults(proxy.addr).await;
}
