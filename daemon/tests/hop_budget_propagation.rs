//! TASK-33 F3: prove the composing per-hop header budget PROPAGATES end-to-end and
//! BITES the two mechanisms that make it real.
//!
//! The prior boundary e2e (scripts/e2e_harness.py chain-timeout-boundary) predates
//! this mechanism and does NOT observe propagation: mutating `parse_hop_budget` to
//! always return `None` yields the same loopback L-vs-budget flip, so it cannot tell
//! whether the budget composes at all. The daemon-core unit tests hit `UpstreamHttp`
//! directly, bypassing the SERVER parse + the `FallbackNarSource` p2p-miss wrapper.
//!
//! These tests exercise the REAL wire path -- the server's `parse_hop_budget`, the
//! `FallbackNarSource` (p2p primary MISS -> HTTP secondary, the NORMAL production
//! path), and `UpstreamHttp` writing the outbound `x-nix-p2p-hop-budget-ms` header --
//! and RECORD that outbound header at the upstream. They assert:
//!   (a) the propagated budget is NON-INCREASING across hops (a hop can only shorten
//!       it -- both the single-hop shrink and a live two-daemon chain);
//!   (b) a hostile-large inbound value is capped to the local `header_timeout` (can
//!       only shorten, never extend);
//!   (c) the F1 p2p-fallback-MISS path forwards the DECREMENTED budget to the CDN
//!       secondary (not a fresh full local timeout).
//!
//! THE BITE (verified by mutation, not by reading): making `parse_hop_budget` return
//! `None`, OR removing the `FallbackNarSource::resolve_within` (F1) override so the
//! default drops the budget, flips `small_downstream_budget_shrinks_the_outbound_header`
//! and `budget_is_non_increasing_across_two_live_daemon_hops` from the shrunk value to
//! the full local `header_timeout`.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use async_trait::async_trait;
use daemon::{
    App, CacheInfo, FallbackNarSource, NarCatalog, NarKey, NarSource, NarinfoSource, NoRawServe,
    NullCorrelation, PublicNarAllowlist, RawUpstream, SourceError, UpstreamHttp, UpstreamResponse,
};
use tokio::io::AsyncWriteExt;

use common::{DaemonHandle, spawn_app};

/// The `x-nix-p2p-hop-budget-ms` request header the daemon chain propagates.
const HOP_BUDGET_HEADER: &str = "x-nix-p2p-hop-budget-ms";

// ---------------------------------------------------------------------------
// A p2p primary that ALWAYS misses, so every request takes the FallbackNarSource
// p2p-miss -> HTTP secondary path (the F1 production path). It ignores the budget
// (inherits the default `resolve_within`), exactly as a real p2p source does -- the
// HTTP-chain budget is forwarded to the HTTP secondary by the wrapper, not consumed
// here.
// ---------------------------------------------------------------------------
struct AlwaysMissP2p;

#[async_trait]
impl NarSource for AlwaysMissP2p {
    async fn resolve(
        &self,
        _key: &NarKey,
        _expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        // A clean p2p miss: the exact signal FallbackNarSource turns into a CDN
        // fetch (S2). Bounded (immediate), so it does not re-introduce a hang.
        Err(SourceError::Unreachable("test p2p always-miss".to_string()))
    }
}

// ---------------------------------------------------------------------------
// An upstream that RECORDS the `x-nix-p2p-hop-budget-ms` value on each request and
// replies 200. This is the observation point: the OUTBOUND header the daemon under
// test actually put on the wire.
// ---------------------------------------------------------------------------
/// The recording log: `(path, parsed hop-budget-ms)` per request, in arrival order.
type SeenLog = Mutex<Vec<(String, Option<u64>)>>;

struct RecordingUpstream {
    addr: SocketAddr,
    seen: Arc<SeenLog>,
    stop: Arc<AtomicBool>,
}

impl RecordingUpstream {
    fn start() -> RecordingUpstream {
        let listener = TcpListener::bind("127.0.0.1:0").expect("recording upstream binds");
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let seen_thread = Arc::clone(&seen);
        let stop_thread = Arc::clone(&stop);
        thread::spawn(move || {
            for incoming in listener.incoming() {
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = incoming else { continue };
                let seen = Arc::clone(&seen_thread);
                thread::spawn(move || serve_recording_conn(stream, &seen));
            }
        });
        RecordingUpstream { addr, seen, stop }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The hop-budget value seen on the FIRST `/nar/` request (there is exactly one
    /// per test flow). Panics if none arrived, so a broken path fails loud.
    fn nar_budget_ms(&self) -> Option<u64> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .find(|(p, _)| p.starts_with("/nar/"))
            .map(|(_, b)| *b)
            .expect("a /nar/ request must have reached the recording upstream")
    }
}

impl Drop for RecordingUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // unblock accept()
    }
}

fn serve_recording_conn(mut stream: TcpStream, seen: &SeenLog) {
    // Read the request head (headers end at the first CRLFCRLF). A recording origin
    // needs only the head; the daemon sends no body.
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return,
            Ok(_) => {
                raw.push(byte[0]);
                if raw.ends_with(b"\r\n\r\n") {
                    break;
                }
                if raw.len() > 64 * 1024 {
                    return;
                }
            }
            Err(_) => return,
        }
    }
    let head = String::from_utf8_lossy(&raw);
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let path = request_line
        .split(' ')
        .nth(1)
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .to_string();
    // Case-insensitive header name match; the value is an integer-ms budget.
    let mut budget = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case(HOP_BUDGET_HEADER)
        {
            budget = value.trim().parse::<u64>().ok();
        }
    }
    seen.lock().unwrap().push((path, budget));

    // A tiny 200 so the daemon's streaming path completes and the client sees 200.
    let body = b"nar-bytes";
    let out = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

// ---------------------------------------------------------------------------
// Build a real daemon App whose NAR seam is FallbackNarSource(always-miss p2p,
// UpstreamHttp -> upstream_url) with an explicit local header_timeout. This is the
// PRODUCTION shape (p2p first, CDN on a miss) the F1 fix targets.
// ---------------------------------------------------------------------------
fn fallback_app(upstream_url: &str, header_timeout: Duration) -> Arc<App> {
    let upstream = Arc::new(
        UpstreamHttp::new(upstream_url)
            .expect("valid upstream")
            .with_header_timeout(header_timeout),
    );
    let nar: Arc<dyn NarSource> = Arc::new(FallbackNarSource::new(
        Arc::new(AlwaysMissP2p),
        upstream.clone() as Arc<dyn NarSource>,
    ));
    Arc::new(App {
        // narinfo/passthrough are unused by the NAR-path tests; wire the same client.
        narinfo: upstream.clone() as Arc<dyn NarinfoSource>,
        nar,
        passthrough: upstream as Arc<dyn RawUpstream>,
        cache_info: CacheInfo::default(),
        catalog: Arc::new(NarCatalog::new()),
        upstream_label: "test-upstream".to_string(),
        correlation: Arc::new(NullCorrelation),
        raw_serve: Arc::new(NoRawServe),
        public_allowlist: Arc::new(PublicNarAllowlist::disabled()),
    })
}

/// GET `path` from `addr`, optionally sending an inbound `x-nix-p2p-hop-budget-ms`
/// header (a downstream chain hop's remaining budget). Returns the status.
async fn get_with_budget(addr: SocketAddr, path: &str, budget_ms: Option<u64>) -> Option<u16> {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to daemon");
    let budget_line = match budget_ms {
        Some(ms) => format!("{HOP_BUDGET_HEADER}: {ms}\r\n"),
        None => String::new(),
    };
    let req =
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{budget_line}Connection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("write");
    stream.flush().await.ok();
    // Read the status line; the body is small and we only need completion.
    let mut raw = Vec::new();
    use tokio::io::AsyncReadExt;
    let _ = stream.read_to_end(&mut raw).await;
    let head = String::from_utf8_lossy(&raw);
    head.lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
}

const LOCAL_TIMEOUT_MS: u64 = 1000;

/// (a)+seeding: with NO inbound budget this hop is the chain ENTRY and seeds the
/// outbound header from its OWN `header_timeout` -- unchanged single-daemon
/// behaviour. Anchors the other tests: this is the value the budget must NOT reach
/// when a downstream propagates a tighter one.
#[tokio::test]
async fn entry_hop_seeds_full_local_budget_on_the_wire() {
    let upstream = RecordingUpstream::start();
    let (addr, _daemon): (_, DaemonHandle) = spawn_app(fallback_app(
        &upstream.base_url(),
        Duration::from_millis(LOCAL_TIMEOUT_MS),
    ))
    .await;

    let status = get_with_budget(addr, "/nar/entry-token", None).await;
    assert_eq!(status, Some(200), "the p2p-miss -> CDN path serves 200");

    // Entry seeds the full local timeout (setup is intentionally ignored for the
    // entry hop), so the outbound header equals the local header_timeout exactly.
    assert_eq!(
        upstream.nar_budget_ms(),
        Some(LOCAL_TIMEOUT_MS),
        "the chain entry must seed the outbound budget from its own header_timeout"
    );
}

/// (a) shrink + (c) F1: a SMALL inbound budget from a downstream hop must reach the
/// CDN secondary DECREMENTED -- not re-seeded to the full local timeout. THE BITE:
/// mutating `parse_hop_budget -> None` (server drops the inbound budget) or removing
/// the `FallbackNarSource::resolve_within` override (F1: the p2p-miss path drops the
/// budget) both make this observe `LOCAL_TIMEOUT_MS` (1000) instead of ~150.
#[tokio::test]
async fn small_downstream_budget_shrinks_the_outbound_header_through_server_and_p2p_fallback() {
    let upstream = RecordingUpstream::start();
    let (addr, _daemon): (_, DaemonHandle) = spawn_app(fallback_app(
        &upstream.base_url(),
        Duration::from_millis(LOCAL_TIMEOUT_MS),
    ))
    .await;

    let inbound_ms = 150;
    let status = get_with_budget(addr, "/nar/small-token", Some(inbound_ms)).await;
    assert_eq!(status, Some(200), "the p2p-miss -> CDN path serves 200");

    let seen = upstream
        .nar_budget_ms()
        .expect("the outbound request must carry the propagated budget header");
    // Non-increasing: the outbound value is at most the inbound budget (a hop can
    // only shorten it), and STRICTLY below the local timeout -- proving both the
    // server parse and the F1 p2p-fallback-miss forwarded the decremented budget.
    assert!(
        seen <= inbound_ms,
        "outbound budget {seen} must not exceed the inbound {inbound_ms} (non-increasing)"
    );
    assert!(
        seen > 0,
        "outbound budget must be positive (the CDN fetch still gets time)"
    );
    assert!(
        seen < LOCAL_TIMEOUT_MS,
        "outbound budget {seen} must be far below the local timeout {LOCAL_TIMEOUT_MS} \
         -- if it equals the local timeout, the budget was DROPPED (parse->None or F1 \
         override missing)"
    );
}

/// (b): a hostile-LARGE inbound budget can only be SHORTENED to the local
/// `header_timeout`, never extend this hop's wait past it.
#[tokio::test]
async fn hostile_large_inbound_budget_is_capped_to_local_header_timeout() {
    let upstream = RecordingUpstream::start();
    let (addr, _daemon): (_, DaemonHandle) = spawn_app(fallback_app(
        &upstream.base_url(),
        Duration::from_millis(LOCAL_TIMEOUT_MS),
    ))
    .await;

    let status = get_with_budget(addr, "/nar/hostile-token", Some(10_000_000)).await;
    assert_eq!(status, Some(200));

    let seen = upstream.nar_budget_ms().expect("outbound budget present");
    assert!(
        seen <= LOCAL_TIMEOUT_MS,
        "a hostile-large inbound budget {seen} must be capped to the local timeout \
         {LOCAL_TIMEOUT_MS} -- it can only shorten this hop, never extend it"
    );
    assert_eq!(
        seen, LOCAL_TIMEOUT_MS,
        "capping a hostile-large budget yields exactly the local header_timeout"
    );
}

/// (a) across a REAL two-daemon wire: client -> D1 -> D2 -> recording upstream. The
/// budget the deepest upstream sees must be NON-INCREASING relative to the entry
/// budget the client sent -- it passed through TWO server parses and TWO
/// FallbackNarSource p2p-miss hops, each of which can only shorten it. THE BITE:
/// dropping the budget at either hop (parse->None or F1 missing) makes the deepest
/// upstream observe the full local timeout (1000), which EXCEEDS the entry budget.
#[tokio::test]
async fn budget_is_non_increasing_across_two_live_daemon_hops() {
    let upstream = RecordingUpstream::start();
    // D2 (inner): p2p-miss -> recording upstream.
    let (d2_addr, _d2): (_, DaemonHandle) = spawn_app(fallback_app(
        &upstream.base_url(),
        Duration::from_millis(LOCAL_TIMEOUT_MS),
    ))
    .await;
    // D1 (entry-facing): p2p-miss -> D2.
    let (d1_addr, _d1): (_, DaemonHandle) = spawn_app(fallback_app(
        &format!("http://{d2_addr}"),
        Duration::from_millis(LOCAL_TIMEOUT_MS),
    ))
    .await;

    let entry_budget = 400;
    let status = get_with_budget(d1_addr, "/nar/chain-token", Some(entry_budget)).await;
    assert_eq!(status, Some(200), "the two-hop p2p-miss chain serves 200");

    let seen = upstream
        .nar_budget_ms()
        .expect("outbound budget present at the leaf");
    assert!(
        seen <= entry_budget,
        "after two hops the deepest budget {seen} must not exceed the entry {entry_budget} \
         (monotone non-increasing); a value >= the local timeout means a hop DROPPED it"
    );
    assert!(
        seen > 0,
        "the budget must still be positive after two fast hops"
    );
    assert!(
        seen < LOCAL_TIMEOUT_MS,
        "the deepest budget {seen} must stay below the local timeout {LOCAL_TIMEOUT_MS}"
    );
}
