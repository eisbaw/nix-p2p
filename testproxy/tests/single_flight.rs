//! task-23: single-flight coalescing of concurrent same-path cold NAR misses.
//!
//! The bites, each mutation-proven (see the task brief):
//!
//! - Bite 1: N concurrent misses for ONE cold path cause exactly ONE upstream
//!   fetch. Bite 3 (integrity) is folded in - every reader gets the whole,
//!   correct bytes and the committed cache entry is byte-correct.
//! - Bite 2: concurrent misses for DIFFERENT paths each fetch independently and
//!   never block the other (keyed by path, no head-of-line blocking).
//! - Bite 4: fault injection preserved - a corrupt-NAR fault reaches EVERY
//!   coalesced waiter's egress, and the cache still holds upstream-correct bytes.
//! - Bite 5: failure path - N concurrent misses for a cold path the origin
//!   REJECTS (404) each see the failure (never a false success), nothing is
//!   cached, and upstream attempts stay bounded (no storm, no livelock).
//!
//! Bite 3's standalone form is the pre-existing
//! `passthrough_cache::concurrent_same_path_requests_are_never_torn`, which
//! still passes under coalescing.
//!
//! Determinism. These bites do not race the wall clock for their load-bearing
//! assertion. The origin is GATED: a leader that reaches it is provably held
//! there until the test opens the gate, so a same-path waiter is provably parked
//! in the coalescer (not at the origin). The GREEN direction (coalescing on) is
//! then timing-independent - exactly one fetch for any concurrency. A short
//! settle window only gives the MUTATION (independent fetches, which would all
//! reach the gated origin) time to reveal itself; coalescing is invariant to it.

mod common;

use common::{RawResponse, get, raw_request};

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use testproxy::http::{self, Request};
use testproxy::{Config, Server, State, origin, server};

/// A one-shot gate: origin responses for gated paths block until `release`.
struct Gate {
    open: Mutex<bool>,
    cv: Condvar,
}

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Gate {
            open: Mutex::new(false),
            cv: Condvar::new(),
        })
    }

    fn wait(&self) {
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.cv.wait(open).unwrap();
        }
    }

    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.cv.notify_all();
    }
}

/// A gated in-memory origin + the proxy under test, with per-path hit counts.
struct Harness {
    _origin: Server,
    proxy: Server,
    state: Arc<State>,
    hit_counts: Arc<Mutex<HashMap<String, u64>>>,
    gate: Arc<Gate>,
    cache_dir: PathBuf,
}

impl Harness {
    fn proxy_addr(&self) -> SocketAddr {
        self.proxy.addr
    }

    /// Times the origin has been ASKED for `path` (counted at request entry,
    /// before any gating), i.e. the number of real upstream fetches.
    fn hits(&self, path: &str) -> u64 {
        *self.hit_counts.lock().unwrap().get(path).unwrap_or(&0)
    }

    fn in_flight(&self) -> u64 {
        self.state.in_flight()
    }

    fn cached(&self, rel: &str) -> Option<Vec<u8>> {
        std::fs::read(self.cache_dir.join(rel)).ok()
    }

    fn arm_fault(&self, query: &str) {
        let resp = raw_request(
            self.proxy_addr(),
            "POST",
            &format!("/__testproxy/faults?{query}"),
        )
        .expect("faults endpoint reachable");
        assert_eq!(
            resp.status,
            Some(200),
            "fault not armed: {:?}",
            resp.body_string()
        );
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.cache_dir);
    }
}

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn nar_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// Build a harness whose origin serves `files` (path -> bytes); every path in
/// `gated` blocks its response until `gate.release()`.
fn harness(files: HashMap<String, Vec<u8>>, gated: HashSet<String>) -> Harness {
    let id = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let cache_dir =
        std::env::temp_dir().join(format!("testproxy-sf-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&cache_dir).unwrap();

    let hit_counts: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let gate = Gate::new();

    let files = Arc::new(files);
    let handler_hits = Arc::clone(&hit_counts);
    let handler_gate = Arc::clone(&gate);
    let handler_files = Arc::clone(&files);
    let handler_gated = Arc::new(gated);

    let origin = server::spawn(
        "127.0.0.1:0".parse().unwrap(),
        move |req: Request, mut stream: TcpStream| {
            let path = req.path().to_string();
            // Count at entry: a leader that reaches here is a real upstream fetch
            // even though the gate then holds its response.
            *handler_hits
                .lock()
                .unwrap()
                .entry(path.clone())
                .or_insert(0) += 1;
            if handler_gated.contains(&path) {
                handler_gate.wait();
            }
            match handler_files.get(&path) {
                Some(bytes) => {
                    let _ = http::write_response(&mut stream, 200, "application/x-nix-nar", bytes);
                }
                None => {
                    let _ = http::write_response(&mut stream, 404, "text/plain", b"not found\n");
                }
            }
        },
    )
    .expect("origin binds");

    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: origin::base_url(origin.addr),
        cache_dir: cache_dir.clone(),
    };
    let (proxy, state) = testproxy::spawn(config).expect("proxy binds");

    Harness {
        _origin: origin,
        proxy,
        state,
        hit_counts,
        gate,
        cache_dir,
    }
}

/// Spin until `cond` holds or `deadline` elapses; returns the final value.
fn await_until<F: Fn() -> bool>(deadline: Duration, cond: F) -> bool {
    let end = Instant::now() + deadline;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= end {
            return cond();
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// BITE 1: N concurrent misses for ONE cold path cause EXACTLY ONE upstream
/// fetch. MUTATION (remove coalescing): all N reach the gated origin and the hit
/// count climbs to N, reddening the `== 1` assertion below.
#[test]
fn concurrent_same_path_misses_cause_exactly_one_upstream_fetch() {
    const N: usize = 16;
    let nar = nar_bytes(64 * 1024);
    let path = "/nar/a.nar";

    let mut files = HashMap::new();
    files.insert(path.to_string(), nar.clone());
    let gated: HashSet<String> = [path.to_string()].into_iter().collect();
    let h = Arc::new(harness(files, gated));

    let mut handles = Vec::new();
    for _ in 0..N {
        let addr = h.proxy_addr();
        handles.push(thread::spawn(move || get(addr, path).unwrap()));
    }

    // All N handlers are up AND the single leader has reached the (gated) origin.
    assert!(
        await_until(Duration::from_secs(10), || h.in_flight() as usize == N
            && h.hits(path) >= 1),
        "expected all {N} handlers in-flight with the leader at the origin; \
         in_flight={}, hits={}",
        h.in_flight(),
        h.hits(path)
    );

    // Settle window: let any NON-coalesced extra fetches reach the gated origin.
    // Under coalescing none can (the other N-1 are parked in the coalescer), so
    // this stays 1; the mutation drives it toward N and breaks out early.
    let settle = Instant::now() + Duration::from_millis(300);
    while Instant::now() < settle && h.hits(path) == 1 {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        h.hits(path),
        1,
        "exactly ONE upstream fetch for {N} concurrent same-path misses \
         (all {N} confirmed in-flight)"
    );

    h.gate.release();

    for (i, handle) in handles.into_iter().enumerate() {
        let resp = handle.join().unwrap();
        assert_eq!(resp.status, Some(200), "req {i} status");
        assert!(resp.complete(), "req {i} whole body");
        assert_eq!(
            resp.body, nar,
            "req {i} exact bytes (integrity under coalescing)"
        );
    }

    // No extra fetch happened when the waiters served from the committed cache.
    assert_eq!(h.hits(path), 1, "still one fetch after all waiters drained");
    // BITE 3 (folded in): the committed cache entry is whole and correct.
    assert_eq!(
        h.cached("nar/a.nar").as_deref(),
        Some(nar.as_slice()),
        "committed cache entry is byte-correct under coalescing"
    );
}

/// BITE 2: concurrent misses for DIFFERENT cold paths fetch INDEPENDENTLY - a
/// slow (gated) fetch for path A must not block an unrelated request for path B.
/// MUTATION (over-coalesce across paths, e.g. key by a constant): B joins A's
/// flight and blocks until A finishes; A is gated forever, so B never returns
/// within the timeout and the `recv_timeout` below fires -> reddens.
#[test]
fn different_paths_fetch_independently_without_head_of_line_blocking() {
    let nar_a = nar_bytes(48 * 1024);
    let nar_b = nar_bytes(32 * 1024 + 7);

    let mut files = HashMap::new();
    files.insert("/nar/a.nar".to_string(), nar_a.clone());
    files.insert("/nar/b.nar".to_string(), nar_b.clone());
    // Only A is gated; B is served immediately.
    let gated: HashSet<String> = ["/nar/a.nar".to_string()].into_iter().collect();
    let h = Arc::new(harness(files, gated));

    // Start A: its leader reaches the origin and is held at the gate.
    let a_handle = {
        let addr = h.proxy_addr();
        thread::spawn(move || get(addr, "/nar/a.nar").unwrap())
    };
    assert!(
        await_until(Duration::from_secs(10), || h.hits("/nar/a.nar") >= 1),
        "A's leader should have reached the origin"
    );

    // Now fire B while A is STILL gated. Keyed by path, B is a separate flight
    // and completes immediately; if different paths were coalesced together B
    // would block on A (which never completes) and recv_timeout would fire.
    let (tx, rx) = mpsc::channel();
    {
        let addr = h.proxy_addr();
        thread::spawn(move || {
            let _ = tx.send(get(addr, "/nar/b.nar"));
        });
    }
    let b: RawResponse = match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(resp)) => resp,
        Ok(Err(err)) => panic!("B request errored: {err}"),
        Err(_) => panic!(
            "different-path request B blocked on A's in-flight fetch: paths were \
             coalesced together instead of keyed by path"
        ),
    };
    assert_eq!(b.status, Some(200), "B served while A gated");
    assert!(b.complete(), "B whole body");
    assert_eq!(b.body, nar_b, "B got its OWN path's bytes");

    // A is still the only A-fetch and still parked at the gate; B fetched once.
    assert_eq!(
        h.hits("/nar/a.nar"),
        1,
        "A fetched exactly once, still gated"
    );
    assert_eq!(
        h.hits("/nar/b.nar"),
        1,
        "B fetched exactly once, independently"
    );

    // Release A and confirm it too completes correctly (one fetch total for A).
    h.gate.release();
    let a = a_handle.join().unwrap();
    assert_eq!(a.status, Some(200));
    assert_eq!(a.body, nar_a, "A got its own bytes");
    assert_eq!(h.hits("/nar/a.nar"), 1, "A never re-fetched");
}

/// BITE 4: a corrupt-NAR fault reaches EVERY coalesced waiter's egress. With the
/// fault armed, N concurrent same-path misses still coalesce to ONE upstream
/// fetch, yet ALL N clients receive corrupted bytes (not a false clean hit), and
/// the cache still holds the upstream-correct bytes. MUTATION (a waiter that
/// serves raw cache bytes, bypassing the egress fault): that waiter's body would
/// equal the clean NAR, reddening the "every body is corrupted" assertion.
#[test]
fn corrupt_fault_reaches_every_coalesced_waiter() {
    const N: usize = 12;
    let nar = nar_bytes(80 * 1024 + 3);
    let path = "/nar/a.nar";
    let corrupted = testproxy::fault::corrupt_chunk(&nar); // bitwise-NOT of every byte

    let mut files = HashMap::new();
    files.insert(path.to_string(), nar.clone());
    let gated: HashSet<String> = [path.to_string()].into_iter().collect();
    let h = Arc::new(harness(files, gated));

    h.arm_fault("corrupt_nar=1");

    let mut handles = Vec::new();
    for _ in 0..N {
        let addr = h.proxy_addr();
        handles.push(thread::spawn(move || get(addr, path).unwrap()));
    }

    assert!(
        await_until(Duration::from_secs(10), || h.in_flight() as usize == N
            && h.hits(path) >= 1),
        "expected all {N} handlers in-flight with the leader at the origin; \
         in_flight={}, hits={}",
        h.in_flight(),
        h.hits(path)
    );
    let settle = Instant::now() + Duration::from_millis(300);
    while Instant::now() < settle && h.hits(path) == 1 {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        h.hits(path),
        1,
        "exactly ONE upstream fetch even with a fault armed"
    );

    h.gate.release();

    for (i, handle) in handles.into_iter().enumerate() {
        let resp = handle.join().unwrap();
        assert_eq!(resp.status, Some(200), "req {i} status");
        assert_eq!(
            resp.body, corrupted,
            "req {i}: coalesced waiter must ALSO see the corrupt-NAR fault on egress"
        );
        assert_ne!(
            resp.body, nar,
            "req {i}: a corrupt egress is NOT a clean hit"
        );
    }

    // Fault discipline: the cache holds the upstream-correct bytes, never the
    // corrupted egress bytes (AC#3 preserved under coalescing).
    assert_eq!(
        h.cached("nar/a.nar").as_deref(),
        Some(nar.as_slice()),
        "cache holds upstream-correct bytes despite the egress corruption"
    );
}

/// BITE 5: the FAILURE path. N concurrent misses for a cold path the origin
/// REJECTS (404) must each see the failure - never a false success from a
/// waiter that assumed the leader committed - nothing may be cached, and the
/// upstream attempts must be BOUNDED (each request attempts at most once; no
/// storm, no livelock). A failed leader does not cache, so waiters re-check the
/// cache (still cold) and re-lead in turn: exactly N attempts, serialized.
///
/// MUTATION (make a failed leader LOOP - `continue` - instead of returning):
/// the leader re-fetches the 404 forever, so its request never returns; the
/// `recv_timeout` below fires and reddens, catching the livelock/storm.
#[test]
fn failure_path_bounded_and_never_a_false_success() {
    const N: usize = 8;
    let missing = "/nar/missing.nar"; // absent from the origin's file map -> 404

    // No files at all; the origin answers 404 for everything. Ungated: a 404 is
    // fast, and the point here is the retry accounting, not the in-flight window.
    let h = Arc::new(harness(HashMap::new(), HashSet::new()));

    let (tx, rx) = mpsc::channel();
    for _ in 0..N {
        let addr = h.proxy_addr();
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send(get(addr, missing));
        });
    }
    drop(tx);

    // Collect all N under an overall deadline. Correct code returns each 404
    // promptly; a looping failed leader never returns, tripping the timeout.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut got = Vec::new();
    while got.len() < N {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(resp) => got.push(resp.expect("client request completed")),
            Err(_) => panic!(
                "only {}/{N} failure-path requests returned before the deadline: a failed \
                 leader is looping instead of returning (livelock/storm)",
                got.len()
            ),
        }
    }

    for (i, resp) in got.iter().enumerate() {
        assert_eq!(
            resp.status,
            Some(404),
            "req {i}: the upstream failure is forwarded, never a false success"
        );
    }
    // A rejected fetch is never cached.
    assert!(
        h.cached("nar/missing.nar").is_none(),
        "a 404 must not leave a cache entry"
    );
    // Bounded: each request makes exactly one upstream attempt (nothing is ever
    // cached, so every request leads once). No amplification beyond N.
    let attempts = h.hits(missing);
    assert!(
        (1..=N as u64).contains(&attempts),
        "upstream attempts must be bounded to [1, {N}] (no storm); got {attempts}"
    );
}
