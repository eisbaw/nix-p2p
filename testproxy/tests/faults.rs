//! AC#4: each of the seven TESTING.md fault modes, with a bite test proving the
//! fault is ACTUALLY emitted - every test contrasts fault-on against fault-off
//! so it cannot pass without the fault changing observable wire behaviour, and
//! also checks the in-process log tagged the fault (the fault-emitted oracle).

mod common;

use common::{Fixture, get};
use std::time::{Duration, Instant};

/// How long [`await_fault_count`] will wait for the server thread to catch up.
/// This bounds a HANG - it is not a timing assertion, and the value is not a
/// tuned constant: any value large enough to survive scheduling noise does.
const LOG_VISIBILITY_DEADLINE: Duration = Duration::from_secs(10);

/// The latency the mode-1 fault injects. Referenced rather than repeated so the
/// fault query and the assertion that reads it can never drift apart.
const LATENCY_FAULT: Duration = Duration::from_millis(400);

/// How many narinfo samples the scoping assertion takes the MINIMUM of. More
/// samples cost ~one loopback round-trip each and make a spurious failure require
/// every sample to be slow at once; see the assertion for why the minimum is the
/// right statistic for a fault that imposes a floor.
const NARINFO_SAMPLES: usize = 5;

/// Count how many log records carry a given fault tag.
fn fault_count(fx: &Fixture, name: &str) -> u64 {
    fx.state
        .log
        .lock()
        .unwrap()
        .stats()
        .faults
        .get(name)
        .copied()
        .unwrap_or(0)
}

/// Wait for `name` to have been counted `want` times, then assert it.
///
/// WHY THIS IS NOT `assert_eq!(fault_count(..), want)` (task-109). The client and
/// the proxy's bookkeeping are not ordered with respect to each other: the proxy
/// pushes its log record in `proxy.rs` AFTER `serve()` has already written the
/// response - or, for a reset, after it has already dropped the connection. So
/// `get()` can return, having fully observed the fault, while the server thread
/// has not yet reached the push. Measured consequence: 6 of 10 failing instances
/// in the task-109 baseline (45% gate failure rate at N=20) were this, split
/// across `connection-reset` and `truncated-nar`.
///
/// This is a WAIT, not a retry: it re-reads a counter that the design guarantees
/// will be written, and FAILS if the deadline passes. It never re-runs the request
/// and never re-rolls the fault, so a fault that genuinely never fired still fails
/// the test - just `LOG_VISIBILITY_DEADLINE` later than it would have.
///
/// It asserts EQUALITY at the end, not `>=`, so an over-count (the same fault
/// recorded twice) still fails exactly as it did before.
#[track_caller]
fn await_fault_count(fx: &Fixture, name: &str, want: u64) {
    let deadline = Instant::now() + LOG_VISIBILITY_DEADLINE;
    while fault_count(fx, name) < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        fault_count(fx, name),
        want,
        "fault {name:?} count after waiting up to {LOG_VISIBILITY_DEADLINE:?} for the \
         proxy to record it"
    );
}

/// Mode 1: added latency per path-kind.
#[test]
fn latency_fault_delays_only_the_targeted_kind() {
    let fx = Fixture::with_nar(4096);

    // Baseline: fault off, warm the cache, measure a fast NAR.
    get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    let t0 = Instant::now();
    get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    let baseline = t0.elapsed();

    // Fault on: LATENCY_FAULT adds a known floor to NAR requests only.
    fx.reset_log();
    fx.set_faults(&format!("latency_nar_ms={}", LATENCY_FAULT.as_millis()));
    let t1 = Instant::now();
    get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    let delayed = t1.elapsed();
    // A LOWER bound, so CPU contention can only make it more true - a loaded host
    // makes the request slower, never faster. Safe to state in absolute time.
    assert!(
        delayed >= LATENCY_FAULT - Duration::from_millis(50),
        "latency fault not felt: {delayed:?} (baseline {baseline:?})"
    );

    // A narinfo request is NOT delayed: the fault is scoped to the nar kind.
    //
    // THE MINIMUM OF SEVERAL SAMPLES, not one sample, and compared against the
    // INJECTED FLOOR rather than a hand-picked constant (task-109, second
    // attempt). Two earlier forms of this assertion were both wrong:
    //   `narinfo < 150ms`          - a claim about how fast the HOST is.
    //   `narinfo + 200ms < delayed` - my first fix. Still two SINGLE samples, so
    //     one scheduling hiccup beats it: the task-109 AFTER run caught it at
    //     narinfo 278ms vs nar 405ms, a spurious failure on correct code.
    // The sound formulation uses what the fault actually does: it imposes a FLOOR
    // on every request of the targeted kind. So if scoping were broken, EVERY
    // narinfo sample would be >= LATENCY_FAULT and so would their minimum. Taking
    // the min means a spurious failure needs ALL samples to be independently
    // slow, while a genuine scoping break is still caught by construction.
    // The threshold is not tuned - it IS the injected latency.
    let mut fastest_narinfo = Duration::MAX;
    for _ in 0..NARINFO_SAMPLES {
        let t2 = Instant::now();
        get(fx.proxy_addr, "/test.narinfo").unwrap();
        fastest_narinfo = fastest_narinfo.min(t2.elapsed());
    }
    assert!(
        fastest_narinfo < LATENCY_FAULT,
        "narinfo wrongly delayed: the fastest of {NARINFO_SAMPLES} narinfo requests \
         took {fastest_narinfo:?}, at or above the {LATENCY_FAULT:?} floor the fault \
         injects into the nar kind - so narinfo is receiving a fault scoped to nar \
         (nar sample {delayed:?}, unfaulted baseline {baseline:?})"
    );

    await_fault_count(&fx, "latency-nar", 1);
}

/// Mode 2: HTTP 500/503.
#[test]
fn http_error_fault_returns_the_status() {
    let fx = Fixture::with_nar(4096);

    // Fault off: a real 200.
    assert_eq!(
        get(fx.proxy_addr, "/nar/testnar.nar").unwrap().status,
        Some(200)
    );

    fx.reset_log();
    fx.set_faults("http_error=503&http_error_kind=nar");
    let resp = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    assert_eq!(resp.status, Some(503), "fault-on must return 503");
    // Scoped to nar: narinfo is unaffected.
    assert_eq!(
        get(fx.proxy_addr, "/test.narinfo").unwrap().status,
        Some(200)
    );
    await_fault_count(&fx, "http-error-503", 1);
}

/// Mode 3: connection reset - no valid HTTP response at all.
#[test]
fn connection_reset_fault_yields_no_response() {
    let fx = Fixture::with_nar(4096);

    assert_eq!(
        get(fx.proxy_addr, "/nar/testnar.nar").unwrap().status,
        Some(200)
    );

    fx.reset_log();
    fx.set_faults("connection_reset=nar");
    let resp = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    assert_eq!(
        resp.status, None,
        "reset must not produce a valid HTTP response"
    );
    assert!(resp.body.is_empty() || resp.short);
    await_fault_count(&fx, "connection-reset", 1);
}

/// Mode 4: truncated NAR at N%.
#[test]
fn truncated_nar_fault_short_reads() {
    let size = 100_000;
    let fx = Fixture::with_nar(size);

    let full = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    assert!(full.complete(), "baseline is a complete transfer");

    fx.reset_log();
    fx.set_faults("truncate_pct=40");
    let resp = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    // Content-Length still advertises the full size; the body is short.
    assert_eq!(resp.content_length, Some(size as u64));
    assert!(
        !resp.complete(),
        "truncated body must be shorter than Content-Length"
    );
    assert!(resp.body.len() < size, "body was truncated");
    assert!(!resp.body.is_empty(), "some bytes still sent");
    // ~40% of the payload, within one stream buffer.
    let expected = size * 40 / 100;
    assert!(
        (resp.body.len() as i64 - expected as i64).abs() <= 64 * 1024,
        "truncated at ~40%: got {} want ~{expected}",
        resp.body.len()
    );
    await_fault_count(&fx, "truncated-nar", 1);

    // The CACHE is NOT corrupted by the fault: the stored NAR is whole+correct.
    assert_eq!(fx.cached_nar().as_deref(), Some(fx.origin_nar().as_slice()));
}

/// Mode 5: corrupted NAR bytes (same length, different content).
#[test]
fn corrupt_nar_fault_alters_bytes_not_length() {
    let size = 20_000;
    let fx = Fixture::with_nar(size);
    let origin = fx.origin_nar();

    let clean = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    assert_eq!(clean.body, origin, "baseline bytes are correct");

    fx.reset_log();
    fx.set_faults("corrupt_nar=1");
    let resp = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    assert_eq!(resp.status, Some(200));
    assert_eq!(
        resp.body.len(),
        origin.len(),
        "length unchanged (Content-Length matches)"
    );
    assert_ne!(resp.body, origin, "bytes corrupted");
    await_fault_count(&fx, "corrupt-nar", 1);

    // Cache integrity holds even though the fault served corrupt bytes.
    assert_eq!(fx.cached_nar().as_deref(), Some(origin.as_slice()));
}

/// Mode 6: wrong/stale narinfo.
#[test]
fn wrong_narinfo_fault_mutates_the_metadata() {
    let fx = Fixture::with_nar(4096);
    let origin_info = std::fs::read(fx.origin_dir.join("test.narinfo")).unwrap();

    let clean = get(fx.proxy_addr, "/test.narinfo").unwrap();
    assert_eq!(clean.body, origin_info, "baseline narinfo is verbatim");

    fx.reset_log();
    fx.set_faults("wrong_narinfo=1");
    let resp = get(fx.proxy_addr, "/test.narinfo").unwrap();
    assert_eq!(resp.status, Some(200));
    assert_ne!(resp.body, origin_info, "narinfo mutated");
    // Specifically the NarHash line differs.
    let served = resp.body_string();
    assert!(served.contains("NarHash:"), "still a narinfo");
    assert!(
        !served.contains("1111111111111111111111111111111111111111111111111111"),
        "the original NarHash value is gone"
    );
    await_fault_count(&fx, "wrong-narinfo", 1);

    // Cache keeps the correct narinfo.
    assert!(fx.cached_nar().is_none()); // nar not fetched
    let cached_info = std::fs::read(fx.cache_dir.join("test.narinfo")).unwrap();
    assert_eq!(cached_info, origin_info, "cached narinfo stays correct");
}

/// Mode 7: upstream unreachable - fast, clean gateway failure.
#[test]
fn unreachable_fault_fails_fast_with_502() {
    let fx = Fixture::with_nar(4096);

    assert_eq!(
        get(fx.proxy_addr, "/nar/testnar.nar").unwrap().status,
        Some(200)
    );

    fx.reset_log();
    fx.set_faults("unreachable=1");
    let t0 = Instant::now();
    let resp = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    let elapsed = t0.elapsed();
    assert_eq!(resp.status, Some(502), "unreachable surfaces as 502");
    assert!(
        elapsed.as_millis() < 500,
        "must fail fast, took {elapsed:?}"
    );
    await_fault_count(&fx, "unreachable", 1);
}
