//! AC#4: each of the seven TESTING.md fault modes, with a bite test proving the
//! fault is ACTUALLY emitted - every test contrasts fault-on against fault-off
//! so it cannot pass without the fault changing observable wire behaviour, and
//! also checks the in-process log tagged the fault (the fault-emitted oracle).

mod common;

use common::{Fixture, get};
use std::time::Instant;

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

/// Mode 1: added latency per path-kind.
#[test]
fn latency_fault_delays_only_the_targeted_kind() {
    let fx = Fixture::with_nar(4096);

    // Baseline: fault off, warm the cache, measure a fast NAR.
    get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    let t0 = Instant::now();
    get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    let baseline = t0.elapsed();
    assert!(
        baseline.as_millis() < 150,
        "baseline unexpectedly slow: {baseline:?}"
    );

    // Fault on: 400 ms added latency to NAR requests only.
    fx.reset_log();
    fx.set_faults("latency_nar_ms=400");
    let t1 = Instant::now();
    get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    let delayed = t1.elapsed();
    assert!(
        delayed.as_millis() >= 350,
        "latency fault not felt: {delayed:?}"
    );

    // A narinfo request is NOT delayed (per-kind scoping) and is fast.
    let t2 = Instant::now();
    get(fx.proxy_addr, "/test.narinfo").unwrap();
    assert!(t2.elapsed().as_millis() < 150, "narinfo wrongly delayed");

    assert_eq!(
        fault_count(&fx, "latency-nar"),
        1,
        "latency tagged in the log"
    );
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
    assert_eq!(fault_count(&fx, "http-error-503"), 1);
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
    assert_eq!(fault_count(&fx, "connection-reset"), 1);
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
    assert_eq!(fault_count(&fx, "truncated-nar"), 1);

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
    assert_eq!(fault_count(&fx, "corrupt-nar"), 1);

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
    assert_eq!(fault_count(&fx, "wrong-narinfo"), 1);

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
    assert_eq!(fault_count(&fx, "unreachable"), 1);
}
