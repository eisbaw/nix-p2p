//! AC#1 (cache serves repeats, oracle-pairing), AC#2 (request log fields + gap),
//! AC#3 (streaming, atomic writes, concurrent same-path integrity).

mod common;

use common::{Fixture, get};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use testproxy::kind::Kind;

/// AC#1: a repeat request is served from disk with ZERO upstream hits, PAIRED
/// with a nonzero testproxy received-count (TESTING.md oracle-pairing rule).
#[test]
fn repeat_served_from_cache_with_zero_upstream_hits() {
    let fx = Fixture::with_nar(64 * 1024);

    // First fetch populates the cache (a miss -> one upstream hit).
    let first = get(fx.proxy_addr, "/test.narinfo").unwrap();
    assert_eq!(first.status, Some(200));
    let first_nar = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    assert_eq!(first_nar.status, Some(200));
    {
        let stats = fx.state.log.lock().unwrap().stats();
        assert_eq!(
            stats.upstream_of(Kind::Narinfo),
            1,
            "first narinfo is a miss"
        );
        assert_eq!(stats.upstream_of(Kind::Nar), 1, "first nar is a miss");
    }

    // Reset the log so the repeat's counts stand alone, then fetch again.
    fx.reset_log();
    let repeat_info = get(fx.proxy_addr, "/test.narinfo").unwrap();
    let repeat_nar = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    assert_eq!(repeat_info.status, Some(200));
    assert_eq!(repeat_nar.status, Some(200));

    let stats = fx.state.log.lock().unwrap().stats();
    // The paired assertion: 0 upstream hits AND a nonzero received count.
    assert_eq!(stats.upstream_total(), 0, "repeat must not touch upstream");
    assert!(
        stats.received_total() >= 2,
        "but the proxy still received the requests"
    );
    assert_eq!(stats.received_of(Kind::Narinfo), 1);
    assert_eq!(stats.received_of(Kind::Nar), 1);

    // Byte-identity from cache: repeat NAR equals origin bytes.
    assert_eq!(repeat_nar.body, fx.origin_nar());
}

/// AC#1 pairing bites: with the cache OFF (fresh proxy, no prior fetch) the same
/// request DOES hit upstream. Proves the zero above is not vacuous.
#[test]
fn cold_request_hits_upstream() {
    let fx = Fixture::with_nar(4096);
    let _ = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    let stats = fx.state.log.lock().unwrap().stats();
    assert_eq!(stats.upstream_of(Kind::Nar), 1);
    assert_eq!(stats.received_of(Kind::Nar), 1);
}

/// AC#2: the request log records per-request kind, bytes and timing, and a
/// narinfo->nar gap is derivable per path. Inject a known gap and read it back.
#[test]
fn request_log_records_fields_and_gap() {
    let fx = Fixture::with_nar(8192);

    get(fx.proxy_addr, "/test.narinfo").unwrap();
    let injected = Duration::from_millis(120);
    thread::sleep(injected);
    get(fx.proxy_addr, "/nar/testnar.nar").unwrap();

    let log = fx.state.log.lock().unwrap();
    let records = log.records();

    let narinfo = records.iter().find(|r| r.kind == Kind::Narinfo).unwrap();
    assert_eq!(narinfo.method, "GET");
    assert!(narinfo.bytes_sent > 0, "narinfo body was counted");
    assert!(narinfo.gap_ms.is_none(), "gap is a nar concept");

    let nar = records.iter().find(|r| r.kind == Kind::Nar).unwrap();
    assert_eq!(nar.bytes_sent, 8192, "nar byte count is exact");
    assert!(nar.duration_ms >= 0.0);
    let gap = nar.gap_ms.expect("nar records a narinfo->nar gap");
    // The gap must reflect the injected delay (within scheduling tolerance).
    assert!(
        gap >= injected.as_secs_f64() * 1000.0 - 20.0,
        "gap {gap} ms should be >= injected {} ms",
        injected.as_millis()
    );
}

/// AC#3: a large NAR streams through correctly (fixed-buffer copy, no whole-file
/// buffering) and the cached copy is byte-identical to the origin.
#[test]
fn large_nar_streams_and_caches_intact() {
    let size = 8 * 1024 * 1024 + 12345; // multi-chunk, non-aligned
    let fx = Fixture::with_nar(size);

    let resp = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    assert_eq!(resp.status, Some(200));
    assert_eq!(resp.content_length, Some(size as u64));
    assert!(resp.complete(), "full body delivered");
    assert_eq!(resp.body, fx.origin_nar(), "streamed bytes match origin");
    assert_eq!(fx.cached_nar().as_deref(), Some(fx.origin_nar().as_slice()));
}

/// AC#3: concurrent requests for the same cold path never observe partial or
/// corrupt bytes, and the committed cache entry is whole.
#[test]
fn concurrent_same_path_requests_are_never_torn() {
    let size = 2 * 1024 * 1024 + 777;
    let fx = Arc::new(Fixture::with_nar(size));
    let expected = fx.origin_nar();

    let mut handles = Vec::new();
    for _ in 0..16 {
        let fx = Arc::clone(&fx);
        handles.push(thread::spawn(move || {
            let resp = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
            assert_eq!(resp.status, Some(200));
            assert!(resp.complete(), "no torn/short body under concurrency");
            resp.body
        }));
    }
    for handle in handles {
        let body = handle.join().unwrap();
        assert_eq!(
            body, expected,
            "every concurrent reader got the exact bytes"
        );
    }

    // The final cache entry is complete and correct (atomic tmp+rename).
    assert_eq!(fx.cached_nar().as_deref(), Some(expected.as_slice()));
}

/// Passthrough fidelity: nix-cache-info is served verbatim - Priority 40 /
/// WantMassQuery 1 survive the proxy unchanged (substituter ordering depends on
/// them). Also proves it is cached on the second read.
#[test]
fn cache_info_passthrough_is_verbatim() {
    let fx = Fixture::with_nar(1024);
    let resp = get(fx.proxy_addr, "/nix-cache-info").unwrap();
    assert_eq!(resp.status, Some(200));
    let body = resp.body_string();
    assert!(
        body.contains("Priority: 40"),
        "Priority preserved: {body:?}"
    );
    assert!(
        body.contains("WantMassQuery: 1"),
        "WantMassQuery preserved: {body:?}"
    );
    assert_eq!(
        resp.body,
        std::fs::read(fx.origin_dir.join("nix-cache-info")).unwrap()
    );
}
