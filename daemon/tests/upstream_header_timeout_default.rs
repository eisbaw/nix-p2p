//! TASK-111 LOCK-IN BITE: the upstream HEADER-timeout PRODUCT default is WAN-sane,
//! and the CONNECT-vs-HEADER split preserves fast-fail against a dead upstream.
//!
//! The wave-1 code set the header timeout to 1000 ms "short by design", which 502'd
//! a slow-but-HEALTHY upstream (a WAN link, a loaded host, an upstream cache-miss
//! doing real work) - needlessly bouncing Nix to the next substituter. TASK-111
//! separates the two numbers and raises the header default to `HEADER_TIMEOUT_MS`
//! (15 s) - a header-TTFB compromise: generous enough for a slow-but-healthy
//! upstream's think-time before its first header, bounded so a connect-then-silent
//! upstream still fails fast (the BODY-idle segment is governed separately by the
//! 30 s `BODY_IDLE_TIMEOUT_MS`, the true analog of Nix's `stalled-download-timeout`).
//!
//! These tests bite in BOTH directions (mutation-proven, see the task notes):
//!   * a healthy upstream that returns headers at ~1500 ms (above the OLD 1000 ms,
//!     far below the new 15 s default) is served, NOT 502'd. RED on the old default,
//!     GREEN after. Reverting `HEADER_TIMEOUT_MS` to 1000 turns this RED.
//!   * a connected-but-silent (dead-after-accept) upstream STILL fails PROMPTLY - the
//!     fast-fail S2 property is preserved - within ~10% of the configured bound (plus
//!     a scheduler grace), NOT hung for the full 15 s / 300 s. Disconnecting the
//!     header timeout from the wait turns this RED.
//!
//! Tested at the `UpstreamHttp` boundary (like `header_hygiene::h2_only_...`): the
//! serving layer maps a `SourceError` to a 502, so `Ok(200)` vs `Err` here is exactly
//! "served vs 502'd" at the wire.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::time::{Duration, Instant};

use daemon::{HEADER_TIMEOUT_MS, NarinfoSource, SourceError, StoreHash, UpstreamHttp};

/// A raw TCP origin modelling upstream RESPONSE-HEADER latency.
///   * `Some(delay)` - read the request head, sleep `delay` (the upstream's OWN
///     work), THEN write a valid HTTP/1.1 200 narinfo. A SLOW-but-HEALTHY upstream.
///   * `None` - read the request head, then stay SILENT (never send headers). A
///     connected-but-dead upstream (black-holed after accept): the case the header
///     timeout - not the connect timeout - must bound.
fn header_latency_origin(delay: Option<Duration>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("origin binds");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else { continue };
            std::thread::spawn(move || {
                // Drain the request head so the client's write completes and the
                // header-wait clock (not the connect clock) is what governs.
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                match delay {
                    Some(d) => {
                        std::thread::sleep(d);
                        let body = b"StorePath: /nix/store/dummy\n";
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/x-nix-narinfo\r\n\
                             Content-Length: {}\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(body);
                        let _ = stream.flush();
                        // Hold briefly so the client reads the full body before FIN.
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    None => {
                        // Silent forever: force the header timeout to be the thing
                        // that fires. Bounded so a leaked thread cannot outlive CI.
                        std::thread::sleep(Duration::from_secs(60));
                    }
                }
            });
        }
    });
    addr
}

/// The two defaults are DIFFERENT numbers for DIFFERENT physics (AC#1), pinned so a
/// future collapse back to one "short" number is caught without waiting on a timer.
#[test]
fn header_default_is_wan_sane_and_distinct_from_connect() {
    // Was a WAN-hostile 1000 ms; TASK-111 raised it to 15 s (comfortably above the
    // ~1500 ms the healthy-upstream bite below uses, and above real WAN cache-miss
    // header latencies), anchored to Nix's own 300 s stalled-download tolerance.
    assert_eq!(HEADER_TIMEOUT_MS, 15_000);
    // Compile-time: the header default must exceed the ~1500 ms healthy-upstream
    // bite below (const block so an inverting edit fails to BUILD; both operands
    // are const, which also keeps clippy::assertions_on_constants happy).
    const _: () = assert!(HEADER_TIMEOUT_MS > 1_500);
}

/// GREEN after TASK-111, RED before: a healthy upstream that takes ~1500 ms to
/// return headers (above the OLD 1000 ms default, far below the new 15 s one) is
/// SERVED, not 502'd. Uses `UpstreamHttp::new` with NO header-timeout override, so
/// it bites the PRODUCT DEFAULT constant directly (revert it to 1000 -> RED).
#[tokio::test]
async fn healthy_slow_upstream_at_1500ms_is_served_not_502d() {
    let addr = header_latency_origin(Some(Duration::from_millis(1500)));
    // No .with_header_timeout(): the product default is under test.
    let client = UpstreamHttp::new(&format!("http://{addr}")).expect("valid base");
    let hash = StoreHash::new("00000000000000000000000000000000");

    let started = Instant::now();
    let result = client.fetch(&hash).await;
    let elapsed = started.elapsed();

    // Served (Ok, 200) - on the old 1000 ms default this was Err(Unreachable) -> 502.
    let resp = result.expect("a healthy upstream at 1500ms must be served, not 502'd");
    assert_eq!(
        resp.status, 200,
        "expected the upstream's 200 to pass through"
    );
    // Sanity: it actually waited for the delayed headers (proves the delay took
    // effect, not that the origin answered instantly).
    assert!(
        elapsed >= Duration::from_millis(1500),
        "must have waited for the ~1500ms-delayed headers, took {elapsed:?}"
    );
}

/// Fast-fail S2 preserved: a connected-but-SILENT (dead-after-accept) upstream still
/// fails PROMPTLY, bounded by the configured header timeout - NOT hung for the 15 s
/// default nor Nix's 300 s. A short bound is injected via the setter so the test is
/// fast; the elapsed time tracks that bound (within ~10% plus a scheduler grace),
/// which is the property that matters: the header timeout still bites proportionally.
#[tokio::test]
async fn dead_after_accept_upstream_fails_within_bound() {
    // Injected header bound. 2 s makes 10% (200 ms) meaningfully larger than timer
    // granularity while keeping the test to ~2 s.
    const BOUND: Duration = Duration::from_millis(2_000);
    // Scheduler grace on a shared/loaded box (matches the codebase's ~1 s convention,
    // e.g. TLS_UPSTREAM_SCHEDULER_GRACE_MS). NOT part of the deadline - only what a
    // timing assert may add before declaring the bound honoured.
    const GRACE: Duration = Duration::from_millis(1_000);

    let addr = header_latency_origin(None); // never sends headers
    let client = UpstreamHttp::new(&format!("http://{addr}"))
        .expect("valid base")
        .with_header_timeout(BOUND);
    let hash = StoreHash::new("00000000000000000000000000000000");

    let started = Instant::now();
    let result = client.fetch(&hash).await;
    let elapsed = started.elapsed();

    // Fails (a transport SourceError -> 502), never a hang / never wrong bytes.
    assert!(
        matches!(result, Err(SourceError::Unreachable(_))),
        "a silent upstream must fail with a header-wait timeout, got {:?}",
        result.map(|r| r.status)
    );
    // It WAITED the configured bound (did not 502 early on something else)...
    // Integer Duration arithmetic only (owner rule: no floats in a timeout/bound).
    assert!(
        elapsed >= BOUND * 9 / 10,
        "must have waited ~the configured bound (fast-fail proportional to it), took {elapsed:?}"
    );
    // ...and fired PROMPTLY at it - within ~10% + scheduler grace, not the 15 s
    // default or Nix's 300 s. This is the preserved fast-fail-against-dead property.
    let upper = BOUND + BOUND / 10 + GRACE;
    assert!(
        elapsed <= upper,
        "the header timeout must fire within ~10%+grace of the {BOUND:?} bound, took {elapsed:?} (> {upper:?})"
    );
}
