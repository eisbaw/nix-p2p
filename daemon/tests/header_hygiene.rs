//! AC#2 (task-13 hardening): PIN the daemon's response-header hygiene policy.
//!
//! The daemon is a transparent proxy, so its header policy is
//! deny-a-fixed-set/forward-everything-else (documented on `server::HOP_BY_HOP`
//! and `forward_headers`). These tests assert the EXACT forwarded/stripped
//! split at the wire, so a future change to the hop-by-hop list or an accidental
//! decoding layer trips a red test rather than silently mangling metadata.
//!
//! Coverage split (kept DRY): the gzip `Content-Encoding` verbatim-body leg is
//! pinned by `passthrough.rs::gzip_nar_is_forwarded_verbatim_no_auto_decompression`;
//! `server.rs`'s unit test pins `transfer-encoding`/`connection` stripping and
//! `content-encoding` survival in isolation. Here we pin (a) the broader
//! end-to-end allowlist through the real serving stack, (b) the RFC 7230 §6.1
//! `Connection:`-listed-token stripping (with a bite), and (c) the HTTP/2-upstream
//! gap - that an h2-only upstream fails CLOSED (a fast 502), never hangs.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{MockResponse, MockUpstream, get, spawn_daemon};
use daemon::{NarinfoSource, SourceError, StoreHash, UpstreamHttp};

/// The full end-to-end allowlist: forward every end-to-end header verbatim,
/// strip every hop-by-hop one. Driven over the real serving stack via a
/// passthrough (`/log/*`) route so no narinfo Content-Length recompute is in play.
#[tokio::test]
async fn forwarded_and_stripped_header_allowlist_is_pinned() {
    // The upstream returns a rich, representative header set on a passthrough path.
    let upstream = MockUpstream::start(|_method, _path| {
        MockResponse::ok("application/x-nix-nar", b"body".to_vec())
            // -- end-to-end: MUST be forwarded verbatim --
            .with_header("Content-Encoding", "gzip") // header pin; body-leg is in passthrough.rs
            .with_header("Cache-Control", "public, max-age=0")
            .with_header("ETag", "\"deadbeef\"")
            .with_header("Age", "5")
            .with_header("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
            .with_header("X-Served-By", "cache-fra-1")
            // -- hop-by-hop: MUST be stripped --
            .with_header("Keep-Alive", "timeout=5, max=100")
            .with_header("Proxy-Authenticate", "Basic realm=\"x\"")
        // NOTE: `Connection: close` is injected by the mock itself and must also
        // be stripped; `transfer-encoding` is excluded here because it conflicts
        // with the mock's Content-Length framing (pinned in the server.rs unit test).
    });
    let (daemon, _h) = spawn_daemon(&upstream.base_url()).await;

    // `/log/*` is the RawUpstream passthrough route (forward() -> forward_headers).
    let resp = get(daemon, "/log/foo.drv").await;
    assert_eq!(resp.status, Some(200));

    let forwarded = [
        ("content-encoding", "gzip"),
        ("cache-control", "public, max-age=0"),
        ("etag", "\"deadbeef\""),
        ("age", "5"),
        ("last-modified", "Wed, 21 Oct 2026 07:28:00 GMT"),
        ("x-served-by", "cache-fra-1"),
        ("content-type", "application/x-nix-nar"),
    ];
    for (name, want) in forwarded {
        assert_eq!(
            resp.header(name),
            Some(want),
            "end-to-end header {name:?} must be forwarded verbatim"
        );
    }

    // The UPSTREAM's hop-by-hop headers must not leak through. `connection` is
    // deliberately NOT asserted absent here: hyper's SERVER layer sets its own
    // `Connection: close` for the client hop (the test client sends
    // `Connection: close`), which is correct end-of-hop behaviour, not a leaked
    // upstream header. Keep-Alive / Proxy-Authenticate are never re-added, so
    // their absence cleanly proves the upstream hop-by-hop set was stripped.
    for name in ["keep-alive", "proxy-authenticate"] {
        assert!(
            resp.header(name).is_none(),
            "upstream hop-by-hop header {name:?} must be stripped, saw {:?}",
            resp.header(name)
        );
    }
}

/// RFC 7230 §6.1: a field named in a `Connection:` header value is hop-by-hop
/// for THIS message and must be stripped. BITE: the same header survives when it
/// is NOT listed in Connection, so the strip is caused by the listing, not by a
/// static denylist entry.
#[tokio::test]
async fn connection_listed_token_is_stripped_but_survives_when_unlisted() {
    // Armed: X-Custom-Hop IS listed in Connection -> must be stripped.
    let listed = MockUpstream::start(|_m, _p| {
        MockResponse::ok("text/plain", b"x".to_vec())
            .with_header("Connection", "X-Custom-Hop")
            .with_header("X-Custom-Hop", "secret-per-connection-value")
    });
    let (d1, _h1) = spawn_daemon(&listed.base_url()).await;
    let r1 = get(d1, "/log/a").await;
    assert_eq!(r1.status, Some(200));
    assert!(
        r1.header("x-custom-hop").is_none(),
        "a Connection-listed token must be stripped, saw {:?}",
        r1.header("x-custom-hop")
    );

    // Bite control: identical header, NOT listed in Connection -> must survive.
    let unlisted = MockUpstream::start(|_m, _p| {
        MockResponse::ok("text/plain", b"x".to_vec())
            .with_header("X-Custom-Hop", "secret-per-connection-value")
    });
    let (d2, _h2) = spawn_daemon(&unlisted.base_url()).await;
    let r2 = get(d2, "/log/a").await;
    assert_eq!(
        r2.header("x-custom-hop"),
        Some("secret-per-connection-value"),
        "an UNLISTED end-to-end header must be forwarded (proves the strip is \
         caused by the Connection listing - the bite)"
    );
}

/// The HTTP/2-upstream gap (documented on `UpstreamHttp`): the daemon's upstream
/// client speaks HTTP/1.1 only. Against an h2-ONLY upstream it must fail CLOSED -
/// a fast [`SourceError`] (which the serving layer turns into a 502), never a
/// hang or a mis-parsed body. Pins the fail-closed ceiling, not h2 support.
#[tokio::test]
async fn h2_only_upstream_fails_closed_not_hang() {
    // A raw "h2-only" origin: on connect it drains the h1 request line and then
    // writes an HTTP/2 SETTINGS frame (the first thing a real h2 server emits),
    // which is binary garbage to an HTTP/1.1 parser.
    let listener = TcpListener::bind("127.0.0.1:0").expect("h2 mock binds");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else { continue };
            std::thread::spawn(move || {
                // Read whatever the h1 client sends (its request), ignore it.
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                // HTTP/2 SETTINGS frame: 9-byte frame header, length=0, type=0x4
                // (SETTINGS), flags=0, stream id=0. No HTTP/1 status line anywhere.
                let settings_frame = [0u8, 0, 0, 4, 0, 0, 0, 0, 0];
                let _ = stream.write_all(&settings_frame);
                let _ = stream.flush();
                // Hold the socket briefly so the client observes frames, not EOF.
                std::thread::sleep(Duration::from_millis(200));
            });
        }
    });

    let client = UpstreamHttp::new(&format!("http://{addr}")).expect("valid base");
    let hash = StoreHash::new("00000000000000000000000000000000");

    let started = Instant::now();
    let result = client.fetch(&hash).await;
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "an h2-only upstream must fail closed, got {:?}",
        result.map(|r| r.status)
    );
    // Fail-CLOSED discipline (S2): the error is a transport SourceError the
    // serving layer maps to 502, and it arrives fast (well within the 1000ms
    // header timeout) - not a hang.
    assert!(
        matches!(
            result,
            Err(SourceError::Upstream(_)) | Err(SourceError::Unreachable(_))
        ),
        "expected a transport SourceError (-> 502 to Nix)"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "must fail fast, not hang; took {elapsed:?}"
    );
    let _ = addr; // silence unused on some cfgs
}

/// A local sanity assert that the mock/daemon plumbing above is not vacuous:
/// a plain end-to-end header with no special handling is forwarded.
#[tokio::test]
async fn plumbing_is_not_vacuous_plain_header_forwards() {
    let upstream: Arc<MockUpstream> = Arc::new(MockUpstream::start(|_m, _p| {
        MockResponse::ok("text/plain", b"ok".to_vec()).with_header("X-Plain", "kept")
    }));
    let (d, _h) = spawn_daemon(&upstream.base_url()).await;
    let r = get(d, "/log/x").await;
    assert_eq!(r.header("x-plain"), Some("kept"));
    let _bound: SocketAddr = d;
}
