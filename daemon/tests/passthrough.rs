//! Transparent-proxy behaviour against an in-process mock upstream:
//! byte-fidelity (S1/AC#3), status fidelity (AC#4), verbatim gzip forwarding and
//! fast failure (AC#6), and local cache-info.

mod common;

use std::time::Instant;

use common::{MockResponse, MockUpstream, get, head, spawn_daemon};

/// A gnarly-but-well-formed narinfo: unknown field, unusual ordering, TWO Sig
/// lines, non-empty References. Every byte must survive the daemon (AC#3).
const NARINFO: &[u8] = b"StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture-lib\n\
Sig: cache.nixos.org-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n\
URL: nar/1abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn.nar.xz\n\
Compression: xz\n\
FileHash: sha256:1111111111111111111111111111111111111111111111111111\n\
FileSize: 1234\n\
X-Unknown-Field: survives\n\
NarHash: sha256:2222222222222222222222222222222222222222222222222222\n\
NarSize: 4096\n\
References: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture-lib\n\
Deriver: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-fixture-lib.drv\n\
Sig: nix-p2p-test-1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==\n";

#[tokio::test]
async fn narinfo_passthrough_is_byte_identical() {
    let body = NARINFO.to_vec();
    let served = body.clone();
    let upstream = MockUpstream::start(move |_m, path| {
        if path.ends_with(".narinfo") {
            MockResponse::ok("text/x-nix-narinfo", served.clone())
        } else {
            MockResponse::status(404)
        }
    });
    let (daemon, _h) = spawn_daemon(&upstream.base_url()).await;

    let resp = get(daemon, "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo").await;
    assert_eq!(resp.status, Some(200));
    assert_eq!(resp.body, body, "narinfo must pass through byte-for-byte");
    // Spot-check the properties byte-identity guarantees.
    let text = resp.body_string();
    assert_eq!(
        text.matches("\nSig: ").count() + text.starts_with("Sig: ") as usize,
        2
    );
    assert!(text.contains("X-Unknown-Field: survives"));
    assert!(text.contains("References: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture-lib"));
}

#[tokio::test]
async fn mutated_signed_field_is_forwarded_verbatim_not_repaired() {
    // The daemon must be transparent to a signed-field mutation: it neither
    // introduces nor masks the discrepancy. A real Nix client re-verifying the
    // signature would then reject the mutated body and accept the clean one -
    // which is only possible because the daemon forwards exactly what it got.
    let clean = NARINFO.to_vec();
    let mut mutated = NARINFO.to_vec();
    // Flip one base32 char of the NarHash value (a signed field).
    let text = String::from_utf8(mutated.clone()).unwrap();
    let mutated_text = text.replacen(
        "NarHash: sha256:2222222222222222222222222222222222222222222222222222",
        "NarHash: sha256:2222222222222222222222222222222222222222222222222223",
        1,
    );
    mutated = mutated_text.into_bytes();
    assert_ne!(
        clean, mutated,
        "the mutation must actually change the bytes"
    );

    let served = mutated.clone();
    let upstream =
        MockUpstream::start(move |_m, _p| MockResponse::ok("text/x-nix-narinfo", served.clone()));
    let (daemon, _h) = spawn_daemon(&upstream.base_url()).await;

    let resp = get(daemon, "/x.narinfo").await;
    assert_eq!(resp.body, mutated, "daemon forwarded the mutation verbatim");
    assert_ne!(
        resp.body, clean,
        "daemon did not silently repair the signed field"
    );
}

#[tokio::test]
async fn upstream_404_stays_404_and_403_stays_403() {
    // A 404 mapped to 5xx makes Nix mark the substituter failed instead of
    // "absent here, fall back". 403 (S3-backed cache) likewise must survive.
    let upstream = MockUpstream::start(|_m, path| {
        if path.contains("forbidden") {
            MockResponse::status(403)
        } else {
            MockResponse::status(404)
        }
    });
    let (daemon, _h) = spawn_daemon(&upstream.base_url()).await;

    assert_eq!(get(daemon, "/missing.narinfo").await.status, Some(404));
    assert_eq!(get(daemon, "/forbidden.narinfo").await.status, Some(403));
    // NAR route too.
    assert_eq!(get(daemon, "/nar/missing.nar").await.status, Some(404));
}

#[tokio::test]
async fn unknown_path_kinds_pass_through_unchanged() {
    // nix log and .ls listings must not break (AC#4): they are neither narinfo
    // nor NAR, so they take the passthrough route.
    let upstream = MockUpstream::start(|_m, path| match path {
        "/log/aaaa-foo.drv" => {
            MockResponse::ok("text/plain", b"build log line 1\nline 2\n".to_vec())
        }
        "/foo.ls" => MockResponse::ok("application/json", br#"{"version":1}"#.to_vec()),
        p if p.starts_with("/debuginfo/") => MockResponse::ok("application/json", b"{}".to_vec()),
        _ => MockResponse::status(404),
    });
    let (daemon, _h) = spawn_daemon(&upstream.base_url()).await;

    let log = get(daemon, "/log/aaaa-foo.drv").await;
    assert_eq!(log.status, Some(200));
    assert_eq!(log.body, b"build log line 1\nline 2\n");

    let ls = get(daemon, "/foo.ls").await;
    assert_eq!(ls.status, Some(200));
    assert_eq!(ls.body, br#"{"version":1}"#);

    assert_eq!(get(daemon, "/debuginfo/xxxx").await.status, Some(200));
    assert_eq!(upstream.count_path("/log/aaaa-foo.drv"), 1);
}

#[tokio::test]
async fn gzip_nar_is_forwarded_verbatim_no_auto_decompression() {
    // AC#6 / the reqwest-gzip trap: upstream serves a NAR with
    // Content-Encoding: gzip and the gzipped Content-Length. The daemon must
    // forward the gzipped bytes, the header, and the length UNCHANGED so the Nix
    // client decompresses and verifies FileHash itself. If the daemon had
    // auto-decompressed, the header would be stripped and the body would equal
    // the plaintext - the two asserts below would fail. THAT is the bite.
    let plaintext = b"nix-archive-1 ... the real uncompressed NAR bytes ...".repeat(64);
    let gzipped = common::gzip(&plaintext);
    assert_ne!(gzipped, plaintext, "gzip must actually change the bytes");

    let served = gzipped.clone();
    let upstream = MockUpstream::start(move |_m, _p| {
        MockResponse::ok("application/x-nix-nar", served.clone())
            .with_header("Content-Encoding", "gzip")
    });
    let (daemon, _h) = spawn_daemon(&upstream.base_url()).await;

    let resp = get(daemon, "/nar/1abc.nar").await;
    assert_eq!(resp.status, Some(200));
    assert_eq!(
        resp.header("content-encoding"),
        Some("gzip"),
        "Content-Encoding must survive (not stripped by decompression)"
    );
    assert_eq!(resp.body, gzipped, "gzipped bytes forwarded verbatim");
    assert_eq!(
        resp.content_length,
        Some(gzipped.len() as u64),
        "Content-Length is the gzipped length, matching the body"
    );
    // The client's view: decompressing yields the true NAR (FileHash verifies),
    // and the forwarded body is NOT the plaintext (proves no decompression).
    assert_eq!(common::gunzip(&resp.body), plaintext);
    assert_ne!(resp.body, plaintext);
}

#[tokio::test]
async fn upstream_unreachable_fails_fast_and_clean() {
    // AC#6 / S2: a down upstream must not hang the build path. Point the daemon
    // at a definitely-closed loopback port and require a clean 502 well within
    // 2 seconds so Nix falls back.
    let dead_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
        // listener dropped here: the port is now closed -> connect refused.
    };
    let (daemon, _h) = spawn_daemon(&format!("http://127.0.0.1:{dead_port}")).await;

    let start = Instant::now();
    let resp = get(daemon, "/nar/anything.nar").await;
    let elapsed = start.elapsed();

    assert_eq!(
        resp.status,
        Some(502),
        "down upstream yields a clean gateway error"
    );
    assert!(
        elapsed.as_millis() < 2000,
        "must fail fast, took {}ms",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn cache_info_is_served_locally_not_proxied() {
    // AC#5: the daemon advertises its OWN cache-info; it must not touch upstream
    // (so it stays instant even when upstream is down - the additive invariant).
    let upstream = MockUpstream::start(|_m, _p| MockResponse::status(500));
    let (daemon, _h) = spawn_daemon(&upstream.base_url()).await;

    let resp = get(daemon, "/nix-cache-info").await;
    assert_eq!(resp.status, Some(200));
    assert_eq!(
        resp.body_string(),
        "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 30\n"
    );
    assert_eq!(resp.header("content-type"), Some("text/x-nix-cache-info"));
    assert_eq!(
        upstream.count_path("/nix-cache-info"),
        0,
        "cache-info must be local, never proxied"
    );
}

#[tokio::test]
async fn head_returns_headers_without_a_body() {
    let served = NARINFO.to_vec();
    let upstream =
        MockUpstream::start(move |_m, _p| MockResponse::ok("text/x-nix-narinfo", served.clone()));
    let (daemon, _h) = spawn_daemon(&upstream.base_url()).await;

    let resp = head(daemon, "/x.narinfo").await;
    assert_eq!(resp.status, Some(200));
    assert!(resp.body.is_empty(), "HEAD must not carry a body");
    assert_eq!(
        resp.content_length,
        Some(NARINFO.len() as u64),
        "HEAD still advertises the true Content-Length"
    );
}
