//! End-to-end anti-trap for the NarSize-vs-FileSize unit determinant (TASK-226,
//! defense-in-depth for TASK-25; the [[nar-size-vs-file-size-unit-trap]] 6th
//! recurrence).
//!
//! The anti-trap was previously tested at TWO layers SEPARATELY - the PARSE layer
//! (`catalog::compression_is_authoritative_not_the_url_suffix`: a `.nar` URL +
//! `Compression: xz` parses as COMPRESSED) and the UPSTREAM layer
//! (`upstream::nar_suffix_url_with_compression_xz_is_not_capped_by_narsize`:
//! `fetch_streaming` supplied a `Compressed` transport DIRECTLY). Neither drives
//! the SERVER layer that threads the authoritative narinfo `Compression` from the
//! catalog into the `NarKey::SignedNarHash { transport }` it hands to the upstream
//! (server.rs, the `Route::Nar` correlation arm). So a single-layer mutation
//! there (injecting `Compression = Raw` for a compressed body) could evade BOTH
//! existing tests while capping a legitimate compressed transfer at the
//! uncompressed NarSize in production.
//!
//! THIS test spans all three layers in one flow, through the REAL daemon over a
//! loopback upstream. First a narinfo GET runs `respond_narinfo ->
//! parse_correlation -> catalog.record` (PARSE + catalog), learning `token ->
//! (NarHash, NarSize, transport)`. Then a nar GET runs `Route::Nar` (SERVER: reads
//! the catalog, builds the `SignedNarHash` key carrying `meta.transport`) ->
//! `resolve_within -> fetch_streaming -> compute_transport_cap` (UPSTREAM).
//!
//! The narinfo deliberately advertises a `.nar` URL suffix (the old heuristic
//! would call it RAW and cap at NarSize) while its AUTHORITATIVE `Compression` is
//! `xz`, and a `NarSize` (uncompressed) SMALLER than the on-wire compressed
//! FileSize/Content-Length. A legitimate compressed transfer whose on-wire bytes
//! exceed the uncompressed NarSize MUST stream to completion - it is bounded by
//! its own Content-Length, NEVER by NarSize (the wrong unit; Nix enforces the
//! uncompressed guarantee downstream via its NarHash/NarSize gate).
//!
//! Because the URL suffix is `.nar` (says raw) but Compression is `xz` (says
//! compressed), a single-layer mutation that smuggles `Raw` for this body at ANY
//! of the three layers - parse (derive from suffix), server (inject Raw into the
//! key), or upstream (cap by suffix) - turns this test RED: the compressed body
//! would then be capped at NarSize and aborted mid-stream, arriving truncated.
//! Mutation-proven at the SERVER layer (server.rs `Route::Nar`, `transport:
//! meta.transport` -> `Compression::Raw`): RED under mutation, green restored.

mod common;

use common::{MockResponse, MockUpstream, get, spawn_daemon};

/// Uncompressed NAR bytes (the SIGNED NarSize). Deliberately SMALLER than the
/// on-wire compressed transfer below - the pathological-but-legitimate case the
/// trap mishandles: NarSize and FileSize are different UNITS and must never be
/// compared. (A tiny/incompressible NAR whose xz framing overhead makes the
/// archive larger is the concrete real-world instance.)
const NAR_SIZE: usize = 1000;
/// On-wire COMPRESSED transfer size (the FileSize / Content-Length). Exceeds
/// NarSize on purpose: the daemon must bound this body by ITS OWN Content-Length,
/// never by the uncompressed NarSize.
const ON_WIRE_FILE_SIZE: usize = 3072;

const STORE_HASH: &str = "0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz";
/// `.nar` suffix (the lying heuristic says RAW) while Compression is xz.
const NAR_TOKEN: &str = "deadbeefanti7trap0000000000000000.nar";
const NAR_HASH: &str = "sha256:1antitrapantitrapantitrapantitrapantitrapanti7";

/// The trap is only observable when the compressed transfer genuinely EXCEEDS the
/// uncompressed NarSize (else `min(CL, NarSize)` and `CL` coincide and a
/// Raw-smuggling mutation could not change the outcome). Compile-time, no floats.
const _: () = assert!(ON_WIRE_FILE_SIZE > NAR_SIZE);

/// A `Compression: xz` narinfo whose URL ends `.nar` and whose signed NarSize
/// (uncompressed) is SMALLER than the on-wire FileSize (compressed).
fn narinfo() -> Vec<u8> {
    format!(
        "StorePath: /nix/store/{STORE_HASH}-nix-p2p-anti-trap\n\
         URL: nar/{NAR_TOKEN}\n\
         Compression: xz\n\
         FileHash: sha256:0anti7trapfilehashfilehashfilehashfilehashfile00\n\
         FileSize: {ON_WIRE_FILE_SIZE}\n\
         NarHash: {NAR_HASH}\n\
         NarSize: {NAR_SIZE}\n\
         References: \n\
         Sig: nix-p2p-test-1:AAAA==\n"
    )
    .into_bytes()
}

/// The on-wire compressed body, a distinctive repeating pattern of exactly
/// `ON_WIRE_FILE_SIZE` bytes so a truncated (capped) transfer is detectable by
/// both length AND content.
fn on_wire_body() -> Vec<u8> {
    let mut b = b"XZ-COMPRESSED-NAR-BYTES-"
        .iter()
        .copied()
        .cycle()
        .take(ON_WIRE_FILE_SIZE)
        .collect::<Vec<u8>>();
    b.truncate(ON_WIRE_FILE_SIZE);
    b
}

#[tokio::test]
async fn compressed_body_over_uncompressed_narsize_streams_end_to_end() {
    let body = on_wire_body();
    let body_for_upstream = body.clone();
    let nar_path = format!("/nar/{NAR_TOKEN}");
    let narinfo_path = format!("/{STORE_HASH}.narinfo");
    let nar_path_for_upstream = nar_path.clone();
    let narinfo_path_for_upstream = narinfo_path.clone();

    let upstream = MockUpstream::start(move |_method, path| {
        if path == narinfo_path_for_upstream {
            MockResponse::ok("text/x-nix-narinfo", narinfo())
        } else if path == nar_path_for_upstream {
            // MockUpstream sends the true body length as Content-Length, so the
            // on-wire Content-Length is ON_WIRE_FILE_SIZE (> NarSize).
            MockResponse::ok("application/x-nix-nar", body_for_upstream.clone())
        } else {
            MockResponse::status(404)
        }
    });
    let (daemon, _h) = spawn_daemon(&upstream.base_url()).await;

    // Layer 1 (PARSE + catalog): the daemon sees the narinfo and records
    // `token -> (NarHash, NarSize, Compression=Compressed)` via parse_correlation.
    let ni = get(daemon, &narinfo_path).await;
    assert_eq!(ni.status, Some(200), "narinfo must be served");

    // Layers 2+3 (SERVER Route::Nar transport threading + UPSTREAM
    // fetch_streaming/compute_transport_cap): the compressed body, whose on-wire
    // Content-Length EXCEEDS the uncompressed NarSize, must stream to completion.
    let nar = get(daemon, &nar_path).await;
    assert_eq!(nar.status, Some(200), "nar must be served");
    assert!(
        nar.complete,
        "the compressed transfer must complete (a Raw-smuggling mutation at parse/server/upstream \
         would cap it at NarSize={NAR_SIZE} and abort mid-stream): got {} of {ON_WIRE_FILE_SIZE} bytes",
        nar.body.len()
    );
    assert_eq!(
        nar.body.len(),
        ON_WIRE_FILE_SIZE,
        "the full compressed body streams verbatim; NarSize is the wrong unit for on-wire bytes"
    );
    assert_eq!(
        nar.body, body,
        "the on-wire bytes are forwarded byte-verbatim, uncapped by NarSize"
    );
    // The daemon fetched the EXACT requested token from upstream exactly once (the
    // correlated SignedNarHash path used the token as its upstream_hint).
    assert_eq!(
        upstream.count_path(&nar_path),
        1,
        "the daemon fetched the exact nar token once via the correlated path"
    );
}
