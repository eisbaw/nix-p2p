//! Regression for the codex integrity blocker: S1 byte-identity when two
//! narinfos share a NarHash but differ in compression (hence in URL token).
//!
//! Two narinfos can carry the SAME signed `NarHash` (identical uncompressed NAR
//! content) while advertising DIFFERENT `URL:` tokens - because the token is
//! FileHash-of-the-compressed-file, and xz vs zstd of the same NAR compress
//! differently. The first cut's `NarHash -> token` reverse map was therefore
//! lossy: recording A then B overwrote the reverse to `NarHash -> B`, so a later
//! `GET /nar/A` fetched B's bytes. This test drives exactly that: it must serve
//! each token's OWN bytes.
//!
//! Fails-before/passes-after: on the reverse-map code, step 3 below served B's
//! bytes for an A request (assert_eq on the body fails). With the token carried
//! as `upstream_hint`, the daemon fetches the exact requested token and passes.

mod common;

use common::{MockResponse, MockUpstream, get, spawn_daemon};

const SHARED_NARHASH: &str = "sha256:1sharedsharedsharedsharedsharedsharedsharedshared99";

/// A narinfo advertising `token` and the SHARED NarHash.
fn narinfo_for(token: &str, compression: &str) -> Vec<u8> {
    format!(
        "StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
         URL: nar/{token}\n\
         Compression: {compression}\n\
         FileHash: sha256:{token}filehashdistinct\n\
         FileSize: 100\n\
         NarHash: {SHARED_NARHASH}\n\
         NarSize: 4096\n\
         References: \n\
         Sig: nix-p2p-test-1:AAAA==\n"
    )
    .into_bytes()
}

#[tokio::test]
async fn shared_nar_hash_still_serves_each_tokens_own_bytes() {
    // Distinct bytes per token so a mix-up is detectable.
    let bytes_a = b"AAAA the xz-compressed bytes for token A".repeat(4);
    let bytes_b = b"BBBB the zstd-compressed bytes for token B".repeat(4);
    let (ba, bb) = (bytes_a.clone(), bytes_b.clone());

    let upstream = MockUpstream::start(move |_m, path| match path {
        "/a.narinfo" => MockResponse::ok("text/x-nix-narinfo", narinfo_for("aaaa.nar.xz", "xz")),
        "/b.narinfo" => MockResponse::ok("text/x-nix-narinfo", narinfo_for("bbbb.nar.zst", "zstd")),
        "/nar/aaaa.nar.xz" => MockResponse::ok("application/x-nix-nar", ba.clone()),
        "/nar/bbbb.nar.zst" => MockResponse::ok("application/x-nix-nar", bb.clone()),
        _ => MockResponse::status(404),
    });
    let (daemon, _h) = spawn_daemon(&upstream.base_url()).await;

    // 1 & 2: the daemon sees both narinfos. Both correlate to SHARED_NARHASH; on
    // the old reverse map, B (recorded second) would win the NarHash->token slot.
    assert_eq!(get(daemon, "/a.narinfo").await.status, Some(200));
    assert_eq!(get(daemon, "/b.narinfo").await.status, Some(200));

    // 3: request A. Must serve A's exact bytes - not B's (the old bug).
    let a = get(daemon, "/nar/aaaa.nar.xz").await;
    assert_eq!(a.status, Some(200));
    assert_eq!(a.body, bytes_a, "GET /nar/aaaa.nar.xz must serve A's bytes");
    assert_ne!(
        a.body, bytes_b,
        "must NOT serve B's bytes (the reverse-map bug)"
    );

    // 4: request B. Must serve B's exact bytes.
    let b = get(daemon, "/nar/bbbb.nar.zst").await;
    assert_eq!(b.status, Some(200));
    assert_eq!(
        b.body, bytes_b,
        "GET /nar/bbbb.nar.zst must serve B's bytes"
    );

    // The upstream saw exactly the tokens requested - the daemon never fetched a
    // token reconstructed from the shared hash.
    assert_eq!(upstream.count_path("/nar/aaaa.nar.xz"), 1);
    assert_eq!(upstream.count_path("/nar/bbbb.nar.zst"), 1);
}
