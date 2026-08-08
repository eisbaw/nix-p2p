//! AC#3 (task-13): a disk-full / unwritable testproxy cache must FAIL CLOSED -
//! it returns a clean gateway error and never serves (or leaves) a partial or
//! corrupt file. ENOSPC and EACCES take the same `File::create`/`write` error
//! branch, so making the cache staging dir unwritable faithfully models "no
//! space" without a size-limited tmpfs (which rootless CI cannot mount).

mod common;

use common::{Fixture, get};
use std::fs;
use std::os::unix::fs::PermissionsExt;

/// Set a directory's mode, returning the previous mode so the test can restore
/// it (a 0500 dir would otherwise block the temp-tree cleanup on drop).
fn chmod(dir: &std::path::Path, mode: u32) -> u32 {
    let prev = fs::metadata(dir).unwrap().permissions().mode();
    let mut perms = fs::metadata(dir).unwrap().permissions();
    perms.set_mode(mode);
    fs::set_permissions(dir, perms).unwrap();
    prev
}

#[test]
fn nar_miss_with_unwritable_cache_fails_closed_no_partial() {
    let fx = Fixture::with_nar(80_000);
    let tmp = fx.cache_dir.join(".tmp");

    // Make the cache staging area unwritable: every `begin_write` now fails,
    // exactly as an ENOSPC would on the write.
    let prev_tmp = chmod(&tmp, 0o500);
    let prev_cache = chmod(&fx.cache_dir, 0o500);

    // A cold NAR miss: the proxy cannot open a cache writer, so it must fail
    // closed (a 5xx), not stream a partial/uncached body that looks complete.
    let resp = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    assert!(
        matches!(resp.status, Some(500) | Some(502)),
        "unwritable cache must fail closed with a 5xx, got {:?}",
        resp.status
    );
    assert!(
        resp.body.len() < 80_000,
        "must NOT have streamed a full body from an unwritable-cache path"
    );

    // Restore perms so the fixture's temp tree can be cleaned up on drop.
    chmod(&fx.cache_dir, prev_cache);
    chmod(&tmp, prev_tmp);

    // And crucially: no NAR file was published into the cache (no partial entry).
    assert!(
        fs::read(fx.cache_dir.join("nar/testnar.nar")).is_err(),
        "a failed write must leave NO cache entry"
    );
}

#[test]
fn narinfo_miss_with_unwritable_cache_fails_closed() {
    let fx = Fixture::with_nar(4096);
    let tmp = fx.cache_dir.join(".tmp");
    let prev_tmp = chmod(&tmp, 0o500);
    let prev_cache = chmod(&fx.cache_dir, 0o500);

    let resp = get(fx.proxy_addr, "/test.narinfo").unwrap();
    assert!(
        matches!(resp.status, Some(500) | Some(502)),
        "unwritable cache must fail closed on the metadata path too, got {:?}",
        resp.status
    );

    chmod(&fx.cache_dir, prev_cache);
    chmod(&tmp, prev_tmp);
    assert!(
        fs::read(fx.cache_dir.join("test.narinfo")).is_err(),
        "no partial narinfo entry may be published"
    );
}
