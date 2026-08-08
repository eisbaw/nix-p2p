//! AC#3 (task-13): a disk-failure in the testproxy cache must FAIL CLOSED - it
//! must never serve or leave a partial/corrupt entry.
//!
//! HONEST SCOPE (codex re-gate finding): a true byte-N *mid-stream* ENOSPC (the
//! write failing after some bytes have already flowed to an open fd) cannot be
//! simulated rootless - you cannot fail an already-open file descriptor's write
//! via chmod, and mounting a size-limited tmpfs needs privileges CI lacks. So
//! this file pins the disk-failure modes that ARE reachable and asserts the
//! fail-closed / no-poison invariant on each, and names what it does NOT cover:
//!
//!   * cache-OPEN failure (begin_write fails before any 200/body) -> 5xx, no
//!     partial entry. Reached by making the staging dir unwritable (ENOSPC and
//!     EACCES take the same `File::create` error branch). Tested here.
//!   * the mid-stream write-failure code path in `serve_nar` (write_all err ->
//!     break -> writer dropped uncommitted) is covered by the `DiskCache`
//!     unit test `commit_is_all_or_nothing` (a dropped-uncommitted writer leaves
//!     NO final file and NO tmp residue) plus the crash-orphan startup reap
//!     (`resolve_rejects_control_bytes_and_reaps_tmp`). Between them, no partial
//!     is ever committed and no `.tmp` leaks across a restart.

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
fn nar_miss_with_cache_open_failure_fails_closed_no_partial() {
    let fx = Fixture::with_nar(80_000);
    let tmp = fx.cache_dir.join(".tmp");

    // Make the cache staging area unwritable: begin_write's File::create now
    // fails BEFORE any 200/body is emitted (the ENOSPC-at-open case).
    let prev_tmp = chmod(&tmp, 0o500);
    let prev_cache = chmod(&fx.cache_dir, 0o500);

    let resp = get(fx.proxy_addr, "/nar/testnar.nar").unwrap();
    assert!(
        matches!(resp.status, Some(500) | Some(502)),
        "cache-open failure must fail closed with a 5xx, got {:?}",
        resp.status
    );
    assert!(
        resp.body.len() < 80_000,
        "must NOT have streamed a full body from a failed-cache path"
    );

    // Restore perms so the fixture's temp tree can be cleaned up on drop.
    chmod(&fx.cache_dir, prev_cache);
    chmod(&tmp, prev_tmp);

    // No NAR file was published, and no partial tmp residue was left behind.
    assert!(
        fs::read(fx.cache_dir.join("nar/testnar.nar")).is_err(),
        "a failed write must leave NO cache entry"
    );
    let tmp_residue = fs::read_dir(&tmp).unwrap().flatten().count();
    assert_eq!(tmp_residue, 0, "no partial .tmp residue may be left");
}

#[test]
fn narinfo_miss_with_cache_open_failure_fails_closed() {
    let fx = Fixture::with_nar(4096);
    let tmp = fx.cache_dir.join(".tmp");
    let prev_tmp = chmod(&tmp, 0o500);
    let prev_cache = chmod(&fx.cache_dir, 0o500);

    let resp = get(fx.proxy_addr, "/test.narinfo").unwrap();
    assert!(
        matches!(resp.status, Some(500) | Some(502)),
        "cache-open failure must fail closed on the metadata path too, got {:?}",
        resp.status
    );

    chmod(&fx.cache_dir, prev_cache);
    chmod(&tmp, prev_tmp);
    assert!(
        fs::read(fx.cache_dir.join("test.narinfo")).is_err(),
        "no partial narinfo entry may be published"
    );
}
