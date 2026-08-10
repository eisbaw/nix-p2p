//! Shared helpers for the TASK-65 residency-oracle tests.
//!
//! ## Why these tests live in SEPARATE TEST TARGETS (task-109)
//!
//! `vm_bytes` reads `/proc/self/status`, which is a WHOLE-PROCESS figure. These
//! tests were originally three `#[tokio::test]`s in ONE binary, and libtest runs
//! the tests of a binary CONCURRENTLY IN THE SAME PROCESS. Each of them moves
//! ~32 MiB, so every RSS reading was being taken while a sibling allocated or
//! freed the same order of magnitude underneath it. Measured consequence: 13
//! failures in 64 runs under load, with tells visible even in the runs that
//! passed - a `VmRSS baseline` HIGHER than the same test's `seeded` reading, and
//! an "allocator returned" figure of 298.4% (and, in another run, -1.0%).
//!
//! The fix is process isolation, and it is an ELIMINATION rather than a
//! mitigation: cargo runs test TARGETS sequentially (verified against this
//! repo's own suite - the log strictly alternates `Running tests/X` and `test
//! result` across all targets, never two in flight), while `/proc/self/status`
//! is per-process. So a test alone in its target is the only allocator of
//! consequence in the process it measures. Load on the MACHINE - other
//! processes, a parallel build - cannot move a per-process reading.
//!
//! DO NOT merge these targets back together to tidy up the file count. One
//! RSS-measuring test per target is the invariant that makes the instrument
//! sound, and `store_residency_retainall.rs` is kept separate for the same
//! reason even though it measures nothing: it SEEDS 32 MiB, which is enough to
//! corrupt a sibling's baseline.
//!
//! Rejected alternative: `--test-threads=1`. It would fix the reading by
//! deleting parallel execution for the whole suite, which buys determinism with
//! coverage and hides exactly the class of concurrency defect the rest of these
//! tests exist to catch.

#![allow(dead_code)]

use std::time::{Duration, Instant};

use daemon::{IrohProvider, StoreResidency};

/// The payload size. Large enough that the resident cost of the content dominates
/// the ~17 MiB process baseline by an order of magnitude, so "the payload really
/// became resident" is an assertion and not a hope; small enough that a parallel
/// `cargo test` run does not turn into a memory experiment of its own.
pub const PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

/// How long to wait for a gc-enabled store to sweep. Generous relative to the 50 ms
/// gc interval: this bounds a HANG, it is not a timing assertion.
pub const RELEASE_DEADLINE: Duration = Duration::from_secs(20);

// ---- a real (uncompressed) nix-archive-1 NAR, synthesised in memory ----------

fn nar_str(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    let pad = (8 - (bytes.len() % 8)) % 8;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// A valid raw NAR for a single regular file whose contents are `contents`.
///
/// Exact capacity, not `Vec::new()`: growth by doubling would leave a transient
/// peak of up to twice the payload inside VmHWM, and these tests' whole subject is
/// what VmHWM does and does not mean.
pub fn synth_raw_nar(contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 128);
    nar_str(&mut out, b"nix-archive-1");
    nar_str(&mut out, b"(");
    nar_str(&mut out, b"type");
    nar_str(&mut out, b"regular");
    nar_str(&mut out, b"contents");
    nar_str(&mut out, contents);
    nar_str(&mut out, b")");
    out
}

// ---- the RSS oracle these tests exist to discredit ---------------------------

/// One `VmXxx: N kB` field of this process, in BYTES.
///
/// Panics rather than returning 0 on a missing field: this is the instrument the
/// test is comparing AGAINST, and an instrument that silently reads 0 would make
/// the comparison come out in the store oracle's favour for the wrong reason.
pub fn vm_bytes(key: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status")
        .expect("/proc/self/status is readable on this platform");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}:")) {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            assert_eq!(
                parts.len(),
                2,
                "/proc/self/status line for {key} is not 'N kB': {line:?}"
            );
            assert_eq!(parts[1], "kB", "unexpected unit in {line:?}");
            return parts[0].parse::<u64>().expect("VmXxx value is an integer") * 1024;
        }
    }
    panic!("/proc/self/status has no {key} field (unknown is not 0)");
}

/// THE ORACLE UNDER TEST'S RIVAL, written down as a function so its verdict can be
/// compared rather than argued about: "the store released the payload iff peak RSS
/// is no longer carrying it". The half-payload threshold is deliberately generous -
/// making the RSS oracle as strong as it can be is what makes its failure a
/// property of the instrument rather than of a badly chosen constant.
pub fn rss_hwm_says_released(hwm_bytes: u64, baseline_bytes: u64, payload_bytes: u64) -> bool {
    hwm_bytes < baseline_bytes + payload_bytes / 2
}

/// The oracle these tests argue for: ask the store.
pub fn store_says_released(residency: StoreResidency) -> bool {
    residency.bytes_uncompressed_nar == 0
}

pub async fn poll_until_released(provider: &IrohProvider) -> StoreResidency {
    let deadline = Instant::now() + RELEASE_DEADLINE;
    loop {
        let residency = provider
            .store_residency()
            .await
            .expect("store residency is queryable");
        if residency.blobs == 0 || Instant::now() >= deadline {
            return residency;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
