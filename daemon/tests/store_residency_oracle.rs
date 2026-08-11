//! TASK-65 AC#3: the RESIDENCY ORACLE, and the mutation that proves it discriminates.
//!
//! ## The problem this file exists for
//!
//! "Does the node still hold the NAR it served?" is the question TASK-61 (supply
//! model), TASK-62 (streaming) and TASK-46 (the `to_vec` clone) will all be judged
//! on. The obvious instrument - peak RSS - CANNOT answer it:
//!
//!   * `VmHWM` is a high-water mark and is monotone by kernel definition. It never
//!     goes down, so it reports the SAME number whether the store released the
//!     content or not. An oracle built on it fails on a correct fix.
//!   * `VmRSS` is not reliable either: glibc's allocator does not have to return a
//!     freed arena to the OS, so a genuinely released NAR can leave current RSS
//!     flat. An oracle built on it passes on a wrong fix.
//!
//! ## The mechanism chosen, and the ones rejected
//!
//! CHOSEN: store-side residency, asked of the blob store itself
//! ([`IrohProvider::store_residency`] -> `blobs().list()` + `blobs().status()`).
//! It is an accounting question answered by iroh-blobs, so no allocator behaviour
//! can move it.
//!
//! REJECTED:
//!   * `malloc_trim(0)` / `M_ARENA_MAX` at a defined point - the workspace sets
//!     `unsafe_code = "forbid"`, so `libc::malloc_trim` is not callable at all
//!     without changing a workspace-wide lint.
//!   * `MALLOC_MMAP_THRESHOLD_` via the environment - callable, but it changes the
//!     allocator configuration of the system being measured, so the fitted
//!     bytes-of-RSS-per-byte-of-NAR slope would no longer describe the default
//!     build. A measurement instrument that alters what it measures is the wrong
//!     trade for a number whose whole purpose is to be quoted.
//!   * `/proc/<pid>/smaps_rollup` - still a process-level current-RSS reading, so
//!     it inherits the same arena problem it was reached for to solve.
//!
//! STATED LIMIT: store residency answers "does the STORE still hold this content".
//! With `MemStore` that IS resident memory by construction. Under a future on-disk
//! store it is not, and the mapping would have to be re-derived (TASK-61).
//!
//! ## Why this is a MUTATION proof and not an assertion
//!
//! The test constructs two states IN ONE PROCESS whose `VmHWM` reading is
//! IDENTICAL and whose ground truth is OPPOSITE - released vs retained - and shows
//! the oracle separates them. That is the discrimination stated as an experiment
//! rather than as a claim, and it also demonstrates, with numbers, that the RSS
//! oracle the task warns about would have reported the same value for both.
//!
//! Two more tests bound the claim. One mutates in the OTHER direction: on a
//! `RetainAll` store the same `release_all()` call must leave residency UNCHANGED -
//! without it, an oracle that simply returned 0 after any release request would pass
//! the first test. The other asks whether CURRENT RSS can be made to lie the same
//! way VmHWM does, and records the measured answer on this host (it could not be:
//! glibc returned ~97% of the payload however the allocations were shaped), so
//! nobody generalises a host-specific accident into "VmRSS is a fine oracle".
//!
//! Nothing here names the generated fixture tree (the source guard forbids it):
//! the NAR is synthesised in memory.

// TASK-109: this file holds EXACTLY ONE test, and must keep holding exactly one.
// `vm_bytes` reads /proc/self/status, a WHOLE-PROCESS figure, and libtest runs the
// tests of a binary concurrently IN THE SAME PROCESS. The three tests that used to
// live here each move ~32 MiB, so every reading was taken while a sibling allocated
// underneath it. See residency_support/mod.rs for the full argument and for why
// separate TARGETS (which cargo runs sequentially) fix it.

mod residency_support;

use std::time::Duration;

use daemon::{IrohProviderNode, StoreResidency, StoreRetention};
use residency_support::{
    PAYLOAD_BYTES, poll_until_released, rss_hwm_says_released, store_says_released, synth_raw_nar,
    vm_bytes,
};

#[tokio::test(flavor = "multi_thread")]
async fn residency_oracle_discriminates_release_from_allocator_retention() {
    let provider = IrohProviderNode::spawn_with_retention(StoreRetention::ReleaseOnRequest {
        sweep_interval: Duration::from_millis(50),
    })
    .await
    .expect("provider spawns");

    let empty = provider
        .store_residency()
        .await
        .expect("store residency is queryable");
    assert_eq!(
        empty,
        StoreResidency::default(),
        "a fresh store holds nothing"
    );
    // BASELINE: taken before the payload exists in any form, so "the process is one
    // payload heavier" is measurable against it.
    let rss_baseline = vm_bytes("VmRSS");
    let hwm_baseline = vm_bytes("VmHWM");

    let nar = synth_raw_nar(&vec![0x5au8; PAYLOAD_BYTES]);
    let nar_len = nar.len() as u64;
    provider.seed(&nar).await.expect("seed succeeds");
    // The caller's copy is no longer needed - `seed` CLONES it into the store
    // (transport_iroh.rs `add_bytes(raw_nar.to_vec())`, the clone TASK-46 owns).
    // Dropping it here means the only remaining copy of the payload is the store's,
    // which is what makes the release below observable at all.
    drop(nar);

    let seeded = provider
        .store_residency()
        .await
        .expect("store residency is queryable");
    assert_eq!(
        seeded,
        StoreResidency {
            blobs: 1,
            bytes_uncompressed_nar: nar_len
        },
        "the store must report exactly the seeded NAR (in NarSize units)"
    );

    // ANTI-VACUITY CONTROL. If the payload never became resident, everything below
    // would compare two readings of a process that did nothing, and the test would
    // pass for the wrong reason - the exact shape of oracle this project has
    // shipped three times. Measured against CURRENT RSS with our own copy already
    // dropped, so what it asserts is precisely "the STORE's copy is resident".
    //
    // 90% of the payload, not 100%: current RSS is a whole-process figure and the
    // iroh runtime frees and allocates underneath us between the two readings.
    // Excluding "the payload never became resident" is an order-of-magnitude
    // question, not a 1% one.
    let rss_seeded = vm_bytes("VmRSS");
    let hwm_seeded = vm_bytes("VmHWM");
    let rss_rise = rss_seeded.saturating_sub(rss_baseline);
    assert!(
        rss_rise >= nar_len / 10 * 9,
        "resident memory rose by {rss_rise} B after seeding a {nar_len} B payload \
         and dropping our own copy - the store's copy did not become resident, so \
         this test would be comparing nothing"
    );

    // ---- STATE 1: the store GENUINELY RELEASES (tags dropped, gc sweeps) ----
    provider.release_all().await.expect("release_all succeeds");
    let released = poll_until_released(&provider).await;
    assert_eq!(
        released,
        StoreResidency::default(),
        "after release_all + gc the store must hold nothing"
    );
    let hwm_released = vm_bytes("VmHWM");
    let rss_released = vm_bytes("VmRSS");

    // ---- STATE 2: the store RETAINS ----
    let nar2 = synth_raw_nar(&vec![0x5au8; PAYLOAD_BYTES]);
    provider.seed(&nar2).await.expect("re-seed succeeds");
    drop(nar2);
    let retained = provider
        .store_residency()
        .await
        .expect("store residency is queryable");
    assert_eq!(
        retained,
        StoreResidency {
            blobs: 1,
            bytes_uncompressed_nar: nar_len
        },
        "the re-seeded NAR must be resident again"
    );
    let hwm_retained = vm_bytes("VmHWM");

    // ---- THE DISCRIMINATION, run as an experiment on both oracles ----
    //
    // Ground truth: state 1 released, state 2 retained. Apply each candidate oracle
    // to each state and compare its verdict with the truth.
    let hwm_verdict_released = rss_hwm_says_released(hwm_released, hwm_baseline, nar_len);
    let hwm_verdict_retained = rss_hwm_says_released(hwm_retained, hwm_baseline, nar_len);
    assert_eq!(
        hwm_verdict_released, hwm_verdict_retained,
        "the peak-RSS oracle must give the SAME verdict for a released and a \
         retained store - if it ever separated them this whole file's premise \
         would be wrong"
    );
    assert!(
        !hwm_verdict_released,
        "the peak-RSS oracle says HELD after a genuine release - this is the WRONG \
         ANSWER that makes it unusable as a residency oracle (VmHWM {hwm_released} \
         vs baseline {hwm_baseline} + payload {nar_len})"
    );

    assert!(
        store_says_released(released),
        "the store-side oracle must say RELEASED for a released store"
    );
    assert!(
        !store_says_released(retained),
        "the store-side oracle must say HELD for a retained store"
    );

    // MEASURED, not assumed: what the allocator actually did with the freed payload,
    // and therefore whether a CURRENT-RSS oracle would have got state 1 right on
    // this host. Printed rather than asserted in either direction, because the
    // answer is a property of glibc's arena policy and not of our code - and this
    // project does not assert things about the wrong system.
    let rss_point_verdict = rss_hwm_says_released(rss_released, rss_baseline, nar_len);
    println!(
        "task-65 residency oracle, measured on this host:\n  \
         payload            = {nar_len} B\n  \
         VmHWM  baseline    = {hwm_baseline} B, seeded = {hwm_seeded} B, \
         released = {hwm_released} B, retained = {hwm_retained} B\n  \
         VmRSS  baseline    = {rss_baseline} B, seeded = {rss_seeded} B, \
         released = {rss_released} B\n  \
         allocator returned = {} B ({:.1}% of the payload) to the OS on release\n  \
         verdicts: peak-RSS oracle released={hwm_verdict_released} \
         retained={hwm_verdict_retained} (identical, and WRONG for the released \
         state); current-RSS oracle on the released state = {rss_point_verdict}; \
         store-side oracle released={} retained={} (correct in both)",
        rss_seeded as i64 - rss_released as i64,
        100.0 * (rss_seeded as f64 - rss_released as f64) / nar_len as f64,
        store_says_released(released),
        store_says_released(retained),
    );

    provider.shutdown().await.unwrap();
}
