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

use std::time::{Duration, Instant};

use daemon::{IrohProvider, StoreResidency, StoreRetention};

/// The payload size. Large enough that the resident cost of the content dominates
/// the ~17 MiB process baseline by an order of magnitude, so "the payload really
/// became resident" is an assertion and not a hope; small enough that a parallel
/// `cargo test` run does not turn into a memory experiment of its own.
const PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

/// How long to wait for a gc-enabled store to sweep. Generous relative to the 50 ms
/// gc interval: this bounds a HANG, it is not a timing assertion.
const RELEASE_DEADLINE: Duration = Duration::from_secs(20);

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
/// peak of up to twice the payload inside VmHWM, and this file's whole subject is
/// what VmHWM does and does not mean.
fn synth_raw_nar(contents: &[u8]) -> Vec<u8> {
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

// ---- the RSS oracle this file exists to discredit ----------------------------

/// One `VmXxx: N kB` field of this process, in BYTES.
///
/// Panics rather than returning 0 on a missing field: this is the instrument the
/// test is comparing AGAINST, and an instrument that silently reads 0 would make
/// the comparison come out in the store oracle's favour for the wrong reason.
fn vm_bytes(key: &str) -> u64 {
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
/// making the RSS oracle as strong as it can be is what makes its failure below a
/// property of the instrument rather than of a badly chosen constant.
fn rss_hwm_says_released(hwm_bytes: u64, baseline_bytes: u64, payload_bytes: u64) -> bool {
    hwm_bytes < baseline_bytes + payload_bytes / 2
}

/// The oracle this file argues for: ask the store.
fn store_says_released(residency: StoreResidency) -> bool {
    residency.bytes_uncompressed_nar == 0
}

async fn poll_until_released(provider: &IrohProvider) -> StoreResidency {
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

#[tokio::test(flavor = "multi_thread")]
async fn residency_oracle_discriminates_release_from_allocator_retention() {
    let provider = IrohProvider::spawn_with_retention(StoreRetention::ReleaseOnRequest {
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

    provider.shutdown().await;
}

/// Chunk size for the constructed "allocator retains" case. 64 KiB is BELOW glibc's
/// 128 KiB default `M_MMAP_THRESHOLD`, so these allocations are served from the
/// arena rather than by `mmap` - and an arena is exactly what glibc does not have to
/// hand back to the OS on `free`.
const RETAINED_CHUNK_BYTES: usize = 64 * 1024;
/// 512 x 64 KiB = the same 32 MiB payload, differently shaped.
const RETAINED_CHUNKS: usize = 512;

#[tokio::test(flavor = "multi_thread")]
async fn current_rss_after_release_is_an_allocator_policy_not_an_oracle() {
    // The first test proved the store-side oracle beats VmHWM, which retains the
    // payload in its reading FOREVER because it is monotone - the guaranteed form
    // of "the allocator kept it". This test asks the harder question: can CURRENT
    // RSS be made to lie the same way, by shaping the same 32 MiB payload as many
    // sub-mmap-threshold allocations so glibc serves them from an arena?
    //
    // MEASURED ANSWER ON THIS HOST: no. glibc returned ~97% either way (see the
    // printout). Recorded as a measured NEGATIVE rather than deleted, because the
    // fact that current RSS tracked the release here is exactly the kind of
    // host-specific accident a later reader would otherwise generalise into "VmRSS
    // is a fine residency oracle". It is not: nothing in glibc promises it, and the
    // reading that this project actually fits - VmHWM - provably never tracks it.
    let provider = IrohProvider::spawn_with_retention(StoreRetention::ReleaseOnRequest {
        sweep_interval: Duration::from_millis(50),
    })
    .await
    .expect("provider spawns");

    let rss_baseline = vm_bytes("VmRSS");
    let hwm_baseline = vm_bytes("VmHWM");

    let mut seeded_bytes = 0u64;
    // ATTEMPTED and MEASURED NOT TO WORK - kept so nobody spends an afternoon
    // re-trying it. The idea was to block glibc from coalescing the freed 64 KiB
    // chunks into one trimmable top-of-heap block by interleaving live 64-byte
    // pins. It changes nothing (~97% still returned) because the blob store's
    // allocations are made on the MemStore actor's own thread, hence in a different
    // malloc arena from this thread's pins. Fragmenting the store's arena from the
    // outside is not possible through the public API.
    let mut pins: Vec<Vec<u8>> = Vec::with_capacity(RETAINED_CHUNKS);
    for chunk in 0..RETAINED_CHUNKS {
        let mut contents = vec![0u8; RETAINED_CHUNK_BYTES];
        // Distinct bytes per chunk, or the store deduplicates by content hash and
        // 512 identical blobs become one - a 64 KiB "32 MiB" payload.
        contents[..8].copy_from_slice(&(chunk as u64).to_le_bytes());
        let nar = synth_raw_nar(&contents);
        seeded_bytes += nar.len() as u64;
        provider.seed(&nar).await.expect("seed succeeds");
        pins.push(vec![chunk as u8; 64]);
    }

    let seeded = provider
        .store_residency()
        .await
        .expect("store residency is queryable");
    assert_eq!(
        seeded,
        StoreResidency {
            blobs: RETAINED_CHUNKS as u64,
            bytes_uncompressed_nar: seeded_bytes
        },
        "the store must report every seeded chunk"
    );
    let rss_seeded = vm_bytes("VmRSS");

    provider.release_all().await.expect("release_all succeeds");
    let released = poll_until_released(&provider).await;
    assert_eq!(
        released,
        StoreResidency::default(),
        "after release_all + gc the store must hold nothing"
    );
    let rss_released = vm_bytes("VmRSS");
    let hwm_released = vm_bytes("VmHWM");

    let returned = rss_seeded as i64 - rss_released as i64;
    // What is STILL RESIDENT above the pre-payload baseline after a genuine release.
    // Above the baseline, not the raw RSS: the ~36 MiB process floor is not payload
    // the allocator retained, and counting it as such would fake the case.
    let retained_by_allocator = rss_released.saturating_sub(rss_baseline);
    let hwm_verdict = rss_hwm_says_released(hwm_released, hwm_baseline, seeded_bytes);
    let rss_verdict = rss_hwm_says_released(rss_released, rss_baseline, seeded_bytes);

    println!(
        "task-65 current-RSS-vs-release measurement:\n  \
         payload            = {seeded_bytes} B in {RETAINED_CHUNKS} x \
         {RETAINED_CHUNK_BYTES} B chunks (below glibc's mmap threshold)\n  \
         VmRSS  baseline    = {rss_baseline} B, seeded = {rss_seeded} B, \
         released = {rss_released} B\n  \
         allocator returned = {returned} B ({:.1}% of the payload); still resident \
         after a genuine release = {retained_by_allocator} B\n  \
         verdicts: peak-RSS oracle says released={hwm_verdict}; current-RSS oracle \
         says released={rss_verdict}; store-side oracle says released={} (ground \
         truth: RELEASED)",
        100.0 * returned as f64 / seeded_bytes as f64,
        store_says_released(released),
    );

    // GUARANTEED half: VmHWM is monotone, so it reports HELD after a real release.
    assert!(
        !hwm_verdict,
        "the peak-RSS oracle must (wrongly) say HELD after a genuine release"
    );
    // The store-side oracle gets it right regardless of what the allocator chose.
    assert!(
        store_says_released(released),
        "the store-side oracle must say RELEASED - its answer does not depend on \
         allocator policy, which is the entire reason it was chosen"
    );
    // The HOST-DEPENDENT half is REPORTED, never asserted in either direction. An
    // assertion here would be an assertion about glibc's arena policy, which is not
    // this project's system; and a test that demanded VmRSS lie would start failing
    // the day a libc got better at trimming, for no defect of ours.
    if returned < (seeded_bytes as i64) / 2 {
        println!(
            "  NOTE: the allocator retained {retained_by_allocator} B after a \
             genuine release, so a current-RSS oracle is WRONG here too."
        );
    } else {
        println!(
            "  NOTE: glibc returned most of the arena on this host, so a \
             current-RSS oracle happens to be right here. That is an allocator \
             policy and not a guarantee, which is why the oracle in use is neither \
             RSS reading."
        );
    }

    // Keep the pins alive to the very end: dropping them earlier would let the
    // arena coalesce and dissolve the case this test constructs.
    assert_eq!(pins.len(), RETAINED_CHUNKS);
    drop(pins);
    provider.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn residency_oracle_reads_the_store_not_the_release_request() {
    // THE OTHER DIRECTION of the mutation. On a RetainAll store - the daemon's own
    // configuration - dropping the tags releases nothing, because nothing sweeps.
    // If `store_residency` were reporting our INTENT rather than the store's state,
    // it would answer 0 here too, and the first test would have proven nothing.
    let nar = synth_raw_nar(&vec![0x33u8; PAYLOAD_BYTES]);
    let nar_len = nar.len() as u64;

    let provider = IrohProvider::spawn_with_retention(StoreRetention::RetainAll)
        .await
        .expect("provider spawns");
    provider.seed(&nar).await.expect("seed succeeds");
    drop(nar);

    provider.release_all().await.expect("release_all succeeds");
    // Long enough that a gc-enabled store would have swept several times over.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let still_held = provider
        .store_residency()
        .await
        .expect("store residency is queryable");
    assert_eq!(
        still_held,
        StoreResidency {
            blobs: 1,
            bytes_uncompressed_nar: nar_len
        },
        "RetainAll must still hold the blob after release_all - the oracle reports \
         what the STORE holds, not what the caller asked for"
    );

    provider.shutdown().await;
}
