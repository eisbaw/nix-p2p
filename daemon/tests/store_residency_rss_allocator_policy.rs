//! TASK-65: can CURRENT RSS be made to lie the way `VmHWM` provably does?
//!
//! Split out of `store_residency_oracle.rs` by TASK-109. It reads whole-process
//! `VmRSS`, so it must be the ONLY test in its process - see
//! `residency_support/mod.rs`. Do not add a second test to this file.

mod residency_support;

use std::time::Duration;

use daemon::{IrohProvider, StoreResidency, StoreRetention};
use residency_support::{
    poll_until_released, rss_hwm_says_released, store_says_released, synth_raw_nar, vm_bytes,
};

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
