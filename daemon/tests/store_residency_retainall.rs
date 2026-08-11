//! TASK-65: the mutation in the OTHER direction - on a `RetainAll` store,
//! `release_all()` must release NOTHING.
//!
//! Split out of `store_residency_oracle.rs` by TASK-109. This test measures no RSS
//! itself, but it SEEDS a 32 MiB payload, which is more than enough to corrupt a
//! sibling's baseline. That is why it gets its own target rather than being folded
//! back in with the tests that do measure.

mod residency_support;

use std::time::Duration;

use daemon::{IrohProviderNode, StoreResidency, StoreRetention};
use residency_support::{PAYLOAD_BYTES, synth_raw_nar};

#[tokio::test(flavor = "multi_thread")]
async fn residency_oracle_reads_the_store_not_the_release_request() {
    // THE OTHER DIRECTION of the mutation. On a RetainAll store - the daemon's own
    // configuration - dropping the tags releases nothing, because nothing sweeps.
    // If `store_residency` were reporting our INTENT rather than the store's state,
    // it would answer 0 here too, and the first test would have proven nothing.
    let nar = synth_raw_nar(&vec![0x33u8; PAYLOAD_BYTES]);
    let nar_len = nar.len() as u64;

    let provider = IrohProviderNode::spawn_with_retention(StoreRetention::RetainAll)
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

    provider.shutdown().await.unwrap();
}
