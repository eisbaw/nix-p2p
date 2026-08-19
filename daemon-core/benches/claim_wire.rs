//! Criterion microbench for the claim/hold-query wire codec — the frozen wire format the
//! PRIMARY libp2p discovery+serve path speaks (`daemon_core::claim`, consumed by
//! `daemon-libp2p`; NOT the deprioritized iroh path). TASK-253 AC#3.
//!
//! This is INSTRUMENTATION ONLY (AC#7): it reports per-operation time estimates for
//! `encode_claim`/`decode_claim`/`encode_hold_query`/`decode_hold_query` so a later change
//! ("did this make the codec slower?") can be re-derived on the primary stack. It gates
//! nothing and asserts no threshold — a throughput threshold on a shared host would be a
//! flake, not an oracle.
//!
//! RUN COST IS BOUNDED AND DOCUMENTED (AC#6): the custom `bounded()` configuration below
//! caps sample size and measurement/warm-up time deliberately small. The box is SHARED;
//! this must never become a CPU-hog farm. Criterion's own timing estimates are floats —
//! that is the tool's terminal statistical output, not a gate/decision field of ours, so
//! the owner no-floats rule (which governs OUR emitted gate fields) is not engaged here.

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use daemon_core::{
    BitTorrentInfoHash, Blake3Digest, CLAIM_SCHEMA_VERSION, Claim, HoldQuery, KnownPayload,
    KnownTransport, NarHashKey, NodeId, QUERY_SCHEMA_VERSION, decode_claim, decode_hold_query,
    encode_claim, encode_hold_query,
};

/// BOUNDED criterion profile (AC#6): small sample size + short measurement + short warm-up,
/// so the whole `just bench` criterion pass is seconds, not minutes, on a shared host.
fn bounded() -> Criterion {
    Criterion::default()
        .sample_size(20) // criterion's floor is 10; 20 keeps a usable estimate, still small.
        .measurement_time(Duration::from_secs(2))
        .warm_up_time(Duration::from_millis(500))
        .without_plots()
}

fn wide_claim() -> Claim {
    Claim {
        schema_version: CLAIM_SCHEMA_VERSION,
        key: NarHashKey::from_raw_nar(b"nix-p2p-task253-claim-wire-bench"),
        payload: Some(KnownPayload::WholeNar {
            blake3: Blake3Digest::from_bytes([0x5a; 32]),
        }),
        holders: (0..48).map(|i| NodeId::from_bytes([i as u8; 32])).collect(),
        transports: vec![
            KnownTransport::Iroh {
                node: NodeId::from_bytes([0xa1; 32]),
            },
            KnownTransport::BitTorrent {
                infohash: BitTorrentInfoHash::v2([0xb2; 32]),
            },
        ],
        relay: None,
        signatures: vec![],
    }
}

fn claim_codec(c: &mut Criterion) {
    let claim = wide_claim();
    let encoded = encode_claim(&claim).expect("encode");

    c.bench_function("claim_encode", |b| {
        b.iter(|| encode_claim(std::hint::black_box(&claim)).expect("encode"))
    });
    c.bench_function("claim_decode", |b| {
        b.iter(|| decode_claim(std::hint::black_box(&encoded)).expect("decode"))
    });
    c.bench_function("claim_roundtrip", |b| {
        b.iter(|| {
            let bytes = encode_claim(std::hint::black_box(&claim)).expect("encode");
            decode_claim(&bytes).expect("decode")
        })
    });
}

fn hold_query_codec(c: &mut Criterion) {
    let query = HoldQuery {
        schema_version: QUERY_SCHEMA_VERSION,
        key: NarHashKey::from_raw_nar(b"nix-p2p-task253-hold-query-bench"),
    };
    let encoded = encode_hold_query(&query).expect("encode");

    c.bench_function("hold_query_roundtrip", |b| {
        b.iter(|| {
            let bytes = encode_hold_query(std::hint::black_box(&query)).expect("encode");
            decode_hold_query(&bytes).expect("decode")
        })
    });
    c.bench_function("hold_query_decode", |b| {
        b.iter(|| decode_hold_query(std::hint::black_box(&encoded)).expect("decode"))
    });
}

criterion_group! {
    name = benches;
    config = bounded();
    targets = claim_codec, hold_query_codec
}
criterion_main!(benches);
