//! `claim_wire_load` — a THIN, bounded load harness over the claim/hold-query wire
//! codec, the frozen wire format the PRIMARY libp2p discovery+serve path speaks
//! (`daemon_core::claim`, consumed by `daemon-libp2p`; NOT the deprioritized iroh path).
//!
//! ONE binary, three lenses (TASK-253):
//!   * `just bench` — hyperfine A/B wraps this binary (wall-clock, whole-process).
//!   * `just profile-cpu` — a CPU profiler (perf/cargo-flamegraph, valgrind fallback) samples
//!     this binary's release build.
//!   * `just profile-ram` — built with `--features dhat-heap`, this binary is its OWN allocation
//!     profiler (dhat), emitting an ALLOCATION profile (total/at-peak bytes+blocks) — the RAM
//!     oracle that is better than peak RSS, per the task. dhat writes `dhat-heap.json`.
//!
//! It is INSTRUMENTATION ONLY (TASK-253 AC#7): it produces no policy evidence, no PRD
//! success claim, and gates nothing. Every number it prints is an INTEGER by construction
//! (counts and byte totals) — no float in any emitted field (owner no-floats rule).
//!
//! Run cost is caller-BOUNDED: `--iters N` sets the exact roundtrip count, so the just
//! recipes pin small, documented values. There is no unbounded loop and no parallelism.

use std::process::ExitCode;

use daemon_core::{
    BitTorrentInfoHash, Blake3Digest, Claim, HoldQuery, KnownPayload, KnownTransport, NarHashKey,
    NodeId, QUERY_SCHEMA_VERSION, decode_claim, decode_hold_query, encode_claim, encode_hold_query,
};

// dhat is the global allocator ONLY under the opt-in profiling feature, so the ordinary
// release build (used by hyperfine + the CPU profiler) allocates through the system
// allocator and pays nothing for the instrumentation.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Which payload shape to exercise. Two REPRESENTATIVE points, not a sweep: a minimal
/// claim (the common discovery case) and a wide claim (many asserted holders), so the
/// A/B has a real, explainable contrast without approaching the 64 KiB wire cap.
#[derive(Clone, Copy)]
enum Payload {
    Small,
    Large,
}

/// Build a valid `Claim` of the requested shape. `Large` piles on distinct holder
/// identities (the field that legitimately grows a claim) but stays well under
/// `MAX_CLAIM_WIRE_BYTES`; the encoder's `check_size` would reject an over-cap value and
/// fail the harness loudly, which is the intended fail-fast.
fn build_claim(payload: Payload) -> Claim {
    // A deterministic, canonical NarHash key derived from fixed bytes (no fixture I/O).
    let key = NarHashKey::from_raw_nar(b"nix-p2p-task253-claim-wire-load-harness");
    let blake3 = Blake3Digest::from_bytes([0x5a; 32]);
    let holder_count = match payload {
        Payload::Small => 1,
        Payload::Large => 48,
    };
    let holders: Vec<NodeId> = (0..holder_count)
        .map(|i| NodeId::from_bytes([i as u8; 32]))
        .collect();
    Claim {
        schema_version: daemon_core::CLAIM_SCHEMA_VERSION,
        key,
        payload: Some(KnownPayload::WholeNar { blake3 }),
        holders,
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

fn build_query() -> HoldQuery {
    HoldQuery {
        schema_version: QUERY_SCHEMA_VERSION,
        key: NarHashKey::from_raw_nar(b"nix-p2p-task253-hold-query-load-harness"),
    }
}

fn parse_args() -> Result<(u64, Payload), String> {
    let mut iters: u64 = 100_000;
    let mut payload = Payload::Large;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--iters" => {
                let v = args.next().ok_or("--iters needs a value")?;
                iters = v.parse().map_err(|_| format!("bad --iters value: {v}"))?;
                if iters == 0 {
                    return Err("--iters must be positive".into());
                }
            }
            "--payload" => {
                let v = args.next().ok_or("--payload needs a value")?;
                payload = match v.as_str() {
                    "small" => Payload::Small,
                    "large" => Payload::Large,
                    other => return Err(format!("--payload must be small|large, got {other}")),
                };
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    Ok((iters, payload))
}

fn main() -> ExitCode {
    let (iters, payload) = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("claim_wire_load: {e}");
            eprintln!("usage: claim_wire_load [--iters N] [--payload small|large]");
            return ExitCode::from(2);
        }
    };

    // The dhat profiler must exist BEFORE the work allocates and be read/dropped AFTER,
    // so it observes the whole roundtrip loop and writes dhat-heap.json on drop.
    #[cfg(feature = "dhat-heap")]
    let profiler = dhat::Profiler::new_heap();

    let claim = build_claim(payload);
    let query = build_query();

    // xor-fold a byte of every output back into `acc` so the optimizer cannot elide the
    // encode/decode work as dead. `acc` is printed, making the whole loop observable.
    let mut acc: u8 = 0;
    let mut last_claim_wire = 0usize;
    let mut last_query_wire = 0usize;
    for _ in 0..iters {
        let claim_bytes = encode_claim(&claim).expect("encode_claim");
        last_claim_wire = claim_bytes.len();
        acc ^= claim_bytes.first().copied().unwrap_or(0);
        let decoded = decode_claim(&claim_bytes).expect("decode_claim");
        acc ^= decoded.holders.len() as u8;

        let query_bytes = encode_hold_query(&query).expect("encode_hold_query");
        last_query_wire = query_bytes.len();
        acc ^= query_bytes.first().copied().unwrap_or(0);
        let decoded_q = decode_hold_query(&query_bytes).expect("decode_hold_query");
        acc ^= decoded_q.schema_version as u8;
    }

    // Every field here is an integer by construction (owner no-floats rule): counts and
    // byte lengths. This is a terminal display line, not a gate.
    println!(
        "claim_wire_load iters={iters} claim_wire_bytes={last_claim_wire} \
         query_wire_bytes={last_query_wire} checksum={acc}"
    );

    #[cfg(feature = "dhat-heap")]
    {
        // dhat's HeapStats are all u64 — an ALLOCATION profile (total + at-peak), which is
        // the residency signal peak RSS cannot give: it counts what the codec actually
        // allocated, not the process high-water mark.
        let stats = dhat::HeapStats::get();
        println!(
            "dhat_alloc total_blocks={} total_bytes={} max_blocks={} max_bytes={} \
             curr_blocks={} curr_bytes={}",
            stats.total_blocks,
            stats.total_bytes,
            stats.max_blocks,
            stats.max_bytes,
            stats.curr_blocks,
            stats.curr_bytes,
        );
        // Explicit drop writes dhat-heap.json to the CWD before the process exits.
        drop(profiler);
    }

    ExitCode::SUCCESS
}
