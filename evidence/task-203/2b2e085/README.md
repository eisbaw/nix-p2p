# TASK-203 evidence: the LAN serial penalty re-evaluated with pipelining ON

TASK-99 measured the shipped `/nar/3` zstd codec on real nar data and found that on a fast LAN
(~204 MB/s) even zstd-3 marginally **lost** to raw, because the whole nar was compressed, then
sent, then decompressed — three costs **in series** (`net_lan.zstd_beats_raw_end_to_end=false`,
`evidence/task-99/468ffbd`). TASK-203 makes the serve-side compressor **pipelined**: it streams
the zstd frame in blocks off the worker, so compress/link/decompress **overlap**. This artifact
re-evaluates that net-LAN verdict under the pipelined model, integer-exact, no float in any
decision (per the project no-floats rule + `scripts/check-no-floats.py`).

## Why this is a re-derivation, not a re-measurement

Pipelining changed the **scheduling** of the serve-side compressor, **not the codec's bytes or
its CPU cost**. A streamed frame is the **same single zstd frame** as the bulk frame — the codec
tests `streamed_frame_decodes_like_bulk` (identical decode → same blob id) and
`streamed_frame_size_matches_bulk_within_tolerance` (streamed size within ~1/64 of bulk) prove
it — and the compress/decompress CPU-ns are the same work regardless of *when* it runs. So the
honest re-evaluation **reuses TASK-99's committed integer-exact harness measurement**
(`evidence/task-99/468ffbd/harness_raw.json`: per-file `compressed_bytes`, `raw_bytes`,
`compress_ns`, `decompress_ns`) and applies the pipelined makespan model to the same numbers. No
fresh shaped-link run is needed — the same measured costs, scheduled differently.

The finalizer **fails closed**: `--task99` ties the SERIAL re-derivation to the committed
`measurement.json` and rejects any mismatch (so the two artifacts cannot drift), and it rejects
non-integer / non-positive fields. `--self-test` proves the guards bite AND that the pipelined
model has **teeth** (a bottleneck-slow compressor still LOSES — it is not a rubber stamp).

## The two models (integers only; compared like-units: compressed transport bytes vs raw bytes over the same link)

- **Serial (TASK-99):** `serial_total_ns = compress_ns + link_ns + decompress_ns`. Reproduces
  TASK-99's `net_lan.zstd_total_ns` **byte-for-byte** (the tie the finalizer asserts).
- **Pipelined (TASK-203), an IDEALIZED / BEST-CASE estimate — NOT a proven bound:** under
  **constant aggregate per-stage rates** and in-order blocks, a 3-stage pipeline's makespan is the
  **bottleneck** stage's total time plus the fill+drain of the two non-bottleneck stages (one block
  each, since at their aggregate rate they never make the bottleneck wait):
  `pipelined_total_ns = bottleneck_total_ns + one_block(otherA) + one_block(otherB)`. This holds
  **exactly only under those assumptions**. It is explicitly **not an upper bound** on the real
  pipeline, for two honest reasons:
  1. **Per-block rate variation can beat it.** Aggregate constant rates do not bound a pipeline
     whose per-block rates vary — a stage that is slow on an *early* block stalls the whole line
     even if its aggregate rate is fast. Counterexample (3 blocks, per-block service times)
     `compress[5,5] / link[8,1] / decode[1,8]`: this model predicts **19**, the real in-order
     schedule takes **22**. The real pipeline can be *slower* than the estimate, not only faster.
  2. **Streaming/channel/allocation overhead is not charged.** The model reuses TASK-99's **bulk**
     single-call compress/decompress CPU-ns. The TASK-203 serve path is different code (raw-stream
     `compress_block` calls, a per-block output allocation, an mpsc channel + a `spawn_blocking`
     hop). So the bulk CPU is a **lower bound** on the streamed path's CPU, not an equality — see
     the **measured cross-check** below.
- `raw_delivery_ns = sum_raw_bytes · 1e9 / lan_bytes_per_sec`; `zstd_beats_raw` is the integer
  compare `model_total_ns < raw_delivery_ns`. The block is the serve compressor's 128 KiB input
  block (`SERVE_COMPRESS_INPUT_BLOCK` = `peer_fabric` `ENCODE_BLOCK`/`DECODE_BLOCK`).

## The estimate (see `measurement.json` for the exact integers)

On the ~204 MB/s LAN, aggregate over the 7 measured nars (sum_raw = 287,530,648 B; zstd-3
sum_compressed = 64,000,619 B):

| model                 | zstd-3 total_ns | raw_delivery_ns | zstd beats raw? |
|-----------------------|-----------------|-----------------|-----------------|
| serial (TASK-99)      | 1,588,001,243   | 1,409,463,960   | **no**          |
| pipelined (idealized) | 910,968,352     | 1,409,463,960   | **yes** (flips) |

**Under the idealized best-case model the LAN verdict FLIPS for the shipped default (level 3)** —
a *conditional* estimate, not a proven result. The bottleneck is the compressor, whose *aggregate*
rate ~316 MB/s **outruns** the 204 MB/s LAN, so compressing-and-overlapping the ~4.5x-smaller
compressed volume delivers it in ≈ the compress time (911 ms) rather than shipping the raw volume
(1409 ms). The serial penalty was the in-series compress (911 M ns) + decompress (364 M ns) added
onto the 314 M ns link; pipelining hides them behind the bottleneck **if** per-block rates stay
near their aggregate and the unmodeled streaming overhead stays under the margin below.

### Sensitivity — how robust is the flip? (integer-exact)

The flip's margin is `raw_delivery_ns − pipelined_total_ns = 498,495,608 ns` against a compress
budget of `910,659,589 ns`. So per-block streaming/channel/allocation overhead would have to add

> **498,495,608 / 910,659,589 ≈ 0.5474 (≈ 54.7% of the compress budget)**

before the idealized flip is erased (`overhead_to_erase_flip` in `measurement.json`,
`headline_net_lan_level3`). The flip survives only while the real unmodeled overhead stays under
that ~55% margin.

### Measured cross-check of the "bulk CPU ≈ streamed CPU" assumption

The model reuses TASK-99's **bulk** compress CPU for the **streamed** path. To check that
assumption directly (rather than assert it), the ignored codec test
`measure_streamed_vs_bulk_compress_cpu` times `StreamingZstdEncoder` (fed in 128 KiB blocks) vs
`compress_zstd` on the **same** 32 MiB level-3 buffer:

```
cargo test -p peer-fabric measure_streamed_vs_bulk_compress_cpu -- --ignored --nocapture
# measured on this box: streamed compress ≈ +2–4% over bulk (~20,000–37,000 ppm, run-to-run)
```

So the streamed encoder's per-block CPU is **a few percent** above bulk — far under the ~55%
sensitivity margin. This is a single-box wall-clock measurement with run-to-run variance, and it
does **not** cover the fabric-libp2p mpsc/`spawn_blocking` hop; that adds one sub-µs channel send
per 128 KiB block (≈ 1,400 sends for the largest nar), analytically negligible against a ~910 ms
compress. The *original TASK-99 corpus was a transient scratchpad and is gone*, so this is a
representative buffer, not a re-run of the exact 7 nars — it verifies the CPU-delta of the code
paths, which is the assumption under question.

### The estimate is honest, not a rubber stamp

At **level 19** the compressor is only ~2.7 MB/s — far **below** the LAN — so it becomes the
pipeline bottleneck and even pipelined zstd-19 LOSES on the LAN (`pipelined_total ≈ 105.2 s` vs
raw `1.41 s`). That is the honest **'raw on a fast LAN' fallback**: a LAN/CPU-bound operator lowers
the level or disables zstd (raw is the mandatory codec floor; `ServeCodecPolicy`), exactly as
`DEFAULT_ZSTD_LEVEL`'s doc already notes. On the home uplink (2.5 MB/s) zstd-3 already won serially
and pipelining only widens the margin.

## Reproduce (and re-derive)

```
python3 scripts/task203_pipelined_measure.py \
    --raw      evidence/task-99/468ffbd/harness_raw.json \
    --task99   evidence/task-99/468ffbd/measurement.json \
    --out      evidence/task-203/2b2e085/measurement.json
python3 scripts/task203_pipelined_measure.py --self-test   # the fail-closed + teeth mutations
```

Re-running on the committed TASK-99 harness reproduces `measurement.json` byte-for-byte; the
`--task99` tie fails closed if either artifact drifts. `2b2e085` is the commit the code landed
under (the numbers depend only on the committed TASK-99 measurement, not on this checkout).

## Scope / honesty

- The compress/decompress ns are TASK-99's single-thread wall-ns proxy on one box; the model uses
  aggregate average rates, so the pipelined figure is an **idealized makespan estimate**, not a
  wall-clock serve trace (a full two-ends-shaped live serve trace is the heavier TASK-198
  territory, not required here so long as the estimate is stated conditionally — which it is). The
  level-3 flip is **conditional**: it holds under constant aggregate rates and while the unmodeled
  streaming overhead stays under the ~55% sensitivity margin above; per-block rate variation can
  make the real pipeline slower than the estimate (see the counterexample). It is **not** a proven
  bound. The level-19 no-flip is on firmer ground — the compressor is ~75x slower than the LAN, so
  no plausible scheduling makes zstd-19 competitive there.
- Like-units only: the LAN link cost is computed from **compressed** transport bytes and compared
  against **raw** bytes over the *same* link; the decode cap remains the **uncompressed** NarSize
  (never the compressed FileSize) — the recurring unit trap is avoided.
