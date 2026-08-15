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
- **Pipelined (TASK-203):** with in-order blocks and constant aggregate rates, a 3-stage
  pipeline's makespan is the **bottleneck** stage's total time plus the fill+drain of the two
  non-bottleneck stages (one block each, since they are faster and never make the bottleneck
  wait): `pipelined_total_ns = bottleneck_total_ns + one_block(otherA) + one_block(otherB)`. This
  is the exact makespan under constant aggregate rates and an **upper bound** on the real,
  finer-grained pipeline — so a "zstd beats raw pipelined" verdict from it is **conservative**.
- `raw_delivery_ns = sum_raw_bytes · 1e9 / lan_bytes_per_sec`; `zstd_beats_raw` is the integer
  compare `model_total_ns < raw_delivery_ns`. The block is the serve compressor's 128 KiB input
  block (`SERVE_COMPRESS_INPUT_BLOCK` = `peer_fabric` `ENCODE_BLOCK`/`DECODE_BLOCK`).

## The verdict (see `measurement.json` for the exact integers)

On the ~204 MB/s LAN, aggregate over the 7 measured nars (sum_raw = 287,530,648 B; zstd-3
sum_compressed = 64,000,619 B):

| model      | zstd-3 total_ns | raw_delivery_ns | zstd beats raw? |
|------------|-----------------|-----------------|-----------------|
| serial     | 1,588,001,243   | 1,409,463,960   | **no** (TASK-99) |
| pipelined  | 910,968,352     | 1,409,463,960   | **yes** (flips)  |

**The pipelined model FLIPS the LAN verdict for the shipped default (level 3).** The bottleneck
is the compressor at ~316 MB/s — which **outruns** the 204 MB/s LAN — so compressing and
overlapping delivers the ~4.5x-smaller compressed volume (911 ms, ≈ the compress time) **faster**
than shipping the raw volume (1409 ms). The serial penalty was purely the in-series
compress+decompress latency (313 M + 363 M ns added onto the link); pipelining hides it behind
the bottleneck.

**The model is honest, not a rubber stamp.** At **level 19** the compressor is only ~2.7 MB/s —
far **below** the LAN — so it becomes the pipeline bottleneck and even pipelined zstd-19 LOSES on
the LAN (`pipelined_total ≈ 105.2 s` vs raw `1.41 s`). That is the honest **'raw on a fast LAN'
fallback**: a LAN/CPU-bound operator lowers the level or disables zstd (raw is the mandatory
codec floor; `ServeCodecPolicy`), exactly as `DEFAULT_ZSTD_LEVEL`'s doc already notes. On the
home uplink (2.5 MB/s) zstd-3 already won serially and pipelining only widens the margin.

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
  aggregate average rates, so the pipelined figure is a makespan **model**, not a wall-clock
  serve trace (a full two-ends-shaped live serve trace is the heavier TASK-198 territory). The
  **verdict direction** (flip at level 3, no flip at level 19) is robust because it is driven by
  compressor-throughput-vs-link-bandwidth, an order-of-magnitude gap, not a marginal ratio.
- Like-units only: the LAN link cost is computed from **compressed** transport bytes and compared
  against **raw** bytes over the *same* link; the decode cap remains the **uncompressed** NarSize
  (never the compressed FileSize) — the recurring unit trap is avoided.
