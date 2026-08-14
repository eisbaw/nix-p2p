# TASK-99 evidence: peer-link zstd compression, measured on real nar data

Generated at HEAD `6ac459a` (working tree carrying the TASK-99 change). Integer-exact; no
float enters any decision (ratios are exact `(compressed, raw)` pairs compared by
cross-multiplication, durations are integer ns, bandwidths integer bytes/sec — the TASK-94
finalizer discipline).

## What is here

- `harness_raw.json` — raw output of `peer-fabric/examples/measure_link_compression.rs`: for
  each real nar and each zstd level, the exact `compressed_bytes/raw_bytes` and integer
  compress/decompress nanoseconds. Uses the SHIPPED codec (`peer_fabric::compress_zstd` +
  `BoundedZstdDecoder`), so the numbers are the wire codec's, not a stand-in's.
- `cdn_narinfo.txt` — the CDN's own xz `FileSize`/`NarSize` for the SAME store paths
  (`cache.nixos.org/<hash>.narinfo`), for the rigorous same-path comparison.
- `measurement.json` — the derived, integer-exact verdict from
  `scripts/task99_link_compression_measure.py` (break-even vs the committed TASK-94 baseline,
  net-throughput model, and the same-path xz-vs-zstd honest verdict).

## Reproduce

```
# dump the 5 CDN-backed paths (re-realise from cache.nixos.org first if absent), then run:
cargo run --release -p peer-fabric --example measure_link_compression -- <nar files> > harness_raw.json
python3 scripts/task99_link_compression_measure.py --raw harness_raw.json \
        --cdn-narinfo cdn_narinfo.txt --out measurement.json
```

The 7 measured store paths span 7.8 KB → 178 MB (a ~5-orders-of-magnitude spread, matching
TASK-94's). Five are on `cache.nixos.org` with an xz `FileSize`, giving an apples-to-apples
per-path comparison across 5 sizes (804 KB → 178 MB); the two smallest are local-only.
Measured `raw_bytes` equals the CDN `NarSize` exactly for every joined path — confirming the
dumped nars are the canonical ones.

## The honest verdict (see `measurement.json` for the exact pairs)

1. **Compression is essential and hugely effective.** A peer serving the RAW nar moves
   ~1/xz-ratio the CDN's wire bytes (~3.07x on TASK-94's set; ~6x on these more-compressible
   paths). zstd cuts the peer's wire volume ~4.5x (raw → zstd-3), collapsing that deficit to
   near-parity. This is THE break-even lever.

2. **zstd does NOT reach xz's ratio on nar data** (measure, do not assume — the task's own
   caution). On the SAME 5 paths: xz aggregate `0.1616`, zstd-19 `0.1681`, zstd-3 `0.2226`.
   Even zstd-19 does not beat xz; zstd-3 is ~38% heavier. So a zstd peer stays slightly
   wire-heavier than the CDN — but now within ~4-38% instead of ~300-600%. (The naive
   compare of these nars' zstd ratio against TASK-94's DIFFERENT 220-path 0.3256 aggregate
   would falsely read as "zstd beats xz" — it is an artifact of different nar sets, called
   out here so the verdict is not over-read.)

3. **The level trades ratio against CPU — PRD risk 11, confirmed.** zstd-19 reaches near-xz
   ratio but compresses at only ~2.9 MB/s (single-thread) — SLOWER than a home uplink — so,
   because this backend compresses the whole nar before sending, level 19 net-LOSES
   end-to-end even at 2.5 MB/s (the compressor is the bottleneck). zstd-3 compresses at ~340
   MB/s and, on a 2.5 MB/s home uplink, delivers ~4.3x the effective throughput of the raw
   path. So the shipped default is **level 3** (throughput-safe for the target home-uplink
   regime), never 19.

4. **On a LAN (transport already CPU-bound ~204 MB/s), even zstd-3 marginally loses** under
   this serial (non-pipelined) whole-nar-compress model (~190 vs 204 MB/s). A LAN/CPU-bound
   operator should lower the level or disable zstd (raw is always available). Pipelined
   streaming compression would remove this serial penalty — a follow-up.

## AC#4 (thin, per the brief; TASK-198 owns the full re-statement)

TASK-94's peer-wins inequality required the peer to sustain >64.5 MiB/s to break even against
the RAW-nar deficit. With the link compressed at zstd-3 the peer moves ~0.223x the raw bytes
(these paths) — a ~4.5x lower volume — so the break-even upload rate drops by that factor. It
does NOT reach xz parity, so the peer is not unconditionally lighter than the CDN; the
residual ~1.04-1.38x gap must be covered by the peer's other advantages (proximity, no CDN
egress, parallel holders). The full shaped-link speedup re-statement with BOTH ends shaped is
**TASK-198** (depends on TASK-99); the README speedup figures, taken against an uncompressed
fixture, are superseded and should be re-measured there, not trusted as-is.
