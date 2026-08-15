---
id: TASK-216
title: >-
  PROFILE (low pri): sweep the pipelined-serve flush/block size + channel depth
  — pick from evidence, don't inherit DECODE_BLOCK
status: To Do
assignee: []
created_date: '2026-08-15 08:13'
labels:
  - profile
  - measurement
  - compression
  - libp2p
  - transport
  - low-pri
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner ask (2026-08-15): the TASK-203 pipelined streaming zstd serve uses ENCODE_BLOCK = 128 KiB, but that value was INHERITED for symmetry from the decoder's DECODE_BLOCK, not chosen by measurement. DECODE_BLOCK = 128 KiB IS principled (it is zstd's format-level max uncompressed block, the "one decode block" term in the decoder memory bound, peer-fabric/src/codec.rs:390) and should STAY. But the ENCODE/pipelining flush granularity is a FREE parameter decoupled from the decoder bound, and nothing profiled it.

Sweep + profile the pipelining parameters and pick them from evidence:
- ENCODE_BLOCK / flush granularity: sweep e.g. 16, 32, 64, 128, 256, 512 KiB, 1 MiB (decoupled from DECODE_BLOCK).
- The bounded channel depth (currently cap 2) and, complementarily, adaptive zstd level / disable-on-fast-link.

Profile each config on these axes (the ones that actually depend on the flush size):
1. TIME-TO-FIRST-BYTE (smaller block ships sooner; the pipelining win).
2. End-to-end serve wall-clock over SHAPED links (reuse scripts/shaped_* + the measurement instrument) at representative rates (home uplink, LAN ~204 MB/s, WAN/RTT) — this is the honest streamed number TASK-203 F1 said the makespan model does NOT charge (per-block calls, allocs, channel sync, scheduling).
3. Serve-side CPU overhead vs bulk (the uncharged streaming overhead) — measure it, don't assume TASK-99 bulk CPU.
4. PREEMPTION granularity: how promptly a serve deadline bounds the serve (smaller block = tighter bound; the TASK-203 F2 one-block-tail concern, worse at high levels).
5. PEAK MEMORY (writer-current + queue-depth + sender-current + encoder scratch — the TASK-203 F4 real bound).
6. COMPRESSION RATIO delta vs bulk (should be ~0 since it is ONE continuous frame regardless of flush size — VERIFY, don't assume; the window/history spans blocks).

Deliverable: a recommended flush size (+ channel depth) with the evidence table, integers/rationals only (no floats in any gate/decision/serialized field; check-no-floats), like-units (compressed transport bytes vs raw bytes; do not mix uncompressed NarSize with compressed wire bytes). If the sweep shows 128 KiB is already near-optimal, that is a fine outcome — but proven, not inherited.

Relates to: TASK-203 (the pipelined serve this tunes; its F1 asked for the real streamed overhead), TASK-198 (live two-ends-shaped trace), TASK-99 (the codec + measurement harness).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The pipelining flush/block size is DECOUPLED from the decoder memory-bound DECODE_BLOCK (128 KiB stays as the zstd-block decode bound); the encoder flush granularity + channel depth are swept across a defined range
- [ ] #2 Each config profiled on: time-to-first-byte, end-to-end serve wall-clock over shaped links, streamed serve-side CPU overhead vs bulk (measured, not assumed), preemption granularity, peak memory, and compression-ratio delta vs bulk (verified ~0) — integers/rationals only, like-units
- [ ] #3 A recommended flush size + channel depth is chosen FROM the evidence table (128 KiB is an acceptable outcome only if the sweep proves it near-optimal, not by inheritance)
<!-- AC:END -->
