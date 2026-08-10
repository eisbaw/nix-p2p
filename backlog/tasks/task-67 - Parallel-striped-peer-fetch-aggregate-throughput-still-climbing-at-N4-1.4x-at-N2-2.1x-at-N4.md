---
id: TASK-67
title: >-
  Parallel/striped peer fetch: aggregate throughput still climbing at N=4 (1.4x
  at N=2, 2.1x at N=4)
status: To Do
assignee: []
created_date: '2026-08-09 14:00'
updated_date: '2026-08-10 09:30'
labels:
  - performance
  - transport
dependencies:
  - TASK-99
  - TASK-63
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
MEASURED HEADROOM, not a hunch (task-64, daemon/examples/iroh_throughput.rs, 110 MiB loopback, medians): one iroh-blobs connection moves 255 MB/s; FOUR concurrent connections to the same provider move 649 MB/s aggregate (2.54x) at 7.81 CPU cores vs 2.95. So the single-fetch ceiling is a PER-CONNECTION wakeup/pacing limit, not a machine-wide one, and it is the only large lever task-64 found that is ours to pull - 73% of the single-connection per-byte cost sits below our code and is inherent to QUIC-over-UDP datagram rate. Shape: iroh-blobs supports RANGE requests, so one NAR can be striped over N connections (to one peer, or better, to N DIFFERENT peers - which is also the p2p-native answer and doubles as resilience). Open design questions this task must settle before implementing: (1) does striping to ONE peer keep the 2.54x, or was the measured gain partly the provider serving one hot MemStore blob to four readers; (2) what N, and is it adaptive; (3) how the streaming NarSize cap and the BLAKE3/bao gate compose across stripes - bao verifies a contiguous range, so per-stripe verification must still add up to gate-1 over the whole NAR, and getting that wrong turns an integrity gate vacuous; (4) CPU cost is real (3x cores for 2.5x bytes) so this is a latency-for-CPU trade, and on any link at or below ~2 Gb/s it buys NOTHING because the single connection already exceeds the link. PREREQUISITE: do NOT start this before TASK-63 (WAN-shaped upstream arm) has established whether the peer path is ever the binding constraint on a realistic link. It very likely is not, in which case this task should be CLOSED as not-worth-it rather than implemented.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The 2.54x is re-measured against a striped fetch of ONE NAR (not N whole-NAR fetches), to N peers and to 1 peer separately, so the gain is attributed to striping rather than to provider-side cache warmth
- [ ] #2 Gate-1 (BLAKE3/bao) is proven to hold over the REASSEMBLED NAR with a mutation bite: a single corrupted stripe must fail the fetch, and the bite must show red-then-green with numbers
- [ ] #3 The streaming NarSize cap still bounds TOTAL memory across all stripes, proven by a hostile-holder test
- [ ] #4 A decision is recorded: implement, or close as not-worth-it because the link is the binding constraint (task-63's number decides)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## WIRE-COST CORRECTION 2026-08-10: every peer-vs-cache number in this task is invalid until TASK-99 lands

MEASURED on 20 signed paths >10 MiB from the live cache.nixos.org: FileSize/NarSize = 0.278 aggregate
(median 0.216). cache.nixos.org serves xz; our peers serve RAW nar (daemon/src/rewrite.rs rewrites
Compression:none with FileHash=NarHash and FileSize=NarSize, asserted in daemon/tests/narinfo_rewrite.rs).
So a peer moves ~3.6x the bytes upstream moves for the same store path, and must sustain
>75 MB/s (604 Mbit/s) upload merely to BREAK EVEN before any discovery latency is counted. A home
uplink is 1.25-5 MB/s. Below that threshold NO NAR size wins, and the deficit GROWS with size.

WHY THIS INVALIDATES PUBLISHED NUMBERS: every speedup figure this project has produced was measured
against a FIXTURE upstream that also served uncompressed - task-64 added assert_unit_coincidence
which proves file_size == nar_size for exactly the speedup attrs. So none of them include the
asymmetry a real cache has. That includes the 6.1x WAN and 0.248 loopback figures.

This is the FOURTH recurrence of the NarSize-vs-FileSize unit trap in this project, and this time it
was in the orchestrator reasoning rather than in the code.

FIX AND ORDER: TASK-94 measures the inequality; TASK-99 fixes it by compressing the LINK (not the
content - the addressed unit must stay BLAKE3(raw nar) or peers compressing with different settings
produce different blob ids and lose all sharing). Do not re-derive any policy threshold, speedup, or
peer-vs-upstream ranking from this task until TASK-99 has landed and TASK-99 AC#4 has re-measured.
<!-- SECTION:NOTES:END -->
