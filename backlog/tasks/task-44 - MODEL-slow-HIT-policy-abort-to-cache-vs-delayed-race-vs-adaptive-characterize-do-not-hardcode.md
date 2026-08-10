---
id: TASK-44
title: >-
  MODEL: slow-HIT policy (abort-to-cache vs delayed-race vs adaptive) -
  characterize, do not hardcode
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-10 09:29'
labels: []
dependencies:
  - TASK-43
  - TASK-52
  - TASK-63
  - TASK-62
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The owner-named policy archetype. Do NOT hardcode a policy - MODEL the three candidates under the slow-peer-HIT scenario (task-G) and report which wins on wall-clock + net egress (hedge losers counted in the reserved hedge_waste channel): (a) abort-to-cache after T; (b) delayed-race/hedge (start cache fetch, first past the NarHash gate wins, cancel loser); (c) adaptive (abort if throughput < X for T). Then FILE the chosen-policy implementation as its own task grounded in this data. This is design-for-data, per the owner goal.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The 3 candidates measured under the slow-peer scenario: wall-clock + net egress (incl hedge_waste) reported per candidate, with the threshold sensitivity (T, X) swept
- [ ] #2 A recommendation with the data behind it; the chosen policy filed as a NEW implementation task (not implemented here)
- [ ] #3 Honest limit: loopback/container throughput is not residential-uplink; the model states what real-network validation it still needs
- [ ] #4 BOTH REGIMES: every candidate measured against the loopback control AND the TASK-63 WAN-shaped upstream. A recommendation valid only on loopback is not a recommendation - the sign of this whole question is set by upstream speed, which the loopback arm fakes at 758 MB/s and ~0 RTT
- [ ] #5 The STREAMING COMMIT DEADLINE is an explicit modeled constraint (post-TASK-62): abort-to-cache is only free BEFORE the first body byte is committed to Nix. Model hedge as 'hold the response head until first-past-the-gate, then commit and stream' with its bounded-buffer cost - not as 'run both to completion and pick a winner'
- [ ] #6 The headline deliverable is the HEDGE-DELAY vs OFFLOAD-RETENTION curve with the crossover as a function of upstream bandwidth/RTT - not a winner. Hedging immediately against a fast upstream makes the cache always win, collapsing offload toward 0 with hedge_waste = the entire NAR every time; 'no candidate justified' is a legitimate outcome
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
