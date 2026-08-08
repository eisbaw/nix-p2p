---
id: TASK-35
title: >-
  Re-measure narinfo->nar gap against a REAL upstream (cache.nixos.org RTT), not
  loopback
status: Done
assignee: []
created_date: '2026-08-08 17:30'
updated_date: '2026-08-08 20:14'
labels:
  - finding
  - wave-2
  - measurement
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FINDING from task-12 (J2 baseline read-out). The wave-1 narinfo->nar gap histogram was measured over LOOPBACK against a local mock origin: median ~0.5ms, p95 <0.9ms, max <2ms, every sample in the [0,10)ms bucket. On these numbers the prefetch window is structurally near-zero and a 1-4s DHT resolve (PRD risk 3) cannot be masked behind it. BUT loopback carries no real RTT: the real client->cache.nixos.org gap includes upstream RTT, TLS, CDN latency and client think-time between the narinfo GET and the NAR GET, plausibly opening a materially larger prefetch window. The wave-1 gap is therefore NOT a verdict that prefetch is dead - it says the prefetch-masking premise MUST be validated against a real upstream before the hedge/prefetch design is committed. Also: the instrument's gap-synthesis is only proven to bite for sub-second injected gaps (daemon 1000ms header_timeout ceiling, see task-33); multi-second real-gap fidelity is unvalidated. Directly feeds task-15 (wave-2 re-plan) and task-16 (checkpoint gap question).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A narinfo->nar gap is measured against a real upstream (cache.nixos.org or a latency-shaped proxy standing in for real RTT), reported next to the wave-1 loopback baseline so the two are comparable
- [x] #2 The measured real-upstream gap is compared against the 1-4s DHT-resolve latency p2p must hide; the report states whether the prefetch window is real at real-upstream RTT (the wave-1 loopback answer was no, but loopback-limited)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE 2026-08-08. Measured real narinfo->nar gap vs REAL cache.nixos.org via scripts/measure_real_gap.py (nix -vvvv download-log timing, out-of-band narinfo URL: pairing; same gap definition as the loopback testproxy). Recorded in TESTING.md 'Real-upstream gap (task-35)' and forward-carried to task-15. RESULT: gap is 500-5000x the loopback sub-ms and SCALES with closure download duration. hello (5 paths, n=5): median 298ms, p95 1093ms, min 41ms, max 1127ms. curl (21 paths, n=1): median 1399ms, max 3082ms (tail inside the 1-4s DHT window; 3/21 paths >2s). Two-phase (narinfos then NARs), so head-of-closure gaps ~one RTT (un-prefetchable) while large-closure tails reach seconds (prefetchable). AC#2 answer: the prefetch window IS real at real RTT (unlike loopback) but only for the tail of large closures and only if the daemon triggers on the narinfo request; it cannot cover any closure's head nor small closures - so HEDGE must carry offload, prefetch is a tail optimisation on top. Caveat: one machine, favourable Nordic RTT ~50-110ms.
<!-- SECTION:NOTES:END -->
