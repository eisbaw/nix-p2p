---
id: TASK-15
title: 'RE-PLAN: wave 2 planning via phase2-backlog-snowball (not feature code)'
status: Done
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-10 22:57'
labels:
  - replan
  - superseded
dependencies:
  - TASK-16
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Re-plan task - not feature code. Re-invoke phase2-backlog-snowball with: the PRD (PRD.md), the current TESTING.md grounding doc, and the lessons/notes wave 1 produced (J2 baseline: egress, p95, narinfo-to-nar gap histogram; journey findings; hardening results). Plan wave 2 to the depth the new knowledge supports. Wave 2 candidates the PRD already names: DHT mechanism spike (mainline vs BEP44 vs iroh-tracker - first freeze surface, will need irreversible labels), iroh-blobs whole-NAR NarSource, peer yes/no probe protocol + rate-limiting design, hedge with throughput abort, figure revision to DHT-authoritative. TESTING.md wave-scoping checklist lists the not-yet-grounded oracles wave 2 must pull in. Write no implementation in this task. Shallow-ahead planning is deliberate: this project is experimental (PRD field), and planning past current knowledge manufactures false certainty.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Wave-2 tasks exist in the tracker, grounded in J2 baseline data
- [ ] #2 New wave ends with its own re-plan task UNLESS project reclassified firm (then full breakdown; PRD field updated)
- [ ] #3 TESTING.md updated with what wave 1 taught (baseline section + pulled-in oracles for wave 2)
- [ ] #4 Irreversible labels applied to wave-2 freeze-surface tasks per PRD map (claim schema, DHT key derivation, addressed-unit encoding)
- [ ] #5 Wave exit gate: just e2e AND just e2e-vm both green at the moment of re-planning (a gate that vanished cannot be required - task-1 stubs must be long gone)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
task-35 real-upstream gap measured (2026-08-08, scripts/measure_real_gap.py vs real cache.nixos.org; see TESTING.md 'Real-upstream gap (task-35)'). Result feeding the prefetch-vs-hedge design: real narinfo->nar gap is 500-5000x the loopback sub-ms gap and SCALES with closure download duration. hello (5 paths): median 298ms, max 1.1s. curl (21 paths): median 1.4s, max 3.08s (tail inside the 1-4s DHT window). Two-phase: narinfos first, then NARs; per-path gap = narinfo-seen -> NAR-demanded. Design consequence: (1) prefetch VIABLE for the TAIL of large closures IF the daemon triggers DHT resolve on the narinfo request; (2) prefetch CANNOT cover any closure's HEAD nor small closures at all (gap < DHT-resolve floor); (3) hedge must carry offload, prefetch is a tail optimisation on top. Loopback 'prefetch is dead' verdict was an artifact - do NOT carry forward. Caveat: favourable Nordic RTT ~50-110ms (near-lower-bound); distant clients see larger gaps.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Superseded on 2026-08-11. Earlier wave-2 planning was already materialized. TASK-114 now owns the test-first two-stage tournament contract and TASK-124 is the next evidence-driven terminal re-plan. No feature completion is claimed by closing this stale planning task.
<!-- SECTION:FINAL_SUMMARY:END -->
