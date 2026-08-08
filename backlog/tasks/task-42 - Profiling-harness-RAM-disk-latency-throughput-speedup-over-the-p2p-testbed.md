---
id: TASK-42
title: 'Profiling harness: RAM/disk/latency/throughput/speedup over the p2p testbed'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-08 20:30'
labels: []
dependencies:
  - TASK-41
  - TASK-18
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The owner-goal profiling instrument (extend task-18 S5 machinery + net-upstream-egress-v2). Over the 2-node+ p2p testbed, sample per-node RSS, disk (castore/blob store footprint), request latency, throughput, and speedup-over-upstream; emit a machine-readable report. Reuse the measure.py arm/report abstraction. This is the tool the scenario models (task-G) drive; per S9 it must BITE (a known-O(n) RAM workload recovers a linear fit; superlinear surfaced as a red flag).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just profile emits a report: per-node RSS/fds, disk footprint, latency p50/p95, throughput, egress-vs-upstream, for a scripted p2p workload
- [ ] #2 S9 bite: a synthetic known-O(n)-RAM scenario recovers a linear regression fit; a known-O(1) recovers constant; wrong-model selection fails the self-test
- [ ] #3 Extrapolation labeled model-output (never measurement); R^2/residuals reported; resource-laws-only caveat stated (no emergent-network-effect claims)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION (S9 bite, arch#4/qa#3/codex#7): (1) The dangerous confusion is linear-vs-SUPERLINEAR, not O(n)-vs-O(1). Add a known-SUPERLINEAR (e.g. O(n^2)) generator the fitter MUST classify superlinear and MUST NOT fit as linear (bite). (2) Define wrong-model = selected-class != generated-class. (3) Extrapolations REQUIRE confidence intervals (S5). (4) The peer axis needs REAL points: a 1..30 process-swarm sweep (many daemon processes on one host), NOT extrapolation from 2 nodes - two points can't discriminate O(n) from O(n log n). Restrict any 100s/1000s claim to labeled model-output over the 1..30 fit. (5) Report high-water RSS/disk, not just point samples. Stale ref fix: 'task-F'=this task(42), 'task-G'=task-43, 'task-H'=task-44.
<!-- SECTION:NOTES:END -->
