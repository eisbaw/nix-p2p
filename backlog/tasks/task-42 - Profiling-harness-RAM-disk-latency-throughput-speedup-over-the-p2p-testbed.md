---
id: TASK-42
title: 'Profiling harness: RAM/disk/latency/throughput/speedup over the p2p testbed'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
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
