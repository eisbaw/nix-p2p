---
id: TASK-18
title: Scale-sweep + regression-fit machinery (S5)
status: To Do
assignee: []
created_date: '2026-08-07 22:10'
updated_date: '2026-08-07 22:14'
labels: []
dependencies:
  - TASK-9
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner requirement (post-review): characterize behavior at 10s/100s/1000s of peers despite the host affording ~1..30 real nodes. This task builds the MACHINERY in wave 1, exercised on the axes that exist now - concurrent clients and proxy-chain depth; the p2p wave points the same sweep at peer count. Sweep runner: run scenario at N in a configured range, sample per-node RSS/fds/request-latency via the harness; fitter: candidate models O(1)/O(log n)/O(n)/O(n log n)/O(n^2), select by fit quality, extrapolate with confidence intervals. TESTING.md S5 honesty rules apply: extrapolations labeled as model outputs, R^2/residuals reported, superlinear RAM/latency fits surfaced as red flags, and claims limited to resource scaling laws - emergent network effects (DHT k-buckets, gossip fan-out) are explicitly out of scope for small-N extrapolation. Prefer process/pod swarms over VMs for sweeps (a daemon is one process; client nix containers are the heavy part - the sweep design must account for which component actually scales).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just scale-sweep runs a sweep (e.g. N clients in 1..16, chain depth 1..5) and emits per-N samples: RSS, fds, latency percentiles per node
- [ ] #2 Fitter selects among candidate models, reports fit quality (R^2, residuals) and confidence intervals; extrapolated values labeled as model output, never measurement (S5 honesty rules asserted in report format)
- [ ] #3 Bite test: synthetic workload with known O(n) memory growth recovers a linear fit; known O(1) workload recovers constant - wrong-model selection fails the test
- [ ] #4 Report flags superlinear RAM or latency fits prominently (red-flag section, not a footnote)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Sweep axes must include the client concurrency knobs max-substitution-jobs / http-connections in {1, 16, 128} (TESTING.md client-knobs rule), alongside client count and chain depth. Ref: bmcgee.ie TIL post.
<!-- SECTION:NOTES:END -->
