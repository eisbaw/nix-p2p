---
id: TASK-237
title: >-
  Value-thesis measurement: libp2p multi-node cache-egress offload on a shaped
  network
status: To Do
assignee: []
created_date: '2026-08-16 14:04'
updated_date: '2026-08-17 22:12'
labels:
  - measurement
  - value-thesis
  - pilot
dependencies:
  - TASK-120
  - TASK-206
  - TASK-219
  - TASK-247
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRD #1 weakest point, previously UNFILED (COMPASS 2026-08-16). Extend TASK-206 (shaped-link libp2p fetch) to a >=3-node kad-DHT-over-shaped-link topology and measure the PRD What-good-looks-like oracle: NET cache egress measurably DROPS with the daemon enabled vs without (gross peer bytes is NOT the metric - lost-hedge pulls still cost cache bytes), with nix build tail latency bounded at cache+hedge. Honest scoping per PRD risk 4: a young/synthetic network offloads little and the kill criterion is STEADY-STATE not launch-day, so a 3-node harness gives a directional number, not the conclusive verdict - that needs a real multi-node pilot. This is the TERMINAL measurement task of the pilot-readiness wave; per owner basics-first steer its EXECUTION is deferred behind connectivity generality (TASK-219) and the operator contract (TASK-120), but it is filed NOW so the make-or-break has an owner. Integers only in any gate/threshold (offload ratio as exact num/denom). Relates TASK-206/198/9 (measurement instrument).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Forward-carried from TASK-247 under COMPASS direction: the value-thesis run must consume the proven real nix-daemon concurrency factor from TASK-247 rather than assuming client parallelism hides peer overhead. TASK-219 remains the connectivity-generalization prerequisite; TASK-120 and TASK-206 are completed prerequisites. Use TASK-247 effective-setting and overlap evidence when preregistering latency bounds.
<!-- SECTION:NOTES:END -->
