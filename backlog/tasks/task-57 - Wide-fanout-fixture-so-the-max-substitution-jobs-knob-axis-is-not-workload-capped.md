---
id: TASK-57
title: >-
  Wide-fanout fixture so the max-substitution-jobs knob axis is not
  workload-capped
status: To Do
assignee: []
created_date: '2026-08-09 10:50'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Discovered in task-18 (S5 scale sweep). TESTING.md's client-knobs rule requires sweeping max-substitution-jobs / http-connections at {1,16,128}, but nix cannot run more concurrent substitutions than there are substitutable paths in the workload. The fixture workload offers 3-4 paths, so 16 and 128 are indistinguishable from ~4: the knob arm proves the knob LANDS (effective-knob readback from nix config show) but cannot show a concurrency effect. Needs a fixture closure with >= 128 substitutable store paths (a wide fan-out of tiny derivations, so the disk cost stays small - TASK-54 bounds the footprint). Then scripts/scale_sweep.py's knobs axis becomes a real concurrency axis and could even be fitted.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A fixture tier exists whose closure has >= 128 substitutable store paths and stays under a stated disk budget
- [ ] #2 scale_sweep.py knobs axis reports a measurable difference between jobs=1 and jobs=128 on that workload (or reports, with evidence, that nix does not parallelise it)
- [ ] #3 The workload_ceiling note in scale_sweep.sweep_knobs is updated to reflect the new ceiling
<!-- AC:END -->
