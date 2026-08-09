---
id: TASK-54
title: 'Bound the disk footprint (target/, fixtures, podman images, blob stores)'
status: To Do
assignee: []
created_date: '2026-08-08 22:11'
updated_date: '2026-08-09 11:16'
labels:
  - tooling
dependencies:
  - TASK-42
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Disk hit 100% during task-48 (target/ got auto-nuked by a cleanup; rebuildable, no loss - but a warning). 97% used / 28G free as of 2026-08-09. Disk-heavy work ahead: container e2e (115MB big fixture + podman images), and especially S5 profiling (task-42) with 1..30 daemon-node swarms each holding a blob store. Bound it: e2e-clean should prune podman images/volumes not just pods; a just recipe to reclaim (cargo clean / fixture generations GC / podman system prune); the profiling harness should cap per-node blob-store size and clean up swarm nodes; document a disk-headroom precondition for the profiling/e2e recipes (fail-fast with a clear message if free space < N GB, rather than a mid-run 100%-full crash).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 e2e-clean and a reclaim recipe bound podman images/volumes + fixture generations; documented
- [ ] #2 The profiling harness (task-42) caps per-node blob store + cleans up swarm nodes; a disk-headroom precondition fails fast with a clear message
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from task-18 (S5 scale-sweep machinery)

A new SLOW-tier consumer of disk landed: `just scale-sweep` (scripts/scale_sweep.py). What it
does today, so the footprint work can bound it deliberately:

- It refuses to start below `MIN_FREE_DISK_BYTES` (8 GiB) with a message pointing at THIS task -
  a guard, not a bound. Host at the time: 48 GiB free / 95% used.
- It sweeps SMALL fixture attrs only (`SWEEP_ATTRS = ("lib","app","zstd")`, sub-MiB). The 110
  MiB `big` payload is deliberately EXCLUDED: every concurrent client realises its own copy, so
  at 12 clients that would be ~1.3 GiB of container-layer churn per sweep point. `SWEEP_ATTRS`
  is the single constant where that bound lives.
- Default grid: clients {1,2,4,6,8,12} + chain depths 1..5 + knobs {1,16,128} = 14 pods and 45
  ephemeral `--rm` client containers per full run. Every pod is label-scoped
  (`nix-p2p-e2e=1`) and torn down in a `finally`, same contract as `just e2e-clean`.
- NOTE the recipe still depends on `fixtures-large`, because `e2e.preflight_gate` requires tier
  `full`. So a scale sweep pulls the 110 MiB fixture onto disk even though it never serves it.
  If you want a tier-aware preflight, that is a real footprint saving and belongs here.
- Do not shrink the default N grid below 5 DISTINCT points to save disk: `scalefit.MIN_POINTS`
  is 5 and the fitter REFUSES to fit fewer. Shrinking the grid silently turns the sweep into a
  no-op that still exits 0 on the arms it skipped. Bound the payload, not the point count.
<!-- SECTION:NOTES:END -->
