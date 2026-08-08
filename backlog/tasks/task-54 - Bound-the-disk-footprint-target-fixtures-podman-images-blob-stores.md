---
id: TASK-54
title: 'Bound the disk footprint (target/, fixtures, podman images, blob stores)'
status: To Do
assignee: []
created_date: '2026-08-08 22:11'
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
