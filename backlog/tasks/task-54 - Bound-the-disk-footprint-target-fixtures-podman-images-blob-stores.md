---
id: TASK-54
title: 'Bound the disk footprint (target/, fixtures, podman images, blob stores)'
status: To Do
assignee: []
created_date: '2026-08-08 22:11'
updated_date: '2026-08-09 17:21'
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

## Forward-carried from task-42 (profiling harness) - AC#2 input

WHAT TASK-42 DELIVERED FOR YOUR AC#2. `just profile` measures footprint at the
right boundary and refuses to run below headroom:
- `MIN_FREE_DISK_BYTES = 8 GiB` fail-fast precondition with a message naming
  TASK-54, so a sweep dies before it starts rather than with a mid-run ENOSPC.
- `dir_footprint()` walks a node's on-disk state HOST-side (apparent + allocated
  + file count) and RAISES on a missing directory - 'measured the wrong place'
  can never present as a comfortable 0 bytes. Host-side because `du`/`find` are
  not in the e2e image (an in-container probe returns rc=127 and reads as 0).
- Every pod is torn down label-scoped on exit AND on SIGTERM; per-point seed
  dirs (a 110 MiB copy each for the speedup arm) are rmtree'd in a `finally`.
- The swarm axis deliberately uses SMALL attrs: every holder seeds every NAR into
  an in-RAM store, so `big` at n=16 would be ~1.8 GiB of held content and would
  measure the host running out of memory rather than a scaling law. Coverage was
  not shrunk to dodge disk - the 110 MiB payload is exercised in full in the
  speedup arm, where only one holder holds it.

THE HEADLINE FINDING, WHICH CHANGES WHAT YOU ARE BOUNDING: there is NO on-disk
blob store. `IrohProvider::spawn` uses `MemStore` (daemon/src/transport_iroh.rs),
so held content costs RESIDENT MEMORY, not disk. Measured:
- per-node on-disk state: 4096 B allocated (1182 B apparent, 2 files) - the
  narinfo disk cache and nothing else, FLAT across n = 1..16 (fitted O(1),
  R^2 = 1.0). A holder that serves no narinfo writes 0 files.
- per-node RSS: holder peak 248 MiB while holding/serving a 110 MiB NAR (2.15x),
  fetching node 141 MiB (whole-NAR transport buffers it too), against 10.7 MiB
  for the same daemon with peers off.
- swarm total RSS is O(n) (R^2 0.9996): 37.8 MiB at n=1 -> 306 MiB at n=16.
  MODEL OUTPUT at n=1000: 18.6 GB (95% CI 18.4-18.9 GB) - a labelled
  extrapolation, not a measurement, and its intervals are known to UNDER-cover
  under multiplicative noise (task-18: 0.865 vs 0.95 nominal at n=1000).

So the footprint you need to bound is a MEMORY footprint, and the two levers are
an on-disk/streaming blob store and an addressed unit smaller than the whole NAR
(castore chunks). A disk cap alone would bound nothing that is currently large.

The report block `disk_finding` states all of this in-band, and
`held_content_ram_cost` reports RSS per held NarSize byte per node - a NAMED
cross-unit ratio (the report's unit gate forbids unlabelled `_bytes` keys
precisely so NarSize and FileSize can never be silently compared).

## Forward-carried from TASK-65: a THIRD disk consumer, and the precondition shape that worked

`just profile` grew a size + concurrency axis (scripts/sizeaxis.py) that
SYNTHESISES its own graded binary cache. What it costs, so this task can bound it
deliberately rather than discover it:

 * default grid: NAR sizes 8/16/32/64/128 MiB (248 MiB) + 5 concurrency payloads
   of 32 MiB (160 MiB) = ~408 MiB of NAR, written once into a scratch cache and
   once more into a PER-POINT seed dir (e2e.build_p2p_seed_dir copies the raw NAR
   out of the cache). Requirement is computed as 3x the grid + 2 GiB slack, so
   ~3.2 GiB at defaults.
 * 30 pods per full run at the default grid (5 sizes x 3 repeats + 5 k x 3
   repeats), each with a state dir under the run's scratch. All label-scoped and
   torn down in a finally, same contract as e2e-clean.
 * the graded cache is rmtree'd as soon as the arms finish, before report
   assembly, rather than at the end of the run.
 * the whole default `just profile` is now ~45 minutes.

WHAT WORKED, and is worth generalising for AC#2: the disk precondition is a
FUNCTION OF THE GRID, not a flat constant. `sizeaxis.disk_precondition_violations`
computes the requirement from the actual --size-grid and fails BEFORE anything is
written, with a message that states the number, where it came from, and that
shrinking coverage silently is not the answer. profile_p2p's older flat
MIN_FREE_DISK_BYTES = 8 GiB is still there for the swarm arm and is exactly the
kind of constant that goes stale when someone widens a grid - AC#2 should
probably replace it with the same derived shape.

HOST AT THE TIME: 44 GiB free / 95% used. The grid fit; nothing had to be cut.
If a future widening does not fit, the instruction in the failure message is to
file it here rather than quietly reduce the size grid below scalefit.MIN_POINTS
(5), which would make the fitted slope unfittable rather than merely coarse.
<!-- SECTION:NOTES:END -->
