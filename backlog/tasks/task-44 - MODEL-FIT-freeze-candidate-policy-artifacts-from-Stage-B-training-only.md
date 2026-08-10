---
id: TASK-44
title: 'MODEL/FIT: freeze candidate policy artifacts from Stage-B training only'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-10 22:57'
labels: []
dependencies:
  - TASK-43
  - TASK-52
  - TASK-62
  - TASK-63
  - TASK-114
  - TASK-122
  - TASK-128
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Fit predeclared static and adaptive candidate policies using only TASK-122's Stage-B TRAINING artifact. Preserve the original slow-HIT candidates (abort, delayed race/hedge, throughput-adaptive) but evaluate them alongside transport, codec, discovery and participation choices using the preregistered objective and constraints. Produce deterministic versioned candidate artifacts for holdout; do not choose a product default, file an implementation task or inspect holdout data. Upstream-only and no candidate are valid outputs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Only training scenario IDs/results are readable by the fitter; attempting to load the holdout partition fails and is covered by a bite.
- [ ] #2 Candidates include upstream-only and best-static baselines plus the predeclared Iroh/BitTorrent, raw/compressed, slow-HIT and layered alternatives; unsupported cells remain unsupported rather than imputed.
- [ ] #3 Thresholds and hyperparameters are selected by a preregistered training-only procedure with overfit/complexity penalties, sensitivity analysis and uncertainty; METRIC_UNUSABLE can yield no candidate.
- [ ] #4 Each candidate is a deterministic machine-readable artifact with schema version, objective/constraint declaration, training-manifest hash, code hash and policy hash reproducible from the same inputs.
- [ ] #5 No implementation/default task is filed here. The artifacts are merely nominees for TASK-123, and failed/no-candidate/upstream-only outcomes are recorded honestly.
- [ ] #6 Any environment not supported by training evidence receives no candidate and a named evidence gap, not an inferred universal rule.
- [ ] #7 Training nominates at most one primary candidate per preregistered deployment profile before holdout; other candidates are labelled exploratory with a predeclared multiplicity procedure and cannot be selected post-hoc as the default.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## WIRE-COST CORRECTION 2026-08-10: every peer-vs-cache number in this task is invalid until TASK-99 lands

MEASURED on 20 signed paths >10 MiB from the live cache.nixos.org: FileSize/NarSize = 0.278 aggregate
(median 0.216). cache.nixos.org serves xz; our peers serve RAW nar (daemon/src/rewrite.rs rewrites
Compression:none with FileHash=NarHash and FileSize=NarSize, asserted in daemon/tests/narinfo_rewrite.rs).
So a peer moves ~3.6x the bytes upstream moves for the same store path, and must sustain
>75 MB/s (604 Mbit/s) upload merely to BREAK EVEN before any discovery latency is counted. A home
uplink is 1.25-5 MB/s. Below that threshold NO NAR size wins, and the deficit GROWS with size.

WHY THIS INVALIDATES PUBLISHED NUMBERS: every speedup figure this project has produced was measured
against a FIXTURE upstream that also served uncompressed - task-64 added assert_unit_coincidence
which proves file_size == nar_size for exactly the speedup attrs. So none of them include the
asymmetry a real cache has. That includes the 6.1x WAN and 0.248 loopback figures.

This is the FOURTH recurrence of the NarSize-vs-FileSize unit trap in this project, and this time it
was in the orchestrator reasoning rather than in the code.

FIX AND ORDER: TASK-94 measures the inequality; TASK-99 fixes it by compressing the LINK (not the
content - the addressed unit must stay BLAKE3(raw nar) or peers compressing with different settings
produce different blob ids and lose all sharing). Do not re-derive any policy threshold, speedup, or
peer-vs-upstream ranking from this task until TASK-99 has landed and TASK-99 AC#4 has re-measured.
<!-- SECTION:NOTES:END -->
