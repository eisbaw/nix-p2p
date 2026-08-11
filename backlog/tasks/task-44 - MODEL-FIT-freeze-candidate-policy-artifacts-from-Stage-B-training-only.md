---
id: TASK-44
title: 'MODEL/FIT: freeze candidate policy artifacts from Stage-B training only'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-11 02:38'
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
Select frozen static and adaptive candidate-policy artifacts using only TASK-122 Stage-B TRAINING A1 evidence. Preserve the original slow-HIT alternatives (abort, delayed race/hedge, throughput-adaptive) alongside transport, codec, discovery and participation choices, but choose only among the exact preregistered TASK-128 catalog artifacts under the frozen objective and constraints. Produce deterministic versioned candidate artifacts for TASK-129 validation; do not tune values, choose a product default, file an implementation task or inspect A2/holdout data. Upstream-only and no candidate are valid outputs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Only training scenario IDs/results are readable by the fitter; attempting to load the holdout partition fails and is covered by a bite.
- [ ] #2 Candidates include upstream-only and best-static baselines plus the predeclared Iroh/BitTorrent, raw/compressed, slow-HIT and layered alternatives; unsupported cells remain unsupported rather than imputed.
- [ ] #3 Each candidate is a deterministic machine-readable artifact with schema version, objective/constraint declaration, training-manifest hash, code hash and policy hash reproducible from the same inputs.
- [ ] #4 Any environment not supported by training evidence receives no candidate and a named evidence gap, not an inferred universal rule.
- [ ] #5 For each selectable profile, deterministically select the capable best-static comparator from permitted A1 evidence first, then select at most one exact TASK-128 catalog artifact whose frozen contrast with that already-selected comparator is eligible. The fitter cannot synthesize thresholds, parameter values or selector families, substitute a different comparator, or access A2 planning/validation observations; no eligible exact match yields the explicit no-candidate result.
- [ ] #6 Thresholds and hyperparameters are never fitted or filled from training: TASK-44 may select only a fully specified preregistered TASK-128 artifact. Selection uses the frozen A1-only procedure with complexity ordering, sensitivity/uncertainty reporting and the centered eligibility mask; METRIC_UNUSABLE can yield no candidate.
- [ ] #7 Training nominates at most one primary candidate for each of the three selectable deployment profiles before A2 validation. Other catalog results are labelled exploratory under the predeclared multiplicity procedure and cannot be substituted post-hoc as a candidate or default.
- [ ] #8 No implementation/default task is filed here. Frozen artifacts are nominees for TASK-129 sealed-A2 validation, and only a later validated slot can reach TASK-123 execution; failed, no-candidate and upstream-only outcomes are recorded honestly.
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
