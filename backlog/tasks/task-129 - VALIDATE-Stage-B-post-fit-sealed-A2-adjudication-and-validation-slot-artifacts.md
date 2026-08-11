---
id: TASK-129
title: >-
  VALIDATE Stage B: post-fit sealed-A2 adjudication and validation-slot
  artifacts
status: To Do
assignee: []
created_date: '2026-08-11 02:36'
labels:
  - tournament
  - validation
  - policy
  - evidence
  - wave-2c
dependencies:
  - TASK-44
  - TASK-122
  - TASK-128
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
After TASK-44 irreversibly freezes the A1-selected best-static comparator and at most one exact eligible candidate per selectable profile, run a separate reader over sealed A2 evidence. Apply the preregistered A/A and hard-validation gates without exposing A2 to fitting, emit one terminal validation-slot artifact per selectable profile, and transfer only those artifacts one-way to TASK-123. This task implements the post-fit validation role split out of TASK-122 so the dependency graph remains executable; it cannot generate or inspect holdout material.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Before opening sealed A2 evidence, verify the hashes of the experiment contract, code, Stage-B manifest/results, TASK-128 causal schema/interpreter/catalog/injection solver, parity results, centered eligibility mask, and the frozen TASK-44 candidate and best-static outputs.
- [ ] #2 Replay each present frozen candidate independently on its matching A2 label evidence and apply the preregistered A/A and hard-validation gates. TASK-44 receives no raw A2, residual, per-label statistic, directional result, pass/fail feedback, or opportunity to refit or nominate a runner-up.
- [ ] #3 Emit exactly one hashed closed tagged-union validation-slot artifact for each of the three selectable profiles. validated and validation_no_go require present candidate/comparator references and hashes; no_candidate requires explicit absent/not_applicable references, forbids candidate/comparator hash keys, records an allowed reason code, and sets A2 validation to not_applicable.
- [ ] #4 Only validated slots are executable by TASK-123. validation_no_go and no_candidate are witnessed terminal outcomes, cannot be reassigned, and do not narrow the preregistered three-profile multiplicity family.
- [ ] #5 Transfer only the three hashed slot artifacts directly and one-way to the TASK-123 freeze input. No holdout ID, seed, topology, permit, manifest, result, or entropy is generated, read, or materialized by this task.
- [ ] #6 Bites prove fail-closed behavior for altered/missing hashes, mismatched A1/A2 labels, malformed present or absent references, attempted A2 access from TASK-44, attempted refit/runner-up selection, and any holdout access.
<!-- AC:END -->
