---
id: TASK-57
title: >-
  Wide-fanout fixture so the max-substitution-jobs knob axis is not
  workload-capped
status: To Do
assignee: []
created_date: '2026-08-09 10:50'
updated_date: '2026-08-18 06:52'
labels:
  - fixture
  - e2e
  - wide-closure
  - integrity
dependencies:
  - TASK-54
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Create the frozen TESTING.md wide_closure fixture class consumed by TASK-247: one reproducible root closure with 128-512 independently substitutable members and total NarSize in the normative 256 MiB-2 GiB range. This task owns fixture construction, cold-closure/cardinality truth, integrity/signature metadata, and apparent/allocated disk budgets only. It does not measure Nix concurrency or performance; TASK-247 owns those experiments after TASK-62 streaming.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A fixture tier exists whose closure has >= 128 substitutable store paths and stays under a stated disk budget
- [ ] #2 The wide tier is a formal closure: one root has at least 128 distinct independently substitutable references, a cold realise requests every member, and a mutation that removes fan-out or pre-realises members fails the closure/cardinality oracle.
- [ ] #3 The generation lock records per-object NarSize/FileSize plus total apparent and allocated bytes; the tier stays within an explicit integer disk budget and remains reproducible under the existing fixture integrity/signature rules.
- [ ] #4 The manifest class is exactly wide_closure with 128-512 independently substitutable store paths and 256 MiB-2 GiB total NarSize; any smaller development fixture uses a different class and cannot satisfy this task.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixture-only prerequisite for TASK-247. Do not run or claim knob effects here: performance, independent http-connections/max-substitution-jobs axes, overlap, A/A, and serialization mutations belong to TASK-247 after TASK-62.
<!-- SECTION:NOTES:END -->
