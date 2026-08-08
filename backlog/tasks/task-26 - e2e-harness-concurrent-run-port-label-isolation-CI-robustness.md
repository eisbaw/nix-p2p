---
id: TASK-26
title: 'e2e harness: concurrent-run port/label isolation (CI robustness)'
status: To Do
assignee: []
created_date: '2026-08-08 10:14'
updated_date: '2026-08-08 17:59'
labels:
  - wave2
dependencies:
  - TASK-5
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deep-gate follow-up (task-5, qa+codex): concurrent just e2e runs collide on global podman ports/labels. Fails nonzero (not false-green) so not gate-breaking, but blocks parallel CI. Namespace ports and pod labels per-run (pid/uuid).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Two just e2e runs in parallel do not collide; each isolates ports and pod labels
- [ ] #2 e2e-clean only removes the invoking run label
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
task-13 triage (KEEP, CI-robustness): e2e harness concurrent-run port/label isolation is a CI-parallelism concern, not a wave-1 correctness finding. task-13's matrix/boundary scenarios reuse the single-runner Pod seam and pass; concurrent-run isolation is orthogonal. Kept as an explicit task; reclassified deferred-finding -> wave2.
<!-- SECTION:NOTES:END -->
