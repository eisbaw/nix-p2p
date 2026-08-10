---
id: TASK-53
title: >-
  Golden-vector check should fail-closed when fixtures absent (not soft-pass
  exit 2)
status: To Do
assignee: []
created_date: '2026-08-08 21:24'
updated_date: '2026-08-10 22:36'
labels:
  - wave-2
dependencies:
  - TASK-48
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
task-48 deep-gate (qa finding 2): check-golden-vectors.py soft-passes (exit 2 nothing-proven) when the fixture tree is absent, and the cargo committed_fixture_digest_is_canonical test is encoding-only (shape, not value). So OUTSIDE just test (where fixtures is a dependency and regenerates the tree), the one irreversible addressed-unit byte (blake3:95f49df0...) is never actually value-checked. Low risk (just test does check it), but the freeze witness should be harder to skip. Options: a CI/gate path that requires the fixture + hard-fails if absent; or a committed raw-NAR sample so the cargo test can value-check without the full fixture tree.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The addressed-unit golden digest is value-checked in a path that fails-closed when its input is missing (no silent exit-2 skip of the one irreversible byte)
<!-- AC:END -->
