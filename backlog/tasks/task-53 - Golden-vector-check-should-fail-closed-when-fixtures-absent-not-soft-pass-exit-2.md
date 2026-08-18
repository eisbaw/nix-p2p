---
id: TASK-53
title: >-
  Golden-vector check should fail-closed when fixtures absent (not soft-pass
  exit 2)
status: Done
assignee: []
created_date: '2026-08-08 21:24'
updated_date: '2026-08-18 20:41'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE (LIGHT gate). Commit 0d723ee. check-golden-vectors.py fail-closed BY DEFAULT (opt-in --allow-missing-fixtures restores the exit-2 soft-skip; gate passes no flag). exit 2 now ONLY from the opt-in skip; all genuine problems -> exit 1. Self-test bite asserts exit==1 specifically (exit 2 is also non-zero). Recipe-vector always exit 1. Extended fail-closed to present-but-wrong cases (removed the exit-2 masking footgun). flake/sandbox never invokes it (flake.nix:105 is a comment) -> not broken. Python-only.
<!-- SECTION:NOTES:END -->
