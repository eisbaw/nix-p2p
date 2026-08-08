---
id: TASK-19
title: Standing home for the full-tier fixture gate
status: To Do
assignee: []
created_date: '2026-08-08 00:28'
updated_date: '2026-08-08 02:01'
labels:
  - deferred-finding
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
There is no CI configuration in this repository, so the full-tier fixture gate (just fixtures-large, --require-tier full) and the build-determinism gate (just fixtures-verify-rebuild) run only when a developer remembers to invoke them. On a cold checkout nothing exercises the 110 MiB payload or proves the payload derivations rebuild identically.

This is a COVERAGE gap, not a correctness defect: both gates exist, both bite (proven in task-3, commit 9dba842), and the fast tier prints an explicit PARTIAL line naming what it did not cover. What is missing is a scheduled or automatic invoker.

Likely resolution: task-5's e2e harness already needs the full tier (it serves fixtures/out/cache from containers), so wiring fixtures-large into the e2e entry point may close most of this for free. fixtures-verify-rebuild is slower and cadence-based - it is a required pre-J2 step recorded on task-9 and task-12, so it may only need a named recipe plus a checklist item rather than automation.

Do not resolve by weakening either gate or by folding the 110 MiB payload into just test - the fast loop staying fast is deliberate.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-3 round 5: the fixture tree is now published as an immutable generation behind a symlink, so every path above that starts fixtures/out/ gains one level: fixtures/out/current/cache, fixtures/out/current/manifest.json, fixtures/out/current/test-key.pub. Resolve through fixtures/out/current (never name a generation directly); it is a relative symlink to generations/gen-<manifest-sha>, and the generation it points at is immutable, so a consumer that resolves it once cannot have the tree change underneath it. Retention is two generations, not a lease: re-resolve on ENOENT if you hold it across repeated regenerations.
<!-- SECTION:NOTES:END -->
