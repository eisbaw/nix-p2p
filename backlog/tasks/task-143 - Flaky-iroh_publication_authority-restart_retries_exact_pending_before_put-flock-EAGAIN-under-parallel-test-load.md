---
id: TASK-143
title: >-
  Flaky: iroh_publication_authority restart_retries_exact_pending_before_put
  (flock EAGAIN under parallel test load)
status: Done
assignee: []
created_date: '2026-08-11 23:07'
updated_date: '2026-08-18 19:19'
labels:
  - flaky
  - hardening
  - test
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Observed during TASK-139: first-run failure of daemon lib test iroh_publication_authority::tests::restart_retries_exact_pending_before_put with flock EAGAIN under parallel test contention; passes in isolation and on clean re-run. Test-isolation issue (shared flock path across parallel tests), pre-existing and unrelated to TASK-139 (purely additive). Root-cause the shared lock/tempdir and make the test hermetic so the gate is deterministic under `cargo test` parallelism.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-08-18 canonical QA reproduction: a unique publisher state directory still hit flock EAGAIN immediately after awaited graceful shutdown. Strace proved this is not temp-path collision: a concurrently forked proc-supervisor child inherited the flock open-file description and retained it during pre-exec PATH search after the parent owner closed. Root fix in progress: explicit LOCK_UN RAII for publisher, authority, and audited sibling stores, with a retained-dup mutation regression. Lucky isolation reruns do not close this task.

2026-08-18 CLOSED: explicit LOCK_UN now releases publication, authority, and allowlist flock guards before inherited duplicate descriptors can prolong the open-file-description lock. Deterministic duplicate-FD regressions prove immediate reacquisition while the duplicate remains open. Final lint, build, workspace tests, just e2e (9/9), and just e2e-full (34/34) passed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Root cause was fork inheritance of the flock open-file description during pre-exec PATH search, not shared temp paths. Explicit unlock-on-drop fixes the real lifetime bug and retained-duplicate mutation tests make the failure deterministic.
<!-- SECTION:FINAL_SUMMARY:END -->
