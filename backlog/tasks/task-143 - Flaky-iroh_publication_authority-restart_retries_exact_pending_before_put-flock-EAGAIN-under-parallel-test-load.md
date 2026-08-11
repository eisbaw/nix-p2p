---
id: TASK-143
title: >-
  Flaky: iroh_publication_authority restart_retries_exact_pending_before_put
  (flock EAGAIN under parallel test load)
status: To Do
assignee: []
created_date: '2026-08-11 23:07'
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
