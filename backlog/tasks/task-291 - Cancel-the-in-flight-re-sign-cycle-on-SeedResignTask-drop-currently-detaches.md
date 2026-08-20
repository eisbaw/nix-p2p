---
id: TASK-291
title: Cancel the in-flight re-sign cycle on SeedResignTask drop (currently detaches)
status: To Do
assignee: []
created_date: '2026-08-20 23:58'
labels:
  - hardening
  - follow-up
dependencies:
  - TASK-285
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
codex-MED from the TASK-285 DEEP gate. SeedResignTask::Drop aborts only the supervisor JoinHandle; the per-cycle child is tokio::spawn(cycle()).await-ed, so aborting the supervisor at that await DETACHES (does not cancel) an in-flight cycle -> it runs to completion and can publish AFTER the guard drops. Harmless under the TCB (a late signed monotonic positive supersede, never a rollback), and the docstring was corrected to admit it (TASK-285 FIX 3), but truly cancelling it is cleaner.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Dropping SeedResignTask cancels an in-flight re-sign cycle (an abort-on-drop guard around the spawned child, or a cancellation token), so no announce publishes after drop. Test: drop mid-cycle => no post-drop put_record.
<!-- AC:END -->
