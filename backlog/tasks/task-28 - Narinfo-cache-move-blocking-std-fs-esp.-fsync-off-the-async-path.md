---
id: TASK-28
title: 'Narinfo cache: move blocking std::fs (esp. fsync) off the async path'
status: To Do
assignee: []
created_date: '2026-08-08 11:24'
updated_date: '2026-08-08 17:59'
labels:
  - wave1-followup
  - daemon
  - hardening
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
daemon/src/narinfo_cache.rs does file I/O with blocking std::fs directly inside the async NarinfoSource::fetch and the sync CorrelationStore::meta_for_token. Reads and small writes are cheap; the sharp edge is write_durably()'s sync_all() fsync, which can stall a Tokio worker thread for milliseconds under load. Move the disk I/O to spawn_blocking (or tokio::fs), and make CorrelationStore lookup async or off-thread. This should land BEFORE the cache is enabled by default in e2e/NixOS (see the default-wiring follow-up).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Cache disk I/O (esp. fsync) no longer runs on a Tokio worker thread directly
- [ ] #2 No regression in the task-8 disk-cache tests
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
task-13 triage: KEEP for wave-2 - moving blocking std::fs/fsync off the async path should land before the narinfo cache is enabled by DEFAULT (task-29); it is a latency/soundness refinement, not a wave-1 correctness finding. Distinct concern.
<!-- SECTION:NOTES:END -->
