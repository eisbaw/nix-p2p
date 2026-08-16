---
id: TASK-28
title: 'Narinfo cache: move blocking std::fs (esp. fsync) off the async path'
status: Done
assignee:
  - '@claude'
created_date: '2026-08-08 11:24'
updated_date: '2026-08-16 16:37'
labels:
  - wave1-followup
  - daemon
  - hardening
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
daemon/src/narinfo_cache.rs does file I/O with blocking std::fs directly inside the async NarinfoSource::fetch and the sync CorrelationStore::meta_for_token. Reads and small writes are cheap; the sharp edge is write_durably()'s sync_all() fsync, which can stall a Tokio worker thread for milliseconds under load. Move the disk I/O to spawn_blocking (or tokio::fs), and make CorrelationStore lookup async or off-thread. This should land BEFORE the cache is enabled by default in e2e/NixOS (see the default-wiring follow-up).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Cache disk I/O (esp. fsync) no longer runs on a Tokio worker thread directly
- [x] #2 No regression in the task-8 disk-cache tests
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
task-13 triage: KEEP for wave-2 - moving blocking std::fs/fsync off the async path should land before the narinfo cache is enabled by DEFAULT (task-29); it is a latency/soundness refinement, not a wave-1 correctness finding. Distinct concern.

TASK-28 plan (in progress): split NarinfoDiskCache disk+book state into Arc<Shared> (all blocking std::fs/fsync methods live on Shared); async facade dispatches read_fresh + install + correlation via tokio::task::spawn_blocking so the sync_all fsync and the sidecar atomic-write+dir-fsync never run on a Tokio worker. Preserve durability ordering (write_durably tmp->fsync->rename, dir fsync, save-before-publish, sidecar-under-lock) unchanged inside the moved closures. Make CorrelationStore::meta_for_token ASYNC (spawn_blocking the disk re-parse); update NullCorrelation impl + server.rs call site (match, in-memory catalog first then persisted) + the two trait test call sites. Constructor load_index stays sync (one-time wiring, not the hot path) - documented. AC#1 bite: current_thread runtime, armed slow Clock that thread::sleeps INSIDE read_fresh (the moved region); ordering oracle - a concurrent 50ms task must finish before the 800ms-blocked fetch; mutation = revert spawn_blocking -> worker starves -> RED.

DONE (LIGHT gate, orchestrator-verified). Commit 75f9272. All fsync-heavy/blocking narinfo-cache I/O moved off the Tokio worker via spawn_blocking (Arc<Shared> split; durability sequence moved byte-for-byte so save-before-publish + atomic tmp->fsync->rename + parent-dir fsync + sidecar all intact); meta_for_token made async (trait). AC#1 mutation-proven bite (ac1_cache_read_runs_off_the_tokio_worker: on-worker read starves a concurrent task -> reddens). AC#2 no regression: daemon-core 219/0, narinfo 16/16, e2e 5/5, golden byte-identical. Unblocks TASK-29 (default-enable the cache).
<!-- SECTION:NOTES:END -->
