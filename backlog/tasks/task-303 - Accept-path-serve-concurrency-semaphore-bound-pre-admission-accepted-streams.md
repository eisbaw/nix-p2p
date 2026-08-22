---
id: TASK-303
title: Accept-path serve concurrency semaphore (bound pre-admission accepted streams)
status: To Do
assignee: []
created_date: '2026-08-22 12:09'
labels:
  - production
  - operator
  - hardening
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-120 AC#3 hardening (codex): the concurrent_serves_count bound is enforced at serve ADMISSION (a CAS in fabric_libp2p ServeGate::admit_plan, after the request digest is read), so it bounds parsed+admitted serves. The libp2p accept loop (fabric-libp2p/src/swarm.rs ~run_accept_loop) still spawns every accepted inbound /nar stream unconditionally, so a peer that connects and opens streams but does not send an admissible request can create >N pre-admission serve tasks, bounded only by transport connection/substream (yamux) limits. This task adds a true accept-path admission gate (a permit acquired BEFORE spawning the per-stream serve task, released on completion/drop) so the concurrent-serve ceiling also bounds pre-admission accepted streams. Until then the operator marker honestly scopes the bound to 'parsed+admitted serves' and does not claim an accept-path semaphore. Prereq: keep the shared server-owned counter (already added) as the accounting SSOT.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The libp2p /nar serve accept loop acquires an admission permit (N = active profile concurrent_serves_count) BEFORE spawning a per-stream serve task; the N+1th accepted stream is bounded (queued/declined) rather than spawned unconditionally
- [ ] #2 A biting test drives >N concurrent PRE-ADMISSION accepted streams (connect + open stream, no admissible request) and proves at most N serve tasks are live; reverting the accept-path gate reddens it
- [ ] #3 The daemon-core operator marker for concurrent_serves_count is upgraded from 'parsed+admitted serves' to cover accepted streams, matching the new mechanism
<!-- AC:END -->
