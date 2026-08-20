---
id: TASK-292
title: >-
  Make announce allocate->commit an atomic per-key sequence reservation (or pin
  the disjoint-ownership invariant)
status: To Do
assignee: []
created_date: '2026-08-20 23:58'
labels:
  - hardening
  - durability
  - follow-up
dependencies:
  - TASK-285
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Architecture note from the TASK-285 round-3 Mark-emulator read (codex did not raise it). In the announcer, next_sequence (allocate, a lock-free read at the caller, daemon-libp2p/src/lib.rs ~833) and advance+persist_checked (commit, under DurableSeqFloor's lock) are NOT one atomic reservation. Two concurrent announces for the SAME key could both read sequence N, both sign a record at N, and both advance(key,N) -> two distinct records tied at one sequence, neither superseding the other. SAFE TODAY only because the seed-vs-grown disjoint-ownership invariant (the TASK-279 seed_owned no-op + the sequential re-sign loop) guarantees no same-key concurrency; the floor's own locking does not. Preempt a future same-key concurrent announce path.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Either (a) allocate+commit become one atomic per-key critical section so two concurrent same-key announces cannot tie a sequence, OR (b) the disjoint-ownership invariant is documented as LOAD-BEARING at both the DurableSeqFloor seam and every announce call site, with a guard/assert that fires if a same-key concurrent announce is ever introduced.
<!-- AC:END -->
