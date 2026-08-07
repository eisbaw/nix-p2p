---
id: TASK-14
title: 'HARDENING: concurrency soak + docs truthfulness sweep'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-07 22:20'
labels:
  - hardening
dependencies:
  - TASK-13
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-end hardening block, part 2. Soak: max-substitution-jobs=16 storm of parallel substitutions through the chain (architect round-2: sixteen concurrent requests is Nix default reality), plus restart-under-load. Docs: README quickstart executed verbatim on a clean machine/container; TESTING.md checked against what the harness actually does; stale claims fixed or deleted (repo cruft policy).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Concurrency soak parameterized by client knobs (TESTING.md): max-substitution-jobs and http-connections swept over {1, 16, 128}; at each point: no deadlock, fd/memory bounds asserted, S1 holds; restart-under-load recovers; results reported per knob value
- [ ] #2 Same-path dogpile at the harshest swept setting (128 jobs): concurrent cold-cache requests for ONE large NAR -> single upstream fetch (or explicitly documented safe alternative); never a partial/corrupt byte served
- [ ] #3 README quickstart executed verbatim in a clean container - every command works as written; TESTING.md drift corrected in the same commit
<!-- AC:END -->
