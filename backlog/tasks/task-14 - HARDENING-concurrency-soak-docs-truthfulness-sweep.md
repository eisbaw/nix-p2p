---
id: TASK-14
title: 'HARDENING: concurrency soak + docs truthfulness sweep'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
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
- [ ] #1 16-parallel substitution soak green: no deadlock, no fd/memory runaway (bounds asserted), all S1 checks pass under load
- [ ] #2 README quickstart reproduced verbatim in a container; every command works as written
- [ ] #3 TESTING.md matches implemented reality; drift corrected in the same commit
<!-- AC:END -->
