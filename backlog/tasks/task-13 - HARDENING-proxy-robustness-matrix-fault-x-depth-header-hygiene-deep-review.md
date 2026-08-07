---
id: TASK-13
title: 'HARDENING: proxy robustness matrix (fault x depth), header hygiene deep review'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-07 22:20'
labels:
  - hardening
dependencies:
  - TASK-6
  - TASK-7
  - TASK-11
  - TASK-16
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-end hardening block, part 1 - runs only against stabilized surfaces (post J1/J2). Enlarge the fault-mode matrix across chain depths (each test-proxy fault mode x depth 1..3), timeout matrix, streaming backpressure under slow consumers, header hygiene audit (what do we forward, strip, must never touch). Deep review pass on daemon HTTP path. Includes any deferred findings phase 3 filed against these surfaces.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Fault x depth matrix (all 7 modes x depth 1..3) green - failures are FIXED in this task; a red row survives only by explicit owner-visible decision, never by silently filing it away (review gate removed the 'or documented' escape)
- [ ] #2 Header hygiene documented in-code and asserted (forwarded/stripped allowlist); gzip Content-Encoding leg and an HTTP/2-upstream leg exercised (harness is otherwise HTTP/1.1-only, the real cache.nixos.org leg is not)
- [ ] #3 Property/fuzz enlargement: narinfo unknown-field fuzz through the chain; path-traversal fuzz on cache keys (..%2f, non-base32, absurd lengths); ENOSPC in both cache layers degrades to passthrough, never serves a partial file
- [ ] #4 deferred-finding label is empty: every deferred finding closed here or converted to an explicit task by owner decision
<!-- AC:END -->
