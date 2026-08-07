---
id: TASK-13
title: 'HARDENING: proxy robustness matrix (fault x depth), header hygiene deep review'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
labels:
  - hardening
dependencies:
  - TASK-6
  - TASK-7
  - TASK-11
  - TASK-12
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-end hardening block, part 1 - runs only against stabilized surfaces (post J1/J2). Enlarge the fault-mode matrix across chain depths (each test-proxy fault mode x depth 1..3), timeout matrix, streaming backpressure under slow consumers, header hygiene audit (what do we forward, strip, must never touch). Deep review pass on daemon HTTP path. Includes any deferred findings phase 3 filed against these surfaces.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Fault x depth matrix implemented and green (or each red documented as a filed bug task)
- [ ] #2 Header hygiene documented in-code and asserted by a test (list of forwarded/stripped headers)
- [ ] #3 Deferred-findings inbox for these surfaces is empty (each closed or converted to a task)
<!-- AC:END -->
