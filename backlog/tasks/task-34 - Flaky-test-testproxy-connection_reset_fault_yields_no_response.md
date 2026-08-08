---
id: TASK-34
title: 'Flaky test: testproxy connection_reset_fault_yields_no_response'
status: To Do
assignee: []
created_date: '2026-08-08 16:53'
labels:
  - deferred-finding
dependencies:
  - TASK-2
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Noted during task-11 (not caused by it): testproxy/tests/faults.rs::connection_reset_fault_yields_no_response intermittently fails, passes on rerun. A flaky test erodes gate trust (a real failure looks like flake, a flake blocks a good commit). Diagnose the race (likely a timing assumption on when the reset lands vs when the client reads) and make it deterministic or mark+fix.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Root cause identified (the timing race)
- [ ] #2 Test made deterministic - runs green 20x in a row
<!-- AC:END -->
