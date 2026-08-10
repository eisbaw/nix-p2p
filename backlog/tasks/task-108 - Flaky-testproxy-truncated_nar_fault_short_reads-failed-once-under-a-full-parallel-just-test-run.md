---
id: TASK-108
title: >-
  Flaky: testproxy truncated_nar_fault_short_reads failed once under a full
  parallel just test run
status: Done
assignee: []
created_date: '2026-08-10 14:07'
updated_date: '2026-08-10 21:35'
labels:
  - flaky
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Observed once during the TASK-91 round-6 fix cycle, on the FIRST 'nix develop -c just test' of that cycle. It is NOT related to that change: TASK-91 touches daemon/ only, and crate independence between daemon and testproxy is enforced by a gate.

FAILURE: testproxy/tests/faults.rs:133 - assertion left==right failed, left 0, right 1. So the truncated-NAR fault injected zero short reads where one was expected.

REPRODUCTION: it did NOT reproduce in 3 consecutive isolated runs of 'cargo test -p testproxy --test faults' (7 passed each time), and the next full 'just test' passed. That pattern - green in isolation, red under the full parallel run - is the same shape as TASK-105 and points at a timing/scheduling assumption in the fault harness rather than at the fault logic.

WHAT IS NEEDED
- Reproduce under load, e.g. a loop of the full parallel test run, or the targeted test under artificial CPU contention. Do not close this on 'it passes now'.
- Identify whether the oracle depends on a read arriving in a particular chunking, which is not something a socket guarantees.
- Fix the oracle or the fault so the property is observed at a boundary that does not depend on scheduling.

A flaky negative-feedback gate is worse than a missing one: it trains the reader to re-run rather than to look.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The failure is REPRODUCED deliberately, with the mechanism named - not merely observed once and re-run
- [ ] #2 The oracle observes the truncation at a boundary that does not depend on how the bytes happen to be chunked
- [ ] #3 The full parallel just test run is green across at least 20 consecutive runs after the fix
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CLOSED BY TASK-109 (2026-08-10). Confirmed as a happens-before race, not anything to do with the task-91 cycle it was observed in - the note here that it is unrelated to that change was correct. fault_count() reads the in-process Mutex<Log>, but the proxy pushes its record at proxy.rs:108 AFTER serve() has written the response, so get() can return having fully observed the fault while the server thread has not yet counted it.

At N=20 under load this species (truncated_nar 2, connection_reset 4) was the DOMINANT cause: 6 of 10 failing instances in a measured 45% gate failure rate - not the once-observed curiosity this task recorded. Fixed by await_fault_count/await_stats across 11 sites, which wait for the guaranteed record and then assert the original equality. Re-measured 0/20 at the same N and load.
<!-- SECTION:NOTES:END -->
