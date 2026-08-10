---
id: TASK-84
title: >-
  cargo test --workspace flaked once under load after task-72 added a heavier
  test binary
status: Done
assignee: []
created_date: '2026-08-09 22:24'
updated_date: '2026-08-10 21:35'
labels:
  - flake
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OBSERVED ONCE, 2026-08-10, during task-72. testproxy/tests/premature_eof.rs failed with 'testproxy: upstream fetch failed for /nar/x.nar: Connection reset by peer (os error 104)' during a full 'just test'. It passed in isolation immediately afterwards, and two subsequent full 'just test' runs were green (26 test binaries, all ok).

WHY IT IS WORTH A TASK RATHER THAN A SHRUG: task-72 added daemon/tests/serve_budget_and_supply.rs, which is materially heavier than anything else in the suite - it allocates 64 MiB payloads and spawns real iroh endpoints (one test runs 8 concurrent clients). cargo runs test BINARIES in parallel, so it now competes with socket-based tests in testproxy. A suite that fails one run in three for reasons unrelated to the change under test is a suite people stop believing.

WHAT TO ESTABLISH FIRST (do not 'fix' by retrying):
  * whether the failure is CPU starvation, ephemeral-port/backlog pressure, or memory. 'Connection reset by peer' on a localhost accept usually means the listener's backlog overflowed or the process was descheduled past a client timeout.
  * whether it reproduces under a deliberate load (e.g. run the suite with --test-threads high while a stress load runs).

CANDIDATE REMEDIES, in order of preference: make testproxy's test server's accept path robust to a slow accept (fix the product/fixture, not the schedule); reduce the new tests' payload from 64 MiB (it is sized to dominate the ~20 MiB process floor, so it cannot go much below ~32 MiB without weakening the assertion); or mark the heavy tests to run in their own pass. Retrying is not a remedy.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The failure mode is REPRODUCED deliberately and named (starvation vs backlog vs memory) before any change is made
- [ ] #2 The chosen remedy is justified against the reproduction, and 'retry on failure' is not it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CLOSED BY TASK-109 (2026-08-10). The symptom recorded here - premature_eof.rs failing with 'upstream fetch failed: Connection reset by peer' during a full just test, passing in isolation immediately after - is task-109's species D, and its cause is NOT task-72's heavier binary. The fake origin in premature_eof.rs drained the request head with ONE read() and then closed the socket; under load it closed while the proxy was still writing its request, so the proxy took ECONNRESET/EPIPE. The origin, not the proxy, was breaking the protocol.

This was not a one-off: at N=20 under 14 CPU burners it failed 3 times, the second-largest contributor to a measured 45% gate failure rate. Fixed by draining to the CRLFCRLF terminator, plus tightening the assertion that had been misattributing the resulting 502 to cache poisoning. Re-measured 0/20 at the same N and load.
<!-- SECTION:NOTES:END -->
