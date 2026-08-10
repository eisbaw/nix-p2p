---
id: TASK-105
title: 'Flaky: store_residency_oracle failed once under a full parallel just test run'
status: To Do
assignee: []
created_date: '2026-08-10 12:25'
labels: []
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Observed during TASK-91's final gate run on 2026-08-10: `just test` exited 101 with `error: test failed, to rerun pass `-p daemon --test store_residency_oracle``.

NOT REPRODUCED in 7 subsequent runs (5 isolated `cargo test --test store_residency_oracle`, all 3/3 green in ~0.6 s; 2 full `just test` runs, both exit 0). The failing assertion text was NOT captured - only the tail of the run was kept - which is the first thing to fix if this recurs.

WHY IT IS PLAUSIBLY REAL AND NOT NOISE TO IGNORE: this suite reasons about MEMORY (peak RSS vs what the blob store says it HOLDS). cargo runs test binaries in parallel, so a residency/RSS assertion can be perturbed by whatever else is resident on the machine at that moment. If the oracle has any dependence on process-level RSS rather than purely on the store's own accounting, that dependence is a flake generator - and worse, it is the same class of confusion (peak RSS is not residency) that the suite exists to prevent.

Task-91 did not touch this area (it changed claim/discovery/availability query shapes, not the transport, the blob store or any RSS path), so this is recorded as pre-existing rather than introduced.

Related: TASK-34 is a different flaky test (testproxy connection_reset_fault_yields_no_response).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The failing assertion is identified and either made insensitive to co-scheduled load or given a stated, justified tolerance - a retry loop is not an acceptable fix for a memory oracle
- [ ] #2 The suite is run under deliberate memory pressure / parallel load and stays green, so the fix is demonstrated rather than assumed
<!-- AC:END -->
