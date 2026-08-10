---
id: TASK-105
title: 'Flaky: store_residency_oracle failed once under a full parallel just test run'
status: To Do
assignee: []
created_date: '2026-08-10 12:25'
updated_date: '2026-08-10 13:11'
labels: []
dependencies: []
priority: high
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## REPRODUCED WITH FULL ASSERTION TEXT (qa-test-runner, 2026-08-10). Priority raised Low -> High.

REPRODUCTION MATRIX:
  60 isolated runs                          0 failures
  40 runs pinned to 2 CPUs                  0 failures
  25 runs pinned to 1 CPU                   0 failures
  8 CONCURRENT PROCESSES x 8 ROUNDS (64)   13 FAILURES, all exit 101
  the same 64 runs with --test-threads=1    0 failures

TWO DISTINCT ASSERTION SITES, both in daemon/tests/store_residency_oracle.rs:
  Site 1 - line 208, the anti-vacuity control (12 of 13):
    'resident memory rose by 12111872 B after seeding a 33554544 B payload and dropping our own copy -
     the store's copy did not become resident, so this test would be comparing nothing'
    Observed rises: 12.1 13.6 15.2 15.8 16.1 18.1 19.1 19.9 20.0 23.8 23.9 25.1 MB, against a required
    30.2 MB (nar_len/10*9).
  Site 2 - line 398 (1 of 13):
    'the peak-RSS oracle must (wrongly) say HELD after a genuine release', VmRSS baseline 156,418,048 B -
    the baseline had already absorbed a sibling test's payload, so hwm_baseline was saturated and the
    payload no longer moved the peak.

ROOT CAUSE: vm_bytes() (line 105) reads /proc/self/status - a WHOLE-PROCESS figure - while all three
tests in that binary run concurrently in the SAME process under libtest's default parallelism, each
allocating and freeing ~32 MiB. The tell is visible even in PASSING runs: test B prints
'VmRSS baseline = 120311808 B, seeded = 80523264 B' (baseline HIGHER than seeded) and
'allocator returned = 298.4% of the payload' / '-1.0%'. A baseline containing another test's payload is
not a baseline.

MECHANISM CORRECTION - this task's description was WRONG: it says 'cargo runs test binaries in
parallel'. It does not. Cargo runs test TARGETS sequentially; libtest parallelizes WITHIN a binary.
This matters for the fix: TASK-91's two new test binaries added NO concurrent load to that process, so
the trigger is intra-binary parallelism plus host-level page reclaim, not the added targets.

PRE-EXISTING, NOT CAUSED BY TASK-91 (verified: the commit range touches neither
store_residency_oracle.rs nor transport_iroh.rs nor any residency path). The implementer's
'pre-existing' verdict was right; the reasoning it recorded for it was not.

FIX CAUTION (AC#1 already forbids papering over): --test-threads=1 DIAGNOSES the cause, it is not
automatically an acceptable fix. The deeper defect is that line 208 asserts on VmRSS, which the kernel
may reclaim at any moment for reasons unrelated to any test. A per-test process, a serialized mutex
around the residency tests, or an oracle that does not rest on whole-process RSS are the real options.

AND: '3/3 green' is not evidence of determinism. QA got 3 clean just test runs and then reproduced 13
failures under load.
<!-- SECTION:NOTES:END -->
