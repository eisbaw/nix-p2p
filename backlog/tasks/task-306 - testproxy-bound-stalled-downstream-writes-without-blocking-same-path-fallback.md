---
id: TASK-306
title: 'testproxy: bound stalled downstream writes without blocking same-path fallback'
status: In Progress
assignee: []
created_date: '2026-09-28 22:04'
updated_date: '2026-09-28 22:59'
labels:
  - testproxy
  - e2e
  - regression
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-305 full E2E exposed a pre-existing SIGSTOP failure reproduced on b980fac: the frozen daemon leaves its upstream TCP socket open, testproxy blocks writing while holding the per-path single-flight lease, and the Nix fallback waits on that lease until its own timeout. TASK-23 bounded upstream reads but not downstream writes. Repair the fixture, preserving one upstream fetch, atomic cache integrity and unchanged Nix fallback assertions.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Baseline crash-sigstop-stall reproduces the same failure; a real TCP stalled-reader regression fails before repair.
- [x] #2 A configurable nonzero downstream write-idle bound detaches stalled egress while the original upstream fetch completes and commits; disconnected clients no longer throttle shared cache fill.
- [x] #3 Concurrent same-path client receives exact complete bytes with one origin fetch while stalled reader remains open; progressing-reader control and existing integrity/coalescing tests pass.
- [ ] #4 Unchanged real-Nix SIGSTOP fallback, NarHash and 32-second assertions pass; required review and E2E gates pass without bypasses.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Baseline b980fac: crash-sigstop-stall FAIL 4/7 checks in 38.3s, same three failed assertions as TASK-305 tree. Both URLs timed out; no complete fallback NAR. Proxy and scenario source identity verified. Architecture and QA reviewed root-cause repair plan; no daemon timeout-policy change.

Real TCP red proof on tree c43c8f58f00875bccd6e521138a66c4ab9728d47: stalled_reader_does_not_block_single_flight_cache_completion failed with waiter Timeout (exit 101, 14.35s). After downstream write bound and dead-reader detach, tree 8465a017d0db60c4f8f3e803ddef158f7e4a6332 passed all testproxy tests: 57 passed, 0 failed, 1 explicitly ignored. Final deterministic origin-gated overlap strengthening and full required gates are still being checked; no completion claim yet.

Final gated TCP regression and all QA passed on staged tree 28a32d0b9037bb1547f0cd157d559742bf04127a. Parallel architecture review found no blocking issue. Remote pinned just lint passed all 21 stages; just test passed both builds, 1384 Rust tests, 0 failures, 12 explicit ignores, plus Python and real-Nix checks. Environment: CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0; nix develop --max-jobs 1 --cores 2 -c just lint / just test. Required Podman full gate remains in progress.

Real Nix SIGSTOP regression PASSED unchanged success/NarHash/full-payload/32-second predicates: recovery exit 0 after 14.3s, proxy detachment witnessed, 8/8 checks (30.1s including setup). Required just e2e-full passed 47/47 scenarios in 1711.1s on tree 28a32d0b9037bb1547f0cd157d559742bf04127a. Fixed N=20/load-workers=2 single_flight measurement and default pre-commit just e2e remain pending. The separate earlier concurrency-soak miss is not attributed to this repair.

Required repeatability measurement PASSED on unchanged tree 28a32d0b9037bb1547f0cd157d559742bf04127a: scripts/flake_rate.py --runs 20 --load-workers 2 --out /tmp/task-306-single-flight-flake -- cargo test --locked -p testproxy --test single_flight, inside the pinned reduced-artifact environment above. All 20 samples PASS, 0 TEST_FAILED, 0 BUILD_FAILED, 0 HARNESS errors; each runs six parallel integration tests including both new TCP controls (120 test executions). Observed failure rate 0/20 under two CPU burners; median 4.4948s. This scoped measurement does not measure the Podman soak or broad-suite rate, which remains unmeasured.
<!-- SECTION:NOTES:END -->
