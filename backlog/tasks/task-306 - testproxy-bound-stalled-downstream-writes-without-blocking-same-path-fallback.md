---
id: TASK-306
title: 'testproxy: bound stalled downstream writes without blocking same-path fallback'
status: In Progress
assignee: []
created_date: '2026-09-28 22:04'
updated_date: '2026-09-29 20:42'
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

Final default just e2e PASSED 17/17 scenarios in 861.4s on tree fc465ea918a2195d866a7021b66e4e7d0176cfbb, identical implementation/test/config/docs blobs to reviewed full-gate tree 28a32d0b9037bb1547f0cd157d559742bf04127a. Only TASK-305/TASK-306 result/status closeout follows the gate. Required full gate, default gate, parallel reviews and fixed-sample loaded TCP measurement passed; no skipped or failed gate is represented as passing.

TASK-307 image build exposed a repeatability failure in the existing stalled-reader TCP regression under a heavier shared-runner load. Nix checkPhase failed: same-path waiter recv_timeout(6s) expired, overall test8.29s, despite logged downstream write detachment. Prior0/20 with two CPU burners remains accurate for that load only; it does not cover this observed failure. Reopened for test-mechanism diagnosis and renewed negative controls/measurement; no deployment or newcommit authorized by the failedgate.

Architecture review identified coupled timing oracles: 32MiB bulk cache/fsync and artificial4MiB/s pacing competed inside6s, while the waiter also had a hidden10s socket deadline. Prepared separate real-TCP tests: unthrottled stalledreader completion and deterministic truncate-at-zero post-detachment pacing, with a connected-throttle positivecontrol and bounded cleanup. Production behavior unchanged. Fixed20-sample CPUload14 baseline measurement is in progress and has reproduced the original timeout; finalcount pending.

Measured baseline: scripts/flake_rate.py --runs 20 --load-workers 14 with cargo test --locked -p testproxy --test single_flight, pinned reduced-artifact environment. Tree299be723: 17 PASS, 3 TEST_FAILED (samples1,15,17), 0 BUILD_FAILED or HARNESS; observed failure rate3/20 (15%), median9.42s. Each failure logged downstream detachment then the6s waiter timeout. This independently reproduces the Nix image-build failure and supersedes any inference of broad stability from the prior load2 sample.

Revised tests on tree 2dab0a59f68452b573214f330647b1039a29d329: all seven single_flight tests passed; fixed N=20 with load-workers=14 passed 20/20 (140 test executions), zero TEST_FAILED/BUILD_FAILED/HARNESS, median 9.23s, versus the preserved 3/20 baseline failures. Both mutation negatives bit: removing the downstream write timeout failed the stalled-reader test at 31.62s; removing the client_open throttle guard failed the detached-reader test at 65.05s. Source restored after each mutation. Architecture review found no remaining code blocker. Final workspace QA and E2E are still blocked by separately recorded publication/refresh test failures; no new completion claim.
<!-- SECTION:NOTES:END -->
