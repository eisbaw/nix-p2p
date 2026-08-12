---
id: TASK-173
title: >-
  De-flake workspace tests under concurrent load (fabric-iroh deadline + daemon
  fault_loop)
status: Done
assignee:
  - mped
created_date: '2026-08-12 18:12'
updated_date: '2026-08-12 21:12'
labels:
  - testing
  - flaky
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Surfaced during TASK-66 gating (qa-test-runner + orchestrator). 'cargo test --workspace' is not reliably green due to TWO load-sensitive, timing-dependent tests that PASS in isolation and only fail under the parallel load of a full workspace run. Neither is related to the change under test (both were observed while TASK-66 touched only daemon discovery). A strict 'workspace must be green' gate will intermittently trip on these.\n\n1) fabric-iroh lib: iroh_node_lookup::tests::synchronous_replay_validation_cannot_return_success_after_absolute_deadline (fabric-iroh/src/iroh_node_lookup.rs ~L1372-1377). Drives resolve against a real 10ms Instant deadline racing a TCP round-trip + replay validation; under load the 10ms deadline fires before validated_sequence() is recorded -> assert_eq!(validated_sequence(), Some(seq)) sees None. Observed ~1/5 by qa.\n2) daemon integration: fault_mode_loop (daemon/tests/fault_loop.rs). Passed 5/5 isolated; failed once under a full 'cargo test --workspace'.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the iroh_node_lookup deadline test drives its deadline off the INJECTED clock (not a real 10ms Instant), or relaxes the 'validated before deadline' assertion so a load-induced early deadline is tolerated
- [x] #2 fault_mode_loop is made robust to concurrent-load timing (or its timing assumptions documented + bounded), so it does not fail under 'cargo test --workspace'
- [x] #3 N consecutive full 'cargo test --workspace' runs are green (pin N, e.g. 10)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. fabric-iroh: replace the racing 10ms Instant deadline in synchronous_replay_validation_cannot_return_success_after_absolute_deadline. Root cause: 10ms deadline races real loopback TCP+validation; under load the deadline fires at the pre-validation checks (L670/L681) so validated_sequence()==None. The DETERMINISTIC breach mechanism is already the injected SlowSecondClock (50ms sleep on the 2nd/post-validation clock read). Fix: give the real TCP generous headroom (deadline >> loopback RTT) and make the post-validation clock sleep provably exceed the deadline, so the breach lands at L783 with sequence recorded. Keep BOTH assertions strict (kind==Deadline AND validated_sequence==Some). Paused-time (tokio) is incompatible: auto-advance would fire timeout_at during the real TCP read. 2. daemon fault_loop: the fast-fallback bounds already compare vs HARNESS_HEADER_TIMEOUT (task-109) and the latency check is a load-insensitive lower bound; empirically confirm under load whether it still flakes and harden only what actually bites. 3. Prove: nix develop -c cargo test --workspace >=5x under load, report per-run counts. 4. Mutation-prove each oracle still bites.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
RESOLUTION (2026-08-12):

Flake #1 (fabric-iroh iroh_node_lookup deadline) — fixed in commit dedc2d8 (prior increment). Confirmed sound + re-run green in isolation this session. The breach is deterministic via the injected SlowSecondClock (post-validation clock read sleeps POST_VALIDATION_SLEEP=400ms > DEADLINE=300ms), while DEADLINE is generous vs a loopback RTT so the pre-validation network checks never trip under load. Oracle bites (per that commit's mutation record): dropping resolve()'s post-validation deadline guard -> unwrap_err() panics; dropping the validated-sequence recording -> validated_sequence()==None -> assert_eq fails. Left as-is.

Flake #2 (daemon fault_loop fault_mode_loop fast-fallback timing) — fixed in commit 0e6ecfe (daemon/tests/fault_loop.rs). The two fast-fallback asserts (unreachable, connection_reset) previously bounded elapsed at exactly HARNESS_HEADER_TIMEOUT (10s = the upstream header deadline). Now bounded at HARNESS_HEADER_TIMEOUT - FAST_FALLBACK_MARGIN (10s - 2s = 8s), via a new local const FAST_FALLBACK_MARGIN.
  Why load-tolerant: the fast path (proxy 502 / reset, no upstream contacted) returns in MILLISECONDS, so 8s leaves ~8s of slack; scheduler jitter under load moves it by ms-to-hundreds-of-ms, never near 8s. The bound states the real invariant ('failed fast, did not wait the deadline out'), not a claim about how fast the HOST schedules a loopback RTT (the old pre-109 '< 2s' form).
  Why still bites (and better than before): a regression that waits the deadline out elapses to >= HARNESS_HEADER_TIMEOUT (10s), exceeding the 8s bound by the full 2s margin — a robust bite, not the photo-finish at exactly 10s the '< 10s' bound gave (where a header-timeout firing a hair early could slip under).
  GOTCHA / bound rationale: 2s margin is a deliberate midpoint — large enough that a wait-out regression (>=10s) clears it decisively, small enough that the fast path keeps ~8s of jitter headroom. Anything in (fast_path_ms, 10s) works; keying off the deadline makes it self-adjust if HARNESS_HEADER_TIMEOUT changes.
  BITE VERIFIED BY MUTATION: injected tokio sleep of HARNESS_HEADER_TIMEOUT-1s (9s, near the deadline) into the measured window at fault-2 -> test FAILED at fault_loop.rs:225 'failed after 9.001s, within 2s of the 10s upstream header timeout'. Reverted; test green.
  Untouched: the '>= 150ms' lower bound (fault 7, injected latency observable) — a lower bound only tightens under load, so it cannot flake from contention.

Flake #3 (daemon iroh_node_lookup.rs:852 shutdown_cancels_...fixed_iroh_port) — NOT fixed here (extreme ~14-core-load-only, did not reproduce under normal/mild load). Filed as TASK-177 (labels flaky,test-infra,low-priority).

VERIFICATION (bounded per shared-machine constraint): nix develop -c just lint -> exit 0 (clippy/check + cargo fmt --check + ruff + source guards all pass; no fmt needed). Cold build exit 0. Workspace runs under normal-to-moderate load (load avg 5–14, never the pathological 21):
  run1 plain: 582 passed / 0 failed (exit 0)
  run2 plain: 582 passed / 0 failed (exit 0)
  run3 plain + ONE concurrent 'cargo test -p daemon' (mild contention): workspace 582/0, concurrent daemon 343/0 (both exit 0)
  run4 plain: 582 passed / 0 failed (exit 0)
  No fault_mode_loop or synchronous_replay_validation failures in any run.
HONESTY: 4 bounded green runs cannot prove absolute flake-freedom; AC#3's original 'N=10' was intentionally capped at <=5 runs under the shared-machine no-stress constraint. This is the strongest evidence permitted here for the two NAMED flakes.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
De-flaked both named load-sensitive tests. Flake #1 (fabric-iroh deadline) fixed in dedc2d8 (confirmed sound + green). Flake #2 (daemon fault_loop fast-fallback) fixed in 0e6ecfe: bound now = HARNESS_HEADER_TIMEOUT - FAST_FALLBACK_MARGIN (10s-2s=8s) — load-tolerant (ms-scale fast path, ~8s slack) yet still bites (mutation: 9s near-deadline sleep -> assert fires). 4 bounded workspace runs 582/0 (+1 concurrent daemon run 343/0) under normal-to-moderate load; lint exit 0. Extreme-load-only 3rd flake filed as TASK-177. Bounded runs can't prove absolute flake-freedom (shared-machine no-stress cap).
<!-- SECTION:FINAL_SUMMARY:END -->
