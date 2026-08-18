---
id: TASK-177
title: >-
  Flaky under pathological load:
  shutdown_cancels_an_active_lookup_and_releases_its_fixed_iroh_port
status: Done
assignee: []
created_date: '2026-08-12 21:02'
updated_date: '2026-08-18 19:19'
labels:
  - flaky
  - test-infra
  - low-priority
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
daemon/tests/iroh_node_lookup.rs:852 shutdown_cancels_an_active_lookup_and_releases_its_fixed_iroh_port flaked ONCE only under pathological ~14-core concurrent load during TASK-173 de-flaking. It does NOT reproduce under normal or mildly-contended load and passed the bounded workspace runs. Likely a fixed-port re-bind / cancellation timing race that only surfaces when the scheduler is saturated. Low priority: does not affect normal CI. Do NOT stress-test to chase it - reproduce only under deliberate heavy load, and if fixed, key any timing bound off the real deadline (as TASK-173 did for fault_loop) rather than a tight wall clock.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Root-cause the fixed-iroh-port shutdown/cancellation race (identify whether it is a port re-bind timing window or a lookup-cancel ordering race)
- [x] #2 Make the assertion load-tolerant without weakening its oracle, or bound it off the real deadline; reproduce only under deliberate heavy load, never as an unbounded stress loop
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-08-18 REOPENED by mandatory TASK-197 QA. Canonical just test reproduced immediate fixed-port restart EADDRINUSE after shutdown returned Graceful, despite the cross-process non-ephemeral lease. Root cause is not port theft: Iroh 1.0.3 drops netwatch UDP sockets through unawaited spawn_blocking close and aborts its actor without a joined socket-close barrier. A pinned upstream-source patch with deterministic blocked-worker regression is in progress; retry/sleep/reuse-port is rejected.

2026-08-18 CLOSED: pinned Iroh 1.0.3 patch makes shutdown cancellation-independent, joins actor/runtime teardown, and waits for managed UDP sockets to close before Endpoint close returns. Six deterministic fixed-port tests saturate blocking workers and prove immediate rebinding without retries, sleeps, SO_REUSEPORT, or weakened assertions. Final lint, build, workspace tests, just e2e (9/9), and just e2e-full (34/34) passed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Root cause was upstream Iroh returning before netwatch UDP close work completed. The exact vendored patch adds an awaited shutdown barrier and deterministic fixed-port regressions; immediate rebind now tests the real lifecycle contract.
<!-- SECTION:FINAL_SUMMARY:END -->
