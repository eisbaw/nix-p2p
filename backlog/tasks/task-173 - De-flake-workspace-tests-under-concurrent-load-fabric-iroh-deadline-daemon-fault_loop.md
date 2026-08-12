---
id: TASK-173
title: >-
  De-flake workspace tests under concurrent load (fabric-iroh deadline + daemon
  fault_loop)
status: To Do
assignee: []
created_date: '2026-08-12 18:12'
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
- [ ] #1 the iroh_node_lookup deadline test drives its deadline off the INJECTED clock (not a real 10ms Instant), or relaxes the 'validated before deadline' assertion so a load-induced early deadline is tolerated
- [ ] #2 fault_mode_loop is made robust to concurrent-load timing (or its timing assumptions documented + bounded), so it does not fail under 'cargo test --workspace'
- [ ] #3 N consecutive full 'cargo test --workspace' runs are green (pin N, e.g. 10)
<!-- AC:END -->
