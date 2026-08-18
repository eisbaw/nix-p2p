---
id: TASK-177
title: >-
  Flaky under pathological load:
  shutdown_cancels_an_active_lookup_and_releases_its_fixed_iroh_port
status: Done
assignee: []
created_date: '2026-08-12 21:02'
updated_date: '2026-08-18 06:34'
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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Root cause was a released ephemeral UDP port being exposed to sibling port:0 allocations before the restart oracle ran. Commit eb41f63 uses a cross-process lease on fixed non-ephemeral port 31035, wildcard preflight, a live AddrInUse negative control, and immediate full Iroh restart bounded by the production shutdown deadline. Focused test 1/1, full workspace 1,125 passed, and just e2e 9/9 scenarios passed.
<!-- SECTION:FINAL_SUMMARY:END -->
