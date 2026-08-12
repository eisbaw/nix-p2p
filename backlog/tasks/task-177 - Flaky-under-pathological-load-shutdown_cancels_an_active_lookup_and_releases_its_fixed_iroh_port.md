---
id: TASK-177
title: >-
  Flaky under pathological load:
  shutdown_cancels_an_active_lookup_and_releases_its_fixed_iroh_port
status: To Do
assignee: []
created_date: '2026-08-12 21:02'
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
- [ ] #1 Root-cause the fixed-iroh-port shutdown/cancellation race (identify whether it is a port re-bind timing window or a lookup-cancel ordering race)
- [ ] #2 Make the assertion load-tolerant without weakening its oracle, or bound it off the real deadline; reproduce only under deliberate heavy load, never as an unbounded stress loop
<!-- AC:END -->
