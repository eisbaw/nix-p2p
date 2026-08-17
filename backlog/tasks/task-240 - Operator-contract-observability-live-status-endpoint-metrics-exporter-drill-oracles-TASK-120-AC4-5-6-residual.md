---
id: TASK-240
title: >-
  Operator-contract observability: live --status endpoint + metrics exporter +
  drill oracles (TASK-120 AC#4/#5/#6 residual)
status: To Do
assignee: []
created_date: '2026-08-17 03:19'
labels:
  - operator
  - observability
  - production
  - follow-up
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-120 (Done) delivered the operator-contract SAFETY CORE runtime-enforced. Three observability ACs are Partial (renderers + vocabulary exist + are unit-tested; the live wiring is pending): AC#4 a live --status endpoint fed by RUNNING node state (real bootstrap health, holder counts, direct/relay path, current budget use, miss-vs-unavailable) - the OperatorStatus renderer + StatusInputs exist; wire them to a running node query. AC#5 a live metrics exporter that APPLIES the PrivacyPolicy redaction + bounded-cardinality MetricLabel vocabulary (both exist) to real emitted metrics. AC#6 the four operational drill ORACLES (restart / dependency-outage / exhausted-budget / kill-switch) as executable e2e/VM assertions that yield actionable health while the S2 additive invariant holds. Integers only; no frozen-wire change; do not weaken the fail-safe defaults. Relates TASK-45 (fresh-host operator journey).
<!-- SECTION:DESCRIPTION:END -->
