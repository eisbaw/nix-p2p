---
id: TASK-128
title: 'FREEZE: generic policy artifact schema and live interpreter before holdout'
status: To Do
assignee: []
created_date: '2026-08-10 22:51'
labels:
  - policy
  - irreversible
  - runtime
  - holdout
  - wave-2c
dependencies:
  - TASK-52
  - TASK-62
  - TASK-100
  - TASK-114
  - TASK-120
  - TASK-125
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Build and freeze the mechanism-neutral executor that will run candidate policies before any holdout is generated or revealed. Parameters are data, not code: the same versioned interpreter must execute upstream-only/static choices, discovery plans, transport/codec selection and the bounded slow-HIT hedge/abort candidates. It may be validated with development/training data only and cannot contain a product default. TASK-44 later fits artifacts; TASK-123 runs those frozen artifacts unchanged.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A versioned typed policy schema represents upstream-only, static mechanism/transport/codec choices, explicit discovery order/parallelism, and bounded abort/hedge/throughput thresholds without embedding tuned values in code.
- [ ] #2 One interpreter executes a supplied artifact live; the mechanism registry only dispatches explicitly selected adapters/offers and contains no hidden Iroh-first, BitTorrent-first or cheapest-first preference.
- [ ] #3 Deterministic golden traces prove identical artifact+observations yield identical decisions, and replay-versus-live parity is checked on development/training scenarios.
- [ ] #4 Unknown schema versions, missing fields, invalid thresholds and unavailable selected mechanisms fail to a named safe fallback within a total deadline; S1/S2 and resource ceilings remain outside policy override.
- [ ] #5 The interpreter records artifact hash, decision inputs, selected action and fallback reason with privacy-safe bounded labels, enough for holdout adjudication without post-hoc inference.
- [ ] #6 No holdout IDs/seeds/topologies are generated or readable, no tuned candidate/default is shipped, and mutation of interpreter semantics changes a pinned version/golden trace before TASK-44 can fit against it.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Closes the fit-to-holdout execution gap. Freeze execution semantics before training fit and before holdout materialization.
<!-- SECTION:NOTES:END -->
