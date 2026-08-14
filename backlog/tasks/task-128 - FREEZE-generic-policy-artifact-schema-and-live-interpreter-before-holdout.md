---
id: TASK-128
title: 'FREEZE: generic policy artifact schema and live interpreter before holdout'
status: To Do
assignee: []
created_date: '2026-08-10 22:51'
updated_date: '2026-08-14 21:48'
labels:
  - policy
  - irreversible
  - runtime
  - holdout
  - wave-2c
  - deferred-pending-202
dependencies:
  - TASK-52
  - TASK-62
  - TASK-100
  - TASK-114
  - TASK-120
  - TASK-125
priority: low
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
- [ ] #7 Before any Stage-B calibration, freeze and hash the causal decision-trace schema, replay interpreter, complete bounded JCS planning catalog for each of the three selectable profiles, exact numeric planning-injection contract, and linked-coordinate solver. Each catalog has at most 16 fully specified selector/hyperparameter artifacts crossed with every capable best-static comparator; families, ranges, training-filled values, comparator substitution, and post-calibration selector invention are forbidden, and any semantic or catalog mutation creates a new experiment version.
- [ ] #8 Development parity qualification covers every frozen dynamic selector across the four preregistered scenario classes with distinct independently fresh A1 and A2 live executions, each compared only with replay of its matching base-arm-label trace. Static one-arm selectors are exempt. The fixed parity catalog and result hashes are inputs to TASK-122; failed parity makes every contrast containing that selector ineligible.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Closes the fit-to-holdout execution gap. Freeze execution semantics before training fit and before holdout materialization.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
