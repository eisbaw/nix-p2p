---
id: TASK-123
title: >-
  HOLDOUT: adjudicate frozen candidate policy against upstream and best-static
  comparators
status: To Do
assignee: []
created_date: '2026-08-10 22:24'
updated_date: '2026-08-14 21:48'
labels:
  - tournament
  - holdout
  - policy
  - review
  - wave-2c
  - deferred-pending-202
dependencies:
  - TASK-44
  - TASK-122
  - TASK-128
  - TASK-129
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
After TASK-44 freezes at most one primary candidate per selectable profile, TASK-128 freezes execution semantics, and TASK-129 emits one terminal validation slot per selectable profile, generate/reveal and run the untouched holdout exactly once. Compare each validated primary against upstream-only and its training-selected best-static comparator. No-go and no-candidate slots execute nothing. Missing evidence fails closed; rejection, upstream-only, LAN-only, consume-only and no public P2P are useful outcomes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The holdout runner verifies no scenario ID/seed/topology appeared in training and that A/A noise is below the declared decision margin; otherwise the verdict is METRIC_UNUSABLE.
- [ ] #2 Missing measurements, unsupported cells or hard-ceiling breaches fail closed; upstream-only, LAN-only, consume-only, a static backend or no public P2P are explicit valid winning outcomes.
- [ ] #3 No holdout-driven tuning occurs. Any change after reveal creates a new policy version and a fresh preregistered holdout; the failed version remains recorded.
- [ ] #4 The signed/versioned verdict names where evidence supports a default and records no default plus a missing-evidence task where it does not.
- [ ] #5 Verify exactly one TASK-129 validation-slot artifact for each selectable profile. Execute holdout rows only for validated slots; validation_no_go and no_candidate remain terminal witnessed outcomes with no reassignment, runner-up substitution, or narrowing of the three-profile multiplicity family.
- [ ] #6 Before reveal, record hashes for the code, contract, training artifact, TASK-129 slot artifacts and every present candidate/comparator reference, plus the preregistered objective, improvement margin, paired confidence method and numeric resource ceilings. Absent references forbid candidate/comparator hashes. Record the generated holdout manifest hash only during the atomic TASK-123 reveal protocol.
- [ ] #7 Only after all required frozen hashes and exactly three valid TASK-129 slot artifacts exist may TASK-123 atomically generate the exact holdout IDs/seeds/topologies from the TASK-114 procedure using fresh logged randomness. Access logs prove no earlier task materialized them; absent candidate/comparator references remain unhashed and cause no profile execution.
- [ ] #8 A validated candidate passes only if it beats the A1-selected frozen best-static comparator by the declared margin on the primary objective, with zero S1/S2/privacy violations and all latency/resource ceilings satisfied.
- [ ] #9 Each of the three selectable profiles has one preregistered primary comparison or a terminal no-go/no-candidate slot. Any exploratory family uses the predeclared multiplicity correction and cannot promote a secondary to production default without a new policy version and fresh holdout.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
This is the sole gate from tournament evidence to production-policy planning.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
