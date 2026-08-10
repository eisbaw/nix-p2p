---
id: TASK-123
title: >-
  HOLDOUT: adjudicate frozen candidate policy against upstream and best-static
  comparators
status: To Do
assignee: []
created_date: '2026-08-10 22:24'
updated_date: '2026-08-10 22:57'
labels:
  - tournament
  - holdout
  - policy
  - review
  - wave-2c
dependencies:
  - TASK-44
  - TASK-122
  - TASK-128
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
After TASK-44 freezes at most one primary candidate per preregistered deployment profile and TASK-128 freezes execution semantics, generate/reveal and run the untouched holdout exactly once. Compare the primary against upstream-only and the training-selected best-static comparator. Exploratory secondary nominees use a predeclared multiplicity correction and cannot become defaults by winner-picking. Missing evidence fails closed; rejection, upstream-only and no public P2P are useful outcomes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Before reveal, the task records hashes of the candidate policy, training artifact, holdout manifest and best-static comparator plus the predeclared objective, improvement margin, paired confidence method and numeric resource ceilings.
- [ ] #2 The holdout runner verifies no scenario ID/seed/topology appeared in training and that A/A noise is below the declared decision margin; otherwise the verdict is METRIC_UNUSABLE.
- [ ] #3 A candidate passes only if it beats the training-tuned best-static comparator by the declared margin on the primary objective, with zero S1/S2/privacy violations and all latency/resource ceilings satisfied.
- [ ] #4 Missing measurements, unsupported cells or hard-ceiling breaches fail closed; upstream-only, LAN-only, consume-only, a static backend or no public P2P are explicit valid winning outcomes.
- [ ] #5 No holdout-driven tuning occurs. Any change after reveal creates a new policy version and a fresh preregistered holdout; the failed version remains recorded.
- [ ] #6 The signed/versioned verdict names where evidence supports a default and records no default plus a missing-evidence task where it does not.
- [ ] #7 Only after code, interpreter, primary-candidate, training and best-static hashes are frozen, TASK-123 generates the exact holdout IDs/seeds/topologies from TASK-114's versioned procedure using fresh logged randomness; access logs prove no earlier task materialized them.
- [ ] #8 Each profile has one preregistered primary comparison. Any exploratory family uses the predeclared multiplicity correction and cannot promote a secondary to production default without a new policy version and fresh holdout.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
This is the sole gate from tournament evidence to production-policy planning.
<!-- SECTION:NOTES:END -->
