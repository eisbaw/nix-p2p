---
id: TASK-250
title: Post-holdout real multi-network field pilot and rollout decision
status: To Do
assignee: []
created_date: '2026-08-18 06:38'
updated_date: '2026-08-18 20:36'
labels:
  - pilot
  - measurement
  - prd
  - field-trial
  - decision
dependencies:
  - TASK-120
  - TASK-124
  - TASK-237
  - TASK-249
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Execute the real multi-network field pilot defined by TASK-124 for the exact policy/no-policy outcome adjudicated by TASK-123. This task validates operational rollout and real-network external validity; it cannot replace, reinterpret, tune against, or promote a candidate rejected or absent in the frozen holdout verdict. TASK-237 contributes development-only planning inputs, TASK-120 the authoritative operator UX/budgets, and TASK-249 bounded relay-churn behavior. Upstream-only, consume-only, LAN-only, limited rollout, or no rollout remain valid outcomes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Nodes run released/shippable configuration with operator profiles and ordinary bootstrap only; no provider address, per-content locator, relay address, claim, test-only delay, or synthetic holder placement is injected into scored rows.
- [ ] #2 Every scored row preserves S1, bounded S2, the owner-reviewed TASK-120 profile budgets, privacy constraints, and the frozen latency guard. Any hard-constraint violation triggers the preregistered stop or no-go path rather than being averaged away.
- [ ] #3 Before outcome observation, the preregistered manifest binds the exact TASK-123 verdict and TASK-124 rollout-plan hashes, selected policy or terminal no-candidate outcome, real independently operated nodes across multiple network/failure domains, workload/population, warm-up/steady-state definition, sample-size rationale, stop/rollback rules, support owner, and operator-UX journey. It contains no new candidate tuning or holdout reinterpretation.
- [ ] #4 The field result evaluates only TASK-124 frozen pilot objectives, margins, hard constraints, kill criteria, and rollout scope. Cache-egress reduction is primary only when that selected plan says so; a field mismatch triggers the predefined rollback/rework/new-policy-version path and never promotes a holdout-rejected or unvalidated alternative.
- [ ] #5 The signed/content-hashed decision package cross-references TASK-123/TASK-124, records raw restricted evidence, a privacy-safe operator-facing summary, exact code/config/topology hashes, deviations and rollback events, and one allowed rollout disposition. It explicitly distinguishes holdout policy validity from field operational/external-validity evidence.
- [ ] #6 Execution follows exactly the TASK-124 matrix. For a holdout-validated P2P policy it independently records cache payload egress, symmetric peer socket/application octets, source attribution, latency, resources, failures/fallbacks, paths, churn, privacy, and UX. For no-candidate/upstream-only/LAN-only/consume-only outcomes, inapplicable P2P rows remain witnessed no-execution and cannot be resurrected.
- [ ] #7 The scored operator journey covers install/profile selection, precise invalid-config errors, preflight, local health/status, effective budget and queue use, dependency/fallback explanation, privacy-safe diagnostics, kill switch, rollback, and recovery on the released configuration; support-facing and normal-user output are separately reviewed.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Downgraded 2026-08-18 (COMPASS F7): depends on TASK-124 (Low, post-holdout tournament re-plan), so it is unreachable while the tournament is deprioritized.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Independent evidence review, operator sign-off, QA/architecture review of any code changes, and all applicable just gates pass.
<!-- DOD:END -->
