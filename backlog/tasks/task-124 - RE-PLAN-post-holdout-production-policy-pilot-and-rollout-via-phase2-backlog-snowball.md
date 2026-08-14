---
id: TASK-124
title: >-
  RE-PLAN: post-holdout production policy, pilot and rollout via
  phase2-backlog-snowball
status: To Do
assignee: []
created_date: '2026-08-10 22:25'
updated_date: '2026-08-14 21:48'
labels:
  - replan
  - production
  - policy
  - wave-2c
  - deferred-pending-202
dependencies:
  - TASK-45
  - TASK-120
  - TASK-123
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Terminal re-plan task, not feature code. Re-invoke phase2-backlog-snowball with PRD.md, TESTING.md, Stage-A diagnostic results, complete Stage-B training artifact, frozen holdout verdict, real-network evidence and operator-journey findings. Create only the next evidence-supported policy implementation, pilot/rollout and release tasks. If upstream-only, LAN-only, consume-only or no adaptive policy wins, make that the product plan rather than manufacturing P2P work.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 TESTING.md and the PRD honest-limits record all winning, losing, unsupported and METRIC_UNUSABLE outcomes before new policy tasks are created.
- [ ] #2 Only holdout-passing defaults become implementation/rollout tasks; rejected adaptive policies are closed or default-disabled and are never tuned against the consumed holdout.
- [ ] #3 The next wave includes the evidence-supported pilot population, rollback/kill criteria, compatibility window, support/runbook and release gate, or explicitly records why no rollout is justified.
- [ ] #4 Every unresolved environment gets no default plus a concrete missing-evidence task; the re-plan does not force one policy across LAN, WAN, CI, home and public-sharing cases.
- [ ] #5 The next experimental wave ends with another self-describing re-plan unless the evidence justifies reclassifying the project as firm.
- [ ] #6 No feature implementation or new benchmark execution occurs inside this task.
- [ ] #7 Every pre-existing deferred candidate (TASK-17,67,74,76,81,92,93,97,98,19,30) is explicitly cancelled/superseded, rescoped with new evidence, or admitted to the new wave with honest dependencies; completion must not blindly unblock them all.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Terminal wave-2c task. It consumes evidence; it must not merely note that evidence exists.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
