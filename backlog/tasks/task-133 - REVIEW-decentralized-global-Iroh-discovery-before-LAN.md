---
id: TASK-133
title: REVIEW decentralized global Iroh discovery before LAN
status: To Do
assignee: []
created_date: '2026-08-11 05:43'
updated_date: '2026-08-14 18:22'
labels:
  - iroh
  - discovery
  - global
  - review
  - architecture
  - qa
  - docs
  - wave-2c
dependencies:
  - TASK-132
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Independently review the exact TASK-89 TASK-103 and TASK-132 implementation and evidence tree before LAN. This task adds no mechanism. It verifies that the production journey uses decentralized exact-key NAR-to-provider discovery with tracker disabled and that peer address resolution transfer privacy deadlines and documentation remain distinct and honest. Only a passing reviewed artifact can flow to TASK-136.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Parallel mped-architect and qa-test-runner reviews examine the exact final implementation and evidence tree and all blocking findings are fixed and re-reviewed.
- [ ] #2 Replay proves exact NarSize peer bytes zero upstream NAR body positive peers-disabled contrast cold run-unique DHT state daemon publications no injected locators no tracker and no LAN with biting mutations.
- [ ] #3 Review verifies no single tracker registry bootstrap node or operator is required and checks bootstrap loss partition rejoin multi-provider withdrawal expiry outage fallback and restart results against frozen deadlines.
- [ ] #4 PRD README TESTING runtime status and backlog consistently distinguish NAR-to-provider discovery NodeId-to-address discovery transport and optional tournament comparators.
- [ ] #5 Any feature fix is a separately implemented reviewed dependency and forces affected TASK-132 scenarios and mutations to rerun on the fixed tree.
- [ ] #6 Emit global-iroh-review-v1 pass bound to final tree TASK-132 evidence reviewer verdicts and mutation results. Missing dirty mismatched tracker-substituted or no-go inputs fail closed.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
COMPASS backlog surgery 2026-08-13 (F3): DEFERRED-STACK. Per PRD Wave-2c the PRODUCTION stack is libp2p-PRIMARY (iroh OPTIONAL). The production-qualifying DECENTRALIZED-DISCOVERY gate is therefore the LIBP2P one — already proven by the landed routed-separate-netns e2e (TASK-179) + the multi-daemon container journey (TASK-161), both Done. This task certifies the OPTIONAL iroh global-discovery path (the tournament arm), so it must NOT consume primary-cornerstone budget: lowered to Medium and marked deferred-stack. Revisit only when the iroh transport tournament is actually run (needs the budget-freeze + evidence forge-resistance TASK-187).

COHERENCE REFRAME 2026-08-14 (COMPASS flag 2 / TASK-202): this is an IROH-framed task. Under the PRD Wave-2c authority (libp2p-PRIMARY) and the now-PROVEN libp2p-kad decentralized discovery (TASK-103 MVP Done + TASK-159 resolution + TASK-179 routed netns), the PRODUCTION decentralized-discovery gate is the LIBP2P path (TASK-103 -> 191 -> 194, all Done), NOT iroh. So this task is OPTIONAL-TRANSPORT REFERENCE (an iroh comparison arm), not the production gate its title/framing implies. OWNER DECISION (COMPASS fork point, not mine to make): whether iroh remains a FUNDED transport/tournament arm at all determines this task's priority — if iroh is deprioritized under libp2p-primary, demote accordingly. Left priority unchanged pending that product call. The PRD execution-order prose (§693-734, 'GLOBAL-IROH GATE') still reads as iroh-first and needs owner-reviewed reconciliation to Wave-2c (that PRD-prose edit is TASK-202, owner-review-gated).
<!-- SECTION:NOTES:END -->
