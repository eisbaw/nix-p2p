---
id: TASK-133
title: REVIEW decentralized global Iroh discovery before LAN
status: To Do
assignee: []
created_date: '2026-08-11 05:43'
updated_date: '2026-08-11 19:52'
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
priority: high
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
