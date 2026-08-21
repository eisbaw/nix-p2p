---
id: TASK-295
title: >-
  Deep isolation bites: production identify-handler event->Kad bite +
  multi-mitigation system RED
status: To Do
assignee: []
created_date: '2026-08-21 04:41'
labels:
  - hardening
  - testing
  - follow-up
dependencies:
  - TASK-282
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deferred-as-hard residuals from the TASK-282 AC#1 codex audit (the genuinely difficult bites; codex itself flagged them as hard). (1) The identify receive-gate is unit-covered only at the pure helper (fabric-libp2p/src/swarm.rs helper tests), NOT at the production event handler (swarm.rs:2505 where an Identify event feeds admitted addresses to Kad). Mutating the handler to pass confined=false or to iterate info.listen_addrs instead of admitted leaves the helper tests green while cross-scope addresses enter Kad. Need a test at the handler boundary that reddens on that mutation - hard because it is inside the swarm event loop and P never establishes a transport connection to a cross-scope peer in the current topology (kad wont route v1). (2) The isolation-bridge system RED currently comes from a SINGLE scope-split revert (reddens KEY + END-TO-END); DIAL/identify have no demonstrated MULTI-mitigation system RED. Build a topology/harness where reverting the DIAL veto (or identify gate) alone produces an attributable system RED.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A test reddens when the PRODUCTION identify handler (swarm.rs:2505) is mutated to admit cross-scope/global addresses (confined=false or listen_addrs instead of admitted) - i.e. the bite observes the real event->Kad wiring, not a pure helper.
- [ ] #2 The isolation-bridge e2e has a DIAL-mitigation (and/or identify-mitigation) single-revert system RED that is attributable to that specific mitigation, not only the scope-split.
<!-- AC:END -->
