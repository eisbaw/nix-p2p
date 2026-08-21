---
id: TASK-297
title: >-
  DeriveBudget per-PeerId amplification cap is NOT live on the shipped
  daemon-libp2p /nar serve path
status: To Do
assignee: []
created_date: '2026-08-21 07:04'
labels:
  - hardening
  - security
  - dos
  - follow-up
dependencies:
  - TASK-282
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found during TASK-282 AC#5 (adversarial breadth): the shipped daemon-libp2p binary sets derive_ledger: None (daemon-libp2p/src/main.rs:~2125), so the per-auth-PeerId DeriveBudget amplification cap (TASK-229/243) is NOT charged on the shipped /nar serve regenerate path. Only ServeBudget's 256 MiB per-serve size-decline is live there. So a hostile peer can drive repeated regenerate work on the serve path without the intended per-PeerId amplification bound. Within the 'hostile peer costs a bounded retry' TCB this is a DoS/availability concern, not integrity - but the intended bound is simply not on the wire, so an adversarial oracle for it cannot be written (AC#5 correctly deferred it rather than attack a non-live bound). Reconcile with TASK-229/243 (which specified charging DeriveBudget on this exact path) - this may be their unwired residual.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The per-PeerId DeriveBudget cap is charged on the shipped daemon-libp2p /nar serve regenerate path (derive_ledger wired, not None), so repeated regenerate work from one auth PeerId is bounded.
- [ ] #2 An adversarial e2e oracle bites the cap: a hostile peer exceeding the per-PeerId budget is refused, attributable to the budget (revert the charge -> unbounded -> RED). Coordinates TASK-282 AC#5 amplification arm.
<!-- AC:END -->
