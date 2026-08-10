---
id: TASK-85
title: >-
  Move the transport-agnostic supply/admission types out of transport_iroh into
  their own module
status: To Do
assignee: []
created_date: '2026-08-09 23:03'
updated_date: '2026-08-10 22:27'
labels:
  - forward-carried-from-task-72
dependencies:
  - TASK-72
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FORWARD-CARRIED FROM TASK-72 (mped-architect review, Q5). transport_iroh.rs is now ~1600 lines carrying at least five concerns, and three of them are not about iroh at all:

  * NarSupplier / SupplyError - what a node can regenerate. Transport-agnostic.
  * ServeBudget / ServeDecline / ServeCounters / ServeGate - admission POLICY. A second transport (the PRD keeps a BitTorrent seam open) would either duplicate these or import them from the iroh module, which is the wrong shape either way.
  * IndexNarSupplier - an adapter between availability and the transport, which currently forces transport_iroh to 'use crate::availability::AvailabilityIndex'. The DIRECTION is right (the index stays transport-blind, which its module docs insist on) but a transport that knows what an availability index is, is a transport that has grown a second job.

PROPOSED SHAPE: a supply.rs holding NarSupplier + SupplyError + ServeBudget + ServeCounters + ServeDecline + ServeGate; transport_iroh depends only on the trait and the gate; IndexNarSupplier moves to availability.rs (the module that owns the concrete type it adapts).

WHY IT WAS NOT DONE IN TASK-72: it is a pure move across a surface that had just grown two remotely-triggerable defects, and doing both at once would have made the security-relevant diff unreadable. Do it as a NO-BEHAVIOUR-CHANGE commit, with the test suite green before and after and no edits to the moved bodies.

TRAP: the frozen ALPN const-assert and the IROH_BLOCKS_ALPN cross-check must stay in transport_iroh - they ARE iroh-specific. Do not sweep them along with the rest.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 supply.rs holds the transport-agnostic supply and admission types; transport_iroh no longer imports availability
- [ ] #2 The move is behaviour-preserving: the same tests pass before and after with no edits to any moved function body
<!-- AC:END -->
