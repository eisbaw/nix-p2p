---
id: TASK-202
title: >-
  PRD reconciliation: Iroh-first execution order (§693-734) contradicts
  libp2p-primary Wave-2c authority (§575+)
status: To Do
assignee: []
created_date: '2026-08-14 08:24'
updated_date: '2026-08-14 21:49'
labels:
  - doc
  - direction
  - tech-debt
  - keystone
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
COMPASS 2026-08-14 domain-coherence flag. The PRD's Wave-2c reconciliation (§575+, the stated CURRENT authority) makes libp2p-kad the mandatory content-discovery gate and iroh an OPTIONAL transport with NO content DHT (iroh has no get_providers). But the 'Iroh-first execution order' subsection (§693-734) and its gate tasks — TASK-132/133 ('GLOBAL-IROH GATE decentralized NAR and peer discovery'), TASK-136, and the TASK-87/88 iroh measurement gates — still read as though IROH is the discovery+measurement PRODUCTION gate. Content discovery over iroh is a category error under Wave-2c. TASK-147 was meant to reconcile this but the execution-order subsection still contradicts. Muddy concept -> muddy sequencing ('what is the production gate?' is ambiguous). SCOPE (doc-only, owner-reviewed — PRD authority sections are high-stakes, show the diff and confirm before editing): re-point the decentralized-discovery production gate at TASK-103/libp2p-kad; demote TASK-87/88/132/133/136 to OPTIONAL-transport reference status (not the production gate); make 'the production gate is libp2p-kad discover -> libp2p-stream fetch -> byte-identical (TASK-103->191->194)' unambiguous. Also decide (owner product call) whether iroh remains a funded tournament arm at all given it has no content DHT — that decides TASK-201/87/88/125-iroh-arm priority.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
AUTONOMOUS BACKLOG PART DONE 2026-08-14: re-pointed TASK-155's stale iroh dep (132 -> 103); appended coherence-reframe notes to the iroh-framed gate tasks 132/133/87/88 (they are optional-transport reference, NOT the production discovery gate, which is the proven libp2p-kad 103/191/194). REMAINING (owner-review-gated, NOT done autonomously): (a) the PRD execution-order PROSE (§693-734 'Iroh-first' / 'GLOBAL-IROH GATE') needs reconciling to the Wave-2c libp2p-primary authority — a PRD authority-section edit I will not make unilaterally; show the diff + confirm; (b) the product decision whether iroh remains a funded arm (sets 87/88/132/133/201 priority). These two are for the owner.

Raised to High in the Wave-2c cleanup (2026-08-14): this is the keystone reconcile that gates the fate of ~29 now-Low tasks (label deferred-pending-202) across the superseded iroh-as-discovery-gate, premature multi-arm tournament, far-future BitTorrent, and optional-comparator tracks. Normative authority = PRD §634-691 (libp2p-kad mandatory discovery, iroh optional transport only); the stale §693-743 Iroh-first execution order is what this task removes/reconciles. Owner/PRD-gated: the 'is iroh a funded transport arm at all' call is owner product intent — route via mped-architect as Mark-emulator against the PRD, do not ask the owner.
<!-- SECTION:NOTES:END -->
