---
id: TASK-131
title: OPTIONAL Iroh Mainline address lookup after Iroh qualification
status: To Do
assignee: []
created_date: '2026-08-11 03:31'
updated_date: '2026-08-14 21:48'
labels:
  - iroh
  - discovery
  - mainline
  - privacy
  - wave-2c
  - optional
  - deferred-pending-202
dependencies:
  - TASK-89
  - TASK-96
  - TASK-120
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Consume TASK-96 public-Mainline evidence and TASK-120 authoritative operator configuration after DNS/pkarr/relay discovery works. If Mainline address lookup is approved, add exactly that explicit capability to TASK-115 runtime without adaptive participation or hidden defaults. If rejected, publish a machine-readable unsupported capability and add no Mainline dependency. This task resolves NodeId to dialable location only; it neither chooses the global content-DHT contract (TASK-126) nor changes operator-mode semantics.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Verify and bind the exact TASK-96 decision-artifact hash, participation decision, privacy findings and versioned dependency choice. Missing, superseded or ambiguous evidence fails closed and cannot enable Mainline.
- [ ] #2 If supported, Mainline address lookup is an explicit TASK-120 capability registered through TASK-115, OFF by default, and enforces the approved client/server behavior. Adaptive auto-promotion is forbidden; a mutation enabling it makes the participation-observation bite fail.
- [ ] #3 If supported, two daemons with no peer-address injection resolve NodeId to a dialable location through Mainline and establish a real Iroh connection under numeric bootstrap/lookup deadlines; restart and bootstrap outage remain observable and bounded.
- [ ] #4 If supported, preflight/status documents every bootstrap peer, query/publication recipient, IP/NodeId exposure, TTL/republish cost and server participation. Offline-test, LAN-only and DNS/relay-only configurations show zero Mainline packets.
- [ ] #5 In either branch, runtime capability output is machine-readable supported or evidenced-unsupported and includes decision/code/dependency hashes. Unsupported means no Mainline crate or silent substitute; TASK-87 and tournaments retain an explicit unsupported cell.
- [ ] #6 This task does not freeze NarHash-to-DHT keys or records and cannot satisfy TASK-126/TASK-103 by address lookup. Bites reject content keys/records, hidden default activation, injected addresses and any configuration path not derived from TASK-120.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Deferred until the mandatory Iroh discovery path and operator contract pass. TASK-96 is unconditional only for this optional Mainline capability; it is conditional and dynamically added if TASK-126 itself selects Mainline.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
