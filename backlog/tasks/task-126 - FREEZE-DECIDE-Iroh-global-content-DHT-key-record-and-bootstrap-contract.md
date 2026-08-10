---
id: TASK-126
title: 'FREEZE/DECIDE: Iroh global content-DHT key, record and bootstrap contract'
status: To Do
assignee: []
created_date: '2026-08-10 22:51'
labels:
  - iroh
  - discovery
  - irreversible
  - grounding
  - wave-2c
dependencies:
  - TASK-89
  - TASK-96
  - TASK-100
  - TASK-102
  - TASK-114
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Make the irreversible global Iroh content-discovery decision before implementation. Consume the Mainline/privacy evidence and choose a substrate, namespace, NarHash-to-key derivation, record shape, NodeId/address resolution, bootstrap, TTL/republish and version-migration contract—or record an evidenced global-DHT no-go. This task produces a versioned decision and golden vectors only. It must not build the DHT. Tracker and bounded direct-query discovery remain usable if global publication is rejected.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A decision record compares every viable substrate on bootstrap, namespace/key width, multi-writer records, NodeId/address handling, TTL/republish cost, eclipse/Sybil exposure, privacy and third-party dependence; global-DHT no-go is explicit and valid.
- [ ] #2 If supported, a versioned domain contract pins NarHash-to-DHT-key derivation, namespace separation, record schema/cardinality, signature/expiry semantics, NodeId/location representation, bootstrap seed format and migration behavior.
- [ ] #3 Golden vectors cover key and record encoding plus malformed/version-skew/unknown-field cases; a one-byte namespace/version mutation changes the vector and incompatible changes require a network version.
- [ ] #4 Publication is structurally downstream of TASK-102, and the decision states client-only/server participation, query exposure, inventory exposure, republish budgets and safe default-off behavior.
- [ ] #5 Cold bootstrap and no-seed behavior have a falsifiable plan with numeric deadlines and S2 fallback; an empty/small/eclipsed DHT may cost availability but never integrity.
- [ ] #6 If no-go, the artifact names the failed constraints and TASK-103/TASK-87 must report global-DHT unsupported rather than inventing or silently substituting a tracker.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Deep freeze gate. TASK-103 implements only a supported contract; it does not choose one.
<!-- SECTION:NOTES:END -->
