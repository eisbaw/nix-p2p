---
id: TASK-175
title: >-
  fabric-libp2p: record DHT exposure conditioned on actual query reach
  (answered>0), not before a doomed query
status: To Do
assignee: []
created_date: '2026-08-12 19:25'
labels:
  - libp2p
  - fabric
  - privacy
  - ledger
  - hardening
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-174 mped-architect review (Finding 2). Both locator.rs (locate_via_dht) and directory.rs (resolve) record the Exposure(DhtNode, OurNodeId) (+ ContentKey) BEFORE issuing the kad query, guarded only by the routing_peers()==0 pre-check. TASK-174 made a new case observable: a routing table of only DEAD entries passes the pre-check, the exposure is recorded, then every dial is refused so identify never runs and OUR NodeId is transmitted to NOBODY, yet the query returns InsufficientRouting (QueryReach.answered==0). The same answered==0 that justifies 'reached nobody' proves the just-recorded ledger entry is spurious. Over-recording is the SAFE direction for a privacy ledger (claims a leak that did not occur), so severity is MEDIUM, not a correctness break, and it does NOT block TASK-174. Fix options: (a) record the DhtNode disclosure conditioned on actual reach (answered>0) after the query, or (b) reconcile post-query. Note the pre-check comment currently claims it avoids 'a spurious ledger disclosure' - true only for the empty-table case, not the dead-entry case. Touches exposure-ledger timing semantics; scope carefully. Reference: absence_from_reach + QueryReach in fabric-libp2p/src/swarm.rs, ledger.record in locator.rs and directory.rs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Exposure(DhtNode, OurNodeId/ContentKey) is recorded only when the query actually reached >=1 peer (answered>0), or is reconciled post-query so a dead-entry lookup (answered==0) records no DhtNode disclosure
- [ ] #2 The pre-check comment's 'spurious ledger disclosure' rationale is corrected to reflect both the empty-table and dead-entry cases
- [ ] #3 A test asserts: a node with only DEAD routing entries records NO DhtNode disclosure for a lookup that returns InsufficientRouting
<!-- AC:END -->
