---
id: TASK-74
title: 'Gossip accelerant: maintain a set of live peers worth probing'
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-09 21:02'
labels:
  - wave-2b
dependencies:
  - TASK-73
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The second half of the discovery design, and the one the owner scoped precisely in phase 1: 'gossip may be OK for a cache accelerant, but cant be a requirement'. So gossip must be strictly an OPTIMIZATION - the system must still resolve via DHT + bounded fan-out with gossip entirely absent or broken.

PRD names its real role: 'maintaining a set of live peers worth probing'. That is what makes the bounded yes/no fan-out (TASK-73) useful - fanning out to a stale peer list is wasted dials, and dial cost is real (DIAL_TIMEOUT is 10 s in the safety envelope).

Verified 2026-08-09: no gossip code exists (no non-comment occurrence in daemon/src). Depends on TASK-73 because a live-peer set is only meaningful once there is a resolution path to accelerate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A live-peer set is maintained and used to order/bound the yes/no fan-out; peers that fail to dial are demoted and stale entries expire
- [ ] #2 PROVE gossip is not a requirement: with gossip disabled or fed deliberately stale data, resolution still succeeds via the DHT + fan-out path. Bite by mutation - the test must fail if resolution silently starts depending on gossip
- [ ] #3 The accelerant is MEASURED, not assumed: dials-per-successful-resolve and time-to-resolve with gossip on vs off, over the profiling harness
- [ ] #4 No enumeration: gossiping a live-peer set must not leak what those peers HOLD
<!-- AC:END -->
