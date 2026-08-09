---
id: TASK-66
title: >-
  Discovery index replaces holders instead of accumulating them (no
  multi-holder)
status: To Do
assignee: []
created_date: '2026-08-09 13:31'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
InMemoryDiscovery::announce replaces on key, so a NarHash resolves to at most ONE holder. Consequence for TASK-43: the dead-holder pathological case degenerates into the peer->upstream fallback that S6 already covers - there is no 'failover to the NEXT holder' to test, so the scenario cannot bite as written. Fix is a multimap in the in-process index. This is a VELOCITY surface (in-process discovery internals) and must NOT touch the claim wire schema, which is FROZEN - do not grow a frozen surface to get multi-holder. If the multimap cannot be done cheaply, the honest outcome is to scope TASK-43's dead-holder case to peer->upstream and name the gap in its limitations, rather than shipping a scenario that looks like failover and is not.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The discovery index accumulates holders per NarHash (multimap) rather than replacing, and resolve returns them in a defined order
- [ ] #2 A dead-holder test bites at the RIGHT boundary: with 2 holders and the first one dead, the fetch reaches the SECOND HOLDER (not upstream) - proven by a provider-side counter on holder 2, and proven non-vacuous by mutation
- [ ] #3 The claim wire schema is unchanged (frozen surface untouched); assert this explicitly
<!-- AC:END -->
