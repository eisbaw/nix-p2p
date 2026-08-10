---
id: TASK-66
title: >-
  Discovery index replaces holders instead of accumulating them (no
  multi-holder)
status: To Do
assignee: []
created_date: '2026-08-09 13:31'
updated_date: '2026-08-10 12:21'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from TASK-91 (batched hold-query)

DirectDiscovery::resolve_many has the same first-Have-wins behaviour as
resolve(): the first peer that answers Have for a key claims it, later peers are
never asked about it (deliberately - it is what makes the common case one round
trip). So multi-holder aggregation has to be decided at the BATCH level too, and
the shapes are not the same:

* aggregating means continuing to probe peers for keys already resolved, i.e.
  paying round trips for redundancy. Quantify that against the measured cost
  (`just discovery`) rather than assuming it is free.
* BatchHoldResponse hoists `offers` to the response because ONE peer answers one
  batch. A multi-holder Claim assembled from several batch responses must merge
  offers per KEY across responses - do not assume a claim's offers all came from
  one peer once aggregation exists.
<!-- SECTION:NOTES:END -->
