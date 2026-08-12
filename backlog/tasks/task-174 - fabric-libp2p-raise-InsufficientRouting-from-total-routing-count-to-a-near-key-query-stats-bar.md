---
id: TASK-174
title: >-
  fabric-libp2p: raise InsufficientRouting from total-routing-count to a
  near-key query-stats bar
status: To Do
assignee: []
created_date: '2026-08-12 18:28'
labels:
  - libp2p
  - fabric
  - dht
  - hardening
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-103 (mped-architect S3) and re-scoped out of TASK-153. Today directory.rs gates Miss-authority on routing_peers()==0 (a TOTAL routing-table count). A node holding only a bootstrap (routing_peers()>0) can report a healthy Miss where InsufficientRouting is the more honest answer, because no peer NEAR THE KEY was actually consulted. Raise the bar to a near-key / query-stats signal: thread kad QueryStats (how many peers close to the key were contacted) out of the get_providers reply and gate Miss vs InsufficientRouting on it. Risk: this touches the Miss/InsufficientRouting boundary the cornerstone test (decentralized_discovery.rs) and classify() depend on - do it behind a unit test that bites the new boundary. Deferred from TASK-153 to keep that task minimal (connectivity/config + test).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 get_providers/get_record reply carries peers-contacted-near-key stats
- [ ] #2 directory gates Miss vs InsufficientRouting on the near-key bar, not the total count
- [ ] #3 a node holding only a bootstrap reports InsufficientRouting (not Miss) for an unannounced key; cornerstone Miss-over-populated-table stays green
<!-- AC:END -->
