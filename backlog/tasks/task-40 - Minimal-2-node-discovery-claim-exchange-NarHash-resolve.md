---
id: TASK-40
title: 'Minimal 2-node discovery: claim exchange + NarHash resolve'
status: To Do
assignee: []
created_date: '2026-08-08 20:12'
labels: []
dependencies:
  - TASK-39
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Enough discovery for S6 (2-node), NOT the full DHT (deferred to the wave-2b spike). A node announces claims (on-demand: when it holds a path) and a peer resolves NarHash -> holder NodeId via a minimal mechanism (direct exchange / a tiny local rendezvous / iroh node discovery + a claim query). No-enumeration: yes/no per NarHash, no listing. This proves the seam->swarm wiring; the DHT/gossip mechanism is chosen after the transport works.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Node A resolves a fixture NarHash to node B (the holder) and dispatches NarKey::SignedNarHash to the iroh transport - end to end, no cache.nixos.org
- [ ] #2 A NarHash no peer holds resolves to a miss fast (bounded), then the daemon falls back to upstream (S2 preserved)
- [ ] #3 No-enumeration: the probe answers yes/no for a concrete NarHash; there is no endpoint listing a peers holdings
<!-- AC:END -->
