---
id: TASK-40
title: 'Minimal 2-node discovery: claim exchange + NarHash resolve'
status: To Do
assignee: []
created_date: '2026-08-08 20:12'
updated_date: '2026-08-08 23:10'
labels: []
dependencies:
  - TASK-37
  - TASK-50
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION: (1) Discovery::resolve returns the COMPLETE transport OFFER (NodeId + RawNarV1 BLAKE3 + transport tag), not merely a holder NodeId (codex#2) - iroh fetches by BLAKE3, so the NarHash->BLAKE3 mapping must be in the offer. (2) The claim PRODUCER is task-50 (availability index) - announce source is the index, not hand-waved. (3) Split discovery: DHT(NarHash-key)->candidate NodeIds [deferred to task-47 spike] THEN per-peer claim query [task-37 envelope, now]. Wave-2a uses minimal/direct discovery; do NOT bake an unversioned query wire (use task-37's envelope).

FROM task-38 (commit 0d9d6e7): discovery replaces the in-memory claim map in TransportNarSource (daemon/src/transport_fetch.rs). Today announce()/claims: HashMap<canonical-NarHash-string, Claim> is the stand-in; swap it for the real index/DHT lookup (likely async). The consumer contract is fixed: discovery must yield a Claim whose content_id() is the Blake3Digest and whose .transports are the offers; fetch_via_offers() already picks offers by tag and skips unimplemented ones. Pick offers -> Transport is DONE - task-40 only needs to feed Claims. Note the key canonicalisation gotcha: keys must be canonical NarHashKey strings or lookup misses.
<!-- SECTION:NOTES:END -->
