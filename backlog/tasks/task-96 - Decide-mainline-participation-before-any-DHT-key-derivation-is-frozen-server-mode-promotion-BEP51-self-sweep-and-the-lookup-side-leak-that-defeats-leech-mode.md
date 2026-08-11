---
id: TASK-96
title: >-
  Decide mainline participation before any DHT key derivation is frozen:
  server-mode promotion, BEP51 self-sweep, and the lookup-side leak that defeats
  leech mode
status: To Do
assignee: []
created_date: '2026-08-10 08:43'
updated_date: '2026-08-11 03:44'
labels:
  - wave-2b
dependencies:
  - TASK-114
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
This is the owner/privacy decision gate for TASK-131 optional Mainline address lookup and TASK-126 global content-DHT grounding. It produces a decision record with measurements, not retained product code or a key derivation. The dependency is new and its adaptive default can promote a publicly reachable client into a server for arbitrary third-party DHT records. BEP51 makes stored per-content keys enumerable, passive get_peers observation leaks lookup intent even without publication, and BEP5 announce_peer cannot carry an Iroh NodeId; n0-mainline instead uses forward BEP44 NodeId-to-address records. First the repository product owner decides whether these structural privacy/participation facts already reject Mainline. A rejection is a complete evidenced no-go and makes external reachability experiments explicitly not_applicable. Only a still-viable candidate proceeds to authorized independent-network measurements. LAN and DNS/pkarr/relay discovery remain independent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A versioned owner_preflight artifact records whether the structural adaptive-server, BEP51 enumeration, passive lookup-leak and NodeId-record facts reject Mainline before external trials. reject is a valid terminal no-go with experiments explicitly not_applicable and no measurement claim; continue requires the authorized resource plan in AC6.
- [ ] #2 If owner_preflight continues, a two-host experiment has host A announce N seed-derived keys and host B run a BEP51 sample_infohashes sweep, reporting recovered fraction and wall time. BITE: B has no seed/key list; a run that hands B the keys fails as vacuous. If rejected, this row is recorded not_applicable with the preflight hash.
- [ ] #3 If owner_preflight continues, client-only behavior is verified by observing zero inbound DHT queries for at least 30 minutes on a publicly reachable node; flipping the identical node to adaptive must make that assertion fail after the promotion window. If rejected, no client-only safety claim is made and the row is not_applicable.
- [ ] #4 If owner_preflight continues, announced-endpoint reachability is measured over at least 20 trials across two ISPs by a third host on a third network, with a same-LAN positive control. If rejected, no reachability claim is made and the row is not_applicable.
- [ ] #5 The final signed decision answers whether Mainline ships, enforced client/server behavior, lookup/publication privacy effects and every factual correction. TASK-131 and TASK-126 bind its hash and cannot complete without it; TASK-89 DNS/pkarr/relay and TASK-130 LAN discovery remain independent.
- [ ] #6 Before a continue-branch external experiment, record a named evidence owner plus concrete two-ISP/third-network host acquisition, credentials, cost and cleanup plan. No paid resource, external account or third-party coordination is implied by this backlog. Missing authorization blocks only the continue branch; it cannot be disguised with containers, VPN namespaces or same-provider hosts.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Current graph: TASK-130 owns LAN discovery; TASK-89 owns DNS/pkarr and relay; TASK-131 alone consumes this decision for optional Mainline address lookup; TASK-126 independently consumes it for global content-DHT grounding. The cross-ISP decision cannot block TASK-130 -> TASK-116 LAN zero-injection work. Before any external trial, record the named evidence owner, host/network acquisition plan and authorization; do not spend money, create external infrastructure or message third parties implicitly. Earlier TASK-89/demotion notes are superseded. Supporting factual research remains in TASK-73 history.
<!-- SECTION:NOTES:END -->
