---
id: TASK-96
title: OPTIONAL decide Mainline participation if selected as a DHT candidate
status: To Do
assignee: []
created_date: '2026-08-10 08:43'
updated_date: '2026-08-14 21:48'
labels:
  - mainline
  - dht
  - privacy
  - optional
  - decision
  - wave-2b
  - deferred-pending-202
dependencies:
  - TASK-114
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Conditional owner and privacy decision gate for optional Mainline address lookup and for TASK-126 only if TASK-126 selects Mainline as its decentralized content substrate. Measure or reject adaptive server promotion BEP51 enumeration passive lookup leakage and the inability of BEP5 announce_peer to carry an Iroh NodeId. A rejection is a Mainline no-go only; it is not a successful global content-discovery result and does not block native Iroh or another decentralized DHT candidate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A versioned owner_preflight artifact records whether the structural adaptive-server, BEP51 enumeration, passive lookup-leak and NodeId-record facts reject Mainline before external trials. reject is a valid terminal no-go with experiments explicitly not_applicable and no measurement claim; continue requires the authorized resource plan in AC6.
- [ ] #2 If owner_preflight continues, a two-host experiment has host A announce N seed-derived keys and host B run a BEP51 sample_infohashes sweep, reporting recovered fraction and wall time. BITE: B has no seed/key list; a run that hands B the keys fails as vacuous. If rejected, this row is recorded not_applicable with the preflight hash.
- [ ] #3 If owner_preflight continues, client-only behavior is verified by observing zero inbound DHT queries for at least 30 minutes on a publicly reachable node; flipping the identical node to adaptive must make that assertion fail after the promotion window. If rejected, no client-only safety claim is made and the row is not_applicable.
- [ ] #4 If owner_preflight continues, announced-endpoint reachability is measured over at least 20 trials across two ISPs by a third host on a third network, with a same-LAN positive control. If rejected, no reachability claim is made and the row is not_applicable.
- [ ] #5 Before a continue-branch external experiment, record a named evidence owner plus concrete two-ISP/third-network host acquisition, credentials, cost and cleanup plan. No paid resource, external account or third-party coordination is implied by this backlog. Missing authorization blocks only the continue branch; it cannot be disguised with containers, VPN namespaces or same-provider hosts.
- [ ] #6 The final signed decision answers whether Mainline ships plus enforced client or server behavior and lookup or publication privacy effects. TASK-131 binds it; TASK-126 binds it only after explicitly selecting Mainline and adding TASK-96 as a dependency.
- [ ] #7 This task cannot satisfy TASK-103 or TASK-132 by rejection or unsupported evidence. Native Iroh and other decentralized candidates remain independent and tracker or LAN cannot substitute for any selected DHT proof.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Conditional Mainline candidate gate. Deferred on the Iroh-first path unless TASK-126 selects Mainline. External trials still require explicit owner infrastructure credential cost and cleanup authorization.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task is an optional-comparator / superseded-discovery / far-future-BitTorrent / premature-tournament track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
