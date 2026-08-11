---
id: TASK-103
title: >-
  Implement the selected ProviderDirectory backend (adopt iroh-dht-experiment /
  fallback libp2p-kad) behind the PeerFabric seam
status: To Do
assignee: []
created_date: '2026-08-10 10:04'
updated_date: '2026-08-11 23:58'
labels:
  - iroh
  - discovery
  - dht
  - decentralized
  - blocking
  - implementation
  - wave-2c
dependencies:
  - TASK-83
  - TASK-100
  - TASK-102
  - TASK-115
  - TASK-126
  - TASK-140
  - TASK-141
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement TASK-126s frozen decentralized exact-key content discovery behind ContentDiscovery. A query for one NAR identity returns bounded signed provider NodeIds and transport offers while tracker LAN and dialable-address resolution remain disabled. If Iroh has no native content DHT use the selected decentralized discovery substrate from TASK-126 while keeping Iroh NodeId identity transport and transfer. Unsupported or central-only behavior is a blocking failure rather than a completed capability. TASK-89 later resolves returned NodeIds to dialable locations and TASK-132 later proves the real-Nix journey.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Implement the frozen versioned NarHash-to-key and signed multi-provider record contract exactly and reject incompatible vectors versions signatures namespaces and malformed records.
- [ ] #2 All daemon-originated publication passes TASK-102 and unsigned private stale replayed expired or ineligible offers never enter accepted DHT state.
- [ ] #3 A cold run-unique multi-node test starts from absent content state and only provider daemons publish. Harness insertion prior rendezvous named candidates tracker and LAN invalidate evidence.
- [ ] #4 Exact-key lookup returns bounded provider NodeIds and transport offers with no IP port relay location or unasked holdings and preserves ContentDiscovery positional batch semantics.
- [ ] #5 At least three independently operated bootstrap or routing nodes are configurable. Loss of any one does not prevent an already admitted healthy network from resolving content and no single central service is required.
- [ ] #6 Tests cover concurrent providers idempotent refresh explicit withdrawal expiry restart replay rollback corrupted state partition and rejoin without lost updates or expired-record resurrection.
- [ ] #7 Return typed MISS only after a healthy completed lookup and typed UNAVAILABLE for bootstrap partition or dependency failure within the 15000 ms total deadline.
- [ ] #8 Resource tests enforce record provider request response storage concurrency rate and work bounds plus poisoning amplification Sybil and eclipse assumptions without compromising integrity.
- [ ] #9 Packet and source guards prove tracker LAN implicit public presets and out-of-band address injection are disabled during qualification. A mutation enabling any substitute makes the proof fail.
- [ ] #10 Emit decentralized-content-discovery-v1 verdict=pass bound to TASK-126 final tree manifests timings packet evidence and mutations. TASK-132 accepts no unsupported tracker-backed or fabricated substitute.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Mandatory production capability. There is no unsupported-completion branch. This task ends at content key to provider NodeId and offer resolution; TASK-89 owns NodeId to address and TASK-132 owns connection transfer and real-Nix proof.

Forward-carry from TASK-141 inc 1 (commit d01fb42): the shared value types are now single-sourced in the peer-fabric seam crate (peer_fabric::ids: NodeId, Blake3Digest incl the frozen BLAKE3(RawNarV1) recipe, TransportTag, InfoHash/TransportOffer; peer_fabric::content: ContentKey, ProviderRecord, DialInfo). The selected ProviderDirectory backend this task implements will live in the fabric-iroh crate (extracted by TASK-144), behind peer_fabric::ProviderDirectory, and construct into IrohFabric's Option<Arc<dyn ProviderDirectory>> field. It depends ONLY on peer-fabric value types - do not reach for daemon-internal types. NOTE: peer_fabric::content (ContentKey/ProviderRecord) is deliberately serde-FREE precisely so THIS task/TASK-126 choose the opaque-value codec against the adopted backend without a churn dep; the ids DO carry frozen serde codecs. Backend crate = fabric-iroh (peer-fabric + iroh + iroh-blobs), never in peer-fabric or daemon-core.
<!-- SECTION:NOTES:END -->
