---
id: TASK-103
title: >-
  Implement the selected ProviderDirectory backend (adopt iroh-dht-experiment /
  fallback libp2p-kad) behind the PeerFabric seam
status: To Do
assignee: []
created_date: '2026-08-10 10:04'
updated_date: '2026-08-12 04:17'
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
FORWARD-CARRY from TASK-144 inc 1 (commit 2394bee): the fabric-iroh backend crate now EXISTS (peer-fabric + iroh; never depends on the daemon). The iroh TRANSFER (iroh-blobs, in transport_iroh - TASK-148 moves it here) and the iroh NodeLocator (pkarr, iroh_node_lookup - already here) live in fabric-iroh. Per docs/peer-fabric-seam.md SPIKE DECISION the ProviderDirectory PRIMARY freeze target is libp2p-kad's opaque put_record/get_record (iroh-dht-experiment is fallback), so the ProviderDirectory impl belongs in a fabric-libp2p crate (not yet a workspace member), NOT in fabric-iroh - a dual-stack IrohFabric would return an iroh transfer + a libp2p directory. A backend plugs in by implementing the peer_fabric capability traits and being assembled into a concrete Fabric struct (Option<Arc<dyn>> fields) at the composition root.
<!-- SECTION:NOTES:END -->
