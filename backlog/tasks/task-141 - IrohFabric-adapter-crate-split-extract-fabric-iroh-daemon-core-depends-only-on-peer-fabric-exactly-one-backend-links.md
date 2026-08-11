---
id: TASK-141
title: >-
  IrohFabric adapter + crate split: extract fabric-iroh, daemon-core depends
  only on peer-fabric, exactly one backend links
status: To Do
assignee: []
created_date: '2026-08-11 21:22'
updated_date: '2026-08-11 22:32'
labels:
  - iroh
  - seam
  - adapter
  - de-welding
  - wave-2c
dependencies:
  - TASK-115
  - TASK-140
documentation:
  - docs/peer-fabric-seam.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement PeerFabric and its capability traits over the concrete iroh stack, moving the currently-welded iroh modules (iroh_runtime, iroh_node_lookup, iroh_publication*, pinned_http; ~195 iroh refs) BEHIND the TASK-140 seam. Without this task the seam is aspirational and a second backend (libp2p) can never be added - nothing else in the backlog covers de-welding iroh.

NarTransfer/NarServer wrap iroh-blobs on the shared TASK-115 endpoint; NodeLocator wraps the done TASK-138 pkarr NodeId->address lookup; ProviderDirectory/AvailabilityAnnouncer are provided by the adopted backend from TASK-126/103. The serving core must require NO change (it already holds zero iroh types).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 IrohFabric implements PeerFabric as a concrete struct with Option<Arc<dyn ...>> capability fields; the feature-gated 'type Fabric = IrohFabric' alias selects it at compile time; a peers-off/upstream_only construction exposes no P2P axis and links/opens no discovery machinery.
- [ ] #2 NarTransfer and NarServer wrap iroh-blobs on the shared TASK-115 endpoint; the existing tag-keyed TransportRegistry is reused unchanged for offer dispatch.
- [ ] #3 NodeLocator wraps the TASK-138 pkarr NodeId->address lookup and records Exposure to the single ledger; resolution mechanism is policy-selected (explicit peer list vs pkarr/Mainline/DNS) and gate-able per profile.
- [ ] #4 The welded modules (iroh_runtime, iroh_node_lookup, iroh_publication*, pinned_http) are reached only through the seam from daemon code; a guard/test asserts the serving core and App hold no concrete iroh types outside the fabric module.
- [ ] #5 No serving-core change is required: the same e2e/S6 peer-served-build passes with the daemon driving IrohFabric through PeerFabric rather than concrete iroh calls.
- [ ] #6 IrohFabric lives in its own 'fabric-iroh' crate (peer-fabric + iroh + iroh-blobs); the welded iroh modules (iroh_runtime, iroh_node_*, iroh_publication*, pinned_http) move into it; 'daemon-core' holds no concrete iroh type and depends on peer-fabric only.
- [ ] #7 Two product binaries daemon-iroh and daemon-libp2p, each = daemon-core + exactly ONE fabric-* crate; the binary is the backend choice (no features, no cfg); each fn main constructs its fabric and calls daemon_core::run(fabric). A build guard proves daemon-iroh's dependency closure contains no libp2p and daemon-libp2p's contains no iroh, so tests and tournament runs never conflate backends.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Crate topology (owner directive 2026-08-11: exactly one P2P backend compiled in, never both required): peer-fabric (seam, TASK-140) <- daemon-core (frontend, no p2p) <- fabric-iroh (this task) / fabric-libp2p (later, TASK-103 if selected) <- daemon bin (one backend, optional-dep + mutually-exclusive feature). fabric-libp2p is not a workspace member until libp2p is chosen. testproxy independence is unaffected (it depends on none of these). See docs/peer-fabric-seam.md.

Forward-carried from TASK-140 (peer-fabric seam landed, commit 9073806):
- peer-fabric is now the CANONICAL HOME of NodeId (32 ed25519 bytes), Blake3Digest (32 bytes), TransportTag, TransportOffer/InfoHash, ContentKey, ProviderRecord, DialInfo, Lookup, Exposure*, budgets. TASK-141 MUST delete the daemon's duplicate NodeId (daemon::transport), Blake3Digest (daemon::content_id), TransportTag (daemon::transport_fetch) and re-point the daemon at peer-fabric's copies. They are byte-compatible by construction (same lengths, same lowercase-hex canonical form) but are DISTINCT TYPES today.
- No cross-crate equivalence guard exists (peer-fabric cannot depend on daemon). Until the daemon copies are deleted, treat any edit to peer-fabric's NodeId/Blake3Digest/TransportTag/TransportOffer as requiring a mirrored daemon edit; ideally TASK-141 lands a test proving the wire encodings agree, then removes the duplicates. TransportTag::as_str()/TransportOffer variants were written to match daemon::claim::KnownTransport serde tags ('iroh','bittorrent') - verify on merge.
- Composition root is TASK-141's: the two thin binaries (daemon-iroh/daemon-libp2p), each daemon_core::run(fabric), must assert the selected profile's REQUIRED axes are Some and FAIL FAST otherwise (the peer-fabric doc's Unsupported-ZST-dilemma resolution). peer-fabric only provides the Option<Arc<dyn>> shape; it does not assert requiredness.
- peer-fabric's SafetyEnvelope/ServeBudget mirror daemon::transport_iroh's shapes; NarTransfer::fetch was given expected_size:Option<u64> to match daemon::transport_fetch::Transport::fetch (the seam doc had dropped it). Reconcile the daemon's real IrohTransport onto peer-fabric::NarTransfer without losing the mid-stream NarSize abort.
- peer-fabric::ServeHandle now owns an opaque Box<dyn Send+Sync> teardown guard; the IrohFabric NarServer impl must attach its real listener/task-abort there so drop = teardown.
<!-- SECTION:NOTES:END -->
