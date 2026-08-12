---
id: TASK-145
title: daemon-iroh thin binary + no-libp2p build guard (TASK-141 inc 3)
status: To Do
assignee: []
created_date: '2026-08-11 23:58'
updated_date: '2026-08-12 06:55'
labels:
  - iroh
  - seam
  - de-welding
  - wave-2c
dependencies:
  - TASK-144
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Increment 3 of the TASK-141 de-welding. Add the daemon-iroh thin binary crate = daemon-core + fabric-iroh, whose fn main() { daemon_core::run(fabric_iroh::IrohFabric::new(cfg)) }. No features, no cfg: the binary IS the backend choice (docs/peer-fabric-seam.md). Add a build guard proving daemon-iroh's dependency closure contains no libp2p. NOTE: daemon-libp2p cannot exist yet (no fabric-libp2p backend until libp2p is adopted) - see the separate daemon-libp2p follow-up gated on fabric-libp2p; do NOT stub a fake one.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 daemon-iroh binary crate = daemon-core + fabric-iroh; fn main constructs IrohFabric and calls daemon_core::run(fabric); no features, no cfg
- [ ] #2 build guard asserts daemon-iroh's dependency closure contains no libp2p
- [ ] #3 just e2e s6-p2p passes driving the daemon-iroh binary
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FORWARD-CARRY from TASK-144 inc 1 (commit 2394bee): the fabric-iroh backend crate now EXISTS and holds the iroh node-discovery/runtime/publication cluster. Remaining for the daemon-core split: (1) the serving core (server/source/upstream/catalog/rewrite/narinfo_cache + availability/discovery/claim/transport/transport_fetch/content_id/supply_catalog) is still in the 'daemon' crate together with transport_iroh; (2) topology requires daemon-core to depend on peer-fabric ONLY, but today the daemon depends on fabric-iroh for BOTH the iroh cluster AND process_group (availability uses ProcessJob/ProcessJobSpec). So daemon-core split is blocked on TASK-148 (move transport_iroh out) AND on relocating process_group to a shared util or into daemon-core (it is generic, not iroh - it only rides in fabric-iroh now to keep the cut acyclic). The composition root (this task's thin binary) is where TASK-144's IrohFabric::new(cfg) is constructed and where the required-axis assertion lives.

TASK-148 inc 1 (commit 9c0472d): iroh transfer axis de-welded onto peer_fabric::NarTransfer via a daemon Transport bridge. When splitting daemon-core: the composition root's fetch-path adoption of peer_fabric::NarTransfer + TransferRegistry (retiring the bridge) is tracked with the transport_iroh move under TASK-150/TASK-148 AC#3. KnownTransport::to_offer() (claim.rs) is the wire->seam offer boundary the core will call at the daemon side.

TASK-150 c39b200: the daemon-iroh binary's serve path can now start serving via peer_fabric::NarServer::serve on a running runtime and own an abortable ServeHandle (de-welded from the shared runtime). No change required yet; forward-carry only.
<!-- SECTION:NOTES:END -->
