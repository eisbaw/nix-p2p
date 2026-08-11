---
id: TASK-144
title: >-
  fabric-iroh crate + daemon-core split + IrohFabric: PeerFabric (TASK-141 inc
  2)
status: To Do
assignee: []
created_date: '2026-08-11 23:57'
labels:
  - iroh
  - seam
  - adapter
  - de-welding
  - wave-2c
dependencies:
  - TASK-141
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Increment 2 of the TASK-141 de-welding, split out from TASK-141 (inc 1 landed: value types de-duplicated behind the seam, commit d01fb42). Extract a daemon-core (frontend: serving core, policy, orchestration; peer-fabric only, NO iroh) and a fabric-iroh crate (the welded iroh modules: iroh_runtime, iroh_node_lookup, iroh_publication*, pinned_http, iroh_relay, transport_iroh, iroh_node_record). Implement IrohFabric as a concrete struct with Option<Arc<dyn Capability>> fields per docs/peer-fabric-seam.md. Wire NodeLocator onto TASK-138's pkarr NodeId->address lookup, NarTransfer/NarServer onto iroh-blobs on the shared TASK-115 endpoint (reuse the existing tag-keyed TransportRegistry). Add the composition-root required-axis assertion (fail fast if a selected profile's required axis is None) and the real ServeHandle teardown (attach the listener/task-abort to peer_fabric::ServeHandle's opaque teardown guard so drop == teardown). Move IROH_BLOBS_ALPN from daemon/src/transport.rs into fabric-iroh (it is iroh-specific; left in transport.rs by inc 1 on purpose). A guard/test asserts the serving core + App hold no concrete iroh types outside the fabric module.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 daemon-core crate holds no concrete iroh type and depends on peer-fabric only (build/guard proves it)
- [ ] #2 fabric-iroh crate contains the welded iroh modules and implements IrohFabric: PeerFabric (concrete struct, Option<Arc<dyn>> capability fields)
- [ ] #3 NodeLocator wraps TASK-138 pkarr lookup; NarTransfer/NarServer wrap iroh-blobs on the TASK-115 endpoint; the tag-keyed TransportRegistry is reused unchanged
- [ ] #4 composition root asserts the selected profile's REQUIRED axes are Some and fails fast otherwise (Unsupported-ZST-dilemma resolution)
- [ ] #5 ServeHandle owns the real listener/task-abort so drop == teardown (no leaked serve task)
- [ ] #6 guard/test asserts the serving core and App hold no concrete iroh types outside the fabric module; just e2e s6-p2p still passes with the daemon driving IrohFabric through PeerFabric
<!-- AC:END -->
