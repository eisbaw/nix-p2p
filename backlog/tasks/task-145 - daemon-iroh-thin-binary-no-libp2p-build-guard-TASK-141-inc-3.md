---
id: TASK-145
title: daemon-iroh thin binary + no-libp2p build guard (TASK-141 inc 3)
status: To Do
assignee: []
created_date: '2026-08-11 23:58'
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
