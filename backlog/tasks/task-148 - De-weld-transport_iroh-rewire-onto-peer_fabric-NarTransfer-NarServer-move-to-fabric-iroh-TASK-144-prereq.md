---
id: TASK-148
title: >-
  De-weld transport_iroh: rewire onto peer_fabric NarTransfer/NarServer + move
  to fabric-iroh (TASK-144 prereq)
status: To Do
assignee: []
created_date: '2026-08-12 04:16'
updated_date: '2026-08-12 07:22'
labels:
  - iroh
  - seam
  - adapter
  - de-welding
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
transport_iroh (the iroh-blobs NAR transfer + provider serve, ~111KB) is the last iroh module still in the daemon after TASK-144 inc 1, because it is welded to the serving core: it depends on daemon claim (KnownTransport/offers), transport_fetch (Transport trait/TransportError/NarSource/TransportRegistry), source, discovery, supply_catalog. To move it into fabric-iroh WITHOUT dragging the serving core along, its IrohTransport must implement peer_fabric::NarTransfer (not daemon::Transport) and its IrohProvider/serve path must implement peer_fabric::NarServer with a real ServeHandle whose drop == teardown (listener/task-abort owned by the peer_fabric::ServeHandle opaque guard). Also move IROH_BLOBS_ALPN from daemon/src/transport.rs into fabric-iroh (iroh-specific; left in transport.rs by TASK-141 inc 1 on purpose). This unblocks TASK-144 IrohFabric transfer/server axes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 IrohTransport implements peer_fabric::NarTransfer (tag + fetch(content, offer, envelope) -> gate-1-verified bytes); the daemon-side Transport trait dependency is removed or bridged behind the seam
- [ ] #2 IrohProvider serve path implements peer_fabric::NarServer returning a ServeHandle whose Drop aborts the listener/serve task (no leaked serve task); proven by a teardown test
- [ ] #3 transport_iroh moved into fabric-iroh with NO edge back to daemon serving core (claim/transport_fetch/source/discovery/supply_catalog either moved below the seam or the needed pieces are peer-fabric types)
- [ ] #4 IROH_BLOBS_ALPN lives in fabric-iroh; the iroh_blobs::ALPN equality assertion moves with it
- [ ] #5 just build/lint/test/e2e green incl s6-p2p (daemon still substitutes + serves P2P)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REFRAMED 2026-08-12 (libp2p-primary): iroh is now the OPTIONAL transport, not the default. This de-weld work stays valid - it makes iroh a clean swappable NarTransfer/NarServer behind the seam - but it is SECONDARY. Primary is fabric-libp2p (TASK-103 kad discovery + TASK-151 libp2p transport). The transport tournament compares this iroh transport vs the libp2p transport under one libp2p-kad discovery.
<!-- SECTION:NOTES:END -->
