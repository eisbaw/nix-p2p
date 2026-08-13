---
id: TASK-146
title: daemon-libp2p thin binary (gated on fabric-libp2p)
status: To Do
assignee: []
created_date: '2026-08-11 23:58'
updated_date: '2026-08-13 00:17'
labels:
  - seam
  - de-welding
  - libp2p
  - blocked
dependencies:
  - TASK-103
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The second product binary from docs/peer-fabric-seam.md's two-binary composition root: daemon-libp2p = daemon-core + fabric-libp2p, fn main() { daemon_core::run(fabric_libp2p::Libp2pFabric::new(cfg)) }, with a build guard that its dep closure contains no iroh. BLOCKED and deliberately NOT stubbed: there is no fabric-libp2p backend crate until libp2p is adopted (TASK-103 selects the ProviderDirectory backend). Filed so the two-binary target architecture is tracked; implement only once fabric-libp2p exists. Referenced from the daemon-iroh inc-3 task and TASK-141.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 daemon-libp2p binary crate = daemon-core + fabric-libp2p; build guard proves its dep closure contains no iroh
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
UNBLOCKED (backend side) by TASK-144 (commit 4a4397c): peer_fabric::require_axes is the shared composition-root REQUIRED-axis gate and is already the live call site on the libp2p fabric (daemon start_and_join_libp2p asserts consumer axes provider_directory+node_locator+Transfer(Iroh), provider adds Server+Announcer). So the daemon-libp2p thin binary inherits the same require_axes assertion once daemon-core is split (TASK-145). No change needed to fabric-libp2p for this; the gate mechanism is in peer-fabric.
<!-- SECTION:NOTES:END -->
