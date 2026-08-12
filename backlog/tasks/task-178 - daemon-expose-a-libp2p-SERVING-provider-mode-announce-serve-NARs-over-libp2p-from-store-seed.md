---
id: TASK-178
title: >-
  daemon: expose a libp2p SERVING/provider mode (announce + serve NARs over
  libp2p from store/seed)
status: To Do
assignee: []
created_date: '2026-08-12 21:21'
labels:
  - libp2p
  - daemon
  - serving
  - fabric
  - core
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-161 (multi-daemon libp2p e2e) needs a daemon that can be the PROVIDER container, but the daemon only CONSUMES via libp2p today: build_libp2p_nar_source uses Libp2pFabric::start() (no supplier), and nothing in daemon/src wires Libp2pServer / Libp2pAvailabilityAnnouncer / a supplier. This is the SERVING half of the libp2p primary path and it is missing. Expose it via CLI, mirroring the iroh serving mode (--iroh-provider / --iroh-seed-nar / --iroh-print-peer-address in daemon/src/main.rs): a --libp2p-provider (or equivalent) mode that starts Libp2pFabric::start_with_supplier(config, supplier) with a supplier serving the seeded/store NAR(s), calls .server().serve(budget) to install the serve gate, and .announcer().announce(record) for each served ContentKey so a consumer can discover it via kad. Reuse fabric-libp2p's Libp2pNarSupplier/MemoryNarSupplier + the serving APIs proven in fabric-libp2p/tests/node_locator_discovery.rs (start_serving_node). Add --libp2p-seed-nar (like --iroh-seed-nar) and/or wire the AvailabilityIndex (see TASK-83 for the iroh /nix/store analogue) + a --libp2p-print-peer-address for the harness to read the provider's PeerId+listen addr. This is a CORE capability (rung 2), not hardening. Deps: TASK-151 (libp2p NarServer/transfer), TASK-103 (announcer/directory).
<!-- SECTION:DESCRIPTION:END -->
