---
id: TASK-169
title: >-
  daemon consumes Libp2pFabric::node_locator - drop the --libp2p-provider-addr
  injection shim
status: To Do
assignee: []
created_date: '2026-08-12 15:32'
updated_date: '2026-08-12 15:32'
labels:
  - libp2p
  - daemon
  - discovery
  - fabric
  - wave-2c
dependencies:
  - TASK-159
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-159 landed Libp2pFabric::node_locator (kad peer-routing resolves a provider PeerId -> dialable Multiaddr through the DHT). The daemon does NOT yet use it: source_libp2p.rs still takes provider_addrs (PeerId,Multiaddr) injected via the --libp2p-provider-addr CLI shim (main.rs:337/639), and the code comments mark this as 'the TASK-159 basic-dial shim: node_locator() is still None'. Now that node_locator exists, wire the daemon's setup_p2p_source / Libp2pNarSource to resolve a discovered provider's dial address via node_locator().locate() instead of the injected map, so the PRODUCTION path is fully decentralized (discover WHO via kad get_providers + resolve WHERE via kad peer-routing, zero injection). Keep --libp2p-provider-addr only as an explicit optional fallback/bootstrap hint (or remove it) - do not require it for a dial. Update the in-process production-path test (daemon/tests/libp2p_production_path.rs) so the daemon dials a provider it never had an injected address for. This is the precursor to TASK-161 (podman multi-daemon libp2p cold-journey e2e). Feature/LIGHT gate.
<!-- SECTION:DESCRIPTION:END -->
