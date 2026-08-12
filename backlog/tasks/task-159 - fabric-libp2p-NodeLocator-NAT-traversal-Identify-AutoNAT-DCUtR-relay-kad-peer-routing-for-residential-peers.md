---
id: TASK-159
title: >-
  fabric-libp2p: NodeLocator + NAT traversal (Identify/AutoNAT/DCUtR/relay + kad
  peer-routing) for residential peers
status: To Do
assignee: []
created_date: '2026-08-12 08:38'
labels:
  - libp2p
  - fabric
  - discovery
  - nat
  - wave-2c
dependencies:
  - TASK-151
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-151 dials a provider by adding its address (add_address) and letting request-response auto-dial - fine for the loopback multi-node test, but a residential peer behind NAT is unreachable. Wire the PRD axis-2 NodeLocator on the shared swarm: kad peer-routing to resolve a NodeId/PeerId to dialable addresses, plus AutoNAT (reachability), DCUtR (hole punching) and relay (circuit-v2) for peers with no public address. Fill Libp2pFabric::node_locator (currently None -> returns a real NodeLocator recording exposure to the ledger). Watch the public-DHT good-citizen duties.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Libp2pFabric::node_locator returns a real NodeLocator resolving a NodeId to dialable coordinates via kad peer-routing, recording exposure
- [ ] #2 AutoNAT/DCUtR/relay let a NAT'd peer be dialed for a fetch (proven by a test or documented harness limitation)
<!-- AC:END -->
