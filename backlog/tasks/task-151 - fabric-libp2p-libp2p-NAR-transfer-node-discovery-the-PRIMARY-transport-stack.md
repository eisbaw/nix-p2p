---
id: TASK-151
title: >-
  fabric-libp2p: libp2p NAR transfer + node discovery (the PRIMARY transport
  stack)
status: To Do
assignee: []
created_date: '2026-08-12 07:22'
labels:
  - libp2p
  - fabric
  - transport
  - discovery
  - primary
  - wave-2c
dependencies:
  - TASK-103
  - TASK-140
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
libp2p-primary direction (owner 2026-08-12): fabric-libp2p is the PRIMARY backend. Beyond the libp2p-kad ProviderDirectory (TASK-103), a pure-libp2p daemon needs a libp2p NarTransfer + NarServer (request-response or stream protocol, BLAKE3-verified exactly like iroh-blobs, with the same task-72 serve-budget/admission) and libp2p node discovery + NAT traversal (Identify + AutoNAT/DCUtR/relay, and kad peer-routing for addresses). This completes Libp2pFabric: PeerFabric so daemon-libp2p is a full single-stack product needing no iroh. iroh-blobs transfer (fabric-iroh) is the OPTIONAL alternative measured against this in the transport tournament (same libp2p-kad discovery, different transport). Watch the rust-libp2p dependency weight and the public-DHT good-citizen duties (bootstrap, provider republish cadence; announce-on-demand bounds the republish load).
<!-- SECTION:DESCRIPTION:END -->
