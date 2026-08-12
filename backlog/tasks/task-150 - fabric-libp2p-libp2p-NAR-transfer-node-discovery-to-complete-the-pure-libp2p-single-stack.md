---
id: TASK-150
title: >-
  fabric-libp2p: libp2p NAR transfer + node discovery to complete the
  pure-libp2p single-stack
status: To Do
assignee: []
created_date: '2026-08-12 04:55'
labels:
  - libp2p
  - fabric
  - transport
  - wave-2c
dependencies:
  - TASK-103
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Single-stack (owner directive, TASK-147 corrected): daemon-libp2p is ALL libp2p, so it needs a full libp2p fabric, not just the libp2p-kad ProviderDirectory (TASK-103). Today the only NAR transfer is iroh-blobs (fabric-iroh); a pure-libp2p binary needs a libp2p NarTransfer + NarServer (libp2p request-response or streaming, BLAKE3-verified same as iroh) and libp2p node discovery (Identify/Kademlia), all behind the peer-fabric seam. This is more work than the reversed dual-stack shortcut, but it is what a fair iroh-vs-libp2p tournament (TASK-114) requires - each stack stands on its own. Scope: implement NarTransfer/NarServer over libp2p in fabric-libp2p, wire Libp2pFabric: PeerFabric (directory from TASK-103 + this transfer + node discovery), and add a libp2p analogue of the s6-p2p peer-served-build e2e.
<!-- SECTION:DESCRIPTION:END -->
