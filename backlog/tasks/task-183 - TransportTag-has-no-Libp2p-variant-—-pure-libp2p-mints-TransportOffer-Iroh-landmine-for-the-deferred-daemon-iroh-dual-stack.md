---
id: TASK-183
title: >-
  TransportTag has no Libp2p variant — pure-libp2p mints TransportOffer::Iroh;
  landmine for the deferred daemon-iroh dual-stack
status: To Do
assignee: []
created_date: '2026-08-13 02:20'
updated_date: '2026-08-15 23:19'
labels:
  - peer-fabric
  - fabric-libp2p
  - transport
  - discovery
  - wave-2c
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
mped review: the pure-libp2p binary requires Axis::Transfer(TransportTag::Iroh) and mints TransportOffer::Iroh (daemon-libp2p main.rs:338, lib.rs:213/280). TransportTag has only Iroh/BitTorrent. The fabric-libp2p ADR (transport.rs:7-30) documents this and flags: two transfers under one Iroh tag would SILENTLY CLOBBER one. Fine for single-stack, but a real landmine for the DEFERRED dual-stack daemon-iroh (TASK-145) which composes iroh transfer + libp2p directory. Resolve (add a Libp2p TransportTag variant or a disambiguation) BEFORE daemon-iroh is built. peer-fabric/fabric-libp2p concern.
<!-- SECTION:DESCRIPTION:END -->
