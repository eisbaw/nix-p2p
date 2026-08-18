---
id: TASK-183
title: >-
  TransportTag has no Libp2p variant — pure-libp2p mints TransportOffer::Iroh;
  landmine for the deferred daemon-iroh dual-stack
status: Done
assignee: []
created_date: '2026-08-13 02:20'
updated_date: '2026-08-18 00:56'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Resolved by TASK-156 in code commit 619300a. peer-fabric now has distinct TransportTag::Libp2p and TransportOffer::Libp2p, the libp2p product publishes and dispatches tag 2 natively, and TransferRegistry proves simultaneous native Iroh and Libp2p entries cannot overwrite one another. Historical Iroh-tagged libp2p records use a separate compatibility fallback namespace; an actual native Iroh backend always wins. Mandatory QA and MPED reviews returned GO, and exact just e2e passed 9/9 scenarios and 107/107 checks.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The deferred dual-stack landmine is removed: native Iroh and Libp2p have distinct registry keys and signed offer tags, with explicit bounded rollout compatibility for historical records.
<!-- SECTION:FINAL_SUMMARY:END -->
