---
id: TASK-156
title: >-
  fabric-libp2p: distinct TransportTag::Libp2p + frozen-codec OFFER_LIBP2P for
  the dual-stack transport tournament
status: To Do
assignee: []
created_date: '2026-08-12 08:38'
labels:
  - libp2p
  - fabric
  - transport
  - frozen-seam
  - wave-2c
dependencies:
  - TASK-151
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-151 landed the libp2p NarTransfer/NarServer but REUSES the NodeId-locator TransportOffer::Iroh { node } and registers Libp2pTransport under TransportTag::Iroh (see fabric-libp2p/src/transport.rs ADR), to keep the FROZEN peer_fabric ids.rs/record_codec (freeze-guarded) untouched. That is honest for a SINGLE-STACK libp2p daemon (the tag names the NodeId-locator shape; one transport per tag). It STRUCTURALLY blocks the DUAL-STACK transport tournament (iroh transfer AND libp2p transfer in ONE process under the SAME kad discovery), which needs distinct dispatch tags. This task adds, as a deliberate frozen-seam change (codex+mped wire-review, golden vectors re-run): a TransportTag::Libp2p + TransportOffer::Libp2p { node } variant in peer-fabric ids.rs (update TransportTag::of/as_str), and an additive OFFER_LIBP2P=2 tag in record_codec write_offer/read_offer/check_provide_invariants/sign_provider_record mirroring the Iroh self-serve NodeId semantics. Existing golden vectors (tags 0/1) must be unaffected. Then switch Libp2pTransport::tag() to Libp2p and let a dual-stack fabric register both.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A distinct TransportTag::Libp2p + TransportOffer::Libp2p{node} exist and Libp2pTransport::tag() returns Libp2p
- [ ] #2 record_codec encodes/decodes OFFER_LIBP2P additively with self-serve NodeId semantics; all pre-existing golden vectors still pass
- [ ] #3 a dual-stack fabric can register both the iroh and libp2p transfers under distinct tags (tournament unblocked)
<!-- AC:END -->
