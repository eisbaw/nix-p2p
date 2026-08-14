---
id: TASK-201
title: >-
  fabric-iroh: adopt peer_fabric::codec (negotiated zstd link compression) on
  the iroh NarTransfer/NarServer path
status: To Do
assignee: []
created_date: '2026-08-14 07:14'
labels:
  - wave-2b
dependencies:
  - TASK-99
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-99 landed the transport-agnostic peer-LINK compression codec in peer_fabric::codec (WireCodec/negotiate_serve_codec/BoundedZstdDecoder/compress_zstd, with the bounded-decode bomb/corruption/truncation integrity bites) and WIRED it into the shipped-primary fabric-libp2p (new /nar/3 protocol, per-connection codec negotiation, raw fallback). The codec module is deliberately transport-agnostic so fabric-iroh can reuse it verbatim. This task wires it into the iroh backend's NAR transfer/serve path so an iroh node also compresses the link (raw NAR vs compressed CDN break-even lever) with the SAME frozen BLAKE3(RawNarV1) addressed unit and the SAME bounded-decode integrity guarantees. NOTE: iroh-blobs already carries its own bao-verified transfer; the seam decision here is whether to negotiate zstd inside the iroh transfer or keep iroh raw and rely on libp2p as the compressed primary — decide against PRD Wave-2c (libp2p is primary). Reuse peer_fabric::codec; do NOT re-implement.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 fabric-iroh's NarTransfer/NarServer negotiate the peer_fabric::codec zstd/raw codec per connection, addressed unit stays BLAKE3(RawNarV1), raw fallback mandatory
- [ ] #2 bounded streaming decode reused from peer_fabric::codec (bomb/corruption/truncation fail closed, bounded memory), proven by mutation on the iroh path
- [ ] #3 content id unchanged by compression on the iroh path; golden vectors + independence stay green
<!-- AC:END -->
