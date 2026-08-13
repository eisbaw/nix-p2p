---
id: TASK-197
title: >-
  fabric-libp2p: bao-outboard on the NAR stream wire for per-chunk verify +
  serve-side stdout passthrough
status: To Do
assignee: []
created_date: '2026-08-13 16:53'
labels:
  - libp2p
  - fabric
  - transport
  - streaming
  - wave-2c
dependencies:
  - TASK-157
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-157 replaced the request-response NAR carrier with a raw libp2p-stream protocol (/nar/2) that carries the raw NAR bytes ALONE. Two honest residuals from that cycle, both rooted in the same missing wire element - a bao outboard tree interleaved with the NAR bytes (as iroh-blobs' bao stream carries): (1) FETCH per-chunk verify - the SIZE abort is truly mid-stream, but per-CHUNK byte-corruption detection (catching a flipped byte before EOF) is not possible without the bao tree; today gate-1 BLAKE3 (frozen from_raw_nar) verifies at stream completion (single pass, memory bounded to cap+chunk). The trust property holds - a corrupt peer fails the fetch - only the detection is at EOF, not per chunk. (2) SERVE stdout passthrough - the serve side still BUFFERS the produced NAR before streaming it out, because the serve-time integrity recheck (len==declared_size AND BLAKE3(RawNarV1)==content, 'never ship the wrong bytes under the right name', exercised by a_rebuilt_store_source_is_declined_and_never_ships_wrong_bytes) must complete BEFORE any byte ships. Piping nix-store --dump stdout straight to the socket needs the bao outboard so the recheck can be incremental. Adding a bao outboard to /nar/2 (or a /nar/3) resolves both. NOTE: this changes the transport wire (churnable), not the frozen RawNarV1/claim/ContentKey/ProviderRecord surfaces.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the NAR stream carries a bao outboard so the fetcher verifies each chunk against the requested BLAKE3 as it arrives (corrupt byte caught before EOF)
- [ ] #2 the serve side pipes produced stdout to the stream without buffering the whole NAR, with the integrity guarantee preserved incrementally
<!-- AC:END -->
