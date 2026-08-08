---
id: TASK-48
title: 'FREEZE: RawNarV1 addressed unit + iroh ALPN (golden vectors)'
status: In Progress
assignee: []
created_date: '2026-08-08 20:28'
updated_date: '2026-08-08 21:10'
labels:
  - irreversible
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The hardest wave-2 freeze (arch+codex: harder than the schema, cannot be versioned once peers hold blobs). Freeze the exact interop bytes: RawNarV1 = the exact nix-store --dump byte sequence; the BLAKE3 digest length/encoding; canonical NarHash + NodeId encodings; the iroh-blobs ALPN string; domain separation; numeric tags/bounds; and GOLDEN wire/hash vectors so two independent impls agree byte-for-byte. Separate UNIVERSAL content identity (NarHash <-> RawNarV1 BLAKE3) from TRANSPORT-SPECIFIC offers (iroh NodeId+blake3; a future BitTorrent needs an infohash/piece-layout locator, NOT just a tag). Freeze CONFIRMED at S6 interop (task-41), not before.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Golden vectors committed: for a fixed fixture NAR, the exact --dump bytes, its BLAKE3, and NarHash - a second impl (or a re-derivation) matches byte-for-byte
- [ ] #2 The iroh ALPN constant + digest encoding + domain separation are pinned as named constants with a conformance test
- [ ] #3 Content-identity (NarHash<->BLAKE3) is separated from transport-offer (NodeId+locator); a BitTorrent offer shape is representable (infohash/piece-layout slot), proving no fork
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented + gate-green (lint 0, daemon tests pass incl golden_vectors, golden checker re-derives blake3:95f49df0 from the fixture, blake3 daemon-only). Committed by orchestrator (implementer agent died on login-expired mid-finalize, work was complete+staged). Awaiting DEEP gate.
<!-- SECTION:NOTES:END -->
