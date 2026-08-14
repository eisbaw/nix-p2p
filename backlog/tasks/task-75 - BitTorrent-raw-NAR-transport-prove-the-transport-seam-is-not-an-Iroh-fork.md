---
id: TASK-75
title: 'BitTorrent raw-NAR transport: prove the transport seam is not an Iroh fork'
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-14 21:48'
labels:
  - wave-2b
  - deferred-pending-202
dependencies:
  - TASK-24
  - TASK-62
  - TASK-85
  - TASK-99
  - TASK-114
  - TASK-117
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement the raw-NAR BitTorrent transport chosen by TASK-117 after the complete Iroh discovery/compression/measurement milestone. This task owns piece/metainfo generation, bounded seeding/fetch and integrity bridging from the transport-specific infohash to universal RawNarV1. TASK-118 owns locator/peer discovery. The TransportRegistry dispatches an explicitly selected offer; selection policy is deliberately outside the registry.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A real BitTorrent Transport fetches a raw /nix/store-backed NAR, verifies BLAKE3 gate-1, and completes Nix signature/NarHash gate-2 end to end.
- [ ] #2 Adding raw BitTorrent requires no silent change to the frozen claim schema; any required amendment is reported as a failed freeze and deep-gated rather than edited under this task.
- [ ] #3 The registry executes only the offer explicitly selected by test/config/policy input; Iroh and BitTorrent arms are each reachable and no Iroh-first, BitTorrent-first or fastest-first preference exists in dispatch.
- [ ] #4 Torrent/metainfo creation, piece verification, seeding lifetime, upload/concurrency, cleanup and metadata/disk growth are bounded and exercised from the real store supply path.
- [ ] #5 A corrupt/truncated piece, dead seeder and budget exhaustion have named bounded failure and upstream fallback; gate-1/gate-2 cannot be bypassed.
- [ ] #6 Provider socket bytes, protocol/control bytes and uncompressed NarSize are distinct fields consumed by TASK-125 and TASK-122; honest interoperability/NAT/tracker/DHT limits are recorded.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Raw BitTorrent only. TASK-125 consumes its raw measurements; TASK-121 is the conditional compressed arm; TASK-122 runs both. No registry preference is frozen here.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
