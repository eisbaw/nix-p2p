---
id: TASK-55
title: Lossless forward-compat preservation for RELAYED/gossiped/DHT-stored claims
status: To Do
assignee: []
created_date: '2026-08-08 22:15'
updated_date: '2026-08-18 20:36'
labels:
  - wave-2
dependencies:
  - TASK-101
  - TASK-103
  - TASK-118
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deferred from task-48 (mark-emulator decision B, 2026-08-09). Wave-2a drops lossless unknown-variant PRESERVATION: unknown payload/transport kinds are TOLERATED (decode succeeds, no error) but NOT re-serialized/relayed - because wave-2a has NO claim relay (nodes announce their OWN claims from their OWN availability index, task-50). The lossless-relay guarantee (a relaying/gossiping/DHT-caching node must preserve an unknown future-version field byte-for-byte so it cannot destroy v2 data in transit) EARNS ITS COST only once claim relay exists. When wave-2b adds gossip/DHT-stored/relayed claims: implement lossless preservation - preserve the EXACT RECEIVED BYTES of unknown fields (not a re-parsed serde_json::Value, which is lossy: u64-overflow -> float), bounded, so a v1 relay node forwards v2 claims intact.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A relay/gossip node forwards a claim carrying an unknown future field byte-for-byte (the field survives; a v2 consumer downstream reads it intact) - proven with a real relay hop
- [ ] #2 Preservation is via exact-received-bytes, not a lossy re-parse; bounded in size
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Downgraded 2026-08-18 (COMPASS §4): hardens lossless preservation for RELAYED/gossiped claims; there is no claim relay, and its deps (TASK-101 tracker, TASK-118 BitTorrent) are both Low/deferred.
<!-- SECTION:NOTES:END -->
