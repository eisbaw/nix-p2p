---
id: TASK-117
title: 'GROUNDING: BitTorrent content identity, bootstrap and representation contract'
status: To Do
assignee: []
created_date: '2026-08-10 22:23'
updated_date: '2026-08-14 21:49'
labels:
  - grounding
  - bittorrent
  - irreversible
  - wave-2c
  - deferred-pending-202
dependencies:
  - TASK-37
  - TASK-45
  - TASK-48
  - TASK-95
  - TASK-96
  - TASK-110
  - TASK-114
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Before implementing a BitTorrent backend, settle how a Nix request that begins with StorePath/NarHash reaches a standard BitTorrent swarm without a user supplying a magnet, infohash or torrent file. RawNarV1 remains the universal uncompressed content identity, while BitTorrent infohashes identify torrent metadata/pieces. Compare per-NAR and closure-level torrents, tracker and Mainline bootstrap, retained versus regenerated metadata, raw versus canonical-compressed payloads, v1/v2/hybrid compatibility, and the privacy/resource consequences. Produce an implementable contract; an evidenced architectural no-go for a cell is valid, silent hand-waving is not.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A versioned mapping contract starts from the data the daemon actually has at request time and specifies how it obtains torrent metadata and peer candidates with no per-content CLI injection or Iroh content-discovery dependency.
- [ ] #2 The analysis compares per-NAR and closure torrents, v1/v2/hybrid infohashes, tracker and Mainline DHT bootstrap, metadata retention/regeneration, random access, seeding cost and interoperability with an independent client.
- [ ] #3 Privacy and participation are priced: published keys, query exposure, tracker/DNS/Mainline dependencies, client-only versus server behavior, leech semantics and the ability to disable publication independently of lookup.
- [ ] #4 Golden vectors cover the selected NarHash/StorePath-to-torrent contract, and a deliberate one-byte or codec-setting mutation changes only the transport locator while Nix gate-2 remains authoritative.
- [ ] #5 If a fully independent standard BitTorrent bootstrap cannot meet the contract, the record names the minimum side channel or protocol extension required and marks unsupported tournament cells explicitly.
- [ ] #6 Raw and compressed representations are separate explicit arms. The contract resolves TASK-110 cardinality by pinning either a bounded (transport,representation) discriminator or one bounded composite BitTorrent offer, re-derives amplification/golden vectors for any schema amendment, and forbids simultaneous duplicate offers of one frozen kind.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Design-for-test and freeze gate for the BitTorrent backend. TASK-75 implements the selected raw representation; a later task owns compressed representation.

Iroh-first gate: this task cannot start until TASK-45 closes the production-shaped Iroh operator journey and TASK-88 has frozen the Iroh measurement artifact.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
