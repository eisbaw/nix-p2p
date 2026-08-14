---
id: TASK-118
title: >-
  BitTorrent peer and content discovery: tracker/Mainline bootstrap with no
  injected magnet
status: To Do
assignee: []
created_date: '2026-08-10 22:23'
updated_date: '2026-08-14 21:49'
labels:
  - bittorrent
  - discovery
  - privacy
  - wave-2c
  - deferred-pending-202
dependencies:
  - TASK-75
  - TASK-96
  - TASK-100
  - TASK-102
  - TASK-117
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement the selected TASK-117 bootstrap contract behind ContentDiscovery and the BitTorrent transport. A fresh client starts with a Nix StorePath/NarHash request plus operator-level bootstrap configuration only; it must find the torrent/swarm and peers without p2p-claim, magnet, infohash or torrent-file injection. Exercise tracker and trackerless Mainline modes where the grounding contract supports them, and keep participation/privacy controls explicit.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A provider publishes a raw-NAR torrent through the single publication filter and a fresh client resolves its transport locator and peer set from NarHash/StorePath with no per-content locator supplied out of band.
- [ ] #2 A tracker-backed scenario and a trackerless Mainline-DHT scenario both run, or an unsupported mode is tied to the evidenced TASK-117 no-go; neither may silently fall back to Iroh content discovery.
- [ ] #3 Peer discovery crosses a real network namespace and records tracker/DHT bootstrap, announce, lookup and peer-connection timings plus third-party dependencies.
- [ ] #4 Client-only, DHT-server, publish-disabled and leech modes are independently configurable and verified by observed inbound/outbound protocol traffic, not configuration narration.
- [ ] #5 Dead discovery infrastructure is reported as unavailable and produces bounded upstream fallback; a lying peer or corrupt piece cannot pass BLAKE3 gate-1 or Nix gate-2.
- [ ] #6 The implementation interoperates with an independent BitTorrent client for the selected representation, or the precise extension that prevents interoperability is documented and measured.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
This owns BitTorrent-native peer/content discovery. It may reuse the common policy seam and publication gate, but not Iroh's tracker or Iroh content DHT as its locator oracle.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
