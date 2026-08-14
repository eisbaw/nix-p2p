---
id: TASK-119
title: 'REVIEW/JOURNEY: zero-injection BitTorrent serves a real Nix build'
status: To Do
assignee: []
created_date: '2026-08-10 22:23'
updated_date: '2026-08-14 21:49'
labels:
  - review
  - journey
  - e2e
  - bittorrent
  - wave-2c
  - deferred-pending-202
dependencies:
  - TASK-83
  - TASK-118
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Run the BitTorrent vertical slice as an operator, then review it before it enters the tournament. Prime a holder from a real /nix/store path; a fresh client with no content-specific flags discovers it through the selected BitTorrent mechanism, downloads it over BitTorrent, and completes a real Nix substitution. Exercise graceful upstream fallback and make the logs/operator controls understandable.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A one-command journey runs holder and client with fresh state and no p2p-claim, magnet, infohash, torrent-file or peer-address injection, then completes a real Nix build from BitTorrent.
- [ ] #2 Provider-side BitTorrent bytes, client source attribution, upstream-byte contrast, BLAKE3 gate-1 and Nix gate-2 all prove the peer path; disabling BitTorrent discovery restores upstream egress.
- [ ] #3 Holder loss before and during transfer yields bounded S2 behavior: the build succeeds through upstream or fails with the predeclared honest boundary, never hangs or installs wrong bytes.
- [ ] #4 Logs identify discovery mechanism, selected peer, raw representation, bytes, duration and fallback reason without exposing private holdings; operator friction becomes explicit tasks.
- [ ] #5 An architecture, QA and operator-journey review records blockers before TASK-121 can run; unresolved correctness, privacy or resource blockers keep this task open.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Interspersed review/e2e gate for the raw BitTorrent vertical slice.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
