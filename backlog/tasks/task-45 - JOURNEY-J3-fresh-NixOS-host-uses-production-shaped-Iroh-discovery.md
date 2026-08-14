---
id: TASK-45
title: 'JOURNEY J3: fresh NixOS host uses production-shaped Iroh discovery'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-14 21:48'
labels:
  - journey
  - deferred-pending-202
dependencies:
  - TASK-24
  - TASK-25
  - TASK-29
  - TASK-83
  - TASK-88
  - TASK-115
  - TASK-120
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Close the Iroh-first milestone from a clean operator perspective. Install the NixOS module, select an explicit Iroh participation profile, start with fresh daemon/store/cache state and no peer/content locator injection, and complete a real Nix substitution through operational node and content discovery. Observe path, source, codec and cost; disable or break P2P and confirm bounded HTTPS-upstream fallback. File every friction point. BitTorrent is deliberately out of scope until this journey passes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A one-command fresh-host journey installs/enables the module, runs preflight, selects an Iroh participation profile and completes a real build without peer addresses or claims.
- [ ] #2 Peer service is proven by provider-side bytes, upstream-byte contrast, source/discovery/codec/path logs and Nix gate-2; fresh state prevents a warm-store false positive.
- [ ] #3 The operator can see stable NodeId, enabled Iroh mechanisms, direct/hole-punched/relay path, discovery health, resource budgets and fallback reason without debug traces.
- [ ] #4 Stopping a holder, tracker/bootstrap service or local daemon yields bounded S2 behavior over the configured HTTPS upstream; disabling P2P restores ordinary substitution.
- [ ] #5 Privacy preflight states what LAN/global Iroh modes publish/query, and consume-only is verified from another node rather than self-report.
- [ ] #6 Journey friction and documentation drift become tracker tasks or an explicit none-found record; unresolved Iroh production blockers keep the milestone open and therefore block TASK-117.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION (qa#5): 'cache.nixos.org untouched' is an OVERCLAIM - the signed narinfo still comes from upstream in wave-2a. Assert NAR-payload served by the peer (egress 0 for the NAR) + narinfo egress as nonzero context. Do not claim the cache is untouched.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
