---
id: TASK-17
title: Revise candidate figures to the settled design
status: To Do
assignee: []
created_date: '2026-08-07 22:06'
updated_date: '2026-08-11 21:57'
labels:
  - docs
  - deferred-post-holdout
dependencies:
  - TASK-124
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Revise architecture and candidate figures only after TASK-124 reconciles the holdout verdict and selects the next product plan. Earlier figures teach a settled DHT-authoritative/public-sharing design that this wave has reopened. Depict the evidence-supported Iroh/BitTorrent discovery, codec, participation and fallback paths; show unsupported/no-go mechanisms explicitly and keep experimental candidates labelled. Do not turn a tournament nominee into the canonical architecture before the re-plan.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Figures match TASK-124's evidence-supported mechanisms and profiles; they do not label global DHT, public sharing, BitTorrent or adaptive policy canonical unless the re-plan did.
- [ ] #2 Unsupported/no-go paths, safe install defaults, upstream fallback, identity/trust boundaries and raw/compressed representation distinctions are visually explicit.
- [ ] #3 PRD stale-figure warning is replaced by a dated provenance/version note and an automated check or review pin catches future drift.
- [ ] #4 Figures reflect the PeerFabric backend-agnostic architecture (decided 2026-08-11): the three seams (NarinfoSource / NarSource / PeerFabric), iroh and libp2p as swappable backends behind PeerFabric, adopt-not-invent discovery, and the one-backend-per-binary crate split (peer-fabric <- daemon-core <- fabric-* <- daemon-{iroh,libp2p}). fig-arch-5-peer-fabric.svg already depicts this as the cohesive overview; reconcile the stale figures (fig-arch-3, fig-candidate-B/C) to it, and keep fig-arch-5's backend primary/fallback in sync with the TASK-126 spike outcome.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-08-11: docs/peer-fabric-seam.md + figures/fig-arch-5-peer-fabric.svg now capture the current architecture (PeerFabric seam, backend-agnostic, crate split). README and figures/README already reference fig-arch-5. This task's remaining job is reconciling the OLDER stale figures (fig-arch-3 wave-2 target, fig-candidate-B/C) to that design after the TASK-124 re-plan, and keeping fig-arch-5 in sync if the adopted backend flips.
<!-- SECTION:NOTES:END -->
