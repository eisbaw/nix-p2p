---
id: TASK-17
title: Revise candidate figures to the settled design
status: To Do
assignee: []
created_date: '2026-08-07 22:06'
updated_date: '2026-08-10 23:00'
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
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Post-holdout documentation task. TASK-124 must first decide whether to cancel, supersede or admit it into the next wave.
<!-- SECTION:NOTES:END -->
