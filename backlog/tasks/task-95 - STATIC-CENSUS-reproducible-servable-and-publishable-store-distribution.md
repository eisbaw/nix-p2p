---
id: TASK-95
title: 'STATIC CENSUS: reproducible servable and publishable store distribution'
status: To Do
assignee: []
created_date: '2026-08-10 08:43'
updated_date: '2026-08-10 22:53'
labels:
  - wave-2b
dependencies:
  - TASK-9
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Produce the early deterministic denominator needed by publication and wire-cost work. The census separates derivations, servable outputs, local/ultimate content, locally signed content and content proven public by bounded upstream-narinfo widening; reports both path and byte distributions; and emits a dated reproducible snapshot. Live-machine numbers are observations that change after GC/channel updates, never acceptance constants. Request-weighted coverage and insert/delete churn require running/longitudinal evidence and belong to TASK-127.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A fixture store with known drv/output/ultimate/signed composition yields exact counts and bytes, including zero-safe all-drv and empty cases; mutation of one large path changes byte totals exactly.
- [ ] #2 A live run emits dated path and byte counts for drv, servable, ultimate, locally signed and safely upstream-widened-public sets without pinning them within a tolerance of an earlier mutable machine snapshot.
- [ ] #3 Size deciles, compression metadata where available and byte-concentration top-N shares are reported with NarSize/FileSize units separate and impossible/unknown fields explicit.
- [ ] #4 The JSON artifact records command/tool/schema version, source database identity, timestamp and input/output hashes so later observations can be compared honestly.
- [ ] #5 PRD.md and backlog references present prior figures with dates/provenance and identify TASK-127 as the owner of request-weighted coverage and longitudinal insert/delete churn.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Earlier 82k/108k path and 6.3k/6.7k publishable figures are retained only as dated observations. Do not require a future swarm here and do not infer deletions from registrationTime.
<!-- SECTION:NOTES:END -->
