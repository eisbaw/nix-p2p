---
id: TASK-95
title: OPTIONAL offline store census for later policy analysis
status: To Do
assignee: []
created_date: '2026-08-10 08:43'
updated_date: '2026-08-11 20:19'
labels:
  - optional
  - measurement
  - policy
  - wave-2b
dependencies:
  - TASK-9
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Optional later measurement of aggregate store composition and size distribution. It is not part of the publication privacy gate and no production discovery task depends on it. Keep prior dated figures as observations only; request-weighted and longitudinal analysis remains TASK-127.
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
Superseded on the discovery critical path by the owner-selected KISS design on 2026-08-11: TASK-102 maintains an append-only allowlist learned from requested NARs proven public by cache.nixos.org. Do not schedule this census before decentralized NAR discovery.
<!-- SECTION:NOTES:END -->
