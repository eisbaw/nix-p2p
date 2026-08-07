---
id: TASK-8
title: Narinfo disk cache in daemon (layered NarinfoSource)
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
labels: []
dependencies:
  - TASK-4
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
First real module layering: NarinfoSource becomes disk-cache-over-upstream. Mirrors Nix client TTL semantics (positive/negative narinfo caching) so daemon-side caching never makes a newly-published path invisible longer than Nix itself would. PRD risk 2 context: this persistence is what later makes repeat-path resolution local-instant when the p2p wave lands - but wave 1 only needs correct layering + persistence.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Repeat narinfo requests served from disk: upstream narinfo hit count 0 on second run (oracle asserted)
- [ ] #2 Cache survives daemon restart; corrupt cache entry is discarded and refetched, never served
- [ ] #3 Negative-cache TTL: a 404d path becomes fetchable within the configured TTL after publication to mock upstream (test manipulates mock content)
<!-- AC:END -->
