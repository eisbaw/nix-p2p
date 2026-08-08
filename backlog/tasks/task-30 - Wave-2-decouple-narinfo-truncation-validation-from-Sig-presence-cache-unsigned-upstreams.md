---
id: TASK-30
title: >-
  Wave-2: decouple narinfo truncation validation from Sig presence (cache
  unsigned upstreams)
status: To Do
assignee: []
created_date: '2026-08-08 11:24'
labels:
  - wave2
  - daemon
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
narinfo_cache.rs is_well_formed_narinfo() requires a Sig: line as its cheap tail-truncation signal, which is correct for wave-1's signed-only targets but means a legitimately UNSIGNED narinfo (private/unsigned substituter) is never cached - passed through but refetched every request. Decouple structural-completeness/truncation detection from signature presence so unsigned upstreams cache too (e.g. length/terminator-based completeness, or an explicit allow-unsigned config).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A complete unsigned narinfo is cached and served from disk on repeat
- [ ] #2 Truncation detection still bites without relying on Sig presence
<!-- AC:END -->
