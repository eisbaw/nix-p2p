---
id: TASK-27
title: 'Narinfo disk cache: bounds/eviction + restart-scan cost'
status: To Do
assignee: []
created_date: '2026-08-08 11:24'
updated_date: '2026-08-08 17:59'
labels:
  - wave1-followup
  - daemon
  - hardening
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The task-8 narinfo disk cache (daemon/src/narinfo_cache.rs) is UNBOUNDED on disk: one .nic entry per distinct narinfo seen, never evicted. Two compounding costs: (a) disk usage grows without limit; (b) NarinfoDiskCache::new() runs rebuild_index(), an O(entries) synchronous full-scan (read+decode+validate every .nic) before the daemon serves, so a large cache slows every restart. Decide a bound + eviction policy (size/count/LRU by mtime or fetched_at) and make restart warm-up cheaper (e.g. a compact index file, or lazy index). Sibling of TASK-25 (which is the NAR-side timeout/NarSize abort, a different concern).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A configurable bound caps on-disk narinfo entries (count or bytes) with a documented eviction policy
- [ ] #2 Restart warm-up is not O(entries) full-parse, or is explicitly bounded/lazy
- [ ] #3 Bite test: exceeding the bound evicts the oldest/coldest entries and the cache stays under the cap
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
task-13 triage: KEEP for wave-2 - narinfo disk-cache bounds/eviction + O(entries) restart scan is a distinct sizable FEATURE (eviction policy), not a wave-1 correctness bug. The cache is opt-in and unbounded-by-design in wave-1; ENOSPC on it now proven fail-closed/passthrough by task-13.
<!-- SECTION:NOTES:END -->
