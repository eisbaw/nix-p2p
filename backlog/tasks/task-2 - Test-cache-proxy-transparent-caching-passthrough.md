---
id: TASK-2
title: 'Test cache-proxy: transparent caching passthrough'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 22:05'
labels: []
dependencies:
  - TASK-1
  - TASK-3
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The fixture crate (PRD: simple, hardcoding allowed, never absorbs product modularity). Fronts a configurable upstream binary cache: /nix-cache-info, *.narinfo, nar/* passthrough with an on-disk cache, plus the request-log/counter endpoint that is the ground-truth oracle for all e2e scenarios (TESTING.md: request-count, egress, gap oracles). Exists so deep/broad tests never load cache.nixos.org.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Integration test: repeat request served from disk cache, upstream hit counter unchanged (oracle bites per TESTING.md)
- [ ] #2 Request log queryable: per-request kind, bytes, timing, plus narinfo-to-nar gap derivable
- [ ] #3 Streams large NARs without buffering whole file in memory
- [ ] #4 All 7 TESTING.md fault modes implemented (latency per path-kind, 500/503, connection reset, truncated NAR at N%, corrupted bytes, wrong/stale narinfo, unreachable), EACH with an in-process bite test proving the fault is actually emitted
<!-- AC:END -->
