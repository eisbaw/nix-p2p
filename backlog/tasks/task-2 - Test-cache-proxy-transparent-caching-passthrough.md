---
id: TASK-2
title: 'Test cache-proxy: transparent caching passthrough'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 22:40'
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
- [ ] #1 Repeat request served from disk cache: upstream hit counter 0 PAIRED WITH nonzero testproxy received-count (TESTING.md oracle-pairing rule)
- [ ] #2 Request log queryable: per-request kind/bytes/timing; narinfo->nar gap derivable per path
- [ ] #3 Streams large NARs without whole-file buffering; cache writes atomic (tmp+rename); concurrent same-path requests never observe partial/corrupt bytes
- [ ] #4 All 7 TESTING.md fault modes implemented (latency per path-kind, 500/503, connection reset, truncated NAR at N%, corrupted bytes, wrong/stale narinfo, unreachable), EACH with an in-process bite test proving the fault is actually emitted
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-1 (e9b3378): testproxy/ crate exists with a scaffold main.rs (banner + placeholder), no dependencies chosen. You own the HTTP stack choice for the FIXTURE and it must NOT be coordinated with the daemon's (PRD round 5: the fixture is an independent witness of wire behavior). 'just independence' now diffs workspace-local dependency SETS against an EMPTY allowlist - if you factor anything out into a shared crate, lint fails until the allowlist is edited, which is deliberate. Do not deduplicate the banner()/test pair that exists in both crates. Add fixtures on disk only after widening the cleanCargoSource filter in flake.nix (see the NOTE(task-3) comment there) or nix build will run them fixture-less and green.
<!-- SECTION:NOTES:END -->
