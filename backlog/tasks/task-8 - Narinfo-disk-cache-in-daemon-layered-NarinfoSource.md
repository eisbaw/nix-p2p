---
id: TASK-8
title: Narinfo disk cache in daemon (layered NarinfoSource)
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-08 07:34'
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
- [ ] #1 Second run: daemon receives NONZERO narinfo requests AND upstream narinfo hits are 0 (oracle-pairing rule; client nix cache wiped per scenario)
- [ ] #2 Negative caching both directions with concrete TTLs (defaults: positive 30d, negative 3600s): 404 persists during the negative TTL after mock publication, fetch succeeds after expiry
- [ ] #3 Cache stores verbatim BYTES, not parsed structs; property test: arbitrary well-formed narinfos (unknown fields, odd ordering, multiple Sig, absent Deriver, empty References) byte-identical through daemon+cache, across a restart
- [ ] #4 Validate-then-atomic-rename: a truncated upstream narinfo never enters the cache (mid-body truncation poisoning test); corrupt entries discarded and refetched, never served
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-2: the testproxy fixture cache mirrors the upstream layout exactly (<hash>.narinfo, nar/<file>.nar) with atomic tmp+rename under <root>/.tmp and passes nix-cache-info through VERBATIM. That is the FIXTURE's cache, a different concern from the daemon's narinfo cache: per TESTING.md the daemon must treat narinfo as byte-verbatim end-to-end with an EMPTY transport-field rewrite allowlist (wave 2 populates URL/Compression/FileHash/FileSize only, never signed fields). Do NOT mirror testproxy's adversarial wrong/stale-narinfo mutation - that mutation lives only in the fixture's fault injector.
<!-- SECTION:NOTES:END -->
