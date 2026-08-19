---
id: TASK-268
title: >-
  Real-cache FETCH timing: peer-serve vs CDN download on a real link
  (competitive question)
status: To Do
assignee: []
created_date: '2026-08-19 18:30'
labels:
  - testing
  - real-upstream
  - e2e
  - measurement
dependencies:
  - TASK-254
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up carved out of TASK-254 (cheap probe half). TASK-254 proved the SHIPPED narinfo PARSER+REWRITER handles the REAL cache.nixos.org corpus (7 vendored xz/zstd narinfos, daemon-core/tests/real_corpus_narinfo.rs, wired into just test). What that does NOT prove: that the real FETCH/serve path is competitive with cache.nixos.org.

SCOPE (the heavier measurement TASK-254 deliberately deferred): actually FETCH a real .nar.zst from cache.nixos.org and TIME the two-node peer-serve path (discovery + peer fetch) against a straight CDN download, on a REAL link (not loopback). Answers the competitive question: does peer-serve beat / match the CDN for a warm holder?

CONSTRAINTS carried from 254/PRD: front the real cache THROUGH the caching testproxy so the CDN sees each path at most once; explicit small path budget asserted in the harness; polite serial low-concurrency identifying user-agent; owner sign-off before the first unattended run; OWN opt-in just recipe, NEVER part of just test / the fast gate. Real-link shaping via scripts/shaped_link*.py (TASK-70 lineage).

NUMBER DISCIPLINE: NarSize (uncompressed) vs FileSize/on-wire (compressed transport) are DIFFERENT UNITS - never compare. Report peer-vs-CDN as a magnitude-bounded delta (noise-dominated: bound |delta| vs a decision margin, sign-agnostic), integer ns/bytes-per-sec, no floats in any gate/decision field. Label where every number came from.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A real .nar.zst is fetched from cache.nixos.org through the caching testproxy, within an asserted path budget, with an identifying user-agent, as an opt-in just recipe outside just test
- [ ] #2 Two-node peer-serve time (discovery + peer fetch) is measured against the CDN download on a real (shaped, non-loopback) link
- [ ] #3 Result reported as an integer-unit, float-free, magnitude-bounded delta with NarSize-vs-transport units kept separate and every number provenance-labelled
<!-- AC:END -->
