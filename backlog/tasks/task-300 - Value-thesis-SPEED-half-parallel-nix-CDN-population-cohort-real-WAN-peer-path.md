---
id: TASK-300
title: >-
  Value thesis: SPEED half (parallel-nix CDN) + population cohort + real-WAN
  peer path
status: To Do
assignee: []
created_date: '2026-08-21 11:35'
labels:
  - testing
  - measurement
  - follow-up
dependencies:
  - TASK-282
  - TASK-298
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-282 AC#3 measured the BYTE thesis (peer /nar4 zstd wire vs real cache.nixos.org, sample n=3, fail-closed): peers SUPPLEMENT at near-parity (~1.02x), do not beat the CDN on transport bytes. Three things remain for a full value-thesis verdict: (1) SPEED - measure the CDN the way NIX actually downloads (parallel connections / real substituter path), not a single-stream sample that flatters peers; only then can a peer-vs-CDN speed comparison be honest (currently UNPROVEN, wall_clock_comparison.comparable=false). (2) POPULATION - the n=3 cohort is reference-free/cached and size/compressibility-spread, NOT a fetch-weighted representative workload draw; measure over a representative closure/fetch distribution. (3) REAL-WAN - the peer arm is a hermetic KVM LAN (bytes are link-independent so the byte finding holds, but wall clocks are LAN not WAN); a real public-internet peer path (coordinate 207/168/247) is needed for a speed verdict.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The CDN speed baseline is measured via nix's real parallel download path (not single-stream); the peer-vs-CDN speed comparison is either resolved to a magnitude-bounded finding or explicitly kept UNPROVEN with the parallel-CDN number recorded.
- [ ] #2 The byte finding is re-run over a fetch-weighted/representative cohort (not n=3 hand-picked) and a real-WAN (or genuinely non-hermetic) peer path, upgrading it from sample-level to a population-level value-thesis result.
<!-- AC:END -->
