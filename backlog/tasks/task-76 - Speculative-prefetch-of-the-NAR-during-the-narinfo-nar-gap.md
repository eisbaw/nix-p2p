---
id: TASK-76
title: Speculative prefetch of the NAR during the narinfo->nar gap
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-10 22:57'
labels:
  - wave-2b
  - deferred-post-holdout
dependencies:
  - TASK-124
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRD MVP scope names 'speculative prefetch'. Nothing exists. The design input was measured by TASK-35 against the REAL cache.nixos.org: median narinfo->nar gap ~300 ms, tail to 3.08 s (the wave-1 loopback measurement said the gap was near-zero and that was an ARTIFACT - the real gap is what makes prefetch conceivable at all).

The idea: the moment a narinfo is served, we know the NarHash, so peer resolution can start BEFORE nix asks for the NAR - hiding resolve latency inside a window nix is already spending. TASK-35's conclusion was that hedging carries the offload case and prefetch is a TAIL-ONLY optimization, so this is explicitly a lower-value item - file it, do not over-invest.

Costs to account for honestly: a prefetch that nix never requests is pure waste (wasted dials, wasted bytes, wasted RAM at 2.0 B/B on the holder), and the wasted bytes must be counted - the counting rule reserves a channel for exactly this class of loss. Interacts with TASK-52 (counting rule v3) and TASK-44 (policy model): do NOT ship a prefetch policy the data has not justified.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Prefetch is measured against the REAL gap distribution from task-35 (median ~300 ms, tail 3.08 s), not a loopback one, and against the WAN-shaped arm from task-63
- [ ] #2 Wasted prefetches are COUNTED (bytes and dials for content nix never requested) in the counting rule's waste channel, not silently absorbed
- [ ] #3 A net-benefit verdict with the data behind it; 'not worth it' is a legitimate and expected outcome given task-35's finding that prefetch is tail-only
<!-- AC:END -->
