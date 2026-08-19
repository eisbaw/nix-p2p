---
id: TASK-271
title: 'Compressed-NAR cache: the lever to make peers beat the CDN on slow links'
status: To Do
assignee: []
created_date: '2026-08-19 20:20'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-269 finding: nix-p2p loses to cache.nixos.org on SLOW links (<~32 Mbps effective) purely because it compresses ON THE FLY, per serve — the per-serve compress CPU is the bottleneck. Measured on git@16 Mbps: zstd-19 MATCHES xz's file size (8.66 vs 8.01 MB) and decompresses 10x faster (0.04 vs 0.34 s), but costs 24 s of compress CPU EVERY serve; the CDN's xz is precomputed once at build time (zero per-serve cost). So no codec wins the slow links under the current stateless serve-raw-compress-on-the-fly design.

THE LEVER: if a peer CACHED the compressed NAR (compress once at a high level, serve many), the per-serve compress cost amortizes and zstd-19 would beat the CDN's xz even at 16 Mbps (matches ratio, 10x faster decompress). This is a real architectural trade-off vs the current 'nothing at rest / no blob store' design (README): a bounded compressed-artifact cache would buy slow-link competitiveness at the cost of on-disk state + a retention policy.

Deferred behind discovery + LAN-first per the North Star (the org/LAN product wins on raw bytes at LAN speed and needs no compression at all). Revisit only if a home-bandwidth WAN swarm becomes a target. Evidence: docs/profiling.md TASK-269 section + evidence/task-269/.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A bounded, expiring compressed-NAR cache (compress once at a chosen level, serve many) is evaluated: does amortized zstd-high beat the CDN's xz on slow links, and at what cache size/hit-rate does it pay
- [ ] #2 The on-disk-state trade-off vs the current stateless design is stated explicitly (retention policy, disk budget, integrity of the cached artifact); NarSize vs compressed-wire units kept separate; no floats in decision fields
<!-- AC:END -->
