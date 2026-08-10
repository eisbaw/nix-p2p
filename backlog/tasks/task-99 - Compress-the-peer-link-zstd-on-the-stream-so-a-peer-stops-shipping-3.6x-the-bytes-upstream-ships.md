---
id: TASK-99
title: >-
  Compress the peer link (zstd on the stream), so a peer stops shipping 3.6x the
  bytes upstream ships
status: To Do
assignee: []
created_date: '2026-08-10 09:10'
updated_date: '2026-08-10 09:16'
labels:
  - wave-2b
dependencies:
  - TASK-94
  - TASK-62
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
THE fix for the wire-cost asymmetry that TASK-94 measures, and the reason that asymmetry is not fatal. See figures/fig-arch-4-signing-and-compression.svg for the whole picture in one page.

THE PROBLEM, measured 2026-08-10 on 20 signed paths >10 MiB from the live cache: cache.nixos.org serves xz at FileSize/NarSize = 0.278 aggregate (median 0.216). Our peers serve RAW nar - daemon/src/rewrite.rs rewrites Compression:none with FileHash=NarHash and FileSize=NarSize, asserted in daemon/tests/narinfo_rewrite.rs. So a peer moves ~3.6x the bytes upstream moves for the same store path, and must sustain >75 MB/s (604 Mbit/s) upload merely to BREAK EVEN before discovery latency is counted. A home uplink is 1.25-5 MB/s. Below the threshold no NAR size wins and the deficit grows with size. Every speedup number this project has published was measured against a FIXTURE cache that also served uncompressed (task-64's assert_unit_coincidence proves file_size == nar_size for the speedup attrs), so none of them included this.

WHY IT IS FIXABLE AND WHY IT TOUCHES NOTHING FROZEN. The ed25519 Sig covers only 1;StorePath;NarHash;NarSize;References, and NarHash is the sha256 of the UNCOMPRESSED nar. Compression/URL/FileHash/FileSize are unsigned transport fields. So the encoding on the wire is free to be anything the two ends agree on: the client decompresses and re-checks the signed hash regardless. The PRD anticipated exactly this at round 3 - the addressed-unit row reads '~3x wire bytes until per-connection zstd (a policy surface, not frozen)'.

COMPRESS THE LINK, NOT THE CONTENT - this distinction is the whole design and getting it wrong breaks the swarm:
  * The addressed unit MUST stay RawNarV1 = BLAKE3(raw nar). It is deterministic, so every peer derives the SAME blob id and a blob is shareable/multi-sourceable. It is also a FROZEN surface.
  * If we instead addressed COMPRESSED bytes, two peers compressing the same nar would produce different bytes (compressor version/settings are not reproducible), hence different ids, hence no sharing and no multi-holder fanout. Do NOT do this.
  * Rejected alternative worth recording: serve the upstream's exact .nar.xz addressed by its FileHash. It would give 0.278x AND perfect sharing among everyone who downloaded it - but nix DISCARDS the compressed file after unpacking, so it needs a retained second copy (~13 GB for this machine's signed set), which is the 'no second copy of the store' position TASK-61 just decided against. Revisit only if link compression underdelivers.

MEASURE, DO NOT ASSUME: zstd on nar data may not reach xz's ratio. Report the achieved ratio and the CPU cost, and remember TASK-64/PRD risk 11 - the peer transport is already CPU-bound at ~204 MB/s doing ~13x TCP's work per byte, so compression CPU competes with transport CPU on the same core. A ratio win that halves throughput is not a win.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The peer link carries compressed bytes while the ADDRESSED UNIT stays BLAKE3(raw nar) - assert the content id is unchanged by compression, so two peers with different compressor settings still offer the SAME blob id and can both serve one fetch
- [ ] #2 Achieved ratio and CPU cost measured on real NAR data across >=5 sizes, reported against the 0.278x upstream baseline; the net effect on end-to-end throughput is measured, not inferred from the ratio (compression CPU competes with the transport's own CPU-bound path, PRD risk 11)
- [ ] #3 Gate-2 still holds: nix accepts the result byte-identically, and a corrupt or truncated compressed stream still FAILS rather than yielding a short nar - proven by mutation at the new boundary
- [ ] #4 TASK-94's peer-wins inequality is re-evaluated with compression ON, and the README's speedup figures are re-measured or withdrawn - the current ones were taken against an uncompressed fixture upstream and overstate the peer path
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ORDERING (orchestrator, 2026-08-10): this is the FIRST thing to build. Nothing about peer-vs-cache performance is measurable until it lands, and every published speedup figure is invalid until AC#4 re-measures them. TASK-94 measures the problem; this fixes it; TASK-67 (parallel/striped fetch) is only worth pricing afterwards, because four slow peers only add up to a CDN once each peer stops shipping 3.6x the bytes. Owner's plain-language summary of the sequence: compress the wire -> turn on LAN discovery (TASK-89) -> re-measure honestly -> multi-peer fetch -> only then decide internet-scale discovery.
<!-- SECTION:NOTES:END -->
