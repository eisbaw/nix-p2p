---
id: TASK-99
title: 'Iroh peer-link compression: negotiated zstd with raw fallback'
status: To Do
assignee: []
created_date: '2026-08-10 09:10'
updated_date: '2026-08-13 14:56'
labels:
  - wave-2b
dependencies:
  - TASK-24
  - TASK-62
  - TASK-89
  - TASK-94
  - TASK-103
  - TASK-114
  - TASK-115
  - TASK-116
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
- [ ] #5 Codec/version is negotiated explicitly per connection; raw remains available, mixed-version peers interoperate, and unsupported codec negotiation falls back to raw or upstream with a named reason.
- [ ] #6 Decode is streaming and bounded by signed NarSize, zstd window, CPU/time and memory limits; decompression bombs, corruption and truncation fail closed with bounded resource use.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Authoritative order: mandatory decentralized Iroh node and content discovery TASK-89/TASK-103/TASK-116 and authenticated HTTPS land first. This task then adds negotiated Iroh zstd; TASK-87/88 exercise raw and compressed Iroh; comparative raw Stage A is TASK-125; BitTorrent starts only at TASK-117/75. Tracker work is optional tournament comparison and is not a prerequisite. Raw fallback remains mandatory.

COMPASS 2026-08-13: link compression is THE break-even lever (raw NAR vs compressed CDN) - the single feature that most determines whether the value thesis passes. It is filed IROH-ONLY and blocked behind the iroh discovery chain (89/116/103), but the shipped primary transport is libp2p (PRD Wave-2c). Re-scope: generalise compression to the transport-agnostic NarTransfer/NarServer seam (both backends) OR file a libp2p sibling, and re-audit the iroh-89/116 deps for staleness under libp2p-primary. As filed, the most thesis-critical feature is pinned to a non-shipped stack.
<!-- SECTION:NOTES:END -->
