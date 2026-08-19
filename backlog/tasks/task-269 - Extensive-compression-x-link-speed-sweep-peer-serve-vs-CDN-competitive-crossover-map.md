---
id: TASK-269
title: >-
  Extensive compression x link-speed sweep: peer-serve vs CDN competitive
  crossover map
status: To Do
assignee: []
created_date: '2026-08-19 19:06'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-268's first cut showed the peer-vs-CDN crossover is set by the raw/compressed byte penalty (2.1-6.3x, serving RAW), and that LINK COMPRESSION is the lever that collapses it. But we have never swept it: TASK-94/198/203 did the raw baseline + one/two shaped-link points, and TASK-99 did negotiated zstd on the DEPRIORITIZED iroh path. No systematic {algorithm x level} x {link speed} x {package} sweep exists for the primary libp2p serve path. This task builds it and produces the competitive crossover map.

KEY ASYMMETRY to model honestly: the peer compresses ON THE FLY, PER SERVE (it regenerates the raw NAR via nix-store --dump, then compresses each serve), whereas cache.nixos.org serves PRE-COMPUTED compressed files. So the peer pays compression CPU on every serve; the sweet spot is compression-ratio-vs-per-serve-CPU, not just ratio.

MEASURE (a data sweep + the transfer model, NOT a full shaped-link e2e): for each real package NAR (hello/curl/git/python3 + a couple more sizes) x each compression setting {none, lz4, zstd-1/3/9/19, xz-6/9, optionally brotli}: compressed size (exact bytes -> ratio), compress CPU time, decompress CPU time. Then model peer transfer at a documented set of link speeds (e.g. ~2, 12.5, 125, 1000 MB/s): peer_wall = regen(measured ~22ms + 2.2GB/s) + compress + compressed_bytes/link + decompress. Compare to the real CDN baseline (already measured; the cache's zstd/xz FileSize is the reference). Output the CROSSOVER MAP: per (package, compression, link) does the peer beat the CDN, the crossover link-speed per compression, and the compression sweet spot.

The point: does link compression make the peer competitive at REALISTIC link speeds (LAN and home), and which codec/level is the ratio-vs-CPU sweet spot for on-the-fly per-serve use.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Sweep {none, lz4, zstd L1/L3/L9/L19, xz L6/L9} x real package NARs (>=5 sizes incl hello/curl/git/python3): measure compressed size (exact bytes), compress CPU time, decompress CPU time. BOUNDED (cap big-NAR x high-level combos to avoid a CPU-hog farm on the shared box; document the caps + any skipped cell)
- [ ] #2 Peer wall-time model per (package, compression, link-speed in a documented set): regen (measured) + compress + compressed_bytes/link + decompress; account for ON-THE-FLY per-serve compression CPU (peer compresses each serve; CDN is pre-computed)
- [ ] #3 Competitive CROSSOVER MAP vs the real CDN baseline: per (package, compression, link) peer-beats-CDN yes/no, the crossover link-speed per compression, and the ratio-vs-CPU sweet-spot codec/level
- [ ] #4 NO floats in decision fields: compression ratio as exact num/den, sizes as integer bytes, times as integer ns/us; RAW NarSize vs per-codec compressed-wire bytes kept as SEPARATE unit-suffixed fields, never conflated
- [ ] #5 Honest caveats stated in the output: EXCLUDES discovery latency (the real e2e wildcard, PRD risk 3); this is a compression+transfer MODEL not a real shaped-link e2e; the CDN baseline is single-sample + specific to this host's link. Evidence + a re-derivable results file committed
- [ ] #6 Findings summarized in docs/profiling.md; if a codec/level is a clear sweet spot for the primary libp2p serve path, note it as a potential negotiated-link-compression default (file a follow-up if it warrants implementation)
<!-- AC:END -->
