---
id: TASK-4
title: >-
  Product daemon skeleton: transparent proxy behind NarinfoSource/NarSource
  traits
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 22:05'
labels: []
dependencies:
  - TASK-1
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The wave-0 product per PRD: a transparent binary-cache proxy whose only cleverness is structure. NarinfoSource and NarSource traits with a single UpstreamHttp implementation; /nix-cache-info served with correct semantics (priority below cache.nixos.org 40, WantMassQuery); streaming NAR passthrough; fast clean errors when upstream is down (no hangs on the build path - Nix must fall back quickly, TESTING.md S2/fault table).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Container nix client substitutes fixture closure via daemon -> testproxy -> mock; S1 byte-identity oracle passes
- [ ] #2 nix-cache-info advertises priority < 40 and correct WantMassQuery; verified by a test reading it through a real nix client ordering decision
- [ ] #3 Upstream unreachable: daemon answers errors within 2s, never hangs; client build still succeeds via fallback substituter
- [ ] #4 All upstream access goes through the two traits; no direct HTTP calls elsewhere (compile-time seam for p2p waves)
- [ ] #5 Upstream unreachable: clean error within 2s, no hang; HTTP client auto-decompression DISABLED - gzip Content-Encoding upstream test asserts FileHash still verifies at the client (reqwest/hyper default-decompression trap)
<!-- AC:END -->
