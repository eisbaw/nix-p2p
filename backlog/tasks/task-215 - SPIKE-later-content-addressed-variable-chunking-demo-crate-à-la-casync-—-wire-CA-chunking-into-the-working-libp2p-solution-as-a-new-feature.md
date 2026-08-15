---
id: TASK-215
title: >-
  SPIKE (later): content-addressed variable-chunking demo crate à la casync —
  wire CA-chunking into the working libp2p solution as a new feature
status: To Do
assignee: []
created_date: '2026-08-15 07:07'
labels:
  - spike
  - ca-chunking
  - compression
  - demo
  - separate-crate
  - deferred
  - later
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner ask (2026-08-15): a LATER spike, as a SEPARATE crate, demoing content-addressed VARIABLE chunking à la casync/desync. Other crates likely already implement the chunker (e.g. fastcdc for content-defined chunking; possibly desync/casync-rs for the store model) — evaluate reuse before hand-rolling. The demo crate takes our WORKING libp2p solution and wires CA-chunking in as a NEW FEATURE (chunk-level content-addressed transfer + dedup), without disturbing the frozen surfaces or the shipped solution.

WHY (and how it differs from link-compression, TASK-203): link-compression (zstd on the wire) reduces the bytes of ONE NAR in flight; CA variable chunking reduces bytes ACROSS NARs by content-addressed dedup — a rebuilt/revised derivation reshares unchanged chunks, and the content-defined boundaries survive small edits (unlike fixed-size chunking). They are orthogonal byte-savers; this spike measures the CA-chunking axis the value thesis has not yet quantified.

SHAPE (exploratory demo, not production): a separate crate so it is additive and disposable — it consumes the working peer-fabric/libp2p transport + supply and layers a CDC chunk store + chunk-addressed fetch on top. It must NOT modify RawNarV1 / the frozen ContentKey / claim schema / golden vectors — the addressed unit stays the raw NAR; chunking is a transport/storage-layer demo beneath or beside it. Honest measurement is the deliverable: chunk-dedup ratio on a realistic closure/revision set, transfer-bytes saved vs whole-NAR and vs link-compression, and the CPU/index cost — so the owner can decide whether CA-chunking earns a place in the real product later.

Prior art to check: fastcdc (Rust CDC), desync (Rust casync-compatible), casync itself (the reference), nix's own experimental content-addressed store / bao. Note: nix store paths are not random (closure/revision correlation, TASK-93) — a chunk store exploits exactly that.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A SEPARATE crate (disposable demo) that consumes the working libp2p transport/supply and layers content-defined variable chunking (evaluate reuse: fastcdc / desync / casync) — hand-roll only if reuse is unfit, with the reason recorded
- [ ] #2 Wires CA-chunking as a NEW feature into the working solution WITHOUT modifying the frozen addressed unit / ContentKey / claim schema / golden vectors (additive; the raw NAR stays the addressed unit)
- [ ] #3 Honest measurement: chunk-dedup ratio on a realistic closure/revision set, transfer-bytes saved vs whole-NAR AND vs TASK-203 link-compression, plus CPU + chunk-index cost — enough for an owner keep/drop decision
<!-- AC:END -->
