---
id: TASK-50
title: >-
  Local availability index: NarHash->StorePath->--dump->BLAKE3,
  announce-on-demand
status: To Do
assignee: []
created_date: '2026-08-08 20:28'
labels: []
dependencies:
  - TASK-48
  - TASK-37
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The PRD supply mechanism + the claim PRODUCER (absent from the original plan). A node must KNOW which NarHashes it holds and be able to serve them: an index mapping NarHash -> local StorePath -> (on-demand nix-store --dump) -> RawNarV1 BLAKE3, with persistence, SINGLE-FLIGHT hashing (dont re-hash a 100MB NAR concurrently), materialization/cleanup, and announce-on-demand (publish a claim when a path lands). Discovery::resolve must return the COMPLETE transport offer (NodeId + BLAKE3 + transport), not merely a holder NodeId. This is what lets a node answer yes/no per NarHash and serve from its real /nix/store (not just a fixture).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Given a store path, the index yields its NarHash and RawNarV1 BLAKE3; a node answers yes/no for a concrete NarHash from its real store (no enumeration endpoint)
- [ ] #2 Single-flight: concurrent requests for the same uncomputed BLAKE3 hash once; persistence survives restart; a GCed store path is dropped from availability
<!-- AC:END -->
