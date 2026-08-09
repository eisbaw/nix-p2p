---
id: TASK-61
title: 'iroh provider holds served content in RAM (MemStore): spill to disk + bound it'
status: To Do
assignee: []
created_date: '2026-08-09 13:24'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by task-42 profiling: daemon/src/transport_iroh.rs:273 uses iroh_blobs::store::mem::MemStore, so every NAR this node serves is held in RAM. Measured: a holder peaks at 2.15x the held NAR size in RSS (110 MiB NAR -> ~237 MiB peak RSS). There is no on-disk blob store and no eviction. This does not scale to announcing a real Nix store: the announce-on-demand path (task-50) derives the NAR then seeds it into the MemStore, so concurrent or large serves are memory-bound, and nothing releases it. iroh-blobs ships store::fs::FsStore as the persistent alternative. This CHANGES TASK-54's subject: the footprint to bound is memory, not disk (measured per-peer on-disk footprint was 4096 B, flat).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 IrohProvider uses a persistent/spilling store (or an explicitly bounded+evicting memory store) so a holder's RSS is NOT proportional to the size of the content it serves
- [ ] #2 Re-run just profile and show the holder RSS-vs-NAR-size relationship measured before and after; the 2.15x multiplier is the pinned before-number
- [ ] #3 The disk footprint that replaces it is bounded and cleaned up (coordinate with TASK-54); measured, not assumed
<!-- AC:END -->
