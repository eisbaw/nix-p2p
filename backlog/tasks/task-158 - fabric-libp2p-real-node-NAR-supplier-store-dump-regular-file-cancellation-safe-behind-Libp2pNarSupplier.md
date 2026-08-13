---
id: TASK-158
title: >-
  fabric-libp2p: real node NAR supplier (store-dump / regular-file,
  cancellation-safe) behind Libp2pNarSupplier
status: To Do
assignee: []
created_date: '2026-08-12 08:38'
updated_date: '2026-08-13 09:07'
labels:
  - libp2p
  - fabric
  - serve
  - supply
  - wave-2c
dependencies:
  - TASK-151
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-151's Libp2pNarSupplier has only an in-memory source (MemoryNarSupplier, tests/inline). A real libp2p-serving node needs a supplier that regenerates a raw NAR on demand from the store (nix-store --dump) or a raw-NAR regular file, WITHOUT holding it at rest (the task-61 regenerate-on-demand model) and cancellation-safely (owned process group), mirroring fabric-iroh's SupplyPlan Process/RegularFile sources + TaskSupervisor.execute_process. Add those NarSource variants (Process/RegularFile) to fabric-libp2p/src/nar.rs behind the same NarSupplyPlan, keeping declared-size-before-produce and NO ENUMERATION. Likely reached via a CatalogProbe-style seam the daemon implements (the daemon wiring is TASK-146).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Libp2pNarSupplier has Process and RegularFile sources that regenerate on demand without holding the NAR at rest, preserving declared-size-before-produce
- [ ] #2 production is cancellation-safe (process group reaped on shutdown), no unkillable worker
<!-- AC:END -->
