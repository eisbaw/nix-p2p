---
id: TASK-83
title: >-
  iroh residual: the legacy --iroh-seed-nar binary supplies from files, not
  /nix/store (libp2p path already does)
status: To Do
assignee: []
created_date: '2026-08-09 22:24'
updated_date: '2026-08-18 20:24'
labels:
  - forward-carried-from-task-72
  - deferred-pending-202
dependencies:
  - TASK-56
  - TASK-72
  - TASK-82
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
RE-SCOPED 2026-08-18. The PRD headline supply property -- a node serves its whole /nix/store on demand, holding no second copy -- is DELIVERED on the primary libp2p path and is no longer an open gap. Verified at HEAD: daemon-libp2p wires Libp2pCatalogProbe (daemon-libp2p/src/store_probe.rs) over daemon_core::SupplyCatalogHandle into fabric_libp2p CatalogNarSupplier, which serves ProbedSource::Process running nix-store --dump (TASK-191); TASK-194 proved it container-e2e, byte-identical, with the provider never holding a .nar file.

WHAT REMAINS is an iroh-only residual: the legacy monolith binary daemon/src/main.rs:1460 still builds FileNarSupplier from --iroh-seed-nar, so the IROH binary supplies from harness-prepared raw-NAR FILES rather than the store. IndexNarSupplier exists and is tested in-process (daemon/tests/serve_budget_and_supply.rs) but is not wired into that binary.

Per owner steer 2026-08-18 (deprioritize iroh; the transport tournament is eventually-nice, not required) this is Low and deferred. Do NOT let this task read as "the product cannot supply from /nix/store" -- it can, and does.

Traps retained if this is ever picked up: CommandNarDumper buffers the whole dump, so the serve budget binds sooner than its docs suggest; AvailabilityIndex is synchronous and holds the per-entry digest lock across the blocking dump, so the spawn_blocking call is load-bearing and must not be "simplified" away.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The daemon can be configured to supply from a real /nix/store via nix-store --dump, with the availability index as the single source of both its hold-answers and its served bytes
- [ ] #2 An e2e scenario serves a peer from a store path the holder never had as a .nar file
- [ ] #3 The per-serve memory of the CommandNarDumper buffering path is measured, and the ServeBudget defaults are re-derived from it rather than inherited
<!-- AC:END -->
