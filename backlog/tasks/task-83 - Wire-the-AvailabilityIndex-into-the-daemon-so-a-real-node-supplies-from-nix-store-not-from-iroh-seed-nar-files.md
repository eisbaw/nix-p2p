---
id: TASK-83
title: >-
  Wire the AvailabilityIndex into the daemon so a real node supplies from
  /nix/store, not from --iroh-seed-nar files
status: To Do
assignee: []
created_date: '2026-08-09 22:24'
labels:
  - forward-carried-from-task-72
dependencies:
  - TASK-72
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FORWARD-CARRIED FROM TASK-72. The supply model is implemented and the index-backed supplier exists (IndexNarSupplier over AvailabilityIndex + CommandNarDumper), but the DAEMON still builds a FileNarSupplier from --iroh-seed-nar. So the shipped binary regenerates from raw-NAR FILES the harness prepared, not from /nix/store.

WHY THIS IS NOT A DEFECT IN TASK-72 AND IS STILL A GAP: task-72's ACs are about bounding the serve and making index coverage equal provider coverage, and both are true of whatever supplier is configured - proven in-process for the index-backed one in daemon/tests/serve_budget_and_supply.rs. But 'a node serves its whole /nix/store' is the PRD's headline supply property and no shipped code path reaches it yet.

WHAT IS NEEDED:
  * a flag that opens an AvailabilityIndex (JsonFileStore path + CommandNarDumper) and hands IndexNarSupplier to IrohProvider::spawn_supplying;
  * a way to REGISTER holdings (announce-on-demand is TASK-77; a bootstrap registration path is needed either way);
  * the e2e harness needs a scenario where node B serves from a real store path rather than a copied .nar file, which means the container needs a nix store with the fixture path realised.

TRAP CARRIED FROM TASK-72: CommandNarDumper BUFFERS the whole dump (availability.rs states this). With the whole store in scope that is a per-serve allocation of NarSize on top of the store's copy - the serve budget bounds it, but the bound will bind much sooner than the numbers in the ServeBudget docs suggest. Measure before choosing defaults.

SECOND TRAP: AvailabilityIndex is SYNCHRONOUS and holds the per-entry digest lock across the blocking dump. The supply path already calls it under spawn_blocking, which is correct - do not 'simplify' that away.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The daemon can be configured to supply from a real /nix/store via nix-store --dump, with the availability index as the single source of both its hold-answers and its served bytes
- [ ] #2 An e2e scenario serves a peer from a store path the holder never had as a .nar file
- [ ] #3 The per-serve memory of the CommandNarDumper buffering path is measured, and the ServeBudget defaults are re-derived from it rather than inherited
<!-- AC:END -->
