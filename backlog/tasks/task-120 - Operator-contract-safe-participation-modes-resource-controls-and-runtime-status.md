---
id: TASK-120
title: >-
  Operator contract: safe participation modes, resource controls and runtime
  status
status: To Do
assignee: []
created_date: '2026-08-10 22:24'
updated_date: '2026-08-10 23:01'
labels:
  - production
  - operator
  - observability
  - privacy
  - wave-2c
dependencies:
  - TASK-24
  - TASK-25
  - TASK-29
  - TASK-31
  - TASK-77
  - TASK-78
  - TASK-83
  - TASK-86
  - TASK-89
  - TASK-100
  - TASK-111
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Define and implement the production-facing core contract for running nix-p2p, realized first by the Iroh milestone. Operators need explicit validated modes rather than accidental flag combinations: upstream-only, consume-only, LAN-share and public-share. Put upload, serve, discovery-query, announce, storage and concurrency budgets in the NixOS configuration; expose privacy-safe health/status and metrics. The transport/discovery registry contract must admit BitTorrent later without changing mode semantics, but TASK-118/TASK-119 own that later integration. This task owns manual controls and observability, not a learned tournament policy.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A fresh install is fail-safe: upstream fallback works, while serving, publication, public DHT/Mainline participation and third-party discovery are OFF until the operator explicitly selects a sharing profile.
- [ ] #2 The NixOS module exposes validated upstream-only, consume-only, LAN-share and public-share profiles plus explicit Iroh mechanism overrides; invalid or privacy-contradictory combinations fail evaluation/startup precisely.
- [ ] #3 Upload rate/bytes, concurrent serves, per-NAR/inflight memory, hold-query work, discovery deadline, announce volume, disk and file-descriptor budgets are bounded, documented and visible in effective configuration.
- [ ] #4 A local status surface reports stable NodeId, enabled discovery/transport/codec mechanisms, bootstrap health, holder counts, direct/hole-punched/relay path, miss versus unavailable, fallback reasons and current budget use.
- [ ] #5 Metrics/logs use bounded-cardinality labels and never export StorePath, NarHash, peer IP or full NodeId by default; opt-in diagnostics carry an explicit privacy warning and lifecycle.
- [ ] #6 Restart, dependency outage, exhausted budget and kill-switch drills yield actionable health while S2 holds; the registry contract lets TASK-119 add BitTorrent without redefining profiles or weakening safe defaults.
- [ ] #7 Before public networking is enabled, a one-command preflight lists every DNS/tracker/relay/Mainline/seed dependency, what the selected profile publishes and queries, and the effective resource/privacy controls.
- [ ] #8 One typed configuration model is authoritative: NixOS options, daemon CLI/config, TASK-115 endpoint profiles, TASK-89 discovery setup and status/preflight are derived from it; contradictory duplicate defaults fail a parity test.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Production foundation independent of tournament-derived automatic defaults. TASK-45 exercises this contract from a clean host.

Milestone order: implement and prove this contract for Iroh in TASK-45 first. TASK-118/TASK-119 must later plug BitTorrent into the same profiles and observability without changing their semantics.
<!-- SECTION:NOTES:END -->
