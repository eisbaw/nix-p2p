---
id: TASK-120
title: >-
  Operator contract: safe participation modes, resource controls and runtime
  status
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-10 22:24'
updated_date: '2026-08-18 06:55'
labels:
  - production
  - operator
  - observability
  - privacy
  - wave-2c
  - rework
dependencies:
  - TASK-24
  - TASK-25
  - TASK-29
  - TASK-31
  - TASK-77
  - TASK-78
  - TASK-100
  - TASK-103
  - TASK-111
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Define and implement the production operator contract for the libp2p-primary product path. Operators select one authoritative validated profile: upstream-only, consume-only, LAN-share, or public-share. That typed profile generates or mechanically parity-checks daemon CLI/runtime, NixOS options, participation, serving/publication, resource budgets, privacy behavior, preflight, and local status. Iroh is a deferred optional mechanism override and cannot define the core contract or bypass profile safety. The UX must make safe setup, current behavior, budget use, dependency health, fallback reasons, and corrective action understandable without reading source code.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A fresh install is fail-safe: upstream fallback works, while serving, publication, public DHT/Mainline participation and third-party discovery are OFF until the operator explicitly selects a sharing profile.
- [x] #2 The NixOS module exposes validated upstream-only, consume-only, LAN-share and public-share profiles plus explicit Iroh mechanism overrides; invalid or privacy-contradictory combinations fail evaluation/startup precisely.
- [ ] #3 Upload rate/bytes, concurrent serves, per-NAR/inflight memory, hold-query work, discovery deadline, announce volume, disk and file-descriptor budgets are bounded, documented and visible in effective configuration.
- [ ] #4 A local status surface reports stable NodeId, enabled discovery/transport/codec mechanisms, bootstrap health, holder counts, direct/hole-punched/relay path, miss versus unavailable, fallback reasons and current budget use.
- [ ] #5 Metrics/logs use bounded-cardinality labels and never export StorePath, NarHash, peer IP or full NodeId by default; opt-in diagnostics carry an explicit privacy warning and lifecycle.
- [ ] #6 Restart, dependency outage, exhausted budget and kill-switch drills yield actionable health while S2 holds; the registry contract lets TASK-119 add BitTorrent without redefining profiles or weakening safe defaults.
- [x] #7 Before public networking is enabled, a one-command preflight lists every DNS/tracker/relay/Mainline/seed dependency, what the selected profile publishes and queries, and the effective resource/privacy controls.
- [x] #8 The authoritative capability model represents Mainline as non-selectable pending or evidenced-unsupported until TASK-131 supplies a supported artifact. TASK-130 LAN and TASK-89 DNS/relay remain usable without it; no profile aliases pending/unsupported to enabled or silently substitutes another mechanism.
- [x] #9 One typed configuration model is authoritative across NixOS options daemon CLI TASK-115 endpoint scopes TASK-130 LAN TASK-116 named hold-query TASK-89 DNS and relay passing TASK-103 decentralized content discovery and status or preflight. Optional tracker Mainline and BitTorrent adapters extend the registry only after their own tasks and contradictory duplicate defaults fail parity tests.
- [ ] #10 A versioned JCS artifact uses typed integer unit-suffixed fields for every profile: upload_payload_bytes_compressed_wire, upload_total_bytes_compressed_wire, upload_rate_bytes_compressed_wire_per_window and window_ns; concurrent serves; single/inflight NarSize bytes_uncompressed_nar; transient RAM bytes_ram; apparent/allocated disk bytes_ondisk; open_fds_count; discovery work/control octets/deadline_ns; announce count/wire octets/rate window; and serve_duration_ns. It is content-hashed, explicitly owner-reviewed, and generates or mechanically parity-checks daemon runtime, NixOS effective values, status, and preflight. Current 512 MiB/300 s values must fail against the normative 256 MiB single, 1 GiB inflight, 120 s envelope unless the owner explicitly revises PRD.md.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Authoritative current direction: the core contract is libp2p-primary and transport-agnostic. Iroh is an optional deferred mechanism governed by TASK-202 and cannot define or bypass profiles. Existing commits 0fff8c0, 4f5d524 and 08085b7 established explicit profiles, fail-closed compatibility checks, profile-derived libp2p participation, capability reporting, preflight, and redaction. This task was reopened on 2026-08-18 because AC#3/#4/#5/#6 and the owner-reviewed per-profile budget artifact remain incomplete; current libp2p 512 MiB/300 s values conflict with the normative 256 MiB/1 GiB/120 s envelope. Preserve the durable/reclaiming NodeId replay-ledger concern from TASK-138. UX is fundamental: profile selection, precise validation, preflight, local health/status, effective budget and queue use, fallback explanations, privacy-safe diagnostics, kill switch, and recovery must be coherent and runtime-authoritative.
<!-- SECTION:NOTES:END -->
