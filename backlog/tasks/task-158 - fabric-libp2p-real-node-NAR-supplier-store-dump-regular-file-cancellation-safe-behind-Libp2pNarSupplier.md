---
id: TASK-158
title: >-
  fabric-libp2p: real node NAR supplier (store-dump / regular-file,
  cancellation-safe) behind Libp2pNarSupplier
status: To Do
assignee: []
created_date: '2026-08-12 08:38'
updated_date: '2026-08-13 10:38'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Forward-carried from TASK-56 regate (commit 3155ed0): the SIGN-SITE seed verification is now IN PLACE at the libp2p announce SSOT - verify_provider_seeds(seeds) runs as the first statement of announce_provider_seeds and asserts NarHashKey::from_raw_nar(bytes)==declared before any ProviderRecord is signed. When 158 wires the verified AvailabilityIndex in as the store-dump supplier: do NOT duplicate or bypass this guard. The bytes 158 feeds the provider still flow through announce_provider_seeds (or must), so the declared NarHash is checked against the actual dump there regardless of supply source (seed-nar OR index dump). If 158 introduces a NEW announce path that does not go through announce_provider_seeds, it MUST call verify_provider_seeds itself (or route through the SSOT). The typed error is daemon_libp2p::SeedNarHashMismatch.

Forward-carried from TASK-82 (persist derived binding): the availability index now PERSISTS the VERIFIED NarHashKey->(StorePath,Blake3Digest,NarSize) binding and WARMS the supply_catalog at open(), so a restarted supplier can reverse-map a previously-announced digest -> store_path WITHOUT a hold-query/re-dump first. When this libp2p supplier leans on the persisted binding: (1) it is safe to trust the persisted digest for a /nix/store path (content-immutable), but you MUST keep the serve-time BLAKE3(dump)==announced recheck (fabric-iroh has the analogue) - for a raw-file-backed non-store source the persisted digest can be stale and only that recheck stops shipping wrong bytes under a right name; (2) declared-size-before-produce is already satisfiable from the persisted NarSize (uncompressed NAR bytes; NOT a compressed FileSize - unit trap) without a dump; (3) persisted state is ONLY the verified binding - a not-yet-served or quarantined path has no persisted digest and must fall back to derive-on-demand. See daemon-core/src/availability.rs open()/derive()/persist_locked and daemon-core/tests/availability_persisted_digest.rs.
<!-- SECTION:NOTES:END -->
