---
id: TASK-191
title: >-
  daemon-libp2p: serve from a real /nix/store via the CatalogProbe store-dump
  supplier (replace --libp2p-seed-nar MemoryNarSupplier), + container e2e
status: To Do
assignee: []
created_date: '2026-08-13 11:29'
labels:
  - libp2p
  - daemon
  - serving
  - fabric
  - core
  - wave-2c
dependencies:
  - TASK-158
  - TASK-178
  - TASK-161
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Consumer of TASK-158. TASK-158 added fabric_libp2p::CatalogNarSupplier + the CatalogProbe digest->store-path reverse-map seam + a cancellation-safe supervised store-dump/regular-file NarSource (Process source run under proc_supervisor, declared-size-before-produce, serve-time BLAKE3 recheck). It is currently UNWIRED into the shipped daemon-libp2p provider: TASK-178 stands the provider up on a MemoryNarSupplier built from --libp2p-seed-nar raw files (holds the NAR at rest). This task wires the daemon's AvailabilityIndex (the TASK-82 persisted NarHashKey->(StorePath,Blake3Digest,NarSize) binding) behind a daemon-side impl of fabric_libp2p::CatalogProbe, constructs a fabric_libp2p::CatalogNarSupplier{catalog, helper_program} in install_libp2p_provider (behind e.g. --libp2p-provide-store, mirroring the iroh TASK-83 AvailabilityIndex-as-supplier path), so a real node regenerates any announced store path on demand via nix-store --dump WITHOUT holding it as a .nar at rest. The daemon must also supply the raw-NAR helper binary for ProbedSource::RegularFile (fabric_libp2p::RAW_NAR_HELPER_ARG convention). MUST route the produced bytes through the announce SSOT verify_provider_seeds guard (do not bypass; TASK-56 sign-site). Then a container e2e (TASK-161 network) proving a provider peer serves a /nix/store path it NEVER held as a .nar file to a consumer that discovers+fetches it byte-identically. Iroh analogue: TASK-83. Provider mode: TASK-178. Container harness: TASK-161. Off-worker streamed production of the store-dump on the swarm worker (so serve does not block the poll loop) is TASK-157 and is a co-requisite for large NARs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 install_libp2p_provider can build a CatalogNarSupplier over a daemon impl of fabric_libp2p::CatalogProbe backed by the AvailabilityIndex, so an announced store path is served by nix-store --dump on demand, holding no .nar at rest
- [ ] #2 the store-dump produced bytes still flow through the announce SSOT NarHash verification (verify_provider_seeds / sign-site guard, TASK-56) - no new announce path bypasses it
- [ ] #3 container e2e: a provider peer serves a /nix/store path it never held as a .nar file; a consumer discovers via kad and fetches byte-identical bytes; the produced bytes BLAKE3-match the announced content
<!-- AC:END -->
