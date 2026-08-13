---
id: TASK-191
title: >-
  daemon-libp2p: serve from a real /nix/store via the CatalogProbe store-dump
  supplier (replace --libp2p-seed-nar MemoryNarSupplier), + container e2e
status: To Do
assignee:
  - '@claude'
created_date: '2026-08-13 11:29'
updated_date: '2026-08-13 13:56'
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
  - TASK-193
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
BLOCKED on TASK-193 (2026-08-13). Root-cause investigation (verified in code + TASK-158 landing notes), ratified by mped-architect (Mark-emulator) ruling A+:

HARD BLOCKER: the shipped libp2p SERVE loop is synchronous + Memory-only, so a store-dump source cannot be served at all this cycle. fabric-libp2p/src/swarm.rs:679 on_nar_event (sync &mut self poll-loop handler) -> ServeGate::respond(&digest) -> NarSupplyPlan::produce() (nar.rs ~310-321) handles ONLY NarSource::Memory; a NarSource::Process (nix-store --dump) returns a loud typed Err -> Declined(SupplyFailed). The async produce_supervised() has ZERO non-test callers; on_nar_event cannot .await it. So a CatalogNarSupplier wired into the shipped provider would ANNOUNCE store paths correctly but DECLINE every serve - the dial-then-fail anti-pattern install_libp2p_provider itself guards against (daemon/src/main.rs:1044-1057). This blocks AC#1 runtime-serve AND AC#3 e2e for a path of ANY size (a 4 KB store path included), not just large NARs.

CORRECTION to this task description: it calls off-worker production a co-requisite "for large NARs" - that is WRONG. Off-worker async production reachable from the serve loop is a PREREQUISITE FOR ANY store-dump serve. Carved out as TASK-193 (focused: async supervised production reachable from the swarm serve loop, WITHIN request-response, no stream rewrite) and added as a dependency. TASK-157 proper (stream rewrite + mid-stream abort + idle bound) is left separate and depends on the TASK-193 seam.

AC status now: AC#1 runtime-serve = BLOCKED on TASK-193. AC#3 e2e = BLOCKED on TASK-193 (cannot serve a store path). AC#2 (verification-gated store announce) = deliberately NOT landed ahead of the serve seam: per A+ ruling it would be a gate on an empty doorway (no serve-capable path, no produced bytes) and reporting it done would over-claim the integrity floor. It lands WITH its live caller once TASK-193 exists (probe bridge mirrors daemon/src/iroh_catalog_probe.rs; content-from-verified-index announce; verify_store_provisions gate - all proven-by-iroh-analogy, so no de-risking is lost by deferring).

CODE ARTIFACT landed this cycle: footgun-guard comments at both shipped provider install sites (daemon-libp2p/src/main.rs::install_provider and daemon/src/main.rs::install_libp2p_provider) - do NOT wire a --libp2p-provide-store CLI mode until TASK-193 lands (announces-then-declines). nar.rs already carries the produce-site note.

RE-SEQUENCING: pick up TASK-193 next; TASK-191 completes immediately after and lands the probe bridge + supplier construction + verify gate + e2e TOGETHER with their live callers (zero uncalled interval; AC#2 becomes a real property of a real serve path).

## Serve prerequisite MET (TASK-193, ready-for-gate)

TASK-193 landed off-worker async supervised production reachable from the shipped libp2p
serve loop: a NarSource::Process (store-dump) inbound request is now SERVED off the poll
loop via ServeGate::admit -> produce_admitted (keeps len+BLAKE3 recheck), instead of
Declined(SupplyFailed). So a store-dump-backed CatalogNarSupplier no longer announces then
declines. This unblocks wiring the store supplier + `--libp2p-provide-store` here.

Wiring note for TASK-191: fabric-libp2p Libp2pServer::new / ServeGate::new now take a
TaskSupervisorHandle. Libp2pFabric::start_with_supplier(_durable) OWNS its own TaskSupervisor
internally (public signature UNCHANGED — the daemon-libp2p caller needs no change to keep
Memory serving working). If TASK-191 wants store-dump production to ride the daemon's
existing TaskSupervisor (unified capacity ceiling), thread the daemon handle through a new
serving constructor rather than the fabric-owned default; the seam already accepts a handle.
The BLOCKED-PENDING-TASK-193 guards at daemon/src/main.rs:1296 and daemon-libp2p/src/main.rs:213
can be lifted once the store supplier is wired. TASK-193 is In Progress pending its DEEP gate.
<!-- SECTION:NOTES:END -->
