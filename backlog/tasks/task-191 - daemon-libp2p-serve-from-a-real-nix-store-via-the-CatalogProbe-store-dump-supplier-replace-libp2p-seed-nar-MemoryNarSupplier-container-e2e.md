---
id: TASK-191
title: >-
  daemon-libp2p: serve from a real /nix/store via the CatalogProbe store-dump
  supplier (replace --libp2p-seed-nar MemoryNarSupplier), + container e2e
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-13 11:29'
updated_date: '2026-08-13 15:41'
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
- [x] #1 install_libp2p_provider can build a CatalogNarSupplier over a daemon impl of fabric_libp2p::CatalogProbe backed by the AvailabilityIndex, so an announced store path is served by nix-store --dump on demand, holding no .nar at rest
- [x] #2 the store-dump produced bytes still flow through the announce SSOT NarHash verification (verify_provider_seeds / sign-site guard, TASK-56) - no new announce path bypasses it
- [ ] #3 container e2e: a provider peer serves a /nix/store path it never held as a .nar file; a consumer discovers via kad and fetches byte-identical bytes; the produced bytes BLAKE3-match the announced content
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
APPROACH (store-supply MVP; loopback bite is the accepted AC#3 proof, container e2e deferred per shared-box + TASK-190 hang):

1. fabric-libp2p: export raw_nar_helper_authorized() (mirror fabric-iroh) so a thin binary can authorize the __dump-raw-nar helper for ProbedSource::RegularFile. Store paths use Process (nix-store --dump) and never invoke the helper; this only makes the RegularFile arm non-vestigial.

2. daemon-libp2p lib: add Libp2pCatalogProbe(SupplyCatalogHandle) newtype bridging daemon-core NarProductionSource -> fabric_libp2p::ProbedSource (exact mirror of daemon/src/iroh_catalog_probe.rs; orphan-rule dodge). Same Blake3Digest type (peer_fabric re-export) so it type-checks.

3. daemon-libp2p lib: refactor sign_libp2p_provider_record to delegate to a content-taking core sign_provider_record_for_content(seed,nar_hash,content,ttl,now,seq); the bytes variant computes content=from_raw_nar(bytes). Single SSOT for the record recipe.

4. daemon-libp2p lib: AC#2 CRUX. Add verify_store_provisions(index,&[NarHashKey]) -> Result<Vec<(NarHashKey,Blake3Digest)>,String>: for each key, index.hold(key) runs the TASK-56 sha256(--dump)==key verify + quarantine; Have{blake3} -> provision carrying the VERIFIED blake3; a NarHashMismatch (quarantine) or Absent (GC'd) FAILS THE WHOLE BATCH (fail-fast, before any announce). This is the store analogue of verify_provider_seeds: the announce content is DERIVED FROM the verified index binding, never the operator's word. Add announce_store_provisions(fabric,index,seed,keys,ttl,now,budget) that calls verify_store_provisions first (all keys), then announces each verified provision (content=verified blake3). No announce path can bypass the gate.

5. daemon-libp2p + daemon binaries: add --libp2p-provide-store <narhash>=<storepath>. install_provider/install_libp2p_provider: remove the BLOCKED-PENDING-TASK-193 guard; build AvailabilityIndex(node_id placeholder, CommandNarDumper::from_path, JsonFileStore under state_dir or NullStore, NullAnnounce); register each; build CatalogNarSupplier(Libp2pCatalogProbe(index.supply_catalog()), current_exe helper); start fabric WITH it; verify+announce via announce_store_provisions. KEEP the AvailabilityIndex ALIVE in the provider guard (its Drop retires the catalog). --libp2p-seed-nar (Memory) path unchanged and can coexist. Add the __dump-raw-nar subcommand to daemon-libp2p main via daemon-core RegularFileNarDumper (no iroh dep).

TESTS (red-green):
- AC#2 (daemon, no nix): verify_store_provisions ACCEPTS a MemoryNarDumper/RegularFileNarDumper path registered under its true NarHash (verified) and REJECTS one registered under a wrong key (quarantine->refused, never announced). Bite: skip the index gate -> unverified path announced.
- AC#1 (daemon, no nix): index+MemoryNarDumper -> Libp2pCatalogProbe -> CatalogNarSupplier.plan(blake3) is Some (store path servable via supplier, nothing at rest); bridge maps a Process record to ProbedSource::Process{nix-store --dump path}. Bite: no register/verify -> probe None (not served).
- AC#3 loopback (fabric two-swarm, extends nar_transport.rs): byte-identical Process serve already exists (process_source_is_served_across_two_nodes); ADD the mismatch bite: a Process source emitting same-length wrong bytes -> provider Declines(SupplyFailed) via produce_admitted BLAKE3 recheck -> consumer fetch fails, NEVER receives wrong bytes.

GATE (bounded): fmt --check; build -p daemon-libp2p -p daemon; clippy -p daemon-libp2p -p daemon -D warnings; check-independence.py; test -p fabric-libp2p -p daemon-libp2p (+ -p daemon). df -h before/after. Commit AC#1/#2+loopback BEFORE any container e2e attempt. Container e2e DEFERRED (TASK-190 hang + shared box) -> file follow-up dep on 191+190. Leave 191 In Progress ready-for-gate; DEEP review (qa+codex).
<!-- SECTION:PLAN:END -->

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

DEEP gate 2026-08-13: codex GO on the store-serve MVP capability (commit 62dfc36). AC#1 (CatalogProbe over the AvailabilityIndex -> CatalogNarSupplier, store path served on demand, nothing at rest) and AC#2 (store announce verification-gated by verify_store_provisions -> TASK-56 index.hold; content from the VERIFIED blake3; fail-fast on quarantine/absent; no shipped bypass) are MET. AC#3's byte-identical integrity proof is met by the loopback two-swarm bite (mutation-proven: wrong-same-length -> Declined -> consumer IntegrityMismatch); the literal CONTAINER e2e is DEFERRED to TASK-194 (shared box + TASK-190 hang) - 191 stays In Progress until that lands (no AC-gaming). Comment overclaim ('un-bypassable by type system') corrected to scope the guarantee to the shipped path + flag the sign_libp2p_store_record footgun (codex finding).
<!-- SECTION:NOTES:END -->
