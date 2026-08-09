---
id: TASK-50
title: >-
  Local availability index: NarHash->StorePath->--dump->BLAKE3,
  announce-on-demand
status: Done
assignee: []
created_date: '2026-08-08 20:28'
updated_date: '2026-08-09 00:09'
labels: []
dependencies:
  - TASK-48
  - TASK-37
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The PRD supply mechanism + the claim PRODUCER (absent from the original plan). A node must KNOW which NarHashes it holds and be able to serve them: an index mapping NarHash -> local StorePath -> (on-demand nix-store --dump) -> RawNarV1 BLAKE3, with persistence, SINGLE-FLIGHT hashing (dont re-hash a 100MB NAR concurrently), materialization/cleanup, and announce-on-demand (publish a claim when a path lands). Discovery::resolve must return the COMPLETE transport offer (NodeId + BLAKE3 + transport), not merely a holder NodeId. This is what lets a node answer yes/no per NarHash and serve from its real /nix/store (not just a fixture).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Given a store path, the index yields its NarHash and RawNarV1 BLAKE3; a node answers yes/no for a concrete NarHash from its real store (no enumeration endpoint)
- [x] #2 Single-flight: concurrent requests for the same uncomputed BLAKE3 hash once; persistence survives restart; a GCed store path is dropped from availability
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE (commit 0450d9c, daemon files only). daemon/src/availability.rs + tests/availability_index.rs (8 oracles) + lib.rs re-exports.

SHAPE: durable state is ONLY the registration NarHashKey->StorePath (persisted via JsonFileStore: sorted JSON, atomic temp+rename). BLAKE3(RawNarV1) is DERIVED (nix-store --dump | content_id::Blake3Digest::from_raw_nar), computed on demand, in-memory single-flight-cached, recomputed after restart (not persisted -> no derived-state dup, no staleness). Availability = filesystem existence checked at query time -> a GC path drops with no bookkeeping.
YES/NO: hold(key)->HoldAnswer; answer(query)->HoldResponse envelope. NO listing method (privacy). COMPLETE OFFER: claim()/publish() -> Claim{key, payload:WholeNar{blake3}, holders:[node], transports:[Iroh{node}]}.
SINGLE-FLIGHT: per-entry Mutex<Option<Blake3Digest>> computed UNDER the lock; 16 concurrent probes -> 1 dump (bite VERIFIED: removing the lock -> 16). Lock order strict (map,then digest); map lock never held across a dump.
--dump: real CommandNarDumper shells `nix-store --dump <path>` (PATH-resolved, no NIX_P2P_ named -> source-guard clean); buffers the dump (streaming forward-carried). Tests use a counting synthetic-NAR dumper (sandbox-safe, names no fixtures/). computed-blake3==golden proven in-sandbox via the committed golden RECIPE VECTORS; the lib-fixture golden 95f49df0 stays re-derived by scripts/check-golden-vectors.py over the SAME recipe.
GATE (LIGHT, own run): just build/lint/test green; clippy -D warnings clean; check-golden-vectors ok (95f49df0); measure --self-test ALL PASS; nix build .#daemon OK. qa-test-runner + mped-architect ran in parallel.
REVIEW FIXES applied: dropped a digest-carry micro-opt that took the per-entry lock under the map lock (HOL-blocking hazard); made the lazy GC-prune pointer-identity-guarded (Arc::ptr_eq) so a concurrent re-register is not clobbered.
GOTCHAS: (1) nix flakes only see git-TRACKED files -> a new .rs must be git add-ed before `nix build .#daemon` compiles it (first build failed: module not found). (2) integration tests CAN use a crate normal dep (serde_json) - confirmed by golden_vectors.rs. (3) source guard forbids fixtures/ and NIX_P2P_ in .rs -> dumper resolves nix-store via PATH.
FORWARD-CARRIES: task-39: IrohProvider::seed() is fed FROM this index (register a held path, then seed its --dump bytes) - not wired here. task-40: discovery serves claim()/publish() outputs; the announce hook (AnnounceSink) is the source; AnnounceSink::announce returns () so a real announce-failure needs an error channel. task-41 (S6): node B registers+seeds from this index, node A resolves a NarHash against it and fetches over iroh. HARDENING (deferred): source-side sha256(dump)==key verification (Nix gate 2 backstops it now); streaming/async dump for the whole /nix/store; persist-before-mutate ordering on save failure.
<!-- SECTION:NOTES:END -->
