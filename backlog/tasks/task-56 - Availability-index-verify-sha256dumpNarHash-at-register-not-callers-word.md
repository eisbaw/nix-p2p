---
id: TASK-56
title: >-
  Availability index: verify sha256(dump)==NarHash at register (not caller's
  word)
status: Done
assignee:
  - '@me'
created_date: '2026-08-09 00:10'
updated_date: '2026-08-13 10:16'
labels:
  - wave-2
dependencies:
  - TASK-50
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
task-50 honest limit: register() binds NarHashKey->store_path on the CALLER's word; blake3_for computes only BLAKE3, never asserts sha256(nix-store --dump path)==the registered NarHash. Nix gate 2 backstops a bad INSTALL (no wrong bytes reach a store), but a MIS-registration produces a FALSE CLAIM - the node advertises holding X but would serve Y, which a consumer fetches then rejects at its NarHash gate = a wasted dial. This directly feeds the pathological lying-claim/wasted-dial cost (task-43/46) and honest offload accounting. Fix: at register (or first blake3_for), compute sha256 of the --dump stream and assert == the registered NarHash; reject/quarantine a mismatch. Needs a sha256 pass over --dump (daemon-side; sha2 is daemon-only, independence denylist is HTTP-only).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 register/first-serve asserts sha256(--dump)==NarHash; a mis-registered path is rejected/quarantined, never announced as a valid claim (bite: register key X for a path whose real NarHash is Y -> rejected)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add sha2 (daemon-side, independence denylist is HTTP-only) to daemon-core/Cargo.toml.
2. claim.rs: add NarHashKey::from_raw_nar(&[u8]) = sha256(RawNarV1) wrapped as the strict key - the sha256 twin of Blake3Digest::from_raw_nar, over the SAME uncompressed --dump bytes. Compare in RAW-BYTE space (NarHashKey == NarHashKey), so no base32/hex ambiguity.
3. availability.rs: verify at first-derive (DUMP ONCE - same buffered stream that feeds BLAKE3). Cache the outcome in the per-entry slot as DeriveOutcome::{Verified(DerivedNar) | Quarantined(NarHashMismatch)} so a deterministic mismatch is computed once, not re-dumped per probe. A dump FAILURE stays None (retry). On mismatch return typed AvailabilityError::NarHashMismatch: hold != Have, claim/publish not announced, answer_batch degrades to logged Absent (safe). Update module honest-limit + register() docs (gap now closed).
4. Tests: NEW biting test daemon-core/tests/ (runs under gate cargo test -p daemon-core): register key X for path whose real NarHash is Y -> Err/quarantine, hold not Have, claim None-or-Err, not announced; honest positive path serves. Mutation proof stated in comment (remove the sha256 assertion -> RED). Add supply_catalog unit tests for the scalar-owner same-digest retirement invariant (moved down from the now-impossible availability-level scenario). Representation proof: Rust KAT vs published SHA-256 vectors + cite scripts/check-golden-vectors.py which already asserts sha256(real --dump)==Nix's committed NarHash on the lib fixture (real path) and cross-checks nixbase32.
5. Fix daemon/tests register sites (availability_index, discovery_resolve_fetch, serve_budget_and_supply) to register the REAL key (from_raw_nar of the dumped bytes) - they relied on the now-closed unverified binding.
6. Gate: just build, just lint (fmt+clippy+independence+ruff), cargo test -p daemon-core; run cargo test -p daemon --test availability_index to confirm the pure daemon tests. Full just test NOT run (TASK-190 hang).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REGATE READY (still In Progress; re-gates codex once more). Regate landed in commit 3155ed0 (6 files) on top of the original 5ed5e72.

GATE-BREAKER FIXED (codex NO-GO): the SHIPPED libp2p provider announced from --libp2p-seed-nar WITHOUT sha256(bytes)==declared-NarHash, so a mis-specified seed minted a FALSE CLAIM on the binary that ships (index check only guarded the future index-backed path). Now guarded at the mint SSOT: new verify_provider_seeds(seeds)->Result<(),SeedNarHashMismatch> (daemon-libp2p/src/lib.rs) reuses daemon_core::NarHashKey::from_raw_nar and runs as the FIRST statement of announce_provider_seeds (the loop BOTH thin binaries + the composite daemon call). Mismatch => typed error naming declared vs actual, whole batch refused before ANY record is signed/put. daemon re-exports verify_provider_seeds + SeedNarHashMismatch.

PROVIDER-LEVEL BITE (daemon-libp2p/tests/provider_seed_verification.rs): over a REAL DHT-joined provider, honest seed announces (Ok, signed record); mis-specified seed REFUSED (Err naming the mismatch). Mutation-proven RED: deleting verify_provider_seeds(seeds)? in announce_provider_seeds makes the mis-seed sign+announce a false record and return Ok (demonstrated: expect_err panics). Plus a cheap pure verify_provider_seeds bite. The restart-durable tests announced under ARBITRARY NarHashes (same closed gap) -> fixed to declare the NAR's true NarHash (removed the now-dead nar_hash_string helper).

LOW#3 fixed: a_quarantined_key test is now genuinely CONCURRENT (16 racing probes via Barrier+delay, single-flight dump-once) matching its description; added a direct answer_batch->Absent assertion for a quarantined key.
LOW#2 fixed (doc): availability honest-limit note now states the RAW-FILE (non-store) immutability caveat explicitly - a RegularFileNarDumper path rewritten after Verified caching could give a stale positive CLAIM, but supply_raw_nar_cancellable re-checks BLAKE3 at serve so no wrong bytes reach a peer; /nix/store immutability makes it moot for store paths.

REGATE GATE (bounded, per coordinator): cargo build -p daemon-libp2p --locked OK; cargo clippy -p daemon-libp2p --all-targets -- -D warnings OK; cargo fmt --all --check OK; check-independence.py GREEN (sha2/daemon-libp2p fine); cargo test -p daemon-libp2p --locked = lib 7 + no_iroh_closure_guard 1 + production_path 1 + provider_seed_verification 2 + restart_durable 2, ALL PASS; cargo test -p daemon-core --locked = 126 lib + 5 narhash-verify + 2 run_gate, ALL PASS; cargo build -p daemon --lib --locked OK (re-export). Full just test NOT run (TASK-190 hang). Disk stayed ~122G (no cargo clean).

HONEST LIMITS: sign_libp2p_provider_record itself stays pure/unguarded (returns ProviderRecord, not Result) - both SHIPPED binaries mint only via announce_provider_seeds so 100% of shipped mint paths are covered; a direct sign() caller (only daemon/tests/libp2p_provider_path.rs, a test) can still craft a record, which is test-only. No new tracker filed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed the availability integrity floor: a node can no longer announce a claim whose bytes don't match the declared Nix NarHash. (1) AvailabilityIndex::derive re-derives sha256(nix-store --dump path) from the SAME buffered dump it BLAKE3s (new NarHashKey::from_raw_nar; no second dump) and asserts ==registered key; a mismatch is a typed NarHashMismatch cached as a sticky Quarantined slot so hold!=Have, claim/publish don't announce, answer_batch->Absent. (2) The SHIPPED libp2p provider (which announces from --libp2p-seed-nar, bypassing the index) now verifies at the announce SSOT announce_provider_seeds: verify_provider_seeds asserts NarHashKey::from_raw_nar(bytes)==declared for every seed and fail-fast rejects the whole batch (typed SeedNarHashMismatch) BEFORE any sign/put; both shipped binaries route through it, no bypass. DEEP-gated: qa GO (mechanics, 132/0 + independence green with new sha2), codex NO-GO (shipped provider bypassed the index - built-but-not-load-bearing) -> fixed at SSOT -> codex GO (all shipped mint paths guarded, 13/13). Representation proven correct (raw-byte compare; from_raw_nar and narinfo->NarHashKey both reduce to same 32 bytes, cross-checked vs Nix's own vector). Frozen wire untouched. Honest limit: cached Verified assumes immutable backing (moot for /nix/store; serving rechecks BLAKE3 so no wrong bytes reach a peer). sha2 added daemon-side (independence green).
<!-- SECTION:FINAL_SUMMARY:END -->
