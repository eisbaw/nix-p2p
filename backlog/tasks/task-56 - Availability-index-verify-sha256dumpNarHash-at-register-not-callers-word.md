---
id: TASK-56
title: >-
  Availability index: verify sha256(dump)==NarHash at register (not caller's
  word)
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-09 00:10'
updated_date: '2026-08-13 09:42'
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
- [ ] #1 register/first-serve asserts sha256(--dump)==NarHash; a mis-registered path is rejected/quarantined, never announced as a valid claim (bite: register key X for a path whose real NarHash is Y -> rejected)
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
READY FOR GATE (leaving In Progress; integrity surface -> DEEP review qa+codex). Landed in commit 5ed5e72 (10 files).

WHAT: AvailabilityIndex::derive re-derives sha256(--dump) from the SAME buffered bytes it BLAKE3s (no second dump) and asserts == the registration key. Mismatch -> DeriveOutcome::Quarantined(NarHashMismatch), cached in the per-entry digest slot (deterministic verdict computed ONCE, not re-dumped per probe; a dump FAILURE stays None -> retry). Typed AvailabilityError::NarHashMismatch: hold != Have, claim/publish do not announce, answer_batch -> logged Absent, never enters supply_catalog. sha2 added daemon-side (independence stays green - denylist is HTTP-only).

REPRESENTATION (proved, not assumed): NarHashKey holds 32 RAW sha256 bytes; comparison is NarHashKey==NarHashKey in RAW-BYTE space, so there is NO base32-vs-hex trap in the check itself. New NarHashKey::from_raw_nar = sha256(RawNarV1), the sha256 twin of Blake3Digest::from_raw_nar. Two-part proof: (1) daemon-core KAT test vs published SHA-256 vectors (empty, "abc") proves recipe==standard sha256 + the nix-base32 Display round-trips; (2) scripts/check-golden-vectors.py ALREADY computes sha256(real nix-store --dump of the lib fixture) and asserts it == Nix's own committed nar_hash, cross-checking Rust vs Python nixbase32 - the real-path anchor.

AC#1 BITE: daemon-core/tests/availability_narhash_verify.rs. Mutation-proven RED: deleting the  block in derive() makes hold(X) return Ok(Have{..}) (the false claim) - demonstrated locally (2 assertions flip). Honest positive path + quarantine-cache (dump once) also covered.

GOTCHAS / carried lessons:
- UNIT: hashed the UNCOMPRESSED --dump bytes (RawNarV1), same buffer as BLAKE3 - never a compressed form. (NarSize-vs-FileSize family.)
- DUMP-ONCE: verification piggybacks the existing single-flight dump under the digest lock; the quarantine verdict is cached so a malicious/mis-registered key is NOT a per-probe re-dump (per-serve RSS, TASK-72/157/158).
- TEST-DEBT REVEALED: many existing tests registered ARBITRARY keys (key_from(0xNN)) for synthetic NARs - only green because the binding was unverified. Fixed to register the TRUE NarHash (from_raw_nar). The 'same-digest siblings' scenario is now UNREACHABLE at the availability layer (key==digest once verified), so that invariant moved DOWN to a supply_catalog unit test where two same-digest owners are directly constructible.

GATE: just build OK; just lint OK (clippy -D warnings + fmt + independence GREEN with sha2 + ruff); cargo test -p daemon-core --locked = 126 lib + 4 narhash-verify + 2 run_gate, all pass. Also ran (not in the daemon-core gate) daemon --test availability_index (11 ok), the two touched serve_budget iroh tests (2 ok), discovery_resolve_fetch (2 ok). Full 'just test' NOT run (TASK-190 unrelated iroh hang). Disk fell to ~7G during iroh test builds - did not cargo clean (forbidden).

HONEST LIMITS / follow-ups: quarantine verdict is in-memory only (re-checked after restart on first probe; correct, just not persisted) - persisted quarantine is an optimisation, not a correctness gap; noted in module docs. No new tracker filed (no deferred gap).
<!-- SECTION:NOTES:END -->
