---
id: TASK-82
title: >-
  Persist the immutable NarHashKey -> (StorePath, Blake3Digest, NarSize) binding
  to close the task-61 seeding gap
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-09 21:25'
updated_date: '2026-08-13 10:46'
labels:
  - forward-carried-from-task-61
dependencies:
  - TASK-72
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FORWARD-CARRIED FROM TASK-61 (supply-model decision, 2026-08-09).

Task-61 chose regenerate-on-demand and accepted a REAL cost: a restart empties the availability index's in-memory digest cache, so a claim already published to the DHT naming a digest this node can no longer REVERSE-MAP is undiallable until a hold-query re-derives it. Bounded failure (the fetcher falls back to upstream), never an integrity problem - but it is the 'seeding gap' the PRD irreversibility map warned about, now real.

THE CHEAP FIX, with its number: persisting the derived digest+size alongside the registration costs about 40 bytes per path beyond what JsonFileStore already writes - ~4.3 MB for the owner's 108,401 paths, 0.003% of content. Compare the rejected alternative (persisting bao outboards, ~0.4% of content = ~0.6 GiB, which does NOT remove the dump).

WHY IT IS SAFE TO PERSIST DERIVED STATE HERE, and why that argument must be made explicitly in the change: availability.rs deliberately does NOT persist the digest ('caching a derived value invites staleness'). The exception is earned by Nix's own invariant - a /nix/store path's content is IMMUTABLE, so BLAKE3(dump(path)) cannot go stale for a given path. If that argument is not written down at the site, this is just a cache with a bug waiting.

TRAP: the registration binding is NOT verified at the source (availability.rs register() takes the caller's word that key -> store_path is true, and blake3_for computes only BLAKE3, never re-deriving sha256(dump) to assert it equals key). Persisting the digest makes a MIS-registration durable. Consider closing the source-side sha256 check in the same change, or state loudly why not.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The NarHashKey -> (StorePath, Blake3Digest, NarSize) binding survives a restart, so a node can serve a previously-announced digest immediately after boot with no hold-query first
- [ ] #2 The immutability argument (Nix store paths are content-immutable, so the digest cannot go stale) is written at the site, and a bite proves a CHANGED path invalidates rather than serving stale bytes
- [ ] #3 The on-disk cost is measured, not asserted: bytes per path, and the total for a 108k-path store
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. DATA DESIGN (on-disk, forward-compat). Change JsonFileStore value from a bare path-string to a serde-untagged StoredValue: legacy PathOnly(String) still loads (pre-82 snapshots re-derive), new WithDerived{store_path, blake3:"blake3:<hex>", nar_size:u64} carries the VERIFIED binding. IndexStore seam load/save now carry Vec<PersistedRegistration{key,store_path,derived:Option<DerivedNar>}>. NarSize persisted as the named uncompressed-NAR field (unit-trap guard).
2. PERSIST ONLY VERIFIED. derive() sets a per-Entry LEAF mutex persisted_derived only on the Verified branch (never Quarantined). Leaf so persist_locked can snapshot it under the map lock WITHOUT ever blocking on a dump (keeps the map->digest order; never digest-under-map). derive() reports fresh vs cached; hold() persists once on the fresh transition (best-effort: a persist failure is logged loud, still serves - the binding is an optimisation, its loss just means a re-derive next boot).
3. WARM AT BOOT (AC#1). open() pre-populates each loaded entry: digest slot = Verified(derived) and publishes the supply-catalog record, so a previously-announced digest is reverse-mappable/suppliable with NO hold-query and NO dump. Existence + BLAKE3 still re-checked at serve.
4. IMMUTABILITY ARGUMENT AT SITE (AC#2). Doc block: module rule 'do not persist derived (staleness)' is OVERRIDDEN here by Nix store-path content-immutability => BLAKE3(dump(path)) is time-invariant, cannot go stale for a store path. The one exception (raw-file-backed non-store paths, rewritable) is caught by the serve-time BLAKE3 recheck in supply_raw_nar_cancellable (fails loud on drift, never wrong bytes); transient stale CLAIM self-heals on re-derive. Update module docs + the supply_catalog STATED-LIMIT (task-82 RESOLVED).
5. BITES. AC#1: legacy-format snapshot -> supply_size None + needs a dump (red-equiv) vs full-format snapshot -> supply_size Some with dumper.calls()==0 after restart (green). AC#2: raw-file path content changed after persistence -> supply_raw_nar(persisted digest) FAILS LOUD (no stale bytes); hold transiently Have(stale) documented. AC#3: measure real JsonFileStore byte delta/path via the real serializer, x real census 89,475 paths.
6. GATE (bounded): fmt, build -p daemon-core, clippy -p daemon-core --all-targets -Dwarnings, check-independence, test -p daemon-core. Leave In Progress + ready-for-gate (codex DEEP).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Forward-carried from TASK-56 (commit 5ed5e72): the key->store_path binding is now VERIFIED at first serve (derive re-derives sha256(--dump)==registration key; mismatch -> quarantined typed NarHashMismatch, never a false Have). When persisting the immutable NarHashKey->(StorePath,Blake3Digest,NarSize) binding: (1) persist ONLY what is VERIFIED - do not persist a binding that was never derived/checked, or you re-open the mis-registration gap across restart; consider persisting the quarantine verdict too (TASK-56 leaves it in-memory-only, re-checked on first post-restart probe). (2) The two content identities come from ONE dump of the SAME uncompressed RawNarV1 bytes: Blake3Digest::from_raw_nar (blake3) and NarHashKey::from_raw_nar (sha256, new in TASK-56). Persist both from that single pass; never recompute one from a compressed form (NarSize-vs-FileSize / unit trap). (3) NarHashKey stores 32 RAW sha256 bytes - persist canonically (sha256:<nix-base32>, JsonFileStore already does) and compare in raw-byte space.

READY FOR GATE (do NOT self-certify Done; awaiting codex DEEP + orchestrator). Implemented on HEAD 8cf04db.

WHAT SHIPPED. Persist the VERIFIED derived binding NarHashKey->(StorePath,Blake3Digest,NarSize) and WARM it at boot so a previously-announced digest is suppliable immediately after restart (no hold-query, no re-dump) - closes the task-61 seeding gap. Files: daemon-core/src/availability.rs (core), daemon-core/src/lib.rs (export PersistedRegistration), daemon-core/tests/availability_persisted_digest.rs (new, 4 tests), daemon/tests/availability_index.rs (comment accuracy only).

AC#1 (survive restart, serve w/o hold-query): open() warms supply_catalog + pre-seeds the single-flight digest slot with Verified from the persisted binding. Bite restart_with_persisted_digest_serves_without_redump: post-restart supply_size returns Some with dumper.calls()==0. Mutation-proven RED (make save() always PathOnly -> digest not on disk -> test fails). Executable RED contrast restart_without_persisted_digest_is_undiallable_until_a_redump (legacy path-only snapshot -> None until a re-dump).

AC#2 (immutability argument at site + changed-path bite): argument written in module 'data design' doc, open() doc, and honest-limit (b). Store-path content is immutable so BLAKE3(dump) is time-invariant; the ONE exception (rewritable raw-file-backed non-store path) is backstopped by the serve-time BLAKE3==announced recheck in supply_raw_nar_cancellable. Bite a_changed_raw_file_backed_path_never_serves_stale_persisted_bytes: rewrite backing file A->B after persist+restart; supply_raw(A) fails LOUD, never ships B under A. Mutation-proven RED (delete the recheck -> served 160 stale bytes).

AC#3 (MEASURED on-disk cost). REAL census from /nix/var/nix/db/db.sqlite ValidPaths (NOT the stale 108,401/.drv figure): 89,475 valid paths, 117,542,151,328 B (~109.47 GiB) NAR content, avg ~1.31 MB/path. Measured via the real JsonFileStore serializer (test measure_persisted_derived_on_disk_cost, N=2000): DELTA = 155.1 bytes/path (pretty-printed JSON), projecting ~13.2 MiB added for 89,475 paths = 0.012% of content. NOTE: this is ~4x the task's '~40 B/path / 4.3 MB' estimate because that assumed a compact encoding; to_vec_pretty puts each object field on its own indented line. Still trivial. A compact/binary serializer (already a stated JsonFileStore scale follow-up) would cut it toward ~40-50 B/path.

GOTCHAS / DESIGN NOTES for reviewers:
- FORWARD-COMPAT: on-disk value is a serde-untagged StoredValue { PathOnly(String) | WithDerived{store_path,blake3,nar_size_uncompressed_nar} }. A pre-82 snapshot (bare path strings) still loads and re-derives; a corrupt key/value still fails LOUD (not silently empty). No deny_unknown_fields so a future field is tolerated.
- LOCK ORDER: persist reads a NEW per-Entry LEAF mutex persisted_derived (mirrored from the digest slot in derive()), NEVER the digest lock, so persist_locked under the map lock never blocks on an in-flight dump. Leaf acquires nothing => no cycle. Preserves the module's map->digest discipline.
- PERSIST ONLY VERIFIED: derive() mirrors into persisted_derived only on its Verified branch; a Quarantined mismatch is never persisted (no durable mis-registration across restart).
- TRUSTED-STATE LIMIT: pre-seeding Verified trusts the on-disk verdict without re-running task-56's sha256(dump)==key check at boot (would defeat the purpose). Sound: record was only written after that check passed; index file is local trusted state; serve-time BLAKE3 recheck + consumer Nix gate-2 still prevent wrong bytes (worst case wasted dial).
- BEST-EFFORT PERSIST: the fresh-serve persist in hold() logs LOUD on failure but still serves (the binding is an optimisation, not a source of truth); loss just means a re-derive next boot.
- WRITE AMPLIFICATION: first serve of each key now also triggers a whole-snapshot rewrite (once per key, not per probe) - same JsonFileStore scale limit already documented; append-log/sqlite is the shared answer.

GATE (bounded, per brief; box shared, disk 122G free): fmt --check OK; build -p daemon-core --locked OK; clippy -p daemon-core --all-targets -Dwarnings OK; check-independence green; test -p daemon-core 137 passed / 0 failed (126 unit + narhash_verify 5 + persisted_digest 4 + run_gate 2). Did NOT run just build/test (hangs on TASK-190 iroh) nor -p daemon (heavy); daemon/tests/availability_index.rs got a comment-only edit, logic unchanged (boot-1-never-served still re-derives).

MPED-ARCHITECT REVIEW ROUND (pre-commit, self-run) — 5 findings, all addressed:
- F1 (Medium, OVERCLAIM fixed): my docs said the rewritten-raw-file stale claim was 'transient/self-healing'. WRONG - a Verified digest slot is TERMINAL (derive() short-circuits; nothing re-derives a still-present path), so hold() keeps answering Have{old} and publish() keeps RE-ANNOUNCING it: a DURABLE wrong CLAIM, now persisted across restarts (strictly worse than the pre-82 in-memory window), clearing only on explicit re-register/GC. Corrected the wording in the data-design section, honest-limit (b), open() doc, and the AC#2 test; added a second-probe assertion proving it does NOT self-heal. Still NEVER a wrong byte (serve-time BLAKE3 recheck + consumer gate-2). Bounded to the non-production RegularFileNarDumper; the /nix/store production case is immutable and moot.
- F2 (Low-Med): supply_size_cancellable trusts the persisted declared_size with only an existence check (no recheck - a recheck would mean a dump). For a mutated raw-file path it returns a STALE size (budget could admit wrong), inside the same no-wrong-bytes envelope. Documented at the method + added a test assertion that it returns the stale A size (documented limit, not wrong bytes).
- F3 (Low): replaced #[serde(untagged)] StoredValue with a HAND-WRITTEN Serialize/Deserialize (deserialize_any visitor: str->PathOnly, map->derived inner struct). Untagged collapsed a corrupt blake3/size to 'did not match any variant', discarding the cause - the one corruption class task-82 adds would have failed LEAST verbosely. Now a bad field surfaces its real parse error. New test a_corrupt_persisted_blake3_fails_loud_with_the_real_cause asserts the message names 'blake3' and is NOT the generic untagged message.
- F4 (Low): made the write-amplification honest - each snapshot write is O(N_total) under the global lock, so warming a legacy store by serving a K-path closure = K full rewrites of the N-entry file (once-ever; later boots warm and don't re-persist). Same JsonFileStore scale limit; sqlite/append-log is the shared answer.
- F5 (Low): documented the deliberate triple-duplication of the derived value (digest slot + persisted_derived leaf + disk) as the accepted price of not taking a digest lock under the map lock.
Also added a one-line ack of the deliberate asymmetric persist-failure policy (register HARD-errors on SSOT path loss; first-serve derived persist is best-effort) to register's docstring.

Re-gate after fixes (bounded): fmt OK; build -p daemon-core OK; clippy -p daemon-core --all-targets -Dwarnings CLEAN (fixed a doc_lazy_continuation from a '- ...' line); check-independence green; test -p daemon-core 138 passed / 0 failed (126 + narhash_verify 5 + persisted_digest 5 + run_gate 2). AC bites re-confirmed by mutation earlier (AC#1 red when save() never persists derived; AC#2 red - served 160 stale bytes - when serve-time recheck deleted).
<!-- SECTION:NOTES:END -->
