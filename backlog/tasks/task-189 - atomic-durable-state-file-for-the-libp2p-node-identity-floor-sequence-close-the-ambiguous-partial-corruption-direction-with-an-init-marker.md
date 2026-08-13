---
id: TASK-189
title: >-
  atomic durable state-file for the libp2p node (identity + floor + sequence):
  close the ambiguous partial-corruption direction with an init marker
status: To Do
assignee: []
created_date: '2026-08-13 08:10'
updated_date: '2026-08-13 11:06'
labels:
  - fabric-libp2p
  - daemon-libp2p
  - integrity
  - durability
  - hardening
  - wave-2c
dependencies:
  - TASK-185
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Root-cause follow-up to TASK-185's state-dir consistency fix. TASK-185 closed the CLEANLY-DETECTABLE corruption direction: a floor/sequence sidecar present while the identity file is ABSENT is fail-closed (a floor can only exist after the eagerly-written identity, so identity-absent+floor-present is always loss -> would silently rekey + orphan records). It did NOT close the SYMMETRIC / ambiguous direction, because the current design uses SEPARATE, LAZILY-created sidecars: identity-seed-v1 (eager, first boot), announce-seq-v1.txt (only after a provider's first announce), provider-floor-v1.txt (only after a consumer's floor first advances). So 'identity present, floor absent' is INDISTINGUISHABLE from a legitimate first boot / pure consumer / pre-first-announce provider - fail-closing there would break normal operation. A provider that keeps its identity but LOSES its sequence file therefore silently re-mints from sequence 1 (self-rollback under the same identity), undetected.

ROOT CAUSE: three independent sidecars with no atomic init marker and no cross-consistency. FIX (this task): replace the sidecar set with a SINGLE atomic durable-state file (or a directory guarded by one eager 'initialized' marker written atomically at first boot alongside the identity), so the load path can enforce a clean trichotomy: (a) marker+all pieces present and valid -> load; (b) nothing present -> genuine first boot; (c) any partial/inconsistent subset -> FAIL-CLOSED naming the inconsistency. This closes BOTH directions (identity-lost AND floor-lost) without special cases, and subsumes: TASK-188 F6 (durable-mode fail-open on IO/parse error), the concurrent-save lost-update race (one serialized reserve+persist), the parent-of-state-dir fsync, and the sequence-overflow fail-closed. Keep TASK-185's existing fail-closed behaviors (malformed identity, explicit-seed mismatch, identity-absent+floor-present) as the generalized invariant.

BITING TEST: identity kept but the sequence/floor file deleted -> restart must FAIL-CLOSED (once an init marker exists to distinguish it from a true first boot). Plus the existing TASK-185 partial-corruption test (identity lost, floor kept) stays green.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
SCOPE EXTENSION collected from TASK-82 DEEP gate (2026-08-13): fold the availability-index (daemon-core) persistence-integrity items into this single atomic durable-state-file work. TASK-82 persists the VERIFIED NarHashKey->(StorePath,Blake3Digest,NarSize) binding in daemon-core/src/availability.rs (JsonFileStore) and WARMS it at boot; the DEEP arbitration ruled tamper of that LOCAL file is a bounded-wasted-dial (availability/claim-accuracy) risk, NOT a byte-integrity risk (byte-integrity stays on the serve-time BLAKE3(dump)==announced recheck + consumer Nix NarHash gate; PRD:157). These are DEFENSE-IN-DEPTH, explicitly NOT TASK-82 gates:
1. Per-binding integrity check (checksum/MAC) over each persisted (key,digest,size) binding so tamper/corruption FAILS LOUD at load instead of warm-loading as Verified (beyond the TCB line).
2. One-way downgrade-compat guard for the StoredValue shape (a new-format snapshot must not be silently mis-read by an old binary; today it is a hand-written serde enum: legacy bare-string | WithDerived object).
3. Persisted quarantine verdict for the availability index (TASK-56 leaves it in-memory-only; re-checked on first post-restart probe) - an optimization, not a correctness need.
4. Fold JsonFileStore's whole-snapshot O(N)-per-mutation rewrite (now also triggered once per key on first serve) into the single atomic durable-state file (the scale answer).
NOTE: TASK-82 already added the atomic+DURABLE write to JsonFileStore::save (write+fsync temp -> rename -> fsync parent dir), mirroring TASK-185; this task subsumes the broader single-file consolidation. Code cross-references this task in a comment at availability.rs persist_locked().
<!-- SECTION:NOTES:END -->
