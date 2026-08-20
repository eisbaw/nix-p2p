---
id: TASK-188
title: >-
  record-lifecycle hardening: fail-closed floor bound (F1/F2), consumer TTL cap
  (F5), durable-reload sweep/cap (F6), state_dir advisory lock (P4), persistence
  integrity (F4 remnants)
status: To Do
assignee: []
created_date: '2026-08-13 06:13'
updated_date: '2026-08-20 23:59'
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
Follow-up to TASK-185 (which production-wired the durable path: state_dir + start_durable + durable positive-sequence allocation + save-before-publish fail-closed with parent-dir fsync). These are the remaining record-lifecycle hardening items TASK-185 deliberately left OUT of scope (core-only), filed here so they are not silently dropped. Each is a real, bounded residue against the now-stabilized durable surface.

F1/F2 (eviction rollback/resurrection window): FloorStore LRU-evicts an ACTIVE floor slot (or a live tombstone) under the 4096-key cap; an evicted guard re-opens a bounded rollback (Active) / resurrection (tombstone) window an attacker can drive by flooding distinct keys + inducing resolves + replaying a captured still-unexpired record the DHT serves. The TASK-176 #3 tradeoff CHOSE rollback over rejection. Design options: fail-closed-at-capacity (reject/quarantine a NEW slot rather than evict a live guard) OR guard_until = max(observed expiry) so a shorter-refresh-TTL record cannot roll back a higher sequence. Decide + implement + bite-by-mutation.

F5 (consumer-side TTL cap): the 24h MAX_RECORD_TTL_SECS cap is ANNOUNCE-side only; consumers (directory admit path) do NOT enforce it, so a non-conforming/malicious provider can put_record a >24h expiry that this node's fixed tombstone floor need not outlive. Enforce the cap on the CONSUMER decode/admit path (clamp or reject an over-cap expiry) so the tombstone-outlives-record invariant holds network-wide, not just for records THIS node published.

F6 (durable-reload sweep/cap): FloorStore::durable and the announcer's load_seqs restore EVERY line at startup with no sweep/cap, so an oversized or maliciously-grown floor/seq file exceeds DEFAULT_STORE_CAP (4096) at startup, defeating the in-session bound. Apply the same TTL sweep + cap on reload as on live admit.

P4 (shared state_dir): two nodes sharing one state_dir silently corrupt each other's floor/seq files (they are keyed by directory, not identity). Add an advisory lock (flock) on the state_dir that FAILS LOUD at startup if another process holds it, rather than silent cross-corruption.

F4 remnants (persistence integrity), now that TASK-185 added parent-dir fsync + save-before-publish fail-closed for the ANNOUNCE path: (a) tombstone/sequence lines carry NO checksum/signature, so valid-looking on-disk corruption can LOWER a persisted sequence (an anti-rollback fail-open); add a per-line integrity check (mac/checksum) or reconstruct from a signed source. (b) write_atomic uses a FIXED .tmp name -> two concurrent writers to one path can clobber the temp; use a unique per-write temp name. (c) the WITHDRAW path still persists AFTER put_record (publish-before-save); make it save-before-publish for symmetry with announce (harmless today since re-mint is idempotent, but asymmetric). (d) a malformed line is skipped and a bad header empties the whole file (anti-rollback fail-OPEN) - acceptable as a security-cache degrade but should be logged as a metric, not silent.

FORWARD-CARRIED LESSONS from TASK-185 (do not rediscover):
- The record is SIGNED ABOVE THE SEAM (sequence is inside the frozen signed bytes; the codec forbids the backend clamping it), so the durable sequence must be chosen BEFORE signing. TASK-185 resolved this with Libp2pFabric::next_announce_sequence (a durable monotonic allocator the composition root queries) + sign_libp2p_provider_record(sequence) - NOT by re-signing inside announce (which would have destabilized the whole 'signing above the seam' contract + the TTL-cap-rejection rationale + existing rollback tests that rely on stale re-puts being admitted at the substrate). Keep that split.
- announce is now save-before-publish: the per-key floor is advanced+persisted (fail-closed) BEFORE the DHT publish. A persisted-but-unpublished sequence is SKIPPED (a gap), never reused - the safe direction. Consumers must tolerate sequence gaps (they already do: strictly-newer, not contiguous).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
MPED-review addendum (from TASK-185 review): F4(b) is NOT merely a fixed-.tmp clobber. The real hazard is a LOST-UPDATE / restart-rollback race in persist::write_atomic: the announcer snapshots its per-key map UNDER the lock but writes OUTSIDE the lock, so two concurrent announce calls (even for DIFFERENT keys) can each take a snapshot and then race the rename - a writer holding an OLDER snapshot can land AFTER a newer one and DROP the newer key's durable sequence advance from disk, even though that announce already returned Ok and published (a restart-rollback for that key). A unique per-write temp name does NOT close this (the lost update is at the rename, not the temp). The FIX is to make snapshot+write ONE serialized critical section (or a persistence mutex / an flock). SAFE TODAY only because the shipped provider announce loop (install_provider) is strictly sequential (one awaited announce per seed). Fold this into the P4 advisory-lock / F4 integrity work.

TASK-185 DEEP-gate (codex) addenda — correct severities + new items:

GB3 CORRECTION (withdraw ordering is NOT harmless): TASK-185's earlier note called the withdraw publish-before-save 'harmless since re-mint is idempotent'. That is FALSE. Real failure: disk floor N; withdraw publishes tombstone N+1; CRASH before the save; restart reloads N; the positive allocator (next_sequence) re-issues N+1 for a NEW announce; consumers that already hold the tombstone reject the new positive record as an equal-sequence conflict, while fresh consumers accept it -> the network SPLITS between a withdrawn view and an active view. Severity: genuine rollback/split integrity hole (not cosmetic). FIX (in 188): make withdraw SAVE-BEFORE-PUBLISH too (persist the advanced tombstone floor before the put_record), symmetric with announce.

FAIL-CLOSED PROVIDER (deferred from GB3/L1): TASK-185 kept the provider WARN-and-continue (not fail-closed) when --libp2p-state-dir is absent, because scripts/e2e_harness.py starts libp2p providers WITHOUT --libp2p-state-dir (it only passes --iroh-state-dir). Flip the provider path to FAIL-CLOSED (refuse to start a provider without durable state, now that identity+sequence both need it) AND update e2e_harness.py to pass --libp2p-state-dir (add it next to --iroh-state-dir, using the existing per-role state_dir()).

F5 (default is non-durable; only providers warn): a default CONSUMER that observed seq 10, restarts without --libp2p-state-dir, loses its floor and will admit a seq-1 replay/rollback with NO warning. Consider warning the consumer too, or a fail-closed durable default.

F6 (consumer durable mode is fail-OPEN): FloorStore::durable turns a load failure into an EMPTY floor (floor_store.rs), a save failure only logs while STILL admitting the record (floor_store.rs persist path / persist.rs save_floors), and load_seqs/load_floors start fresh on a read error (persist.rs). So an unwritable/malformed state dir SILENTLY disables anti-rollback. In durable mode this should FAIL-CLOSED (refuse admission, or refuse to start) on a durable-mode IO/parse error, not degrade silently. (Contrast: TASK-185 already made the ANNOUNCE seq-save fail-closed and the persisted IDENTITY malformed-file fail-closed; the consumer floor is the remaining fail-open.)

PLAUSIBLE-a (parent-of-state-dir fsync): first-ever creation of the state dir fsyncs the file and the immediate parent (the state dir) but NOT the state dir's PARENT, so a power loss right after the first announce can lose the state dir's directory entry. Fsync up one more level on first creation.

PLAUSIBLE-b (sequence overflow): next_sequence does last.sequence + 1 and withdrawal minting does last+1 with no overflow guard; a corrupted seq file carrying u64::MAX wraps to 0 in release (a silent rollback) or panics in debug. Handle fail-closed (reject a u64::MAX-or-corrupt floor line on load, or saturate + refuse to publish).

TASK-185 re-gate #2 addendum: the state-dir CONSISTENCY invariant (partial-sidecar-set = corruption) is now PARTLY closed in TASK-185 - the cleanly-detectable direction (floor/seq file present while identity ABSENT -> fail-closed rekey guard) is done. The SYMMETRIC direction (identity present, floor lost -> silent self-rollback) is NOT cleanly detectable under the current lazily-created separate sidecars and is deliberately NOT special-cased; it is root-caused in the NEW TASK-189 (single atomic durable-state file with an init marker), which SUBSUMES this F6 item (consumer/provider durable-mode fail-open) plus the concurrent-save race, parent-of-state-dir fsync, and sequence-overflow. Treat F6 here as covered-by-TASK-189 to avoid overlap; leave the non-durable-default consumer-warning (F5) and the F1/F2/F5 record-lifecycle items in this task.

2026-08-21: the SERIALIZED-SAVE portion of this task is CLOSED by TASK-285 (commit be46e1f) -- DurableSeqFloor now holds a persist_lock across snapshot->save->atomic-rename as one critical section for all in-process announce savers (codex-confirmed). REMAINING scope for TASK-188: only the CROSS-PROCESS shared-state-dir advisory lock (two daemons sharing one --libp2p-state-dir). See [[durable-floor-save-requires-single-writer]] + TASK-291 (per-key atomic reservation residual).

Correction: the per-key atomic-reservation residual is TASK-292 (not 291); 291 is the drop-cancel follow-up.
<!-- SECTION:NOTES:END -->
