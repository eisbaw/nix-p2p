---
id: TASK-188
title: >-
  record-lifecycle hardening: fail-closed floor bound (F1/F2), consumer TTL cap
  (F5), durable-reload sweep/cap (F6), state_dir advisory lock (P4), persistence
  integrity (F4 remnants)
status: To Do
assignee: []
created_date: '2026-08-13 06:13'
updated_date: '2026-08-13 06:40'
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
<!-- SECTION:NOTES:END -->
