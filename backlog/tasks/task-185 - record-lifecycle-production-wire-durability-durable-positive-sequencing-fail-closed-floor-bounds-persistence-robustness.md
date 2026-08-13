---
id: TASK-185
title: >-
  record-lifecycle: production-wire durability + durable positive-sequencing;
  fail-closed floor bounds; persistence robustness
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-13 04:03'
updated_date: '2026-08-13 06:33'
labels:
  - fabric-libp2p
  - daemon-libp2p
  - integrity
  - durability
  - hardening
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-176 DEEP gate (qa+mped+codex) — codex NO-GO, findings CONFIRMED. The floor/persist/TTL MECHANISMS are built + unit-tested, but: (F3, CONFIRMED) the durable path is NOT wired into the shipped daemon — daemon-libp2p/src/lib.rs:263-264 uses non-durable start()/start_with_supplier(), mints positive records at sequence:1 (line 214), nothing outside tests calls start_durable; so restart-durability + anti-rollback across restart is proven only in tests. To production-wire #1: thread a per-node state_dir into daemon-libp2p, use start_durable, and ALLOCATE positive-record sequences durably (a real monotonic sequence allocator; seq:1-always makes post-restart records collide/rollback). (F1/F2 design) live LRU eviction of an active floor slot (or a live tombstone) under 4096-key cap pressure re-opens a bounded rollback/RESURRECTION window (attacker floods keys + induces resolves + replays a captured still-unexpired record + DHT serves it); the tradeoff CHOSE rollback over rejection. Consider fail-closed-at-capacity (reject/quarantine a new slot rather than evict a guard) OR a guard_until=max(observed expiry) so a shorter-refresh-TTL record cannot roll back a higher sequence. (F5) the 24h TTL cap is announce-side only — consumers do not enforce it, so a non-conforming provider put_record'ing a >24h expiry voids the bound. (F4) persistence is anti-rollback FAIL-OPEN: malformed line skipped (guard lost), bad header -> whole file empty; tombstone/sequence lines have NO checksum/signature (valid-looking corruption can lower a sequence); publish-before-save (announce publishes to DHT then saves seq -> a crash exposes an unpersisted record); save errors only logged; concurrent announces can save out of order (lock released before write); no parent-dir fsync; fixed .tmp name. (F6) FloorStore::durable reload restores every line with NO sweep/cap -> an oversized/corrupt file exceeds 4096 at startup. (mped P4) shared state_dir silently corrupts -> add an advisory lock / fail-loud.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 daemon-libp2p threads a per-node state_dir and starts via start_durable (not the non-durable start()/start_with_supplier at lib.rs:263-264); a shipped node reloads its anti-rollback floor on restart through the production run() path, not only in unit tests
- [ ] #2 positive provider records receive durably-allocated monotonic sequence numbers (replacing the seq:1-always mint at line 214); after a restart the node's next record carries a sequence strictly greater than every previously published one — no collision, no self-rollback
- [ ] #3 durable ordering is save-before-publish: a sequence/record is persisted (with parent-dir fsync) BEFORE it is announced to the DHT, and a save error is fail-closed (no DHT announce on persistence failure) — so a crash cannot expose an unpersisted record
- [ ] #4 an integration/e2e test exercises restart-durability through the shipped run() path (start node, publish, kill, restart, assert sequence monotonicity + floor survival) and BITES BY MUTATION: reverting to start()/seq:1 makes it fail
- [ ] #5 the remaining record-lifecycle hardening (F1/F2 eviction-rollback window, F5 consumer-side TTL enforcement, F6 durable-reload sweep/cap, mped-P4 state_dir advisory lock) is filed as a separate hardening follow-up with dependency edges — NOT silently dropped
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
F3 root-cause wiring. (1) daemon-libp2p Libp2pSourceConfig gains state_dir: Option<PathBuf>, threaded through build_libp2p_{nar,provider}_source -> start_and_join_libp2p, which routes Some(dir) to start_durable/start_with_supplier_durable. --libp2p-state-dir flag added to both binaries. (2) Durable positive-sequence: the record is signed ABOVE the seam (sequence in frozen signed bytes; codec forbids backend clamp), so add Libp2pFabric::next_announce_sequence(key) = announcer's disk-reseeded per-key floor last+1; sign_libp2p_provider_record takes a sequence param (was hardcoded 1); composition root allocates then signs. NOT re-signing inside announce (would destabilize signing-above-seam + TTL-cap rationale + rollback tests). (3) announce reordered to save-before-publish: advance+persist per-key floor fail-closed (AnnounceError::Persist, new variant) BEFORE the DHT publish; persist.rs write_atomic now fsyncs parent dir + propagates errors; save_seqs_checked is the fail-closed save. Persisted-but-unpublished seq is SKIPPED (gap), never reused. (4) AC4 test daemon-libp2p/tests/restart_durable_sequence_through_run.rs: B+P1(prod provider builder,state_dir)+restart P2 same seed/dir + C via prod consumer builder served through daemon_core::run; asserts record.sequence strict-monotone across restart (1 -> 2) + seq-file survival + p2p hit through run() with 0 fallback. AC3 test in record_lifecycle.rs forces persist failure (state_dir under a regular file) -> AnnounceError::Persist. (5) hardening filed as TASK-188 (dep 185).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-08-13: core wiring landed + all 3 AC bites verified by mutation (sign->seq:1 fails AC4; non-durable start* fails AC4; drop fail-closed persist fails AC3). Targeted suites green: peer-fabric 83, fabric-libp2p all (incl durable restart e2e + new AC3), AC4 stable x3 (~1.6s). Full just build OK (2m21s), just lint OK after fmt+2 doc-lint fixes. Full just test + mped review in flight. Docs corrected (fabric/announcer/directory no longer claim NOT-WIRED; F1/F2/F5 repointed to TASK-188). README disclosure updated.
<!-- SECTION:NOTES:END -->
