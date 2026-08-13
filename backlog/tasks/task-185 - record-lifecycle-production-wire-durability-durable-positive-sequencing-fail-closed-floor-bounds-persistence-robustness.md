---
id: TASK-185
title: >-
  record-lifecycle: production-wire durability + durable positive-sequencing;
  fail-closed floor bounds; persistence robustness
status: Done
assignee:
  - '@me'
created_date: '2026-08-13 04:03'
updated_date: '2026-08-13 09:07'
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
- [x] #1 daemon-libp2p threads a per-node state_dir and starts via start_durable (not the non-durable start()/start_with_supplier at lib.rs:263-264); a shipped node reloads its anti-rollback floor on restart through the production run() path, not only in unit tests
- [x] #2 positive provider records receive durably-allocated monotonic sequence numbers (replacing the seq:1-always mint at line 214); after a restart the node's next record carries a sequence strictly greater than every previously published one — no collision, no self-rollback
- [x] #3 durable ordering is save-before-publish: a sequence/record is persisted (with parent-dir fsync) BEFORE it is announced to the DHT, and a save error is fail-closed (no DHT announce on persistence failure) — so a crash cannot expose an unpersisted record
- [x] #4 an integration/e2e test exercises restart-durability through the shipped run() path (start node, publish, kill, restart, assert sequence monotonicity + floor survival) and BITES BY MUTATION: reverting to start()/seq:1 makes it fail
- [x] #5 the remaining record-lifecycle hardening (F1/F2 eviction-rollback window, F5 consumer-side TTL enforcement, F6 durable-reload sweep/cap, mped-P4 state_dir advisory lock) is filed as a separate hardening follow-up with dependency edges — NOT silently dropped
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
F3 root-cause wiring. (1) daemon-libp2p Libp2pSourceConfig gains state_dir: Option<PathBuf>, threaded through build_libp2p_{nar,provider}_source -> start_and_join_libp2p, which routes Some(dir) to start_durable/start_with_supplier_durable. --libp2p-state-dir flag added to both binaries. (2) Durable positive-sequence: the record is signed ABOVE the seam (sequence in frozen signed bytes; codec forbids backend clamp), so add Libp2pFabric::next_announce_sequence(key) = announcer's disk-reseeded per-key floor last+1; sign_libp2p_provider_record takes a sequence param (was hardcoded 1); composition root allocates then signs. NOT re-signing inside announce (would destabilize signing-above-seam + TTL-cap rationale + rollback tests). (3) announce reordered to save-before-publish: advance+persist per-key floor fail-closed (AnnounceError::Persist, new variant) BEFORE the DHT publish; persist.rs write_atomic now fsyncs parent dir + propagates errors; save_seqs_checked is the fail-closed save. Persisted-but-unpublished seq is SKIPPED (gap), never reused. (4) AC4 test daemon-libp2p/tests/restart_durable_sequence_through_run.rs: B+P1(prod provider builder,state_dir)+restart P2 same seed/dir + C via prod consumer builder served through daemon_core::run; asserts record.sequence strict-monotone across restart (1 -> 2) + seq-file survival + p2p hit through run() with 0 fallback. AC3 test in record_lifecycle.rs forces persist failure (state_dir under a regular file) -> AnnounceError::Persist. (5) hardening filed as TASK-188 (dep 185).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-08-13: core wiring landed + all 3 AC bites verified by mutation (sign->seq:1 fails AC4; non-durable start* fails AC4; drop fail-closed persist fails AC3). Targeted suites green: peer-fabric 83, fabric-libp2p all (incl durable restart e2e + new AC3), AC4 stable x3 (~1.6s). Full just build OK (2m21s), just lint OK after fmt+2 doc-lint fixes. Full just test + mped review in flight. Docs corrected (fabric/announcer/directory no longer claim NOT-WIRED; F1/F2/F5 repointed to TASK-188). README disclosure updated.

2026-08-13: READY FOR DEEP GATE (qa+mped+codex). Landed in 4 commits 24ed679, 6441d82, a7d08b6, 5a290c0 (on master, not pushed). Full gate GREEN: just build (exit 0), just lint (exit 0), just test (exit 0 = cargo test --locked --workspace + fixture/golden/real-nix checks all passed). All 3 AC bites verified by mutation. mped-architect reviewed: no blockers; addressed all should-fix (directory.rs consumer-coverage honesty; announcer withdraw-comment truth; persist.rs concurrent-save lost-update race documented + filed to TASK-188; provider-without-state_dir now warns loudly; next_announce_sequence TOCTOU contract documented). Left In Progress per brief (no self-certify Done). Known honest limits: consumer floor RELOAD across restart is unit-test-only (provider announce-seq is e2e through run()); withdraw path still publish-before-save (idempotent, filed TASK-188); non-serialized concurrent save is safe only because the announce loop is sequential (filed TASK-188).

2026-08-13: DEEP-gate (codex) NO-GO addressed. GB1 (decisive): identity was ephemeral (random /dev/urandom each start), so --libp2p-state-dir persisted the sequence floor but NOT the identity -> a state-dir-only restart came back a NEW NodeId and orphaned its own records. FIX: resolve_durable_identity_seed(state_dir, explicit) in daemon-libp2p lib (SSOT) load-or-generate-and-persists the seed under state_dir/identity-seed-v1 (0600, atomic, file+parent fsync); explicit seed wins but a mismatch with a persisted one is a hard ERROR (fail-safe); malformed persisted seed is fail-closed (not silently regenerated). Wired into daemon-libp2p source_config + daemon from_args; removed both binaries' local random_identity_seed. GB2: extracted the shipped announce loop into daemon-libp2p::announce_provider_seeds (SSOT called by BOTH binaries AND the AC4 test), and reworked tests/restart_durable_sequence_through_run.rs to resolve identity FROM the state dir (no hardcoded seed passed twice), boot P1 state-dir-only -> drop -> boot P2 state-dir-only, and assert SAME provider + strictly-newer sequence. PROVEN to bite: stubbed load_identity_seed->None, test FAILED on the same-provider assertion, reverted. GB3: corrected TASK-188 (withdraw publish-before-save is NOT harmless -> real withdrawn/active network split; filed with fix); softened the provider warn comment to 'warns' (NOT fail-closed) because the e2e harness starts providers without --libp2p-state-dir - fail-closed-provider + harness update deferred to TASK-188. GB4: added --libp2p-state-dir to daemon libp2p_requested() so a state-dir-only invocation is honored (was silently dropped to upstream-only). Added 5 identity-seed unit tests (all pass). F5/F6/overflow/parent-fsync filed to TASK-188.

2026-08-13: READY FOR RE-GATE (qa + codex). DEEP-gate fixes landed in commits 51d9ddd (GB1/GB2/GB4 code), 3984dbb (AC4 rework), bf3d839 (backlog GB3/F5/F6), plus docs commit for README. Full gate GREEN: just lint (exit 0), just test (exit 0 = cargo test --locked --workspace + fixtures + golden-vectors + real-nix accept/reject all passed). New/reworked tests: 5 identity-seed unit tests (stable/explicit-persist/conflict-fail-closed/malformed-fail-closed/session-scoped), reworked restart_durable_sequence_through_run (same-identity-from-state-dir + strictly-newer sequence + serve-through-run), all stable on repeat. GB1 bite PROVEN by stubbing load_identity_seed->None (test failed on same-provider assert, reverted). Honest limits carried to TASK-188: provider WARNs not fail-closed (e2e harness spins providers without --libp2p-state-dir); withdraw still publish-before-save; consumer floor fail-open on IO error; consumer non-durable default unwarned; sequence-overflow + parent-of-state-dir fsync. NOT run: just e2e (podman/netns, unchanged no-state-dir provider behavior; harness update for fail-closed-provider is a TASK-188 item).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Production-wired restart durability into the shipped daemon-libp2p (and composite daemon): --libp2p-state-dir anchors BOTH the node identity (identity-seed-v1) and the durable per-key sequence floor, so a plain identical-argv restart keeps the same provider NodeId and a strictly-newer sequence (no self-rollback). Positive announces allocate a durable monotonic sequence and are save-before-publish with parent-dir fsync, fail-closed on save error. State dir is treated as one consistent unit: floor-present+identity-absent fails closed (rejects silent rekey). DEEP-gated across 3 rounds; codex (cross-model) overturned two same-model+qa GOs (the random-identity rekey GB1, then the partial-corruption residual) - both fixed with biting tests through the shipped run() path. Remaining hardening filed: TASK-188 (F1/F2/F5 record-lifecycle) and TASK-189 (single atomic durable-state file, subsuming F6/concurrent-save/fsync/overflow and the symmetric floor-lost direction, which is liveness-not-integrity - caught by consumer anti-rollback). Gate: build+lint green, daemon-libp2p 11/11 + fabric-libp2p 45/45 + golden/wire clean; full 'just test' blocked by an UNRELATED pre-existing iroh hanging_authority test (filed).
<!-- SECTION:FINAL_SUMMARY:END -->
