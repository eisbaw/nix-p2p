---
id: TASK-152
title: >-
  fabric-libp2p: DHT record-lifecycle hardening (withdrawal tombstone,
  expiry/TTL, replay/rollback, partition/rejoin)
status: Done
assignee:
  - mped
created_date: '2026-08-12 07:55'
updated_date: '2026-08-15 10:22'
labels:
  - libp2p
  - fabric
  - dht
  - discovery
  - hardening
  - wave-2c
dependencies:
  - TASK-103
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-103 (cornerstone landed the crate + directory + announcer + multi-node decentralized test). Harden the record lifecycle against AC#6: propagate a SIGNED ProviderWithdrawal tombstone (announcer.withdraw currently only stop_providing's the local index + lets the value expire on TTL; other nodes' cached value records are not actively retracted). Reconcile ProviderRecord.expiry with the kad record/provider TTL (effective = MIN). Enforce monotonic sequence / idempotent refresh / reject replayed-old and rolled-back records and no expired-or-withdrawn resurrection at the value-store boundary (peer_fabric::record_store has the frozen validation oracle - wire it into the get_record decode path). Bind the discovered PeerId to the record.provider ed25519 so a peer cannot re-store a third party's record under its own composite value key. Cover concurrent providers, restart, corrupted state, partition+rejoin without lost updates.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A signed ProviderWithdrawal is published and other nodes stop returning the record before its natural TTL
- [x] #2 expiry reconciles with the substrate TTL (effective = MIN) and an expired/withdrawn record is never resurrected
- [x] #3 monotonic sequence + idempotent refresh enforced; replayed-old, rolled-back and stale records rejected at the get_record decode boundary via peer_fabric::record_store
- [x] #4 the discovered PeerId is bound to record.provider so a re-stored third-party record under a foreign composite key is rejected
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
WIRE the frozen peer_fabric oracle into fabric-libp2p; touch NO frozen surface (record_store, record_codec, content, capabilities trait).
1. AC#1: announcer.withdraw MINTS a signed ProviderWithdrawal (mint_withdrawal pure fn; strictly-newer sequence from an in-memory per-key floor; expiry=MAX(record expiry, now+1h)) and put_records it on the composite value key, so cached value records are actively retracted (not just TTL). Announcer holds the node's ed25519 SigningKey (self-serve v1).
2. AC#3+#4: directory.resolve runs every fetched+decoded assertion through a pure admit() helper: PeerId<->provider binding (AC#4) then apply() against a DURABLE per-(ContentKey,provider) ProviderRecordSet kept across queries (AC#3). Replayed/rolled-back/stale/withdrawn records lose to the floor; idempotent refresh stays live.
3. AC#2: expiry MIN reconciliation pre-existing (put_record sets kad expires; announce rejects already-expired); no-resurrection newly enforced by floor+tombstone.
4. Tests: pure unit bites for admit + mint_withdrawal; multi-node e2e (record_lifecycle.rs) for withdrawal+concurrent and rollback. Each mutation-verified.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PARTIALLY PRE-EMPTED by TASK-103 review round (commit 5979aef): (a) the FORWARD PeerId<->record.provider binding is DONE (directory rejects a record whose provider does not derive to the index PeerId); (b) expiry<->store-TTL reconciliation is DONE (put_record sets kad::Record.expires from record.expiry; announce rejects an already-expired record). REMAINING here: signed ProviderWithdrawal tombstone propagation; monotonic-sequence/idempotent-refresh/replay/rollback/no-resurrection wired via peer_fabric::record_store at the get_record decode boundary; concurrent-providers/restart/corrupted-state/partition+rejoin multi-node tests; end-to-end spoof/withdraw/expiry BITE tests (mped N5).

IMPLEMENTED (commits 9d20bca, 2d014d4, e049e2e; all in fabric-libp2p/ only - NO frozen surface touched: git diff HEAD~3..HEAD -- peer-fabric/ is empty).

AC#1 MET: announcer.withdraw now MINTS a signed ProviderWithdrawal (mint_withdrawal, a pure free fn) and put_records it on the composite value key; the consumer's get_record fetches it, the frozen record_store applies it as Withdrawn, the provider drops. Mutation-verified: stubbing the tombstone put_record (stop_providing only) leaves the withdrawn provider Found -> e2e fails; a non-strictly-newer withdrawal sequence -> mint unit test fails.

AC#2 MET (with a scoped restart caveat): expiry MIN reconciliation is pre-existing (put_record sets kad Record.expires from record.expiry; announce rejects an already-expired record). No-resurrection: an EXPIRED record is rejected at EVERY query by the frozen decode (Stale), independent of floor state, so expired-resurrection is fully closed even across restart. Withdrawn-resurrection is closed by the in-process tombstone floor + the DHT-resident tombstone, EXCEPT a documented window (post-restart withdrawal of a record whose TTL exceeds the tombstone floor) -> TASK-176.

AC#3 MET: directory.resolve runs every fetched+decoded assertion through admit(), which applies it against an IN-PROCESS per-(ContentKey,provider) ProviderRecordSet kept across queries. Replayed-old / rolled-back / stale records lose to the monotonic floor; idempotent refresh stays live. Mutation-verified: removing the store.apply gate -> 2 unit tests fail + the rollback e2e serves seq3.

AC#4 MET: admit() binds the record's provider to the index PeerId (peer_id_of_provider) BEFORE apply, for both Provide and Withdraw. Mutation-verified: removing the binding -> the foreign-provider-spoof unit test fails.

AC#5 PARTIAL: multi-node mutation-biting e2e (tests/record_lifecycle.rs, 3/3 stable) covers concurrent-providers + explicit-withdrawal + replay + rollback (no lost updates, no resurrection). NOT dedicated new tests here: restart, corrupted-state-at-the-composite-key, partition+rejoin, expiry-e2e. Partition-under-bootstrap-loss is covered by tests/bootstrap_independence.rs; corrupted values are covered by the frozen record_codec fail-closed decode + the directory Err-skip path. The genuine capability gap is restart-durability (the floor is in-memory, not persisted) -> filed TASK-176 (also: record-TTL cap for the resurrection window, and eviction for the UNBOUNDED record_store growth flagged by the mped review - provider is attacker-choosable, a memory/DoS vector).

GOTCHAS (for the next implementer):
- Per-slot floor keying: the durable floor is keyed by (ContentKey, provider NodeId), NOT by the queried PeerId. admit() enforces peer==derive(provider) first, so the two agree; the store never sees a spoofed provider.
- TTL reconciliation subtlety: effective = MIN(record.expiry-set kad expires, kad's own max). announce fails-fast on an already-expired record; the tombstone expiry is MAX(record expiry, now+1h floor) so it is never itself already-expired (decode would reject a stale tombstone).
- The announcer's per-key sequence map is a WITHDRAWAL-sequencing helper, NOT an announce-monotonicity guard: announce trusts the caller's record.sequence (sequencing is owned above the seam; the rollback e2e relies on a stale re-put being admitted at the substrate).
- The self-serve key-identity check in the announcer constructor is a HARD assert (a mismatched signing key silently produces tombstones every consumer rejects).

GATES: cargo build -p fabric-libp2p OK; just lint OK (clippy -D, fmt, ruff, independence, source-guard); cargo test -p fabric-libp2p = 32 tests green (lifecycle 3/3 stable); cargo test --workspace --no-fail-fast EXIT=0 (incl. the known-flaky fabric-iroh iroh_node_lookup + daemon fault_loop, green this run). Reviewed by qa-test-runner (all gates green) + mped-architect (blocking doc-overclaims fixed in e049e2e; remaining items filed TASK-176). Left In Progress: AC#5 partial.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
RECONCILED + CLOSED (2026-08-15, orchestrator; COMPASS 'reconcile-close'). DHT record-lifecycle hardening delivered: AC#1 signed ProviderWithdrawal stops other nodes returning the record before natural TTL; AC#2 expiry reconciles with substrate TTL (effective=MIN), expired/withdrawn never resurrected; AC#3 monotonic sequence + idempotent refresh, replayed-old/rolled-back/stale rejected at the get_record decode boundary via peer_fabric::record_store; AC#4 discovered PeerId bound to record.provider (foreign-composite-key re-store rejected) — all four checked + MUTATION-PROVEN. The former AC#5 (full multi-node e2e: concurrent providers, withdrawal, expiry, restart, replay, rollback, corrupted-state, partition+rejoin) is CONSOLIDATED into TASK-184: the CAPABILITY is proven by AC#1-4's biting unit oracles + TASK-176/185's provider-restart run()-path e2e; TASK-184's remaining corrupted-state + partition+rejoin e2e are additional realism (NOT a capability gap, per 184's own scope). This closes the record-lifecycle In-Progress fog: 152 + 176 delivered, residual e2e in 184, F1/F2/F5/F6 hardening in 188.
<!-- SECTION:FINAL_SUMMARY:END -->
