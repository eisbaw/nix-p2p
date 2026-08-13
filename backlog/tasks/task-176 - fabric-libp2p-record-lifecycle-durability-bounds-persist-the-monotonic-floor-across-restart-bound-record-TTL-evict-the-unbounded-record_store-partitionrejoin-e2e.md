---
id: TASK-176
title: >-
  fabric-libp2p record-lifecycle durability + bounds: persist the monotonic
  floor across restart, bound record TTL, evict the unbounded record_store,
  partition+rejoin e2e
status: In Progress
assignee:
  - mped
created_date: '2026-08-12 20:01'
updated_date: '2026-08-13 04:09'
labels:
  - libp2p
  - fabric
  - dht
  - hardening
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-152 (which WIRED the frozen peer_fabric record_store oracle into the fabric-libp2p directory/announcer as an IN-PROCESS floor). The DEEP review surfaced four honest limits that TASK-152 scoped out and documented in fabric-libp2p/src/{directory.rs,announcer.rs}:

1. RESTART-DURABLE FLOOR. The directory's ProviderRecordSet and the announcer's per-key sequence map are in-memory only. A restarted consumer loses its anti-rollback floor (can be served a still-unexpired stale/rolled-back record until it re-observes the newer sequence); a restarted provider loses its sequence counter and mints a withdrawal at sequence 1 that loses to consumers already at a higher floor (silently ineffective withdrawal). The frozen record_store module doc names DURABLE SEQUENCE as the backend's obligation. Persist per-(key,provider) floors + per-key announce sequence (Git-backed or on-disk).

2. RECORD-TTL CAP + tombstone resurrection window. Record expiry is provider-chosen and unbounded; a post-restart withdrawal (record expiry unknown) mints a tombstone with only the fixed MIN_TOMBSTONE_TTL_SECS floor, leaving a resurrection window against a longer-TTL record. Bound record TTL at announce and set the tombstone floor >= that cap so 'tombstone outlives the record' becomes a real invariant.

3. UNBOUNDED record_store growth. The consumer's ProviderRecordSet never evicts, and provider is attacker-choosable (anyone can announce under any key), so resolving attacker-chosen keys grows it without bound - a memory/DoS vector. Add bounded/TTL eviction (the frozen module leaves GC to the backend). Needs an eviction API on the store or a backend-side cap.

4. MULTI-NODE lifecycle e2e gaps. TASK-152 covers concurrent-providers + explicit-withdrawal + replay + rollback (tests/record_lifecycle.rs, mutation-verified). Add dedicated multi-node tests for: provider restart (re-announce newer honored, no resurrection), corrupted-state-at-the-composite-key (needs a crate-internal put helper), and partition+rejoin lifecycle (beyond bootstrap_independence's bootstrap-loss). Also an expiry e2e.

Also consider surfacing withdraw()'s 'published but not provably retracted' semantics in the Receipt rather than only in docs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The per-(key,provider) monotonic floor and per-key announce/withdraw sequence survive a process restart (a restarted consumer rejects a rolled-back record; a restarted provider's withdrawal is network-effective)
- [x] #2 Record TTL is bounded at announce and the withdrawal tombstone floor >= that cap, closing the post-restart/long-TTL resurrection window (invariant, test-proven)
- [x] #3 The consumer record_store is bounded (TTL/LRU eviction); resolving many attacker-chosen keys does not grow memory without bound
- [ ] #4 Multi-node e2e for restart, corrupted-state-at-composite-key, and partition+rejoin - no lost updates, no resurrection; each mutation-bites
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Land incrementally (commit each green), priority #3 then #1 then #2 then #4.
INC-A (#3 DoS): extend frozen record_store with GC/query API (slot_count, contains_slot, evict_expired, remove_slot) + a SlotFloor export/restore; add fabric-libp2p FloorStore wrapping ProviderRecordSet with a hard entry CAP + TTL sweep + LRU eviction; wire into directory.rs. Prove: resolving many distinct keys never exceeds cap (mutation: drop eviction -> grows).
INC-B (#1 restart-durable): on-disk text floor file (greppable, git-friendly) for the directory floors + announcer per-key seq map; thread state_dir Option<PathBuf> through NodeConfig -> fabric -> directory/announcer; load on construct, atomic-rewrite on change. Prove: FloorStore round-trip through a real file rejects a rolled-back seq post-restart (mutation: skip load/write -> admitted).
INC-C (#2 TTL cap): announce-side reject expiry > now+MAX_RECORD_TTL_SECS (fail fast; record is signed above the seam so cannot clamp); raise MIN_TOMBSTONE_TTL_SECS >= cap with a compile-time pin so tombstone provably outlives any capped record even post-restart. Prove: over-cap announce Rejected; post-restart tombstone.expiry >= now+cap.
INC-D (#4 e2e): record_lifecycle.rs multi-node provider-restart (state_dir preserved, newer honored, no resurrection), corrupted-state-at-composite-key (crate-internal put helper), partition+rejoin, expiry e2e. Each mutation-bites.
FROZEN: no change to record_codec wire bytes / ProviderRecord/ContentKey layout; record_store GC+persistence API is validation/GC, not wire.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DEEP-gate HONESTY RECONCILIATION (post NO-GO): the MECHANISMS are real + unit-tested and STAY; several CLAIMS were overclaims and are corrected (docs/backlog only, NO behavior code changed). Substantive hardening deferred to TASK-185.

Commits: 3cc38db, 28ab0bf, 5584fc0, d849954 (mechanisms) + <honesty-fix commit> (comments/claims). All in peer-fabric/ + fabric-libp2p/ only; FROZEN WIRE 0-line (git diff peer-fabric/src/{record_codec.rs,content.rs} empty).

#3 (DoS cap) - MET, PRODUCTION-LIVE. FloorStore bounds the directory floor (hard cap DEFAULT_STORE_CAP=4096 + TTL sweep + LRU) and is wired into Libp2pProviderDirectory::new, which the shipped daemon path uses. Resolving attacker-chosen keys can no longer grow memory. PROOF (mutation-verified): 100 distinct keys into a cap-4 store keep slot_count<=4; neutralize enforce_cap -> climbs to 100 (fails). CAVEAT (now documented, not code-changed): the eviction is NOT fail-closed anti-rollback. Because sequence and expiry are INDEPENDENT signed fields, TTL/LRU eviction of a live slot re-admits a later replay below the forgotten floor: a ROLLBACK if the slot was Active, a RESURRECTION if it was a live TOMBSTONE. Bounded session-fresh residue (same window a restart has); a fail-closed guard-window bound is TASK-185.

#1 (restart-durable) - MECHANISM BUILT + UNIT-TESTED, NOT PRODUCTION-WIRED. AC#1 UN-CHECKED. FloorStore::durable + announcer::durable + Libp2pFabric::start_durable persist the floor + per-key announce sequence and re-seed on restart, proven by a mutation-biting unit test + the multi-node provider-restart e2e. BUT the shipped daemon-libp2p (src/lib.rs ~263) builds the fabric via the NON-durable Libp2pFabric::start / start_with_supplier AND mints positive records at sequence:1 (line ~214); nothing outside tests calls start_durable. So restart-durability is proven in tests only, NOT delivered by the production binary (built-but-not-wired, like TASK-146's run()). Production-wiring + a durable POSITIVE-sequence source is TASK-185. Corrected the claim in fabric.rs (start/start_durable docs), directory.rs (store doc), announcer.rs (module doc), and here.

#2 (TTL cap + tombstone) - MET AS A SENDER POLICY + LOCAL ARITHMETIC PIN; NOT a network invariant. announce REJECTS an over-cap record TTL (fail fast; a signed record cannot be clamped), and a compile-time const _ pins MIN_TOMBSTONE_TTL_SECS >= MAX_RECORD_TTL_SECS, so a tombstone THIS announcer mints outlives any record THIS announcer published. PROOF (mutation-verified): over-cap announce Rejected (integration bite); post-restart tombstone.expiry >= a capped record's; lowering the floor below the cap fails compilation. OVERREACH CORRECTED: this is NOT an end-to-end no-resurrection network invariant - CONSUMERS do not enforce the 24h cap, so a non-conforming/malicious provider can put_record a >cap expiry the fixed tombstone floor does not outlive. Consumer-side cap enforcement is TASK-185. Claim scoped in announcer.rs (module doc + const docs + announce comment) and here. (AC#2 left checked: the sender-side mechanism + pin is real and test-proven; the network-invariant framing was doc-only and is removed.)

#4 (multi-node e2e) - PARTIAL. Landed a_restarted_provider_withdrawal_blocks_resurrection (stable, mutation-biting: non-durable restart -> seq-1 withdrawal loses -> re-served seq-5 record resurrects -> fails). NOTE it proves the MECHANISM over a live net, not production behavior (daemon is non-durable). corrupted-state / partition+rejoin / expiry e2e deferred to TASK-184.

GOTCHAS: persistence store = per-node greppable text file under state_dir (active floors via the FROZEN wire codec so reload re-verifies signature; tombstones seq+expiry; corrupt line skipped, never fatal). Eviction = hard cap 4096 + TTL-sweep-then-LRU; NOT fail-closed (see #3 caveat). TTL cap = 86400s (24h), MUST equal MIN_TOMBSTONE_TTL_SECS (const-pinned) for the SENDER-side outlives arithmetic. The provider-restart e2e only bites via a resurrection attempt (put_record overwrite masks the sequence distinction on a plain drop).

GATES (actual, after the honesty fix): nix develop -c just lint OK (clippy --locked --workspace --all-targets -D + daemon evidence-fixture; fmt; ruff; source-guard 132 .rs; lock-sources). nix develop -c cargo test --workspace: exit 0, ZERO failures (no behavior changed - docs/claims only); peer-fabric 75, fabric-libp2p lib 29 + record_lifecycle 4, daemon-core 124, fabric-iroh 91, all others 0 failed; known iroh_node_lookup/fault_loop did NOT flake. FROZEN WIRE 0-line. NO AI/co-author credit in commits.

HONEST STATE: #3 DoS cap production-live; #1/#2 mechanisms built+tested but production-wiring + network-invariant + fail-closed eviction design deferred to TASK-185.
<!-- SECTION:NOTES:END -->
