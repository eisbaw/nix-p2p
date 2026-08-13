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
updated_date: '2026-08-13 02:52'
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
- [ ] #2 Record TTL is bounded at announce and the withdrawal tombstone floor >= that cap, closing the post-restart/long-TTL resurrection window (invariant, test-proven)
- [ ] #3 The consumer record_store is bounded (TTL/LRU eviction); resolving many attacker-chosen keys does not grow memory without bound
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
