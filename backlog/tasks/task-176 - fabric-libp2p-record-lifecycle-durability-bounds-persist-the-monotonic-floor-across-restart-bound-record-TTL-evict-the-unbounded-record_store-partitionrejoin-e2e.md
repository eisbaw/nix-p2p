---
id: TASK-176
title: >-
  fabric-libp2p record-lifecycle durability + bounds: persist the monotonic
  floor across restart, bound record TTL, evict the unbounded record_store,
  partition+rejoin e2e
status: To Do
assignee: []
created_date: '2026-08-12 20:01'
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
