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
updated_date: '2026-08-13 03:28'
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
- [x] #1 The per-(key,provider) monotonic floor and per-key announce/withdraw sequence survive a process restart (a restarted consumer rejects a rolled-back record; a restarted provider's withdrawal is network-effective)
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
LANDED (commits 3cc38db, 28ab0bf, 5584fc0, d849954; all in peer-fabric/ + fabric-libp2p/ only; FROZEN WIRE 0-line: git diff on peer-fabric/src/{record_codec.rs,content.rs} is empty across all four).

#3 (MOST URGENT, DoS) MET - bound the consumer ProviderRecordSet. Extended the frozen record_store with the GC/query API its own doc hands to the backend (slot_count, contains_slot, evict_expired, remove_slot) + a SlotFloor export/restore. New fabric-libp2p FloorStore wraps ProviderRecordSet with a HARD entry cap (DEFAULT_STORE_CAP=4096) + a TTL sweep (expired slots guard nothing) + LRU eviction; wired as the directory floor. Eviction policy: on a new slot over cap, sweep expired first, then LRU-evict live floors (evicting a live floor degrades that slot to session-fresh - the same residue a restart has - the price of a hard bound against an attacker controlling keys/providers/sequences/TTLs). PROOF (mutation-verified): resolving 100 distinct keys into a cap-4 store keeps slot_count<=4; neutralize enforce_cap and it climbs to 100 (test fails).

#1 MET - restart-durable floor. On-disk GREPPABLE text file (git-not-db lean), atomic write-temp+rename. persist.rs serializes the directory floor (active records via the FROZEN wire codec so reload re-verifies the signature; tombstones as seq+expiry) and the announcer per-key sequence. FloorStore::durable(path) + announcer::durable(seq_path) re-seed at startup and re-flush only on ADVANCE (Applied/Withdrawn) or eviction of a persisted slot (idempotent refreshes/rejected replays write nothing). Libp2pFabric::start_durable / start_with_supplier_durable thread a per-node state_dir; non-durable start/start_with_supplier unchanged (no NodeConfig field, no downstream construction sites moved). PROOF (mutation-verified): a durable FloorStore admits seq 5, is DROPPED (restart), a fresh store on the same path rejects a seq-3 rollback BEFORE any re-observation; neutralize the persist flush OR the load and seq 3 is admitted (test fails). Also the multi-node provider-restart e2e (below).

#2 MET - record-TTL cap + tombstone window. Announce-side POLICY: MAX_RECORD_TTL_SECS=86400 (24h); announce REJECTS (fail fast; cannot clamp a signed record) an expiry > now+cap. MIN_TOMBSTONE_TTL_SECS raised to == MAX_RECORD_TTL_SECS, so a withdrawal at now mints expiry >= now+cap >= any record's expiry EVEN post-restart -> "tombstone outlives the record" is now an invariant, compile-time-pinned (const _ assert: build fails if the floor drops below the cap). PROOF (mutation-verified): single-node announce of an over-cap record is Rejected before any network op (integration test bites); a post-restart tombstone.expiry >= a max-TTL record's expiry (unit); lowering MIN below cap fails compilation. Stale "resurrection window / TTLs unbounded" module doc corrected.

#4 PARTIAL - added a mutation-biting multi-node PROVIDER-RESTART e2e (a_restarted_provider_withdrawal_blocks_resurrection, stable 3/3): durable announce-seq -> restarted provider mints a seq-6 tombstone that blocks resurrection of a re-served seq-5 record. Mutation: restart with start() (in-memory) -> withdrawal minted at seq 1, loses to the consumer floor, the re-served seq-5 record RESURRECTS -> the sustained-absence assertion fails. (This is the first oracle to bite provider-side durability over a live net - the put_record overwrite masks the sequence distinction unless a resurrection is attempted.) DEFERRED to TASK-184: corrupted-state-at-composite-key (fail-closed decode already exhaustively unit-tested in the frozen codec + directory Err-skip; a live test needs a test-only put helper on the production API), partition+rejoin (no clean in-process connection-cut primitive; bootstrap_independence covers bootstrap-loss), expiry-e2e (bite is on the frozen decode, already unit-tested).

GOTCHAS for the next implementer:
- Persistence store choice: a small on-disk TEXT file per node under state_dir (provider-floor-v1.txt, announce-seq-v1.txt), keyed by DIRECTORY not identity - each node needs its OWN state_dir or the files clobber. Active floors round-trip through the FROZEN wire codec (encode_provider_record/decode_provider_assertion with now=0), so reload re-verifies authenticity; tombstones store seq+expiry only (the store never keeps the withdrawal bytes). A corrupt line is logged+SKIPPED (degrades only its slot to session-fresh), never fatal.
- Eviction policy: hard cap 4096 + TTL-sweep-then-LRU. LRU order is a VecDeque kept in sync with the frozen set (touch=move-to-back, evict=pop-front, TTL-sweep=retain-reconcile). Evicting a live floor is the documented anti-rollback residue.
- TTL cap value 86400s (24h): a generous refresh cadence above kad's own record republish; MUST equal MIN_TOMBSTONE_TTL_SECS (compile-time-pinned) or the post-restart tombstone-outlives-record invariant breaks. announce REJECTS over-cap (the record is signed above the seam; the backend cannot clamp).
- The provider-restart e2e ONLY bites via a resurrection attempt (re-serve the old record after the withdrawal); a plain "provider drops after withdraw" check passes even non-durable because put_record overwrites the stored value regardless of sequence. Don't regress that test into a non-biting form.

GATES (actual): cargo build -p fabric-libp2p -p peer-fabric OK. just lint OK (clippy --locked --workspace --all-targets -D warnings + daemon evidence-fixture; fmt --check; ruff check+format 26 files; source-guard 132 .rs scanned; lock-sources). just independence OK (self-test green: 10 bypasses caught, 2 legit passed; HTTP denylist green: 2 convergences caught, 18 crates denied). cargo test --workspace: exit 0, ZERO failures across all crates; peer-fabric 75, fabric-libp2p lib 29 + record_lifecycle 4 (incl. the new restart e2e) + all fabric-libp2p integration green, daemon-core 124, fabric-iroh 91, testproxy/daemon/etc all 0 failed. Known-flaky iroh_node_lookup / daemon fault_loop did NOT flake this run. FROZEN WIRE 0-line confirmed (git diff peer-fabric/src/{record_codec.rs,content.rs} empty across all four commits). Provider-restart e2e stable 3/3; DoS/restart/TTL-cap oracles each mutation-verified to bite.
<!-- SECTION:NOTES:END -->
