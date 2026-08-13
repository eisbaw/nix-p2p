---
id: TASK-185
title: >-
  record-lifecycle: production-wire durability + durable positive-sequencing;
  fail-closed floor bounds; persistence robustness
status: To Do
assignee: []
created_date: '2026-08-13 04:03'
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
