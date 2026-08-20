---
id: TASK-285
title: >-
  Periodic re-sign/republish of durable seed provider records before signed-TTL
  expiry
status: To Do
assignee: []
created_date: '2026-08-20 18:26'
labels:
  - hardening
  - durability
  - north-star
dependencies:
  - TASK-279
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The static-seed leg (--libp2p-seed-nar) announces its provider records ONCE at startup with an absolute signed expiry = now + ttl_secs (cap 24h, fabric-libp2p/src/announcer.rs MAX_RECORD_TTL_SECS=86400) and NOTHING re-signs them (daemon-libp2p/src/lib.rs: one-shot announce ~L332, expiry ~L478; comment ~L1637 'never re-announces'). libp2p-kad's native record republishing re-provides the same bytes but CANNOT extend the signed absolute expiry, so after the TTL a consumer rejects the record and the seed goes UNDISCOVERABLE until daemon restart -- with zero operator signal. This is PRE-EXISTING (a pure --libp2p-seed-nar node vanished after TTL before TASK-279) and TASK-279's SeedOwned guard (correctly) removes the announce-after-fetch hook's accidental re-announce path for seed keys, so the seed leg now needs its OWN re-sign. HIGH because it lands on the NORTH STAR: a box left seeding overnight is dark by morning -- 'useful out of the box' failing for the exact org/LAN zero-config loop (273/276/278/279/280) that is THE priority. Found by codex in the TASK-279 DEEP gate; Mark-emulator ruled it a separate task, flagged more important than 279's own edge case.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The durable seed leg re-signs/re-announces each of its provider records BEFORE the signed expiry (a bounded refresh well inside ttl_secs), so a continuously-running seeding node stays discoverable for its seeded NarHashes indefinitely -- no TTL cliff, no restart required.
- [ ] #2 Biting e2e: a node seeding S stays discoverable for S past one full record-TTL window (test uses a short ttl_secs), verified by a fresh consumer resolving+fetching S after the original record would have expired; mutation removing the re-sign task => consumer discovery of S fails after the TTL.
- [ ] #3 Re-sign is fail-closed and durable-floor-correct: it allocates monotonic sequences via the same anti-rollback path as the initial announce (no sequence reuse/rollback), and a node in --libp2p-state-dir durable mode persists the advanced floor before republishing. No floats in any expiry/sequence field.
<!-- AC:END -->
