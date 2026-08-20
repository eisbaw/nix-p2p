---
id: TASK-285
title: >-
  Periodic re-sign/republish of durable seed provider records before signed-TTL
  expiry
status: Done
assignee: []
created_date: '2026-08-20 18:26'
updated_date: '2026-08-20 23:59'
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
- [x] #1 The durable seed leg re-signs/re-announces each of its provider records BEFORE the signed expiry (a bounded refresh well inside ttl_secs), so a continuously-running seeding node stays discoverable for its seeded NarHashes indefinitely -- no TTL cliff, no restart required.
- [x] #2 Biting e2e: a node seeding S stays discoverable for S past one full record-TTL window (test uses a short ttl_secs), verified by a fresh consumer resolving+fetching S after the original record would have expired; mutation removing the re-sign task => consumer discovery of S fails after the TTL.
- [x] #3 Re-sign is fail-closed and durable-floor-correct: it allocates monotonic sequences via the same anti-rollback path as the initial announce (no sequence reuse/rollback), and a node in --libp2p-state-dir durable mode persists the advanced floor before republishing. No floats in any expiry/sequence field.
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DELIVERED across 3 DEEP-gate rounds (qa + mped + codex cross-model + 2 Mark-emulator arbitrations). Feature: a supervised periodic re-sign task (run_resign_supervised) re-signs each durable static-seed provider record at ttl/2 with a fresh monotonic sequence before its signed expiry, so a continuously-running --libp2p-seed-nar node stays discoverable indefinitely (was: undiscoverable within <=24h until restart). Commits: 283f975 (feat) + be46e1f (5 codex-HIGH fixes) + a982788 (3 Mark-emulator must-fix). KEY OUTCOME: HIGH-1 was a durable-integrity defect (the re-sign task was a concurrent floor writer violating persist.rs's documented single-writer precondition -> restart sequence-rollback) that same-model mped GO'd and cross-model codex caught; root-caused into a new DurableSeqFloor holding persist_lock across snapshot->save->atomic-rename for ALL announce savers -- codex-confirmed, and this CLOSES TASK-188's serialized-save portion. AC#1 re-sign + AC#2 continuous-discoverability-past-TTL (in-process integration bite, positive proves >=2 refresh cycles) + AC#3 monotonic-sequence/floor-tracking anti-rollback, all mutation-proven. Round-3 fixes: fresh now-per-seed (no cross-seed timestamp contamination), AC#3 test honesty (dropped false before-publish claim), Drop docstring honesty. Gate: cargo test 0 failed, just lint 14/14 exit 0 (orchestrator re-derived), libp2p e2e s7/s8/s9/s10/s10-thin ALL PASS (no regression from the DurableSeqFloor refactor). FILED hardening (Mark-emulator ruling, not gate-breaking under the TCB): TASK-289 (provide-store leg re-sign, same durability gap), 290 (test-oracle tightening + wiring e2e), 291 (drop-cancel in-flight cycle), 292 (atomic per-key allocate->commit reservation). AC#2 remains an in-process bite (not a container scenario) + provide-store leg unre-signed -- both flagged, 290/289 track them.
<!-- SECTION:FINAL_SUMMARY:END -->
