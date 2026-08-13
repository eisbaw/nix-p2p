---
id: TASK-194
title: >-
  container e2e: libp2p provider serves a real /nix/store path (never held as
  .nar) to a consumer over kad, byte-identical
status: To Do
assignee: []
created_date: '2026-08-13 15:33'
updated_date: '2026-08-13 15:41'
labels:
  - daemon-libp2p
  - e2e
  - libp2p
  - supply
  - integration
dependencies:
  - TASK-191
  - TASK-190
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
AC#3 of TASK-191, DEFERRED there because the shared box + the TASK-190 'just test' iroh hang make container e2e unreliable this cycle; TASK-191 landed the byte-identical proof as a LOOPBACK two-swarm bite (fabric-libp2p/tests/nar_transport.rs: Process source served byte-identical + a same-length-wrong-bytes mismatch -> Declined -> consumer never gets wrong bytes). This task adds the CONTAINER e2e: a provider container with --libp2p-provide-store serves a /nix/store path it realised but NEVER held as a .nar file; a consumer container discovers via kad, resolves, fetches byte-identical, and the produced bytes BLAKE3-match the announced content; upstream untouched on the hit. Reuse scripts/e2e_harness.py + the TASK-161 multi-daemon journey; the provider container needs a nix store with the fixture path realised. Bite: corrupt the provider's store path -> serve fails loud (BLAKE3 recheck) / consumer falls back, never a bad store path. Prereq: a quiet-enough box (container builds eat disk) and ideally TASK-190 fixed so the full gate can run.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ALSO (codex TASK-191 finding, test debt): add a SHIPPED-ANNOUNCE regression oracle - a test that goes through announce_store_provisions (not just verify_store_provisions directly) and asserts a mis-registered/quarantined key produces NO signed ProviderRecord, so a future direct-sign regression in a binary is caught. Cheaper than the full container e2e; do it here or as a unit test alongside.
<!-- SECTION:NOTES:END -->
