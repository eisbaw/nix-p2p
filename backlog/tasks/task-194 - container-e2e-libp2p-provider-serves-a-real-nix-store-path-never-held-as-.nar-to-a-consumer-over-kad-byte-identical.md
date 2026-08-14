---
id: TASK-194
title: >-
  container e2e: libp2p provider serves a real /nix/store path (never held as
  .nar) to a consumer over kad, byte-identical
status: Done
assignee:
  - '@claude'
created_date: '2026-08-13 15:33'
updated_date: '2026-08-14 16:45'
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

DONE (2026-08-14): container e2e landed as e2e_harness scenario s8-libp2p-store. A libp2p PROVIDER serves a REAL /nix/store path it REALISED (from the origin cache at boot, require-sigs) but NEVER held as a .nar - it regenerates the NAR on demand via nix-store --dump (--libp2p-provide-store), announced through the verification-gated PUBLIC door. Consumer bootstraps to BOOT ALONE, discovers via kad (hardened AC#9 no-injection oracle), fetches byte-identical (BLAKE3-match), 0 upstream NAR egress; kill-P control -> upstream serves the full NAR (peer path load-bearing). 13/13 checks, stable x2 (26.1s/25.9s). No .nar is mounted (host-side oracle: only signed narinfos staged); the provider's own log proves the store-dump path (LIBP2P-PROVIDE-STORE, never LIBP2P-SEED) + realise-then-dumpable.

Realise from ORIGIN not proxy (deliberate): keeps the proxy NAR cache cold so the kill-P control is a true upstream miss.

Also landed the codex test-debt SHIPPED-ANNOUNCE regression oracle (191 impl note) in daemon-libp2p/tests/store_supply_provision.rs: announce_store_provisions publishes the VERIFIED content and mints no record for a quarantined key; mutation-confirmed to bite. Fills the gap that the LAN announce_store_provisions had no direct test (container e2e uses the PUBLIC door).

Gate: cargo test -p daemon-core -p daemon-libp2p -p daemon all green (incl serve_budget_and_supply, store_supply_provision 3/3); fmt --check clean; clippy -D warnings on daemon/daemon-libp2p/daemon-core (+ --tests) clean; ruff clean; just independence green. Disk 93G free, no orphan pods/builds. 191 AC#3 checked; leaving 191 for the orchestrator DEEP gate to close.
<!-- SECTION:NOTES:END -->
