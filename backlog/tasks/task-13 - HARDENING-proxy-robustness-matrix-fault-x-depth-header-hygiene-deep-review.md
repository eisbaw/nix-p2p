---
id: TASK-13
title: 'HARDENING: proxy robustness matrix (fault x depth), header hygiene deep review'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-08 17:18'
labels:
  - hardening
dependencies:
  - TASK-6
  - TASK-7
  - TASK-11
  - TASK-16
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave-end hardening block, part 1 - runs only against stabilized surfaces (post J1/J2). Enlarge the fault-mode matrix across chain depths (each test-proxy fault mode x depth 1..3), timeout matrix, streaming backpressure under slow consumers, header hygiene audit (what do we forward, strip, must never touch). Deep review pass on daemon HTTP path. Includes any deferred findings phase 3 filed against these surfaces.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Fault x depth matrix (all 7 modes x depth 1..3) green - failures are FIXED in this task; a red row survives only by explicit owner-visible decision, never by silently filing it away (review gate removed the 'or documented' escape)
- [ ] #2 Header hygiene documented in-code and asserted (forwarded/stripped allowlist); gzip Content-Encoding leg and an HTTP/2-upstream leg exercised (harness is otherwise HTTP/1.1-only, the real cache.nixos.org leg is not)
- [ ] #3 Property/fuzz enlargement: narinfo unknown-field fuzz through the chain; path-traversal fuzz on cache keys (..%2f, non-base32, absurd lengths); ENOSPC in both cache layers degrades to passthrough, never serves a partial file
- [ ] #4 deferred-finding label is empty: every deferred finding closed here or converted to an explicit task by owner decision
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carry from task-10: the NixOS VM truth layer (nixos/vm-test.nix, just e2e-vm) now exists with S1/S2/module-additive proven on a real systemd nix-daemon. HARDENING TODO here (VM-level, deferred by task-10 for feature velocity): re-assert the three tamper narinfos AND testproxy fault modes THROUGH the systemd daemon in the VM, asserting the daemon-side message strings task-5 found: sig reject = "not signed by any of the keys in 'trusted-public-keys'", content = "hash mismatch importing path". Reuse build_tamper_tree/build_corrupt_nar_tree (scripts/e2e_harness.py) to build key-free tamper caches, serve them from a peer node (a plain http.server of the cache dir, OR a second nix-serve), point the client at it, and expect the realise to FAIL with those strings. ORACLE GOTCHA (banked, cost 2 slow VM runs): absent-before MUST use nix-VALIDITY (`nix-store -q --hash` fails 'not valid') NOT `test -e` - the nixos-test 9p-shared host store makes fixture files physically present on every node, so test -e is a false oracle. Interpose testproxy between daemon and nix-serve if you want VM-level request-count/fault oracles.
<!-- SECTION:NOTES:END -->
