---
id: TASK-20
title: Fix check-rebuild cold-store misdiagnosis + closure scope note
status: Done
assignee: []
created_date: '2026-08-08 00:34'
updated_date: '2026-08-08 00:52'
labels:
  - deferred-finding
dependencies:
  - TASK-3
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Round-2 deep-gate finding (qa, medium): on a store where a payload derivation was never realised, nix build --rebuild returns "outputs are not valid, so checking is not possible" and check-rebuild.py wrongly prints "The payload is NONDETERMINISTIC ... Fix the derivation" (exit 1 - fail-closed but misdiagnosed; a fresh clone/CI runner gets accused of workload nondeterminism). Fix: realise first (plain nix build), then --rebuild; or classify the "are not valid" error as its own exit-2 environment error. Also document (low finding): check-rebuild rebuilds each attr's own derivation only, not its closure - fine for the current leaf-shaped workload, must be stated in the script docstring before task-9 reuses it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Cold-store run (payload never realised): exit-2 class environment message, NOT a nondeterminism accusation; bite test simulates the cold store
- [x] #2 Genuine nondeterminism (realised output + --rebuild differs) still exits 1 with the nondeterminism diagnosis
- [x] #3 Closure-scope limitation documented in the script docstring
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed in commit 0a70c5e alongside task-3 round 3 (check-rebuild.py was already being reworked for the store-path provenance finding, so folding this in avoided touching the file twice).

Cold-store misdiagnosis: check-rebuild now REALISES each payload with a plain 'nix build --print-out-paths' before running 'nix build --rebuild'. A failure at the realise step is exit 2 with the message 'This is an environment or expression failure, NOT evidence about determinism - nothing was proven either way'. Exit 1 is now reserved for realised-and-differs.

Verified by actually deleting a payload from the store ('nix store delete /nix/store/n4gcfilnaljqkqsadj7mcwyd6p0rvv0c-nix-p2p-fixture-zstd'), which reproduced the raw failure the old code misread: 'error: some outputs of ...-nix-p2p-fixture-zstd.drv are not valid, so checking is not possible'. The new script realises it and exits 0.

Genuine nondeterminism still exits 1 with the nondeterminism diagnosis, verified in isolation: only the zstd payload was made nondeterministic (date +%s%N, replacing the seeded blob so lib/app/big kept their pinned store paths) and the lock was pointed at its path, so the new store-path provenance check could not fire first and mask the result. Output: 'fixture-zstd did not rebuild to the same output ... The payload is NONDETERMINISTIC', exit 1.

Closure scope documented in the script docstring, stated as a conditional rather than a blanket reassurance: each payload's OWN derivation is rebuilt, not its closure. That covers the current leaf-shaped workload (runCommands over stdenv; the only intra-workload reference is app -> lib, itself a payload), and would NOT cover a payload that grew a first-party dependency - in which case the attr list needs extending. Flagged because the gap is invisible while the shape holds, and task-9 reuses this script.

Not deep-gated. Gate at commit: build/lint/fmt/test/package exit 0, fixtures-large exit 0, fixtures-verify-rebuild exit 0 (4/4 payloads), nix build .#daemon .#testproxy exit 0, nix flake check exit 0 (8 checks).
<!-- SECTION:FINAL_SUMMARY:END -->
