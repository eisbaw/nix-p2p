---
id: TASK-20
title: Fix check-rebuild cold-store misdiagnosis + closure scope note
status: To Do
assignee: []
created_date: '2026-08-08 00:34'
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
- [ ] #1 Cold-store run (payload never realised): exit-2 class environment message, NOT a nondeterminism accusation; bite test simulates the cold store
- [ ] #2 Genuine nondeterminism (realised output + --rebuild differs) still exits 1 with the nondeterminism diagnosis
- [ ] #3 Closure-scope limitation documented in the script docstring
<!-- AC:END -->
