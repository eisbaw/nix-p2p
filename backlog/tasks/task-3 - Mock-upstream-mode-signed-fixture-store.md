---
id: TASK-3
title: Mock upstream mode + signed fixture store
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 22:05'
labels:
  - irreversible
dependencies:
  - TASK-1
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Signed fixture store + mock upstream serving it. Review-gate hardened: fixtures are built from LOCAL derivations never signed by upstream (verified trap: nix copy of a cache-fetched path carries two Sig lines - cache.nixos.org-1 plus test key - making tamper bites vacuous and S1 pass for the wrong reason). Fixture generation is pinned to flake inputs and versioned: the J2 baseline freezes against this workload, which is why this task carries the irreversible label (changing the workload later invalidates cross-wave comparison).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Mock serves nix-cache-info/narinfo/nar for fixture closures; a container nix client with the test public key substitutes them successfully with require-sigs enabled
- [ ] #2 Fixture set includes a NAR large enough (>=100MB) for mid-transfer kill tests
- [ ] #3 Tampering test: flip one byte in a fixture narinfo signature field; client MUST reject (bite test)
- [ ] #4 Mock serves nix-cache-info with EXPLICIT Priority and WantMassQuery (file:// stores emit only StoreDir - verified; implicit defaults would un-ground ordering tests)
<!-- AC:END -->
