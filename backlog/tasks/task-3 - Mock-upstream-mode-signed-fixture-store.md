---
id: TASK-3
title: Mock upstream mode + signed fixture store
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 22:19'
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
- [ ] #1 Generator produces closures covering Compression none, xz and zstd, plus one >=100MB NAR stored with compression=none (kill-at-50%-bytes needs real wire volume); generation pinned to flake inputs; workload version recorded in TESTING.md
- [ ] #2 Narinfos signed ONLY by the test key - no foreign Sig lines (asserted); harness client trusted-public-keys contains exactly the test key (asserted)
- [ ] #3 Tamper bite: mutate NarHash and Sig in a served narinfo -> in-process client verification rejects; re-asserted through the full container chain once task-5 exists (documented: this proves the chain preserves Nix's verification)
- [ ] #4 Mock serves nix-cache-info with EXPLICIT Priority and WantMassQuery (file:// stores emit only StoreDir - verified; implicit defaults would un-ground ordering tests)
<!-- AC:END -->
