---
id: TASK-3
title: Mock upstream mode + signed fixture store
status: In Progress
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 23:39'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-1 (e9b3378): flake.nix uses craneLib.cleanCargoSource, which keeps ONLY Cargo manifests and *.rs. Signed fixture narinfos, NAR blobs and the test ed25519 keypair will be silently excluded from the nix build source, while 'nix build .#testproxy' still runs cargo test in checkPhase - a test that skips-when-fixtures-absent becomes a vacuously green nix build while passing honestly under 'nix develop'. Widen the filter (lib.fileset union of filterCargoSources + tests/) in the same commit that adds the first fixture. A NOTE(task-3) comment marks the exact spot in flake.nix.

codex review of task-1 (finding 7): flake.nix cleanCargoSource excludes NARs/narinfos/keys - when adding fixtures, switch to an explicit fileset union and make MISSING fixtures a hard failure so nix-side tests cannot go vacuously green.
<!-- SECTION:NOTES:END -->
