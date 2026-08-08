---
id: TASK-29
title: >-
  Enable narinfo disk cache by default + wire into e2e/NixOS + container AC#1
  re-assert
status: To Do
assignee: []
created_date: '2026-08-08 11:24'
updated_date: '2026-08-08 17:18'
labels:
  - wave1-followup
  - daemon
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
task-8 shipped the narinfo disk cache OPT-IN via --narinfo-cache-dir (daemon/src/main.rs); the container/NixOS paths do not set it, so the feature is unexercised end-to-end. Wire a default cache dir into the daemon (or the NixOS module state dir), pass it in scripts/e2e_harness.py and the flake NixOS module, and add a container-level assert of AC#1 (second build: nonzero daemon narinfo requests AND zero upstream narinfo hits, per the oracle-pairing rule). Depends on the blocking-fsync follow-up landing first.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Daemon uses a narinfo disk cache by default (sensible state dir), documented
- [ ] #2 e2e harness + NixOS module pass the cache dir; a container scenario asserts AC#1 oracle-paired (nonzero daemon narinfo, zero upstream narinfo on the repeat)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
From TASK-6 (J1 journey): scripts/journey.py has a runtime friction DETECTOR for this task - it greps the default daemon's log for 'narinfo disk cache at' and, while absent, emits FRICTION referencing TASK-29. When you default-wire the narinfo disk cache (main.rs prints that line when --narinfo-cache-dir is set), the journey's FRICTION for TASK-29 auto-clears - so re-run 'just journey' as part of this task's DoD to confirm the default operator now gets a persistent cache.

forward-carry from task-10: the NixOS module nixos/nix-p2p.nix has a narinfoCacheDir option (default null = OFF; daemon --narinfo-cache-dir unset). Wire a DEFAULT here. CAUTION: the daemon service runs under systemd DynamicUser, which cannot write an arbitrary absolute dir - use serviceConfig.StateDirectory (=> /var/lib/<name>, owned by the dynamic user) and pass that path, or drop DynamicUser. The VM test (nixos/vm-test.nix) is where you re-assert the e2e AC1 through systemd once the cache is on.
<!-- SECTION:NOTES:END -->
