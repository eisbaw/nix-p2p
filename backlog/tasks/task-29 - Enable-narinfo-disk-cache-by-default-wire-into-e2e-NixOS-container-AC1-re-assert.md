---
id: TASK-29
title: >-
  Enable narinfo disk cache by default + wire into e2e/NixOS + container AC#1
  re-assert
status: To Do
assignee: []
created_date: '2026-08-08 11:24'
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
