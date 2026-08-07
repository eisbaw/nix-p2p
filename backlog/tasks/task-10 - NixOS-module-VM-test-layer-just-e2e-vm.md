---
id: TASK-10
title: NixOS module + VM test layer (just e2e-vm)
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-07 22:06'
labels: []
dependencies:
  - TASK-5
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Minimal NixOS module (enable, port, upstream URL, nix.settings wiring for substituters + trusted key) and a NixOS VM test running the core scenario on real nix-daemon + systemd: the truth layer for S2 store-open behavior and service ordering. Reuses scenario definitions from the compose harness where practical - but do not force sharing that distorts either layer.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just e2e-vm green: VM client substitutes fixture closure through daemon on a peer VM with testproxy+mock; S1+S2 asserted
- [ ] #2 Module sets substituter ordering via nix.settings; daemon-off VM boots and builds fine (additive invariant at the module level)
- [ ] #3 VM test wired into nix flake check or a just recipe (documented which, and why)
- [ ] #4 Module: enable/port/upstream options, sets nix.settings substituter ordering; daemon-off VM boots and builds via fallback (module-level additive invariant)
<!-- AC:END -->
