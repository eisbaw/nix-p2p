---
id: TASK-10
title: NixOS module + VM test layer (just e2e-vm)
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-07 22:53'
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
- [ ] #1 VM test green: client VM substitutes fixture closure through daemon + testproxy/mock VMs; S1+S2 asserted; fixtures reach the upstream VM via virtualisation.additionalPaths and are asserted ABSENT from the client VM store (else S1 passes vacuously); client substituters forced via lib.mkForce
- [ ] #2 Module: enable/port/upstream options, sets nix.settings substituter ordering with an explicit ?priority=10 URL param on the daemon substituter; daemon-off VM boots and builds via fallback (module-level additive invariant)
- [ ] #3 just e2e-vm builds/runs the VM test via a dedicated flake output (e.g. packages or apps), NOT via checks consumed by nix flake check; only fast checks feed nix flake check and the devshell (codex task-1 finding 4: everything under checks gets built by nix flake check, and flake.nix feeds checks into the devshell - VM test there would make every gate slow)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Module should pin the daemon substituter with an explicit ?priority=10 URL param (client-side override, deterministic regardless of advertised priority) in addition to serving nix-cache-info Priority < 40. Ref: bmcgee.ie TIL post.

forward-carried from task-1 (e9b3378): the NixOS module must consume flake packages.x86_64-linux.daemon (crane-built; bin/daemon; meta.mainProgram = "daemon"), not a rebuilt derivation. That attribute name is a de-facto interface shared with task-5's container images - renaming it breaks both. The flake pins nixpkgs nixos-26.05 (crane requires >= 26.05) while the dev host is NixOS 25.11; VM tests run against the flake's nixpkgs, so that is the version your test nodes get. System is hardcoded to x86_64-linux. When this lands, DELETE the 'just e2e-vm' stub (currently exits 0 printing '0 scenarios registered - NOT a pass') and add a DoD grep for that marker requiring zero hits.
<!-- SECTION:NOTES:END -->
