---
id: TASK-241
title: >-
  Reconcile nixos/nat-vm-test.nix relay/zboot with the TASK-120
  operator-contract (--profile upstream-only rejects their bootstrap flags)
status: To Do
assignee: []
created_date: '2026-08-17 04:15'
labels:
  - ci
  - nixos
  - operator
  - regression
  - nat
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-120 (operator contract, commit 4f5d524) made --profile validation fail-closed: a node with --libp2p-bootstrap under --profile upstream-only is rejected (daemon-libp2p/src/main.rs:459). nixos/nat-vm-test.nix configures the relay + zboot nodes as libp2p.enable=true with listen+bootstrap but NO explicit role/profile, so nixos/nix-p2p.nix (profile->flag mapping ~L36-38) emits the DEFAULT --profile upstream-only alongside --libp2p-bootstrap -> nix-p2p-daemon.service exits at boot, and the NAT-VM test fails at subtest 2 (services come up FIRST) before ANY circuit/discovery subtest. The daemon behavior is CORRECT (fail-closed working); the TEST MODULE drifted. Surfaced by TASK-236 (libp2p 0.56 bump) re-running the NAT-VM; NOT a libp2p regression (would fail identically on 0.54). FIX: give the nat-vm relay/zboot nodes an explicit valid profile (a bootstrap/relay node is a provider or a router, not upstream-only) OR fix the nix-p2p.nix default profile for a libp2p.enable+bootstrap node. Then re-run nix build .#nat-vm-test on libp2p 0.56 to complete TASK-236 AC#4 NAT proof + re-validate TASK-218. The TASK-120 just-e2e gate did not catch this because the NAT-VM is not in just e2e - consider adding a nix flake check of the NixOS module to the operator-contract gate.
<!-- SECTION:DESCRIPTION:END -->
