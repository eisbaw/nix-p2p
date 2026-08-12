---
id: TASK-160
title: >-
  Interim: wire fabric-libp2p discovery+transfer into the daemon p2p NarSource
  (running end-to-end, precursor to the clean daemon-core split)
status: To Do
assignee: []
created_date: '2026-08-12 09:30'
labels:
  - libp2p
  - daemon
  - integration
  - poc
  - wave-2c
dependencies:
  - TASK-103
  - TASK-151
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Functionality-first path to a RUNNING decentralized content path, ahead of the clean daemon-core/two-binary split (TASK-145/146). Wire fabric-libp2p into the EXISTING daemon crate: on a NAR miss the daemon derives ContentKey from the signed NarHash (frozen content.rs recipe), calls Libp2pFabric ProviderDirectory.find_providers, picks a ProviderRecord, fetches the raw NAR by its content Blake3Digest via NarTransfer, gate-1 BLAKE3-verifies, and serves it to Nix (which re-verifies sig+NarHash). NO injected provider - the answer comes from libp2p-kad. Pass bar: an in-process integration test through the daemon serving stack proving decentralized discover->fetch->serve over libp2p (a full podman multi-daemon e2e is a follow-up). The daemon temporarily links both fabric-iroh and fabric-libp2p; the clean per-binary packaging is TASK-145/146. Reuse the existing main.rs::setup_p2p_source plumbing.
<!-- SECTION:DESCRIPTION:END -->
