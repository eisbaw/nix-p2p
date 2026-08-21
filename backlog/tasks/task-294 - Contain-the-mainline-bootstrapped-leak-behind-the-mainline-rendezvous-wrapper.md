---
id: TASK-294
title: >-
  Contain the mainline bootstrapped() leak behind the mainline-rendezvous
  wrapper
status: To Do
assignee: []
created_date: '2026-08-21 02:28'
labels:
  - hardening
  - follow-up
dependencies:
  - TASK-284
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Pre-existing containment leak (mped, unchanged by TASK-284): daemon-libp2p/src/mainline_bootstrap.rs:~172 calls dht.bootstrapped() directly on the re-exported bare mainline AsyncDht (via RendezvousNode alias, mainline-rendezvous/src/lib.rs:~35). build_node/announce/discover are wrapped, but this one inherent method leaks the mainline API surface into daemon-libp2p. Cargo.toml claims the mainline edge stays behind the one wrapping crate - true for the dependency graph, overstated for the API surface. Expose mainline_rendezvous::bootstrapped(&node, timeout) so the seam is one crate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 daemon-libp2p reaches no inherent mainline method directly; bootstrapped() (and any other mainline call) goes through a mainline-rendezvous wrapper fn, so the mainline API surface is contained behind the one crate.
<!-- AC:END -->
