---
id: TASK-208
title: >-
  relay circuit-v2 server resource bounds + opt-out (every node relays
  unconditionally with default caps)
status: To Do
assignee: []
created_date: '2026-08-14 17:23'
labels:
  - libp2p
  - connectivity
  - resource-bounds
  - hardening
dependencies:
  - TASK-168
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Surfaced by TASK-168 AC#1: the swarm runs libp2p relay::Behaviour (circuit-v2 SERVER) UNCONDITIONALLY on every node with relay::Config::default() (fabric-libp2p/src/swarm.rs:1033), so any public node relays arbitrary traffic for NAT'd peers with no dedicated infra. This is the correct permissionless-swarm pattern, but 'unconditional + default caps on every node' is a real resource/abuse surface (bandwidth, reservation/circuit slots, connection limits). Add: (1) a NodeConfig opt-out (a node can decline to be a relay server); (2) explicit reservation/circuit/bandwidth/duration limits (do not rely on library defaults for a shipped node); (3) a bound test. Complements TASK-154 (kad resource bounds). Not a correctness bug - a deployment-safety hardening. Medium.
<!-- SECTION:DESCRIPTION:END -->
