---
id: TASK-262
title: >-
  Deterministic cross-scope mDNS peer eviction from the kad routing table
  (event-driven; TASK-257 F-2 downscope)
status: To Do
assignee: []
created_date: '2026-08-19 08:00'
labels:
  - fabric-libp2p
  - discovery
  - mdns
  - hardening
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Downscoped from TASK-257 F-2 (DEEP gate + direction review). TASK-257 BOUNDS cross-scope mDNS routing pollution via the F-1 admission cap: a cross-scope peer occupies <= cap kad routing slots as a decaying dead-end (answers no scoped query), bounded, content-safe -- the 257 7/7 content-isolation e2e proves the boundary, and a cross-scope peer costs at most ONE wasted dial (inside the "a cross peer costs a retry" TCB line). This follow-up adds DETERMINISTIC eviction so a cross-scope peer does not occupy routing slots or propagate as a FIND_NODE hint even transiently: on a scoped-handshake FAILURE (identify::Event::Error for an mdns_pending peer that negotiated a different/no /nix-p2p/<scope>/id), remove_address it. EVENT-DRIVEN, NO timer/sweep (257 abandoned a tokio::time::interval sweep as flaky/stall-prone). Priority LOW: routing-hygiene above the product TCB line; only matters when MULTIPLE distinct pools share one LAN -- a single-scope home/org user never hits it (per the out-of-box north star). Bite: a cross-scope mDNS peer is ABSENT from routing_peers() after its failed scoped handshake. Relates TASK-257, check-discovery-no-shortcut.
<!-- SECTION:DESCRIPTION:END -->
