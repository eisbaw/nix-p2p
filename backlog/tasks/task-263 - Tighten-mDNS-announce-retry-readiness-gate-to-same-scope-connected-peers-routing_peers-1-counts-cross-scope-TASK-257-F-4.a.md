---
id: TASK-263
title: >-
  Tighten mDNS announce-retry readiness gate to same-scope/connected peers
  (routing_peers>=1 counts cross-scope; TASK-257 F-4.a)
status: To Do
assignee: []
created_date: '2026-08-19 08:52'
labels:
  - daemon-libp2p
  - discovery
  - mdns
  - hardening
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Surfaced by the TASK-257 arbitration (mped F-4.a). The in-daemon announce-retry readiness gate (routing_peers >= 1, in announce_seed_records + build_libp2p_provider_source, daemon-libp2p/src/lib.rs) counts ALL kad routing entries incl cross-scope Disconnected peers (libp2p-kad add_address inserts cross-scope peers as Disconnected + routing_peers counts them). So a lone-genesis provider whose only mDNS neighbour is CROSS-scope sees routing_peers>=1, exits the discovery wait early, and re-attempts announce against a table with no usable SAME-scope quorum peer -> loops until the 30s ANNOUNCE_QUORUM_RETRY_WINDOW deadline. BOUNDED + fails loud (not a TCB break), but the readiness signal is coarser than intended. FIX: tighten the readiness gate to count SAME-SCOPE / CONNECTED peers (a peer that completed the scoped /nix-p2p/<scope>/id handshake), not raw routing_peers. Relates TASK-257, TASK-262 (both stem from cross-scope peers occupying routing state).
<!-- SECTION:DESCRIPTION:END -->
