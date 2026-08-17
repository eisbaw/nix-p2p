---
id: TASK-242
title: >-
  Operator observability follow-ups: live peer_path direct/relay +
  SwarmStatusFacts runtime test + containerized drill oracles
status: To Do
assignee: []
created_date: '2026-08-17 07:15'
labels:
  - operator
  - observability
  - follow-up
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-240 landed the live --status/--metrics surfaces + 4 in-process drill oracles. Residual partials to close: (1) peer_path direct/relay is hardcoded PeerPath::None in SwarmStatusFacts (main.rs) - the discriminator needs the swarm to track ConnectedPoint::is_relayed on ConnectionEstablished and expose it via a query command; also render peer_path=unknown (not none) when unmeasured so bootstrap_healthy=2/2 + peer_path=none is not contradictory. (2) SwarmStatusFacts (the is_connected bootstrap-health loop) has no runtime test - drills exercise a controllable MutFacts; add an integration test over a real Libp2pFabric swarm asserting is_connected polarity + bootstrap-list mapping. (3) the AC#6 drills are in-process at the observability seam; add containerized/VM network-fault drill scenarios (kill a real bootstrap process, watch is_connected flip) wired into just e2e.
<!-- SECTION:DESCRIPTION:END -->
