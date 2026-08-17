---
id: TASK-242
title: >-
  Operator observability follow-ups: live peer_path direct/relay +
  SwarmStatusFacts runtime test + containerized drill oracles
status: Done
assignee:
  - '@claude'
created_date: '2026-08-17 07:15'
updated_date: '2026-08-17 08:41'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Started: read TASK-240 residuals + code. Plan: (1) add PeerPath::Unknown + live direct/relay detection in fabric-libp2p swarm (track ConnectedPoint::is_relayed on ConnectionEstablished/Closed) exposed via a query cmd, wired into SwarmStatusFacts; Rust bite mutation-proven. (2) move SwarmStatusFacts to lib.rs + runtime integration test over a real Libp2pFabric (is_connected polarity + bootstrap mapping). (3) containerize the dependency-outage drill (kill boot, --status flips bootstrap_healthy + fallback_reason=bootstrap-outage, nix build still succeeds via S2). NullStatusFacts stays PeerPath::None (no swarm); SwarmStatusFacts defaults Unknown (swarm present, no classified path).

Items 1+2 landed + green (unit/integration): (1) PeerPath::Unknown added (4 distinct tokens, test peer_path_tokens_are_four_distinct_states); live direct/relay detection in fabric-libp2p (ConnPath enum + Command::ConnectionPath + Worker conn_paths ledger fed by ConnectionEstablished/Closed is_relayed; SwarmHandle::connection_path). Bites: conn_counts_classify_direct_dominant (unit), nat_traversal now asserts connection_path==Relay over a REAL circuit + ==Direct to the relay (relay-detection bite). (2) SwarmStatusFacts moved to daemon-libp2p lib.rs (pub, ::new), maps ConnPath->PeerPath (Direct/Relay/Unknown; None reserved for no-swarm NullStatusFacts); new runtime test swarm_status_facts_runtime.rs over two real Nodes: connected->healthy 1/1+Direct, unconnected->0+Unknown, mixed list mapping, and a real drop(B)->ConnectionClosed->is_connected false->0/Unknown outage flip (mutation-proven). TASK-240 drills + redaction + operator safety tests all still green. Golden byte-identical; no-floats/fmt/clippy/discovery-guard(self-test+real)/audit RC0 green. Also fixed pre-existing discovery-guard RED: TASK-241 left the forbidden token rendezvous as prose in daemon-libp2p/src/main.rs (guard scans that root) - reworded to bootstrap/entry root, non-weakening. (3) containerized dependency-outage drill added (scenario_libp2p_bootstrap_outage) + E2E_FAST; running just e2e next.

DONE (LIGHT gate). Commit fa2d2ba. Item1 live peer_path direct/relay (conn_paths ledger by ConnectedPoint::is_relayed; discriminated over a real circuit-v2 hop; 4 distinct PeerPath states) DONE mutation-proven; Item2 SwarmStatusFacts runtime test (two real Nodes, genuine drop->ConnectionClosed outage flip, both-direction mutation guards) DONE; Item3 container drill scenario_libp2p_bootstrap_outage in E2E_FAST (podman-kill real bootstrap -> live --status flips healthy+fallback_reason, S2 byte-identical) DONE; other 3 drills in-process by design (stated reason). Golden byte-identical; 120/240 no-regression; just audit RC 0; just e2e 9/9 247.4s. Incidentally fixed TASK-241 latent-red discovery guard (rendezvous prose -> reworded). Honest scope: peer_path bootstrap-scoped not NAT verdict.
<!-- SECTION:NOTES:END -->
