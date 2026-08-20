---
id: TASK-280
title: >-
  LAN-non-transitive publication + serving substrate for no-allowlist lan-share
  (isolation guarantee)
status: In Progress
assignee: []
created_date: '2026-08-20 07:29'
updated_date: '2026-08-20 10:14'
labels:
  - irreversible
  - privacy
  - security
dependencies:
  - TASK-276
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Splits out the CRITICAL egress-transitivity defect codex found during TASK-276 (Mark-emulator: listener-INDEPENDENT, so PRE-EXISTING, fires identically under the pre-276 loopback default; 276 did not create it). A lan-share node feeds mDNS/Kad-returned/Identify addresses into Kademlia UNFILTERED, dials them, announces transitively (start_providing/put_record), and serves /nar over ANY established connection incl provider-ORIGINATED (libp2p bidirectional) -> a dual-homed same-v1 Kad node on the LAN also joined to public peers bridges the provider to the public DHT; a public peer fetches over the outbound connection, never traversing the private listener. Cannot fire by default (no default public swarm at HEAD) but falsifies the lan-share public-isolation GUARANTEE. This task holds that guarantee.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 No-allowlist lan-share path filters mDNS / Kad-returned / Identify addresses to LAN-only literals (reuse the TASK-276 FIX#1 positive-grammar classifier) BEFORE they enter Kademlia or the dial queue -> the node never dials a non-LAN peer address
- [x] #2 /nar serving is restricted to connections of LAN PROVENANCE (peer observed remote address is loopback/link-local/private) -> an outbound connection to a non-LAN peer cannot be used to serve (closes the bidirectional-serve leg)
- [x] #3 Evaluate a DISTINCT Kademlia protocol scope for lan-share (not the shared v1) so a lan-share node's DHT is structurally not the public DHT; decide in-task whether address-filtering + serve-provenance suffice or the scope split is required
- [ ] #4 Biting e2e (the codex exploit as a negative control): a dual-homed same-v1 bridge node on the LAN + a public peer; the public peer CANNOT learn the content key and CANNOT fetch. RED against today's HEAD (proves it bites), GREEN after the fix
- [x] #5 Consumer/provider scope PARITY: the zero-config lan-share CONSUMER defaults to the SAME new lan-share scope as providers (or discovery silently breaks). --libp2p-scope still overrides (advanced escape hatch); public-share stays on v1
- [x] #6 WIRE FREEZE: the lan-share scope string is a compatibility surface -> use a VERSIONED constant (lan-share.v1) and FREEZE it in PRD.md (correct risk #13); pick now while TASK-276 cross-host serving is unreleased (no deployed lan-share-on-v1 base to strand)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Mark-emulator decision: implement ALL THREE (none redundant; exploit needs both legs).
(1) ADDRESS-INGESTION FILTERING via a Swarm-level DIAL VETO -- a thin wrapping NetworkBehaviour (LanDialGuard) whose handle_pending_outbound_connection returns Err for any addr failing a new fabric-libp2p multiaddr_lan_provenance predicate (first IP hop loopback/link-local/private AND no P2pCircuit/Dns/relay hop). This is the REAL chokepoint (covers kad-INTERNAL autonomous dials, not just the two add_address callsites swarm.rs:2422/2501 -- gate those too as hygiene). Gated on PublicationPlan::Lan only; public-share unrestricted.
(2) /nar SERVE-PROVENANCE: extend the conn_routes ledger (fed at ConnectionEstablished swarm.rs:~1833 from ConnectedPoint) to record multiaddr_lan_provenance(remote); publish a live LAN-provenance-peer view; run_accept_loop (swarm.rs:2694) requires >=1 LAN-provenance live connection before serve_stream, else drop+warn. Closes the bidirectional-serve leg. Gated on Lan.
(3) DISTINCT lan-share SCOPE: const LAN_SHARE_NETWORK_SCOPE="lan-share.v1" (single-sourced in fabric-libp2p); selected in the SINGLE publication decision so both binaries agree (Lan + no explicit --libp2p-scope -> lan-share.v1; else honour override / v1 for allowlist); fed to Libp2pProviderConfig.network_scope (lib.rs:2406). Scope namespaces kad+identify+nar together, so a v1 bridge is cross-scope on all three. CONSUMER must default to the same scope.
Shared classifier: move ip_is_provably_private core DOWN into fabric-libp2p (re-export from daemon-libp2p); add multiaddr_lan_provenance sibling (dial/serve grammar allows trailing /p2p/<id>, unlike the strict LISTEN grammar).
Biting e2e (E2E_FAST): dual-homed bridge X on TWO podman networks (LAN 10.211.34.0/24 + public 10.99.0.0/24) running a standard v1 node; P provider lan-share LAN-only; P_pub public-only v1 runs get_providers(K)+/nar fetch. Assert P_pub CANNOT learn K (bites 3) AND P never dials 10.99.x (bites 1) AND /nar refused over public-provenance conn (bites 2); each fix reverted independently -> its assertion RED; RED-at-HEAD proven by WAITING on P_pub query terminal event (not sleep) + re-deriving from raw. Full DEEP gate (irreversible+security+wire-freeze); codex verifies the dial-veto chokepoint completeness, provenance source (Listener send_back_addr + relayed classify non-LAN), consumer/provider scope parity, versioned frozen constant.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-280 implementation (commits 5e44a2e fabric, c0618fa daemon layer). AC#1/#2/#3/#5/#6 DONE + mutation-proven (RED-on-revert then reverted). AC#4 (biting e2e) OPEN: feasibility CONFIRMED (rootless dual-homed 2-network podman verified: eth0 LAN 10.211.99.5 + eth1 non-private 203.0.113.5), NOT yet built/run.

Design: three composed mitigations gated on the no-allowlist lan-share path only (NodeConfig.lan_confinement, set iff profile==LanShare / PublicationPlan::Lan).
(1) DIAL VETO: LanDialGuard NetworkBehaviour. Chokepoint is handle_established_outbound_connection (per concrete address), NOT the pending hook — verified against shipped sources that libp2p-kad 0.48 dials by PeerId with empty DialOpts and supplies addresses via its OWN pending-hook return, and the derive passes every sibling field the same empty slice. Pending hook additionally denies explicit all-non-LAN dials pre-transport; add_address gated as hygiene. Honest residual: a transport connect may briefly occur before deny, but no usable libp2p session forms.
(2) SERVE PROVENANCE: worker records each kept connection LAN provenance (remote=dialed addr for outbound / send_back_addr for inbound; relayed=non-LAN) into a shared live view; run_accept_loop refuses serving a peer with no live LAN-provenance connection (fail-closed).
(3) DISTINCT SCOPE (WIRE FREEZE): LAN_SHARE_NETWORK_SCOPE=lan-share.v1 single-sourced in fabric-libp2p; effective_network_scope(explicit,lan_share) selects it; both binaries agree; consumer/provider parity is structural (one fabric, one scope). PRD risk #13 records the freeze.

Shared classifier moved DOWN to fabric-libp2p/src/lan.rs (ip_is_provably_private re-exported by daemon-libp2p; new multiaddr_lan_provenance).

AC#4 e2e SPEC (harness-verified by explore): new topology in scripts/e2e_harness.py modeled on Libp2pLanShareServeTopology (:2765); TWO podman networks LAN + a genuinely NON-private public net (use 203.0.113.0/24 TEST-NET-3, NOT 10.99.0.0/24 which is RFC1918 and would classify LAN); P=--profile lan-share on LAN only seeds K; X dual-homed (--network lan --network pub) standard /bin/daemon on scope v1 bootstrapping P_pub; P_pub on public net only runs get_providers(K)+/nar fetch. Oracles reuse existing: proxy upstream.nar>=1 + absence of daemon-core/src/peer_source.rs:194 discovered-provider-record log line within a bounded poll of P_pub query terminal (NOT a sleep); attribute DIAL leg (P never dials 203.0.113.x) + SERVE leg (public-provenance /nar refused). Register in SCENARIOS + E2E_FAST. RED-at-HEAD must be proven against the reverted mitigations, positively observing P_pub learning K at pre-fix HEAD.

Gates green: cargo test -p daemon-core -p daemon-libp2p -p daemon -p fabric-libp2p (exit 0); cargo fmt --all --check; ruff check scripts; nix-instantiate --parse nixos/nix-p2p.nix. NOT marking Done (AC#4 open).
<!-- SECTION:NOTES:END -->
