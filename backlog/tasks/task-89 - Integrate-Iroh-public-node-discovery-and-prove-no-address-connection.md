---
id: TASK-89
title: Integrate Iroh public node discovery and prove no-address connection
status: To Do
assignee: []
created_date: '2026-08-10 07:09'
updated_date: '2026-08-14 21:48'
labels:
  - wave-2b
  - discovery
  - iroh
  - deferred-pending-202
dependencies:
  - TASK-114
  - TASK-115
  - TASK-137
  - TASK-138
  - TASK-139
  - TASK-166
  - TASK-187
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Integrate independently implemented node-address publication TASK-137 NodeId lookup TASK-138 and relay transport TASK-139 on the shared TASK-115 runtime. Prove a public/global Iroh connection without peer-address injection and emit public-node-discovery-v1. This task owns only the capability matrix and connection component proof; it does not implement content discovery use LAN or select operator policy. TASK-132 later composes its result with TASK-103 decentralized NAR discovery.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Validate iroh-node-publication-v1, iroh-node-lookup-v1 and iroh-relay-capability-v1 schema, tree/evidence hashes and verdicts before integration. All three must pass for public-node-discovery-v1 pass; any evidenced no_go/unsupported propagates no_go. Missing/stale/fabricated artifacts fail closed, while ordinary fixable integration defects remain failure.
- [ ] #2 Node publication, node lookup and relay remain separate typed default-off capabilities under a full enabled/disabled matrix. Lookup-only publishes nothing, publication-only performs no lookup, direct mode emits no relay traffic, and relay does not enable either discovery direction or content lookup; source/packet mutations make every independence assertion bite.
- [ ] #3 With empty run-unique locally operated discovery state, two daemons in routed non-LAN namespaces publish and resolve stable NodeIds and establish real direct and forced-relay Iroh connections with no peer address, claim, content locator, prior rendezvous state, LAN multicast or harness record insertion. Path/source attribution proves both controls.
- [ ] #4 Provider-daemon startup precedes all clocks and publication. Current signed node record is visible within 10000 ms; lookup completes within the next 10000 ms; cold startup to a resolved dialable candidate is capped at 20000 ms; relay connect is capped at 10000 ms. Monotonic configured/observed timings allow at most 1000 ms scheduler grace and starting after readiness invalidates the artifact.
- [ ] #5 Publication failure, lookup empty/outage/stale record, undiallable candidate, direct-path failure and relay failure are independent typed stages and timings. None becomes content MISS or another stage's success; disabling each selected component restores the expected alternate path or whole-node UNAVAILABLE.
- [ ] #6 Status/preflight distinguishes publication, lookup and relay enabled state, health, source, TTL/sequence, recipients/privacy exposure, direct/hole-punched/relay path and observed control bytes without full NodeId/IP labels by default. It selects no production profile or default.
- [ ] #7 Offline-test and later LAN-only configurations remain free of DNS/pkarr/relay traffic. Packet captures plus dependency/source guards reject implicit n0 presets/default services, hidden Mainline, wildcard published addresses and any TASK-130/TASK-116 dependency.
- [ ] #8 External n0/public services, accounts, credentials, spend, infrastructure or third-party coordination require a named owner and explicit authorization. Without it, only locally operated routed DNS/pkarr/relay services are used and the artifact is labelled production-shaped, not public-Internet/NAT evidence.
- [ ] #9 Emit public-node-discovery-v1 with final tree component matrix timing and mutation hashes plus failed constraints. TASK-132 validates it; any no-go blocks global qualification and cannot be mistaken for working peer discovery.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Atomic split 2026-08-11: TASK-137 owns node/address publication and crash-safe record state; TASK-138 owns NodeId lookup; TASK-139 owns relay transport; TASK-89 owns only their typed matrix and no-peer-address connection proof. TASK-101/103 own content discovery, TASK-132 the combined global Nix journey, TASK-133 the reviewed verdict and TASK-136 sole LAN admission/re-plan.

Forward-carried from TASK-138 review: Iroh 1.0.3 address_lookup::Item carries last_updated sequence but no TTL/expiry, and an Endpoint may retain resolved remote paths without another lookup. TASK-138 proves freshness only at its narrow resolver API. TASK-89 connection composition must explicitly enforce re-resolution and expiry/withdrawal invalidation (including any Iroh remote-path cache) before claiming stale-address rejection end to end; the current product fetch path still requires explicit --iroh-peer address injection until TASK-89 removes that dependency.

## forward-carried from TASK-139 (relay transport capability)

TASK-89 composes 137 (publish) + 138 (lookup) + 139 (relay) into the no-address connection proof. From landing the 139 relay cornerstone (daemon/src/iroh_relay.rs, commit 5f750cc):

- Use daemon::RelayTransportConfig to turn ON relay for the shared endpoint: it yields RelayCapability::Enabled(RelayMode::Custom(map)) built from ONE explicit local relay URL and never inherits presets::N0 / RelayMode::Default. Do NOT hand-build a RelayMode elsewhere — go through this so the "no implicit public default" invariant holds.
- Relay attribution gotcha (important for the no-address proof): iroh's remote_addr is on Connecting/Accepting, and an established Connection can upgrade relay->direct after holepunching. So "the peer was reached with NO direct address, via relay" is only unfalsifiable when the direct path is BLOCKED (routed namespaces / L3). Reuse daemon::classify_connection_path(&IncomingAddr) -> RelayConnectionPath; only Relayed.is_relay_attributed()==true. A direct-positive control must stay Direct and must NOT be credited to relay.
- Typed outcomes to expect/propagate: daemon::RelayTransportUnavailableKind {disabled, untrusted_configuration, external_relay_unsupported, wrong_relay_url, relay_outage, wrong_certificate, wrong_identity, half_open_stream, forced_direct_failure, deadline, no_relay_candidate, closed}. Deadline bound: RELAY_CONNECT_DEADLINE 10000ms + RELAY_SCHEDULER_GRACE 1000ms (11000ms admissible). NOTE: as of 139 the live connect path + most typed producers are NOT yet wired — TASK-142 (routed relay evidence harness) owns that; 89 depends on 142's real relayed connection, not just 139's config layer.
- External/public (n0) relay is out of scope: only a locally operated routed relay is enabled; evidence is labelled production-shaped. Do NOT reach n0 default relays in the 89 proof.
- The routed harness setup that 89 needs already exists as a template: scripts/iroh_node_lookup_evidence.py (two rootless-podman internal networks + a tiny L3 router; tcpdump in the resolver netns). TASK-142 adapts it to block the direct path and force relay.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
