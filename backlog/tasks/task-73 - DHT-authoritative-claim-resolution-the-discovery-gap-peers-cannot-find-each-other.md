---
id: TASK-73
title: >-
  DHT-authoritative claim resolution (the discovery gap: peers cannot find each
  other)
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-10 10:04'
labels:
  - wave-2b
dependencies:
  - TASK-89
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
THE largest gap between what exists and the PRD. Verified 2026-08-09: there is ZERO discovery code - no non-comment occurrence of dht/gossip anywhere in daemon/src. Nodes connect only because the harness passes --iroh-peer <node_id>@<sockets> and --p2p-claim <narhash>=<blake3>@<node_id> on the command line. daemon/src/discovery.rs has InMemoryDiscovery (a HashMap the harness populates) and DirectDiscovery (probes a KNOWN peer list). So the project currently decentralizes TRANSFER, not DISCOVERY, and 'decentralized cache' overstates what ships.

PRD scope names: 'DHT-authoritative claim resolution PLUS bounded fan-out yes/no queries to known peers - this is how un-announced whole-store supply becomes reachable'. Both halves matter: the DHT answers 'who has NarHash X' for announced content; the bounded yes/no fan-out reaches content nobody announced (which, given announce-on-demand, is most of it).

FROZEN SURFACE WARNING: the PRD's irreversibility map lists DHT KEY DERIVATION (NarHash -> DHT key mapping, and WHICH DHT) as a wave-2 frozen surface - changing it splits the network. So this needs the DEEP gate, and the spike (mainline vs BEP44 vs iroh-native) must come before the freeze, not after. TASK-47's re-plan currently bundles that spike; this task is the implementation the spike feeds.

Privacy constraint (owner, round 4, non-negotiable): peers answer YES/NO to a query and must never allow enumeration of what they hold - a listing is a secret leak. The existing HoldQuery envelope in discovery.rs already has this shape; do not regress it.

Honest scale caveat: TESTING.md S5 explicitly excludes emergent network effects (DHT k-bucket dynamics, gossip fan-out) from what small-N sweeps can predict. Whatever is measured on 1..30 local nodes says nothing about mainline DHT behaviour at scale.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A spike compares mainline DHT vs BEP44 vs iroh-native discovery on: does it answer who-has-NarHash-X, bootstrap cost, privacy leakage of the query itself, and dependence on third-party infrastructure - with a recommendation and the reasoning recorded
- [ ] #2 The NarHash -> DHT key derivation is specified and frozen with golden vectors, deep-gated (it is an irreversible surface: a change splits the network)
- [ ] #3 A real resolve works with NO peer addresses passed on the command line: node A finds node B's claim for a NarHash it has never been told about, and the resulting nix build is served from that peer
- [ ] #4 The bounded yes/no fan-out to known peers reaches UNANNOUNCED content (the whole-store supply case), with the fan-out bounded and the no-enumeration property preserved and tested
- [ ] #5 Honest limit stated: what the local testbed can and cannot say about real DHT behaviour at swarm scale
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
OWNER DIRECTIVE 2026-08-10: global/DHT decentralization is HIGH priority; LAN and tiered discovery are LOW priority (TASK-89 demoted). Privacy resolved by decision: a node publishes ONLY NARs already public at cache.nixos.org, which acts as the filter - filed as TASK-102 and enforced in code, not convention. Substrate choice and build are TASK-103 (own Kademlia over iroh vs mainline + identify responder). This task stays the umbrella; TASK-103 carries the work.
<!-- SECTION:NOTES:END -->
