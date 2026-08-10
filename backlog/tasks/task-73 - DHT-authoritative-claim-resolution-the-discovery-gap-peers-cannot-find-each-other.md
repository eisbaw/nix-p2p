---
id: TASK-73
title: >-
  DHT-authoritative claim resolution (the discovery gap: peers cannot find each
  other)
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-10 07:25'
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
## Why a DHT is the FALLBACK layer, not the primary path (owner question 2026-08-10)

A DHT is the textbook answer to 'who has hash X' and it stays in scope - but the arithmetic says it
cannot carry the COMMON case, for two independent reasons. Record these before the spike so it is
not re-litigated.

(1) A DHT MAKES LOOKUP CHEAP BY MAKING PUBLICATION EXPENSIVE, and publication is our expensive side.
    To be findable you must ANNOUNCE. Our node holds 108,401 paths. Verified against the specs:
      * BEP44 values are capped at 1000 BYTES and entries expire in ~1-2h, requiring periodic
        re-put. 108k paths republished hourly is ~30 puts/second sustained, forever, per node - and
        each put needs an iterative closest-node lookup (~8 round trips), so ~240 RTT/s of DHT
        traffic per idle node. That is not a tuning problem.
      * announce_peer/get_peers has the RIGHT multi-writer set semantics (many holders per infohash)
        but its value type is fixed to IP+port and cannot carry an iroh NodeId - so NAT'd nodes
        cannot be providers (n0's own finding). BEP44 has arbitrary values but the WRONG write
        semantics: immutable items are keyed by hash-of-value, mutable items by publisher pubkey.
        Neither gives 'many independent writers append to one content-derived key'.
      => mainline has exactly one multi-writer set primitive and its value type is unusable for us.
         This is a specific impasse, not a preference. The spike must confirm or refute it FIRST.
      * And announcing 108k paths publishes our entire holdings list to a global network - the
        privacy tension already recorded above, at its worst.
    Contrast: the probe path (TASK-91) costs work proportional to what is actually REQUESTED and
    zero for everything else. Announce-on-demand exists precisely because publication does not scale.

(2) DHT LOOKUP IS SLOWER THAN JUST FETCHING THE THING. TESTING.md's S8 row already flags '1-4s DHT
    latency leaks into every build'. The MEDIAN NAR on the owner's store is 1.44 MiB; cache.nixos.org
    sustained ~21 MB/s in task-63's probe, so the median NAR downloads in ~70 ms. A 1-4 s DHT lookup
    is 15-60x the cost of not bothering. For the median path a DHT lookup is strictly worse than
    going to the CDN, and a 200-path closure makes it catastrophic unless fully parallel/prefetched.

WHERE A DHT IS STILL RIGHT, and why this task keeps it: the COLD, GLOBAL, RARE case - a node with no
peer set, or content no known peer has. That is exactly the long tail the PRD already concedes is
where a CDN is strong and swarms are weak. So the DHT earns its place as the fallback that makes
bootstrapping possible, not as the thing every build waits on.

RESULTING LAYERING (cheapest first; each layer only handles what the one above missed):
  0. node discovery: iroh's own, incl. mDNS on LAN (TASK-89)
  1. peer set: gossip / config / LAN (TASK-74)
  2. local answer, zero round trips: set digest over PUBLIC paths (TASK-92)
  3. one round trip per closure per peer: batched hold-query (TASK-91)
  4. peer ordering prior: closure/revision correlation (TASK-93)
  5. cold/global fallback: THIS TASK - tracker and/or DHT, latency-tolerant because it is off the
     hot path
The spike should size how often layers 0-4 miss, because that miss rate is what layer 5 must serve -
and if it is small, a tracker may beat a DHT on every axis that matters here.
<!-- SECTION:NOTES:END -->
