---
id: TASK-73
title: >-
  DHT-authoritative claim resolution (the discovery gap: peers cannot find each
  other)
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-10 07:27'
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
## CORRECTION 2026-08-10 (owner pushback: 'iroh provides libs for content discovery' / 'why cant we afford DHT publication')

Two things I got wrong above. Both correct the record; do NOT design from scratch.

CORRECTION 1 - IROH DOES SHIP CONTENT-DISCOVERY CRATES. The claim 'none of iroh's mechanisms do
content discovery' is true only of CORE iroh's discovery module (node addresses). Adjacent crates
exist and one is current:
  * iroh-mainline-content-discovery 0.6.0, released 2026-06-20, actively developed. TWO-TIER:
    query_dht() 'queries the mainline DHT for trackers for the given content, then queries each
    tracker for peers'. Provider sets live in TRACKERS; the DHT stores tracker locations. Its
    TrackerId is 'either a node id or an address', which is how it bridges mainline's IP:port to
    iroh NodeIds - i.e. they did NOT solve NodeId-in-mainline, they routed around it.
  * iroh-content-discovery - protocol + client + tracker + CLI (iroh-experiments).
  * iroh-dht-experiment - a KADEMLIA DHT over iroh connections, 32-byte keyspace, maps BLAKE3
    hashes -> providers, responses carry NodeAddr. This solves the NodeId problem NATIVELY because
    the DHT nodes are iroh nodes. Explicitly NOT production ready.
  => The spike is now mostly EVALUATION, not design: try iroh-mainline-content-discovery first
     (real, current, maintained), and read iroh-dht-experiment for the native-keyspace design.
     Only build something ourselves if both are shown unsuitable, and say why.

CORRECTION 2 - 'CANNOT AFFORD PUBLICATION' WAS OVERSTATED, and the note above should be read with
this. The 30 puts/sec figure assumed the WORST granularity: all 108,401 paths, per-path, hourly.
That case is infeasible. Other granularities are not:
    every store path              108,401 keys   ~30 puts/sec   infeasible
    recently fetched/served only   ~2-10k keys   ~0.5-3/sec     fine
    one key per (rev, system)      ~1 key        trivial
  A BitTorrent seeder announcing a few thousand infohashes does exactly this routinely. So the
  honest statement is: PER-PATH PUBLICATION OF A WHOLE STORE is infeasible; publication at the
  right GRANULARITY is cheap. This makes TASK-93 (closure/revision correlation) load-bearing for a
  new reason - it is the granularity fix that makes DHT publication affordable, not merely a
  peer-ordering prior.

WHAT SURVIVES, and it is narrower than the note above implies. Neither point argues against a DHT;
both argue about WHEN it is consulted and WHAT is published:
  * LOOKUP LATENCY ON THE HOT PATH. 1-4 s lookup vs ~70 ms to fetch the median 1.44 MiB NAR from a
    ~21 MB/s cache. So resolve OFF the critical path - inside the ~300 ms narinfo->NAR window
    (task-35), or only after a local probe/digest missed - never in front of every substitution.
  * PUBLISHING REVEALS HOLDINGS (the privacy tension recorded above), which is a granularity and
    opt-out question (TASK-78), not a blocker.
<!-- SECTION:NOTES:END -->
