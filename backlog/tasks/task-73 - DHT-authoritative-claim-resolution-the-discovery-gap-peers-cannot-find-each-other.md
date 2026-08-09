---
id: TASK-73
title: >-
  DHT-authoritative claim resolution (the discovery gap: peers cannot find each
  other)
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-09 22:09'
labels:
  - wave-2b
dependencies: []
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
## Forward-carried from TASK-61/TASK-72: what a resolved claim now promises

DHT resolution hands a fetcher a `Blake3Digest` + a holder `NodeId`. As of
task-72 that digest is servable if and only if the holder's availability index
has ANSWERED a hold-query for it in this process lifetime - `hold()` is what
records the `BLAKE3 -> entry` binding the supply path reads back.

TWO CONSEQUENCES FOR YOUR DESIGN, both real:

1. A CLAIM OUTLIVES THE BINDING THAT MAKES IT SERVABLE. Claims persist in the
   DHT; the reverse map is in-memory and empty after a restart. So a resolution
   can legitimately return a holder that will decline. The decline is NAMED and
   counted (`ServeDecline::Unknown`, `IROH-SERVE-COUNTERS declined_unknown`), not
   an opaque mid-stream failure - use it. The permanent fix is task-82 (persist
   the immutable digest binding, ~40 B/path); until then your resolution logic
   must treat 'holder declines' as an ordinary outcome and try the next offer.

2. A HOLDER CAN NOW ALSO DECLINE FOR CAPACITY, not only for absence. A serve
   larger than `--iroh-max-serve-nar-bytes` (default 256 MiB) or arriving when
   `--iroh-max-inflight-nar-bytes` (default 1 GiB) is exhausted is refused with
   `AbortReason::RateLimited` (busy) rather than `Permission`. Those are different
   findings: 'not from me, ever' vs 'try later'. If discovery caches negative
   results, do NOT cache a busy the way you cache an unknown, or a momentarily
   loaded peer disappears from the swarm for the cache TTL.

3. NO ENUMERATION, still. The supply path added a reverse index but exposes only
   per-digest probes (`supply_size`/`supply_raw_nar`, both private-by-shape:
   nothing returns the map, its keys or its length). Whatever wire endpoint you
   add for peer yes/no queries must keep that. It is an owner constraint from
   phase 1 and it is easy to regress while adding a lookup.
<!-- SECTION:NOTES:END -->
