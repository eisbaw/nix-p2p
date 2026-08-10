---
id: TASK-73
title: >-
  DHT-authoritative claim resolution (the discovery gap: peers cannot find each
  other)
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-10 08:44'
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
## CORRECTION-OF-THE-CORRECTION 2026-08-10 (dht-publication-study workflow, 20 agents)

The 'iroh already ships content-discovery crates, so this spike is mostly EVALUATION' note above is
WRONG ON THE FACTS. Verified against crates.io versions API and upstream git history:
  * iroh-mainline-content-discovery 0.6.0 was published 2025-04-04, NOT 2026-06-20, and it pins
    iroh 0.34 while we are on iroh 1.x (which renamed NodeId->EndpointId and discovery->
    address_lookup). Its mainline layer was DELIBERATELY DELETED upstream: commits 'Purge all but
    the iroh connection option' (2025-05-13) and 'Remove everything but iroh connections' (2025-06-02).
  * The successor iroh-content-discovery has NO DHT and NO default trackers - the CLI's --tracker is
    a required argument with no built-in value.
  * iroh-dht-experiment does NOT usably map BLAKE3 -> providers: its Blake3Provider record type has
    private fields, no constructor, and ZERO uses anywhere in the crate; only put_immutable/
    get_immutable are wired. Largest test is 500 nodes with hand-initialised routing tables. The
    promised implementation/testing blog posts were never written across the 11 months in which n0
    shipped iroh 1.0.
  * Lifetime downloads: 766 / 1,900 / 540. Nobody runs any of them.
  => 'Adopt iroh's content discovery' is NOT available. Forking the ~1,200-line tracker IS viable.

## AND COST IS NOT THE DECIDING VARIABLE - THE OWNER WAS RIGHT

Retire the 'publishing 100k entries is unaffordable' claim entirely. Measured/verified:
  * STORAGE is free: 108k keys x 8 replicas x ~52 B = ~45 MB across the whole DHT = ~45 BYTES per
    node at 10^6 nodes.
  * ROUTING STATE is sparse exactly as the owner said: ~8*log2(n) ~ 184 contacts, a few kB. No node
    holds a global view.
  * ADMISSION not binding: libtorrent dht_max_torrents = 2000/node; our contribution is 0.87 extra
    tracked infohashes per node.
  * The republish treadmill was overstated 20-30x. 'Hourly' is a BEP44 SHOULD, not reality:
    libtorrent dht_item_lifetime defaults to 0 = NEVER EXPIRE; pkarr measures 99.64% survival at
    2 days (k=20) with optimum republish 17.7-30 h; IPFS uses 22 h reprovide / 48 h TTL. Mainline
    BEP5 PEER records are the exception at 45 min (added + announce_interval*3/2, dht_storage.cpp).
  * DONE IN PRODUCTION AT OUR SCALE: Kubo's Provide Sweep reprovided 100,000 CIDs in a 3-hour window
    with a SINGLE worker on the live Amino DHT; a documented node runs 67,704,411 CIDs with 8
    workers at 15,668 CIDs/min/worker.
  * Trackers are trivially cheap: opentrackr ~10M torrents, ~200,000 conn/s, 4 TB/day on a
    ten-year-old Dell R410 that is idle half the time; aquatic 226,065 resp/s on ONE core.

## WHAT ACTUALLY DECIDES IT (none of these are cost)

  (i)   MAINLINE CANNOT CARRY AN iroh NodeId - mechanical, verified twice against the BEPs and
        libtorrent source. announce_peer stores the publisher's (source IP, port); implied_port only
        selects WHICH port, it is not a value field. BEP44 does not rescue it: immutable target =
        SHA1(value), mutable target = SHA1(pubkey[||salt]) - there is NO construction storing a
        chosen value under a CONTENT-derived key. The derived-keypair trick (seed=KDF(NarHash)) dies
        four ways, the worst being that the private key is public so one put with seq=0x7fffffff...
        permanently FREEZES the slot (~20 packets). Note constraint 1 does NOT cover that: it is
        denial, not poisoning.
  (ii)  THE BATCHING THAT MAKES 100k AFFORDABLE DOES NOT PORT TO MAINLINE. Provide Sweep works
        because Amino has ~10,000 servers so 100k CIDs land ~10 per region across ~3,000 regions.
        Mainline has 10^6-10^7 nodes => 125,000-1,250,000 regions => 0.87 to 0.087 keys per region.
        Amortisation needs #keys >> #nodes/k; we have #keys << #nodes/k by two orders of magnitude,
        so a full traversal costs MORE than independent lookups. Also libtorrent's generate_token
        hashes address+secret+info_hash (node.cpp), so a token from one key is invalid for another
        on the same node - a get is required per (key,node) pair regardless. libp2p's ADD_PROVIDER
        carries no token, which is precisely why the trick fires there and not here.
  (iii) PUBLISHING PER-PATH IS THE ENUMERATION THE OWNER FORBADE, and BEP51 sample_infohashes lets
        an indexer sweep the keyspace on a ~6 h cycle to recover the key set.

## THE KEY COUNT WAS WRONG BY 9-17x (measured from /nix/var/nix/db/db.sqlite, this machine, today)

  82,528 valid paths, of which 70,662 are .drv (85.6%) totalling only 253 MiB - cache.nixos.org does
  not serve .drv NARs, they are local evaluation artifacts, and publishing them is useless AND a
  privacy leak. 11,866 non-.drv output paths hold 94,908 MiB. Only 6,307 carry a cache.nixos.org
  signature, so THE PUBLISHABLE SET UNDER THE NO-ENUMERATION RULE IS 6,307 PATHS, NOT 108,401.
  (Lower bound of unknown looseness: nix records a sig only on paths it SUBSTITUTED, so a locally
  rebuilt copy of a public path has none; the daemon can widen this using narinfos it already proxies.)
  Signed paths hold 48,398 of 94,908 MiB = 51% of bytes => NEARLY HALF THE SERVABLE BYTES CAN NEVER
  BE PUBLISHED and stay reachable only by direct hold-query, which makes TASK-91 load-bearing in a
  way this backlog did not say out loud.
  Concentration: 691 paths (5.8%) hold 91.7% of NAR bytes; 1,243 (10.5%) hold 95.5%; 151 hold 74%.
  Median 96 KiB, p90 4.3 MiB, p99 139 MiB.
  At 691 or 6,307 keys EVERY substrate is affordable and cost stops being the question.

ALSO: the '1.44 MiB median downloads in ~70 ms' framing conflated MEAN with MEDIAN. 1.44 MiB is the
mean; the measured median is 96 KiB => ~5 ms. So the gap between a 647 ms DHT lookup and the thing it
saves is ~130x at the median, not 9x.

Gate: TASK-96 (mainline participation decision) must complete BEFORE this task freezes any key
derivation. TASK-94 (peer-wins inequality) may kill the premise entirely.
<!-- SECTION:NOTES:END -->
