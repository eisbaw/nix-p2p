---
id: TASK-73
title: >-
  DHT-authoritative claim resolution (the discovery gap: peers cannot find each
  other)
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-10 07:09'
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
## Research 2026-08-10 (iroh docs + n0 experiments) - READ BEFORE THE SPIKE

THE LOAD-BEARING DISTINCTION: iroh's 'discovery' is NODE discovery (EndpointId -> relay URL +
direct socket addrs). It is NOT content discovery. Confirmed in docs.iroh.computer/concepts/discovery:
none of its mechanisms map a blob hash to holders. So this task is really TWO problems and they
have different answers.

(1) NODE DISCOVERY - essentially free, we just have it switched off.
    iroh ships three, and daemon/src/transport_iroh.rs bind_loopback_endpoint currently binds with
    'the relay DISABLED and NO discovery':
      * DNS/pkarr - DEFAULT ON upstream; publishes signed records to an iroh-dns-server, resolved
        over DNS. Infra is RUN BY n0 (a third-party dependency to declare, not decentralized).
      * Local/mDNS-like address lookup - default OFF, no infra, LAN only. Cheap win for the
        office/CI/home-lab case, which is also the case where the peer path actually beats a CDN.
      * DHT address lookup - default OFF, publishes the SAME signed pkarr records to the BitTorrent
        Mainline DHT. Crate iroh-mainline-address-lookup (0.4+), wired via Endpoint::builder.
        Fully distributed; documented tradeoff is 'slower lookups than DNS'.

(2) CONTENT DISCOVERY - the actual open problem. n0 explored it in iroh-experiments/content-discovery
    (repo self-describes as 'very low level and unpolished'; 'most will not' graduate - do NOT depend
    on it, but DO mine its design). Their findings, which pre-empt our spike:
      * MAINLINE DHT CANNOT HOLD OUR RECORD, and this is the killer: the classic get_peers path
        stores only IPv4/IPv6 + port, NOT an iroh NodeId - so a NAT'd node cannot be a provider.
        Also 20-byte SHA1 keys vs our 32-byte BLAKE3; their workaround is 'just SHA1 hash the BLAKE3
        hash, or take the first 20 bytes'. This is the single most important input to our FROZEN
        'NarHash -> DHT key derivation' decision, and it argues that plain mainline get_peers is the
        WRONG substrate for holder records. BEP44 mutable/immutable items are the alternative to
        evaluate (they carry arbitrary signed payloads) - the spike must compare get_peers vs BEP44
        explicitly, not treat 'mainline' as one option.
      * TRACKER: a small server holding 'a set of signed node ids for each piece of content'; announce
        by hash or ticket, query by hash / ticket / hash+format. n0's recommended hybrid is to use the
        mainline DHT to FIND TRACKERS rather than to store content locations.
      * A tracker is far less dangerous for US than for most projects: our daemon and peers sit OUTSIDE
        the trust base and nix re-verifies sig+NarHash, so a tracker is a HINT PROVIDER, not an
        authority. A lying tracker costs a wasted dial, never a bad store path. Weigh it accordingly
        instead of rejecting it reflexively for being a server.
      * ANTI-SPAM BY PROBE (steal this - see TASK-90): before trusting an announce, their tracker
        downloads a RANDOM 2 KiB blake3 chunk from the announcer and verifies it; for partial content
        it asks only for unverified size; for hash sequences it probes a random chunk of a random
        child. bao lets us verify any chunk against the root, so this is cheap and directly applicable.
      * GOSSIP: iroh-gossip is epidemic broadcast trees (HyParView + PlumTree) over topics - what
        Delta Chat uses. Ecosystem prior art worth reading: distributed-topic-tracker ('auto discovery,
        no servers') and iroh-gossip-discovery. Feeds TASK-74.

(3) PRIVACY TENSION WE HAVE NOT RECORDED ANYWHERE. Our no-enumeration rule (owner, phase 1) stops a
    peer LISTING what we hold. But ANNOUNCING to a public tracker or a global DHT publishes exactly
    that, at internet scale and durably. Announce-on-demand + bounded yes/no probing is privacy-
    preserving; DHT/tracker announce is not. The spike must state, per option, what it leaks. This
    also bears on TASK-77 (announce-after-fetch) and TASK-78 (leech mode).

Sources: docs.iroh.computer/concepts/discovery, docs.iroh.computer/connecting/dht-discovery,
iroh.computer/blog/iroh-content-discovery, github.com/n0-computer/iroh-experiments.
<!-- SECTION:NOTES:END -->
