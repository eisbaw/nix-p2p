---
id: TASK-103
title: >-
  Global content DHT: choose the substrate (own Kademlia over iroh vs mainline +
  identify), then build it
status: To Do
assignee: []
created_date: '2026-08-10 10:04'
updated_date: '2026-08-10 10:04'
labels:
  - wave-2b
dependencies:
  - TASK-102
  - TASK-96
  - TASK-100
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OWNER DIRECTIVE 2026-08-10: global decentralized discovery is HIGH priority; LAN and tiered discovery are low priority and can come later. This is the core crux task.

THE BLOCKER, and it is mechanical. mainline announce_peer publishes the announcer's (source IP, port) and NOTHING ELSE - implied_port only selects WHICH port, it is not a value field. There is no room for a 32-byte iroh NodeId. BEP44 does not rescue it: immutable target = SHA1(value), mutable target = SHA1(pubkey[||salt]), so there is NO construction storing a chosen value under a CONTENT-derived key. The derived-keypair trick (seed=KDF(NarHash)) yields a content-keyed anyone-writable slot and dies four ways, the worst being that the private key is public so ONE put with seq=0x7fffffffffffffff permanently FREEZES the slot for ~20 packets. Note that is DENIAL, which our trust model does NOT cover - it covers wrong bytes, not unavailability.

TWO PATHS. Decide, with evidence, before building.

PATH 1 - MAINLINE + IDENTIFY RESPONDER. The announced port is freely chosen, so run a 1-RTT responder on it that returns {NodeId, RelayUrl}; the DHT record then carries a NodeId indirectly. Uses get_peers/announce_peer natively, and get_peers IS already a multi-writer set per key - exactly the 'who has X' shape. Free network, no bootstrap problem.
  COSTS: only publicly-reachable peers are findable this way (NAT'd peers remain consumers, reachable later via gossip/PEX); 20-byte SHA1 keyspace so BLAKE3 must be truncated or re-hashed (collisions cost only a wasted dial, acceptable); BEP51 sample_infohashes lets an indexer sweep and recover our key set on a ~6h cycle; peer records expire in ~45 min (libtorrent: added + announce_interval*3/2) forcing a fast republish treadmill; and our announces are INDISTINGUISHABLE FROM TORRENT ANNOUNCES to the commercial monitors that continuously crawl mainline and log IPs - an operational hazard for our users that has nothing to do with our correctness.

PATH 2 - OUR OWN KADEMLIA OVER IROH (RECOMMENDED). Records natively hold NodeIds; full 32-byte keyspace so BLAKE3 is the key with no truncation; we set the TTL (hours, not 45 minutes, cutting republish traffic 10-30x); no BEP51 exposure; no BitTorrent-monitor collateral. iroh already provides authenticated identity, NAT traversal, relays and QUIC streams, so a DHT on top is markedly simpler than a UDP one - transport, auth and NAT are already solved. n0-computer/iroh-dht-experiment demonstrates the shape (Kademlia, 32-byte keyspace, XOR metric) but is immature: its Blake3Provider type has private fields, no constructor and zero uses, only put_immutable/get_immutable are wired, largest test is 500 nodes with hand-initialised routing tables. Read it as a reference; do not depend on it.
  COSTS: COLD START is the real problem - an empty DHT has no nodes, so bootstrap matters more than the DHT itself. Plan it explicitly (seed nodes, iroh DNS/pkarr discovery, or mainline used ONLY for node-address bootstrap). A small DHT is also easy to Sybil/eclipse - which our trust model tolerates for CORRECTNESS (a wrong answer costs a dial, nix re-verifies) but NOT for availability; state what an eclipse costs.

PUBLICATION VOLUME IS AFFORDABLE - the earlier 'unaffordable' claim is retired. With TASK-102's public-only filter the set is ~6,769 paths. Storage is free (~45 bytes per node at 10^6 nodes for 100k keys); Kademlia routing state is ~8*log2(n) ~ 184 contacts; and Kubo has reprovided 100,000 CIDs in a 3-hour window with a SINGLE worker on the live Amino DHT. Estimate ~100 queries/s and ~20 KB/s sustained at 6,769 keys with per-key lookups, dropping 10-30x on path 2 where we control the TTL. VERIFY these rather than inheriting them.

WORTH TAKING EITHER WAY: BitTorrent publishes per TORRENT, not per FILE. The Nix analogue of a torrent is a CLOSURE, not a path. Publishing closure-level keys alongside the hot per-NAR ones gives comparable reachability for a fraction of the keys, and a peer found via a closure key almost certainly holds the other ~199 paths the build needs. See TASK-97.

Everything published here MUST pass TASK-102's filter. Build behind TASK-100's seam as one mechanism, never as a special case.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The substrate decision is made and written down with evidence for BOTH paths: bootstrap cost, NodeId handling, keyspace, TTL/republish traffic, eclipse exposure, and the third-party-monitoring hazard. A decision that does not answer the mainline-crawler question is not accepted
- [ ] #2 Two daemons with NO peer addresses and NO tracker configured complete a real peer-served nix build: one publishes, the other resolves via the DHT and fetches, with peer bytes counted at the provider
- [ ] #3 The NodeId gap is closed and tested end to end: whichever path is chosen, a DHT record resolves to a dialable iroh endpoint, and the extra hop (if any) is MEASURED, not assumed
- [ ] #4 Publication respects TASK-102 by construction: a locally built unsigned path is never published, proven by mutation
- [ ] #5 Cold start and republish are MEASURED not modelled: time from a cold daemon to first successful resolve, and the sustained query rate and bandwidth to keep the publishable set alive
- [ ] #6 Honest limits: what an eclipse or Sybil majority costs us (availability, NOT integrity - say so precisely), and what fraction of peers are unreachable under the chosen path
<!-- AC:END -->
