---
id: TASK-258
title: >-
  SPIKE: BitTorrent Mainline as a peer-rendezvous bootstrap behind
  --libp2p-mainline-rendezvous
status: To Do
assignee: []
created_date: '2026-08-18 20:54'
updated_date: '2026-08-18 20:59'
labels:
  - libp2p
  - mainline
  - bittorrent
  - bootstrap
  - rendezvous
  - privacy
  - spike
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OWNER DIRECTION 2026-08-18, SECOND PRIORITY after mDNS (TASK-257). A SPIKE: the deliverable is a decision backed by a working prototype and measured privacy cost, not a shipped default.

THE IDEA: use the BitTorrent Mainline DHT as a RENDEZVOUS layer to find other nix-p2p NODES, then run our own /nix-p2p/<scope>/kad among them. Publish under ONE well-known infohash meaning "I speak nix-p2p", get_peers it to learn addresses, hand those into the existing bootstrap path. Content routing stays entirely on our own kad.

WHY THIS AND NOT THE IPFS DHT: joining the IPFS Amino DHT would mean writing provider records for Nix NARs into someone elses shared keyspace, which is exactly the PRD "what bad looks like" bullet (DHT announce traffic abusive to the shared DHT); Amino provider records also expire ~24h and need republishing, lookup latency is seconds (PRD risk 3 on the user path), and our content keys would become visible to every IPFS DHT crawler. Mainline-as-RENDEZVOUS avoids all four: one infohash, negligible traffic, semantically correct use of get_peers (it is FOR finding peers), and NO content keys leave our own DHT.

WHY IT MATTERS: it is the only one of the three bootstrap options that needs NO infrastructure we own or fund. router.bittorrent.com and dht.transmissionbt.com have been up for 15+ years and exist to be contacted by strangers. DNSADDR (TASK-259) still depends on our domain and our routers; this does not.

THE PRIVACY COST IS THE CENTRAL QUESTION, NOT A FOOTNOTE. BEP5 announce_peer lists our IP as a peer for that infohash, so anyone running get_peers on it can ENUMERATE the nix-p2p node population. That is enumeration of NODE MEMBERSHIP, not of content holdings, so it does not violate the frozen no-enumeration invariant (which is about holdings) -- but it must be stated in exactly those terms and never blurred. TASK-96 already analysed the adjacent Mainline hazards and its findings are inputs here: BEP51 sample_infohashes sweeps, adaptive server promotion, and passive lookup leakage. Consult TASK-96 rather than re-deriving.

SCOPE:
  * Evaluate Rust Mainline DHT crates (libp2p has NO Mainline implementation -- this is a separate dependency and that choice is part of the spike). Assess maintenance, BEP5 coverage, and whether it can run strictly as a CLIENT without adaptive promotion to a serving DHT node.
  * New CLI flag --libp2p-mainline-rendezvous, DEFAULT OFF, mirrored as a NixOS module option.
  * Rendezvous supplies peer ADDRESSES into the existing bootstrap/NodeLocator path. It is NOT content discovery and must never be reported as satisfying the decentralized content-discovery production gate.
  * Deliverable: a working two-host prototype plus a written recommendation -- adopt, adopt-with-conditions, or reject -- with the measured privacy cost.

OPERATOR-CONTRACT MAPPING (TASK-120):
  * Axis 2 (node/address discovery) plus axis 6 (lookup leakage). Enabling it never implies serving or publication.
  * HARD CONSTRAINT from the Wave-2c privacy contract: lan_share emits ZERO packets to public tracker, DNS, relay, DHT or Mainline infrastructure. So this must be REFUSED under lan_share and under upstream_only, and fail closed at startup rather than silently no-op.
  * Under consume_only it is public-network participation and must be surfaced as such by preflight -- the PRD is explicit that public lookup is not smuggled into consume-only.

TESTING IS REQUIRED (owner: "we need to test both"). Oracles must BITE by mutation:
  * Two hosts, neither given the others address, find each other via Mainline rendezvous and complete a real fetch over our own kad.
  * BITE: disable rendezvous on one and discovery must fail -- proving no address arrived by another path (the same no-injection discipline TASK-103/155 already enforce).
  * Profile refusal is proven: upstream_only and lan_share emit ZERO Mainline packets, verified at packet level, guard bites under mutation.
  * Measure and record the enumeration exposure: from a third host, run get_peers on the rendezvous infohash and report how much of the node population is recoverable and how fast. A vacuous run that is handed the peer list fails.
  * Bound the announce/lookup traffic and prove the bound holds.

OUTCOME: reject is a fully valid and useful result. If the enumeration exposure is judged too high, say so and fall back to TASK-259 DNSADDR plus operator-run routers.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A Rust Mainline client crate is selected with a written rationale, and can run strictly as a client with no adaptive promotion to a serving DHT node
- [ ] #2 New default-OFF --libp2p-mainline-rendezvous flag plus the mirrored NixOS module option; it feeds peer addresses into the existing bootstrap path only
- [ ] #3 Two hosts, neither given the others address, discover each other via Mainline rendezvous and complete a real byte-identical fetch over our own kad
- [ ] #4 BITE: disabling rendezvous on one host makes discovery fail, proving no address arrived by another path
- [ ] #5 It is REFUSED fail-closed under upstream_only and lan_share, with packet-level proof of zero Mainline traffic and a guard that bites under mutation
- [ ] #6 Under consume_only, preflight explicitly reports it as public-network participation and records the lookup exposure
- [ ] #7 The node-membership enumeration exposure is MEASURED: a third host runs get_peers on the rendezvous infohash and reports recoverable fraction and wall time; a run handed the peer list fails as vacuous
- [ ] #8 Announce and lookup traffic are bounded and the bound is proven, not asserted
- [ ] #9 A bounded, expiring peer cache persists discovered nix-p2p peers (in the existing --libp2p-state-dir) and is tried BEFORE Mainline on subsequent starts; Mainline is contacted only when the cached peers are all unreachable
- [ ] #10 BITE: a second start with a warm cache emits ZERO Mainline packets, verified at packet level, and the guard bites under mutation. A corrupt or absent cache degrades to a normal Mainline lookup, never to a crash and never to dialing unvalidated addresses
- [ ] #11 TEST-VACUITY GUARD: cold-discovery oracles must run with the peer cache empty or disabled, and assert it. A persisted cache would otherwise hand a test the address it was supposed to discover, silently making every no-injection bite in this task vacuous
- [ ] #12 Deliverable is a written adopt / adopt-with-conditions / reject recommendation. Reject is a valid terminal outcome, and its honest consequence is NO PUBLIC POOL (private/enterprise pools only) -- not a fallback to operator-run routers, which the owner has ruled out
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
OWNER CONSTRAINT 2026-08-18, added same day: "i wont run public server infra, so i wont provide public bootstrap nodes -- hence the need for bittorrent, but for enterprise i may run internal nodes."

THIS CHANGES THIS TASKS STANDING. Mainline rendezvous is not one of three interchangeable bootstrap options -- for the GLOBAL PUBLIC POOL it is the ONLY viable path, because every alternative (DNSADDR names, hardcoded seeds, operator-run router nodes) requires public infrastructure the owner has ruled out. DNSADDR (TASK-259) is now scoped to ENTERPRISE/INTERNAL deployments only.

CORRECTION to the description and to AC#9: the stated fallback "reject falls back to DNSADDR plus operator routers" is WRONG under this constraint. There are no operator routers for the public case. The honest fallback on a reject verdict is: NO PUBLIC POOL -- the product ships as private/enterprise pools only (LAN via mDNS TASK-257, internal bootstrap via TASK-259), and the global permissionless swarm stays an unrealized aim rather than a deliverable.

That raises the stakes of this spike: it is now the gate on whether a public nix-p2p network can exist at all without someone funding infrastructure. Judge the privacy cost against THAT, not against a comfortable alternative -- and if the enumeration exposure really is too high, say so plainly and let the public pool be the thing that does not ship.
<!-- SECTION:NOTES:END -->
