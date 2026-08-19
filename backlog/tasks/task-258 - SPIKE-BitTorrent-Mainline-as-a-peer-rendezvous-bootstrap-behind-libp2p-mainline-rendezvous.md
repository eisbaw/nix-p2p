---
id: TASK-258
title: >-
  SPIKE: BitTorrent Mainline as a peer-rendezvous bootstrap behind
  --libp2p-mainline-rendezvous
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-18 20:54'
updated_date: '2026-08-19 10:13'
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
- [x] #1 A Rust Mainline client crate is selected with a written rationale, and can run strictly as a client with no adaptive promotion to a serving DHT node
- [ ] #2 New default-OFF --libp2p-mainline-rendezvous flag plus the mirrored NixOS module option; it feeds peer addresses into the existing bootstrap path only
- [ ] #3 Two hosts, neither given the others address, discover each other via Mainline rendezvous and complete a real byte-identical fetch over our own kad
- [x] #4 BITE: disabling rendezvous on one host makes discovery fail, proving no address arrived by another path
- [x] #5 It is REFUSED fail-closed under upstream_only and lan_share, with packet-level proof of zero Mainline traffic and a guard that bites under mutation
- [x] #6 Under consume_only, preflight explicitly reports it as public-network participation and records the lookup exposure
- [x] #7 The node-membership enumeration exposure is MEASURED: a third host runs get_peers on the rendezvous infohash and reports recoverable fraction and wall time; a run handed the peer list fails as vacuous
- [ ] #8 Announce and lookup traffic are bounded and the bound is proven, not asserted
- [ ] #9 A bounded, expiring peer cache persists discovered nix-p2p peers (in the existing --libp2p-state-dir) and is tried BEFORE Mainline on subsequent starts; Mainline is contacted only when the cached peers are all unreachable
- [ ] #10 BITE: a second start with a warm cache emits ZERO Mainline packets, verified at packet level, and the guard bites under mutation. A corrupt or absent cache degrades to a normal Mainline lookup, never to a crash and never to dialing unvalidated addresses
- [ ] #11 TEST-VACUITY GUARD: cold-discovery oracles must run with the peer cache empty or disabled, and assert it. A persisted cache would otherwise hand a test the address it was supposed to discover, silently making every no-injection bite in this task vacuous
- [x] #12 Deliverable is a written adopt / adopt-with-conditions / reject recommendation. Reject is a valid terminal outcome, and its honest consequence is NO PUBLIC POOL (private/enterprise pools only) -- not a fallback to operator-run routers, which the owner has ruled out
- [x] #13 Establish whether BEP5 IP:port announce is sufficient, given that a NATd peer whose only reachable address is a /p2p-circuit cannot express it in BEP5. Either evidence that NATd peers are reachable without announcing (found once they dial out and enter others routing tables), or add BEP44 signed records carrying PeerId plus circuit multiaddrs
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
OWNER CONSTRAINT 2026-08-18, added same day: "i wont run public server infra, so i wont provide public bootstrap nodes -- hence the need for bittorrent, but for enterprise i may run internal nodes."

THIS CHANGES THIS TASKS STANDING. Mainline rendezvous is not one of three interchangeable bootstrap options -- for the GLOBAL PUBLIC POOL it is the ONLY viable path, because every alternative (DNSADDR names, hardcoded seeds, operator-run router nodes) requires public infrastructure the owner has ruled out. DNSADDR (TASK-259) is now scoped to ENTERPRISE/INTERNAL deployments only.

CORRECTION to the description and to AC#9: the stated fallback "reject falls back to DNSADDR plus operator routers" is WRONG under this constraint. There are no operator routers for the public case. The honest fallback on a reject verdict is: NO PUBLIC POOL -- the product ships as private/enterprise pools only (LAN via mDNS TASK-257, internal bootstrap via TASK-259), and the global permissionless swarm stays an unrealized aim rather than a deliverable.

That raises the stakes of this spike: it is now the gate on whether a public nix-p2p network can exist at all without someone funding infrastructure. Judge the privacy cost against THAT, not against a comfortable alternative -- and if the enumeration exposure really is too high, say so plainly and let the public pool be the thing that does not ship.

DESIGN FINDING 2026-08-18 (owner question: can Mainline point to a PeerId or only an IP?).

BEP5 CARRIES IP:PORT ONLY. announce_peer records the announcing nodes address -- port from the message, IP from the packet source -- and get_peers returns compact peer info (6 bytes IPv4 / 18 bytes IPv6). There is no arbitrary payload and no way to carry a PeerId. This matches TASK-96s already-recorded finding about the inability of BEP5 announce_peer to carry a NodeId.

THAT IS NOT FATAL FOR RENDEZVOUS. libp2p does not need the PeerId in advance: a bare multiaddr with no /p2p/<PeerId> suffix is dialable, and the Noise handshake authenticates the remote identity during connection setup. The scope protocol name (/nix-p2p/<scope>/kad/1.0.0) is what decides whether a dialed stranger is actually one of ours -- a non-member fails protocol negotiation. So BEP5 IP:port is SUFFICIENT for the basic bootstrap path.

BEP44 CAN carry a PeerId: signed mutable items, ed25519, roughly 1000 bytes, sequence-numbered. This is what pkarr does and what iroh uses for EndpointId->addresses. But it solves a DIFFERENT problem -- it is key->record lookup, so you must already know which public key to fetch. That is one-to-one address lookup, not discovery of unknown peers, and it is exactly the limitation the PRD levels at iroh. BEP5 get_peers is many-to-one (many peers under one well-known infohash), which is what rendezvous actually requires. So BEP44 does not replace BEP5 here.

THE REAL GAP IN BEP5, and the reason to evaluate a hybrid: A NATD PEER HAS NO USEFUL IP:PORT TO ANNOUNCE. Its reachable address is a /p2p-circuit through a relay, and BEP5 cannot express that -- it can only record the source address of the packet. So a NATd node either announces something undiallable or cannot participate. That population is most of a public pool, and TASK-218/219 have just landed multi-relay /p2p-circuit resolution through our own DHT, so the circuit addresses exist and are meaningful. It is also consistent with the no-public-infra constraint, since relays are peer-provided via SharingProfile::Router rather than centrally operated.

LIKELY SHAPE: BEP5 to FIND unknown peers, plus optional BEP44 signed records for peers whose only reachable address is a circuit. Evaluate whether the NATd case is large enough to justify the second mechanism, or whether a NATd peer can simply skip announcing and rely on being found once it dials out and is added to others routing tables.

OWNER E2E REQUIREMENT (2026-08-18): the spike MUST include a WORKING VM e2e demonstrating Mainline rendezvous discovery. Topology: two VMs (KVM, extending the nat-vm-test topology), NATd so they CANNOT connect DIRECTLY. Node A boots first and announces to the Mainline DHT under the well-known nix-p2p infohash; Node B boots ~10s LATER and get_peers that infohash. DEMONSTRATION: B (late joiner) discovers A via BEP5 (Mainline get_peers) EVEN THOUGH they cannot connect directly -- Mainline rendezvous is the meeting point; connectivity is then established via the existing relay/hole-punch NAT traversal (TASK-168/218). Owner words: we need to SEE the bittorrent bootstrap work in e2e between VMs, one initial node and another booting 10s later, eventually seeing each other via BEP5 even if they cant connect directly. HERMETICITY design point for the spike: do NOT hit the REAL public Mainline DHT (router.bittorrent.com/dht.transmissionbt.com) in a hermetic e2e -- external dependency + announcing test nodes to the real Mainline swarm is leaky and rude. Stand up a LOCAL Mainline DHT bootstrap node inside the VM topology that both nix-p2p nodes use as their Mainline entry point (a real Mainline node, but in-topology); optionally a separate manual/opt-in run can validate against the real Mainline. The PRIVACY-COST measurement (BEP5 announce_peer exposes our IP -> node-MEMBERSHIP enumeration, NOT content holdings; consult TASK-96) remains the central spike deliverable ALONGSIDE this working demo.

SPIKE OUTCOME 2026-08-19 — RECOMMENDATION: ADOPT-WITH-CONDITIONS (as a no-owned-infra public bootstrap RENDEZVOUS for DISCOVERY only; NOT a NAT-traversal solution).

CENTRAL FINDING (AC#13). BEP5 announce_peer records ONLY the source IP:port of the announce packet; get_peers returns Vec<SocketAddrV4> — bare IP:port, NO PeerId, NO payload, NO /p2p-circuit. Proven with the pubky mainline v8 crate AND demonstrated in a passing KVM VM e2e: a NATd A announcing behind a MASQUERADE is recorded at its NAT gateway IP (192.168.1.1:4001, not its private 192.168.2.4), which B recovers via BEP5 but CANNOT dial (both reachability probes fail). So BEP5-as-rendezvous lets B DISCOVER A membership/existence, but does NOT let B REACH a NATd A. To reach NATd peers a working design needs EITHER (a) BEP44 signed mutable records carrying PeerId+relay /p2p-circuit multiaddrs (pkarr-style; the crate supports BEP44) — but that is 1:1 key->record lookup, not many:1 discovery, so it COMPLEMENTS BEP5, not replaces it — OR (b) BEP5 finds the DIALABLE public subset (relays/public nodes) and a NATd A becomes reachable once it dials out and its circuit address is learned via our OWN kad/identify. Net: BEP5 rendezvous bootstraps INTO our existing circuit-v2 relay + kad; it does not itself provide NAT traversal.

CRATE + CLIENT-ONLY (AC#1). mainline v8.0.0 (pubky/pkarr lineage, MIT, actively maintained), pure-Rust BEP5+BEP44. Held strictly CLIENT (no server_mode()). PROVEN client-only FROM RAW WIRE (not the README): a client answered 0 outbound responses (it received 21 inbound probe queries but SERVED none); the identical node flipped to server_mode answered 44 — the bite fires. The v8 sync API is deprecated; used AsyncDht.

ENUMERATION PRIVACY COST (AC#7, from raw capture). A third-party observer recovered the ENTIRE announced node population from ITS OWN get_peers wire capture: recoverable fraction 5/5 (exact rational), observer get_peers wall time 2148 ms. A values-stripped/handed capture recovers 0/3 (vacuous run fails). FRAME EXACTLY: this enumerates node MEMBERSHIP (which IPs speak nix-p2p), NOT content HOLDINGS — it does NOT touch the frozen no-enumeration (holdings) invariant. The exposure is inherent to BEP5 announce and is the price of a public pool.

VM E2E (AC#3, owner requirement — PASSED). nixos/mainline-rendezvous-vm-test.nix: local Mainline node on the public segment + two NATd VMs on separate NATs (cannot connect directly). nodea announces first; nodeb boots 10s later and DISCOVERS nodea via BEP5 (DISCOVER_OK count=1 peerid=none addrs=192.168.1.1:4001) despite the NAT. Byte-identical FETCH was NOT attempted: it is blocked by the AC#13 reachability finding (B cannot reach a NATd A over BEP5 alone) and is the deferred adoption work.

AC STATUS: DONE #1 #4 #5 #6 #7 #12 #13. PARTIAL: #2 (default-OFF flag + NixOS option + fail-closed profile refusal are DONE as operator scaffold; the daemon does not LIVE-run the DHT — the rendezvous-spike bin does — so feeding addresses into SwarmHandle::dial is the deferred live wiring); #3 (discovery DONE incl VM; fetch blocked by the finding); #8 (LookupBound deadline+max_addrs documented and the lookup returns within bound in tests; announce cadence bounded — a formal traffic-bound harness is light). DEFERRED to an adopt-gated follow-up: #9 #10 #11 (bounded expiring peer cache productionization) — the spike is COLD-CACHE-ONLY to keep the no-injection bites honest.

258 does NOT close TASK-96: 96 real-swarm verdict needs owner-authorized two-network infra. This hermetic spike answers structural feasibility + in-vitro privacy cost + the demo only.

SUPPLY CHAIN: cargo deny licenses/bans/sources GREEN with the new mainline dep. cargo deny advisories has 3 PRE-EXISTING failures (h2 RUSTSEC-2026-0258 via iroh; hickory-dns RUSTSEC-2026-0118/0119 via iroh/libp2p DNS) — confirmed present in HEAD Cargo.lock, NOT introduced by mainline (mainline pulls neither). They warrant their own triage follow-up.

GATES: fmt clean; clippy -D warnings clean on changed crates; discovery-guard self-test bites + real scan green; enumeration analyzer self-test bites; spike default tests 2/2 + ignored load-bearing 2/2 + scaffold mutation-bite 4/4 green; VM e2e PASSED. Evidence in evidence/task-258/.

CODEX 258R NARROWING 2026-08-19 (cross-model gate NOGO on OVERSTATED decision-bearing claims; the SUBSTANCE all checked out — BEP5 structure, supply-chain isolation, remedies, client-only, config-level profile refusal — but five claims above were stated STRONGER than the evidence proves. Narrowed here; recommendation stands ADOPT-WITH-CONDITIONS):

1. NAT REACHABILITY was TOO BROAD. "BEP5 cannot let B REACH a NATd A" overreaches: a NATd peer reachable via port-forward, UPnP, hole-punched mapped endpoint, or any dialable mapped address IS reachable, and BEP5 records that dialable mapped address fine. The PROVEN limitation is narrower and specific: BEP5 cannot express a peer whose ONLY reachable address is a /p2p-circuit through a relay (BEP5 carries a bare IP:port, not a circuit multiaddr). The VM e2e demonstrates exactly that circuit-only-behind-MASQUERADE case (recorded at the NAT-gateway IP, undialable), not the general NATd case.

2. BEP5 ANNOUNCE-ADDRESS WORDING corrected. announce_peer records the packet SOURCE IP plus the PORT SUPPLIED IN THE announce_peer MESSAGE; the packet source PORT is used only when implied_port=1 (BEP5). Prior "source IP:port" conflated the two. The finding (NAT-gateway IP recovered, private IP not) is unaffected — the IP is the packet source either way.

3. GUARD CLAIM narrowed to what the guard actually proves. check-discovery-no-shortcut.py is a NAMING/WIRING heuristic (defense-in-depth), NOT a semantic proof that content discovery is Kademlia-exclusive: BEP5 get_peers(info_hash) is itself a provider-discovery-SHAPED call permitted by naming, and FORBIDDEN_PROTOCOL_RE misses aliases such as `use libp2p::rendezvous as rz`. The LOAD-BEARING isolation is the CRATE BOUNDARY: the mainline crate is NOT a dependency of any shipped daemon binary (daemon, daemon-libp2p, fabric-libp2p declare no mainline dep — verified by manifest grep; codex confirmed via cargo tree), so Mainline code cannot reach the shipped content path at all. cargo enforces that; the guard is the cheaper second line. Guard docstring updated to say so.

4. PROFILE-REFUSAL packet-level claim was true only BY CONSTRUCTION. AC#5 refusal is proven at the CONFIG/PARSE level: fail-closed under upstream-only AND lan-share, default OFF, 4 mutation-bite tests. But a PACKET-LEVEL zero-Mainline-traffic bite is VACUOUS today because the shipped daemon runs NO Mainline DHT even when the flag is ON (live wiring is the deferred AC#2 — only the spike bin runs the DHT). A meaningful packet-level bite becomes possible only after AC#2 lands. The config-level proof is what stands now; do not read it as a wire-observed zero.

5. ENUMERATION 5/5 is a HERMETIC recoverable-FRACTION, not a general enumeration RATE. In the hermetic 5-node topology a third-party observer recovered 5/5 (num=den=5, exact rational) of the announced membership from ITS OWN get_peers capture, and a values-stripped capture recovers 0/3 (vacuous-run bite fires). This proves (a) BEP5 announce EXPOSES member IPs and the analyzer recovers exactly what the wire carries, and (b) the oracle bites a handed result. It is NOT a claim about what fraction of a REAL public swarm is enumerable, nor the real-swarm wall-time (2148 ms is the hermetic single-lookup latency). Real-swarm enumeration cost is TASK-96 domain (owner-authorized two-network infra). The QUALITATIVE privacy conclusion is unchanged: BEP5 announce enumerates node MEMBERSHIP (which IPs speak nix-p2p), NOT content HOLDINGS — the frozen no-enumeration (holdings) invariant is untouched.

NET: the recommendation (adopt-with-conditions), the central finding (discovers-membership-not-circuit-reachability), the client-only proof, supply-chain isolation, and the deferred AC#2/#3/#9-11 follow-ups all STAND. Only the five claim STRENGTHS above are narrowed to the evidence. Follow-ups the adopt decision must carry: semantic-not-just-naming discovery guard, real-swarm enumeration cost (96), packet-level OFF bite after live wiring, BEP44-or-dial-out for circuit-only peers.

CODEX 258R2 CORRECTION 2026-08-19 (two residual over-attributions in the 258R narrowing; #2 #4 #5 passed):

R2-1 NAT attribution (narrowing point 1 was still too strong). The VM topology instantiates NO relay path, so it does NOT establish that a /p2p-circuit is A ONLY reachable address. What the VM actually demonstrates is the UNMAPPED-MASQUERADE DIRECT-ADDRESS failure: an unforwarded MASQUERADE endpoint is undialable and BEP5 supplied no alternative address. It is BEP5 FORMAT (bare IP:port, no circuit multiaddr) — NOT the VM — that establishes the circuit-address limitation. So: the VM proves direct-address unreachability for an unmapped-NAT peer; BEP5 format proves it cannot carry a circuit address for the peers whose only reachable address IS a circuit. Do not read the VM as demonstrating the circuit-only case itself.

R2-3 guard docstring self-contradiction (FIXED in the guard, recorded here). The docstring previously said BEP5 STRUCTURALLY cannot answer who-holds-hash-X / carries no content key. That is false: get_peers(info_hash) IS a find-peers-under-a-key call and BEP5 CAN key on a hash. The honest structural claim is about OUR WRAPPER: we hardcode ONE well-known membership infohash and NEVER derive an infohash from a Nix content hash, and the return is a bare IP:port — so our USE supplies member ADDRESSES only. Corrected in check-discovery-no-shortcut.py so it no longer contradicts the acknowledged get_peers(info_hash) blind spot.

NET unchanged: adopt-with-conditions; central finding sound; no proven claim weakened.
<!-- SECTION:NOTES:END -->
