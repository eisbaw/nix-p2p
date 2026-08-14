---
id: TASK-168
title: >-
  fabric-libp2p: NAT traversal (AutoNAT/DCUtR/relay) + static peer address book
  for the NodeLocator
status: In Progress
assignee: []
created_date: '2026-08-12 14:28'
updated_date: '2026-08-14 19:55'
labels:
  - libp2p
  - fabric
  - nat
  - hardening
dependencies:
  - TASK-159
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-159 AC#1 (which decentralized address RESOLUTION via kad peer-routing on the loopback test network). AC#1 proved a NAT-free resolver dials a provider whose address reached it through the DHT/identify via a shared bootstrap - no injection. AC#2 (residential peers behind NAT) is a DOCUMENTED HARNESS LIMITATION: the CI/test network is loopback/single-host, so there is no real NAT to hole-punch and no honest test can prove AutoNAT/DCUtR/relay here. This task carries the real NAT work: wire libp2p AutoNAT (reachability), DCUtR (hole punching) and relay (circuit-v2) onto the shared swarm so a peer with no public address can still be dialed for a fetch, proven against a real (or containerized-NAT) network. Also carries two smaller NodeLocator gaps deferred from TASK-159: (1) ExplicitPeersOnly currently returns Miss because this backend has no statically-configured peer address book - add one so explicit-peers resolution is functional with zero disclosure; (2) the frozen peer_fabric::Disclosed enum has no variant for the QUERIED third-party NodeId a peer-routing lookup discloses to contacted DHT nodes (it models OUR disclosures + ContentKey), so the locator records only the expressible OurNodeId - extending Disclosed is a frozen-seam change needing wire review.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 AutoNAT/DCUtR/relay let a NAT'd peer be dialed for a fetch, proven by a test against a real or containerized-NAT network (not loopback)
- [x] #2 ExplicitPeersOnly resolves from a statically-configured peer address book with zero third-party disclosure
- [ ] #3 The queried-NodeId disclosure a peer-routing lookup incurs is represented in the exposure ledger (frozen Disclosed extension, wire-reviewed)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
SUPERSEDES the --libp2p-provider-addr / Libp2pSourceConfig.provider_addrs shim (from TASK-169 mped review F3): TASK-169 demoted that injection channel from required to an OPTIONAL out-of-band dial-address override hint (kept, not removed, as the lower-risk interim). It is now a SECOND source of truth for 'where is P' alongside node_locator's DHT resolution, and it is exercised by NO test (the acceptance test sets provider_addrs=[]). This task's ExplicitPeersOnly static peer address book is the clean seam-level home for 'reach a peer the DHT has not propagated' - when it lands, converge --libp2p-provider-addr into ExplicitPeersOnly (feed the CLI-supplied peers to the static address book resolved under ExplicitPeersOnly, disclosing nothing) and REMOVE the parallel add_address injection loop in build_libp2p_nar_source (daemon/src/source_libp2p.rs). Until then the retained shim is untested surface - either add a small test of the override role or remove-and-reintroduce here.

COMPASS 2026-08-14: RAISED to High + this is a rung-2 CORNERSTONE (not hardening). It is the LAST unproven half of 'robust connectivity' and the PRD's #1 failure mode (risk 8: works in the harness, fails behind real NAT). All connectivity proofs so far (TASK-103 discovery, TASK-159 address resolution, TASK-179 routed netns) use ROUTABLE addresses with ZERO NAT — hole-punching/relay/AutoNAT/DCUtR are completely unexercised, the direct analogue of the compression thesis needing real link shaping before 94/99 could be believed. Highest-leverage cornerstone after TASK-194. HARNESS CAVEAT (from TASK-179 notes): the e2e image ships no iproute2, so a containerized-NAT topology is a harness fight; spike it first and FILE the true-multi-host residual separately if it balloons (the 179 file-it-keep-the-proof discipline). TEST-LOCK-IN: a minimal-pair bite — a peer reachable ONLY via hole-punch/relay fetches byte-identical; disable DCUtR/relay -> that peer is undiallable -> upstream fallback (proves traversal is load-bearing, not incidental).

--- 2026-08-14 cycle (AC#1 CODE landed; harness residual + AC#2/#3 deferred) ---
Commit e2dcbac. AC#1 split into CODE (done) + HARNESS (blocked, filed TASK-207).

DONE (AC#1 CODE): AutoNAT + DCUtR + relay (circuit-v2 SERVER, run unconditionally so any public node helps NAT'd peers with no dedicated infra) + relay_client (circuit-v2 CLIENT, via with_relay_client transport) wired onto the shared swarm in fabric-libp2p/src/swarm.rs. kad+identify+stream unchanged. on_event logs the NAT-traversal state fail-verbosely (autonat reachability flips, relay reservations, each dcutr hole-punch outcome). Added SwarmHandle::add_external_address (a node advertises a known-public address so identify propagates it and the relay server can cite it in reservation vouchers - without it, clients abort with NoAddressesInReservation). Unit proof tests/nat_traversal.rs: (1) the 7-behaviour swarm builds+binds with the trio active; (2) LOAD-BEARING - a provider that listens ONLY on a relay /p2p-circuit (no directly-reachable address) is fetched byte-identical by a consumer holding ONLY the circuit address, so NAR bytes flow THROUGH the relay circuit. Existing discovery/transport suites stay green (no regression).

AC#9 guard (check-discovery-no-shortcut.py) updated: autonat/dcutr/relay are DIAL-ASSISTANCE, not discovery substitutes (they change HOW you dial an already-kad-discovered peer, never HOW you find who holds content). Removed autonat from FORBIDDEN; added PERMITTED_DIAL_ASSISTANCE rationale + a 2nd self-test arm asserting the trio is allowed. mdns/rendezvous/gossipsub/floodsub still forbidden; the mdns mutation still BITES. Discovery stays kad-exclusive; the no-injection oracle is undisturbed. GOTCHA recorded: the substring scan false-positives on PROSE that names the forbidden tokens (my Behaviour doc comment listing "mdns/rendezvous/..." tripped it) - keep such rationale prose token-free (say "LAN-multicast / central-tracker / pubsub-flooding").

BLOCKED (AC#1 HARNESS) -> TASK-207: a faithful containerized-NAT topology is not constructible on this box. Decisive obstacle: a rootless podman container cannot enable net.ipv4.ip_forward (/proc/sys read-only in the rootless userns, even with --cap-add NET_ADMIN), so a container NAT-gateway that MASQUERADEs between two podman nets is impossible; and host ip netns + nft MASQUERADE needs root (no passwordless sudo). The loopback relay proof is the honest interim; the real-NAT/cross-host minimal-pair is TASK-207. This is the TASK-179 "file-it-keep-the-proof" discipline, as the task pre-authorized.

DEFERRED this cycle (not touched):
- AC#2 (ExplicitPeersOnly static peer address book, zero-disclosure; converge the --libp2p-provider-addr shim into it): separable code gap. Not started. Stays open on this task.
- AC#3 (extend the FROZEN peer_fabric::Disclosed enum for the queried-NodeId disclosure): FROZEN-SEAM change needing wire review - deliberately not touched this cycle.

AC#1 CODE LANDED + orchestrator-verified 2026-08-14 (commits e2dcbac code, e364b93 notes). Wired autonat + relay(server, unconditional) + relay_client + dcutr onto the swarm (kad+identify+stream unchanged); added SwarmHandle::add_external_address (root-caused a NoAddressesInReservation bug). PROVEN LOAD-BEARING at the relay data path (nat_traversal.rs: a provider on a relay /p2p-circuit ONLY, no direct addr, is fetched byte-identical THROUGH the relay). AC#9 guard updated (trio = dial-assistance permitted; mdns still bites; discovery kad-exclusive). NO regression. REMAINS PARTIAL: the real-NAT proof (DCUtR hole-punch + the disable-relay/dcutr->undiallable->upstream-fallback minimal-pair) is BLOCKED on this box (rootless podman /proc/sys RO -> no ip_forward; no sudo) -> TASK-207 (HIGH). AC#2 (ExplicitPeersOnly static address book) + AC#3 (frozen Disclosed extension, wire-reviewed) DEFERRED. Follow-up filed: relay-server resource bounds/opt-out. 168 stays In Progress until 207's real-NAT proof backs the cornerstone claim.

--- 2026-08-14 cycle (AC#2 static peer address book LANDED) ---

DONE (AC#2): ExplicitPeersOnly now resolves from a statically-configured peer address book with ZERO third-party disclosure. Root: fabric-libp2p/src/locator.rs previously hard-returned Lookup::Miss for ExplicitPeersOnly (no book existed). Added:
- NodeConfig::peer_address_book: BTreeMap<NodeId, Vec<Multiaddr>> + builder with_explicit_peer(node, addrs) (swarm.rs). A pure LOCATOR concern: taken out of config in fabric.rs::assemble BEFORE Node::start consumes it, flattened to opaque DialInfo location strings (Multiaddr::to_string, same shape the kad path yields), and handed to Libp2pNodeLocator::new. It NEVER enters the swarm and does not affect discovery/dialing/the kad routing table.
- Libp2pNodeLocator holds the book; new locate_via_book(node) is a pure LOCAL map lookup: Found(configured addrs) or honest Miss. Restructured locate(): the PeerId derivation (peer_id_of_provider) moved INTO the PublicInfrastructure arm only; the ExplicitPeersOnly arm never derives/dials.

ZERO-DISCLOSURE PROOF (the load-bearing property): tests/node_locator_discovery.rs::explicit_peers_only_resolves_from_static_book_with_zero_disclosure. A single node with an EMPTY routing table (routing_peers()==0, never joined/bootstrapped) asserted: (1) ExplicitPeersOnly(configured) -> Found(book addr); (2) the SAME node SAME peer under PublicInfrastructure -> Unavailable(InsufficientRouting) - the kad path genuinely cannot answer off-network, so the Found in (1) MUST have come from the local book, not the DHT; (3) ExplicitPeersOnly(unconfigured) -> Miss (no fabrication); (4) exposure_ledger().len() UNCHANGED across every explicit resolve (no network query, no disclosure). Oracle bites: a book that returned Miss fails (1); a book path that recorded to the ledger fails (4).

AC#3 Disclosed extension: NOT needed for AC#2, as predicted. A local-book lookup discloses nothing, so it fits the EXISTING exposure model with NO ledger record at all (the frozen Disclosed enum is untouched). AC#3 (queried-NodeId disclosure on the kad path) remains a separate frozen-seam wire-review change.

kad resolve path (159) + discovery: UNCHANGED and green. locate_via_dht untouched; the existing 159 acceptance test (Found via DHT / Miss / Unavailable arms + fetch) still passes, and its ExplicitPeersOnly-with-no-book-Miss assertion still holds (default book is empty).

NOT DONE THIS CYCLE (honest scope): the implementation-note convergence of the --libp2p-provider-addr shim INTO ExplicitPeersOnly (feed CLI peers to the book; make the transport consult ExplicitPeersOnly; remove the add_address injection loop in daemon/src/source_libp2p.rs) is a larger daemon+transport change and was deliberately NOT attempted here to keep AC#2 surgical (no risk to the kad path). The book seam is now in place for it; filed as follow-up. The transport (transport.rs) still resolves via PublicInfrastructure only - it does not yet consult the book.

BOUNDED GATE (all green): cargo build -p fabric-libp2p -p daemon-libp2p (exit 0); cargo test -p fabric-libp2p (86 tests, 0 failed, incl. the new AC#2 test + the 159 acceptance test); cargo fmt --all --check (exit 0); cargo clippy --locked -p fabric-libp2p --all-targets -D warnings (exit 0); just independence (exit 0). no_enumeration N/A (no persisted/exposure/Disclosed type touched; the new path records NO exposure).

AC status: AC#2 MET; AC#1 CODE done + HARNESS blocked->TASK-207; AC#3 deferred (frozen Disclosed, wire review).

AC#2 DONE 2026-08-14 (commit e1d000c): ExplicitPeersOnly now resolves from a local static peer address book (NodeConfig.peer_address_book / with_explicit_peer) — a pure local map lookup, ZERO third-party disclosure (proven: a node with an EMPTY routing table resolves a book peer Found while the SAME peer under PublicInfrastructure is Unavailable(InsufficientRouting), so Found came from the book not the DHT; exposure_ledger unchanged across explicit resolves; unconfigured -> Miss; oracle bites by mutation). AC#3's frozen Disclosed extension NOT needed (local lookup discloses nothing). kad path (159) + discovery unchanged/green. Orchestrator-verified. 168 STAYS In Progress: AC#1 (real-NAT proof) blocked -> TASK-207 (env); AC#3 (queried-NodeId Disclosed extension, wire-review) deferred. Follow-up seam noted: the transport doesn't yet consult the book on fetch + the --libp2p-provider-addr shim convergence into ExplicitPeersOnly is a larger daemon+transport change (book seam in place, untested surface until then).
<!-- SECTION:NOTES:END -->
