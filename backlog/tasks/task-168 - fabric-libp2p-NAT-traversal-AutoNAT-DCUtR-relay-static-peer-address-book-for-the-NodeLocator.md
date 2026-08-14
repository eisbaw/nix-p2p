---
id: TASK-168
title: >-
  fabric-libp2p: NAT traversal (AutoNAT/DCUtR/relay) + static peer address book
  for the NodeLocator
status: In Progress
assignee: []
created_date: '2026-08-12 14:28'
updated_date: '2026-08-14 16:59'
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
- [ ] #2 ExplicitPeersOnly resolves from a statically-configured peer address book with zero third-party disclosure
- [ ] #3 The queried-NodeId disclosure a peer-routing lookup incurs is represented in the exposure ledger (frozen Disclosed extension, wire-reviewed)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
SUPERSEDES the --libp2p-provider-addr / Libp2pSourceConfig.provider_addrs shim (from TASK-169 mped review F3): TASK-169 demoted that injection channel from required to an OPTIONAL out-of-band dial-address override hint (kept, not removed, as the lower-risk interim). It is now a SECOND source of truth for 'where is P' alongside node_locator's DHT resolution, and it is exercised by NO test (the acceptance test sets provider_addrs=[]). This task's ExplicitPeersOnly static peer address book is the clean seam-level home for 'reach a peer the DHT has not propagated' - when it lands, converge --libp2p-provider-addr into ExplicitPeersOnly (feed the CLI-supplied peers to the static address book resolved under ExplicitPeersOnly, disclosing nothing) and REMOVE the parallel add_address injection loop in build_libp2p_nar_source (daemon/src/source_libp2p.rs). Until then the retained shim is untested surface - either add a small test of the override role or remove-and-reintroduce here.

COMPASS 2026-08-14: RAISED to High + this is a rung-2 CORNERSTONE (not hardening). It is the LAST unproven half of 'robust connectivity' and the PRD's #1 failure mode (risk 8: works in the harness, fails behind real NAT). All connectivity proofs so far (TASK-103 discovery, TASK-159 address resolution, TASK-179 routed netns) use ROUTABLE addresses with ZERO NAT — hole-punching/relay/AutoNAT/DCUtR are completely unexercised, the direct analogue of the compression thesis needing real link shaping before 94/99 could be believed. Highest-leverage cornerstone after TASK-194. HARNESS CAVEAT (from TASK-179 notes): the e2e image ships no iproute2, so a containerized-NAT topology is a harness fight; spike it first and FILE the true-multi-host residual separately if it balloons (the 179 file-it-keep-the-proof discipline). TEST-LOCK-IN: a minimal-pair bite — a peer reachable ONLY via hole-punch/relay fetches byte-identical; disable DCUtR/relay -> that peer is undiallable -> upstream fallback (proves traversal is load-bearing, not incidental).
<!-- SECTION:NOTES:END -->
