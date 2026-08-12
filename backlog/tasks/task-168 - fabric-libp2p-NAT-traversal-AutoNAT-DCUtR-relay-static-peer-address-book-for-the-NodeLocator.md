---
id: TASK-168
title: >-
  fabric-libp2p: NAT traversal (AutoNAT/DCUtR/relay) + static peer address book
  for the NodeLocator
status: To Do
assignee: []
created_date: '2026-08-12 14:28'
labels:
  - libp2p
  - fabric
  - nat
  - hardening
dependencies:
  - TASK-159
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
