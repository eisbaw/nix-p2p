---
id: TASK-132
title: GLOBAL-IROH GATE decentralized NAR and peer discovery before LAN
status: To Do
assignee: []
created_date: '2026-08-11 05:31'
updated_date: '2026-08-11 19:52'
labels:
  - iroh
  - discovery
  - dht
  - decentralized
  - global
  - journey
  - e2e
  - blocking
  - wave-2c
dependencies:
  - TASK-83
  - TASK-89
  - TASK-103
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Prove the mandatory global Iroh journey before LAN using decentralized content discovery. Validate decentralized-content-discovery-v1 and public-node-discovery-v1 then start from cold empty run-unique state: resolve one asked NAR identity to provider NodeIds through TASK-103 with tracker and LAN disabled resolve a returned NodeId through TASK-89 connect over Iroh and complete a real-Nix transfer. No central tracker or single discovery service may be required. Failure blocks production and LAN admission.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Validate passing decentralized-content-discovery-v1 and public-node-discovery-v1 schemas tree evidence hashes and mutations. Unsupported tracker-backed stale missing or fabricated inputs fail closed.
- [ ] #2 A cold two-daemon real-Nix build resolves the asked NAR through TASK-103 then its provider NodeId through TASK-89 and transfers exactly NarSize decoded bytes over Iroh with zero upstream NAR-body egress.
- [ ] #3 An identical cold peers-disabled control succeeds with positive upstream NAR-body egress and narinfo probe control QUIC wire and decoded payload bytes remain separately attributed.
- [ ] #4 Tracker LAN named candidate peer address content locator prior rendezvous and harness DHT insertion are disabled and packet or source mutations prove each guard.
- [ ] #5 At least three independent DHT routing or bootstrap nodes start with run-unique state. Loss of any one partition rejoin provider withdrawal expiry and persistent-provider restart have bounded typed outcomes without a central dependency.
- [ ] #6 Content lookup address resolution dialing and transfer have distinct spans sources deadlines and outcomes. MISS cannot hide dependency failure undiallable providers or transfer failure.
- [ ] #7 Clocks start before services and daemons. Content lookup is bounded by 15000 ms address lookup by 10000 ms outage-to-upstream fallback by 16000 ms and cold startup-to-resolved dialable offer by 30000 ms with at most 1000 ms scheduler grace.
- [ ] #8 Emit global-iroh-journey-v1 verdict=pass bound to manifests bytes timings packets inputs and mutations. Only decentralized pass is eligible for review and no result selects a production default or claims public-Internet NAT proof.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Mandatory decentralized qualification gate. TASK-101 tracker artifacts may be attached later only as comparison data and are neither dependencies nor valid substitutes.
<!-- SECTION:NOTES:END -->
