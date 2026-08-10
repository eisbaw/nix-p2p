---
id: TASK-103
title: 'Implement the selected Iroh global content DHT, or record it unsupported'
status: To Do
assignee: []
created_date: '2026-08-10 10:04'
updated_date: '2026-08-10 22:53'
labels:
  - wave-2b
dependencies:
  - TASK-82
  - TASK-100
  - TASK-102
  - TASK-115
  - TASK-126
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Consume TASK-126's frozen decision. If global DHT is supported, implement exactly its versioned key/record/bootstrap contract behind ContentDiscovery and prove a no-address/no-tracker real-Nix path. If TASK-126 records a no-go, do not invent a substrate: publish a machine-readable unsupported capability so the Iroh harness and tournaments retain the cell explicitly while tracker and bounded direct-query discovery continue. Substrate/key design is out of scope here.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The implementation records supported or unsupported from TASK-126 and rejects any key/record/bootstrap contract whose version or golden vectors differ.
- [ ] #2 If supported, two daemons with no peer addresses and no tracker complete a real peer-served Nix build through the DHT, with provider bytes and Nix gate-2.
- [ ] #3 If supported, cold bootstrap, NodeId-to-dialable-location resolution, TTL/republish traffic, daemon restart and bootstrap/outage behavior are measured under numeric deadlines.
- [ ] #4 If supported, all publication passes TASK-102 and an unsigned/private-path mutation never reaches a DHT record.
- [ ] #5 If supported, malformed/version-skew/unknown records, empty bootstrap and eclipse/Sybil simulations have bounded availability failure and never bypass integrity gates.
- [ ] #6 In either branch, status/logs expose the selected substrate or unsupported reason plus DNS/relay/Mainline/seed dependencies and no successful lookup is credited to injected addresses.
- [ ] #7 If unsupported, TASK-87 and tournament artifacts contain an explicit global-DHT unsupported cell linked to TASK-126; tracker and known-candidate hold-query paths are proven not to masquerade as global DHT.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Conditional task: every AC states the supported or unsupported branch. A no-go is completion only with TASK-126 evidence and explicit downstream capability reporting.
<!-- SECTION:NOTES:END -->
