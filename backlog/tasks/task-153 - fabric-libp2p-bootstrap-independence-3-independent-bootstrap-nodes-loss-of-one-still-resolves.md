---
id: TASK-153
title: >-
  fabric-libp2p: bootstrap independence (>=3 independent bootstrap nodes; loss
  of one still resolves)
status: To Do
assignee: []
created_date: '2026-08-12 07:55'
labels:
  - libp2p
  - fabric
  - dht
  - decentralized
  - hardening
  - wave-2c
dependencies:
  - TASK-103
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-103 (AC#5). The cornerstone test uses a single bootstrap. Make >=3 independently operated bootstrap/routing nodes configurable (NodeConfig currently drives connectivity via explicit handle calls; add a bootstrap-set config + standard join). Prove an already-admitted healthy network keeps resolving content when ANY single bootstrap is lost, and that no single central service is required. Distinguish BootstrapOutage vs Partition in the Unavailable mapping where detectable.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 >=3 independent bootstrap nodes are configurable and used to join
- [ ] #2 a multi-node test kills any one bootstrap and shows an already-admitted network still resolves an announced key
- [ ] #3 no single central service is required; BootstrapOutage vs Partition are distinguished where detectable
<!-- AC:END -->
