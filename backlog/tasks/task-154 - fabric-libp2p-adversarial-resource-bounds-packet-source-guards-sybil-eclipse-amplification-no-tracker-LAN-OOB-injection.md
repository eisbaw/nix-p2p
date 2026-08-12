---
id: TASK-154
title: >-
  fabric-libp2p: adversarial resource bounds + packet/source guards
  (sybil/eclipse/amplification; no tracker/LAN/OOB injection)
status: To Do
assignee: []
created_date: '2026-08-12 07:55'
labels:
  - libp2p
  - fabric
  - dht
  - security
  - hardening
  - wave-2c
dependencies:
  - TASK-103
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-103 (AC#8 + AC#9). Enforce record/provider/request/response/storage/concurrency/rate/work bounds on the kad path (MemoryStore caps, get_providers fan-out cap via DiscoveryBudget.max_peers, per-query concurrency, put/announce rate) so poisoning/amplification/sybil/eclipse assumptions hold without compromising integrity. Add packet/source guards proving tracker/LAN/implicit-public presets and out-of-band address injection are DISABLED during qualification, with a mutation that enables any substitute making the proof FAIL (oracle bites by mutation). The custom /nix-p2p kad protocol already keeps these nodes off the public IPFS DHT; make that a guarded invariant.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 record/provider/request/storage/concurrency/rate/work bounds enforced and unit-proven on the kad path
- [ ] #2 sybil/eclipse/amplification/poisoning assumptions documented and bounded without compromising integrity
- [ ] #3 packet/source guard proves no tracker/LAN/implicit-public/OOB injection during qualification; a mutation enabling any substitute makes the proof fail
<!-- AC:END -->
