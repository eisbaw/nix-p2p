---
id: TASK-126
title: FREEZE mandatory decentralized NAR-to-provider-NodeId DHT contract
status: To Do
assignee: []
created_date: '2026-08-10 22:51'
updated_date: '2026-08-11 19:58'
labels:
  - iroh
  - discovery
  - dht
  - decentralized
  - blocking
  - grounding
  - wave-2c
dependencies:
  - TASK-100
  - TASK-102
  - TASK-114
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Freeze the mandatory global content-discovery contract before implementation. Select a concrete decentralized DHT substrate for exact NarHash/content-key to bounded signed provider NodeId and transport-offer lookup. Native Iroh support is preferred; if Iroh has no suitable content DHT then select and pin an implementable decentralized substrate used only for discovery while Iroh remains the transfer and node-identity transport. A central tracker or registry cannot satisfy this task and cannot be a production fallback. Failure to identify a viable substrate is a blocking production no-go rather than project completion. TASK-89 separately owns NodeId-to-dialable-address lookup.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Compare viable decentralized substrates using primary-source evidence and select one concrete pinned implementation with no required central service.
- [ ] #2 Freeze a versioned domain-separated NarHash-to-content-key derivation and bounded signed multi-provider record containing provider NodeIds and transport offers but no IP port relay address or unasked key.
- [ ] #3 Require multiple independently configurable bootstrap nodes and prove that no single bootstrap node service tracker registry or operator is required after peer admission.
- [ ] #4 Freeze monotonic publication sequence TTL refresh withdrawal replay rejection expiry crash recovery and concurrent multi-provider merge semantics.
- [ ] #5 TASK-102 remains the only publication eligibility gate and query behavior cannot enumerate a node inventory or return holdings for unasked keys.
- [ ] #6 Freeze bounded record cardinality request work storage concurrency rate and amplification controls plus explicit Sybil eclipse partition and poisoning threat assumptions.
- [ ] #7 Golden and cross-version vectors cover key and record encoding malformed signatures unknown versions rollback duplicate expiry resurrection and namespace mutation.
- [ ] #8 Define a cold run-unique multi-node proof with tracker and LAN disabled including empty network bootstrap single-bootstrap loss partition rejoin multiple providers withdrawal expiry MISS versus UNAVAILABLE and a 15000 ms total lookup deadline.
- [ ] #9 Emit a versioned pass-only decentralized-content-contract-v1 artifact bound to sources vectors and final tree. Unsupported or central-only results keep global production blocked and do not complete TASK-103.
- [ ] #10 Tracker experiments remain optional tournament comparators and can never be credited as decentralized NAR discovery.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Mandatory freeze for production. TASK-103 implements only a pass contract and stays blocked if no decentralized substrate qualifies. TASK-132 consumes only a passing decentralized-content-discovery-v1 artifact. Tracker tasks are optional comparison inputs for later tournaments.

TASK-96 is Mainline-candidate-specific and is not an unconditional prerequisite. If this task selects Mainline as the decentralized substrate it must first add and consume TASK-96 as a dependency; native Iroh or another substrate remains free of that coupling.
<!-- SECTION:NOTES:END -->
