---
id: TASK-126
title: >-
  Select + freeze the ProviderDirectory backend and opaque-value
  content-key/provider-record schema
status: In Progress
assignee: []
created_date: '2026-08-10 22:51'
updated_date: '2026-08-11 21:21'
labels:
  - iroh
  - discovery
  - dht
  - decentralized
  - cornerstone
  - implementation
  - blocking
  - wave-2c
dependencies:
  - TASK-114
  - TASK-115
  - TASK-140
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement the cornerstone decentralized exact-key discovery core now. Build a bounded Kademlia-style overlay carried over an explicit Iroh ALPN on the shared TASK-115 endpoint. The domain-separated NAR content key resolves to signed provider records containing Iroh NodeIds and bounded transport offers but no dialable addresses. Multiple configurable bootstrap NodeIds are allowed but no tracker registry server or single operator is required. This task owns the protocol codec routing record store and multi-node core proof; TASK-103 later wires it behind ContentDiscovery and TASK-102 gates real daemon publication.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Freeze versioned domain-separated NarHash-to-DHT-key and provider-record codecs with golden cross-version and one-byte namespace mutation vectors.
- [ ] #2 Provider records are signed by the provider Iroh identity and contain exact content key provider NodeId bounded transport offers sequence issued-at and expiry but no IP port relay address StorePath or unasked key.
- [ ] #3 Exact-key lookup returns multiple current providers and cannot enumerate inventory. Empty healthy lookup is MISS while bootstrap outage partition deadline or insufficient routing is UNAVAILABLE.
- [ ] #4 Enforce monotonic provider sequence idempotent refresh explicit signed withdrawal expiry replay rejection concurrent-provider merge and no expired-record resurrection.
- [ ] #5 At least three configurable bootstrap NodeIds are supported. After admission loss of any one bootstrap or routing node does not prevent lookup and tests cover partition rejoin node churn and provider restart.
- [ ] #6 Requests responses provider counts record bytes routing buckets concurrency work amplification and deadlines are bounded and malformed bad-signature wrong-key unknown-version stale and oversized messages fail closed.
- [ ] #7 A cold run-unique multi-process or multi-endpoint integration test publishes through a provider node and resolves NarHash to the exact provider NodeId from a requester with tracker LAN named candidates and harness record insertion disabled.
- [ ] #8 Emit decentralized-content-dht-core-v1 pass evidence bound to final tree golden vectors topology timings packets and biting mutations. Unsupported central-only or simulated map substitution does not complete the task.
- [ ] #9 SPIKE GATE (first): decide the ProviderDirectory backend with evidence, not faith. Confirm the substrate can store an OPAQUE signed value (our ContentKey -> signed ProviderRecord bytes) so the frozen codec does NOT leak into the substrate's own record wire; if iroh-dht-experiment exposes only its typed records, libp2p-kad put_record/get_record becomes the freeze target and primary/fallback flips. Primary iroh-dht-experiment / fallback libp2p-kad; the in-progress hand-rolled Kademlia is salvaged as a FakeProviderDirectory in-memory test oracle, not shipped infra.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Re-scoped 2026-08-11 per mped-architect + owner: adopt a proven prior DHT, do not hand-roll. AC#3 (implement PING/FIND_NODE/FIND_PROVIDERS/STORE_PROVIDER) DROPPED - the adopted substrate provides routing/RPCs. Surviving ACs freeze OUR schema as an opaque value inside the substrate. AC#6/#8 (bootstrap, cold multi-node proof) now target the adopted substrate. Must land AFTER TASK-140 (seam) so the ProviderRecord shape and the frozen codec agree on the opaque-value model. See docs/peer-fabric-seam.md.
<!-- SECTION:NOTES:END -->
