---
id: TASK-126
title: Implement decentralized Iroh NAR-to-provider-NodeId DHT core
status: In Progress
assignee: []
created_date: '2026-08-10 22:51'
updated_date: '2026-08-11 20:21'
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
- [ ] #3 Implement bounded PING FIND_NODE FIND_PROVIDERS and STORE_PROVIDER RPCs over an explicit default-off Iroh ALPN with Kademlia routing and replication across at least five independent nodes.
- [ ] #4 Exact-key lookup returns multiple current providers and cannot enumerate inventory. Empty healthy lookup is MISS while bootstrap outage partition deadline or insufficient routing is UNAVAILABLE.
- [ ] #5 Enforce monotonic provider sequence idempotent refresh explicit signed withdrawal expiry replay rejection concurrent-provider merge and no expired-record resurrection.
- [ ] #6 At least three configurable bootstrap NodeIds are supported. After admission loss of any one bootstrap or routing node does not prevent lookup and tests cover partition rejoin node churn and provider restart.
- [ ] #7 Requests responses provider counts record bytes routing buckets concurrency work amplification and deadlines are bounded and malformed bad-signature wrong-key unknown-version stale and oversized messages fail closed.
- [ ] #8 A cold run-unique multi-process or multi-endpoint integration test publishes through a provider node and resolves NarHash to the exact provider NodeId from a requester with tracker LAN named candidates and harness record insertion disabled.
- [ ] #9 Emit decentralized-content-dht-core-v1 pass evidence bound to final tree golden vectors topology timings packets and biting mutations. Unsupported central-only or simulated map substitution does not complete the task.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Owner priority 2026-08-11: NarHash to provider NodeId is the project cornerstone and is implemented before the allowlist and broader daemon integration. TASK-102 remains the KISS publication gate; TASK-103 composes both.
<!-- SECTION:NOTES:END -->
