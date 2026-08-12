---
id: TASK-126
title: >-
  Select + freeze the ProviderDirectory backend and opaque-value
  content-key/provider-record schema
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-10 22:51'
updated_date: '2026-08-12 02:25'
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
- [ ] #3 Enforce monotonic provider sequence idempotent refresh explicit signed withdrawal expiry replay rejection concurrent-provider merge and no expired-record resurrection.
- [ ] #4 Requests responses provider counts record bytes routing buckets concurrency work amplification and deadlines are bounded and malformed bad-signature wrong-key unknown-version stale and oversized messages fail closed.
- [ ] #5 SPIKE GATE (first): decide the ProviderDirectory backend with evidence, not faith. Confirm the substrate can store an OPAQUE signed value (our ContentKey -> signed ProviderRecord bytes) so the frozen codec does NOT leak into the substrate's own record wire; if iroh-dht-experiment exposes only its typed records, libp2p-kad put_record/get_record becomes the freeze target and primary/fallback flips. Primary iroh-dht-experiment / fallback libp2p-kad; the in-progress hand-rolled Kademlia is salvaged as a FakeProviderDirectory in-memory test oracle, not shipped infra.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Re-gate round-2 (Workflow wsgcxn3uy): qa GO, codex NO_GO but confirms frozen bytes SOUND + all 6 prior findings resolved. Round-3 (FINAL freeze-proof hardening) queued: (1) fix release-red test (cfg-gate the debug-only assert; cargo test --release must be green); (2) python anchor must reject small-order A and R to match Rust verify_strict + add an identity-forgery reject vector exercised by BOTH impls + document the normative canonical-signature policy so a second implementation agrees; (3) golden error_tag must compare FULL typed error payload not variant name; (4) reject_iroh_node_not_provider must use a VALID alt ed25519 key (genuine offer!=provider). Positive frozen bytes must NOT change (codex confirms sound). After round-3: mark Done on GO, or accept-with-justification if only minor proof-nits remain (bytes sound across 3 rounds).
<!-- SECTION:NOTES:END -->
