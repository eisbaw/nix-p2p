---
id: TASK-126
title: >-
  Select + freeze the ProviderDirectory backend and opaque-value
  content-key/provider-record schema
status: In Progress
assignee: []
created_date: '2026-08-10 22:51'
updated_date: '2026-08-11 23:58'
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

Forward-carried from TASK-140 (peer-fabric seam landed, commit 9073806) - data-design questions the codec freeze MUST settle (raised by mped-architect review of the seam):
- ProviderRecord.key vs the DHT storage key: peer-fabric documents the SSOT invariant record.key == put_record storage key, signature binds it, codec validates fail-fast on read. TASK-126 decides whether to keep the field (so the signature covers it) or reconstruct it for signing. State which key wins; do not leave both independently mutable.
- ProviderRecord.content (Blake3Digest): OPEN whether it is LEARNED from the record or already KNOWN by an asker who possessed the NarHash to derive ContentKey and run gate-1. If already known, it may be redundant (drop it); if a record is discoverable by key alone without knowing the content digest, it must stay. Same question for HoldAnswer::Have{content,offers}. Freeze the answer with the codec.
- ContentKey privacy: the seam doc was corrected to state honestly that the key/NarHash separation only hides the signed hash from ROUTING nodes; the k closest STORING nodes still learn ProviderRecord.content. Keep this framing; the adversarial exposure analysis is TASK-132's.
- ContentKey derivation (NarHash -> 32 bytes) and ProviderRecord codec/size-cap and expiry-vs-substrate-TTL reconciliation (AC#6) are all still TASK-126's to freeze; peer-fabric names only the field SHAPE (from_bytes is the only ContentKey constructor until you pin the derivation).

Forward-carry from TASK-141 inc 1 (commit d01fb42): ContentKey + ProviderRecord live in peer_fabric::content and are still serde-FREE by design - this task's freeze chooses their codec inside an opaque DHT value against the adopted backend, without a churn dep on peer-fabric. CONTRAST with the ids (peer_fabric::ids): NodeId/Blake3Digest/InfoHash now DO carry frozen serde/FromStr string codecs (moved out of the daemon in inc 1, forced by the orphan rule since the daemon claim wire needs them). So when freezing ProviderRecord, its embedded content Blake3Digest / provider NodeId already have frozen canonical string forms (blake3:<hex> / bare 64-hex) - reuse those, do not re-invent. The golden-value SSOT pattern to mirror: hardcode the golden bytes ONCE (committed golden JSON, cross-checked by scripts/check-golden-vectors.py against a stock tool) rather than re-hardcoding literals across crates.
<!-- SECTION:NOTES:END -->
