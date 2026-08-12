---
id: TASK-170
title: 'Discovery multimap: partition merge by content_id under untrusted announces'
status: Done
assignee:
  - mped
created_date: '2026-08-12 18:12'
updated_date: '2026-08-12 20:28'
labels:
  - discovery
  - wave-2b
  - security
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-66 (mped review). InMemoryDiscovery::merge takes the merged content id from the first holder that carries a payload and unions ALL holders' offers under it. Sound for TRUSTED wave-2a seeds (announces are local config, and DirectDiscovery — the network path — is first-Have-wins single-holder, no merge). It becomes a griefing vector the instant a push/gossip layer feeds the multimap UNTRUSTED announces: a malicious FIRST announce carrying a wrong blake3 poisons the merged content_id, so every honest holder's offer is dialed for the wrong content, fails gate-1, and the whole key collapses to a discovery-exhausted miss -> forced upstream for that key.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 merge partitions accumulated claims by content_id and only unions offers WITHIN a content-id group (a disagreeing/minority blake3 cannot mask the honest majority's content id)
- [ ] #2 a test drives >=2 content-id groups under one key and proves the honest group still resolves+fetches while a wrong-blake3 announce is segregated, not merged
- [ ] #3 honest limit named: this only matters once untrusted announces reach the in-process index (push/gossip); until then it is latent
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Done together as ONE coherent re-model of InMemoryDiscovery per-key index (daemon/src/discovery.rs). (1) Re-key the inner index by HOLDER: HashMap<NarHashKey, HashMap<Vec<NodeId>, HeldClaim>> where HeldClaim={claim, announced_at: Instant}. announce REPLACES that holder-identity latest claim (per-holder LWW, TASK-171 AC#1) instead of full-Claim contains()-dedup, so a re-announced/updated offer set retracts the holder stale locators. (2) Eviction/TTL: ANNOUNCE_TTL const (default 3600s), lazy eviction on announce+resolve, empty buckets pruned; injectable Clock seam (SystemClock default, ManualClock in tests) so the eviction test advances time without sleeping (TASK-171 AC#2/3). (3) merge/resolve PARTITIONs the live holders by content_id (Option<Blake3Digest> from content_id()); resolve yields the single partition with the MOST corroborating live holders (ties: earliest announce), inert (payload==None) claims folded into the winner since they assert no conflicting content. A minority wrong-blake3 announce forms its own partition and is NOT surfaced (TASK-170 AC#1/2). Honest limit: no trust/reputation, so a sybil flood announcing more holders than the honest set could still win the majority vote; one lying announce cannot (TASK-170 AC#3). DirectDiscovery UNCHANGED. Frozen surfaces (claim.rs wire, peer-fabric) untouched. Mutation tests for both defects.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE. Re-modeled InMemoryDiscovery per-key index (daemon/src/discovery.rs, commit ec8ac66) together with TASK-171. resolve now PARTITIONS live holders by content_id and surfaces only the partition with the most corroborating holders (ties -> earliest announce); a wrong-blake3 announce forms its own minority partition and is segregated. Inert (payload==None) announces are folded into the winner. AC#1 met (merge unions offers only WITHIN a content-id group). AC#2 met: test a_poisoning_announce_is_partitioned_off_not_merged_into_honest_holders drives a poison partition (1 liar, wrong blake3, announced FIRST) + honest partition (2 holders) and proves the honest content id + both honest locators resolve while the liar is excluded. AC#3 met: honest limit documented on the type + here. MUTATION VERIFIED: reverting resolve to union-under-first-content_id makes the poison test fail (surfaces poison blake3 + unions liar in). GOTCHAS for future tasks: (1) Discovery::resolve returns a SINGLE Claim carrying ONE content_id, so resolve can surface only ONE partition; a driver that wants to try BOTH partitions in turn needs a multi-claim resolve (not built). (2) This is a MAJORITY vote with NO trust/reputation: >=2 honest holders beat one liar, but a sybil announcing more fake holders than the honest set would win, and a 1-vs-1 tie breaks by earliest announce (poison-first would win the tie). (3) Latent until untrusted announces actually reach the in-process index (push/gossip, task-47); DirectDiscovery network path is unchanged (still first-Have-wins).
<!-- SECTION:NOTES:END -->
