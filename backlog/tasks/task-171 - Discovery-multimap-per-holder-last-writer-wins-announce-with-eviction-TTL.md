---
id: TASK-171
title: 'Discovery multimap: per-holder last-writer-wins announce with eviction/TTL'
status: Done
assignee:
  - mped
created_date: '2026-08-12 18:12'
updated_date: '2026-08-12 20:28'
labels:
  - discovery
  - wave-2b
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-66 (mped review). announce() de-dupes by FULL Claim equality, so idempotency is only shallow (a byte-identical re-announce). The natural unit is the HOLDER (NodeId): a holder is the single source of truth for ITS OWN offers, so its latest announce should REPLACE its prior offer set (per-holder LWW). Under full-Claim dedup a holder that re-announces an UPDATED/corrected offer set accumulates a SECOND entry; merge then unions old+new, so a holder can never retract a stale locator. The multimap is grow-only with no eviction/TTL, so every dead locator a holder ever announced is dialed (and eats a dial timeout) on every fetch, forever. Harmless for write-once test/seed usage; a state leak + failover-latency tax for anything long-lived.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 announce keys a holder by NodeId and REPLACES that holder's offer set (per-holder last-writer-wins), so an updated announce retracts the holder's stale offers
- [ ] #2 stale entries are evictable (TTL or explicit retract); the index is not grow-only
- [ ] #3 a test proves a holder's updated announce drops its old locator from resolve (the current full-Claim-dedup tests still pass, confirming they did not pin this semantics)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Done together as ONE coherent re-model of InMemoryDiscovery per-key index (daemon/src/discovery.rs). (1) Re-key the inner index by HOLDER: HashMap<NarHashKey, HashMap<Vec<NodeId>, HeldClaim>> where HeldClaim={claim, announced_at: Instant}. announce REPLACES that holder-identity latest claim (per-holder LWW, TASK-171 AC#1) instead of full-Claim contains()-dedup, so a re-announced/updated offer set retracts the holder stale locators. (2) Eviction/TTL: ANNOUNCE_TTL const (default 3600s), lazy eviction on announce+resolve, empty buckets pruned; injectable Clock seam (SystemClock default, ManualClock in tests) so the eviction test advances time without sleeping (TASK-171 AC#2/3). (3) merge/resolve PARTITIONs the live holders by content_id (Option<Blake3Digest> from content_id()); resolve yields the single partition with the MOST corroborating live holders (ties: earliest announce), inert (payload==None) claims folded into the winner since they assert no conflicting content. A minority wrong-blake3 announce forms its own partition and is NOT surfaced (TASK-170 AC#1/2). Honest limit: no trust/reputation, so a sybil flood announcing more holders than the honest set could still win the majority vote; one lying announce cannot (TASK-170 AC#3). DirectDiscovery UNCHANGED. Frozen surfaces (claim.rs wire, peer-fabric) untouched. Mutation tests for both defects.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE. Re-modeled InMemoryDiscovery index from grow-only Vec<Claim> to HashMap<NarHashKey, HashMap<HolderId, HeldClaim>> (daemon/src/discovery.rs, commit ec8ac66) together with TASK-170. AC#1 met: announce keys each holder by its identity (its holders set; every real announce is single-self-holder so per-NodeId in practice) and REPLACES that holder latest claim (LWW). AC#2 met: HeldClaim carries announced_at; entries past ANNOUNCE_TTL (const, default 3600s) are evicted lazily on announce+resolve; index no longer grow-only. AC#3 met: test a_holder_reannouncing_an_updated_offer_set_retracts_its_stale_locator proves the old locator is GONE after an updated announce; all pre-existing task-66 full-Claim-dedup tests stay green (they did not pin this semantics). MUTATIONS VERIFIED: (a) folding the offer set into HolderId (so an updated set accumulates) makes the retract test fail; (b) removing the eviction retain (both announce+resolve) makes a_holder_past_the_ttl_is_evicted fail. GOTCHAS: (1) Eviction is LAZY (no background reaper) - an untouched key keeps stale entries until next announce/resolve; harmless since nothing dials an untouched key, but a future metrics/size-bound task should know the index size is only accurate post-touch. (2) First-seen seq preserves task-66 announce order across the HashMap; a re-announce KEEPS its holder seq (a refresh must not reshuffle failover order) while still refreshing announced_at + replacing offers. (3) A Clock seam (SystemClock default, ManualClock in tests) makes TTL provable without sleeping - reuse it for any future time-dependent discovery test. TTL default 3600s is coarse/placeholder; a real push/gossip refresh cadence is task-47.
<!-- SECTION:NOTES:END -->
