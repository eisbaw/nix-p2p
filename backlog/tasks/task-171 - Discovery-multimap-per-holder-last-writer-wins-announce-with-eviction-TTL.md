---
id: TASK-171
title: 'Discovery multimap: per-holder last-writer-wins announce with eviction/TTL'
status: To Do
assignee: []
created_date: '2026-08-12 18:12'
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
