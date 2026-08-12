---
id: TASK-66
title: >-
  Discovery index replaces holders instead of accumulating them (no
  multi-holder)
status: In Progress
assignee:
  - mped
created_date: '2026-08-09 13:31'
updated_date: '2026-08-12 17:50'
labels: []
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
InMemoryDiscovery::announce replaces on key, so a NarHash resolves to at most ONE holder. Consequence for TASK-43: the dead-holder pathological case degenerates into the peer->upstream fallback that S6 already covers - there is no 'failover to the NEXT holder' to test, so the scenario cannot bite as written. Fix is a multimap in the in-process index. This is a VELOCITY surface (in-process discovery internals) and must NOT touch the claim wire schema, which is FROZEN - do not grow a frozen surface to get multi-holder. If the multimap cannot be done cheaply, the honest outcome is to scope TASK-43's dead-holder case to peer->upstream and name the gap in its limitations, rather than shipping a scenario that looks like failover and is not.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The discovery index accumulates holders per NarHash (multimap) rather than replacing, and resolve returns them in a defined order
- [ ] #2 A dead-holder test bites at the RIGHT boundary: with 2 holders and the first one dead, the fetch reaches the SECOND HOLDER (not upstream) - proven by a provider-side counter on holder 2, and proven non-vacuous by mutation
- [ ] #3 The claim wire schema is unchanged (frozen surface untouched); assert this explicitly
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Implementation Plan (mped)

Root cause: InMemoryDiscovery.claims is HashMap<NarHashKey, Claim> and announce() does insert(key, claim) — replace-on-key, so a NarHash resolves to at most ONE holder. The dead-holder failover in TASK-43 then degenerates to peer->upstream (S6), never holder->next-holder.

Key seam observation: the fetch driver fetch_via_offers() (transport_fetch.rs) ALREADY fails over across a single claim's transports list, in order. So multi-holder failover needs only that the resolved Claim carry the UNION of holders' offers. That is achievable purely in the in-process index — no Claim wire-schema change (holders/transports are already Vec on the frozen type; I construct an in-memory value, I do not grow the schema).

Change:
1. claims: Mutex<HashMap<NarHashKey, Vec<Claim>>> (multimap).
2. announce(): push claim to the key's Vec, deduping FULL-equal claims (idempotent re-announce). Claim derives PartialEq/Eq.
3. resolve(): merge the accumulated Vec into ONE Claim at the resolve site — payload from the first claim (honest holders of a NarHash agree on blake3; a disagreeing holder's offer simply fails gate-1 downstream, daemon is outside the TCB), holders = union in announce order, transports = union in announce order (dedup). Defined order = announce/insertion order.
4. Fix module + struct + method docs that assert 'last announce wins'.

Tests (must bite by mutation vs old replace-on-key):
- discovery.rs unit: two holders announce same key -> resolve carries BOTH holders and BOTH transports in announce order; re-announce by an existing holder does NOT duplicate. (Bites AC#1 + dedup: old code returns only the last holder.)
- transport_fetch.rs integration: A announces then B; A is a DEAD holder (transport Unavailable for node A), B serves; fetch tries A first (dead), fails over to B, succeeds; provider-side per-node counter proves B was reached AFTER A was attempted. (Bites AC#2: old code drops A, so 'A attempted then failover' cannot hold and transports != [A,B].)

Gate (LIGHT/feature): nix develop -c cargo build -p daemon; just lint; cargo test -p daemon; cargo test --workspace. Report actual numbers. Not e2e.

Forward: annotate TASK-43 that its dead-holder case can now bite as REAL holder->holder failover.
<!-- SECTION:NOTES:END -->
