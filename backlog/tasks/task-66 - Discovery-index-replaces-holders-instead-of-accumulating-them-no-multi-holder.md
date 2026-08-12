---
id: TASK-66
title: >-
  Discovery index replaces holders instead of accumulating them (no
  multi-holder)
status: Done
assignee:
  - mped
created_date: '2026-08-09 13:31'
updated_date: '2026-08-12 18:13'
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

## Gotchas / decisions (implementation)

- The failover MECHANISM already existed: fetch_via_offers() iterates a claim's transports in order and fails over. So the ONLY missing piece was the resolved claim carrying >1 holder's offers. Fix is entirely in the in-process index; the fetch driver, the Discovery trait, and claim.rs (frozen wire) are untouched (confirmed: claim.rs 0 lines in the diff).
- Multi-holder is expressed by MERGING accumulated claims at resolve into ONE Claim (union of holders/transports, in announce order). This is a synthetic value no holder asserted — fine for v1 (fungible offers under one blake3, empty signatures/relay), but the wrong shape once claim signatures are real. Filed TASK-172 (Option<Vec<Claim>> seam).
- announce dedups by FULL Claim equality (shallow idempotency). A holder that re-announces an UPDATED offer set accumulates a second entry rather than replacing its own — grow-only, no eviction. Filed TASK-171 (per-holder LWW + TTL).
- content_id poisoning is latent: merge keys purely on NarHashKey, so under UNTRUSTED announces a wrong-blake3 first announce could grief a key. Not reachable in wave-2a (trusted seeds; DirectDiscovery network path is first-Have-wins, no merge). Filed TASK-170.
- Hardening applied from mped review: merge takes content_id/relay from the first holder that CARRIES one (find_map), not claims[0] unconditionally, so an inert-payload first holder doesn't blind a key. Pinned by a unit test.
- Oracle discipline: the failover test asserts the per-holder dial ATTEMPT ORDER ([dead_a, live_b]), not merely that bytes arrived (vacuous — the live holder serves regardless). Verified all 3 multi-holder tests fail when announce is reverted to replace-on-key; the miss-control test stays green.
- Workspace test flakiness is PRE-EXISTING and unrelated: 'cargo test --workspace' intermittently trips on two load-sensitive timing tests (fabric-iroh iroh_node_lookup deadline; daemon fault_loop) that pass in isolation. Filed TASK-173. TASK-66's own surface (cargo test -p daemon) is deterministically green.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DONE. InMemoryDiscovery's in-process index is now a multimap (HashMap<NarHashKey, Vec<Claim>>): announce ACCUMULATES distinct holders in announce order (idempotent on identical re-announce), and resolve MERGES them into one Claim whose transports is the union of holders' offers — exactly the shape fetch_via_offers already fails over across, so real holder->holder failover falls out of the existing fetch driver with NO change to it and NO change to the FROZEN claim wire schema (holders/transports already Vec on Claim; claim.rs untouched, 0 lines in diff).

Commits (master, not pushed): 0781d56 (multimap + accumulate + failover tests), 5a73c28 (rustfmt), 9209eb3 (mped hardening: first-Some payload/relay + lying-holder safety test).

Files: daemon/src/discovery.rs (announce/merge/resolve), daemon/src/transport_fetch.rs (NodeAwareTransport + failover/lying-holder tests).

Gate (LIGHT/feature, in nix develop): cargo build -p daemon = 0; just lint = 0 (clippy -D + rustfmt + ruff + guards); cargo test -p daemon = 0 (134 lib + all integration, incl 6 TASK-66 tests). cargo test --workspace intermittently red on TWO pre-existing, unrelated load-sensitive flakes (fabric-iroh iroh_node_lookup; daemon fault_loop) — both pass in isolation; filed TASK-173.

Oracle bites: reverting announce to replace-on-key fails all 3 multi-holder tests; the failover oracle is the dial ATTEMPT ORDER, not mere success.

AC#1 accumulate+ordered resolve: met. AC#2 dead-first-holder reaches the SECOND holder (attempt-order oracle), non-vacuous by mutation: met. AC#3 frozen wire untouched (asserted; claim.rs 0 lines): met.

Reviews: qa-test-runner (daemon green; workspace flake is unrelated) + mped-architect (sound for wave-2a, tests bite). Follow-ups filed: TASK-170 (content_id partitioning under untrusted announces), TASK-171 (per-holder LWW + eviction), TASK-172 (Option<Vec<Claim>> seam for signed v2), TASK-173 (de-flake workspace). Forward-carried note appended to TASK-43 (its dead-holder case can now bite as real holder->holder failover, with the e2e recipe).
<!-- SECTION:FINAL_SUMMARY:END -->
