---
id: TASK-232
title: >-
  Wire shipped daemon-core DirectDiscovery onto the ProviderDirectory contract
  (TASK-100 AC#3/AC#1 integration residual)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-16 09:07'
updated_date: '2026-08-16 15:24'
labels:
  - daemon-core
  - discovery
  - fabric
  - integration
dependencies:
  - TASK-100
  - TASK-106
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-100 residual (AC#3/AC#1 integration). TASK-100 hardened the ProviderDirectory CONTRACT (batch multi-holder, typed Miss/Unavailable/NotAttempted, unified outcome-finalization at one choke-point, caller total-deadline enforcement, structural no-enumeration on shipped paths, no-default versioned execution plan, eligibility-consumption contract + SwarmHandle raw-publish seal) - all codex+mped+orchestrator verified, the 5-round aggregation defect class closed. But the SHIPPED daemon-core::DirectDiscovery (daemon-core/src/discovery.rs resolve_many) still returns Vec<Option<Claim>> with its OWN internal total timeout (TASK-106) and folds unresolved/deadline/fault to None - it is NOT wired onto the new ProviderDirectory contract. This task: migrate the shipped in-process/direct discovery onto ProviderDirectory (batch multi-holder + typed outcomes + the caller DiscoveryBudget/ExecutionPlan), SUBSUMING the TASK-106 RESOLVE_MANY_TIMEOUT as the caller budget, so the shipped daemon path gets the contract's typed-outcome + deadline guarantees end-to-end. Also close the discipline residual: the raw trait find_providers is unbound for a NEW direct caller (must use find_providers_bound) - consider making the trait return a key-bound type. Do NOT regress the TASK-106 bites. DEEP-gate (discovery contract). Frozen wire untouched.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Shipped daemon-core::DirectDiscovery::resolve_many returns typed KeyResolution outcomes (Found/Miss/Unavailable/NotAttempted) via the ProviderDirectory contract, not Vec<Option<Claim>> folding faults to None
- [ ] #2 The TASK-106 RESOLVE_MANY_TIMEOUT is subsumed as the caller DiscoveryBudget/ExecutionPlan total-deadline (no double-bound); the existing TASK-106 deadline bites are preserved, not regressed
- [ ] #3 A dead/faulted mechanism yields Unavailable (not a false Miss) on the SHIPPED resolve path - biting test, mutation-proven; the direct caller uses find_providers_bound (no unbound find_providers)
- [ ] #4 No-enumeration structural guard holds on the shipped path; frozen wire untouched (golden byte-identical); full gate incl just e2e green
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DESIGN (mped-architect Mark-emulator arbitrated; Option B disciplined):
Two discovery type-universes exist. (1) peer-fabric ProviderDirectory (ContentKey->signed ProviderRecord) is the GENUINELY-SHIPPED decentralized path via daemon-core PeerFabricNarSource, which ALREADY uses find_providers_bound and ALREADY distinguishes Lookup::Miss vs Unavailable (AC#3 direct-caller requirement already satisfied on the real shipped path). (2) daemon-core Discovery/DirectDiscovery (NarHashKey->unsigned Claim over PeerQuery) is wave-2a scaffolding, constructed only in tests/examples; production TransportNarSource consumes single-key Discovery::resolve, not resolve_many.

The literal AC clause return KeyResolution/Vec<ProviderRecord> via finalize_batch is NOT faithfully realizable: ProviderRecord is a FROZEN signed surface and there is no honest Claim->ProviderRecord map; fabricating signed records from unsigned claims would violate the frozen surface. Realizing the CONTRACT INTENT (the four-way typed distinction; a dead/faulted mechanism can never read as an authoritative Miss; single caller total-deadline) in the correct type universe:

- New daemon-core enum ClaimResolution { Found(Claim), Miss, Unavailable(peer_fabric::Unavailable), NotAttempted } reusing peer-fabric Unavailable taxonomy (touches NO frozen wire).
- Discovery::resolve_many(keys, budget: &DiscoveryBudget) -> Vec<ClaimResolution>; trait default is honest Found/Miss/NotAttempted (single-key resolve cannot express Unavailable).
- DirectDiscovery::resolve_many: swap internal total_timeout for budget.deadline (SINGLE bound; RESOLVE_MANY_TIMEOUT no longer a live field, kept only as the default deadline a caller passes). Probe fault/timeout/misalignment -> Unavailable (never a false Miss); deadline-cut-before-full-consult -> NotAttempted; first Have -> Found; every consulted peer Absent in full within budget -> authoritative Miss. One choke-point finalize on a per-key ClaimAcc.
- Re-point TASK-91/106/107 bites onto the typed return (kept biting); add AC#3 mutation-proof a_dead_mechanism_yields_unavailable_not_a_false_miss (fault+absent -> Unavailable, control all-absent -> Miss; mutation: drop the fault arm in ClaimAcc::finalize -> reddens).
- Shipped-path (PeerFabricNarSource) test: a directory Unavailable folds to fast Unreachable fallback, never a false serve/hang; load-bearing Miss!=Unavailable distinction cited to peer-fabric classify_lookup/KeyResolution bites (rides in via find_providers_bound).
- no_enumeration guard: add ClaimResolution to IDENTITY_TYPES so resolve_many stays recognized as keyed-plural (line 650), still key-bound => not a violation.
- Frozen wire untouched (no encode/decode/Claim/ProviderRecord change) => golden byte-identical. NOTE: cannot reword ACs (owner owns them); documenting reinterpretation here + in final report.

CODEX DEEP GATE NO-GO on 0694dffe - PREMISE STALE (codex-verified vs production wiring): the shipped DHT path (run->PeerFabricNarSource) ALREADY used find_providers_bound + Miss!=Unavailable before this commit; DirectDiscovery::resolve_many is test/example-only (production TransportNarSource uses single-key resolve->InMemoryDiscovery). COMPASS theater-on-shipped-path premise was WRONG. The commit hardened unshipped wave-2a scaffolding + added a divergent ClaimResolution enum (lacks finalize_batch resource-envelope/multi-holder/exec-plan/peer-cap). AC#2/#4 pass; AC#1/#3 fail as shipped-path criteria; shipped_path test is not a distinction bite (Unavailable and Miss both fold to Unreachable). Disposition (revert vs keep+reconcile vs re-scope) routing through mped-architect as Mark-emulator; not grinding the implementer to fix a mis-scoped task.

CLOSED as premise-stale / SUPERSEDED — NOT implemented (this is not a delivered feature; Done only because the tracker has no Cancelled state). codex NO-GO + mped(Mark-emulator) both verified the shipped path (run->PeerFabricNarSource) was ALREADY fault!=miss-correct before any 232 work; DirectDiscovery::resolve_many is test/example-only; COMPASS theater-on-shipped-path premise refuted by code. Commit 0694dffe REVERTED in c18d866 (kept only the peer_source shipped_path_tests salvage). Prune-vs-promote of the wave-2a DirectDiscovery scaffolding folded into TASK-202.
<!-- SECTION:NOTES:END -->
