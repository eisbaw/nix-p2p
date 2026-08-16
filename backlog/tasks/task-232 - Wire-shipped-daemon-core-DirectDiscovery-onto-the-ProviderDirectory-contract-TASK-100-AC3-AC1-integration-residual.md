---
id: TASK-232
title: >-
  Wire shipped daemon-core DirectDiscovery onto the ProviderDirectory contract
  (TASK-100 AC#3/AC#1 integration residual)
status: To Do
assignee: []
created_date: '2026-08-16 09:07'
updated_date: '2026-08-16 14:04'
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
