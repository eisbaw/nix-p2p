---
id: TASK-237
title: >-
  Value-thesis measurement: libp2p multi-node cache-egress offload on a shaped
  network
status: To Do
assignee: []
created_date: '2026-08-16 14:04'
updated_date: '2026-08-18 20:35'
labels:
  - measurement
  - value-thesis
  - synthetic
  - development
dependencies:
  - TASK-120
  - TASK-206
  - TASK-219
  - TASK-247
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Development-only directional value-thesis measurement. Extend TASK-206 to a reproducible at-least-three-node libp2p kad-DHT topology over shaped links and measure whether steady-state NET cache payload egress drops with nix-p2p while S1, bounded S2, operator budgets, privacy, and the paired p95 latency guard hold. Consume TASK-247 real-daemon concurrency evidence, TASK-180 symmetric peer/socket evidence, and TASK-52 hedge-aware v3 provenance accounting. This topology is never real_3_network, policy training, holdout, field pilot, or PRD success; it produces a hashed planning input for the post-holdout field pilot.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A reproducible at-least-three-node libp2p kad-DHT topology runs over declared shaped cache and peer links; fresh requesters receive only operator profile/bootstrap configuration, with no provider address, per-content locator, relay address, or claim injection.
- [ ] #2 Paired daemon-enabled and upstream-only arms use the exact effective nix-daemon concurrency proven by TASK-247 and independently record cache payload octets, provider/requester peer-socket total/payload/control octets, requester source attribution, signed NarHash results, and confirmed path; no byte field is derived from another.
- [ ] #3 Cold-start and steady-state results are reported separately. The steady-state net cache-egress reduction uses an exact integer numerator/denominator, preregistered repeat/noise rules, randomized pair order, and an A/A control; gross peer bytes or a single successful build cannot satisfy the value oracle.
- [ ] #4 Every scored peer arm preserves S1 and bounded S2, passes the owner-reviewed TASK-120 profile budgets, and retains the PRD normal paired-p95 latency guard of at most 11000/10000 of upstream; dead provider, relay outage, and mixed hit/miss rows remain additive rather than blocking Nix.
- [ ] #5 A canonical just recipe emits a machine-readable, content-hashed report containing topology/config hashes, effective settings, per-run raw counters/timestamps, invalid reasons, resource maxima, and the directional conclusion. The report and TESTING.md state that a synthetic three-node result is not a conclusive real-network verdict.
- [ ] #6 The outcome selects exactly one honest disposition: proceed to the real pilot with the measured planning inputs, rework a named owning boundary and rerun, or no-go with a failed hard constraint. It feeds the separately tracked real multi-network pilot; no favorable synthetic result is labeled PRD success by itself.
- [ ] #7 All value accounting uses net-upstream-egress-v3 and the exact TESTING.md unit-suffixed byte fields. Every hedge request carries provenance; winner payload and losing upstream/peer hedge waste remain separate, and a truncated primary remains invalid.
- [ ] #8 The output sets policy_training_eligible=false and topology_class=development_shaped_3_node, never real_3_network, holdout, field-pilot, or PRD-success. A separate content-hashed pilot-planning artifact freezes effect/noise estimates, missingness assumptions, sample-size rationale, and stop inputs for TASK-250 without exposing or reinterpreting holdout material.
- [ ] #9 Before execution, the manifest freezes integer/rational thresholds for steady-state net cache-egress effect, A/A equivalence, paired-p95 latency, resource/budget maxima, missingness/attrition validity, repeat count, and sample-size/noise rationale. Missing or post-result thresholds invalidate the conclusion.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Consume the proven effective real-daemon concurrency result from TASK-247, the v3 provenance rule from TASK-52, and the symmetric evidence from TASK-180. TASK-120 is a required In Progress prerequisite; TASK-206 and TASK-219 are completed prerequisites. This task emits only development_shaped_3_node planning evidence. TASK-250 is the post-holdout field successor, and TASK-124 consumes the hashed planning artifact before freezing that field matrix. No favorable TASK-237 result is policy training, holdout, real_3_network, field-pilot, or PRD success.

Dropped the TASK-52 dependency 2026-08-18 (COMPASS F3, owner steer: no academic gymnastics). Hedging is UNIMPLEMENTED; TASK-247 AC#8 already mandates net-upstream-egress-v2 with hedging explicitly disabled and forbids emitting hedge evidence; TASK-52 s stated consumer is TASK-44, which is Low/deferred. Holding the value thesis hostage to an irreversible freeze for a mechanism that does not exist was the single largest self-inflicted block in the backlog. AC#7 should be rewritten to v2 hedge-off to match TASK-247.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Mandatory QA and architecture reviews pass, just build/lint/test passes, and the relevant full just e2e gate passes without retrying a failed measurement for luck.
- [ ] #2 All generated evidence is reproducible from a documented command and contains no StorePath, NarHash, peer IP, or full NodeId in normal reports.
<!-- DOD:END -->
