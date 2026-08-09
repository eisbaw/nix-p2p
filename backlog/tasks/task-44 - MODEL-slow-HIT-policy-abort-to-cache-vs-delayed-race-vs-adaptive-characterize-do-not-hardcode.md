---
id: TASK-44
title: >-
  MODEL: slow-HIT policy (abort-to-cache vs delayed-race vs adaptive) -
  characterize, do not hardcode
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-09 01:33'
labels: []
dependencies:
  - TASK-43
  - TASK-52
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The owner-named policy archetype. Do NOT hardcode a policy - MODEL the three candidates under the slow-peer-HIT scenario (task-G) and report which wins on wall-clock + net egress (hedge losers counted in the reserved hedge_waste channel): (a) abort-to-cache after T; (b) delayed-race/hedge (start cache fetch, first past the NarHash gate wins, cancel loser); (c) adaptive (abort if throughput < X for T). Then FILE the chosen-policy implementation as its own task grounded in this data. This is design-for-data, per the owner goal.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The 3 candidates measured under the slow-peer scenario: wall-clock + net egress (incl hedge_waste) reported per candidate, with the threshold sensitivity (T, X) swept
- [ ] #2 A recommendation with the data behind it; the chosen policy filed as a NEW implementation task (not implemented here)
- [ ] #3 Honest limit: loopback/container throughput is not residential-uplink; the model states what real-network validation it still needs
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION (qa#1/arch#6/codex#7 + task-35): (1) DEPENDS ON task-52 (counting-rule v3) - v2 CANNOT measure hedge (every hedge run is INVALID/fail-closed; hedge-loser indistinguishable from truncated primary). Without v3 this task produces unfalsifiable numbers deciding the core latency mechanism. (2) task-35 GROUNDING: hedge is the PRIMARY offload mechanism (real gap 300ms-3s, prefetch viable ONLY on the tail of large closures, never the head/small builds). So the model is 'hedge tuning + when-to-prefetch-on-the-tail', not prefetch-vs-hedge. (3) Trace-model oracle cases with KNOWN winners (validate the model picks the right one); declared sweep ranges for T/X; cache-only AND peer-only baselines; 'NO candidate justified' is a VALID outcome. (4) hedge_waste bytes from task-52's provenance-tagged channel. Stale-ref: 'task-G'=task-43.

FORWARD-CARRY from task-51: the conservative safety envelope is the PROVISIONAL DEFAULT your policy model replaces/measures against. Current default slow-HIT behavior = bounded abort -> fall back to upstream (the simplest safe thing; NO hedge/delayed-race/adaptive). Knobs to model: SafetyEnvelope{dial_timeout=10s, body_idle_timeout=10s, total_timeout=60s} (all PROVISIONAL, injectable via IrohTransport::with_envelope) + the streaming NarSize cap (a safety invariant, NOT a tunable - keep it). The floor task-43 asserts is your lower bound: whatever policy you pick must still never unbounded-hang, never OOM, never serve wrong bytes. The NarSize bound is the SIGNED NarSize (uncompressed), never FileSize. Measure your model against this default as the baseline.
<!-- SECTION:NOTES:END -->
