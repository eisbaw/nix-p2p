---
id: TASK-47
title: 'RE-PLAN wave-2b: DHT spike, full pathological matrix, BitTorrent, policies'
status: Done
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-10 22:57'
labels:
  - replan
  - superseded
dependencies:
  - TASK-15
  - TASK-42
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Re-plan task - NOT feature code. Re-invoke phase2-backlog-snowball with: PRD.md (Wave 2 scope), TESTING.md (wave-2 grounding + what wave-2a taught), and the wave-2a lessons/notes (S6 result, profiling numbers, the slow-HIT policy model, pathological findings, task-35 real-gap). Plan wave-2b to the depth wave-2a knowledge now supports. Wave-2b candidates: the DHT mechanism SPIKE (mainline vs BEP44 vs iroh-native - the frozen DHT-key-derivation surface) + full discovery; the REST of the S8 pathological matrix (NAT/relay, thundering-herd single-flight, lying-claim scoring, seeder-churn); the chosen slow-HIT policy implementation + other policies the models exposed; the BitTorrent transport (2nd backend, proving the transport tag); scale profiling to 1000s (S5 extrapolation); chunked/castore (Candidate C); v2 signed-narinfo-relay (outage resilience). Write no implementation here. Shallow-ahead planning is deliberate: the DHT spike outcome reshapes discovery, so planning past it now manufactures false certainty.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Wave-2b tasks exist in the tracker, grounded in wave-2a data (S6 + profiling + policy model + task-35)
- [ ] #2 Wave-2b ends with its own re-plan task unless the project is now firm enough for a full breakdown
- [ ] #3 TESTING.md updated with what wave-2a taught (S6 outcome, profiling baseline, policy finding, pathological coverage)
- [ ] #4 Irreversible labels applied to wave-2b freeze tasks (DHT key derivation; any addressed-unit change)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
SCOPE UPDATE 2026-08-09 (owner: 'file the gaps as backlog tasks if not already'): the items this re-plan bundled in its description are now FILED as real tasks, so the re-plan's job narrows from 'invent the wave-2b list' to 'order, scope and gate what already exists'. Filed: TASK-73 (DHT-authoritative resolution - the discovery gap, incl. the DHT-key-derivation freeze this task's spike must feed), TASK-74 (gossip accelerant, must remain non-required), TASK-75 (BitTorrent second transport, doubles as a falsification test of the claim-schema freeze), TASK-76 (speculative prefetch - tail-only per task-35), TASK-77 (announce-after-fetch + budget), TASK-78 (leech mode), TASK-79 (pathological suite v2: NAT/relay, thundering herd, lying claim, seeder churn), TASK-80 (real-network validation - the one thing the single-host testbed structurally cannot answer), TASK-81 (verify the Candidate C castore seam is still open). Policy IMPLEMENTATION is deliberately NOT filed - TASK-44 files it as its own output once the data justifies a choice.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed by supersession on 2026-08-11: the wave-2b candidates were already decomposed into TASK-73 through TASK-81 and follow-on discovery tasks. This records planning completion only, not feature completion.
<!-- SECTION:FINAL_SUMMARY:END -->
