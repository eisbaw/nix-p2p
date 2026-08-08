---
id: TASK-47
title: 'RE-PLAN wave-2b: DHT spike, full pathological matrix, BitTorrent, policies'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
labels:
  - replan
dependencies:
  - TASK-45
  - TASK-46
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
