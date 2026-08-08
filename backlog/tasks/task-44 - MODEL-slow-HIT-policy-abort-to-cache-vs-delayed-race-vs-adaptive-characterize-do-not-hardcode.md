---
id: TASK-44
title: >-
  MODEL: slow-HIT policy (abort-to-cache vs delayed-race vs adaptive) -
  characterize, do not hardcode
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
labels: []
dependencies:
  - TASK-43
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
