---
id: TASK-43
title: 'Pathological scenario suite v1: slow-HIT, dead-holder, cold-start'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
labels: []
dependencies:
  - TASK-42
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The first cut of the S8 pathological matrix (the rest deferred to wave-2b re-plan). Using the testproxy throttle (mode 8) + iroh peer control: (1) slow/throttled peer on a HIT; (2) dead/unreachable holder after a positive claim; (3) DHT/discovery cold-start empty index. Each asserts the S8 good behavior (bounded time, correct fallback, never wrong bytes, never unbounded hang) and FEEDS the profiling harness (task-F) with the resource/latency cost. Findings drive policy (task-H).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each of the 3 scenarios runs in the harness and asserts its S8 good-row behavior with a bite (the assertion fails if the daemon hangs/serves-wrong/unbounded)
- [ ] #2 Each scenario emits its profiling cost (added latency, wasted bytes, RAM) into the task-F report
- [ ] #3 Honest limit: which pathological cases are NOT yet covered (NAT, herd, lying-claim, churn) named for the wave-2b re-plan
<!-- AC:END -->
