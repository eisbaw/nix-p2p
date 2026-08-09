---
id: TASK-43
title: 'Pathological scenario suite v1: slow-HIT, dead-holder, cold-start'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-09 01:33'
labels: []
dependencies:
  - TASK-42
  - TASK-51
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION (arch#3/qa#4/codex#5): (1) The slow-HIT policy does NOT exist at task-43 runtime (task-44 models it, later task implements). So task-43 asserts ONLY the WEAK invariant - never unbounded-hang, never wrong bytes - via the task-51 conservative safety envelope (dep added). Do NOT assert 'policy fires'. (2) PIN numeric bounds; add a per-cell FAULT-OFF baseline (like the wave-1 fault x depth matrix) so the bite bites. (3) Rename 'DHT cold-start' -> 'minimal-discovery cold-start' (no DHT in wave-2a, codex#7). (4) Collects traces to FEED task-44's policy model.

FORWARD-CARRY from task-51: the pathological suite should assert the envelope bounds as the FLOOR (never unbounded-hang, never OOM, never wrong bytes). Good rows already proven in daemon/tests/iroh_safety_envelope.rs and reusable as models: slow-HIT/stalled-peer -> bounded abort (body-idle) -> upstream fallback; dead-holder -> bounded dial-timeout failure; oversized-blob (> signed NarSize) -> streaming TooLarge abort with memory bounded (streamed << blob). Injection points for the suite: IrohTransport::with_envelope(short bounds) for determinism; a stalling ProtocolHandler (accept then sleep) for the mid-transfer stall; a black-hole UDP socket + IrohPeerAddr::new(validNode, deadAddr) for the dead holder; seed a big NAR + fetch with a small expected_size for the NarSize abort. Bites were validated by mutation (neutralize cap / enlarge the specific bound -> falls to coarse backstop). These are the PROVISIONAL floor, not task-44's tuned policy.
<!-- SECTION:NOTES:END -->
