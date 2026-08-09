---
id: TASK-79
title: >-
  Pathological scenario suite v2: NAT/relay, thundering herd, lying claim,
  seeder churn
status: To Do
assignee: []
created_date: '2026-08-09 21:02'
updated_date: '2026-08-09 21:02'
labels:
  - wave-2b
dependencies:
  - TASK-43
  - TASK-66
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The four TESTING.md S8 rows that TASK-43 (v1: slow-HIT, dead-holder, cold-start) explicitly deferred and named in its own honest-limits AC. Filed as real tasks rather than living only inside TASK-47's re-plan description. Each row already has a defined good/bad in TESTING.md S8 - use those, do not invent new ones.

- NAT-BLOCKED PEER: good = relay path used, or peer skipped fast; bad = undialable peer stalls the fetch. Note iroh has relay + holepunching, and the current test endpoints are bound loopback with the RELAY DISABLED and no discovery (transport_iroh.rs bind_loopback_endpoint) - so this scenario needs a topology that can actually exercise the relay, which the current single-host container setup cannot fully provide (see TASK-80).
- THUNDERING HERD on a popular path: good = bounded fan-out, no self-DoS, single-flight per path; bad = N concurrent identical fetches. Note TASK-23 already tracks single-flight for the testproxy; the daemon-side p2p equivalent does not exist.
- LYING / SPAM CLAIM: good = the NarHash gate rejects, wasted dials bounded, peer scored down; bad = an attacker-chosen huge blob downloaded in full before the gate. The streaming NarSize abort (TASK-51) already bounds the huge-blob case on the FETCH side; peer SCORING does not exist at all.
- SEEDER CHURN: good = resolution tolerates holders joining/leaving, no wrong bytes; bad = churn causes a wrong-bytes serve or a crash. Needs multi-holder (TASK-66) to be meaningful.

Severity calibration: the daemon and peers are OUTSIDE the trust base and nix re-verifies sig+NarHash, so none of these can produce wrong bytes in the store - they are availability/robustness failures. Do not inflate them to integrity bugs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each of the four scenarios runs in the harness and asserts its S8 good-row behaviour with a bite that fails if the daemon hangs, self-DoSes, or degrades unboundedly - plus a per-cell fault-OFF baseline so the bite is non-vacuous
- [ ] #2 Peer scoring exists at least minimally: a peer that serves a failing claim is demoted, and the demotion is observable and bounded (no permanent ban from one failure)
- [ ] #3 Single-flight per path on the p2p fetch path: N concurrent requests for the same NarHash produce ONE peer fetch, proven by a provider-side counter
- [ ] #4 Each scenario emits its cost (added latency, wasted bytes, RAM) into the profiling report, and honest limits name what the single-host testbed could not exercise (esp. real NAT/relay - see TASK-80)
<!-- AC:END -->
