---
id: TASK-11
title: 'Long-chain test: client -> daemon x3 -> testproxy -> mock'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-08 09:46'
labels: []
dependencies:
  - TASK-5
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRD round-5 requirement: proxy composition must survive depth. Chain at least three product daemons; assert S1 byte identity, no header/metadata mangling (content-type, content-length vs chunked, compression fields untouched), bounded added latency (timeouts must not multiply per hop), and clean fallback when a middle daemon is killed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Depth-3 chain green: S1 + exact per-hop request counts; scenario exercises BOTH compression encodings (none + xz) and 404 fidelity at depth
- [ ] #2 Timeout invariant: client-visible failure time at depth 3 approximately equals depth 1 (must NOT scale with depth); per-hop added-latency bound fixed BEFORE implementation at 50ms/hop local (changed only by a recorded review note, never post-hoc to fit results)
- [ ] #3 Kill middle daemon mid-run: client build still succeeds; failure mode visible in logs
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
--- from task-5 (80319ec): chaining N daemons ---
Pod currently starts ONE daemon (--upstream testproxy). To chain client -> d1 -> d2 -> ... -> dN -> testproxy: start N daemon containers in the pod on distinct ports (8082, 8083, ...), each --upstream the NEXT one's http://127.0.0.1:PORT, the last --upstream the testproxy. Generalise Pod with a daemon_chain=N param (a small loop over the existing daemon-run block); bind each 0.0.0.0 (the port-forward gotcha) and publish only the ones you assert on. Client substituter = the FIRST daemon (?priority=10). S1 byte oracle must hold end-to-end (NarHash == manifest through N hops); added-latency bound is the S4 oracle from task-9's counters (gap_ms accumulates per hop). The daemon is a transparent passthrough with no disk cache (wave 1), so a repeat still shows upstream==0 only at the testproxy layer, not the daemons.
<!-- SECTION:NOTES:END -->
