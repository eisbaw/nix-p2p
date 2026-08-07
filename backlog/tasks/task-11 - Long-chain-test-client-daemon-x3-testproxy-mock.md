---
id: TASK-11
title: 'Long-chain test: client -> daemon x3 -> testproxy -> mock'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-07 22:20'
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
