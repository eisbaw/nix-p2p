---
id: TASK-11
title: 'Long-chain test: client -> daemon x3 -> testproxy -> mock'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-07 22:06'
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
- [ ] #1 Depth-3 chain green with S1 oracle and exact per-hop request counts asserted
- [ ] #2 Latency budget asserted: chain adds < a stated per-hop bound (documented in scenario)
- [ ] #3 Kill middle daemon mid-run: client build still succeeds; failure mode visible in logs
- [ ] #4 Kill middle daemon mid-run: client build still succeeds; failure mode visible in logs
<!-- AC:END -->
