---
id: TASK-106
title: >-
  resolve_many has no TOTAL deadline: 8 peers x 4 chunks x 5 s = ~31 min worst
  case
status: To Do
assignee: []
created_date: '2026-08-10 14:06'
labels:
  - wave-2b
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by the TASK-91 DEEP gate (mped-architect M1), deferred there deliberately to keep that cycle bounded.

DirectDiscovery::resolve_many bounds each PROBE at PROBE_TIMEOUT (5 s) but bounds NOTHING in aggregate. A 1000-path closure chunks to 4 probes per peer; with 8 configured peers that is 32 sequential probes, so a set of silent peers costs 8 x 4 x 5 s = ~160 s per resolve_many call, and a pathological configuration reaches ~31 minutes. The whole point of PROBE_TIMEOUT is that a miss must not leak latency into the Nix build path; batching multiplied the number of bounded waits without adding a bound over their sum.

It also CONTRADICTS a rule the same file already states: PeerQuery::query_batch documents that a per-PEER fault propagates rather than burning the other 255 keys, because retrying against a peer we cannot reach is pure waste. resolve_many does the opposite - it logs the failed chunk and continues to the next chunk against the SAME peer.

WHAT IS NEEDED
- A total deadline for one resolve_many call (the closure resolution is on the build path; the caller has a budget, not the individual probe).
- On a per-PEER fault, abandon that PEER's remaining chunks rather than the current chunk only - matching the rule query_batch already states.
- Decide whether peers should be probed CONCURRENTLY; today they are strictly sequential, which is also why the AC#3 baseline is the most naive possible one.

This lands with TASK-100 because that task re-shapes the same call: do not inherit the assumption that a per-probe bound is a bound.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 resolve_many is bounded in TOTAL, not only per probe, and the bound is asserted by a test with N silent peers
- [ ] #2 A per-PEER fault abandons that peer's remaining chunks, matching the rule query_batch already documents
- [ ] #3 The sequential-vs-concurrent peer decision is made explicitly and written down, not left implicit
<!-- AC:END -->
