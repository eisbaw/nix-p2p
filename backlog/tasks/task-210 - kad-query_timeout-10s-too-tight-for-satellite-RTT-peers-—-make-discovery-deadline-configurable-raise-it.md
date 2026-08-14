---
id: TASK-210
title: >-
  kad query_timeout (10s) too tight for satellite-RTT peers — make discovery
  deadline configurable / raise it
status: To Do
assignee: []
created_date: '2026-08-14 19:07'
labels:
  - connectivity
  - libp2p
  - measurement
  - finding
dependencies:
  - TASK-209
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-209's RTT sweep of kad DISCOVERY over a tc-netem-shaped link (host-side RTT asserted at every point; shaping confirmed to ~3.7s RTT) found the fabric-libp2p kad query_timeout (Duration::from_secs(10), swarm.rs) starts MISSING under plausible real-world RTT. Measured breaking points (3-node topology, bootstrap+provider in ns A, consumer in ns B; each get_providers/get_closest_peers query bounded by the 10s kad query_timeout): a SINGLE one-shot discovery held to 250ms one-way (~733ms RTT, 8.5s) but at 500ms one-way (~1.7s RTT) the FIRST get_providers query exceeded 10s and needed a retry (24s to resolve); with retries it still eventually resolved at 500ms but was fully UNRESOLVED at 750ms one-way (~2.7s RTT, every attempt DeadlineExceeded). Discovery latency grew steeply super-linearly with RTT (20ms->0.65s, 100ms->3.6s, 250ms->8.5s, 500ms->24s). REAL-WORLD RELEVANCE: GEO-satellite peers (~600ms one-way / ~1.2s RTT) land squarely in the single-shot danger zone; residential/WAN (20-250ms) are fine. So a one-shot consumer lookup on a satellite uplink can silently DeadlineExceed. RECOMMENDATION: make the discovery/locate deadline configurable (and the kad query_timeout), OR raise the default (e.g. 20-30s), OR document that discovery on >500ms-one-way links requires application-level retry (the harness already shows retry rescues up to 500ms). Evidence: scripts/shaped_kad.py --sweep (reproducible via 'just shaped-kad --sweep'); example fabric-libp2p/examples/shaped_kad_probe.rs. NOTE: emulated link (mean RTT + rate cap; NOT loss/jitter/cross-traffic) — removes the loopback bound, not a field measurement.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The kad discovery/locate deadline (and/or kad query_timeout) is configurable OR raised so a single-shot discovery resolves at >=600ms one-way RTT (GEO-satellite)
- [ ] #2 A regression asserts the chosen budget holds at the target RTT over the shaped-kad sweep, with the host-side shaping oracle firing
- [ ] #3 If left as retry-dependent instead of raised, the >500ms-one-way retry requirement is documented at the discovery API
<!-- AC:END -->
