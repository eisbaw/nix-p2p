---
id: TASK-283
title: >-
  Discovery-latency measurement: build the measure-discovery-latency scenario +
  mDNS/kad integer-ms instrumentation (fix the dangling just discovery-latency
  recipe)
status: To Do
assignee: []
created_date: '2026-08-20 14:54'
labels:
  - measurement
  - testing
dependencies:
  - TASK-272
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
COMPASS value-measurement item, now enabled by TASK-272 (the composite RUST_LOG subscriber). At HEAD the just discovery-latency recipe (Justfile:363) runs --only measure-discovery-latency but that scenario DOES NOT EXIST, there is NO mDNS/kad discovery-latency instrumentation, and evidence/task-272/ + the docs/profiling.md discovery-latency section reference numbers that were never produced. Answers PRD risk-3 (discovery latency, seconds-scale, could dominate small-package fetches and flip the peer-vs-CDN verdict).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Instrument the shipped discovery path to emit INTEGER-millisecond latencies via tracing (no floats): mDNS peer-discovery elapsed + kad get_providers elapsed, labelled with provenance (which node, which query)
- [ ] #2 Implement the measure-discovery-latency e2e scenario (reuse the zero-bootstrap mDNS topology + RUST_LOG=info passthrough into containers) that drives a real discovery + captures the integer-ms numbers to evidence/task-272/ with the raw daemon logs; the just discovery-latency recipe runs it green (no longer dangling)
- [ ] #3 Report the captured numbers (mDNS + kad, integer ms, provenance-labelled) in docs/profiling.md; state the container/loopback caveat (real-network discovery latency is TASK-268/237/282, not this containerized floor)
- [ ] #4 Bite: the scenario fails/nulls if the instrumentation or the composite RUST_LOG subscriber is removed (proves it measures the real path, not a hardcoded value)
<!-- AC:END -->
