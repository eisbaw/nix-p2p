---
id: TASK-9
title: 'Measurement: request/byte counters + egress report + gap histogram'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
labels: []
dependencies:
  - TASK-5
  - TASK-8
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The instrument the kill criterion depends on (PRD: <20% net egress cut kills p2p thesis; TESTING.md S3/S4). Test proxy byte counters are ground truth; daemon exports its own counters (JSON or prometheus text) but is measured, not trusted. Harness scenario runs an identical scripted workload daemon-on vs daemon-off and emits a report: net upstream egress, p95 build wall-clock, and the narinfo-to-nar gap histogram (empirical input for the DHT wave, PRD risk 3).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just measure (or e2e scenario) emits machine-readable report: egress bytes both arms, p95 wall-clock both arms, gap histogram
- [ ] #2 Bite test: test-proxy cache on vs off changes reported egress in the expected direction (S3)
- [ ] #3 Latency bound check implemented: report flags p95 regression > 10% (S4) as failure
<!-- AC:END -->
