---
id: TASK-9
title: 'Measurement: request/byte counters + egress report + gap histogram'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-07 22:40'
labels:
  - irreversible
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
- [ ] #1 Counting rule committed as a doc next to the code: exactly what net upstream egress includes (bodies vs headers, narinfo vs nar bytes, retries, hedge losers); testproxy counters are ground truth; irreversible label rationale: the J2 baseline freezes against this definition
- [ ] #2 Report: egress + p95 for both arms, N>=10 runs per arm with variance; A/A calibration (daemon-off vs daemon-off) proves noise floor <10%, else S4 is flagged unusable in the report itself
- [ ] #3 Magnitude bite: fixed scenario asserts absolute egress equals the known sum of fixture file sizes within framing tolerance; daemon self-counters agree with testproxy ground truth within stated tolerance
- [ ] #4 Gap-oracle bite: testproxy injects a known narinfo->nar delay X; histogram reports X within tolerance and tracks a changed X
- [ ] #5 Latency bite: injected 200ms/request trips the >10% p95 flag; product-side bite: toggling the daemon narinfo cache (task-8) measurably moves narinfo egress (instrument validated against a PRODUCT change, not only the fixture)
- [ ] #6 just measure replaces the task-1 stub as a real recipe
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-1 (e9b3378): 'just measure' is currently a stub that exits 0 printing '0 scenarios registered - NOT a pass'. Replace it, and add a DoD check that greps for that marker and requires zero hits for measure.
<!-- SECTION:NOTES:END -->
