---
id: TASK-136
title: ADMIT LAN only after global Iroh pass; re-plan on global no-go
status: To Do
assignee: []
created_date: '2026-08-11 05:53'
updated_date: '2026-08-11 19:52'
labels:
  - iroh
  - discovery
  - global
  - gate
  - re-plan
  - wave-2c
dependencies:
  - TASK-133
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Admission and sole re-plan task. Read TASK-133 global-iroh-review-v1. On pass emit the admission artifact TASK-130 requires. On failure re-run phase2 backlog planning from the evidence and rewire TASK-130 to a new reviewed pass gate before completion. Central tracker success or task completion alone never admits LAN.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Pass verifies TASK-133 schema final tree TASK-132 evidence both reviewer verdicts all required mutations and budget hash before emitting global-iroh-pass-v1.
- [ ] #2 The admission artifact records passing decentralized NAR-to-provider discovery public NodeId resolution and Iroh transfer with tracker disabled. Tracker or partial DHT results cannot satisfy it.
- [ ] #3 TASK-130 validates the current admission artifact hash and rejects completion-only stale fabricated central-only and no-go inputs.
- [ ] #4 A failure emits no token and invokes phase2 exactly once to create and wire a successor reviewed pass gate before this task can complete as superseded.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Only the mandatory decentralized global pass admits LAN. Optional tracker measurements and tournament artifacts are non-qualifying comparison data.
<!-- SECTION:NOTES:END -->
