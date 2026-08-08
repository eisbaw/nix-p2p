---
id: TASK-16
title: >-
  Baseline read-out: run the measurement, record it, proceed to wave 2 (NOT a
  kill gate)
status: To Do
assignee: []
created_date: '2026-08-07 22:06'
updated_date: '2026-08-08 12:46'
labels:
  - checkpoint
dependencies:
  - TASK-12
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision task, not code (inserted at review gate: hardening a product whose prefetch-window premise just died is planned waste). With the J2 baseline and gap histogram in hand, the owner answers: does the narinfo->nar gap leave room to mask DHT resolution (PRD risk 3)? Do egress numbers make the 20% kill criterion plausibly reachable once p2p exists? Outcome: continue (hardening + wave-2 planning proceed), adjust (re-plan scope changes), or stop (kill criterion logic applies early).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Decision recorded via backlog decision log citing baseline numbers: continue / adjust / stop
- [ ] #2 If adjust or stop: task-15 re-plan scope updated BEFORE any hardening work starts
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Owner standing intent (2026-08-08, pre-baseline): 'implement entire backlog - first full-NAR decentralized, then ca-chunked; iroh first prio.' This leans continue, but the checkpoint still runs: the J2 baseline (gap histogram, egress) gets surfaced to the owner before the p2p wave is planned, per PRD kill-criterion discipline.

Owner directive (2026-08-08): do not ask the owner - when this checkpoint is reached, route the GO/NO-GO decision through an mped-architect subagent framed as Mark-emulator (give it the J2 baseline, PRD kill criterion, and owner standing goals), record the verdict here, and proceed. Owner can override asynchronously.

SCOPE CHANGE (owner, 2026-08-08): 'dont worry about kill criterion keep going, but do the measurement.' This is NO LONGER a GO/NO-GO kill decision - the owner proceeds to the p2p wave regardless of the baseline. Recast: run task-9's instrument, record the baseline (egress, p95, gap histogram) into TESTING.md for later comparison and tuning, then hand to task-15 wave-2 planning. No mark-emulator kill decision needed; keep going by directive.
<!-- SECTION:NOTES:END -->
