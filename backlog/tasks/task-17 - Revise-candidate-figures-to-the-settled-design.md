---
id: TASK-17
title: Revise candidate figures to the settled design
status: To Do
assignee: []
created_date: '2026-08-07 22:06'
labels:
  - docs
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRD open question 3 calls the stale figures a phase-2 onboarding blocker, so it belongs in wave 1, not deferred (review-gate finding). Update fig-candidate-B (and C where touched) to match settled decisions: DHT-authoritative resolution with peer yes/no probes, announce-on-demand, no-enumeration privacy invariant, gossip as accelerant only, raw-NAR addressed unit. The figures must stop teaching implementers the superseded gossip-first/tracker design.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 fig-candidate-B matches PRD settled decisions (checklist in task: DHT-authoritative, peer probes, announce-on-demand, no-enumeration, raw NAR)
- [ ] #2 Stale-figure warning removed from PRD risk list in the same commit
<!-- AC:END -->
