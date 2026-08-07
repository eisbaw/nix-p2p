---
id: TASK-15
title: 'RE-PLAN: wave 2 planning via phase2-backlog-snowball (not feature code)'
status: To Do
assignee: []
created_date: '2026-08-07 21:56'
updated_date: '2026-08-07 22:06'
labels:
  - replan
dependencies:
  - TASK-14
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Re-plan task - not feature code. Re-invoke phase2-backlog-snowball with: the PRD (PRD.md), the current TESTING.md grounding doc, and the lessons/notes wave 1 produced (J2 baseline: egress, p95, narinfo-to-nar gap histogram; journey findings; hardening results). Plan wave 2 to the depth the new knowledge supports. Wave 2 candidates the PRD already names: DHT mechanism spike (mainline vs BEP44 vs iroh-tracker - first freeze surface, will need irreversible labels), iroh-blobs whole-NAR NarSource, peer yes/no probe protocol + rate-limiting design, hedge with throughput abort, figure revision to DHT-authoritative. TESTING.md wave-scoping checklist lists the not-yet-grounded oracles wave 2 must pull in. Write no implementation in this task. Shallow-ahead planning is deliberate: this project is experimental (PRD field), and planning past current knowledge manufactures false certainty.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Wave-2 tasks exist in the tracker, grounded in J2 baseline data
- [ ] #2 New wave ends with its own re-plan task UNLESS project reclassified firm (then full breakdown; PRD field updated)
- [ ] #3 TESTING.md updated with what wave 1 taught (baseline section + pulled-in oracles for wave 2)
- [ ] #4 Irreversible labels applied to wave-2 freeze-surface tasks per PRD map (claim schema, DHT key derivation, addressed-unit encoding)
- [ ] #5 Wave exit gate: just e2e AND just e2e-vm both green at the moment of re-planning (a gate that vanished cannot be required - task-1 stubs must be long gone)
<!-- AC:END -->
