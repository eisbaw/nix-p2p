---
id: TASK-6
title: 'JOURNEY J1: operator substitutes, then loses the daemon'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 22:19'
labels:
  - journey
dependencies:
  - TASK-5
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
First interspersed journey (every ~5 tasks). Act as a fresh operator, not a test: start daemon with default config, run a real nix build through the chain, watch logs tell a comprehensible story, then stop the daemon and build again - fallback must feel invisible. File every rough edge found as a new backlog task; journey findings are feature work, not polish.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Journey is executable, not prose: just journey runs the operator steps; log comprehensibility is asserted (one line per substitution: path, source, bytes, duration - grep-asserted, nonzero exit on missing events)
- [ ] #2 S2 experienced AND asserted: daemon stopped mid-journey, subsequent build succeeds via fallback (request counts prove fallback served)
- [ ] #3 Friction points filed as backlog tasks, or 'none found' emitted by the journey run itself (not hand-written prose)
<!-- AC:END -->
