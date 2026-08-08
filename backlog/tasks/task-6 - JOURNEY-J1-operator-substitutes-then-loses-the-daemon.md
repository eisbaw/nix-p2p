---
id: TASK-6
title: 'JOURNEY J1: operator substitutes, then loses the daemon'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-08 09:46'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-1 (e9b3378): 'just journey' is currently a stub that exits 0 printing '0 scenarios registered - NOT a pass'. Replace it, and add a DoD check that greps for that marker and requires zero hits for journey.

--- from task-5 (80319ec): how to run a scenario as an operator journey ---
Reuse scripts/e2e_harness.py's Pod: `with Pod(ctx, "j1", fixtures.cache, with_daemon=True) as pod:` then narrate `pod.client_run([store_path], ctx.substituter_daemon_only(), fixtures.public_key)` for the substitute step, then `pod.kill("daemon")` and re-run with `ctx.substituter_daemon_and_fallback()` for the "loses the daemon" step - the ClientResult carries exit_code/stderr/path_info to narrate. Ctx + load_image()/resolve_fixtures()/cleanup_pods() are ready to import. Ports/labels/teardown are handled. J1 is essentially the s2-fallback scenario framed as a journey; start from that function.
<!-- SECTION:NOTES:END -->
