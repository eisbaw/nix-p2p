---
id: TASK-244
title: >-
  scripts/ ruff-format drift: 4 files fail ruff 0.15.14 format --check, just
  lint red on master
status: To Do
assignee: []
created_date: '2026-08-17 13:04'
labels:
  - tooling
  - lint
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Pre-existing, discovered during TASK-68. Under the pinned devshell ruff (0.15.14), 'ruff format --check scripts' reports 4 committed files as needing reformat, so 'just lint' exits 1 independent of any feature change: scripts/check-discovery-no-shortcut.py, scripts/e2e_harness.py, scripts/shaped_compress.py, scripts/task203_pipelined_measure.py. These were last touched by TASK-242/earlier and drifted when ruff was bumped (the formatter's line-wrapping changed). profile_p2p.py was in the same set and was reformatted as part of TASK-68 since it was already being edited; the remaining 4 are untouched by TASK-68 and left for a dedicated pure-format sweep so a measurement-honesty commit does not absorb repo-wide churn. Fix: run 'ruff format scripts' in the devshell and commit as an isolated format-only change (no logic), then confirm 'just lint' is green. Verify no self-test regresses (each script has its own --self-test).
<!-- SECTION:DESCRIPTION:END -->
