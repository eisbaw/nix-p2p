---
id: TASK-222
title: ruff format drift on 3 scripts breaks just lint (pre-existing)
status: To Do
assignee: []
created_date: '2026-08-15 19:35'
labels:
  - chore
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
just lint fails at 'ruff format --check scripts': scripts/check-discovery-no-shortcut.py, scripts/shaped_compress.py, scripts/task203_pipelined_measure.py would be reformatted. These files are byte-identical to HEAD (confirmed via git diff HEAD) and unrelated to any single change - the drift predates TASK-110 and was surfaced while gating it. cargo fmt/clippy/source-guards are all green; only ruff format bites. Fix: run 'nix develop -c ruff format scripts' and commit the formatting-only diff, then verify just lint is green. Keep it a standalone formatting commit (no logic changes to task203/shaped_compress mid-flight).
<!-- SECTION:DESCRIPTION:END -->
