---
id: TASK-222
title: ruff format drift on 3 scripts breaks just lint (pre-existing)
status: Done
assignee: []
created_date: '2026-08-15 19:35'
updated_date: '2026-08-17 13:09'
labels:
  - chore
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
just lint fails at 'ruff format --check scripts': scripts/check-discovery-no-shortcut.py, scripts/shaped_compress.py, scripts/task203_pipelined_measure.py would be reformatted. These files are byte-identical to HEAD (confirmed via git diff HEAD) and unrelated to any single change - the drift predates TASK-110 and was surfaced while gating it. cargo fmt/clippy/source-guards are all green; only ruff format bites. Fix: run 'nix develop -c ruff format scripts' and commit the formatting-only diff, then verify just lint is green. Keep it a standalone formatting commit (no logic changes to task203/shaped_compress mid-flight).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Re-surfaced during TASK-68 under ruff 0.15.14: the drifting set is now FOUR files - the three listed plus scripts/e2e_harness.py. profile_p2p.py was also in the set but was reformatted as part of TASK-68 (it was already being edited), so it is no longer drifting. Remaining for the standalone format-only sweep: check-discovery-no-shortcut.py, e2e_harness.py, shaped_compress.py, task203_pipelined_measure.py.

DONE. ruff format scripts (4 files: check-discovery-no-shortcut, e2e_harness, shaped_compress, task203_pipelined_measure — e2e_harness drifted in after filing). Formatting-only, no logic. just lint green: ruff format --check rc0 + ruff check rc0. Discovery guard self-test + real-scan still rc0 post-format.
<!-- SECTION:NOTES:END -->
