---
id: TASK-58
title: Container instruments share one podman label and tear each other down
status: To Do
assignee: []
created_date: '2026-08-09 12:21'
labels:
  - harness
  - footgun
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Every container instrument (just e2e, e2e-clean, measure, scale-sweep, profile) calls e2e.cleanup_pods(), which is scoped to the single PROJECT_LABEL 'nix-p2p-e2e=1'. Running two of them concurrently - or running e2e while a long profile/scale-sweep is in flight - makes each destroy the other's pods mid-measurement. The failure presents as a mysterious invalid sweep point or a scenario that lost its daemon, not as a collision.

Found while landing task-42 (profile_p2p): the profiling run takes ~20 minutes, which makes an accidental overlap far more likely than it was for the short instruments.

Fix direction: give each instrument RUN its own label suffix (e.g. nix-p2p-e2e=1 plus a per-run nix-p2p-run=<pid/uuid>), have cleanup_pods() default to the current run's suffix, and keep a --clean-all escape hatch for e2e-clean. A cheap interim guard is a host-wide lock file that makes the second instrument refuse to start with a clear message rather than silently corrupting both runs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 cleanup_pods() removes only the current run's pods by default; a concurrent second instrument does not disturb the first
- [ ] #2 e2e-clean retains a way to remove EVERY nix-p2p pod (the manual escape hatch)
- [ ] #3 starting a second container instrument while one is running either works cleanly or refuses with a clear message - never silently tears down the other
<!-- AC:END -->
