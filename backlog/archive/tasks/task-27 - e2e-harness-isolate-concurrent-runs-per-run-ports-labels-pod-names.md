---
id: TASK-27
title: 'e2e harness: isolate concurrent runs (per-run ports/labels/pod names)'
status: To Do
assignee: []
created_date: '2026-08-08 10:24'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deferred finding from task-5 deep gate (vacuous-oracle fix round). The e2e harness uses GLOBAL fixed host ports (18080/18081/18082), a single PROJECT_LABEL, and fixed pod names, so two concurrent 'just e2e' runs (e.g. parallel CI jobs on one host) collide. This fails NONZERO (port bind clash / pod-name clash), not false-green, so it is not gate-breaking - filed for CI robustness rather than fixed in the functionality round. Fix: derive host ports from an offset (e.g. base + PID%N or an ephemeral-port probe), suffix the label/pod names with a per-run token, and have e2e-clean scope to that token. Keep the label prefix so a blanket clean still works.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Two 'just e2e' runs on one host do not collide (distinct ports, pod names, labels)
- [ ] #2 e2e-clean removes only the invoking run's pods by default, with an --all escape hatch
<!-- AC:END -->
