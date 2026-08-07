---
id: TASK-5
title: 'E2E harness v1: compose topology + scripted scenarios'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
labels: []
dependencies:
  - TASK-3
  - TASK-4
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Containerized harness, the canonical just e2e: client (real nix, controlled nix.conf: daemon as only/preferred substituter + test public key), daemon, test proxy, mock upstream. Scenario runner asserting via TESTING.md oracles (request-count, byte, build). Compose flavor first for fast iteration and network shaping; VM layer is a separate task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just e2e runs headless and green: build fixture closure through full chain, S1 oracle asserted, exact upstream hit counts asserted
- [ ] #2 Corrupt-NAR fault scenario: build FAILS with hash error (prove-the-check-bites, TESTING.md)
- [ ] #3 Scenario runner reports per-scenario pass/fail; a failing oracle fails just e2e (blocks commits per repo policy)
<!-- AC:END -->
