---
id: TASK-5
title: 'E2E harness v1: podman-pod topology + scripted scenarios'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 22:06'
labels: []
dependencies:
  - TASK-3
  - TASK-4
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Containerized harness, the canonical just e2e. Review-gate reality check (host-verified): NO docker daemon - rootless podman 5.7 pods driven directly by the scenario runner; podman-compose too partial to trust. Client image via dockerTools.buildImageWithNixDb (plain images have empty /nix/var/nix/db -> every path invalid), sandbox=false inside the container (nested userns; wave 1 only substitutes). All faults are application-level at the test proxy - no netem/NET_ADMIN (rootless cannot modprobe; nothing needs it). Counting scenarios follow the TESTING.md oracle-pairing rule: wipe client XDG_CACHE_HOME/nix, pin max-substitution-jobs=1.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just e2e runs headless and green: build fixture closure through full chain, S1 oracle asserted, exact upstream hit counts asserted
- [ ] #2 Corrupt-NAR fault scenario: build FAILS with hash error (prove-the-check-bites, TESTING.md)
- [ ] #3 Scenario runner reports per-scenario pass/fail; a failing oracle fails just e2e (blocks commits per repo policy)
- [ ] #4 Scenario runner reports per-scenario pass/fail; any failing oracle fails just e2e; just e2e-clean tears down pods reliably (Ctrl-C leak trap)
<!-- AC:END -->
