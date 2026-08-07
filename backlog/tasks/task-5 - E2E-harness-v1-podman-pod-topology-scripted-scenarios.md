---
id: TASK-5
title: 'E2E harness v1: podman-pod topology + scripted scenarios'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
updated_date: '2026-08-07 22:40'
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
- [ ] #1 just e2e green headless on rootless podman (no docker daemon): fixture closure through full chain, S1 byte oracle + exact per-layer request counts (client nix cache wiped; max-substitution-jobs=1 in counting scenarios)
- [ ] #2 nix.conf topology pinned: daemon (priority<40) AND mock/testproxy as explicit direct fallback substituter; S2 scenarios assert the fallback actually served the bytes via request counts, not merely exit 0
- [ ] #3 Corrupt-NAR scenario: build FAILS with hash error (bite); 404-fidelity scenario: absent path -> 404 at the client, build proceeds, substituter NOT marked failed
- [ ] #4 Scenario runner reports per-scenario pass/fail; any failing oracle fails just e2e; just e2e-clean tears down pods reliably (Ctrl-C leak trap)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
forward-carried from task-1 (e9b3378): the flake exposes packages.x86_64-linux.daemon and .testproxy (crane-built, single binary each at bin/<name>, meta.mainProgram set, so 'nix run .#daemon' works). Consume THOSE for dockerTools images - do not re-derive builds. 'just package' prints both store paths. Renaming those attribute names breaks you and task-10, so treat them as an interface. When this task lands, DELETE the 'just e2e' stub: it currently exits 0 while printing '0 scenarios registered - NOT a pass'. Add a check to your DoD that greps the repo for that marker string and requires zero hits for e2e.
<!-- SECTION:NOTES:END -->
