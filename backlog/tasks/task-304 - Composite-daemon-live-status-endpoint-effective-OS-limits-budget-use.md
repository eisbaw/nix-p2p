---
id: TASK-304
title: Composite daemon live-status endpoint (effective OS limits + budget use)
status: To Do
assignee: []
created_date: '2026-08-22 13:12'
labels:
  - production
  - operator
  - observability
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-120 AC#3 follow-up (codex): the composite 'daemon' binary (the flake DEFAULT + the NixOS module's package) ships NO live --status endpoint (deferred at daemon/src/main.rs; only the thin daemon-libp2p binary has one). So a NixOS operator running the default package cannot see the running service's live effective RLIMIT_NOFILE / cgroup MemoryMax / budget use from the daemon itself; today its --preflight honestly says 'live-status: NONE' and points to systemctl. Add a minimal live-status HTTP surface to the composite (parity with daemon-libp2p): node id, budget use, and effective_rlimit_nofile + effective_cgroup_memory_max read from the running process, plus announce_after_fetch_budget. Until then the composite preflight must not imply live values it cannot expose (already fixed).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The composite daemon exposes a live --status endpoint at parity with daemon-libp2p, including effective_rlimit_nofile + effective_cgroup_memory_max read from the running process
- [ ] #2 An e2e/integration check drives the composite --status and asserts the live OS-limit lines are present and match the running service
<!-- AC:END -->
