---
id: TASK-190
title: >-
  gate BLOCKER: daemon iroh_node_lookup
  'hanging_authority_is_cancelled_at_the_single_absolute_ten_second_deadline'
  hangs >5min in isolation, blocking full 'just test'
status: To Do
assignee: []
created_date: '2026-08-13 09:08'
labels:
  - infra
  - daemon
  - fabric-iroh
  - flaky
  - gate-blocker
  - verification
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The daemon crate test iroh_node_lookup::hanging_authority_is_cancelled_at_the_single_absolute_ten_second_deadline (#[tokio::test(start_paused = true)] standing up a REAL Iroh endpoint) hangs indefinitely (>5min even in isolation, no contention; qa observed 30min+ under load). Its own comment flags the paused-tokio-time vs real-socket-readiness fragility: with time paused, the Iroh network/socket never becomes ready so the 10s absolute deadline (in virtual time) does not advance to fire. Effect: 'just test' (cargo test --locked --workspace) CANNOT run to completion, so the phase3 FAST gate cannot be closed end-to-end on this host — a rung-1 verification-infra blocker. This is DISTINCT from TASK-143 (publication_authority restart flake) and TASK-177 (shutdown_cancels_an_active_lookup under pathological load): this one hangs in isolation and is a hard gate stopper. FIX options: drive the deadline off a mock/injected clock decoupled from socket readiness; or don't pause tokio time while awaiting a real endpoint (use a real short timeout); or gate the real-Iroh-endpoint test behind a feature/ignore so the workspace gate completes and run it in a dedicated networked lane. Oracle must still bite (a never-cancelled hang must fail, not hang). Found during TASK-185 re-gate.
<!-- SECTION:DESCRIPTION:END -->
