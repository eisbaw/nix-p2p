---
id: TASK-115
title: >-
  Iroh node runtime: persistent identity, one shared endpoint/router, explicit
  network profiles
status: To Do
assignee: []
created_date: '2026-08-10 22:23'
labels:
  - iroh
  - production
  - wave-2c
dependencies:
  - TASK-39
  - TASK-69
  - TASK-114
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Replace the current test-shaped endpoint lifecycle with one deployment-capable Iroh node runtime. The daemon currently creates separate ephemeral loopback-only endpoints for serving and fetching, while discovery and relay are disabled. A real node needs one persistent identity and one long-lived Endpoint/router that can host transfer and discovery ALPNs. Deterministic tests must keep an offline loopback profile; public discovery must never turn on implicitly.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A daemon state directory contains a persisted Iroh secret key with restrictive permissions; restart preserves NodeId, missing state initializes atomically, and corrupt state fails loudly instead of silently creating a new identity.
- [ ] #2 One long-lived Endpoint/router is shared by provider, fetcher and registered application protocols; serving and fetching no longer create independent ephemeral endpoints.
- [ ] #3 Explicit offline-test, LAN and global deployment profiles control bind addresses, relay and each node-discovery mechanism; the offline profile cannot contact public infrastructure and is the default in tests.
- [ ] #4 Shutdown drains or cancels in-flight streams within a numeric bound, closes the endpoint, and restart on the same state succeeds without stale-process or port artifacts.
- [ ] #5 The benchmark and daemon use the same endpoint constructor/configuration, and mutation of either side makes the TASK-69 equivalence guard fail.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Foundation for operational Iroh node and content discovery. This task owns node lifetime and identity, not content lookup policy.
<!-- SECTION:NOTES:END -->
