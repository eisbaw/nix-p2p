---
id: TASK-308
title: 'Dogfooding: keep Nix usable through cache failures and routed network changes'
status: In Progress
assignee: []
created_date: '2026-10-04 21:22'
labels:
  - dogfooding
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Observed on a configured client: a nonexistent narinfo returned HTTP 404 directly from the public upstream in 0.27 seconds, while the preferred local nix-p2p endpoint returned HTTP 502 after 15.30 seconds. The daemon logged a TLS connect timeout. Its service interface allowlist excluded the active upstream route. This is not evidence that an upstream 404 was translated to 502. Nix 2.31.2 has fallback=false on the affected client; metadata errors can prevent trying the healthy second substituter. Track deterministic CI reproduction first, then root-cause fixes and deployment integration. No public host identifiers or private network details belong in this task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 CI container or NixOS VM regression demonstrates the old failure with real Nix, a cold store, preferred proxy, and a healthy signed second cache.
- [ ] #2 Received 404 remains 404; genuine 502/503 stays distinguishable from absence; corrected client integration survives errors without weakening signatures.
- [ ] #3 Routed upstream access and scoped peer networking are separately specified and tested; current confinement failure is resolved or explicitly blocked.
- [ ] #4 Exact-tree CI gates and parallel QA/architecture reviews precede completion; documentation and child tasks state observed results only.
<!-- AC:END -->
