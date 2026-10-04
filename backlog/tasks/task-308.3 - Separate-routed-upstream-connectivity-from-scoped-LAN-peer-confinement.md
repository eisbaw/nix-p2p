---
id: TASK-308.3
title: Separate routed upstream connectivity from scoped LAN peer confinement
status: To Do
assignee: []
created_date: '2026-10-04 21:23'
labels: []
dependencies: []
parent_task_id: TASK-308
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Dogfooding exposed service RestrictNetworkInterfaces excluding the active VPN egress route, while an unrestricted client can reach the upstream. Reproduce interface-restricted upstream failure in a NixOS VM and design explicit configuration preserving intended peer scope. Do not silently permit all interfaces or deploy untested network changes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 NixOS VM proves the denied route fails and explicitly permitted routed upstream succeeds with production service confinement.
- [ ] #2 Peer discovery/publication remains within configured LAN/private scope and a negative arm enforces excluded interfaces.
- [ ] #3 Host integration requirements and any remaining deployment work are stated accurately.
<!-- AC:END -->
