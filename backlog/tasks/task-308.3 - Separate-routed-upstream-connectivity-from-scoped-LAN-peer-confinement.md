---
id: TASK-308.3
title: Separate routed upstream connectivity from scoped LAN peer confinement
status: To Do
assignee: []
created_date: '2026-10-04 21:23'
updated_date: '2026-10-04 22:06'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CI capability check: the existing VM truth-layer workflow requires a self-hosted runner labeled kvm. Repository runner inventory returned total_count=0. The GitHub-hosted Podman regression for metadata/client fallback remains independently runnable. No restricted-interface VM result and no network-confinement fix/deployment are claimed.
<!-- SECTION:NOTES:END -->
