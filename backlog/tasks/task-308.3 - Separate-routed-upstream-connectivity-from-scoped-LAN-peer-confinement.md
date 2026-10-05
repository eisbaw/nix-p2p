---
id: TASK-308.3
title: Separate routed upstream connectivity from scoped LAN peer confinement
status: In Progress
assignee: []
created_date: '2026-10-04 21:23'
updated_date: '2026-10-05 08:08'
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
- [ ] #4 With NIX_CONFIG unset, fresh ordinary fetches avoid preferred-cache 502 retries and the roughly 33-second regression; record latency against direct upstream without masking primary failure.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CI capability check: the existing VM truth-layer workflow requires a self-hosted runner labeled kvm. Repository runner inventory returned total_count=0. The GitHub-hosted Podman regression for metadata/client fallback remains independently runnable. No restricted-interface VM result and no network-confinement fix/deployment are claimed.

Post-deployment ordinary-fetch check, with NIX_CONFIG explicitly unset and configured substituters unchanged: figlet and cmatrix were physically absent and invalid before realization. Both nix-store --realise commands exited 0 after downloading from cache.nixos.org (32s and 33s), then nix-store --verify-path passed; cmatrix -V ran successfully. Both first printed preferred localhost 502 errors/retries. This proves usable client recovery, not repaired daemon upstream connectivity. The routed-interface issue remains open.

Owner requested elimination of the observed fetch latency. Architecture review supports an opt-in independent loopback upstream-only service: peer daemon retains interface confinement, HTTP egress follows normal routing, direct Nix fallback remains the configured external cache. Investigating a dedicated GitHub-hosted KVM job rather than treating the old self-hosted runner restriction as universal. Test execution is pending; no routed-egress fix is claimed yet.

Added a test-first three-node NixOS VM regression and hosted KVM CI job. Narrow Nix evaluation passed; no VM was run locally. The old confined process is a control; the future opt-in helper will be enabled only on the positive client. Runtime input-addressed origin builds, primary-only untrusted Nix realization, foreign-signature rejection, permitted/forbidden peer ingress and helper-outage fallback are asserted. CI runtime reproduction is still pending. The draft CI bootstrap exception is required because E2E belongs in CI; no pre-commit E2E pass is claimed for this test-first tree.
<!-- SECTION:NOTES:END -->
