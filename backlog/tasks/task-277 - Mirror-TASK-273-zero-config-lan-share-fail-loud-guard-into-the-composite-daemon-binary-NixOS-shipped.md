---
id: TASK-277
title: >-
  Mirror TASK-273 zero-config lan-share + fail-loud guard into the composite
  daemon binary (NixOS-shipped)
status: To Do
assignee: []
created_date: '2026-08-19 23:17'
labels:
  - parity
  - usability
  - follow-up
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-273 delivered zero-config lan-share (tri-state mDNS default_lan_mdns, --profile lan-share provider back-fill, AC#5 announce-after-fetch + loopback listen defaults) and the AC#1 undiscoverable-provider fail-loud guard ONLY in daemon-libp2p/src/main.rs. But the NixOS module (nixos/nix-p2p.nix) drives packages.<system>.daemon = the COMPOSITE /bin/daemon binary, which has none of these. Consequences on the NixOS path: (1) FIXED in TASK-273: composite now accepts --libp2p-no-mdns (was a hard 'unknown flag' crash for libp2p.mdns=false). (2) STILL OPEN: the composite daemon has NO undiscoverable-provider fail-loud guard, so a NixOS lan-share provider with mdns off + no bootstrap/external still runs silently dark (AC#1 not enforced on the shipped path). The module currently COMPENSATES for zero-config by emitting explicit --libp2p-provider/--libp2p-mdns/--libp2p-announce-after-fetch/--libp2p-listen, so a DEFAULT profile=lan-share works, but the fail-loud safety net is absent. Mirror default_lan_mdns (tri-state Option<bool>), the explicit-lan-share provider back-fill, the AC#5 supply/reachability defaults, and the AC#1 fail-loud guard into daemon/src/main.rs so the composite binary and daemon-libp2p have one operator contract. Prove with a composite-binary unit test + a NixOS-path e2e.
<!-- SECTION:DESCRIPTION:END -->
