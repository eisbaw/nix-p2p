---
id: TASK-277
title: >-
  Mirror TASK-273 zero-config lan-share + fail-loud guard into the composite
  daemon binary (NixOS-shipped)
status: To Do
assignee: []
created_date: '2026-08-19 23:17'
updated_date: '2026-08-20 01:22'
labels:
  - parity
  - usability
  - follow-up
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-273 delivered zero-config lan-share (tri-state mDNS default_lan_mdns, --profile lan-share provider back-fill, AC#5 announce-after-fetch + loopback listen defaults) and the AC#1 undiscoverable-provider fail-loud guard ONLY in daemon-libp2p/src/main.rs. But the NixOS module (nixos/nix-p2p.nix) drives packages.<system>.daemon = the COMPOSITE /bin/daemon binary, which has none of these. Consequences on the NixOS path: (1) FIXED in TASK-273: composite now accepts --libp2p-no-mdns (was a hard 'unknown flag' crash for libp2p.mdns=false). (2) STILL OPEN: the composite daemon has NO undiscoverable-provider fail-loud guard, so a NixOS lan-share provider with mdns off + no bootstrap/external still runs silently dark (AC#1 not enforced on the shipped path). The module currently COMPENSATES for zero-config by emitting explicit --libp2p-provider/--libp2p-mdns/--libp2p-announce-after-fetch/--libp2p-listen, so a DEFAULT profile=lan-share works, but the fail-loud safety net is absent. Mirror default_lan_mdns (tri-state Option<bool>), the explicit-lan-share provider back-fill, the AC#5 supply/reachability defaults, and the AC#1 fail-loud guard into daemon/src/main.rs so the composite binary and daemon-libp2p have one operator contract. Prove with a composite-binary unit test + a NixOS-path e2e.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DEEP-gate (mped) correction: the composite is NOT silently dark. daemon/src/main.rs:1232 (libp2p_requested() && bootstrap.is_empty() && !libp2p_mdns) already fails an undiscoverable provider loud on the shipped binary. Real residual = (a) accept --libp2p-external-address as an entry path on the composite (currently over-refuses an external-address-only provider), and (b) unify the error message with daemon-libp2p. Downgrade from "missing guard" to "parity/message polish".

CORRECTION (mped DEEP review F3): the composite daemon does NOT run an undiscoverable provider silently dark — the pre-existing entry-path guard at daemon/src/main.rs:1232 (libp2p_requested() && bootstrap.is_empty() && !libp2p_mdns) already fails such a node LOUD. The real residual is NARROW, hence downgraded to Low: (a) that guard does not accept --libp2p-external-address as an entry path (daemon-libp2p TASK-273 guard does), and (b) message/scope unification (composite fires on any libp2p-requested node with a generic message; daemon-libp2p is provider-scoped with the three-path message). The other conveniences (default_lan_mdns / back-fill / AC#5 defaults) are supplied on the NixOS path by the module emitting explicit flags.

Add finding #7: the composite parser rejects --libp2p-external-address as unknown-flag while the NixOS module emits it (nixos/nix-p2p.nix:478); latent crash when a user sets externalAddresses (default []). Composite must accept --libp2p-external-address.

codex #5: composite public-share with ONLY --libp2p-provider-addr is over-rejected (daemon/src/main.rs:1256 recognizes only bootstrap/mdns as entry, though :1285 counts provider-addr as libp2p-requesting). Fail-closed, not silent-dark. Add provider-addr as an accepted composite entry path (parity with daemon-libp2p:840).
<!-- SECTION:NOTES:END -->
