---
id: TASK-179
title: >-
  S7 libp2p e2e on a separate-netns routed podman network (fully discharge the
  F1 resolution-load-bearing caveat)
status: To Do
assignee: []
created_date: '2026-08-12 22:28'
labels:
  - libp2p
  - e2e
  - daemon
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-161. TASK-161 landed the S7 libp2p arm GREEN on a shared-loopback podman POD (positive 0-egress + byte-identity + no-injection, a MISS arm, and a load-bearing control that kills the provider). But the pod shares one loopback netns, so it is NOT the 'REAL routed container network' the F1 arm specified: on shared loopback a kad get_providers query MAY pre-open a connection to the provider P, so the topology narrows but does not fully ISOLATE that the address-RESOLUTION (kad peer-routing) leg is load-bearing independently of a pre-populated shared routing table / pre-open connection (transport.rs's own stated HONEST LIMIT, carried from TASK-159/169). Build S7 on a podman BRIDGE network (each daemon in its own netns with its own container IP, provider --libp2p-listen on the routable IP), so a dial genuinely requires the DHT-resolved routable address and no loopback shortcut exists. Then add a control that breaks ONLY resolution (record discoverable but peer-routing yields no address) and assert the dial is REFUSED -> upstream fallback. This requires reworking the harness Pod (currently pod-shared-netns + published ports) to a bridge topology, or a parallel driver. Also add the missing LIBP2P-SERVED-TOTAL provider counter (the analogue of IROH-SERVED-TOTAL) so peer-served bytes are attributed provider-side, not only via the proxy egress ledger.
<!-- SECTION:DESCRIPTION:END -->
