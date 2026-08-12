---
id: TASK-161
title: >-
  Podman multi-daemon libp2p e2e: decentralized discover->fetch->serve across
  real containers
status: To Do
assignee: []
created_date: '2026-08-12 10:22'
updated_date: '2026-08-12 16:00'
labels:
  - libp2p
  - daemon
  - e2e
  - wave-2c
dependencies:
  - TASK-160
  - TASK-164
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-160 (which proved the in-process daemon<->libp2p integration test). Stand up >=3 real daemon containers on a podman pod (a bootstrap, a serving provider that announces a known NAR, and a consumer daemon): the consumer discovers the provider via libp2p-kad (NOT injected) and fetches+serves the NAR byte-identical through its serving stack, with a MISS arm falling back to upstream. Extends the existing s6-p2p iroh e2e with a libp2p arm. Depends on the production main.rs libp2p config wiring.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Forward-carried from TASK-169 (F1, MEDIUM/HIGH): the daemon production path now consults Libp2pFabric::node_locator().locate() in Libp2pNarSource::resolve and no longer REQUIRES an injected --libp2p-provider-addr, but it DISCARDS locate()s returned DialInfo (source_libp2p.rs Found(_dial_info) => {}) and relies on locate()s routing-table SIDE EFFECT for the actual dial. Verified by mutation on loopback: bypassing locate entirely still serves byte-identical, because an earlier kad discovery query already opened the connection to the provider - so locate is NOT provably load-bearing on loopback (only the exposure-ledger oracle proves it is CALLED).
This real multi-container e2e must: (1) make resolve USE the resolved DialInfo - parse the DHT-resolved Multiaddr string(s) and add_address(provider_peer, addr) so the dial is driven by the RESOLUTION, not an incidental side effect. NOTE the implementer conflated this with injection: add_address of a DHT-RESOLVED address is NOT injection (injection = an operator-supplied out-of-band address); using the resolved address is the correct consumption of the seam. (2) PROVE locate is load-bearing on a real network where discovery does not pre-open the provider connection: a broken/empty locate MUST break the dial (fall to upstream), not silently succeed. Watch for silent degradation. (3) Drop --libp2p-provider-addr from the consumer container entirely (it is now only an optional override hint).
<!-- SECTION:NOTES:END -->
