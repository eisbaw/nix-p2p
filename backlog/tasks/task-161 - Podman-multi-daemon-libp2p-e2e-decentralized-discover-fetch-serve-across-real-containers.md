---
id: TASK-161
title: >-
  Podman multi-daemon libp2p e2e: decentralized discover->fetch->serve across
  real containers
status: To Do
assignee: []
created_date: '2026-08-12 10:22'
updated_date: '2026-08-12 15:51'
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
UNBLOCKED by TASK-162 (64d0779): the daemon binary now takes real libp2p CLI config - --libp2p-bootstrap <PeerId@multiaddr> (repeatable), --libp2p-provider-addr <PeerId@multiaddr> (repeatable, now an OPTIONAL override hint - see TASK-169), --libp2p-listen <multiaddr>, --libp2p-scope <str>, --libp2p-identity-seed <64hex>. A libp2p-only daemon runs with NO iroh runtime (setup_p2p_source composes libp2p PRIMARY -> iroh -> HTTP). For the podman arm: bootstrap container listens; provider container serves+announces (needs the serving/supplier path - currently TASK-146 territory, the daemon binary has no catalog-backed libp2p supplier flag yet, so the provider container may need a fixture/interim supplier); consumer container gets ONLY --libp2p-bootstrap <bootstrap> (NO --libp2p-provider-addr - see TASK-169). NOTE: the daemon binary today wires only the CONSUMER libp2p path (Libp2pFabric::start, no supplier); a libp2p SERVING daemon (start_with_supplier from the real catalog) is not yet CLI-exposed - confirm/extend before the provider container.

FORWARD-CARRIED FROM TASK-169 (commits a3bc9f9/378ecbe/48186ce/eb812bc): the consumer daemon now resolves a provider dial address via node_locator (kad peer-routing) with ZERO injection - drop --libp2p-provider-addr from the consumer container.
  NAMED RISK (mped review F1, MEDIUM/HIGH - THIS TASK is the only place it can be proven): Libp2pNarSource::resolve DISCARDS locate()'s returned DialInfo and relies on locate()'s SIDE EFFECT (get_closest_peers warming the shared swarm's kad routing table) so the request-response fetch can dial. The NodeLocator seam returns DialInfo.locations as OPAQUE strings, so seam-level code cannot reparse+use them without breaking the abstraction - hence the side-effect coupling. In the TASK-169 loopback test this side effect is NOT PROVABLE as load-bearing (the fetch can reuse a connection an earlier discovery query opened to P; verified by mutation the byte-path passes even with locate() bypassed - only the exposure-ledger delta oracle proves resolve CONSULTS locate). This real multi-container e2e (distinct hosts, no shared earlier connection to reuse) is where to VERIFY the locate side effect is the ACTUAL dial-enabling mechanism. If it is NOT, the fix is architectural: either locate() owns address-book warming behind the seam and returns a readiness signal, or the fabric exposes a seam-legal make-dialable op. Watch for silent degradation: if the side effect stops warming the dial path, the consumer fetch fails -> HTTP fallback, looking identical to a normal miss (a connectivity regression masquerading as a benign miss).
<!-- SECTION:NOTES:END -->
