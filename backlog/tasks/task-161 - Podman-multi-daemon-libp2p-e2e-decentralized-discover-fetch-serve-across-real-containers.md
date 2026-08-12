---
id: TASK-161
title: >-
  Podman multi-daemon libp2p e2e: decentralized discover->fetch->serve across
  real containers
status: To Do
assignee: []
created_date: '2026-08-12 10:22'
updated_date: '2026-08-12 11:27'
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
UNBLOCKED by TASK-162 (64d0779): the daemon binary now takes real libp2p CLI config - --libp2p-bootstrap <PeerId@multiaddr> (repeatable), --libp2p-provider-addr <PeerId@multiaddr> (repeatable, TASK-159 basic-dial shim), --libp2p-listen <multiaddr>, --libp2p-scope <str>, --libp2p-identity-seed <64hex>. A libp2p-only daemon runs with NO iroh runtime (setup_p2p_source composes libp2p PRIMARY -> iroh -> HTTP). For the podman arm: bootstrap container listens; provider container serves+announces (needs the serving/supplier path - currently TASK-146 territory, the daemon binary has no catalog-backed libp2p supplier flag yet, so the provider container may need a fixture/interim supplier); consumer container gets --libp2p-bootstrap <bootstrap> + --libp2p-provider-addr <provider>. NOTE: the daemon binary today wires only the CONSUMER libp2p path (Libp2pFabric::start, no supplier); a libp2p SERVING daemon (start_with_supplier from the real catalog) is not yet CLI-exposed - confirm/extend before the provider container.
<!-- SECTION:NOTES:END -->
