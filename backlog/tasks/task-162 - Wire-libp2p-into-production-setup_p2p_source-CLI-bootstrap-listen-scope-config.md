---
id: TASK-162
title: >-
  Wire libp2p into production setup_p2p_source (CLI bootstrap/listen/scope
  config)
status: To Do
assignee: []
created_date: '2026-08-12 10:22'
labels:
  - libp2p
  - daemon
  - integration
  - wave-2c
dependencies:
  - TASK-160
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-160. The Libp2pNarSource seam piece exists and is proven through the serving stack (daemon/src/source_libp2p.rs), but production main.rs setup_p2p_source (daemon/src/main.rs:~1041) still builds ONLY the iroh source. Add CLI/config (libp2p bootstrap peers, listen addr, network scope, discovery/announce budgets, fetch envelope) so the binary can construct a Libp2pFabric + Libp2pNarSource and compose it into the FallbackNarSource chain additively (iroh path intact). Precursor is really the clean daemon-core/two-binary split (TASK-145/146); this interim wiring enables the podman libp2p e2e.
<!-- SECTION:DESCRIPTION:END -->
