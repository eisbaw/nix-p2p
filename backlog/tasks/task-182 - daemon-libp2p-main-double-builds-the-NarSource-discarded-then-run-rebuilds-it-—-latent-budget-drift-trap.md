---
id: TASK-182
title: >-
  daemon-libp2p: main() double-builds the NarSource (discarded) then run()
  rebuilds it — latent budget-drift trap
status: To Do
assignee: []
created_date: '2026-08-13 02:19'
labels:
  - daemon-libp2p
  - refactor
  - hardening
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
mped review of the daemon-core refactor: daemon-libp2p/src/main.rs:362 calls build_libp2p_nar_source and discards _source/_raw, then daemon_core::run rebuilds PeerFabricNarSource/PeerFabricRawServe from the raw fabric. Harmless today (both use DiscoveryBudget::default()/SafetyEnvelope::default()), but a latent drift trap if the binary's source_config budgets ever diverge from RunConfig budgets. Fix: pass the already-built source into run(), or document that run() is authoritative and the builder source is intentionally discarded.
<!-- SECTION:DESCRIPTION:END -->
