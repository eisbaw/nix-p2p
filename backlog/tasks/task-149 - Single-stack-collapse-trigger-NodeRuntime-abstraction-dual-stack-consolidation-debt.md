---
id: TASK-149
title: >-
  Single-stack collapse trigger + NodeRuntime abstraction (dual-stack
  consolidation debt)
status: To Do
assignee: []
created_date: '2026-08-12 04:29'
labels:
  - architecture
  - debt
  - wave-2c
dependencies:
  - TASK-147
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-147 accepted dual-stack (libp2p-kad directory + iroh-blobs transfer) as the default, which runs two event loops / two holepunchers / two dependency closures with no NodeRuntime abstraction beneath the fabric (shared ed25519 unifies identity, not connectivity). This records the deferred consolidation debt so it stays visible: revisit collapsing to a single stack if EITHER iroh grows a content-keyed opaque value store (making iroh-dht viable for our ProviderRecord) OR libp2p transfer proves equal to iroh-blobs (making daemon-libp2p single-stack the default). Consider whether a NodeRuntime seam beneath PeerFabric is worth introducing then. Not a blocker; a standing review trigger.
<!-- SECTION:DESCRIPTION:END -->
