---
id: TASK-155
title: >-
  fabric-libp2p: decentralized-content-discovery-v1 evidence artifact (bound to
  TASK-126 freeze)
status: To Do
assignee: []
created_date: '2026-08-12 07:55'
labels:
  - libp2p
  - fabric
  - evidence
  - decentralized
  - wave-2c
dependencies:
  - TASK-103
  - TASK-132
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-103 (AC#10). Emit a decentralized-content-discovery-v1 verdict=pass artifact bound to the TASK-126 final tree, with manifests, timings, packet evidence and the mutation set, from a cold run-unique multi-node discovery (harness insertion / prior rendezvous / named candidates / tracker / LAN invalidate the evidence). TASK-132 accepts no unsupported tracker-backed or fabricated substitute. Mirror the existing iroh evidence harness+finalizer shape (scripts/*_evidence.py + finalize_*.py + Justfile recipes).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a cold, run-unique multi-node run emits decentralized-content-discovery-v1 verdict=pass bound to the TASK-126 tree with manifests/timings/packet evidence/mutations
- [ ] #2 harness insertion, prior rendezvous, named candidates, tracker or LAN invalidate the evidence (bite by mutation)
- [ ] #3 an evidence finalizer binds a passing raw run to its reviewed implementation commit, like the iroh artifacts
<!-- AC:END -->
