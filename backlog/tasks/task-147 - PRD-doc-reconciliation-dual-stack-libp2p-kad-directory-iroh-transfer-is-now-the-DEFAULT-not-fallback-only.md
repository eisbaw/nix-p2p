---
id: TASK-147
title: >-
  PRD/doc reconciliation: dual-stack (libp2p-kad directory + iroh transfer) is
  now the DEFAULT, not 'fallback only'
status: To Do
assignee: []
created_date: '2026-08-12 01:31'
labels:
  - architecture
  - docs
  - wave-2c
  - owner-decision
dependencies:
  - TASK-126
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-126 spike found iroh-dht-experiment stores a FIXED TYPED enum, not opaque bytes, so libp2p-kad put_record/get_record is the only viable opaque-value ProviderDirectory -> PRIMARY. With iroh-blobs still the transfer, the shipping architecture is now DUAL-STACK (iroh transfer + libp2p directory). This contradicts docs/peer-fabric-seam.md which calls dual-stack "sound but heavy - fallback posture, never default", and the PRD "Pluggable P2P substrate" subsection which lists iroh-dht-experiment primary. The freeze itself is backend-agnostic (all 3 DEEP reviewers agree no frozen byte depends on the choice), so this does NOT gate the freeze - but it is an OWNER-LEVEL architecture-stance reversal that must be reconciled in PRD.md + docs/peer-fabric-seam.md (the iroh-native single-stack preference no longer holds for content discovery), and it revives the shared-ed25519 PeerId==NodeId question and the two-networking-stacks resource cost. Evidence: TASK-126 spike notes; DEEP gate Workflow wiba389dr (mped-architect major finding, codex confirmation).
<!-- SECTION:DESCRIPTION:END -->
