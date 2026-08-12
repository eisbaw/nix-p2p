---
id: TASK-147
title: >-
  PRD/doc reconciliation: dual-stack (libp2p-kad directory + iroh transfer) is
  now the DEFAULT, not 'fallback only'
status: Done
assignee: []
created_date: '2026-08-12 01:31'
updated_date: '2026-08-12 05:04'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
OWNER RATIFIED (informed) 2026-08-12: after I surfaced that single-stack means daemon-iroh CANNOT do global content discovery (iroh has no opaque-value DHT), the owner chose dual-stack — 'if iroh is so limited, I'll let it borrow from libp2p.' So daemon-iroh = iroh-blobs transfer + iroh node/LAN discovery (pkarr/Mainline/mDNS) + BORROWED libp2p-kad content directory (dual-stack, the default). daemon-libp2p (pure libp2p, incl its own transfer) remains an optional single-stack comparator/fallback, not on the MVP critical path. This supersedes the brief single-stack reversal (git-reverted). Shared ed25519 identity (PeerId==NodeId, same-keypair not byte-equal — TASK-103 carries the bite test). Decision trail: mped proposed dual-stack -> owner questioned -> single-stack cost surfaced -> owner ratified dual-stack informed. TASK-149 (consolidation debt) stays open; the pure-libp2p transfer gap is noted here rather than as a separate MVP task.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DECIDED by Mark-emulator (mped-architect) 2026-08-12 per the route-judgment-through-mped rule (no owner escalation needed): ratify DUAL-STACK as the default - libp2p-kad put_record/get_record directory + iroh-blobs transfer, unified by a shared ed25519 identity (PeerId==NodeId, same-keypair not byte-equal). Rationale: evidence over coherence (libp2p-kad is the only opaque-value store for our ProviderRecord); the directory is untrusted availability-only hint infra so a second stack's usual objections dissolve; adopt-not-invent kills a thin-iroh-layer (option B); don't-trade-working-code kills full-libp2p (option C, kept as single-stack fallback daemon-libp2p). Accepted cost: two event loops/holepunchers, filed as a collapse-trigger follow-up. Applied: 4 edits to docs/peer-fabric-seam.md + 4 to PRD.md reconciling the 'fallback only, never default' contradiction; retitled TASK-103 to libp2p-kad primary with the shared-identity byte-equality caveat + bite-test requirement.
<!-- SECTION:FINAL_SUMMARY:END -->
