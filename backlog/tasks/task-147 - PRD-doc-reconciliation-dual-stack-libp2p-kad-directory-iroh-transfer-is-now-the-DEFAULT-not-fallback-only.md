---
id: TASK-147
title: >-
  PRD/doc reconciliation: dual-stack (libp2p-kad directory + iroh transfer) is
  now the DEFAULT, not 'fallback only'
status: Done
assignee: []
created_date: '2026-08-12 01:31'
updated_date: '2026-08-12 07:22'
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
DIRECTION UPDATE 2026-08-12 (owner): libp2p-PRIMARY, iroh OPTIONAL. Supersedes the dual-stack 'iroh borrows libp2p' framing. iroh is a connectivity substrate with NO content-provider routing ('who has hash X?') - only address lookup - so libp2p-kad is the MANDATORY discovery layer (robust, IPFS-proven, ADOPTED: no hand-roll, no Kademlia-over-iroh). iroh-blobs is kept as an OPTIONAL NarTransfer for its NAT traversal, measured vs libp2p's own transport in the tournament; if iroh doesn't win, the product collapses to pure libp2p. Discovery is always libp2p-kad regardless of transport. dig-dht (v0.11) is a comparison arm at most, never a dependency. PRD + docs/peer-fabric-seam.md + README updated with iroh's shortcomings.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DECIDED by Mark-emulator (mped-architect) 2026-08-12 per the route-judgment-through-mped rule (no owner escalation needed): ratify DUAL-STACK as the default - libp2p-kad put_record/get_record directory + iroh-blobs transfer, unified by a shared ed25519 identity (PeerId==NodeId, same-keypair not byte-equal). Rationale: evidence over coherence (libp2p-kad is the only opaque-value store for our ProviderRecord); the directory is untrusted availability-only hint infra so a second stack's usual objections dissolve; adopt-not-invent kills a thin-iroh-layer (option B); don't-trade-working-code kills full-libp2p (option C, kept as single-stack fallback daemon-libp2p). Accepted cost: two event loops/holepunchers, filed as a collapse-trigger follow-up. Applied: 4 edits to docs/peer-fabric-seam.md + 4 to PRD.md reconciling the 'fallback only, never default' contradiction; retitled TASK-103 to libp2p-kad primary with the shared-identity byte-equality caveat + bite-test requirement.
<!-- SECTION:FINAL_SUMMARY:END -->
