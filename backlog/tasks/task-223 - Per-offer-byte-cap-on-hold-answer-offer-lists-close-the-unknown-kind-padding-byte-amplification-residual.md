---
id: TASK-223
title: >-
  Per-offer byte cap on hold-answer offer lists (close the unknown-kind padding
  byte-amplification residual)
status: To Do
assignee: []
created_date: '2026-08-15 19:54'
updated_date: '2026-08-15 20:36'
labels:
  - irreversible
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-110 bounded the single-key HoldAnswer::Have.offers COUNT (<=4, one per transport kind), closing the KNOWN-offer enumeration/content-count vector (the unknown-KIND opaque-slot enumeration is a separate pre-existing residual, TASK-224). It did NOT bound message BYTES: an unknown-kind offer is retained as an opaque serde_json::Value slot whose body is byte-unbounded, so a hostile single-key Have (or a batch answer) can still pad up to MAX_CLAIM_WIRE_BYTES (64 KiB) with as few as one dropped unknown offer -> worst-case wire amplification ~744x against an 88 B query, unchanged from before TASK-110 and identical to the batch path. Both reviewers (qa-test-runner + mped-architect) flagged this; mped recommended honest wording over a byte cap for TASK-110 because a future transport's LEGITIMATE locator may itself be large, so a byte cap needs its own forward-compat analysis. This task: decide+freeze a per-offer (or per-Have total-offer) serialized-byte cap that closes the padding channel WITHOUT breaking a legitimate future large locator, applied to BOTH the single-key path (check_single_offer_bindings) and the batch path (check_batch_offer_bindings), which share the OfferSlot machinery. Pinned honest residual is daemon-core/src/claim.rs::a_padded_unknown_kind_have_still_saturates_the_frame_and_decodes_empty. If a per-offer byte cap is chosen, that test flips from decodes to rejected. FROZEN-SURFACE: this is a further decoder-acceptance narrowing, DEEP-gate it like TASK-110.
<!-- SECTION:DESCRIPTION:END -->
