---
id: TASK-223
title: >-
  Per-offer byte cap on hold-answer offer lists (close the unknown-kind padding
  byte-amplification residual)
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-15 19:54'
updated_date: '2026-08-17 14:09'
labels:
  - irreversible
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-110 bounded the single-key HoldAnswer::Have.offers COUNT (<=4, one per transport kind), closing the KNOWN-offer enumeration/content-count vector (the unknown-KIND opaque-slot enumeration is a separate pre-existing residual, TASK-224). It did NOT bound message BYTES: an unknown-kind offer is retained as an opaque serde_json::Value slot whose body is byte-unbounded, so a hostile single-key Have (or a batch answer) can still pad up to MAX_CLAIM_WIRE_BYTES (64 KiB) with as few as one dropped unknown offer -> worst-case wire amplification ~744x against an 88 B query, unchanged from before TASK-110 and identical to the batch path. Both reviewers (qa-test-runner + mped-architect) flagged this; mped recommended honest wording over a byte cap for TASK-110 because a future transport's LEGITIMATE locator may itself be large, so a byte cap needs its own forward-compat analysis. This task: decide+freeze a per-offer (or per-Have total-offer) serialized-byte cap that closes the padding channel WITHOUT breaking a legitimate future large locator, applied to BOTH the single-key path (check_single_offer_bindings) and the batch path (check_batch_offer_bindings), which share the OfferSlot machinery. Pinned honest residual is daemon-core/src/claim.rs::a_padded_unknown_kind_have_still_saturates_the_frame_and_decodes_empty. If a per-offer byte cap is chosen, that test flips from decodes to rejected. FROZEN-SURFACE: this is a further decoder-acceptance narrowing, DEEP-gate it like TASK-110.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
SCOPE CLARIFICATION (2026-08-16, TASK-224 codex re-gate arbitration): TASK-223 is byte-VOLUME ONLY. It bounds how MANY bytes an unknown-kind offer can pad onto the wire (the ~744x amplification against the 64 KiB frame). It does NOT own, and a per-offer byte cap does NOT discharge, the unknown-KIND identity-NAMING (enumeration) residual: a byte cap still admits one (or a few short) identities per slot, and one accepted unasked identity is already a claim.rs:332 defect. The identity-shaped TEXT residual across the tag / field-name / value channels is owned by TASK-227, NOT this task. Keep 223 focused on byte volume.

IMPLEMENTED (commit 68e0c3a, awaiting DEEP gate; orchestrator owns Done).

CAP: MAX_OFFER_WIRE_BYTES = 2 KiB (2048), a PER-OFFER cap on each offer's compact serialized size, in offer_within_byte_cap. Applied to EVERY offer element (known+unknown) in the two shared slot/drop deserializers: deserialize_transport_slots (single-key AND batch hold-response) + deserialize_known_transports (Claim.transports). Single source, kept in step by the_slot_and_drop_transport_decoders_agree. Encode untouched (emit-set unchanged; a KnownTransport is type-bounded ~114 B, far under cap).

FORWARD-COMPAT JUSTIFICATION (the freeze decision): 2 KiB is deliberately GENEROUS, not maximally tight. Every plausible legit single-scalar locator fits with headroom (iroh NodeId 32 B; full iroh ticket ~200-400 B; multiaddr ~150 B; even a max-length URL < 2 KiB) and it is >17x the largest offer this build emits, >40x the tolerated carrier_pigeon golden. Loosening later is backward-safe (a newer decoder accepting a larger offer is soft version-skew, NOT a network split); tightening is a real break. Owner rule: pick safe-NOW over tight. Amplification collapse: ~744x (one 60 KB offer filling the frame) -> a FIXED ceiling of MAX_OFFERS_PER_ANSWER*2 KiB = 8 KiB offer content for a single-key Have (~94x incl envelope), independent of the 64 KiB frame; a single offer now <= 2 KiB (~23x, was ~744x).

HONEST LIMITS: (1) raw-JSON whitespace/escape inflation is NOT bounded by this content cap - it is universal (any message, incl Absent), frame-bounded, draft-codec-only (gone under the final binary codec), NOT an offer-body channel; disclosed at MAX_OFFER_WIRE_BYTES and NOT claimed closed. (2) the identity-shaped TEXT residual (one short string via tag/field-name/value) is TASK-227, not dischargeable by any byte cap (one accepted identity is already the defect). No legit locator is anywhere near the cap.

PINNED TEST FLIP: a_padded_unknown_kind_have_still_saturates_the_frame_and_decodes_empty -> renamed a_padded_unknown_kind_have_is_rejected_by_the_per_offer_byte_cap (now asserts REJECTED).

BITES (each mutation-proven red via a temporary env-gate, removed before commit): (1) single-key over-cap Have REJECTED [disable cap -> red]; (2) legit iroh + ~1 KiB under-cap unknown offer still ACCEPTED/tolerated [tiny cap 10 -> red]; (3) batch over-cap offer REJECTED [disable cap -> red]; (4) golden every_reject_vector_is_refused with 3 new byte-cap vectors [disable cap -> red]; parity test over-cap+control [disable -> red]. Golden existing wires byte-identical (pure additions; git diff 0 deletions on the wire strings).

GATE (actual, nix dev shell): cargo test --workspace 1055 passed / 0 failed (89 blocks); cargo fmt --all --check ok; cargo clippy --workspace --all-targets -D warnings rc 0; check-no-floats/check-golden-vectors/check-discovery-no-shortcut rc 0; just audit rc 0; just e2e 9/9 scenarios PASS (s1 11/11, narinfo 20/20, s2 9/9, tamper 4/4, chain 13/13, s6-p2p 11/11, bootstrap-outage 9/9, s9-grow 14/14, leech 16/16; 247.6s) exit 0.
<!-- SECTION:NOTES:END -->
