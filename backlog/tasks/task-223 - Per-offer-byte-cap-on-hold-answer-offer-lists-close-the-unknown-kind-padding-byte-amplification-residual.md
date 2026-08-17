---
id: TASK-223
title: >-
  Per-offer byte cap on hold-answer offer lists (close the unknown-kind padding
  byte-amplification residual)
status: Done
assignee:
  - '@me'
created_date: '2026-08-15 19:54'
updated_date: '2026-08-17 14:49'
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

DEEP-gate round 2 fixes (commit aa53bb8 on top of 68e0c3a). Mechanism unchanged (cap 2048, offer_within_byte_cap logic byte-identical); honesty + freeze-precision + bite-quality only. No runtime path changed, so e2e NOT re-run (68e0c3a was e2e 9/9).

F1 (HONESTY, wire-vs-decoded unit switch): re-scoped the claim EVERYWHERE from "closes byte-amplification / 744x->94x wire" to what the cap ACTUALLY delivers. The cap measures COMPACT re-serialized JSON, so whitespace/escape padding normalizes away and does NOT count; a mostly-whitespace 64 KiB response with <=4 tiny offers passes every gate, so raw WIRE amplification stays ~744x, and since unknown bodies are never re-emitted, whitespace is threat-equivalent. What the cap buys: (a) FIXED DECODED offer-CONTENT bound <= MAX_OFFERS_PER_ANSWER*2 KiB = 8 KiB, frame-independent (measured in decoded-content bytes, NOT a wire ratio); (b) forward-portability (binding constraint under the planned binary codec); (c) defense-in-depth. Raw-wire whitespace residual is frame-bounded ~744x, within the frame-bounded/cost-a-retry guarantee, now cited as TASK-244. Fixed at claim.rs (MAX_OFFER_WIRE_BYTES doc, check_single_offer_bindings "B." block, HoldAnswer/HoldResponseWire/deserialize_* docs, flipped+batch+after test comments), PRD.md (both sites), golden notes (reject_hold_response_two_locators_of_one_kind + the 3 new byte-cap vectors).

F2 (FREEZE VALUE, wrapper arithmetic): the 2048 cap counts the whole offer incl. the ~32 B JSON wrapper, so the single-locator PAYLOAD budget is ~2016 B, not 2048. Removed the wrong "max-length ~2048 B URL fits" claim (2048 URL + wrapper ~2080 -> rejected); stated the honest ~2016 B ceiling (>5x a full iroh ticket, ~4x a long URL). Backward-safety corrected: an over-cap offer HARD-REJECTS the whole response (discarding co-located KNOWN offers); an old peer meeting a future >cap legit offer does NOT self-heal by retry, the resolver SKIPS that peer; the fix is a coordinated network-wide cap loosening BEFORE such a transport ships, not a per-exchange retry.

F3 (BITE QUALITY, exact boundary): added the_per_offer_cap_constant_is_pinned (assert_eq!(MAX_OFFER_WIRE_BYTES, 2048)); an_offer_of_exactly_the_cap_is_accepted (compact size EXACTLY 2048 -> accepted, pins <= vs <); an_offer_one_byte_over_the_cap_is_rejected (EXACTLY 2049 -> rejected). Boundary tests use FIXED literals (2048/2049) so a constant drift moves the threshold, not the vector. MUTATIONS verified: (A) `>`->`>=` reddens 2048-accept, 2049-reject+constant-pin stay green; (B) constant 2048->2100 reddens constant-pin AND 2049-reject, 2048-accept stays green. Also added a_batch_response_with_an_under_cap_unknown_offer_is_accepted (batch accept-under-cap twin; mped LOW). Justfile "5 scenarios" comment NOT touched (not in a file I edited; orchestrator said skip).

Gate (round 2): cargo test --workspace 1059 passed / 0 failed (89 blocks; +4 new tests); cargo fmt --all --check ok; cargo clippy --workspace --all-targets -D warnings rc 0 (fixed a doc-list-indentation lint on the new constant doc); check-no-floats/check-golden-vectors/check-discovery-no-shortcut rc 0; just audit rc 0; claim_wire_golden 16/16, doc_citations 3/3. Existing AND new golden wire strings byte-identical (only note text + tests changed this round).

DEEP GATE PASSED (2026-08-17). Commits 68e0c3a + aa53bb8 + c4c0ee6. qa GREEN (1059/0, e2e 9/9), mped GO-conditional (met), codex NOGO(F1 false-wire-claim/F2 wrapper-arithmetic/F3 boundary-not-pinned)->fixed->GO-VERDICT-223R. Per-offer MAX_OFFER_WIRE_BYTES=2048 bounds DECODED offer-content <=8KiB (NOT wire: raw wire stays ~744x via whitespace -> TASK-244), both paths via shared deserializer, exact-boundary mutation-pinned (2048-accept/2049-reject/constant-pin). Golden byte-identical.
<!-- SECTION:NOTES:END -->
