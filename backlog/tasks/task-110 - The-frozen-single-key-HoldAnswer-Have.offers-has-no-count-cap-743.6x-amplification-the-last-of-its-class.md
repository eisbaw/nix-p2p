---
id: TASK-110
title: >-
  The frozen single-key HoldAnswer::Have.offers has no count cap: 743.6x
  amplification, the last of its class
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-10 17:11'
updated_date: '2026-08-15 19:36'
labels:
  - irreversible
dependencies:
  - TASK-91
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deferred from TASK-91 round 7, and it is the LAST member of the amplification class.

TASK-91 fixed the batched path: the offer dictionary is now bounded against ANSWERED keys (<= MAX_OFFERS_PER_ANSWER=4 per answer, and at most one per transport KIND, since the content behind a key has one identity per transport). Amplification fell 613.8x -> 4.0x; a 91 B query now elicits at most 366 B carrying at most one content identity.

THE FROZEN SINGLE-KEY PATH WAS NOT FIXED AND IS NOW THE WORST REMAINING CASE. HoldAnswer::Have.offers has no count cap at all. Measured by two independent reviewers: 622 offers = 65,440 B against an 88 B query = 743.6x amplification, bounded only by the pre-existing 64 KiB MAX_CLAIM_WIRE_BYTES gate. A BitTorrent infohash is a CONTENT identity, so this is both an amplification vector and a no-enumeration vector: a peer asked about ONE key may volunteer hundreds of content identities the asker never named.

WHY IT WAS DEFERRED, correctly: capping it narrows what a FROZEN type ACCEPTS. That is the same decoder-acceptance decision the orchestrator ruled on for deny_unknown_fields at KnownTransport/KnownPayload (see TASK-91 notes, ruling recorded 2026-08-10) - approved there because it aligned the code with the file's own documented 'malformed-known errors' rule, preserved unknown-kind forward compatibility, and costs nothing while no peers are deployed. The same four arguments apply here and should be re-examined, not assumed.

THE SEMANTIC ARGUMENT TO REUSE: the batch fix succeeded because it replaced an ARITHMETIC bound with a SEMANTIC one. 'offers.len() <= have_count * 4' became a theorem rather than a check, because the content behind a key genuinely has one identity per transport kind. The single-key Have answers about exactly one key, so the same reasoning gives a tighter bound directly - one offer per transport kind, full stop.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 HoldAnswer::Have.offers is bounded by the same SEMANTIC rule as the batch path (at most one offer per transport kind for the single key being answered), not by an arbitrary count
- [ ] #2 Amplification for the single-key path is MEASURED before and after; the 743.6x figure (622 offers, 65,440 B against an 88 B query) is the pinned before-number and the after-number is reported with its query/response byte sizes
- [ ] #3 The decoder-acceptance narrowing is recorded as a DELIBERATE freeze amendment with its rationale, the way the KnownTransport/KnownPayload one was - an auditor must find a decision, not infer a slip
- [ ] #4 Unknown transport KINDS still decode inertly afterwards (forward compatibility preserved), proven by test
- [ ] #5 Bites by mutation: removing the cap restores an over-cap response being accepted, and the check is proven to have applied before the result is trusted
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PLAN (TASK-110): Apply the batch semantic bound to the FROZEN single-key HoldAnswer::Have.offers wire codec in daemon-core/src/claim.rs.

Root cause: decode_hold_response parses HoldResponse via serde derive; offers go through deserialize_known_transports which DROPS unknown kinds but has NO count cap and NO one-per-kind rule. Only the outer 64 KiB MAX_CLAIM_WIRE_BYTES gate bounds it -> 622 bittorrent offers = 65,440 B vs an 88 B query = 743.6x (reproduced externally, matches the pinned before-number exactly; 622 bittorrent infohashes = 621 content identities the asker never named = enumeration vector).

Fix, mirroring the batch path (check_batch_offer_bindings + BatchHoldResponseWire + not_deserialize):
1. add check_single_offer_bindings(offers: &[OfferSlot]): at most MAX_OFFERS_PER_ANSWER (4) offers AND one per transport KIND, counting RAW slots (unknown kinds included, by wire_tag) so unknown-kind PADDING is bounded too, not only the enumeration.
2. add wire-twin HoldResponseWire/HoldAnswerWire whose Have.offers keep OfferSlot (unknown kinds preserved via deserialize_transport_slots); remove Deserialize from HoldResponse+HoldAnswer and add them to the not_deserialize coherence proof so decode_hold_response is the ONLY path from bytes (same no-bypass argument task-91 made for the index-rebind hazard).
3. decode_hold_response: parse twin -> version -> check_single_offer_bindings on RAW slots -> drop unknowns (keep_known_offers) -> HoldResponse. encode_hold_response: validate before emit (node cannot emit what it would refuse).

After: one iroh + one bittorrent = 330 B = 15/4 = 3.75x (exact rational; float only as display). Valid golden vectors (<=1 offer/kind) unaffected -> golden must still pass.

AC#3 records the decoder-acceptance narrowing as a DELIBERATE freeze amendment reusing the four TASK-91 KnownTransport/KnownPayload arguments. AC#4 forward-compat test: unknown kinds still decode inertly. AC#5 mutation bite: removing the check re-accepts an over-cap response (RED), rejection proven BEFORE any HoldAnswer::Have is trusted.

Gate: cargo test -p daemon-core -p daemon, fmt, clippy -D warnings, check-no-floats, check-golden-vectors, and full just e2e.

PROGRESS (gate in flight):
- IMPLEMENTED in daemon-core/src/claim.rs: check_single_offer_bindings (<=MAX_OFFERS_PER_ANSWER=4 AND one-per-transport-kind) applied on encode (encode_hold_response) and decode (decode_hold_response) against RAW pre-drop OfferSlot list via new HoldResponseWire/HoldAnswerWire twin. HoldResponse+HoldAnswer lost derived Deserialize and joined the not_deserialize coherence proof so decode is the ONLY path from bytes. Unknown kinds counted then dropped (keep_known_offers) = forward-compat.
- MEASURED (AC#2): before = 622 bittorrent offers = 65,440 B vs 88 B query = 743.6x (reproduced exactly, matches pinned). after = 1 iroh + 1 bittorrent = 330 B; amp 330/88 = 15/4 = 3.75x. Asserted as integer cross-product (after*4 == query*15); float only as display. No-floats guard green.
- MUTATION (AC#5): neutralised the decode-side check_single_offer_bindings(&offers)?; -> the two bound tests went RED (over-cap + two-of-a-kind re-accepted); restored -> GREEN. Proven the bound applies before any HoldAnswer::Have is returned (decode returns Err).
- GOLDEN: added reject vector reject_hold_response_two_locators_of_one_kind + dispatch branch; every_reject_vector_is_refused + EXERCISED list updated. All 16 claim_wire_golden tests pass; valid hold_response_* encodings byte-identical (emit-set unchanged).
- GATES so far GREEN: cargo test -p daemon-core -p daemon = 431 passed / 0 failed; cargo fmt --all --check; cargo clippy --locked --workspace + daemon evidence-fixture -D warnings; check-independence/shaping/no-floats; check-golden-vectors path (golden test). just e2e RUNNING.
- GOTCHA (not mine): just lint fails only at ruff format --check on 3 UNTOUCHED scripts (check-discovery-no-shortcut.py, shaped_compress.py, task203_pipelined_measure.py), byte-identical to HEAD -> pre-existing drift, filed TASK-222. Not included in this commit.
- SEAM SAFETY: availability serve path emits exactly one iroh offer per key (availability.rs ~1257), so encode_hold_response never rejects a legitimate produced answer.
<!-- SECTION:NOTES:END -->
