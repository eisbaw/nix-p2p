---
id: TASK-224
title: >-
  Unknown-KIND transport offer can name content identities on the wire
  (no-enumeration residual; forward-compat tension)
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-15 20:17'
updated_date: '2026-08-16 00:06'
labels:
  - irreversible
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
codex DEEP gate (TASK-110 re-gate) proved with an executable probe that a SINGLE unknown-KIND offer smuggles content identities the asker never named and is ACCEPTED (decoded to empty, but accepted on the wire): {"transport":"future_bulk","content_ids":["blake3:bbbb...","blake3:cccc..."]}. ROOT: the tolerate-but-drop deserializer reads ONLY the transport tag and discards the rest as an opaque serde_json::Value. deserialize_known_transports (~daemon-core/src/claim.rs:429) serves Claim::transports; BOTH the single-key AND batch hold-response paths decode their offers via deserialize_transport_slots (the slot-preserving tolerate-drop variant, wired at ~claim.rs:659 and ~claim.rs:978), so the residual is shared by both response paths. deny_unknown_fields rejects extra fields inside a KNOWN transport, but an unknown KIND is accepted-and-dropped - the exact also_held enumeration defect the KNOWN-transport rule at claim.rs:332 forbids, on the unknown-KIND path. This is a real no-enumeration-invariant gap (PRD privacy invariant, no-enumeration section) and it is SHARED by the single-key (decode_hold_response) and batch (decode_batch_hold_response) paths - PRE-EXISTING in both, NOT introduced by TASK-110 (TASK-110 closed only the KNOWN-offer count/enumeration, <=1 identity per transport kind). NOT the same as TASK-223 (per-offer byte cap): codex showed a byte cap still permits several SHORT identities in one opaque slot. THE TENSION to resolve: accept an unknown FUTURE transport opaquely (forward compat, AC#4 of TASK-110) while forbidding it from naming content identities. Candidate approaches: constrain an unknown-kind offer object to a whitelisted minimal shape (transport tag + at most one bounded SCALAR locator field), or reject unknown-kind offers whose body contains any array / nested object / digest-shaped string. This is a further FROZEN decoder-acceptance narrowing -> DEEP/irreversible. Parity + residual pinned by daemon-core/src/claim.rs::an_unknown_kind_offer_still_carries_content_ids_on_the_wire_on_both_paths.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PLAN + DESIGN DECISION (TASK-224).

CHOSEN: Approach A (whitelisted minimal shape), REJECT (error) on violation - NOT silent drop.

RULE (the frozen decoder-acceptance narrowing): a tolerated unknown-KIND transport offer is a JSON object carrying the `transport` tag plus AT MOST ONE other field whose value is a SCALAR STRING (one opaque locator). Any ARRAY, any NESTED OBJECT, any NON-STRING extra value, a SECOND non-transport field, or an array/object in the `transport` tag slot ERRORS the whole decode. A well-shaped unknown offer still decodes INERTLY (dropped from the value) - forward-compat preserved.

REJECT-vs-DROP: REJECT/error, per the claim.rs:332 also_held precedent - accepting-then-dropping a wire that NAMED identities is itself the enumeration defect, so the wire must be un-acceptable, not merely un-used.

WHY A over B: A is an allowlist (cannot be evaded); B (reject digest-shaped strings) is a blocklist that depends on recognising an identity and can be dodged by a different identity encoding. A mirrors the format contract a KNOWN transport already meets (one scalar locator per offer), so a LIST of identities becomes INEXPRESSIBLE in the format - the same no-enumeration guarantee known transports already have.

NO byte/length cap here (deliberate): the byte VOLUME of one opaque scalar (how many identities could be delimiter-crammed into one string) is the SAME residual a known transports own string locator has, bounded by the 64 KiB frame and OWNED BY TASK-223. Adding a cap here would also flip the TASK-223 oracle a_padded_unknown_kind_have_still_saturates_the_frame_and_decodes_empty, which must stay green. mped TASK-223 rationale: a legit future locator may be large and needs its own forward-compat analysis.

SCOPE: applied at BOTH tolerate-drop decoders via ONE shared helper - deserialize_transport_slots (single-key + batch hold-response offer dictionaries, the task target) AND deserialize_known_transports (Claim.transports, its documented twin) - so the rule lives once (like KNOWN_TRANSPORT_TAGS) and the two cannot drift; the_slot_and_drop_transport_decoders_agree keeps asserting parity. Golden vectors confirm the legit tolerated shape is exactly tag+one-string (carrier_pigeon/coop:loft-7) - my rule admits it byte-identically.

DELIVERABLES: flip an_unknown_kind_offer_still_carries_content_ids_on_the_wire_on_both_paths from ACCEPTED->REJECTED (mutation-proven); keep forward-compat oracle green; add golden reject vectors on single-key+batch(+claim); update honest wording (claim.rs docs + PRD) from OPEN to CLOSED; record as deliberate freeze amendment.

GATE (all green, on the uncommitted change):
- cargo test -p daemon-core -p daemon = 446 passed / 0 failed (42 test-result blocks, exit 0).
- cargo fmt --all --check = OK.
- cargo clippy --workspace --all-targets -- -D warnings = exit 0 (clean).
- scripts/check-no-floats.py = OK (self-test 6 bite cases; real scan clean).
- Golden: claim_wire_golden 16/16 (incl every_reject_vector_is_refused with the 3 new reject vectors + every_golden_vector_is_exercised), golden_vectors 2/2. Valid claim/hold-response encodings byte-identical (frozen_*_byte_for_byte_pinned green).
- just e2e = 5/5 scenarios PASS, exit 0: s1-byte-and-counts 11/11, s2-fallback 9/9, tamper-narhash 4/4, chain-s1-and-counts 13/13, s6-p2p 11/11 (76.0s). The decoder change did not disturb the s6-p2p iroh path.

MUTATION BITE (proven, not described): with reject_enumeration_shaped_unknown_offer neutralised (env-gated no-op), these went RED and restored to GREEN:
- an_unknown_kind_offer_cannot_name_content_ids_on_the_wire_on_both_paths (both single-key + batch asserts)
- an_unknown_offer_carrying_a_digest_is_rejected_not_dropped (claim path)
- the_slot_and_drop_transport_decoders_agree (coherence)
- every_reject_vector_is_refused (golden, on reject_hold_response_unknown_transport_names_content_ids)

PER-PATH STATUS: single-key (deserialize_transport_slots via decode_hold_response) CLOSED; batch (deserialize_transport_slots via decode_batch_hold_response) CLOSED; claim twin (deserialize_known_transports via decode_claim) ALSO closed via the same shared helper (kept coherent by the_slot_and_drop_transport_decoders_agree).

FROZEN SURFACE: only the ACCEPT-set narrowed; emit-set unchanged (encode builds from KnownTransport only, shape check never runs on emit). RawNarV1 / ContentKey / ProviderRecord preimage untouched. check-discovery-no-shortcut.py not weakened (not touched).

HONEST LIMIT carried forward: no length cap on the single tolerated scalar - the delimiter-crammed-single-string residual (one opaque string could carry many identities as raw text, bounded only by the 64 KiB frame) is treated as the BYTE-VOLUME concern owned by TASK-223 (its padded-frame oracle stays green). Flagged to mped-architect for the DEEP review as the key judgment call: structural closure vs a genuine length cap. Awaiting qa-test-runner + mped-architect (running in parallel), then codex DEEP re-gate.

REVIEW GATE (qa-test-runner + mped-architect, run in parallel):
- qa-test-runner: GREEN across the board. cargo test -p daemon-core -p daemon 446 passed / 0 failed / 1 ignored (network-gated TLS); fmt clean; clippy --workspace --all-targets -D warnings exit 0; check-no-floats clean; claim_wire_golden 16/16 (incl every_reject_vector_is_refused + every_golden_vector_is_exercised); golden_vectors 2/2; the 5 named decoder tests all pass; 3 new reject vectors present + exercised. No orphaned builds; disk stable.
- mped-architect: LAND THE CODE (structural rule + shared guard at all 3 wire routes + reject-not-drop + claim-path narrowing all CORRECT; mutation bite verified independently), but do NOT add a byte cap, and FIX THE OVERCLAIMING NARRATIVE. Findings addressed:
  * MEDIUM-1 (core): the "same residual as a KNOWN transports string locator" PARITY claim is FALSE. Known locators (Iroh node = 64 fixed hex via NodeId::from_str; BitTorrent infohash) are TYPE-VALIDATED fixed-length -> no cram residual. The one tolerated unknown scalar is unbounded/unvalidated -> STRICTLY MORE PERMISSIVE; {"transport":"future","loc":"blake3:a,blake3:b,..."} is still ACCEPTED and still names identities as raw text. So the invariant is discharged at the SCHEMA level (a LIST is inexpressible) but NOT literally. FIXED: deleted the false parity sentence; relabelled every CLOSED/discharged site (claim.rs helper doc + module doc + deserialize_* docs + HoldAnswer + check_single_offer_bindings residual-A + BatchHoldQuery doc; discovery.rs; PRD 827-838 + 869; golden batch note; the two flipped-test comments) to "structural list-affordance closed; crammable unbounded-scalar residual = TASK-223, strictly more permissive than a known locator".
  * MEDIUM-2: disclosed the FORWARD-COMPAT REGRESSION - a future transport needing 2+ scalar fields (host+port, node+relay) is now a HARD decode error, not an inert drop (foreclosing {"a":id,"b":id} and tolerating a multi-field future are the same affordance). Stated as an explicit cost in the helper doc + PRD + the count-bound forward-compat bullet.
  * LOW-1: disclosed that a non-OBJECT offer element is now hard-rejected (was dropped); no golden/emit wire uses that shape.
  * LOW-2: fixed helper error strings that implied a single string is safe.
- Byte cap deliberately NOT added (mped concurred): a cap does not change the KIND of residual (codex: a byte cap still admits several short ids/slot) and collides with the large-future-locator concern; the unbounded-scalar byte volume is genuinely TASK-223.

RE-GATE after the doc/wording corrections (docs + JSON notes + one Err message TEXT only; no control-flow/acceptance change - tests match the Malformed variant, not strings): cargo test -p daemon-core -p daemon = 446/0; fmt clean; clippy --workspace -D warnings exit 0; check-no-floats rc=0. just e2e 5/5 result STANDS (comment/text-only change since the green run; e2e does not inspect these strings).

HONEST FINAL SCOPE: TASK-224 closes the STRUCTURAL/list half of the unknown-KIND enumeration vector on all three tolerate-drop routes (claim + single-key + batch). It does NOT achieve literal parity with a known transport; the crammable-single-scalar byte-volume residual is owned by TASK-223. Multi-field future transports are now hard-rejected (disclosed forward-compat cost). Proceeding to commit; codex DEEP re-gate is the orchestrators call.
<!-- SECTION:NOTES:END -->
