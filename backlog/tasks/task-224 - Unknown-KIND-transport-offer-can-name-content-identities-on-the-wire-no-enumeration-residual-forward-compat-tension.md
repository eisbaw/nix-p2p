---
id: TASK-224
title: >-
  Unknown-KIND transport offer can name content identities on the wire
  (no-enumeration residual; forward-compat tension)
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-15 20:17'
updated_date: '2026-08-16 00:51'
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

CLOSING STATUS (left In Progress deliberately; code LANDED + fully gated):

COMMIT: 3f56d55 (claim: close the STRUCTURAL half of the unknown-KIND no-enumeration gap). Tree clean, no AI co-author, not pushed.

WHY NOT MARKED DONE: the Done bar is "the gap is genuinely closed on both paths." What is genuinely + mutation-provenly closed on all three tolerate-drop routes (claim + single-key + batch) is the STRUCTURAL/list form - the exact codex-proven probe ({"transport":"future","content_ids":[..]}) and every array/nested/multi-field variant. But mped-architect proved (and I confirmed) the invariant is NOT LITERALLY discharged: the one tolerated scalar is unbounded/unvalidated, so a delimiter-crammed single string ({"transport":"future","loc":"blake3:a,blake3:b,..."}) is still ACCEPTED and still names identities as raw text. That is strictly more permissive than a type-validated known-transport locator, and is a byte-volume residual owned by TASK-223. Marking Done with "enumeration closed" would repeat the exact overclaim that cost TASK-110 three codex NO-GO rounds. So: honest In Progress.

RECOMMENDATION FOR THE ORCHESTRATOR / codex DEEP re-gate (a genuine scope call I should not make alone):
  Option 1 - accept the 224/223 split as the task itself architected it: 224 = structural list-affordance closure (DONE as committed); 223 = the per-offer byte cap that bounds the crammable single scalar. Under this reading 224 is complete and can be marked Done on its structural scope, with 223 owning literal closure. This matches the task body ("a byte cap still permits several short identities in one opaque slot" - i.e. structure is 224, bytes are 223) and codex framing.
  Option 2 - hold 224 to LITERAL closure: then 224 must also bound the single scalar (a length/byte cap), which (a) collides with the recorded large-future-locator concern and (b) largely subsumes 223. mped advised AGAINST adding a cap here (a cap does not change the KIND of residual; it belongs in 223). If the orchestrator wants literal closure, the cleanest is to merge the byte cap work (223) rather than add it under 224.

WHAT IS SOLID regardless of that call: structural gap closed on both response paths + the claim twin via one shared guard; mutation-proven bite (guard neutralised -> bite test + flipped claim test + coherence test + golden every_reject_vector_is_refused all RED; restored GREEN); forward-compat preserved for a single-locator transport (multi-field future = disclosed hard-reject cost); frozen surface accept-only, emit byte-identical; full gate green (446/0, fmt, clippy --workspace -D warnings, no-floats, golden 16/16 + 2/2, just e2e 5/5 incl s6-p2p 11/11); all narrative honest (no "closed/discharged" overclaim - relabelled to structural-closed + residual=223 across claim.rs/discovery.rs/PRD/golden/tests) per mped MEDIUM-1.

NO new follow-up filed: TASK-223 already owns the crammable-scalar byte-volume residual (its padded-frame oracle stays green and its scope already covers this). If the orchestrator picks Option 2, update TASK-223 scope rather than filing a duplicate.

DEEP gate (codex) NO-GO - stays In Progress. codex VERIFIED the structural close is airtight (arrays/nested/multi-field/non-string-value/array-or-object-transport-slot/dup-keys/escape-dup all REJECT on all 3 routes; bite tests mutation-proven; valid golden byte-identical; a tag+one-string offer decodes inertly). The NO-GO is about HONESTY + RESIDUAL OWNERSHIP (the TASK-110 overclaim lesson), NOT that the structural fix is wrong.
Findings:
1 (HIGH): TASK-223 (byte cap) does NOT own/close the residual - a byte cap BOUNDS volume, it does not ELIMINATE identity naming, and even ONE accepted unasked identity is a defect per claim.rs:332; 223 also omits the Claim.transports route. The residual needs a PROPER owning task with a GENUINE closure criterion covering all 3 routes.
2 (HIGH): the residual is THREE text channels, not one: the transport TAG ({"transport":"blake3:a,blake3:b"}), an extra FIELD NAME ({"transport":"future","blake3:a,blake3:b":"x"}), and the string VALUE. Any future closure must cover the WHOLE serialized offer on every route.
3 (MED): the allowlist does not actually require a string transport tag - {"transport":7|true|null|absent,"loc":"opaque"} is accepted (mapped to empty-tag). Reject a non-string/absent transport tag so it is a strict allowlist.
4 (MED): several sites still OVERCLAIM closure/fwd-compat: claim.rs:56, :349 (seam "untouched"), :2484 (smuggling "closed", remainder "only padding"), golden claim_wire_v1.json:146/:164, discovery.rs:523. Every "no-enumeration closed/discharged/structural-closed-only-padding" claim must be corrected to: STRUCTURAL/list enumeration closed; a TEXT residual remains across 3 channels; NOT owned by 223.
5 (MED): the "frozen golden makes literal closure impossible" argument is WRONG - the golden pins ONE carrier_pigeon input; it is the CHOSEN arbitrary-string forward-compat contract (not the golden) that admits the residual. Literal closure IS possible with a substantial forward-compat cost. Correct this reasoning wherever stated.
6 (LOW): add committed regression vectors for non-string/missing transport tag, transport-slot array/object, field-name cramming, value cramming - pin every clause so a selective weakening bites.
ARBITRATION (orchestrator, vs project TCB): the ACTUAL privacy invariant (an honest peer's secret holdings never enumerated) is NOT violated by this channel - a hostile RESPONDER naming FAKE identities to an asker leaks nothing about any honest peer. It is a format-cleanliness gap per the repo's self-imposed claim.rs:332 rule. So full text-closure is worth a proper task but is not a same-severity privacy hole; the load-bearing fix NOW is honest framing + proper ownership + the allowlist tightening.

codex DEEP-gate NO-GO addressed (commit 44ae8e7; stays In Progress - coordinator owns Done after codex re-gate). codex verified the structural close is airtight (no structured-JSON evasion on any of the 3 routes; bite tests mutation-proven; valid golden byte-identical; forward-compat inert). The NO-GO was HONESTY + residual OWNERSHIP + one code tightening. Per-finding status:

FINDING 4/5 (overclaims - DONE): corrected every site that said the unknown-KIND enumeration was closed/discharged or that the residual was only padding/owned-by-223. Honest statement now everywhere - claim.rs:56 (module doc), claim.rs:349 (the seam-untouched line), claim.rs:2484 (amp-test), the helper doc, HoldAnswer/BatchHoldQuery/check_single_offer_bindings docs, the flipped+padded test comments; discovery.rs:57-66; PRD (both blocks); golden notes :146/:158/:164: TASK-224 closes the STRUCTURAL/list enumeration on all 3 routes; a TEXT residual REMAINS across THREE channels (transport TAG, extra FIELD NAME, string VALUE); NOT owned by TASK-223; literal closure IS possible at a forward-compat cost (the arbitrary-string CONTRACT, not the frozen golden, admits it). Key honest sentences quoted in code: "It is NOT literal closure of no-enumeration" and "one accepted unasked identity is already the claim.rs:332 defect" and "This residual is NOT owned by TASK-223 ... a byte cap ... does NOT ELIMINATE identity naming".

FINDING 3 (string-tag allowlist - DONE): the guard now requires a PRESENT STRING transport tag; absent/null/number/boolean/array/object tags are REJECTED (previously {"transport":7,"loc":"opaque"} decoded). Mutation-proven via an_unknown_offer_with_a_non_string_tag_is_rejected (neutralise guard -> RED on all 3 routes).

FINDING 1 (owning task - DONE): filed TASK-227 (full text-enumeration closure; all 3 routes x all 3 channels; genuine ELIMINATION criterion not a byte bound; the forward-compat-vs-enumeration architectural fork with options A/B/C; the orchestrator threat-model note that this is format-cleanliness per claim.rs:332, NOT an honest-peer-holdings leak). Referenced in code at the reject_enumeration_shaped_unknown_offer guard doc. TASK-223 annotated: byte-VOLUME only, does NOT own the enumeration residual.

FINDING 6 (regression vectors - DONE): golden reject_hold_response_unknown_transport_non_string_tag (+EXERCISED); rust an_unknown_offer_with_a_non_string_tag_is_rejected (reject, 3 routes, mutation-proven); rust an_unknown_kind_offer_text_residual_is_documented_not_closed (residual oracle - tag/field-name/value cram all still ACCEPTED, pinned OPEN so TASK-227 closure flips it deliberately); the accept-inert tag+one-string case stays pinned by claim_unknown_transport_dropped + the forward-compat test.

GATE (all green): cargo test -p daemon-core -p daemon 448/0 (2 unrelated iroh_node_lookup load-flakes, confirmed 15/15 green in isolation + a clean full rerun 448/0); cargo fmt --all --check; cargo clippy --workspace --all-targets -- -D warnings exit 0; check-no-floats rc=0; claim_wire_golden 16/16 + golden_vectors 2/2 + doc_citations green; just e2e 5/5 (s1 11/11, s2 9/9, tamper 4/4, chain 13/13, s6-p2p 11/11), exit 0. Mutation bite (guard neutralised -> RED, restored -> GREEN): list-form test, string-tag test, flipped claim-digest test, coherence test, golden every_reject_vector_is_refused. Frozen surface accept-only; emit byte-identical; RawNarV1/ContentKey/ProviderRecord preimage untouched. Commit 44ae8e7. Awaiting codex re-gate on the framing.
<!-- SECTION:NOTES:END -->
