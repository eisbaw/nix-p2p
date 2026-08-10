---
id: TASK-91
title: 'Batched hold-query: ask one peer about a whole closure in one round trip'
status: Done
assignee:
  - '@me'
created_date: '2026-08-10 07:23'
updated_date: '2026-08-10 20:32'
labels:
  - wave-2b
dependencies:
  - TASK-40
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
THE scaling fix for content discovery, and the first thing to build after node discovery. daemon/src/claim.rs HoldQuery carries ONE key ('The single content identity being probed'), so finding holders costs one round trip PER NAR PER PEER. A nix build of a 200-path closure against 8 peers is 1,600 probes - each with dial/timeout exposure from the safety envelope. That is not a tuning problem, it is the wrong query granularity.

It is also the wrong granularity for how nix actually behaves: nix resolves a whole CLOSURE at once and already knows every NarHash from the signed narinfos before it asks for any NAR. So the natural query is 'of these 200 hashes, which do you have?' - one round trip, one bounded answer.

WHY THIS DOES NOT BREAK THE NO-ENUMERATION RULE. The answer is a bitmap over hashes THE ASKER ALREADY NAMED. It reveals nothing about holdings the asker could not already enumerate by asking one at a time; it only removes the round trips. A peer still cannot be asked 'what do you have?'. State this explicitly in the code comment, because it looks like a listing and is not.

FROZEN-SURFACE NOTE: the claim wire schema is frozen. Adding a new message type is ADDITIVE (the envelope is version-tagged and unknown kinds are tolerated inertly); CHANGING HoldQuery's shape is not. Add BatchHoldQuery/BatchHoldAnswer alongside, keep the single-key form working, and do not mutate the frozen types.

BOUND THE ANSWER: a batch query must have a maximum key count and a maximum answer size, or it becomes an amplification and memory vector (see the 64 KiB MAX_CLAIM_WIRE_BYTES precedent). Decide and pin the cap.

TIMING OPPORTUNITY worth taking here: the daemon knows every NarHash the moment it serves the narinfos, which is BEFORE nix asks for the NARs. Task-35 measured that real gap at ~300 ms median (tail 3.08 s). A batched probe issued in that window is latency-free for the common case - this is the useful half of TASK-76's prefetch idea and it does not require speculatively fetching any bytes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A batched hold-query asks about N keys in one round trip and returns a bounded have/not-have answer; the single-key form still works and the frozen types are unchanged (new message kinds added alongside, not mutated)
- [x] #2 Key count and answer size are capped, with the caps pinned and a bite proving an over-large batch is rejected rather than allocated
- [x] #3 Measured: probes-per-substitution and discovery wall-clock for a multi-path closure, batched vs one-at-a-time, over the profiling harness - the win is demonstrated, not assumed
- [x] #4 The no-enumeration property is preserved and TESTED: a peer still cannot be asked what it holds, only whether it holds hashes the asker already named
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. PIN THE FREEZE FIRST. The claim wire was frozen in prose and guarded only by
   round-trip tests, which cannot see a rename/retag. Write
   daemon/tests/golden/claim_wire_v1.json + claim_wire_golden.rs pinning the
   BYTES of Claim / HoldQuery / HoldResponse{have,absent} in both directions
   (what we emit, what we accept), and verify green against untouched code
   BEFORE adding anything.
2. ADD the batch message kinds alongside: BatchHoldQuery{keys},
   BatchHoldAnswer{Have{blake3}|Absent}, BatchHoldResponse{offers, answers}.
   Positional answers, no keys echoed. Offers hoisted (one peer answers one
   batch). Caps: MAX_BATCH_HOLD_KEYS chosen so BOTH directions fit the existing
   64 KiB pre-parse gate with headroom, asserted by test. Reject over-cap on
   encode AND decode; never truncate. decode_batch_hold_response takes the asked
   count so the positional contract cannot be forgotten.
3. SEAM: AvailabilityIndex::answer_batch, PeerQuery::query_batch (default =
   loop the single form, so existing impls keep working and the loop is the
   measurement baseline), InProcessPeerQuery overrides it natively,
   Discovery::resolve_many (default = loop resolve) with DirectDiscovery
   overriding: per peer, one probe per chunk of distinct unresolved keys.
4. NO-ENUMERATION as a STRUCTURAL guard (daemon/tests/no_enumeration.rs): a
   source-shape rule over claim/availability/discovery - plural holdings out
   requires named keys in - because the invariant is about ABSENCE and no
   amount of calling the API proves a listing method is not there.
5. MEASURE (AC#3): daemon/examples/closure_discovery.rs counts round trips at
   the PeerQuery seam and injects a per-round-trip delay (the network is
   in-process); scripts/discoveryaxis.py runs it at 0 ms and at the profiler's
   WAN_RTT_MS, validates the run, and is folded into profile_p2p as an arm with
   --discovery-only and `just discovery`.
6. Prove every oracle by MUTATION, asserting each mutation applied.
7. Gates: build, lint, test, e2e. Then notes + forward-carry.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## ORCHESTRATOR RULING on the round-7 freeze question (implementer correctly escalated rather than deciding alone)

QUESTION: deny_unknown_fields on KnownTransport/KnownPayload tightens what the FROZEN Claim.transports
and HoldAnswer::Have.offers ACCEPT - a v1 wire carrying an extra field inside a KNOWN transport no
longer decodes. Nothing emitted changes; unknown transport KINDS are still tolerated and dropped.

RULING: APPROVED. Reasoning, in order of weight:
1. IT ALIGNS THE CODE WITH THE RULE THE FILE ALREADY DOCUMENTS. The established, written contract is
   'unknown-kind tolerated-but-inert, malformed-known errors'. A known kind carrying an unexpected
   field IS malformed-known. The code was not implementing its own stated policy; this closes that
   gap rather than inventing a new policy.
2. FORWARD COMPATIBILITY IS PRESERVED WHERE IT MATTERS. Unknown transport kinds still decode inertly,
   so a future transport still ships without a wire break. Only unknown FIELDS inside a kind we claim
   to understand are refused - which is precisely the surface the smuggling attacks used.
3. IT CLOSES A CLASS THREE REVIEWERS INDEPENDENTLY FLAGGED. codex demonstrated a 60,489 B dictionary
   entry carrying also_held, blake3 and a 60 KB pad decoding successfully through exactly this gap.
4. NO DEPLOYED PEERS EXIST. There is no released network to break; the cost of tightening is zero
   today and rises monotonically from here. Tightening later is a real break; tightening now is not.
This is recorded as a DELIBERATE FREEZE AMENDMENT, not an oversight: the accept-set narrowed, the
emit-set did not. Anyone auditing the freeze later should find this note rather than infer a slip.

REMAINING, NOT CLOSED THIS ROUND (correctly deferred): the frozen single-key HoldAnswer::Have.offers
still has NO count cap - 622 offers = 65,440 B against an 88 B query = 743.6x amplification. That is
the SAME defect class just fixed for the batch path, on the frozen single-key path, and it needs the
same decoder-acceptance decision I just ruled on. Filed as its own task.

## GATE-REGIME WARNING FROM TASK-109 (2026-08-10)

task-109 measured the verification gate at the commit that opened it: cargo test --locked
--workspace, N=20 IDENTICAL binaries, 14 CPU burners on a 14-core host -> 9/20 = 45% failure rate.
Zero of those failures were product defects; all were load-sensitive test assumptions.

CONSEQUENCE FOR THIS TASK: round-7's gate numbers were taken under that regime. A single green
'test 0' from that period is one sample from a distribution that was green about 55% of the time,
so it is NOT the evidence it was quoted as. This does not imply round-7's fix is wrong - the
observed flakes were in testproxy faults/premature_eof and the residency oracle, none of which is
task-91's subject - but the CERTIFICATION is weaker than recorded.

WHAT TO DO AT THE RE-GATE: re-run the gate on this task's head after task-109's fixes land, and
quote the rate with its N and load per the new TESTING.md 'Gate honesty' rules. Do not carry the
old single-run green forward as if it were equivalent.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Batched hold-query landed as an ADDITION to the frozen claim wire, with the
frozen bytes pinned first - and then landed AGAIN after a three-reviewer DEEP
gate returned NO-GO on the first attempt. This summary describes the second,
corrected shape.

WHAT: BatchHoldQuery / BatchHoldAnswer / BatchHoldResponse on the same
QUERY_SCHEMA_VERSION envelope; HoldQuery / HoldAnswer / HoldResponse / Claim
byte-identical and pinned in daemon/tests/golden/claim_wire_v1.json in both
directions. Seam: AvailabilityIndex::answer_batch, PeerQuery::query_batch,
Discovery::resolve_many, each with a default that loops the single-key form.

LOCATORS BIND TO THEIR KEY, which is the design question the first attempt got
wrong. A transport offer is not always peer-scoped: iroh's is a NodeId (one per
PEER), BitTorrent's is an infohash (one per CONTENT). The response carries an
offer DICTIONARY and each Have names its own entries BY INDEX, with every index
in range, no index repeated inside one answer, and every dictionary entry
referenced by at least one Have - so an all-Absent response cannot carry a
locator at all. Chosen over inline per-answer offers on a measurement, not a
preference: a full 256-key answer with an iroh locator plus a per-content
infohash is 58 910 B indexed and ~79 912 B inlined against a 65 536 B gate, so
inlining makes a legal, fully-populated answer unsendable once a second
transport exists.

NO ENUMERATION: the answer is positional over keys the asker named and carries
no keys of its own - the golden response bytes contain no `sha256:` string at
all - so volunteering a holding is inexpressible rather than merely unanswered.
Made structural in daemon/tests/no_enumeration.rs, which now also sees a listing
hidden in a WRAPPER return type and scopes its exemptions per file.

BOUNDED, as a property of the messages rather than of their callers:
MAX_BATCH_HOLD_KEYS = 256 and MAX_BATCH_HOLD_OFFERS = 512, applied on encode, on
decode, to the caller-supplied asked count itself, in the responder, and in the
compatibility shim. Every encoder gates its OUTPUT length, so this node cannot
emit a message it would itself refuse. Over-cap is rejected, never truncated.

MEASURED (200-path closure, 8 peers, 120 resolved): 1180 -> 8 round trips
(147.5x). Round trips are a pure COUNT and that is the result. The wall-clock
figure is NOT a second, corroborating result: the harness computes the expected
shaped time as round_trips x the injected RTT and invalidates a run outside the
recovery band, so under a 50 ms injected delay the 60 483 ms -> 413 ms figure is
that same count restated. The honest floor is the UNSHAPED arm, ~5.5x (single-digit
milliseconds, so noisy run to run), against the most naive baseline available:
strictly sequential across the 8 peers, no pipelining. The harness itself was
printing both factors in one sentence and emitting the derived one in its JSON,
so the correction is in the INSTRUMENT, not only in this text - it now names the
round-trip count as the result, labels the shaped factor as confirming the
emulation, and prints the unshaped floor. `just discovery` re-runs it in ~1 min.

Gates: build/lint/test/e2e/discovery all exit 0; 279 cargo tests; 26/26 e2e
scenarios. 19/19 mutations bit a NAMED check, each verified to have APPLIED and
to have been RESTORED - one of which (the caller-side key cap) came back GREEN
first time because the oracle asserted the outcome rather than the boundary, and
was rewritten until it bit.

NOT DONE, deliberately: resolve_many is not yet called from the serving path, so
the ~300 ms narinfo->NAR window is not exploited (TASK-93 + TASK-100); a chunk
probe keeps the 5 s single-probe bound so a cold peer can under-report
(TASK-104); resolve_many has no TOTAL deadline (TASK-106); the batch path can
log up to 256 lines per message (TASK-107). Three lines were removed from
claim.rs - the bodies of three pre-existing encoders gaining the output size
gate - and none is in a type definition, a serde attribute, a const or a
decoder. THIS ROUND HAS NOT BEEN INDEPENDENTLY REVIEWED: the DEEP gate must be
re-run by the orchestrator; the implementer does not self-certify.
<!-- SECTION:FINAL_SUMMARY:END -->
