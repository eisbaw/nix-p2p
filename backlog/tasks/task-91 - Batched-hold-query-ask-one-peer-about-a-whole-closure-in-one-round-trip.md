---
id: TASK-91
title: 'Batched hold-query: ask one peer about a whole closure in one round trip'
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-10 07:23'
updated_date: '2026-08-10 13:08'
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
## CROSS-MODEL DEEP GATE: NO-GO (codex gpt-5.6, read-only, 2026-08-10) - and it is WORSE than the architect found

Codex ran on retry after its first invocation died with an internal router error (recorded in git notes).
It independently confirmed G1/G2/G3 AND found four things the architecture review did not. All by
mutation under /tmp; no repository edits.

C1 (CRITICAL, ESCALATES G2 FROM A DOC GAP TO A LIVE BUG). Response-wide offer hoisting MISBINDS
   content-specific locators - this is not a future limitation, it is a present correctness defect.
   BatchHoldResponse has ONE global offers list (claim.rs:541) but BitTorrent{infohash} is
   content-specific (claim.rs:301). The compatibility shim retains only the FIRST Have's offers
   (discovery.rs:272), then the resolver CLONES those onto EVERY Have (discovery.rs:588).
   RUNTIME TEST: two keys with distinct BLAKE3s and distinct BitTorrent infohashes -> KEY 2'S CLAIM
   RECEIVED KEY 1'S INFOHASH. Also: an all-Absent response can legally carry arbitrary BitTorrent
   offers, so locators need not bind to any asked key and can VOLUNTEER content-specific holdings -
   which is a no-enumeration vector as well. Verdict: needs a schema redesign BEFORE freezing -
   per-Have offers, an indexed offer dictionary, or a separate global type restricted to genuinely
   peer-scoped locators.

C2 (CRITICAL, = G1 confirmed, with more attack surface). BatchHoldAnswer lacks deny_unknown_fields
   (claim.rs:546). Wires that decode successfully today: Have with a valid blake3 PLUS a different
   blake3_shadow; Have with an also_held list containing an UNASKED key; Absent carrying a blake3 or
   key. So an accepted wire can carry two identity-like values while the decoder silently picks one -
   the two-blob-claim class the round-3 freeze closed, reappearing. Codex independently reached the
   same conclusion as the architect that C1 and C2 must be fixed TOGETHER.

C3 (HIGH, NEW - the decode side has no cap at all). encode_batch_hold_response checks only
   answers.len() (claim.rs:850) and bounds neither offers nor final serialized size;
   decode_batch_hold_response TRUSTS keys_asked and never independently enforces MAX_BATCH_HOLD_KEYS
   (claim.rs:874). Reproduced: 1 answer + 1,000 iroh offers encoded to 95,144 B (over the 64 KiB gate);
   a 257-answer response DECODED when passed keys_asked=257; a 91-byte one-key query can receive an
   accepted 52,644-byte response = 578.5x WIRE AMPLIFICATION. AvailabilityIndex::answer_batch has only
   debug assertions (availability.rs:715), so the cap is a caller precondition, not a type invariant.

C4 (HIGH, NEW - the golden freeze has a specific hole, proven by surviving mutation). The change IS
   textually additive (585 insertions, zero deletions) and the golden DOES catch a renamed
   HoldQuery.key (exit 101). BUT its only Have vector uses NON-EMPTY offers
   (claim_wire_golden.rs:159), so adding skip_serializing_if="Vec::is_empty" - which CHANGES the legal
   legacy Have{offers:[]} bytes - left all 7 golden tests GREEN. Removing #[serde(default)], which
   changes decoder acceptance of omitted offers, also survives. Needs an explicit empty-offers encoding
   vector plus decode-only vectors for accepted noncanonical legacy inputs.

C5 (MEDIUM, NEW - the no-enumeration guard is demonstrably bypassable, not merely narrow). A /tmp
   mutation added a NO-ARGUMENT method returning every derived holding's BLAKE3 wrapped in
   BatchHoldResponse; BOTH no_enumeration tests still passed (exit 0). The honest responder does derive
   answers from caller-supplied keys, but the GUARD does not enforce it.

VERIFIED GOOD by codex (independent of the architect): both batch decoders run the 64 KiB size gate
BEFORE duplicate scanning and typed parsing; empty / over-256 / repeated semantic query keys rejected
without truncation; 256 copies of one key rejected; a malformed NarHash mid-batch rejects the whole
query; whole-tree duplicate JSON fields including nested answer fields rejected; unknown transport kinds
dropped inertly while malformed known transports fail hard; positional answer length re-checked at the
mapping site.

Codex gates from a pristine HEAD copy under /tmp: build 0, lint 0, test 0 (257 cargo tests + script
gates). Its adversarial suite reproduced 8/8 asserted bad behaviours. Note a preliminary just test
exited 1 only because redirected cargo output hid ./target/debug/daemon from check-rewrite-realnix -
an artifact of its own redirection, not a product fault.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Batched hold-query landed as an ADDITION to the frozen claim wire, with the
frozen bytes pinned first.

WHAT: BatchHoldQuery / BatchHoldAnswer / BatchHoldResponse on the same
QUERY_SCHEMA_VERSION envelope; HoldQuery / HoldAnswer / HoldResponse / Claim
byte-identical and now pinned in daemon/tests/golden/claim_wire_v1.json (both
directions - what we emit and what we accept). Seam: AvailabilityIndex::
answer_batch, PeerQuery::query_batch, Discovery::resolve_many, each with a
default that loops the single-key form so no existing impl changed.

MEASURED (200-path closure, 8 peers, 120 resolved): 1180 -> 8 round trips
(147.5x), and 60 434 ms -> 412 ms discovery wall clock (146.5x) with a 50 ms
per-round-trip delay injected. Round trips are a pure count; the wall clock is
measured under an emulated network, stated as such. `just discovery` re-runs it
in ~1 minute.

NO ENUMERATION, which is the design question this task really turns on: the
answer is positional over keys the asker named and carries no keys of its own -
the golden response bytes contain no `sha256:` string at all - so volunteering a
holding is inexpressible rather than merely unanswered. Made structural in
daemon/tests/no_enumeration.rs: across claim/availability/discovery, plural
holdings out requires named keys in.

BOUNDED: MAX_BATCH_HOLD_KEYS = 256, chosen against the existing 64 KiB wire gate
rather than beside it (full query ~15.9 KiB, full all-Have response ~26 KiB) and
asserted, so raising it to 1024 fails the build. Over-cap is rejected on encode
AND decode, never truncated.

Gates: build/lint/test/e2e all exit 0; 257 cargo tests; 26/26 e2e scenarios.
10/10 oracles proven to bite by mutation, each mutation asserted to have applied
- one of which (M8) exposed a genuinely vacuous equivalence test that had been
running against a single peer, now fixed.

NOT DONE, deliberately: resolve_many is not yet called from the serving path
(production still wires InMemoryDiscovery from config), so the ~300 ms
narinfo->NAR window is not exploited - that needs TASK-93 + TASK-100. A chunk
probe keeps the 5 s single-probe bound, so a cold peer can under-report;
TASK-104. This is a DEEP-gated task and independent review has NOT run yet.
<!-- SECTION:FINAL_SUMMARY:END -->
