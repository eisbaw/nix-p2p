---
id: TASK-91
title: 'Batched hold-query: ask one peer about a whole closure in one round trip'
status: Done
assignee:
  - '@me'
created_date: '2026-08-10 07:23'
updated_date: '2026-08-10 14:36'
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

## IMPLEMENTER PLAN (fixing the DEEP-gate NO-GO, 2026-08-10)

C1 SCHEMA DECISION: option (b), an INDEXED OFFER DICTIONARY.
  BatchHoldResponse keeps ONE response-level `offers: Vec<KnownTransport>` (the
  dictionary); every `BatchHoldAnswer::Have` carries `offer_indices: Vec<u16>`
  naming ITS OWN locators inside it. Decode enforces referential integrity:
  every index in range, no index repeated inside one Have, and EVERY dictionary
  entry referenced by at least one Have (so an all-Absent response can no longer
  carry a locator at all - the no-enumeration half of C1).
  WHY (b) OVER (a) per-Have offers: (a) is simpler, but it duplicates the same
  locator up to 256x on the wire and breaks the cap's own headroom argument as
  soon as a second transport exists - a 256-Have answer with iroh+bittorrent per
  key is ~68 KiB under (a), OVER the 64 KiB pre-parse gate, i.e. that peer could
  not answer a legal full batch at all. Under (b) the same case is ~30 KiB.
  (b) also fixes H2: the resolver selects each claim's own small offer vector
  instead of cloning the whole dictionary 256 times.
  COST of (b), stated honestly: an index space is a re-binding hazard, and the
  tolerate-but-drop rule for unknown transports would SHIFT indices. So decode
  parses the dictionary into POSITION-PRESERVING slots (unknown -> None), checks
  bindings against the RAW positions, then compacts and REMAPS. BatchHoldResponse
  therefore no longer derives Deserialize: decode_batch_hold_response is the only
  way to get one from bytes, so the remap cannot be bypassed.

C2 SERDE FACT ESTABLISHED BY EXPERIMENT (not by prose): `deny_unknown_fields`
  on an internally-tagged enum DOES bite on STRUCT variants but is SILENTLY
  INERT on UNIT variants (`{"answer":"absent","blake3":"x"}` decoded fine).
  Fix: `Absent` becomes an EMPTY STRUCT variant `Absent {}` - identical wire
  bytes `{"answer":"absent"}`, now strict. HoldAnswer is NOT touched (frozen).

C3 decode enforces MAX_BATCH_HOLD_KEYS on keys_asked itself; MAX_BATCH_HOLD_OFFERS
  caps the dictionary; check_size() runs on the OUTPUT of every encoder.
  answer_batch returns Result and hard-checks the cap.

C4 golden gains: empty-offers ENCODING vector, decode-only noncanonical vectors,
  the reserved v2 field names (relay.blob / signatures.key_id+sig), a
  distinct-locator batch vector, and a test that every vector in the file is
  exercised by name.

C5 no_enumeration: ALLOWED becomes (file, name); wrapper types (BatchHoldResponse)
  count as plural holdings; key-bearing PARAM types (HoldQuery/BatchHoldQuery)
  count as named keys in; honest-limits states the three-module scope.

G3 prose only: AC#3's wall-clock figure is the round-trip count times the knob by
  harness construction. Honest floor is the 0 ms arm.

## ROUND-6 FIX LANDED (implementer, 2026-08-10). A RE-GATE IS REQUIRED - I DO NOT SELF-CERTIFY.

Commits: d6ea284 (C5 guard), 20357ce (C1-C4 schema + codec + wiring + golden).

C1 - RESOLVED BY SCHEMA CHANGE, option (b), an INDEXED OFFER DICTIONARY.
  BatchHoldResponse keeps ONE response-level `offers: Vec<KnownTransport>`; every
  `Have` carries `offer_indices: Vec<u16>` naming ITS OWN entries. Three binding
  rules, enforced on encode AND decode: every index in range, no index repeated
  inside one answer, every dictionary entry referenced by at least one Have. The
  last one is what kills the no-enumeration half - an all-Absent response is now
  REQUIRED to carry an empty dictionary, so a content-specific locator can never
  be volunteered.
  WHY (b) AND NOT (a) PER-HAVE INLINE OFFERS, on measurement not preference: a
  full 256-key answer carrying an iroh locator plus a per-content infohash is
  58 910 B indexed and ~79 912 B inlined, against a 65 536 B pre-parse gate. The
  inline form makes a legal, fully-populated answer UNSENDABLE the moment a second
  transport exists (TASK-75) - it does not merely waste bytes, it breaks the cap's
  own headroom argument. (b) also fixes H2: the resolver selects each claim's own
  small offer vector instead of cloning the dictionary per answered key.
  THE COST OF (b), STATED: an index space is itself a rebinding hazard, and the
  tolerate-but-drop rule for unknown transports would SHIFT indices. So the
  decoder parses the dictionary into POSITION-PRESERVING slots, validates against
  the RAW positions, then compacts and RE-INDEXES together - and BatchHoldResponse
  no longer derives Deserialize at all, so decode_batch_hold_response is the only
  way to build one from bytes and the remap cannot be bypassed. Pinned by a
  decode-only golden vector and by a mutation (M5).
  compact_offer_slots uses `get`, not `[]`: an out-of-range index is already
  rejected upstream, but a decoder that PANICS on hostile input is a DoS even when
  the panic is technically fail-fast.

C2 - RESOLVED, and the serde fact was established BY EXPERIMENT, not by reading.
  `deny_unknown_fields` on an internally-tagged enum IS honoured for STRUCT
  variants and is SILENTLY INERT for UNIT variants: `{"answer":"absent","blake3":
  "..."}` decoded cleanly with the attribute present. `Absent` is therefore an
  EMPTY STRUCT variant `Absent {}` - byte-identical encoding, strict decoding.
  The prose now states the real behaviour. HoldAnswer is NOT touched: it has the
  same laxity and is already frozen, so tightening it would itself be a wire
  change. C1 and C2 landed together, so no future per-answer field is welded shut
  by C2's strictness - the per-answer offer binding is IN the schema now.

C3 - RESOLVED at four sites. decode_batch_hold_response applies the key cap to
  `keys_asked` ITSELF, before the parse; MAX_BATCH_HOLD_OFFERS caps the
  dictionary; `encode_checked` gates the SERIALIZED length of all five encoders
  (claim, hold query, hold response, batch query, batch response);
  AvailabilityIndex::answer_batch returns Result and hard-checks the cap instead
  of debug_asserting it, and the compatibility shim checks before issuing any
  probe. Note the shim's behaviour CHANGED deliberately: it used to answer an
  over-cap batch happily on the reasoning that it sends N legal single-key
  messages. True, but its RETURN VALUE is a wire message, and an over-cap
  BatchHoldResponse is one no decoder on the network accepts.

C4 - RESOLVED. Golden gains an empty-offers ENCODING vector, decode-only vectors
  for legal inputs we accept but never emit (omitted `transports`, omitted
  `offers`, a dropped unknown transport kind, the unknown-slot re-index), the
  RESERVED v2 fields pinned POPULATED (M2: `relay.blob`, `signatures[].key_id`,
  `signatures[].sig` were renameable with the whole suite green), an all-absent
  batch vector, a distinct-locator batch vector, and a census test so a vector in
  the file that nothing asserts fails the suite. 6 vectors -> 14.

C5 - RESOLVED, and the guard had a THIRD defect nobody had reported: its parser
  silently mis-read `pub(crate) fn` (it split the parameter list at the paren in
  `pub(crate)`, giving name "", params "crate", and the entire real signature as
  the return type). Every `pub(crate)` function in the three modules was being
  checked against the wrong text. Plus the two reported: PLURAL_WRAPPERS so a bare
  `BatchHoldResponse` return counts as plural holdings, and (file, name) ALLOWED
  scoping. Honest limits now state the three-module scope and that the wrapper
  list is hand-maintained.

G3 - the AC#3 double-count is corrected in the Final Summary below.

MUTATION EVIDENCE: 17/17 mutations bit a NAMED check, each verified to have
APPLIED (file sha compared before/after) and each verified RESTORED (sha back to
HEAD) before the next. One mutation (M8, removing the keys_asked cap) came back
GREEN on the first pass - the answer-count cap downstream caught the same wire
and produced an indistinguishable error, so the test was asserting the OUTCOME
rather than the BOUNDARY. The oracle was rewritten to hand in non-JSON bytes with
an illegal count, which can only be refused if the count is checked before the
parse; it then bit. That is exactly the class of vacuous oracle this repo keeps
finding, and it was found by mutating rather than by reading.

GATES (all inside `nix develop`): build 0, lint 0, test 0, e2e 0 (26/26
scenarios), discovery 0. 131 daemon lib tests + 14 golden + 6 no-enumeration.

HONEST LIMITS OF THIS ROUND
  * Three lines were REMOVED from claim.rs: the bodies of encode_claim,
    encode_hold_query and encode_hold_response, each gaining the output size gate.
    `git diff da74e47^..HEAD -- daemon/src/claim.rs | grep '^-' | grep -v '^---'`
    returns exactly those three `serde_json::to_vec(...)` lines. NONE is in a type
    definition, a serde attribute, a const or a decoder, and the golden byte
    vectors prove no encoding changed. This is a deliberate trade: leaving a known
    encode-side amplification gap unfixed on a DEEP-gated task is worse than a
    non-zero (and precisely characterised) removed-line count.
  * The per-content worst case has only ~10% headroom under the wire gate, not
    the 25% the common cases keep. Asserted in both directions so it cannot rot
    into an assumption, but it is thin, and a third per-content locator kind would
    need the cap re-derived.
  * The version gate still reads the version from the PARSED value, so a future
    version whose SHAPE also differs is reported as Malformed rather than
    UnsupportedVersion. Still rejected; the diagnostic is the weaker of the two.
    Shared with all five decoders; fixing it piecemeal here would be inconsistent.
  * `deserialize_transport_slots` DUPLICATES the tolerate-but-drop loop of the
    frozen `deserialize_known_transports` rather than refactoring it, to keep the
    freeze audit over claim.rs meaningful. The shared rule (which tags are known)
    lives once; a test asserts the two decoders agree on the same inputs.
  * One test failure was observed and is NOT mine: testproxy
    truncated_nar_fault_short_reads failed once under the full parallel run and
    passed 3/3 in isolation. testproxy is crate-independent from daemon and this
    change touches daemon only. Filed as TASK-108.

FOLLOW-UPS FILED: TASK-106 (M1 total deadline + the per-peer-fault contradiction),
TASK-107 (M3 log flood, M4 test name, M5 or_insert_with side effect), TASK-108
(the testproxy flake). Forward-carried to TASK-100/101/103/75.

## G3 WAS WIDER THAN THE GATE SCOPED IT (found while fixing it)

The finding was handed over as prose-only, on the reading that the harness emits
no wall-clock speedup factor and TESTING.md quotes none. The second half is true;
the first is not. scripts/discoveryaxis.py emits wall_clock_reduction_factor_shaped
in its JSON and PRINTED both factors in one semicolon-joined sentence every run:
'round trips 147.5x fewer; discovery wall clock under emulated latency 146.2x
faster'. That is the doubled claim, produced by the instrument. Correcting only the
task notes would have left the machine still saying it.
Fixed in e8a8175: the printer names the round-trip count as THE result, labels the
shaped factor as confirming the emulation rather than corroborating the count, and
prints the unshaped floor (5.5x this run) with its caveats; the JSON gains
wall_clock_reduction_factor_shaped_is_derived and ..._unshaped. Both rules bite by
mutation against discoveryaxis --self-test (M18, M19).
This is the fifth-round pattern holding: assume one more hole remains.
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
