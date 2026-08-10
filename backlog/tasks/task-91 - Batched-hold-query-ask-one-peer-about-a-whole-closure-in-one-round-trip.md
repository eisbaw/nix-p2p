---
id: TASK-91
title: 'Batched hold-query: ask one peer about a whole closure in one round trip'
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-10 07:23'
updated_date: '2026-08-10 12:20'
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
## What landed (commits da74e47, 44e0df7, f421ee5, 922323a, 96b2834, 4da9eca)

FROZEN SURFACE, unchanged: HoldQuery / HoldAnswer / HoldResponse / Claim keep
their exact bytes, now PINNED in daemon/tests/golden/claim_wire_v1.json. Those
four vectors were written and verified green BEFORE any new type existed.

ADDED alongside: BatchHoldQuery / BatchHoldAnswer / BatchHoldResponse on the same
QUERY_SCHEMA_VERSION envelope.

CAPS: MAX_BATCH_HOLD_KEYS = 256 (a real closure is ~200 paths; larger closures
chunk). Chosen so BOTH directions fit the existing 64 KiB MAX_CLAIM_WIRE_BYTES
pre-parse gate with >=25% headroom - a full query is ~15.9 KiB, a full all-Have
response ~26 KiB - and that arithmetic is a TEST, so raising the cap to 1024
fails the build (proven: mutation M5).

MEASURED (200-path closure, 8 peers, hit-rate 0.6 -> 120 resolved):
  0 ms RTT   serial 1180 round trips (9.83/substitution)  6.1 ms
             batched   8 round trips (0.07/substitution)  1.1 ms
  50 ms RTT  serial 1180 round trips                  60 434 ms
             batched   8 round trips                     412 ms
  = 147.5x fewer round trips, 146.5x faster discovery wall clock.
The 1180 (not 1600) is because a hit stops at the first holder; 1600 is the
all-miss worst case.

## Gotchas and rejected approaches (feed-forward)

* PER-ANSWER OFFERS WERE REJECTED. Mirroring HoldAnswer exactly (offers inside
  each Have) costs ~207 B/entry, so 256 all-Have answers would be ~53 KiB -
  inside the 64 KiB gate but with no room for a future field. Hoisting offers to
  the response is both smaller (~26 KiB) and TRUER: one peer answers one batch,
  so its locators are a property of the peer, not of each key. Duplicated state
  on the wire is the thing to avoid, not the thing to mirror.
* THE RESPONSE DELIBERATELY ECHOES NO KEYS. Echoing them would have made the
  answer self-describing - and would have created the one place a peer could
  name a hash the asker did not. Positional-only makes 'volunteer a holding'
  inexpressible rather than merely unanswered.
* DUPLICATE KEYS IN A BATCH ARE REJECTED, not deduplicated, so a request has one
  canonical meaning (same reasoning as the duplicate-JSON-key guard). The
  RESOLVER de-duplicates before probing, because a caller's closure list may
  legitimately repeat a hash.
* PER-KEY FAULTS ANSWER Absent, they do not propagate. Propagating would let one
  broken store path deny a peer a whole 200-path closure - a strictly worse
  outcome CREATED by batching. Per-PEER faults (no route, wire fault) do
  propagate: they are true of every key. This 'batching must not enlarge a blast
  radius' rule is the general principle, not a local choice.
* decode_batch_hold_response TAKES the asked count. A courtesy check a caller
  might forget was not enough: a short answer silently re-indexes every later
  key onto the wrong hash, which is the only way this message shape can produce
  confident wrong answers.

## Two oracles that were VACUOUS until a mutation said so

1. The batched-vs-serial equivalence test ran against ONE peer, so mutating the
   resolver to `&self.peers[..1]` (stop after the first peer) left it GREEN. Now
   three peers hold disjoint slices and each claim's attribution is checked.
2. Round trips are counted at the PeerQuery seam, so a transport that implemented
   query_batch by internally looping the single-key form would be counted as ONE
   exchange while costing N on the wire. Added
   `the_in_process_batch_really_crosses_the_wire_not_the_shim`, which tells them
   apart from OUTSIDE: only the encoding (native) path can refuse an over-cap
   batch.

## Mutation evidence: 10/10 oracles bite

Each mutation asserted to have APPLIED (exact-once anchor + post-write check)
before its result was trusted, then reverted and re-run green:
  M1 HoldAnswer tag -> SCREAMING_SNAKE ................ golden hold_response RED
  M2 Claim.holders renamed on the wire ................ golden claim RED
  M3 BatchHoldResponse drops deny_unknown_fields ...... smuggled-listing test RED
  M4 the key cap stops rejecting ...................... over-cap test RED
  M4b same mutation .................................. native-vs-shim test RED
  M5 MAX_BATCH_HOLD_KEYS 256 -> 1024 .................. wire-budget test RED
  M6 codec answer-count check removed ................. wrong-length test RED
  M7 resolver alignment check removed ................. misaligned test RED
  M8 resolver probes only the first peer .............. equivalence test RED
  M9 all_holdings() added to the index ................ no-enumeration guard RED

## Honest limits (all stated in code, not only here)

* NOT WIRED INTO THE SERVING PATH. Production still builds InMemoryDiscovery from
  --p2p-claim config (daemon/src/main.rs), so nothing in the daemon calls
  resolve_many yet and the ~300 ms narinfo->NAR window (task-35) is NOT yet used
  to issue the batch. That wiring needs the closure correlation (TASK-93) and the
  discovery seam v2 (TASK-100); doing it here would have meant designing both.
* The measurement is CONTAINER-FREE for the same reason: there is no
  peer-probing container path to run it over. It measures the library resolver
  over the real wire codec, which is where the round trips are decided, with the
  network emulated by an injected per-round-trip delay.
* A chunk probe carries the same PROBE_TIMEOUT as a single probe, so a cold peer
  that must hash 256 large NARs can time out and be treated as a miss. Safe
  direction, but it under-reports. Filed as TASK-104 (do NOT fix by raising the
  timeout).
* The measured topology is uniform (key i held by peer i % peers). A skewed real
  distribution would make the SERIAL arm cheaper (hits found at the first peer),
  so this is not the batched arm's best case, but it is not a worst case for
  serial either.
<!-- SECTION:NOTES:END -->
