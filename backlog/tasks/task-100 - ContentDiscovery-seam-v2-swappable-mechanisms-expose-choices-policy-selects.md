---
id: TASK-100
title: 'ContentDiscovery seam v2: swappable mechanisms expose choices, policy selects'
status: To Do
assignee: []
created_date: '2026-08-10 09:26'
updated_date: '2026-08-10 22:53'
labels:
  - wave-2b
dependencies:
  - TASK-66
  - TASK-91
  - TASK-102
  - TASK-104
  - TASK-106
  - TASK-107
  - TASK-110
  - TASK-114
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Replace the insufficient single-key/single-holder seam with a mechanism-neutral discovery domain boundary. Adapters batch named keys, return multiple holders and typed MISS versus UNAVAILABLE outcomes, enforce caller deadlines and publication eligibility, and report measured latency/control cost/capabilities. A separate resolver execution plan—explicit configuration now, frozen policy artifact later—chooses ordering, parallelism, racing and stop conditions. The seam/registry must not hardcode cheapest-first, Iroh-first or any production preference before holdout. Mechanisms include in-process/direct probe, LAN/node discovery, tracker and TASK-103's selected global-DHT implementation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The seam batch-resolves named keys to multiple holders, with single-key compatibility; in-process and direct-probe adapters preserve existing behavior.
- [ ] #2 MISS, UNAVAILABLE(reason), deadline expiry and partial results are typed and observable; a dead mechanism cannot silently read as nobody-has-it.
- [ ] #3 Every adapter enforces the caller's total deadline and reports capabilities plus observed latency/control bytes/resource outcome; these are measurements, not a timeless cheap/expensive class.
- [ ] #4 No-enumeration is structural: no listing method exists, batches contain only asker-named keys, and a negative mutation proves inventory cannot be requested.
- [ ] #5 Ordering, parallelism/racing and stop conditions come from an explicit versioned execution plan. A named fixed baseline is testable, but neither the seam nor registry selects a production default before TASK-123.
- [ ] #6 Every publish-capable adapter consumes the single TASK-102 eligibility decision, preserves transport offers, and emits mechanism-neutral publication outcomes; bypassing the filter makes a test fail.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Forward-carried from TASK-91 (batched hold-query) - read before designing the trait

TASK-91 landed the batch CALL SHAPE this seam has to carry. Take it as given
rather than re-deriving it:

* The plural method is `resolve_many(&self, keys: &[NarHashKey]) ->
  Vec<Option<Claim>>`, POSITIONAL: result[i] is about keys[i], length equal,
  duplicates in the caller's list handled by the impl. Positional (rather than a
  map keyed by hash) is not a style choice - it is what makes the ANSWER unable
  to name a key the asker did not, which is the no-enumeration invariant in
  structural form. A `HashMap<NarHashKey, Claim>` return would quietly re-open it.
* Give the plural method a DEFAULT implementation that loops the singular one.
  That is what let TASK-91 add batching without touching any existing impl, and
  it doubles as the honest one-at-a-time baseline the measurement compares to.
* A mechanism that natively batches must be DISTINGUISHABLE from one that loops
  internally, or every round-trip count taken over the seam is wrong. TASK-91's
  trick: only the encoding path can refuse an over-cap batch, so handing both an
  over-cap batch tells them apart from outside
  (`the_in_process_batch_really_crosses_the_wire_not_the_shim`). Provide an
  equivalent discriminator per mechanism.
* Blast-radius rule, and it generalises to every mechanism here: a per-KEY fault
  must degrade that key only (answer Absent, log it), while a per-MECHANISM fault
  (no route, wire fault) propagates. Batching must never make one bad path deny a
  whole closure.
* MAX_BATCH_HOLD_KEYS = 256 is a WIRE bound (message size and per-message work),
  not a caller bound. A caller with a 1000-path closure chunks; the seam should
  chunk for it rather than making every caller remember.
* Whatever this seam returns, keep `daemon/tests/no_enumeration.rs` passing - it
  is a source-shape rule (plural holdings out requires named keys in) over
  claim/availability/discovery. Add this module to its SOURCES list.

## CARRIED FORWARD from TASK-91 round 6 (the batch call shape you inherit)

A TRANSPORT OFFER IS NOT ALWAYS PEER-SCOPED, and assuming it is produced a live
bug. Iroh's locator is the holder NodeId - one value for a whole batch -
but BitTorrent's is an infohash, which addresses one piece of CONTENT. The
first batch response hoisted ONE offer list to the envelope and let every Have
share it; key 2's claim silently received key 1's infohash. The fix:
BatchHoldResponse carries an offer DICTIONARY and each Have names its own entries
BY INDEX (claim.rs BatchHoldAnswer::Have::offer_indices), with every index in
range, no index repeated inside one answer, and every dictionary entry referenced
by at least one Have - so an all-Absent response cannot carry a locator at all.
DO NOT re-introduce a response-wide offer list in any new mechanism.

TWO RULES THAT COST NOTHING TO KEEP AND ARE EXPENSIVE TO RE-DISCOVER:
  * Unknown transport kinds are tolerate-but-drop. On an INDEXED list that means
    the decoder must keep position-preserving SLOTS, validate against the RAW
    positions, then compact and RE-INDEX together. BatchHoldResponse deliberately
    has no derived Deserialize so this cannot be bypassed.
  * serde deny_unknown_fields on an internally-tagged enum is honoured for STRUCT
    variants and SILENTLY INERT for UNIT variants. Any new answer enum must use
    empty struct variants (`Absent {}`), which emit identical bytes.

BOUNDS ARE TYPE INVARIANTS, NOT CALLER PRECONDITIONS: the cap is applied to the
caller-supplied asked-count itself, the responder hard-checks it (it was a
debug_assert, i.e. absent in release), the compatibility shim checks it before
issuing any probe, and every encoder gates its OUTPUT length so this node cannot
emit a message it would itself refuse.

ALSO INHERITED, and it is a defect not a style note: DirectDiscovery::resolve_many
has NO TOTAL DEADLINE (per-probe only; 8 peers x 4 chunks x 5 s = ~31 min worst
case) and it CONTRADICTS the per-peer-fault rule query_batch itself documents.
Filed as TASK-106 and deliberately not fixed inside task-91's fix cycle. This task
re-shapes the same call - do not inherit the assumption that a per-probe bound is
a bound.
<!-- SECTION:NOTES:END -->
