---
id: TASK-100
title: >-
  ContentDiscovery seam v2: one trait, many swappable mechanisms (LAN, tracker,
  direct probe, DHT)
status: To Do
assignee: []
created_date: '2026-08-10 09:26'
updated_date: '2026-08-10 14:07'
labels:
  - wave-2b
dependencies:
  - TASK-66
  - TASK-91
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner directive 2026-08-10: design discovery NOW behind a seam so mechanisms can be swapped, because iroh's built-in discovery solves node ADDRESSES and not content.

A seam already exists and is not sufficient. daemon/src/discovery.rs has trait Discovery { async fn resolve(&self, key: &NarHashKey) -> Option<Claim> } plus a PeerQuery seam for one-peer/one-key probes. Five limits, four of which its own doc comments already admit:

1. SINGLE HOLDER. resolve returns one Claim, and InMemoryDiscovery::announce REPLACES on key ('last announce wins'). At N peers several hold the same path; there is no failover and no load spreading (TASK-66).
2. SINGLE KEY. One round trip per NAR per peer. A 200-path closure across 8 peers is 1,600 probes (TASK-91).
3. MISS AND FAULT ARE THE SAME VALUE. The doc says a broken mechanism 'logs it and still returns None ... for wave-2a a fault and an absence are indistinguishable'. That is right for a local probe and WRONG for a tracker or DHT, where 'the tracker is down' must be distinguishable from 'nobody has it' - otherwise a dead mechanism looks like a cold swarm forever and no operator can tell.
4. NO COST CLASS. A LAN probe (~1 ms), a tracker query (~50 ms) and a mainline lookup (median 647 ms, p98 3.7 s) cannot share one call shape with no budget. The caller must be able to try cheap mechanisms first and abandon expensive ones against a deadline - the median NAR is 96 KiB and fetches from upstream in ~5 ms, so an unbudgeted lookup is strictly worse than not asking.
5. NO PUBLISH SIDE. Announcing is not in the trait, yet mechanisms differ in whether they CAN publish (a tracker can, a direct probe cannot) and whether publishing is permitted at all (publishing is enumeration - TASK-96 decides).

WHAT TO BUILD. A seam carrying: batch resolve (many keys, one call), multiple holders per key, an explicit outcome distinguishing HOLDERS / NONE / UNAVAILABLE(reason), a declared cost class and per-call deadline, and an optional publish capability a mechanism may decline. Plus a LAYERED RESOLVER that runs mechanisms cheapest-first with a total budget, returns as soon as it has enough holders, and degrades to upstream rather than waiting.

NON-NEGOTIABLE: the no-enumeration property must stay STRUCTURAL, as it is today ('there is deliberately NO list-holdings method, so the invariant is structural at this seam, not just at the index'). A batch query asks about keys the caller already named; it must remain impossible to ask a peer what it has.

Mechanisms to slot behind it: InProcess (tests, exists), DirectPeerProbe (exists), LAN/mDNS (TASK-89), Tracker (TASK-101), DHT (TASK-73, gated on TASK-96). Do NOT build the DHT here.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The seam supports batch resolve over many keys and returns MULTIPLE holders per key; the existing single-key path is expressible through it and the in-process and direct-probe mechanisms are ported with no behaviour change (existing tests still pass)
- [ ] #2 A mechanism failure is distinguishable from a miss at the trait level, and the layered resolver treats them differently - prove by mutation that a mechanism returning UNAVAILABLE is visible in the daemon's log/metrics and does NOT silently read as 'nobody has it'
- [ ] #3 Each mechanism declares a cost class and every resolve honours a caller deadline; a deliberately slow mechanism is abandoned at the deadline and the build falls back to upstream, proven by a test that fails if the deadline is not enforced
- [ ] #4 No-enumeration remains STRUCTURAL: there is no list-holdings method on the trait or any implementation, and a test asserts a peer cannot be asked what it holds - only whether it holds keys the asker named
- [ ] #5 The layered resolver tries mechanisms cheapest-first and stops early once satisfied; measured: probes issued and wall-clock for a multi-path closure with LAN-only, tracker-only, and layered configurations
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
