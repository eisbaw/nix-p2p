---
id: TASK-72
title: >-
  A single large NAR OOMs the node, and the index promises more than the
  provider can serve
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-09 17:45'
updated_date: '2026-08-09 23:12'
labels: []
dependencies:
  - TASK-65
  - TASK-50
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Two coupled gaps found 2026-08-09 while answering the owner's question 'do we need to publish and hold in memory what we have cached locally?'. Answer: no - and here is why it matters.

GAP 1 - UNBOUNDED SINGLE-SERVE COST (self-DoS). daemon/src/main.rs:243 setup_iroh_provider seeds EAGERLY at startup: std::fs::read(path) reads the whole NAR into RAM, provider.seed() clones it again into MemStore (transport_iroh.rs:350), and nothing ever evicts it. Combined with the TASK-65 holder slope of 2.0033 B RAM per B NAR, serving one NAR costs ~2x its size in RAM, unbounded. On the owner's real store the tail is brutal: mean NAR 1.44 MiB (~2.9 MiB RAM, fine) but p100 is 3186 MiB -> ~6.2 GiB of RAM for a SINGLE serve (model output, extrapolated past the fitted grid). Since the daemon is outside the trust base, ANY peer can request the largest NAR we announce; there is no size cap on what we agree to serve. The safety envelope's NarSize abort bounds a LYING peer on the FETCH side - it does not bound a legitimately huge NAR on the SERVE side. Severity: robustness/availability, not integrity (Nix still re-verifies sig+NarHash, so no wrong bytes) - but a peer can OOM us on demand.

GAP 2 - INDEX COVERAGE != PROVIDER COVERAGE. The availability index (TASK-50) answers hold-queries for the whole store by deriving NarHash->StorePath->--dump->BLAKE3 on demand, so it can say 'yes' for all 108,401 local paths. The provider can only actually SERVE what was eagerly seeded via --iroh-seed-nar. So a positive claim does not imply a servable blob. Today that is masked because the harness seeds exactly what it claims; in a real deployment the index would promise what the provider cannot deliver, producing dial-then-fail for every unseeded path.

Both gaps have the same root: the provider has no on-demand supply path. The fix direction is the PRD's stated position - hold nothing persistent, regenerate via nix-store --dump on demand, hold only the in-flight serve - which is exactly the decision TASK-61 owns. This task makes that decision LOAD-BEARING for wave-2a rather than a wave-2b nicety, and adds the size cap that is needed regardless of which supply model wins.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Serving is bounded: a configurable maximum served-NAR size (and/or a maximum total in-flight serve bytes) above which the node declines to serve rather than allocating. Prove by mutation that removing the bound restores the unbounded allocation
- [ ] #2 A hold-answer is only positive for content the provider can actually SERVE - index coverage and provider coverage are the same set, or the difference is explicit and tested (a claim for an unseeded path must not produce a dial-then-fail)
- [ ] #3 The eager startup seed is replaced by, or supplemented with, an on-demand supply path so that announcing does not require holding; measured with TASK-65's residency oracle (store residency after an idle period, not peak RSS)
- [ ] #4 Pathological row for TASK-43: a peer requests the largest announced NAR - the node must degrade (decline / bounded memory) rather than OOM. Bites: without the bound, RSS tracks the NAR size
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Replace the eager startup seed with a NarSupplier seam: announce by streaming BLAKE3 in 64 KiB slices (Blake3Digest::stream_raw_nar), regenerate on demand at serve time.
2. Admission gate on iroh-blobs RequestMode::InterceptLog - the provider ANSWERS each get-request before it is served, so the ServeBudget (max single NAR, max total in-flight, both NarSize units) is checked BEFORE anything is produced.
3. Release after serve (StoreRetention::ReleaseAfterServe), solving the task-65 collector race by arming a sweep only from quiescence plus registering the hash before the add.
4. Make index coverage == provider coverage: a positive hold-answer records the BLAKE3 -> entry binding and supply_size repeats hold's materialisation check, so both sets change together. No listing method is added.
5. Prove EVERY oracle by mutation, each on a NAMED check, and re-measure the task-65 size axis for the before/after slopes.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Progress: implementation landed (d83dd97) + two follow-up defects found by self-review

WHAT SHIPPED
  * NarSupplier seam + FileNarSupplier (the daemon's --iroh-seed-nar path) +
    IndexNarSupplier (AvailabilityIndex -> nix-store --dump).
  * Blake3Digest::stream_raw_nar - the frozen recipe over a byte STREAM in 64 KiB
    slices, so announcing a 3 GiB path costs 64 KiB of peak allocation. Unit test
    asserts it equals the one-shot recipe across the chunk boundary.
  * ServeBudget + the admission gate on iroh-blobs RequestMode::InterceptLog. The
    verdict is answered BEFORE handle_get_impl touches the store (upstream:
    handle_get calls get_request first; EventSender::request does rx.await??), so
    the bound is checked before anything is produced.
  * StoreRetention::ReleaseAfterServe - hold only the in-flight serve.
  * Single flight via tokio::sync::watch (state, not just an edge, so a late
    follower cannot miss the wakeup and hang).
  * availability.rs: DerivedNar {blake3, nar_size} from ONE dump; a by_digest
    reverse map populated by hold(); supply_size/supply_raw_nar as per-digest
    probes only.

TWO DEFECTS I INTRODUCED AND THEN FOUND BY SELF-REVIEW - recording them because
both are the kind that pass every test until they do not:
  1. ReleaseOnRequest and ReleaseAfterServe shared one arming flag, so a completed
     serve silently released a store whose documented contract is 'hold everything
     until release_all'. Fixed with an explicit release_after_serve flag and a
     regression test proven by mutation (M7).
  2. The Reservation::Ready path took no TempTag, so a blob that was resident at
     admission could be swept by a run already past its protect callback. Now
     re-checked and re-materialised under a releasing retention only.

## MUTATION SWEEP - every oracle broken, watched go red on a NAMED check, restored

  M1 per-NAR bound removed from reserve()        -> declined_too_large 1 -> 0
     (NOTE: the request was still refused, as declined_busy. A test asserting only
     'the fetch failed' would have PASSED. The reason-specific assertion is what
     makes this bite.)
  M2 admission produces bytes before deciding    -> supplier calls 0 -> 1
  M3 single flight removed                       -> regenerations 1 -> 8
  M4 post-serve sweep never armed                -> residency 0 -> 67,108,976 B
  M5 supply drops the materialisation check      -> None -> Some(2,097,264) for a GC'd path
  M6 unknown digest admitted not declined        -> declined_unknown 1 -> 0, admitted 0 -> 1
  M7 the two releasing retentions collapsed      -> ReleaseOnRequest released after a serve

MEASURED, in-process (the AC#1/AC#4 bite):
  NAR 67,108,976 B, per-NAR bound 16,777,216 B
  BOUNDED   -> declined, supplier calls 0, VmHWM rise      581,632 B (0.87% of the NAR)
  UNBOUNDED -> served,   supplier calls 1, VmHWM rise 137,904,128 B (2.055x the NAR)
The 2.055x is task-65's 2.0033 slope arriving on cue, which is a useful check that
the mutated arm really did reproduce the old behaviour.

ORACLE DISCIPLINE: VmHWM is used ONLY for 'did we allocate' (monotone, so it
cannot miss an allocation). Every release claim is on IROH-STORE-RESIDENT /
store_residency(). Stated in the test file's module docs.

## Architecture review (mped-architect) found TWO remotely-triggerable defects the tests did not cover

Recorded in full: both defeated the property this task claims, and both were
invisible to a suite that only ran the happy configuration.

S1 - PERMANENT BUDGET EXHAUSTION BY HANGING UP. The reservation was released where
the transfer's update stream ended, and an early return skipped it when the verdict
could not be delivered - which is what happens when the peer disconnects, across a
window spanning the whole regeneration. Now an RAII guard (five release sites -> one).

  MEASURED WHILE WRITING THE ORACLE, and worth carrying forward: when a peer
  vanishes the provider's update stream does NOT end. The connection stays live
  from our side until QUIC's idle timeout, and nothing at our layer distinguishes
  an abandoned peer from a slow one. So a SERVE DEADLINE is the bound that actually
  does the work: --iroh-max-serve-duration-ms, default 120 s, PROVISIONAL. Too long
  and abandoned requests hold the budget; too short and a slow peer loses a real
  transfer. Deriving it from a minimum-throughput policy is task-44's territory.

S2 - 'HOLDS NOTHING AT REST' HELD ONLY WHEN IDLE. The protect callback ABORTED the
sweep whenever anything was in flight, so under sustained traffic nothing was ever
collected; a MemStore has no capacity of its own, so resident bytes would grow to
the whole announced corpus while the budget bounded only concurrently-ADMITTED
bytes. ONE SLOW READER is enough. The callback now PROTECTS in-flight hashes
instead of refusing to run - safer (the hash is registered before the add) and
stronger. This also supersedes the task-65 warning that a background evictor was
not a policy option: it is, once the protect callback is used for protection.

Smaller, all fixed: produced bytes reconciled against the CAP not the RESERVATION;
the Ready re-check gated on the caller's own status read (skipping it for the
caller with the freshest evidence of absence); by_digest never pruned, so supply
outgrew hold - AC#2 failing in the direction that matters; a FAILED store query
reported as 'we do not have it', which this module's own docs forbid; declines
dropping the cause string; a supplier PANIC indistinguishable from a missing file;
two booleans projected from one enum.

## THE MUTATION SWEEP CAUGHT TWO VACUOUS ORACLES OF MY OWN

This is the reason to run it, and it is the third cycle in a row this project has
shipped a vacuous oracle - so the pattern is worth naming rather than the instance.

  1. The collector test served its NAR BEFORE anything was in flight, so the
     collector got a quiet moment and the test passed under the broken callback
     too. ORDER was the whole experiment and I had it backwards.
  2. Its 'ceiling' allowed one in-flight serve's worth of residency - but the
     blocked serve is stuck INSIDE its supplier, so it occupies no store bytes at
     all and the ceiling could never be exceeded. A ceiling that cannot be exceeded
     is not a ceiling.

Also: a mutation patch that FAILS TO APPLY looks exactly like a passing oracle. One
of mine did (a string that had changed), and all three tests in that batch 'passed'
against unmutated code. Every patch now asserts it applied before the test runs.

And: an unbounded spin in a spawn_blocking supplier makes a FAILING test hang
forever, because dropping a tokio runtime waits for blocking tasks.

## FULL MUTATION LEDGER (each broken, watched go red on a NAMED check, restored)

  M1 per-NAR bound removed              -> declined_too_large 1 -> 0 (still refused as
     busy, so a test asserting only 'it failed' would have PASSED)
  M2 admission produces bytes first     -> supplier calls 0 -> 1
  M3 single flight removed              -> regenerations 1 -> 8
  M4 post-serve sweep never armed       -> residency 0 -> 67,108,976 B
  M5 supply drops the exists() check    -> None -> Some(2,097,264) for a GC'd path
  M6 unknown digest admitted            -> declined_unknown 1 -> 0, admitted 0 -> 1
  M7 the two releasing retentions merged-> ReleaseOnRequest released after a serve
  M8 serve deadline removed             -> honest peer still refused after 20 s
  M9 collector aborts while in flight   -> store still holding 4,194,416 B
  M10 produced size vs cap not reservation -> a 4 MiB body admitted on a 1 KiB
     reservation

## AC#4 INSTRUMENT CHANGED, and the reason is a measurement

VmHWM is a high-water mark over the whole PROCESS and cargo runs these tests as
threads of one, so once any test allocated 64 MiB the next identical allocation
produced NO RISE - the assertion failed on correct code (measured: 8,359,936 B of
rise for a 67,108,976 B NAR that really was allocated). It now reads VmRSS WHILE
THE PAYLOAD IS LIVE: sound in that one direction (live touched pages are resident
by definition), and stated to be unsound in the other, where store residency is
used instead.

  BOUNDED   -> declined, supplier calls 0, VmRSS rise         720,896 B
  UNBOUNDED -> served 67,108,976 B, supplier calls 1, VmRSS rise 156,946,432 B

## AC#3 measured: the residency oracle, fitted, before and after

  size.holder_store_resident_bytes_uncompressed_nar (IROH-STORE-RESIDENT, asked of
  the blob store - NOT peak RSS, which is monotone and cannot observe a release)
    BEFORE  slope 1.000000 [1.000000 .. 1.000000], resident_over_seeded_ratio 1.0
    AFTER   slope 0.000000,                        resident_over_seeded_ratio 0.0

  size.holder_rss_hwm_bytes_ram (peak RSS, the memory the node actually costs)
    BEFORE  2.004426 [2.000129 .. 2.008723] R2 0.999987
    AFTER   1.020232 [1.009284 .. 1.031180] R2 0.999679   <- DISJOINT intervals

  size.fetcher_rss_hwm_bytes_ram (CONTROL - TASK-62's territory, untouched)
    BEFORE  1.018814 [1.009204 .. 1.028424]
    AFTER   1.018838 [1.007846 .. 1.029831]

15/15 valid points in both runs (5 sizes x 3 replicates), honesty compliant, 0 red
flags, size_axis_usable true. Both runs exit 1 for the SAME reason - --swarm 1
leaves the swarm axis with one distinct n, below scalefit's MIN_POINTS, so the
whole report is marked unusable-for-quoting. That verdict is about the swarm axis;
run a full profile before quoting anything but these size-axis slopes.
<!-- SECTION:NOTES:END -->
