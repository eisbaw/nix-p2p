---
id: TASK-72
title: >-
  A single large NAR OOMs the node, and the index promises more than the
  provider can serve
status: Done
assignee:
  - '@me'
created_date: '2026-08-09 17:45'
updated_date: '2026-08-10 09:29'
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
- [x] #1 Serving is bounded: a configurable maximum served-NAR size (and/or a maximum total in-flight serve bytes) above which the node declines to serve rather than allocating. Prove by mutation that removing the bound restores the unbounded allocation
- [x] #2 A hold-answer is only positive for content the provider can actually SERVE - index coverage and provider coverage are the same set, or the difference is explicit and tested (a claim for an unseeded path must not produce a dial-then-fail)
- [x] #3 The eager startup seed is replaced by, or supplemented with, an on-demand supply path so that announcing does not require holding; measured with TASK-65's residency oracle (store residency after an idle period, not peak RSS)
- [x] #4 Pathological row for TASK-43: a peer requests the largest announced NAR - the node must degrade (decline / bounded memory) rather than OOM. Bites: without the bound, RSS tracks the NAR size
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
## CENSUS CORRECTION 2026-08-10 (re-derived by the orchestrator from /nix/var/nix/db/db.sqlite)

Any figure in this task quoting 108,401 paths / 155,621 MiB / "mean NAR 1.44 MiB" is WRONG and must
not be used. The original numbers came from `nix path-info --all`, which counts .drv files. Those are
local evaluation artifacts cache.nixos.org does not serve; they are 85.6% of all paths while holding
0.2% of the bytes, so they inflated the path count ~7x and deflated the mean NAR ~6x.

AUTHORITATIVE (measured 2026-08-10, independently re-derived - not taken from a subagent report):
  valid paths                85,808
    .drv                     73,412 (85.6%), only 263 MiB   <- never publish these: useless AND a privacy leak
    SERVABLE output paths    12,396, 105,713 MiB
      signed by cache.nixos.org   6,769 paths / 53,854 MiB = 50.9% of bytes
      locally built (ultimate)    2,250 paths / 35,870 MiB
  size distribution (servable): mean 8.53 MiB, p50 0.10 MiB, p90 4.48 MiB, p99 151.06 MiB, p100 3186.03 MiB
  byte concentration: top 151 paths = 73.5% of bytes, top 691 = 91.7%, top 1,243 = 95.5%

THREE CONSEQUENCES that change reasoning, not just arithmetic:
1. The publishable set (signed, hence already-public) is ~6,769 paths, not 108,401 - a ~16x reduction.
   Every per-path cost model shrinks by that factor.
2. HALF THE SERVABLE BYTES (49.1%) carry no upstream signature and therefore can NEVER be published
   under the no-enumeration rule. They stay reachable only by direct hold-query, which makes TASK-91
   (batched hold-query) load-bearing rather than an optimization.
3. The distribution is far more extreme than "mean 1.44 MiB" implied: the MEDIAN is 100 KiB (~5 ms
   from a 21 MB/s upstream) while 151 paths hold three quarters of all bytes. Any claim that a
   discovery round trip amortises against a download must be checked against the MEDIAN, not the mean.

Note also 1.44 MiB was a MEAN misdescribed as a median in places; the servable mean is 8.53 MiB.
Canonical source of truth going forward: TASK-95 (reproducible store census).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Both gaps closed, and two MORE remotely-triggerable defects found by architecture review and closed with them.

AC#1 MET. Three numeric knobs, all in NarSize units and all fail-fast on 0:
--iroh-max-serve-nar-bytes (256 MiB), --iroh-max-inflight-nar-bytes (1 GiB),
--iroh-max-serve-duration-ms (120 s), logged at startup as IROH-SERVE-BUDGET. The
bound is checked BEFORE anything is produced - iroh-blobs blocks on our verdict
(RequestMode::InterceptLog) and only then reads the store - so a 3 GiB request
costs a stat. Proven by mutation FOUR ways (M1 bound removed, M2 bytes produced
before deciding, M8 deadline removed, M10 produced size checked against the cap
rather than the reservation). Measured: 64 MiB NAR, 16 MiB bound -> declined,
supplier never called, VmRSS rise 720,896 B; unbounded -> served, VmRSS rise
156,946,432 B.

AC#2 MET IN-PROCESS, with its boundary stated. A positive hold-answer records the
BLAKE3->entry binding and supply_size repeats hold's materialisation check, so the
two sets change together in BOTH directions (M5 proves a GC'd path leaves both;
by_digest is pruned with the registration so supply cannot outgrow hold). An
unknown digest is a NAMED, counted decline, not a dial-then-fail (M6). NOT met at
the daemon level in the sense of serving /nix/store: the shipped binary supplies
from raw-NAR files, and there is no wire endpoint for hold-queries yet - task-83
and task-73. The restart gap (in-memory binding) is stated and filed as task-82.

AC#3 MET, on the right oracle: store residency after an idle period, fitted over 5
NAR sizes - 1.000000 [1.0 .. 1.0] -> 0.000000. Holder peak RSS 2.004426 [2.000129
.. 2.008723] -> 1.020232 [1.009284 .. 1.031180], disjoint. Fetcher unchanged
(control).

AC#4 MET in-process with numbers, and the CONTAINER row is forward-carried to
task-43 with the oracles it needs (IROH-SERVE-COUNTERS, IROH-SERVE-BUDGET).

WHAT THE REVIEW CAUGHT THAT THE TESTS DID NOT: a peer could permanently exhaust the
budget by hanging up mid-admission (the release was tied to the update stream, and
an early return skipped it); and 'holds nothing at rest' held only when idle,
because the collector refused to run while anything was in flight - one slow reader
could make a node retain everything it ever served. Both now have oracles that bite
(M8, M9). Along the way the mutation sweep caught TWO VACUOUS ORACLES OF MY OWN and
one mutation that silently failed to apply; all three are written up in the notes,
because a vacuous oracle is this project's most frequent defect.

NOT DONE, filed with reasons: task-83 (supply from a real /nix/store), task-85
(move the transport-agnostic supply/admission types out of transport_iroh),
task-86 (the iroh-blobs collector loop exits permanently on its first error and
nothing here can see it - which silently turns the supply model back into
retain-everything), task-84 (a suite flake under the new load), task-82 (persist
the digest binding). Task-46 gained the serve-side decline log as a second spam
surface it should solve alongside the abort spam.

GATES: build 0, lint 0, test 0 (twice, 26 binaries), e2e 0 with 26/26 scenarios
including all four p2p ones, profile size axis 15/15 valid points, honesty
compliant, 0 red flags. Both profile runs exit 1 for the same swarm-axis reason;
see the git note on abdda0e.
<!-- SECTION:FINAL_SUMMARY:END -->
