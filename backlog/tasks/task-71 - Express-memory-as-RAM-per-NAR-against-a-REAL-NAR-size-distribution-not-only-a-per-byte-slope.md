---
id: TASK-71
title: >-
  Express memory as RAM-per-NAR against a REAL NAR-size distribution, not only a
  per-byte slope
status: To Do
assignee: []
created_date: '2026-08-09 17:45'
updated_date: '2026-08-10 09:29'
labels: []
dependencies:
  - TASK-65
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner feedback 2026-08-09: 'RAM per NAR instead of RAM per NAR byte is more interesting.' Correct - the dimensionless slope (2.0033 B RAM / B NAR holder, 1.0156 fetcher, TASK-65) characterizes the ARCHITECTURE's overhead factor, but it does not answer the operator question the goal actually asks ('estimate RAM usage'): how much RAM does serving a NAR cost, and how much for k concurrent serves.

That needs an empirical NAR-size distribution. Measured on the owner's own store (nix path-info --json --all, 2026-08-09): 108,401 paths, 155,621 MiB of NAR bytes, mean 1.44 MiB, p50 ~0, p90 0.04 MiB, p95 0.59 MiB, p99 10.92 MiB, p100 3186.03 MiB. The distribution is extremely heavy-tailed - almost everything is tiny and a handful of paths are gigabytes.

Applying the TASK-65 holder slope (MODEL OUTPUT, extrapolated well past the fitted size grid - label it as such and state the grid's top size): mean NAR ~2.9 MiB per serve on top of the ~19-21 MiB per-peer baseline; p99 ~22 MiB; p100 ~6.2 GiB for ONE serve. See TASK-72 for what that tail implies.

Do NOT replace the slope - it is the right unit for judging TASK-46/61/62 fixes. ADD the per-NAR readout beside it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The profile report expresses holder and fetcher memory as RAM-per-NAR at named percentiles (p50/p90/p99/max) of a real NAR-size distribution, alongside the existing per-byte slope, with the baseline intercept stated separately from the size-dependent term
- [ ] #2 The size distribution is measured, not assumed: sampled from a real store (nix path-info --json --all) or from real cache.nixos.org narinfos, with the sample size and its provenance recorded in the report
- [ ] #3 Every per-NAR figure beyond the fitted size grid is labelled model output per the S5 rules (scalefit.sweep_report_violations must still pass), and the top of the fitted grid is stated so a reader can see how far the extrapolation reaches
- [ ] #4 k-concurrent-serve cost is expressed the same way: RAM for k simultaneous serves at a given percentile, so an operator can read a capacity bound rather than a slope
<!-- AC:END -->

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
