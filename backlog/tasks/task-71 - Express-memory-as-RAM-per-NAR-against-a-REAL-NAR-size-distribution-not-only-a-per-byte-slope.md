---
id: TASK-71
title: >-
  Express memory as RAM-per-NAR against a REAL NAR-size distribution, not only a
  per-byte slope
status: To Do
assignee: []
created_date: '2026-08-09 17:45'
updated_date: '2026-08-09 17:45'
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
