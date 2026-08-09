---
id: TASK-18
title: Scale-sweep + regression-fit machinery (S5)
status: Done
assignee:
  - '@me'
created_date: '2026-08-07 22:10'
updated_date: '2026-08-09 11:51'
labels: []
dependencies:
  - TASK-9
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner requirement (post-review): characterize behavior at 10s/100s/1000s of peers despite the host affording ~1..30 real nodes. This task builds the MACHINERY in wave 1, exercised on the axes that exist now - concurrent clients and proxy-chain depth; the p2p wave points the same sweep at peer count. Sweep runner: run scenario at N in a configured range, sample per-node RSS/fds/request-latency via the harness; fitter: candidate models O(1)/O(log n)/O(n)/O(n log n)/O(n^2), select by fit quality, extrapolate with confidence intervals. TESTING.md S5 honesty rules apply: extrapolations labeled as model outputs, R^2/residuals reported, superlinear RAM/latency fits surfaced as red flags, and claims limited to resource scaling laws - emergent network effects (DHT k-buckets, gossip fan-out) are explicitly out of scope for small-N extrapolation. Prefer process/pod swarms over VMs for sweeps (a daemon is one process; client nix containers are the heavy part - the sweep design must account for which component actually scales).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 just scale-sweep runs a sweep (e.g. N clients in 1..16, chain depth 1..5) and emits per-N samples: RSS, fds, latency percentiles per node
- [x] #2 Fitter selects among candidate models, reports fit quality (R^2, residuals) and confidence intervals; extrapolated values labeled as model output, never measurement (S5 honesty rules asserted in report format)
- [x] #3 Bite test: synthetic workload with known O(n) memory growth recovers a linear fit; known O(1) workload recovers constant - wrong-model selection fails the test
- [x] #4 Report flags superlinear RAM or latency fits prominently (red-flag section, not a footnote)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. scripts/scalefit.py - STANDALONE stdlib-only fitter (no containers, no e2e import; task-42
   imports it for the peer-count axis). Candidate bases y = a + b*f(n) with
   f in {0 (const), log n, n, n log n, n^2}; OLS on the transformed axis, R^2/adj-R^2
   against the ORIGINAL y (comparable across classes), residuals per point, AICc model
   selection with a parsimony margin, Student-t confidence + prediction intervals via a
   pure-python regularized incomplete beta + bisection ppf (verified against a t-table in
   the self-test). Extrapolate to 10/100/1000 with every extrapolated number structurally
   labelled {"kind": "model_output", ...}. Ships honesty_violations(report) - the S5 rule
   asserted, not documented.
2. scripts/scale_sweep.py - the sweep RUNNER over the e2e_harness Pod seam. Axes:
   (a) concurrent clients N, chain depth 1; (b) chain depth 1..5; (c) client knobs
   max-substitution-jobs/http-connections in {1,16,128}. Per-node samples: VmHWM
   (HIGH-WATER peak RSS) AND VmRSS (point sample) from /proc/<hostpid>/status read
   host-side via podman inspect .State.Pid (rootless -> own uid, no container binary
   needed - the dead-oracle lesson), fd count from /proc/<hostpid>/fd, latency
   percentiles per client. Feeds scalefit; emits JSON report + human summary with a
   RED FLAGS section first when a RAM/latency fit is superlinear.
3. just scale-sweep (SLOW tier, like measure) + both --self-test modes wired into the
   FAST just test gate.
4. Bites, each proven by MUTATION (fails-before/passes-after recorded with numbers):
   B1 known-O(n) generator recovers linear; B2 known-O(1) recovers constant; B3
   known-O(n^2) is classified SUPERLINEAR and NOT linear (the dangerous confusion);
   B4 an extrapolation block stripped of its model_output label is REJECTED by the
   honesty validator; B5 a report whose superlinear fit is not in red_flags is REJECTED;
   B6 /proc parse of a missing VmHWM is fail-closed (unknown != 0).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Sweep axes must include the client concurrency knobs max-substitution-jobs / http-connections in {1, 16, 128} (TESTING.md client-knobs rule), alongside client count and chain depth. Ref: bmcgee.ie TIL post.

## Implementation (landed)

- scripts/scalefit.py - STANDALONE stdlib-only fitter (no numpy/scipy, no harness import, so
  task-42 can import it for the peer-count axis). Family y = a + b*f(n), f in
  {0, log n, n, n log n, n^2}; OLS on the transformed axis; R^2/adj-R^2 against the ORIGINAL y
  (comparable across classes); AICc selection with a parsimony margin (simplest candidate within
  dAICc <= 2 of the best, and every candidate inside the margin reported as `competitive_models`
  with `identifiable`); Student-t intervals from a hand-rolled regularized incomplete beta
  (Lentz) + bisection ppf, VERIFIED against published t-table values in the self-test.
  Mean-response CI and prediction interval, both labelled `{"kind": "model_output"}`.
  `fit_violations()` / `sweep_report_violations()` / `red_flags_for()` make the S5 honesty rules
  MECHANICAL, not prose.
- scripts/scale_sweep.py - the sweep runner over the e2e_harness Pod seam. Axes: clients
  (N concurrent clients at one daemon), chain (daemon_chain 1..5), knobs ({1,16,128}, reported
  per value, NOT fitted). Pure functions (/proc parsing, aggregation, overlap, report assembly)
  are separated from the container driving, so `--self-test` covers the honesty logic with no
  containers.
- e2e_harness.py: public `Pod.container/roles/daemon_roles/host_pid`; `client_run_bg`;
  `jobs`/`conns`/`start_at_ns` on the client script (all defaulting to today's behaviour);
  REALISE_NS/T0/T1 markers and a ===KNOBS=== readback section.
- Justfile: `just scale-sweep` (SLOW tier); both `--self-test`s wired into FAST `just test`.

## Gotchas hit (feed-forward)

1. `grep` IS NOT IN THE E2E IMAGE (buildEnv ships coreutils, not findutils/grep). My first knob
   readback piped `nix config show` into grep inside the container: rc=127, empty section. The
   fail-closed design turned that into "knob UNCONFIRMED -> arm unusable" instead of a silent
   pass - same family as the old `find` rc=127 dead oracle. Fix: `nix config show <name>` (one
   query per knob, nix does the selection) and parse host-side.
2. THE KNOB AXIS IS WORKLOAD-CAPPED. nix cannot run more concurrent substitutions than there
   are substitutable paths; the fixture workload has 3, so jobs=16 and jobs=128 are
   indistinguishable from 3. The arm proves the knob LANDS (readback asserted as a precondition)
   and reports the numbers, but it cannot show a concurrency effect. Filed TASK-57.
3. CONCURRENCY MUST BE MEASURED, NOT ASSUMED. The clients report absolute realise windows and
   the point is INVALID unless measured max overlap == N. A mutation that serialised the fleet
   drove overlap to 1/4 and correctly invalidated the point. NOTE: a second mutation DISPROVED
   my original rationale - with the barrier disabled, overlap was still 6/6, because the
   launches are asynchronous. The barrier is jitter insurance; the MEASUREMENT is the guarantee.
   Comments corrected to say so rather than keep the tidier-but-false story.
4. A SINGLE-SEED "the 95% CI covered the truth" check is a coin flip dressed as an oracle (it
   fails 5% of the time by construction, and picking the passing seed is cherry-picking). It
   failed on the first run. Replaced with a MONTE-CARLO coverage rate over 200 replicates,
   asserted in [0.88, 1.0]. Measured: 0.965 at n=100 and 0.960 at n=1000 (homoscedastic).
5. The multiplicative-noise coverage is 0.865 at n=1000 - the OLS interval UNDER-COVERS when
   variance grows with the mean, which is what resource metrics actually look like. Printed as
   an INFO line in the self-test and stated in fit_scaling()'s assumptions rather than hidden.
6. AICc needs n - k - 1 > 0, so MIN_POINTS = 5 distinct n. `fit_scaling` RAISES rather than
   fitting fewer - a starved axis is reported unfitted with the reason, never fitted on the
   survivors.
7. Rejected: adding numpy/scipy (changes the flake closure; the source-guard gates police script
   imports). OLS, R^2, residuals, incomplete beta and the t quantile are pure stdlib.
8. Rejected: a second percentile implementation. `scale_sweep` imports `measure.percentile` -
   two definitions of p95 in one repo would diverge invisibly.

## Bites proven by MUTATION (fails-before / passes-after, with numbers)

Control for all: `scalefit --self-test` ALL PASS (41 checks), `scale_sweep --self-test`
ALL PASS (47 checks).

- M1 selector forced to `candidates[0]` (always constant):
  FAIL "known logarithmic/linear/linearithmic/quadratic generator recovers <class>" (4),
  FAIL "known linearithmic/quadratic: superlinear flag == True" (2). Restored -> ALL PASS.
- M2a superlinear bases deleted from BASES: self-test CRASHES (KeyError 'linearithmic') -
  loud, not silent. Restored -> ALL PASS.
- M2b quadratic mislabelled `superlinear=False`:
  FAIL "known quadratic: superlinear flag == True", FAIL "O(n^2) RAM is flagged superlinear",
  FAIL "superlinear fit reached the red-flag section", and in scale_sweep FAIL
  "known O(n^2) RSS axis is flagged superlinear" + FAIL "the superlinear fit reaches the
  red-flag section, by id". Restored -> ALL PASS.
  FINDING FROM THIS MUTATION: the first version compared the flag against BASIS_BY_NAME (the
  same constant the code uses), so it was SELF-REFERENTIAL and stayed green. Fixed to a literal
  expectation table; re-running M2b then bit as it should. A mutation run earning a real fix.
- M3 `red_flags_for()` returns [] always:
  FAIL "compliant report -> no violations" (the validator reports the missing red flag),
  FAIL "superlinear fit reached the red-flag section", FAIL scale_sweep's by-id check.
  Restored -> ALL PASS.
- M4 `extrapolate()` stops emitting `"kind": "model_output"`:
  FAIL "compliant report -> no violations" (6 labelled violations), FAIL scale_sweep
  "assembled report is honesty-COMPLIANT" (9 violations), FAIL "verdict usable on a clean
  synthetic sweep". Restored -> ALL PASS.
- M5 `parse_status_kb` returns 0 instead of raising on a missing field:
  FAIL "fail-closed: missing VmHWM -> SampleError", FAIL "fail-closed: empty status".
  Restored -> ALL PASS.
- M6 `max_overlap` returns len(intervals) (trusts the launch count):
  FAIL "SERIALISED clients -> overlap 1, not 3", FAIL "partial overlap counts the true peak",
  FAIL "touching-but-not-overlapping intervals". Restored -> ALL PASS.
- M7 REAL CONTAINERS, barrier disabled at N=6: overlap still 6/6, point VALID. The oracle did
  NOT bite - which DISPROVED the barrier rationale (see gotcha 3) rather than proving it.
- M7b REAL CONTAINERS, fleet serialised at N=4: measured overlap 1 != requested 4, point
  INVALID with the reason recorded, arm unusable, exit 1. Restored -> ALL PASS.

## Real sweep results (`just scale-sweep`, exit 0, all axes usable, honesty compliant)

clients axis (6/6 valid, measured overlap == N at every point):
  daemon VmHWM 7.16 MB @N=1 -> 9.89 MB @N=12; selected O(log n), R^2 0.9839, UNIQUELY
  identifiable (dAICc: constant 14.78, linear 8.63, n log n 12.66, n^2 16.14). NOT superlinear.
  daemon fds: O(1) at 7. client p95 realise: O(1) ~0.13-0.18 s up to 12 concurrent clients.
chain axis (5/5 valid): per-hop VmHWM O(1) ~7.2 MB; whole-chain total O(n) R^2 = 0.99998
  (7.20/14.52/21.71/28.82/36.03 MB at depth 1..5) - an INDEPENDENT real-data check that the
  fitter recovers a law that must be linear by construction; per-hop fds O(1) at 8;
  latency O(1).
knobs axis (3/3 valid): knob confirmed by nix readback at 1/16/128; no effect visible, as the
  workload ceiling predicts (TASK-57).
red flags: NONE. No superlinear RAM or latency law on this host at this range.

## Honest limitations of the machinery

- The 1000-peer extrapolations are 33x-200x beyond the largest measured n. The interval widens
  with distance but expresses SAMPLING uncertainty around the SELECTED model only.
- `daemon_rss_point_max_bytes == daemon_rss_hwm_bytes` at every measured point on this
  workload: the daemon's RSS grows monotonically and is never released, so the high-water /
  point-sample distinction is currently UNEXERCISED by real data. The machinery reports both
  and the self-test proves the aggregation distinguishes them, but no real gap has been observed
  yet. Expect one with a bursty p2p workload (task-42).
- Only container PID 1 is observed. The daemon and testproxy fork nothing, so this is exact
  today; a component that spawned children would be under-counted, and the fix is cgroup
  accounting.
- The clients axis measures ONE daemon under N clients. It is NOT a 12-peer network: peer count
  is task-42's axis. Emergent network effects remain out of scope by construction.
- n log n vs n^2 are collinear at small n; the robust discrimination is superlinear vs not,
  which is what the red flag keys off.

## Late findings (after the first green sweep) - both fixed, both proven

A. RUN-TO-RUN CLASS INSTABILITY. Three consecutive full sweeps selected O(log n)
   (R^2 0.9839, identifiable), O(log n) (R^2 0.9083, NOT identifiable) and O(n)
   (R^2 0.9956) for the SAME metric (daemon VmHWM vs concurrent clients). With one
   observation per N the metric is a single noisy draw and the fitter was being asked to
   identify a class from six points it could not distinguish. FIX: --repeats (default 3);
   replicates go to the fitter as SEPARATE observations at the same n, never averaged
   (averaging would discard exactly the spread the intervals need). Duplicate n still
   counts once toward MIN_POINTS. HONEST CAVEAT: one run at repeats=3 does NOT prove
   stability - it takes 18 observations instead of 6 and lets the residual variance
   absorb run-to-run noise. Proving stability needs repeated full sweeps; not done.
B. AN INTERVAL BELOW ZERO. Run 2 reported client p95 latency at n=1000 as
   "0.37 s (95% CI -0.19 .. 0.93)". A symmetric t interval knows nothing about a metric's
   domain. NOT clamped (that would hide the uncertainty): flagged as
   `interval_extends_below_zero` + an UNINFORMATIVE sentence in the caveat and a marker
   in the human summary. Bite M8: hardcoding the flag False turns the self-test red.
C. SIGTERM LEAKED A POD. A `timeout`-killed sweep left `nix-p2p-e2e-scale-knobs-1-2`
   running; only KeyboardInterrupt was handled. Fixed with a SIGTERM handler that runs
   the label-scoped cleanup. `just e2e-clean` remains the manual counterpart.

## Final real run (`just scale-sweep`, default grid, repeats=3)

exit 0, 695 s, disk unchanged at 48 GiB free. 18/18 clients + 15/15 chain + 9/9 knobs
valid observations; honesty_compliant=True; red_flags=0.
  clients.daemon_rss_hwm_bytes   O(n)      R^2 0.9496  -> n=1000: 3.13e8 B (CI 2.76e8..3.50e8)
  clients.daemon_fd_max          O(1)      R^2 0.0000  -> ~7.2 fds [class NOT identifiable]
  clients.realise_p95_s          O(n)      R^2 0.6392  -> [class NOT identifiable]
  chain.daemon_rss_hwm_bytes     O(log n)  R^2 0.4308  (weak; per-hop RSS barely varies)
  chain.chain_total_rss_hwm_bytes O(n)     R^2 0.9999  (linear by construction - real-data
                                                        confirmation the fitter is right)
  chain.daemon_fd_max / chain.realise_p95_s  O(1)
No superlinear RAM or latency law on this host over this range, so the red-flag section is
legitimately empty - its wiring is proven by mutation instead (M2b/M3), not by an
accidental real red flag.

## Gate results (all inside `nix develop`)

  just build       exit 0
  just lint        exit 0 (ruff + clippy -D warnings + source/lock guards)
  just test        exit 0 - 141 cargo tests (98+10+8+2+1+2+8+5+6+1), and 104 script
                   self-test PASS lines including scalefit (43) and scale_sweep (52)
  just e2e         exit 0 - 26/26 scenarios PASS (the client-script change touches every
                   scenario, so this was the gate that mattered)
  just scale-sweep exit 0 - 695 s, results above
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
S5 machinery landed and exercised for real. Two composable pieces:

scripts/scalefit.py - a STANDALONE, stdlib-only fitter (no numpy/scipy, no harness import,
so task-42 can point the same fitter at peer count). Candidate family
y = a + b*f(n) for f in {0, log n, n, n log n, n^2}; OLS on the transformed axis; R^2
against the ORIGINAL y so it is comparable across classes; AICc selection with a parsimony
margin plus `competitive_models`/`identifiable` so a class is never presented as identified
when it is not; residuals; Student-t mean-response and prediction intervals from a
hand-rolled regularized incomplete beta + bisection ppf, verified against published
t-table values. TESTING.md S5's honesty rules are MECHANICAL here, not prose:
sweep_report_violations() rejects a report with an unlabelled extrapolation, a fit without
R^2/residuals, a superlinear fit missing from red_flags, a missing resource-laws-only
caveat, or a model output leaked into `measured`.

scripts/scale_sweep.py + `just scale-sweep` (SLOW tier) - the runner over the e2e Pod seam.
Axes: N concurrent clients at one daemon (the daemon is one process, so its per-node
RSS/fd growth is the law worth extrapolating; the client containers are the host-bound
part), chain depth 1..5, and the TESTING.md client knobs {1,16,128} reported per value and
explicitly NOT fitted. RSS HIGH-WATER (VmHWM) is fitted with VmRSS point samples beside it;
/proc is read host-side via podman inspect .State.Pid (nothing shelled into the image -
`grep` and `find` are absent there, the rc=127 dead-oracle trap, which bit again on the
knob readback); latency is the in-container realise duration, never the podman wall clock.
Every point is run 3x and the replicates are fitted as separate observations.

Preconditions are ASSERTED, not assumed: measured client overlap must equal N (proven on
real containers - serialising the fleet drove overlap to 1/4 and invalidated the point),
and the knob must be read back from nix (an unconfirmed knob makes the arm unusable).

All four ACs met. Both self-tests are container-free and wired into FAST `just test`, and
every oracle was proven to bite by MUTATION (9 mutations recorded with numbers in the notes
and the git verification note) - including one mutation that DISPROVED a stated rationale
(the start barrier) and one that exposed a self-referential expectation in my own test.

Gates: build/lint/test/e2e/scale-sweep all exit 0. 141 cargo tests, 104 script self-test
PASS lines, 26/26 e2e scenarios, and a 695 s real sweep with 42/42 valid observations, no
honesty violations and no red flags (nothing superlinear on this host at this range - the
red-flag wiring is proven by mutation, not by an accidental finding).

Honest limitations, all in the notes: the 1000-peer extrapolations are 33x-200x beyond the
measured range and cover resource laws ONLY (emergent network effects are out of scope by
construction); intervals under-cover when variance grows with the mean (measured 0.865 vs
nominal 0.95); VmHWM == max VmRSS on this workload, so the high-water/point distinction is
so far unexercised by real data; only container PID 1 is observed; the knob axis is capped
by the number of substitutable paths in the workload (TASK-57 filed); and one run at
repeats=3 does not by itself prove the class selection is now stable.
<!-- SECTION:FINAL_SUMMARY:END -->
