---
id: TASK-42
title: 'Profiling harness: RAM/disk/latency/throughput/speedup over the p2p testbed'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-09 11:16'
labels: []
dependencies:
  - TASK-41
  - TASK-18
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The owner-goal profiling instrument (extend task-18 S5 machinery + net-upstream-egress-v2). Over the 2-node+ p2p testbed, sample per-node RSS, disk (castore/blob store footprint), request latency, throughput, and speedup-over-upstream; emit a machine-readable report. Reuse the measure.py arm/report abstraction. This is the tool the scenario models (task-G) drive; per S9 it must BITE (a known-O(n) RAM workload recovers a linear fit; superlinear surfaced as a red flag).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just profile emits a report: per-node RSS/fds, disk footprint, latency p50/p95, throughput, egress-vs-upstream, for a scripted p2p workload
- [ ] #2 S9 bite: a synthetic known-O(n)-RAM scenario recovers a linear regression fit; a known-O(1) recovers constant; wrong-model selection fails the self-test
- [ ] #3 Extrapolation labeled model-output (never measurement); R^2/residuals reported; resource-laws-only caveat stated (no emergent-network-effect claims)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION (S9 bite, arch#4/qa#3/codex#7): (1) The dangerous confusion is linear-vs-SUPERLINEAR, not O(n)-vs-O(1). Add a known-SUPERLINEAR (e.g. O(n^2)) generator the fitter MUST classify superlinear and MUST NOT fit as linear (bite). (2) Define wrong-model = selected-class != generated-class. (3) Extrapolations REQUIRE confidence intervals (S5). (4) The peer axis needs REAL points: a 1..30 process-swarm sweep (many daemon processes on one host), NOT extrapolation from 2 nodes - two points can't discriminate O(n) from O(n log n). Restrict any 100s/1000s claim to labeled model-output over the 1..30 fit. (5) Report high-water RSS/disk, not just point samples. Stale ref fix: 'task-F'=this task(42), 'task-G'=task-43, 'task-H'=task-44.

## Forward-carried from task-18 (S5 scale-sweep machinery)

The fitter you need already exists and is deliberately import-clean.

- `scripts/scalefit.py` imports ONLY the stdlib (no numpy/scipy - the pinned env is
  `python3.withPackages [cryptography blake3]`, and the source-guard gates police script
  imports; do NOT add a dep, file a task). It has no harness import, so
  `import scalefit; scalefit.fit_scaling(peer_counts, ys, metric=..., unit=..., targets=...)`
  works from anywhere. Reuse it for the PEER-COUNT axis instead of writing a second fitter.
- Also reuse `scalefit.sweep_report_violations(report)` + `scalefit.red_flags_for(models)` and
  FAIL on a non-empty violation list. The S5 honesty rules are mechanical there: extrapolations
  must carry `{"kind": "model_output"}`, R^2/residuals must travel with them, superlinear fits
  must appear in `red_flags`, the resource-laws-only caveat must be present, and nothing under
  `measured` may be a model output. `scripts/scale_sweep.py::build_report` is a working example
  of the measured/models split.
- MIN_POINTS = 5 DISTINCT n. AICc is undefined below that; `fit_scaling` RAISES rather than
  fitting. Plan your peer-count grid accordingly (e.g. 1,2,4,8,16 or 1..30).

HIGH-WATER, NOT POINT SAMPLES (forward-carried requirement, now implemented). Use
`/proc/<pid>/status` VmHWM (kernel peak RSS) as the FITTED quantity and report VmRSS point
samples beside it. `scale_sweep.read_node()` does this host-side: rootless podman runs the
container init as our uid, so `podman inspect -f {{.State.Pid}}` + /proc works with NO binary
inside the image. Do not shell into the container for this - `grep` and `find` are NOT in the
e2e image (rc=127, the dead-oracle trap; it bit me again on the knob readback).
Honest gap you may be the first to exercise: on task-18's workload VmHWM == max VmRSS at every
point (daemon RSS grows monotonically and is never released), so the high-water/point
distinction is UNEXERCISED by real data so far. A bursty p2p fetch workload should finally
separate them - if it does not, say so rather than implying the distinction was validated.

CONCURRENCY MUST BE MEASURED. `Pod.client_run_bg(..., jobs=, conns=, start_at_ns=)` exists and
the client emits REALISE_NS / REALISE_T0_NS / REALISE_T1_NS. `scale_sweep.max_overlap()` turns
those into the measured max overlap, and a point whose overlap != N is INVALID. Proven on real
containers: serialising the fleet drove overlap to 1/4 and invalidated the point. Also proven
the other way - disabling the start barrier did NOT reduce overlap (launches are async), so the
BARRIER is jitter insurance and the MEASUREMENT is the guarantee. Do not assume N peers were
concurrent because you started N of them.

Other traps:
- Fit latency from the IN-CONTAINER realise duration, never the host-side `podman run` wall
  clock: the latter carries container create/start/teardown, which itself scales, so you would
  recover podman's law rather than the product's.
- The client knob axis (max-substitution-jobs/http-connections) is capped by the number of
  substitutable paths in the workload (3 today), so 16 and 128 are indistinguishable. TASK-57
  tracks a wide-fanout fixture. Assert the knob READBACK (`nix config show <name>`, parsed from
  the ===KNOBS=== section) as a precondition - an unconfirmed knob makes the arm unusable.
- A single-seed "the 95% CI covered the truth" check is a coin flip, not an oracle. Use a
  Monte-Carlo coverage rate (scalefit's self-test does; measured 0.965 / 0.960).
- The intervals UNDER-COVER under multiplicative noise (0.865 measured at n=1000). Resource
  metrics are multiplicative-ish, so treat far extrapolation intervals as optimistic and say so.
<!-- SECTION:NOTES:END -->
