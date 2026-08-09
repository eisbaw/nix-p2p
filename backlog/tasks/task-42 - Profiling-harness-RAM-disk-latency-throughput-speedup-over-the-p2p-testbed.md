---
id: TASK-42
title: 'Profiling harness: RAM/disk/latency/throughput/speedup over the p2p testbed'
status: Done
assignee:
  - '@me'
created_date: '2026-08-08 20:13'
updated_date: '2026-08-09 13:22'
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
- [x] #1 just profile emits a report: per-node RSS/fds, disk footprint, latency p50/p95, throughput, egress-vs-upstream, for a scripted p2p workload
- [x] #2 S9 bite: a synthetic known-O(n)-RAM scenario recovers a linear regression fit; a known-O(1) recovers constant; wrong-model selection fails the self-test
- [x] #3 Extrapolation labeled model-output (never measurement); R^2/residuals reported; resource-laws-only caveat stated (no emergent-network-effect claims)
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

## Implementation plan (task-42 implementer)

NEW: `scripts/profile_p2p.py` (+ `just profile`, SLOW tier), reusing rather than
reimplementing: `scale_sweep.{NodeSampler,read_node,aggregate_samples,max_overlap,
parse_realise_seconds,latency_block,SweepPoint,Axis}`, `scalefit.{fit_scaling,
sweep_report_violations,red_flags_for}`, `measure.{classify_run,percentile,stat_block}`.

TWO ARMS.
1. SWARM axis (FITTED, n = holder peers, grid 1,2,4,8,16): a real p2p swarm of
   n+1 daemon PROCESSES in one pod (node-a + node-b..node-bN, every holder an
   iroh provider seeded with the raw NARs). Fitted: worst per-peer VmHWM, swarm
   total VmHWM, worst per-peer fds, per-peer on-disk bytes, client p95 realise.
2. SPEEDUP/THROUGHPUT arm (NOT fitted): peers-ON vs peers-OFF over the frozen
   net-upstream-egress-v2 rule (measure.classify_run), with `big` (110 MiB) so
   throughput is a real number and VmHWM/VmRSS finally get a bursty workload.

UNIT DISCIPLINE (the NarSize-vs-FileSize trap, 3x recurred) is MECHANICAL here:
every key ending in `_bytes` must carry one of `_ram`/`_ondisk`/
`_uncompressed_nar`/`_compressed_wire`; `unit_violations(report)` fails the run
otherwise, proven by mutation. The speedup arm uses ONLY `compression: none`
attrs (lib, big) and ASSERTS file_size == nar_size from the manifest, so wire
and NarSize coincide by checked precondition rather than by hope.

S9 BITE (AC#2) is a Monte-Carlo class-recovery study over the REAL grid, gated
on rates (not one lucky seed): O(n)->linear, O(1)->constant, O(n^2)->superlinear
and NEVER linear, O(n log n)->superlinear; wrong-model = selected class outside
the generated class's family -> self-test FAILS.

Pod seam extension: `p2p_holders=N` (swarm) and `state_root=` (a host-side
bind-mounted --narinfo-cache-dir per node, so DISK is walked host-side at the
right boundary - no in-container binary, no rc=127 dead oracle).

## Implementation record (task-42)

LANDED: `scripts/profile_p2p.py` + `just profile` (SLOW) + its container-free
`--self-test` in the FAST `just test` gate; `Pod(p2p_holders=N, state_root=)`
in the e2e seam; a correctness fix in `scalefit` (FITTER_VERSION -> v2).

### Gotchas that cost time (forward-carried to 43/44/52/54)

1. THE IROH BLOB STORE IS `MemStore`. There is no on-disk blob store to profile.
   Held content costs RSS: holder peak 248 MiB for a 110 MiB NAR (2.15x),
   fetching node 141 MiB, vs 10.7 MiB for the peers-OFF daemon. On-disk state is
   4096 B (the narinfo cache), FLAT across n=1..16. The disk AC is answered by a
   finding, not a number.
2. `InMemoryDiscovery::announce` REPLACES on key, so `--p2p-claim` cannot express
   a multi-holder claim. The swarm axis therefore measures n peer PROCESSES plus
   an n-entry address book, NOT holder selection or dial fan-out.
3. `e2e.die` is `sys.exit(2)`, not an exception. With 17 containers per point one
   holder failing to announce killed the WHOLE run. Caught and demoted to an
   invalid POINT; root fix filed as TASK-60.
4. REPLICATES DECIDE THE CLASS. --repeats 1 fitted client latency O(n log n) and
   raised a RED FLAG; --repeats 3 fitted O(1) on one run and O(n) on the next,
   both with identifiable=false. Three classes, one metric. task-18's lesson,
   re-confirmed.
5. A red flag meant a superlinear BASIS, not superlinear GROWTH. The fd series
   11,11,...,10,10,10 fitted quadratic with slope -0.004, was flagged, and
   extrapolated to -4015 descriptors. Fixed in scalefit (slope > 0 required) and
   regression-tested with that exact series, direction-sensitivity proven by
   MIRRORING it about its mean.
6. `hash()` IS NOT REPRODUCIBLE. The S9 study's seeds looked deterministic only
   because nixpkgs' python hook sets PYTHONHASHSEED, which this repo does not.
   The gated rates wandered to 0.892 against a 0.88 floor. Use crc32.
7. THE UNIT GATE WAS ITSELF THE VACUOUS SHAPE. endswith('_bytes') let
   `bytes_sent` (a real key here), `egress_bytes_total` and `total_bytes_moved`
   through, and the mutations had been chosen to match the code, not the claim.
8. `aggregate_samples` per_role includes the fixture origin and testproxy. The
   'RAM per held byte: worst node' line takes a max over it - one unlucky
   fixture-server RSS and the summary attributes it to the blob store.
9. A peers-ON arm can silently become peers-OFF. Assert the holder's OWN
   provider counter, and record the upstream egress beside any shortfall:
   'fell back to upstream' and 'the holder's log monitor lagged' are otherwise
   the same observation.

### Rejected approaches
- Extrapolating the peer axis from the 2-node S6 topology: two points cannot
  discriminate O(n) from O(n log n). Built a real swarm instead.
- Measuring container disk via `podman ps --size` or an in-container `du`: `du`
  and `find` are not in the e2e image (rc=127, reads as 0 bytes). Bind-mounted a
  host dir as --narinfo-cache-dir and walked the HOST side.
- Filtering the false red flag inside profile_p2p: that is a workaround. Fixed
  the meaning of `superlinear` in scalefit instead.
- A one-seed 'the fitter got it right' bite: a coin flip dressed as an oracle.
  Monte-Carlo rate gates instead.

## Final summary (task-42 DONE)

DELIVERED: `scripts/profile_p2p.py` (~2.5k lines) + `just profile` (SLOW) + a
91-check container-free `--self-test` in the FAST `just test` gate; the Pod seam
gains `p2p_holders=N` (a real n+1-process peer swarm) and `state_root=` (host-side
disk measurement); `scalefit` -> v2 (a red flag now means superlinear GROWTH).

GATES (this tree): build 0, lint 0, test 0 (209 cargo tests; 202 self-test
checks across four instruments), e2e 0 (26/26 scenarios, 200 checks),
profile 0 (usable=true, honesty_compliant=true, red_flags=0, 15/15 swarm points,
10/10 per speedup arm). git notes --ref=verification carries the detail.

HEADLINE MEASUREMENTS (this host; every byte figure unit-labelled by schema):
  MEASURED, swarm 1..16 holder peers, 3 replicates, 15/15 valid
    per-peer peak RSS (VmHWM)  19.1-21.2 MiB     fitted O(1), NOT identifiable
    swarm-total peak RSS       37.9 -> ~305 MiB  fitted O(n), R^2 0.9985
    per-peer fds               10-11             fit not identifiable, R^2 0.54
    per-peer on-disk           4096 B allocated  fitted O(1), R^2 1.0, FLAT
    client realise             0.028-0.037 s     fitted O(1), R^2 0.0
  MEASURED, speedup arm (110 MiB + 64 KiB, compression:none, 10 valid runs/arm)
    egress payload   peers-off 115,409,920 B(wire) -> peers-on 0 -> offload 1.00
    realise mean     peers-off 0.159 s vs peers-on 0.562 s
    latency speedup  0.283 (range 0.177-0.511) -> THE PEER PATH IS ~3.5x SLOWER
    throughput       iroh 210 MB/s vs HTTP-through-daemon 758 MB/s (NarSize)
    peak RSS         node-b 236.7 MiB, node-a 135.9 MiB, peers-OFF daemon 10.7 MiB
    RAM per held NarSize byte  node-b 2.15x, node-a 1.23x
  MODEL OUTPUT (labelled, never a measurement)
    swarm-total RSS at n=1000: 18.75 GB (95% CI 18.32-19.18 GB)

FINDINGS THE NEXT WAVE MUST NOT REDISCOVER
1. THERE IS NO ON-DISK BLOB STORE. `IrohProvider` uses `MemStore`, so held
   content costs RAM. Per-node disk is 4096 B, flat. The binding constraint for
   scale is MEMORY, and a whole-NAR addressed unit makes BOTH ends resident-size
   the payload. -> TASK-54's subject changes.
2. THE PEER PATH IS SLOWER THAN THE CACHE ON THIS TESTBED, while offloading 100%
   of payload egress. The 'upstream' is a loopback testproxy, i.e. an
   unrealistically fast cache, so 0.283 is NOT a product number - but it does
   mean the slow-HIT policy question is the NORMAL case here, not an edge case.
   -> TASK-44 must model both regimes.
3. TASK-18's HIGH-WATER GAP IS NOW CLOSED. The 110 MiB burst separated VmHWM
   from the point sample by 99.8 MiB on the holder. The distinction is
   EXERCISED, not merely reported.
4. SWARM SIZE 1..16 MOVED NOTHING per-peer: RSS, fds, disk and client latency
   are all flat. Only the host total grows, linearly.

HONEST LIMITATIONS OF THE INSTRUMENT
- The fitted CLASSES for RSS and latency are not backed by a demonstrated
  recovery rate: on this grid the linear-vs-superlinear split is demonstrated
  only to ~1% relative noise, and the observed replicate spread is 1.7-4.0%.
  The report computes this per metric and prints a NOISE warning; read
  `identifiable`, R^2 and interval width, not the class name.
- Extrapolation intervals UNDER-cover under multiplicative noise (0.865 vs 0.95
  nominal at n=1000). Far extrapolations are optimistic.
- The swarm axis measures n peer PROCESSES plus an n-entry address book, NOT
  holder selection or dial fan-out: a multi-holder claim is not expressible
  (announce replaces on key).
- `nix flake check` was NOT run; the cargo results come from a warm ./target.
- Follow-ups filed: TASK-58 (shared podman label), TASK-59 (parallel S5 report
  implementations + the unit rule policing only one schema), TASK-60
  (e2e.die as control flow).
<!-- SECTION:NOTES:END -->
