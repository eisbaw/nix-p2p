---
id: TASK-32
title: 'measure: time inner nix-store --realise for a clean S4 build wall-clock'
status: To Do
assignee: []
created_date: '2026-08-08 13:35'
updated_date: '2026-08-10 23:07'
labels:
  - measurement
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
measure.py (task-9) times the whole 'podman run --rm' per run, so the p95 build wall-clock is dominated by container-startup jitter (~1-2s over a ~0.5s workload). Consequence: the A/A noise floor straddles the 10% S4 threshold (observed 3.76%/9.72%/11.78% across three N=10 runs on the same host), so s4_usable flips run-to-run and S4 is often flagged UNUSABLE. The EGRESS instrument is unaffected (exact, all bites pass) and the trustworthy verdict is stable; only the S4 latency axis is noise-limited. Fix: emit REALISE_START/REALISE_END markers around 'nix-store --realise' in scripts/e2e_harness.py::_CLIENT_SCRIPT (date +%s.%N; coreutils has date) and have measure.py use the inner realise duration as the build wall-clock instead of the podman-run wall. Alternatively/additionally, measure the S4 latency bound on the VM tier (task-10). Blocks a usable container-tier S4 for the J2 baseline (task-12).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The harness emits exactly one validated inner-realise start/end pair around the clean nix-store --realise operation, and measure.py uses that elapsed duration for S4 while retaining orchestration/container duration as a separately named metric.
- [ ] #2 Missing, duplicate, reversed, non-finite or unparsable inner-realise markers make the latency sample INVALID; the implementation never silently substitutes outer podman time.
- [ ] #3 Unit/integration tests cover valid parsing, every invalid-marker case, units, percentile selection and report schema/versioning without changing the frozen net-upstream-egress-v2 byte count.
- [ ] #4 An anti-vacuity bite proves an injected container-start delay moves only orchestration time, while an injected delay inside nix-store --realise moves the S4 inner duration by the expected tolerance.
- [ ] #5 A paired A/A run at N>=20 reports the inner-realise noise floor and confidence interval. S4 is usable only when the calibrated floor is below the 10% decision margin; otherwise the result remains explicitly METRIC_UNUSABLE and no latency conclusion is claimed.
- [ ] #6 TESTING.md documents the inner-realise clock, invalidation rules, separate outer-duration diagnostic, calibration result and exact reproducer.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
task-12 data point (J2 baseline read-out, 2026-08-08): the two J2 runs observed A/A noise floors of 0.161 and 0.103 - BOTH >= the 10% S4 threshold, so s4_usable=false in both reports and no container-tier p95 bound was quoted in the J2 baseline (TESTING.md). Confirms this task blocks a usable container-tier S4. The egress axis was byte-identical run-to-run and unaffected, as predicted here.

task-13 triage: KEEP for wave-2 - measure inner nix-store --realise wall-clock is measurement-instrument work (S4 noise floor), not a daemon/proxy hardening finding. Distinct concern.
<!-- SECTION:NOTES:END -->
