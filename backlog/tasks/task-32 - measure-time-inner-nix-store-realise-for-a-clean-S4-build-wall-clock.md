---
id: TASK-32
title: 'measure: time inner nix-store --realise for a clean S4 build wall-clock'
status: To Do
assignee: []
created_date: '2026-08-08 13:35'
labels:
  - measurement
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
measure.py (task-9) times the whole 'podman run --rm' per run, so the p95 build wall-clock is dominated by container-startup jitter (~1-2s over a ~0.5s workload). Consequence: the A/A noise floor straddles the 10% S4 threshold (observed 3.76%/9.72%/11.78% across three N=10 runs on the same host), so s4_usable flips run-to-run and S4 is often flagged UNUSABLE. The EGRESS instrument is unaffected (exact, all bites pass) and the trustworthy verdict is stable; only the S4 latency axis is noise-limited. Fix: emit REALISE_START/REALISE_END markers around 'nix-store --realise' in scripts/e2e_harness.py::_CLIENT_SCRIPT (date +%s.%N; coreutils has date) and have measure.py use the inner realise duration as the build wall-clock instead of the podman-run wall. Alternatively/additionally, measure the S4 latency bound on the VM tier (task-10). Blocks a usable container-tier S4 for the J2 baseline (task-12).
<!-- SECTION:DESCRIPTION:END -->
