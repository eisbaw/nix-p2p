---
id: TASK-253
title: >-
  Profiling and benchmarking toolchain: hyperfine + criterion + CPU/RAM
  profilers on the libp2p path
status: To Do
assignee: []
created_date: '2026-08-18 20:25'
updated_date: '2026-08-19 14:23'
labels:
  - measurement
  - profiling
  - tooling
  - performance
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OWNER ASK 2026-08-18: "we need measurements. we need profiling of CPU and RAM; use hyperfine and other tools for rust."

GAP VERIFIED AT HEAD: there is NO standard benchmarking or profiling tooling in the project. grep over flake.nix, Justfile and Cargo.toml finds zero hits for hyperfine, criterion, flamegraph, perf, dhat, heaptrack or valgrind. Every number the PRD quotes came from a bespoke one-off harness -- task-64 cpu-ns/byte from daemon/examples/iroh_throughput.rs behind just iroh-bench, task-65 RSS-per-NAR-byte from its own fitter, profile_p2p and scale_sweep from Python. Those harnesses are not reusable, they are not wired into a gate, and two of them measure the deprioritized iroh path.

Consequence: the project cannot cheaply answer "did this change make it slower or fatter?", which is exactly the question the value-thesis work (TASK-237) and the streaming change (TASK-62) are about to raise repeatedly.

Scope -- adopt standard tools, do not hand-roll another harness:
  * hyperfine for wall-clock A/B of the shipped binaries and just recipes (warmups, statistical output, --export-json for the report layer).
  * criterion for in-process Rust microbenchmarks on the hot paths: the NAR serve two-pass regenerate, per-leaf Bao authentication, zstd codec, claim-wire encode/decode.
  * A RAM oracle better than peak RSS -- dhat or heaptrack for allocation profiles; keep the existing residency oracle for the serve budget since peak RSS was already rejected as the residency measure.
  * CPU attribution: perf plus flamegraph on the libp2p serve and fetch paths, so the "72% sits below our code" style claim can be re-derived on the PRIMARY stack rather than inherited from the iroh measurement.
  * Package all of it in flake.nix and expose canonical just recipes (bench, profile-cpu, profile-ram) so results are reproducible on the dev host.

Explicit non-goals: this is instrumentation, NOT the value-thesis measurement (TASK-237) and NOT tournament training material. It produces no policy evidence and no PRD success claim.

Cautions from prior rounds: obey the no-floats rule for any gate or decision field (integers or exact rationals; floats only as terminal display). Bound the run cost -- the box is shared and prior stress loops exhausted disk and tmpfs. Do not build a CPU-hog farm.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 flake.nix provides hyperfine + criterion (dev-dep) + a flamegraph/perf tool; just recipes bench, profile-cpu, profile-ram exist and run on the dev host
- [ ] #2 hyperfine A/B recipe benchmarks a shipped binary/just-recipe on the PRIMARY libp2p path (NOT iroh), with --export-json; run cost BOUNDED (small warmup + capped run count, documented)
- [ ] #3 at least one criterion microbench on a hot path (NAR serve two-pass regenerate OR zstd codec OR claim-wire encode/decode), runnable via just bench, bounded sample size
- [ ] #4 a RAM oracle better than peak RSS (dhat or heaptrack allocation profile) via just profile-ram on the libp2p serve path; the existing serve-budget residency oracle stays intact
- [ ] #5 just profile-cpu produces a flamegraph on the libp2p serve OR fetch path (primary stack, not the deprioritized iroh path)
- [ ] #6 NO floats in any gate/decision field the tooling emits (integers/exact rationals; floats only as terminal display); run cost BOUNDED — no CPU-hog farm, bench sample counts + durations capped and documented
- [ ] #7 instrumentation ONLY — explicitly NOT the value-thesis measurement (TASK-237), NOT tournament/policy training material, no PRD success claim
<!-- AC:END -->
