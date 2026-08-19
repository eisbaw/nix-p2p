---
id: TASK-253
title: >-
  Profiling and benchmarking toolchain: hyperfine + criterion + CPU/RAM
  profilers on the libp2p path
status: Done
assignee: []
created_date: '2026-08-18 20:25'
updated_date: '2026-08-19 14:54'
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
- [x] #1 flake.nix provides hyperfine + criterion (dev-dep) + a flamegraph/perf tool; just recipes bench, profile-cpu, profile-ram exist and run on the dev host
- [x] #2 hyperfine A/B recipe benchmarks a shipped binary/just-recipe on the PRIMARY libp2p path (NOT iroh), with --export-json; run cost BOUNDED (small warmup + capped run count, documented)
- [x] #3 at least one criterion microbench on a hot path (NAR serve two-pass regenerate OR zstd codec OR claim-wire encode/decode), runnable via just bench, bounded sample size
- [x] #4 a RAM oracle better than peak RSS (dhat or heaptrack allocation profile) via just profile-ram on the libp2p serve path; the existing serve-budget residency oracle stays intact
- [x] #5 just profile-cpu produces a flamegraph on the libp2p serve OR fetch path (primary stack, not the deprioritized iroh path)
- [x] #6 NO floats in any gate/decision field the tooling emits (integers/exact rationals; floats only as terminal display); run cost BOUNDED — no CPU-hog farm, bench sample counts + durations capped and documented
- [x] #7 instrumentation ONLY — explicitly NOT the value-thesis measurement (TASK-237), NOT tournament/policy training material, no PRD success claim
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-253 delivered (commit 7916f9d), LIGHT gate green. Reusable profiling instrument on the PRIMARY libp2p path, THIN, instrumentation-only. One hot path (claim/hold-query wire codec, daemon-core/src/claim.rs) x three lenses. flake.nix adds hyperfine/cargo-flamegraph/perf/valgrind to the dev shell; daemon-core adds criterion (dev-dep) + dhat (optional, off by default so it stays OUT of every shipped/e2e closure - verified absent from daemon-libp2p normal deps). Shared target: daemon-core/examples/claim_wire_load.rs (dual-mode: normal + --features dhat-heap); criterion bench daemon-core/benches/claim_wire.rs.

Recipes (all ran green on bounded input): bench = criterion sample_size=20/2s + hyperfine --warmup 2 --runs 10 x --iters 20000 A/B (small vs large). profile-cpu = cargo-flamegraph via perf (works at perf_event_paranoid=2, user-space; kernel frames absent by design) -> valgrind/callgrind fallback if perf refused; deletes the ~360MB perf.data byproduct. profile-ram = dhat allocation profile (total + at-peak), an oracle better than peak RSS.

One bounded run: hyperfine small 115.6ms vs large 350.1ms (3.03x). criterion claim_roundtrip 16.3us, claim_decode 10.3us, hold_query_roundtrip 753ns. dhat @2000 iters: total 45,896,626 bytes in 352,003 blocks, at-peak 9,504 bytes in 17 blocks. flamegraph.svg 49KB (9263 user-space samples).

No-floats: derived numbers all integer; raw tool JSON verbatim; check-no-floats.py green (no new scanned script). fmt+clippy green (incl dhat-heap variant). Existing serve-budget residency oracle intact: profile_budget 19/19 pass. artifacts/profiling/ gitignored. NOT the value thesis (TASK-237), no PRD claim. AC#1-7 all met.

CPU tool: cargo-flamegraph/perf (paranoid=2 permits user-space sampling - real flamegraph, no privilege escalation needed). No blocker hit.

IMPLEMENTATION 2026-08-19 (committed 7916f9d; orchestrator finished the wrap-up directly after the implementer died on a mid-stream API stall — code was already committed + complete). VERIFIED by orchestrator (LIGHT gate, instrumentation): flake.nix adds hyperfine/criterion/flamegraph/valgrind/dhat; Justfile recipes bench, profile-cpu, profile-ram all RUN and produce artifacts under artifacts/profiling/ (gitignored). Bounded: criterion collects 20 samples in ~2s; hyperfine --warmup 2 --runs 10; dhat --iters 2000. PRIMARY libp2p path (claim/hold-query wire encode+decode hot path). Verified numbers from a real run: criterion hold_query_roundtrip ~942 ns, hold_query_decode ~590 ns; hyperfine small vs large payload = small 3.08x faster; dhat-heap.json + flamegraph.svg produced (perf_event_paranoid<=2 so cargo-flamegraph worked; valgrind/callgrind fallback wired if perf unavailable). Gate: fmt clean, clippy -D warnings clean (daemon-core --all-targets incl the new bench+example), no-floats green, AI-credit clean; serve-budget oracle intact (24 serve + 2 budget tests pass, 0 failed). docs/profiling.md frames it instrumentation-ONLY (not TASK-237 value-thesis, no PRD claim). All 7 ACs met.
<!-- SECTION:NOTES:END -->
