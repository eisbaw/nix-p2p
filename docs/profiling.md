# Profiling & benchmark toolchain (TASK-253)

The reusable CPU/RAM/wall-clock instrument for the **primary libp2p path**. This is
**instrumentation only** — it produces no policy evidence, no PRD success claim, and gates
nothing. The value-thesis measurement is TASK-237, a separate thing; the bespoke iroh-path
harnesses (`just iroh-bench`, `scripts/profile_p2p.py`, task-65 fitters) are left in place
and are explicitly **not** what this replaces day-to-day.

## What it targets

One hot path, three lenses: the **claim / hold-query wire codec** (`daemon-core/src/claim.rs`
— `encode_claim`/`decode_claim`, `encode_hold_query`/`decode_hold_query`). This is the frozen
wire format the libp2p discovery+serve path speaks (`daemon-core` is consumed by the primary
`daemon-libp2p` binary; there is **no iroh** in this path). It was chosen over the NAR two-pass
regenerate and the zstd codec because it is hermetic, deterministic, and bounded — no `nix`
subprocess, no swarm, no sockets — which is what lets the recipes stay cheap on a shared host.

**Honest altitude limit:** these three lenses profile the *wire-codec component* of the
serve/discovery path, not a full two-node swarm serve. A whole-swarm profile would be heavy
and flaky (the exact CPU-hog/soak risk the task forbids on this shared, disk-tight box). The
codec is the representative in-process hot path; a swarm-level profile is a separate,
heavier instrument if one is ever needed.

## Recipes (all `nix develop -c just <recipe>`)

| recipe | tool | what | bounded cap |
| --- | --- | --- | --- |
| `bench` | criterion + hyperfine | per-op time estimate (in-process) **and** whole-process wall-clock A/B (small vs large claim) | criterion `sample_size=20`, 2 s measure, 0.5 s warmup; hyperfine `--warmup 2 --runs 10`, `--iters 20000`/invocation |
| `profile-cpu` | cargo-flamegraph (perf) → valgrind/callgrind fallback | CPU attribution / flamegraph | perf run `--iters 400000` (~1–2 s of samples); callgrind `--iters 4000` |
| `profile-ram` | dhat | **allocation** profile (total + at-peak bytes/blocks) — better than peak RSS | `--iters 2000` (dhat instruments every allocation) |

Outputs land under `artifacts/profiling/`:
`hyperfine-claim-wire.json`, `flamegraph.svg` (or `callgrind.out`), `dhat-heap.json`.

## perf privilege note (the likely blocker, handled)

`cargo-flamegraph` drives Linux `perf`, which reads `kernel.perf_event_paranoid`:

- `<= 1` — kernel + user-space sampling.
- `= 2` — **user-space sampling only** (the default on many hosts). This is enough for a real
  flamegraph of *our* code, which is user-space; kernel frames are simply absent.
- `> 2` or no `perf` binary — sampling is refused.

`profile-cpu` reads `/proc/sys/kernel/perf_event_paranoid` and, when perf cannot sample,
**falls back to `valgrind --tool=callgrind`** (privilege-independent, deterministic
instruction counting) and prints which tool it used. That fallback is a call-graph
attribution (`callgrind_annotate artifacts/profiling/callgrind.out`), not a flamegraph — a
precise "perf needs paranoid ≤ 2, used callgrind instead" is the intended honest outcome, not
a faked SVG.

## no-floats

Every number these recipes / the harness *derive and emit* is an integer (roundtrip counts,
wire byte lengths, dhat block/byte totals). The raw tool JSON (criterion estimates, hyperfine
seconds) contains the tools' own statistical floats — those are terminal display, not a
gate/decision field of ours, so the owner no-floats rule is not engaged. `check-no-floats.py`
scans the Python gate scripts; this change adds none.

## Findings on real packages (2026-08-19)

The codec lenses above are hermetic micro-benchmarks. A first *real-package* pass profiled
the shipped serve path's dominant cost — **NAR regeneration** (`nix-store --dump`, a
subprocess; the daemon then Bao-hashes + streams the bytes). hyperfine, 5 runs each, on a
loaded shared host (treat as rough, ±10-20%):

| package | NAR size | regen mean | effective MB/s | fixed-overhead share |
| --- | ---: | ---: | ---: | ---: |
| hello | 274 KB | 20.7 ms | 13 | ~62% |
| curl | 1.18 MB | 25.3 ms | 47 | ~51% |
| git | 50.5 MB | 35.0 ms | 1445 | ~37% |
| python3 | 133 MB | 71.1 ms | 1874 | ~18% |

Fitting the two largest (least overhead-dominated) gives a clean model:
**~13 ms FIXED per-path overhead** (subprocess spawn + nix DB lookup) **+ ~2.3 GB/s per-byte**
streaming. BLAKE3/bao hashing (~1-3 GB/s) and loopback transport are comparable-or-faster, so
neither is the bottleneck.

**The load-bearing insight:** for small paths the ~13 ms *fixed* cost dominates (a 274 KB
`hello` regenerates at an effective 13 MB/s — 62% overhead), and **real closures are
many-small-paths** (the TASK-256 probe found closures of 20-166 paths, mostly small). So a
50-small-path closure spends **~0.6 s in `nix-store --dump` spawns alone, independent of
bytes**. The serve-side lever for the org/LAN same-pin case (the honest first product) is
therefore **per-path subprocess overhead**, not NAR throughput — e.g. batching regeneration
or a persistent nix-store connection would cut it. This is consistent with TASK-64/62's
"~70% of the per-byte cost sits below our code": on real packages our serve code is cheap;
the cost is the external `nix-store` regeneration overhead + the bytes themselves.
