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

The codec lenses above are hermetic micro-benchmarks. A *real-package* pass profiled the
shipped serve path's dominant cost — **NAR regeneration** (`nix-store --dump`, a subprocess;
the daemon then Bao-hashes + streams the bytes). hyperfine, warmup 3 + 15 runs each, on an
**idle** host (σ 2.8-4 ms; still treat as indicative, not a benchmark of record):

| package | NAR size | regen mean | effective MB/s |
| --- | ---: | ---: | ---: |
| hello | 274 KB | 22.2 ms | 12 |
| curl | 1.18 MB | 21.2 ms | 56 |
| bash | 1.65 MB | 22.6 ms | 73 |
| glibc-locales | 3.07 MB | 22.7 ms | 135 |
| git | 50.5 MB | 32.0 ms | 1579 |
| python3 | 133 MB | 68.8 ms | 1937 |

Two regimes, stated separately rather than over-fit to one line:
- **A ~22 ms per-path FLOOR.** The four packages from 274 KB to 3 MB all land at ~22 ms,
  essentially size-independent — that is the fixed cost of `nix-store --dump` (fork/exec +
  nix DB lookup). (An earlier loaded-box pass mis-fit this as ~13 ms by extrapolating from the
  two largest points; the real small-path floor is ~22 ms.)
- **~2.2 GB/s per-byte** streaming above the floor (git→python3 slope), so large packages
  amortize it. BLAKE3/bao hashing (~1-3 GB/s, comparable) and loopback transport are not the
  bottleneck. (`b3sum` was absent from the shell, so hashing is characterized from its known
  rate, not measured here.)

**The load-bearing insight:** small paths are floor-bound (`hello`'s 274 KB regenerates at an
effective 12 MB/s — almost all of the 22 ms is fixed overhead), and **real closures are
many-small-paths** (the TASK-256 probe found closures of 20-166 paths, mostly small). So a
50-small-path closure spends **~1.1 s in `nix-store --dump` spawns alone, independent of
bytes**. The serve-side lever for the org/LAN same-pin case (the honest first product) is
therefore **per-path subprocess overhead**, not NAR throughput — batching regeneration or a
persistent nix-store connection would cut it. This is consistent with TASK-64/62's "~70% of
the per-byte cost sits below our code": on real packages our serve code is cheap; the cost is
the external `nix-store` regeneration overhead + the bytes themselves.
