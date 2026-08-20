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

## nix-p2p vs cache.nixos.org — a first competitive cut (TASK-268, 2026-08-19)

The **CDN side is measured** (this host's real link to cache.nixos.org, one timed fetch each);
the **peer side is MODELLED** from the measured serve cost — so the peer numbers are an
*optimistic lower bound*, and this is a first cut, not a verdict of record.

Real CDN download (this host's WAN link to Fastly was ~1-4 MB/s — box-specific, single sample):

| package | compressed (CDN) | CDN time | raw NAR (peer) | raw / compressed |
| --- | ---: | ---: | ---: | ---: |
| hello | 57 KB | 0.05 s | 275 KB | 4.8x |
| curl | 554 KB | 0.26 s | 1.18 MB | 2.1x |
| git | 8.0 MB | 2.14 s | 50.5 MB | 6.3x |
| python3 | 56.6 MB | 48.3 s | 133 MB | 2.4x |

Peer TRANSFER model (serves the RAW NAR; wall ≈ 22 ms floor + max(regen@2.2 GB/s, transfer))
vs the measured CDN, by peer-link speed:
- **LAN 1 Gbps:** nix-p2p wins **2-44x** — the local link so outweighs the 2.4-6.3x raw-byte
  penalty that it stops mattering.
- **home 100 Mbps:** mixed — nix-p2p wins *except* `git`, whose 6.3x compression ratio (the
  best-compressing package) is the peer's worst case.
- **WAN comparable to the CDN link:** cache.nixos.org wins everywhere (it moves 2.4-6.3x fewer bytes).

**Verdict, with the caveat that decides it:**
- On **data transfer alone**, nix-p2p wins on a fast *local* link — confirming the org/LAN
  same-pin thesis (256) with numbers — and loses over a link comparable to the CDN's, where
  compression wins.
- **This EXCLUDES discovery latency**, which the PRD flags as seconds-scale and which is **not
  measured here**. For small packages (sub-second transfers) a multi-second DHT lookup would
  dominate and could *flip* the result. So the end-to-end verdict is **unsettled**: transfer
  favours the LAN peer; discovery is the unmeasured wildcard.
- The peer side is a model (ignores dial/handshake/framing/**discovery**); the CDN side is a
  single sample on one host's link. A real two-machine e2e that *includes discovery* is the
  honest confirmation — still to run (this is the transfer-model half of TASK-268).

## Compression x link-speed sweep — the crossover map (TASK-269, 2026-08-19)

The 268 cut modelled the peer serving the **raw** NAR. 269 asks the next question:
if the **peer link itself compresses** (on the fly, per serve), does that move the
crossover? The sweep measures every real package NAR against a codec grid
(`none, lz4, zstd-1/3/9/19, xz-6/9, brotli-5/11`) — exact compressed **bytes**,
compress **CPU**, decompress **CPU** — then models the peer wall at four link
speeds and compares to the measured CDN. Raw data:
`evidence/task-269/sweep_results.json`; the map is COMPUTED from it by
`scripts/task269_crossover.py` (`evidence/task-269/crossover_map.json`).

Model: `peer_wall = regen + compress_cpu + compressed_bytes/link + decompress_cpu`.
**The asymmetry that decides it:** the peer regenerates the raw NAR and compresses
it **on every serve**, so `compress_cpu` is a real per-serve tax; the CDN serves a
**precomputed** file and pays no per-serve compress cost. (`regen` = the measured
serve model: 22 ms floor + NAR/2.2 GB/s. All quantities integer ns/bytes; the
crossover decision is an integer `peer_wall_ns < cdn_wall_ns`; ratios are exact
`compressed/raw` rationals — `check-no-floats.py` scans both new scripts.)

**Sweet spot per (package, link)** — the codec giving the minimum peer wall:

| link | best codec | nix-p2p vs cache.nixos.org |
| --- | --- | --- |
| 2 MB/s (16 Mbit WAN) | light zstd / brotli-5 | mixed (cache.nixos.org wins the small pkgs) |
| 12.5 MB/s (100 Mbit home) | **zstd-1..3** | **nix-p2p wins every package** |
| 125 MB/s (1 Gbit LAN) | **none (raw)** | nix-p2p wins every package |
| 1000 MB/s (10 GbE) | **none (raw)** | nix-p2p wins every package |

Three findings, stated separately:

- **Heavy codecs NEVER beat the CDN — the per-serve compress CPU sinks them.**
  `zstd-19`, `xz-6/9`, `brotli-11` cost hundreds of ms (python3 `xz-9` = **51 s** of
  compress CPU *per serve*) — more than they save in transfer at any link, so their
  crossover is "never". On-the-fly per-serve compression rules out the high-ratio
  codecs categorically; only the *cheap* end of the curve is viable.
- **At home bandwidth (100 Mbit), light link-compression is the sweet spot and
  flips the peer to a win.** `zstd-1..3` (ratio ~2-4x, compress CPU 2-12 ms on
  small pkgs, ~0.2-0.5 s on python3) minimizes wall and beats the CDN on every
  package — where raw ("none") alone was mixed in the 268 cut.
- **At LAN/datacenter speed, raw wins — don't compress.** Above ~125 MB/s the link
  so outpaces the codec that any compress CPU is pure overhead; `none` is the min-wall
  choice and nix-p2p wins outright. This is the **org/LAN-first product regime
  (256)**: it needs **no link compression at all**.

**Headline answer:** link compression makes the peer competitive **only in the
home-bandwidth WAN-swarm regime (~100 Mbit)**, and only with a **light** codec
(`zstd-1..3`); for the org/LAN-first product the fast link already wins with raw
bytes, so link compression is a **non-priority** there. If a home-bandwidth swarm
becomes a target, a **negotiated `zstd-3` link option** is the candidate default —
NOT a fixed high-ratio codec, because the per-serve compress CPU is the binding
constraint. Follow-up: TASK-270 (consider negotiated light-compression on the peer
link) — deliberately deferred behind discovery/LAN-first per the North Star.

**Caveats (this is a model, not an e2e):**
- **EXCLUDES discovery latency** (PRD risk 3) — transfer+compression only; a
  multi-second DHT lookup could still flip the small-package cases.
- It is a **model**: measured compression + the transfer model, NOT a shaped-link
  e2e. The additive wall is conservative for the peer (a real serve could pipeline
  compress with transfer).
- CDN walls are **single WAN samples** on this host's link (1-4 MB/s,
  package-dependent) — the 2 MB/s column is the noisiest because the peer's modelled
  link and the CDN's measured link differ per package. `cdn_wall` is download-only
  (excludes the client's decompress of the CDN file); negligible in the crossover
  region, where transfer dominates.
- **Bounded-sweep caps:** full grid on the <=3 MB packages (3 runs, min CPU); on
  git/python3 the high-CPU middle levels (`zstd-9`, `xz-6`) and the slow `brotli`
  levels were **skipped** (recorded as `status: skipped` cells, never dropped) and
  large packages ran a single pass. Disk held flat at 21.9 GB (NARs streamed to
  memory, no temp files on disk).

**Effective (post-decompression), apples-to-apples.** The crossover above compares
*download* bytes. But the fair unit is *time to usable RAW bytes* — and the CDN's
compressed file is not free to the client, which must decompress it. The CDN serves
**xz** for most packages (`hello/bash/git/glibc`); nix-p2p, when it compresses at all,
wants **zstd** (the sweet spot). Client decompress cost, measured in the sweep:

| package | CDN codec | CDN file | client decompress | nix-p2p zstd-3 decompress |
| --- | --- | ---: | ---: | ---: |
| hello | xz | 57 KB | 4.6 ms | 1.5 ms |
| git | xz | 8.0 MB | **270 ms** | 77 ms |
| python3 | zstd | 56.6 MB | 175 ms | 175 ms |

So: (1) on a LAN nix-p2p serves **raw** — client decompress is **0**, while the CDN still
pays its xz-decompress (git: +270 ms); (2) where nix-p2p *does* compress (home bandwidth),
**zstd-3 decompresses ~3.5× faster than the CDN's xz** (git 77 ms vs 270 ms) *and* is cheap
enough to compress per-serve, which xz is not. The xz-vs-zstd asymmetry favours nix-p2p on
the decompression leg in both regimes. (`cdn_wall` in the crossover map is still
download-only; folding client-decompress in only widens nix-p2p's margin — it never narrows
it.)

**Why the CDN holds the slow links — the per-serve compression moat.** At a slow link, transfer
dominates, so ratio should matter — yet no codec lets nix-p2p win, because it compresses **on
the fly, per serve**. The full zstd ladder on `git` (50.5 MB NAR) at 16 Mbps, vs the CDN's
precomputed xz (`FileSize` 8.01 MB, 4.35 s effective incl. its 0.34 s client xz-decompress):

| peer codec | size | compress (per serve) | transfer | total | vs CDN |
| --- | ---: | ---: | ---: | ---: | --- |
| zstd-9 | 11.4 MB | 0.88 s | 5.71 s | **6.66 s** (best) | CDN |
| zstd-17 | 9.0 MB | 14.4 s | 4.51 s | 18.98 s | CDN |
| zstd-19 | 8.7 MB | **24.0 s** | 4.33 s | 28.44 s | CDN |

`zstd-19` actually *matches* xz's file size (8.66 vs 8.01 MB) and decompresses **10× faster**
(0.04 vs 0.34 s) — but it costs **24 s of compress CPU on every serve**, while the CDN's xz is
**compressed once at build time** (zero per-serve cost). The cheap levels that avoid that CPU
lose on ratio. There is no level that is both small *and* cheap-to-compress-per-serve, so the
build-once-vs-serve-every-time asymmetry is the CDN's moat on slow links; nix-p2p wins the fast
links on raw bytes, not compression. **The lever** (TASK-271): a peer that *cached* the
compressed NAR (compress once, serve many) amortizes the CPU and would let `zstd-19` win even at
16 Mbps — at the cost of the current stateless "nothing at rest" design.

## Discovery latency — the container floor (TASK-283, 2026-08-20)

The compression sweeps above **exclude** discovery latency (PRD risk 3), and it was the one
unmeasured leg. This is the first real measurement of the **shipped** libp2p discovery path —
mDNS peer-discovery + kad `get_providers` — in **integer milliseconds**. It is produced, not
modelled: `fabric-libp2p` emits a `DISCOVERY-LATENCY-*` `tracing::info!` marker at each real
boundary (`swarm.rs`), the composite `/bin/daemon` installs the subscriber when `RUST_LOG` is
set (TASK-272 `init_tracing`), and `just discovery-latency` drives a real two-node zero-bootstrap
mDNS fetch and parses the integers **from the raw daemon logs** into `evidence/task-272/`
(`discovery-latency.json` + `lp-provider.log` / `lp-consumer.log`).

**Measured (one run, one podman bridge, one host):**

| boundary | node | integer ms | provenance |
| --- | --- | ---: | --- |
| mDNS time-to-first-peer | provider (`.11`) | **1** | discovered the already-present consumer instantly |
| mDNS time-to-first-peer | consumer (`.10`) | **610** | came up first; waited for the provider to join the multicast segment |
| kad `get_providers` | consumer (`.10`) | **0** (×6 walks) | sub-millisecond; the provider's address was already in the k-buckets (mDNS `add_address`), so the walk is a local lookup |

The **kad `0 ms`** is an honest observation, not a missing number: on loopback, once mDNS has
seeded the provider's address, the `get_providers` walk resolves in **under one millisecond** and
integer-flooring reports `0`. The measurement is per real query (the fetch issued six walks, all
`0`). What this says: on a LAN with the peer already known, kad content-discovery is effectively
free; the real cost on a real network is the RTT-bound walk, which this loopback floor does **not**
capture.

**Caveat — this is a CONTAINER/LOOPBACK FLOOR, a lower bound.** All nodes share one podman bridge
on one host, so these are the smallest numbers the mechanism can produce, not real-network
discovery latency. The mDNS `610 ms` is dominated by **startup ordering** (the consumer starting
before the provider announced) plus the provider's lone-genesis announce-quorum retry, not by
multicast propagation. Real-network discovery latency — multi-hop DHT walks, WAN RTT, NAT
traversal — is **TASK-268 / TASK-237 / TASK-282**, not this. The number here exists to (a) prove
the shipped path is instrumented and (b) give the LAN floor the compression sweeps were missing.

**Integers only.** Every emitted latency is a `u64` millisecond (`Duration::as_millis` floored via
`u64::try_from`); the serialized `discovery-latency.json` carries only integers and provenance
strings — no float enters any field. The instrumentation is off the byte path (one marker per
discovered peer / completed walk), so it does not perturb transfer timing.
