# TESTING.md — test grounding & negative feedback (wave 1)

Companion to `PRD.md` (accepted round 6). This document defines what
"good" and "bad" observably mean, and *how the system tells us it is
wrong*. Phase 3's review gate and implementer contract lean on this
file. Update it at the end of every wave (the re-plan task enforces
this).

## Acceptance signals (the strongest e2e checks)

S1. **Byte-identity (trust invariant, testable form).** A store path
substituted through the daemon chain is byte-identical to the same
path substituted directly from the upstream: identical NarHash as
reported by `nix path-info`, and `nix-store --dump` output identical
bit-for-bit. This holds for every acquisition path (upstream
passthrough now; peers later). If S1 can fail silently, nothing else
matters.

S2. **Additive invariant.** With the daemon configured as preferred
substituter: (a) daemon not running at nix-daemon start, (b) daemon
killed mid-NAR-transfer, (c) daemon returning errors — in all cases
`nix build` still succeeds via fallback to the next substituter, and
the local store is never corrupted. This is a standing e2e test, not
documentation prose.

S3. **Offload measurability.** The harness produces, for an identical
scripted build workload, net upstream egress bytes with-daemon vs
without-daemon. Wave 1 does not require offload > 0 (there is no p2p
yet); it requires the *instrument* to be trustworthy: the measured
delta must be provably nonzero in a scenario engineered to have one
(test-proxy cache on vs off).

S4. **Latency bound.** p95 wall-clock of the scripted build with the
daemon enabled ≤ 110% of daemon-off, in the harness. (PRD kill
criterion: this bound plus, in later waves, ≥20% net egress cut on
the favorable testbed — else the p2p thesis dies.)

S5. **Scaling laws, measured then modeled (owner requirement, post-
review).** Behavior at 10s/100s/1000s of peers must be characterized,
but the host cannot run 1000 real nodes — so the harness sweeps the
real system across a feasible range (target 1..30 nodes; peers are
single processes, so prefer process/pod swarms over VMs for sweeps),
samples per-node RSS, fds, and request latency, fits candidate
models (O(1), O(log n), O(n), O(n log n), O(n²)) and extrapolates
with confidence intervals. Honesty rules: (a) the report labels
every extrapolated number as a model output, never a measurement;
(b) fit quality (R², residuals) is reported alongside; (c) a
superlinear fit on RAM or latency is a red flag surfaced, not a
footnote; (d) extrapolation claims cover **resource scaling laws
only** — emergent network effects (mainline DHT k-bucket dynamics,
gossip fan-out at scale) are explicitly outside what small-N sweeps
can predict, and the report must say so. Wave 1 builds and
bite-tests this machinery on the axes that exist (concurrent
clients, chain depth); the p2p wave points it at peer count.

## Good vs bad, observable

| Observable | Good | Bad |
|---|---|---|
| `nix build` of fixture closure via chain | exit 0, S1 holds | any hash mismatch accepted silently |
| Daemon killed mid-transfer | build still exits 0 (S2) | build fails or store corrupted |
| Upstream request counter on repeat build | 0 new upstream hits (cache layer) | re-fetches what a cache layer holds |
| `nix-cache-info` served by daemon | priority < 40, WantMassQuery correct | Nix orders daemon after cache.nixos.org, or errors |
| Upstream down (test-proxy fault mode) | fast, clean substituter failure → fallback | hang / long timeout on the build path |
| Egress report | numbers move when they must (S3 bite test) | metrics flat when traffic changes |
| Long proxy chain (depth ≥ 3) | S1 + bounded added latency | header/metadata mangling, timeout multiplication |

## Negative feedback — how the system tells us it is wrong

Fast/slow split (owner requirement, 2026-08-08): the suite is
explicitly two-tier to keep the iteration cycle fast. FAST =
`just build lint test` + e2e smoke — runs on every cycle, minutes.
SLOW = full e2e matrix, VM tests, soaks, sweeps, fuzzing — runs on a
cadence (wave boundaries, before handoff) via dedicated `just`
recipes (`e2e`, `e2e-vm`, and later `test-slow`). A cycle that ran
only FAST must say so; slow-tier results are never implied.

Gates (all must pass; `just` recipes are the canonical entry points):
1. `just build` — workspace compiles.
2. `just lint` — clippy, `-D warnings`.
3. `just test` — unit + integration (in-process, mock upstream).
4. `just e2e` — container harness: scripted scenarios with oracles
   below. E2E failures BLOCK commits (repo policy).
5. `just e2e-vm` — NixOS VM test (real nix-daemon + systemd
   semantics; slower; standing, and required before wave exit). It
   builds ONE dedicated flake output, `packages.x86_64-linux.vm-test`
   (`nix build .#vm-test`), NOT a flake check: everything under
   `checks` is built by `nix flake check` and pulled into the devshell
   closure, so a VM test there would make every fast gate boot QEMU
   (task-1 codex finding 4). `nix flake check` therefore does NOT cover
   the VM test — `just e2e-vm` is its only entry point. Needs
   `/dev/kvm`.

Oracles (what a scenario asserts against):
- **Request-count oracle**: the test proxy logs every request with
  source, path kind (narinfo/nar/cache-info), bytes, timing; scenarios
  assert exact upstream hit counts (e.g. "second build: 0 upstream
  NAR hits").
  **Oracle-pairing rule (review gate, wave 1): a "0 upstream hits"
  assertion is only valid when paired with an asserted NONZERO
  request count at the layer under test** — otherwise Nix's own
  client-side narinfo cache (`binary-cache-v6.sqlite`, 30-day
  positive TTL) or an already-populated store makes the zero pass
  vacuously. Counting scenarios therefore (a) wipe the client's
  `$XDG_CACHE_HOME/nix` (or zero the narinfo TTLs) per scenario, and
  (b) pin `max-substitution-jobs = 1`; concurrent cases belong to the
  hardening soak, where exact counts are not asserted.

  Client knobs are scenario parameters, not ambient defaults
  (ref: bmcgee.ie "TIL: how to optimise substitutions in Nix"):
  `max-substitution-jobs` (default 16) and `http-connections`
  (default 25) are pinned per scenario and swept where concurrency
  matters — soak and S5 sweeps run at least {1, 16 (default), 128
  (documented real-world power-user setting)}, reported per knob
  value; a default-only pass is not a pass for concurrency-sensitive
  scenarios. Substituter ordering in scenarios uses the
  `?priority=N` URL override (client-side, lower wins, overrides the
  advertised `nix-cache-info` Priority) as the canonical pinning
  mechanism — belt and braces with the daemon's advertised value,
  and a cheap second lever for ordering-flip bite tests. Wave-2
  note: at 128 substitution jobs a naive 200 ms hedge fires ~128
  concurrent upstream fetches — hedge design must be tested against
  this knob, not only the default.
- **Byte oracle**: NarHash / `nix-store --dump` comparison (S1).
- **Build oracle**: `nix build` exit code + `--json` output.
- **Egress oracle**: byte counters at the test proxy = ground truth
  for "net upstream egress" (daemon self-reporting is *not* trusted
  for the kill criterion — the fixture measures, the product is
  measured).
- **Gap oracle**: narinfo→nar request-gap histogram per path,
  recorded by the test proxy; this is the empirical input the DHT
  wave needs (PRD risk 3: is the prefetch window real?). Like every
  oracle it must bite: the harness injects a known artificial gap and
  the histogram must report it within tolerance.

Measurement discipline (S3/S4 are decision inputs, so extra rigor):
- The **counting rule** (exactly what "net upstream egress" includes:
  bodies vs headers, narinfo vs nar, retries) is committed as a doc
  next to the code; the test proxy's byte counters are ground truth
  and the daemon's self-reported counters must agree within a stated
  tolerance (the product is measured, not trusted).
  The frozen doc is `scripts/MEASUREMENT_COUNTING_RULE.md` (counting-rule
  version **`net-upstream-egress-v2`**); its executable form is
  `scripts/measure.py` (`just measure`, task-9). Egress ground truth is the
  testproxy `bytes_sent` (body bytes) at the cache boundary; the unit is
  **compressed on-wire bytes (`file_size`), never `NarSize`**; truncated and
  retried transfers are excluded (a run containing one is INVALID, fail-closed).
  The daemon self-counter tolerance is **≤ 1%** (NAR only). Every report embeds
  the workload version + fixture lock public key/hashes + the counting-rule
  version. **The J2 baseline (task-12) is what records numbers here** by running
  `just measure` after `just fixtures-large` + `just fixtures-verify-rebuild`;
  this task delivers the instrument, not the baseline.
  The p2p profiling instrument (`just profile`, task-42) EXECUTES this
  same rule via `measure.classify_run` rather than restating it, and
  marks any arm below the 10-valid-run floor `dev_smoke_below_n10`
  instead of presenting it as a baseline.
- **Sample discipline**: N ≥ 10 runs per arm, variance reported.
- **A/A calibration**: daemon-off vs daemon-off must show a noise
  floor below the 10% S4 threshold, else S4 is reported as unusable
  — never silently trusted.

Prove-the-check-bites (each oracle must be shown able to fail):
- Corrupt-NAR fault mode on → build MUST fail with a hash error
  (proves Nix's gate + our plumbing don't mask corruption). A test
  that cannot distinguish corrupt from correct bytes is deleted, not
  skipped.
- Cache off vs on MUST move the request-count oracle.
- Kill-mid-transfer MUST show a truncated-transfer event in the log
  AND a successful fallback (both, or the scenario is lying).

Fault-injection modes (live in the **test proxy only** — never in
the product daemon, per PRD): added latency (per path-kind),
HTTP 500/503, connection reset, truncated NAR at N%, corrupted NAR
bytes, wrong/stale narinfo, upstream unreachable. **Ownership
(review gate): all modes are implemented with an in-process bite
test in the test-proxy task; the e2e harness carries the corrupt-NAR
and 404-fidelity scenarios; the hardening block enlarges to the full
fault × chain-depth matrix.** All fault modes are application-level
— no kernel network shaping (netem/NET_ADMIN) in wave 1; rootless
podman cannot provide it and nothing here needs it ("unreachable" =
stop the container).

Narinfo byte-fidelity policy: on the **normal (non-peer) path** the
daemon and its cache treat narinfo as **verbatim bytes** end to end
(`rewrite::apply` is the identity). A property test asserts arbitrary
well-formed narinfos (unknown fields, odd ordering, multiple `Sig:`)
pass through byte-identical, including across a daemon restart.

**Transport-field rewrite (task-49, `rewrite::to_raw`):** on the
**peer-served path** — gated by `RawServeDecision::will_serve_raw`,
i.e. only when the daemon will serve this NarHash's RAW nar itself —
the allowlist is now populated with exactly
`{Compression, URL, FileHash, FileSize}` (the UNSIGNED transport
fields) and nothing else. Those are rewritten to describe the raw nar
(`Compression: none`, `URL -> nar/<NarHash>.nar`, `FileHash = NarHash`,
`FileSize = NarSize`) while every SIGNED field (`StorePath`, `NarHash`,
`NarSize`, `References`, `Deriver`, `CA`, `Sig`) stays **byte-identical**
— the ed25519 fingerprint is untouched, so the client's signature and
NarHash gates both pass. Unit tests pin the allowlist ∩ signed-fields =
∅, the FileHash==NarHash / FileSize==NarSize invariants (the
NarSize-vs-FileSize unit trap), and that the already-`none` form is a
byte-for-byte fixed point. `scripts/check-rewrite-realnix.py` is the
end-to-end oracle: **real nix** accepts the daemon's own rewrite (via
`daemon rewrite-narinfo`) + the raw nar for none/xz/zstd, and **rejects**
a one-char mutation of the signed `NarHash` (the bite proving signed
fields must be preserved). The wave-1 binary wires `NoRawServe` (never
rewrite); task-41 wires the availability-backed decision + a raw NAR
source. **Peer-miss / mid-transfer:** a raw source that fails yields a
fast clean **502**, so nix falls back to the next substituter / upstream
(S2); the daemon never masks a short or corrupt transfer.

## Hardening: fault × depth, header hygiene, fuzz (task-13)

Wave-end hardening against the stabilized wave-1 surfaces.

**Fault × depth matrix** (`e2e_harness.py::scenario_fault_depth_matrix`):
all 7 testproxy fault modes × chain depth 1–3 on one depth-3 pod
(entering at daemon-3/-2/-1), observed at the **client** boundary (raw
HTTP status/bytes) and the testproxy — never daemon self-narration.
Each cell contrasts against a fault-off baseline (so a cell that could
not tell faulted from clean is not a passing cell): mode 1 latency
(sub-timeout) stays 200; mode 2 HTTP-503 forwards verbatim; modes 3/7
(reset, unreachable) become a fast clean **502**; mode 4 truncate yields
a short body (Content-Length full, bytes fewer); mode 5 corrupt yields
same-length different bytes (the daemon does **not** mask corruption —
Nix is the arbiter, proven separately by the real-build
`chain-corrupt-bite`); mode 6 wrong-narinfo forwards mutated metadata.
Mode 8 (throttle) is a crash-window aid, exercised by the crash suite.

**TASK-33 header-timeout ceiling** (`scenario_chain_timeout_boundary`,
task-33 **REOPENED**): the per-hop upstream header timeout is a **fixed
per-hop deadline** that does not compose across a daemon chain — an
upstream of latency `L` is served iff `L + (depth-1)·per_hop_overhead <
header_timeout` at every hop. The timeout is now configurable
(`daemon --header-timeout-ms`, was a hardcoded 1000 ms). What is
**honestly pinned** is the `L`-vs-`T` boundary at **full chain depth**,
shown to **move with the timeout**: at `T=500 ms`, `L=250` (<T) serves
200 and `L=900` (>T) flips to 502; at `T=1200 ms` the same `L=900` serves
200 again (the bite is that *pair*, requiring the flip to depend on `T`).
What is **NOT** claimed: a **depth-pinned** boundary. Per-hop connect/send
overhead is sub-millisecond on pod loopback, so the depth-composition term
is below the noise floor and depths 1–3 flip **together** at `L≈T`
(printed as an observation, never asserted). A clean depth-separated flip
is WAN-scale; validating it, and the budget-aware composing-timeout fix,
is the reopened task-33's remaining work, owned by wave-2 (task-15) and
tied to the real-RTT re-measure (task-35).

**Header hygiene** (`daemon/src/server.rs`, pinned by
`daemon/tests/header_hygiene.rs`): the daemon is a transparent proxy, so
the policy is **strip a fixed hop-by-hop set, forward everything else
verbatim** (the inverse of a curated allowlist — the client-verified
content fields must all survive). STRIP = the RFC 7230 §6.1 hop-by-hop
headers **plus any field named in a `Connection:` header value** (a
keep-alive/desync hazard the long-chain guards against; new in task-13).
FORWARD = `Content-Encoding` (gzip relayed verbatim, no auto-decompress
— pinned by `passthrough.rs`), `Content-Type`, `ETag`, `Cache-Control`,
`Age`, `Last-Modified`, and any `X-*`. `Content-Length` is the one
header the serving layer recomputes, and only for the buffered narinfo
path. **HTTP/2 gap (documented ceiling):** the upstream client speaks
HTTP/1.1 only; cache.nixos.org also serves h1.1 so the daemon reaches
it, but an **h2-only** upstream fails **closed** (a fast 502, never a
hang or mis-decode) — pinned by `h2_only_upstream_fails_closed_not_hang`.
h2/ALPN is bundled with the wave-2 TLS work (task-24).

**Fuzz / fail-closed** (seeded, deterministic — no entropy/Date flake).
Two distinct guarantees, each with its own claim so neither is over-read:
- *Daemon narinfo cache key* (`narinfo_cache.rs`, 20 000 iters): a store
  hash is EXACTLY 32 Nix-base32 characters, so `safe_key` **rejects**
  wrong length, the non-base32 letters `e o u t`, NUL, uppercase and
  non-ASCII — proven explicitly — and every accepted key is a single
  component under root (containment). Non-vacuous: a real key is accepted.
- *testproxy cache path* (`cache.rs`, 20 000 iters): request paths are NOT
  base32 (they carry `.nar[.xz]` etc.), so the claim is **containment
  only** — no path escapes the root — plus a NUL/ASCII-control reject for
  hygiene. Corpus includes `..%2f`, absolute, unicode, control bytes and
  absurd lengths.
A 5 000-iteration narinfo fuzz proves arbitrary well-formed narinfos
(random ordering, unknown fields, multiple `Sig:`, mixed line endings)
survive **`rewrite::apply` (identity) and the disk frame** byte-identical.
This is a **unit-level** narinfo-identity fuzz. What is proven at
**chain** level is **NAR** byte-identity — the e2e `chain-s1-and-counts`
scenario compares the client-side **NarHash** through daemon×3 — **not**
narinfo bytes: there is no chain-level narinfo-byte-identity oracle, and
none is claimed. (The task-8 restart property above covers narinfo
byte-identity across a daemon restart, still unit level.)

**Write-failure fail-closed — the precise two-layer statement** (the two
caches degrade *differently*, both safely): the **daemon narinfo cache**
→ **passthrough** (serves the upstream bytes at 200, writes no entry,
refetches, leaves no `.tmp` residue —
`narinfo_cache_write_failure_degrades_to_passthrough`); the **testproxy
NAR cache** → **fail-closed 5xx** (a cache it cannot open is a hard error,
by design). **Both**: never a partial or poison entry, and both **reap
orphaned `.tmp` partials on startup** (crash-between-write-and-rename
residue). HONEST scope: this exercises the ENOSPC-**at-open**/EACCES
branch (same `install()`/`begin_write` path as a mid-write ENOSPC); a true
byte-N mid-stream ENOSPC needs a size-limited tmpfs not mountable rootless
— the mid-stream no-poison invariant is instead covered by the
`CacheWriter` drop-uncommitted unit test plus the startup reap.

## J2 measurement baseline (task-12)

**Recorded 2026-08-08.** Instrument: `scripts/measure.py` (`just measure
--runs 10`), counting rule `net-upstream-egress-v2`
(`scripts/MEASUREMENT_COUNTING_RULE.md`). Provenance stamp (a number
without this cannot be compared to anything later):

- `workload_version`: **`nix-p2p-fixture-workload-v1`**, tier `full`,
  generation `gen-d2ab43402b88715a`.
- fixture lock public key:
  `nix-p2p-test-1:empdFBu9wVZG12rPKToHMOTsU1qzWzeCcLdq/KQH0JQ=`.
- per-payload wire sizes (`file_size`, the on-wire compressed bytes the
  counting rule reads — **NOT `NarSize`**): `lib` 66 048 (none),
  `app` 260 (xz, `nar_size` 408), `zstd` 524 649 (zstd, `nar_size`
  524 808), `big` 115 343 872 (none). Payload sum = **115 934 829 B**.
- rebuild determinism: `just fixtures-verify-rebuild` PASSED before this
  baseline — 4 payloads rebuilt to identical outputs matching the lock,
  **on this machine only** (cross-host reproducibility is proven by
  nothing here and not implied).

**Run-to-run agreement (AC#1): asserted, not assumed.** The full 10-run
× 3-arm measurement was regenerated TWICE. The egress axis agreed
**byte-for-byte** across both runs (every figure in the table below was
identical run-1 vs run-2, same generation). The latency axis did not and
is reported as unusable (see S4 below). Reports:
`scratchpad/measure-run{1,2}.json`; instrument verdict both runs
`instrument_trustworthy=true` (all four falsifiability bites pass,
arms_usable=true).

### Egress (both arms, N=10 valid/10, stdev = 0 across runs)

| Channel | daemon-on | daemon-off | note |
|---|---|---|---|
| **payload NAR** (the metric) | **115 934 829 B** | **115 934 829 B** | identical → offload **0.0** |
| narinfo (context) | 10 665 B | 10 665 B | held identical across arms by frozen rule |
| cache-info (context) | 0 B | 51 B | daemon serves `nix-cache-info` locally |
| total (context) | 115 945 494 B | 115 945 545 B | differ by 51 B = the cache-info only |

**Offload = 0 BY CONSTRUCTION.** Wave 1 has no p2p, so both arms fetch
identical bytes; this baseline validates the *instrument* and fixes the
pre-p2p reference, it does **not** measure offload (offload > 0 is a
wave-2 measurement by this same instrument). Reading 0 here as failure
would be wrong. The daemon-on arm's total is 51 B *lower* only because it
absorbs `nix-cache-info` metadata — exactly the definitional artifact the
counting rule excludes by measuring offload on **payload** egress, not
total.

Compression caveat: fixture payloads are incompressible seeded bytes, so
the narinfo/nar split and the xz/zstd ratios here are **not
representative** of real nixpkgs closures. The workload is 4 paths
dominated by one 110 MiB uncompressed NAR — it exercises byte *volume*,
not closure breadth or narinfo count; a many-small-paths question is not
answered by this baseline.

### p95 wall-clock — S4 UNUSABLE, do NOT quote a container-tier bound

N=10 valid/10 per arm. Per-run p95 (seconds): daemon-on 0.59 / 0.62,
daemon-off-A1 0.63 / 0.62, daemon-off-A2 0.53 / 0.55 (run-1 / run-2).
The **A/A noise floor** (two daemon-off arms that should agree) was
**0.161 (run 1)** and **0.103 (run 2)** — both **≥ the 10% S4
threshold**, so `s4_usable=false` in both reports. The harness cannot
distinguish a 10% latency effect from its own podman-startup jitter, so
**no container-tier p95 bound (S4) is trustworthy from this baseline** —
stated honestly, not hidden. The VM tier (task-10, `just e2e-vm`) is the
real store-open/service-ordering truth layer; the latency axis needs a
quieter harness (or many more runs) before any S4 number can be quoted.
`instrument_trustworthy` is orthogonal to `s4_usable`: the egress
baseline above is sound even though the latency axis is not.

### narinfo→nar gap histogram (PRD risk 3 empirical input)

Per arm, n=40 gap samples, both runs. **Every sample fell in the
`[0,10)` ms bucket.** Median gap **~0.44–0.57 ms**; p95 **~0.73–0.89
ms**; max **< 2 ms** (1.9 ms worst single sample, run 2). The gap is
**sub-millisecond on this loopback harness with a local mock origin.**

### Informational answers (AC#2) — descoped from GO/NO-GO to read-out

The owner descoped the kill criterion (2026-08-08): the project proceeds
to the p2p wave regardless. These are the honest read of the data, now
informational, feeding the wave-2 re-plan (task-15) rather than gating.

**Is the prefetch window real (measured narinfo→nar gap vs the 1–4 s DHT
lookup p2p must hide)?** On this harness, **no — the window is
structurally near-zero (~0.5 ms median, < 2 ms max).** A DHT resolve of
1–4 s (PRD risk 3) cannot be masked behind a sub-millisecond gap: p2p
resolution would be ~1000–8000× longer than the lead time the daemon
gets here. On these numbers alone the prefetch-masking premise does not
hold and hedge (not prefetch) would carry offload.

**CRITICAL caveat — this is loopback, not a verdict on the real gap.**
The gap was measured over loopback against a local mock origin, which
carries no real RTT. The real client→`cache.nixos.org` narinfo→nar gap
includes upstream RTT, TLS, CDN latency and client think-time between the
narinfo GET and the NAR GET — plausibly opening a materially larger
prefetch window. A sub-millisecond loopback gap says the prefetch-masking
assumption **must be validated against a real upstream in wave-2**, NOT
that prefetch is dead. The instrument's gap-synthesis is only *proven to
bite* for sub-second injected gaps (daemon 1000 ms `header_timeout`
ceiling); multi-second real-gap fidelity is unvalidated here.

**What must p2p beat?** To offload the payload NAR egress fixed above
(~115.9 MB/workload here, dominated by the 110 MiB path), a peer path
must deliver the NAR **before** the daemon would otherwise pull it from
the cache — i.e. DHT-resolve + peer-fetch latency must be hidden inside
the narinfo→nar gap **or** a hedge must win the race without the loser's
bytes crossing the boundary (hedge-loser waste is a *separate* channel,
still unresolved in the counting rule, deferred to the wave-2 freeze).
Against a sub-ms loopback gap, prefetch cannot; against a real-upstream
gap (unmeasured), it might. Wave-2 must re-measure the gap on a real
upstream before committing the hedge/prefetch design.

### Real-upstream gap (task-35)

**Recorded 2026-08-08.** The real-upstream re-measurement the caveat
above demanded. Instrument: `scripts/measure_real_gap.py` against the
**real `cache.nixos.org`** (no mock, no proxy in the measured path).

**Methodology.** The gap is a client-side quantity, so we read `nix`'s
own behaviour. Per closure: `nix copy --from https://cache.nixos.org
--to <fresh temp store>` with a fresh (cold) `XDG_CACHE_HOME` forces a
real cache miss — every narinfo and NAR is fetched over the wire.
`nix copy`'s substitution download path is the same machinery
`nix build` uses to pull a cache-miss closure. We parse nix's `-vvvv`
`starting download of <URL>` lines, timestamping each at read time as a
proxy for request-issue time (the two differ by nix-side buffering and
NAR-phase reader backpressure — a non-constant lag of order tens of ms
that does *not* fully cancel; negligible vs the seconds-scale tail, but a
real fraction of the tens–hundreds-ms head, so **head gaps are
order-of-magnitude, not precise**). Each nar URL is paired to its store
path via the
narinfo's `URL:` field (fetched once out of band — does not perturb
timing), reproducing the loopback testproxy's exact pairing. We keep the
**default** narinfo TTL: setting TTL=0 makes nix redundantly re-fetch
each narinfo immediately before its NAR, collapsing the gap to one RTT
(an artifact). Two anchors reported: `gap_first` (nar-start minus the
**first** narinfo request for that path — the earliest signal, the
best-case prefetch window) and `gap_last` (minus the **last** narinfo
request — the loopback instrument's last-write-wins semantics). Here the
two nearly coincide (each narinfo is fetched ~once per run). Definition
of "gap" per path: request-issue time of the NAR minus request-issue
time of that path's narinfo, at the client boundary — the lead time a
fronting daemon would get. Network context: served from a Nordic Fastly
edge PoP (`x-served-by: cache-bma-*`), steady-state RTT ~50–110 ms — a
**favourable** RTT (client near a PoP); farther clients see larger gaps.

**Numbers (gap_first, ms):**

| Closure | paths / MiB | runs | median | p95 | min | max |
|---|---|---|---|---|---|---|
| `hello` | 5 / 11 | 5 | **298** | 1093 | 41 | 1127 |
| `curl` | 21 / 21 | 1 | **1399** | 2132 | 182 | 3082 |

Loopback baseline for comparison (task-12): median ~0.5 ms, max < 2 ms.

**The gap is 500–5000× the loopback gap — and it is not a fixed number,
it scales with closure NAR-download duration.** Structure is two-phase:
nix fetches the closure's narinfos first (a short burst, ~50 ms RTT
each, concurrent), then downloads the NARs. A path's gap is therefore
`(time its narinfo was seen) → (time its NAR reaches the front of the
download queue)`. Consequences, both empirically visible above:
- **Head of the closure** (first NAR demanded): gap ≈ one narinfo-phase
  ≈ tens–low-hundreds ms (`hello` min 41 ms, `curl` min 182 ms). A
  1–4 s DHT resolve **cannot** be hidden here.
- **Tail of a non-trivial closure**: gap grows with the NAR queue —
  `curl`'s tail already reaches **3.08 s**, inside the 1–4 s DHT window
  (3 of 21 paths in the [2000,5000) ms bucket). A bigger closure (a real
  `nixpkgs` build is hundreds of paths / hundreds of MB) pushes tail
  gaps to many seconds.

**Implication for wave-2 (task-15) prefetch-vs-hedge design.** The
loopback "prefetch is structurally dead" verdict was a **loopback
artifact — do not carry it forward.** But prefetch is *not* uniformly
viable either:
1. **Prefetch is viable for the TAIL of large closures** — the daemon,
   if it begins a DHT resolve on the *narinfo* request (the `gap_first`
   signal, not the NAR request), has 1–3 s+ of lead for tail paths,
   enough to overlap a DHT resolve.
2. **Prefetch cannot cover the HEAD of any closure, nor small closures
   at all** — the first few NARs (and every NAR of a `hello`-sized
   build) are demanded within tens–hundreds of ms of their narinfo,
   below the DHT-resolve floor. These MUST come from upstream or from a
   **hedge** (race peer vs upstream, abort the loser) — prefetch alone
   leaves them uncovered.
3. Therefore **hedge must carry offload; prefetch is an optimisation on
   top** that shrinks the hedge's redundant-fetch waste on the tail of
   large closures. A prefetch-only design would offload ~nothing on
   small/interactive builds and nothing on any closure's head.

**Honest limits.** Point values are noisy across time: a later session
measured `hello` at median ~115 ms (min 23 ms, max 684 ms) vs the ~298 ms
in the table — a ~2.5× swing from RTT / Fastly-shield-warmth drift. Read
the table as **representative order-of-magnitude, not a stable constant**;
the two load-bearing facts survive the noise (real gap is 2–3 orders
above sub-ms loopback; small-closure gaps are sub-second while `curl`'s
tail reaches ~3 s). One machine, one CDN PoP, one moment; favourable
Nordic RTT (~50–110 ms) — a near-lower-bound on the RTT contribution, so
real-world gaps for distant clients are *larger*, not smaller (this
strengthens, not weakens, the tail-prefetch case). Small closures only
(polite to the public cache); the large-closure tail is reasoned +
demonstrated on `curl`, not measured at nixpkgs scale. `gap_first`
assumes the daemon triggers on the narinfo request; a daemon that only
reacts at the NAR request gets `gap_last` ≈ one RTT and prefetch dies —
the trigger point is a wave-2 design decision, not a given.

### Upstream conditions for the speedup arm (task-63)

**Recorded 2026-08-09.** Instrument: `scripts/profile_p2p.py`
(`just profile`), counting rule `net-upstream-egress-v2`. n = 10 valid
runs per arm, 4 arms, workload `lib` + `big` (110 MiB, `Compression:
none`, so wire bytes and NarSize coincide by checked precondition).

**Why two conditions.** Task-42 raced the peer path against the in-pod
testproxy on loopback — ~0 RTT, ~1 GB/s — and the peer path came out
3.5× *slower*. The owner goal names a speedup **over cache.nixos.org**,
and no user owns that upstream. So `just profile` now runs the arm under
two **named** upstream conditions, and no speedup number is emitted
without one (enforced by `speedup_qualifier_violations` over the JSON and
`human_summary_violations` over the printed text).

**Shaping parameters, derived — not invented.** Applied in the testproxy
via its existing fault modes 1 (per-request added latency, all kinds) and
8 (`throttle_nar_bps`); the cap is in **`bytes_compressed_wire` per
second**, the bytes actually on the wire.

| Knob | Value | Derivation |
|---|---|---|
| RTT | **50 ms**/request | bottom of task-35's measured 50–110 ms to the Fastly PoP; this host measures 27–78 ms per TCP round trip (2026-08-09) |
| Bandwidth | **20 MiB/s** wire | this host sustained **21.4 MB/s** on a single-stream 56.6 MB `.nar.zst` GET from cache.nixos.org; task-35's tail gaps imply only 6.8–9.8 MB/s aggregate |

Both knob *values* sit at the **upstream-favourable** end of the measured
evidence. The *model* is not uniformly so, and that has to be said rather
than waved at: the delay is charged **per request**, and a real client on
a reused keep-alive connection does not pay a fresh round trip for each
one — worth ~5 × 50 ms = ~0.25 s of a 5.92 s `peers-off` realise, about
**4%**, in the upstream's disfavour. So this arm is **not** a clean lower
bound on the peer advantage. The bound that *is* clean runs the other way:
the peer side is unshaped loopback, so the peer advantage is an **upper**
bound on the peer side.

**The shaping is ASSERTED, not assumed, in two places.**
`probe_upstream_link` times the proxy **host-side through the published
port — outside the shaper**, unshaped and then shaped over the same
channel, so the channel's own cost cancels out of the latency delta and
the unshaped rate is a negative control. The latency is checked **per
request kind**: the narinfo GET *and* the NAR's time-to-first-byte, because
`latency_nar_ms` applies to the arm's dominant request and a probe that
only timed narinfos never looked at it. Measured this run:

| | unshaped (control) | shaped | injected |
|---|---|---|---|
| narinfo latency (median of 7) | 1.20 ms | 51.47 ms | 50 ms (recovered **50.27 ms**) |
| NAR time-to-first-byte | 1.35 ms | 51.69 ms | 50 ms (recovered **50.34 ms**) |
| NAR rate | 1394.6 MB/s | **20.00 MB/s** | 20.97 MB/s cap (0.954×) |

The unshaped control is **66.5× the cap**, so the measurement channel is
nowhere near the limiter — that anti-vacuity check is asserted, not
assumed, and a probe whose control is not materially faster is a *named*
failure. The margin itself is recorded, so channel drift is visible while
it is still passing.

The probe is a point-in-time claim about the *host*→proxy path, so a
**second** assertion covers the path that was actually measured: the arm's
own link rate at the cache boundary (the testproxy's per-record
`bytes_sent`/`duration_ms`, over the scored runs) must land in the same
band. That closes both the temporal gap and the path gap. It is applied to
the CONTROL too — a control that quietly ran shaped would erase the
contrast this section claims.

**Both bites proven by mutation**, not by reading: stubbing
`fault_params()` to arm nothing gives recovered RTT 0.03 ms and 3055 MB/s
(145× the cap), exit 1 with both violations named; dropping only
`latency_nar_ms` still hits the cap and still recovers the narinfo RTT,
and is caught solely by the NAR-first-byte check (`recovered −0.78 ms`,
exit 1).

**Result — the ranking flips.**

| Upstream condition | peers-off realise | peers-on realise | speedup | upstream link rate | egress offload |
|---|---|---|---|---|---|
| `loopback_control` (~0 RTT, unshaped) | 0.171 s (σ 0.040) | 0.617 s (σ 0.038) | **0.276** (peers 3.6× *slower*) | 1073.3 MB/s | 1.00 |
| `wan_shaped` (50 ms, 20 MiB/s) | 5.919 s (σ 0.047) | 0.638 s (σ 0.086) | **9.27** (peers 9.3× faster) | 19.9 MB/s | 1.00 |

Observed range (min/max of the runs themselves, not a CI): 0.18–0.48 for
`loopback_control`, 7.66–12.67 for `wan_shaped`. The pinned task-42
control (peers-on 0.562 s, peers-off 0.159 s, speedup 0.283) reproduces
within noise, and so does an earlier run of this same arm (0.297 / 9.46).

**Reading.** The task-42 3.5× deficit is a property of the *upstream*,
not of the peer transport. Task-64's per-connection ceiling (187 MB/s for
the product's fetch path, 255 MB/s for iroh-blobs) only binds against an
upstream faster than ~2 Gb/s, which on this testbed means exactly one
machine: the loopback testproxy. Against a 20 MiB/s upstream the peer
path is ~9× the link and the link binds first. Note what the 9.27× *is*,
though: with the peer arm unshaped, it is approximately (peer-path rate ÷
cap), so its **magnitude is linear in a knob** and was sampled at one cap.
The *flip* is robust — it happens anywhere below ~187 MB/s — but the
number is not a property of the system alone. Sweeping the cap is
task-44's crossover curve, and `--wan-bandwidth-mib-s` exists for it.

**Honest limits of the shaping** (`shaping_fidelity` in the report). This
is a **service-latency and egress-rate shaper, not a link emulator**: one
delay per *request* plus body pacing. `shaping_fidelity.bias_directions`
in the report lists both signs and their magnitudes. It does **not** model per-round-trip
RTT inside a transfer, TCP slow start, or the
receive-window-over-RTT ceiling — so the bandwidth-delay product that
binds a real WAN transfer is **absent by construction**, and the WAN arm
still flatters the upstream. No TLS (task-22/24), no loss/jitter, no CDN
behaviour. And **only the upstream is shaped**: the peer transport still
runs over pod loopback at 187–255 MB/s, which no real peer link reaches
(1 GbE is 125 MB/s), so the peer-advantage figure is simultaneously an
upper bound on the peer side — task-70 owns closing that.

## Test layers

1. **Unit** (product crates): trait-level tests of
   `NarinfoSource`/`NarSource` impls against in-process fakes.
   Narinfo parsing is upstream `nix-compat`'s job — we test our use,
   not their parser.
2. **Integration** (in-process): daemon against test proxy + mock
   upstream, no containers; fast loop for fault-mode behavior.
3. **E2E containers**: rootless **podman pods driven by the scenario
   runner** (host-verified: no Docker daemon; podman-compose too
   partial to trust) — client (real `nix`, image built with
   `dockerTools.buildImageWithNixDb`, `sandbox = false` inside the
   container) + daemon + test proxy + mock upstream; controlled
   `nix.conf`: daemon (priority < 40) AND the mock/testproxy as an
   explicit direct fallback substituter — S2 requires a real
   fallback target, and its scenarios assert the fallback actually
   served the bytes (request counts), not merely exit 0.
4. **NixOS VM tests** (`nixos/vm-test.nix`, via the NixOS module
   `nixos/nix-p2p.nix`): real nix-daemon + systemd; the truth layer for
   S2 (store-open behavior, service ordering). Wave-1 scope: S1
   byte-identity through the daemon, S2 fallback with the daemon
   stopped, and the module's daemon-off additive invariant — each with
   an absent-before/present-after substitution (per-node writable store
   images, so the fixture is genuinely absent on the client, not merely
   unregistered). The systemd nix-daemon trusts EXACTLY the test cache
   key with require-sigs on. Deferred to the hardening wave (task-13/14,
   filed): the three tamper narinfos and testproxy fault modes
   re-asserted through the systemd daemon, and VM-level request-count
   oracles.
5. **Long-chain**: client → daemon×N → test proxy → upstream,
   N ≥ 3.

Signing in tests: the mock upstream owns a **test ed25519 keypair**;
fixture narinfos are signed with it; client `nix.conf` trusts only
the test public key. Real-cache runs (manual/optional) use the real
`cache.nixos.org-1` key. The trust chain under test is the real one,
never a `require-sigs = false` shortcut — disabling sig checking in
the harness would un-ground S1 (explicitly forbidden).

## Wave scoping (honesty section)

Grounded in wave 1: S1–S4 as above, all oracles, all fault modes,
long-chain, VM layer, measurement baseline + gap histogram.

Explicitly NOT grounded yet (owned by future waves, named now so
their absence is visible): DHT resolve latency oracles, peer yes/no
probe abuse tests, claim-schema conformance/versioning tests,
announce-on-demand behavior, hedge race + throughput-abort tests,
NarSize-abort (claim-spam DoS) tests, multi-node p2p topologies,
**peer-count scale sweeps** (S5 machinery is wave-1; pointing it at
1..30 real peers and extrapolating to 100s/1000s is p2p-wave work),
**real-world NAT traversal** (PRD "what bad looks like" names it;
the container harness cannot prove it). PRD wave-0 reconciliation:
its "multi-node topologies" is satisfied in wave 1 by the long-chain
(multi-daemon) test; multi-node *p2p* topologies necessarily wait
for p2p. Its "claims disk cache" is narinfo-only in wave 1; a claims
cache without claims would be fiction.
The wave-1 re-plan task must pull these from this list into
grounding as the p2p wave gets planned — this list is the checklist
it starts from.

Irreversibility note (revised at the review gate): wave 1 carries
**two** `irreversible`-labeled tasks, not zero as first claimed. The
review found that (a) the **measurement counting rule** and (b) the
**pinned fixture workload** freeze the moment the J2 baseline is
written into this file — redefining either afterwards invalidates
every cross-wave comparison the kill criterion depends on. Those two
tasks get phase 3's deep-review gate. Everything else in wave 1
(crate layout, cache formats, harness internals) remains local and
replaceable. The next freeze events (claim schema, addressed-unit
encoding, DHT key derivation) belong to the p2p wave and MUST carry
the label there.

Go/no-go: an explicit owner-facing checkpoint task sits between the
J2 baseline and the hardening block — hardening a product whose
prefetch-window premise just died would be planned waste.

## Fixture workload (pinned; task-3)

Version: **`nix-p2p-fixture-workload-v1`**. Every measurement number in
this document is only comparable to another number taken against the
same string — changing the payload set changes the egress baseline,
which is why task-3 carries the `irreversible` label.

Four locally-built paths, served as an ordinary static binary cache
(`nix-cache-info` + narinfos + `nar/`), signed only by the test key
`nix-p2p-test-1`:

| Payload | Compression | Size | Why it is in the set |
|---|---|---|---|
| `fixture-lib` | none | 64 KiB | Raw-NAR case; referent of the closure below |
| `fixture-app` | xz | tiny | Non-empty `References` — the reference list is part of the signed fingerprint |
| `fixture-zstd` | zstd | 512 KiB | Third compression Nix may advertise |
| `fixture-big` | none | 110 MiB | Byte-volume for kill-at-50%-bytes and the egress oracle; uncompressed so wire bytes equal disk bytes |

This table is descriptive. The **authoritative** lock is the one **inside
each generation** (`gen-<sha>/lock.json`), resolved at runtime via
`current -> gen-<sha>/lock.json`; the gate holds the served tree to it.
`fixtures/workload.lock.json` is a **demoted, git-tracked baseline** —
byte-identical content, but a review artifact only: it is read solely by
the generator's freeze/`--write-lock` path (which is what notices a
`flake.lock` bump at build time and keeps the frozen baseline in `git
diff`), never by runtime or gate code. Its schema is closed: an
unrecognised field is a hard error, because an ignored field looks like a
pin and is erased by the next rewrite. `fixtures/README.md` holds the
design rationale; regeneration and the change procedure live there.

The fixture is **published with one atomic symlink flip, and one only**:
`fixtures/out/generations/gen-<sha>/` is built and validated — *including
its own `lock.json`* — then `fixtures/out/current` is `os.replace`d to
point at it, committing the tree and its authoritative lock in the same
syscall. `publish()` has **no rollback and no read-back** (the machinery
that failed rounds 2–7); crash consistency is not "windowless" but
*split-free* — killed before the flip leaves the old generation complete,
killed after leaves the new one complete, with nothing in between.
Everything that consumes the fixture — the gate, `just fixtures-serve`,
task-5's containers — resolves through `current`, and must keep doing so
rather than naming a generation directly.

`nix-cache-info` advertises **`Priority: 40`** and
**`WantMassQuery: 1`** explicitly (a `file://` store writes `StoreDir`
alone, and the omitted fields would silently become client defaults).

The limits on what the fixture gate proves, stated so a green line is
not over-read:

- **The reproducibility contract covers bytes *and* file metadata.**
  Modes and mtimes are normalised at generation (0644/0755, mtime 1,
  the signing key 0600), so the tree is umask-independent and a
  consumer that copies it with rsync/tar sees what an HTTP client
  sees. The determinism check compares metadata too.
- **A reader that already resolved `current` is never torn.** It goes on
  reading a complete, immutable generation across a republication, and
  that generation survives one further publication before it becomes
  collectable — retention is implemented by the `previous` symlink and
  applies on the warm-reuse path too, so a reader that resolved a *path*
  (holding no descriptor) is protected, not only one holding an open
  directory. (The previous publish-by-rename design gave such a reader an
  `ENOENT` window instead; that window is gone.) What is *not* provided
  is a lease: a reader idle across **two** publications can still have
  its generation collected, so long-lived consumers should re-resolve
  `current` on ENOENT.
- **`just test` proves EXPORT repeatability, not build determinism.**
  Regeneration finds the payloads already realised in the store, so it
  re-serialises, recompresses and re-signs them — it never rebuilds.
  A payload that built nondeterministically would be realised once and
  pass forever. **`just fixtures-verify-rebuild`** (`nix build
  --rebuild`) is what covers that, and it is a **required step before
  the J2 baseline is recorded**. Neither proves byte-stability across
  machines or nixpkgs revisions; the lock file is the instrument for
  that case. `just test` also verifies whichever tier is *published*,
  and a full tier satisfies a fast request — so on a warm machine it
  may verify four payloads while a cold CI run verifies three. The
  fast tier is the coverage that can be relied on; `just
  fixtures-large` is what guarantees the 110 MiB payload was touched.
- **Enforcement is proven in Nix's direct store mode only.** The gate
  drives the `nix` CLI, where `trusted-public-keys` is client-side.
  A real `nix-daemon` ignores that setting for a non-trusted user and
  enforces `require-sigs` daemon-side, so task-5 (containers) re-asserts
  the same three tampered inputs through the **daemon** enforcement
  path. That is a different proof, not a repeat. task-10's VM layer
  proves the daemon-side POSITIVE path (S1 accepted on exactly the test
  key, require-sigs on) through the real systemd nix-daemon; re-asserting
  the three tamper NEGATIVES there is deferred to the hardening wave
  (task-13/14, filed).

The fixture gate deliberately does **not** run inside `nix flake
check`: the tree is generated and gitignored, so a sandboxed run would
find no fixture and go vacuously green. It runs under `just test`
(fast tier) and `just fixtures-large` (full tier, gates the 110 MiB
payload). Any CI must invoke those inside `nix develop`, not rely on
`nix flake check` alone.

# WAVE 2 grounding — real p2p, modeling & profiling (design-for-test)

Companion to PRD "Wave 2 scope". Wave-1 signals S1–S5 still hold; these
add the p2p and profiling grounding. The trust invariant is UNCHANGED:
Nix re-verifies sig+NarHash, so the daemon+peers stay outside the TCB;
a peer can only ever cost a failed-build-and-retry, never a poisoned
store path. Every p2p acquisition still ends at the `sha256(nar)==NarHash`
gate (wave-1 S1).

## Acceptance signals

S6. **Peer-served NAR (the core p2p acceptance signal).** In a >=2-node
testbed, node A resolves a path's NarHash (via the discovery layer),
fetches the NAR from node B over iroh (whole-blob), and it passes the
NarHash gate — byte-identical to what cache.nixos.org would serve. The
measurement (net-upstream-egress-v2) counts this as a VALID 0-egress
crossing (a real offload). If S6 can pass while bytes crossed the cache
boundary, or fail while a peer genuinely served it, the instrument is
lying (wave-1 already grounded that distinction).

S7. **Speedup / offload, measured not asserted.** On the p2p testbed,
net cache egress with peers vs without is reported per the frozen
counting rule; a peer HIT shows as 0 payload egress. "Speedup over
cache.nixos.org" = wall-clock and egress delta, with the honest caveat
that a container/loopback testbed is not residential-uplink reality.

S8. **Pathological scenarios degrade gracefully (policy-observable).**
Each pathological case has a DEFINED good behavior; the system never
serves wrong bytes and never hangs unbounded. The cases + their
observable good/bad:

| Scenario | Good (observable) | Bad |
|---|---|---|
| Slow/throttled peer on a HIT | policy fires (abort->cache, or hedge wins) within a bounded time; build succeeds | build stalls on the slow peer for minutes |
| Dead/unreachable holder after a positive claim | fast failover to next holder or cache; claim marked stale | hang waiting on a dead NodeId |
| DHT resolve timeout / cold-start empty index | bounded resolve wait, then cache fallback; never blocks the build path unboundedly | 1-4s DHT latency leaks into every build |
| NAT-blocked peer | relay path used, or peer skipped fast | undialable peer stalls the fetch |
| Thundering herd on a popular path | bounded fan-out; no self-DoS; single-flight per path | N concurrent identical fetches |
| Lying / spam claim | NarHash gate rejects; wasted-dial bounded; peer scored down | attacker-chosen huge blob downloaded in full before the gate |
| Seeder churn | resolution tolerates holders joining/leaving; no wrong bytes | churn causes a wrong-bytes serve or a crash |

S10. **A real swarm, cold then warm (owner requirement, 2026-08-10).**
Everything up to S9 measures either two nodes or a swarm of daemon
*processes* fed synthetic payloads with a host-side HTTP reader standing
in for nix. S10 is the deployment-shaped case: **≥10 containers, each a
real nix client plus a daemon, substituting a real closure, with NAR
bytes actually crossing iroh.**

The load-bearing distinction is **cold-start vs steady state**, and it
invalidates a naive reading of every offload number published so far. At
t=0 no peer holds anything, so every path comes from upstream and offload
is **~0** — a cold swarm *cannot* offload. Offload rises only as peers
fetch and announce. Therefore:

- The result is a **curve** (offload vs how much the swarm has already
  seen) plus a time/volume to plateau — never a single figure.
- Every offload number measured with a **pre-seeded holder** — which is
  all of them, including the 1.00 in S3/S7 arms and in `README.md` — is
  **steady-state by construction** and must be labelled so. It answers
  "can a peer that has it serve it", not "does a swarm offload".
- Good: the plateau is materially above 0 and the swarm's total upstream
  egress is materially below N independent nodes', in uncompressed-NAR
  units under the frozen counting rule. Bad: a single offload figure
  quoted without its position on the curve.

BITE: the cold arm must actually be cold — assert the swarm holds nothing
at t=0 and that offload measured there is ~0. A "cold" arm that starts
warm passes trivially and proves nothing, which is the vacuous-oracle
shape this document exists to prevent. Thundering-herd cost (N peers
wanting one path at once) is counted, not assumed to be 1.

Honest limits that travel with any S10 result: one host, loopback peer
links (so peer throughput is an **upper** bound), no NAT or relay, and a
residential uplink would plausibly invert the latency finding. Claims
about 100s/1000s of peers remain model output per S5.

S9. **Profiling models bite (resource/perf estimation).** The scenario
models estimate RAM, disk, latency, throughput, speedup and extrapolate
to 10s/100s/1000s of peers (S5 machinery: measure 1..30, regression-fit,
resource-laws-only caveat, extrapolations labeled model-output). BITE:
a synthetic workload with known O(n) RAM growth recovers a linear fit;
a superlinear RAM/latency fit is surfaced as a red flag, not buried. A
model that reports plausible-but-unfalsifiable numbers is the worst
outcome (wave-1 oracle-bite lesson applies).

**S9 as built (task-42, `scripts/profile_p2p.py`, `just profile`).** The
instrument sweeps a REAL swarm — n holder peers plus a fetching node,
n+1 daemon *processes* in one pod, over n ∈ {1,2,4,8,16} — and runs a
peers-ON vs peers-OFF speedup arm scored by the frozen
`net-upstream-egress-v2` rule (`measure.classify_run`, not a second
definition). Three rules are mechanical, not editorial:

- **Units.** Every `*_bytes` key must end in `_ram`, `_ondisk`,
  `_uncompressed_nar` or `_bytes_compressed_wire`; `unit_violations()`
  fails the run otherwise. NarSize (uncompressed, signed) and FileSize
  (compressed, on-wire) are different units and this project has
  confused them three times — a reader cannot mix what the schema will
  not let the writer spell. The speedup arm additionally ASSERTS
  `file_size == nar_size` from the manifest for its payloads, so the two
  coincide by *checked precondition*; a fixture regenerated to xz makes
  the arm refuse to run rather than emit a cross-unit ratio.
- **The bite is MEASURED, not asserted.** `class_recovery_study()` runs
  a Monte-Carlo over known-class generators *on the swept grid*, under
  multiplicative noise, and the self-test gates on RATES — one lucky
  seed is a coin flip, not an oracle. The seeds are `crc32`-derived, not
  `hash()`: Python randomizes `str.__hash__` per process, so the earlier
  version's rates were reproducible only because nixpkgs happens to set
  `PYTHONHASHSEED` — a FAST-tier gate one environment change from being
  a lottery. Measured at 2% noise on {1,2,4,8,16}, 120 replicates:
  O(n²) is fitted linear **0.000** of the time (the bite), O(n log n)
  likewise 0.000, O(n) recovers linear 0.933, O(1) recovers constant
  0.900. The instrument's own error rates are now GATED, not merely
  printed — they are exactly what the superlinear-rule change moves: a
  genuinely linear law is falsely flagged superlinear 6.7% of the time
  at 2% noise (ceiling 12%), and O(n log n) is mistaken for linear 12.5%
  of the time at 5% noise (ceiling 20%). The report puts the sweep's
  OBSERVED replicate spread beside those numbers via
  `verdict.bite_applicability`, so a reader can see whether the real
  data sits inside the regime where the bite holds — on this grid that
  regime reaches only ~1% relative noise, and the measured RSS spread
  (2–4%) and latency spread (8–20%) are both OUTSIDE it. A grid too
  short to demonstrate the bite sets `s9_bite_demonstrated=false` and
  makes the report UNUSABLE.
- **A red flag means superlinear GROWTH.** The first real run fitted the
  peer fd series (11,11,…,10,10,10) as quadratic with a *negative* slope
  and flagged it, extrapolating to −4015 descriptors. `scalefit` now
  requires `slope > 0` for the superlinear flag; a false flag on a
  metric that went DOWN is what teaches a reader to skip the section.

Honest scope of this instrument: it characterizes RESOURCE LAWS and
does not pre-hardcode any policy (see "Policy derivation" below); its
"upstream" is a loopback testproxy, so the latency speedup it reports is
a lower bound and the egress offload is the transferable number; and
node A's claims all name one holder (`InMemoryDiscovery::announce`
replaces on key), so the swarm axis measures the cost of n peer
processes plus an n-entry address book, not holder selection or dial
fan-out.

## Policy derivation (findings -> tasks, do NOT pre-hardcode)

The models EXPOSE the policy decisions; wave-2 does not bake a policy
the data hasn't justified. The archetype (owner-named): on a HIT whose
transfer is extremely slow, the choices are (a) abort and fall back to
cache.nixos.org, (b) delayed-race / hedge (start the cache fetch, first
past the NarHash gate wins, cancel the loser), (c) adaptive by observed
throughput (abort only if throughput < X for T seconds). The wave-2
plan includes a MODELING task that characterizes each under the slow-peer
scenario; the chosen policy is filed as its own task grounded in that
data, with the loser-bytes cost counted in the hedge_waste channel the
counting rule reserves.

## Wave-2 frozen surfaces (irreversible — deep-gated in phase 3)

- **Claim wire schema** (version field, payload enum WholeNar{blake3} /
  future CastoreRoot, reserved fields for signed-narinfo-relay + claim
  signatures, and a TRANSPORT tag so BitTorrent is not a network fork).
- **DHT key derivation** (NarHash -> DHT key mapping; which DHT).
- **Addressed-unit encoding** (raw-NAR BLAKE3 per PRD; the byte a peer
  is asked for).
These freeze the moment two independent daemons interoperate; changing
them splits the network. Everything else (transport internals, the
profiler, policy thresholds, gossip) is a velocity surface.
