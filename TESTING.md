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

S4. **Historical Wave-1 latency bound.** p95 wall-clock of the scripted build with the
daemon enabled ≤ 110% of daemon-off, in the harness. (PRD kill
criterion: this bound plus, in later waves, ≥20% net egress cut on
the favorable testbed — else the p2p thesis dies.) TASK-114 supersedes that
project-wide reading with per-profile rules while preserving this 10% value as
a hard normal-latency ceiling.

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
3. `just test` — unit + integration (in-process, mock upstream). Also
   runs the PROPERTY tests (proptest for Rust, hypothesis for Python:
   claim-wire round-trip / fail-closed / offer caps, safe_key
   containment, flake_rate.classify fail-closed, narinfo parse
   round-trip/fail-closed) at a FIXED seed + bounded case count, so a
   randomized test lives in the flake-gated fast suite without
   reintroducing the task-109 non-determinism.
   `just prop` — the SAME properties at a FREE seed + many cases
   (`PROPTEST_FREE_SEED`, hypothesis `explore` profile). Exploration
   mode, run deliberately, NOT on every cycle. A failure in either mode
   persists a replayable reproducer (proptest `.proptest-regressions` /
   hypothesis "Falsifying example").
   The frozen ProviderRecord wire has two independent anchors in this tier:
   `provider_record_v1.json` remains the immutable TASK-126 tag-0/tag-1 fixture,
   while `provider_record_libp2p_tag2.json` separately pins TASK-156's additive
   schema-v1 tag 2. Rust checks exact emitted/accepted bytes and typed reject
   payloads; `scripts/check-provider-record-libp2p-tag2.py` independently parses
   the layout, validates strict bounded relay identities, verifies signatures with
   a pure-Python RFC 8032 implementation, and proves a historical v1 reader returns
   `UnknownOffer` rather than silently dropping tag 2.
   TASK-219's runtime proof is
   `cargo test --locked -p daemon-libp2p --test multi_relay_hints -- --nocapture`:
   C bootstraps only through R1, P has only a live reservation on R2, and the shipped
   writer/reader fetches the exact NAR after resolving the signed R2 identity through
   raw kad with no provider/relay address injection. The same test bites empty and
   wrong hints while proving ambient R2 remains live but unusable, R2 loss after a warm
   fetch without fallback to live R1, two hints with one dead, the at-most-two lookup
   bound, two overlapping streams through the same authorized R2 connection, and
   simultaneous R2-only/R1-only streams whose outcomes follow their exact connection
   when R2 is severed. `direct_listener_readiness_wait_is_bounded` separately proves
   successful direct-listener readiness is event-correlated and externally bounded;
   `provider_startup_refuses_a_requested_but_unaccepted_reservation` proves the shared
   construction used by both binaries fails closed, by correlated terminal close or bounded
   timeout, when a requested relay reservation is not accepted. The production multi-relay
   path crosses the provider builder's private readiness token before its initial signed batch.
   `scripts/check-discovery-no-shortcut.py --self-test` permits only the exact bounded
   signed `RelayHints` association and mutation-proves that auxiliary provider-keyed
   relay maps/caches still fail the structural guard.
4. `just e2e` — container harness, FAST subset: five scenarios, one
   per distinct path (S1 byte/counts, S2 fallback, the tamper-narhash
   safety bite, depth-3 chain composition, S6 p2p). Sized for the
   common pre-commit loop.
   `just e2e-full` — every scenario, including the crash suite, the
   fault × depth matrix and the timeout boundary. Those are where
   regressions hide, so **`e2e-full` is the gate that must be green
   before shipping a serving-path change**; a green `just e2e` is a
   smoke signal, not that gate. E2E failures BLOCK commits (repo
   policy). Both print per-scenario seconds, so the split stays
   defensible from timings rather than from an impression of which
   scenario feels slow.
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

**Structured wire/parse fuzzing — BROAD tier, `just fuzz-smoke`** (TASK-282
AC#4; folds TASK-113). The seeded loops above run in the FAST `just test`
loop and stay there. SEPARATELY, `just fuzz-smoke` is a **SLOW/BROAD**
recipe — **never** a `just test`/`just lint` dependency — that runs
`proptest`-driven fuzz targets over the untrusted decoders: the **multiaddr
LAN-provenance classifier**, the **`/nar/4` bao leaf+proof decoder**, the
**signed provider-record decode+verify**, and the **narinfo parser**. The
targets are `#[ignore]`d `#[test]`s (so `cargo test` skips them) in each
crate's `src/fuzz.rs`; the corpora and the crash-triage runbook live in
`fuzz/`. Each asserts a real invariant, not just no-panic — e.g. an
**ACCEPTED** multiaddr can carry no routable IP / DNS / relay hop
(independent oracle → the compound-address bypass bites), and a decoder
**never** returns `Ok` on bytes that fail signature/bao integrity.
**Engine honesty:** this is bounded random structured fuzzing on the pinned
**stable** toolchain, **not** coverage-guided — `cargo-fuzz`/libFuzzer needs
nightly + `-Zsanitizer`, which the reproducibility pin forbids
(rust-toolchain.toml); a nightly `cargo-fuzz` tier is a deferred follow-up.
On a crash: proptest shrinks + persists the minimal repro, which is committed
to the corpus and pinned as a **non-ignored** regression replayed by
`just test` (that path is what closes the loop from fuzz find → fast-loop
guard).

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

### Value thesis — peer vs CDN, real network (task-282 AC#3)

**Recorded 2026-08-21.** The BROAD `value-thesis-*` tier addresses "do peers beat
or supplement a CDN?" — and its honest answer is **UNPROVEN**. The full note is
`docs/task-282-value-thesis.md`; the re-derived numbers are
`evidence/task-282/verdict.json` (regenerate with `just value-thesis`). Two
deliberately-separate arms — a **REAL** `cache.nixos.org` fetch over verified TLS
(the CDN arm) and a **hermetic** three-node LAN KVM VM peer fetch of a synthetic
payload (`nixos/value-thesis-vm-test.nix`) — different environments AND different
content, so the harness reports each wall clock as its own magnitude and **never**
a peer-vs-CDN sign/delta (the TASK-203 trap). What is MEASURED is the CDN's
**compression** ratio: over 15 size-stratified real paths, uncompressed:compressed
ran **~1.2× → ~5.6×** (most ~2.0×–2.5×) — a compression finding, **not** a
peer-vs-CDN transport gap. It is NOT a peer-vs-CDN verdict because the shipped
`/nar/4` peer transport is itself zstd-**compressed** and this slice did not
measure the peer's wire bytes. The peer arm is an **existence proof** only
(NarHash-verified byte-identity; kad discovery ~2 ms, warm transfer ~365 ms). The
finalizer is float-free and **fail-closed**: a MANIFEST pins the exact cohort +
run count, malformed captures RAISE (no silent skip), provenance is derived from
the endpoint and cross-checked, a present-but-invalid peer capture fails, and the
aggregate must lie within the per-path [min,max]; `just value-thesis-self-test`
mutation-proves each guard bites.

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

## Gate honesty — "tests: 0 failures" is a claim about a DISTRIBUTION (task-109)

The verification gate is not a truth oracle. It is a sampler, and until
task-109 nobody knew its variance. Measured on 2026-08-10, at the commit
that opened that task: `cargo test --locked --workspace`, N=20 runs of
**identical binaries** under a stated load (14 CPU burners on a 14-core
host), failed **9 times — a 45% failure rate**. Not one of those failures
was a product defect. Every one was a test making a load-sensitive
assumption: reading a counter the server had not yet written, asserting a
wall-clock upper bound, or measuring whole-process RSS while a sibling
test allocated 32 MiB in the same process.

The consequence is uncomfortable and must not be softened: **every "tests:
0 failures" this project certified before that date was a single sample
from a distribution that produced a green ~55% of the time.** The code was
very likely fine. The *evidence* was worth about half of what it was
quoted as being.

THE RULE, binding on every cycle, Final Summary, git note and task closure:

1. A cycle MUST NOT certify "test 0" from one green run while a known
   flake rate is outstanding. Quote the rate, or state plainly that it is
   unmeasured. "Unmeasured" is an acceptable, honest answer; silence is
   not.
2. A flake rate quoted WITHOUT its N and its load definition is
   meaningless and MUST be rejected in review. The load is part of the
   measurement, not context for it.
3. Re-measure with `scripts/flake_rate.py` after any change to test
   harness synchronisation, process/thread layout, or timeouts. It sorts
   every run into PASS / TEST_FAILED / BUILD_FAILED / HARNESS and ABORTS
   on the last two, because cargo returns exit 101 both for a failed test
   and for a crate that did not compile — a harness here once read exit
   127 as green, and another counted compile failures as mutation kills.
4. Fix a flake at its MECHANISM. `--test-threads=1` and retry-until-green
   are rejected: the first buys determinism by deleting the parallel
   coverage that catches concurrency defects, and the second re-rolls the
   dice until the answer is convenient.
5. A single green run is NOT evidence that a flake is fixed. That
   assumption is precisely what let a 45% failure rate go unnoticed.
   Demonstrate the fix at the same N and load that demonstrated the
   defect.

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

### Independent `wide_closure` fixture (task-57)

The `wide_closure` class is a separate frozen fixture family; it does not
extend or replace the canonical four-path workload above, and ordinary e2e
continues to use `fixtures/out`. Its identity comes from the independent
one-line `fixtures/WIDE_WORKLOAD_VERSION`, currently
`nix-p2p-fixture-workload-v1-wide-closure-v1`. That same value seeds
the wide Nix derivations and is recorded in their manifest and lock, so a
canonical `WORKLOAD_VERSION` bump cannot rekey this family. It
publishes under `fixtures/out-wide`, with its independent, git-tracked review
baseline at `fixtures/wide_closure.lock.json`; generated wide cache and
generation artifacts remain gitignored.

The class budget permits 128--512 independently substitutable members plus one
root, hence 129--513 closure paths. The frozen v1 fixture is exactly 128
distinct, locally built 2 MiB members plus one root, 129 store paths total.
Every member is reference-free; the root's direct `References` set is exactly
all 128 current members.
The sum of the closure's signed, uncompressed `NarSize` values must stay in the
inclusive integer range 268435456--2147483648 bytes. `FileSize` and either disk
measure are not substitutes for that NarSize oracle.

The disk budget covers regular files in the served `cache/` only. Each object's
apparent/allocated contribution is its NAR blob plus its narinfo; the totals add
`nix-cache-info` exactly once. Apparent bytes are `st_size`, allocated bytes are
`st_blocks * 512`, and both totals must be at most 536870912 bytes. Allocated
bytes are filesystem-specific evidence, not workload identity or a cross-host
reproducibility claim. Each generation lock pins its locally observed
`st_blocks`, and the checker verifies that observation against the same
generation. The git baseline retains one reviewed observation; portable
baseline/regeneration equality excludes only allocated-byte fields and
independently enforces the integer budget on both generated trees while keeping
every portable field exact. Actual peak headroom is higher because generation and
verification can coexist with source, destination, determinism, retained
generation, and Nix-store copies.

`just fixtures-wide` generates and gates this family. Its positive control asks
real Nix to substitute the root only into a fresh store and cache, then requires
all 129 NARs, the exact direct fan-out, and the exact recursive closure. A
re-signed root with one reference removed and a trial with one member
pre-realised must each make that cold-closure oracle fail. The existing
signature, content-hash, and export-repeatability bites still apply;
`just fixtures-wide-verify-rebuild` separately proves build repeatability on
this host. This fixture establishes workload shape and integrity only: it makes
no concurrency, performance, knob-effect, or scale-sweep claim.

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

**How the claim-wire freeze is ENFORCED (task-91).** It used to be
enforced by round-trip tests, which are blind to exactly the change that
splits a network: rename a field or retag a variant and encode+decode
still agree with each other, just not with the other node. The bytes are
now pinned in `daemon/tests/golden/claim_wire_v1.json` and checked in
both directions — what we emit and what we accept — by
`daemon/tests/claim_wire_golden.rs`. Proven to bite: renaming
`HoldAnswer::Absent`'s tag and renaming `Claim::holders` on the wire each
turn a named vector red. Changing a vector is a RE-FREEZE; the correct
response to a failure is a `schema_version` bump or a revert, never an
updated vector. The one legitimate re-pin is the planned move off the
JSON draft codec.

That first version had a HOLE, found by a cross-model review and fixed in
the same task: every vector populated its optional fields, so a mutation
that only changes the DEFAULTED encoding survived it. Adding
`skip_serializing_if = "Vec::is_empty"` to `HoldAnswer::Have::offers`
(which rewrites the legal bytes of an empty-offers Have) and removing
`serde(default)` (which changes what we still accept) both left all seven
tests green. The file now also carries an EMPTY-value encoding vector
wherever an optional field exists, `decode-only` vectors for legal inputs
we accept but never emit, and the RESERVED v2 fields POPULATED — those
exist so v2 needs no wire break, so `relay.blob`, `signatures[].key_id`
and `signatures[].sig` are part of the freeze and were previously
renameable with the whole suite green. `every_golden_vector_is_exercised`
stops the data file and the assertions from drifting apart.

**Batched hold-query (task-91), added ALONGSIDE the frozen types.**
`BatchHoldQuery`/`BatchHoldAnswer`/`BatchHoldResponse` ask about a whole
closure in one round trip. Two properties are gated rather than
described:

- **No enumeration**, which matters more here than anywhere because a
  batch answer is the first message whose SHAPE resembles a listing. The
  answer is positional over keys the asker named and carries no keys of
  its own — the golden bytes contain no `sha256:` string at all — and
  `daemon/tests/no_enumeration.rs` makes it structural: across
  `claim`/`availability`/`discovery` — three modules, and NO others — a
  plural holdings return requires named keys in its parameters. That
  guard proves it bites against a synthetic
  `all_holdings() -> Vec<NarHashKey>` AND against the bypass a
  cross-model review actually built: a no-argument method returning the
  WRAPPER type `BatchHoldResponse`, which carries a whole vector of
  holdings without a container in its return type. Exemptions are scoped
  `(file, name)`, so an argument written for `availability.rs::load`
  cannot be inherited by a `load` added to `discovery.rs`.
- **Locators bind to their key.** A transport offer is not always
  peer-scoped: iroh's is a `NodeId` (per PEER), BitTorrent's is an
  infohash (per CONTENT). The response therefore carries an offer
  DICTIONARY and each `Have` names its own entries BY INDEX. Enforced at
  both boundaries: every index in range, no index repeated inside one
  answer, every dictionary entry referenced by at least one `Have`, at
  most `MAX_OFFERS_PER_ANSWER` (4) entries per answer, and at most one
  per transport KIND — because the content behind a key has one identity
  per transport, so a second `bittorrent` offer on the same answer names
  a second blob. The last two rules are what bound the dictionary against
  what was ANSWERED. Referencing alone bounds it against the mere
  EXISTENCE of a `Have`: one `Have` could name all 512 entries, so a 91 B
  one-key query could be answered with 512 infohashes — 511 content
  identities the asker never named, at ~600x wire amplification. Three
  independent reviews measured that hole (578x, 613.8x, 557.6x) before it
  was closed; `a_single_have_cannot_legitimise_a_pile_of_content_locators`
  is the bite. Dropping an unknown transport kind compacts and RE-INDEXES
  together, which is why `BatchHoldResponse` has no derived `Deserialize`:
  `decode_batch_hold_response` is the only way to build one from bytes,
  and `claim.rs`'s `not_deserialize` coherence proof makes re-adding the
  derive an E0119 BUILD error rather than a silently green suite.
- **Bounded**: `MAX_BATCH_HOLD_KEYS = 256`, chosen against the 64 KiB
  wire gate rather than beside it — measured, not estimated: a full query
  is 15 901 B, a full all-`Have` response sharing one iroh locator is
  31 114 B, and the same response with a distinct per-content locator for
  every key is 58 910 B (~10% spare, the honest limit). Raising the cap
  to 1024 fails the TEST `a_full_batch_fits_the_wire_cap_with_headroom`
  — `cargo build` still exits 0, so this is caught by `just test`, not
  by `just build`. (It was documented as "fails the build", which sends
  a reader to the wrong gate.) Over-cap is rejected, never truncated — on
  encode, on decode, in the responder, and in the compatibility shim.
  The cap is applied to `keys_asked` itself, so it is a property of the
  decoder rather than a caller precondition, and every encoder gates its
  OUTPUT size so this node cannot emit a message it would itself refuse.

The measured win lives in `just discovery` (or `profile_p2p.py
--discovery-only`), whose honesty rules — both arms must ask about the
same number of keys; the injected RTT must be recovered from the
measurement, not trusted from the knob — are proven by mutation in
`discoveryaxis --self-test`, which `just test` runs every cycle.

## Wave-2c experiment contract: two stages, training, then sealed holdout

This section supersedes earlier Wave-2 policy-grounding prose where it
conflicts, while preserving the measurements and provenance above. Its contract
version is **`nix-p2p-tournament-v1`** and its scenario generator version is
**`nix-p2p-scenarios-v1`**. The profile objectives, margins, inherited hard
bounds and prerequisite budget ownership are defined exactly once in PRD.md,
“Wave 2c reconciliation and tournament decision contract”; every artifact
records that section's content hash and the two version strings. A backend,
codec or public-discovery no-go is evidence, not a missing row.

Before Stage-B manifest generation, the reader validates the inherited numeric
safety caps named in PRD.md and requires the complete, owner-reviewed TASK-120
artifact with numeric upload/RAM/disk/fd/discovery/announcement budgets for
every profile. Missing content, owner review, a profile entry, a number or its
hash fails before execution with `PROFILE_BUDGET_ARTIFACT_MISSING`; no field is
filled with a calibration observation or “unbounded.” Frozen caps are checked
in every opportunity and qualification observation. This preflight is distinct
from the generator's technical matrix/compute ceilings below.

### Four strongest Wave-2c signals

All four signals require fresh requester store, Nix narinfo cache, daemon cache,
daemon identity/discovery state as declared by the scenario; provider state is
created only by the declared store-placement rule. Every peer success requires
provider-side socket bytes, requester source attribution, upstream-byte
contrast, S1, and the bounded S2 fault row. An exit-zero build by itself is
never peer evidence.

1. **Zero-injection Iroh build.** A fresh real Nix requester begins with only an
   operator participation profile and mechanism-level bootstrap configuration.
   It receives no `--iroh-peer`, peer address, `--p2p-claim`, claim record or
   per-content locator. Operational node/address discovery and content
   discovery find a store-backed provider; provider bytes are nonzero and the
   upstream payload crossing is absent or reduced as declared. Tracker,
   named-candidate direct query and supported global DHT results remain
   separately attributed; an unsupported global DHT remains visible.
2. **Zero-injection BitTorrent build.** A fresh requester begins with NarHash /
   StorePath plus operator-level tracker/Mainline bootstrap only. No peer
   address, magnet, infohash, torrent file, claim, or Iroh discovery result is
   injected. A standard/evidenced-extension BitTorrent path supplies a real Nix
   build and records provider bytes, or the exact TASK-117 unsupported branch is
   emitted. Disabling BitTorrent discovery must restore upstream behavior.
3. **Stage A raw diagnostic.** Upstream-only, raw Iroh and raw BitTorrent run as
   paired `diagnostic_uncompressed` arms. It qualifies discovery, attribution,
   transport correctness and failure behavior; it cannot fit or select policy.
4. **Stage-B training, followed later by sealed holdout.** Training contains
   upstream-only, Iroh raw/zstd and BitTorrent raw/compressed-or-evidenced-
   unsupported. TASK-44 may fit training only. TASK-123 later generates the
   hitherto nonexistent holdout and adjudicates frozen candidates unchanged.

### Layers are separate evidence, never synthetic end-to-end

Every scenario record has exactly one `measurement_layer`:

- `component_discovery`: starts without a content locator, ends at a bounded set
  of offers, and records local discovery, node/address bootstrap and named-key
  content resolve separately. It transfers no NAR payload.
- `component_transfer`: starts from a recorded explicit offer solely to isolate
  the transport/codec. Discovery is disabled and the report says that the offer
  was injected at this layer; this result cannot support a zero-injection claim.
- `full_real_nix`: starts from the declared fresh state, uses operational
  discovery with no content-specific injection, and ends at a real Nix store
  path plus S1/provider/upstream oracles.

Adding component discovery time to component transfer time is a model output,
not `full_real_nix`. It must never be relabelled end-to-end.

### Stage schemas and arm matrices

Stage A uses schema **`diagnostic-tournament-v1`** with the required closed
discriminators:

```text
purpose = "diagnostic_uncompressed"
diagnostic_uncompressed = true
policy_training_eligible = false
base_arms = ["upstream_only", "iroh_raw", "bittorrent_raw"]
execution_labels = [
  "upstream_only/A1", "upstream_only/A2",
  "iroh_raw/A1", "iroh_raw/A2",
  "bittorrent_raw/A1", "bittorrent_raw/A2"
]
```

The schema forbids `policy_candidate`, `objective_score`, fitted thresholds and
compressed arm records. Its component-transfer and `full_real_nix` records run
both labels of all three supported base arms; component-discovery has explicit
`not_applicable` label slots for upstream and a supported/unsupported record for
each P2P mechanism. Compression being available in the implementation does not
enable it here.

Stage B uses a different closed schema, **`policy-training-v1`**:

```text
purpose = "stage_b_training"
diagnostic_uncompressed = false
policy_training_eligible = true
base_arms = ["upstream_only", "iroh_raw", "iroh_zstd",
             "bittorrent_raw", "bittorrent_compressed"]
execution_labels = [
  "upstream_only/A1", "upstream_only/A2",
  "iroh_raw/A1", "iroh_raw/A2",
  "iroh_zstd/A1", "iroh_zstd/A2",
  "bittorrent_raw/A1", "bittorrent_raw/A2",
  "bittorrent_compressed/A1", "bittorrent_compressed/A2"
]
```

`bittorrent_compressed` is either measured or has
`cell_status=evidenced_unsupported` plus TASK-117/TASK-121 artifact hashes.
Every matrix cell has one of `measured`, `evidenced_unsupported`, `invalid`,
`excluded`, or `failed`; omission and numeric imputation are schema errors. The
same applies to backend-specific NAT, relay, tracker, Mainline and global-DHT
cells. Stage B does not choose a default.

`A1` and `A2` are indistinguishable configurations with separate fresh-state
executions; the suffix is a blinded experimental label, not a policy variant.
Both labels for every supported base arm execute throughout calibration and
extension, before best-static or adaptive policy selection exists. For an
unsupported or `not_applicable` base-arm cell, the base cell remains explicit
and both label slots record the same nonnumeric status/evidence; neither label
executes and no A/A metric is fabricated. Primary effects use only the
canonical `A1` dataset. `A2` is validation-only and never counts as another
cluster or increases N.

The TASK-44 reader accepts only `policy-training-v1` with
`policy_training_eligible=true`. Feeding it Stage A must fail before parsing any
metric with **`STAGE_A_POLICY_INPUT_FORBIDDEN`**. A mutation that flips/removes
any discriminator or adds a policy field is a required bite. File extensions,
directory names and caller assertions are not the boundary; the closed typed
schema is.

### Versioned scenario-generation contract

`nix-p2p-scenarios-v1` is a pure manifest function. Its typed input is
`{experiment_version, partition, seed_256, workload_catalog,
network_catalog, supported_capabilities, execution_label_contract, profiles,
planning_contrast_catalog, generation_plan, exclusion_registry}`. `partition`
is exactly `development`, `training`, or `holdout`; the last value additionally
requires the permit described below. `execution_label_contract` is the complete closed
base-arm-to-`[A1,A2]` mapping printed in the selected Stage schema; bytewise JCS
inequality, a missing label or an extra label rejects generation.
`profiles` is exactly the ordered list
`[upstream_only,consume_only,lan_share,public_share]`, so one invocation can
enforce the cross-profile partition ceilings rather than relying on four
uncoordinated per-profile calls.
`generation_plan` is the following closed tagged union (fields from another tag
are forbidden):

```text
{"phase":"calibration","replicates_per_opportunity_stratum":20}
{"phase":"extension","calibration_manifest":complete_jcs_object,
 "calibration_manifest_hash":sha256,"calibration_results_hash":sha256,
 "planning_artifact":complete_jcs_object,"planning_artifact_hash":sha256}
{"phase":"fixed","source_training_plan":complete_jcs_object,
 "source_training_plan_hash":sha256}
```

Training uses `calibration` and then, if calibration is usable, one `extension`;
holdout uses only `fixed` with the training-frozen target map. Development may
use `fixed`, but cannot supply a holdout permit. Development/training seeds are
32 bytes rendered as 64 lowercase hexadecimal digits. No holdout seed or
holdout input exists yet. Every complete object above is canonicalized and its
declared hash verified; a hash without its content is rejected. Calibration and
fixed phases emit all qualification rows once. Extension emits only opportunity
ordinals 20 onward, so qualification rows are not accidentally multiplied by
the two training phases.

#### Canonical bytes, catalogs and identifiers

Every hash and equality check uses RFC 8785 JSON Canonicalization Scheme (JCS)
UTF-8 bytes, not a language's default JSON printer. Contract objects use only
objects, arrays, booleans, strings and integers in `[-(2^53-1), 2^53-1]`;
floating point, `null`, duplicate object keys, invalid UTF-8 and non-ASCII
schema keys/IDs are rejected before hashing. JCS does not normalize strings, so
catalog production must emit NFC and the reader rejects a string that changes
under NFC. A `*_hash` is lowercase hexadecimal SHA-256 of the complete JCS byte
sequence. Distinct JCS rows with the same digest fail `HASH_COLLISION`; they are
never collapsed.

The workload catalog is the complete, immutable list of candidates available to
this experiment version. Each entry has a unique ASCII `candidate_id`, an
ordered list of store-path tokens, exact path count, total and maximum NarSize,
and the upstream FileSize/NarSize quartile labels needed below. The network
catalog is likewise the complete list of topology templates, each with a unique
ASCII `topology_id`, sorted ASCII `node_id`s, designated requester/provider
roles, physical-network labels, and an explicit ordered list of supported NAT
paths. Its node count must be exactly the count named by its topology stratum;
a mismatch rejects the catalog. Entries are sorted by the unsigned UTF-8 bytes
of their ID before use; input order is not evidence. The catalogs contain no
sampling weight. Catalog hashes, not abbreviated summaries, travel in every
manifest.

`exclusion_registry` is the complete immutable JCS object
`{registry_version, previous_entry_hash, concrete_tuple_ids}`. The listed IDs
are exactly the full concrete identities defined below, not symbolic-row or
catalog-pair aliases. IDs are unique, lowercase SHA-256 hex sorted by raw digest
bytes; duplicate, unsorted or invalid IDs reject the input. The generator
verifies and records
`exclusion_registry_hash=SHA256(JCS(exclusion_registry))`; a hash without the
content is not a usable input. Development/training supply their frozen registry
snapshot, while holdout supplies the exact independently witnessed snapshot
named by its permit.

`supported_capabilities` is a closed map keyed by stage arm, topology stratum,
NAT/path and discovery mechanism. A value is `measured_capable` or
`evidenced_unsupported` with a nonempty evidence hash. It may label a generated
cell unsupported but cannot remove the row from the inventory. An absent key is
`CAPABILITY_UNDECLARED` and invalidates generation.

#### Frozen planning-contrast catalog

Before the first calibration cluster, TASK-128 freezes the selector schema,
pure interpreter and enumeration code hashes. The complete
`planning_contrast_catalog` is a JCS object containing those hashes and, for
each selectable profile, sorted arrays of `selector_artifacts`,
`best_static_comparators`, and `contrasts`. Each selector artifact contains a
full closed selector AST, its exact integer/string hyperparameters, required
causal-trace fields, allowed base arms and
`selector_id=SHA256(JCS(selector_artifact))`. It must be total and deterministic
on every logical opportunity trace. Ranges, wildcards, training-filled fields
and unspecified defaults are forbidden: choosing parameters later means TASK-44
chooses one already enumerated exact artifact using A1, not that it creates a
new parameter value.

TASK-128 also freezes the closed causal trace schema and replay interpreter.
One label-local trace bundle contains pre-execution context plus only
observations available by each decision timestamp: discovery/offer state,
elapsed monotonic time, source-attributed bytes, rolling throughput, integrity
or terminal state, timers and confirmed path events. It contains no future
event, other-label field or post-hoc outcome summary. `Replay(selector,trace)`
emits the ordered start/abort/hedge/race/fallback actions and derives latency,
bytes, upload and waste from provenance; a static one-arm selector is merely a
special AST. Replay is run independently on A1 and A2 trace bundles. Every
dynamic selector class needs hashed development replay-versus-live parity
evidence before catalog freeze, with the same A1/A2-by-class matrix,
independent fresh states and label-matched traces required below. Each dynamic
artifact's immutable catalog entry also names blinded
`training_parity_qualification_id`s that the calibration manifest must execute;
their hashed pass result is required before TASK-44 nomination. Missing/failed
training parity marks every catalog contrast containing that selector
`replay_parity_ineligible` without rewriting or removing any catalog entry. A
whole-arm `selector(context)`
shortcut cannot qualify abort, hedge, race, throughput-adaptive or layered
behavior.

Every dynamic selector artifact names exactly eight blinded
`selector_parity_qualification_id`s, one for each Cartesian pair of label
`A1,A2` and closed scenario class:
`clean_early_choice`, `slow_hit_abort`, `delayed_alternate_hedge_race`, and
`throughput_drop_layered_fallback`. Their frozen predicates respectively require
a healthy prompt source; an advertised source that stalls before completion
with a healthy alternate; an incomplete first path at the frozen hedge timer
with a usable delayed alternate; and initial payload progress followed by a
rate collapse/terminal event with a healthy next-layer or upstream fallback.
From the bounded `full_real_nix` qualification targets, the generator takes the
raw-`target_row_id`-first feasible row for each predicate before calibration;
outcomes and human-supplied row overrides are forbidden. The catalog freezes
the exact rows and
`selector_parity_qualification_id=SHA256(JCS({profile,selector_id,class,label,
target_row_id}))`. The four underlying rows are included within that profile's
64-row qualification ceiling and may be shared as scenarios, but every
`(selector_id,class,label)` has a distinct execution ID and live slot. A
missing class/label pair or duplicate ID is `CONTRAST_CATALOG_INCOMPLETE`.

For each selector and class, the live policy runs twice from independently
fresh state: once as A1 and once as A2. Each replay consumes only the matching
already-recorded base-arm label trace bundle and adds no live execution; an A1
live result can be compared only with A1 replay, and likewise for A2. Live
executions run in raw parity-execution-ID order after a seeded Fisher-Yates
relabeling, with a fresh reset between them. Parity compares the
ordered causal action/provenance trace and exact byte/source/terminal fields;
the schema names any timing tolerance. These qualification-only executions are
closed `parity_execution` records keyed by qualification ID, selector ID,
class and label; they are not base-arm `execution_labels`, do not enter the Williams
schedule, A/A, N or an estimand, and cannot carry an objective score. Static
one-arm artifacts need no dynamic live-parity slot. The budget nevertheless
assumes all 16 artifacts are dynamic: at most `4*2*16=128` live slots per
profile and 384 across the three selectable profiles.

The catalog also has a closed `required_selector_class_inventory` covering
static raw/compressed Iroh and BitTorrent where capable, slow-HIT abort,
delayed hedge/race, throughput-adaptive selection and layered alternate/fallback.
Each class is either represented by at least one exact selector artifact or has
an `evidenced_unsupported` record and nonempty evidence hash. Omitting a class,
exact artifact or supported base arm is `CONTRAST_CATALOG_INCOMPLETE`, never an
implicit narrowing of the tournament.

Possible best-static comparators are the complete sorted set of capable P2P
base arms (`iroh_raw`, `iroh_zstd`, `bittorrent_raw`, and
`bittorrent_compressed`, at most four); upstream remains the fixed external
comparator. For each profile, `contrasts` is the exact Cartesian product of its
selector artifacts and possible best-static comparators, with
`contrast_id=SHA256(JCS({profile,selector_id,best_static_base_arm}))`. The
reader recomputes that product and rejects omissions, additions, duplicate IDs
or unequal JCS objects.

##### Frozen numeric planning injections

The catalog contains the complete `planning_injection_contract` object and
`planning_injection_contract_hash=SHA256(JCS(planning_injection_contract))`.
Every contrast and hypothesis case names that hash. The object includes
`solver_version="linked-coordinate-v1"`, the ordered solver operations and all
physical-domain predicates below,
`arithmetic="ieee754-binary64-round-to-nearest-ties-even"`, and the reduced
rational transform-unit tolerance `1/1099511627776` (`2^-40`). The frozen
analysis binary and Nix closure supply the logged `ln`/`exp` implementation. It
encodes numbers without JSON floats: a rational is
`{"form":"rational","num":n,"den":d}` and a scaled natural logarithm is
`{"form":"scaled_ln_ratio","scale_num":s_n,"scale_den":s_d,
"ratio_num":r_n,"ratio_den":r_d}`. Denominators and ratio terms are positive,
fractions are reduced, and zero is the rational `0/1`. Any other encoding,
missing rule or unequal recomputed hash is `PLANNING_INJECTION_CONTRACT_INVALID`
before calibration.

The following is the exact semantic table serialized in that object; `t` is
the injected statistic in one stratum, `a` is the candidate, `b` best-static,
`u` upstream, `f[x]=U[x]/U[u]`, and
`R[x]=sum(U[u]-U[x])/sum(P[x])`:

| Rule ID | Decision direction and boundary | Joint-power alternative | Exact coordinate equation |
|---|---|---|---|
| `consume_benefit` | lower, `1/20 = 0.05` | `3/40 = 0.075` | `mean(f[b/A1]-f[a/A1])=t` |
| `p2p_egress_cut` | lower, `1/5 = 0.20` | `3/10 = 0.30` | `mean(1-f[a/A1])=t` |
| `lan_log_benefit` | lower, `ln(20/19) = -ln(0.95)` | `(3/2)*ln(20/19)` | `Q95(L[a/A1])/Q95(L[b/A1])=exp(-t)` |
| `public_log_relief_improvement` | lower, `ln(11/10)` | `(3/2)*ln(11/10)` | `R[a/A1]/R[b/A1]=exp(t)` |
| `public_absolute_log_relief` | lower, `0/1` | `ln(11/10)` | `R[a/A1]=exp(t)` |
| `p2p_latency_guard` | upper, `ln(11/10)` | `0/1` (no regression) | `Q95(L[a/A1])/Q95(L[u/A1])=exp(t)` |
| `aa_egress` | equivalence boundaries `-(1/20), +(1/20)` | `0/1` | `mean(f[x/A1]-f[x/A2])=t` |
| `aa_latency` | equivalence boundaries `-ln(21/20), +ln(21/20)` | `0/1` | `Q95(L[x/A2])/Q95(L[x/A1])=exp(t)` |
| `aa_relief` | equivalence boundaries `-ln(11/10), +ln(11/10)` | `0/1` | `R[x/A2]/R[x/A1]=exp(t)` |

The contract records the applicable profile and candidate/comparator/upstream
series for every row. A joint-power case assigns every applicable performance
row its displayed alternative and every required A/A row zero. A performance
boundary case changes only the named rule and boundary stratum; an A/A boundary
case changes only the named series, sign and boundary stratum. Thus a case
cannot silently substitute a more favorable alternative.

The frozen consistent-coordinate solver applies those targets to the centered
whole-cluster vector in this order, using a single shared coordinate graph for
all aliases of an underlying field:

1. Keep each positive upstream denominator `U[u/d,c]` fixed. Apply one additive
   constant to each required fraction series. Candidate A1 is shifted to solve
   the egress equation; for consume-only, comparator A1 is then shifted to solve
   its benefit equation. For public-share, where comparator egress is a nuisance
   rather than a rule, shift comparator A1 so its upstream-byte-weighted avoided
   numerator equals the candidate's. Recompute `U[x/d,c]=f[x/d,c]*U[u/d,c]`
   and `D[x/d,c]=U[u/d,c]-U[x/d,c]`; fraction, byte and relief-numerator views
   may not diverge.
2. Multiply each complete positive latency series by one positive scalar.
   Candidate A1 first solves the upstream guard; LAN comparator A1 then solves
   the candidate/comparator ratio. Type-7 Q95 is scale-equivariant, so the
   displayed equations are exact without changing within-series ranks.
3. For public relief, require positive candidate and comparator sums of `D` and
   positive centered upload sums. Scale each complete nonnegative upload series
   by one positive scalar so candidate absolute relief is `exp(t_abs)` and
   comparator relief is `R[a]*exp(-t_relative)`.
4. Inject A/A last. An additive A2 fraction shift solves its displayed A1-A2
   mean; a positive A2 latency scale solves its Q95 ratio. For relief A/A, derive
   the A2 numerator from its already-linked fraction/byte coordinates, give an
   otherwise-unconstrained comparator A2 numerator the same positive total as
   comparator A1, then scale A2 upload to `R[A1]*exp(t_aa)`. All other required
   A/A targets remain exactly zero.

Each operation preserves cluster indices and residual ordering; the complete
joint vector is still resampled as one unit. After solving, recompute every
target from the linked coordinates. Nonfinite/nonpositive denominators or
latencies, a negative implied payload/upload byte count, a nonpositive required
relief numerator/upload sum, an inconsistent shared view, or target mismatch is
`PLANNING_INJECTION_PHYSICAL_DOMAIN` for that contrast. Clipping, projection,
replacement and retry are forbidden; the contrast becomes
`injection_domain_ineligible`, while unrelated contrasts remain usable.

The finite planning limits are:

```text
MAX_SELECTOR_ARTIFACTS_PER_PROFILE = 16
MAX_BEST_STATIC_COMPARATORS_PER_PROFILE = 4
MAX_PLANNING_CONTRASTS_PER_PROFILE = 64
MAX_PLANNING_CONTRASTS_TOTAL = 192
MAX_PLANNING_HYPOTHESIS_CASES_PER_CONTRAST = 64
PLANNING_SYNTHETIC_EXPERIMENTS_PER_CASE = 128
PLANNING_BOOTSTRAP_DRAWS_PER_EXPERIMENT = 10000
MAX_TOTAL_PLANNING_CONTRAST_DECISIONS_U64 = 15728640000
```

The 64 cases include the power alternative. The worst public-share contrast is
exactly `1 + 4*4 + 4*2*5 = 57`: one joint alternative; four possible boundary
strata for each of primary, egress, absolute-relief and latency-guard rules; and
two signs in four strata for five required A/A series/transforms (candidate and
comparator relief, candidate egress, candidate latency and upstream latency).
Other profiles require fewer cases. The checked-u64 worst-case total is exactly
`192*64*128*10000 = 15728640000` authoritative-N contrast-decision evaluations.
Catalog counts, case counts and checked multiplication are recorded before
calibration; overflow or exceeding a bound fails
`CONTRAST_CATALOG_BUDGET_EXCEEDED`. More policy space requires a new experiment
version and an explicitly raised reviewed ceiling, not pruning selectors after
seeing data. N=125 is not simulated in v1; it may be added only as labeled
diagnostic work under a new compute artifact and can never rescue N=100.

After centered planning below and before TASK-44 sees training A1, the planning
custodian releases only a JCS eligibility mask containing catalog hash, global
`N_required=100`, planning-artifact hash and one
`{contrast_id,status,reason_code}` per contrast. Status is `eligible_at_100`,
`structurally_ineligible`, `replay_parity_ineligible`, or
`injection_domain_ineligible`, or `underpowered_at_100`. Structural status uses
only the frozen catalogs/capabilities, parity status only the predeclared
qualification oracle, injection status only the frozen solver's physical-domain
checks, and underpower status only centered power/null criteria. The mask exposes no
raw A2, residual, per-label effect,
uncentered statistic, boundary rate or directional result. Full planning bytes
remain sealed until candidate and best-static hashes freeze, then an
independent reader may verify them. This coarse mask/global-N interface is not
an A2 outcome channel.

The factor domains are frozen below in their displayed order. `MiB`/`KiB` mean
powers of two; bandwidth is payload octets per second at the named socket, not
NarSize per second. The eight cache/peer link dimensions are atomic factors;
they are never collapsed into a 144-level tuple.

| Factor | v1 levels / generation rule |
|---|---|
| Workload | `small_head`: 1–8 paths and 1–32 MiB total NarSize; `wide_closure`: 128–512 independently substitutable members plus one root (129–513 closure paths total) and 256 MiB–2 GiB total NarSize; `large_tail`: at least one 64–256 MiB NarSize and at most 4 GiB total; `compression_mix`: at least 20 paths spanning all available upstream FileSize/NarSize quartiles. Complete workload candidates, not individual paths, are selected from the versioned catalog by the partition seed; a catalog unable to satisfy a stratum emits unsupported, never a hand-picked substitute. |
| Topology stratum/template binding | Logical levels are `component_2_namespace`, `swarm_10_namespace`, `swarm_30_process`, and `real_3_network`. `component_2_namespace` supports `component_discovery` and `component_transfer`; `swarm_10_namespace` supports all three layers; `swarm_30_process` supports **only** `component_discovery` resource-law qualification and can never emit `component_transfer` or `full_real_nix`; `real_3_network` supports only `full_real_nix`. Once a topology-stratum and NAT/path pair is chosen, the seeded binding rule below selects one compatible concrete `topology_id` before any capacity-dependent factor. Unsupported backend/topology cells stay present, but a layer mismatch is structurally invalid. |
| Requester/store state | Requester Nix store, XDG/Nix narinfo cache and daemon cache are fresh for every scored pair. Swarm seen fraction is `0`, `2500`, `5000`, or `10000` basis points. Provider identity persistence is `false` or `true`, never inherited accidentally. |
| Holder selector | The fixed five-level domain is `none`, `one`, `two`, `half`, `all`. After `topology_id` is bound with exact provider capacity `P>=1`, resolve respectively to `0`, `min(1,P)`, `min(2,P)`, `ceil(P/2)`, and `P` holders. Placement is seed-derived and recorded, not inferred from either selector or count. |
| NAT/path | `same_l2_direct`, `public_direct`, `cone_nat_hole_punched`, `symmetric_nat_relay_required`, `relay_unavailable`. Confirmed observed path is required; configuration narration does not select the level. A backend without a relay cell emits evidenced unsupported. |
| Dependency state | Ordered levels are `available`, `dns_unavailable`, `tracker_unavailable`, `relay_service_unavailable`, `mainline_bootstrap_unavailable`, and `iroh_seed_unavailable`. `available` schedules no outage. Every other level creates exactly one event from monotonic offset 0 through `trial_window_ns` for the named dependency. The row remains for every arm; an arm that does not use that dependency records `not_applicable`, never silently removes it. |
| Cache RTT | `cache_rtt_ms` = `0`, `25`, `75`, `150`. |
| Cache bandwidth | `cache_bandwidth_bytes_compressed_wire_per_s` = `unshaped`, `5*2^20`, `20*2^20`, `100*2^20`. |
| Cache loss | `cache_loss_basis_points` = `0`, `100`, `500`. |
| Cache jitter | `cache_jitter_p95_ms` = `0`, `5`, `25`. |
| Peer RTT | `peer_rtt_ms` = `0`, `25`, `75`, `150`. |
| Peer bandwidth | `peer_bandwidth_bytes_compressed_wire_per_s` = `unshaped`, `5*2^20`, `20*2^20`, `100*2^20`. |
| Peer loss | `peer_loss_basis_points` = `0`, `100`, `500`. |
| Peer jitter | `peer_jitter_p95_ms` = `0`, `5`, `25`. Direction and measured application point are recorded for every link factor. |
| Nix concurrency | `(max-substitution-jobs,http-connections)` = `(1,1)`, `(16,25)`, `(128,128)`. Readback and measured overlap must equal the requested level. |
| Churn | `holder_churn_basis_points_per_minute` = `0, 1000, 5000`; seeded join/leave times and the actually observed live-holder series are recorded. |
| Herd selector | The fixed three-level domain is `one`, `ten`, `all_requesters`. After binding exact requester capacity `R>=1`, resolve respectively to `min(1,R)`, `min(10,R)`, and `R` concurrent requesters. Measured first-request start skew must be at most **100 ms**; otherwise the row is invalid. |
| Liar selector/kind | The fixed `liar_selector` domain is `none`, `one`, `half_holders`; after holder resolution to `H`, these resolve to `0`, `min(1,H)`, and `ceil(H/2)`. `lie_kind_offset` is `not_applicable` when the realized count is zero and otherwise one of `wrong_locator`, `corrupt_bytes`, or `oversized_slow_body`. Assigned liars cycle through the three kinds starting at that offset. A realized one-liar anchor exists at each offset, so every kind is generated and hits its named integrity/resource oracle. |
| Slow holders | `slow_mode` = `unshaped`, `cap_64k`, `cap_1m`, or `stall_at_2500bp`; caps mean respectively `64*2^10` and `1*2^20 bytes_compressed_wire/s`, and the stall point is basis points of signed NarSize. Measured rate/stall point, not the knob, defines validity. |
| Leeching | `leech_fraction_basis_points` = `0`, `5000`, `9000`, or fault-only `10000`. The `10000` level selects every available provider and supplies the mandatory all-leech anchor. Publication-disabled and serve-disabled are two recorded booleans; lookup leakage is measured independently rather than inferred from “leech”. |

Selector resolution has one canonical alias rule. For holder, herd and liar
selectors separately, group all symbolic selectors that resolve to the same
integer under the bound template/`H`; the first selector in the displayed
domain order is canonical and the ordered full group is `selector_aliases`.
Construct physical rows from realized integers plus the canonical selector and
alias list, then merge JCS-identical physical rows before target IDs, row counts
or execution. IPOG coverage expands the alias lists, so one physical execution
covers every logically identical selector pair; aliases never become duplicate
scenarios or extra statistical weight.

#### Exact PRF and unbiased selection

For a 32-byte seed, partition and an ASCII domain matching
`[a-z0-9/_-]+`, byte block `c` is:

```text
HMAC-SHA256(
  key = seed_256,
  data = ASCII("nix-p2p-scenarios-v1") || 0x00 || ASCII(partition) ||
         0x00 || ASCII(domain) || 0x00 || U64BE(c))
```

Each operation owns one uniquely named domain and a stream formed by
concatenating blocks for counters `0,1,...`; counters and stream cursors never
cross domains. `uniform(m)` reads the next eight bytes as unsigned big-endian
`x`, sets `limit = 2^64 - (2^64 mod m)`, rejects `x >= limit`, and otherwise
returns `x mod m`; `m=0` is an error. A permutation is unbiased Fisher-Yates,
iterating `i=n-1` down to `1` and swapping `a[i]` with
`a[uniform(i+1)]`. There is no modulo bias, implicit platform RNG, hash-map
iteration or relative weight.

Normative development-only test vectors (they contain no holdout material):

```text
JCS input:       {"z":1,"a":[3,true,"x"]}
JCS bytes:       {"a":[3,true,"x"],"z":1}
SHA-256:         9a69ee35dfc4bdc6e0d09549c9dfb36b2b0fc7df880abd98c0465bdfff58436b

seed_256:        000102030405060708090a0b0c0d0e0f
                 101112131415161718191a1b1c1d1e1f
partition:       development
domain:          test/vector
block 0:         fb7d84fff1dc00caf59d4d883b38de5c
                 719cf1f5b2505063df3b0944e5ff16d7
shuffle a,b,c,d: d,b,a,c
```

An implementation that misses any vector cannot emit a manifest.

#### Bounded target construction; no Cartesian universe

The generator constructs opportunity targets once per coarse
`(profile, full_real_nix, workload_stratum)` decision stratum. It constructs
the **entire** qualification target set once per `(profile, measurement_layer)`;
workload stratum is an IPOG factor there, so the 64-row qualification cap is not
multiplied by four workloads. For opportunity construction, topology stratum
and NAT/path are the first two varying factors; for qualification they follow
workload stratum. They never create nested per-template target sets. When
topology and NAT are both assigned, sort the compatible catalog
templates by raw `topology_id`, shuffle with domain
`template/<partition>/<profile>/<layer>/<workload-stratum>/<topology-stratum>/<nat-path>`,
and bind the first concrete `topology_id`. That binding occurs before fixed
holder/herd/liar selectors are resolved, canonicalized, assigned target-row IDs
or placed, so all capacity-dependent values use exact catalog capacities
without multiplying rows by catalog size. A
workload candidate must satisfy every inclusive bound of its named workload
stratum; a candidate satisfying multiple strata is independently eligible in
each. A selected topology must list the NAT/path. These checks, the table's
layer allow-list, and the following ordered local rules are the complete
feasibility predicate:

1. the already-bound template must have `P>=1` and `R>=1`; holder and herd
   selectors resolve and canonicalize by the rule above, then the liar selector
   resolves from the realized `H`. A zero liar count forces
   `lie_kind_offset=not_applicable`; a positive count requires exactly one of
   the three declared offsets;
2. `H=0` forces zero churn and `slow_mode=unshaped`;
   `component_discovery` forces `slow_mode=unshaped`; and
   `component_transfer` forces seen fraction `0` and persistence `false`;
3. the herd selector resolves against the bound requester capacity; and
4. `relay_unavailable` and every dependency state other than `available` are
   deliberate fault rows, never normal paths. A non-applicable dependency/arm
   cell is retained with that status.

Backend capability does not remove a target. Every target is crossed with every
stage arm; an incapable cell is retained as `evidenced_unsupported` with its
evidence hash. Upstream `component_discovery` is explicit `not_applicable`.

Each target row carries exactly one `decision_use`. A row is
`performance_opportunity` only when its layer is `full_real_nix`, `H>0`, NAT is
not `relay_unavailable`, churn/lying/leech are zero, `slow_mode=unshaped`, and
dependency state is `available`. All component rows and every zero-holder,
all-leech or serve-disabled, unavailable/unsupported selected mechanism,
corrupt/lying, slow/stalled, churn, relay/dependency outage, or deliberately
forced-fallback row are `fault_qualification`. Classification uses only the
frozen manifest, candidate selector, capability map and scheduled events before
results are read. A frozen candidate must have a measured capable selection in
every required normal opportunity target; reclassifying one because its chosen
mechanism is unsupported fails `OPPORTUNITY_COVERAGE_INCOMPLETE` rather than
shrinking the estimand. Every workload stratum has cold and warm honest
one-holder normal anchors. If those anchors cannot be built, generation fails
`OPPORTUNITY_SET_EMPTY`.

Targets are constructed without enumerating a Cartesian product:

Before growth, enumerate only unordered factor-name pairs and their ordered
symbolic-level pairs. `pair_feasible` first applies this closed conditional
closure: nonzero churn, a liar selector that realizes positive or a non-default
slow mode requires a holder selector that realizes positive; a concrete
lie-kind offset defaults an unset liar selector to `one`; a realized zero-holder
selection conflicts with any of those; and all remaining unset conditional
fields take their declared normal selector/level. It then scans the
precomputed, PRF-ranked compatible `(topology-stratum,NAT/path,topology_id)`
bindings (at most `3*5*16=240` for any layer) and returns the first binding that
satisfies fixed topology/NAT plus the resolved holder/herd/liar selectors. No
binding means the pair is infeasible. The returned binding and all canonical
aliases are recorded as the pair's completion witness. Because every structural
dependency is in that closure or the earlier topology binding, this is a
bounded scan with no recursive search/backtracking.

1. Add the cold/warm opportunity anchors. Add fault anchors for zero holders,
   all providers leeching with publication/serve disabled, each lying kind,
   every non-default slow mode, each nonzero churn level, relay unavailable,
   every non-available dependency state, and selected-mechanism unsupported.
   Add first/last-level OFAT rows from the
   appropriate cold opportunity or fault anchor. Merge exact JCS duplicates and
   retain the sorted role union.
2. Run deterministic IPOG-style pairwise growth independently for opportunity
   and qualification factors. Opportunity factor order is topology stratum,
   normal NAT/path, seen fraction, identity persistence, a holder selector that resolves positive, the eight
   atomic link factors in table order, Nix concurrency and herd selector; dependency,
   churn, liar selector/kind, slow and leech are fixed at their normal levels.
   Qualification prepends workload stratum and then uses the full order
   including dependency, churn, liar selector, lie-kind offset, slow and leech.
   Seed the table
   with every feasible pair of the first two factors. For each later factor,
   visit existing rows in their fixed PRF rank and choose the locally feasible
   level covering the most uncovered pairs; ties use domain
   `ipog/level/<profile>/<layer>/<coarse-id>/<factor>/<row-id>`. Then visit
   uncovered feasible pairs in domain `ipog/vertical/...` rank, create a
   partial row containing that pair, and fill unset earlier factors in order
   with the feasible level covering most remaining pairs using the same tie
   rule. A partial assignment that violates an ordered local rule is discarded
   immediately; the algorithm never scans or materializes full combinations.
3. Directly verify that every declared feasible pair occurs in the result and
   that no infeasible pair does. An uncovered feasible pair, a row without a
   completion, or any ceiling below is `MATRIX_BUDGET_EXCEEDED`; rows are never
   sampled, truncated, or silently dropped to fit.

Normative development-only IPOG vector: factors `a,b,c`, each with ordered
levels `0,1`, have no constraints; initial-row rank is `00,01,10,11` and level
tie rank is `0,1`. Horizontal growth must produce, in order,
`000,011,101,110`; all 12 cross-factor value pairs are then covered and vertical
growth adds no row. A different result cannot emit a manifest.

The following technical ceilings bound generator and execution work; they are
not substitutes for TASK-120 product resource budgets:

```text
MAX_TOPOLOGY_TEMPLATES_PER_TOPOLOGY_STRATUM = 16
MAX_WORKLOAD_CANDIDATES_PER_WORKLOAD_STRATUM = 64
MAX_OPPORTUNITY_ROWS_PER_DECISION_STRATUM = 48
MAX_QUALIFICATION_ROWS_PER_PROFILE_LAYER = 64
MAX_TARGET_ROWS_PER_PROFILE_LAYER = 256
MAX_OPPORTUNITY_CLUSTERS_PER_DECISION_STRATUM = 100
MAX_SCENARIO_CLUSTERS_PER_PROFILE = 592
MAX_SCENARIO_CLUSTERS_PER_PARTITION = 2368
MAX_BASE_EXECUTION_LABEL_SLOTS_PER_PARTITION = 23680
TRAINING_SELECTOR_PARITY_SCENARIO_CLASSES_PER_ARTIFACT = 4
TRAINING_SELECTOR_PARITY_LABELS_PER_SCENARIO_CLASS = 2
MAX_TRAINING_PARITY_EXECUTION_SLOTS_PER_PROFILE = 128
MAX_TRAINING_PARITY_EXECUTION_SLOTS_PER_PARTITION = 384
MAX_STAGE_B_EXECUTION_SLOTS_PER_PARTITION = 24064
MAX_PAIR_FEASIBILITY_BINDING_PROBES_PER_PROFILE_LAYER = 2000000
MAX_CONCRETE_ID_PROBES_PER_PARTITION = 100000
```

There are exactly four opportunity decision strata per profile, keyed only by
`(profile, full_real_nix, workload_stratum)`. Thus the computable worst case is
`4*100 + 3*64 = 592` clusters per profile and `4*592 = 2368` per partition.
Stage B has at most ten execution-label slots per cluster (five base arms times
two labels), hence `2368*10 = 23680` base slots; Stage A has at most six. The
four selector-parity classes reuse four qualification scenarios already
counted in each profile's 64-row ceiling, so they add no scenario cluster, but
up to 16 dynamic selector artifacts execute fresh A1 and A2 live parity in each
class. They therefore add at most `3*16*4*2 = 384` live slots, for a total
Stage-B ceiling of `23680+384 = 24064`. Unsupported and not-applicable
base-label slots remain
explicit but do not execute, so they cannot exceed the declared base maximum
or masquerade as clone observations.
Full-real-Nix target rows are at most `4*48 + 64 = 256` per profile/layer;
component layers have at most 64 each. The generator records all these counts
before execution. It also records every pair-feasibility binding probe and
concrete-identity probe. Exceeding any bound fails `MATRIX_BUDGET_EXCEEDED`;
enumeration never continues unbounded and execution never starts.
The largest qualification domain has 22 atomic factors and 81 total levels, so
direct level-pair enumeration has at most
`(81^2 - sum(level_count^2))/2 = 3123` pairs and at most
`3123*240 = 749520` binding probes, below the declared ceiling.

No row count or catalog frequency is a weight. Changing a domain/order,
feasibility rule, classification, anchor, pair definition, IPOG mechanics,
ceiling, PRF or catalog eligibility is a generator-version change.

#### Coarse decision strata, concrete placement and IDs

`decision_stratum_id` is SHA-256 of JCS
`{experiment_version,profile,measurement_layer:"full_real_nix",
decision_use:"performance_opportunity",workload_stratum}`; it is deliberately
not a target-row ID. Within each decision stratum, sort the unique opportunity
target rows by raw `target_row_id=SHA256(JCS(target_row))`. Put the cold anchor
then warm anchor first; shuffle all remaining rows once with domain
`row-schedule/<partition>/<decision-stratum-id>` and append them. Assign cluster
ordinal `i` row `i mod row_count`. `N_required` must be at least `row_count`, so
every nuisance row runs, repetition counts differ by at most one, and the pilot
always contains both anchors. Fault and component qualification rows run
exactly one cluster each and have `qualification_row_id`, not an inferential N.

The calibration manifest always contains exactly ordinals `0..19` in every
opportunity stratum. If `row_count>20`, these are the first 20 entries of the
already-frozen cyclic schedule, not a regenerated or favorable subset; the
extension continues at ordinal 20 and `N_required>=row_count` guarantees that
the final inferential sample covers every target. The pilot is used only for
power planning, never for candidate direction or row selection. Unseen
nuisance interactions can therefore reduce realized power and yield no winner,
but cannot be dropped from the final interval or create a favorable resample;
the final A/A and decision intervals use the complete calibration-plus-extension
sample.

For an assigned row, the already-bound topology supplies exact capacities.
Shuffle its eligible workload candidates with domain
`catalog/<partition>/<target-row-id>`. For each candidate in that order, derive
up to eight finite placement variants with domains containing
`candidate_id/variant-0` through `candidate_id/variant-7`; select the first full
concrete tuple whose ID is neither already selected nor in the exclusion
registry. Exhausting this bounded list emits the finite counts and
`METRIC_UNUSABLE_CATALOG_EXHAUSTED`; there is no reroll, cycling, catalog
substitution, or relaxed exclusion.

For each variant, independently permute the bound template's provider and
requester IDs. Take the realized `H` holders and realized herd requesters; select exact
liar, slow and leech placements from independent domains. `slow_mode=unshaped`
selects no slow holder and another mode selects one when `H>0`; leech count is
`floor((fraction_basis_points * provider_count + 5000) / 10000)`. Record the
leech nodes' publication-enabled and serve-enabled booleans explicitly. Overlap
is allowed and recorded. Assign liar kinds in cyclic order
`wrong_locator,corrupt_bytes,oversized_slow_body`, beginning at the target row's
declared `lie_kind_offset`. For every nonzero churn
minute and holder, draw `uniform(10000)`; a draw below the basis-point rate
schedules one toggle at
`minute_start_ns + uniform(min(60_000_000_000, remaining_trial_ns))`. Events
start from recorded state and sort by timestamp then ASCII node ID. A zero or
too-short catalog `trial_window_ns` is invalid.

The *complete identity object* is
`{target_row,candidate_id,topology_id,provider_roles,requester_roles,
holder_placement,liar_placement_and_kind,slow_placement_and_mode,
leech_placement_publish_serve_flags,scheduled_events,dependency_events,
initial_node_states}`. `concrete_tuple_id=SHA256(JCS(identity_object))`;
variant numbers, cluster ordinals and arm presentation order do not create a new
underlying identity. The exclusion registry contains these exact IDs, so a
counterbalance change cannot make a training tuple eligible for holdout.
`scenario_id=SHA256(JCS({generator_version,experiment_version,partition,
decision_or_qualification_id,cluster_ordinal,concrete_tuple_id,
arm_order_and_schedule}))`. The manifest sorts by raw scenario-ID bytes and
records the full identity object and arm schedule, seed, PRF domains, complete
catalogs, `planning_contrast_catalog_hash`,
`execution_label_contract_hash`, exact selector-parity schedules,
target/registry hashes, unsupported cells, rejected rows/reasons, and all
finite selected/unselected counts. Any duplicate or excluded concrete identity
is a hard error.

### Closed profile estimands and conservative aggregation

For a profile `p`, `O_p` is the closed, nonempty set of its four coarse
`performance_opportunity` decision strata, one per workload stratum. The
pairwise/anchor/OFAT nuisance targets are deterministically distributed across
cluster ordinals inside those strata; they do not each receive an inferential
N. `Q_p` is every generated `fault_qualification` observation, including all
component rows and full-real-Nix fault rows. No `Q_p` row contributes a benefit,
normal-latency, egress or relief margin. It instead must pass every applicable
S1, bounded-S2, privacy, resource, fallback, attribution and anti-vacuity gate.
There is no post-hoc subset, workload/topology weight or average across strata,
and a candidate cannot move a bad measurement from `O_p` to `Q_p`.

One independent `scenario_cluster` is one concrete generated tuple with fresh
state and both counterbalanced labels of every supported base arm. It still
contributes exactly one primary observation per arm: for any field `X`, define
`X[a,c]=X[a/A1,c]`; `a/A2` is validation-only and never another sample.
Request-level observations remain diagnostic and never increase N. For cluster
`c` in stratum `s`, let `U[a,c]` be upstream cache payload bytes, `P[a,c]`
provider upload bytes and `L[a,c]` full-build wall time under that canonical
definition; `u` is upstream-only and `b` is the later training-selected
best-static comparator. Every denominator below must be positive and every
required field observed, otherwise the whole cluster is invalid.

Selection cannot create an A/A series after seeing results. For any frozen
static or adaptive selector `pi` and label `d` in `A1,A2`, derive
`X[pi/d,c]` by running the **same frozen** TASK-128 replay interpreter on only
cluster c's label-d causal trace bundle. Static replay reads one base arm;
dynamic replay derives its ordered actions and provenance-attributed combined
outcome. Primary policy effects use
`pi/A1`; `pi/A2` only validates that selection. Selecting an unsupported arm in
any required opportunity cluster makes the policy ineligible and yields no
numeric clone. TASK-44 selects using A1 only; raw A2 values are withheld
from its fitting interface until the candidate and best-static hashes freeze.
The planning reader may use sealed A1/A2 solely for the preregistered centered
power/null eligibility test at fixed `N_required=100`; it cannot calculate a
different N or expose a directional result.

All sample quantiles use Hyndman-Fan type 7: for sorted `x[0..n-1]`,
`h=(n-1)*q`, interpolate linearly between `floor(h)` and `ceil(h)`. The exact
per-opportunity-stratum primary transforms are:

- **`upstream_only`:** its two indistinguishable labels give
  `aa_latency_s[u] = log(Q95(L[u/A2])/Q95(L[u/A1]))`. This is an equivalence/validity
  estimand, not a P2P score.
- **`consume_only`:** define `f[a,c]=U[a,c]/U[u,c]`.
  `benefit_s = mean_c(f[b,c]-f[a,c])`, an absolute upstream-egress fraction
  improvement over best-static. `egress_cut_s=mean_c(1-f[a,c])` is retained
  separately against upstream-only.
- **`lan_share`:**
  `benefit_s=log(Q95(L[b])/Q95(L[a]))`; positive is faster. Egress eligibility
  uses the same `egress_cut_s` as consume-only.
- **`public_share`:**
  `relief[a,s]=sum_c(U[u,c]-U[a,c])/sum_c(P[a,c])`, using signed avoided bytes
  and all provider upload bytes. Zero/negative delivery, nonpositive avoided
  bytes, or a nonpositive denominator is ineligible, never infinity.
  `benefit_s=log(relief[a,s]/relief[b,s])`. A public candidate requires a
  frozen eligible best-static with positive relief; if none exists,
  upstream-only remains the result rather than manufacturing a zero comparator.

For a base arm or a post-freeze policy `x`, define label-specific
`f[x/d,c]=U[x/d,c]/U[u/d,c]` and label-specific relief using the matching
upstream label. Its recorded A/A transforms are
`aa_egress_s[x]=mean_c(f[x/A1,c]-f[x/A2,c])`,
`aa_latency_s[x]=log(Q95(L[x/A2])/Q95(L[x/A1]))`, and
`aa_relief_s[x]=log(relief[x/A2,s]/relief[x/A1,s])`. Relief validation requires
both labels to have positive delivery/relief. A latency A/A cannot validate
egress or relief; every registered inference uses the selected policy's own
pre-existing label pair.

The profile statistics recomputed on every resample are deliberately
worst-stratum:

```text
profile_benefit[p] = min(s in O_p, benefit_s)
profile_egress_cut[p] = min(s in O_p, egress_cut_s)
profile_relief[public_share] = min(s in O_p, log(relief[a,s]))
profile_latency_guard[p] = max(s in O_p,
    log(Q95(L[a])/Q95(L[u])))
aa_min[p,metric] = min(s in O_p, aa_<metric>_s[a])
aa_max[p,metric] = max(s in O_p, aa_<metric>_s[a])
```

On the simultaneous intervals defined below, every P2P profile also requires
the upper `profile_latency_guard` endpoint to be at most `log(1.10)`.
Consume-only passes only when the
lower bound of `profile_benefit` is strictly greater than `0.05` and the lower
bound of `profile_egress_cut` is at least `0.20`. LAN-share uses a primary
margin `-log(0.95)` and the same `0.20` egress bite. Public-share uses a primary
margin `log(1.10)`, lower `profile_relief` bound at least `0`, and the `0.20`
egress bite. Reports may back-transform log effects to percentages, but
comparison happens on the registered transform.

S1, bounded S2, privacy and every frozen numeric budget must pass in every
mandatory observation in both `O_p` and `Q_p`; one actual violation rejects the
candidate. Every `Q_p` observation must reach its declared terminal oracle, so
a fault row cannot pass merely because it produced no numeric performance
effect. An unknown hard-constraint observation makes the profile
`METRIC_UNUSABLE`. An `evidenced_unsupported` arm cell has no numeric value. A
frozen policy may qualify a fault row only by executing and measuring its
predeclared supported alternate or upstream fallback; imputing or dropping the
row rejects it. Candidate and static comparator must both have valid measured
coverage of every required `O_p` cluster, and the comparator must pass all
applicable `Q_p` gates. Too few valid opportunity clusters or any missing
qualification row makes the whole profile unusable. The unsupported/no-go
record remains in the matrix in all cases.

### Paired trial validity and statistical contract

- A scenario cluster runs both labels of every supported base arm from independently reset
  requester state and identical workload, topology, provider placement and
  event schedule. Remove nonexecuting unsupported/not-applicable label slots,
  preserving their explicit records; for the remaining `k` execution labels in
  Stage-schema order, the Williams schedule
  starts with `row[0]=0`; for `j=1..k-1`,
  `row[j]=(j+1)/2` when j is odd and `row[j]=k-j/2` when j is even. It adds
  `i` to every value modulo k for rows `i=0..k-1` and, when k is odd, appends each
  row's reverse. One
  Fisher-Yates permutation from domain
  `arm-labels/<partition>/<profile>/<decision-or-qualification-id>/<supported-label-set-hash>`
  relabels the columns;
  cluster ordinal selects the schedule row modulo its length. Across completed
  cycles every execution label appears in every position equally and each predecessor is
  balanced. Check the at-most-one position-count difference separately within
  each exact supported-label-set group; labels evidenced unsupported in a row
  have no execution position. A violation makes the stratum unusable. Reusing
  one warm state or changing placement in a later label invalidates the whole
  cluster.
- Training seed, order, reset evidence, config/code/fixture/topology hashes and
  all raw observations are stored. A paired cluster is valid only when all
  required supported execution labels are valid. Unsupported labels remain
  nonnumeric with evidence and are not invalid partners. Invalid executed
  partners remain with reason; they are not
  counted as zero, rerun or replaced within that manifest; falling below N in
  an opportunity stratum or losing the sole observation of a qualification row
  makes the profile unusable. Exclusion codes are `HARNESS_START`,
  `STATE_RESET`, `ORACLE_MISSING`, `SHAPER_NOT_RECOVERED`,
  `PATH_NOT_CONFIRMED`, `RESOURCE_UNKNOWN`, and `EXTERNAL_OUTAGE`; the last is
  an unrelated undeclared dependency failure, never a planned outage row. Any
  other code requires a new experiment version.

#### Deterministic cluster bootstrap and multiplicity

The analysis seed for one profile/metric is exactly:

```text
HMAC-SHA256(
  key = partition seed_256,
  data = ASCII("nix-p2p-analysis-v1") || 0x00 ||
         ASCII(experiment_version) || 0x00 || ASCII(partition) || 0x00 ||
         ASCII(profile) || 0x00 || ASCII(metric_id) || 0x00 ||
         raw_bytes(SHA256(JCS(manifest))))
```

Use that digest as `seed_256` with the generator's exact HMAC stream and
`uniform()` algorithm. For bootstrap replicate `r` and stratum `s`, domain
`analysis/<profile>/<metric-id>/<r>/<decision-stratum-id>` samples `|C_s|`
cluster indexes with replacement. A draw carries the **whole paired cluster and
all arms**; individual requests, paths or arms are never resampled. Each of
10,000 replicates recomputes the per-stratum quantile/ratio, then the
cross-stratum minimum/maximum above. CI endpoints use the same type-7 quantile
of the bootstrap statistics.

The sole potential primary holdout family reserves exactly the three selectable
profile slots `consume_only`, `lan_share`, and `public_share`, with zero or one
frozen candidate in each. A no-candidate slot stays explicit and is never
reassigned or used to narrow the multiplicity denominator.
Bonferroni controls two-sided familywise alpha at `0.05`: each primary profile
uses the central `1-0.05/3 = 0.983333...` interval, with endpoints at `1/120`
and `119/120`. Taking the minimum/maximum inside every replicate makes the
strata a single intersection-union profile claim; no favorable stratum is
selected afterward. The upstream A/A gate uses the same interval level as a
shared validity precondition. Exploratory effects use labeled unadjusted 95%
intervals and can never select a default; adding another primary candidate or
hypothesis requires a new experiment version and holdout.

For every inferential metric, apply the A/A gate separately to the frozen
candidate, its best-static comparator and upstream where that transform is
used; failure of any required selected series rejects the comparison. The
entire simultaneous interval must be inside its own equivalence band: the lower
endpoint for `aa_min[p,metric]` must
be strictly above `-m_aa` and the upper endpoint for
`aa_max[p,metric]` strictly below `+m_aa`. `m_aa` is `log(1.05)` for the
latency transform in every profile, `0.05` for the additive egress transform in
every P2P profile, and `log(1.10)` for public log relief. Thus the separately
inferred 20-point egress eligibility, LAN latency objective and 1.10
normal-latency guard reuse a transform-specific A/A only after that narrower
band is satisfied. A point estimate, interval half-width, a latency-only A/A or
one-sided overlap is not enough. Missing/non-finite output fails closed.

Latency p50 and p99 remain descriptive. p95 is the registered decision
quantile, but the adjusted `1/120` tail is not authorized at a smaller sample
size: every p95-dependent objective, guard and A/A requires exactly 100 valid
independent clusters and an exact planning pass at n=100. One invalid cluster
therefore makes p95 inference unusable; it is never analyzed at achieved n=99.
A distribution-free two-sided 95% p99 interval needs at least 367 independent
valid clusters in every decision stratum; because v1 permits at most 100, p99
is always `METRIC_UNUSABLE` for inference and cannot reject or select a
candidate.

#### A/A-grounded N without a formula mismatch

Training is an exact two-phase flow. First, one `calibration` manifest freezes
the complete nuisance-row schedule and exactly 20 planned clusters (ordinals
`0..19`) in **each** opportunity decision stratum. Every supported base arm
already has both A1/A2 labels; there is no selected comparator or policy at
this point. All 20 terminal records remain. An invalid/failed execution label
is not replaced; because calibration requires 20 valid paired clusters across
every supported label, one invalid cluster yields `CALIBRATION_UNUSABLE` and no
extension or candidate claim for that experiment version. Unsupported base
arms keep their evidenced status and are not treated as missing calibration.
The calibration retains the **whole** joint vector for every base arm/label in
each cluster. Hash the complete manifest/results before planning. For every
catalog contrast `q=(pi,b)`, planning is one four-stratum procedure, never four
isolated arm or stratum screens:

1. Replay candidate selector `pi` independently on every cluster's A1 and A2
   causal trace bundles, deriving ordered actions and provenance-attributed
   outcomes; read best-static `b/A1,b/A2` and upstream `u/A1,u/A2` from the same
   joint cluster vectors. If replay or the comparator uses a capability-declared
   missing/unsupported label in any required opportunity context, mark only q
   `structurally_ineligible`; do not impute or invalidate another contrast.
   An actually invalid/missing calibration observation has already made the
   calibration globally unusable above and cannot become a contrast-specific
   mask bit.
2. Before any power/null injection, deterministically center away **all**
   observed direction for q. After selector application, form a planning-only
   shared coordinate graph containing every final fraction, latency series,
   avoided-byte/upload pair and candidate/comparator/upstream label pair with
   its original cluster index. Multiple estimand views of one raw field are
   aliases in that graph, never independent values. The joint solver subtracts
   observed additive offsets, divides out observed Q95 ratios, normalizes relief
   residuals around the symbolic reference `R=1`, and centers every required
   A1/A2 transform. Its algebraic residual statistic for every registered rule
   must be zero within the frozen tolerance before a target is applied; failure
   is `PLANNING_CENTERING_ERROR` for the entire artifact. It then immediately
   applies one numeric target case using the frozen injection contract above and
   materializes linked physical coordinates; no unlinked intermediate vector is
   simulated. Keeping the graph in one cluster vector preserves its empirical
   copula/covariance. Centering constants, coordinates and uncentered statistics
   remain sealed.
3. Freeze q's hypothesis-case inventory before simulation. It contains one
   **joint power alternative** with every performance/eligibility rule at its
   registered alternative and every A/A at zero. For each one-sided primary,
   egress, absolute-relief or latency-guard rule, add one least-favorable null
   case for each of the four possible boundary strata, leaving the other rules
   at the joint alternative. For every required candidate/comparator/upstream
   A/A transform, add both `-m_aa` and `+m_aa` cases for each possible boundary
   stratum, with all other A/A coordinates zero. Every value and injection
   equation comes from the catalog-bound `planning_injection_contract`; a case
   may only reference its hash, rule ID, boundary stratum and optional A/A sign.
   The generator records and hashes the complete set including the joint
   alternative; more than 64 makes the catalog fail its compute ceiling.
4. For every hypothesis case, first materialize q's linked coordinate vector
   with the frozen solver. A physical-domain failure marks only q
   `injection_domain_ineligible` and runs no simulation for it. Otherwise
   generate exactly 128 synthetic experiments at authoritative N=100. One
   synthetic experiment resamples 100 **whole** pilot
   cluster vectors within each of all four coarse strata. Each of its 10,000 inner
   bootstrap replicates again resamples whole cluster vectors in all four
   strata, applies `pi` and `b` to matching A1/A2 data, and recomputes the exact
   final candidate-vs-b benefit, upstream egress, absolute relief, p95 latency
   guard, selected candidate/comparator/upstream A/A, and cross-stratum
   min/max. Only then does it take type-7 `1/120,119/120` endpoints and execute
   the final conjunction of decision rules. Candidate/comparator covariance and
   arm-by-context mixing therefore remain inside every draw.
5. Set q `eligible_at_100` only when the exact Clopper-Pearson 95% lower bound
   on the joint-alternative decision power is at least `0.80` and every
   least-favorable boundary case has at most `floor(128/120)=1` false-positive
   decision. A missing case, nonfinite statistic or failed boundary marks only
   q `underpowered_at_100`. HMAC domains contain catalog/contrast/case hashes,
   synthetic index, bootstrap index and stratum, so scheduling cannot alter the
   mask. The full loop is bounded by the catalog-wide 15,728,640,000 evaluations
   declared above. No uncentered effect or direction participates in status.

TASK-44 later computes the deterministic A1 best-static winner from the
catalog's complete comparator set, then may score/nominate only a pre-enumerated
selector artifact whose exact `(selector_id,best_static_base_arm)` contrast is
`eligible_at_100`. It cannot choose a different comparator because that
contrast happened to pass, and cannot synthesize a threshold after seeing A1.
An ineligible contrast does not poison other catalog entries. If no eligible
contrast matches the A1-selected best-static comparator, that profile has no
candidate; upstream/no acceptable candidate remains the honest result.

After candidate and best-static hashes freeze, the separate TASK-129 validation
reader receives the sealed A1/A2 evidence and those hashes, replays the exact
selector independently on A2, and applies the preregistered training A/A and
hard-validation gates. It emits only a hashed `validated` or terminal
`validation_no_go` artifact directly to the TASK-123 freeze input; TASK-44 gets
no raw A2, residual, per-label statistic or refitting response. A no-go cannot
reopen A1 selection or nominate a runner-up, so the profile has no candidate for
that experiment version.

TASK-129 emits exactly one hashed `validation_slot_artifact` per selectable
profile. It is a closed tagged union. `validated` and `validation_no_go` require
`candidate_ref={presence:"present",sha256:...}` and
`comparator_ref={presence:"present",sha256:...}`. If TASK-44 produced no
candidate, the only legal object has `status="no_candidate"`,
`candidate_ref={presence:"absent",hash_status:"not_applicable"}` and
`comparator_ref={presence:"absent",hash_status:"not_applicable"}`, plus the
reason code `no_capable_best_static`, `no_eligible_matching_contrast`, or
`a1_selection_unusable`; candidate/comparator hash keys are forbidden. Its
`a2_validation_status` is explicitly `not_applicable`. All variants record
`validation_slot_artifact_hash=SHA256(JCS(validation_slot_artifact))`. TASK-123
runs a holdout profile only for `validated`; `validation_no_go` and
`no_candidate` remain witnessed terminal slots and cannot be reassigned or used
to narrow the three-profile multiplicity family.

The one `extension` manifest receives and verifies the complete calibration and
planning artifacts named by its tagged input. It uses the same
experiment/partition seed and catalog/capability/target hashes, plus the
successor exclusion-registry head that contains every calibration concrete ID.
It contains exactly the precomputed ordinals `20..99` for each stratum and
records their ordered concrete IDs and hashes before execution. The union hash
of calibration and extension is the training manifest hash. Invalid extension
clusters remain and are never replaced; fewer than 100 valid clusters makes
that stratum unusable. The fixed holdout plan verifies the complete training
planning artifact and imports its frozen global `N_required=100`, catalog and
eligibility-mask hashes. It generates one manifest after reveal and does not
recalibrate on holdout.

This bounded planning asks whether the exact selector-derived joint decision is
recognizable at N=100. Candidate direction is not an input, and later
best-static/adaptive selection cannot introduce an uncataloged or underpowered
contrast. The final evidence still uses the exact 10,000-resample cross-stratum
procedure and selected policy A/A gates above.
TASK-122 may parallelize or memoize identical deterministic draws, but may not
change the catalog, counts, estimator, ordinals or manifest hashes without a new
experiment version.

Bottleneck isolation is mandatory. Injected RTT must be recovered within
`max(2 ms, 10%)`; bandwidth within **10%**; loss within **25 basis points**;
jitter p95 within `max(2 ms, 20%)`; the unshaped rate control must be at least
**2×** the shaped cap. Nix knob readback and measured concurrency must match,
NAT/relay path must be observed, and CPU/disk saturation must be reported. A
neutralized or non-binding shaper makes the row invalid, never “fast”.

Stage A is diagnostic but follows the same pairing, whole-cluster resampling,
A/A and invalid-run rules with labeled unadjusted 95% intervals; it
cannot make a primary selection. Stage B must use TASK-52's hedge-aware
`net-upstream-egress-v3`; Stage A, which forbids hedging, may use frozen
`net-upstream-egress-v2`. Reports always carry the exact counting-rule version.

### Metric schema: distinct quantities, explicit units

No report may derive one byte quantity from another merely because a raw fixture
makes their values coincide. `_bytes_compressed_wire` means octets of the named
wire representation (`Compression:none` is a valid representation); it is not
NarSize. `_bytes_uncompressed_nar`, `_bytes_ram`, and `_bytes_ondisk` retain the
existing `profile_p2p.py` meanings. At minimum every measured cell records:

| Field | Meaning / unit |
|---|---|
| `upstream_cache_payload_bytes_compressed_wire` | Testproxy/cache-boundary NAR body bytes, FileSize representation, per the named counting rule. |
| `peer_socket_total_bytes_compressed_wire` | All octets actually observed on peer sockets, separately per requester/provider, direction, transport and codec. Never substituted for cache egress. |
| `peer_socket_payload_bytes_compressed_wire`, `peer_socket_protocol_control_bytes_compressed_wire` | The total's payload and transfer-protocol/control decomposition; missing framing attribution is unknown, not silently assigned to payload. |
| `payload_bytes_uncompressed_nar` | Signed NarSize / raw NAR length successfully delivered. It is not added to either wire-byte field. |
| `hedge_waste_upstream_bytes_compressed_wire`, `hedge_waste_peer_bytes_compressed_wire` | Losing hedge bytes by source, attributed by request provenance. |
| `prefetch_waste_peer_bytes_compressed_wire`, `prefetch_waste_upstream_bytes_compressed_wire` | Prefetched bytes not consumed by the build, by source. |
| `discovery_control_bytes_compressed_wire` | Tracker/DHT/Mainline/hold-query/node-discovery/relay control octets, broken down by mechanism and direction. |
| `provider_upload_bytes_compressed_wire` | All provider peer-socket upload octets; payload and protocol/control subfields remain separate. |
| `full_build_wall_ns`, `nar_ttfb_ns`, `bootstrap_ns`, `node_resolve_ns`, `content_resolve_ns` | Monotonic-clock durations; bootstrap, node/address resolve, content resolve, transfer TTFB and full build never collapse into one number. |
| `requester_cpu_ns`, `provider_cpu_ns` | Process CPU time; report CPU-ns per `payload_bytes_uncompressed_nar` only as an explicitly named ratio. |
| `rss_hwm_bytes_ram`, `rss_idle_60s_bytes_ram` | Per-node high-water and post-60-second residency, not interchangeable point samples. |
| `disk_apparent_bytes_ondisk`, `disk_allocated_bytes_ondisk` | Per-node state/metadata/content footprint; both reported. |
| `open_fds_count`, `success_count`, `failure_count`, `fallback_count`, `serve_decline_count` | Integer counts with denominators; missing is unknown, never zero. |
| `confirmed_network_path` | Closed enum `upstream`, `lan_direct`, `direct`, `hole_punched`, `relay`, `unsupported`, confirmed from trace/socket evidence. |
| `fallback_reason`, `cell_status`, `invalid_reason` | Closed, versioned reason codes; success plus fallback is distinguishable from pure peer success. |

Compression ratio is a named ratio of two separately retained fields. Cache
wire bytes, peer socket bytes, NarSize, discovery/control, waste and provider
upload remain available independently in raw results even when a profile score
uses two of them.

### Discovery privacy and participation observables

Configuration narration is insufficient. Per mechanism, a boundary trace or
packet/application event log records:

- local discovery enabled, node/address source and content-discovery source;
- count and restricted-capture SHA-256 of every published key/record, its schema
  version, publishability class and run-keyed HMAC token (normal reports do not
  export StorePath/NarHash); published record wire bytes remain in the
  access-controlled audit artifact;
- every query recipient class/count, the queried-key token count, and whether
  requester IP and full/partial NodeId were exposed to LAN peers, tracker, DNS,
  relay, DHT/Mainline nodes, bootstrap seeds or payload peers;
- exact configured tracker/DNS/relay/Mainline/bootstrap dependencies and which
  were contacted; dependency outage is `unavailable`, not an empty `miss`;
- `client_only`, inbound listener/server participation, publication enabled,
  serving enabled, payload bytes served, and lookup enabled as independent
  booleans/counters.

The consume-only assertion is therefore three assertions: **zero publication**,
**zero serving**, and a separately measured lookup-leakage result. It must never
claim “private” merely because the first two are zero. `lan_share` additionally
asserts zero packets to public dependencies. `public_share` requires explicit
preflight and proves TASK-102 blocked every non-signed-public key. Absence of a
capture/recipient oracle invalidates the privacy cell.

### Anti-vacuity matrix

Every supported arm must demonstrate the negative control appropriate to its
layer before its positive result is publishable:

| Bite | Required observable failure/change |
|---|---|
| Disable the selected discovery mechanism(s) from identical fresh state | Peer provider bytes become 0 and upstream payload egress returns to the upstream-only amount; a warm Nix store/cache is not allowed to satisfy the build. |
| Kill the provider after a positive result, before dial and again mid-body | Named unavailable/timeout, bounded S2 fallback and successful S1 build; no unbounded hang and no false clean miss. |
| Corrupt/truncate provider bytes (and corrupt upstream in its control arm) | BLAKE3 gate 1 and/or Nix signature/NarHash gate 2 rejects; the corrupted path is never installed. Neutralizing the gate makes the bite fail. |
| Neutralize delay/rate/loss/jitter shaping | Recovery checks above fail and the row becomes invalid; configuration values alone cannot keep it green. |
| Feed a Stage-A artifact to TASK-44 | Closed-schema rejection `STAGE_A_POLICY_INPUT_FORBIDDEN` before fitting; changing a filename must not bypass it. |
| Call any pre-TASK-123 holdout API/namespace | `HOLDOUT_FORBIDDEN_BEFORE_FREEZE`, no scenario object/file emitted, and the attempted run is invalid with an audit event. |

### Sealed holdout generation and reveal protocol

Only `development` and `training` partitions can be materialized before
TASK-123. This document freezes the **procedure and distribution only**. It
contains no exact holdout ID, seed, workload selection, holder placement,
network endpoint or topology; none may exist elsewhere yet.

The generator API requires a typed `HoldoutRevealPermit` for
`partition=holdout`. Before TASK-123 that type can be verified but no permit can
be issued. TASK-88, TASK-125, TASK-80, TASK-122, TASK-44 and TASK-129 runners compile/run
with development/training capabilities only. A request to generate, enumerate,
open or infer a holdout namespace fails atomically with
`HOLDOUT_FORBIDDEN_BEFORE_FREEZE` before a path, ID or PRNG is created; the
attempt is audit-logged and invalidates that run. TASK-128 likewise contains no
holdout material while freezing interpreter semantics.

#### Roles and append-only registry

- The **freeze custodian** (TASK-123) assembles the freeze record and executes
  the already-frozen generator/interpreter. The custodian cannot contribute or
  replace entropy and cannot own a candidate implementation.
- At least **two entropy witnesses**, independent of the custodian and of every
  candidate owner, each control their own signing key and append-only receipt
  location. Witness identities/keys are named in the freeze record before any
  commitment. A witness supplies randomness but cannot run, tune or interpret
  the experiment.
- The **verdict custodian** verifies the immutable results and applies the
  preregistered rules. It may be the TASK-123 freeze custodian because the
  generator and interpretation are already hashed, but it cannot edit either.

`holdout-registry-v1` is a content-addressed, fast-forward-only Git sequence,
kept beside the code rather than in a mutable database. Every JCS entry contains
`previous_entry_hash`; publication uses compare-and-swap against a protected
registry ref. Each entropy witness signs and independently retains the new head
hash, so rewriting only the repository copy is detectable. The registry starts
with hashes of every development/training manifest and every
`concrete_tuple_id`.
It retains every reservation, commitment, reveal, generated manifest, selected
tuple and terminal outcome from **all** later revealed holdouts, including
failed/invalid attempts and superseded experiment versions. A missing previous
entry, signature or independent receipt is a hard stop.

There is exactly one reserved attempt for an `experiment_version`; registry CAS
rejects a second reservation even if the freeze hash differs. The reservation
is the point of no return. A process crash, witness refusal, invalid reveal,
catalog exhaustion, generator failure or infrastructure failure after it
consumes that version's holdout and produces a failed/`METRIC_UNUSABLE` verdict,
not a fresh seed. A new attempt requires a new experiment version, fresh
training/fitting and a newly frozen candidate.

#### Freeze, commit/reveal and exact seed

TASK-123 performs the one reveal in this order:

1. Create a JCS `freeze_record` containing hashes for experiment/generator and
   analysis contracts, generator/interpreter code and golden traces, Nix closure
   and container images, workload/network catalogs, complete development and
   training manifests/results, the execution-label contract, complete
   planning-contrast catalog, causal-trace schema/replay interpreter, centered
   planning artifact, released eligibility mask, fixed-class training-parity
   results and exactly one hashed `validation_slot_artifact` for each selectable
   profile, the current
   exclusion-registry head, all profile
   rules/margins/budgets and `N_required`. A `validated` or
   `validation_no_go` slot requires its frozen candidate/comparator hashes; a
   `no_candidate` slot requires the explicit absent/not-applicable references
   above and TASK-123 must not demand or invent either hash. Append a signed
   reservation containing `freeze_hash=SHA256(JCS(freeze_record))`, the witness
   IDs/keys and previous registry head. Any absent hash or bytewise catalog/mask
   mismatch aborts before reservation; after reservation it consumes the attempt.
2. Each witness independently draws a 32-byte OS-CSPRNG nonce. For witness `w`,
   append and sign only this lowercase-hex commitment:

   ```text
   SHA256(JCS({
     "domain":"nix-p2p-holdout-commit-v1",
     "experiment_version": experiment_version,
     "freeze_hash": freeze_hash,
     "witness_id": w,
     "nonce_256": lowercase_hex(nonce)
   }))
   ```

   Every commitment and independent receipt must exist before any nonce is
   revealed. A duplicate witness, changed key, early reveal or missing receipt
   consumes the attempt as invalid.
3. Witnesses reveal their nonces and signatures. Verify each commitment, sort
   the records by unsigned UTF-8 `witness_id`, reject duplicates, and derive the
   only holdout seed as:

   ```text
   seed_256 = SHA256(JCS({
     "domain":"nix-p2p-holdout-seed-v1",
     "experiment_version": experiment_version,
     "freeze_hash": freeze_hash,
     "reservation_hash": SHA256(JCS(reservation)),
     "witnesses":[
       {"witness_id": id, "commitment": hex_digest,
        "nonce_256": lowercase_hex(nonce)}, ...
     ]
   }))
   ```

   This post-freeze derivation is the first moment the seed exists. No witness
   can choose a nonce after seeing another's reveal; withholding one cannot
   induce a retry.
4. Build the exclusion input from the witnessed registry head: it is the union
   of every `concrete_tuple_id` in development, training and **all previously
   revealed holdouts**, plus the IDs already selected earlier in this manifest.
   Run the exact without-replacement generator. Any duplicate within the
   manifest or match in that immutable set is `HOLDOUT_DUPLICATE`; exhaustion
   records the finite counts and consumes the attempt without substituting,
   reusing or relaxing a stratum.
5. There is no reusable permit file. Inside one compare-and-swap transaction,
   TASK-123 mints a permit bound to `freeze_hash`, `reservation_hash`, seed hash,
   registry head and exact generator binary; the generator returns the complete
   manifest to that transaction, which validates it and atomically appends both
   `permit_consumed` and the manifest bytes/hash to the registry. Neither may
   become visible alone. A crash or CAS loss before publication still leaves the
   witnessed reservation/reveals and consumes the attempt; it does not authorize
   regeneration. On success, byte-for-byte manifest copies may be recovered by
   hash, but a second generation call is forbidden.

#### Execution has no reroll path

Manifest scenarios execute in sorted `scenario_id` order. The append-only state
machine is `unstarted -> started -> terminal`; `terminal` is one of `measured`,
`evidenced_unsupported`, `invalid`, or `failed`. A scenario marked `started`
before a harness/process/host crash becomes terminal `invalid` with the exact
reason and is never rerun. Execution may resume only the still-`unstarted` rows
from the same manifest with identical hashes. Invalid partners remain and the
profile becomes unusable if N falls short; there is no replacement ordinal,
seed, topology, workload or arm order in holdout. Planned dead-provider and
dependency-outage rows remain ordinary test rows, not retry permission.

Only a `validated` slot materializes candidate execution rows. A
`validation_no_go` or `no_candidate` slot is copied into manifest metadata with
zero candidate executions; that is its witnessed terminal result, not generator
failure. Each validated frozen primary is compared with upstream-only and
best-static under its one profile rule and the unchanged three-profile family.
Exploratory output is
descriptive and cannot become a default. The manifest, raw results, audit
events, analysis output and terminal verdict are appended and independently
witnessed whether the result is a winner, upstream-only, no candidate, invalid
or `METRIC_UNUSABLE`.

Any objective, constraint, generator/distribution, profile or interpretation
change after Stage-B training begins bumps the experiment version, restarts
training/fitting and requires a fresh never-generated holdout. Any code,
interpreter, candidate or comparator change after the reveal freeze does the
same. The failed/no-candidate/upstream-only verdict remains recorded; TASK-123
never repairs a result by tuning on its holdout.

### Artifact and decision boundaries

| Owner | May produce | Must not do |
|---|---|---|
| TASK-114 assignee; repository product owner | Experimental contract/generator version; retained authority over later production intent/defaults | Claim new production approval, materialize holdout or choose a backend |
| TASK-88 | Iroh-only development/training reference | Make a cross-backend/default claim or read holdout |
| TASK-117/TASK-121 | BitTorrent identity and compressed supported/no-go evidence | Impute an unsupported cell or select policy |
| TASK-125 | Stage-A `diagnostic-tournament-v1` artifact | Emit candidate/score/default fields or read holdout |
| TASK-122 | Stage-B `policy-training-v1` A1/A2 evidence, all invalid/unsupported rows, fixed-class parity results and centered joint eligibility mask; raw A2 remains sealed for TASK-129 | Expose raw A2 or directional planning detail to TASK-44, change the frozen catalog, choose a default, fit on holdout or omit losing cells |
| TASK-128 | Pre-calibration causal-trace schema/replay interpreter, complete exact planning-contrast/injection catalog and development parity traces | Tune/add a selector, numeric target or parameter after calibration starts, embed a default, or include holdout data |
| TASK-44 | Deterministic A1-only best-static and at most one exact eligible catalog artifact/profile; its frozen output is later validated by the TASK-129 A2 reader | Read raw A2 or receive validation feedback while fitting/selecting, synthesize parameters, swap comparators to obtain eligibility, alter a selector after A2 validation, file a product implementation/default task or access holdout |
| TASK-129 | Post-fit sealed-A2 validation and exactly one hashed validated/validation-no-go/no-candidate slot artifact per selectable profile | Return A2 feedback for refitting, nominate a runner-up, fabricate hashes in an absent slot, narrow the three-profile family, generate holdout material or execute a no-go/no-candidate slot |
| TASK-123 freeze/verdict custodian + independent entropy witnesses | One reserved commit/reveal, atomic permit/manifest, unchanged execution and signed/versioned verdict | Reroll/reuse, contribute custodian entropy, tune, promote an exploratory result, or hide no-go |
| TASK-124 | Post-verdict production/pilot re-plan | Reinterpret or overwrite TASK-123 evidence |

The registry only dispatches an explicitly selected mechanism/offer from an
artifact. No schema, generator, fitter or interpreter may encode Iroh-first,
BitTorrent-first, cheapest-first or “winner must exist.”
