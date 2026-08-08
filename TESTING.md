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

Narinfo byte-fidelity policy (wave 1): the daemon and its cache
treat narinfo as **verbatim bytes** end to end — the transport-field
rewrite allowlist exists in code and is **empty**; wave 2 (raw-NAR
p2p) will populate it (`URL`/`Compression`/`FileHash`/`FileSize`
only — never the signed fields). A property test asserts arbitrary
well-formed narinfos (unknown fields, odd ordering, multiple `Sig:`)
pass through byte-identical, including across a daemon restart.

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
