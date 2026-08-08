# nix-p2p

A decentralized Nix binary cache: a localhost substituter daemon that serves
the standard binary-cache HTTP API, passes signed metadata through from
cache.nixos.org, and (wave 2) fetches NAR payloads from a p2p swarm,
hash-verified against the signed NarHash. An unmodified Nix client re-verifies
signature and NarHash itself, so the daemon and all peers stay outside the
trusted computing base.

The goal is bandwidth offload for cache.nixos.org — decentralizing the bytes,
not the trust. Metadata and signatures remain the cache's job.

## Status

**Wave 1 complete, wave 2 (p2p) in planning.** The daemon today is a
transparent proxy: correct `nix-cache-info` semantics, narinfo disk cache,
NAR correlation catalog, and a measurement instrument — no peer transfer yet.
The `NarSource`/`NarinfoSource` trait seams it grows behind are frozen; wave 2
adds an iroh whole-NAR transport (and later BitTorrent) as new implementations,
not serving-layer changes. See `PRD.md` for the full design record and
`backlog/` for task state.

## Architecture

Two strictly separated Rust binaries (no shared crates, enforced by
`just independence`):

- **`daemon/`** — the product. Modular; all capability behind two traits:
  `NarinfoSource` (narinfo lookup: upstream HTTP, disk cache; p2p relay in v2)
  and `NarSource` (resolve a typed `NarKey` — the signed NarHash on the normal
  path — to a verified NAR stream). The seam carries the exact identity a
  DHT/claims index resolves, so the p2p swap needs no HTTP-layer change.
- **`testproxy/`** — the permanent test fixture. A simple caching proxy that
  fronts the upstream (real or mock) and owns all fault injection: latency,
  errors, corruption, throttling. Adversarial-upstream logic never lives in
  the product. It also shields cache.nixos.org from test load.

Supporting pieces:

- **`fixtures/`** — a signed mock binary cache, generated deterministically
  and published via atomic generation flips (`scripts/gen-fixtures.py`).
- **`scripts/`** — the e2e harness (rootless podman pods:
  client → daemon → testproxy → mock origin), the measurement instrument, and
  fail-closed policy gates.
- **`nixos/`** — NixOS module plus a 3-VM test (real nix-daemon + systemd).

Key invariants, tested end-to-end (see `TESTING.md`):

- **S1 byte-identity**: paths substituted through the daemon chain are
  bit-identical to upstream-served ones (NarHash gate).
- **S2 additive invariant**: with the daemon dead, killed mid-transfer, or
  erroring, `nix build` still succeeds via substituter fallback and the local
  store is never corrupted.
- **S3 honest measurement**: net upstream egress with-daemon vs without, under
  a frozen counting rule (`scripts/MEASUREMENT_COUNTING_RULE.md`). Gross
  "bytes from peers" is not the metric.
- **S4 latency bound**: p95 build wall-clock with the daemon ≤ 110% of
  daemon-off.

## Development

Everything runs inside the pinned flake devshell; the Justfile refuses any
other toolchain.

```sh
nix develop
just            # list gates
```

Fast tier (seconds):

```sh
just build      # cargo build, all targets
just lint       # clippy -D warnings, rustfmt, ruff, source-policy guards
just test       # cargo test + fixture gate + measurement self-test
```

Slow tier (minutes, containers/VMs; not part of the fast loop):

```sh
just e2e        # podman-pod scenario suite (needs rootless podman)
just e2e-vm     # NixOS VM test (needs /dev/kvm)
just measure    # egress/latency/gap measurement report
just journey    # J1 operator journey
```

`nix flake check` re-runs build/lint/test in the sandbox for CI.

## Documents

- `PRD.md` — accepted design record: decisions, irreversibility map, risks,
  wave-2 scope.
- `TESTING.md` — what good and bad observably mean; the oracles the gates
  enforce.
- `backlog/` — task tracker (use the `backlog` CLI, not direct file edits).
- `figures/` — architecture overviews: `fig-arch-1` (wave-1 daemon seams),
  `fig-arch-2` (test harness), `fig-arch-3` (wave-2 target, planned).
  The `fig-candidate-*` originals predate the settled design and are stale
  until task-17 revises them.
