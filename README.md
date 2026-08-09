# nix-p2p

> **Work in progress — nothing here is stable.** The name "nix-p2p" is
> tentative. Peer *transfer* works; peer *discovery* does not exist yet — the
> DHT mechanism and its key derivation are still open design work, and nodes
> currently learn about each other from the command line. The claim wire
> schema and the addressed unit are frozen; everything else may change.

A decentralized Nix binary cache: a localhost substituter daemon that serves
the standard binary-cache HTTP API, passes signed metadata through from
cache.nixos.org, and fetches NAR payloads from peers over iroh, hash-verified
against the signed NarHash. An unmodified Nix client re-verifies signature and
NarHash itself, so the daemon and all peers stay outside the trusted computing
base.

The goal is bandwidth offload for cache.nixos.org — decentralizing the bytes,
not the trust. Metadata and signatures remain the cache's job.

## Status

**Wave 1 complete; wave 2a (peer transfer) working; discovery not started.**

A real `nix build` is served from a peer over iroh, across container network
namespaces, verified twice: BLAKE3/bao on arrival and Nix's own signature +
NarHash check. A corrupt peer fails the build rather than poisoning the store;
a dead peer falls back to upstream.

What works:

- Transparent substituter proxy — `nix-cache-info` semantics, narinfo disk
  cache, NAR correlation catalog, multi-daemon chains, NixOS module + VM test.
- iroh whole-NAR transport behind `NarSource`, with a frozen claim wire schema,
  an announce-on-demand availability index that never allows enumeration, and a
  conservative safety envelope (dial/idle/fetch timeouts, streaming NarSize
  abort).
- A measurement and profiling stack: frozen egress counting rule, regression
  fitter with model selection and confidence intervals, and a p2p profiler
  covering RAM, disk, latency, throughput and speedup.

What does **not** work yet — the honest headline:

- **Peers cannot find each other.** There is no DHT and no gossip. Nodes
  connect because `--iroh-peer` and `--p2p-claim` were passed on the command
  line, so today this decentralizes *transfer*, not *discovery*.
- A node cannot serve the store it advertises: the availability index answers
  for every local path, but the provider only serves what was eagerly seeded.
- No serve-side size bound, no multi-holder failover, no streaming (the whole
  NAR is buffered), and no policies at all — no hedge, prefetch, announce
  budget, or leech mode.
- Nothing has run on a real network: no NAT, no relay, no residential uplink.

Measured on the container testbed (single host, so read the caveats):

| Measurement | Result |
|---|---|
| Upstream NAR-payload egress offloaded | **1.00** (all of it) |
| vs. a WAN-shaped upstream (50 ms RTT, 20 MiB/s) | peer path **9.3× faster** |
| vs. a zero-latency loopback upstream | peer path **3.6× slower** |
| Holder RAM per byte served | **2.00 B/B** (its blob store holds 1.00) |

The two speedup figures are the same system against different upstreams — the
ranking flips, so neither is quotable alone. The 9.3× magnitude is linear in
the bandwidth cap; the *flip* is the robust part. `TESTING.md` forbids claiming
emergent network effects from single-host sweeps, and the peer link is still
loopback, so peer-side numbers are upper bounds.

See `PRD.md` for the full design record and `backlog/` for task state.

## Architecture

Two strictly separated Rust binaries (no shared crates, enforced by
`just independence`):

- **`daemon/`** — the product. Modular; all capability behind two traits:
  `NarinfoSource` (narinfo lookup: upstream HTTP, disk cache; p2p relay in v2)
  and `NarSource` (resolve a typed `NarKey` — the signed NarHash on the normal
  path — to a verified NAR stream). The seam carries the exact identity a
  DHT/claims index resolves, so the p2p swap needs no HTTP-layer change.
  The iroh transport plugs in here as one `NarSource` implementation behind a
  `Transport` trait, with a `TransportRegistry` dispatching on the transport
  tag each claim offer carries — so a second transport (BitTorrent) is a new
  implementation, not a network fork.
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
- **S6 peer-served build**: a real `nix build` whose NAR came from a peer, with
  the bytes counted at the *provider* (the fetching daemon's own claim to have
  used a peer is untrusted narration), plus a peers-off contrast arm proving
  the upstream channel was live.
- **S9 models bite**: the profiler's fits are proven by mutation — a known
  superlinear workload must be classified superlinear and must not fit as
  linear, and extrapolations are structurally labelled model output, never
  measurement.

Two frozen surfaces, deep-reviewed because changing them splits the network:
the **claim wire schema** and the **addressed unit** (`RawNarV1` — the exact
`nix-store --dump` bytes, keyed by plain BLAKE3, which equals the iroh-blobs
hash by construction). DHT key derivation is the third and is not settled.

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
just e2e         # podman-pod scenario suite (needs rootless podman)
just e2e-vm      # NixOS VM test (needs /dev/kvm)
just measure     # egress/latency/gap measurement report
just scale-sweep # scaling sweep + regression fit (clients, chain depth, knobs)
just profile     # p2p RAM/disk/latency/throughput/speedup report (peer swarm)
just journey     # J1 operator journey
```

These are hours, not minutes: `just profile` runs a peer swarm, a NAR-size
axis, a concurrency axis and both upstream conditions.

`nix flake check` re-runs build/lint/test in the sandbox for CI.

## Documents

- `PRD.md` — accepted design record: decisions, irreversibility map, risks,
  wave-2 scope.
- `TESTING.md` — what good and bad observably mean; the oracles the gates
  enforce.
- `backlog/` — task tracker (use the `backlog` CLI, not direct file edits).
- `figures/` — architecture overviews: `fig-arch-1` (wave-1 daemon seams),
  `fig-arch-2` (test harness), `fig-arch-3` (wave-2 target — the transport
  half is now built, the discovery half is not).
  The `fig-candidate-*` originals predate the settled design and are stale
  until task-17 revises them.

## References

Prior art and the problem this exists to address. Both threads are from June
2023 and neither has produced a shipped implementation, which is part of why
this project is deliberately measurement-first.

- [Peer-to-peer binary cache RFC/working group/poll](https://discourse.nixos.org/t/peer-to-peer-binary-cache-rfc-working-group-poll/29568)
  (NixOS Discourse, Nabile-Rahmani) — polls the community on a decentralized
  binary cache, motivated by CDN costs cited in the thread as exceeding
  €50k/month, and sketches a `services.nix-serve-p2p` where users seed. The
  discussion is largely BitTorrent-vs-IPFS, and the objections raised there —
  availability of the long tail, untrusted peers, sharding and rebalancing —
  are the ones this design has to answer rather than assume away.
- [Migration of S3 bucket payments to the Foundation](https://github.com/NixOS/foundation/issues/86)
  (NixOS/foundation, refroni) — the storage-cost side of the same problem,
  cataloguing ~11 alternatives from distributed stores (Tahoe-LAFS, Garage,
  Ceph) to decentralized mirror networks and outright deletion.

Where this project differs from most of those proposals: it decentralizes the
**bytes only** and leaves trust exactly where it is. cache.nixos.org keeps
signing narinfos, an unmodified Nix client re-verifies the signature and
NarHash, and every peer stays outside the trusted computing base — so a hostile
or broken peer costs a retry, never a bad store path. It also targets
*bandwidth* rather than storage: `PRD.md` treats the long tail as a case where
a CDN is strong and swarms are weak, and does not pretend otherwise. Whether
peers actually beat a CDN as a byte source is treated as a thesis to measure,
not a premise — see the numbers and their caveats under Status.

## License

MIT — see `LICENSE`.
