# nix-p2p

> **Work in progress — nothing here is stable.** The name "nix-p2p" is
> tentative. Peer *transfer* works; peer *discovery* does not — the query
> protocol exists and is measured, but the DHT mechanism and its key derivation
> are still open design work, and nodes currently learn about each other from
> the command line. The claim wire schema and the addressed unit are frozen;
> everything else may change.

A decentralized Nix binary cache: a localhost substituter daemon that serves
the standard binary-cache HTTP API, passes signed metadata through from an
upstream cache, and fetches NAR payloads from peers over iroh, hash-verified
against the signed NarHash. An unmodified Nix client re-verifies signature and
NarHash itself, so the daemon and all peers stay outside the trusted computing
base.

The goal is bandwidth offload for cache.nixos.org — decentralizing the bytes,
not the trust. Metadata and signatures remain the cache's job.

**It has never been pointed at the real cache.nixos.org.** The daemon speaks
plain HTTP only and rejects an `https://` upstream outright
(`daemon/src/upstream.rs`), so every result below was produced against a local
mock cache behind a test proxy. Fronting the real thing needs TLS on both
(tracked as tasks 22 and 24).

## Status

**Wave 1 complete; wave 2a (peer transfer) working; discovery is a protocol
without a mechanism.**

A real `nix build` is served from a peer over iroh, across container network
namespaces, verified twice: BLAKE3/bao on arrival and Nix's own signature +
NarHash check. A corrupt peer fails the build rather than poisoning the store;
a dead peer falls back to upstream.

What works:

- Transparent substituter proxy — `nix-cache-info` semantics, narinfo disk
  cache, NAR correlation catalog, multi-daemon chains, NixOS module + VM test.
- iroh whole-NAR transport behind `NarSource`, with a frozen claim wire schema,
  an announce-on-demand availability index that answers yes/no and has no
  listing call at all (enumeration is prevented by construction, not by a
  filter), and a conservative safety envelope (dial/idle/fetch timeouts,
  streaming NarSize abort).
- A **hold-query protocol**, single-key and batched: one bounded message asks a
  peer about a whole closure and gets back positional yes/nos, so discovery
  costs a round trip per peer rather than per NAR. It is still not a listing —
  the answer names nothing the asker did not ask about.
- A **regenerate-on-demand supply model**: a node announces what it can serve
  without holding it, regenerates on request inside an explicit serve budget
  (max NAR size, max concurrent bytes, max serve duration), and releases
  afterwards. What it answers "yes" about and what it can actually serve are
  the same set — proven where both sets exist in one process; no node has yet
  answered another's hold-query over a network, so this is not yet demonstrated
  between two hosts.
- A measurement and profiling stack: frozen egress counting rule, regression
  fitter with model selection and confidence intervals, and a p2p profiler
  covering RAM, disk, latency, throughput and speedup.

What does **not** work yet — the honest headline:

- **Peers cannot find each other.** There is no DHT and no gossip. Nodes
  connect because `--iroh-peer` and `--p2p-claim` were passed on the command
  line, so today this decentralizes *transfer*, not *discovery*. The hold-query
  that will do the asking runs only over an in-process rendezvous: nothing
  carries it over iroh yet, and the serving path does not call it.
- A node supplies from raw-NAR *files* it was pointed at, not from
  `/nix/store`. The index-backed supplier that dumps real store paths exists
  and is tested, but nothing wires it into the daemon yet.
- No multi-holder failover, no streaming (the fetching side still buffers the
  whole NAR), and no policies at all — no hedge, prefetch, announce budget, or
  leech mode.
- A published claim does not survive a restart: the digest→path binding is
  in-memory, so a peer holding an old claim gets a clean decline until some
  hold-query re-derives it.
- Nothing has run on a real network: no NAT, no relay, no residential uplink.

Measured on the container testbed (single host, so read the caveats):

| Measurement | Result |
|---|---|
| Upstream NAR-payload egress offloaded | **1.00**, both conditions — but see below |
| vs. a WAN-shaped upstream (50 ms RTT, 20 MiB/s) | peer path 6.1× faster — **withdrawn, see below** |
| vs. a zero-latency loopback upstream | peer path 4.0× slower — **withdrawn, see below** |
| Holder RAM per byte served | **1.018 B/B** [1.007 .. 1.028] |
| Holder RAM held per byte *announced*, at rest | **0.00** |
| Holder RAM per concurrent serve | **38.4 MB** [38.0 .. 38.8] |

Every figure above is from one full profiling run at commit `63caca2`, and the
transport and discovery code has changed since without being re-measured — read
them as of that commit, not of `HEAD`. Holder RAM is a slope fitted over five
NAR sizes with a 95% confidence interval, not a single-point ratio; before the
supply model it was **2.004 [2.000 .. 2.009]** with the blob store holding 1.00
bytes per byte announced *forever*.

**The offload figure is steady-state by construction and must not be read as a
swarm result.** It is measured with a holder pre-seeded with exactly what the
client asks for — one peer that already has it. A *cold* swarm cannot offload
anything: at t=0 nobody holds anything, every path comes from upstream, and
offload is ~0. What a real swarm achieves is a curve between those, and this
project has not measured it (tasks 87/88). Announce-after-fetch, the mechanism
that would let a swarm warm up at all, is not implemented either (task 77).

**Both speedup figures are withdrawn.** They were measured against a fixture
upstream that serves NAR data *uncompressed*, exactly as our peers do. The real
cache.nixos.org serves xz: measured on 20 signed paths over 10 MiB from the live
cache, `FileSize/NarSize` is **0.278** (median 0.216). A peer therefore moves
about **3.6× the bytes** upstream moves for the same store path, and would need
to sustain roughly **75 MB/s (604 Mbit/s) upload just to break even** — before
any discovery cost. A home uplink is 1.25–5 MB/s.

So the honest position on speed is: **unknown, and probably unfavourable for a
remote peer until the peer link is compressed.** The fix does not touch anything
frozen (compression is an unsigned transport field, and the addressed unit stays
the raw NAR), it just has not been built yet. The numbers above will be
re-measured against a compressed upstream once it is.

What survives unchanged is the offload result, which does not depend on relative
speed — and the observation that the *ranking* between the two conditions flips,
which is why no single speedup number was ever quotable alone.

The supply model **cost latency to buy the memory guarantee**: regenerating a
NAR per serve moved peers-on from 0.638 s to 0.964 s under WAN shaping (6.1×
rather than the 9.3× the retain-everything build reached). That trade is stated
rather than buried — holding nothing at rest is not free.

Discovery is measured separately (`just discovery`): finding the holders of a
200-path closure across 8 peers costs **1180 → 8 round trips**. That is a count,
not a speedup — the wall-clock gain depends entirely on the RTT the round trips
would have crossed, and these peers were in one process.

`TESTING.md` forbids claiming emergent network effects from single-host sweeps,
and the peer link is still loopback, so peer-side numbers are upper bounds.

See `PRD.md` for the full design record and `backlog/` for task state.

## Architecture

A stack-neutral **frontend** with a swappable P2P **backend**, plus a separate
test fixture. `just independence` enforces that the product and the fixture
never share code, so the fixture stays an independent witness of wire behaviour.
See `figures/fig-arch-5-peer-fabric.svg` for the whole picture and
`docs/peer-fabric-seam.md` for the seam.

- **`daemon/`** — the product. All *serving* behaviour sits behind two frozen
  seams: `NarinfoSource` (narinfo lookup: upstream HTTP, disk cache; p2p relay
  in v2) and `NarSource` (resolve a typed `NarKey` — the signed NarHash on the
  normal path — to a verified NAR stream), so the p2p swap needs no HTTP-layer
  change. All *P2P* behaviour sits behind a third, intention-level seam,
  **`PeerFabric`** (find providers · announce · locate · fetch · serve ·
  hold-query · LAN): iroh and libp2p are *backends* behind it, not the
  architecture, and the content-routing DHT is an **adopted** prior solution
  (`iroh-dht-experiment` / `libp2p-kad`), not hand-rolled. Target packaging is a
  stack-neutral `daemon-core` frontend over one backend crate (`fabric-iroh` /
  `fabric-libp2p`), shipped as **one binary per backend** (`daemon-iroh` /
  `daemon-libp2p`) so exactly one stack ever links. *Today the daemon is a single
  crate with iroh welded in; the seam and crate split are the target, not yet
  built.* A NAR transport plugs in as one `NarSource`/`Transport` impl with a
  `TransportRegistry` dispatching on each claim offer's tag — so a second
  transport (BitTorrent) is a new implementation, not a network fork.
- **`testproxy/`** — the permanent test fixture. A simple caching proxy that
  fronts the upstream (real or mock) and owns all fault injection: latency,
  errors, corruption, throttling. Adversarial-upstream logic never lives in
  the product. It is *intended* to also shield cache.nixos.org from test load,
  but it is plain-HTTP only today (task-22), so it currently fronts a local
  mock origin rather than the real cache.

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
  daemon-off. This was defined for the wave-1 transparent proxy and holds
  there. It is **not** met by the p2p path: peers-on against the loopback
  control is ~4× daemon-off. Whether that matters depends entirely on how
  fast the real upstream is, which is exactly what has not been measured.
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
hash by construction). Both are pinned in bytes by golden vectors, so a rename
or a retag fails a test rather than a deployment. The global discovery key
derivation is the third frozen surface: the *model* is settled — our schema
frozen as an opaque value inside an adopted DHT substrate, so the substrate's own
wire format can churn without touching the freeze — while the substrate itself
(`iroh-dht-experiment` / `libp2p-kad`) is chosen by the TASK-126 spike.

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

A green `just test` is one sample, not a proof: the gate's own flake rate is
something this project measures (`scripts/flake_rate.py`) rather than assumes.
`TESTING.md` states the rule.

Slow tier (containers/VMs; not part of the fast loop — minutes to hours):

```sh
just e2e         # FAST podman-pod subset: 5 scenarios, one per path
just e2e-full    # every e2e scenario - the real gate before shipping
just e2e-vm      # NixOS VM test (needs /dev/kvm)
just measure     # egress/latency/gap measurement report
just scale-sweep # scaling sweep + regression fit (clients, chain depth, knobs)
just profile     # p2p RAM/disk/latency/throughput/speedup report (peer swarm)
just discovery   # closure-discovery cost, batched vs one-at-a-time (~1 min)
just journey     # J1 operator journey
```

Most are hours, not minutes: `just profile` runs a peer swarm, a NAR-size
axis, a concurrency axis and both upstream conditions. `just discovery` is the
exception — it needs no containers, because discovery has no container path yet.

`nix flake check` re-runs build/lint/test in the sandbox for CI.

## Documents

- `PRD.md` — accepted design record: decisions, irreversibility map, risks,
  wave-2 scope.
- `TESTING.md` — what good and bad observably mean; the oracles the gates
  enforce.
- `backlog/` — task tracker (use the `backlog` CLI, not direct file edits).
- `figures/` — architecture overviews: **`fig-arch-5-peer-fabric`** (the whole
  system: the three seams, iroh/libp2p as swappable backends behind
  `PeerFabric`, the trust boundary, and the crate topology), `fig-arch-1`
  (wave-1 daemon seams), `fig-arch-2` (test harness), `fig-arch-3` (wave-2
  target). The `fig-candidate-*` originals and `fig-arch-3` predate the
  PeerFabric decision and are stale until task-17 revises them.

## References

Prior art and the problem this exists to address. Both threads are from June
2023; this project is not aware of a shipped implementation coming out of
either, though that is an impression from reading them rather than a survey.

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
