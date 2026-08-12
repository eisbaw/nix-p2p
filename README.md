# nix-p2p

A decentralized Nix binary cache: a localhost substituter daemon that speaks the
standard binary-cache HTTP API, passes signed metadata through from
cache.nixos.org, and fetches NAR payloads **from peers it discovers over a
decentralized DHT** — every payload hash-verified against the signed NarHash. An
unmodified Nix client re-verifies the signature and NarHash itself, so the daemon
and every peer stay **outside the trusted computing base**: a hostile or broken
peer costs a retry, never a bad store path.

The goal is **bandwidth offload for cache.nixos.org — decentralizing the bytes,
not the trust.** Signing stays the cache's job.

> **Research prototype — not production, and not on a real network yet.** It has
> never been pointed at the real cache.nixos.org (the daemon is plain-HTTP only;
> TLS is tasks 22/24), and every result below is from loopback / in-process /
> rootless-container testbeds — **no NAT, no relay, no residential uplink.** The
> addressed unit, the claim wire schema, and the discovery key/record are frozen;
> much else is still moving.

## What works today

The core decentralized path **runs and is verified end-to-end (in-process)** — the
big recent change is that discovery is no longer a protocol without a mechanism:

- **Decentralized content discovery.** `fabric-libp2p` runs **libp2p-kad**: a node
  announces a signed provider record under a NarHash-derived key, and another node
  resolves *"who has this NAR?"* through the Kademlia DHT with **no injected
  answer**. Proven by multi-node tests (a bootstrap + providers + a consumer that
  knows only the bootstrap's address) covering the *found / miss / unavailable*
  arms. A custom protocol keeps it off the public IPFS DHT.
- **Peer transfer, two backends** — the fetched NAR is BLAKE3/bao-verified on
  arrival:
  - **iroh-blobs** (whole-NAR over QUIC): a real `nix build` served from a peer
    across container network namespaces (the s6 e2e); a corrupt peer fails the
    build, a dead peer falls back to upstream.
  - **libp2p** (request-response over the same swarm as discovery): multi-node
    byte-identical, BLAKE3-verified fetch with streaming size-abort and serve-budget
    bites.
- **The daemon actually uses it.** An integration test drives the real serving
  stack: given a NarHash the daemon derives the discovery key, finds a provider via
  libp2p-kad (not injected), fetches + verifies the NAR over libp2p, and serves
  byte-identical bytes to Nix — with a clean upstream fallback on a miss.
- **Transparent substituter proxy** (solid): `nix-cache-info` semantics, narinfo
  disk cache, NAR correlation catalog, multi-daemon chains, additive-invariant
  crash tests, a NixOS module + 3-VM test.
- **Regenerate-on-demand supply.** A node announces what it can serve without
  holding it, regenerates from `/nix/store` on request inside a serve budget (max
  NAR size, max in-flight bytes, max duration), and holds **0 bytes at rest**.
- **No enumeration, by construction.** There is no "list my holdings" call at all;
  discovery answers only about keys the asker named.

## What does not work yet (the honest headline)

- **Nothing has run on a real network.** All of the above is loopback / in-process
  / single-host containers. No NAT traversal, relay, or residential uplink — the
  libp2p `NodeLocator` (AutoNAT/DCUtR/relay) is TASK-159, and the byte-transfer
  dial address is still injected out-of-band (only the *discovery* is decentralized
  today).
- **No cold-journey PoC yet.** A real *cold* `nix build` that discovers and fetches
  fully decentrally with zero injection (TASK-132), and a multi-daemon podman e2e
  for the libp2p path (TASK-161), are not built.
- **The clean packaging isn't done.** One `daemon` crate still links everything; the
  `daemon-core` split into separate `daemon-iroh` / `daemon-libp2p` binaries is the
  target (TASK-145/146). Production CLI wiring for libp2p is landing (TASK-162).
- **The value thesis is unproven** (see below) and **no swarm dynamics are
  measured**: cold warm-up, announce-after-fetch, multi-holder failover, and
  hedge/prefetch policies do not exist yet.
- **Provider records don't survive a restart**, and the DHT hardening — signed
  withdrawal tombstones, replay/eclipse/sybil bounds, true streaming — is filed but
  not done (TASK-152–159).

## The catch you should know up front: will peers actually beat a CDN?

This is the project's weakest point, and it's stated plainly rather than assumed
away. A peer ships the **raw** NAR; cache.nixos.org ships **xz** (`FileSize/NarSize
≈ 0.278`, measured on 20 live paths), so a peer moves ~**3.6× the bytes** and would
need to sustain ~**75 MB/s upload just to break even** — against a 1.25–5 MB/s home
uplink. Compressing the peer link (an *unsigned* transport field; the addressed
unit stays the raw NAR) can claw this back but isn't built. **So on speed the
honest answer is: unknown, and probably unfavourable for a remote peer until the
link is compressed.** The long tail is where a CDN is strong and swarms are weak,
and the PRD does not pretend otherwise. What *is* solid is the trust model and the
offload accounting (a peer hit is a genuine 0-egress crossing at the cache).

*Measurements* (iroh transport, commit `63caca2`, single-host — upper bounds only;
`TESTING.md` forbids reading swarm effects into single-host sweeps): upstream
NAR-payload egress offload **1.00** steady-state (one pre-seeded holder — a *cold*
swarm offloads ~0); holder RAM **1.018 B/B** while serving, **0.00** at rest;
**38.4 MB** per concurrent serve. The libp2p transfer and discovery are newer and
not yet throughput-profiled.

## Architecture

A stack-neutral **frontend** over a swappable P2P **backend**, plus a separate test
fixture (`just independence` keeps the product and the fixture from sharing code,
so the fixture stays an independent witness of wire behaviour). See
`figures/fig-arch-5-peer-fabric.svg` and `docs/peer-fabric-seam.md`.

**Three seams.** Serving sits behind `NarinfoSource` (narinfo lookup) and
`NarSource` (resolve a signed NarHash to a verified byte stream). All P2P sits
behind the intention-level **`PeerFabric`** seam — *find providers · announce ·
locate · fetch · serve · hold-query · LAN* — so the serving core holds **zero** p2p
types.

**libp2p-primary; iroh optional.** iroh is a superb *connectivity* substrate ("dial
an `EndpointId`, get authenticated QUIC bytes") but has **no content-provider
routing** — it answers "*where is this node?*", never "*who has hash X?*". So
**discovery is always `libp2p-kad`** (adopted, IPFS-mainnet-proven; not hand-rolled,
no Kademlia-over-iroh), and **iroh-blobs is an *optional* transport** kept for its
NAT traversal and measured against libp2p's own transport. See "iroh's shortcomings"
in `PRD.md`.

Crates:

- **`peer-fabric/`** — the seam: capability traits, `Lookup`/`Exposure`, and the
  frozen `ContentKey`/`ProviderRecord` codec. **Zero** p2p-library deps.
- **`fabric-libp2p/`** — the **primary** backend: libp2p-kad `ProviderDirectory` +
  `AvailabilityAnnouncer`, and libp2p `NarTransfer`/`NarServer` over the same swarm.
- **`fabric-iroh/`** — the **optional** iroh transport (iroh-blobs) + pkarr node
  lookup, behind the same seam.
- **`daemon/`** — the product; wires a `NarSource` to fabric discovery→transfer.
- **`testproxy/`** — the permanent test fixture: a caching proxy that owns all
  fault injection (latency, errors, corruption, throttling). Plain-HTTP only today.
- Supporting: `fixtures/` (signed mock cache), `scripts/` (rootless-podman e2e +
  the measurement instrument), `nixos/` (module + 3-VM test).

**Frozen surfaces** — deep-reviewed because changing them splits the network, and
pinned in bytes by golden vectors so a rename fails a test rather than a deployment:

- **Addressed unit** — `RawNarV1`, the exact `nix-store --dump` bytes keyed by plain
  BLAKE3 (equals the iroh-blobs hash by construction).
- **Claim wire schema** and the **discovery key + provider record** — `ContentKey =
  BLAKE3-derive(domain, signed NarHash)` and an ed25519-signed `ProviderRecord`
  stored as an **opaque value**, so the DHT substrate's own wire format can churn
  without touching the freeze. Verified by golden vectors *and* an independent
  from-scratch Python verifier; the record freeze cleared a 3-round cross-model
  review.

**Trust & invariants** (`TESTING.md`): signed narinfo fields are untouched, Nix
re-verifies signature + NarHash, and the daemon + peers are outside the TCB. Tested
end-to-end: **S1** byte-identity · **S2** additive invariant (daemon dead / killed
mid-transfer → `nix build` still succeeds via fallback, store never corrupted) ·
**S3** honest egress accounting (a peer hit counted at the provider, not the
fetcher's self-report) · **S6** peer-served build · **S9** models-bite.

## Development

Everything runs in the pinned flake devshell; the Justfile refuses any other
toolchain.

```sh
nix develop
just            # list gates

just build      # cargo build, all targets
just lint       # clippy -D warnings, rustfmt, ruff, independence + source guards
just test       # cargo test — incl. the multi-node discovery + transfer +
                # daemon-integration tests — + the fixture and measurement gates
```

Slow tier (containers / VMs — minutes to hours):

```sh
just e2e         # rootless-podman subset (incl. the s6 peer-served build)
just e2e-full    # every e2e scenario
just e2e-vm      # NixOS VM test (needs /dev/kvm)
just measure     # egress / latency / gap report
just profile     # p2p RAM / disk / latency / throughput report
```

A green `just test` is one sample, not a proof: the gate's own flake rate is
something this project *measures* (`scripts/flake_rate.py`) rather than assumes.
`nix flake check` re-runs build/lint/test in the CI sandbox.

## Documents

- **`PRD.md`** — the durable design record: essence, key decisions, iroh's
  shortcomings, the irreversibility map, risks, and the two-stage tournament
  contract.
- **`docs/peer-fabric-seam.md`** — the `PeerFabric` seam design.
- **`TESTING.md`** — what "good" and "bad" observably mean; the oracles the gates
  enforce.
- **`figures/fig-arch-5-peer-fabric.svg`** — the one-glance architecture overview.
- **`backlog/`** — the task tracker (use the `backlog` CLI, never edit the files
  directly).

## References

Prior art and the problem this exists to address (both threads June 2023; no shipped
implementation is known to have come out of either):

- [Peer-to-peer binary cache RFC / working-group poll](https://discourse.nixos.org/t/peer-to-peer-binary-cache-rfc-working-group-poll/29568)
  (NixOS Discourse) — polls the community on a decentralized binary cache, motivated
  by CDN costs cited as exceeding €50k/month; the availability / untrusted-peer /
  sharding objections raised there are the ones this design answers rather than
  assumes away.
- [Migration of S3 bucket payments to the Foundation](https://github.com/NixOS/foundation/issues/86)
  (NixOS/foundation) — the storage-cost side of the same problem, cataloguing ~11
  alternatives from distributed stores to decentralized mirrors.

Where this differs from most such proposals: it decentralizes the **bytes only** and
leaves trust exactly where it is (cache.nixos.org keeps signing; Nix re-verifies;
peers stay outside the TCB), and it targets *bandwidth*, not storage — treating
"do peers beat a CDN?" as a thesis to measure, not a premise.

## License

MIT — see `LICENSE`.
