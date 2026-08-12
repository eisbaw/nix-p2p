# nix-p2p

A decentralized Nix binary cache. A localhost substituter daemon speaks the
standard binary-cache HTTP API, passes signed metadata through from
cache.nixos.org, and fetches NAR payloads from peers it discovers over a
decentralized DHT — every payload hash-verified against the signed NarHash. An
unmodified Nix client re-verifies the signature and NarHash itself, so the daemon
and every peer stay **outside the trusted computing base**: a hostile or broken
peer costs a retry, never a bad store path.

The aim is **bandwidth offload for cache.nixos.org — decentralizing the bytes, not
the trust.** Signing stays the cache's job.

> **Research prototype.** It has not been pointed at the real cache.nixos.org (the
> daemon is plain-HTTP; TLS is future work), and it has not run on a real network —
> no NAT, no relay, no residential uplink. It runs on loopback / in-process /
> single-host containers. The addressed unit, the claim wire schema, and the
> discovery key/record are frozen; much else is still moving.

## Architecture

![nix-p2p architecture: the three seams, libp2p/iroh backends behind the PeerFabric seam, the trust boundary, and the crate topology](figures/fig-arch-5-peer-fabric.svg)

A stack-neutral **frontend** over a swappable P2P **backend**, plus a separate test
fixture (`just independence` keeps the product and the fixture from sharing code, so
the fixture stays an independent witness of wire behaviour). The seam is documented
in `docs/peer-fabric-seam.md`.

**Three seams.** Serving sits behind `NarinfoSource` (narinfo lookup) and `NarSource`
(resolve a signed NarHash to a verified byte stream). All P2P sits behind the
intention-level **`PeerFabric`** seam — *find providers · announce · locate · fetch ·
serve · hold-query · LAN* — so the serving core holds **zero** p2p types.

**libp2p-primary; iroh optional.** iroh is a strong *connectivity* substrate ("dial
an `EndpointId`, get authenticated QUIC bytes") but has **no content-provider
routing**: it answers "*where is this node?*", never "*who has hash X?*". So
**discovery is `libp2p-kad`** — adopted from a robust existing library, not
hand-rolled, and not Kademlia-over-iroh — and **iroh-blobs is an optional transport**
kept for its NAT traversal. Discovery is libp2p-kad regardless of transport. (See
"iroh's shortcomings" in `PRD.md`.)

Crates:

- **`peer-fabric/`** — the seam: capability traits, `Lookup`/`Exposure`, and the
  frozen `ContentKey`/`ProviderRecord` codec. **Zero** p2p-library deps.
- **`fabric-libp2p/`** — the primary backend: the libp2p-kad `ProviderDirectory` +
  `AvailabilityAnnouncer`, and a libp2p `NarTransfer`/`NarServer` on the same swarm.
- **`fabric-iroh/`** — the optional iroh transport (iroh-blobs) + pkarr node lookup.
- **`daemon/`** — the product; wires a `NarSource` to fabric discovery→transfer.
- **`testproxy/`** — the permanent test fixture: a caching proxy that owns all fault
  injection (latency, errors, corruption, throttling).
- Supporting: `fixtures/` (signed mock cache), `scripts/` (rootless-podman e2e + the
  measurement instrument), `nixos/` (module + VM test).

## Trust and verification

![what the ed25519 signature covers (the uncompressed NAR), which narinfo fields are rewritable, where each hash is taken in the pipeline, and the raw-versus-compressed wire cost](figures/fig-arch-4-signing-and-compression.svg)

Trust stays where it is. cache.nixos.org signs narinfos; an unmodified Nix client
re-verifies the ed25519 signature and the NarHash; the daemon and every peer are
outside the TCB. A peer serves the **raw** NAR — the addressed unit, `RawNarV1`, the
exact `nix-store --dump` bytes keyed by plain BLAKE3 — verified BLAKE3/bao on arrival
and again by Nix's own signature + NarHash check.

**Frozen surfaces** (deep-reviewed because changing them splits the network, and
pinned in bytes by golden vectors): the addressed unit; the claim wire schema; and
the discovery key + provider record — a `ContentKey` derived from the signed NarHash
and an ed25519-signed `ProviderRecord` stored as an **opaque value**, so the DHT
substrate's own wire format can churn without touching the freeze.

**The open question — do peers beat a CDN?** A peer serves the raw NAR while the CDN
serves a compressed file, so a peer moves more bytes per path and may not beat a fast
CDN on speed until the peer link is itself compressed (an unsigned transport field;
the addressed unit stays the raw NAR). The long tail is where a CDN is strong and
swarms are weak. Whether peers usefully beat or supplement a CDN as a byte source is
treated as a thesis to measure, not a premise; the measurement instrument is a
first-class part of the project, and the real-network and swarm results are not in.

## What is

- **Decentralized content discovery.** A node announces a signed provider record
  under a NarHash-derived key; another node resolves "who has this NAR?" through the
  libp2p-kad DHT with no injected answer. The *found / miss / unavailable* outcomes
  are distinct, and there is no "list my holdings" call at all — no enumeration, by
  construction.
- **Peer transfer over two backends,** each BLAKE3/bao-verified on arrival:
  iroh-blobs whole-NAR over QUIC (a real `nix build` served from a peer across
  container network namespaces — a corrupt peer fails the build, a dead peer falls
  back to upstream), and libp2p request-response over the same swarm as discovery.
- **The daemon uses it end-to-end:** given a NarHash it derives the discovery key,
  finds a provider via libp2p-kad, fetches and verifies the NAR, and serves it to Nix
  with a clean upstream fallback on a miss — configurable from the CLI.
- **A transparent substituter proxy:** `nix-cache-info` semantics, a narinfo disk
  cache, the NAR correlation catalog, multi-daemon chains, the additive-invariant
  crash behaviour (daemon dead or killed mid-transfer → `nix build` still succeeds via
  fallback, the store never corrupted), a NixOS module + VM test.
- **Regenerate-on-demand supply:** a node announces what it can serve without holding
  it, regenerates from `/nix/store` on request inside a serve budget, and holds
  nothing at rest.

## What is not yet

- **A real network.** No NAT traversal, relay, or residential uplink; the
  byte-transfer dial address is still supplied out-of-band, so only *discovery* is
  decentralized so far.
- **A real-Nix cold-journey demo** — a cold `nix build` that discovers and fetches
  fully decentrally with zero injection — and a multi-daemon container e2e for the
  libp2p path.
- **Correct serving under a compressed upstream narinfo over libp2p:** a libp2p hit
  must rewrite the narinfo to match the raw bytes it serves (as the iroh path already
  does); until then a real Nix client would reject a compressed-narinfo libp2p hit.
- **The clean packaging:** one daemon crate still links everything; the split into
  separate per-backend binaries is the target.
- **Swarm dynamics and policies:** cold warm-up, announce-after-fetch, multi-holder
  failover, hedge/prefetch, provider records surviving a restart, and DHT hardening
  (signed withdrawal, replay/eclipse/sybil bounds, true streaming).
- **A verdict on the value thesis:** whether peers beat a CDN is unmeasured on a real
  network.

## Development

Everything runs in the pinned flake devshell; the Justfile refuses any other
toolchain.

```sh
nix develop
just            # list gates

just build      # cargo build, all targets
just lint       # clippy -D warnings, rustfmt, ruff, independence + source guards
just test       # cargo test — incl. the multi-node discovery + transfer +
                # daemon-integration tests — plus the fixture and measurement gates
```

Slow tier (containers / VMs):

```sh
just e2e         # rootless-podman subset, incl. the peer-served build
just e2e-full    # every e2e scenario
just e2e-vm      # NixOS VM test (needs /dev/kvm)
just measure     # egress / latency / gap report
just profile     # p2p resource / throughput report
```

`nix flake check` re-runs build/lint/test in the CI sandbox.

## Documents

- **`PRD.md`** — the durable design record: essence, decisions, iroh's shortcomings,
  the irreversibility map, risks, the tournament contract.
- **`docs/peer-fabric-seam.md`** — the `PeerFabric` seam design.
- **`TESTING.md`** — what "good" and "bad" observably mean; the oracles the gates
  enforce.
- **`figures/`** — architecture overviews (the two above; `fig-arch-1`/`-2` zoom into
  the wave-1 daemon and the test harness).
- **`backlog/`** — the task tracker (use the `backlog` CLI, not direct edits).

## References

Prior art and the problem this addresses:

- [Peer-to-peer binary cache RFC / working-group poll](https://discourse.nixos.org/t/peer-to-peer-binary-cache-rfc-working-group-poll/29568)
  (NixOS Discourse) — polls the community on a decentralized binary cache motivated by
  CDN bandwidth cost; the availability / untrusted-peer / sharding objections raised
  there are the ones this design answers rather than assumes away.
- [Migration of S3 bucket payments to the Foundation](https://github.com/NixOS/foundation/issues/86)
  (NixOS/foundation) — the storage-cost side of the same problem, cataloguing
  alternatives from distributed stores to decentralized mirrors.

Where this differs from most such proposals: it decentralizes the **bytes only** and
leaves trust exactly where it is, and it targets *bandwidth* rather than storage.

## License

MIT — see `LICENSE`.
