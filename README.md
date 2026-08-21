# nix-p2p

A decentralized Nix binary cache. A localhost substituter daemon speaks the standard
binary-cache HTTP API, passes signed metadata through from cache.nixos.org, and fetches
NAR payloads from peers it discovers over a DHT — every payload hash-verified against
the signed NarHash.

**Why:** cache.nixos.org is a single point of failure for the Nix ecosystem's
*bandwidth*. Its trust role — signing narinfos — is cheap and replicable; its
byte-serving role is not. nix-p2p decentralizes the bytes and only the bytes. An
unmodified Nix client re-verifies the signature and NarHash itself, so the daemon and
every peer stay **outside the trusted computing base**: a hostile or broken peer costs
a retry, never a bad store path.

> **Research prototype.** No production deployment, and no real public *peer* network —
> NAT and relay are proven only on containerized/VM NAT, with no residential uplinks. The
> daemon's routine correctness tests front cache.nixos.org through a disjoint-TLS *fixture*
> (`testproxy`), not the live CDN. (The one exception: the value-thesis measurement fetched
> real narinfos and NARs from the **live cache.nixos.org over verified TLS** — see
> [Does this help?](#does-this-help).) Otherwise it runs on loopback, in-process, and
> single-host rootless-podman containers; within that scope the decentralized path is real
> end to end. Whether peers beat or supplement a CDN is a thesis being measured, not a premise.

## Quick start

```sh
nix develop          # pinned toolchain; the Justfile refuses any other
just e2e             # see it work: containers discover a peer and serve a real nix build
```

`just e2e` stands up separate daemon containers — a bootstrap router holding no content,
a provider, and a consumer told *only* the bootstrap — and drives a real `nix build`
whose NAR is discovered over the DHT, resolved, fetched, and served from the peer, with
no injected addresses and upstream untouched on a hit.

**Run it as your substituter.** The daemon is additive: it advertises a priority below
cache.nixos.org, so Nix falls back automatically if it is slow, stopped, or killed
mid-transfer.

```sh
nix run .#daemon-libp2p -- --listen 127.0.0.1:8082 --upstream https://cache.nixos.org
```

```
# /etc/nix/nix.conf  — nix-p2p first, the real cache as fallback
substituters = http://127.0.0.1:8082 https://cache.nixos.org
```

On NixOS, use the module instead:

```nix
services.nix-p2p = {
  enable = true;
  port = 8082;                        # loopback only; it is a substituter, not a service
  libp2p.enable = true;
  libp2p.profile = "consume-only";    # upstream-only (default) | consume-only
};                                    # | lan-share | public-share | router
```

**A fresh install gives nothing away.** The default profile is `upstream-only`: no
serving, no announcing, no DHT participation, no discovery traffic at all. Sharing is
an explicit opt-in, and a profile that contradicts an explicit flag fails closed at
startup. Opting into `lan-share` additionally turns on LAN mDNS by default: the node then
multicasts its presence, NodeId, and libp2p listen multiaddrs to the local link so same-pin
peers find it with zero config — decline that LAN presence disclosure with
`services.nix-p2p.libp2p.mdns = false` (`--libp2p-no-mdns`).

## How it works

![nix-p2p architecture: the three seams, libp2p/iroh backends behind the PeerFabric seam, the trust boundary, and the crate topology](figures/fig-arch-5-peer-fabric.svg)

**Three seams.** Serving sits behind `NarinfoSource` (narinfo lookup) and `NarSource`
(resolve a signed NarHash to a verified byte stream). All P2P sits behind the
intention-level `PeerFabric` seam — *find providers · announce · locate · fetch · serve
· hold-query · LAN* — so the serving core holds **zero** p2p types.

**The backend is the binary,** not a runtime flag: `daemon-libp2p` links libp2p and
nothing of iroh, enforced by a crate-graph guard that walks `cargo tree` and bites if an
iroh crate ever appears.

**Discovery is libp2p-kad.** iroh is a strong *connectivity* substrate ("dial an
`EndpointId`, get authenticated QUIC bytes") but has no content-provider routing — it
answers "*where is this node?*", never "*who has hash X?*". So discovery uses
libp2p-kad's `get_providers`, adopted from a mainnet-proven library rather than
hand-rolled, and iroh-blobs remains an optional transport backend.

**Bootstrapping the first peer.** A DHT can't start from nothing. On a **LAN** this is
zero-config: mDNS finds neighbours by multicast and hands their addresses to the kad
bootstrap path — never to content discovery (on by default only under `lan-share`, with the
presence disclosure described under Quick start above). Across the **internet**, the
zero-infrastructure entry point is an opt-in rendezvous over the BitTorrent Mainline DHT
(`--libp2p-mainline-rendezvous`, default off): the node joins Mainline strictly as a
**client**, announces membership under one well-known infohash, and `get_peers`-es it to
learn peer *addresses* for the libp2p dial path. Content routing stays kad-exclusive — no
infohash is ever derived from a Nix content hash — and the disclosed, load-bearing cost is
that anyone who knows the infohash can enumerate node **membership** (which IPs run nix-p2p),
never content holdings. Because it would bridge a private pool onto the public swarm, it is
refused under `lan-share` / `upstream-only`.

*Caveat:* a home-NAT node announces a listen port with no NAT mapping (the DHT and the libp2p
transport use different sockets), so it is **discoverable but unreachable** this way — a
usable provider bootstrap only for a genuinely reachable (public or forwarded) listen.
Residential NAT hole-punching / relay is separate, unfinished work.

**Serving costs no disk.** A node holds no second copy of anything: it regenerates a
path's raw NAR from `/nix/store` on demand via `nix-store --dump`, so there is no blob
store, no retention policy, and nothing at rest. Note the current limit — *which* paths a
node offers is still per-path: either named explicitly with `--libp2p-provide-store`, or
picked up automatically for paths fetched through the daemon
(`--libp2p-announce-after-fetch`). Offering a store's existing contents wholesale is not
wired up yet.

Crates: `peer-fabric/` (the seam, zero p2p deps) · `fabric-libp2p/` (primary backend) ·
`fabric-iroh/` (optional backend) · `daemon-core/` (stack-neutral frontend) ·
`daemon-libp2p/` (the primary binary) · `testproxy/` (permanent test fixture owning all
fault injection). Design: `docs/peer-fabric-seam.md`.

## Trust and verification

![what the ed25519 signature covers (the uncompressed NAR), which narinfo fields are rewritable, where each hash is taken in the pipeline, and the raw-versus-compressed wire cost](figures/fig-arch-4-signing-and-compression.svg)

Trust stays where it is. cache.nixos.org signs narinfos; an unmodified Nix client
re-verifies the ed25519 signature and the NarHash; the daemon and every peer are outside
the TCB. A peer serves the **raw** NAR — the addressed unit, `RawNarV1`, the exact
`nix-store --dump` bytes keyed by plain BLAKE3 — verified BLAKE3/bao on arrival and again
by Nix's own signature and NarHash check.

**No enumeration, by construction.** Peers answer yes/no about a NarHash you already
name. There is no call that lists a node's holdings, so an outsider cannot discover
which private paths you hold.

**Frozen surfaces** (deep-reviewed because changing them splits the network, and pinned
in bytes by golden vectors): the addressed unit; the claim wire schema; and the discovery
key + provider record — a `ContentKey` derived from the signed NarHash and an
ed25519-signed `ProviderRecord` stored as an **opaque value**, so the DHT substrate's own
wire format can churn without touching the freeze.

## Does this help?

Honest answer: **not proven yet.** A peer serves the raw NAR and compresses it on the fly,
per serve, with a cheap codec (light zstd); the CDN serves a file compressed once, hard, at
build time (`xz`). On slow links the CDN's smaller artifact wins the wire; as the peer link
speeds up, the peer's shorter hop and cheaper bytes take over. The long tail — rarely-fetched
paths — is exactly where a CDN is strong and a swarm is weak.

Early shaped-link measurement points to **supplement, not replace** — the *bytes-per-hit*
half of the question, matching the stated aim of bandwidth offload. But the transport-bytes
comparison is still being pinned down against the shipped (compressed) peer transport, and
real public-network numbers are not in yet, so treat the table below as a first cut.

An offline overlap probe measured the other half — *hit-rate*. Machines on the **same
nixpkgs pin** (a LAN, or an org) share almost all of a cold build's closure: overlap warms
to ~95% of paths. Machines on **different** nixpkgs revisions share essentially nothing —
store paths are input-addressed, so a different stdenv rehashes everything downstream, and
cross-revision overlap is structurally zero. So the honest first product is the **org / LAN
same-pin pool**; a global permissionless swarm across arbitrary revisions offloads nothing
unless it is segmented into same-pin cohorts. The project treats all of this as a thesis to
falsify rather than a premise.

**Measured, on real packages (a first cut).** Read this as a **link-speed** comparison, not a
protocol verdict: it holds the CDN fixed at this host's slow ~16 Mbps WAN and varies the *peer*
link, so the "winner" is mostly *whose link is faster*. A peer moves **2.4–6.3× more** bytes
(raw vs xz), so **at a peer link comparable to your CDN link, cache.nixos.org wins everywhere**;
nix-p2p only pulls ahead once the local link outweighs those extra bytes. Where a peer has the
path:

| peer link (vs a fixed ~16 Mbps CDN) | faster | codec + effective (post-decompress) |
| --- | --- | --- |
| **16 Mbps** (DSL) | mostly `cache.nixos.org` | its smaller xz file wins the wire; nix-p2p (zstd-3) wins only poorly-compressing packages |
| **32 Mbps** | mostly **nix-p2p** | light **zstd-3** tips most packages; the CDN holds only the best-compressing (`git`) |
| **64 Mbps** | mostly **nix-p2p** | zstd-1/3; the CDN holds only the single most-compressible package |
| **100 Mbps** (home) | **nix-p2p** — all | **zstd-1..3**, which decompresses ~3.5× faster than the CDN's xz |
| **300 Mbps** | **nix-p2p** — all | link fast enough that even raw wins — compression stops paying |
| **1000 Mbps** (LAN) | **nix-p2p — 2–44×** | serves **raw**: zero compress, zero client decompress |

**Why the CDN keeps the slow links:** nix-p2p compresses (and the client decompresses) **on
the fly, per serve**, and *compression is the bottleneck* — a codec small enough to match the
CDN's `xz` (zstd-19 ≈ xz's size, and decompresses 10× faster) costs ~24 s of CPU on **every
serve**, so it never pays; the cheap codecs that *do* pay lose on ratio. The CDN serves an
artifact **compressed once at build time**, paying that cost zero times per download. So
nix-p2p wins the fast links on raw bytes and a shorter hop, not on compression — and a
compressed-NAR cache (compress once, serve many) is the lever that would change the slow links.

*First cut: **transfer** only — **excludes discovery latency**, and holds only where a peer has
the path. CDN baseline is this host's WAN (~16 Mbps effective, incl. its xz-decompress); the
crossover scales with your CDN link. Details: `docs/profiling.md`.*

## Status

The decentralized path works end to end across containers and VMs: kad discovery, address
resolution with nothing injected, Bao-authenticated transfer, byte-identical delivery to a
real `nix build`, multi-provider fail-over, and a clean upstream fallback on a miss.

**Works today**

- **Decentralized discovery** — libp2p-kad `get_providers`; nothing injected; no holdings enumeration, by construction.
- **Hash-verified peer transfer** — raw `RawNarV1` NAR, BLAKE3/bao-checked on arrival, then Nix's own signature + NarHash check.
- **Transparent substituter** — additive, with automatic fallback to cache.nixos.org; serves by regenerating NARs from `/nix/store` on demand, nothing held at rest.
- **Zero-config org/LAN same-pin sharing** — mDNS bootstrap, cross-host serving, and a LAN↔public isolation guarantee.
- **Sharing profiles** — the `upstream-only` default gives nothing away; `consume-only` / `lan-share` / `public-share` / `router` opt in; a profile that contradicts a flag fails closed at startup.
- **Durable seeding** — a node advertising a path stays discoverable across the record TTL (periodic re-sign), not just for the first hour.
- **Opt-in internet bootstrap** — a Mainline (BitTorrent DHT) rendezvous, strictly client, membership-only, refused under `lan-share`.
- **Robustness** — multi-provider fail-over; replay/rollback-rejecting signed provider records; restart-durable identity + anti-rollback sequence floor; a supply-integrity floor that re-verifies a path's NarHash before advertising it.
- **Packaging** — a NixOS module and a VM test.

**In progress**

- **Socket-to-HTTP streaming** — removing the final in-RAM NAR collector. Mid-transfer failure is already safe (a killed peer still yields a correct build via fallback); the streaming refactor is scoped and pending.
- **Real public network** — NAT hole-punching / relay for residential peers, proven only on containerized NAT so far.
- **Operator-contract hardening** — the last resource-control acceptance criteria.

**Not yet / out of scope**

- **A public internet swarm at scale** — real residential uplinks and a real-cache deployment are unproven.
- **Whole-store offering** — a node offers paths per-path (named with `--libp2p-provide-store`, or picked up via `--libp2p-announce-after-fetch`), not a store's existing contents wholesale.
- **A compressed-NAR cache** (compress once, serve many) — the lever that would win the slow links; measured-but-deferred.
- **A settled value thesis** — whether peers beat or supplement a CDN is still being measured, not assumed (see [Does this help?](#does-this-help)).

Full inventory: **`docs/status.md`**.

## Development

```sh
just            # list gates
just build      # cargo build, all targets
just lint       # clippy -D warnings, rustfmt, ruff, independence + source guards
just test       # cargo test incl. multi-node discovery/transfer + fixture and
                # measurement gates + property tests at a FIXED seed
just prop       # the same property tests at a FREE seed — exploration, run deliberately
```

Slow tier (containers / VMs):

```sh
just e2e         # rootless-podman subset
just e2e-full    # every e2e scenario
just e2e-vm      # NixOS VM test (needs /dev/kvm)
just measure     # egress / latency / gap report
just profile     # p2p resource / throughput report
just bench       # criterion + hyperfine micro / wall-clock benchmarks
just profile-cpu # flamegraph (or callgrind) CPU attribution
just profile-ram # dhat allocation profile
```

`nix flake check` re-runs build/lint/test in the CI sandbox.

## Testing

Correctness is gated, not asserted — the suite spans several kinds of test:

- **Unit + property tests** — per-crate, with focused coverage of the security-critical
  surfaces (multiaddr LAN-provenance grammar, per-connection serve provenance, the identify
  scope gate, dial veto, scope-as-audience). Property tests run at a **fixed** seed in
  `just test`, and at a **free** seed in `just prop` for exploration.
- **Integration / multi-node** — subprocess and in-process multi-daemon discovery and
  transfer.
- **End-to-end (rootless podman)** — real `nix build`s served across separate daemon
  containers: discovery, transfer, the LAN↔public isolation bridge, and adversarial negative
  controls (dead-holder fail-over, a bounded concurrency soak). `just e2e` (subset) ·
  `just e2e-full` · `just e2e-adversarial`.
- **NixOS VM tests** (`just e2e-vm`, needs `/dev/kvm`) — a real multi-host / NAT topology,
  beyond container netns.
- **Fuzzing** — structured (proptest) fuzzing of the wire/parse surfaces: the multiaddr
  classifier, `/nar/4` bao decode, signed provider records, narinfo. Run BROAD via
  `just fuzz-smoke` with a persisted crash corpus — never the fast loop.
- **Mutation-bite discipline** — a security oracle counts only if reverting the *production*
  guard turns it RED; a test that stays green regardless is treated as a defect.
- **Frozen-wire golden vectors** — the addressed unit, the claim schema, and the discovery
  key / provider record are pinned in bytes.
- **Guards (`just lint`)** — clippy `-D warnings`, rustfmt, a no-float rule on every
  gate/decision field, daemon/testproxy independence, and discovery / DHT-isolation source
  scans.
- **Cross-model review** — security- and measurement-critical changes are gated by an
  independent build/test runner, an architecture review, *and* a separate cross-model
  reviewer, because same-model self-review repeatedly passes real defects.
- **Measurement** — egress / latency / throughput and CPU / RAM profiling (`just measure` ·
  `just profile` · `just bench` · `just profile-cpu` · `just profile-ram`).

The `testproxy/` crate is a permanent fixture over a deliberately disjoint TLS stack, owning
all fault injection so the product and the fixture stay independent witnesses. `TESTING.md`
defines what "good" and "bad" observably mean.

## Documents

- **`PRD.md`** — the durable design record: decisions, the irreversibility map, risks.
- **`docs/status.md`** — the full capability inventory.
- **`docs/peer-fabric-seam.md`** — the `PeerFabric` seam design.
- **`TESTING.md`** — what "good" and "bad" observably mean; the oracles the gates enforce.
- **`backlog/`** — the task tracker (use the `backlog` CLI, not direct edits).

## References

- [Peer-to-peer binary cache RFC / working-group poll](https://discourse.nixos.org/t/peer-to-peer-binary-cache-rfc-working-group-poll/29568)
  (NixOS Discourse) — polls the community on a decentralized binary cache motivated by
  CDN bandwidth cost; the availability / untrusted-peer / sharding objections raised
  there are the ones this design answers rather than assumes away.
- [Migration of S3 bucket payments to the Foundation](https://github.com/NixOS/foundation/issues/86)
  (NixOS/foundation) — the storage-cost side of the same problem.

Where this differs from most such proposals: it decentralizes the **bytes only** and
leaves trust exactly where it is, and it targets *bandwidth* rather than storage.

## AI assistance

This project's code and documentation were developed with substantial assistance from an
AI coding agent (Anthropic's Claude). By project convention individual commits do **not**
carry AI co-author trailers — the disclosure lives here instead. Design decisions, the
trust model, and every merge remain human-owned; the AI implemented against a
human-reviewed backlog under gated, test-grounded review.

## License

MIT — see `LICENSE`.
