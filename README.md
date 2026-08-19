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

> **Research prototype.** It has not been run against the real cache.nixos.org in a
> deployment and has not faced a public network — no residential uplinks. Today it runs
> on loopback, in-process, and single-host rootless-podman containers (NAT and relay are
> proven only on containerized NAT). Within that scope the decentralized path is real
> end to end. Whether peers actually beat a CDN is a thesis being measured, not a
> premise — see [Does this help?](#does-this-help) below.

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
startup.

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

**Bootstrapping the first peer.** A DHT can't start from nothing, so a fresh node needs a
way to meet its first peer. On a LAN this is zero-config: mDNS (`--libp2p-mdns`, off by
default) finds neighbours by multicast and hands their addresses to the kad bootstrap path
— never to content discovery. A zero-infrastructure global rendezvous over the BitTorrent
Mainline DHT was prototyped and found to discover node *membership* across NAT (though not
to traverse it); it too feeds only the address path, so content routing stays
kad-exclusive. Both are opt-in and gated by the sharing profile.

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

Honest answer: **not proven yet.** A peer serves the raw NAR while the CDN serves a
compressed file, so a peer moves more bytes per path and may lose on speed until the peer
link is itself compressed. The long tail is exactly where a CDN is strong and swarms are
weak.

Early shaped-link measurement says **supplement, not replace**: raw, a peer loses at
every size; with fast negotiated link compression the gap closes back toward parity. That
is the *bytes-per-hit* half of the question, and it matches the stated aim — bandwidth
offload — but real public-network numbers are still out.

An offline overlap probe measured the other half — *hit-rate*. Machines on the **same
nixpkgs pin** (a LAN, or an org) share almost all of a cold build's closure: overlap warms
to ~95% of paths. Machines on **different** nixpkgs revisions share essentially nothing —
store paths are input-addressed, so a different stdenv rehashes everything downstream, and
cross-revision overlap is structurally zero. So the honest first product is the **org / LAN
same-pin pool**; a global permissionless swarm across arbitrary revisions offloads nothing
unless it is segmented into same-pin cohorts. The project treats all of this as a thesis to
falsify rather than a premise.

**Measured, on real packages (a first cut) — who's faster when a peer has the path:**

| setting | faster | why |
| --- | --- | --- |
| **LAN / org** (1 Gbit) | **nix-p2p — 2–44×** | local link beats the WAN hop; serves the raw NAR, so the client skips the CDN's xz-decompress (~270 ms for `git`) |
| home swarm (100 Mbit) | nix-p2p, with light **zstd** | zstd decompresses ~3.5× faster than the CDN's xz and is cheap enough per-serve |
| open internet, comparable link | `cache.nixos.org` | its smaller xz file wins on the wire |
| no same-pin peer (cross-rev) | `cache.nixos.org` | nothing local to serve — nix-p2p falls back |

*First cut: **transfer** time only — **excludes discovery latency** (the unsettled wildcard,
esp. for small packages), and holds only where a peer has the path. Effective, apples-to-apples
(the CDN's compressed file must be client-decompressed; nix-p2p serves raw). Details:
`docs/profiling.md`.*

## Status

The decentralized path works end to end across containers: kad discovery, address
resolution with nothing injected, Bao-authenticated transfer, byte-identical delivery to
a real `nix build`, multi-provider fail-over, and a clean upstream fallback on a miss.

Landed since: zero-config LAN bootstrap (mDNS), a frozen operator-contract budget
artifact, an offline value-thesis probe (org/LAN-first), and profiling tooling.

Not yet: a public network, a real-cache deployment, and socket-to-HTTP streaming
completion — the mid-transfer failure semantics are de-risked (a killed peer still
yields a correct build via fallback), the streaming refactor itself is scoped and pending.

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
