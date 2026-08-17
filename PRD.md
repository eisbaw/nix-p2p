# PRD — nix-p2p: decentralized Nix binary cache (Candidate B)

Status: **ACCEPTED (round 6) — owner declared good enough; handed to phase 2**
Tentative-vs-Committed: **experimental** (confirmed by owner, round 1)

> **Current authority (TASK-114, Wave 2c, experiment contract
> `nix-p2p-tournament-v1`).** This PRD deliberately retains the earlier owner
> decisions as provenance. The Wave-2c reconciliation at the end of this file
> supersedes, for this wave, the older phrases **“DHT-authoritative”**, **“public
> global swarm / announcing opt-out”**, and both historical forms of the
> project-wide **20% egress / 10% latency kill criterion**. Those statements are
> not silently deleted: they explain how the project arrived here, but they are
> no longer implementation instructions. Discovery is evidence-gated; a fresh
> install is upstream-only and joins/publishes to no public network; and
> performance is adjudicated per deployment profile against preregistered
> margins and hard constraints. When old and new prose conflict, the TASK-114
> section is normative.

## Essence / problem

cache.nixos.org is a single point of failure for the entire Nix
ecosystem's *bandwidth*. Its trust role (signing narinfos) is cheap,
replicable, and not the problem; its byte-serving role is. We
decentralize the bytes and only the bytes: a localhost substituter
daemon serves Nix the same binary-cache HTTP API it already speaks,
passing signed metadata through from cache.nixos.org and fetching NAR
payloads from an iroh p2p swarm, hash-verified against the signed
NarHash. An unmodified Nix client re-verifies signature and NarHash
itself, so the daemon and all peers stay outside the trusted
computing base.

**MVP promise (settled, round 1): bandwidth offload, not outage
resilience.** Metadata always comes from cache.nixos.org (plus the
daemon's local disk cache). Full outage resilience — p2p relay of
signed narinfos — is explicitly v2; the claim schema must not
preclude it.

**Value thesis to validate, not assume (architect review, round 2):**
peers must actually beat or usefully supplement a global CDN as a
byte source. Residential uplinks, thin seeders, and leech opt-outs
all argue against; the implementation strategy below is deliberately
measurement-first so this thesis is tested before any DHT code
exists.

**HISTORICAL SCOPE CHANGE (owner directive, 2026-08-08; superseded as a
Wave-2c decision rule by TASK-114): the kill criterion was DESCOPED to a
non-blocking metric.** The project proceeded to the p2p wave regardless of the
wave-1 measurement outcome. That remains the provenance for task-16 and for why
the p2p implementation exists; it no longer means “performance cannot reject a
deployment profile.” The measurement instrument (task-9) remains the stable
comparison basis. See the current, context-specific profile rules below.


## Implementation strategy (settled, round 2, owner)

**Wave 0 is a transparent proxy**: a daemon that does nothing but
intercept binary-cache HTTP traffic and pass it to the real
cache.nixos.org. This is the hook point everything else grows from,
and it is independently useful: it carries the measurement
instrumentation (net cache egress, request timing, narinfo→nar gaps
from real builds) that validates or kills the value thesis.

Capabilities are then added gradually behind **module interfaces**:

- `NarinfoSource` — narinfo lookup (upstream HTTP now; disk cache;
  mock for tests; p2p relay in v2).
- `NarSource` — resolve(NarHash) → verified NAR stream (upstream
  HTTP now; iroh whole-blob later; chunked castore in C).
- The upstream cache itself is mockable: tests run against a fake
  cache.nixos.org with controlled latency, failures, and content.

**Two components, strictly separated (settled, round 4, owner):**

1. **The product daemon** (the decentralized proxy): very modular,
   everything behind the interfaces above.
2. **A local test cache-proxy**: a simple — hardcoding allowed —
   transparent *caching* proxy that fronts cache.nixos.org. It exists
   first as a pre-step: deep and broad test runs are developed against
   it so the real cache is never loaded needlessly. It remains
   permanently as the test fixture for fault injection (latency,
   failures, wrong/corrupt data), so adversarial-upstream logic never
   lives inside the product daemon. Product modularity is for
   capability growth; the test proxy earns none of that complexity.

   Code sharing between the two (settled, round 5, owner): **low-level
   crates only** — pure-data code such as narinfo parsing and shared
   types (likely nix-compat upstream anyway). No shared proxy or HTTP
   logic: the fixture stays an independent witness of wire behavior.

**Test strategy (settled, round 2, owner)**: container-based e2e from
the start — controlled `nix.conf`, controlled networking, multiple
daemon nodes connected to each other. Both docker-compose-style
container setups and NixOS VM tests are in scope (VM tests give real
nix-daemon + systemd semantics; compose gives fast iteration and
adversarial network shaping). The e2e harness is wave-0 scope, not an
afterthought: the additive invariant and crash behavior (below) must
be tested from the first release.

Standing test topologies (settled, round 4, owner):
- nix client → product daemon → local test proxy → (mock | real
  cache), the everyday development loop;
- **long-chain**: multiple proxies chained (client → daemon → daemon
  → … → test proxy → upstream) to prove composition — correct
  passthrough, no header/metadata mangling, sane timeout behavior —
  survives depth;
- multi-node p2p topologies with fault injection at the test proxy.

## Users / actors

- **Operator**: a NixOS/Nix user who installs the daemon and adds it
  as the preferred substituter. Expects zero behavioral change except
  bandwidth offload and bounded latency.
- **Peers**: other instances of the same daemon; untrusted byte
  sources, DHT publishers, optional gossip participants.
- **cache.nixos.org**: unchanged; sole metadata/trust authority and
  HTTP fallback.
- **HISTORICAL deployment model (round 1; superseded for Wave 2c): public
  global swarm, documented privacy risk.** Announcing was opt-out (leech mode).
  The provenance is retained, but current installs are upstream-only/private
  and every LAN or public participation mode is explicit opt-in; see TASK-114.
- **Privacy invariant (settled, round 3): no enumeration, ever.**
  Peers answer yes/no to a concrete NarHash query and serve bytes on
  request; there is no endpoint that lists holdings. Precisely: this
  protects *unguessable* paths (secret/private derivations — their
  store hashes cannot be constructed by an outsider). It does NOT
  prevent targeted membership probing of guessable public paths
  (anyone can compute the store path of any nixpkgs derivation);
  that residual leak stays documented under the public-swarm risk.

## What good looks like

- **Net egress at cache.nixos.org measurably drops** with the daemon
  enabled vs without, on a realistic multi-node testbed. (Gross
  "bytes from peers" is not the metric — hedges that lose the race
  still pull cache bytes.)
- `nix build` tail latency bounded at (cache latency + hedge window),
  holding even with completely cold daemon state. Cold start degrades
  offload ratio, never latency.
- A daemon started with empty state can resolve claims via the DHT
  and fetch from peers on its first request — no warm-up requirement.
- **Additive invariant, precisely**: the daemon advertises correct
  `nix-cache-info` (priority below cache.nixos.org's 40,
  WantMassQuery set correctly); with the daemon stopped or killed
  mid-transfer, Nix falls back and the build still succeeds. This is
  a standing e2e test, not a slogan.
- A path fetched via p2p is byte-identical to cache-served —
  enforced by the NarHash gate.

## What bad looks like

- Everyday builds get slower — DHT resolve latency (1–4 s typical)
  leaking into the request path.
- Offload theater: dashboards show peer bytes while cache.nixos.org
  egress is unchanged or worse (lost hedge races, duplicated pulls).
- A frozen-surface change after peers exist (claim schema, DHT key
  derivation, addressed unit) that splits the network.
- The daemon must be trusted for integrity (design bug).
- DHT announce traffic that is abusive to the shared DHT or melts
  home NAT tables.
- Works in the container harness, fails behind real-world NAT.

## Scope & non-goals

In scope (MVP, in delivery order):
- **Wave 0**: local test cache-proxy (the pre-step shielding
  cache.nixos.org) + transparent product proxy + `nix-cache-info`
  semantics + narinfo/claims disk cache + measurement + container/VM
  e2e harness with mock upstream, long-chain, and multi-node
  topologies.
- **Then (historical round-3 discovery plan; superseded by TASK-114)**:
  iroh-blobs whole-NAR transfer (client + provider) behind
  `NarSource`; DHT-authoritative claim resolution **plus bounded
  fan-out yes/no queries to known peers** (this is how un-announced
  whole-store supply becomes reachable, and the gossip accelerant's
  real role: maintaining a set of live peers worth probing);
  speculative prefetch; HTTP hedge with **throughput-based abort** (a peer that
  starts fast then stalls at 50 KB/s must lose the race too — start
  latency alone is not the guardrail); announce-after-fetch with an
  explicit **announce budget**; leech-mode flag.
- **Seeding via `nix-store --dump`** (or equivalent): NARs are
  regenerated deterministically from /nix/store on demand — no
  second copy of the store, no retention policy problem, and NarHash
  for any local path is computable locally (no narinfo herd against
  the cache). Serving any bit-identical path — including locally
  built ones — is safe *by construction*: the consumer's NarHash gate
  is the arbiter, not the producer's provenance. (Reversed from
  round 2 after architect review; final scope = open question 2.)
  **SETTLED by task-61, 2026-08-09 — see "Supply model" below: this
  bullet is now implemented, not aspirational, and its costs are
  written down.**
- Linux first. NixOS module for deployment.

Non-goals (explicit):
- Outage resilience for metadata (v2; schema keeps the door open).
- Decentralizing *trust* (Trustix territory).
- Chunk-level dedup (Candidate C; seam kept open).
- Incentives/economics; long-tail availability guarantees. The long
  tail is where a CDN is strong and swarms are weak; MVP does not
  pretend otherwise.
- Private swarms / pre-shared topic keys (possible later).

## Key decisions (settled)

| Decision | Choice | Why |
|---|---|---|
| Integration | Native substituter daemon, not nginx proxy | Substituters list does fallback; daemon sees narinfo → prefetch; one moving part |
| Delivery | Transparent proxy first, capabilities behind module interfaces, mockable upstream (round 2, owner) | Hook point + measurement before p2p; value thesis tested before DHT code |
| Testing | Container + NixOS VM multi-node e2e from wave 0 (round 2, owner) | Controlled nix.conf/networking; real nix-daemon semantics; crash/fallback tests standing |
| Payload granularity | Whole-NAR blobs | One BLAKE3 per NAR; no chunking agreement; shippable (C deferred) |
| **Addressed unit** | **Raw (uncompressed) NAR**, BLAKE3 (round 3, owner) | Enables `--dump` seeding + C dedup; narinfo transport fields rewritten (unsigned, legal); ~3x wire bytes until per-connection zstd (a policy surface, not frozen) |
| **Seeding scope** | **Whole /nix/store via `--dump`**, but strictly **query-answer only: yes/no per NarHash, no enumeration** (round 3, owner) | Largest supply at zero storage cost; listing endpoint would leak secret path names — see privacy invariant below |
| **Announce policy** | **On-demand only**: publish a claim only when a path is fetched through the daemon (round 3, owner) | Demand-proven records; minimal DHT load; supply lags demand — un-announced holdings reachable via peer yes/no queries |
| **Kill criterion (historical; superseded by TASK-114)** | **<20% net cache-egress cut on the favorable testbed kills the p2p thesis**; p95 build latency regression must stay <10% (round 3, owner) | Preserved provenance; Wave 2c now applies profile-specific margins plus hard latency/privacy/resource constraints rather than killing every context at once |
| Transport | iroh / iroh-blobs (one `NarTransfer` backend behind the `PeerFabric` seam) | BLAKE3 incremental verified streaming, QUIC + holepunching; not the fixed stack — see P2P substrate row |
| Discovery (historical; superseded by TASK-114/TASK-126) | DHT-authoritative, gossip as accelerant (round 1, owner) | Preserved provenance; the chosen substrate remains evidence-gated, but production now requires a passing decentralized exact-key mechanism |
| **P2P substrate** (2026-08-12) | **libp2p-PRIMARY behind the `PeerFabric` seam: libp2p-kad is the mandatory discovery layer; iroh is an OPTIONAL transport** | iroh is a connectivity substrate with NO content-provider routing ("who has hash X?") — only address lookup; so discovery is `libp2p-kad` `get_providers`/`start_providing` (robust, IPFS-proven), adopted not invented (no hand-roll, no Kademlia-over-iroh). iroh-blobs is kept as an optional `NarTransfer` for its NAT traversal, measured vs libp2p transport in the tournament; discovery is libp2p-kad regardless. Serving core stays stack-neutral. See `docs/peer-fabric-seam.md` |
| Latency guardrails | Prefetch + hedge (throughput-abort) | The only thing keeping DHT seconds off the user path — load-bearing |
| Metadata | cache.nixos.org only + daemon disk cache | Bandwidth offload MVP (round 1, owner) |
| Privacy (historical; superseded by TASK-114/TASK-120) | Public swarm, documented risk, leech opt-out (round 1, owner) | Preserved provenance; fresh installs are upstream-only/private and LAN/public participation is explicit opt-in |
| Trust | Signed fields untouched; Nix verifies sig + NarHash | Daemon/peers outside TCB. Note: passthrough is **not byte-verbatim** — see compression, open question 1 |
| Language / toolchain | **Everything in Rust** (tokio); **nix flakes** for the dev/build environment (round 4, owner) | iroh is Rust; nix-compat crates exist; flakes pin the toolchain and feed the NixOS VM tests directly |
| Test upstream shield | Separate simple local caching proxy, permanent fixture, fault injection lives there — never in the product (round 4, owner) | Protects cache.nixos.org from test load; keeps adversarial logic out of the modular daemon |

## Modularity seam for Candidate C (load-bearing requirement)

- **Claim record versioned from day one**; payload is a tagged enum
  (`WholeNar { blake3 }` now, `CastoreRoot { digest }` later);
  reserved room for v2 narinfo relay and future claim signatures.
- **`NarSource` trait** hides whole-blob vs chunked assembly from the
  HTTP layer (and, in wave 0, hides plain upstream HTTP).
- **B→C is a supply contract, not just a schema swap** (architect):
  C nodes MUST remain able to serve whole-blob requests to B nodes —
  render the NAR from chunks and keep/compute the bao outboard for
  the whole-NAR BLAKE3. Without this stated requirement, C forks the
  supply network the day it ships.
- Transfer uses stock iroh-blobs ALPN.

## Irreversibility map

Frozen once peers exist (deep-review surfaces):
- **The addressed unit and hash function** — raw NAR vs compressed
  file, and BLAKE3-of-that-unit (open question 1 — must be settled
  before any peer transfer ships). Bytes peers already hold cannot be
  re-addressed; this freezes *harder* than the schema, which can at
  least be versioned.
- **Claim record schema** (version field, payload enum, reserved
  fields).
- **Any selected global discovery mechanism & key derivation** (substrate,
  NarHash→key mapping, record contents). Historically this assumed a DHT;
  TASK-126 now **adopts** (does not hand-roll) one viable decentralized substrate
  behind the `PeerFabric` seam and freezes OUR key/record schema as an *opaque
  value inside it*, so the substrate's own wire format may churn without touching
  the freeze. Failure to find one blocks production qualification rather than
  completing the gate.
- **Trust invariant**: signed narinfo fields untouched + NarHash
  gate. Changes here are security events, not refactors.

Fixed externally (cannot change, must conform):
- Nix binary-cache HTTP API (incl. `nix-cache-info`
  priority/WantMassQuery semantics, narinfo compression/transport
  fields); ed25519 signature scheme; Nix's client-side narinfo cache
  behavior (30-day positive TTL — see risk 5); (if mainline) BEP
  semantics and rate norms.

Tentative / replaceable (velocity surfaces):
- ~~Whether a local blob copy exists at all (`--dump`-on-demand vs
  stored blobs — but note: switching *from* stored blobs later means
  re-hashing and a seeding gap; decide deliberately in phase 2).~~
  **DECIDED (task-61, 2026-08-09): no local blob copy exists at rest.
  See "Supply model" below for the arms, the numbers, and the costs
  paid — the re-hash and the seeding gap are now REAL, accepted and
  quantified, not hypothetical.**
- Narinfo/claims disk-cache format; gossip accelerant (optional by
  design); hedge/prefetch/announce policies; NixOS module interface;
  metrics; the container harness internals.

## Supply model (task-61, settled 2026-08-09) — how a node produces the bytes it serves

The question the owner asked: *must a node publish and hold in memory what it
has cached locally?* **No.** This section records the decision, the arms that
lost, and what the winner costs. It decides the irreversibility-map entry
"whether a local blob copy exists at all".

### The measurement that forced the decision

Measured on the owner's real store. **Corrected 2026-08-10** — the first
version of this table used `nix path-info --all`, which counts `.drv` files.
Those are local evaluation artifacts that cache.nixos.org does not serve, and
they are 85.6% of all paths while holding 0.2% of the bytes, so they dragged
the path count up ~7× and the mean NAR *down* ~6×. Re-derived directly from
`/nix/var/nix/db/db.sqlite`:

| Quantity | Value |
|---|---|
| Valid paths (all) | 85,808 |
| — of which `.drv` | 73,412 (85.6%), only 263 MiB |
| **Servable output paths** | **12,396** |
| Total NAR (NarSize, uncompressed) | 105,713 MiB ≈ 103 GiB |
| — signed by cache.nixos.org | 6,769 paths / 53,854 MiB (**50.9% of bytes**) |
| — locally built (`ultimate`) | 2,250 paths / 35,870 MiB |
| Mean NAR (servable) | 8.53 MiB |
| p50 / p90 / p99 | 0.10 / 4.48 / 151.06 MiB |
| **p100** | **3186.03 MiB** |
| Byte concentration | top 151 paths = 73.5%, top 691 = 91.7% |

Two consequences the earlier table obscured. **Half the servable bytes carry no
upstream signature**, so under the no-enumeration rule they can never be
*published* and stay reachable only by direct hold-query — which makes the
batched hold-query load-bearing rather than an optimization. And the
distribution is far more extreme than "mean 1.44 MiB" suggested: the median is
100 KiB while 151 paths hold three quarters of all bytes.

Against task-65's fitted holder cost of **2.0033 bytes of peak RSS per byte of
uncompressed NAR** (95% CI 2.0021..2.0046, R² 1.0000, ≥5 NAR sizes):

- Holding the whole servable store in the iroh-blobs `MemStore` would cost
  **~206 GiB of RAM** (~105 GiB at the post-supply-model 1.02 slope).
  Disqualifying either way, and not by a small factor.
- The tail is the sharper problem: **one** p100 path costs **~6.2 GiB of RAM to
  serve** at the old slope (~3.2 GiB at the new one) — model output,
  extrapolated past the 8..128 MiB fitted grid, label it as such. The daemon is
  outside the trust base, so *any* peer can ask for the largest NAR we announce.

### The arms

**(a) Regenerate on demand via `nix-store --dump`; hold only the in-flight
serve.** Optionally persist bao outboards (~0.4% of content ≈ 0.6 GiB) rather
than content.

**(b) A bounded, evicting on-disk content store (`FsStore`).** An unbounded one
is a full second copy of /nix/store — 152 GiB, which does not even fit on this
project's development host (43 GiB free). A *bounded* one fits, but then supply
is capped at the budget, which throws away the exact property the "Seeding
scope: whole /nix/store via `--dump`" decision bought: **largest supply at zero
storage cost**.

### Decision: arm (a). No local blob copy exists at rest.

A copy of a NAR exists only for the duration of a serve, and its size is now
bounded by an explicit budget (task-72). The PRD's "no second copy of the store,
no retention policy problem" position is **upheld and implemented**, not
weakened.

### What arm (a) costs — stated, not hand-waved

1. **Re-hash on demand.** Every serve of a path whose `BLAKE3(RawNarV1)` is not
   already cached in memory costs one full `nix-store --dump` (a read of the
   whole path off disk) plus one BLAKE3 pass, and iroh-blobs recomputes the bao
   outboard on add. Task-64 measured the peer path at ~204 MB/s CPU-bound with
   72% of the work below our code, so the hash is not the bottleneck — the dump
   is. Repeat serves inside one process pay it once (the availability index
   caches the digest under a single-flight lock).
2. **A real, bounded seeding gap.** A restart empties the blob store *and* the
   in-memory digest cache. Until a hold-query re-derives a path's digest, a
   claim already published to the DHT naming that digest is undiallable: the
   fetching peer gets a bounded `Unavailable` and falls back to upstream. This
   is an AVAILABILITY cost, never an integrity one (Nix re-verifies sig +
   NarHash; the daemon is outside the TCB). Warming the whole cache at boot is
   NOT an option — it would re-dump and re-hash 152 GiB.
3. **In-flight memory becomes the whole memory cost, so it must be bounded.**
   With nothing held at rest, the only RAM the supply path costs is the NAR
   being served right now. Bounding it is task-72 and is a hard requirement of
   this decision, not a follow-up.

### Rejected sub-option: persisting bao outboards

The brief's candidate was the outboard (~0.4% of content, ~0.6 GiB for this
store) as the artifact worth keeping. Rejected, for two reasons:

- **It does not buy the thing that hurts.** The outboard removes the *tree*
  recomputation, not the dump — bao still verifies against the content, so the
  content must still be regenerated. Cost #1 above is dominated by the dump.
- **The pinned API cannot express it.** iroh-blobs 0.103 ships exactly two
  writable stores (`mem`, `fs`), and each owns its content; there is no public
  way to serve a blob whose outboard is persisted while its content is produced
  on demand. Implementing it means a custom `Store` impl against an unstable
  trait. Re-openable if that is ever justified; not justified now.

**What IS worth persisting is the 32-byte digest, not the 620 MiB outboard.**
Binding `NarHashKey -> (StorePath, Blake3Digest, NarSize)` on disk costs about
40 bytes per path beyond the registration already persisted — **~0.5 MB for the
12,396 servable paths, 0.0005% of content** — and closes cost #2 (the seeding gap)
outright, because a store path's content is immutable by Nix's own invariant, so
the digest cannot go stale. It is deliberately NOT done in task-61/72 (the
availability index's stated design is to persist only the source of truth, and
reversing that is its own reviewable change); it is filed as task-82.

### What is NOT in this decision

Task-61 AC#3 (a numeric disk budget, an eviction bite, a kill-9 reclamation
bite) was written **conditional on choosing an on-disk store**. Arm (a) was
chosen, so it does not apply as written, and it is not silently dropped: its
RAM analogue is a hard requirement of task-72 — a numeric served-bytes budget,
an eviction bite proving the store releases after a serve, and a residency
oracle that is not peak RSS.

## Weak assumptions & risks

1. **Value thesis** (the weakest point, per architect): peers may
   simply be a worse byte source than Fastly for everything the
   swarm can realistically hold (popular recent paths — exactly what
   a CDN caches well). Wave-0 measurement exists to answer this
   before p2p code is written. If it answers "no", the honest outcome
   is stopping.
2. **Prefetch window is structurally zero on repeat runs**: Nix's
   narinfo cache (30-day positive TTL) skips the narinfo GET, so the
   daemon gets no lead time. Mitigation: daemon's own persisted
   claim/narinfo cache makes repeat-path resolution local-instant;
   first-sight paths still enjoy the prefetch window. Offload on
   repeat paths depends entirely on this persistence working.
3. **DHT latency (1–4 s)** must be fully masked by prefetch + hedge;
   if real narinfo→nar gaps are shorter, hedge wins, offload
   collapses (latency stays bounded — the failure is thesis-level,
   not UX-level).
4. **Announce-on-demand means supply lags demand** (settled,
   round 3): a path never fetched through any daemon since deployment
   is undiscoverable via the DHT, regardless of how many stores hold
   it. First-sight fetches always hit the cache; peer yes/no probes
   partially compensate. A young network offloads little — the kill
   criterion measures steady state, not launch day.
5. **Raw-NAR wire cost**: if the addressed unit is the raw NAR
   (open question 1), peers ship ~3x the bytes of xz'd transfers.
   Per-connection compression can claw this back but is added
   complexity. If the unit is the compressed file, `--dump` seeding
   and all of Candidate C's dedup die. This tension is the sharpest
   open decision.
6. **Claim spam is amplification DoS, not merely wasteful**: a lying
   claim can point at an attacker-chosen huge blob; iroh verifies
   against the *claimed* hash, so the NarHash gate fires only after
   the full download. Requirement: abort any transfer exceeding the
   signed NarSize/FileSize. (Schema must also not preclude claim
   signatures later.)
7. **Seeder density**: leech opt-outs + laptops + long tail. Accepted
   and stated honestly.
8. **n0 relay dependence** for holepunching; self-hosted relays
   post-MVP.
9. **Privacy accepted, not solved**; leech mode is the mitigation.
10. **iroh API churn**: accepted maintenance tax.
11. **The peer path does ~13x TCP's CPU work per byte, and one
    connection recruits only ~2.7 of 14 cores to do it** (MEASURED,
    task-64, `daemon/examples/iroh_throughput.rs`, `just iroh-bench`,
    110 MiB loopback, medians of 5, 14-core host). Throughput and CPU
    per byte, same host, same payload, same run:

        loopback TCP, one write_all     1165 MB/s   0.98 cpu-ns/B
        loopback TCP, 1452 B writes     1154 MB/s   1.35
        plain UDP, 1452 B datagrams      287 MB/s   4.95
        raw QUIC on the iroh stack       445 MB/s   5.64
        iroh-blobs get_blob              318 MB/s   9.47
        IrohTransport::fetch (product)   204 MB/s  13.20

    CAUSE, with the control that pins it. Two hypotheses were tried and
    REFUTED before this one, so the discriminating experiment matters
    more than the story: `tcp_write_1452` hands the SAME socket and
    protocol the SAME bytes in QUIC-sized pieces — ~79 000 writes
    instead of one — and throughput does not move (1154 vs 1165) even
    though context switches rise 3.6x. So per-syscall granularity and
    handoff COUNT are not the binding term. What does bind is
    per-PACKET work: those 79 000 TCP writes are coalesced by the
    kernel into 3 723 segments of ~31 KB, while the UDP arm's 79 000
    writes become 79 492 real packets of 1451 B — and that difference
    alone costs +3.6 cpu-ns/B (~5.5 us of CPU per extra packet, both
    directions, including the userspace async wakeup). QUIC's GSO wins
    5.8x of that back (13 784 units at ~8.4 KB), which is why QUIC
    beats naive UDP while also doing crypto, congestion control and
    reliability. On top of the packet path, iroh-blobs+bao adds ~3.8
    cpu-ns/B of per-BYTE work at unchanged packet count.
    NOT the cause, each ruled out by measurement: CPU saturation (2.7
    of 14 cores; no OS thread above 0.61 on any iroh arm — though see
    the limits below); crypto; BLAKE3/bao alone (blake3 over the whole
    payload is 0.45 cpu-ns/B, ~3%); our own copies (~12%).
    OURS vs NOT OURS: ~72% of the per-byte cost sits below our code
    (stable at 68-73% across runs). Our `Vec` accumulation plus
    `verify_blake3` and the per-leaf timeouts are ~28%, so deleting ALL
    of our own overhead buys 1.4-1.6x — not the 3.6x the task-42
    framing implies. NOTE one impurity: a slice of the "not ours"
    bucket IS ours (`IrohProvider`'s own provider-event plumbing runs
    on the serve path).
    NOT a host ceiling: concurrent fetches aggregate 306 / 433 / 643
    MB/s at N = 1 / 2 / 4 — sublinear but still climbing at 4, so the
    limit is per-connection. That is the one large lever not yet
    pulled (task-67), and it costs ~3x the CPU for ~2x the bytes.
    WHAT THIS DOES **NOT** ESTABLISH. (a) Every number is zero-RTT
    loopback. Single-stream QUIC on a WAN is bounded by receive window
    over RTT, a regime NO arm here touches, and quinn's defaults can
    bind well below these figures at 30-100 ms RTT. So this is NOT
    "peers are fast enough on a real network" — that is unmeasured and
    is task-63's job. (b) Which per-byte term dominates INSIDE the
    transport is not resolved: the iroh-blobs-vs-our-overhead split
    swings by +-0.7 ns/B between runs of the same binary, so quote the
    ~72% headline, never the sub-percentages. (c) `busiest-thread`
    rules out a saturated OS THREAD, not a saturated tokio TASK — on a
    work-stealing runtime one pegged task migrates and reads as ~0.5
    on several threads. Settling that needs a `current_thread` arm
    that does not exist yet.
    HONEST LIMITS OF THE INSTRUMENT: provider and client share ONE
    process and ONE tokio runtime, so absolute figures are likely
    pessimistic — which is why `fetch` reads 204 MB/s here while
    task-42's in-daemon figure is 210 MB/s for a path that ALSO
    contains all of nix. Conclusions rest on ratios between arms
    measured under identical conditions. One host; load average moved
    2.7-6.5 between runs and several arms move 20% with it; treat
    sub-10% differences as noise.
    NEGATIVE RESULT worth keeping: pre-sizing the receive buffer was
    measured in situ before being written and is worth 0-3% (inside
    noise), against 12% for the same change in isolation. Not shipped;
    it would also let an unverified narinfo NarSize trigger a huge
    eager allocation, and allocation failure in Rust aborts.
12. **Stale figures, twice superseded**: fig-candidate-B/C SVGs show
    gossip-first with tracker cold-start. Round 1 superseded that with a
    DHT-authoritative decision; TASK-114 has now superseded both with an
    evidence-gated mechanism set. Tournament reports may retain unsupported
    cells, but the product gate requires a passing decentralized global cell.
    The figures are provenance only until revised to the current contract.

## Open questions (remaining — deferred to phase 2 unless grilled further)

1. **Global DHT mechanism (historical question, now owned by TASK-126)**
   (frozen surface, needs a spike not a guess):
   an Iroh-native decentralized content mechanism if one exists vs a dedicated
   Kademlia/DHT substrate vs Mainline only after TASK-96. A centralized tracker
   is an optional comparator, not a candidate for this gate. The decision pins
   provider NodeId records, bootstrap independence, privacy and announce cost;
   TASK-89 separately owns NodeId-to-address dialability.
2. **Peer-query protocol details**: fan-out bound, timeout, how the
   known-peer set is maintained (gossip membership vs past-peer
   cache), and rate-limiting so yes/no probes do not become the new
   enumeration vector (an attacker sweeping queries at high rate).
3. **Figure revision** (housekeeping): fig-candidate-B/C still show
   gossip-first + tracker cold-start. The intermediate instruction to redraw
   them as DHT-authoritative is itself superseded; any revision must show the
   TASK-114 evidence-gated mechanism/profile contract.

## Wave 2 scope (owner goal, 2026-08-08; historical framing)

Build the actual decentralization and CHARACTERIZE it. Not just "make
iroh work" — model and profile the resource/performance envelope, then
derive policies from what the models show.

**Transports (pluggable behind the frozen `NarSource` seam):**
- iroh whole-NAR (Candidate B payload) — FIRST PRIORITY.
- BitTorrent — a SECOND transport backend; the transport interface and
  the claim schema must admit it without a network fork.
- (chunked/castore = Candidate C, later.)

**Discovery/claims (historical 2026-08-08 plan; superseded by TASK-114):**
DHT-authoritative (mainline vs BEP44 vs iroh-native — a spike, first frozen surface), gossip accelerant,
announce-on-demand, no-enumeration privacy (yes/no peer probes),
NodeId->addr via iroh discovery. Keyed on `NarKey::SignedNarHash`
(seam already frozen wave-1) via the correlation catalog.

**Modeling & profiling (load-bearing, reuse/extend task-18 S5
machinery):** scenario models covering TYPICAL and PATHOLOGICAL cases,
estimating **RAM, disk, latency, throughput, and speedup over
cache.nixos.org**. Pathological cases to model at minimum: a slow/
throttled peer on a HIT; a dead/unreachable holder after a positive
claim; DHT resolve timeout / cold-start empty index; NAT-blocked peer
needing relay; thundering herd on a popular path; a lying/spam claim;
seeder churn. Extrapolate to 10s/100s/1000s of peers per S5 (measure
1..30, regression-fit, honest resource-laws-only caveat).

**Policy derivation (findings -> backlog tasks):** the models surface
the decisions. The archetype the owner named: on a HIT whose transfer
is extremely slow, do we (a) abort and fall back to cache.nixos.org,
(b) delayed-race / hedge (start the cache fetch, first-past-the-gate
wins), or (c) adaptive by observed throughput? File a policy task per
such decision the scenarios expose; do NOT hardcode a policy the data
hasn't justified.

**Grounding:** the wave-1 measurement instrument (`net-upstream-egress-v2`,
which already counts a peer hit as a valid 0-egress crossing) is the
speedup/offload yardstick; task-35's real-upstream narinfo->nar gap is
the prefetch-vs-hedge design input.

## Wave 2c reconciliation and tournament decision contract (TASK-114)

This section is the current product/experiment authority. It reconciles the
historical decisions above without erasing them. The contract version is
**`nix-p2p-tournament-v1`**; TESTING.md pins the executable scenario and report
semantics. The experiment remains allowed to conclude that upstream-only, a
LAN-only deployment, consume-only operation, a static backend, or no acceptable
public P2P candidate is the correct result.

### Current product and privacy contract

The invariant boundary remains narrow: signed metadata and trust stay upstream;
only NAR payload bytes may be decentralized; Nix still enforces signature and
NarHash. Discovery is **evidence-gated**, but production qualification now
requires decentralized global exact-key discovery. Global DHT, bounded direct
hold-query, local discovery and the optional centralized tracker comparator are
independent mechanisms behind `ContentDiscovery`. TASK-126 must freeze a viable
decentralized NAR-identity-to-provider-NodeId contract and TASK-103 must
implement and pass it. An unsupported or central-only result leaves the product
gate blocked; it is not a completed discovery capability. Tracker and
named-candidate hold-query must never masquerade as the decentralized global
path.

The following operations are distinct configuration and evidence axes; enabling
one never implies another:

1. **Local discovery** — LAN-scoped presence/address discovery such as mDNS.
2. **Node/address discovery** — learning a NodeId and dialable direct/relay
   locations from an explicit peer list, prior rendezvous, tracker, DNS or DHT.
3. **Content discovery** — asking which named NarHash has an offer; direct
   hold-query remains named-key-only and is not global discovery.
4. **Publication** — emitting a content key/record to LAN, tracker, DHT or
   Mainline infrastructure.
5. **Serving** — accepting inbound requests and uploading payload bytes.
6. **Lookup leakage** — disclosing an IP, NodeId or queried content key to a LAN
   peer, tracker, DNS resolver, relay, DHT/Mainline participant or bootstrap
   service even when publication and serving are off.

A fresh installation selects **`upstream_only`**. Local/P2P discovery, inbound
serving, publication, public trackers, public DHT/Mainline server participation,
and public relay/network joining are all off. Merely installing or starting the
daemon therefore emits no P2P discovery traffic. `consume_only`, `lan_share`
and `public_share` require explicit operator selection; public lookup itself is
public-network participation and is not smuggled into consume-only. A
consume-only configuration can suppress publication and serving yet still leak
lookups if the operator explicitly enables a public lookup mechanism; preflight
must say so. TASK-120 owns the single typed configuration, budgets, preflight
and status proof. TASK-102 remains the publication gate: a public record may
name only content established as signed-public upstream. No mode permits
inventory enumeration.

### Pluggable P2P substrate — the PeerFabric seam (2026-08-11)

All p2p behaviour sits behind one intention-level internal seam, `PeerFabric`,
which names *what the daemon wants* of any substrate — find providers, announce
availability, locate a node, fetch a NAR, serve a NAR, ask a peer, discover LAN
peers — never how a stack does it. The API and its churn-prone detail live in
`docs/peer-fabric-seam.md`.

**Why libp2p is the primary stack and iroh is optional — iroh's shortcomings
(owner direction 2026-08-12).** iroh is a *connectivity substrate*, not a general
P2P framework. Its whole API is "give me a cryptographic `EndpointId` and I will
establish a good QUIC connection to it" — excellent NAT traversal, relay fallback,
QUIC multipath. What it does **not** provide is the thing a decentralized cache
most needs:
- **No content-provider routing.** iroh has no "who has hash X?" query — no
  Kademlia `GET_PROVIDERS`/`ADD_PROVIDER`, no generic content DHT. Its only DHT is
  an *address-lookup* mechanism (`EndpointId → signed pkarr record → addresses`,
  optionally via the BitTorrent Mainline DHT); you must already know the
  EndpointId. (TASK-126 spike: `iroh-dht-experiment` stores a fixed typed enum,
  not opaque bytes, so it cannot even be bent into our provider record.)
- **No generic distributed key/value store, no provider records, no rendezvous
  for unknown peers.** iroh's own docs say how peers learn about one another is an
  application concern (QR code, tracker, gossip, DHT — your problem, not iroh's).

So iroh gets you *from an EndpointId to bytes* superbly, but not *from a store-path
to an EndpointId*. A global, permissionless Nix cache needs the latter, and no
iroh project delivers it at Nix scale — so we do not build on iroh's discovery, we
adopt libp2p's. Durable decisions:

- **libp2p-kad is the discovery layer — mandatory, robust, adopted.**
  `start_providing`/`get_providers` is exactly our store-path→providers query, and
  it is IPFS-mainnet-proven (years of sybil/eclipse/republish hardening — an
  availability property that matters for a permissionless global DHT and that iroh
  and any fresh Kademlia lack). We **use the robust existing library**; we do NOT
  hand-roll a Kademlia and do NOT run Kademlia-over-iroh (rejected as fundamental
  research). `dig-dht` is an interesting standalone-Kad reference but is
  v0.11/unproven — a comparison arm at most, never the primary dependency.
- **iroh is an OPTIONAL transport, not the architecture.** iroh-blobs whole-NAR
  transfer works today (the s6-p2p peer-served build is green) and iroh's NAT
  traversal is genuinely strong for residential peers — so iroh is kept as a
  swappable `NarTransfer`/`NarServer` backend. Whether it beats libp2p's own
  transport (request-response/stream over AutoNAT/DCUtR/relay) on real NATs is what
  the transport tournament measures; if it does not, the product collapses to pure
  libp2p. **Discovery is always libp2p-kad regardless of transport.**
- **The frozen discovery surface is our schema as an opaque value inside the
  substrate** (`ContentKey → signed ProviderRecord bytes`); the multi-transport
  `offers` in that record are exactly right now that libp2p and iroh transports
  coexist. Substrate wire churn never touches the freeze (see the irreversibility
  map).
- **Seam packaging.** The frontend stays stack-neutral (crates: `peer-fabric` seam
  ← `daemon-core` frontend ← `fabric-libp2p` / `fabric-iroh`); the serving core
  holds zero p2p types. `ProviderDirectory` is always libp2p-kad; `NarTransfer` is
  libp2p (default) or iroh (optional). A pure `daemon-libp2p` links one stack; an
  iroh-transport build additionally links iroh for the data plane only. A single
  ed25519 keypair derives both the libp2p `PeerId` and the iroh `EndpointId`
  (same-keypair, not byte-equal).
- **The seam changes packaging, not the gates.** Production still requires a
  passing decentralized exact-key mechanism (TASK-126 froze the contract, TASK-103
  implements + passes it over libp2p-kad); a backend swap is never a shortcut
  around evidence.

This reconciles the earlier "Transport: iroh/iroh-blobs" and "everything in Rust,
iroh is Rust" lines: still Rust, iroh still serves and transfers the bytes, but
**content discovery is libp2p-kad** and iroh is now one backend behind the seam
rather than the substrate itself. The default is therefore **dual-stack** — an
evidence-forced flip of the original iroh-first single-stack preference, not an
aesthetic choice.

### Execution order (libp2p-primary — reconciled 2026-08-15)

**Reconciliation note (2026-08-15, TASK-202).** This subsection historically
read as an "Iroh-first execution order" whose gate was to "prove global Iroh
peer and decentralized content discovery before LAN." That framing is aligned
here to the libp2p-primary authority above (2026-08-12) and to what has since
shipped. The alignment is a drift-fix, not a new product call: the authority
already decided that iroh has **no content-provider routing**, so an
"Iroh global content-discovery gate" was a category error; discovery is
libp2p-kad. Concretely this note (a) re-points the decentralized-discovery
production gate at libp2p-kad, which is **proven** — TASK-126 froze the exact-key
contract and TASK-103 implements and passes it (real multi-node decentralized
test green, TASK-155 evidence), with store-supply and byte-identical transfer
also proven (TASK-158/TASK-193/TASK-194, streamed NAR TASK-157); (b) marks the
iroh-framed discovery-gate tasks (TASK-132/TASK-133/TASK-136), the iroh
node/address-discovery arm (TASK-137/TASK-138/TASK-139/TASK-89) and the iroh LAN
tasks (TASK-130/TASK-116) as **superseded for discovery** — now Low priority +
`deferred-pending-202`, retained only as optional iroh-transport reference; and
(c) **preserves iroh as an optional, measured transport backend** — the transport
tournament is deferred basics-first (owner steer: decentralized discovery and
robust connectivity first), **not dropped**, so the dual-stack transport-tag work
(TASK-156/TASK-183) stays deferred-not-cancelled. (Updated owner steer 2026-08-15:
fast link-compression is pulled EARLIER — it is the value-thesis lever that brings
the peer path to near-parity, an unsigned transport field that never touches the
frozen addressed unit — see TASK-203; content-addressed variable chunking à la
casync is a separate later demo-crate spike, distinct from this transport
tournament — see TASK-215.)
The build order below is implementation risk ordering only:

1. **libp2p-kad decentralized discovery is the production gate — and it is
   proven.** On the persistent shared runtime (TASK-115), TASK-126 freezes the
   mandatory decentralized exact-key contract (NAR identity → bounded provider
   NodeIds, no central tracker) and TASK-103 implements and passes it over
   libp2p-kad `start_providing`/`get_providers`. **Discovery is libp2p-kad, never
   global iroh content discovery** — iroh has no `GET_PROVIDERS`, so proving
   "global iroh content discovery" is a category error under the authority above.
   TASK-100 and TASK-102 establish the typed content seam and the single
   publication-eligibility gate. The requester may receive operator-level
   bootstrap configuration for multiple independent DHT/routing nodes, but no peer
   address, claim, per-content locator, magnet, prior peer rendezvous state or
   equivalent test injection; endpoint bind scope alone never activates discovery
   or public participation. Unsupported or central-only discovery blocks
   production qualification rather than completing this milestone.
   TASK-134/TASK-135/TASK-101 remain optional centralized tournament comparators
   that never satisfy this gate, and TASK-96 is consumed only if TASK-126
   explicitly selects Mainline. The iroh-framed global-discovery journey/gate
   tasks (TASK-132/TASK-133/TASK-136) and the iroh node/address-discovery arm
   (TASK-137/TASK-138/TASK-139/TASK-89) are superseded for discovery (Low +
   `deferred-pending-202`); they are optional iroh-transport reference material,
   not the production discovery gate.
2. **The libp2p data plane is proven; the transport tournament is deferred
   basics-first, not dropped.** libp2p store-supply and serving
   (TASK-158/TASK-193) and byte-identical end-to-end supply (TASK-194), with
   streamed NAR transfer (TASK-157), are green — the libp2p transport works from
   cold libp2p-kad discovery through fetch. Iroh remains an **optional, measured**
   `NarTransfer`/`NarServer` backend behind the seam: whether iroh's transport
   beats libp2p's own transport (request-response/stream over AutoNAT/DCUtR/relay)
   on real NATs is exactly what the transport tournament measures, under one
   libp2p-kad discovery; if it does not, the product collapses to pure libp2p.
   Per the owner's basics-first steer, the tournament and its dual-stack
   transport-tag work (TASK-156/TASK-183) are **deferred, not cancelled** — iroh
   stays a funded measured arm and the winner is decided by evidence, not here.
   The LAN component (TASK-130) and LAN BatchHoldQuery slice (TASK-116) are
   likewise deferred (Low, `deferred-pending-202`) and are no longer gated behind
   an iroh global verdict.
3. **Iroh transport reference (deferred optional-transport measurement).** When
   the tournament is scheduled, exercise the production-shaped 10+ node iroh
   harness (TASK-87), measure iroh raw and compressed from cold discovery through
   real-Nix completion (TASK-88), land authenticated HTTPS upstream support
   (TASK-22/TASK-24) and negotiated, bounded iroh raw/zstd operation (TASK-99,
   raw fallback explicit), and close the fresh-host operator journey (TASK-45).
   TASK-120 makes the operator-mode mapping authoritative and is a hard
   prerequisite for the production-shaped harness. TASK-131 may later consume
   TASK-96/TASK-120 as an optional Mainline address adapter and comparison cell;
   it neither blocks nor qualifies anything. These artifacts are an iroh
   **reference, not a default-policy verdict** (TASK-87/TASK-88 are Low +
   `deferred-pending-202`).
4. **BitTorrent grounding and implementation stay far-future**, beginning only
   after the tournament evidence freezes (TASK-117, TASK-75, TASK-118, TASK-119,
   then conditional TASK-121; Low, `deferred-pending-202`).
5. After both transport backends exist and are measured, run cross-backend
   property/fuzz rigor and the preregistered sequence: diagnostic raw Stage A
   (TASK-125), real-network development/training evidence (TASK-80), Stage-B
   training (TASK-122), training-only fitting (TASK-44), sealed-A2 validation
   (TASK-129), and one later holdout (TASK-123).

The ordering above is implementation risk ordering only. Transport registries,
policy artifacts and tournament scoring contain no implicit libp2p-first,
iroh-first, BitTorrent-first, fastest-first or cheapest-first preference: libp2p
is the primary *discovery* stack by the authority above, while which *transport*
wins is decided only by the tournament's measured evidence.

### Evidence-grounded eligibility constraints

S1 and S2 remain hard constraints, never objective terms that a fast candidate
can trade away. This contract makes the numeric safety ceilings already
implemented and reviewed in the repository hard constraints now; it does not
invent absent operator budgets. The repository product owner has accepted this
split for TASK-114: the evidence-backed numbers below govern the current
contract, while the complete operator-budget artifact remains a fail-closed
TASK-120 prerequisite. For every supported arm/profile:

- **S1:** zero accepted byte/signature/NarHash deviations. Corruption must fail
  gate 1 or Nix gate 2; one violation rejects the candidate.
- **S2:** every declared dead/slow/unavailable mechanism row completes through
  upstream fallback with the correct store path. TASK-51's provisional fetch
  safety floor is the v1 bound: **10 s dial**, **10 s body idle**, and **60 s
  total per peer attempt**. The experiment observes both the bounded abort and
  final fallback success; it does not add an unevidenced aggregate full-build
  allowance. TASK-44 may replace this provisional policy only in a new frozen
  candidate/version that is at least as safe.
- **Normal full-build latency:** the retained owner-accepted Wave-1 guard is
  paired p95 at most **1.10×** upstream. p99 is reported descriptively but is
  not a v1 decision bound: the v1 cap of 100 independent clusters cannot
  support a distribution-free two-sided 95% p99 interval (which needs at least
  367); it is `METRIC_UNUSABLE` for selection rather than silently promoted.
- **Serve resources:** TASK-72's existing admission envelope is inherited by
  every sharing profile: maximum single served NarSize **256 MiB**, maximum
  aggregate in-flight served NarSize **1 GiB**, and maximum serve duration
  **120 s**. Admission happens before bytes are produced; a decline is explicit
  and cannot be reported as a peer success.
- **Persistent content and query shape:** TASK-61's selected supply model keeps
  **0 B of a second blob/content copy at rest**; separately measured metadata,
  caches and transient allocations are not mislabeled as content. TASK-91's
  batch contract admits at most **256 named keys**, **512 dictionary offers**,
  **4 offers per positive answer** with at most one per transport kind, and a
  **64 KiB encoded-message** gate. TASK-110 extends the same semantic COUNT bound
  to the frozen single-key path — a single-key `Have` now carries at most **4
  offers with one per transport kind**, applied on encode and decode against the
  raw pre-drop offer list. This closes the single-key **KNOWN-offer
  count/enumeration vector** (622 offers naming 621 unasked content identities → at
  most one KNOWN content identity per transport kind; a legitimate known-only
  answer is **330 B, 3.75×**), consistent with the batch path's
  `deny_unknown_fields`. The unknown-**KIND** enumeration vector is narrowed
  SEPARATELY by **TASK-224**, which closes its **structural/list half**: the
  shared tolerate-drop decoder now constrains an unknown offer to a whitelisted
  minimal shape (the `transport` tag plus at most one scalar string locator) and
  **REJECTS** any unknown offer whose body could name a *list* of identities (an
  array, a nested object, more than one scalar field, or a non-string tag), on the
  claim path and both hold-response paths. This is **not literal closure** of
  no-enumeration: a single opaque scalar of identity-shaped **text** can still ride
  in an accepted unknown offer through three channels — the transport **tag**
  itself (`{"transport":"blake3:…"}`), an extra **field name**
  (`{"transport":"future","blake3:…":"x"}`), and the string **value**
  (`{"transport":"future","loc":"blake3:a,blake3:b,…"}`). Each is accepted-then-
  dropped, and one accepted unasked identity is already a `claim.rs:332` defect, so
  the invariant is discharged at the *schema* level (a list is inexpressible) but
  not literally. This **TEXT residual is owned by TASK-227** — *not* TASK-223: a
  byte cap bounds volume, it does not eliminate identity naming. Per orchestrator
  arbitration this is a **format-cleanliness** gap by the repo's own rule, not an
  honest-peer-holdings leak (a hostile responder naming fake identities reveals
  nothing about any honest peer), hence Low urgency; literal closure is possible at
  a forward-compat cost (it is the arbitrary-string *contract*, not the frozen
  golden, that admits it). A plausible future *single-locator* transport still
  decodes inertly, but a future *multi-field* transport is now a hard decode error
  (a disclosed forward-compat cost). Separately, the worst-case **byte**
  amplification (a well-shaped unknown-kind slot had a byte-unbounded single scalar,
  so a hostile single-key `Have` could pad to the **64 KiB** frame, ~**744×**) is
  now **CLOSED by TASK-223**: a per-offer serialized-byte cap
  (`MAX_OFFER_WIRE_BYTES` = **2 KiB**, applied to every offer on the claim and both
  hold-response paths) refuses any single offer over the cap, so one offer can no
  longer fill the frame and a single-key `Have`'s offer content is at most
  `MAX_OFFERS_PER_ANSWER × 2 KiB` — a fixed constant, not the frame. The cap was set
  deliberately generous over any plausible legitimate locator (a max-length URL
  fits under 2 KiB; loosening later is backward-safe, tightening is not). A residual
  raw-JSON whitespace/escape inflation channel is universal, frame-bounded and
  draft-codec-only, out of scope of the offer-body cap. The single-key hold-query
  cell is supported for training on the same terms as the batch path.
- **Privacy:** `upstream_only` emits zero P2P publication/query/serve records;
  `consume_only` emits zero publication and serve records and reports each
  opted-in lookup recipient/exposure; `lan_share` emits zero packets/records to
  public tracker, DNS discovery, relay, DHT or Mainline infrastructure;
  `public_share` publishes zero unsigned/private-path records and uses only the
  explicitly preflighted dependencies. Any inventory-listing response or
  unrecorded recipient rejects the candidate.

TASK-42's measured 110 MiB raw-Iroh calibration cell -- holder VmHWM
**236.7 MiB**, requester VmHWM **135.9 MiB**, peers-off daemon VmHWM
**10.7 MiB**, per-peer allocated state **4096 B**, and **10--11 fds** -- is an
instrument/testbed drift reference, not a universal ceiling. A candidate is not
rejected merely for exceeding a calibration observation.

Unresolved safety surfaces are fail-closed prerequisites for Stage-B
training, not values this document may guess:

- TASK-104 must freeze bounded responder work for a 256-key batch.
- TASK-106 must freeze a total discovery deadline and concurrency bound rather
  than relying on a per-probe timeout.
- TASK-110 **(mechanism landed)** bounded the single-key offer COUNT with the same
  one-offer-per-transport-kind semantic rule as the batch path, closing the
  KNOWN-offer count/enumeration vector (legitimate answer 330 B, 3.75×).
  **TASK-224 (landed)** closes the **structural/list half** of the second vector —
  enumeration via the opaque unknown-**KIND** slot — by narrowing the shared
  tolerate-drop decoder to a whitelisted minimal shape (string tag + at most one
  scalar string locator) and rejecting any unknown offer that could name a *list*
  of identities (array/nested/multi-field/non-string-tag), on the claim path and
  both hold-response paths, with forward-compat for a single-locator transport
  preserved (a multi-field future transport is a disclosed hard-reject). The
  no-enumeration invariant is therefore discharged **at the schema level** for both
  paths (a list of identities is inexpressible), but **not literally**: a single
  identity-shaped **string** can still ride via the tag, an extra field name, or
  the value. That **TEXT residual is owned by TASK-227** — distinct from **TASK-223
  (landed)**, which bounds byte VOLUME (the ~744× padding) with a per-offer 2 KiB
  serialized-byte cap: a byte cap does not eliminate identity naming, since one
  accepted unasked identity is already the defect regardless of its length. Per
  orchestrator arbitration the TEXT residual is format-cleanliness (a hostile
  responder naming fake identities is not an honest-peer-holdings leak), hence Low
  urgency but a real defect to own; literal closure is possible at a forward-compat
  cost.
- TASK-120 must freeze a hashed, typed, **complete and owner-reviewed** budget
  artifact for every profile with numeric upload bytes/rate, concurrent serves,
  transient RAM, metadata/disk, fd, discovery work/traffic/deadline and
  announcement bounds. It may tighten or recalibrate the inherited values
  above before any public-network trial.

A missing TASK-120 artifact prevents Stage-B training from starting with
`PROFILE_BUDGET_ARTIFACT_MISSING`. A missing observation or an unknown/exceeded
mandatory value after freeze yields `METRIC_UNUSABLE` (or an explicit
unsupported cell where the mechanism cannot run), never zero or “unbounded.”
Once TASK-104/106/110/120 are frozen, their hashes and values are experiment
inputs; changing one after training starts creates a new experiment version.
The only historical owner-accepted performance thresholds reused here are p95
**1.10×** and the **20 percentage point** egress bite. The profile comparison
margins below are TASK-114 preregistration choices, not claims about production
defaults.

### Exactly one primary rule per operator profile

Every rule uses the paired, familywise-95% procedure in TESTING.md: the three
selectable profiles each receive a Bonferroni-adjusted 98.333% interval, with
the worst mandatory stratum computed inside every resample. “Beats” means the
whole interval strictly clears the stated comparison margin; an interval
touching it is a tie and retains the comparator. Eligibility thresholds stated
as “at least” include equality. All hard constraints above are checked first.
Unsupported cells are never imputed, and no acceptable candidate is a valid
outcome.

No training-selected comparator is named during calibration. Before the first
calibration cluster, TASK-128 freezes the closed causal-trace schema, replay
interpreter and complete planning-contrast catalog. Each selectable profile has
at most 16 fully specified selector artifacts and the complete capable
best-static set of at most four base arms, hence at most 64 exact contrasts per
profile and 192 total. Selector families, parameter ranges and fields filled
from training are forbidden: every threshold and fallback order is already in
one hashed artifact. A dynamic artifact may consume pre-execution context and
only its own label-local observations available by the decision timestamp; it
cannot read future, other-label or post-hoc outcome fields. Four fixed-class
training replay-versus-live parity rows per dynamic artifact are predeclared,
with two independently fresh live executions on each row: A1 live is checked
only against A1 replay and A2 live only against A2 replay. Failure makes every
catalog contrast containing that artifact ineligible without changing the
catalog. The worst case is `3*16*4*2 = 384` parity live slots; with 23,680 base
Stage-B label slots the total ceiling is 24,064.

The same catalog hashes an exact integer/expression-encoded planning-injection
table before calibration. Power alternatives are consume benefit `0.075`,
egress cut `0.30`, LAN log benefit `1.5*(-log(0.95))`, public relative log
relief `1.5*log(1.10)`, public absolute log relief `log(1.10)`, and latency
guard `0` (no regression). Their null boundaries remain respectively `0.05`,
`0.20`, `-log(0.95)`, `log(1.10)`, `0`, and `log(1.10)`; every A/A power
alternative is zero with both predeclared `+/-m_aa` boundary injections. A
single linked-coordinate solver shifts fraction/byte, latency-ratio and relief
numerator/upload coordinates without splitting shared views. It never clips or
retries: inability to materialize a finite physical target makes only that
contrast ineligible.

Every supported Stage-B base arm runs indistinguishable A1/A2 labels from the
first calibration cluster through extension and the fixed holdout. TASK-122
plans every catalog contrast jointly across all four strata at authoritative
N=100, using the final 10,000-draw selector-derived candidate-versus-comparator
procedure. Planning centers away observed direction and exposes to TASK-44 only
the immutable contrast eligibility mask, global N and hashes: no raw A2,
residual, per-label effect or uncentered statistic crosses that boundary.
TASK-44 uses canonical A1 only to choose the deterministic best-static arm and
one already-enumerated artifact whose exact matching contrast is eligible. It
cannot synthesize a threshold or swap to a comparator whose contrast happened
to pass. With no eligible match the profile has no candidate. After candidate
and comparator hashes freeze, the separate TASK-129 reader replays the same
selector independently on A2 for validation and sends only its hashed
validated/no-go artifact to the TASK-123 freeze input. TASK-44 receives no A2
feedback and cannot nominate a runner-up; failure means no candidate for that
experiment version. Unsupported arms remain explicit and have no fabricated
clone metric. Every p95-dependent rule, guard or A/A below requires exactly 100
valid independent clusters per opportunity stratum and an exact planning pass
at N=100; p99 stays descriptive.

Each selectable profile always produces one hashed validation-slot artifact.
A present candidate uses `validated` or `validation_no_go` and binds its
candidate/comparator hashes. A training no-candidate result instead uses
`status=no_candidate`, explicit absent candidate/comparator references and
`a2_validation_status=not_applicable`; hash fields are forbidden rather than
fabricated. TASK-123 requires hashes only for present references and executes
only validated slots. No-go/no-candidate slots remain witnessed, are not
reassigned, and do not narrow the three-profile multiplicity family.

| Operator profile | One primary decision rule and margin |
|---|---|
| `upstream_only` | This is the fixed comparator, not a fitted P2P candidate. Its sole scalar validity rule is paired upstream A/A full-build p95 agreement within **5%**; outside that margin the profile metric is `METRIC_UNUSABLE`, not a P2P win. Provider upload is 0 B and upstream payload egress defines fraction 1.0. |
| `consume_only` | Minimize requester **upstream cache payload bytes (compressed-wire)**. A nominee displaces the training-selected best-static comparator only when its adjusted lower bound clears an absolute **5 percentage-point** reduction, and its lower bound against upstream-only must be at least **20 percentage points**. Local provider upload remains exactly 0 B; latency and privacy remain hard constraints. |
| `lan_share` | Minimize **p95 full-real-Nix build latency**. A nominee displaces best-static only when its adjusted lower bound clears a **5%** reduction. It is eligible only if its lower bound on upstream compressed-wire payload-egress reduction is at least **20 percentage points** and provider upload stays under its frozen TASK-120 profile budget. |
| `public_share` | Maximize **cache-relief efficiency** = `avoided_upstream_payload_bytes_compressed_wire / provider_upload_bytes_compressed_wire`, computed only from separately reported source fields. A nominee's adjusted lower bound must clear a **10%** improvement over best-static and its lower adjusted efficiency bound must be at least **1.00**; its lower egress-reduction bound must also reach **20 percentage points**, and it must satisfy latency/privacy/resource constraints. Zero peer delivery is ineligible, never an infinite score. |

These rules intentionally differ by operator context. The old “<20% and >10%
kills the whole P2P thesis” statement is therefore superseded: 20 percentage
points remains an eligibility bite for sharing/consuming profiles, while latency,
upload, privacy and resources can independently reject a profile. A LAN win does
not license public publication; a public loss does not erase a consume-only win.

### Decision ownership, artifacts and version changes

- The **repository product owner** retains authority to accept production
  profile intent, defaults and budgets. TASK-114 freezes the experimental
  contract and generator version without claiming that its new technical
  margins are production-approved. TASK-120 freezes the reviewed numeric
  profile-budget artifact before Stage-B training. No role may change either by
  editing a result artifact.
- TASK-88 owns the Iroh-only reference. TASK-117 owns BitTorrent identity and
  representation feasibility. TASK-125 owns diagnostic Stage A. Before
  calibration, TASK-128 owns and freezes the generic causal-trace schema, replay
  interpreter and complete exact selector/comparator contrast plus numeric
  injection catalog; it may not tune them from training. TASK-122 owns
  execution, exclusions, fixed-class replay parity and centered joint planning
  for Stage-B **training only**. It releases only the immutable eligibility
  mask/global N/hashes before selection and seals raw A2 and every directional
  value outside the TASK-44 fitting surface.
  TASK-44 owns deterministic A1-only selection: the best-static comparator and
  at most one exact eligible catalog artifact per profile. It may not create a
  parameter, substitute a comparator, receive A2 feedback or alter a selector
  after A2 validation. TASK-129 owns the post-freeze A2 reader and sends exactly
  one hashed validated/validation-no-go/no-candidate slot per selectable profile
  directly to TASK-123 without returning feedback to TASK-44. TASK-123 owns the
  freeze/execution/verdict protocol with the independent entropy witnesses
  required by TESTING.md.
- TASK-123 may begin only with frozen hashes for code, experiment contract,
  training manifest/results, causal-trace/replay interpreter, complete contrast
  catalog, centered planning artifact and eligibility mask, fixed-class parity
  results and exactly one hashed validated/validation-no-go/no-candidate slot
  artifact per selectable profile. Candidate/comparator hashes are required
  only for a present reference and forbidden for an explicit absent/not-applicable
  reference. It generates the hitherto nonexistent holdout material and runs
  each validated candidate unchanged; an absent/no-go profile stays
  no-candidate. TASK-124 alone plans a production default/rollout from the
  verdict.
- The first accepted Stage-B training run freezes
  `nix-p2p-tournament-v1`. Any later change to an objective, margin, hard
  constraint, scenario generator/distribution, or profile semantics creates a
  **new experiment version**, restarts training/fitting, and requires a fresh
  never-before-generated holdout. The old artifact and failed/no-go verdict stay
  recorded. Implementation/interpreter changes after their freeze likewise
  require new hashes and new evidence; holdout-driven tuning is forbidden.
