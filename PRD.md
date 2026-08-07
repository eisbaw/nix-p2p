# PRD — nix-p2p: decentralized Nix binary cache (Candidate B)

Status: **round 4 draft — under grill**
Tentative-vs-Committed: **experimental** (confirmed by owner, round 1)

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

## Implementation strategy (settled, round 2, owner)

**Wave 0 is a transparent proxy**: a daemon that does nothing but
intercept binary-cache HTTP traffic and pass it to the real
cache.nixos.org. This is the hook point everything else grows from,
and it is independently useful: it carries the measurement
instrumentation (net cache egress, request timing, narinfo→nar gaps
from real builds) that validates or kills the value thesis.

Capabilities are then added gradually behind **module interfaces**:

- `MetadataSource` — narinfo lookup (upstream HTTP now; disk cache;
  mock for tests; p2p relay in v2).
- `NarSource` — resolve(NarHash) → verified NAR stream (upstream
  HTTP now; iroh whole-blob later; chunked castore in C).
- The upstream cache itself is mockable: tests run against a fake
  cache.nixos.org with controlled latency, failures, and content.

**Test strategy (settled, round 2, owner)**: container-based e2e from
the start — controlled `nix.conf`, controlled networking, multiple
daemon nodes connected to each other. Both docker-compose-style
container setups and NixOS VM tests are in scope (VM tests give real
nix-daemon + systemd semantics; compose gives fast iteration and
adversarial network shaping). The e2e harness is wave-0 scope, not an
afterthought: the additive invariant and crash behavior (below) must
be tested from the first release.

## Users / actors

- **Operator**: a NixOS/Nix user who installs the daemon and adds it
  as the preferred substituter. Expects zero behavioral change except
  bandwidth offload and bounded latency.
- **Peers**: other instances of the same daemon; untrusted byte
  sources, DHT publishers, optional gossip participants.
- **cache.nixos.org**: unchanged; sole metadata/trust authority and
  HTTP fallback.
- **Deployment model (settled, round 1): public global swarm,
  documented privacy risk.** Announcing is opt-out (leech mode).
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
- **Wave 0**: transparent proxy + `nix-cache-info` semantics +
  narinfo/claims disk cache + measurement + container/VM e2e harness
  with mock upstream and multi-node topology.
- **Then**: iroh-blobs whole-NAR transfer (client + provider) behind
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
| **Kill criterion** | **<20% net cache-egress cut on the favorable testbed kills the p2p thesis**; p95 build latency regression must stay <10% (round 3, owner) | If controlled always-on peers cannot hit 20%, the real world never will |
| Transport | iroh / iroh-blobs | BLAKE3 incremental verified streaming, QUIC + holepunching |
| Discovery | DHT-authoritative, gossip as accelerant (round 1, owner) | Must work from empty state; warm map is an optimization, never a requirement |
| Latency guardrails | Prefetch + hedge (throughput-abort) | The only thing keeping DHT seconds off the user path — load-bearing |
| Metadata | cache.nixos.org only + daemon disk cache | Bandwidth offload MVP (round 1, owner) |
| Privacy | Public swarm, documented risk, leech opt-out (round 1, owner) | Network effect; risk stated plainly |
| Trust | Signed fields untouched; Nix verifies sig + NarHash | Daemon/peers outside TCB. Note: passthrough is **not byte-verbatim** — see compression, open question 1 |
| Language | Rust (tokio) | iroh is Rust; nix-compat crates exist |

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
- **DHT mechanism & key derivation** (which DHT, NarHash→key mapping,
  record contents).
- **Trust invariant**: signed narinfo fields untouched + NarHash
  gate. Changes here are security events, not refactors.

Fixed externally (cannot change, must conform):
- Nix binary-cache HTTP API (incl. `nix-cache-info`
  priority/WantMassQuery semantics, narinfo compression/transport
  fields); ed25519 signature scheme; Nix's client-side narinfo cache
  behavior (30-day positive TTL — see risk 5); (if mainline) BEP
  semantics and rate norms.

Tentative / replaceable (velocity surfaces):
- Whether a local blob copy exists at all (`--dump`-on-demand vs
  stored blobs — but note: switching *from* stored blobs later means
  re-hashing and a seeding gap; decide deliberately in phase 2).
- Narinfo/claims disk-cache format; gossip accelerant (optional by
  design); hedge/prefetch/announce policies; NixOS module interface;
  metrics; the container harness internals.

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
11. **Stale figures**: fig-candidate-B/C SVGs still show gossip-first
    with tracker cold-start; superseded by DHT-authoritative
    decision. Revise before phase 2 or implementers will build the
    wrong discovery layer.

## Open questions (remaining — deferred to phase 2 unless grilled further)

1. **DHT mechanism** (frozen surface, needs a spike not a guess):
   mainline get_peers/announce on a NarHash-derived key vs BEP44
   records vs iroh-native tracker/content-discovery. Decides
   NodeId-vs-IP:port dialability (risk 8) and what an announce
   actually costs. Planned as the first spike of the p2p wave.
2. **Peer-query protocol details**: fan-out bound, timeout, how the
   known-peer set is maintained (gossip membership vs past-peer
   cache), and rate-limiting so yes/no probes do not become the new
   enumeration vector (an attacker sweeping queries at high rate).
3. **Figure revision** (housekeeping, blocks phase-2 onboarding):
   fig-candidate-B/C still show gossip-first + tracker cold-start;
   must be redrawn to DHT-authoritative + peer-probe before
   implementers use them.
