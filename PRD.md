# PRD — nix-p2p: decentralized Nix binary cache (Candidate B)

Status: **round 1 draft — under grill**
Tentative-vs-Committed: **experimental** (to be confirmed by owner)

## Essence / problem

cache.nixos.org is a single point of failure for the entire Nix
ecosystem's *bandwidth*. Its trust role (signing narinfos) is cheap,
replicable, and not the problem; its byte-serving role is. We
decentralize the bytes and only the bytes: a localhost substituter
daemon serves Nix the same binary-cache HTTP API it already speaks,
passing signed metadata through verbatim from cache.nixos.org and
fetching NAR payloads from an iroh p2p swarm, hash-verified against
the signed NarHash. An unmodified Nix client re-verifies signature
and NarHash itself, so the daemon and all peers stay outside the
trusted computing base.

Architecture: **Candidate B** (whole-NAR blobs, gossip-fed claims
index) — see `fig-candidate-B-substituter-daemon.svg` — with an
explicit modularity seam so **Candidate C** (chunked castore,
`fig-candidate-C-chunked-castore.svg`) can replace the payload layer
later without breaking the network.

## Users / actors

- **Operator**: a NixOS/Nix user who installs the daemon and adds
  `http://localhost:5000` first in `substituters`. Expects zero
  behavioral change except resilience and (maybe) speed.
- **Peers**: other instances of the same daemon; untrusted byte
  sources and gossip participants.
- **cache.nixos.org**: unchanged; sole metadata/trust authority and
  HTTP fallback.
- *Open: is the primary deployment a global public swarm, or
  org/LAN/friends circles with a shared topic key?* (privacy-relevant)

## What good looks like

- `nix build` with the daemon enabled is never meaningfully slower
  than without it: tail latency bounded at (cache latency + hedge
  window). Measurable.
- With cache.nixos.org unreachable, a path previously seen by the
  swarm still substitutes successfully from peers. (Degree depends on
  the metadata question — open, see below.)
- Measurable bandwidth offload: N% of NAR bytes served from peers in
  steady state on a realistic machine set.
- **Additive invariant**: stop the daemon (or delete it) and Nix
  behaves exactly as today. No lock-in, no migration.
- A path fetched via p2p is byte-identical to the cache-served one —
  enforced by the NarHash gate; a corrupted peer transfer can never
  reach the Nix store.

## What bad looks like

- Everyday builds get slower (resolve latency leaking into the hot
  path, misses that hang instead of failing fast).
- A wire/claim format change after peers exist that splits the
  network.
- The daemon must be trusted for integrity (would be a design bug:
  Nix's own sig + NarHash verification is the invariant).
- Privacy surprise: operators discover announcing claims broadcast
  their installed-package set and consider it a leak.
- Works on the developer's LAN, fails behind real-world NAT.

## Scope & non-goals

In scope (MVP):
- One Rust binary: binary-cache HTTP API server, narinfo passthrough
  + local narinfo cache, gossip-fed in-memory claims index, iroh-blobs
  whole-NAR transfer (client + provider), speculative prefetch at
  narinfo time, HTTP hedge (~200 ms), announce-after-fetch.
- Seeding of paths the daemon itself fetched (it has the narinfo, the
  NAR bytes, and the NarHash).
- Linux first. NixOS module for deployment.

Non-goals (explicit):
- Decentralizing *trust* (no build transparency, no alternative
  signing; Trustix territory).
- Replacing or mirroring cache.nixos.org's metadata service (but see
  open question on p2p narinfo relay).
- Chunk-level dedup (that is Candidate C; we only keep the seam open).
- Incentives/economics for seeders; long-tail availability guarantees.
- Serving locally-built (unsigned) paths to peers.

## Key decisions (settled)

| Decision | Choice | Why |
|---|---|---|
| Integration | Native substituter daemon, not nginx proxy | Nix's substituters list already does fallback; daemon sees narinfo content → prefetch; one moving part (Candidate A rejected) |
| Payload granularity | Whole-NAR blobs | One BLAKE3 per NAR, no tree walk, no network-wide chunking agreement; shippable (Candidate C deferred) |
| Transport | iroh / iroh-blobs | BLAKE3 incremental verified streaming, QUIC + holepunching; IPFS perf unacceptable, BitTorrent data model mismatch |
| Discovery | iroh-gossip claims topic, local in-memory map | Resolve must be ~0 on hot path; DHT (1–4 s lookups) only ever off hot path |
| Latency guardrails | Prefetch at narinfo time + 200 ms HTTP hedge | Hides p2p constants under Nix's scheduling; bounds tail near today's |
| Trust | narinfo passthrough verbatim; Nix verifies sig + NarHash | Daemon and peers outside TCB by construction |
| Language | Rust (tokio) | iroh is Rust; async fan-out; nix-compat crates exist |

## Modularity seam for Candidate C (load-bearing requirement)

The B→C upgrade must be a payload-layer swap, not a network fork:

- **Claim record is versioned from day one** and its payload is a
  tagged enum: `WholeNar { blake3 }` now, `CastoreRoot { digest }`
  later. Peers ignore payload variants they don't understand.
- **Internal seam**: a `NarSource` trait — resolve(NarHash) →
  verified NAR stream — hides whole-blob vs chunked assembly from the
  HTTP layer. The local blob store layout is explicitly replaceable
  (local-only, migratable).
- Transfer uses stock iroh-blobs ALPN (no custom wire protocol to
  freeze beyond the claim schema).

## Irreversibility map

Frozen once peers exist (deep-review surfaces):
- **Claim wire schema** (version field, payload enum, signature-of-
  claim question) — the network's shared language.
- **Gossip topic identity & semantics** (topic id derivation, what an
  announcement means, rate expectations).
- **Trust invariant**: narinfo passthrough + NarHash gate. Any change
  here is a security event, not a refactor.

Fixed externally (cannot change, must conform):
- Nix binary-cache HTTP API; narinfo format; ed25519 signature scheme.

Tentative / replaceable (velocity surfaces):
- Local NAR/blob store layout and persistence; index persistence
  across restarts; hedge timing policy; prefetch policy; resolver
  internals; NixOS module interface; metrics.

## Weak assumptions & risks

1. **Gossip is ephemeral** — a freshly started daemon has an *empty*
   claims map until broadcasts arrive. Without a state-sync/bootstrap
   story the "instant local lookup" property is cold-start fiction.
   (Open question below — currently the biggest design hole.)
2. **Claims map fits in memory and gossip scales** to the swarm size
   we target. True for thousands of nodes × recent paths; unexamined
   beyond that.
3. **Seeder density**: demand-becomes-supply only covers popular
   recent paths on always-on machines. The disaster-recovery case
   (old revisions) has no seeders unless someone runs dedicated ones.
   Accepted for MVP; must be stated honestly in any announcement.
4. **n0 relay dependence**: holepunching relies on relay infra —
   a soft centralization point in a resilience project. Self-hosted
   relays exist; not wired up in MVP.
5. **Privacy**: claims + NodeId→addr discovery make "which packages
   does this IP have" observable to swarm participants. Severity
   depends on deployment model (open question).
6. **Claim spam/poisoning** is only *wasteful* (NarHash gate catches
   lies) but wasted round trips are a latency/DoS vector at scale.
   Mitigation (per-peer scoring, claim signing) deferred — but the
   claim schema must not preclude adding signatures (see seam).
7. **iroh API stability**: pre-1.0-ish ecosystem; API churn is a
   maintenance tax we accept.

## Open questions (this round's grill)

1. **Metadata during an outage**: B still needs cache.nixos.org for
   every first-sight narinfo. Signed narinfos are safely relayable
   p2p (Nix verifies the sig regardless of transport). Do claims
   carry the signed narinfo, making the outage story real — or is
   MVP bandwidth-offload only?
2. **Claims cold start**: neighbor state-sync on join? tracker
   bootstrap? accept-empty-and-warm?
3. **Deployment/privacy model**: public global swarm vs pre-shared
   topic key (org/friends circles) as the default?
4. **Commitment level**: confirm `experimental` (phase 2 will plan in
   waves with re-plan points) vs `firm`.
