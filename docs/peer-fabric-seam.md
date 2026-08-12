# `PeerFabric` — intention-level P2P seam (proposal v2, for review)

Status: **PROPOSAL — not implemented.** v2 folds in the mped-architect
pressure-test (verdict: REVISE) and the owner's decisions: **dynamic dispatch
(trait objects)** and **two per-backend binaries**. Supersedes the
hand-rolled-Kademlia framing of TASK-126.

## Why this exists

The daemon is iroh-native below the `NarSource`/`Transport` seam: the serving
core (`server`/`source`/`upstream`/`catalog`/`rewrite`/`narinfo_cache`) holds
**zero** iroh types, but the node runtime, node/content discovery and
publication (`iroh_runtime`, `iroh_node_*`, `iroh_publication*`, `pinned_http`,
~195 refs) are welded to iroh with no stack-neutral interface. We are **not
married to iroh**. The live decision — adopt a proven prior DHT
(`iroh-dht-experiment` vs `libp2p-kad`) instead of hand-rolling one — is
entangled with the networking stack precisely because that layer has no seam.

This proposes the missing seam **at the intentional level**: it names *what the
daemon wants from any peer substrate*, not how a stack does it. Defined first, so
the backend becomes a **compile-time selection**.

## Two orthogonal selections (keep them separate)

| Selection | When | Mechanism |
|---|---|---|
| **Backend** — iroh vs libp2p vs future | **compile time** | cargo feature → `type Fabric = …` alias; the unselected backend is **not linked** |
| **Participation profile** — `upstream_only` / `consume_only` / `lan_share` / `public_share` | **run time** (operator config) | which capabilities the constructed fabric exposes (`Some`/`None`) |

## Crate topology — one backend linked, ever

The split the owner asked for: shared *frontend*, swappable *backend*, and
**exactly one P2P backend compiled in at a time — the other is never required.**

```
peer-fabric      seam only: the 7 capability traits, PeerFabric, value types
                 (ContentKey, ProviderRecord, NodeId, Blake3Digest), Lookup,
                 Exposure, budgets, FakeFabric.  NO iroh, NO libp2p.
      ^   ^
daemon-core      the FRONTEND: serving core, correlation, policy, budgets,
      |   |      orchestration.  Depends on peer-fabric only.  NO iroh, NO libp2p.
      |   |
      |   +-- fabric-iroh     IrohFabric   = peer-fabric + iroh + iroh-blobs
      |   +-- fabric-libp2p   Libp2pFabric = peer-fabric + libp2p   (added only
      |                       when TASK-103 selects libp2p; absent until then)
   daemon-iroh   thin bins over daemon-core.  daemon-libp2p = daemon-core + ONE
   daemon-libp2p fabric (pure libp2p, single-stack fallback).  daemon-iroh is the
                 DEFAULT and is DUAL-STACK (fabric-iroh transfer/locator +
                 fabric-libp2p directory), so its closure links BOTH; the binary,
                 not a feature, IS the composition.
```

Why this satisfies "never both, never require both" **for the single-stack
build** — and how the dual-stack default relaxes it (amended 2026-08-12, TASK-147):
- A single-stack binary depends on exactly one `fabric-*`, so its closure
  contains exactly one stack — this is `daemon-libp2p` (libp2p directory *and*
  transfer, no iroh). **The default `daemon-iroh` is the deliberate exception: it
  is dual-stack** (iroh transfer/locator + libp2p-kad directory), so its closure
  links both. The disjoint-closure guarantee holds for the pure fallback, not for
  the default. No feature, no `cfg`, no `compile_error!` — composition is by which
  `fabric-*` crates the binary's `fn main()` assembles, and the default assembles
  two.
- `daemon-core` and `peer-fabric` carry **zero** p2p-lib deps, so the frontend
  compiles and unit-tests without either stack — which also *proves*
  stack-neutrality by construction: a `FakeFabric` is the only backend the core
  tests ever link.
- `libp2p` is not even a workspace member until it is chosen, so today nothing in
  the tree pulls it.

Final wiring (DECIDED, owner 2026-08-11; **amended 2026-08-12, TASK-147**): **two
thin binaries** `daemon-iroh` and `daemon-libp2p`, each a `fn main()` constructing
its fabric and calling `daemon_core::run(fabric)` — no features, no `cfg`.
`daemon-libp2p` = `daemon-core` + one backend crate (pure libp2p, single-stack
fallback). `daemon-iroh` is the **default and dual-stack**: its `fn main()`
assembles an iroh transfer/locator with a libp2p-kad directory into one `Fabric`. Rationale beyond dep-exclusion: it keeps **tests and tournament runs from
conflating backends** — each backend is a distinct build artifact, so Stage-B
tournament evidence (TASK-122) and every test bind to a named binary, never to an
ambiguous feature combination.

Independence guard unaffected: these crates are shared **among the daemon's own
components**, never with `testproxy` (which stays an independent wire witness and
depends on none of them). The workspace "no shared crate" rule was conditioned on
"once a second consumer actually exists" — two backends is that second consumer,
so the precondition is now met.

## Dispatch — dynamic trait objects (decided)

Your directive was "static, and compile-time-selectable which backend." The
architect pushed back on *static dispatch* specifically: every axis here is
I/O-bound by 3–9 orders of magnitude over a vtable call (network RTTs, MiB over
QUIC, LAN), so associated-type monomorphisation buys nothing measurable while
costing object-safety and per-axis test doubles, and it regresses the seams that
are already `dyn` today (`Arc<dyn NarSource>`, `Box<dyn Transport>`).

**What "one backend per binary" needs is dep-exclusion — not static dispatch**
(see Crate topology): each binary links one backend crate, so the other's deps
never appear. The fabric is a *concrete struct* whose capabilities are
`Option<Arc<dyn …>>` — dynamic dispatch, chosen deliberately: every axis is
I/O-bound so the vtable hop is unmeasurable, while trait objects keep the
frontend non-generic (no viral `<F>`), make per-axis test doubles trivial, and
let a dual-stack fabric mix a libp2p directory with an iroh transfer.
`#[async_trait]` already boxes every call, so "static is faster" is moot anyway.

```rust
pub struct IrohFabric {                     // a plain struct, not a generic umbrella
    directory:  Option<Arc<dyn ProviderDirectory>>,
    announcer:  Option<Arc<dyn AvailabilityAnnouncer>>,
    locator:    Option<Arc<dyn NodeLocator>>,
    transfers:  TransportRegistry,          // the existing runtime, tag-keyed registry
    server:     Option<Arc<dyn NarServer>>,
    hold_query: Option<Arc<dyn PeerHoldQuery>>,
    local:      Option<Arc<dyn LocalPeerDiscovery>>,
    ledger:     ExposureLedger,
}

// each backend crate constructs its own fabric; the binary IS the choice:
// daemon-iroh   bin:  fn main() { daemon_core::run(fabric_iroh::IrohFabric::new(cfg)) }
// daemon-libp2p bin:  fn main() { daemon_core::run(fabric_libp2p::Libp2pFabric::new(cfg)) }
```

`None` then means exactly one thing — "this profile turned this axis off." The
composition root asserts the selected profile's required axes are present and
**fails fast**. This dissolves the `Unsupported`-ZST dilemma entirely (no
backend categorically lacks an axis, so a compile-time "can't do X" guard
protects against a miswiring that cannot occur).

> **Decided (owner 2026-08-11):** dynamic trait objects (`Option<Arc<dyn …>>`),
> two per-backend binaries. Associated-type static dispatch was considered and
> rejected: separate binaries already remove its only real upside
> (monomorphisation bloat), leaving only its costs — viral generics, all-axes
> test doubles, no dual-stack mixing.

## Design principles

1. **Intentional vocabulary** aligned to the PRD's six participation axes — not
   `kademlia_lookup`.
2. **MISS ≠ UNAVAILABLE.** Every exact-key consultation returns a 3-way
   `Lookup<T>`; healthy-absent and could-not-consult are peers, not error-vs-ok.
3. **Exposure is a single-sink ledger, and it is cooperative.** Disclosures are
   written to one `ExposureLedger` as they happen; each capability also answers
   `declared_exposure()` a-priori for TASK-120 preflight. Honest caveat: the
   ledger is *self-reported* — the adversarial audit is the packet/source
   mutation guard (TASK-132/103), not the ledger.
4. **Policy above the seam.** Eligibility (TASK-102), profile selection, and
   budget *numbers* (TASK-120) are the daemon's; the fabric only enforces the
   mechanism bounds it is handed.
5. **Untrusted hint infrastructure.** `NarTransfer::fetch` returns gate-1
   (BLAKE3) verified bytes; Nix does gate-2. A hostile substrate costs a
   fallback, never a bad store path — which is *why* we need no IPFS-grade attack
   hardening in the directory.

## Shared vocabulary

```rust
use crate::{Blake3Digest, NodeId, KnownTransport, TransportTag,
            BatchHoldQuery, BatchHoldResponse, SafetyEnvelope, ServeBudget,
            NarSupplier};

/// Domain-separated discovery key derived from the signed NarHash. NEW.
pub struct ContentKey([u8; 32]);

/// WHO can serve WHAT, HOW, until WHEN — signed. No dialable address, no
/// StorePath. Stored in the DHT as an OPAQUE value (see freeze note). NEW.
pub struct ProviderRecord {
    pub key: ContentKey,
    pub provider: NodeId,
    pub offers: Vec<KnownTransport>,
    pub sequence: u64,
    pub issued_at: u64,
    pub expiry: u64,          // reconciled against the store's record TTL
    pub signature: [u8; 64],
}

/// What a NodeLocator yields — stays INSIDE the fabric, never reaches the core.
pub struct DialInfo { /* direct/relay locations, opaque above the seam */ }
```

## Outcome / exposure types

```rust
pub enum Lookup<T> { Found(T), Miss, Unavailable(Unavailable) }
pub enum Unavailable {
    BootstrapOutage, Partition, DeadlineExceeded, InsufficientRouting, Backend(String),
}

pub struct Exposure { pub to: Recipient, pub disclosed: Disclosed }
pub enum Recipient { LanPeer, Tracker, DnsResolver, Relay, DhtNode, Bootstrap }
pub enum Disclosed { OurAddress, OurNodeId, ContentKey }

/// The single sink. Capabilities append; preflight/status read.
pub struct ExposureLedger { /* … */ }
/// A-priori surface: which Recipients an enabled capability WILL touch.
pub struct ExposureSurface { /* … */ }
```

## Capability traits (seven intentions)

```rust
/// "Find who can give me this NAR." Decentralized, exact-key, no enumeration.
/// Backed by a Kademlia VALUE store, so the signed record is learnable without
/// the provider being online. (libp2p-kad: put_record/get_record — NOT get_providers.)
#[async_trait]
pub trait ProviderDirectory: Send + Sync {
    async fn find_providers(&self, key: &ContentKey, budget: &DiscoveryBudget)
        -> Lookup<Vec<ProviderRecord>>;              // exposure -> ledger
    fn declared_exposure(&self) -> ExposureSurface;
}

/// "Tell the network I can serve this NAR." Eligibility decided above the seam.
#[async_trait]
pub trait AvailabilityAnnouncer: Send + Sync {
    async fn announce(&self, record: &ProviderRecord, budget: &AnnounceBudget)
        -> Result<Receipt, AnnounceError>;
    async fn withdraw(&self, key: &ContentKey) -> Result<Receipt, AnnounceError>;
    fn declared_exposure(&self) -> ExposureSurface;
}

/// "Learn how to dial this NodeId." PRD axis 2 — its own gate-able seam, used BY
/// transfer/announce internally; DialInfo never surfaces to the core, the policy
/// choice (explicit peer list vs pkarr/Mainline/DNS) and the exposure do.
#[async_trait]
pub trait NodeLocator: Send + Sync {
    async fn locate(&self, node: &NodeId, policy: &ResolutionPolicy)
        -> Lookup<DialInfo>;                         // exposure -> ledger
    fn declared_exposure(&self) -> ExposureSurface;
}

/// "Get the bytes from a provider." gate-1-verified raw NAR, size-aborted.
/// == today's `Transport`. Selected at request time by TransportTag (a claim
/// carries several offers) — a legitimately-runtime axis, kept in a registry.
#[async_trait]
pub trait NarTransfer: Send + Sync {
    fn tag(&self) -> TransportTag;
    async fn fetch(&self, content: &Blake3Digest, offer: &KnownTransport,
                   envelope: &SafetyEnvelope) -> Result<Vec<u8>, TransportError>;
}

/// "Hand out bytes to whoever asks, within budget." A lifecycle, not a call.
#[async_trait]
pub trait NarServer: Send + Sync {
    async fn serve(&self, supplier: Arc<dyn NarSupplier>, budget: ServeBudget)
        -> Result<ServeHandle, ServeError>;
}

/// "Ask THIS peer, directly, whether it holds these NARs." Named-key only.
#[async_trait]
pub trait PeerHoldQuery: Send + Sync {
    async fn ask_holds(&self, peer: &NodeId, query: &BatchHoldQuery, budget: &DiscoveryBudget)
        -> Lookup<BatchHoldResponse>;                // exposure -> ledger
    fn declared_exposure(&self) -> ExposureSurface;
}

/// "Notice peers near me." LAN-scoped; admitted only after the global gate.
#[async_trait]
pub trait LocalPeerDiscovery: Send + Sync {
    async fn nearby_peers(&self) -> Vec<NodeId>;     // exposure -> ledger
    fn declared_exposure(&self) -> ExposureSurface;
}
```

## The umbrella

```rust
pub trait PeerFabric: Send + Sync {
    fn node_id(&self) -> NodeId;

    fn provider_directory(&self) -> Option<&Arc<dyn ProviderDirectory>>;
    fn announcer(&self)          -> Option<&Arc<dyn AvailabilityAnnouncer>>;
    fn node_locator(&self)       -> Option<&Arc<dyn NodeLocator>>;
    fn transfer(&self, tag: TransportTag) -> Option<&dyn NarTransfer>; // via registry
    fn server(&self)             -> Option<&Arc<dyn NarServer>>;
    fn hold_query(&self)         -> Option<&Arc<dyn PeerHoldQuery>>;
    fn local_peers(&self)        -> Option<&Arc<dyn LocalPeerDiscovery>>;

    fn exposure_ledger(&self) -> &ExposureLedger;
}
```

Downstream code takes `&dyn PeerFabric` (or the concrete `Fabric`); `App` is a
plain type, no `where F: PeerFabric + …` spread. A `FakeFabric` (per-axis fakes)
exercises the whole daemon substrate-free.

## How both stacks map onto it

| Intention | Trait | iroh backend | libp2p backend |
|---|---|---|---|
| find providers | `ProviderDirectory` | iroh-dht-experiment value store | `libp2p-kad` `put_record`/`get_record` |
| announce | `AvailabilityAnnouncer` | value `Set` over the DHT | `libp2p-kad` `put_record` |
| dial a NodeId | `NodeLocator` | pkarr / Mainline (TASK-138) | Identify + Kademlia |
| fetch NAR | `NarTransfer` | `iroh-blobs get_blob` | libp2p request-response / stream |
| serve NAR | `NarServer` | `iroh-blobs` provider | libp2p stream handler |
| ask a peer | `PeerHoldQuery` | BatchHoldQuery ALPN | libp2p request-response |
| nearby peers | `LocalPeerDiscovery` | iroh mDNS | `libp2p-mdns` |

**Directory uses the DHT value store, not the provider API** — libp2p-kad's
`get_providers` returns PeerIds only (no offers/expiry/signature), so we key
`ContentKey → signed ProviderRecord` via `put_record`/`get_record` on *both*
backends and keep `find_providers → Vec<ProviderRecord>` honest.

A **dual-stack** arrangement (iroh-blobs transfer + libp2p-kad directory) is one
`Fabric` returning impls from two libraries — the core never knows. This is **the
default** (Mark-emulator decision 2026-08-12, TASK-147), forced by the TASK-126
spike: `libp2p-kad` is the only substrate that stores our opaque `ContentKey →
signed ProviderRecord`, while iroh-blobs is the proven, green NAR transfer — so
the shipping fabric mixes them. The honest cost: there is **no `NodeRuntime`
abstraction beneath the fabric**, so dual-stack runs two event loops / two
holepunchers and links two dependency closures; the shared-ed25519 `PeerId ==
NodeId` derivation unifies *identity, not connectivity* (a peer is dialable once
per stack). This is acceptable because the directory is **untrusted,
availability-only hint infrastructure** — a bad or missing record costs an
upstream fallback, never a bad store path (Nix re-verifies) — so we buy the
second stack for the *one* primitive iroh lacks, not for trust. The pure
single-stack `daemon-libp2p` (directory *and* transfer on libp2p) remains the
coherence fallback. Collapsing back to one stack is a future option, gated on
either iroh growing a content-keyed opaque value store **or** libp2p transfer
proving equal to iroh-blobs — tracked as a follow-up, not a blocker.

## The freeze surface (RESOLVED by TASK-126's spike + freeze)

TASK-126 freezes `ContentKey` + `ProviderRecord` under deep review. You cannot
freeze a codec on top of an experimental substrate whose *own* record format
moves. So the freeze surface must be **our schema inside an opaque value the DHT
merely stores** (`ContentKey → signed opaque bytes`). If iroh-dht-experiment only
exposes its *own typed* records (no opaque value store), the freeze leaks into
it and **libp2p-kad's stable `put_record`/`get_record` becomes the safer freeze
target — flipping primary/fallback.** Decide empirically; do not freeze on faith.

### SPIKE DECISION (2026-08-12) — primary/fallback FLIPPED, evidence-based

Read `iroh-dht-experiment`'s source (github.com/n0-computer/iroh-dht-experiment,
`src/lib.rs`). It stores a **fixed typed `Value` enum**, NOT a generic opaque
`Vec<u8>`:

```rust
pub enum Value { Blake3Provider(..), ED25519SignedMessage(..), Blake3Immutable(..) }
```

Its opaque-carrier variants each **bind the storage key to the value**, none of
which is our content-derived `ContentKey → mutable, multi-provider, signed record`:
- `Blake3Immutable { timestamp, data }` — key MUST equal `blake3(data)`; immutable,
  so no sequence / refresh / withdrawal.
- `ED25519SignedMessage { timestamp, signature, data<=1024B }` — key IS the signer's
  **public key**, i.e. keyed by *provider identity*, not by content (multiple
  providers of one content cannot share a key). Wrong lookup axis.
- `Blake3Provider { timestamp, node_id }` — a bare provider tuple, no
  offers/sequence/signature.

Also experimental (record validation is a `TODO`). **Conclusion: it cannot store
`ContentKey → signed ProviderRecord` as an opaque value under a content-derived,
mutable, multi-provider key.**

**→ libp2p-kad `put_record`/`get_record` is the PRIMARY freeze target** — its
`Record { key: arbitrary, value: opaque Vec<u8> }` is exactly the opaque-value
model. **iroh-dht-experiment is the FALLBACK / future candidate** (blocked today
for our keying model; if it later grows a content-keyed opaque value, our record
already fits its 1024-byte `ED25519SignedMessage.data` carrier — which is why
`MAX_PROVIDER_RECORD_BYTES = 1024`). The **freeze is safe regardless**: the codec
emits `ContentKey → signed opaque bytes`, and libp2p-kad *guarantees* opaque-value
storage, so the opaque-value model holds no matter which backend TASK-103 adopts.

### What is now FROZEN (peer-fabric)

- **`ContentKey` recipe** (`content.rs`): `BLAKE3 derive_key(CONTENT_KEY_CONTEXT,
  signed_sha256_NarHash)`, domain-separated ON PURPOSE (the inverse of
  `Blake3Digest`'s plain unkeyed recipe), pinned by a compile-assert + golden
  vectors + a one-byte namespace-mutation control + an independent python
  `blake3 derive_key` anchor (`scripts/check-content-key-derivation.py`).
- **`ProviderRecord` / `ProviderWithdrawal` codec** (`record_codec.rs`): a versioned,
  canonical **fixed-layout binary** opaque value, ed25519-signed over
  `SIGNING_DOMAIN || body`; the `provider` `NodeId` **is** the verifying key
  (self-verifying). A fixed layout structurally forecloses any IP/port/relay/
  StorePath/second-digest/unasked field (AC#2). Fail-closed decode
  (`decode_provider_assertion`) with a distinct typed rejection — oversized,
  truncated, trailing-bytes, unknown-version, unknown-kind, unknown-offer,
  too-many-offers, bad-provider-key, bad-signature, **wrong-key (SSOT)**, stale —
  each with a bite test. Byte-pinned goldens in
  `peer-fabric/tests/golden/provider_record_v1.json`.
- **Validation rules** (`record_store.rs`, the salvaged `FakeProviderDirectory`
  oracle — NOT a running DHT, which is TASK-103): monotonic sequence, idempotent
  refresh, explicit signed withdrawal, expiry, replay rejection, concurrent-provider
  merge, no expired/withdrawn resurrection.

### Forward-carried notes (TASK-140/141) — RESOLVED
- **key SSOT**: `record.key` is kept AND signature-bound; `decode_provider_assertion`
  takes the storage key as `expected_key` and rejects `WrongKey`. Duplication is a
  checked invariant, not an accident.
- **`.content` redundancy**: NOT redundant — `content` is the plain-BLAKE3 *fetch*
  identity, `ContentKey` derives from the *sha256* NarHash; neither is derivable from
  the other, so `content` is LEARNED from the record and STAYS.
- **privacy framing**: routing-only nodes see an opaque key in a separate keyspace;
  a k-closest *storing* node learns `content` (narrows, does not hide). Full
  adversarial analysis remains TASK-132.

## Backlog surgery (done)

- **TASK-140** (this seam) — deps `TASK-114` only; built first as the standalone
  `peer-fabric` crate, zero p2p deps.
- **TASK-126** — re-scoped from "implement our own Kademlia" to "select + freeze
  the `ProviderDirectory` backend + opaque-value schema." AC#3 (implement RPCs)
  dropped; spike-gate AC added; deps `+TASK-140`. Hand-rolled work salvaged as a
  `FakeProviderDirectory`.
- **TASK-100** — re-scoped from a duplicate "ContentDiscovery seam" to
  "ProviderDirectory contract hardening" on the TASK-140 seam; deps `+TASK-140`.
- **TASK-103** — "implement the *selected* backend behind the seam"; deps `+TASK-140`.
- **TASK-141** (new) — **IrohFabric adapter + crate split**: extract the welded
  iroh modules (`iroh_runtime` / `iroh_node_*` / `iroh_publication*` /
  `pinned_http`) into a `fabric-iroh` crate; split the frontend into `daemon-core`
  (peer-fabric only); wire the one-backend build + guard; wire `NodeLocator` onto
  TASK-138. Without it the seam is aspirational.
- **TASK-132** (global gate) — unchanged; it is indifferent to hand-rolled vs
  adopted as long as the mechanism is decentralized and the packet guards pass.

## Sequencing

TASK-140 lands **before** TASK-126's freeze — the `ProviderRecord` shape the seam
names and the codec TASK-126 freezes must agree on the opaque-value model.
Build the seam → freeze the schema inside it → adopt the backend.
