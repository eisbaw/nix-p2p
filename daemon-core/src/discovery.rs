//! MINIMAL 2-node discovery (task-40): resolve a signed `NarHash` to a COMPLETE
//! fetch offer from a holder, without a DHT.
//!
//! ## Where this sits (the seam->swarm wiring)
//!
//! This is the piece that turns "I have a signed `NarHash`" into "here is a
//! holder and how to fetch it", so the URL-less [`crate::transport_fetch`] layer
//! can pull the bytes:
//!
//! ```text
//!   NarSource::resolve(SignedNarHash{hash})            (frozen wave-1 seam)
//!     -> Discovery::resolve(NarHashKey)  -> Option<Claim{ blake3, offers }>
//!     -> fetch_via_offers(registry, blake3, offers)    (task-38/39 iroh)
//!         -> BLAKE3-verified raw NAR bytes             (gate 1)
//!     -> Nix re-verifies sha256(nar) == NarHash        (gate 2, downstream)
//! ```
//!
//! ## The minimal mechanism (and what the DHT spike must replace)
//!
//! The full wave-2b design is DHT-authoritative: a `NarHash`-derived key maps to
//! candidate `NodeId`s, then each candidate is probed. Task-47 is that spike.
//! Wave-2a uses the SECOND half only, against a KNOWN-PEER SET:
//!
//!   * [`DirectDiscovery`] holds a fixed list of peer [`NodeId`]s (the wave-2a
//!     rendezvous - config, not a DHT) and probes each with the versioned
//!     [`HoldQuery`]/[`HoldResponse`] envelope (task-37) until one answers `Have`.
//!   * [`PeerQuery`] is the query TRANSPORT seam. [`InProcessPeerQuery`] is the
//!     wave-2a impl: it genuinely ENCODES the query, DECODES it on the peer side,
//!     answers it from that peer's REAL [`AvailabilityIndex`] (task-50), and
//!     encodes/decodes the response back - the wire format is real; only the
//!     topology (a shared in-process map keyed by `NodeId`) is minimal. A real
//!     over-iroh query protocol is wave-2b (task-47).
//!
//! HONEST LIMITS (forward-carried to task-47, the DHT spike):
//!   * The candidate set is CONFIGURED, not discovered - there is no `NarHash ->
//!     candidate NodeIds` mapping yet, so a node only finds holders it was told
//!     about. This is the exact half task-47 replaces.
//!   * `NodeId -> dialable address` for the FETCH is the task-39 in-memory address
//!     book ([`crate::transport_iroh::IrohTransport::add_peer`]); the integration
//!     site wires the known peers' addresses. Dynamic address resolution (iroh
//!     node discovery / a real rendezvous) is task-47.
//!   * Discovery is PULL (query on demand), not PUSH (announce). The task-50
//!     [`crate::AnnounceSink`] stays fire-and-forget and is deliberately NOT on
//!     this resolve path, so its `()` return (no error channel) is not a
//!     correctness gap here; a push/gossip layer that needs announce-failure
//!     signalling is wave-2b.
//!   * First `Have` wins - a single holder's claim is returned, not a merged
//!     multi-holder set. Aggregation is deferred (task-47).
//!
//! ## No-enumeration (PRD privacy invariant, preserved)
//!
//! Every query names concrete [`NarHashKey`]s - one ([`HoldQuery`]) or many
//! ([`BatchHoldQuery`], task-91) - and gets back yes/no about exactly those. There
//! is, by construction, no method on [`Discovery`] or [`PeerQuery`] that lists a
//! peer's holdings - the probes reuse task-50's [`HoldQuery`]/[`HoldAnswer`] and
//! the positional batch form, which forbid KNOWN-offer enumeration in their
//! SHAPE: an honest peer's answer carries no keys of its own and is meaningless
//! detached from the asker's own query. Probing X (alone or in a batch) reveals
//! nothing about a key Y an honest peer also holds (proven by test, for both
//! forms). The unknown-KIND decoder path is narrowed too (task-224): the shared
//! tolerate-drop decoder REJECTS an unknown offer whose SHAPE (array / nested
//! object / multiple scalar fields, or a non-string tag) could name a LIST of
//! unqueried identities, so the schema-level list-smuggling vector is closed.
//! A TEXT residual remains (NOT closed, task-227): a single identity-shaped
//! string can still ride in an accepted unknown offer via its tag, an extra field
//! name, or its string value. Note (orchestrator arbitration): this is
//! format-cleanliness by the repo's own claim.rs rule, not an honest-peer-holdings
//! leak - a hostile RESPONDER naming FAKE identities reveals nothing about any
//! honest peer. (Distinct from task-223, which bounds byte VOLUME.)
//!
//! ## Bounded miss (the real correctness point)
//!
//! An unresolvable `NarHash` must NOT leak dial/query latency into the Nix build
//! path (PRD risk 3 / the hedge design). Each peer probe is wrapped in a
//! [`PROBE_TIMEOUT`]-bounded [`tokio::time::timeout`], so a wedged/silent peer
//! yields a FAST miss, not a hang. A miss then composes into upstream fallback via
//! [`FallbackNarSource`] (S2 preserved). Task-51's safety envelope tightens this
//! into the full abort/hedge policy; task-40 only guarantees the miss is bounded.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use peer_fabric::{DiscoveryBudget, Unavailable};

use crate::availability::AvailabilityIndex;
use crate::claim::{
    BatchHoldAnswer, BatchHoldQuery, BatchHoldResponse, CLAIM_SCHEMA_VERSION, Claim, HoldAnswer,
    HoldQuery, HoldResponse, KnownPayload, KnownTransport, MAX_BATCH_HOLD_KEYS,
    MAX_BATCH_HOLD_OFFERS, NarHashKey, OfferIndex, QUERY_SCHEMA_VERSION, as_offer_slots,
    check_batch_keys, check_batch_offer_bindings, decode_batch_hold_query,
    decode_batch_hold_response, decode_hold_query, decode_hold_response, encode_batch_hold_query,
    encode_batch_hold_response, encode_hold_query, encode_hold_response,
};
use crate::source::{NarKey, NarSource, SourceError, UpstreamResponse};
use crate::transport::NodeId;

/// How long a single peer probe may take before it is declared a non-answer and
/// the resolver moves on. The guard that keeps a miss FAST: a silent/wedged peer
/// cannot stall the resolution (and therefore the build path) beyond this per-peer
/// bound. Coarse on purpose - the fine-grained per-request abort/hedge is task-51.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The TOTAL wall-clock a single [`DirectDiscovery::resolve_many`] call may spend
/// probing peers, regardless of how many peers are configured or how many chunks a
/// closure splits into. [`PROBE_TIMEOUT`] bounds ONE probe; without a bound over
/// their SUM, batching multiplied the number of bounded waits (8 peers x 4 chunks x
/// 5 s = ~160 s, and a pathological config ~31 min - task-106). This is the backstop
/// over the whole call: once it is spent, the keys resolved so far are returned and
/// every still-unresolved key folds to a CLEAN miss -> upstream fallback (the safe
/// direction; never wrong bytes - task-40).
///
/// 30 s = 6 x [`PROBE_TIMEOUT`] and half the fabric-iroh `FETCH_TIMEOUT` (60 s) total
/// fetch bound, so discovery stays a bounded FRACTION of the overall build-path
/// budget. It is a BACKSTOP, not the common path: on a live peer set the first peer
/// answers in milliseconds and this never fires; it bites only the pathological
/// silent/wedged config the per-probe bound alone left unbounded.
///
/// SUBSUMED (TASK-232). This is NO LONGER a live internal bound raced against a caller
/// deadline: [`Discovery::resolve_many`] now takes the caller's
/// [`DiscoveryBudget`] and enforces `budget.deadline` as the SINGLE total-call bound
/// (no double-bound). This constant survives only as the DEFAULT deadline a composition
/// root passes when it has no tighter budget of its own; `DirectDiscovery` holds no
/// internal total-timeout field anymore.
pub const RESOLVE_MANY_TIMEOUT: Duration = Duration::from_secs(30);

// -------------------------------------------------------------------------
// TASK-232: the typed per-key outcome of a closure resolution.
// -------------------------------------------------------------------------

/// The TYPED outcome of resolving ONE closure key (TASK-232): the daemon-core / wave-2a
/// mirror of peer-fabric's [`KeyResolution`](peer_fabric::KeyResolution), in THIS type
/// universe ([`NarHashKey`] -> [`Claim`]). It carries the SAME four-way distinction the
/// TASK-100 `ProviderDirectory` contract hardened, replacing the old `Option<Claim>` whose
/// `None` folded a dead/faulted mechanism, a spent deadline and a genuine absence into ONE
/// indistinguishable value:
///
///   * [`Found`](ClaimResolution::Found) - a peer answered `Have`; the merged holder claim.
///   * [`Miss`](ClaimResolution::Miss) - EVERY consulted known peer authoritatively answered
///     `Absent`, in full, within budget. A caller may trust this as absence.
///   * [`Unavailable`](ClaimResolution::Unavailable) - a peer that could hold the key could
///     NOT be consulted (a per-peer fault, a probe timeout, or an unusable/misaligned
///     answer). NOT absence: a dead mechanism can never read as nobody-has-it, so this is
///     the variant that keeps a fault from becoming a false [`Miss`](ClaimResolution::Miss).
///   * [`NotAttempted`](ClaimResolution::NotAttempted) - the caller's TOTAL deadline was
///     spent before the full known-peer set was consulted for this key (a PARTIAL result).
///
/// `Found` carries a [`Claim`], NOT a peer-fabric `ProviderRecord`: `DirectDiscovery` probes
/// a wave-2a known-peer set over the [`PeerQuery`] seam and produces UNSIGNED claims, a
/// different surface from the DHT's signed `ProviderRecord`. Only the OUTCOME taxonomy
/// (peer-fabric's [`Unavailable`]) is shared, not the holder payload - so no frozen wire is
/// touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimResolution {
    /// A peer answered `Have`: the complete, merged holder [`Claim`].
    Found(Claim),
    /// Every consulted known peer authoritatively answered `Absent`, in full, within budget.
    Miss,
    /// A peer that could hold the key could not be consulted (fault / timeout / unusable
    /// answer). NOT absence; never cache it as a negative.
    Unavailable(Unavailable),
    /// The total deadline was spent before the full known-peer set was consulted (partial).
    NotAttempted,
}

impl ClaimResolution {
    /// The holder claim if this is a [`Found`](ClaimResolution::Found), else `None`. A
    /// convenience that FLATTENS the Miss/Unavailable/NotAttempted distinction; use the
    /// variant directly where that distinction matters.
    pub fn found(&self) -> Option<&Claim> {
        match self {
            ClaimResolution::Found(claim) => Some(claim),
            _ => None,
        }
    }

    /// Consume into the holder claim if [`Found`](ClaimResolution::Found), else `None`.
    pub fn into_found(self) -> Option<Claim> {
        match self {
            ClaimResolution::Found(claim) => Some(claim),
            _ => None,
        }
    }

    /// `true` only for [`Found`](ClaimResolution::Found).
    pub fn is_found(&self) -> bool {
        matches!(self, ClaimResolution::Found(_))
    }

    /// `true` only for [`Miss`](ClaimResolution::Miss) - a healthy, authoritative absence.
    pub fn is_miss(&self) -> bool {
        matches!(self, ClaimResolution::Miss)
    }

    /// `true` only for [`Unavailable`](ClaimResolution::Unavailable) - could-not-consult.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, ClaimResolution::Unavailable(_))
    }

    /// `true` only for [`NotAttempted`](ClaimResolution::NotAttempted) - the deadline was
    /// spent before the full peer set was consulted.
    pub fn is_not_attempted(&self) -> bool {
        matches!(self, ClaimResolution::NotAttempted)
    }

    /// Whether this key reached an AUTHORITATIVE verdict - a `Found` claim or a healthy
    /// `Miss`. Unavailable and NotAttempted are non-authoritative (the resolution is partial
    /// while any key is one of them).
    pub fn is_authoritative(&self) -> bool {
        matches!(self, ClaimResolution::Found(_) | ClaimResolution::Miss)
    }
}

// -------------------------------------------------------------------------
// The Discovery seam: NarHash -> a complete claim, or a miss.
// -------------------------------------------------------------------------

/// Resolve a signed `NarHash` (as the canonical [`NarHashKey`]) to a COMPLETE
/// [`Claim`] - content id PLUS fetch offers - from some holder, or `None` for a
/// MISS (no known peer holds it). The whole offer is returned, not merely a holder
/// [`NodeId`], because the fetch layer addresses the blob by its `BLAKE3` and that
/// mapping lives in the claim (the task-40 review finding).
///
/// A `None` is a CLEAN miss the caller falls back on (see [`FallbackNarSource`]);
/// it is deliberately not an error, because "no peer here holds it" is the normal,
/// expected outcome for most paths and must be fast, not exceptional. A resolver
/// that hits a genuinely broken mechanism logs it and still returns `None` (folds
/// to a miss -> upstream) rather than propagating - for wave-2a a fault and an
/// absence are indistinguishable to the caller and both correctly trigger
/// fallback. A future DHT mechanism (task-47) may want a real error channel; noted
/// there.
#[async_trait]
pub trait Discovery: Send + Sync {
    /// Resolve `key` to a holder's complete claim, or `None` for a bounded miss.
    async fn resolve(&self, key: &NarHashKey) -> Option<Claim>;

    /// Resolve a WHOLE CLOSURE at once (task-91): one `Option<Claim>` per key, in
    /// the caller's order, `None` where no known peer holds it.
    ///
    /// This exists because Nix resolves a closure, not a path: it knows every
    /// signed `NarHash` in a build's closure before it asks for any NAR, so the
    /// natural question is "of these 200 hashes, which can I get from a peer?".
    /// Asking it one key at a time costs one round trip per key PER PEER, each
    /// with its own dial and timeout exposure - the wrong granularity, not a
    /// tuning problem.
    ///
    /// POSITIONAL, like the wire it rides on: the result has exactly `keys.len()`
    /// elements and element `i` is about `keys[i]`. Duplicate keys in `keys` are
    /// the CALLER's business and are handled (each position gets its own answer);
    /// the wire form forbids duplicates, so an implementation must de-duplicate
    /// before it probes.
    ///
    /// The DEFAULT implementation is one [`resolve`](Self::resolve) per key under the
    /// caller's TOTAL `budget` (TASK-232): so every existing [`Discovery`] impl keeps
    /// working unchanged and a batching impl is an override, not a rewrite. Keys reached
    /// after `budget.deadline` is spent are typed [`ClaimResolution::NotAttempted`] (a
    /// PARTIAL result), never a false [`Miss`](ClaimResolution::Miss). Because single-key
    /// [`resolve`](Self::resolve) can only answer `Some`/`None`, this default can produce
    /// only `Found`/`Miss`/`NotAttempted` - it NEVER fabricates an `Unavailable`, which is
    /// the honest thing for a mechanism whose single-key primitive cannot report a fault.
    async fn resolve_many(
        &self,
        keys: &[NarHashKey],
        budget: &DiscoveryBudget,
    ) -> Vec<ClaimResolution> {
        // The SINGLE total-call bound (TASK-232): the caller's deadline, taken once. No
        // internal timeout races it. Integer Instant/Duration only - no floats.
        let deadline = Instant::now() + budget.deadline;
        let mut out = Vec::with_capacity(keys.len());
        let mut cut = false;
        for key in keys {
            if cut || Instant::now() >= deadline {
                cut = true;
                out.push(ClaimResolution::NotAttempted);
                continue;
            }
            out.push(match self.resolve(key).await {
                Some(claim) => ClaimResolution::Found(claim),
                None => ClaimResolution::Miss,
            });
        }
        out
    }
}

// -------------------------------------------------------------------------
// InMemoryDiscovery: the wave-1/test stand-in (was TransportNarSource's inline
// map). A per-HOLDER index: a NarHash maps to every distinct holder that
// announces it (that holder's LATEST offer set), so resolve can offer more than
// one holder and the fetch driver can fail over from a dead holder to the next
// (task-66), while an untrusted or stale announce cannot poison the key
// (task-170/171).
// -------------------------------------------------------------------------

/// How long a holder's announce stays live in [`InMemoryDiscovery`] before it is
/// evicted as stale. A holder that stops re-announcing (crashed, retired, or lied
/// once and moved on) must not be dialed forever: without a TTL the index is
/// grow-only and every dead locator costs a dial timeout on every fetch (task-171).
///
/// One hour is deliberately COARSE: this is a wave-1/test stand-in and re-announce
/// cadence is not yet a tuned parameter (a real push/gossip layer picks its own
/// refresh interval, task-47). It is long enough that a normally-refreshing holder
/// never falls out mid-session, short enough that a dead holder is reaped within a
/// bounded window. Eviction is LAZY - performed on `announce`/`resolve`, not by a
/// background task - so an idle index simply keeps stale entries until next touched
/// (harmless: nothing dials an untouched key).
pub const ANNOUNCE_TTL: Duration = Duration::from_secs(3600);

/// The time source for [`InMemoryDiscovery`] TTL accounting. A SEAM only so a test
/// can drive eviction by advancing a logical clock instead of sleeping a real
/// [`ANNOUNCE_TTL`] (which would be a multi-second, flake-prone test). Production
/// uses [`SystemClock`] and never sees this.
pub trait Clock: Send + Sync {
    /// The current instant, monotonic per the platform's [`Instant`].
    fn now(&self) -> Instant;
}

/// The real clock: [`Instant::now`]. The only [`Clock`] outside tests.
#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A holder's LATEST announce for a key, plus WHEN it was recorded (for TTL). One
/// per holder identity under a key - a re-announce REPLACES this in place
/// (per-holder last-writer-wins, task-171), it does not accumulate a second entry.
struct HeldClaim {
    claim: Claim,
    /// When this holder last (re-)announced. Reset on every announce (LWW), read by
    /// eviction to reap a holder that stopped refreshing past [`ANNOUNCE_TTL`].
    announced_at: Instant,
    /// A per-key monotonic sequence stamped at announce time, so resolve can order
    /// holders by ANNOUNCE ORDER deterministically even though the per-key store is
    /// a `HashMap` (whose iteration order is not). Preserves the task-66 "offers in
    /// announce order, so failover tries the first-announced holder first" contract.
    seq: u64,
}

/// The identity a holder is keyed by within one `NarHash`. It is the announce's
/// `holders` set: every REAL announce is a single self-holder (`vec![node]`, see
/// `AvailabilityIndex::claim` and the daemon's config-claim wiring), so this is
/// per-`NodeId` last-writer-wins in practice; a (rare, hand-built) multi-holder
/// claim is simply its own identity. Using the whole set - rather than picking an
/// arbitrary element - is a TOTAL function over any [`Claim`] (an empty-holders
/// claim collapses to one degenerate bucket, never a panic).
type HolderId = Vec<NodeId>;

/// A discovery source backed by an in-memory per-HOLDER index of announced claims,
/// keyed on the canonical [`NarHashKey`]. This is the task-38 "discovery stand-in"
/// made a first-class [`Discovery`] impl: a test (or a wave-1 seed) [`announce`]s
/// claims and `resolve` returns them. It shares the [`Discovery`] contract with
/// [`DirectDiscovery`], so the same [`crate::transport_fetch::TransportNarSource`]
/// drives either without change.
///
/// ## Multi-holder (task-66): index by holder, do not replace the KEY
///
/// A single `NarHash` can be held by MANY peers, and the whole point of a decentral
/// cache is that a DEAD holder fails over to the NEXT one. So the index accumulates
/// distinct HOLDERS under a key (it used to REPLACE the whole key, which capped it at
/// one holder and collapsed failover into the peer->upstream fallback S6 already
/// covers). `resolve` merges the live holders into ONE [`Claim`] whose `transports`
/// is the UNION of the winning partition's fetch offers, in ANNOUNCE ORDER - exactly
/// the shape [`crate::transport_fetch::fetch_via_offers`] already iterates and fails
/// over across, so multi-holder failover falls out of the EXISTING fetch driver with
/// NO change to the FROZEN claim wire schema (`holders`/`transports` are already
/// `Vec` on [`Claim`]; this constructs an in-memory value with several entries, it
/// does not grow the on-wire surface).
///
/// ## Per-holder last-writer-wins + eviction (task-171)
///
/// The natural unit of an announce is the HOLDER: a holder is the single source of
/// truth for ITS OWN offers, so its latest announce must REPLACE its prior offer set,
/// not accumulate alongside it. The index therefore keys each key's holders by
/// [`HolderId`] and stores each holder's LATEST [`HeldClaim`]. A holder correcting or
/// shrinking its offers RETRACTS the stale ones (the old full-`Claim` dedup could
/// only ever GROW: an updated announce was a distinct value that piled on, so a dead
/// locator was dialed forever). Entries past [`ANNOUNCE_TTL`] are evicted lazily on
/// `announce`/`resolve`, so the index is not grow-only.
///
/// ## Partition-by-content-id: one lying announce cannot collapse the key (task-170)
///
/// `resolve` PARTITIONS the live holders by their claimed content id
/// ([`Claim::content_id`], the `BLAKE3(RawNarV1)`) and surfaces only the partition
/// with the MOST corroborating live holders (ties broken by earliest announce, so it
/// is deterministic). Honest holders of one `NarHash` agree on its `BLAKE3` (a pure
/// function of the same bytes), so they land in one partition; a holder announcing a
/// WRONG blake3 forms its OWN, minority partition and is segregated, NOT unioned in -
/// so it cannot make every honest holder be dialed for the wrong content and collapse
/// the key to a discovery-exhausted miss. Inert announces (`payload == None`, an
/// unknown/undecodable payload kind) assert NO content id, so they are folded into the
/// winning partition rather than forming a rival one - their offers still fail over,
/// exactly as before. HONEST LIMIT: this is a MAJORITY vote with no trust or
/// reputation, so a sybil that announces MORE (fake) holders than the honest set could
/// still win; stopping ONE lying announce from collapsing the key is the bounded claim
/// (task-170 AC#3). The daemon is outside the TCB regardless - a surfaced-but-lying
/// offer only ever yields bytes that fail the downstream gate-1 integrity check, never
/// wrong bytes (see [`crate::transport_fetch`]).
///
/// Keyed on [`NarHashKey`] (not a loose string) so it agrees BY CONSTRUCTION with
/// the availability index and the claim wire - the canonical-key discipline the
/// task-38/48 notes call out (a non-canonical key can never be inserted, because
/// the claim already carries a strict `NarHashKey`).
pub struct InMemoryDiscovery {
    /// key -> (holder identity -> that holder's latest claim + announce time). The
    /// inner map is per-holder so a re-announce REPLACES in place (task-171 LWW);
    /// announce order for resolve is reconstructed from [`HeldClaim::seq`].
    claims: Mutex<HashMap<NarHashKey, HashMap<HolderId, HeldClaim>>>,
    /// A per-instance monotonic announce counter, stamped onto every NEW holder's
    /// [`HeldClaim`] so resolve can recover a deterministic FIRST-SEEN announce order
    /// across the `HashMap`. A re-announce KEEPS its holder's original `seq`, so a
    /// refresh does not reshuffle failover order.
    seq: std::sync::atomic::AtomicU64,
    /// How long a holder's announce stays live before eviction (default
    /// [`ANNOUNCE_TTL`]; a short one in tests).
    ttl: Duration,
    /// The time source (real [`SystemClock`] in production; a manual clock in tests
    /// so eviction is provable without sleeping).
    clock: Arc<dyn Clock>,
}

impl Default for InMemoryDiscovery {
    fn default() -> Self {
        Self {
            claims: Mutex::new(HashMap::new()),
            seq: std::sync::atomic::AtomicU64::new(0),
            ttl: ANNOUNCE_TTL,
            clock: Arc::new(SystemClock),
        }
    }
}

impl InMemoryDiscovery {
    /// An empty discovery source with the default [`ANNOUNCE_TTL`] and the real clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// As [`new`](Self::new) but with an explicit eviction TTL and time source. Used
    /// by tests to prove eviction without sleeping a real hour; production takes the
    /// [`Default`] (a [`SystemClock`] and [`ANNOUNCE_TTL`]).
    #[cfg(test)]
    fn with_ttl_and_clock(ttl: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            claims: Mutex::new(HashMap::new()),
            seq: std::sync::atomic::AtomicU64::new(0),
            ttl,
            clock,
        }
    }

    /// The identity a claim is keyed by within a `NarHash` (its `holders` set). See
    /// [`HolderId`] for why the whole set, not an arbitrary element.
    fn holder_id(claim: &Claim) -> HolderId {
        claim.holders.clone()
    }

    /// Record a claim under its own canonical [`NarHashKey`], as the LATEST announce
    /// from its holder identity (task-171 per-holder last-writer-wins): a re-announce
    /// from the same holder REPLACES that holder's prior offer set in place (so a
    /// corrected/shrunk offer set retracts the stale locators), while a DIFFERENT
    /// holder accumulates alongside it (task-66 multi-holder). Refreshing the same
    /// offers is idempotent as to the holder set and simply resets the holder's TTL.
    /// Stale holders (past [`ANNOUNCE_TTL`]) for the touched key are evicted here.
    pub fn announce(&self, claim: Claim) {
        let now = self.clock.now();
        let mut claims = self.claims.lock().expect("claims mutex");
        let holders = claims.entry(claim.key).or_default();
        // Reap this key's dead holders while we hold the lock, so an updated announce
        // also gc's the neighbours that stopped refreshing.
        holders.retain(|_, held| now.duration_since(held.announced_at) < self.ttl);
        let id = Self::holder_id(&claim);
        // FIRST-SEEN order: a re-announce keeps the holder's original sequence (it is
        // the same holder failing over in the same slot); only a genuinely new holder
        // takes the next sequence. This keeps the deterministic announce order the
        // task-66 tests pin, while LWW still replaces the offers and refreshes the TTL.
        let seq = match holders.get(&id) {
            Some(existing) => existing.seq,
            None => self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        };
        holders.insert(
            id,
            HeldClaim {
                claim,
                announced_at: now,
                seq,
            },
        );
    }

    /// Merge one content-id PARTITION's live claims (already selected as the winner by
    /// [`resolve`]) into a SINGLE claim whose `holders`/`transports`/`signatures` are
    /// the UNION across them in ANNOUNCE ORDER, de-duplicating repeats. `claims` is
    /// non-empty. The content id / relay come from the first claim that actually
    /// carries one (`find_map`): the inert (`payload == None`) claims folded into the
    /// winner carry none, and must not blind a partition whose honest holders do.
    fn merge(claims: &[&Claim]) -> Claim {
        let first = claims[0];
        let payload = claims.iter().find_map(|c| c.payload.clone());
        let relay = claims.iter().find_map(|c| c.relay.clone());
        let mut holders: Vec<NodeId> = Vec::new();
        let mut transports: Vec<KnownTransport> = Vec::new();
        let mut signatures: Vec<crate::claim::ClaimSignature> = Vec::new();
        for claim in claims {
            for holder in &claim.holders {
                if !holders.contains(holder) {
                    holders.push(*holder);
                }
            }
            for transport in &claim.transports {
                if !transports.contains(transport) {
                    transports.push(transport.clone());
                }
            }
            for signature in &claim.signatures {
                if !signatures.contains(signature) {
                    signatures.push(signature.clone());
                }
            }
        }
        Claim {
            schema_version: first.schema_version,
            key: first.key,
            payload,
            holders,
            transports,
            relay,
            signatures,
        }
    }

    /// Choose the content-id partition to surface for a key and merge it, or `None`
    /// if the key has no live holders. Steps (task-170):
    ///   1. Order the live holders by announce order ([`HeldClaim::seq`]).
    ///   2. Partition by claimed content id (`Option<Blake3Digest>`). The inert
    ///      (`None`) group asserts no content id and is not a rival - it is folded
    ///      into whichever real partition wins.
    ///   3. Pick the real partition with the MOST holders (ties: earliest announce),
    ///      fold in the inert claims, and [`merge`](Self::merge). If there is NO real
    ///      partition (every announce inert), fall back to merging the inert group so
    ///      an all-inert key still surfaces its holders (its content id is `None`,
    ///      i.e. unfetchable - unchanged from before).
    fn resolve_key(holders: &HashMap<HolderId, HeldClaim>) -> Option<Claim> {
        if holders.is_empty() {
            return None;
        }
        // Announce order across the HashMap: sort the live claims by their sequence.
        let mut ordered: Vec<&HeldClaim> = holders.values().collect();
        ordered.sort_by_key(|held| held.seq);

        // Partition indices of `ordered` by claimed content id; keep inert separate.
        let mut partitions: Vec<(crate::content_id::Blake3Digest, Vec<&Claim>)> = Vec::new();
        let mut inert: Vec<&Claim> = Vec::new();
        for held in &ordered {
            match held.claim.content_id() {
                Some(cid) => match partitions.iter_mut().find(|(id, _)| id == cid) {
                    Some((_, group)) => group.push(&held.claim),
                    None => partitions.push((*cid, vec![&held.claim])),
                },
                None => inert.push(&held.claim),
            }
        }

        // The winning real partition: MOST holders, ties -> EARLIEST announce.
        // `partitions` is already in first-announce order (it was built by scanning
        // `ordered`), so the winner is the one that is longer, and on equal length
        // the one with the smaller index. The comparator returns `Greater` for the
        // claim that should win: longer length, then (on a tie) the smaller index -
        // `b_idx.cmp(a_idx)` is `Greater` exactly when `a_idx < b_idx`.
        let winner = partitions
            .iter()
            .enumerate()
            .max_by(|(a_idx, (_, a)), (b_idx, (_, b))| {
                a.len().cmp(&b.len()).then_with(|| b_idx.cmp(a_idx))
            })
            .map(|(_, (_, group))| group.clone());

        let mut winning: Vec<&Claim> = match winner {
            Some(group) => group,
            // No real partition at all: every announce was inert. Surface the inert
            // holders (content id stays None, i.e. unfetchable - unchanged behaviour).
            None => return Some(Self::merge(&inert)),
        };
        // Fold the inert (no-content-id) announces into the winner so their offers
        // still fail over; they assert no conflicting content id.
        winning.extend(inert);
        // Re-sort the folded set into announce order so the merged offer list stays
        // in deterministic announce order (the fold appended the inert group).
        winning.sort_by_key(|claim| {
            ordered
                .iter()
                .position(|held| std::ptr::eq(&held.claim, *claim))
                .unwrap_or(usize::MAX)
        });
        Some(Self::merge(&winning))
    }
}

#[async_trait]
impl Discovery for InMemoryDiscovery {
    async fn resolve(&self, key: &NarHashKey) -> Option<Claim> {
        let now = self.clock.now();
        let mut claims = self.claims.lock().expect("claims mutex");
        let holders = claims.get_mut(key)?;
        // Evict this key's stale holders before resolving, so a dead locator is not
        // dialed (task-171) and a key whose every holder has expired misses cleanly.
        holders.retain(|_, held| now.duration_since(held.announced_at) < self.ttl);
        if holders.is_empty() {
            claims.remove(key);
            return None;
        }
        Self::resolve_key(holders)
    }
}

// -------------------------------------------------------------------------
// The PeerQuery seam: ask ONE peer "do you hold X?" over the versioned envelope.
// -------------------------------------------------------------------------

/// Why a single peer probe could not produce an answer. These are per-PEER
/// failures the resolver records and treats as "not a holder" (it moves to the
/// next peer); they are never fatal to the whole resolution.
#[derive(Debug)]
pub enum PeerQueryError {
    /// No route to this peer (no address/index registered for its `NodeId`).
    UnknownPeer(NodeId),
    /// The query/response could not be encoded or decoded (a wire fault).
    Codec(String),
    /// The peer's index failed to answer (e.g. its `nix-store --dump` failed).
    Answer(String),
}

impl std::fmt::Display for PeerQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerQueryError::UnknownPeer(node) => write!(f, "no route to peer {node}"),
            PeerQueryError::Codec(why) => write!(f, "peer-query wire fault: {why}"),
            PeerQueryError::Answer(why) => write!(f, "peer failed to answer: {why}"),
        }
    }
}

impl std::error::Error for PeerQueryError {}

/// The query TRANSPORT: send ONE [`HoldQuery`] to ONE peer and get its
/// [`HoldResponse`]. A SEAM so the wave-2a in-process query ([`InProcessPeerQuery`])
/// and a wave-2b over-iroh query (task-47) are interchangeable behind
/// [`DirectDiscovery`].
///
/// The method takes exactly one key (inside the [`HoldQuery`]) and returns exactly
/// one yes/no answer; [`query_batch`](PeerQuery::query_batch) takes N keys the
/// caller named and returns N positional yes/no answers. There is deliberately NO
/// "list holdings" method in either form, so the no-enumeration invariant is
/// structural at this seam (no list method), not just at the index. (A SEPARATE
/// decoder-layer residual - an unknown-KIND offer can carry identity-shaped TEXT
/// in its tag / field-name / scalar value - is tracked by task-227; task-224
/// closed only the structured/list form, not this text channel.)
#[async_trait]
pub trait PeerQuery: Send + Sync {
    /// Probe `node` for the key named in `query`.
    async fn query(&self, node: &NodeId, query: &HoldQuery)
    -> Result<HoldResponse, PeerQueryError>;

    /// Probe `node` for EVERY key named in `query`, in ONE exchange (task-91).
    ///
    /// The returned response is positionally aligned with `query.keys` and that is
    /// checked, not trusted - see [`decode_batch_hold_response`], which takes the
    /// asked count.
    ///
    /// The DEFAULT implementation is a COMPATIBILITY SHIM: it issues one
    /// single-key [`query`](PeerQuery::query) per key, so an existing transport
    /// that has not learned the batch message still answers correctly - at N round
    /// trips, which is exactly the cost this task removes. A transport that really
    /// batches overrides this. (The measurement arm uses the shim as its
    /// one-at-a-time baseline, so the two arms differ in ONE thing: whether the
    /// peer is asked once or N times.)
    ///
    /// Fault handling matches the index's: a per-KEY fault
    /// ([`PeerQueryError::Answer`]) answers `Absent` for that key, while a
    /// per-PEER fault (no route, a wire fault - both true of every key alike)
    /// propagates, because retrying the other 255 keys against a peer we cannot
    /// reach is pure waste.
    async fn query_batch(
        &self,
        node: &NodeId,
        query: &BatchHoldQuery,
    ) -> Result<BatchHoldResponse, PeerQueryError> {
        let (response, notes) = run_query_batch_shim(self, node, query).await?;
        // Emit the AGGREGATED operator notes (task-107 M3): at most one line per
        // fault class for the WHOLE batch, never one per key. Otherwise a peer whose
        // store was GC'd out from under it could make one N-key batch print N
        // near-identical "failed; Absent" lines - log amplification a peer provokes.
        // The decision (WHICH bounded lines) lives in `run_query_batch_shim`, which
        // RETURNS them so it is testable in process; this is only the effect.
        for note in &notes {
            eprintln!("{note}");
        }
        Ok(response)
    }
}

/// The compatibility-shim body of [`PeerQuery::query_batch`], factored out so it can
/// RETURN its operator notes instead of printing them (task-107 M3). This is what
/// makes "the shim logs at most one line per fault class per batch, never one per
/// key" provable in process: a test drives it with a peer that faults every key and
/// asserts the returned `notes.len()` stays small. `peer` is the transport whose
/// single-key [`PeerQuery::query`] the shim loops; the trait default calls this and
/// emits the notes.
async fn run_query_batch_shim<P: PeerQuery + ?Sized>(
    peer: &P,
    node: &NodeId,
    query: &BatchHoldQuery,
) -> Result<(BatchHoldResponse, Vec<String>), PeerQueryError> {
    // The cap applies to the SHIM too, and before any probe is issued. Its
    // return value is a wire message: constructing an over-cap one would build
    // something no decoder on the network accepts, and doing so only AFTER 257
    // single round trips would spend the cost first and refuse afterwards.
    check_batch_keys(&query.keys).map_err(|e| PeerQueryError::Codec(e.to_string()))?;
    let mut answers = Vec::with_capacity(query.keys.len().min(MAX_BATCH_HOLD_KEYS));
    // The offer DICTIONARY built up as the per-key answers arrive. Each key's
    // own locators are interned here and referenced BY INDEX, so a locator that
    // is content-specific (a BitTorrent infohash belongs to one NAR, not to the
    // peer) stays bound to the key it came from. An earlier revision kept the
    // FIRST Have's offers and gave them to every Have, which bound key 2's
    // claim to key 1's infohash - a wrong dial, and a locator volunteered for
    // content the asker never asked about.
    let mut offers: Vec<KnownTransport> = Vec::new();
    // AGGREGATE the per-key `Answer` faults (task-107 M3): count them and keep only
    // the FIRST offender's context, so the batch costs ONE summary line, not one per
    // faulting key.
    let mut faulted: u32 = 0;
    let mut first_fault: Option<String> = None;
    for key in &query.keys {
        let single = HoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            key: *key,
        };
        match peer.query(node, &single).await {
            Ok(response) => match response.answer {
                HoldAnswer::Have {
                    blake3,
                    offers: key_offers,
                } => {
                    let mut offer_indices = Vec::with_capacity(key_offers.len());
                    for offer in key_offers {
                        // Intern: an identical locator (the common case - one
                        // iroh NodeId for every key) is stored once.
                        let at = match offers.iter().position(|known| *known == offer) {
                            Some(at) => at,
                            None => {
                                if offers.len() >= MAX_BATCH_HOLD_OFFERS {
                                    return Err(PeerQueryError::Codec(format!(
                                        "peer {node} offered more than \
                                         {MAX_BATCH_HOLD_OFFERS} distinct locators \
                                         across one batch"
                                    )));
                                }
                                offers.push(offer);
                                offers.len() - 1
                            }
                        };
                        let at = at as OfferIndex;
                        // The wire rejects a repeated index inside one answer,
                        // and a peer may legally repeat an offer within one
                        // single-key answer, so dedupe here.
                        if !offer_indices.contains(&at) {
                            offer_indices.push(at);
                        }
                    }
                    answers.push(BatchHoldAnswer::Have {
                        blake3,
                        offer_indices,
                    });
                }
                HoldAnswer::Absent => answers.push(BatchHoldAnswer::Absent {}),
            },
            Err(err @ PeerQueryError::Answer(_)) => {
                // Loud, but AGGREGATED (task-107 M3): record the count and the first
                // offender here; the caller emits ONE summary line for the whole
                // batch. A per-KEY answer fault degrades that key to Absent (the safe
                // direction) without denying the rest of the closure.
                faulted = faulted.saturating_add(1);
                if first_fault.is_none() {
                    first_fault = Some(format!("{key} ({err})"));
                }
                answers.push(BatchHoldAnswer::Absent {});
            }
            // A peer-level fault is true of every key; do not burn N-1 more.
            Err(err) => return Err(err),
        }
    }
    // Interning can leave an entry no surviving answer references only if a
    // Have was later replaced - it cannot happen above, but the codec's rule is
    // the authority, so assemble and let the shared check speak if it ever does.
    let response = BatchHoldResponse {
        schema_version: QUERY_SCHEMA_VERSION,
        offers,
        answers,
    };
    check_batch_offer_bindings(&as_offer_slots(&response.offers), &response.answers)
        .map_err(|e| PeerQueryError::Codec(e.to_string()))?;

    // At most ONE aggregated fault line for the whole batch, naming the COUNT and the
    // first offender - never one line per faulting key.
    let mut notes = Vec::new();
    if faulted > 0 {
        notes.push(format!(
            "daemon: batch probe of {node}: {faulted} key(s) failed (answered Absent \
             for each); first: {}",
            first_fault.as_deref().unwrap_or("<unknown>")
        ));
    }
    Ok((response, notes))
}

/// The wave-2a query transport: a shared, in-process rendezvous mapping each peer
/// [`NodeId`] to that peer's REAL [`AvailabilityIndex`]. A probe genuinely
/// round-trips the frozen [`HoldQuery`]/[`HoldResponse`] envelope through the
/// task-37 codec and is answered by the task-50 index - the WIRE is real, only the
/// topology (a `HashMap`, not a QUIC connection) is minimal. Wave-2b (task-47)
/// swaps this for an over-iroh protocol behind the same [`PeerQuery`] seam.
#[derive(Default)]
pub struct InProcessPeerQuery {
    peers: HashMap<NodeId, Arc<AvailabilityIndex>>,
}

impl InProcessPeerQuery {
    /// An empty rendezvous.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a peer's availability index under its `NodeId`, so a probe of that
    /// `NodeId` is answered from this index. `node` MUST be the index's own node
    /// identity (the value its offers carry), or a resolved claim would name a
    /// holder the query never actually reached.
    pub fn add_index(&mut self, node: NodeId, index: Arc<AvailabilityIndex>) {
        self.peers.insert(node, index);
    }
}

#[async_trait]
impl PeerQuery for InProcessPeerQuery {
    async fn query(
        &self,
        node: &NodeId,
        query: &HoldQuery,
    ) -> Result<HoldResponse, PeerQueryError> {
        let index = self
            .peers
            .get(node)
            .cloned()
            .ok_or(PeerQueryError::UnknownPeer(*node))?;

        // Node A side: serialise the probe onto the (in-process) wire.
        let on_wire = encode_hold_query(query).map_err(|e| PeerQueryError::Codec(e.to_string()))?;

        // Node B side: decode it and answer from the REAL availability index. The
        // index query is synchronous and may block on `nix-store --dump` under its
        // digest lock, so it is driven on a blocking thread (the availability
        // module's documented contract for an async caller) rather than stalling
        // the runtime.
        let decoded =
            decode_hold_query(&on_wire).map_err(|e| PeerQueryError::Codec(e.to_string()))?;
        let response = tokio::task::spawn_blocking(move || index.answer(&decoded))
            .await
            .map_err(|e| PeerQueryError::Answer(format!("query task panicked: {e}")))?
            .map_err(|e| PeerQueryError::Answer(e.to_string()))?;

        // Node B -> A: serialise the response and decode it on A's side, so the
        // whole probe crosses the frozen envelope in both directions.
        let back =
            encode_hold_response(&response).map_err(|e| PeerQueryError::Codec(e.to_string()))?;
        decode_hold_response(&back).map_err(|e| PeerQueryError::Codec(e.to_string()))
    }

    /// The REAL batched probe (task-91): ONE exchange carrying every key, answered
    /// from the peer's real index in one pass. This overrides the compatibility
    /// shim on [`PeerQuery`], so a `DirectDiscovery` over this transport really
    /// does spend one round trip per peer per chunk instead of one per key.
    ///
    /// The wire is real in both directions, exactly as the single-key path is: the
    /// batch query is ENCODED, DECODED on the peer side, answered from that peer's
    /// [`AvailabilityIndex`], then encoded and decoded back - so the cap checks,
    /// the duplicate-key guard and the positional length check all actually run.
    async fn query_batch(
        &self,
        node: &NodeId,
        query: &BatchHoldQuery,
    ) -> Result<BatchHoldResponse, PeerQueryError> {
        let index = self
            .peers
            .get(node)
            .cloned()
            .ok_or(PeerQueryError::UnknownPeer(*node))?;

        // Node A side: serialise the batch probe (this REFUSES an over-cap,
        // empty or duplicate-bearing batch before it ever reaches the peer).
        let on_wire =
            encode_batch_hold_query(query).map_err(|e| PeerQueryError::Codec(e.to_string()))?;

        // Node B side: decode (size gate, then key cap, then the answer), and
        // answer from the REAL index on a blocking thread - task-104 caps the fresh
        // dumps this batch may trigger at MAX_BATCH_DERIVE_WORK (not one per key), so
        // a cold batch does bounded `nix-store --dump` work under the digest locks.
        let decoded =
            decode_batch_hold_query(&on_wire).map_err(|e| PeerQueryError::Codec(e.to_string()))?;
        let keys_asked = decoded.keys.len();
        let response = tokio::task::spawn_blocking(move || index.answer_batch(&decoded))
            .await
            .map_err(|e| PeerQueryError::Answer(format!("batch query task panicked: {e}")))?
            .map_err(|e| PeerQueryError::Codec(e.to_string()))?;

        // Node B -> A: back across the envelope, with the positional length
        // checked against what THIS node asked - never against what B claims.
        let back = encode_batch_hold_response(&response)
            .map_err(|e| PeerQueryError::Codec(e.to_string()))?;
        decode_batch_hold_response(&back, keys_asked)
            .map_err(|e| PeerQueryError::Codec(e.to_string()))
    }
}

// -------------------------------------------------------------------------
// DirectDiscovery: probe a known-peer set, first Have wins, bounded per peer.
// -------------------------------------------------------------------------

/// The wave-2a [`Discovery`] impl: probe a CONFIGURED set of peer [`NodeId`]s (the
/// minimal rendezvous) with the [`HoldQuery`] envelope, returning the first
/// holder's complete claim. Each probe is [`PROBE_TIMEOUT`]-bounded so a
/// silent/wedged peer yields a fast miss rather than a hang (the AC#2 correctness
/// point). See the module docs for the honest limits the task-47 DHT spike lifts.
pub struct DirectDiscovery {
    /// The known peers to probe, in order. Configured (not DHT-discovered) - this
    /// is exactly the `NarHash -> candidate NodeIds` half deferred to task-47.
    peers: Vec<NodeId>,
    query: Arc<dyn PeerQuery>,
    probe_timeout: Duration,
}

impl DirectDiscovery {
    /// Probe `peers` (in order) via `query`, with the default [`PROBE_TIMEOUT`] per
    /// probe. The TOTAL-call bound is the caller's [`DiscoveryBudget`] passed to
    /// [`resolve_many`](Discovery::resolve_many) (TASK-232) - it is no longer an
    /// internal field, so there is exactly ONE total deadline, not two racing.
    pub fn new(peers: Vec<NodeId>, query: Arc<dyn PeerQuery>) -> Self {
        Self {
            peers,
            query,
            probe_timeout: PROBE_TIMEOUT,
        }
    }

    /// As [`new`](Self::new) but with an explicit per-peer probe bound (tests use a
    /// short one to prove a hanging peer still yields a fast, typed outcome). The
    /// total-call bound is the caller's [`DiscoveryBudget`], not a field here.
    pub fn with_timeout(
        peers: Vec<NodeId>,
        query: Arc<dyn PeerQuery>,
        probe_timeout: Duration,
    ) -> Self {
        Self {
            peers,
            query,
            probe_timeout,
        }
    }

    /// Build the holder's claim from its `Have` answer: the single content id
    /// (`blake3`), the queried peer as holder, and the peer's own transport offers.
    /// The daemon is outside the TCB, so a lying offer (wrong holder/blake3) fails
    /// the fetch gates and falls back - never wrong bytes (task-56 hardens the
    /// source side).
    fn claim_from_have(key: &NarHashKey, holder: NodeId, blake3_and_offers: HoldAnswer) -> Claim {
        let (blake3, offers) = match blake3_and_offers {
            HoldAnswer::Have { blake3, offers } => (blake3, offers),
            // Only ever called with a Have; Absent is filtered in `resolve`.
            HoldAnswer::Absent => unreachable!("claim_from_have called on an Absent answer"),
        };
        Claim {
            schema_version: CLAIM_SCHEMA_VERSION,
            key: *key,
            payload: Some(KnownPayload::WholeNar { blake3 }),
            holders: vec![holder],
            transports: offers,
            relay: None,
            signatures: vec![],
        }
    }
}

/// Per-key cross-peer accumulator for [`DirectDiscovery::resolve_many`] (TASK-232),
/// applying the TASK-100 contract's ONE RULE in the Claim type universe: a key is an
/// authoritative [`Miss`](ClaimResolution::Miss) ONLY if at least one peer authoritatively
/// answered `Absent`, no peer that could have answered it faulted, and the total deadline
/// did not cut its consultation short. `Found` is terminal (first `Have` wins); a mechanism
/// fault is sticky and BLOCKS a `Miss` (a dead/unusable peer can never read as
/// nobody-has-it).
#[derive(Clone, Default)]
struct ClaimAcc {
    /// The first `Have` claim for this key (a `Found` is terminal - it wins).
    found: Option<Claim>,
    /// The first could-not-consult reason (a per-peer fault, a probe timeout, or an
    /// unusable answer). First-wins keeps the most specific earlier reason.
    fault: Option<Unavailable>,
    /// At least one consulted peer authoritatively answered `Absent` for this key.
    saw_absent: bool,
}

impl ClaimAcc {
    fn is_found(&self) -> bool {
        self.found.is_some()
    }

    fn note_found(&mut self, claim: Claim) {
        if self.found.is_none() {
            self.found = Some(claim);
        }
    }

    fn note_absent(&mut self) {
        self.saw_absent = true;
    }

    fn note_fault(&mut self, why: Unavailable) {
        if self.fault.is_none() {
            self.fault = Some(why);
        }
    }

    /// Decide the key's final typed outcome. `deadline_cut` is the batch-level flag: the
    /// total deadline stopped the peer loop before the full known-peer set was consulted.
    /// Found wins; else a fault is could-not-consult (Unavailable), NEVER an authoritative
    /// absence; else a deadline cut leaves it a partial NotAttempted; else an authoritative
    /// Absent-by-every-consulted-peer is a Miss; else (no peer was ever consulted, e.g. an
    /// empty peer set) nothing was attempted, so NotAttempted - never a false Miss.
    fn finalize(self, deadline_cut: bool) -> ClaimResolution {
        if let Some(claim) = self.found {
            ClaimResolution::Found(claim)
        } else if let Some(why) = self.fault {
            ClaimResolution::Unavailable(why)
        } else if deadline_cut {
            ClaimResolution::NotAttempted
        } else if self.saw_absent {
            ClaimResolution::Miss
        } else {
            ClaimResolution::NotAttempted
        }
    }
}

/// Mark EVERY still-pending key of a peer (all of `positions`) as could-not-consult - the
/// per-PEER fault path, where the fault is true of every key the peer was going to answer.
fn note_fault_all(
    acc: &mut [ClaimAcc],
    positions: &HashMap<NarHashKey, Vec<usize>>,
    why: Unavailable,
) {
    for idxs in positions.values() {
        for &i in idxs {
            acc[i].note_fault(why.clone());
        }
    }
}

/// Mark only THIS chunk's keys as could-not-consult - the per-ANSWER fault path (a
/// misaligned reply), which does not implicate the peer's other chunks.
fn note_fault_chunk(
    acc: &mut [ClaimAcc],
    positions: &HashMap<NarHashKey, Vec<usize>>,
    chunk: &[NarHashKey],
    why: Unavailable,
) {
    for key in chunk {
        for &i in positions.get(key).into_iter().flatten() {
            acc[i].note_fault(why.clone());
        }
    }
}

#[async_trait]
impl Discovery for DirectDiscovery {
    async fn resolve(&self, key: &NarHashKey) -> Option<Claim> {
        let query = HoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            key: *key,
        };
        for peer in &self.peers {
            // Bounded probe: a peer that never answers times out and is skipped, so
            // a miss cannot leak unbounded latency into the build path.
            match tokio::time::timeout(self.probe_timeout, self.query.query(peer, &query)).await {
                Ok(Ok(response)) => match response.answer {
                    have @ HoldAnswer::Have { .. } => {
                        return Some(Self::claim_from_have(key, *peer, have));
                    }
                    HoldAnswer::Absent => continue,
                },
                Ok(Err(err)) => {
                    // A per-peer fault is not fatal: log and treat as a non-holder.
                    eprintln!("daemon: discovery probe of {peer} failed: {err}");
                    continue;
                }
                Err(_elapsed) => {
                    eprintln!(
                        "daemon: discovery probe of {peer} exceeded {:?}; treating as a miss",
                        self.probe_timeout
                    );
                    continue;
                }
            }
        }
        None
    }

    /// Resolve a whole closure with ONE probe per peer per chunk (task-91), into TYPED
    /// per-key [`ClaimResolution`]s (TASK-232) - never a lossy `Option<Claim>` that folds
    /// a dead peer, a spent deadline and a genuine absence into one indistinguishable
    /// `None`.
    ///
    /// The shape of the work, and why it is this shape:
    ///   * The DISTINCT keys still WITHOUT a holder are collected per peer, so a peer is
    ///     never asked about a key an earlier peer already answered `Have` for, and never
    ///     asked the same key twice (the wire forbids duplicates; a caller's closure list
    ///     may legitimately contain them). A key one peer faulted on OR answered `Absent`
    ///     is still worth asking a LATER peer (only a `Found` is terminal).
    ///   * The batch is chunked at [`MAX_BATCH_HOLD_KEYS`], so a 1000-path closure is 4
    ///     probes per peer rather than 1000 - the cap enforced by construction here.
    ///   * Peers are tried in order and the loop STOPS as soon as every key has a holder,
    ///     so the common case (the first peer holds the closure) really is one round trip.
    ///   * The whole call is bounded by the CALLER's [`DiscoveryBudget`] total deadline
    ///     (TASK-232, subsuming the old internal `RESOLVE_MANY_TIMEOUT` - ONE bound, not
    ///     two racing): the deadline is taken once at entry, each probe waits at most
    ///     `min(probe_timeout, remaining)`, and once the budget is spent the peer loop
    ///     stops. Every key STILL without a holder when the deadline cut the loop is typed
    ///     [`ClaimResolution::NotAttempted`] (a PARTIAL marker), never a false `Miss`.
    ///   * On a per-PEER fault (a `query_batch` error - no route / a wire fault - or a
    ///     probe TIMEOUT, both true of every key alike) the peer's REMAINING chunks are
    ///     ABANDONED, not just the current one (task-106 AC#2), and every key that peer
    ///     was going to answer is marked [`ClaimResolution::Unavailable`] - a
    ///     could-not-consult, NEVER a false `Miss` (a dead peer might have held it). A
    ///     later peer can still override that to `Found`.
    ///   * A per-ANSWER fault (a misaligned reply, or an out-of-range offer index) is the
    ///     answering peer's fault for the affected keys only: they are marked
    ///     `Unavailable` and the chunk is skipped WITHOUT abandoning the peer.
    ///   * A key EVERY consulted peer authoritatively answered `Absent` for, in full and
    ///     within budget, with no fault blocking it, is an authoritative
    ///     [`ClaimResolution::Miss`] - the caller may trust it as absence.
    ///   * SEQUENTIAL, not concurrent, is a DELIBERATE choice (task-106 AC#3): the total
    ///     deadline makes the sequential worst case bounded regardless of peer count.
    ///     Concurrency needs a bounded fan-out plus a Have tiebreak - the versioned
    ///     execution plan task-100 AC#5 owns and must not be hardcoded before holdout.
    async fn resolve_many(
        &self,
        keys: &[NarHashKey],
        budget: &DiscoveryBudget,
    ) -> Vec<ClaimResolution> {
        let mut acc: Vec<ClaimAcc> = vec![ClaimAcc::default(); keys.len()];
        if keys.is_empty() {
            return Vec::new();
        }

        // The SINGLE total-call bound (TASK-232, subsuming RESOLVE_MANY_TIMEOUT). Taken
        // once, checked before each peer and each chunk; each probe is additionally clamped
        // to the remaining budget so no single wait can overrun it. Integer Instant/Duration
        // arithmetic only - no floats in a build-path bound.
        let deadline = Instant::now() + budget.deadline;
        // Whether the total deadline actually cut the peer loop short, so a key that still
        // has no holder is a PARTIAL NotAttempted (the full known-peer set was NOT consulted
        // for it), never a fabricated authoritative Miss.
        let mut deadline_cut = false;

        'peers: for peer in &self.peers {
            // The distinct keys still WITHOUT a holder, and where each one's answer goes.
            let mut positions: HashMap<NarHashKey, Vec<usize>> = HashMap::new();
            let mut pending: Vec<NarHashKey> = Vec::new();
            for (i, key) in keys.iter().enumerate() {
                if acc[i].is_found() {
                    continue;
                }
                match positions.entry(*key) {
                    Entry::Occupied(mut slot) => slot.get_mut().push(i),
                    Entry::Vacant(slot) => {
                        pending.push(*key);
                        slot.insert(vec![i]);
                    }
                }
            }
            if pending.is_empty() {
                break; // every key has a holder; no further peer is worth a round trip
            }

            for chunk in pending.chunks(MAX_BATCH_HOLD_KEYS) {
                // The remaining total budget. Zero means the call deadline is spent: stop
                // probing entirely. Clamp this probe to the remainder so a single wait
                // cannot overrun the total (task-106 AC#1).
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    eprintln!(
                        "daemon: resolve_many hit its total {:?} budget; keys still without a \
                         holder are NotAttempted (partial), never a false miss",
                        budget.deadline
                    );
                    deadline_cut = true;
                    break 'peers;
                }
                let probe_bound = self.probe_timeout.min(remaining);
                let query = BatchHoldQuery {
                    schema_version: QUERY_SCHEMA_VERSION,
                    keys: chunk.to_vec(),
                };
                let response = match tokio::time::timeout(
                    probe_bound,
                    self.query.query_batch(peer, &query),
                )
                .await
                {
                    Ok(Ok(response)) => response,
                    Ok(Err(err)) => {
                        // A per-PEER fault (no route / a wire fault) is true of every key
                        // alike: every key this peer was going to answer is could-not-consult
                        // (never a false Miss), and its remaining chunks are ABANDONED
                        // (task-106 AC#2).
                        eprintln!(
                            "daemon: batched discovery probe of {peer} ({} keys) failed: {err}; \
                             abandoning this peer's remaining chunks",
                            chunk.len()
                        );
                        note_fault_all(
                            &mut acc,
                            &positions,
                            Unavailable::Backend(format!("peer {peer} probe failed: {err}")),
                        );
                        continue 'peers;
                    }
                    Err(_elapsed) => {
                        // A probe TIMEOUT is a per-PEER fault too (the peer did not answer):
                        // could-not-consult for every key, never a false Miss; abandon the
                        // peer's remaining chunks (task-106 AC#2). `probe_bound` is the
                        // clamped bound actually applied (<= PROBE_TIMEOUT once budget is low).
                        eprintln!(
                            "daemon: batched discovery probe of {peer} ({} keys) exceeded {:?}; \
                             treating as could-not-consult and abandoning its remaining chunks",
                            chunk.len(),
                            probe_bound
                        );
                        note_fault_all(
                            &mut acc,
                            &positions,
                            Unavailable::Backend(format!(
                                "peer {peer} probe exceeded {probe_bound:?}"
                            )),
                        );
                        continue 'peers;
                    }
                };
                // Defence in depth: a mis-aligned answer would silently bind every later
                // key to the wrong hash. It is an UNUSABLE (protocol-broken) answer for this
                // chunk's keys - mark them could-not-consult (never a fabricated Miss) and
                // skip the chunk, but do NOT abandon the peer (a per-answer, not per-peer,
                // fault).
                if response.answers.len() != chunk.len() {
                    eprintln!(
                        "daemon: peer {peer} answered {} of {} batched keys; discarding the \
                         whole answer (positional alignment is not recoverable)",
                        response.answers.len(),
                        chunk.len()
                    );
                    note_fault_chunk(
                        &mut acc,
                        &positions,
                        chunk,
                        Unavailable::Backend(format!(
                            "peer {peer} returned a misaligned batch reply"
                        )),
                    );
                    continue;
                }
                for (key, answer) in chunk.iter().zip(response.answers.iter()) {
                    let BatchHoldAnswer::Have {
                        blake3,
                        offer_indices,
                    } = answer
                    else {
                        // Absent: this peer authoritatively does not hold the key.
                        for i in positions.get(key).into_iter().flatten() {
                            acc[*i].note_absent();
                        }
                        continue;
                    };
                    // THIS key's own locators, selected from the response's offer dictionary
                    // (not the whole dictionary) so a content-specific locator stays bound to
                    // its key. The codec already proved every index is in range; a missing
                    // one is a bug on THIS side - it is an unusable answer for that key, so it
                    // is marked Unavailable rather than silently producing a partial claim.
                    let mut offers = Vec::with_capacity(offer_indices.len());
                    let mut out_of_range = false;
                    for index in offer_indices {
                        match response.offers.get(usize::from(*index)) {
                            Some(offer) => offers.push(offer.clone()),
                            None => out_of_range = true,
                        }
                    }
                    if out_of_range {
                        eprintln!(
                            "daemon: peer {peer} answered {key} with an offer index outside \
                             its own dictionary of {}; discarding that answer",
                            response.offers.len()
                        );
                        for i in positions.get(key).into_iter().flatten() {
                            acc[*i].note_fault(Unavailable::Backend(format!(
                                "peer {peer} answer for {key} carried an out-of-range offer index"
                            )));
                        }
                        continue;
                    }
                    let claim = Self::claim_from_have(
                        key,
                        *peer,
                        HoldAnswer::Have {
                            blake3: *blake3,
                            offers,
                        },
                    );
                    for i in positions.get(key).into_iter().flatten() {
                        acc[*i].note_found(claim.clone());
                    }
                }
            }
        }
        // THE ONE choke-point: each per-key accumulator is finalized under the SAME rule the
        // contract enforces - Found wins; else a fault (dead/unusable mechanism) is
        // Unavailable, never a Miss; else a deadline cut is NotAttempted (partial); else an
        // authoritative Absent-by-all is a Miss.
        acc.into_iter().map(|a| a.finalize(deadline_cut)).collect()
    }
}

// -------------------------------------------------------------------------
// FallbackNarSource: p2p first, upstream on a miss (S2 preserved).
// -------------------------------------------------------------------------

/// Compose a PRIMARY (p2p) [`NarSource`] with a SECONDARY (upstream/CDN)
/// [`NarSource`]: a primary MISS falls back to the secondary, so a `NarHash` no
/// peer holds is still served (the wave-1 S2 path, preserved). This is the
/// composable seam task-41 wires into the serving layer; task-51's safety envelope
/// upgrades the SEQUENTIAL fallback here into the concurrent abort/hedge policy.
///
/// Fallback policy (deliberate, stated as one):
///   * [`SourceError::Unreachable`] and [`SourceError::Upstream`] from the primary
///     mean "p2p cannot serve this here" (a discovery miss, an exhausted offer
///     set, an unknown-payload claim) - FALL BACK to the secondary.
///   * [`SourceError::TooLarge`] is the risk-6 size ABORT (task-25/51). It is NOT a
///     "try elsewhere" signal - falling back would be a workaround for a
///     deliberate abort - so it PROPAGATES unchanged.
///
/// The SAME [`NarKey`] drives both: on the normal path it is
/// [`NarKey::SignedNarHash`], carrying the signed hash (which the p2p primary
/// resolves on) AND the exact upstream token (which the HTTP secondary fetches on),
/// so no key rewriting is needed at the fallback boundary.
pub struct FallbackNarSource {
    primary: Arc<dyn NarSource>,
    secondary: Arc<dyn NarSource>,
}

impl FallbackNarSource {
    /// Try `primary` first, `secondary` on a p2p miss.
    pub fn new(primary: Arc<dyn NarSource>, secondary: Arc<dyn NarSource>) -> Self {
        Self { primary, secondary }
    }
}

#[async_trait]
impl NarSource for FallbackNarSource {
    async fn resolve(
        &self,
        key: &NarKey,
        expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        // Single source of truth for the fallback policy: the no-budget (chain
        // ENTRY / lone-daemon) path is just `resolve_within` with `None`, which
        // seeds the secondary from its own local timeout exactly as wave-1 did.
        self.resolve_within(key, expected_size, None).await
    }

    /// Budget-aware fallback (TASK-33 F1). The end-to-end header-wait budget must
    /// survive a p2p MISS: the primary attempt (a bounded discovery + fetch) spends
    /// real time, so the HTTP secondary is granted only the REMAINING budget, not a
    /// fresh full local timeout. Without this override the default `resolve_within`
    /// would drop the budget and call `resolve`, and on the NORMAL p2p-miss -> CDN
    /// path the secondary `UpstreamHttp` would re-seed its whole local
    /// `header_timeout`, breaking chain composition on the most common production
    /// path. Nested `FallbackNarSource` wrappers compose correctly because each
    /// level subtracts its OWN primary's elapsed before forwarding the remainder.
    async fn resolve_within(
        &self,
        key: &NarKey,
        expected_size: Option<u64>,
        budget: Option<Duration>,
    ) -> Result<UpstreamResponse, SourceError> {
        // Anchor the shared end-to-end clock at the START of the primary attempt so
        // the secondary's grant is decremented by the time the primary actually
        // spent (a genuine shrinking deadline, not a fresh timeout).
        let started = Instant::now();
        match self
            .primary
            .resolve_within(key, expected_size, budget)
            .await
        {
            Ok(resp) => Ok(resp),
            Err(err @ (SourceError::Unreachable(_) | SourceError::Upstream(_))) => {
                // p2p could not serve it here: fall back to upstream (S2). The miss
                // is already bounded upstream of here (DirectDiscovery / the
                // transport timeout), so this does not re-introduce a hang.
                eprintln!("daemon: p2p miss ({err}); falling back to upstream");
                // Forward the budget MINUS what the primary attempt consumed. `None`
                // (chain entry) stays `None` so the secondary seeds from its own
                // local timeout; a `Some` budget already spent by the primary
                // saturates to zero, so the CDN fetch fails fast rather than
                // starting a fresh full wait the chain has no time for.
                let remaining = budget.map(|b| b.saturating_sub(started.elapsed()));
                self.secondary
                    .resolve_within(key, expected_size, remaining)
                    .await
            }
            // A size abort is not a "try elsewhere" - do not paper over it.
            Err(err @ SourceError::TooLarge { .. }) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use http::HeaderMap;
    use http_body_util::{BodyExt, Full};

    use crate::availability::{
        MemoryNarDumper, NullAnnounce, NullStore, RegularFileNarDumper, StorePath,
    };
    use crate::claim::KnownTransport;
    use crate::content_id::Blake3Digest;
    use crate::source::{NarHash, NarPathToken};

    // ---- helpers -----------------------------------------------------------

    /// A temp dir that removes itself on drop (mirrors the availability tests), so
    /// a `StorePath` can point at a file that actually EXISTS - the index answers
    /// `Absent` for a path that does not.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "nixp2p-disco-{label}-{}-{n}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            TempDir { path }
        }

        fn store_file(&self, name: &str) -> StorePath {
            let p = self.path.join(name);
            std::fs::write(&p, b"stand-in store path").expect("write store file");
            StorePath::new(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Two distinct canonical NarHash keys, built from real sha256-shaped bytes.
    /// A generous total-call budget for the closure-resolution tests whose subject is NOT
    /// the deadline (TASK-232). Mirrors the old `RESOLVE_MANY_TIMEOUT` default so behaviour
    /// unrelated to the deadline is unchanged; deadline-focused tests build their own.
    fn budget() -> DiscoveryBudget {
        DiscoveryBudget::new(RESOLVE_MANY_TIMEOUT, 16)
    }

    fn key_x() -> NarHashKey {
        NarHashKey::from_sha256_bytes([0x11; 32])
    }
    fn key_y() -> NarHashKey {
        NarHashKey::from_sha256_bytes([0x22; 32])
    }

    fn node_b() -> NodeId {
        NodeId::from_bytes([0xbb; 32])
    }

    /// An index for `node`, holding a real (existing) store file whose NAR is
    /// `nar`, registered under its TRUE NarHash (`sha256(nar)`) - task-56 verifies
    /// this at first serve, so a test must register the real key, not an arbitrary
    /// one. Returns the index, the (true) key it holds, and the temp dir.
    fn index_holding(node: NodeId, nar: Vec<u8>) -> (Arc<AvailabilityIndex>, NarHashKey, TempDir) {
        let dir = TempDir::new("idx");
        let store_path = dir.store_file("nar");
        let key = NarHashKey::from_raw_nar(&nar);
        let index = AvailabilityIndex::open(
            node,
            Arc::new(MemoryNarDumper::new(nar)),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("open index");
        index.register(key, store_path).expect("register");
        (Arc::new(index), key, dir)
    }

    // ---- the REAL query envelope, answered from the REAL index -------------

    #[tokio::test]
    async fn in_process_query_round_trips_the_envelope_and_answers_from_the_index() {
        let nar = b"the raw NAR node B holds".to_vec();
        let (index, key, _dir) = index_holding(node_b(), nar.clone());
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);

        let query = HoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            key,
        };
        let response = rendezvous
            .query(&node_b(), &query)
            .await
            .expect("a real round-trip through the frozen envelope");

        match response.answer {
            HoldAnswer::Have { blake3, offers } => {
                assert_eq!(
                    blake3,
                    Blake3Digest::from_raw_nar(&nar),
                    "the addressed unit"
                );
                assert_eq!(offers, vec![KnownTransport::Iroh { node: node_b() }]);
            }
            HoldAnswer::Absent => panic!("B holds key_x - the probe must answer Have"),
        }
    }

    // ---- AC#3: no-enumeration - probing X reveals nothing about Y ----------

    #[tokio::test]
    async fn probing_one_key_never_reveals_another_holding() {
        // B holds Y but NOT X. A probes X: it learns only that X is Absent - the
        // response cannot enumerate that B also holds Y (there is no such method).
        // Y is the TRUE NarHash of B's held NAR (task-56); X is an arbitrary key B
        // never registered, so it is Absent BEFORE any verification even runs.
        let (index, key_y, _dir) = index_holding(node_b(), b"B holds only Y".to_vec());
        let key_x = key_x();
        assert_ne!(
            key_x, key_y,
            "X and Y must be distinct for the test to bite"
        );
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);

        let probe_x = HoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            key: key_x,
        };
        let response = rendezvous.query(&node_b(), &probe_x).await.expect("probe");
        assert_eq!(
            response.answer,
            HoldAnswer::Absent,
            "an unheld key answers Absent and leaks no listing of the peer's real holdings"
        );

        // And discovery over the same peer misses on X even though B holds Y - the
        // resolver is strictly per-key.
        let discovery = DirectDiscovery::new(vec![node_b()], Arc::new(rendezvous));
        assert!(
            discovery.resolve(&key_x).await.is_none(),
            "X is not held; Y being held must not turn this into a hit"
        );
        assert!(
            discovery.resolve(&key_y).await.is_some(),
            "Y is held; the same resolver finds it (control)"
        );
    }

    // ---- DirectDiscovery: a hit yields the complete offer ------------------

    #[tokio::test]
    async fn resolve_returns_the_complete_offer_from_the_holder() {
        let nar = b"resolve me".to_vec();
        let (index, key, _dir) = index_holding(node_b(), nar.clone());
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);
        let discovery = DirectDiscovery::new(vec![node_b()], Arc::new(rendezvous));

        let claim = discovery.resolve(&key).await.expect("a hit");
        assert_eq!(claim.key, key);
        assert_eq!(
            claim.content_id(),
            Some(&Blake3Digest::from_raw_nar(&nar)),
            "the claim carries the addressed unit (not merely a holder)"
        );
        assert_eq!(claim.holders, vec![node_b()]);
        assert_eq!(
            claim.transports,
            vec![KnownTransport::Iroh { node: node_b() }]
        );
    }

    // ---- task-66: InMemoryDiscovery accumulates holders (multimap) ---------

    /// A whole-NAR claim for `key`, held by `holder`, offering the iroh locator for
    /// that holder. `blake3` is shared across holders of the same key (honest
    /// holders of one NarHash agree on it) so the merge is over ONE content id.
    fn claim_held_by(key: NarHashKey, holder: NodeId, blake3: Blake3Digest) -> Claim {
        Claim {
            schema_version: CLAIM_SCHEMA_VERSION,
            key,
            payload: Some(KnownPayload::WholeNar { blake3 }),
            holders: vec![holder],
            transports: vec![KnownTransport::Iroh { node: holder }],
            relay: None,
            signatures: vec![],
        }
    }

    #[tokio::test]
    async fn announce_accumulates_holders_instead_of_replacing_them() {
        // The task-66 core: two DISTINCT holders announce the SAME NarHash. The
        // in-process index must resolve to BOTH (a multimap), not just the last one
        // (the replace-on-key bug). With the old `insert(key, claim)`, holder A is
        // gone the instant B announces and this bites: holders == [B] only.
        let content = Blake3Digest::from_raw_nar(b"one NAR, two holders");
        let a = NodeId::from_bytes([0xaa; 32]);
        let b = NodeId::from_bytes([0xbb; 32]);

        let discovery = InMemoryDiscovery::new();
        discovery.announce(claim_held_by(key_x(), a, content));
        discovery.announce(claim_held_by(key_x(), b, content));

        let claim = discovery.resolve(&key_x()).await.expect("a hit");
        assert_eq!(
            claim.holders,
            vec![a, b],
            "both holders survive, in announce order - not replace-on-key"
        );
        assert_eq!(
            claim.transports,
            vec![
                KnownTransport::Iroh { node: a },
                KnownTransport::Iroh { node: b },
            ],
            "the merged claim offers BOTH holders' locators, in announce order, so \
             the fetch driver can fail over from the first to the second"
        );
        // The content id is single and shared (the merge is over one NAR).
        assert_eq!(claim.content_id(), Some(&content));
    }

    #[tokio::test]
    async fn re_announcing_an_existing_holder_does_not_duplicate_it() {
        // Idempotency: a holder refreshing its identical announce stays ONE entry,
        // so a chatty holder does not inflate the offer list (and does not get
        // itself tried twice by the fetch driver).
        let content = Blake3Digest::from_raw_nar(b"idempotent announce");
        let a = NodeId::from_bytes([0xaa; 32]);
        let b = NodeId::from_bytes([0xbb; 32]);

        let discovery = InMemoryDiscovery::new();
        discovery.announce(claim_held_by(key_x(), a, content));
        discovery.announce(claim_held_by(key_x(), b, content));
        // A re-announces the SAME claim twice more.
        discovery.announce(claim_held_by(key_x(), a, content));
        discovery.announce(claim_held_by(key_x(), a, content));

        let claim = discovery.resolve(&key_x()).await.expect("a hit");
        assert_eq!(
            claim.holders,
            vec![a, b],
            "a re-announced holder is not duplicated"
        );
        assert_eq!(claim.transports.len(), 2, "no duplicate offers");
    }

    #[tokio::test]
    async fn merge_takes_the_content_id_from_the_first_holder_that_carries_one() {
        // Hardening (mped review): a FIRST holder whose payload decoded to an
        // unknown, inert kind (payload == None - tolerated but inert per claim.rs)
        // must not blind the whole key. resolve takes the content id from the first
        // holder that actually carries one, so a later holder's usable WholeNar is
        // still fetchable. (With an unconditional `claims[0].payload` this returns
        // None and the key becomes an unfetchable no-content-id miss.)
        let content = Blake3Digest::from_raw_nar(b"the usable payload arrives second");
        let a = NodeId::from_bytes([0xaa; 32]);
        let b = NodeId::from_bytes([0xbb; 32]);

        let mut inert = claim_held_by(key_x(), a, content);
        inert.payload = None; // as if decoded from an unknown-kind wire payload

        let discovery = InMemoryDiscovery::new();
        discovery.announce(inert);
        discovery.announce(claim_held_by(key_x(), b, content));

        let claim = discovery.resolve(&key_x()).await.expect("a hit");
        assert_eq!(
            claim.content_id(),
            Some(&content),
            "the usable content id from the second holder is not masked by the first \
             holder's inert payload"
        );
        // Both holders' offers are still present for failover.
        assert_eq!(claim.holders, vec![a, b]);
    }

    #[tokio::test]
    async fn resolve_misses_an_unannounced_key() {
        // Control: the multimap still misses cleanly on a key nobody announced.
        let discovery = InMemoryDiscovery::new();
        discovery.announce(claim_held_by(
            key_x(),
            node_b(),
            Blake3Digest::from_raw_nar(b"x"),
        ));
        assert!(
            discovery.resolve(&key_y()).await.is_none(),
            "an unannounced key is a clean miss"
        );
    }

    // ---- task-170/171: harden the per-holder index -------------------------

    /// A manual, monotonic clock so TTL eviction is provable WITHOUT sleeping a real
    /// [`ANNOUNCE_TTL`] (a multi-second, flake-prone test). It advances only when the
    /// test advances it, so eviction is deterministic.
    struct ManualClock {
        base: Instant,
        offset_nanos: AtomicUsize,
    }
    impl ManualClock {
        fn new() -> Arc<Self> {
            Arc::new(ManualClock {
                base: Instant::now(),
                offset_nanos: AtomicUsize::new(0),
            })
        }
        fn advance(&self, by: Duration) {
            self.offset_nanos
                .fetch_add(by.as_nanos() as usize, Ordering::Relaxed);
        }
    }
    impl Clock for ManualClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_nanos(self.offset_nanos.load(Ordering::Relaxed) as u64)
        }
    }

    /// A whole-NAR claim for `key`, held by `holder`, carrying an EXPLICIT offer set
    /// (so a test can drive a holder that changes its offers between announces).
    fn claim_with(
        key: NarHashKey,
        holder: NodeId,
        blake3: Blake3Digest,
        transports: Vec<KnownTransport>,
    ) -> Claim {
        Claim {
            schema_version: CLAIM_SCHEMA_VERSION,
            key,
            payload: Some(KnownPayload::WholeNar { blake3 }),
            holders: vec![holder],
            transports,
            relay: None,
            signatures: vec![],
        }
    }

    #[tokio::test]
    async fn a_poisoning_announce_is_partitioned_off_not_merged_into_honest_holders() {
        // TASK-170. Honest holders of one NarHash AGREE on its blake3 (a pure function
        // of the same bytes); a liar announcing a WRONG blake3 forms its OWN partition
        // and must not be unioned under the honest content id. Here the poisoning
        // announce is FIRST - exactly the case the old merge broke on, because it took
        // the merged content id from the first holder that carried one.
        let honest = Blake3Digest::from_raw_nar(b"the content every honest holder agrees on");
        let poison = Blake3Digest::from_raw_nar(b"a WRONG blake3 that one liar announces");
        assert_ne!(honest, poison, "the two content ids must genuinely differ");

        let liar = NodeId::from_bytes([0x66; 32]);
        let h1 = NodeId::from_bytes([0xa1; 32]);
        let h2 = NodeId::from_bytes([0xa2; 32]);

        let discovery = InMemoryDiscovery::new();
        // FIRST: the poisoning announce (honest key, wrong blake3).
        discovery.announce(claim_held_by(key_x(), liar, poison));
        // Then two honest holders, agreeing on the real content id.
        discovery.announce(claim_held_by(key_x(), h1, honest));
        discovery.announce(claim_held_by(key_x(), h2, honest));

        let claim = discovery.resolve(&key_x()).await.expect("a hit");
        // The honest MAJORITY partition is surfaced, not the first (poison) content id.
        assert_eq!(
            claim.content_id(),
            Some(&honest),
            "the honest majority content id is surfaced; a first wrong-blake3 announce \
             is segregated, not merged in (a union-under-first merge yields the poison here)"
        );
        // The honest holders remain dialable for the correct content...
        assert_eq!(
            claim.holders,
            vec![h1, h2],
            "the honest holders resolve; the poison holder is not unioned into their partition"
        );
        assert_eq!(
            claim.transports,
            vec![
                KnownTransport::Iroh { node: h1 },
                KnownTransport::Iroh { node: h2 },
            ]
        );
        // ...and the liar's offer is NOT present (dialing it would be for wrong content).
        assert!(
            !claim.holders.contains(&liar),
            "the poisoning holder must not appear in the honest partition"
        );
        assert!(
            !claim
                .transports
                .contains(&KnownTransport::Iroh { node: liar }),
            "the poisoning holder's locator must not be dialed under the honest content id"
        );
    }

    #[tokio::test]
    async fn a_holder_reannouncing_an_updated_offer_set_retracts_its_stale_locator() {
        // TASK-171 AC#1: a holder is the single source of truth for its OWN offers, so
        // its latest announce REPLACES its prior offer set (per-holder LWW). Under the
        // old full-Claim dedup the two announces below (they differ) BOTH accumulated
        // and merge unioned them, so a holder could never retract a dead locator.
        let content = Blake3Digest::from_raw_nar(b"one holder, an evolving offer set");
        let a = NodeId::from_bytes([0xaa; 32]);
        let fresh = KnownTransport::Iroh { node: a };
        let stale = KnownTransport::BitTorrent {
            infohash: crate::transport::BitTorrentInfoHash::v2([0x5a; 32]),
        };

        let discovery = InMemoryDiscovery::new();
        // First announce carries a locator that will later go dead.
        discovery.announce(claim_with(
            key_x(),
            a,
            content,
            vec![fresh.clone(), stale.clone()],
        ));
        // The SAME holder re-announces a CORRECTED offer set, without the stale locator.
        discovery.announce(claim_with(key_x(), a, content, vec![fresh.clone()]));

        let claim = discovery.resolve(&key_x()).await.expect("a hit");
        assert_eq!(claim.holders, vec![a], "still exactly one holder");
        assert_eq!(
            claim.transports,
            vec![fresh.clone()],
            "the holder's UPDATED offer set is authoritative"
        );
        assert!(
            !claim.transports.contains(&stale),
            "the stale locator is RETRACTED by the holder's updated announce, not accumulated \
             (a full-Claim-dedup merge would still union it in and dial it forever)"
        );
    }

    #[tokio::test]
    async fn a_holder_past_the_ttl_is_evicted_not_dialed_forever() {
        // TASK-171 AC#2: the index is not grow-only. A holder that stops re-announcing
        // is evicted past ANNOUNCE_TTL, so its dead locator is not dialed on every
        // fetch. A manual clock proves it without sleeping a real hour.
        let content = Blake3Digest::from_raw_nar(b"a holder that later goes silent");
        let a = NodeId::from_bytes([0xaa; 32]);
        let b = NodeId::from_bytes([0xbb; 32]);
        let ttl = Duration::from_secs(100);
        let clock = ManualClock::new();
        let discovery = InMemoryDiscovery::with_ttl_and_clock(ttl, clock.clone());

        discovery.announce(claim_held_by(key_x(), a, content));
        assert_eq!(
            discovery.resolve(&key_x()).await.expect("hit").holders,
            vec![a],
            "control: A resolves while its announce is fresh"
        );

        // Time passes beyond the TTL; A never refreshed. A fresh holder B then announces.
        clock.advance(ttl + Duration::from_secs(1));
        discovery.announce(claim_held_by(key_x(), b, content));

        let claim = discovery.resolve(&key_x()).await.expect("hit");
        assert_eq!(
            claim.holders,
            vec![b],
            "the silent holder A is evicted past the TTL; only fresh B remains (no eviction \
             would leave A dialable forever)"
        );
        assert!(
            !claim.transports.contains(&KnownTransport::Iroh { node: a }),
            "A's dead locator is not offered for dialing"
        );

        // Once EVERY holder is past the TTL the key is a clean miss, not a stale dial.
        clock.advance(ttl + Duration::from_secs(1));
        assert!(
            discovery.resolve(&key_x()).await.is_none(),
            "a key whose every holder has aged out misses cleanly, not a stale hit"
        );
    }

    #[tokio::test]
    async fn a_refreshing_holder_stays_live_across_the_ttl() {
        // The other side of eviction: a holder that KEEPS re-announcing within the TTL
        // must never fall out. LWW resets its announce time on every refresh.
        let content = Blake3Digest::from_raw_nar(b"a holder that keeps refreshing");
        let a = NodeId::from_bytes([0xaa; 32]);
        let ttl = Duration::from_secs(100);
        let clock = ManualClock::new();
        let discovery = InMemoryDiscovery::with_ttl_and_clock(ttl, clock.clone());

        // Announce, then re-announce every 60s (< TTL) across 5 minutes of logical time.
        discovery.announce(claim_held_by(key_x(), a, content));
        for _ in 0..5 {
            clock.advance(Duration::from_secs(60));
            discovery.announce(claim_held_by(key_x(), a, content));
        }
        let claim = discovery.resolve(&key_x()).await.expect("hit");
        assert_eq!(
            claim.holders,
            vec![a],
            "a holder refreshing inside the TTL never ages out"
        );
    }

    // ---- task-91: the BATCHED probe ---------------------------------------

    /// The distinct raw NAR bytes for holding index `i`. The single source of the
    /// content<->key coupling: `keys()[i] == NarHashKey::from_raw_nar(&nar_for(i))`,
    /// and [`index_holding_many`] writes exactly these bytes to holding `i`'s file.
    /// task-56 verifies `sha256(--dump) == key` at first serve, so a test's key MUST
    /// be the true NarHash of the bytes the dumper yields - content is chosen first,
    /// the key follows.
    fn nar_for(i: usize) -> Vec<u8> {
        format!("distinct raw NAR content for discovery holding #{i}").into_bytes()
    }

    /// An index for `node` holding the given holding INDICES, each backed by its own
    /// real file whose bytes are [`nar_for`]`(i)` and registered under that content's
    /// TRUE NarHash (so every key is genuinely servable and has a DISTINCT blake3).
    fn index_holding_many(node: NodeId, held: &[usize]) -> (Arc<AvailabilityIndex>, TempDir) {
        let dir = TempDir::new("idx-many");
        let index = AvailabilityIndex::open(
            node,
            // Per-path bytes: the dumper reads the file it is pointed at, so each
            // registration derives its own digest.
            Arc::new(RegularFileNarDumper),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("open index");
        for &i in held {
            let content = nar_for(i);
            let key = NarHashKey::from_raw_nar(&content);
            let path = dir.path.join(format!("nar-{i}"));
            std::fs::write(&path, &content).expect("write");
            index.register(key, StorePath::new(path)).expect("register");
        }
        (Arc::new(index), dir)
    }

    /// `n` distinct canonical keys, each the TRUE NarHash of its holding's content
    /// ([`nar_for`]), so `keys()[i]` is what [`index_holding_many`]`(&[i])` registers.
    fn keys(n: usize) -> Vec<NarHashKey> {
        (0..n)
            .map(|i| NarHashKey::from_raw_nar(&nar_for(i)))
            .collect()
    }

    /// Wraps a real transport and COUNTS how many times each shape was asked. This
    /// is the AC#3 instrument at unit scale: the win claimed by this task is a
    /// reduction in ROUND TRIPS, so the test observes round trips directly rather
    /// than inferring them from wall-clock (which on an in-process transport would
    /// measure almost nothing).
    struct CountingQuery {
        inner: Arc<dyn PeerQuery>,
        singles: AtomicUsize,
        batches: AtomicUsize,
        keys_in_batches: AtomicUsize,
    }

    impl CountingQuery {
        fn wrap(inner: Arc<dyn PeerQuery>) -> Arc<Self> {
            Arc::new(CountingQuery {
                inner,
                singles: AtomicUsize::new(0),
                batches: AtomicUsize::new(0),
                keys_in_batches: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl PeerQuery for CountingQuery {
        async fn query(
            &self,
            node: &NodeId,
            query: &HoldQuery,
        ) -> Result<HoldResponse, PeerQueryError> {
            self.singles.fetch_add(1, Ordering::Relaxed);
            self.inner.query(node, query).await
        }

        async fn query_batch(
            &self,
            node: &NodeId,
            query: &BatchHoldQuery,
        ) -> Result<BatchHoldResponse, PeerQueryError> {
            self.batches.fetch_add(1, Ordering::Relaxed);
            self.keys_in_batches
                .fetch_add(query.keys.len(), Ordering::Relaxed);
            self.inner.query_batch(node, query).await
        }
    }

    #[tokio::test]
    async fn a_batched_resolve_agrees_with_the_serial_one_key_for_key() {
        // The EQUIVALENCE oracle: batching is only allowed to change the number of
        // round trips, never the answers.
        //
        // THREE peers, each holding a different slice, plus keys nobody holds -
        // deliberately, because a single-peer version of this test is vacuous
        // against the failure that matters most here. A resolver that stopped
        // after the first peer would still agree with itself on one peer; it is
        // only a spread holding set that makes "batched found what serial found"
        // a real claim. (Proven: mutating the peer loop to `&self.peers[..1]`
        // left the one-peer version GREEN.)
        let all = keys(9);
        let nodes: Vec<NodeId> = (1..=3u8).map(|i| NodeId::from_bytes([i; 32])).collect();
        let mut rendezvous = InProcessPeerQuery::new();
        let mut dirs = Vec::new();
        // Peer 0 holds keys 0,3; peer 1 holds 1,4; peer 2 holds 2,5. Keys 6..9
        // are held by nobody, so they cost every peer a probe in both arms.
        for (p, node) in nodes.iter().enumerate() {
            let held = [p, p + 3];
            let (index, dir) = index_holding_many(*node, &held);
            rendezvous.add_index(*node, index);
            dirs.push(dir);
        }
        let discovery = DirectDiscovery::new(nodes.clone(), Arc::new(rendezvous));

        let mut serial = Vec::new();
        for key in &all {
            serial.push(discovery.resolve(key).await);
        }
        let batched = discovery.resolve_many(&all, &budget()).await;

        // The batched TYPED answer must AGREE with the one-at-a-time answer, position for
        // position: a Found holds exactly the serial claim, and a key no peer holds is an
        // authoritative Miss (every one of the 3 peers answered Absent, in full) - NOT the
        // old indistinguishable None (TASK-232).
        assert_eq!(batched.len(), serial.len());
        for (i, (typed, opt)) in batched.iter().zip(serial.iter()).enumerate() {
            assert_eq!(
                typed.found(),
                opt.as_ref(),
                "position {i} must agree with the serial one-at-a-time claim"
            );
        }
        // ...and it is a real mixture across peers, so the equality is not vacuous.
        assert_eq!(batched.iter().filter(|c| c.is_found()).count(), 6);
        assert!(
            batched[6..].iter().all(ClaimResolution::is_miss),
            "keys no peer holds are an authoritative Miss (every peer answered Absent), \
             never a fault or a partial"
        );
        for (i, res) in batched.iter().enumerate() {
            let Some(claim) = res.found() else { continue };
            assert_eq!(claim.key, all[i], "position {i} must answer about all[{i}]");
            assert_eq!(
                claim.holders,
                vec![nodes[i % 3]],
                "position {i} must be attributed to the peer that actually holds it"
            );
        }
    }

    #[tokio::test]
    async fn batching_collapses_n_round_trips_into_one() {
        // AC#1/AC#3 at unit scale: same peer, same keys, same answers - the ONLY
        // difference is how many times the peer was asked.
        let all = keys(20);
        let (index, _dir) = index_holding_many(node_b(), &(0..20).collect::<Vec<_>>());
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);
        let counting = CountingQuery::wrap(Arc::new(rendezvous));
        let discovery = DirectDiscovery::new(vec![node_b()], counting.clone());

        for key in &all {
            discovery.resolve(key).await;
        }
        let serial_probes = counting.singles.load(Ordering::Relaxed);

        let batched = discovery.resolve_many(&all, &budget()).await;
        let batch_probes = counting.batches.load(Ordering::Relaxed);

        assert_eq!(serial_probes, 20, "one-at-a-time costs one probe per key");
        assert_eq!(batch_probes, 1, "batched costs ONE probe for the whole set");
        assert_eq!(
            counting.singles.load(Ordering::Relaxed),
            serial_probes,
            "the batched arm must not have fallen back to single-key probes"
        );
        assert!(
            batched.iter().all(ClaimResolution::is_found),
            "and it still resolved every key to a Found holder"
        );
    }

    #[tokio::test]
    async fn a_closure_larger_than_the_cap_is_chunked_not_rejected() {
        // A 1000-path closure is 4 probes per peer, not 1000 and not an error.
        let all = keys(MAX_BATCH_HOLD_KEYS * 3 + 7);
        let (index, _dir) = index_holding_many(node_b(), &[0, 1, 2, 3, 4]);
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);
        let counting = CountingQuery::wrap(Arc::new(rendezvous));
        let discovery = DirectDiscovery::new(vec![node_b()], counting.clone());

        let resolved = discovery.resolve_many(&all, &budget()).await;
        assert_eq!(resolved.len(), all.len());
        assert_eq!(
            resolved.iter().filter(|c| c.is_found()).count(),
            5,
            "the 5 held keys resolve to Found"
        );
        assert!(
            resolved
                .iter()
                .filter(|c| !c.is_found())
                .all(ClaimResolution::is_miss),
            "the rest are an authoritative Miss (the single peer answered Absent for each)"
        );
        assert_eq!(
            counting.batches.load(Ordering::Relaxed),
            4,
            "ceil({} / {MAX_BATCH_HOLD_KEYS}) chunks",
            all.len()
        );
        assert_eq!(
            counting.keys_in_batches.load(Ordering::Relaxed),
            all.len(),
            "every key is asked exactly once - chunking must not drop or repeat any"
        );
    }

    #[tokio::test]
    async fn repeated_keys_in_a_closure_are_asked_once_and_answered_everywhere() {
        // A caller's closure list may repeat a hash; the WIRE forbids duplicates.
        // The resolver de-duplicates before probing and fans the answer back out.
        let all = keys(3);
        let with_repeats = vec![all[0], all[1], all[0], all[2], all[0]];
        let (index, _dir) = index_holding_many(node_b(), &[0]);
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);
        let counting = CountingQuery::wrap(Arc::new(rendezvous));
        let discovery = DirectDiscovery::new(vec![node_b()], counting.clone());

        let resolved = discovery.resolve_many(&with_repeats, &budget()).await;
        assert_eq!(
            counting.keys_in_batches.load(Ordering::Relaxed),
            3,
            "5 positions, 3 distinct keys - the peer is asked 3 things"
        );
        for (i, res) in resolved.iter().enumerate() {
            match with_repeats[i] == all[0] {
                true => assert!(
                    res.is_found(),
                    "every position of the held key resolves to Found"
                ),
                false => assert!(
                    res.is_miss(),
                    "an unheld key the single peer answered Absent for is an authoritative Miss"
                ),
            }
        }
    }

    #[tokio::test]
    async fn a_batch_never_reveals_a_holding_the_asker_did_not_name() {
        // AC#4, at the discovery seam. B holds Y and Z; A asks about V, W, X.
        // A learns three noes and NOTHING about Y or Z - not their existence, not
        // their count. There is no method to ask, and the answer has no room to
        // volunteer: it is positional over V, W, X.
        let all = keys(5);
        let (asked, held) = (&all[..3], &all[3..]);
        let (index, _dir) = index_holding_many(node_b(), &[3, 4]);
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);

        let query = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: asked.to_vec(),
        };
        let response = rendezvous
            .query_batch(&node_b(), &query)
            .await
            .expect("probe");

        assert_eq!(response.answers.len(), asked.len());
        assert!(
            response
                .answers
                .iter()
                .all(|a| matches!(a, BatchHoldAnswer::Absent {})),
            "B holds none of the asked keys"
        );
        assert!(
            response.offers.is_empty(),
            "an all-absent batch says nothing at all about the responder"
        );
        // The serialised answer contains no NarHash whatsoever - so even a peer
        // that WANTED to leak its holdings has nowhere to put them.
        let on_wire =
            String::from_utf8(crate::claim::encode_batch_hold_response(&response).expect("encode"))
                .expect("utf8");
        assert!(
            !on_wire.contains("sha256:"),
            "no key on the wire: {on_wire}"
        );
        for key in held {
            assert!(
                !on_wire.contains(&key.to_string()),
                "a held-but-unasked key must not appear: {on_wire}"
            );
        }

        // And the control: asking about what B DOES hold works, so the negative
        // above is not "the index is empty".
        let control = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: held.to_vec(),
        };
        let response = rendezvous
            .query_batch(&node_b(), &control)
            .await
            .expect("probe");
        assert!(
            response
                .answers
                .iter()
                .all(|a| matches!(a, BatchHoldAnswer::Have { .. })),
            "the same index answers Have for keys the asker named"
        );
    }

    /// A peer that answers a DIFFERENT number of keys than it was asked - the
    /// failure that would silently bind every later key to the wrong hash.
    struct MisalignedPeer;
    #[async_trait]
    impl PeerQuery for MisalignedPeer {
        async fn query(
            &self,
            _node: &NodeId,
            _query: &HoldQuery,
        ) -> Result<HoldResponse, PeerQueryError> {
            unreachable!("this test only drives the batch path")
        }
        async fn query_batch(
            &self,
            _node: &NodeId,
            query: &BatchHoldQuery,
        ) -> Result<BatchHoldResponse, PeerQueryError> {
            // One answer too few, with a Have first: a naive zip would bind key[0]
            // to this blake3 and then shift everything.
            Ok(BatchHoldResponse {
                schema_version: QUERY_SCHEMA_VERSION,
                offers: vec![KnownTransport::Iroh { node: node_b() }],
                answers: (0..query.keys.len().saturating_sub(1))
                    .map(|_| BatchHoldAnswer::Have {
                        blake3: Blake3Digest::from_bytes([0x99; 32]),
                        offer_indices: vec![0],
                    })
                    .collect(),
            })
        }
    }

    #[tokio::test]
    async fn a_misaligned_batch_answer_is_discarded_whole() {
        // Positional alignment is not recoverable from a short answer, so the resolver must
        // throw the WHOLE answer away rather than use its prefix. TASK-232: a discarded
        // (unusable) answer is could-not-consult -> Unavailable, NEVER a fabricated Miss (the
        // key's true holding is unknown; the sole peer's reply was protocol-broken).
        let all = keys(4);
        let discovery = DirectDiscovery::new(vec![node_b()], Arc::new(MisalignedPeer));
        let resolved = discovery.resolve_many(&all, &budget()).await;
        assert_eq!(resolved.len(), 4);
        assert!(
            resolved.iter().all(ClaimResolution::is_unavailable),
            "a mis-aligned answer must resolve to Unavailable (could-not-consult), never a \
             shifted prefix and never a false Miss"
        );
    }

    #[tokio::test]
    async fn the_default_batch_shim_answers_correctly_at_n_round_trips() {
        // A transport that has not learned the batch message still answers - via
        // the trait's default shim - at N round trips. This is what makes the
        // seam addition backwards-compatible, and it is the honest baseline the
        // measurement arm compares the real batch against.
        // The counter sits INSIDE the shim (the shim calls `query` on ITSELF, so a
        // counter wrapped around the outside would observe nothing - which is
        // exactly what the first cut of this test did, and it "passed" by counting
        // zero of everything).
        struct SingleOnly(Arc<CountingQuery>);
        #[async_trait]
        impl PeerQuery for SingleOnly {
            async fn query(
                &self,
                node: &NodeId,
                query: &HoldQuery,
            ) -> Result<HoldResponse, PeerQueryError> {
                self.0.query(node, query).await
            }
            // NOTE: no query_batch override - the default shim is under test.
        }

        let all = keys(6);
        let (index, _dir) = index_holding_many(node_b(), &[0, 1]);
        let mut inner = InProcessPeerQuery::new();
        inner.add_index(node_b(), index);
        let counting = CountingQuery::wrap(Arc::new(inner));
        let discovery =
            DirectDiscovery::new(vec![node_b()], Arc::new(SingleOnly(counting.clone())));

        let resolved = discovery.resolve_many(&all, &budget()).await;
        assert_eq!(
            counting.singles.load(Ordering::Relaxed),
            6,
            "the shim really does cost one round trip per key"
        );
        assert_eq!(resolved.iter().filter(|c| c.is_found()).count(), 2);
        for (i, res) in resolved.iter().enumerate().take(2) {
            let claim = res.found().expect("held");
            assert_eq!(claim.key, all[i]);
            assert_eq!(
                claim.transports,
                vec![KnownTransport::Iroh { node: node_b() }],
                "the shim hoists the peer's offers onto the batch response"
            );
        }
    }

    #[tokio::test]
    async fn the_in_process_batch_is_encoded_once_not_looped_per_key() {
        // WHY THIS TEST EXISTS. Round trips are counted at the `PeerQuery` seam
        // (that is what the measurement instrument observes), and a transport that
        // implemented `query_batch` by internally looping the single-key form
        // would be counted as ONE exchange while costing N on a real network. So
        // the count is only meaningful if the transport under measurement NATIVELY
        // batches - and "it does, look at the source" is not an oracle.
        //
        // The discriminator: the native path ENCODES a BatchHoldQuery, so it
        // enforces the wire bounds; the shim never encodes one, so it does not.
        // Handing both an over-cap batch therefore tells them apart from outside.
        let over_cap = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: keys(MAX_BATCH_HOLD_KEYS + 1),
        };
        let (index, _dir) = index_holding_many(node_b(), &[0]);
        let mut inner = InProcessPeerQuery::new();
        inner.add_index(node_b(), index);

        let native = inner.query_batch(&node_b(), &over_cap).await;
        assert!(
            matches!(native, Err(PeerQueryError::Codec(_))),
            "the in-process transport must really encode the batch (and so refuse \
             an over-cap one); if this passes the batch, it is looping single \
             probes and every round-trip count taken over it is wrong"
        );

        // The SHIM refuses it too, and refuses it BEFORE issuing any probe. An
        // earlier revision let the shim through on the reasoning that it sends N
        // separate legal single-key messages - true, but its RETURN VALUE is a
        // wire message, and an over-cap BatchHoldResponse is one no decoder on the
        // network would accept. The cap is a property of the message, not a
        // courtesy the caller may opt out of by picking a different transport.
        struct SingleOnly(InProcessPeerQuery);
        #[async_trait]
        impl PeerQuery for SingleOnly {
            async fn query(
                &self,
                node: &NodeId,
                query: &HoldQuery,
            ) -> Result<HoldResponse, PeerQueryError> {
                self.0.query(node, query).await
            }
        }
        let (index, _dir) = index_holding_many(node_b(), &[0]);
        let mut inner = InProcessPeerQuery::new();
        inner.add_index(node_b(), index);
        let shim = SingleOnly(inner).query_batch(&node_b(), &over_cap).await;
        assert!(
            matches!(shim, Err(PeerQueryError::Codec(_))),
            "the shim must refuse an over-cap batch as well: got {shim:?}"
        );
    }

    #[test]
    fn the_responder_enforces_the_key_cap_itself() {
        // The RESPONDER's own refusal, reached without the wire in front of it.
        // The wire path already rejects an over-cap query in `decode_batch_hold_
        // query`, so every test that goes through a transport proves the DECODER's
        // check and says nothing about the index's. That check used to be a
        // `debug_assert` - absent in a release build - which made "at most 256
        // `nix-store --dump`s per message" a caller precondition rather than a
        // property of the responder.
        let all = keys(MAX_BATCH_HOLD_KEYS + 1);
        let (index, _dir) = index_holding_many(node_b(), &[0]);
        let over_cap = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: all,
        };
        assert!(
            matches!(
                index.answer_batch(&over_cap),
                Err(crate::claim::ClaimCodecError::BatchTooLarge { .. })
            ),
            "answer_batch must refuse an over-cap batch, not probe 257 keys"
        );
        // The control: one key under the cap is answered normally, so the refusal
        // above is the cap speaking and not a blanket failure.
        let legal = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: over_cap.keys[..1].to_vec(),
        };
        assert!(index.answer_batch(&legal).is_ok());
    }

    #[tokio::test]
    async fn a_hanging_peer_yields_a_bounded_batched_unavailable() {
        // The AC#2 bounded-outcome guarantee must survive batching: a wedged peer cannot
        // stall a whole closure resolution. TASK-232: a wedged (dead) peer is could-not-
        // consult -> Unavailable, NEVER a fabricated Miss - the key's true holding is
        // unknown because the only peer never answered.
        let probe_bound = Duration::from_millis(150);
        let discovery =
            DirectDiscovery::with_timeout(vec![node_b()], Arc::new(HangingQuery), probe_bound);
        let all = keys(4);
        let started = std::time::Instant::now();
        let resolved = discovery.resolve_many(&all, &budget()).await;
        let elapsed = started.elapsed();
        assert!(
            resolved.iter().all(ClaimResolution::is_unavailable),
            "a wedged peer yields Unavailable (could-not-consult), never a false Miss"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "a batched resolution against a wedged peer must be bounded too, took {elapsed:?}"
        );
    }

    // ---- task-106 AC#1 bite: the WHOLE call is bounded, not just per probe ----

    #[tokio::test]
    async fn resolve_many_is_bounded_in_total_not_per_probe() {
        // Many SILENT peers. Per probe each times out at `probe_bound`; the OLD code
        // bounded only ONE probe, so the sum was N x probe_bound (here 50 x 100 ms =
        // 5 s, and at production scale 8 x 4 x 5 s = ~160 s / ~31 min). The total
        // deadline bounds the SUM: the call returns at ~`total` regardless of N.
        //
        // MUTATION PROOF (task-106 AC#1, TASK-232): delete the `deadline` / `remaining` /
        // `break 'peers` budget check in `resolve_many` (now sourced from `budget.deadline`)
        // and this reverts to ~N x probe_bound (~5 s here), blowing the `< 1500 ms`
        // assertion. The gap between the 300 ms budget and the 5 s naive sum is the bite.
        // The total deadline is now the CALLER's DiscoveryBudget - a SINGLE bound, no
        // internal RESOLVE_MANY_TIMEOUT racing it.
        let probe_bound = Duration::from_millis(100);
        let total = Duration::from_millis(300);
        let silent: Vec<NodeId> = (1..=50u8).map(|i| NodeId::from_bytes([i; 32])).collect();
        let discovery = DirectDiscovery::with_timeout(silent, Arc::new(HangingQuery), probe_bound);

        let all = keys(4);
        let started = std::time::Instant::now();
        let resolved = discovery
            .resolve_many(&all, &DiscoveryBudget::new(total, 16))
            .await;
        let elapsed = started.elapsed();

        assert!(
            resolved.iter().all(ClaimResolution::is_unavailable),
            "every silent peer is could-not-consult -> Unavailable (never a false Miss); \
             the closure still folds to upstream because nothing is Found"
        );
        assert!(
            elapsed < Duration::from_millis(1500),
            "resolve_many must be bounded by its TOTAL caller deadline (~{total:?}), not by \
             50 x {probe_bound:?} = ~5 s; took {elapsed:?}"
        );
    }

    // ---- task-106 AC#2 bite: a per-peer fault abandons that peer's chunks ----

    /// A peer whose batch probe always FAULTS (a per-peer error, true of every key
    /// alike), counting how many times it is probed. The resolver must abandon it
    /// after the FIRST faulting chunk, not re-probe it chunk by chunk.
    struct CountingFaultPeer {
        batch_calls: AtomicUsize,
    }
    #[async_trait]
    impl PeerQuery for CountingFaultPeer {
        async fn query(
            &self,
            _node: &NodeId,
            _query: &HoldQuery,
        ) -> Result<HoldResponse, PeerQueryError> {
            unreachable!("this test only drives the batch path")
        }
        async fn query_batch(
            &self,
            _node: &NodeId,
            _query: &BatchHoldQuery,
        ) -> Result<BatchHoldResponse, PeerQueryError> {
            self.batch_calls.fetch_add(1, Ordering::Relaxed);
            Err(PeerQueryError::Answer("simulated per-peer fault".into()))
        }
    }

    #[tokio::test]
    async fn a_faulting_peer_abandons_its_remaining_chunks() {
        // A closure that SPLITS into two chunks (MAX_BATCH_HOLD_KEYS + 1 keys). The
        // first chunk faults. Because a per-peer fault is true of every key alike
        // (the rule `query_batch` documents), the peer's SECOND chunk must NOT be
        // probed - retrying an unreachable peer is pure waste.
        //
        // MUTATION PROOF (task-106 AC#2): change the fault arm's `continue 'peers`
        // back to `continue` (skip only the current chunk) and this reads 2 probes.
        let all = keys(MAX_BATCH_HOLD_KEYS + 1);
        let peer = Arc::new(CountingFaultPeer {
            batch_calls: AtomicUsize::new(0),
        });
        let discovery = DirectDiscovery::new(vec![node_b()], peer.clone());

        let resolved = discovery.resolve_many(&all, &budget()).await;
        assert!(
            resolved.iter().all(ClaimResolution::is_unavailable),
            "a peer that faults every chunk leaves every key Unavailable (could-not-consult), \
             never a false Miss"
        );
        assert_eq!(
            peer.batch_calls.load(Ordering::Relaxed),
            1,
            "the faulting peer must be abandoned after its FIRST chunk (2-chunk \
             closure), not re-probed for the second"
        );
    }

    // ---- TASK-232 AC#3 bite: a dead mechanism yields Unavailable, not a false Miss ----

    /// A transport that FAULTS (a per-peer error) for one designated node and answers
    /// honestly from an in-process index for every other node. Lets one `resolve_many` call
    /// mix a could-not-consult peer with an honest Absent peer.
    struct MixedPeer {
        honest: InProcessPeerQuery,
        faulty_node: NodeId,
    }
    #[async_trait]
    impl PeerQuery for MixedPeer {
        async fn query(
            &self,
            _node: &NodeId,
            _query: &HoldQuery,
        ) -> Result<HoldResponse, PeerQueryError> {
            unreachable!("this test only drives the batch path")
        }
        async fn query_batch(
            &self,
            node: &NodeId,
            query: &BatchHoldQuery,
        ) -> Result<BatchHoldResponse, PeerQueryError> {
            if *node == self.faulty_node {
                return Err(PeerQueryError::Answer("simulated dead mechanism".into()));
            }
            self.honest.query_batch(node, query).await
        }
    }

    #[tokio::test]
    async fn a_dead_mechanism_yields_unavailable_not_a_false_miss() {
        // AC#3 (TASK-232), the load-bearing distinction on the shipped resolve path: a key
        // NO peer holds is an authoritative Miss ONLY when every consulted peer answered
        // Absent in full; if a peer that could have held it FAULTED, the key is Unavailable
        // (could-not-consult), NEVER a false Miss - a dead mechanism can never read as
        // nobody-has-it.
        //
        // MUTATION PROOF: drop the `else if let Some(why) = self.fault` arm in
        // ClaimAcc::finalize (so a faulted+absent key falls through to the `saw_absent` Miss
        // arm). The Unavailable assertion below then reddens while the Miss CONTROL stays
        // green - pinning the fault-blocks-Miss rule exactly, not merely "something differs".
        let unheld = key_x();

        // CONTROL: with only an HONEST peer that answers Absent, an unheld key is an
        // authoritative Miss - so the bite below is a real state change, not a vacuous
        // "nothing is ever a Miss".
        let (honest_idx, held_key, _dir) =
            index_holding(node_b(), b"the honest peer holds something else".to_vec());
        assert_ne!(
            unheld, held_key,
            "the probed key must be one node_b does NOT hold"
        );
        let mut honest_only = InProcessPeerQuery::new();
        honest_only.add_index(node_b(), honest_idx);
        let miss = DirectDiscovery::new(vec![node_b()], Arc::new(honest_only));
        let control = miss
            .resolve_many(std::slice::from_ref(&unheld), &budget())
            .await;
        assert!(
            control[0].is_miss(),
            "every consulted peer answered Absent in full -> authoritative Miss, got {:?}",
            control[0]
        );

        // THE BITE: put a FAULTING peer AHEAD of the honest one. The faulting peer might
        // have held `unheld`; we could not consult it, so even though the honest peer says
        // Absent the outcome must be Unavailable, not Miss.
        let (honest_idx2, _k, _dir2) =
            index_holding(node_b(), b"the honest peer holds something else".to_vec());
        let mut honest2 = InProcessPeerQuery::new();
        honest2.add_index(node_b(), honest_idx2);
        let faulty_node = NodeId::from_bytes([0xf0; 32]);
        let mixed = MixedPeer {
            honest: honest2,
            faulty_node,
        };
        let discovery = DirectDiscovery::new(vec![faulty_node, node_b()], Arc::new(mixed));
        let resolved = discovery
            .resolve_many(std::slice::from_ref(&unheld), &budget())
            .await;
        assert!(
            resolved[0].is_unavailable(),
            "a faulted (dead) mechanism must yield Unavailable, not a false Miss; got {:?}",
            resolved[0]
        );
        assert!(
            !resolved[0].is_miss(),
            "a dead mechanism can NEVER read as an authoritative Miss (the honest peer's \
             Absent does not license absence while a peer that could hold it was unreachable)"
        );
    }

    // ---- task-107 M3 bite: the shim aggregates per-key faults to ONE line ----

    /// A transport whose SINGLE-key `query` faults every key with a per-KEY
    /// [`PeerQueryError::Answer`]. It uses the DEFAULT `query_batch` shim, so the
    /// shim loops it once per key and each loop records an answer fault - the exact
    /// arm task-107 M3 aggregates.
    struct AnswerFaultEveryKey;
    #[async_trait]
    impl PeerQuery for AnswerFaultEveryKey {
        async fn query(
            &self,
            _node: &NodeId,
            _query: &HoldQuery,
        ) -> Result<HoldResponse, PeerQueryError> {
            Err(PeerQueryError::Answer(
                "simulated per-key answer fault".into(),
            ))
        }
        // No `query_batch` override: the compatibility shim under test drives this.
    }

    #[tokio::test]
    async fn shim_batch_fault_logging_is_aggregated_not_one_line_per_key() {
        // The compatibility shim, asked a full-cap batch against a peer that faults
        // EVERY key (a per-KEY answer fault, which degrades that key to Absent rather
        // than abandoning the whole peer), must cost ONE aggregated log line for the
        // whole message - not one per key, which a peer could provoke up to
        // MAX_BATCH_HOLD_KEYS times with a single 91-byte query.
        //
        // MUTATION PROOF: revert `run_query_batch_shim` to push (or eprintln) a note
        // per faulting key and `notes` grows to MAX_BATCH_HOLD_KEYS lines, failing the
        // `== 1` assert below.
        let peer = AnswerFaultEveryKey;
        let query = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: keys(MAX_BATCH_HOLD_KEYS),
        };
        let (response, notes) = run_query_batch_shim(&peer, &node_b(), &query)
            .await
            .expect("an all-Absent shim response is well-formed");

        // Behaviour preserved: every faulting key degrades to a positional Absent.
        assert_eq!(
            response.answers.len(),
            MAX_BATCH_HOLD_KEYS,
            "positional: exactly one answer per asked key"
        );
        assert!(
            response
                .answers
                .iter()
                .all(|a| matches!(a, BatchHoldAnswer::Absent {})),
            "a per-key answer fault degrades that key to Absent, never a false Have"
        );

        // The BITE: the whole batch costs ONE aggregated fault line, not ~N.
        assert_eq!(
            notes.len(),
            1,
            "the shim must aggregate {MAX_BATCH_HOLD_KEYS} per-key faults into ONE \
             line; got {} lines: {notes:?}",
            notes.len()
        );
        assert!(
            notes[0].contains(&format!("{MAX_BATCH_HOLD_KEYS} key(s) failed")),
            "the aggregate line must report the fault COUNT: {}",
            notes[0]
        );
    }

    // ---- AC#2 bite: a hanging peer yields a FAST, bounded miss -------------

    /// A query transport that never answers (models a wedged/silent peer). The
    /// resolver must NOT hang on it.
    struct HangingQuery;
    #[async_trait]
    impl PeerQuery for HangingQuery {
        async fn query(
            &self,
            _node: &NodeId,
            _query: &HoldQuery,
        ) -> Result<HoldResponse, PeerQueryError> {
            // Far longer than the test's probe bound; the timeout must cancel it.
            tokio::time::sleep(Duration::from_secs(60)).await;
            unreachable!("the probe timeout must fire before this resolves")
        }
    }

    #[tokio::test]
    async fn a_hanging_peer_yields_a_bounded_miss_not_a_hang() {
        let probe_bound = Duration::from_millis(150);
        let discovery =
            DirectDiscovery::with_timeout(vec![node_b()], Arc::new(HangingQuery), probe_bound);

        let started = std::time::Instant::now();
        let result = discovery.resolve(&key_x()).await;
        let elapsed = started.elapsed();

        assert!(result.is_none(), "a hanging peer must resolve to a miss");
        // Bounded: comfortably under the 60s hang, on the order of the probe bound.
        assert!(
            elapsed < Duration::from_secs(5),
            "the miss must be bounded (~probe timeout), took {elapsed:?}"
        );
    }

    // ---- AC#2: the bounded miss composes into upstream fallback (S2) -------

    /// A trivial NAR source that always serves `body` (stands in for the upstream
    /// CDN secondary).
    struct StubUpstream {
        body: Vec<u8>,
    }
    #[async_trait]
    impl NarSource for StubUpstream {
        async fn resolve(
            &self,
            _key: &NarKey,
            _expected_size: Option<u64>,
        ) -> Result<UpstreamResponse, SourceError> {
            let mut headers = HeaderMap::new();
            headers.insert(http::header::CONTENT_LENGTH, self.body.len().into());
            Ok(UpstreamResponse {
                status: 200,
                headers,
                body: Full::new(Bytes::from(self.body.clone()))
                    .map_err(|never| match never {})
                    .boxed(),
            })
        }
    }

    /// A p2p source that always misses (models discovery finding no holder).
    struct AlwaysMiss;
    #[async_trait]
    impl NarSource for AlwaysMiss {
        async fn resolve(
            &self,
            _key: &NarKey,
            _expected_size: Option<u64>,
        ) -> Result<UpstreamResponse, SourceError> {
            Err(SourceError::Unreachable("discovery miss".into()))
        }
    }

    async fn collect(resp: UpstreamResponse) -> Vec<u8> {
        resp.body.collect().await.expect("body").to_bytes().to_vec()
    }

    #[tokio::test]
    async fn a_p2p_miss_falls_back_to_upstream() {
        let upstream_bytes = b"served by the upstream CDN after the p2p miss".to_vec();
        let fallback = FallbackNarSource::new(
            Arc::new(AlwaysMiss),
            Arc::new(StubUpstream {
                body: upstream_bytes.clone(),
            }),
        );
        let key = NarKey::SignedNarHash {
            hash: NarHash::new(key_x().to_string()),
            upstream_hint: NarPathToken::new("nar/1abc.nar.xz"),
            transport: crate::source::NarinfoTransport::default(),
        };
        let resp = fallback
            .resolve(&key, None)
            .await
            .expect("the miss falls back and the upstream serves");
        assert_eq!(collect(resp).await, upstream_bytes);
    }

    #[tokio::test]
    async fn a_size_abort_does_not_fall_back() {
        // TooLarge is a deliberate risk-6 abort, not a "try elsewhere" - it must
        // propagate, never be papered over by an upstream fetch.
        struct Abort;
        #[async_trait]
        impl NarSource for Abort {
            async fn resolve(
                &self,
                _key: &NarKey,
                _expected_size: Option<u64>,
            ) -> Result<UpstreamResponse, SourceError> {
                Err(SourceError::TooLarge {
                    limit: 10,
                    declared: 999,
                })
            }
        }
        let fallback = FallbackNarSource::new(
            Arc::new(Abort),
            Arc::new(StubUpstream {
                body: b"must NOT be served".to_vec(),
            }),
        );
        let key = NarKey::UpstreamPath(NarPathToken::new("nar/1abc.nar.xz"));
        match fallback.resolve(&key, None).await {
            Err(SourceError::TooLarge { limit, declared }) => {
                assert_eq!((limit, declared), (10, 999));
            }
            Ok(_) => panic!("a size abort must NOT be papered over by an upstream fetch"),
            Err(other) => panic!("a size abort must propagate unchanged, got {other}"),
        }
    }

    // ---- the defect that sent task-91 back: locators must bind to their key ----

    /// A peer that answers every key `Have`, giving each key its OWN
    /// content-specific BitTorrent locator plus one shared peer-scoped iroh
    /// locator. Only the SINGLE-key method is implemented, so a `resolve_many`
    /// over it exercises the default batch SHIM - which is where the misbinding
    /// lived.
    struct PerContentLocatorPeer;

    /// A cheap, collision-free-enough digest of a key's canonical string, so each
    /// stand-in locator below is DISTINCT per key and the expected binding is
    /// computable in the assertions (FNV-1a; this is test scaffolding, not a
    /// security primitive).
    fn key_fingerprint(key: &NarHashKey) -> [u8; 32] {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in key.to_string().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
        let mut raw = [0u8; 32];
        for chunk in 0..4 {
            raw[chunk * 8..chunk * 8 + 8]
                .copy_from_slice(&hash.wrapping_add(chunk as u64).to_be_bytes());
        }
        raw
    }

    /// The infohash this stand-in peer assigns to `key`: a pure function of the
    /// key, so the expected binding is computable in the assertions.
    fn infohash_for(key: &NarHashKey) -> crate::transport::BitTorrentInfoHash {
        crate::transport::BitTorrentInfoHash::v2(key_fingerprint(key))
    }

    #[async_trait]
    impl PeerQuery for PerContentLocatorPeer {
        async fn query(
            &self,
            _node: &NodeId,
            query: &HoldQuery,
        ) -> Result<HoldResponse, PeerQueryError> {
            Ok(HoldResponse {
                schema_version: QUERY_SCHEMA_VERSION,
                answer: HoldAnswer::Have {
                    blake3: Blake3Digest::from_bytes(key_fingerprint(&query.key)),
                    offers: vec![
                        KnownTransport::Iroh { node: node_b() },
                        KnownTransport::BitTorrent {
                            infohash: infohash_for(&query.key),
                        },
                    ],
                },
            })
        }
    }

    #[tokio::test]
    async fn each_key_keeps_its_own_content_specific_locator() {
        // THE regression test whose absence let the defect ship. A BitTorrent
        // infohash addresses one piece of CONTENT, not a peer, so a response-wide
        // offer list cannot express two keys with different infohashes. The old
        // shim kept the FIRST Have's offers and the resolver cloned them onto every
        // Have, so key 2's claim received key 1's infohash: a wrong dial, and a
        // locator that binds to a key the asker never asked about.
        let all = keys(3);
        let discovery = DirectDiscovery::new(vec![node_b()], Arc::new(PerContentLocatorPeer));
        let resolved = discovery.resolve_many(&all, &budget()).await;

        assert_eq!(resolved.len(), 3);
        for (i, key) in all.iter().enumerate() {
            let claim = resolved[i]
                .found()
                .unwrap_or_else(|| panic!("key {i} must resolve"));
            let mine = KnownTransport::BitTorrent {
                infohash: infohash_for(key),
            };
            assert!(
                claim.transports.contains(&mine),
                "claim {i} must carry ITS OWN infohash; got {:?}",
                claim.transports
            );
            // ...and NOT any other key's. This is the half that actually failed.
            for (j, other) in all.iter().enumerate() {
                if i == j {
                    continue;
                }
                let theirs = KnownTransport::BitTorrent {
                    infohash: infohash_for(other),
                };
                assert!(
                    !claim.transports.contains(&theirs),
                    "claim {i} received key {j}'s infohash - locators are not bound \
                     to their key: {:?}",
                    claim.transports
                );
            }
            // The genuinely peer-scoped locator is shared, which is the whole
            // reason the dictionary exists rather than per-answer inline offers.
            assert!(
                claim
                    .transports
                    .contains(&KnownTransport::Iroh { node: node_b() }),
                "the peer-scoped iroh locator must reach every claim"
            );
        }
    }

    #[tokio::test]
    async fn the_shim_interns_a_shared_locator_instead_of_repeating_it() {
        // The reason the offers are INDICES and not inline copies: one iroh
        // locator answering N keys must cost one copy on the wire, or a full
        // 256-key answer with two transports per key does not fit the 64 KiB gate
        // that MAX_BATCH_HOLD_KEYS was chosen against.
        let all = keys(4);
        let query = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: all.clone(),
        };
        let response = PerContentLocatorPeer
            .query_batch(&node_b(), &query)
            .await
            .expect("probe");
        assert_eq!(
            response
                .offers
                .iter()
                .filter(|o| matches!(o, KnownTransport::Iroh { .. }))
                .count(),
            1,
            "the shared iroh locator must be interned once: {:?}",
            response.offers
        );
        assert_eq!(
            response.offers.len(),
            1 + all.len(),
            "one shared iroh locator plus one infohash per key"
        );
        // And it survives a real encode/decode with its bindings intact.
        let bytes = encode_batch_hold_response(&response).expect("encode");
        assert_eq!(
            decode_batch_hold_response(&bytes, all.len()).expect("decode"),
            response
        );
    }
}
