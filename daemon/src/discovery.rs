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
//! the positional batch form, which forbid enumeration in their SHAPE: a batch
//! answer carries no keys of its own and is meaningless detached from the asker's
//! own query. Probing X (alone or in a batch) reveals nothing about a key Y the
//! peer also holds (proven by test, for both forms).
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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::availability::AvailabilityIndex;
use crate::claim::{
    BatchHoldAnswer, BatchHoldQuery, BatchHoldResponse, CLAIM_SCHEMA_VERSION, Claim, HoldAnswer,
    HoldQuery, HoldResponse, KnownPayload, KnownTransport, MAX_BATCH_HOLD_KEYS, NarHashKey,
    QUERY_SCHEMA_VERSION, decode_batch_hold_query, decode_batch_hold_response, decode_hold_query,
    decode_hold_response, encode_batch_hold_query, encode_batch_hold_response, encode_hold_query,
    encode_hold_response,
};
use crate::source::{NarKey, NarSource, SourceError, UpstreamResponse};
use crate::transport::NodeId;

/// How long a single peer probe may take before it is declared a non-answer and
/// the resolver moves on. The guard that keeps a miss FAST: a silent/wedged peer
/// cannot stall the resolution (and therefore the build path) beyond this per-peer
/// bound. Coarse on purpose - the fine-grained per-request abort/hedge is task-51.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// The DEFAULT implementation is the pre-task-91 behaviour - one
    /// [`resolve`](Self::resolve) per key - so every existing [`Discovery`] impl
    /// keeps working unchanged and a batching impl is an override, not a rewrite.
    /// It is also the honest baseline the measurement compares against.
    async fn resolve_many(&self, keys: &[NarHashKey]) -> Vec<Option<Claim>> {
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            out.push(self.resolve(key).await);
        }
        out
    }
}

// -------------------------------------------------------------------------
// InMemoryDiscovery: the wave-1/test stand-in (was TransportNarSource's inline
// map). One announced claim per key; last announce wins.
// -------------------------------------------------------------------------

/// A discovery source backed by an in-memory map of announced claims, keyed on the
/// canonical [`NarHashKey`]. This is the task-38 "discovery stand-in" made a
/// first-class [`Discovery`] impl: a test (or a wave-1 seed) [`announce`]s claims
/// and `resolve` returns them. It shares the [`Discovery`] contract with
/// [`DirectDiscovery`], so the same [`crate::transport_fetch::TransportNarSource`]
/// drives either without change.
///
/// Keyed on [`NarHashKey`] (not a loose string) so it agrees BY CONSTRUCTION with
/// the availability index and the claim wire - the canonical-key discipline the
/// task-38/48 notes call out (a non-canonical key can never be inserted, because
/// the claim already carries a strict `NarHashKey`).
#[derive(Default)]
pub struct InMemoryDiscovery {
    claims: Mutex<HashMap<NarHashKey, Claim>>,
}

impl InMemoryDiscovery {
    /// An empty discovery source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a claim, keyed on its own canonical [`NarHashKey`], so a later
    /// `resolve` of that key returns it. Idempotent-ish: re-announcing a key
    /// replaces the prior claim (a fresh holder/offer set).
    pub fn announce(&self, claim: Claim) {
        self.claims
            .lock()
            .expect("claims mutex")
            .insert(claim.key, claim);
    }
}

#[async_trait]
impl Discovery for InMemoryDiscovery {
    async fn resolve(&self, key: &NarHashKey) -> Option<Claim> {
        self.claims.lock().expect("claims mutex").get(key).cloned()
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
/// structural at this seam, not just at the index.
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
        let mut answers = Vec::with_capacity(query.keys.len().min(MAX_BATCH_HOLD_KEYS));
        let mut offers: Vec<KnownTransport> = Vec::new();
        for key in &query.keys {
            let single = HoldQuery {
                schema_version: QUERY_SCHEMA_VERSION,
                key: *key,
            };
            match self.query(node, &single).await {
                Ok(response) => match response.answer {
                    HoldAnswer::Have {
                        blake3,
                        offers: key_offers,
                    } => {
                        // The batch form hoists offers to the response; in the shim
                        // they come per-key, so the first Have's offers become the
                        // peer's. They are the same peer's locators by construction
                        // (one node answered every probe).
                        if offers.is_empty() {
                            offers = key_offers;
                        }
                        answers.push(BatchHoldAnswer::Have { blake3 });
                    }
                    HoldAnswer::Absent => answers.push(BatchHoldAnswer::Absent),
                },
                Err(err @ PeerQueryError::Answer(_)) => {
                    eprintln!("daemon: batch probe of {node}: {key} failed ({err}); Absent");
                    answers.push(BatchHoldAnswer::Absent);
                }
                // A peer-level fault is true of every key; do not burn N-1 more.
                Err(err) => return Err(err),
            }
        }
        Ok(BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            offers,
            answers,
        })
    }
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
        // answer from the REAL index on a blocking thread - the batch may cost up
        // to MAX_BATCH_HOLD_KEYS `nix-store --dump`s under the digest locks.
        let decoded =
            decode_batch_hold_query(&on_wire).map_err(|e| PeerQueryError::Codec(e.to_string()))?;
        let keys_asked = decoded.keys.len();
        let response = tokio::task::spawn_blocking(move || index.answer_batch(&decoded))
            .await
            .map_err(|e| PeerQueryError::Answer(format!("batch query task panicked: {e}")))?;

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
    /// Probe `peers` (in order) via `query`, with the default [`PROBE_TIMEOUT`].
    pub fn new(peers: Vec<NodeId>, query: Arc<dyn PeerQuery>) -> Self {
        Self {
            peers,
            query,
            probe_timeout: PROBE_TIMEOUT,
        }
    }

    /// As [`new`](Self::new) but with an explicit per-peer probe bound (tests use a
    /// short one to prove a hanging peer still yields a fast miss).
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

    /// Resolve a whole closure with ONE probe per peer per chunk (task-91).
    ///
    /// The shape of the work, and why it is this shape:
    ///   * The DISTINCT still-unresolved keys are collected per peer, so a peer is
    ///     never asked about a key an earlier peer already answered `Have` for, and
    ///     never asked the same key twice (the wire forbids duplicates; a caller's
    ///     closure list may legitimately contain them).
    ///   * The batch is chunked at [`MAX_BATCH_HOLD_KEYS`], so a 1000-path closure
    ///     is 4 probes per peer rather than 1000 - and the cap is enforced by
    ///     construction here, never discovered as a peer's rejection.
    ///   * Peers are tried in order and the loop STOPS as soon as every key is
    ///     resolved, so the common case (the first peer holds the closure) really
    ///     is one round trip.
    ///   * Each chunk probe carries the same [`PROBE_TIMEOUT`] bound as a single
    ///     probe, so a wedged peer still yields a fast miss. STATED LIMIT: a cold
    ///     peer that must hash 256 large NARs to answer may exceed that bound and
    ///     be treated as a miss. That is the safe direction (the fetch falls back
    ///     upstream), but it does mean a first batch against a cold peer can
    ///     under-report. A responder-side "answer with what is already derived"
    ///     policy is TASK-102.
    async fn resolve_many(&self, keys: &[NarHashKey]) -> Vec<Option<Claim>> {
        let mut results: Vec<Option<Claim>> = vec![None; keys.len()];
        if keys.is_empty() {
            return results;
        }

        for peer in &self.peers {
            // The distinct keys still unanswered, and where each one's answer goes.
            let mut positions: HashMap<NarHashKey, Vec<usize>> = HashMap::new();
            let mut pending: Vec<NarHashKey> = Vec::new();
            for (i, key) in keys.iter().enumerate() {
                if results[i].is_some() {
                    continue;
                }
                positions.entry(*key).or_insert_with(|| {
                    pending.push(*key);
                    Vec::new()
                });
                positions.get_mut(key).expect("just inserted").push(i);
            }
            if pending.is_empty() {
                break; // every key resolved; no further peer is worth a round trip
            }

            for chunk in pending.chunks(MAX_BATCH_HOLD_KEYS) {
                let query = BatchHoldQuery {
                    schema_version: QUERY_SCHEMA_VERSION,
                    keys: chunk.to_vec(),
                };
                let response = match tokio::time::timeout(
                    self.probe_timeout,
                    self.query.query_batch(peer, &query),
                )
                .await
                {
                    Ok(Ok(response)) => response,
                    Ok(Err(err)) => {
                        eprintln!(
                            "daemon: batched discovery probe of {peer} ({} keys) failed: {err}",
                            chunk.len()
                        );
                        continue;
                    }
                    Err(_elapsed) => {
                        eprintln!(
                            "daemon: batched discovery probe of {peer} ({} keys) exceeded {:?}; \
                             treating as a miss",
                            chunk.len(),
                            self.probe_timeout
                        );
                        continue;
                    }
                };
                // Defence in depth: the transport already checked this against the
                // asked count, but a mis-aligned answer would silently bind every
                // later key to the wrong hash, so it is re-checked at the one place
                // the mapping is actually performed.
                if response.answers.len() != chunk.len() {
                    eprintln!(
                        "daemon: peer {peer} answered {} of {} batched keys; discarding the \
                         whole answer (positional alignment is not recoverable)",
                        response.answers.len(),
                        chunk.len()
                    );
                    continue;
                }
                for (key, answer) in chunk.iter().zip(response.answers.iter()) {
                    let BatchHoldAnswer::Have { blake3 } = answer else {
                        continue;
                    };
                    let claim = Self::claim_from_have(
                        key,
                        *peer,
                        HoldAnswer::Have {
                            blake3: *blake3,
                            offers: response.offers.clone(),
                        },
                    );
                    for i in positions.get(key).into_iter().flatten() {
                        results[*i] = Some(claim.clone());
                    }
                }
            }
        }
        results
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
        match self.primary.resolve(key, expected_size).await {
            Ok(resp) => Ok(resp),
            Err(err @ (SourceError::Unreachable(_) | SourceError::Upstream(_))) => {
                // p2p could not serve it here: fall back to upstream (S2). The miss
                // is already bounded upstream of here (DirectDiscovery / the
                // transport timeout), so this does not re-introduce a hang.
                eprintln!("daemon: p2p miss ({err}); falling back to upstream");
                self.secondary.resolve(key, expected_size).await
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

    use crate::availability::{DumpError, NarDumper, NullAnnounce, NullStore, StorePath};
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

    /// A dumper returning FIXED bytes (no nix needed); the addressed unit is
    /// `BLAKE3` of exactly these bytes.
    struct FixedDumper(Vec<u8>);
    impl NarDumper for FixedDumper {
        fn dump(&self, _path: &StorePath) -> Result<Vec<u8>, DumpError> {
            Ok(self.0.clone())
        }
    }

    /// Two distinct canonical NarHash keys, built from real sha256-shaped bytes.
    fn key_x() -> NarHashKey {
        NarHashKey::from_sha256_bytes([0x11; 32])
    }
    fn key_y() -> NarHashKey {
        NarHashKey::from_sha256_bytes([0x22; 32])
    }

    fn node_b() -> NodeId {
        NodeId::from_bytes([0xbb; 32])
    }

    /// An index for `node`, holding `key -> a real (existing) store file` whose NAR
    /// is `nar`. Returns the index and the temp dir (kept alive by the caller).
    fn index_holding(
        node: NodeId,
        key: NarHashKey,
        nar: Vec<u8>,
    ) -> (Arc<AvailabilityIndex>, TempDir) {
        let dir = TempDir::new("idx");
        let store_path = dir.store_file("nar");
        let index = AvailabilityIndex::open(
            node,
            Arc::new(FixedDumper(nar)),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("open index");
        index.register(key, store_path).expect("register");
        (Arc::new(index), dir)
    }

    // ---- the REAL query envelope, answered from the REAL index -------------

    #[tokio::test]
    async fn in_process_query_round_trips_the_envelope_and_answers_from_the_index() {
        let nar = b"the raw NAR node B holds".to_vec();
        let (index, _dir) = index_holding(node_b(), key_x(), nar.clone());
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);

        let query = HoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            key: key_x(),
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
        let (index, _dir) = index_holding(node_b(), key_y(), b"B holds only Y".to_vec());
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);

        let probe_x = HoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            key: key_x(),
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
            discovery.resolve(&key_x()).await.is_none(),
            "X is not held; Y being held must not turn this into a hit"
        );
        assert!(
            discovery.resolve(&key_y()).await.is_some(),
            "Y is held; the same resolver finds it (control)"
        );
    }

    // ---- DirectDiscovery: a hit yields the complete offer ------------------

    #[tokio::test]
    async fn resolve_returns_the_complete_offer_from_the_holder() {
        let nar = b"resolve me".to_vec();
        let (index, _dir) = index_holding(node_b(), key_x(), nar.clone());
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);
        let discovery = DirectDiscovery::new(vec![node_b()], Arc::new(rendezvous));

        let claim = discovery.resolve(&key_x()).await.expect("a hit");
        assert_eq!(claim.key, key_x());
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

    // ---- task-91: the BATCHED probe ---------------------------------------

    /// An index for `node` holding several keys, each backed by its own real file
    /// whose NAR bytes are derived from the key (so every key has a DISTINCT
    /// blake3 and a mis-mapped answer is detectable, not a coincidence).
    fn index_holding_many(node: NodeId, keys: &[NarHashKey]) -> (Arc<AvailabilityIndex>, TempDir) {
        let dir = TempDir::new("idx-many");
        let index = AvailabilityIndex::open(
            node,
            // Per-path bytes: the dumper reads the file it is pointed at, so each
            // registration derives its own digest.
            Arc::new(FileDumper),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("open index");
        for (i, key) in keys.iter().enumerate() {
            let path = dir.path.join(format!("nar-{i}"));
            std::fs::write(&path, format!("NAR bytes for {key}")).expect("write");
            index
                .register(*key, StorePath::new(path))
                .expect("register");
        }
        (Arc::new(index), dir)
    }

    /// A dumper that returns the file's own bytes - distinct content per path.
    struct FileDumper;
    impl NarDumper for FileDumper {
        fn dump(&self, path: &StorePath) -> Result<Vec<u8>, DumpError> {
            std::fs::read(path.as_path()).map_err(|e| DumpError(e.to_string()))
        }
    }

    /// `n` distinct canonical keys.
    fn keys(n: usize) -> Vec<NarHashKey> {
        (0..n)
            .map(|i| {
                let mut raw = [0u8; 32];
                raw[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
                NarHashKey::from_sha256_bytes(raw)
            })
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
        // round trips, never the answers. B holds 3 of 5 keys.
        let all = keys(5);
        let held = vec![all[0], all[2], all[4]];
        let (index, _dir) = index_holding_many(node_b(), &held);
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);
        let discovery = DirectDiscovery::new(vec![node_b()], Arc::new(rendezvous));

        let mut serial = Vec::new();
        for key in &all {
            serial.push(discovery.resolve(key).await);
        }
        let batched = discovery.resolve_many(&all).await;

        assert_eq!(
            batched, serial,
            "the batched answer must equal the one-at-a-time answer, position for position"
        );
        // ...and it is a real mixture, so the equality is not vacuous.
        assert_eq!(batched.iter().filter(|c| c.is_some()).count(), 3);
        assert!(batched[1].is_none() && batched[3].is_none());
        for (i, claim) in batched.iter().enumerate() {
            if let Some(claim) = claim {
                assert_eq!(claim.key, all[i], "position {i} must answer about all[{i}]");
            }
        }
    }

    #[tokio::test]
    async fn batching_collapses_n_round_trips_into_one() {
        // AC#1/AC#3 at unit scale: same peer, same keys, same answers - the ONLY
        // difference is how many times the peer was asked.
        let all = keys(20);
        let (index, _dir) = index_holding_many(node_b(), &all);
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);
        let counting = CountingQuery::wrap(Arc::new(rendezvous));
        let discovery = DirectDiscovery::new(vec![node_b()], counting.clone());

        for key in &all {
            discovery.resolve(key).await;
        }
        let serial_probes = counting.singles.load(Ordering::Relaxed);

        let batched = discovery.resolve_many(&all).await;
        let batch_probes = counting.batches.load(Ordering::Relaxed);

        assert_eq!(serial_probes, 20, "one-at-a-time costs one probe per key");
        assert_eq!(batch_probes, 1, "batched costs ONE probe for the whole set");
        assert_eq!(
            counting.singles.load(Ordering::Relaxed),
            serial_probes,
            "the batched arm must not have fallen back to single-key probes"
        );
        assert!(
            batched.iter().all(Option::is_some),
            "and it still resolved every key"
        );
    }

    #[tokio::test]
    async fn a_closure_larger_than_the_cap_is_chunked_not_rejected() {
        // A 1000-path closure is 4 probes per peer, not 1000 and not an error.
        let all = keys(MAX_BATCH_HOLD_KEYS * 3 + 7);
        let (index, _dir) = index_holding_many(node_b(), &all[..5]);
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);
        let counting = CountingQuery::wrap(Arc::new(rendezvous));
        let discovery = DirectDiscovery::new(vec![node_b()], counting.clone());

        let resolved = discovery.resolve_many(&all).await;
        assert_eq!(resolved.len(), all.len());
        assert_eq!(
            resolved.iter().filter(|c| c.is_some()).count(),
            5,
            "the 5 held keys resolve; the rest miss"
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
        let (index, _dir) = index_holding_many(node_b(), &[all[0]]);
        let mut rendezvous = InProcessPeerQuery::new();
        rendezvous.add_index(node_b(), index);
        let counting = CountingQuery::wrap(Arc::new(rendezvous));
        let discovery = DirectDiscovery::new(vec![node_b()], counting.clone());

        let resolved = discovery.resolve_many(&with_repeats).await;
        assert_eq!(
            counting.keys_in_batches.load(Ordering::Relaxed),
            3,
            "5 positions, 3 distinct keys - the peer is asked 3 things"
        );
        for (i, claim) in resolved.iter().enumerate() {
            match with_repeats[i] == all[0] {
                true => assert!(claim.is_some(), "every position of the held key resolves"),
                false => assert!(claim.is_none()),
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
        let (index, _dir) = index_holding_many(node_b(), held);
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
                .all(|a| *a == BatchHoldAnswer::Absent),
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
                    })
                    .collect(),
            })
        }
    }

    #[tokio::test]
    async fn a_misaligned_batch_answer_is_discarded_whole() {
        // Positional alignment is not recoverable from a short answer, so the
        // resolver must throw the WHOLE answer away rather than use its prefix.
        let all = keys(4);
        let discovery = DirectDiscovery::new(vec![node_b()], Arc::new(MisalignedPeer));
        let resolved = discovery.resolve_many(&all).await;
        assert_eq!(resolved.len(), 4);
        assert!(
            resolved.iter().all(Option::is_none),
            "a mis-aligned answer must resolve NOTHING, not a shifted prefix"
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
        let (index, _dir) = index_holding_many(node_b(), &all[..2]);
        let mut inner = InProcessPeerQuery::new();
        inner.add_index(node_b(), index);
        let counting = CountingQuery::wrap(Arc::new(inner));
        let discovery =
            DirectDiscovery::new(vec![node_b()], Arc::new(SingleOnly(counting.clone())));

        let resolved = discovery.resolve_many(&all).await;
        assert_eq!(
            counting.singles.load(Ordering::Relaxed),
            6,
            "the shim really does cost one round trip per key"
        );
        assert_eq!(resolved.iter().filter(|c| c.is_some()).count(), 2);
        for (i, claim) in resolved.iter().enumerate().take(2) {
            let claim = claim.as_ref().expect("held");
            assert_eq!(claim.key, all[i]);
            assert_eq!(
                claim.transports,
                vec![KnownTransport::Iroh { node: node_b() }],
                "the shim hoists the peer's offers onto the batch response"
            );
        }
    }

    #[tokio::test]
    async fn a_hanging_peer_yields_a_bounded_batched_miss() {
        // The AC#2 bounded-miss guarantee must survive batching: a wedged peer
        // cannot stall a whole closure resolution either.
        let probe_bound = Duration::from_millis(150);
        let discovery =
            DirectDiscovery::with_timeout(vec![node_b()], Arc::new(HangingQuery), probe_bound);
        let all = keys(4);
        let started = std::time::Instant::now();
        let resolved = discovery.resolve_many(&all).await;
        let elapsed = started.elapsed();
        assert!(resolved.iter().all(Option::is_none));
        assert!(
            elapsed < Duration::from_secs(5),
            "a batched miss must be bounded too, took {elapsed:?}"
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
}
