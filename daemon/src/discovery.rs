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
//! Every query names ONE concrete [`NarHashKey`] and gets a yes/no answer. There
//! is, by construction, no method on [`Discovery`] or [`PeerQuery`] that lists a
//! peer's holdings - the probe reuses task-50's [`HoldQuery`]/[`HoldAnswer`],
//! which already forbid enumeration. Probing key X reveals nothing about a key Y
//! the peer also holds (proven by test).
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
    CLAIM_SCHEMA_VERSION, Claim, HoldAnswer, HoldQuery, HoldResponse, KnownPayload, NarHashKey,
    QUERY_SCHEMA_VERSION, decode_hold_query, decode_hold_response, encode_hold_query,
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
/// one yes/no answer: there is deliberately NO "list holdings" method, so the
/// no-enumeration invariant is structural at this seam, not just at the index.
#[async_trait]
pub trait PeerQuery: Send + Sync {
    /// Probe `node` for the key named in `query`.
    async fn query(&self, node: &NodeId, query: &HoldQuery)
    -> Result<HoldResponse, PeerQueryError>;
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
