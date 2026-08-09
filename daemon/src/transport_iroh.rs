//! The REAL iroh whole-NAR [`Transport`] (task-39): the FIRST peer-to-peer byte
//! transfer in the project. It fills the task-38 [`Transport`] trait for the
//! [`TransportTag::Iroh`] tag, replacing the in-memory `FakeTransport` with two
//! genuine iroh endpoints exchanging bytes over a real QUIC connection.
//!
//! ## Provider + client
//!
//!   * [`IrohProvider`] (node B) runs an iroh-blobs PROVIDER: it adds a node's raw
//!     NARs to an in-memory iroh-blobs store addressed by `BLAKE3(RawNarV1)` and
//!     serves them under the stock iroh-blobs ALPN via an [`iroh::protocol::Router`].
//!     ([`IrohProvider::seed`] models the content-addressed "put"; the real
//!     seeding index that enumerates a node's held NARs is task-50.)
//!   * [`IrohTransport`] (node A) is the [`Transport`] impl: given a
//!     [`Blake3Digest`] and a peer [`NodeId`] (from a claim's `Iroh` offer), it
//!     dials the peer and fetches the blob by that exact digest. iroh-blobs' `bao`
//!     streaming decode verifies BLAKE3 incrementally against the requested hash
//!     (gate 1) as bytes arrive, so a holder that cannot honestly serve the digest
//!     yields an error, never wrong bytes.
//!
//! ## Why our [`Blake3Digest`] IS the iroh blob hash
//!
//! The task-48 freeze pinned the addressed unit to PLAIN, UNKEYED `BLAKE3(RawNarV1)`
//! with no domain separation precisely because that equals the iroh-blobs blob
//! hash of the same bytes (`content_id.rs`). So we convert a [`Blake3Digest`] to an
//! [`iroh_blobs::Hash`] by its raw 32 bytes and fetch by it directly - no
//! re-hashing, no second identity.
//!
//! ## The TWO gates (kept distinct)
//!
//! Gate 1 (transport BLAKE3/bao) is owned here and re-asserted with the daemon's
//! own [`verify_blake3`] single-source-of-truth recipe before any bytes are
//! returned. Gate 2 (`sha256 == NarHash`, Nix's signed trust anchor) is downstream
//! and NOT re-implemented here - the daemon is outside the TCB (see
//! `transport_fetch` module docs).
//!
//! ## Relay / discovery (honest scope)
//!
//! Both endpoints are built with the n0 relay DISABLED ([`RelayMode::Disabled`])
//! and NO discovery (the `Minimal` preset), so this transport - and its test - need
//! no external relay server: the client dials the peer's DIRECT address on
//! loopback. In production a discovery layer (task-40) resolves a `NodeId` to an
//! address; here [`IrohTransport::add_peer`] stands in for that resolution (an
//! in-memory address book keyed by `NodeId`). n0 relay dependence for WAN
//! holepunch is a known soft-centralization limit (PRD); solving it is out of
//! scope. A coarse dial/fetch TIMEOUT ([`FETCH_TIMEOUT`]) guards against an
//! unbounded hang; the full safety envelope (per-request abort, the signed NarSize
//! streaming bound) is task-51 / task-25.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bao_tree::io::BaoContentItem;
use iroh::endpoint::{RelayMode, presets};
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, PublicKey};
use iroh_blobs::get::request::{GetBlobItem, get_blob};
use iroh_blobs::provider::events::{
    EventMask, EventSender, ProviderMessage, RequestMode, RequestUpdate,
};
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::{BlobsProtocol, Hash};
use n0_future::StreamExt;

use crate::claim::KnownTransport;
use crate::content_id::Blake3Digest;
use crate::transport::{IROH_BLOBS_ALPN, NodeId};
use crate::transport_fetch::{Transport, TransportError, TransportTag, verify_blake3};

// -------------------------------------------------------------------------
// AC#4: the ALPN cross-check, as a COMPILE-TIME assertion.
// -------------------------------------------------------------------------

/// Const byte-slice equality (the stdlib `==` on `&[u8]` is not const), so the
/// assertion below fails at COMPILE time rather than only in a test.
const fn alpn_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The task-48 freeze pinned [`IROH_BLOBS_ALPN`] WITHOUT an iroh dependency in
/// tree and explicitly deferred the cross-check to task-39. Now that iroh IS a
/// dependency, a divergence between our frozen constant and the real
/// `iroh_blobs::ALPN` must fail LOUD - and the loudest possible failure is the
/// build itself. (codex confirmed `/iroh-bytes/4` is current; this ASSERTS it.)
const _: () = assert!(
    alpn_bytes_eq(IROH_BLOBS_ALPN, iroh_blobs::ALPN),
    "frozen IROH_BLOBS_ALPN diverged from iroh_blobs::ALPN - realign the constant \
     in transport.rs to the pinned iroh version",
);

/// The real iroh-blobs ALPN, exposed so a test can cross-check the frozen constant
/// without depending on the `iroh_blobs` crate itself.
pub fn iroh_blobs_alpn() -> &'static [u8] {
    iroh_blobs::ALPN
}

// -------------------------------------------------------------------------
// The conservative safety envelope (task-51). PROVISIONAL DEFAULTS.
// -------------------------------------------------------------------------
//
// These three time bounds plus the streaming NarSize cap are the FLOOR task-43
// asserts (never unbounded-hang, never OOM), NOT a tuned policy. task-44 MODELS
// the real slow-HIT policy (hedge / delayed-race / adaptive) and a later task
// implements the winner; do NOT read these numbers as the answer. The slow-HIT
// DEFAULT here is the simplest safe thing: a bounded abort -> fall back to
// upstream. The values are deliberately generous (a healthy LAN peer finishes far
// inside them) and conservative (a dead/stalled/lying peer is cut off well before
// it can hang a build or exhaust memory).

/// DIAL bound: how long `endpoint.connect()` may take before a holder is declared
/// dead/unreachable. A `NodeId` that never answers the QUIC handshake is cut off
/// here -> bounded failure -> the driver tries the next offer or falls back to
/// upstream, never a hang. (task-40's `PROBE_TIMEOUT` bounded DISCOVERY; this
/// bounds the FETCH dial.) PROVISIONAL.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// BODY-IDLE bound: the maximum gap between successive bytes once the transfer has
/// started. A peer that connects then STALLS mid-stream (no progress for this long)
/// is aborted. This is the real slow-peer guard - distinct from a total-time cap: a
/// slow-but-PROGRESSING peer keeps resetting this idle clock and is tolerated,
/// while a STALLED one trips it fast. PROVISIONAL.
pub const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// TOTAL bound: a coarse backstop over the whole dial+transfer, so a peer that
/// stays just under the idle bound forever (dribbling one chunk per idle-epsilon)
/// still cannot run unbounded. The idle bound is the precise guard; this is the
/// belt-and-suspenders ceiling. PROVISIONAL. (Kept as `FETCH_TIMEOUT`, the name
/// task-39 exported, now widened to sit above dial+idle.)
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(60);

/// The three time bounds of the safety envelope, injectable so a test can pin
/// SHORT bounds and prove a dead/stalled peer yields a bounded abort (mirrors
/// [`crate::discovery::DirectDiscovery::with_timeout`]). [`Default`] is the
/// PROVISIONAL production envelope above.
#[derive(Debug, Clone, Copy)]
pub struct SafetyEnvelope {
    /// Bound on `connect()` (the dead-holder guard).
    pub dial_timeout: Duration,
    /// Bound on the gap between successive body chunks (the stall guard).
    pub body_idle_timeout: Duration,
    /// Coarse backstop over the whole dial+transfer.
    pub total_timeout: Duration,
}

impl Default for SafetyEnvelope {
    fn default() -> Self {
        Self {
            dial_timeout: DIAL_TIMEOUT,
            body_idle_timeout: BODY_IDLE_TIMEOUT,
            total_timeout: FETCH_TIMEOUT,
        }
    }
}

// -------------------------------------------------------------------------
// Errors.
// -------------------------------------------------------------------------

/// Why an iroh provider/transport operation failed. Kept separate from
/// [`TransportError`] (the trait's per-offer failure) so setup failures
/// (bind/seed) are distinguishable from a fetch that should just try the next
/// offer; [`IrohTransport::fetch`] maps the fetch-path ones into [`TransportError`].
#[derive(Debug)]
pub enum IrohError {
    /// Binding the iroh endpoint failed (socket/config).
    Bind(String),
    /// Adding bytes to the provider's blob store failed.
    Seed(String),
    /// A `NodeId`'s 32 bytes are not a valid ed25519 curve point (AC#4's
    /// deferred-from-task-48 validity check).
    InvalidNodeId(String),
    /// No socket address is bound yet, so no dialable address can be published.
    NoBoundAddress,
}

impl fmt::Display for IrohError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrohError::Bind(why) => write!(f, "iroh endpoint bind failed: {why}"),
            IrohError::Seed(why) => write!(f, "iroh-blobs seed failed: {why}"),
            IrohError::InvalidNodeId(why) => write!(f, "invalid iroh node id: {why}"),
            IrohError::NoBoundAddress => f.write_str("iroh endpoint has no bound address yet"),
        }
    }
}

impl std::error::Error for IrohError {}

// -------------------------------------------------------------------------
// A peer's dialable address (opaque wrapper so callers/tests never touch iroh).
// -------------------------------------------------------------------------

/// A peer's dialable iroh address: its [`NodeId`] plus concrete direct socket
/// addresses. Opaque on purpose - it wraps an [`EndpointAddr`] so tests and future
/// discovery code hand it around without depending on the `iroh` crate. In wave-2
/// this is what a discovery layer (task-40) resolves a `NodeId` to.
#[derive(Clone)]
pub struct IrohPeerAddr(EndpointAddr);

impl IrohPeerAddr {
    /// Build a dialable address from a peer's [`NodeId`] and its direct socket
    /// addresses. This is the resolution a discovery layer (task-40/47) produces -
    /// "here is the node and where to reach it" - made constructible without the
    /// `iroh` crate. (task-51's dead-holder bite also uses it to point a valid
    /// `NodeId` at a black-hole socket.)
    pub fn new(node: NodeId, sockets: impl IntoIterator<Item = SocketAddr>) -> Self {
        // A NodeId is 32 bytes; PublicKey::from_bytes only fails off-curve, which
        // Transport::fetch rejects via validate_node_id before dialing. Build the
        // EndpointAddr from whatever key bytes we were given; an off-curve id simply
        // never gets past validation to a dial.
        let key = PublicKey::from_bytes(node.as_bytes())
            .unwrap_or_else(|_| PublicKey::from_bytes(&[0u8; 32]).expect("zero key is on-curve"));
        let mut addr = EndpointAddr::new(key);
        for socket in sockets {
            addr = addr.with_ip_addr(socket);
        }
        IrohPeerAddr(addr)
    }

    /// The peer's node identity (our canonical [`NodeId`] type).
    pub fn node_id(&self) -> NodeId {
        NodeId::from_bytes(*self.0.id.as_bytes())
    }
}

// -------------------------------------------------------------------------
// Provider (node B): serve this node's NARs by BLAKE3 over iroh-blobs.
// -------------------------------------------------------------------------

/// An iroh-blobs PROVIDER: an endpoint + an in-memory blob store served under the
/// iroh-blobs ALPN. It answers a client's get-request for a blob addressed by
/// `BLAKE3(RawNarV1)`.
pub struct IrohProvider {
    endpoint: Endpoint,
    store: MemStore,
    router: Router,
    /// Total DECLARED size of the whole-blob transfers this provider has COMPLETED,
    /// observed from iroh-blobs' own provider events (never a client self-report).
    /// This is the S6 ground-truth oracle: node A's daemon claiming it "fetched from
    /// a peer" is untrusted narration; node B counting the bytes it SERVED is the
    /// ground truth. It is a LOWER BOUND on wire bytes: it credits the blob size on
    /// `Completed` (for a fresh whole-blob serve, size == bytes sent), never credits
    /// `Aborted`, and would under-count only if the bounded event channel lagged
    /// (harmless for S6's small blobs; exact byte-on-wire accounting for large
    /// payloads is a task-42/43 concern).
    bytes_served: Arc<AtomicU64>,
    /// Count of COMPLETED get-transfers served (each a whole blob handed to a
    /// client). Paired with [`Self::bytes_served`] so a nonzero byte count is
    /// attributable to real transfers, not a spurious event.
    transfers_completed: Arc<AtomicU64>,
}

impl IrohProvider {
    /// Bind a provider endpoint on loopback with the relay DISABLED and NO
    /// discovery, and start serving its (initially empty) blob store under the
    /// iroh-blobs ALPN. Seed blobs with [`Self::seed`].
    pub async fn spawn() -> Result<Self, IrohError> {
        let endpoint = bind_loopback_endpoint().await?;
        let store = MemStore::new();

        // Provider-side byte counter (the S6 ground-truth oracle). `NotifyLog`
        // asks iroh-blobs for per-request transfer events on a NOTIFY channel -
        // observe-only, no intercept to answer - so serving is never gated on us
        // draining events, yet we see the exact bytes each get-transfer moves.
        let mask = EventMask {
            get: RequestMode::NotifyLog,
            ..EventMask::DEFAULT
        };
        let (events, mut rx) = EventSender::channel(64, mask);
        let bytes_served = Arc::new(AtomicU64::new(0));
        let transfers_completed = Arc::new(AtomicU64::new(0));
        {
            let bytes_served = bytes_served.clone();
            let transfers_completed = transfers_completed.clone();
            tokio::spawn(async move {
                // One outer message per get-request; each carries an update
                // sub-stream (Started -> [Progress] -> Completed/Aborted). We sum
                // the Started size of every transfer that reaches Completed.
                while let Some(msg) = rx.recv().await {
                    if let ProviderMessage::GetRequestReceivedNotify(msg) = msg {
                        let bytes_served = bytes_served.clone();
                        let transfers_completed = transfers_completed.clone();
                        let mut updates = msg.rx;
                        tokio::spawn(async move {
                            let mut blob_size: u64 = 0;
                            while let Ok(Some(update)) = updates.recv().await {
                                match update {
                                    RequestUpdate::Started(started) => blob_size = started.size,
                                    RequestUpdate::Completed(_) => {
                                        bytes_served.fetch_add(blob_size, Ordering::Relaxed);
                                        transfers_completed.fetch_add(1, Ordering::Relaxed);
                                    }
                                    // Progress is redundant with Started.size for a
                                    // whole-blob serve; an Aborted transfer is NOT
                                    // counted (no bytes credited to a failed serve).
                                    _ => {}
                                }
                            }
                        });
                    }
                }
            });
        }

        // BlobsProtocol serves get-requests from `store`; MemStore is a cheap
        // shared handle, so blobs seeded AFTER spawn are served by the same store.
        let blobs = BlobsProtocol::new(&store, Some(events));
        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();
        Ok(Self {
            endpoint,
            store,
            router,
            bytes_served,
            transfers_completed,
        })
    }

    /// Total raw-NAR bytes this provider has SERVED to clients over completed
    /// get-transfers (the ground-truth peer-served counter). Observed from
    /// iroh-blobs provider events, so it cannot be forged by a client.
    pub fn bytes_served(&self) -> u64 {
        self.bytes_served.load(Ordering::Relaxed)
    }

    /// Count of completed get-transfers served (see [`Self::bytes_served`]).
    pub fn transfers_completed(&self) -> u64 {
        self.transfers_completed.load(Ordering::Relaxed)
    }

    /// Content-addressed "put": add the raw NAR bytes to the served store and
    /// return their [`Blake3Digest`] (the iroh-blobs blob hash, which equals our
    /// frozen addressed unit). This is the honest holder path; the real index that
    /// renders a node's NARs via `nix-store --dump` is task-50.
    pub async fn seed(&self, raw_nar: &[u8]) -> Result<Blake3Digest, IrohError> {
        let tag = self
            .store
            .add_bytes(raw_nar.to_vec())
            .await
            .map_err(|e| IrohError::Seed(e.to_string()))?;
        let digest = Blake3Digest::from_bytes(*tag.hash.as_bytes());
        // The iroh-blobs blob hash MUST equal our plain-unkeyed BLAKE3 recipe, or
        // the task-48 "content identity == blob hash" freeze is broken.
        debug_assert_eq!(
            digest,
            Blake3Digest::from_raw_nar(raw_nar),
            "iroh-blobs blob hash must equal BLAKE3(RawNarV1) (task-48 freeze)"
        );
        Ok(digest)
    }

    /// This provider's node identity (the locator a claim's `Iroh` offer carries).
    pub fn node_id(&self) -> NodeId {
        NodeId::from_bytes(*self.endpoint.id().as_bytes())
    }

    /// The concrete direct sockets this provider is bound to. In the wave-2a pod
    /// these are loopback (`127.0.0.1:PORT`), reachable by a peer in the SAME
    /// (shared) pod network namespace. node B prints these so node A can dial it
    /// with no relay/discovery; a real discovery/DHT (task-47) resolves them.
    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// This provider's dialable address (node id + bound loopback sockets), for a
    /// client to reach it directly with no relay/discovery. Stands in for what a
    /// discovery layer (task-40) resolves a `NodeId` to.
    pub async fn addr(&self) -> Result<IrohPeerAddr, IrohError> {
        let sockets = self.endpoint.bound_sockets();
        if sockets.is_empty() {
            return Err(IrohError::NoBoundAddress);
        }
        let mut addr = EndpointAddr::new(self.endpoint.id());
        for socket in sockets {
            addr = addr.with_ip_addr(socket);
        }
        Ok(IrohPeerAddr(addr))
    }

    /// Stop serving and close the endpoint (best-effort).
    pub async fn shutdown(self) {
        let _ = self.router.shutdown().await;
        self.endpoint.close().await;
    }
}

// -------------------------------------------------------------------------
// Client (node A): the Transport impl that fetches by BLAKE3 from a peer.
// -------------------------------------------------------------------------

/// The real iroh [`Transport`]: fetches a NAR by [`Blake3Digest`] from a peer
/// [`NodeId`] over iroh-blobs. Holds a client endpoint and an address book keyed
/// by `NodeId` (the discovery stand-in - task-40 supplies these resolutions).
pub struct IrohTransport {
    endpoint: Endpoint,
    /// `NodeId` -> dialable address. In production a discovery lookup fills this;
    /// here a test wires it via [`Self::add_peer`]. Behind a `Mutex` because
    /// [`Transport::fetch`] takes `&self`.
    peers: Mutex<HashMap<NodeId, EndpointAddr>>,
    /// The task-51 safety envelope (dial / body-idle / total bounds). Default is
    /// the PROVISIONAL production envelope; a test pins short bounds via
    /// [`Self::with_envelope`].
    envelope: SafetyEnvelope,
}

impl IrohTransport {
    /// Bind a client endpoint on loopback with the relay DISABLED and NO
    /// discovery. Register the peers it may dial with [`Self::add_peer`]. Uses the
    /// default (PROVISIONAL) [`SafetyEnvelope`]; override with [`Self::with_envelope`].
    pub async fn spawn() -> Result<Self, IrohError> {
        let endpoint = bind_loopback_endpoint().await?;
        Ok(Self {
            endpoint,
            peers: Mutex::new(HashMap::new()),
            envelope: SafetyEnvelope::default(),
        })
    }

    /// Replace the safety envelope (dial / body-idle / total time bounds). A test
    /// pins SHORT bounds to prove a dead/stalled peer yields a bounded abort without
    /// waiting the production seconds.
    pub fn with_envelope(mut self, envelope: SafetyEnvelope) -> Self {
        self.envelope = envelope;
        self
    }

    /// Register a peer's dialable address (the discovery stand-in): a subsequent
    /// [`Transport::fetch`] for an `Iroh` offer naming this peer's `NodeId` can
    /// then dial it directly.
    pub fn add_peer(&self, addr: &IrohPeerAddr) {
        self.peers
            .lock()
            .expect("peers mutex")
            .insert(addr.node_id(), addr.0.clone());
    }

    /// AC#4 (deferred from the task-48 freeze): validate that a [`NodeId`]'s 32
    /// bytes are a real ed25519 curve point, using the pinned iroh key
    /// constructor. A non-point id is undiallable and must be rejected loudly, not
    /// silently dialled.
    pub fn validate_node_id(node: &NodeId) -> Result<(), IrohError> {
        PublicKey::from_bytes(node.as_bytes())
            .map(|_| ())
            .map_err(|e| IrohError::InvalidNodeId(e.to_string()))
    }

    /// Close the client endpoint (best-effort).
    pub async fn shutdown(self) {
        self.endpoint.close().await;
    }

    /// The dial+stream, with the full task-51 envelope:
    ///   1. DIAL bounded by `envelope.dial_timeout` (dead-holder guard).
    ///   2. The body is STREAMED leaf-by-leaf (never buffered whole first), with:
    ///      - each stream step bounded by `envelope.body_idle_timeout` (stall guard);
    ///      - a running NarSize CAP: the moment cumulative bytes exceed
    ///        `expected_size` the stream is dropped and [`TransportError::TooLarge`]
    ///        returned, so a lying holder claiming a small NarSize but serving a huge
    ///        blob is cut off at ~NarSize, memory bounded (risk 6). The bound is the
    ///        SIGNED NarSize (uncompressed raw NAR) - the exact unit of the streamed
    ///        `RawNarV1` - NEVER the compressed FileSize.
    ///
    /// The whole thing is additionally wrapped in `envelope.total_timeout` by the
    /// caller as a coarse backstop.
    async fn dial_and_stream(
        &self,
        content: &Blake3Digest,
        addr: EndpointAddr,
        node: &NodeId,
        expected_size: Option<u64>,
    ) -> Result<Vec<u8>, TransportError> {
        // 1. DIAL, bounded: a NodeId that never answers the QUIC handshake is cut
        //    off here rather than hanging the resolution.
        let connection = match tokio::time::timeout(
            self.envelope.dial_timeout,
            self.endpoint.connect(addr, iroh_blobs::ALPN),
        )
        .await
        {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                return Err(TransportError::Unavailable(format!(
                    "iroh dial to {node} failed: {e}"
                )));
            }
            Err(_elapsed) => {
                return Err(TransportError::Unavailable(format!(
                    "iroh dial to {node} exceeded {:?} (dead holder)",
                    self.envelope.dial_timeout
                )));
            }
        };

        // 2. STREAM by the exact BLAKE3 addressed unit. iroh-blobs' bao decode
        //    verifies each leaf against `hash` as it arrives (gate 1, incremental).
        //    We drive it as a STREAM (not `.bytes()`, which buffers everything) so
        //    the NarSize cap can abort mid-transfer.
        let hash = Hash::from_bytes(*content.as_bytes());
        let mut stream = get_blob(connection, hash);
        let mut raw: Vec<u8> = Vec::new();
        loop {
            // Body-idle guard: no forward progress within the bound => stalled peer.
            let item =
                match tokio::time::timeout(self.envelope.body_idle_timeout, stream.next()).await {
                    Ok(Some(item)) => item,
                    Ok(None) => {
                        return Err(TransportError::Unavailable(format!(
                            "iroh stream from {node} ended before the blob completed"
                        )));
                    }
                    Err(_elapsed) => {
                        // Dropping `stream` (and its connection) here aborts the transfer.
                        return Err(TransportError::Unavailable(format!(
                            "iroh transfer from {node} stalled: no bytes for {:?}",
                            self.envelope.body_idle_timeout
                        )));
                    }
                };

            match item {
                GetBlobItem::Item(BaoContentItem::Leaf(leaf)) => {
                    raw.extend_from_slice(&leaf.data);
                    // Running NarSize cap: abort the instant we exceed the signed
                    // bound. Memory is held to <= bound + one bao chunk, regardless
                    // of how large the lying blob actually is. Dropping `stream` at
                    // the return aborts the transfer; we never drain the rest.
                    if let Some(limit) = expected_size
                        && raw.len() as u64 > limit
                    {
                        return Err(TransportError::TooLarge {
                            limit,
                            streamed: raw.len() as u64,
                        });
                    }
                }
                // Parent (tree) nodes carry no leaf data - bao uses them to verify.
                GetBlobItem::Item(BaoContentItem::Parent(_)) => {}
                GetBlobItem::Done(_stats) => break,
                GetBlobItem::Error(cause) => {
                    return Err(TransportError::Unavailable(format!(
                        "iroh get_blob failed (holder cannot honestly serve {content}): {cause}"
                    )));
                }
            }
        }

        // Re-assert gate 1 with the daemon's single-source-of-truth recipe. bao
        // already enforced it on the wire; this makes the trait contract explicit
        // and non-vacuous (never return unverified bytes).
        verify_blake3(content, &raw)?;
        Ok(raw)
    }
}

#[async_trait]
impl Transport for IrohTransport {
    fn tag(&self) -> TransportTag {
        TransportTag::Iroh
    }

    async fn fetch(
        &self,
        content: &Blake3Digest,
        offer: &KnownTransport,
        expected_size: Option<u64>,
    ) -> Result<Vec<u8>, TransportError> {
        // Defensive: the registry dispatches by tag, but a wrong variant is a bug
        // worth surfacing rather than silently mis-serving.
        let node = match offer {
            KnownTransport::Iroh { node } => node,
            other => {
                return Err(TransportError::WrongOffer {
                    expected: TransportTag::Iroh,
                    got: TransportTag::of(other),
                });
            }
        };

        // AC#4: reject a NodeId that is not a valid ed25519 curve point (it is
        // structurally 32 bytes, so only the curve check catches it) before dialing.
        Self::validate_node_id(node).map_err(|e| TransportError::Unavailable(e.to_string()))?;

        // Resolve the locator to a dialable address (discovery stand-in). No entry
        // means "no address known for this NodeId" - task-40 supplies it.
        let addr = self
            .peers
            .lock()
            .expect("peers mutex")
            .get(node)
            .cloned()
            .ok_or_else(|| {
                TransportError::Unavailable(format!(
                    "no known address for {node}; discovery (task-40) resolves NodeId->addr"
                ))
            })?;

        // Coarse total backstop over dial+transfer, on top of the finer-grained
        // dial and body-idle bounds inside `dial_and_stream`. A TooLarge abort from
        // the streaming cap propagates through unchanged (it is a deliberate abort,
        // not a hang the backstop should mask).
        match tokio::time::timeout(
            self.envelope.total_timeout,
            self.dial_and_stream(content, addr, node, expected_size),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(TransportError::Unavailable(format!(
                "iroh fetch from {node} exceeded total bound {:?}",
                self.envelope.total_timeout
            ))),
        }
    }
}

// -------------------------------------------------------------------------
// Shared: bind a loopback endpoint with relay disabled and no discovery.
// -------------------------------------------------------------------------

/// Bind an iroh endpoint on `127.0.0.1:0` (an OS-assigned loopback port) with the
/// relay DISABLED and the `Minimal` preset (no discovery/address-lookup), so two
/// in-process endpoints connect by DIRECT address with no external relay. Binding
/// to loopback explicitly (not the default `0.0.0.0`) makes `bound_sockets()`
/// return a deterministically dialable `127.0.0.1:PORT`.
async fn bind_loopback_endpoint() -> Result<Endpoint, IrohError> {
    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("loopback literal parses");
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind_addr(loopback)
        .map_err(|e| IrohError::Bind(e.to_string()))?
        .bind()
        .await
        .map_err(|e| IrohError::Bind(e.to_string()))
}
