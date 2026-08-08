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
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use iroh::endpoint::{RelayMode, presets};
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, PublicKey};
use iroh_blobs::get::request::get_blob;
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::{BlobsProtocol, Hash};

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

/// A coarse upper bound on how long one dial+fetch may take before it is declared
/// unusable. NOT the full safety envelope (task-51 owns per-request abort; task-25
/// owns the signed NarSize streaming bound) - just a guard so a wedged connection
/// cannot hang a resolution forever. Fail fast, try the next offer.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

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
}

impl IrohProvider {
    /// Bind a provider endpoint on loopback with the relay DISABLED and NO
    /// discovery, and start serving its (initially empty) blob store under the
    /// iroh-blobs ALPN. Seed blobs with [`Self::seed`].
    pub async fn spawn() -> Result<Self, IrohError> {
        let endpoint = bind_loopback_endpoint().await?;
        let store = MemStore::new();
        // BlobsProtocol serves get-requests from `store`; MemStore is a cheap
        // shared handle, so blobs seeded AFTER spawn are served by the same store.
        let blobs = BlobsProtocol::new(&store, None);
        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs)
            .spawn();
        Ok(Self {
            endpoint,
            store,
            router,
        })
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
}

impl IrohTransport {
    /// Bind a client endpoint on loopback with the relay DISABLED and NO
    /// discovery. Register the peers it may dial with [`Self::add_peer`].
    pub async fn spawn() -> Result<Self, IrohError> {
        let endpoint = bind_loopback_endpoint().await?;
        Ok(Self {
            endpoint,
            peers: Mutex::new(HashMap::new()),
        })
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

    /// The dial+fetch, factored out so a single [`FETCH_TIMEOUT`] wraps it.
    async fn dial_and_fetch(
        &self,
        content: &Blake3Digest,
        addr: EndpointAddr,
        node: &NodeId,
    ) -> Result<Vec<u8>, TransportError> {
        // Direct dial (no relay): the address carries the peer's loopback sockets.
        let connection = self
            .endpoint
            .connect(addr, iroh_blobs::ALPN)
            .await
            .map_err(|e| TransportError::Unavailable(format!("iroh dial to {node} failed: {e}")))?;

        // Fetch by the exact BLAKE3 addressed unit. iroh-blobs' bao decode verifies
        // each content item against `hash` as it streams (gate 1, incremental and
        // fail-fast) - a holder that cannot honestly serve `hash` errors here
        // rather than delivering wrong bytes.
        let hash = Hash::from_bytes(*content.as_bytes());
        let bytes = get_blob(connection, hash).bytes().await.map_err(|e| {
            TransportError::Unavailable(format!(
                "iroh get_blob failed (holder cannot honestly serve {content}): {e}"
            ))
        })?;
        let raw = bytes.to_vec();

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

        // Coarse fail-fast bound so a wedged dial/transfer cannot hang forever.
        match tokio::time::timeout(FETCH_TIMEOUT, self.dial_and_fetch(content, addr, node)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(TransportError::Unavailable(format!(
                "iroh fetch from {node} exceeded {FETCH_TIMEOUT:?}"
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
