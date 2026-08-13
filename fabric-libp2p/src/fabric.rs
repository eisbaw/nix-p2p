//! [`Libp2pFabric`] - the concrete [`PeerFabric`] for the libp2p backend. It exposes
//! the content-discovery axes (directory + announcer) AND, from TASK-151, the transport
//! (always) and the serve axis (when built with a supplier), all over the SAME swarm.
//! From TASK-159 the node-locator axis resolves a provider's dial address through kad
//! peer-routing; TASK-169 has the transport drive its dial off that SAME locator (the
//! resolve-then-dial lives inside the fabric). The hold-query / LAN axes remain `None`
//! (hold-query is unimplemented; NAT traversal for residential peers is TASK-168).

use std::path::PathBuf;
use std::sync::Arc;

use libp2p::PeerId;
use peer_fabric::{
    AvailabilityAnnouncer, ExposureLedger, LocalPeerDiscovery, NarServer, NarTransfer, NodeId,
    NodeLocator, PeerFabric, PeerHoldQuery, ProviderDirectory, TransferRegistry, TransportTag,
};

use crate::announcer::Libp2pAvailabilityAnnouncer;
use crate::directory::Libp2pProviderDirectory;
use crate::locator::Libp2pNodeLocator;
use crate::nar::Libp2pNarSupplier;
use crate::server::Libp2pServer;
use crate::swarm::{Node, NodeConfig, NodeError, SwarmHandle};
use crate::transport::Libp2pTransport;

/// The libp2p [`PeerFabric`]. Holds the running [`Node`] (its worker stays alive as
/// long as the fabric does) and the kad-backed capabilities.
pub struct Libp2pFabric {
    node_id: NodeId,
    peer_id: PeerId,
    handle: SwarmHandle,
    ledger: Arc<ExposureLedger>,
    directory: Arc<dyn ProviderDirectory>,
    announcer: Arc<dyn AvailabilityAnnouncer>,
    locator: Arc<dyn NodeLocator>,
    transfers: TransferRegistry,
    server: Option<Arc<dyn NarServer>>,
    _node: Node,
}

impl Libp2pFabric {
    /// Start a libp2p node for `config` with discovery + the fetch transport, but NOT
    /// serving (no supplier). A pure CONSUMER fabric: `server()` is `None`. The
    /// anti-rollback floor is IN-MEMORY (session-scoped); [`start_durable`] persists it
    /// across restart.
    ///
    /// PRODUCTION PATH TODAY: `daemon-libp2p` builds its fabric through THIS
    /// (non-durable) constructor, so the shipped daemon's floor + announce sequence do
    /// NOT survive a restart. Wiring the daemon onto [`start_durable`] (and minting
    /// durable POSITIVE sequences rather than the current `sequence: 1`) is TASK-185; the
    /// durable path below is built and unit-tested but not yet used in the binary.
    ///
    /// [`start_durable`]: Self::start_durable
    pub fn start(config: NodeConfig) -> Result<Libp2pFabric, NodeError> {
        Self::assemble(config, None, None)
    }

    /// Start a CONSUMER fabric whose anti-rollback floor + per-key announce sequence are
    /// DURABLY persisted under `state_dir` (TASK-176 #1), so a restarted node still
    /// rejects a rolled-back record and mints a network-effective withdrawal. Each node
    /// needs its OWN `state_dir` (the files are keyed by directory, not identity).
    ///
    /// BUILT AND UNIT-TESTED, NOT WIRED: no production binary calls this yet - the
    /// `daemon-libp2p` composition root uses the non-durable [`start`]. Wiring it (and the
    /// durable positive-sequence source that makes a restarted PROVIDER's re-announce win)
    /// is TASK-185. So restart-durability is proven by tests, not yet delivered by the
    /// shipped daemon.
    ///
    /// [`start`]: Self::start
    pub fn start_durable(
        config: NodeConfig,
        state_dir: PathBuf,
    ) -> Result<Libp2pFabric, NodeError> {
        Self::assemble(config, None, Some(state_dir))
    }

    /// Start a libp2p node that ALSO serves NARs from `supplier` (a substrate-internal
    /// supply seam; the daemon's real catalog-backed supplier is TASK-146). `server()`
    /// is `Some`.
    pub fn start_with_supplier(
        config: NodeConfig,
        supplier: Arc<dyn Libp2pNarSupplier>,
    ) -> Result<Libp2pFabric, NodeError> {
        Self::assemble(config, Some(supplier), None)
    }

    /// A serving fabric ([`start_with_supplier`]) whose floor + announce sequence are
    /// DURABLY persisted under `state_dir` (TASK-176 #1).
    ///
    /// [`start_with_supplier`]: Self::start_with_supplier
    pub fn start_with_supplier_durable(
        config: NodeConfig,
        supplier: Arc<dyn Libp2pNarSupplier>,
        state_dir: PathBuf,
    ) -> Result<Libp2pFabric, NodeError> {
        Self::assemble(config, Some(supplier), Some(state_dir))
    }

    fn assemble(
        config: NodeConfig,
        supplier: Option<Arc<dyn Libp2pNarSupplier>>,
        state_dir: Option<PathBuf>,
    ) -> Result<Libp2pFabric, NodeError> {
        // The node identity IS the record-signing secret (self-serve v1). Capture it
        // BEFORE `Node::start` consumes `config`, so the announcer can sign its own
        // withdrawal tombstones (TASK-152, AC#1) with the same key `node_id` derives from.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&config.identity_seed);
        let node = Node::start(config)?;
        let ledger = Arc::new(ExposureLedger::new());

        // The durable-floor files (TASK-176 #1) live under `state_dir` when configured:
        // the directory's anti-rollback floor and the announcer's per-key sequence, each
        // in its own greppable text file. Without a `state_dir` both stay in-memory
        // (session-scoped), exactly as before.
        let directory: Arc<dyn ProviderDirectory> = Arc::new(match &state_dir {
            Some(dir) => Libp2pProviderDirectory::durable(
                node.handle.clone(),
                ledger.clone(),
                dir.join("provider-floor-v1.txt"),
            ),
            None => Libp2pProviderDirectory::new(node.handle.clone(), ledger.clone()),
        });
        let announcer: Arc<dyn AvailabilityAnnouncer> = Arc::new(match &state_dir {
            Some(dir) => Libp2pAvailabilityAnnouncer::durable(
                node.handle.clone(),
                ledger.clone(),
                node.node_id,
                node.peer_id,
                signing_key,
                dir.join("announce-seq-v1.txt"),
            ),
            None => Libp2pAvailabilityAnnouncer::new(
                node.handle.clone(),
                ledger.clone(),
                node.node_id,
                node.peer_id,
                signing_key,
            ),
        });
        // The node-locator resolves a provider's dial address THROUGH kad peer-routing.
        // ONE concrete instance is shared (TASK-169): the fetch transport drives its dial
        // off this SAME locator (so the resolve-then-dial lives inside the fabric, and its
        // OurNodeId->DhtNode disclosure lands on the fabric's single `ledger`), and the
        // `node_locator()` axis (TASK-159, gate-able + unit-tested) exposes it too.
        let node_locator = Arc::new(Libp2pNodeLocator::new(node.handle.clone(), ledger.clone()));

        // The fetch transport is always available (a consumer needs it); it registers
        // under the NodeId-locator tag (see transport.rs ADR). It resolves the provider's
        // dial address through the shared locator BEFORE dialing (TASK-169).
        let mut transfers = TransferRegistry::new();
        transfers.register(Arc::new(Libp2pTransport::new(
            node.handle.clone(),
            node_locator.clone(),
        )));

        let locator: Arc<dyn NodeLocator> = node_locator;

        // The serve axis exists only when a supplier was provided (a serving node).
        let server: Option<Arc<dyn NarServer>> = supplier
            .map(|supplier| Arc::new(Libp2pServer::new(node.handle.clone(), supplier)) as _);

        Ok(Libp2pFabric {
            node_id: node.node_id,
            peer_id: node.peer_id,
            handle: node.handle.clone(),
            ledger,
            directory,
            announcer,
            locator,
            transfers,
            server,
            _node: node,
        })
    }

    /// The libp2p `PeerId` of this node (for a peer to dial / for tests to assert
    /// which provider answered).
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The swarm handle, so connectivity (listen / dial / bootstrap) can be driven.
    /// TASK-151 will fold the standard connectivity setup behind a config; for now the
    /// composition root / tests drive it explicitly.
    pub fn handle(&self) -> &SwarmHandle {
        &self.handle
    }
}

impl PeerFabric for Libp2pFabric {
    fn node_id(&self) -> NodeId {
        self.node_id
    }

    fn provider_directory(&self) -> Option<&Arc<dyn ProviderDirectory>> {
        Some(&self.directory)
    }

    fn announcer(&self) -> Option<&Arc<dyn AvailabilityAnnouncer>> {
        Some(&self.announcer)
    }

    fn node_locator(&self) -> Option<&Arc<dyn NodeLocator>> {
        // TASK-159 AC#1: the kad peer-routing NodeLocator - resolves a provider's dial
        // address THROUGH the DHT (get_closest_peers), so the address is no longer
        // injected. NAT traversal (AutoNAT/DCUtR/relay) for residential peers is TASK-168.
        Some(&self.locator)
    }

    fn transfer(&self, tag: TransportTag) -> Option<&dyn NarTransfer> {
        // The libp2p NarTransfer (request-response, BLAKE3-verified) is registered under
        // the NodeId-locator tag (TransportTag::Iroh; see transport.rs ADR).
        self.transfers.get(tag)
    }

    fn server(&self) -> Option<&Arc<dyn NarServer>> {
        // `Some` iff this fabric was built with a supplier (start_with_supplier).
        self.server.as_ref()
    }

    fn hold_query(&self) -> Option<&Arc<dyn PeerHoldQuery>> {
        None // TASK-151
    }

    fn local_peers(&self) -> Option<&Arc<dyn LocalPeerDiscovery>> {
        None
    }

    fn exposure_ledger(&self) -> &ExposureLedger {
        self.ledger.as_ref()
    }
}
