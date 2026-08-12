//! [`Libp2pFabric`] - the concrete [`PeerFabric`] for the libp2p backend. It exposes
//! the content-discovery axes (directory + announcer) AND, from TASK-151, the transport
//! (always) and the serve axis (when built with a supplier), all over the SAME swarm.
//! The node-locator / hold-query / LAN axes remain `None` (NAT traversal + node
//! discovery is TASK-159; hold-query is unimplemented).

use std::sync::Arc;

use libp2p::PeerId;
use peer_fabric::{
    AvailabilityAnnouncer, ExposureLedger, LocalPeerDiscovery, NarServer, NarTransfer, NodeId,
    NodeLocator, PeerFabric, PeerHoldQuery, ProviderDirectory, TransferRegistry, TransportTag,
};

use crate::announcer::Libp2pAvailabilityAnnouncer;
use crate::directory::Libp2pProviderDirectory;
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
    transfers: TransferRegistry,
    server: Option<Arc<dyn NarServer>>,
    _node: Node,
}

impl Libp2pFabric {
    /// Start a libp2p node for `config` with discovery + the fetch transport, but NOT
    /// serving (no supplier). A pure CONSUMER fabric: `server()` is `None`.
    pub fn start(config: NodeConfig) -> Result<Libp2pFabric, NodeError> {
        Self::assemble(config, None)
    }

    /// Start a libp2p node that ALSO serves NARs from `supplier` (a substrate-internal
    /// supply seam; the daemon's real catalog-backed supplier is TASK-146). `server()`
    /// is `Some`.
    pub fn start_with_supplier(
        config: NodeConfig,
        supplier: Arc<dyn Libp2pNarSupplier>,
    ) -> Result<Libp2pFabric, NodeError> {
        Self::assemble(config, Some(supplier))
    }

    fn assemble(
        config: NodeConfig,
        supplier: Option<Arc<dyn Libp2pNarSupplier>>,
    ) -> Result<Libp2pFabric, NodeError> {
        let node = Node::start(config)?;
        let ledger = Arc::new(ExposureLedger::new());

        let directory: Arc<dyn ProviderDirectory> = Arc::new(Libp2pProviderDirectory::new(
            node.handle.clone(),
            ledger.clone(),
        ));
        let announcer: Arc<dyn AvailabilityAnnouncer> = Arc::new(Libp2pAvailabilityAnnouncer::new(
            node.handle.clone(),
            ledger.clone(),
            node.node_id,
            node.peer_id,
        ));

        // The fetch transport is always available (a consumer needs it); it registers
        // under the NodeId-locator tag (see transport.rs ADR).
        let mut transfers = TransferRegistry::new();
        transfers.register(Arc::new(Libp2pTransport::new(node.handle.clone())));

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
        // TASK-159: libp2p node discovery / NAT traversal (Identify + AutoNAT/DCUtR +
        // kad peer-routing) yields the NodeLocator. kad peer-routing already carries
        // addresses for a basic dial; the gate-able NodeLocator axis is not wired yet.
        None
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
