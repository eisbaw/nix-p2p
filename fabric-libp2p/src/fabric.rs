//! [`Libp2pFabric`] - the concrete [`PeerFabric`] for the libp2p backend. This cycle
//! it exposes the content-discovery axes (directory + announcer); the transport /
//! locator / serve / hold-query / LAN axes are `None` until TASK-151 wires the libp2p
//! NAR transfer + node discovery over the SAME swarm.

use std::sync::Arc;

use libp2p::PeerId;
use peer_fabric::{
    AvailabilityAnnouncer, ExposureLedger, LocalPeerDiscovery, NarServer, NarTransfer, NodeId,
    NodeLocator, PeerFabric, PeerHoldQuery, ProviderDirectory, TransferRegistry, TransportTag,
};

use crate::announcer::Libp2pAvailabilityAnnouncer;
use crate::directory::Libp2pProviderDirectory;
use crate::swarm::{Node, NodeConfig, NodeError, SwarmHandle};

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
    _node: Node,
}

impl Libp2pFabric {
    /// Start a libp2p node for `config` and assemble its content-discovery fabric.
    pub fn start(config: NodeConfig) -> Result<Libp2pFabric, NodeError> {
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

        Ok(Libp2pFabric {
            node_id: node.node_id,
            peer_id: node.peer_id,
            handle: node.handle.clone(),
            ledger,
            directory,
            announcer,
            transfers: TransferRegistry::new(),
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
        // TASK-151: libp2p node discovery / NAT traversal (Identify + AutoNAT/DCUtR +
        // kad peer-routing) yields the NodeLocator.
        None
    }

    fn transfer(&self, tag: TransportTag) -> Option<&dyn NarTransfer> {
        // TASK-151: the libp2p NarTransfer (request-response / stream, BLAKE3-verified)
        // registers here. Empty registry today -> None for every tag.
        self.transfers.get(tag)
    }

    fn server(&self) -> Option<&Arc<dyn NarServer>> {
        None // TASK-151
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
