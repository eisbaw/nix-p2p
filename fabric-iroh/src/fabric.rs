//! [`IrohFabric`] - the concrete [`PeerFabric`] for the iroh backend (TASK-144), the
//! symmetric sibling of `fabric_libp2p::Libp2pFabric`. It wraps ONE long-lived
//! [`IrohNode`] and exposes its capabilities through the stack-neutral seam:
//!
//!   * **transfer** (always) - the node's iroh-blobs whole-NAR transport
//!     ([`IrohTransport`], a native `peer_fabric::NarTransfer`), registered under the
//!     `Iroh` tag in the runtime [`TransferRegistry`];
//!   * **node_locator** (iff the node runs pkarr address lookup) - the pkarr NodeId ->
//!     address resolver ([`crate::locator::IrohNodeLocator`] over the runtime's
//!     `NodeLookupHandle`, TASK-138);
//!   * **server** (iff the node was built with a provider) - the iroh-blobs provider
//!     ([`IrohProvider`], a native `peer_fabric::NarServer` with a real teardown
//!     `ServeHandle`, TASK-150). A DEFERRED-serve provider is exposed here NOT-yet-serving;
//!     the composition root calls `server().serve(budget)` and holds the returned handle.
//!
//! # Which axes are honestly `None`, and WHY (the whole reason libp2p is primary)
//!
//!   * **provider_directory** (content discovery, PRD axis 3a) - `None`. iroh has NO
//!     content-provider routing: it offers no Kademlia VALUE store from which a signed
//!     `ProviderRecord` (who-holds-this-NAR) is learnable. Global exact-key content
//!     discovery is libp2p-kad's job; that asymmetry is exactly why libp2p is the primary
//!     backend and iroh the optional transport (PRD Wave-2c). The daemon's iroh path
//!     discovers via a static claim set ABOVE the seam, not through this fabric.
//!   * **announcer** (availability publication, PRD axis 4) - `None`. iroh's publication
//!     (`iroh_publication`) is NODE-ADDRESS publication (pkarr), which FEEDS the
//!     node-locator above; it is not content-availability announcement, and there is no
//!     content-availability announcer on iroh (there is no content directory to announce
//!     INTO). Node-address publication is driven directly on the [`IrohNode`] runtime.
//!   * **hold_query** (direct named-key hold-query, PRD axis 3b) - `None`. No over-iroh
//!     hold-query protocol is implemented (a wave-2b future).
//!   * **local_peers** (LAN discovery, PRD axis 1) - `None`. No mDNS is wired here.
//!
//! # Lifecycle
//!
//! The fabric OWNS the [`IrohNode`], so the node runtime (endpoint/router/supervisor)
//! stays alive as long as the fabric does. Connectivity join and node-address publication
//! are driven on the node by the composition root (as the daemon already does today);
//! wiring the daemon's fetch path onto an `IrohNarSource` over this fabric - retiring the
//! `transport_iroh_bridge` - is the remaining daemon-side step (TASK-144 follow-up), and
//! is unblocked now that every iroh transfer/serve/locate axis sits behind this seam.

use std::sync::Arc;

use peer_fabric::{
    AvailabilityAnnouncer, ExposureLedger, LocalPeerDiscovery, NarServer, NarTransfer, NodeId,
    NodeLocator, PeerFabric, PeerHoldQuery, ProviderDirectory, TransferRegistry, TransportTag,
};

use crate::locator::IrohNodeLocator;
use crate::transport_iroh::{IrohError, IrohNode};

/// The iroh [`PeerFabric`]. Holds the running [`IrohNode`] (its runtime stays alive as long
/// as the fabric does) and the iroh-backed capabilities.
pub struct IrohFabric {
    node_id: NodeId,
    ledger: Arc<ExposureLedger>,
    locator: Option<Arc<dyn NodeLocator>>,
    transfers: TransferRegistry,
    server: Option<Arc<dyn NarServer>>,
    _node: IrohNode,
}

impl IrohFabric {
    /// Wrap an already-spawned [`IrohNode`] as a [`PeerFabric`], wiring the axes iroh
    /// supports (transfer always; node_locator iff pkarr lookup is enabled; server iff a
    /// provider was built) and leaving the unsupported axes honestly `None` (see the module
    /// docs for which and why).
    ///
    /// Fails only if the node's own identity cannot be read (a dead runtime), surfaced as
    /// [`IrohError`] so the composition root fails fast rather than constructing a fabric
    /// with no `node_id`.
    pub fn wrap(node: IrohNode) -> Result<IrohFabric, IrohError> {
        let node_id = node.node_id()?;
        let ledger = Arc::new(ExposureLedger::new());

        // TRANSFER axis: always present (a consumer needs it). The node's content transport
        // IS a native `peer_fabric::NarTransfer`; register it under the Iroh tag.
        let mut transfers = TransferRegistry::new();
        transfers.register(Arc::new(node.transport_handle()));

        // NODE-LOCATOR axis: present iff the node runtime runs pkarr address lookup
        // (`node_lookup_handle()` is `None` when address discovery is disabled, e.g. an
        // offline/ephemeral node) - honestly `None` otherwise, never a stub that always
        // fails. Shares the fabric's single `ledger`.
        let locator: Option<Arc<dyn NodeLocator>> = node.node_lookup_handle().map(|handle| {
            Arc::new(IrohNodeLocator::new(handle, ledger.clone())) as Arc<dyn NodeLocator>
        });

        // SERVE axis: present iff the node was built with a provider. The provider IS a
        // native `peer_fabric::NarServer`; a deferred-serve provider is exposed here not yet
        // serving (the composition root calls `serve(budget)` and holds the ServeHandle).
        let server: Option<Arc<dyn NarServer>> = node
            .provider_handle()
            .map(|provider| provider as Arc<dyn NarServer>);

        Ok(IrohFabric {
            node_id,
            ledger,
            locator,
            transfers,
            server,
            _node: node,
        })
    }

    /// The [`IrohNode`] this fabric owns, so the composition root can drive connectivity
    /// join and node-address publication on the SAME runtime the axes are backed by (the
    /// iroh analogue of `Libp2pFabric::handle()`).
    pub fn node(&self) -> &IrohNode {
        &self._node
    }

    /// Consume the fabric and reclaim the owned [`IrohNode`] - so the composition root can
    /// drive the node's consuming `shutdown(self)` for a clean teardown (the axes borrow
    /// only the runtime; taking the node back drops them).
    pub fn into_node(self) -> IrohNode {
        self._node
    }
}

impl PeerFabric for IrohFabric {
    fn node_id(&self) -> NodeId {
        self.node_id
    }

    fn provider_directory(&self) -> Option<&Arc<dyn ProviderDirectory>> {
        // iroh has NO content-provider routing (no Kademlia VALUE store); content discovery
        // is libp2p-kad's job. See the module docs - this is why libp2p is primary.
        None
    }

    fn announcer(&self) -> Option<&Arc<dyn AvailabilityAnnouncer>> {
        // iroh's publication is NODE-ADDRESS (pkarr), feeding the node_locator, not
        // content-availability announcement. No content announcer on iroh.
        None
    }

    fn node_locator(&self) -> Option<&Arc<dyn NodeLocator>> {
        // Some iff the node runtime runs pkarr address lookup (TASK-138); the pkarr
        // NodeId -> address resolver behind the seam.
        self.locator.as_ref()
    }

    fn transfer(&self, tag: TransportTag) -> Option<&dyn NarTransfer> {
        // The iroh-blobs NAR transport, registered under the Iroh tag.
        self.transfers.get(tag)
    }

    fn server(&self) -> Option<&Arc<dyn NarServer>> {
        // Some iff this fabric wraps a node built with a provider.
        self.server.as_ref()
    }

    fn hold_query(&self) -> Option<&Arc<dyn PeerHoldQuery>> {
        None // no over-iroh hold-query protocol (wave-2b future)
    }

    fn local_peers(&self) -> Option<&Arc<dyn LocalPeerDiscovery>> {
        None // no mDNS wired
    }

    fn exposure_ledger(&self) -> &ExposureLedger {
        self.ledger.as_ref()
    }
}
