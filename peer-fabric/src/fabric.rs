//! The umbrella: [`PeerFabric`], and the runtime tag-keyed [`TransferRegistry`] the
//! fetch axis lives in.
//!
//! ## Dynamic dispatch, decided (docs/peer-fabric-seam.md)
//!
//! A fabric exposes its capabilities as `Option<&Arc<dyn Capability>>` accessors -
//! dynamic trait objects, NOT associated types. This was decided deliberately:
//! every axis is I/O-bound (network RTTs, MiB over QUIC, LAN), so a vtable hop is
//! unmeasurable, while trait objects keep the frontend non-generic (no viral
//! `<F>`), make per-axis test doubles trivial (see
//! [`FakeFabric`](crate::FakeFabric)), and let a dual-stack fabric mix a libp2p
//! directory with an iroh transfer. `#[async_trait]` already boxes every call, so
//! "static is faster" is moot.
//!
//! ## `None` means exactly one thing: this profile turned this axis off
//!
//! A capability accessor is `Some` when the constructed fabric offers that axis and
//! `None` when the operator's participation profile disabled it (AC#5). A fresh
//! `upstream_only` fabric returns `None` from every P2P accessor and discloses
//! nothing. The composition root (TASK-141: the two per-backend binaries) asserts
//! the selected profile's REQUIRED axes are present and FAILS FAST otherwise; that
//! wiring is not this crate's job (see the note below).
//!
//! ## Deferred to TASK-141 (kept out of this crate on purpose)
//!
//! This crate delivers the trait + the `Option<Arc<dyn>>` shape + a
//! [`FakeFabric`](crate::FakeFabric). It does NOT deliver:
//!   * the feature-gated `type Fabric = ...` alias / the two `daemon-iroh` and
//!     `daemon-libp2p` binaries (the binary IS the backend choice);
//!   * the concrete `IrohFabric`/`Libp2pFabric` backend structs;
//!   * the composition-root assertion of a profile's required axes.
//!
//! All of that is TASK-141, which also deletes the daemon's duplicate value types
//! and re-points the daemon at THIS crate. For TASK-140 it suffices that the seam
//! exists standalone with zero p2p deps and CAN be depended on.

use std::collections::HashMap;
use std::sync::Arc;

use crate::capabilities::{
    AvailabilityAnnouncer, LocalPeerDiscovery, NarServer, NarTransfer, NodeLocator, PeerHoldQuery,
    ProviderDirectory,
};
use crate::exposure::ExposureLedger;
use crate::ids::{NodeId, TransportTag};

/// The runtime, tag-keyed registry the fetch axis lives in: a
/// [`TransportTag`] -> [`NarTransfer`] backend map. A lookup MISS is the
/// "unknown/unimplemented transport" case - the offer is skipped by the fetch
/// driver, not a crash. This is separate from the compile-time backend selection on
/// purpose (AC#5): a single claim carries several [`TransportOffer`](crate::TransportOffer)s
/// and the transport is chosen at REQUEST time, so it is a legitimately-runtime
/// axis rather than a hole in the one-backend-per-binary model. Mirrors the daemon's
/// `TransportRegistry`.
#[derive(Default)]
pub struct TransferRegistry {
    by_tag: HashMap<TransportTag, Arc<dyn NarTransfer>>,
}

impl TransferRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a transport under its own [`NarTransfer::tag`]. Re-registering a tag
    /// replaces the previous impl.
    pub fn register(&mut self, transport: Arc<dyn NarTransfer>) -> &mut Self {
        self.by_tag.insert(transport.tag(), transport);
        self
    }

    /// The transport servicing `tag`, or `None` if none is registered (the offer is
    /// skipped by the caller).
    pub fn get(&self, tag: TransportTag) -> Option<&dyn NarTransfer> {
        self.by_tag.get(&tag).map(Arc::as_ref)
    }

    /// Whether a backend is registered for `tag`.
    pub fn has(&self, tag: TransportTag) -> bool {
        self.by_tag.contains_key(&tag)
    }

    /// Whether the registry has no transports at all (the upstream_only case).
    pub fn is_empty(&self) -> bool {
        self.by_tag.is_empty()
    }
}

/// The seam the frontend sees: WHAT any peer substrate offers this node, as
/// capability accessors that are `Some` when the axis is enabled and `None` when the
/// profile turned it off. Downstream code takes `&dyn PeerFabric` (or a concrete
/// fabric); the frontend stays non-generic - no `where F: PeerFabric + ...` spread.
///
/// Every disclosure any capability makes lands in ONE
/// [`exposure_ledger`](PeerFabric::exposure_ledger); that is the single place
/// preflight/status reads what a run disclosed (AC#3).
pub trait PeerFabric: Send + Sync {
    /// This node's own identity.
    fn node_id(&self) -> NodeId;

    /// Global exact-key content discovery (PRD axis 3a), or `None` if disabled.
    fn provider_directory(&self) -> Option<&Arc<dyn ProviderDirectory>>;

    /// Availability publication (PRD axis 4), or `None` if disabled.
    fn announcer(&self) -> Option<&Arc<dyn AvailabilityAnnouncer>>;

    /// Node/address resolution (PRD axis 2), or `None` if disabled.
    fn node_locator(&self) -> Option<&Arc<dyn NodeLocator>>;

    /// The transport servicing `tag` from the runtime registry, or `None` if no
    /// backend is registered for it (the fetch axis, AC#5).
    fn transfer(&self, tag: TransportTag) -> Option<&dyn NarTransfer>;

    /// Inbound serving (PRD axis 5), or `None` if disabled.
    fn server(&self) -> Option<&Arc<dyn NarServer>>;

    /// Direct named-key hold-query (PRD axis 3b), or `None` if disabled.
    fn hold_query(&self) -> Option<&Arc<dyn PeerHoldQuery>>;

    /// LAN peer discovery (PRD axis 1), or `None` if disabled.
    fn local_peers(&self) -> Option<&Arc<dyn LocalPeerDiscovery>>;

    /// The single exposure sink for this fabric (AC#3).
    fn exposure_ledger(&self) -> &ExposureLedger;
}
