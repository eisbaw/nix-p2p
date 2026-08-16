//! [`LeechFabric`] - the CONSUME-ONLY / leech capability mask (TASK-78).
//!
//! A leech fetches from the swarm but gives nothing back: it does not SERVE NARs and
//! does not ANNOUNCE availability. This decorator realises that at the
//! **transport/discovery-agnostic capability seam** (AC#4): it wraps ANY
//! [`PeerFabric`] and forces the two GIVE axes to `None`, while passing every CONSUME
//! axis through unchanged. Because it wraps `Arc<dyn PeerFabric>`, EVERY backend
//! inherits the identical remote-observation contract - a peer cannot obtain content
//! from a leech, and the node publishes nothing - with no per-backend code.
//!
//! ## What it disables, and why that is fail-closed at the SEAM
//!
//!   * [`server`](PeerFabric::server) -> `None`. A [`NarServer`](crate::NarServer)
//!     is a LIFECYCLE: bytes flow only once a caller has `serve()`d it (the backend
//!     installs an inbound handler / gate). With the accessor masked to `None`, no
//!     composition root, `run()`, or future caller can reach the inner server to
//!     start that lifecycle - so on a fresh leech the backend's inbound serve path is
//!     never armed and answers every request "not held". This is a structural
//!     absence at the seam, NOT a scattered set of `if leech { skip }` checks.
//!   * [`announcer`](PeerFabric::announcer) -> `None`. Nothing can publish a
//!     [`ProviderRecord`](crate::ProviderRecord), so no peer ever learns this node
//!     holds anything - the discovery half of "give nothing back".
//!
//! ## HONEST LIMIT: the mask is a seam guarantee, not a retroactive stop (AC#1)
//!
//! Masking the accessor forecloses *starting* the serve lifecycle; it cannot *stop* a
//! server whose lifecycle a caller ALREADY started on the inner fabric before it was
//! wrapped. The airtight guarantee therefore holds when a leech is built from a fabric
//! that never had `serve()` called on it (the shipped path: a leech is a pure consumer,
//! constructed without a supplier, so its backend installs no serve gate at all - see
//! `fabric-libp2p`'s leech serve-barrier test). Wrapping is the seam-level formalisation
//! and the belt-and-suspenders mask; "no serve gate was ever installed" is the load-
//! bearing enforcement the peer observes.
//!
//! ## HONEST LIMIT: a leech still SENDS the queries it makes (AC#5)
//!
//! Consume-only is NOT private lookup. The CONSUME axes stay present and are what a
//! leech uses to fetch: [`provider_directory`](PeerFabric::provider_directory) sends
//! `get_record` lookups and [`node_locator`](PeerFabric::node_locator) sends
//! peer-routing queries - both disclose this node's interest to the DHT nodes they
//! touch, and those disclosures still land in the inner
//! [`exposure_ledger`](PeerFabric::exposure_ledger) (passed through unchanged). Leech
//! mode hides what this node SERVES and ANNOUNCES; it does not hide what it LOOKS UP.
//! Any status/preflight that reads the ledger sees the query exposures exactly as it
//! would for a non-leech consumer - the honesty is structural, not a promise.

use std::sync::Arc;

use crate::capabilities::{
    AvailabilityAnnouncer, LocalPeerDiscovery, NarServer, NarTransfer, NodeLocator, PeerHoldQuery,
    ProviderDirectory,
};
use crate::exposure::ExposureLedger;
use crate::fabric::PeerFabric;
use crate::ids::{NodeId, TransportTag};

/// The consume-only / leech mask over an inner [`PeerFabric`]. See the module docs.
pub struct LeechFabric {
    inner: Arc<dyn PeerFabric>,
}

impl LeechFabric {
    /// Wrap `inner` so that its SERVE and ANNOUNCE axes read `None` while every CONSUME
    /// axis (and the exposure ledger) passes through unchanged.
    pub fn new(inner: Arc<dyn PeerFabric>) -> Self {
        LeechFabric { inner }
    }

    /// The wrapped fabric, for callers that need the concrete consume axes the mask
    /// leaves intact (the mask only removes serve + announce).
    pub fn inner(&self) -> &Arc<dyn PeerFabric> {
        &self.inner
    }
}

impl PeerFabric for LeechFabric {
    fn node_id(&self) -> NodeId {
        self.inner.node_id()
    }

    fn provider_directory(&self) -> Option<&Arc<dyn ProviderDirectory>> {
        // CONSUME axis - a leech looks content up (and discloses that lookup); passed through.
        self.inner.provider_directory()
    }

    fn announcer(&self) -> Option<&Arc<dyn AvailabilityAnnouncer>> {
        // GIVE axis - masked. A leech announces NOTHING (AC#1), fail-closed at the seam.
        None
    }

    fn node_locator(&self) -> Option<&Arc<dyn NodeLocator>> {
        // CONSUME axis - a leech resolves a provider's dial address to fetch; passed through.
        self.inner.node_locator()
    }

    fn transfer(&self, tag: TransportTag) -> Option<&dyn NarTransfer> {
        // CONSUME axis - the fetch transport; passed through so a leech still fetches.
        self.inner.transfer(tag)
    }

    fn server(&self) -> Option<&Arc<dyn NarServer>> {
        // GIVE axis - masked. A leech serves NOTHING (AC#1), fail-closed at the seam.
        None
    }

    fn hold_query(&self) -> Option<&Arc<dyn PeerHoldQuery>> {
        // CONSUME axis - a leech ASKS peers (it does not answer); passed through.
        self.inner.hold_query()
    }

    fn local_peers(&self) -> Option<&Arc<dyn LocalPeerDiscovery>> {
        // DISCOVERY axis - noticing nearby peers is a consume-side lookup; passed through.
        self.inner.local_peers()
    }

    fn exposure_ledger(&self) -> &ExposureLedger {
        // ONE sink, shared with the inner fabric: the leech's own consume-side query
        // disclosures still land here, so status/preflight reads them honestly (AC#5).
        self.inner.exposure_ledger()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::budget::ServeBudget;
    use crate::capabilities::{NarServer, ServeError, ServeHandle};
    use crate::content::DialInfo;
    use crate::exposure::ExposureSurface;
    use crate::fake::{
        FakeAvailabilityAnnouncer, FakeFabric, FakeNarTransfer, FakeNodeLocator,
        FakeProviderDirectory,
    };
    use crate::ids::NodeId;
    use crate::outcome::Lookup;
    use crate::require::{Axis, require_axes};

    fn node() -> NodeId {
        NodeId::from_bytes([0x42; 32])
    }

    /// A trivial server so we can build a fabric that CAN serve/announce and prove the
    /// mask removes both even then (fail-closed regardless of the inner fabric).
    struct DummyServer;

    #[async_trait::async_trait]
    impl NarServer for DummyServer {
        async fn serve(&self, _budget: ServeBudget) -> Result<ServeHandle, ServeError> {
            Ok(ServeHandle::new("dummy"))
        }
    }

    /// A fabric that offers the CONSUME axes (directory via the fake) AND both GIVE axes
    /// (announcer + server). Wrapping it must strip serve + announce yet keep consume.
    fn serving_fabric() -> FakeFabric {
        let ledger = Arc::new(ExposureLedger::new());
        FakeFabric::upstream_only(node())
            .with_provider_directory(Arc::new(FakeProviderDirectory::new(
                Lookup::Miss,
                Vec::new(),
                ExposureSurface::none(),
                ledger.clone(),
            )))
            .with_node_locator(Arc::new(FakeNodeLocator::new(
                DialInfo::new(["direct:10.0.0.1:9000".to_string()]),
                Vec::new(),
                ExposureSurface::none(),
                ledger.clone(),
            )))
            .with_transfer(Arc::new(FakeNarTransfer::new(TransportTag::Iroh)))
            .with_announcer(Arc::new(FakeAvailabilityAnnouncer::accepting(
                Vec::new(),
                ExposureSurface::none(),
                ledger,
            )))
            .with_server(Arc::new(DummyServer))
    }

    #[test]
    fn leech_masks_serve_and_announce_even_over_a_serving_fabric() {
        let inner: Arc<dyn PeerFabric> = Arc::new(serving_fabric());
        // Sanity: the inner fabric DOES offer both give axes.
        assert!(inner.server().is_some(), "inner offers a server");
        assert!(inner.announcer().is_some(), "inner offers an announcer");

        let leech = LeechFabric::new(inner);
        assert!(
            leech.server().is_none(),
            "a leech must expose NO server (fail-closed at the seam)"
        );
        assert!(
            leech.announcer().is_none(),
            "a leech must expose NO announcer (fail-closed at the seam)"
        );
    }

    #[test]
    fn leech_keeps_every_consume_axis() {
        let leech = LeechFabric::new(Arc::new(serving_fabric()));
        assert!(
            leech.provider_directory().is_some(),
            "a leech still LOOKS UP providers (consume)"
        );
        assert!(
            leech.node_locator().is_some(),
            "a leech still resolves dial addresses (consume)"
        );
        assert!(
            leech.transfer(TransportTag::Iroh).is_some(),
            "a leech still fetches NAR bytes (consume)"
        );
        assert_eq!(leech.node_id(), node(), "identity is preserved");
    }

    #[test]
    fn require_axes_rejects_serve_or_announce_on_a_leech() {
        // The composition root's REQUIRED-axis gate must treat a leech as consumer-only:
        // requiring Server/Announcer fails fast (they are masked), while the consumer
        // axes pass. This is the seam-level proof that a leech cannot be wired to serve.
        let leech = LeechFabric::new(Arc::new(serving_fabric()));
        require_axes(
            &leech,
            &[
                Axis::ProviderDirectory,
                Axis::NodeLocator,
                Axis::Transfer(TransportTag::Iroh),
            ],
        )
        .expect("a leech satisfies the CONSUMER required axes");

        let err = require_axes(&leech, &[Axis::Server, Axis::Announcer])
            .expect_err("a leech must FAIL a profile that requires serving or announcing");
        assert_eq!(err.missing, vec![Axis::Server, Axis::Announcer]);
    }

    #[test]
    fn leech_shares_the_inner_exposure_ledger() {
        // AC#5 honesty: the ledger is the SAME instance, so a leech's consume-side query
        // disclosures are visible exactly as for the unwrapped consumer - the mask hides
        // nothing about what the node looks up.
        let inner = Arc::new(serving_fabric());
        let inner_ledger_ptr = inner.exposure_ledger() as *const ExposureLedger;
        let leech = LeechFabric::new(inner);
        let leech_ledger_ptr = leech.exposure_ledger() as *const ExposureLedger;
        assert_eq!(
            inner_ledger_ptr, leech_ledger_ptr,
            "the leech exposes the SAME exposure ledger as its inner fabric"
        );
    }
}
