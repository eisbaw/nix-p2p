//! Substrate-free test doubles: a [`FakeFabric`] and one fake per axis, so the
//! whole seam - and eventually the whole daemon-core (TASK-141) - is unit-testable
//! with NO p2p stack linked. This is the concrete proof of AC#7's "a FakeFabric
//! exercises the whole daemon substrate-free" and of AC#4's per-axis fakeability:
//! because each capability is an `Arc<dyn ...>`, a test double is a trivial struct,
//! not a stubbed-out real backend.
//!
//! Every leak-capable fake shares the fabric's ONE [`ExposureLedger`] (AC#3), so a
//! test can assert exactly what a run disclosed by reading a single sink.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::budget::{AnnounceBudget, DiscoveryBudget, SafetyEnvelope, ServeBudget};
use crate::capabilities::{
    AnnounceError, AvailabilityAnnouncer, HoldAnswer, LocalPeerDiscovery, NarServer, NarSupplier,
    NarTransfer, NodeLocator, PeerHoldQuery, PeerHoldReply, PeerHoldRequest, ProviderDirectory,
    Receipt, ServeError, ServeHandle, TransferError,
};
use crate::content::{ContentKey, DialInfo, ProviderRecord, ResolutionPolicy};
use crate::exposure::{Exposure, ExposureLedger, ExposureSurface};
use crate::fabric::{PeerFabric, TransferRegistry};
use crate::ids::{Blake3Digest, NodeId, TransportOffer, TransportTag};
use crate::outcome::Lookup;

// -------------------------------------------------------------------------
// Per-axis fakes. Each holds the shared ledger and records its configured
// exposure when exercised, so an honest fabric's disclosures are observable.
// -------------------------------------------------------------------------

/// A [`ProviderDirectory`] that returns a configured [`Lookup`] and records a
/// configured exposure. Lets a test choose Found / Miss / Unavailable per key class.
pub struct FakeProviderDirectory {
    result: Lookup<Vec<ProviderRecord>>,
    on_call: Vec<Exposure>,
    surface: ExposureSurface,
    ledger: Arc<ExposureLedger>,
}

impl FakeProviderDirectory {
    /// A directory that answers every lookup with `result`, recording `on_call`
    /// exposures to `ledger` and declaring `surface` a-priori.
    pub fn new(
        result: Lookup<Vec<ProviderRecord>>,
        on_call: Vec<Exposure>,
        surface: ExposureSurface,
        ledger: Arc<ExposureLedger>,
    ) -> Self {
        FakeProviderDirectory {
            result,
            on_call,
            surface,
            ledger,
        }
    }
}

#[async_trait]
impl ProviderDirectory for FakeProviderDirectory {
    async fn find_providers(
        &self,
        _key: &ContentKey,
        _budget: &DiscoveryBudget,
    ) -> Lookup<Vec<ProviderRecord>> {
        self.ledger.record_all(self.on_call.iter().copied());
        self.result.clone()
    }

    fn declared_exposure(&self) -> ExposureSurface {
        self.surface.clone()
    }
}

/// An [`AvailabilityAnnouncer`] that accepts every publish with a fixed receipt (or
/// fails if `fail` is set) and records a configured exposure.
pub struct FakeAvailabilityAnnouncer {
    fail: bool,
    on_call: Vec<Exposure>,
    surface: ExposureSurface,
    ledger: Arc<ExposureLedger>,
}

impl FakeAvailabilityAnnouncer {
    /// An announcer that accepts publishes, recording `on_call` to `ledger`.
    pub fn accepting(
        on_call: Vec<Exposure>,
        surface: ExposureSurface,
        ledger: Arc<ExposureLedger>,
    ) -> Self {
        FakeAvailabilityAnnouncer {
            fail: false,
            on_call,
            surface,
            ledger,
        }
    }
}

#[async_trait]
impl AvailabilityAnnouncer for FakeAvailabilityAnnouncer {
    async fn announce(
        &self,
        _record: &ProviderRecord,
        _budget: &AnnounceBudget,
    ) -> Result<Receipt, AnnounceError> {
        self.ledger.record_all(self.on_call.iter().copied());
        if self.fail {
            Err(AnnounceError::Rejected(
                "fake configured to reject".to_string(),
            ))
        } else {
            Ok(Receipt::new("fake-accepted"))
        }
    }

    async fn withdraw(&self, _key: &ContentKey) -> Result<Receipt, AnnounceError> {
        Ok(Receipt::new("fake-withdrawn"))
    }

    fn declared_exposure(&self) -> ExposureSurface {
        self.surface.clone()
    }
}

/// A [`NodeLocator`] that resolves to a fixed [`DialInfo`] and records exposure ONLY
/// when the policy consults public infrastructure - an explicit-peers-only policy
/// discloses nothing, which is the whole point of axis 2 being gate-able.
pub struct FakeNodeLocator {
    dial: DialInfo,
    public_exposure: Vec<Exposure>,
    surface: ExposureSurface,
    ledger: Arc<ExposureLedger>,
}

impl FakeNodeLocator {
    /// A locator yielding `dial`, disclosing `public_exposure` only under a
    /// [`ResolutionPolicy::PublicInfrastructure`] policy.
    pub fn new(
        dial: DialInfo,
        public_exposure: Vec<Exposure>,
        surface: ExposureSurface,
        ledger: Arc<ExposureLedger>,
    ) -> Self {
        FakeNodeLocator {
            dial,
            public_exposure,
            surface,
            ledger,
        }
    }
}

#[async_trait]
impl NodeLocator for FakeNodeLocator {
    async fn locate(&self, _node: &NodeId, policy: &ResolutionPolicy) -> Lookup<DialInfo> {
        if matches!(policy, ResolutionPolicy::PublicInfrastructure) {
            self.ledger.record_all(self.public_exposure.iter().copied());
        }
        Lookup::Found(self.dial.clone())
    }

    fn declared_exposure(&self) -> ExposureSurface {
        self.surface.clone()
    }
}

/// A content-addressed [`NarTransfer`] keyed on the digest it was seeded under. It
/// does NOT hash (this crate carries no hashing recipe - that is the daemon's
/// `content_id` freeze): it returns the bytes stored under `content`, modelling the
/// honest holder path. A real backend adds gate-1 BLAKE3 verification.
pub struct FakeNarTransfer {
    tag: TransportTag,
    by_content: HashMap<Blake3Digest, Vec<u8>>,
}

impl FakeNarTransfer {
    /// A transfer serving offers of `tag`.
    pub fn new(tag: TransportTag) -> Self {
        FakeNarTransfer {
            tag,
            by_content: HashMap::new(),
        }
    }

    /// Seed raw NAR bytes under a content identity, so a fetch for it succeeds.
    pub fn seed(&mut self, content: Blake3Digest, raw_nar: Vec<u8>) -> &mut Self {
        self.by_content.insert(content, raw_nar);
        self
    }
}

#[async_trait]
impl NarTransfer for FakeNarTransfer {
    fn tag(&self) -> TransportTag {
        self.tag
    }

    async fn fetch(
        &self,
        content: &Blake3Digest,
        offer: &TransportOffer,
        expected_size: Option<u64>,
        _envelope: &SafetyEnvelope,
    ) -> Result<Vec<u8>, TransferError> {
        let got = offer.tag();
        if got != self.tag {
            return Err(TransferError::WrongOffer {
                expected: self.tag,
                got,
            });
        }
        let bytes = self
            .by_content
            .get(content)
            .cloned()
            .ok_or(TransferError::NotHeld(*content))?;
        // Model the signed-NarSize abort: a real streaming backend cuts the transfer
        // off the instant cumulative bytes exceed the bound. This whole-buffer fake
        // checks the final length, which is enough to prove the bound is WIRED
        // (`expected_size` reaches the transport and produces `TooLarge`); the real
        // mid-stream abort lives in the iroh backend.
        if let Some(limit) = expected_size {
            let streamed = bytes.len() as u64;
            if streamed > limit {
                return Err(TransferError::TooLarge { limit, streamed });
            }
        }
        Ok(bytes)
    }
}

/// A [`NarServer`] that starts a no-op session and returns a labelled handle.
pub struct FakeNarServer;

#[async_trait]
impl NarServer for FakeNarServer {
    async fn serve(
        &self,
        _supplier: Arc<dyn NarSupplier>,
        _budget: ServeBudget,
    ) -> Result<ServeHandle, ServeError> {
        Ok(ServeHandle::new("fake-serve"))
    }
}

/// A [`PeerHoldQuery`] that answers from a fixed holdings set: a key it holds is
/// `Have`, any other key is `Absent`, positionally aligned with the request.
pub struct FakePeerHoldQuery {
    holds: HashMap<ContentKey, (Blake3Digest, Vec<TransportOffer>)>,
    on_call: Vec<Exposure>,
    surface: ExposureSurface,
    ledger: Arc<ExposureLedger>,
}

impl FakePeerHoldQuery {
    /// A hold-query answering from `holds`, recording `on_call` to `ledger`.
    pub fn new(
        holds: HashMap<ContentKey, (Blake3Digest, Vec<TransportOffer>)>,
        on_call: Vec<Exposure>,
        surface: ExposureSurface,
        ledger: Arc<ExposureLedger>,
    ) -> Self {
        FakePeerHoldQuery {
            holds,
            on_call,
            surface,
            ledger,
        }
    }
}

#[async_trait]
impl PeerHoldQuery for FakePeerHoldQuery {
    async fn ask_holds(
        &self,
        _peer: &NodeId,
        query: &PeerHoldRequest,
        _budget: &DiscoveryBudget,
    ) -> Lookup<PeerHoldReply> {
        self.ledger.record_all(self.on_call.iter().copied());
        // Positional over exactly the asked keys - never a listing of our own.
        let answers = query
            .keys
            .iter()
            .map(|key| match self.holds.get(key) {
                Some((content, offers)) => HoldAnswer::Have {
                    content: *content,
                    offers: offers.clone(),
                },
                None => HoldAnswer::Absent,
            })
            .collect();
        Lookup::Found(PeerHoldReply { answers })
    }

    fn declared_exposure(&self) -> ExposureSurface {
        self.surface.clone()
    }
}

/// A [`LocalPeerDiscovery`] that reports a fixed peer set and records exposure when
/// consulted (even passive LAN presence discloses this node to LAN peers).
pub struct FakeLocalPeerDiscovery {
    peers: Vec<NodeId>,
    on_call: Vec<Exposure>,
    surface: ExposureSurface,
    ledger: Arc<ExposureLedger>,
}

impl FakeLocalPeerDiscovery {
    /// A LAN discovery reporting `peers`, recording `on_call` to `ledger`.
    pub fn new(
        peers: Vec<NodeId>,
        on_call: Vec<Exposure>,
        surface: ExposureSurface,
        ledger: Arc<ExposureLedger>,
    ) -> Self {
        FakeLocalPeerDiscovery {
            peers,
            on_call,
            surface,
            ledger,
        }
    }
}

#[async_trait]
impl LocalPeerDiscovery for FakeLocalPeerDiscovery {
    async fn nearby_peers(&self) -> Vec<NodeId> {
        self.ledger.record_all(self.on_call.iter().copied());
        self.peers.clone()
    }

    fn declared_exposure(&self) -> ExposureSurface {
        self.surface.clone()
    }
}

// -------------------------------------------------------------------------
// FakeFabric: a concrete PeerFabric whose axes are Option<Arc<dyn ...>>.
// -------------------------------------------------------------------------

/// A concrete [`PeerFabric`] for tests. Constructed via
/// [`upstream_only`](FakeFabric::upstream_only) (every P2P axis `None`) and then
/// enabled axis-by-axis with the `with_*` builders, each sharing the fabric's ONE
/// [`ExposureLedger`] (obtain it first with
/// [`shared_ledger`](FakeFabric::shared_ledger)). This mirrors the real fabric shape
/// (docs/peer-fabric-seam.md): the constructed struct's `Some`/`None` fields ARE the
/// operator's participation profile.
pub struct FakeFabric {
    node_id: NodeId,
    ledger: Arc<ExposureLedger>,
    directory: Option<Arc<dyn ProviderDirectory>>,
    announcer: Option<Arc<dyn AvailabilityAnnouncer>>,
    locator: Option<Arc<dyn NodeLocator>>,
    transfers: TransferRegistry,
    server: Option<Arc<dyn NarServer>>,
    hold_query: Option<Arc<dyn PeerHoldQuery>>,
    local: Option<Arc<dyn LocalPeerDiscovery>>,
}

impl FakeFabric {
    /// A fresh `upstream_only` fabric: every P2P axis `None`, an empty transfer
    /// registry, an empty ledger. This is the fresh-install default (AC#5) - it can
    /// consume from upstream but emits nothing and exposes no axis.
    pub fn upstream_only(node_id: NodeId) -> Self {
        FakeFabric {
            node_id,
            ledger: Arc::new(ExposureLedger::new()),
            directory: None,
            announcer: None,
            locator: None,
            transfers: TransferRegistry::new(),
            server: None,
            hold_query: None,
            local: None,
        }
    }

    /// The fabric's single shared ledger, to hand each fake so its disclosures land
    /// in the one sink the fabric exposes.
    pub fn shared_ledger(&self) -> Arc<ExposureLedger> {
        Arc::clone(&self.ledger)
    }

    /// Enable global content discovery.
    pub fn with_provider_directory(mut self, directory: Arc<dyn ProviderDirectory>) -> Self {
        self.directory = Some(directory);
        self
    }

    /// Enable publication.
    pub fn with_announcer(mut self, announcer: Arc<dyn AvailabilityAnnouncer>) -> Self {
        self.announcer = Some(announcer);
        self
    }

    /// Enable node/address resolution.
    pub fn with_node_locator(mut self, locator: Arc<dyn NodeLocator>) -> Self {
        self.locator = Some(locator);
        self
    }

    /// Register a transfer backend in the runtime tag-keyed registry.
    pub fn with_transfer(mut self, transfer: Arc<dyn NarTransfer>) -> Self {
        self.transfers.register(transfer);
        self
    }

    /// Enable serving.
    pub fn with_server(mut self, server: Arc<dyn NarServer>) -> Self {
        self.server = Some(server);
        self
    }

    /// Enable direct hold-query.
    pub fn with_hold_query(mut self, hold_query: Arc<dyn PeerHoldQuery>) -> Self {
        self.hold_query = Some(hold_query);
        self
    }

    /// Enable LAN discovery.
    pub fn with_local_peers(mut self, local: Arc<dyn LocalPeerDiscovery>) -> Self {
        self.local = Some(local);
        self
    }

    /// The union of the a-priori [`ExposureSurface`]s of every ENABLED leak-capable
    /// axis - the surface TASK-120 preflight checks against a profile's allowance.
    /// A disabled axis contributes nothing (it is `None`), so `upstream_only`
    /// returns an empty surface: it exposes no axis. Fetch and serve are not
    /// leak-capable and contribute no surface.
    pub fn declared_exposure_surface(&self) -> ExposureSurface {
        let mut exposures = Vec::new();
        if let Some(d) = &self.directory {
            exposures.extend_from_slice(d.declared_exposure().exposures());
        }
        if let Some(a) = &self.announcer {
            exposures.extend_from_slice(a.declared_exposure().exposures());
        }
        if let Some(l) = &self.locator {
            exposures.extend_from_slice(l.declared_exposure().exposures());
        }
        if let Some(h) = &self.hold_query {
            exposures.extend_from_slice(h.declared_exposure().exposures());
        }
        if let Some(lp) = &self.local {
            exposures.extend_from_slice(lp.declared_exposure().exposures());
        }
        ExposureSurface::from_exposures(exposures)
    }
}

impl PeerFabric for FakeFabric {
    fn node_id(&self) -> NodeId {
        self.node_id
    }

    fn provider_directory(&self) -> Option<&Arc<dyn ProviderDirectory>> {
        self.directory.as_ref()
    }

    fn announcer(&self) -> Option<&Arc<dyn AvailabilityAnnouncer>> {
        self.announcer.as_ref()
    }

    fn node_locator(&self) -> Option<&Arc<dyn NodeLocator>> {
        self.locator.as_ref()
    }

    fn transfer(&self, tag: TransportTag) -> Option<&dyn NarTransfer> {
        self.transfers.get(tag)
    }

    fn server(&self) -> Option<&Arc<dyn NarServer>> {
        self.server.as_ref()
    }

    fn hold_query(&self) -> Option<&Arc<dyn PeerHoldQuery>> {
        self.hold_query.as_ref()
    }

    fn local_peers(&self) -> Option<&Arc<dyn LocalPeerDiscovery>> {
        self.local.as_ref()
    }

    fn exposure_ledger(&self) -> &ExposureLedger {
        self.ledger.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::HoldMisalignment;
    use crate::content::{CONTENT_KEY_LEN, PROVIDER_SIGNATURE_LEN};
    use crate::exposure::{Disclosed, Recipient};
    use crate::outcome::Unavailable;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }
    fn content_key(seed: u8) -> ContentKey {
        ContentKey::from_bytes([seed; CONTENT_KEY_LEN])
    }
    fn digest(seed: u8) -> Blake3Digest {
        Blake3Digest::from_bytes([seed; 32])
    }

    fn record_for(key: ContentKey, provider: NodeId) -> ProviderRecord {
        ProviderRecord {
            key,
            content: digest(0x42),
            provider,
            offers: vec![TransportOffer::Iroh { node: provider }],
            sequence: 1,
            issued_at: 100,
            expiry: 200,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        }
    }

    // AC#5: a fresh upstream_only fabric exposes NO axis and discloses nothing.
    #[tokio::test]
    async fn upstream_only_fabric_exposes_no_axis() {
        let fabric = FakeFabric::upstream_only(node(0x01));

        assert!(fabric.provider_directory().is_none());
        assert!(fabric.announcer().is_none());
        assert!(fabric.node_locator().is_none());
        assert!(fabric.server().is_none());
        assert!(fabric.hold_query().is_none());
        assert!(fabric.local_peers().is_none());
        assert!(fabric.transfer(TransportTag::Iroh).is_none());
        assert!(fabric.transfer(TransportTag::BitTorrent).is_none());

        // No axis is enabled, so the a-priori surface is empty and nothing has been
        // disclosed - it can consume from upstream but emits no P2P traffic.
        assert!(fabric.declared_exposure_surface().is_empty());
        assert!(fabric.exposure_ledger().is_empty());
    }

    // AC#6: find_providers returns Vec<ProviderRecord>, and the lookup records its
    // exposure to the fabric's single ledger (AC#3).
    #[tokio::test]
    async fn find_providers_returns_records_and_records_exposure() {
        let fabric = FakeFabric::upstream_only(node(0x02));
        let ledger = fabric.shared_ledger();

        let key = content_key(0xaa);
        let found = vec![record_for(key, node(0x03)), record_for(key, node(0x04))];
        let dir = FakeProviderDirectory::new(
            Lookup::Found(found.clone()),
            vec![Exposure::new(Recipient::DhtNode, Disclosed::ContentKey)],
            ExposureSurface::from_exposures([Exposure::new(
                Recipient::DhtNode,
                Disclosed::ContentKey,
            )]),
            ledger,
        );
        let fabric = fabric.with_provider_directory(Arc::new(dir));

        let directory = fabric
            .provider_directory()
            .expect("directory enabled")
            .clone();
        let outcome = directory
            .find_providers(&key, &DiscoveryBudget::default())
            .await;

        match outcome {
            Lookup::Found(records) => {
                assert_eq!(records, found);
                assert_eq!(records.len(), 2, "a Vec<ProviderRecord>, not a single one");
            }
            other => panic!("expected Found(records), got {other:?}"),
        }

        // The consultation's disclosure landed in the ONE sink the fabric exposes.
        let disclosed = fabric.exposure_ledger().entries();
        assert_eq!(disclosed.len(), 1);
        assert_eq!(
            disclosed[0],
            Exposure::new(Recipient::DhtNode, Disclosed::ContentKey)
        );
    }

    // AC#2: a directory can return MISS vs UNAVAILABLE through the fabric, and the
    // two are distinguishable at the call site (not collapsed to Ok(None)).
    #[tokio::test]
    async fn a_directory_distinguishes_miss_from_unavailable() {
        let make = |result| {
            let fabric = FakeFabric::upstream_only(node(0x05));
            let ledger = fabric.shared_ledger();
            fabric.with_provider_directory(Arc::new(FakeProviderDirectory::new(
                result,
                vec![],
                ExposureSurface::none(),
                ledger,
            )))
        };

        let miss = make(Lookup::Miss);
        let out = miss
            .provider_directory()
            .unwrap()
            .find_providers(&content_key(0x01), &DiscoveryBudget::default())
            .await;
        assert!(out.is_miss(), "a healthy absence is a Miss");

        let unavailable = make(Lookup::Unavailable(Unavailable::BootstrapOutage));
        let out = unavailable
            .provider_directory()
            .unwrap()
            .find_providers(&content_key(0x01), &DiscoveryBudget::default())
            .await;
        assert!(out.is_unavailable(), "a could-not-consult is Unavailable");
        assert!(
            !out.is_miss(),
            "and it is NOT a Miss - the AC#2 distinction"
        );
    }

    // AC#4/AC#5: the runtime tag-keyed transfer registry dispatches by tag; a fetch
    // for an unregistered tag misses (skipped, not a crash).
    #[tokio::test]
    async fn transfer_registry_dispatches_by_tag() {
        let content = digest(0x11);
        let mut transfer = FakeNarTransfer::new(TransportTag::Iroh);
        transfer.seed(content, b"raw nar bytes".to_vec());
        let fabric = FakeFabric::upstream_only(node(0x06)).with_transfer(Arc::new(transfer));

        // Iroh is registered; BitTorrent is not.
        assert!(fabric.transfer(TransportTag::Iroh).is_some());
        assert!(fabric.transfer(TransportTag::BitTorrent).is_none());

        let offer = TransportOffer::Iroh { node: node(0x06) };
        let bytes = fabric
            .transfer(TransportTag::Iroh)
            .unwrap()
            .fetch(&content, &offer, Some(64), &SafetyEnvelope::default())
            .await
            .expect("held content within the size bound fetches");
        assert_eq!(bytes, b"raw nar bytes");

        // The signed-NarSize bound is WIRED: a limit below the served size aborts
        // with TooLarge rather than returning oversized bytes (proves `limit` has a
        // real input path - the review's finding #1).
        let aborted = fabric
            .transfer(TransportTag::Iroh)
            .unwrap()
            .fetch(&content, &offer, Some(4), &SafetyEnvelope::default())
            .await;
        assert!(
            matches!(aborted, Err(TransferError::TooLarge { limit: 4, streamed }) if streamed == 13),
            "expected a TooLarge abort, got {aborted:?}"
        );
    }

    // Review finding #3: PeerHoldReply's positional invariant is a CHECKED
    // precondition of reading it - a short/long reply from a peer fails fast rather
    // than silently shifting every key onto the wrong answer.
    #[tokio::test]
    async fn peer_hold_reply_alignment_is_checked() {
        let fabric = FakeFabric::upstream_only(node(0x20));
        let ledger = fabric.shared_ledger();
        let mut holds = HashMap::new();
        holds.insert(
            content_key(0x30),
            (
                digest(0x31),
                vec![TransportOffer::Iroh { node: node(0x20) }],
            ),
        );
        let fabric = fabric.with_hold_query(Arc::new(FakePeerHoldQuery::new(
            holds,
            vec![Exposure::new(Recipient::DhtNode, Disclosed::ContentKey)],
            ExposureSurface::from_exposures([Exposure::new(
                Recipient::DhtNode,
                Disclosed::ContentKey,
            )]),
            ledger,
        )));

        let request = PeerHoldRequest::new([content_key(0x30), content_key(0x31)]);
        let reply = match fabric
            .hold_query()
            .unwrap()
            .ask_holds(&node(0x21), &request, &DiscoveryBudget::default())
            .await
        {
            Lookup::Found(reply) => reply,
            other => panic!("expected a Found reply, got {other:?}"),
        };

        // Aligned: one answer per asked key, in order - Have for 0x30, Absent for 0x31.
        let pairs: Vec<_> = reply
            .aligned_with(&request)
            .expect("counts match")
            .collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, &content_key(0x30));
        assert!(matches!(pairs[0].1, HoldAnswer::Have { .. }));
        assert!(matches!(pairs[1].1, HoldAnswer::Absent));

        // A hostile short reply fails fast against the ASKED count, not the peer's.
        let short = PeerHoldReply {
            answers: vec![HoldAnswer::Absent],
        };
        assert_eq!(
            short.aligned_with(&request).err(),
            Some(HoldMisalignment {
                asked: 2,
                answered: 1
            })
        );
    }

    // Axis 2 is gate-able: an explicit-peers policy discloses nothing; public
    // infrastructure discloses the queried NodeId - both to the one ledger.
    #[tokio::test]
    async fn node_locator_exposure_depends_on_policy() {
        let fabric = FakeFabric::upstream_only(node(0x07));
        let ledger = fabric.shared_ledger();
        let locator = FakeNodeLocator::new(
            DialInfo::new(["direct:10.0.0.1:9000".to_string()]),
            vec![Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId)],
            ExposureSurface::from_exposures([Exposure::new(
                Recipient::DhtNode,
                Disclosed::OurNodeId,
            )]),
            ledger,
        );
        let fabric = fabric.with_node_locator(Arc::new(locator));
        let locator = fabric.node_locator().unwrap().clone();

        // Explicit peers only: nothing disclosed.
        let out = locator
            .locate(&node(0x08), &ResolutionPolicy::ExplicitPeersOnly)
            .await;
        assert!(out.is_found());
        assert!(fabric.exposure_ledger().is_empty());

        // Public infrastructure: the queried NodeId is disclosed.
        let _ = locator
            .locate(&node(0x08), &ResolutionPolicy::PublicInfrastructure)
            .await;
        assert_eq!(fabric.exposure_ledger().len(), 1);
    }

    // AC#7: a fully-enabled fabric unions every axis's declared surface, and the
    // whole seam is exercised with NO p2p stack linked.
    #[tokio::test]
    async fn a_fully_enabled_fabric_unions_every_axis_surface() {
        let fabric = FakeFabric::upstream_only(node(0x09));
        let ledger = fabric.shared_ledger();

        let dir = FakeProviderDirectory::new(
            Lookup::Miss,
            vec![],
            ExposureSurface::from_exposures([Exposure::new(
                Recipient::DhtNode,
                Disclosed::ContentKey,
            )]),
            Arc::clone(&ledger),
        );
        let ann = FakeAvailabilityAnnouncer::accepting(
            vec![],
            ExposureSurface::from_exposures([Exposure::new(
                Recipient::DhtNode,
                Disclosed::ContentKey,
            )]),
            Arc::clone(&ledger),
        );
        let lan = FakeLocalPeerDiscovery::new(
            vec![node(0x0a)],
            vec![],
            ExposureSurface::from_exposures([Exposure::new(
                Recipient::LanPeer,
                Disclosed::OurNodeId,
            )]),
            Arc::clone(&ledger),
        );

        let fabric = fabric
            .with_provider_directory(Arc::new(dir))
            .with_announcer(Arc::new(ann))
            .with_local_peers(Arc::new(lan))
            .with_server(Arc::new(FakeNarServer));

        // Every enabled leak-capable axis contributes; server (not leak-capable)
        // does not. Recipients seen: DhtNode (directory + announce) and LanPeer.
        let surface = fabric.declared_exposure_surface();
        assert!(surface.recipients().contains(&Recipient::DhtNode));
        assert!(surface.recipients().contains(&Recipient::LanPeer));

        // The server axis is enabled and usable substrate-free.
        let handle = fabric
            .server()
            .unwrap()
            .serve(Arc::new(NoOpSupplier), ServeBudget::default())
            .await
            .expect("fake serve starts");
        assert_eq!(handle.label, "fake-serve");
    }

    struct NoOpSupplier;
    #[async_trait]
    impl NarSupplier for NoOpSupplier {
        async fn supply(&self, _content: &Blake3Digest) -> Option<Vec<u8>> {
            None
        }
    }
}
