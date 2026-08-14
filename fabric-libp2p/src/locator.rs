//! [`Libp2pNodeLocator`] - the PRD axis-2 [`NodeLocator`] on libp2p: resolve a provider's
//! ed25519 [`NodeId`] to dialable coordinates THROUGH kad peer-routing, so the daemon no
//! longer needs the provider's dial address handed to it out of band.
//!
//! # What this decentralizes (TASK-159 AC#1)
//!
//! Before this, a resolver discovered WHO holds a NAR (the kad-backed
//! [`crate::directory::Libp2pProviderDirectory`]) and fetched it
//! ([`crate::transport::Libp2pTransport`]), but the provider's DIAL address was injected
//! by the caller (`SwarmHandle::add_address`, or the test's `wire_consumer`). This locator
//! closes that gap: [`locate`](Libp2pNodeLocator::locate) issues an iterative
//! `get_closest_peers` to the target [`PeerId`]'s own key, and the k-closest set the query
//! converges on carries the addresses a shared bootstrap reported for the target (it
//! learned them via identify when the target connected). The resolver thus learns the dial
//! address through the DHT, not from the caller.
//!
//! Because the same peer-routing query also teaches this node's kad routing table (and
//! usually leaves a live connection to the target), the subsequent request-response fetch
//! dials via kad's own `handle_pending_outbound_connection` - so no `add_address` of the
//! provider is needed anywhere on the resolver.
//!
//! # `ResolutionPolicy` mapping (and its honest current limit)
//!
//!   * [`ResolutionPolicy::PublicInfrastructure`] - the active kad peer-routing query
//!     above. It discloses this node's identity to the DHT nodes / bootstrap it contacts
//!     (recorded to the ledger). Returns [`Lookup::Found`] with the learned Multiaddr
//!     strings, [`Lookup::Miss`] when a query that reached responding peers near the key
//!     knows no address, and [`Lookup::Unavailable`] when the mechanism could not be
//!     consulted (`InsufficientRouting` when the peer-routing walk reached NO responding
//!     peer - either an empty routing table or one of only dead entries, gated on the
//!     near-key [`crate::QueryReach`], TASK-174; `DeadlineExceeded` on timeout). See
//!     [`crate::QueryReach`] for the honest limit of the `Miss` direction: reaching this
//!     node's REACHABLE subgraph is not proof of reaching the target's global custodians
//!     (an inherent single-node-view partition/eclipse residue).
//!   * [`ResolutionPolicy::ExplicitPeersOnly`] - consult ONLY the statically configured peer
//!     address book ([`NodeConfig::peer_address_book`](crate::NodeConfig::peer_address_book),
//!     TASK-168 AC#2), disclosing NOTHING. This is a pure LOCAL map lookup:
//!     [`locate`](Libp2pNodeLocator::locate) makes NO network query, opens NO connection,
//!     and records NO ledger disclosure on this path. A [`NodeId`] present in the book
//!     resolves [`Lookup::Found`] with its configured Multiaddr strings; an absent one is an
//!     honest [`Lookup::Miss`] (a node given no explicit peer for that identity genuinely
//!     knows no address - never a fabricated result). The ZERO-DISCLOSURE property is
//!     load-bearing: it is the whole reason the explicit policy exists, and it holds because
//!     the answer comes from local config, not from asking a third party. Contrast
//!     `locate_via_dht` above, which DOES disclose (OUR identity, and the queried NodeId) to
//!     the DHT nodes it contacts.
//!
//! NAT traversal (AutoNAT/DCUtR/relay) for residential peers with no public address is
//! TASK-168 AC#1: this locator is the AC#1-RESOLUTION cornerstone (decentralized RESOLUTION
//! on the test network) plus the AC#2 static address book, not the AC#1 NAT-hole-punch story.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use libp2p::PeerId;
use peer_fabric::{
    DialInfo, Disclosed, Exposure, ExposureLedger, ExposureSurface, Lookup, NodeId, NodeLocator,
    Recipient, ResolutionPolicy, Unavailable,
};

use crate::keys::peer_id_of_provider;
use crate::swarm::{QueryFail, SwarmHandle, absence_from_reach};

/// The kad-backed [`NodeLocator`]. Holds a [`SwarmHandle`] to drive peer-routing, the
/// shared [`ExposureLedger`] every capability appends to, and the statically-configured
/// peer address book consulted (LOCALLY, disclosing nothing) under
/// [`ResolutionPolicy::ExplicitPeersOnly`].
pub struct Libp2pNodeLocator {
    handle: SwarmHandle,
    ledger: Arc<ExposureLedger>,
    /// The static peer address book (TASK-168 AC#2): a provider's [`NodeId`] -> its dialable
    /// location strings (opaque above the seam; libp2p Multiaddr strings here, the same shape
    /// `locate_via_dht` yields). Consulted ONLY on the [`ResolutionPolicy::ExplicitPeersOnly`]
    /// path as a pure local lookup - no network query, no ledger disclosure. Empty for a node
    /// configured with no explicit peers.
    peer_address_book: BTreeMap<NodeId, Vec<String>>,
}

impl Libp2pNodeLocator {
    /// A locator driving `handle`, recording disclosures to `ledger`, and answering
    /// [`ResolutionPolicy::ExplicitPeersOnly`] from the static `peer_address_book` (a
    /// provider [`NodeId`] -> its dialable location strings). Pass an empty map for a node
    /// with no explicit peers.
    pub fn new(
        handle: SwarmHandle,
        ledger: Arc<ExposureLedger>,
        peer_address_book: BTreeMap<NodeId, Vec<String>>,
    ) -> Self {
        Libp2pNodeLocator {
            handle,
            ledger,
            peer_address_book,
        }
    }

    /// The [`ResolutionPolicy::ExplicitPeersOnly`] resolution: a pure LOCAL lookup in the
    /// statically-configured address book. It makes NO network query, opens NO connection,
    /// and records NO ledger disclosure - the load-bearing ZERO-DISCLOSURE property that
    /// distinguishes the explicit policy from `locate_via_dht` (which reveals our identity,
    /// and the queried NodeId, to the DHT nodes it contacts). A configured `node` yields
    /// [`Lookup::Found`] with its book addresses; an unconfigured one is an honest
    /// [`Lookup::Miss`] (no explicit peer -> genuinely no address, never a fabricated one).
    fn locate_via_book(&self, node: &NodeId) -> Lookup<DialInfo> {
        match self.peer_address_book.get(node) {
            Some(locations) if !locations.is_empty() => {
                Lookup::Found(DialInfo::new(locations.iter().cloned()))
            }
            // Absent (or a book entry that somehow carries no address) is a healthy Miss: the
            // explicit policy consults nothing else, so there is no fallback and no disclosure.
            _ => Lookup::Miss,
        }
    }

    /// The active kad peer-routing resolution (PublicInfrastructure). Kept separate so the
    /// routing-bar short-circuit and the ledger disclosure live in one place.
    async fn locate_via_dht(&self, peer: PeerId) -> Lookup<DialInfo> {
        // A peer-routing query over an EMPTY routing table is not authoritative: a Miss
        // would be a lie (we simply are not on the network to ask). This cheap pre-check
        // short-circuits it to Unavailable before issuing a doomed query or recording a
        // spurious ledger disclosure. The FINER near-key bar is applied below, on the
        // QueryReach the walk actually achieved (TASK-174), so a routing table of only
        // DEAD entries - which passes this pre-check - is still classified honestly.
        if self.handle.routing_peers().await == 0 {
            return Lookup::Unavailable(Unavailable::InsufficientRouting);
        }

        // We are about to actually consult the DHT: record the disclosure HERE, after the
        // short-circuit, so a query that never touched the network does not pollute the
        // ledger. An active peer-routing query reveals OUR identity to the DHT nodes it
        // contacts. HONEST GAP: it also reveals the QUERIED target NodeId to those nodes,
        // but the frozen `peer_fabric::Disclosed` enum models OUR disclosures + ContentKey
        // and has no third-party-NodeId variant; recording that is a frozen-seam change
        // under wire review (TASK-168), so we record the expressible OurNodeId disclosure.
        self.ledger
            .record(Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId));

        match self.handle.locate_peer(peer).await {
            Ok((addrs, _)) if !addrs.is_empty() => {
                // The frozen seam treats DialInfo locations as OPAQUE strings; for libp2p
                // they are Multiaddr strings, reparsed inside the fabric when dialing.
                Lookup::Found(DialInfo::new(
                    addrs.into_iter().map(|addr| addr.to_string()),
                ))
            }
            // A completed query that learned no address for the target. Whether that is
            // "no address known right now" (Miss) or a could-not-consult
            // (InsufficientRouting) turns on the NEAR-KEY bar: did the peer-routing walk
            // actually reach any responding peer? (TASK-174; the Miss direction carries
            // the partition/eclipse limit QueryReach documents.)
            Ok((_, reach)) => absence_from_reach(reach),
            Err(QueryFail::Timeout) => Lookup::Unavailable(Unavailable::DeadlineExceeded),
            Err(QueryFail::Backend(why)) => Lookup::Unavailable(Unavailable::Backend(why)),
        }
    }
}

#[async_trait]
impl NodeLocator for Libp2pNodeLocator {
    async fn locate(&self, node: &NodeId, policy: &ResolutionPolicy) -> Lookup<DialInfo> {
        match policy {
            // A pure LOCAL address-book lookup: no third party is consulted, so NOTHING is
            // disclosed (no kad query, no dial, no ledger record). TASK-168 AC#2. We do NOT
            // derive/validate the PeerId here: this path never dials, and a NodeId that is
            // not in the book is simply an honest Miss (a malformed key can never match a
            // book entry either way, so it lands on the same zero-disclosure Miss).
            ResolutionPolicy::ExplicitPeersOnly => self.locate_via_book(node),
            ResolutionPolicy::PublicInfrastructure => {
                // The provider identity IS an ed25519 verifying key; derive the libp2p PeerId
                // it MUST correspond to. A non-point key can never be dialed over libp2p -
                // fail it as could-not-consult (a malformed target, not a healthy absence).
                let peer = match peer_id_of_provider(node) {
                    Some(peer) => peer,
                    None => {
                        return Lookup::Unavailable(Unavailable::Backend(format!(
                            "node {node} is not a valid ed25519 peer id; cannot resolve over libp2p"
                        )));
                    }
                };
                self.locate_via_dht(peer).await
            }
        }
    }

    fn declared_exposure(&self) -> ExposureSurface {
        // The a-priori MAY-disclose surface, taken as the SUPERSET over policies: an active
        // peer-routing query (PublicInfrastructure) reveals OUR identity to the DHT nodes
        // and the bootstrap it contacts. ExplicitPeersOnly is a strict subset (discloses
        // nothing). See the module note on the queried-NodeId gap (TASK-168).
        ExposureSurface::from_exposures([
            Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId),
            Exposure::new(Recipient::Bootstrap, Disclosed::OurNodeId),
        ])
    }
}
