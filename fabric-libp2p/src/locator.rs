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
//!     strings, [`Lookup::Miss`] when a healthy query knows no address, and
//!     [`Lookup::Unavailable`] when the mechanism could not be consulted
//!     (`InsufficientRouting` over an empty routing table, `DeadlineExceeded` on timeout).
//!   * [`ResolutionPolicy::ExplicitPeersOnly`] - consult ONLY a statically configured peer
//!     address book, disclosing nothing. This backend has no such book yet, so an
//!     explicit-peers-only resolution has no source to answer from and returns
//!     [`Lookup::Miss`] with zero disclosure (matching `declared_exposure` = none for that
//!     policy). Wiring a real static address book is TASK-168 (dep TASK-159); it is NOT a
//!     fabricated result - a node given no explicit peers genuinely knows no address.
//!
//! NAT traversal (AutoNAT/DCUtR/relay) for residential peers with no public address, and
//! the static address book above, are TASK-168: this locator is the AC#1 cornerstone
//! (decentralized RESOLUTION on the test network), not the AC#2 NAT story.

use std::sync::Arc;

use async_trait::async_trait;
use libp2p::PeerId;
use peer_fabric::{
    DialInfo, Disclosed, Exposure, ExposureLedger, ExposureSurface, Lookup, NodeId, NodeLocator,
    Recipient, ResolutionPolicy, Unavailable,
};

use crate::keys::peer_id_of_provider;
use crate::swarm::{QueryFail, SwarmHandle};

/// The kad-backed [`NodeLocator`]. Holds a [`SwarmHandle`] to drive peer-routing and the
/// shared [`ExposureLedger`] every capability appends to.
pub struct Libp2pNodeLocator {
    handle: SwarmHandle,
    ledger: Arc<ExposureLedger>,
}

impl Libp2pNodeLocator {
    /// A locator driving `handle`, recording disclosures to `ledger`.
    pub fn new(handle: SwarmHandle, ledger: Arc<ExposureLedger>) -> Self {
        Libp2pNodeLocator { handle, ledger }
    }

    /// The active kad peer-routing resolution (PublicInfrastructure). Kept separate so the
    /// routing-bar short-circuit and the ledger disclosure live in one place.
    async fn locate_via_dht(&self, peer: PeerId) -> Lookup<DialInfo> {
        // A peer-routing query over an EMPTY routing table is not authoritative: a Miss
        // would be a lie (we simply are not on the network to ask). Fail it as Unavailable,
        // distinct from a healthy "the DHT knows no address" - mirrors the directory's
        // total-routing bar (and shares its honest limit: this is a total-routing bar, not
        // a peers-near-the-key bar; TASK-153 tracks tightening it).
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
            Ok(addrs) if !addrs.is_empty() => {
                // The frozen seam treats DialInfo locations as OPAQUE strings; for libp2p
                // they are Multiaddr strings, reparsed inside the fabric when dialing.
                Lookup::Found(DialInfo::new(
                    addrs.into_iter().map(|addr| addr.to_string()),
                ))
            }
            // A healthy, completed query that learned no address for the target: an
            // authoritative "no address known right now", distinct from could-not-consult.
            Ok(_) => Lookup::Miss,
            Err(QueryFail::Timeout) => Lookup::Unavailable(Unavailable::DeadlineExceeded),
            Err(QueryFail::Backend(why)) => Lookup::Unavailable(Unavailable::Backend(why)),
        }
    }
}

#[async_trait]
impl NodeLocator for Libp2pNodeLocator {
    async fn locate(&self, node: &NodeId, policy: &ResolutionPolicy) -> Lookup<DialInfo> {
        // The provider identity IS an ed25519 verifying key; derive the libp2p PeerId it
        // MUST correspond to. A non-point key can never be dialed over libp2p - fail it as
        // could-not-consult (a malformed target, not a healthy absence).
        let peer = match peer_id_of_provider(node) {
            Some(peer) => peer,
            None => {
                return Lookup::Unavailable(Unavailable::Backend(format!(
                    "node {node} is not a valid ed25519 peer id; cannot resolve over libp2p"
                )));
            }
        };

        match policy {
            // No third party is consulted, so nothing is disclosed. This backend has no
            // statically-configured peer address book yet (TASK-168), so there is no source
            // to answer from: a genuine Miss, never a fabricated address.
            ResolutionPolicy::ExplicitPeersOnly => Lookup::Miss,
            ResolutionPolicy::PublicInfrastructure => self.locate_via_dht(peer).await,
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
