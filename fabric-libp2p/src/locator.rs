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
//!   * [`ResolutionPolicy::PublicInfrastructure`] - a UNION of two independent dial-candidate
//!     provenances (TASK-218): the active kad peer-routing query (which discloses this node's
//!     identity to the DHT nodes / bootstrap it contacts, recorded to the ledger) AND, for a
//!     provider kad could only place at non-public addresses (or not at all), a `/p2p-circuit`
//!     dial-address CONSTRUCTED from a relay this node knows via bootstrap config (a NAT'd
//!     provider is reachable only THROUGH its relay; disclosing to that relay operator that we
//!     relay to the target, also recorded). Returns [`Lookup::Found`] when the union is
//!     non-empty - so `Found` means "at least one dial candidate exists, from DHT peer-routing
//!     AND/OR permitted relay-circuit composition", NOT "learned exclusively through the DHT".
//!     When NEITHER provenance yields a candidate it returns the kad walk's OWN honest verdict:
//!     [`Lookup::Miss`] when a query that reached responding peers near the key knows no
//!     address, and [`Lookup::Unavailable`] when the mechanism could not be consulted
//!     (`InsufficientRouting` when the peer-routing walk reached NO responding peer - either an
//!     empty routing table or one of only dead entries, gated on the near-key
//!     [`crate::QueryReach`], TASK-174; `DeadlineExceeded` on timeout). See
//!     [`crate::QueryReach`] for the honest limit of the `Miss` direction: reaching this
//!     node's REACHABLE subgraph is not proof of reaching the target's global custodians
//!     (an inherent single-node-view partition/eclipse residue). GENERALITY LIMIT: the
//!     relay-circuit provenance only resolves a provider that reserved on a relay THIS node
//!     already knows from config (the single shared-relay case); the multi-relay case is
//!     the filed follow-up TASK-219.
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
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use async_trait::async_trait;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
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
    /// Relays this node knows from bootstrap/relay config (TASK-218): each a libp2p
    /// [`PeerId`] + its direct transport [`Multiaddr`]. Used ON THE
    /// [`ResolutionPolicy::PublicInfrastructure`] path to CONSTRUCT a `/p2p-circuit`
    /// dial-address for a provider discovered via kad `get_providers` (composed
    /// `<relayAddr>/p2p/<relayPeer>/p2p-circuit/p2p/<providerPeer>`). This is a
    /// CONFIG-LEVEL, provider-INDEPENDENT set - the SAME relays for every provider - so it
    /// is dial-assistance, never a per-provider address injection: the provider identity
    /// still comes ONLY from kad. Empty by default (no relay known -> no circuit composed).
    known_relays: Vec<(PeerId, Multiaddr)>,
}

impl Libp2pNodeLocator {
    /// A locator driving `handle`, recording disclosures to `ledger`, answering
    /// [`ResolutionPolicy::ExplicitPeersOnly`] from the static `peer_address_book` (a
    /// provider [`NodeId`] -> its dialable location strings), and composing `/p2p-circuit`
    /// dial-addresses on the [`ResolutionPolicy::PublicInfrastructure`] path from
    /// `known_relays` (TASK-218). Pass empties for a node with no explicit peers / no
    /// known relays.
    pub fn new(
        handle: SwarmHandle,
        ledger: Arc<ExposureLedger>,
        peer_address_book: BTreeMap<NodeId, Vec<String>>,
        known_relays: Vec<(PeerId, Multiaddr)>,
    ) -> Self {
        Libp2pNodeLocator {
            handle,
            ledger,
            peer_address_book,
            known_relays,
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

    /// The active PublicInfrastructure resolution: a UNION of two INDEPENDENT dial-candidate
    /// provenances (TASK-218, mped-architect ruling), each honest about what it did:
    ///
    ///   1. the kad peer-routing walk (`get_closest_peers`) - the addresses the DHT learned
    ///      for the target; it keeps its OWN [`crate::QueryReach`] classification and its own
    ///      `OurNodeId->DhtNode` ledger disclosure EXACTLY as before, and records NO
    ///      disclosure when the routing table is empty (no query happened);
    ///   2. relay-circuit composition - for a provider that kad could only place at
    ///      non-public (loopback/private/link-local) addresses, or not at all, and when this
    ///      node knows relays from bootstrap config, we CONSTRUCT
    ///      `<relayAddr>/p2p/<relayPeer>/p2p-circuit/p2p/<providerPeer>` for each known relay.
    ///      This is the standard circuit-v2 dial pattern, not injection (the provider PeerId
    ///      came from kad; the relays are provider-INDEPENDENT config). Composing candidates
    ///      dials THROUGH the relay, which discloses to that relay operator that we relay to
    ///      this provider - recorded as `OurNodeId->Relay`, and ONLY when candidates are
    ///      actually added.
    ///
    /// [`Lookup::Found`] iff the union is non-empty; otherwise the DHT walk's OWN honest
    /// absence ([`Lookup::Miss`] / [`Unavailable`]). So `Found` here means "at least one
    /// dial candidate exists, from DHT peer-routing AND/OR permitted relay-circuit
    /// composition" - NOT "learned exclusively through the DHT".
    async fn locate_via_dht(&self, peer: PeerId) -> Lookup<DialInfo> {
        // --- Provenance 1: the kad peer-routing walk (unchanged honesty). ---
        // A peer-routing query over an EMPTY routing table is not authoritative: a Miss
        // would be a lie (we simply are not on the network to ask). This cheap pre-check
        // short-circuits the query, recording NO ledger disclosure (no query touched the
        // network). The FINER near-key bar (TASK-174) is applied on the QueryReach an actual
        // walk achieved. `dht_addrs` are the DHT-learned addresses; `dht_absence` is the
        // honest Lookup to fall back to if NEITHER provenance yields a candidate.
        let (dht_addrs, dht_absence): (Vec<Multiaddr>, Lookup<DialInfo>) =
            if self.handle.routing_peers().await == 0 {
                (
                    Vec::new(),
                    Lookup::Unavailable(Unavailable::InsufficientRouting),
                )
            } else {
                // We are about to actually consult the DHT: record the disclosure HERE, after
                // the short-circuit, so a query that never touched the network does not
                // pollute the ledger. An active peer-routing query reveals OUR identity to the
                // DHT nodes it contacts. HONEST GAP: it also reveals the QUERIED target NodeId
                // to those nodes, but the frozen `peer_fabric::Disclosed` enum models OUR
                // disclosures + ContentKey and has no third-party-NodeId variant (TASK-168).
                self.ledger
                    .record(Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId));
                match self.handle.locate_peer(peer).await {
                    Ok((addrs, _)) if !addrs.is_empty() => (addrs, Lookup::Miss),
                    // A completed query that learned no address: Miss vs InsufficientRouting
                    // turns on the NEAR-KEY bar (TASK-174). `dht_addrs` stays empty.
                    Ok((_, reach)) => (Vec::new(), absence_from_reach(reach)),
                    Err(QueryFail::Timeout) => (
                        Vec::new(),
                        Lookup::Unavailable(Unavailable::DeadlineExceeded),
                    ),
                    Err(QueryFail::Backend(why)) => {
                        (Vec::new(), Lookup::Unavailable(Unavailable::Backend(why)))
                    }
                }
            };

        // --- Provenance 2: relay-circuit composition (TASK-218). ---
        // Compose circuit candidates only when this node knows relays AND kad could NOT
        // place the provider at a plausibly-public address (it returned nothing, or only
        // loopback/private/link-local addrs - the exact NAT symptom). This SHOULD-filter
        // avoids a gratuitous relay dial + Relay disclosure for a genuinely-public provider;
        // both misfire directions are tolerable (over-compose = a wasted dial; under-compose
        // = upstream fallback). Pure integer IP classification, no floats.
        let circuit_locations: Vec<Multiaddr> =
            if !self.known_relays.is_empty() && !addrs_include_public(&dht_addrs) {
                self.compose_circuit_locations(peer)
            } else {
                Vec::new()
            };
        if !circuit_locations.is_empty() {
            // Dialing a provider THROUGH a relay reveals to that relay operator that we relay
            // to this provider. Record it ONLY here, where candidates are actually added, and
            // separately from the DhtNode record above (so the empty-kad -> Found-via-circuit
            // path records Relay-without-DhtNode honestly).
            self.ledger
                .record(Exposure::new(Recipient::Relay, Disclosed::OurNodeId));
        }

        // --- Union. The frozen seam treats DialInfo locations as OPAQUE strings; for libp2p
        // they are Multiaddr strings, reparsed inside the fabric when dialing. ---
        let locations: Vec<String> = dht_addrs
            .iter()
            .chain(circuit_locations.iter())
            .map(|addr| addr.to_string())
            .collect();
        if locations.is_empty() {
            // Neither provenance produced a candidate: return the DHT walk's OWN honest
            // absence (Miss / InsufficientRouting / DeadlineExceeded / Backend).
            dht_absence
        } else {
            Lookup::Found(DialInfo::new(locations))
        }
    }

    /// Construct a `/p2p-circuit` dial-address for `provider` through each known relay:
    /// `<relayTransportAddr>/p2p/<relayPeer>/p2p-circuit/p2p/<providerPeer>` (TASK-218). Any
    /// trailing `/p2p/<x>` AND any stray `/p2p-circuit` on the configured relay address are
    /// stripped first, so the composed address carries exactly ONE relay-peer component and
    /// ONE circuit hop even if a malformed config supplied a circuit-shaped relay addr. A
    /// pure LOCAL construction - it consults no third party (the disclosure is recorded by
    /// the caller only when these are actually added for dialing).
    fn compose_circuit_locations(&self, provider: PeerId) -> Vec<Multiaddr> {
        self.known_relays
            .iter()
            .map(|(relay_peer, relay_addr)| {
                let mut base: Multiaddr = relay_addr
                    .iter()
                    .filter(|p| !matches!(p, Protocol::P2p(_) | Protocol::P2pCircuit))
                    .collect();
                base.push(Protocol::P2p(*relay_peer));
                base.push(Protocol::P2pCircuit);
                base.push(Protocol::P2p(provider));
                base
            })
            .collect()
    }
}

/// Does any address carry a plausibly-PUBLIC IP (TASK-218 SHOULD-filter)? Used to decide
/// whether a provider looks NAT'd (all non-public / no address) and therefore warrants
/// relay-circuit composition. An address with no IP component is treated as non-public (it
/// is not a directly-dialable public transport address). Pure integer classification.
fn addrs_include_public(addrs: &[Multiaddr]) -> bool {
    addrs.iter().any(addr_is_public)
}

/// Classify a single multiaddr as carrying a public IP: the FIRST `Ip4`/`Ip6` component
/// decides. Loopback / RFC1918-private / link-local / unspecified are NON-public (the NAT
/// symptom); everything else is public. A `/dns*`-addressed provider (no IP literal) is
/// treated as non-public, so we may over-compose a circuit + record one Relay disclosure for
/// a DNS-named public provider - a tolerable wasted dial (the direct dns dial still wins),
/// never a wrong answer.
fn addr_is_public(addr: &Multiaddr) -> bool {
    for p in addr.iter() {
        match p {
            Protocol::Ip4(ip) => return ipv4_is_public(ip),
            Protocol::Ip6(ip) => return ipv6_is_public(ip),
            _ => {}
        }
    }
    false
}

/// A v4 address is NON-public if it falls in a non-globally-routable range. This covers the
/// IANA special-purpose ranges that matter for dial-address classification (it is not a claim
/// to enumerate every last IANA registry entry - the tail-anycast/6to4 corners are irrelevant
/// here). Covering carrier-grade NAT 100.64.0.0/10 (RFC 6598) and the class-E 240.0.0.0/4 is
/// load-bearing: a provider behind a CARRIER NAT (or on a reserved address) is NOT directly
/// dialable, so it must still get a relay-circuit candidate composed (PRD risk 8 - "fails
/// behind a real-world NAT"). All checks are integer octet math (no floats, no unstable std).
fn ipv4_is_public(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let non_public = ip.is_loopback()            // 127.0.0.0/8
        || ip.is_private()                       // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()                    // 169.254.0.0/16
        || ip.is_unspecified()                   // 0.0.0.0
        || ip.is_broadcast()                     // 255.255.255.255
        || ip.is_multicast()                     // 224.0.0.0/4
        || o[0] == 0                                   // "this network" 0.0.0.0/8
        || (o[0] & 0xf0) == 0xf0                       // reserved/class-E 240.0.0.0/4 (incl. 255/8)
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40)      // CGNAT 100.64.0.0/10 (RFC 6598)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // IETF protocol assignments 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18)        // benchmarking 198.18.0.0/15
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)     // documentation 192.0.2.0/24
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)  // documentation 198.51.100.0/24
        || (o[0] == 203 && o[1] == 0 && o[2] == 113); // documentation 203.0.113.0/24
    !non_public
}

/// A v6 address is NON-public if loopback (::1), unspecified (::), ULA (fc00::/7),
/// link-local (fe80::/10), multicast (ff00::/8), or documentation (2001:db8::/32). Integer
/// segment math only.
fn ipv6_is_public(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let is_ula = (s[0] & 0xfe00) == 0xfc00;
    let is_link_local = (s[0] & 0xffc0) == 0xfe80;
    let is_documentation = s[0] == 0x2001 && s[1] == 0x0db8;
    let non_public = ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast() // ff00::/8
        || is_ula
        || is_link_local
        || is_documentation;
    !non_public
}

#[cfg(test)]
mod ip_classification_tests {
    use super::{ipv4_is_public, ipv6_is_public};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn v4_non_public_ranges_are_not_public() {
        for ip in [
            "127.0.0.1",       // loopback
            "10.1.2.3",        // private
            "172.16.5.6",      // private
            "192.168.2.3",     // private (the VM provider)
            "169.254.1.1",     // link-local
            "0.0.0.0",         // unspecified
            "255.255.255.255", // broadcast
            "224.0.0.1",       // multicast
            "100.64.0.1",      // CGNAT low edge (RFC 6598)
            "100.127.255.255", // CGNAT high edge
            "198.18.0.1",      // benchmarking
            "198.19.255.255",  // benchmarking
            "192.0.2.5",       // documentation
            "198.51.100.5",    // documentation
            "203.0.113.5",     // documentation
            "0.1.2.3",         // "this network" 0.0.0.0/8
            "192.0.0.8",       // IETF protocol assignments 192.0.0.0/24
            "240.0.0.1",       // reserved/class-E 240.0.0.0/4 low edge
            "254.254.254.254", // reserved/class-E high side
        ] {
            let a: Ipv4Addr = ip.parse().unwrap();
            assert!(!ipv4_is_public(a), "{ip} must be classified non-public");
        }
    }

    #[test]
    fn v4_public_ranges_are_public() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "192.0.3.0",
            "203.0.114.0",
        ] {
            let a: Ipv4Addr = ip.parse().unwrap();
            assert!(ipv4_is_public(a), "{ip} must be classified public");
        }
    }

    #[test]
    fn v6_classification() {
        for ip in [
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
        ] {
            let a: Ipv6Addr = ip.parse().unwrap();
            assert!(!ipv6_is_public(a), "{ip} must be non-public");
        }
        for ip in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            let a: Ipv6Addr = ip.parse().unwrap();
            assert!(ipv6_is_public(a), "{ip} must be public");
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
        // and the bootstrap it contacts; when it composes a relay-circuit dial candidate
        // (TASK-218) it also reveals to the relay operator that we relay to the target. The
        // Relay entry belongs to the superset whether or not any concrete resolve composes a
        // circuit. ExplicitPeersOnly is a strict subset (discloses nothing). See the module
        // note on the queried-NodeId gap (TASK-168).
        ExposureSurface::from_exposures([
            Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId),
            Exposure::new(Recipient::Bootstrap, Disclosed::OurNodeId),
            Exposure::new(Recipient::Relay, Disclosed::OurNodeId),
        ])
    }
}
