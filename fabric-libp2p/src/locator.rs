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
//!     provider that is NOT directly reachable, a `/p2p-circuit`
//!     dial-address CONSTRUCTED from a relay this node knows via bootstrap config (a NAT'd
//!     provider is reachable only THROUGH its relay; disclosing to that relay operator that we
//!     relay to the target, also recorded). "Directly reachable" is decided by OBSERVED
//!     reachability, not by the address alone (TASK-221): a PUBLIC IP or LOOPBACK address is
//!     directly reachable a-priori; a provider kad could only place at PRIVATE (RFC1918) /
//!     link-local addresses is PROBED — a bounded direct dial — because such an address is
//!     directly reachable when the provider is on our OWN LAN (same-LAN) but NOT across a NAT,
//!     and the two are indistinguishable from the address alone. A same-LAN provider whose
//!     probe connects DIRECTLY composes NO circuit and records NO Relay disclosure (the
//!     over-disclosure TASK-218 accepted is now suppressed); a cross-NAT provider (probe never
//!     reaches it) or an addressless one still composes the circuit (the nat-vm-test 192.168.x
//!     cornerstone). Returns [`Lookup::Found`] when the union is
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
use std::time::Duration;

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
    ///   2. relay-circuit composition - for a provider that is NOT DIRECTLY REACHABLE (a PUBLIC
    ///      IP or LOOPBACK is directly reachable a-priori and does NOT compose; a provider placed
    ///      ONLY at PRIVATE/link-local addresses is PROBED via a bounded direct dial — TASK-221 —
    ///      composing only if the probe never reaches it directly, i.e. it is across a NAT rather
    ///      than on our own LAN; an addressless provider composes without a probe), and when this
    ///      node knows relays from bootstrap config, we CONSTRUCT
    ///      `<relayAddr>/p2p/<relayPeer>/p2p-circuit/p2p/<providerPeer>` for each known relay.
    ///      This is the standard circuit-v2 dial pattern, not injection (the provider PeerId
    ///      came from kad; the relays are provider-INDEPENDENT config). Composing candidates
    ///      dials THROUGH the relay, which discloses to that relay operator that we relay to
    ///      this provider - recorded as `OurNodeId->Relay`, and ONLY when candidates are
    ///      actually added (so a localhost / public / same-LAN provider records NO Relay
    ///      disclosure).
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

        // --- Provenance 2: relay-circuit composition (TASK-218, refined by TASK-221). ---
        // `circuit_provenance` couples the whole chain in ONE place (probe -> reachability
        // verdict -> compose? -> record?), so the privacy invariant "a /p2p-circuit in the
        // resolved dial set <=> exactly one Relay disclosure" holds over the UNION it will dial,
        // not just over what THIS node composed (F2).
        let circuit_locations = self.circuit_provenance(peer, &dht_addrs).await;

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

    /// Provenance 2 as ONE coupled decision (TASK-218 / TASK-221): decide reachability, compose
    /// the `/p2p-circuit` candidates if warranted, and record the Relay disclosure — all here, so
    /// a caller cannot suppress the circuit without ALSO dropping the disclosure and vice-versa
    /// (the F1 coupling). Returns the candidates THIS node composed (empty when the provider is
    /// directly reachable, when no relay is known, or when there is nothing to probe).
    ///
    /// Reachability is decided by OBSERVATION, not the address alone:
    ///   * a PUBLIC IP or LOOPBACK address (::1 / 127.0.0.0/8) is directly reachable a-priori —
    ///     you never need a relay to reach a public host or localhost, so composing one is a
    ///     gratuitous over-disclosure to the relay operator (a tracked privacy axis);
    ///   * a provider placed ONLY at PRIVATE (RFC1918) / link-local addresses is AMBIGUOUS: it is
    ///     directly reachable on OUR OWN LAN (same-LAN) but not across a NAT, and the address
    ///     alone cannot tell those apart. So we PROBE — a bounded direct dial. A same-LAN provider
    ///     connects DIRECTLY within the budget and composes NO circuit (the over-disclosure
    ///     TASK-218 accepted is now suppressed); a cross-NAT provider is never reached directly and
    ///     DOES compose (the real-NAT cornerstone). Observing reachability — not a subnet heuristic
    ///     — cannot be fooled by two NATs numbering their LANs identically (RFC1918 collision), and
    ///     a too-short probe only forgoes the privacy win (falls back to composing), never the
    ///     cornerstone.
    ///   * an ADDRESSLESS provider (kad placed it nowhere) has nothing to probe — the NAT symptom —
    ///     so it composes without a probe.
    ///
    /// DCUtR EDGE (F3): `probe_direct_reachable` reports `ConnPath::Direct`, which is also what a
    /// relayed connection that DCUtR has hole-punched to a real direct connection reads as (the
    /// upgraded link is genuinely non-relayed). So a provider whose relay circuit was hole-punched
    /// to direct — before this probe, or within its window — is seen as directly reachable and its
    /// circuit is suppressed. This is SAFE: a hole-punched connection IS a direct path, the fabric
    /// reuses that live connection by PeerId for the fetch (it dials by PeerId, and an open
    /// connection is reused rather than re-dialing the suppressed RFC1918 addr), and if that
    /// connection drops before the fetch the fetch simply fails and RETRIES, re-composing the
    /// circuit — it can NEVER yield a bad store path, only cost a retry. We deliberately do NOT try
    /// to distinguish a hole-punched-from-relay `Direct` from a native-LAN `Direct`: it would need
    /// new per-connection provenance bookkeeping in the swarm, and a hole-punched direct connection
    /// is arguably the RIGHT thing to prefer over the relay anyway (it already avoids the relay).
    /// The nat-vm cornerstone does not exercise this (DCUtR fails there and the link stays relayed).
    async fn circuit_provenance(&self, peer: PeerId, dht_addrs: &[Multiaddr]) -> Vec<Multiaddr> {
        let reachable_directly = if addrs_include_directly_reachable(dht_addrs) {
            true
        } else if !self.known_relays.is_empty() && !dht_addrs.is_empty() {
            // Identity-check each probe target so a wrong host at a colliding private address
            // cannot masquerade as the provider (its handshake peer id would not match).
            let targets: Vec<Multiaddr> = dht_addrs
                .iter()
                .map(|addr| with_peer_id(addr, peer))
                .collect();
            self.handle
                .probe_direct_reachable(peer, &targets, DIRECT_PROBE_BUDGET)
                .await
        } else {
            // No relays to compose anyway, or nothing to probe: skip the probe latency.
            false
        };
        self.circuit_from_verdict(peer, dht_addrs, reachable_directly)
    }

    /// The LOCATOR's USE of the reachability `verdict` (F5), split out so BOTH directions are
    /// unit-couplable with an INJECTED verdict — a hermetic reachable-PRIVATE address cannot be
    /// bound on a test host, so `circuit_provenance`'s real probe can only ever produce
    /// verdict=false for a private address in a test. Here the verdict is a parameter, so a test
    /// drives verdict=true (a same-LAN private provider the probe DID reach) and asserts the
    /// locator SUPPRESSES the circuit and records NO disclosure, and verdict=false and asserts it
    /// composes + discloses. This is the load-bearing positive-direction coupling: if the locator's
    /// use of the verdict is broken (composes despite verdict=true), the over-disclosure TASK-221
    /// removes comes back and the verdict=true test reddens.
    fn circuit_from_verdict(
        &self,
        peer: PeerId,
        dht_addrs: &[Multiaddr],
        reachable_directly: bool,
    ) -> Vec<Multiaddr> {
        let composed = compose_circuit_candidates(&self.known_relays, peer, reachable_directly);
        self.record_relay_if_circuit_dialed(dht_addrs, &composed);
        composed
    }

    /// The END-TO-END privacy invariant (F2): dialing THROUGH a relay — a `/p2p-circuit` ANYWHERE
    /// in the resolved dial set, whether WE composed it (cross-NAT) or one arrived among the
    /// DHT-provided addresses — discloses to that relay operator that we relay to this provider.
    /// Recording on the UNION (`dht_addrs` + `composed`), not just our composed set, closes a
    /// circuit-WITHOUT-disclosure under-count. This is LOAD-BEARING, not merely defensive: kad
    /// PEER-ROUTING (separate from the `ProviderRecord`, which carries no dial address) feeds a
    /// target's identify listen addresses into the routing table UNFILTERED and returns them from
    /// `get_closest_peers` (`swarm.rs`, identify->kad `add_address` and the `GetClosestPeers`
    /// `info.addrs`), so a provider that advertises a `/p2p-circuit` listen address CAN surface one
    /// in `dht_addrs`. That the harness provider currently advertises only a direct addr is OBSERVED
    /// behaviour, not a frozen-schema guarantee — so the union-record here (with
    /// [`addr_is_directly_reachable`] refusing to classify a circuit as directly reachable) is what
    /// keeps "circuit dialed <=> Relay disclosed" true on that reachable path.
    fn record_relay_if_circuit_dialed(&self, dht_addrs: &[Multiaddr], composed: &[Multiaddr]) {
        let dials_via_circuit = dht_addrs
            .iter()
            .chain(composed.iter())
            .any(is_circuit_multiaddr);
        if dials_via_circuit {
            self.ledger
                .record(Exposure::new(Recipient::Relay, Disclosed::OurNodeId));
        }
    }
}

/// How long the TASK-221 same-LAN probe (`probe_direct_reachable`) waits for a DIRECT
/// connection before concluding a private-addressed provider is across a NAT and composing the
/// relay circuit. SHORT and integer (owner no-floats rule): a same-LAN provider connects in a
/// few RTT so the common case returns fast; a cross-NAT provider is never reached and spends
/// this full budget once, on the LOCATE, before falling back to the circuit — it HARD-bounds the
/// whole probe (a `tokio::time::timeout` wraps the fast-path + dials + poll), well inside the fetch
/// envelope. On the nat-vm's 600s budgets this is negligible, and a too-short value only forgoes
/// the privacy win (it falls back to composing), never the cornerstone.
const DIRECT_PROBE_BUDGET: Duration = Duration::from_millis(2000);

/// Append `/p2p/<peer>` to `addr` for an identity-checked dial, unless it already ends in a
/// `/p2p/<x>` component. Used to build TASK-221 probe targets so libp2p verifies the dialed
/// host really is `peer` (a wrong host at a colliding private address fails the handshake and
/// never registers as a DIRECT connection to `peer`).
fn with_peer_id(addr: &Multiaddr, peer: PeerId) -> Multiaddr {
    if matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
        addr.clone()
    } else {
        let mut out = addr.clone();
        out.push(Protocol::P2p(peer));
        out
    }
}

/// Is `addr` a `/p2p-circuit` (relay) multiaddr? A circuit dial goes THROUGH a relay operator,
/// so it is never a direct path and always incurs a Relay disclosure — [`circuit_provenance`]
/// keys the end-to-end privacy invariant on this, and [`addr_is_directly_reachable`] uses it to
/// refuse to classify a circuit as directly reachable (F2).
fn is_circuit_multiaddr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
}

/// Compose the `/p2p-circuit` dial candidates for `provider` (TASK-218 / TASK-221): one per known
/// relay, `<relayTransportAddr>/p2p/<relayPeer>/p2p-circuit/p2p/<providerPeer>`, IFF this node
/// knows relays AND the provider is NOT directly reachable (`reachable_directly` is the caller's
/// observed verdict). Returns empty otherwise. PURE — it records nothing; the single Relay
/// disclosure is recorded by [`circuit_provenance`] over the whole resolved dial set, so
/// "composed nothing" and "recorded nothing" cannot drift apart. Any trailing `/p2p/<x>` and any
/// stray `/p2p-circuit` on the configured relay address are stripped first, so the composed
/// address carries exactly ONE relay-peer component and ONE circuit hop.
fn compose_circuit_candidates(
    known_relays: &[(PeerId, Multiaddr)],
    provider: PeerId,
    reachable_directly: bool,
) -> Vec<Multiaddr> {
    if known_relays.is_empty() || reachable_directly {
        return Vec::new();
    }
    known_relays
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

/// Does any address let the consumer reach the provider DIRECTLY, without a relay (TASK-218
/// SHOULD-filter)? A provider with such an address must NOT trigger relay-circuit composition
/// (composing one is a gratuitous Relay over-disclosure). "Directly reachable" = a PUBLIC IP OR
/// a LOOPBACK address (same host - always self-reachable). Deliberately NOT counted here: a
/// private-LAN address (unreachable across a NAT - the cornerstone case that MUST compose) and
/// an addressless / `/dns*` result. Used to decide whether the provider looks NAT'd (no directly
/// reachable address) and therefore warrants a circuit. Pure integer classification.
fn addrs_include_directly_reachable(addrs: &[Multiaddr]) -> bool {
    addrs.iter().any(addr_is_directly_reachable)
}

/// A single multiaddr is DIRECTLY reachable if its FIRST `Ip4`/`Ip6` component is a PUBLIC IP or
/// a LOOPBACK address. A `/dns*`-addressed provider (no IP literal) is treated as NOT directly
/// reachable, so we may over-compose a circuit + record one Relay disclosure for a DNS-named
/// public provider - a tolerable wasted dial (the direct dns dial still wins), never a wrong
/// answer. A `/p2p-circuit` multiaddr is NEVER directly reachable regardless of its leading IP
/// (F2b): its first IP is the RELAY's, so a public-relay circuit would otherwise be mis-read as a
/// direct dial and skip both the probe and the Relay disclosure — a circuit dial is a relay dial.
fn addr_is_directly_reachable(addr: &Multiaddr) -> bool {
    if is_circuit_multiaddr(addr) {
        return false;
    }
    for p in addr.iter() {
        match p {
            Protocol::Ip4(ip) => return ip.is_loopback() || ipv4_is_public(ip),
            Protocol::Ip6(ip) => return ip.is_loopback() || ipv6_is_public(ip),
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

#[cfg(test)]
mod ip_classification_tests {
    use super::{addr_is_directly_reachable, ipv4_is_public, ipv6_is_public};
    use crate::Multiaddr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// TASK-218 finding 1 (loopback exclusion): a DIRECTLY-REACHABLE provider must NOT trigger
    /// relay-circuit composition (composing one is a gratuitous Relay over-disclosure that the
    /// daemon production-path disclosure oracle trips on). Loopback (self-reachable) and public
    /// addresses are directly reachable; a PRIVATE (RFC1918) address is NOT (unreachable across
    /// a NAT - the cornerstone case that must still compose).
    #[test]
    fn directly_reachable_excludes_loopback_and_public_but_not_private() {
        for a in [
            "/ip4/127.0.0.1/tcp/4001", // loopback (the e2e production-path provider)
            "/ip6/::1/tcp/4001",       // loopback v6
            "/ip4/8.8.8.8/tcp/4001",   // public
            "/ip6/2606:4700:4700::1111/tcp/4001", // public v6
        ] {
            let m: Multiaddr = a.parse().unwrap();
            assert!(
                addr_is_directly_reachable(&m),
                "{a} is directly reachable -> must NOT compose a circuit"
            );
        }
        for a in [
            "/ip4/192.168.2.3/tcp/4001", // private (the NAT VM provider) -> must compose
            "/ip4/10.1.2.3/tcp/4001",    // private
            "/dns4/example.com/tcp/4001", // no IP literal -> treated as not directly reachable
        ] {
            let m: Multiaddr = a.parse().unwrap();
            assert!(
                !addr_is_directly_reachable(&m),
                "{a} is NOT directly reachable -> a NAT'd provider that must compose a circuit"
            );
        }
    }

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

#[cfg(test)]
mod circuit_compose_tests {
    //! TASK-221 — the PURE compose decision + address classification (no network). The DISCLOSURE
    //! side (which is coupled to the compose decision AND the probe in `circuit_provenance`) is
    //! exercised end to end in `circuit_provenance_tests` below.
    use super::{
        addr_is_directly_reachable, compose_circuit_candidates, is_circuit_multiaddr, with_peer_id,
    };
    use crate::{Multiaddr, PeerId, Protocol};

    fn relay_set() -> Vec<(PeerId, Multiaddr)> {
        vec![(
            PeerId::random(),
            "/ip4/203.0.113.7/tcp/4001".parse().unwrap(),
        )]
    }

    /// A directly-reachable provider (`reachable_directly = true`) composes NOTHING; a
    /// non-directly-reachable one composes one `/p2p-circuit` per known relay; no relays composes
    /// nothing regardless.
    #[test]
    fn compose_gates_on_reachability_and_known_relays() {
        let provider = PeerId::random();
        assert!(compose_circuit_candidates(&relay_set(), provider, true).is_empty());
        assert!(compose_circuit_candidates(&[], provider, false).is_empty());
        let composed = compose_circuit_candidates(&relay_set(), provider, false);
        assert_eq!(composed.len(), 1);
        assert!(is_circuit_multiaddr(&composed[0]));
    }

    /// F2(b): a `/p2p-circuit` multiaddr is NEVER directly reachable — even one whose leading IP is
    /// PUBLIC (the relay's) — so it can never skip the probe/compose and dodge a Relay disclosure.
    #[test]
    fn a_circuit_multiaddr_is_never_directly_reachable_even_with_a_public_relay_ip() {
        let relay = PeerId::random();
        let provider = PeerId::random();
        let public_circuit: Multiaddr =
            format!("/ip4/8.8.8.8/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{provider}")
                .parse()
                .unwrap();
        assert!(is_circuit_multiaddr(&public_circuit));
        assert!(
            !addr_is_directly_reachable(&public_circuit),
            "a /p2p-circuit is a RELAY path, never directly reachable, regardless of its first IP"
        );
        // The plain public IP underneath IS directly reachable — the circuit wrapper is what flips it.
        assert!(addr_is_directly_reachable(
            &"/ip4/8.8.8.8/tcp/4001".parse().unwrap()
        ));
    }

    /// `with_peer_id` appends an identity check for the probe dial, idempotent when the address
    /// already carries a `/p2p/<x>` tail.
    #[test]
    fn with_peer_id_appends_identity_once() {
        let peer = PeerId::random();
        let bare: Multiaddr = "/ip4/192.168.3.9/tcp/4001".parse().unwrap();
        let checked = with_peer_id(&bare, peer);
        assert_eq!(
            checked
                .iter()
                .filter(|p| matches!(p, Protocol::P2p(_)))
                .count(),
            1
        );
        assert!(matches!(checked.iter().last(), Some(Protocol::P2p(p)) if p == peer));
        assert_eq!(with_peer_id(&checked, PeerId::random()), checked);
    }
}

#[cfg(test)]
mod circuit_provenance_tests {
    //! TASK-221 — the COUPLED chain, asserted on the DISCLOSURE (ledger): probe result -> the
    //! locator's reachability verdict -> circuit composed? -> Relay disclosure recorded?, driven
    //! through the REAL `Libp2pNodeLocator::circuit_provenance` over a live consumer swarm. These
    //! bite the CALLER's suppression decision, not just a helper fed a literal verdict (F1). A
    //! reachable PRIVATE provider (probe TRUE -> suppress) cannot be bound hermetically on a test
    //! host, so the suppress side is covered here via the BY-ADDRESS branch (a reachable loopback
    //! provider) plus the swarm probe-TRUE test in `tests/direct_reachability_probe.rs`; the
    //! cross-NAT NON-suppression is proven end to end in `nixos/nat-vm-test.nix`.
    use std::sync::Arc;

    use super::{DIRECT_PROBE_BUDGET, Libp2pNodeLocator};
    use crate::swarm::Node;
    use crate::{Multiaddr, NodeConfig, PeerId};
    use peer_fabric::{ExposureLedger, Recipient};

    fn relay_disclosures(ledger: &ExposureLedger) -> usize {
        ledger
            .entries()
            .iter()
            .filter(|e| e.to == Recipient::Relay)
            .count()
    }

    async fn consumer(
        seed: [u8; 32],
        known_relays: Vec<(PeerId, Multiaddr)>,
    ) -> (Node, Arc<ExposureLedger>, Libp2pNodeLocator) {
        let node = Node::start(NodeConfig::new(seed).with_network_scope("task221-provenance"))
            .expect("consumer node starts");
        let ledger = Arc::new(ExposureLedger::new());
        let locator = Libp2pNodeLocator::new(
            node.handle.clone(),
            ledger.clone(),
            std::collections::BTreeMap::new(),
            known_relays,
        );
        (node, ledger, locator)
    }

    /// F1 COUPLED BITE: an UNREACHABLE private provider drives the REAL probe FALSE, so the locator
    /// composes the circuit AND records the Relay disclosure. MUTATION in the CALLER (force the
    /// reachability verdict true / skip the probe / suppress regardless) -> circuit suppressed +
    /// NO disclosure for an unreachable provider -> this test reddens. The budget bounds the wait.
    #[tokio::test]
    async fn unreachable_private_provider_composes_and_discloses_through_the_real_locator() {
        let relay = (
            PeerId::random(),
            "/ip4/203.0.113.7/tcp/4001".parse().unwrap(),
        );
        let (_node, ledger, locator) = consumer([31u8; 32], vec![relay]).await;
        let provider = PeerId::random();
        // TEST-NET-1 192.0.2.0/24: private-class, reserved, never routed -> the probe cannot reach it.
        let dht_addrs: Vec<Multiaddr> = vec!["/ip4/192.0.2.9/tcp/4001".parse().unwrap()];

        let composed = locator.circuit_provenance(provider, &dht_addrs).await;

        assert_eq!(
            composed.len(),
            1,
            "an UNREACHABLE (cross-NAT) provider MUST compose the relay circuit"
        );
        assert_eq!(
            relay_disclosures(&ledger),
            1,
            "composing the circuit MUST record exactly one OurNodeId->Relay disclosure"
        );
    }

    /// SUPPRESS side through the real locator (by-address branch): a reachable LOOPBACK provider is
    /// classified directly reachable, so the locator composes NO circuit and records NO Relay
    /// disclosure. MUTATION (classify loopback as non-reachable / force compose) -> a circuit +
    /// disclosure appear for a directly-reachable provider -> reddens.
    #[tokio::test]
    async fn directly_reachable_provider_suppresses_circuit_and_discloses_nothing() {
        let relay = (
            PeerId::random(),
            "/ip4/203.0.113.7/tcp/4001".parse().unwrap(),
        );
        let (_node, ledger, locator) = consumer([32u8; 32], vec![relay]).await;
        let provider = PeerId::random();
        let dht_addrs: Vec<Multiaddr> = vec!["/ip4/127.0.0.1/tcp/4001".parse().unwrap()];

        let composed = locator.circuit_provenance(provider, &dht_addrs).await;

        assert!(
            composed.is_empty(),
            "a directly-reachable (loopback) provider MUST NOT compose a circuit"
        );
        assert_eq!(
            relay_disclosures(&ledger),
            0,
            "a directly-reachable provider MUST record NO Relay disclosure (the privacy win)"
        );
    }

    /// F2 END-TO-END INVARIANT: a `/p2p-circuit` that arrives among the DHT-provided addresses
    /// (even with NO known relay, so this node composes nothing) still records a Relay disclosure —
    /// dialing THROUGH a relay is disclosed however the circuit entered the resolved dial set.
    /// MUTATION (record only over what WE composed, not the union) -> a DHT-provided circuit dials
    /// a relay with NO disclosure -> reddens.
    #[tokio::test]
    async fn a_dht_provided_circuit_records_a_relay_disclosure_even_when_we_compose_nothing() {
        let (_node, ledger, locator) = consumer([33u8; 32], Vec::new()).await;
        let relay = PeerId::random();
        let provider = PeerId::random();
        let dht_circuit: Multiaddr =
            format!("/ip4/8.8.8.8/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{provider}")
                .parse()
                .unwrap();

        let composed = locator.circuit_provenance(provider, &[dht_circuit]).await;

        assert!(
            composed.is_empty(),
            "no known relay -> we compose nothing; the circuit came from the DHT set"
        );
        assert_eq!(
            relay_disclosures(&ledger),
            1,
            "a DHT-provided /p2p-circuit in the dial set MUST still record a Relay disclosure"
        );
    }

    /// F5 POSITIVE-DIRECTION COUPLING: the locator's USE of a verdict=TRUE for a genuinely
    /// reachable PRIVATE provider SUPPRESSES the circuit and records NO disclosure (the exact
    /// over-disclosure TASK-221 removes). Driven through the real `circuit_from_verdict` with an
    /// injected verdict because a reachable private address cannot be bound hermetically.
    /// MUTATION: the locator ignoring the verdict (composing despite verdict=true — e.g.
    /// `compose_circuit_candidates(.., false)`) -> a circuit + disclosure appear for a reachable
    /// same-LAN provider -> this test reddens.
    #[tokio::test]
    async fn reachable_private_verdict_suppresses_circuit_and_discloses_nothing() {
        let relay = (
            PeerId::random(),
            "/ip4/203.0.113.7/tcp/4001".parse().unwrap(),
        );
        let (_node, ledger, locator) = consumer([34u8; 32], vec![relay]).await;
        let provider = PeerId::random();
        // A PRIVATE (RFC1918) same-LAN address the probe DID reach -> verdict = true.
        let dht_addrs: Vec<Multiaddr> = vec!["/ip4/192.168.3.9/tcp/4001".parse().unwrap()];

        let composed = locator.circuit_from_verdict(provider, &dht_addrs, true);

        assert!(
            composed.is_empty(),
            "a REACHABLE same-LAN private provider (verdict=true) MUST NOT compose a circuit — \
             that is the TASK-221 over-disclosure we remove"
        );
        assert_eq!(
            relay_disclosures(&ledger),
            0,
            "a reachable same-LAN private provider MUST record NO Relay disclosure"
        );
    }

    /// F5 NEGATIVE-DIRECTION COUPLING (the mirror): the SAME private provider with verdict=FALSE
    /// (probe did NOT reach it — cross-NAT) composes the circuit + records exactly one disclosure.
    /// MUTATION: the locator ignoring the verdict the OTHER way (always suppress — e.g.
    /// `compose_circuit_candidates(.., true)`) -> a cross-NAT provider gets no circuit -> reddens.
    #[tokio::test]
    async fn unreachable_private_verdict_composes_circuit_and_discloses_once() {
        let relay = (
            PeerId::random(),
            "/ip4/203.0.113.7/tcp/4001".parse().unwrap(),
        );
        let (_node, ledger, locator) = consumer([35u8; 32], vec![relay]).await;
        let provider = PeerId::random();
        let dht_addrs: Vec<Multiaddr> = vec!["/ip4/192.168.3.9/tcp/4001".parse().unwrap()];

        let composed = locator.circuit_from_verdict(provider, &dht_addrs, false);

        assert_eq!(
            composed.len(),
            1,
            "a NON-reachable (cross-NAT) private provider (verdict=false) MUST compose the circuit"
        );
        assert_eq!(
            relay_disclosures(&ledger),
            1,
            "composing the circuit MUST record exactly one Relay disclosure"
        );
    }

    // Keep `DIRECT_PROBE_BUDGET` referenced so a future refactor that drops the bound trips here.
    #[test]
    fn probe_budget_is_a_short_integer_bound() {
        assert!(DIRECT_PROBE_BUDGET.as_millis() > 0 && DIRECT_PROBE_BUDGET.as_secs() <= 5);
    }
}
