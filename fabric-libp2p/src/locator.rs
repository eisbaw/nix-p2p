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
//! Direct coordinates learned by that query are explicitly handed to the transport. Circuit
//! coordinates learned incidentally for the provider are rejected: the provider-to-relay
//! association is authoritative only when it occurs in that provider's exact signed offer.
//!
//! # `ResolutionPolicy` mapping
//!
//!   * [`ResolutionPolicy::PublicInfrastructure`] - resolve in a strict order. First query the
//!     provider through raw kad and retain only direct coordinates. A PUBLIC IP or LOOPBACK is
//!     directly reachable a-priori; PRIVATE/link-local coordinates are probed with a short bound
//!     because they may be same-LAN or cross-NAT (TASK-221). A live direct route returns
//!     immediately and performs zero relay-hint queries. Otherwise, resolve each of the exact
//!     signed offer's at-most-two canonical relay identities through raw kad and compose bounded
//!     transient `/p2p-circuit` candidates. The flat provider-independent `known_relays` rollout
//!     fallback is used only when the signed hint set is actually empty (a legacy record), never
//!     when a non-empty signed set is currently unresolved. The transient candidates
//!     are never inserted into kad or a provider-keyed side cache. Candidate composition itself
//!     records no exposure; the transport records relay use only after selecting the exact live
//!     relayed connection that carries the request. Returns [`Lookup::Found`] when at least one
//!     direct or authorized circuit candidate exists.
//!
//!     Raw provider peer-routing may incidentally open an unsigned circuit connection. Its
//!     observed relay is accounted as an exposure, but it can carry the fetch only when its live
//!     `ConnectedPoint` relay identity matches the current signed/fallback candidate set. Other
//!     relayed connection IDs remain live for concurrent work but cannot carry this request.
//!
//!     When NEITHER provenance yields a candidate it returns the kad walk's OWN honest verdict:
//!     [`Lookup::Miss`] when a query that reached responding peers near the key knows no
//!     address, and [`Lookup::Unavailable`] when the mechanism could not be consulted
//!     (`InsufficientRouting` when the peer-routing walk reached NO responding peer - either an
//!     empty routing table or one of only dead entries, gated on the near-key
//!     [`crate::QueryReach`], TASK-174; `DeadlineExceeded` on timeout). See
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
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use peer_fabric::{
    DialInfo, Disclosed, Exposure, ExposureLedger, ExposureSurface, Lookup, MAX_LIBP2P_RELAY_HINTS,
    NodeId, NodeLocator, Recipient, RelayHints, ResolutionPolicy, Unavailable,
};

use crate::keys::peer_id_of_provider;
use crate::swarm::{ConnPath, QueryFail, SwarmHandle, absence_from_reach};

/// An internal libp2p dial plan. Both direct and circuit candidates are carried only in exact
/// [`libp2p::swarm::dial_opts::DialOpts`] for this fetch; neither is persisted in kad or a
/// provider-keyed side cache. This type stays below the public `NodeLocator` seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Libp2pDialPlan {
    pub(crate) direct: Vec<Multiaddr>,
    pub(crate) circuits: Vec<Multiaddr>,
}

impl Libp2pDialPlan {
    fn into_dial_info(self) -> DialInfo {
        DialInfo::new(
            self.direct
                .into_iter()
                .chain(self.circuits)
                .map(|address| address.to_string()),
        )
    }
}

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

    /// Resolve a signed libp2p offer below the public [`NodeLocator`] seam.
    ///
    /// Provider peer-routing is always attempted first. If it yields no usable direct path, each
    /// relay identity bound into the signed offer is resolved through its own raw kad lookup and
    /// composed into a transient circuit candidate. The provider-independent `known_relays`
    /// configuration is a compatibility fallback only for an actually empty legacy hint set;
    /// it never overrides a non-empty signed set whose relays are currently unresolved.
    pub(crate) async fn locate_libp2p_offer(
        &self,
        node: &NodeId,
        relay_hints: RelayHints,
    ) -> Lookup<Libp2pDialPlan> {
        let peer = match peer_id_of_provider(node) {
            Some(peer) => peer,
            None => {
                return Lookup::Unavailable(Unavailable::Backend(format!(
                    "node {node} is not a valid ed25519 peer id; cannot resolve over libp2p"
                )));
            }
        };
        self.locate_via_dht(peer, relay_hints).await
    }

    async fn locate_via_dht(
        &self,
        peer: PeerId,
        relay_hints: RelayHints,
    ) -> Lookup<Libp2pDialPlan> {
        // Provenance 1: query the provider itself. Only DIRECT coordinates are authoritative on
        // this leg. A provider -> relay binding belongs to the exact signed offer; ambient circuit
        // addresses in raw kad peer-routing are deliberately ignored. They may remain as ambient
        // kad/live-connection facts, but production opens the NAR stream only on the exact
        // ConnectionId selected from this offer, so they cannot substitute for an authorized path.
        // `dht_absence` remains the honest verdict if no direct, signed-hint, or legacy-circuit
        // candidate can be built.
        let (dht_addrs, dht_absence) = self.query_peer_addresses(peer).await;
        let mut direct: Vec<Multiaddr> = dht_addrs
            .iter()
            .filter(|address| !is_circuit_multiaddr(address))
            .cloned()
            .collect();
        canonicalize_addresses(&mut direct);

        // libp2p-kad may dial the exact target while walking its key. If an intermediate peer
        // happened to report an unsigned circuit address, the raw provider lookup can therefore
        // leave one or more RELAYED connections open even though we rejected those addresses.
        // Inspect per-connection relay facts rather than the direct-dominant aggregate path: a
        // direct+relay mixed set still made a real relay disclosure. Ambient routes remain open,
        // but only an offer-authorized exact ConnectionId may carry the later stream.
        let live_relays_after_query = self.handle.connection_relay_peers(peer).await;
        let live_path_after_query = self.handle.connection_path(peer).await;
        if !live_relays_after_query.is_empty() {
            // Record from the OBSERVED connection path, not from the returned addresses: the
            // libp2p-kad multi-source overwrite that motivated TASK-219 can drop the very circuit
            // address whose query-side dial established this connection.
            self.ledger
                .record(Exposure::new(Recipient::Relay, Disclosed::OurNodeId));
            tracing::debug!(
                %peer,
                relays = ?live_relays_after_query,
                "fabric-libp2p: raw provider peer-routing has live relay circuit(s); \
                 route reuse remains gated by the exact offer's signed relay identities"
            );
        }

        // A public/loopback address is directly reachable a-priori. Private addresses are
        // ambiguous, so probe them when any relay route could otherwise be used. `ConnPath::Direct`
        // is the only positive probe verdict; an existing relayed connection cannot suppress
        // hint resolution. This decision happens BEFORE every hint lookup.
        let has_relay_alternative = !relay_hints.is_empty() || !self.known_relays.is_empty();
        let reachable_directly = if live_path_after_query == ConnPath::Direct
            || addrs_include_directly_reachable(&direct)
        {
            true
        } else if has_relay_alternative && !direct.is_empty() {
            let targets: Vec<Multiaddr> = direct
                .iter()
                .map(|address| with_peer_id(address, peer))
                .collect();
            self.handle
                .probe_direct_reachable(peer, &targets, DIRECT_PROBE_BUDGET)
                .await
        } else {
            false
        };
        if reachable_directly {
            // Zero relay queries and zero gratuitous circuit candidates on the direct path.
            // Ambient relay connections coexist; the transport selects/opens an exact direct ID.
            return Lookup::Found(Libp2pDialPlan {
                direct,
                circuits: Vec::new(),
            });
        }

        // Provenance 2: signed exact-record relay identities. RelayHints' private shape already
        // enforces <=2 canonical unique strict identities, so this loop performs at most two raw
        // kad lookups. An unresolved relay is skipped; it never poisons the other hint.
        let has_signed_hints = !relay_hints.is_empty();
        let hinted = self.resolve_hinted_circuits(peer, relay_hints).await;
        let circuits = if !hinted.is_empty() {
            hinted
        } else if has_signed_hints {
            // A signed non-empty set is authoritative even when every member is dead/unresolved.
            // Falling back here would let a provider-independent ambient relay replace the exact
            // signed provider->relay binding.
            Vec::new()
        } else {
            // TASK-218 compatibility fallback for pre-tag-2 / empty-hint records only.
            bound_circuit_candidates(
                compose_circuit_candidates(&self.known_relays, peer, false),
                "legacy known-relay fallback",
            )
        };
        if direct.is_empty() && circuits.is_empty() {
            dht_absence
        } else {
            Lookup::Found(Libp2pDialPlan { direct, circuits })
        }
    }

    /// One raw kad peer-routing consultation, with the same honest absence classification and
    /// exposure accounting for providers and relay identities. No cached address map is read.
    async fn query_peer_addresses(&self, peer: PeerId) -> (Vec<Multiaddr>, Lookup<Libp2pDialPlan>) {
        if self.handle.routing_peers().await == 0 {
            return (
                Vec::new(),
                Lookup::Unavailable(Unavailable::InsufficientRouting),
            );
        }
        self.ledger
            .record(Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId));
        match self.handle.locate_peer(peer).await {
            Ok((addresses, _)) if !addresses.is_empty() => (addresses, Lookup::Miss),
            Ok((_, reach)) => (Vec::new(), absence_from_reach(reach)),
            Err(QueryFail::Timeout) => (
                Vec::new(),
                Lookup::Unavailable(Unavailable::DeadlineExceeded),
            ),
            Err(QueryFail::Backend(why)) => {
                (Vec::new(), Lookup::Unavailable(Unavailable::Backend(why)))
            }
        }
    }

    /// Resolve at most two signed relay identities through raw kad and compose at most two
    /// transient circuit candidates. Selection is round-robin across relays: with two hints each
    /// gets one candidate before a second address from either relay, so a dead first relay cannot
    /// consume the entire dial bound and hide the live second relay.
    async fn resolve_hinted_circuits(
        &self,
        provider: PeerId,
        relay_hints: RelayHints,
    ) -> Vec<Multiaddr> {
        let mut per_hint = Vec::with_capacity(relay_hints.len());
        for relay_node in relay_hints.as_slice() {
            let Some(relay_peer) = peer_id_of_provider(relay_node) else {
                // Defense in depth: the frozen RelayHints constructor already enforces strict
                // ed25519 identities. Skip rather than turn one impossible bad hint into an
                // unbounded retry or suppress a second valid hint.
                tracing::warn!(relay = %relay_node, "fabric-libp2p: signed relay hint cannot derive a PeerId; skipping");
                per_hint.push(Vec::new());
                continue;
            };
            tracing::debug!(relay = %relay_node, %relay_peer, "fabric-libp2p: resolving signed relay hint through raw kad");
            let (addresses, _) = self.query_peer_addresses(relay_peer).await;
            let mut direct_addresses: Vec<Multiaddr> = addresses
                .into_iter()
                .filter(|address| !is_circuit_multiaddr(address))
                .collect();
            canonicalize_addresses(&mut direct_addresses);
            if direct_addresses.is_empty() {
                tracing::debug!(relay = %relay_node, %relay_peer, "fabric-libp2p: signed relay hint unresolved or had no direct address; skipping");
            }
            per_hint.push(
                direct_addresses
                    .into_iter()
                    .map(|address| compose_circuit_candidate(relay_peer, &address, provider))
                    .collect::<Vec<_>>(),
            );
        }

        let mut candidates = Vec::with_capacity(MAX_LIBP2P_RELAY_HINTS);
        let max_depth = per_hint.iter().map(Vec::len).max().unwrap_or(0);
        'depths: for depth in 0..max_depth {
            for addresses in &per_hint {
                if let Some(address) = addresses.get(depth) {
                    candidates.push(address.clone());
                    if candidates.len() == MAX_LIBP2P_RELAY_HINTS {
                        break 'depths;
                    }
                }
            }
        }
        candidates
    }

    /// Test-only proof of the legacy known-relay fallback's coupled decision (TASK-218 /
    /// TASK-221): decide reachability and compose `/p2p-circuit` candidates if warranted.
    /// Production performs the same decision in `locate_via_dht`, with
    /// signed hints before this fallback and with raw provider circuit coordinates rejected.
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
    #[cfg(test)]
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
        self.circuit_from_verdict(peer, reachable_directly)
    }

    /// The LOCATOR's USE of the reachability `verdict` (F5), split out so BOTH directions are
    /// unit-couplable with an INJECTED verdict — a hermetic reachable-PRIVATE address cannot be
    /// bound on a test host, so `circuit_provenance`'s real probe can only ever produce
    /// verdict=false for a private address in a test. Here the verdict is a parameter, so a test
    /// drives verdict=true (a same-LAN private provider the probe DID reach) and asserts the
    /// locator SUPPRESSES the circuit, and verdict=false and asserts it composes. Candidate
    /// composition itself records no exposure: the transport records only after an exact route is
    /// selected. This is the load-bearing positive-direction coupling: if the locator's
    /// use of the verdict is broken (composes despite verdict=true), the over-disclosure TASK-221
    /// removes comes back and the verdict=true test reddens.
    #[cfg(test)]
    fn circuit_from_verdict(&self, peer: PeerId, reachable_directly: bool) -> Vec<Multiaddr> {
        compose_circuit_candidates(&self.known_relays, peer, reachable_directly)
    }

    /// Record actual use of the exact selected relayed ConnectionId. Merely composing a candidate
    /// is not a disclosure; this is called only after route establishment/selection succeeds.
    pub(crate) fn record_selected_relay(&self, provider: PeerId, relay: PeerId) {
        self.ledger
            .record(Exposure::new(Recipient::Relay, Disclosed::OurNodeId));
        tracing::debug!(
            %provider,
            %relay,
            "fabric-libp2p: selected exact relayed connection for NAR stream"
        );
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
/// so it is never a direct path and always incurs a Relay disclosure when it is an authorized
/// candidate. [`addr_is_directly_reachable`] uses this to refuse to classify a circuit as direct.
fn is_circuit_multiaddr(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
}

/// Canonicalize an untrusted address result so candidate selection is deterministic and duplicate
/// reports do not consume the finite circuit budget.
fn canonicalize_addresses(addresses: &mut Vec<Multiaddr>) {
    addresses.sort_by_key(|address| address.to_string());
    addresses.dedup();
}

/// Enforce the same two-candidate work bound as the signed hint set. DHT/legacy address sets are
/// not signed input, so excess candidates are resource-bounded at use time and logged rather than
/// allowed to amplify a single fetch. Signed relay identities themselves are never truncated:
/// their constructor/provider writer rejects over-cap input before this path.
fn bound_circuit_candidates(
    mut candidates: Vec<Multiaddr>,
    provenance: &'static str,
) -> Vec<Multiaddr> {
    canonicalize_addresses(&mut candidates);
    if candidates.len() > MAX_LIBP2P_RELAY_HINTS {
        tracing::warn!(
            found = candidates.len(),
            cap = MAX_LIBP2P_RELAY_HINTS,
            %provenance,
            "fabric-libp2p: bounding transient circuit dial candidates"
        );
        candidates.truncate(MAX_LIBP2P_RELAY_HINTS);
    }
    candidates
}

/// Compose one standard circuit-v2 destination from a raw-kad-resolved direct relay address.
fn compose_circuit_candidate(
    relay_peer: PeerId,
    relay_addr: &Multiaddr,
    provider: PeerId,
) -> Multiaddr {
    let mut base: Multiaddr = relay_addr
        .iter()
        .filter(|p| !matches!(p, Protocol::P2p(_) | Protocol::P2pCircuit))
        .collect();
    base.push(Protocol::P2p(relay_peer));
    base.push(Protocol::P2pCircuit);
    base.push(Protocol::P2p(provider));
    base
}

/// Compose the `/p2p-circuit` dial candidates for `provider` (TASK-218 / TASK-221): one per known
/// relay, `<relayTransportAddr>/p2p/<relayPeer>/p2p-circuit/p2p/<providerPeer>`, IFF this node
/// knows relays AND the provider is NOT directly reachable (`reachable_directly` is the caller's
/// observed verdict). Returns empty otherwise. PURE — it records nothing; the single Relay
/// disclosure is recorded by the caller over the authorized candidate set, so "composed nothing"
/// and "recorded nothing" cannot drift apart. Any trailing `/p2p/<x>` and any
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
            compose_circuit_candidate(*relay_peer, relay_addr, provider)
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
                match self.locate_via_dht(peer, RelayHints::empty()).await {
                    Lookup::Found(plan) => Lookup::Found(plan.into_dial_info()),
                    Lookup::Miss => Lookup::Miss,
                    Lookup::Unavailable(reason) => Lookup::Unavailable(reason),
                }
            }
        }
    }

    fn declared_exposure(&self) -> ExposureSurface {
        // The a-priori MAY-disclose surface, taken as the SUPERSET over policies: an active
        // peer-routing query (PublicInfrastructure) reveals OUR identity to the DHT nodes
        // and the bootstrap it contacts. The Relay entry is also in this a-priori superset because
        // selecting and opening a relayed route reveals to that relay operator that we contact the
        // target. Merely composing a circuit candidate does not record actual exposure; accounting
        // occurs only after a concrete live route is observed/selected. ExplicitPeersOnly is a
        // strict subset (discloses nothing). See the module note on the queried-NodeId gap
        // (TASK-168).
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
    //! TASK-221 — the PURE compose decision + address classification (no network). Candidate
    //! composition is intentionally distinct from actual selected-route disclosure.
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
    /// PUBLIC (the relay's) — so it can never skip the probe/compose decision.
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
    //! TASK-221 — probe result -> the locator's reachability verdict -> circuit composed?, driven
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
    /// composes the circuit without claiming it was used. The budget bounds the wait.
    #[tokio::test]
    async fn unreachable_private_provider_composes_without_premature_disclosure() {
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
            0,
            "candidate composition is not route use and must not record a disclosure"
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
        let composed = locator.circuit_from_verdict(provider, true);

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
    /// (probe did NOT reach it — cross-NAT) composes the circuit without recording use.
    /// MUTATION: the locator ignoring the verdict the OTHER way (always suppress — e.g.
    /// `compose_circuit_candidates(.., true)`) -> a cross-NAT provider gets no circuit -> reddens.
    #[tokio::test]
    async fn unreachable_private_verdict_composes_without_disclosure_until_selected() {
        let relay = (
            PeerId::random(),
            "/ip4/203.0.113.7/tcp/4001".parse().unwrap(),
        );
        let relay_peer = relay.0;
        let (_node, ledger, locator) = consumer([35u8; 32], vec![relay]).await;
        let provider = PeerId::random();
        let composed = locator.circuit_from_verdict(provider, false);

        assert_eq!(
            composed.len(),
            1,
            "a NON-reachable (cross-NAT) private provider (verdict=false) MUST compose the circuit"
        );
        assert_eq!(
            relay_disclosures(&ledger),
            0,
            "composing a candidate MUST NOT record a relay disclosure"
        );

        locator.record_selected_relay(provider, relay_peer);
        assert_eq!(
            relay_disclosures(&ledger),
            1,
            "selecting an exact live relayed route records the actual disclosure"
        );
    }

    // Keep `DIRECT_PROBE_BUDGET` referenced so a future refactor that drops the bound trips here.
    #[test]
    fn probe_budget_is_a_short_integer_bound() {
        assert!(DIRECT_PROBE_BUDGET.as_millis() > 0 && DIRECT_PROBE_BUDGET.as_secs() <= 5);
    }
}
