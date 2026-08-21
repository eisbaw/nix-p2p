//! The libp2p [`Swarm`] worker: a single task owns the swarm (which is `!Sync` and
//! must be polled from one place), and the directory / announcer talk to it over
//! tokio channels - an mpsc of [`Command`]s in, a oneshot reply per command out. This
//! is the standard rust-libp2p driver shape; it keeps the async capability traits free
//! of the swarm's single-threaded ownership.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::{AsyncRead, StreamExt};
use libp2p::core::ConnectedPoint;
use libp2p::core::transport::ListenerId;
use libp2p::kad::store::{MemoryStore, MemoryStoreConfig};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{ConnectionId, SwarmEvent};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, autonat, dcutr, identify, kad, mdns, noise, relay,
    tcp, yamux,
};
use libp2p_stream::{Control, IncomingStreams};
use tokio::sync::{mpsc, oneshot};

use crate::keys::{keypair_from_seed, node_id_of};
use crate::lan::{LanDialGuard, multiaddr_lan_provenance};
use crate::nar::{self, ServeGate};
use peer_fabric::{
    AdmitAllPublication, Blake3Digest, Lookup, NodeId, PublicationEligibility, RefusePublication,
    TransferError, Unavailable, WireCodec,
};

/// The shared serve-gate slot (TASK-157): the installed [`ServeGate`], or `None` when this
/// node is not serving inbound NAR requests. Written by
/// [`SwarmHandle::install_serve`] / [`SwarmHandle::uninstall_serve_nonblocking`] and read by
/// the accept loop for each inbound stream. A brief `std::sync::Mutex` (never held across an
/// `.await`, never on the swarm poll loop) is all it needs - the hot path is a single `Arc`
/// clone per inbound stream, off the poll loop.
type ServeSlot = Arc<Mutex<Option<Arc<ServeGate>>>>;

/// The live set of LAN-PROVENANCE connections per peer (TASK-280 mitigation #2), maintained by the
/// worker on `ConnectionEstablished`/`ConnectionClosed` and read by the NAR accept loop before it
/// serves. A connection is recorded here IFF its remote address (the dialed address for an outbound
/// connection, the observed `send_back_addr` for an inbound one) has LAN provenance
/// ([`multiaddr_lan_provenance`]). `Some` ONLY on the no-allowlist `lan-share` path
/// ([`NodeConfig::with_lan_confinement`]); `None` for every other profile, where serving is
/// unrestricted (public-share serves per its allowlist, a consumer never serves). A brief
/// `std::sync::Mutex` shared with the accept loop — like [`ServeSlot`], never held across an
/// `.await` and never on the swarm poll loop.
type LanServeConns = Arc<Mutex<HashMap<PeerId, HashSet<ConnectionId>>>>;

/// Why a kad query did not return a healthy answer. Mapped to
/// [`peer_fabric::Unavailable`] by the directory.
#[derive(Debug, Clone)]
pub enum QueryFail {
    /// The query timed out inside kad before completing.
    Timeout,
    /// A backend-specific failure, carried verbatim for the log.
    Backend(String),
}

/// How far a completed kad iterative query actually REACHED into the DHT (TASK-174).
///
/// `answered` is `kad::QueryStats::num_successes()` at the terminal step: the number of
/// DISTINCT peers that SUCCESSFULLY responded to our query messages during the walk
/// toward the key (kad only counts a peer's first real response). Because an iterative
/// Kademlia lookup always walks TOWARD the key, this is the near-key signal:
///
///   * `answered > 0` - at least one peer answered, so the walk reached as close to the
///     key as THIS NODE'S REACHABLE subgraph holds; an EMPTY result is then classified
///     as an absence ([`Lookup::Miss`]).
///   * `answered == 0` - NO peer ever answered (an empty routing table, or a table whose
///     entries are all dead / unreachable), so we never consulted ANY peer near the
///     key; an empty result is a could-not-consult
///     ([`Unavailable::InsufficientRouting`]), never a `Miss`.
///
/// This is strictly tighter than the old `routing_peers() == 0` bar: a routing table
/// full of DEAD entries has `routing_peers() > 0` (which the old bar read as "on the
/// network", yielding a false `Miss`) yet `answered == 0` here (the honest
/// `InsufficientRouting`).
///
/// HONEST LIMIT (do not over-read the `Miss` direction): `answered > 0` proves the walk
/// reached responding peers in this node's REACHABLE subgraph, NOT that it reached the
/// key's true global k-custodians. A node PARTITIONED or ECLIPSED from those custodians
/// can get `answered > 0` from the peers it CAN reach and still see an empty result -
/// which this bar reports as `Miss` though the truth is "cannot reach the custodians".
/// That false-`Miss` is inherent to a single-node DHT view (indistinguishable from
/// global absence without global knowledge) and is the SAME class of limit
/// `directory.rs` documents for the empty-table BootstrapOutage-vs-Partition case. This
/// bar is strictly better than the old total-routing one; it does not - and at this
/// layer cannot - eliminate the partition false-`Miss`.
#[derive(Debug, Clone, Copy)]
pub struct QueryReach {
    /// Peers that successfully answered the iterative query (`num_successes`).
    pub answered: u32,
}

impl QueryReach {
    /// Whether the query reached at least one responding peer in the key's
    /// neighborhood, so an empty result is an authoritative absence rather than a
    /// could-not-consult.
    pub fn reached_neighborhood(self) -> bool {
        self.answered > 0
    }
}

/// Classify an EMPTY, completed kad query by how far it actually reached (TASK-174):
/// the SHARED near-key bar both the directory (provider-index lookup) and the locator
/// (peer-routing) gate Miss-vs-Unavailable on. An empty result that reached responding
/// peers near the key is treated as an absence ([`Lookup::Miss`]); one that reached
/// nobody is a could-not-consult ([`Unavailable::InsufficientRouting`]), never a `Miss`.
/// See [`QueryReach`] for the honest limit of the `Miss` direction (partition/eclipse).
pub fn absence_from_reach<T>(reach: QueryReach) -> Lookup<T> {
    if reach.reached_neighborhood() {
        Lookup::Miss
    } else {
        Lookup::Unavailable(Unavailable::InsufficientRouting)
    }
}

/// The result of a bounded `get_providers` walk (TASK-154 AC#1). The provider set is capped
/// to at most `max_peers` DURING aggregation (see [`retain_bounded_provider`]), so the worker
/// never holds more than `max_peers` PeerIds no matter how many (possibly forged) providers a
/// sybil flood streams in - the bound is on WORK/MEMORY, enforced at the source, not a
/// post-hoc sort+truncate over an already-unbounded set.
///
/// TASK-214 THREAT MODEL - targeted-key censorship of the fan-out subset, and its HONEST bound.
/// The retained subset is the `max_peers` smallest by RANK under a FRESH per-query salt
/// ([`provider_rank`]), NOT the fixed `max_peers` smallest-by-`PeerId`. This closes the
/// PERMANENT-censorship vector (a griefer grinding PeerIds to own the retained slots for a chosen
/// key and evict a legit provider FOREVER, with deterministic retries re-chasing the identical
/// dead subset) and makes an out-competed key SELF-HEAL on retry. It is NOT a full close, and we
/// do not claim one (the TASK-110/224 lesson - state the bound, do not overclaim):
///   * Per query, v (the victim) is retained iff its rank is among the `max_peers` smallest of the
///     T named providers the walk saw (S forged + the legit set incl. v). The EXACT retention
///     probability is N_v / 2^64, where N_v is the number of salts under which v makes the cut;
///     `provider_rank` (FNV-1a + splitmix64) is NOT a proven-uniform PRF and 2^64 is not divisible
///     by T, so this is not a clean fraction. Under an IDEALIZED-UNIFORM model it is
///     P(v retained) ~ min(1, max_peers / T) for one query (an approximation, not an equality).
///   * Salts are drawn independently per retry (a fresh `rand::random()` per query), so the
///     modeled probability v is never retained over R retries is ~ (1 - min(1, max_peers/T))^R.
///     The `min(1, .)` clamp matters: when fewer than `max_peers` providers are named (T <=
///     max_peers) EVERY named provider is retained, so the exclusion probability is 0. As R -> oo
///     this -> 0: healing is ALMOST SURE under a FIXED FINITE provider population and INDEFINITELY
///     MANY INDEPENDENT retries. This is NOT a finite-retry guarantee - it removes the old rule's
///     ability to force NEVER, but it does not bound healing to any fixed number of tries.
///   * RESIDUAL (accepted, not closed): a determined attacker who SUSTAINS S forged providers on
///     the key drives the per-query success probability down to ~ max_peers/(S + legit) and thus
///     raises the EXPECTED number of retries to first success to ~ (S + legit)/max_peers. They
///     cannot force permanent denial, but they CAN drive expected retries (and resolve latency)
///     arbitrarily high by keeping more forged providers on the key - a probabilistic degradation,
///     not an outright denial. That count is itself capped per store node: any single honest store
///     node holds at most [`STORE_MAX_PROVIDERS_PER_KEY`] providers per key, so per honest
///     record-holder T <= 20 and the modeled per-query success probability is ~ >= max_peers/20 =
///     16/20 at prod defaults (expected retries ~ <= 5/4). Across the DHT's k-replication the union
///     the walk sees CAN exceed 20, so the honest worst case is larger - a bounded probabilistic
///     degradation with almost-sure (not finite-guaranteed) healing, never the old permanent,
///     deterministic denial. Integrity is untouched throughout: every retained record is still
///     ed25519-verified and Nix re-verifies the store path, so a forged provider costs at most a
///     wasted round trip, never a bad path.
#[derive(Debug, Clone)]
pub struct ProviderFanOut {
    /// The bounded provider set: the `max_peers` smallest by RANK under this query's fresh salt
    /// (TASK-214 - see the struct-level threat model), presented in ascending `PeerId` order.
    /// The MEMBERSHIP is salt-dependent (re-drawn per query, so non-grindable and self-healing);
    /// the presentation ORDER is salt-independent (the directory fetches every retained provider
    /// concurrently, so order carries no selection weight). Selection is stable within a single
    /// query regardless of `FoundProviders` arrival order, and the intermediate set is never
    /// larger than `max_peers` (the TASK-154 O(max_peers) memory bound, preserved).
    pub providers: Vec<PeerId>,
    /// `true` if the `max_peers` bound DISCARDED at least one named provider (the returned set
    /// is a strict subset of what the index named). Load-bearing for the Miss/Unavailable
    /// boundary (TASK-154 B2): when the retained subset yields no live record but a provider
    /// was discarded, the lookup is NOT an authoritative absence - a discarded provider may
    /// have been the valid one - so the directory must return a RETRYABLE `Unavailable`, never
    /// a `Miss` (which would poison negative caching). `max_peers == 0` over a non-empty index
    /// therefore also sets this.
    pub truncated: bool,
    /// How far the iterative walk reached (the near-key Miss-vs-`InsufficientRouting` signal,
    /// TASK-174), for classifying a GENUINELY empty index (nothing named, nothing discarded).
    pub reach: QueryReach,
}

/// The per-query fan-out SALT (TASK-214). A fresh `u64` is drawn from the OS CSPRNG for EVERY
/// `get_providers` query (see the `Command::GetProviders` handler), so it is re-drawn on every
/// RETRY. It seeds [`provider_rank`], which is what the bounded fan-out selection orders by -
/// turning "keep the `max_peers` smallest-by-`PeerId`" (a FIXED, grindable subset) into "keep
/// the `max_peers` smallest-by-*rank-under-this-salt*" (a fresh pseudo-random subset each query).
/// Integer by type: no float ever enters the selection decision (owner no-floats rule).
type FanOutSalt = u64;

/// The integer selection rank of `peer` under this query's `salt` (TASK-214). The fan-out keeps
/// the `max_peers` SMALLEST ranks, so with a fresh random `salt` per query the retained subset is
/// a pseudo-random size-`max_peers` sample of the named providers, re-drawn every retry.
///
/// WHY THIS DEFEATS GRINDING. PeerIds are grindable: under the OLD "smallest-by-`PeerId`" rule an
/// attacker mints identities whose `PeerId` sorts below a victim's and PERMANENTLY owns the
/// retained slots for a CHOSEN key - and a deterministic retry re-chases the identical dead
/// subset, so it never self-heals (the TASK-214 vector). Here the rank is a keyed hash of the
/// peer bytes; a griefer cannot pre-compute it without the `salt`, and the `salt` is chosen
/// FRESH at query time, AFTER the attacker's identities are already fixed. So no set of forged
/// identities can guarantee the `max_peers` smallest ranks for a chosen key across retries: each
/// retry is an independent draw (see the honest residual bound on [`ProviderFanOut`]).
///
/// Pure and deterministic in `(salt, peer)` so the selection is unit-testable and STABLE within a
/// single query (the retained set does not depend on `FoundProviders` arrival order - the same
/// order-independence the old `PeerId` order had, now under the rank order). Integer-only: FNV-1a
/// over the peer's multihash bytes seeded by the salt, then a splitmix64 avalanche so
/// structurally-similar PeerIds do not produce correlated ranks. NOT a cryptographic commitment
/// and NOT serialized - it is an in-process selection key only, never a wire/integrity field.
fn provider_rank(salt: FanOutSalt, peer: &PeerId) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET ^ salt;
    for b in peer.to_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    // splitmix64 finalizer (integer-only avalanche).
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

/// Fold one advertised provider `peer` into the BOUNDED aggregation set `found`, retaining at
/// most `max_peers` providers - the `max_peers` smallest by RANK under the query `salt`
/// ([`provider_rank`]). TASK-154 B1: called for EVERY provider each `FoundProviders` event
/// advertises, so a sybil flood of N >> max_peers forged providers costs O(max_peers) retained
/// memory (and O(N log max_peers) work), never O(N) - the bound is enforced as records arrive,
/// not after the whole set is accumulated.
///
/// TASK-214: the set is keyed by `(rank, peer)` and the LARGEST-ranked is evicted when over the
/// bound, so the retained subset is the `max_peers` smallest-by-rank. With a FRESH random `salt`
/// per query this is a fresh pseudo-random sample each retry, not the fixed grindable
/// smallest-by-`PeerId`. The `peer` is kept in the key purely as a deterministic tiebreak for the
/// (astronomically rare) 64-bit rank collision, so the total order is strict and eviction is
/// well-defined. `discarded` is set to `true` whenever a provider is dropped by the bound (an
/// incoming one that does not make the cut, or an already-retained one evicted by a
/// smaller-ranked newcomer), so the caller can tell a bounded result from a complete one. After
/// each call `found.len() <= max_peers` holds (the set is transiently `max_peers + 1` inside,
/// then trimmed), which is the retained-memory bound - preserved unchanged from TASK-154.
fn retain_bounded_provider(
    found: &mut BTreeSet<(u64, PeerId)>,
    max_peers: usize,
    salt: FanOutSalt,
    discarded: &mut bool,
    peer: PeerId,
) {
    let entry = (provider_rank(salt, &peer), peer);
    if !found.insert(entry) {
        // Already retained (same peer, same salt => same rank): no change, no discard.
        return;
    }
    if found.len() > max_peers {
        // Over the bound: evict the current LARGEST-ranked so the retained set stays the
        // `max_peers` smallest by rank. If `entry` itself ranks largest it is the one evicted
        // (a newcomer that does not make the cut). `max_peers == 0` evicts every insert.
        let largest = *found
            .iter()
            .next_back()
            .expect("just inserted, so the set is non-empty");
        found.remove(&largest);
        *discarded = true;
    }
}

/// The combined behaviour: Kademlia (the DHT content discovery) plus Identify (so peers
/// learn each other's listen addresses and feed them into kad routing) plus the RAW-STREAM
/// NAR protocol (TASK-157: the byte-transfer half as a libp2p-stream substrate, over the
/// SAME swarm - replacing the TASK-151 request-response carrier so bytes flow as a stream)
/// plus the NAT-traversal trio (TASK-168).
///
/// `stream` carries no swarm events we act on (its `ToSwarm` is `()`); the byte transfer is
/// driven entirely through a [`libp2p_stream::Control`] on tasks OFF this poll loop.
///
/// NAT TRAVERSAL (TASK-168) - `autonat` / `relay` / `relay_client` / `dcutr`. This is the
/// LAST unproven half of "robust connectivity" (the PRD's risk 8: works in the harness,
/// fails behind real NAT). All prior connectivity proofs used ROUTABLE addresses with zero
/// NAT; these behaviours let a peer with NO public address still be dialed for a fetch:
///
///   * `autonat` - reachability detection: peers probe whether OUR advertised addresses are
///     dialable from outside, so a node learns it is behind NAT (`NatStatus::Private`) and
///     should seek a relay rather than advertise a dead direct address.
///   * `relay_client` - circuit-v2 CLIENT: a NAT'd node listens on a relay's
///     `/p2p-circuit` address, obtaining a reservation so others can reach it THROUGH the
///     relay even though its direct address is undialable.
///   * `dcutr` - Direct Connection Upgrade through Relay (hole punching): once two peers
///     share a relayed connection, DCUtR coordinates a simultaneous-open to UPGRADE it to a
///     DIRECT connection, so the relay carries only the coordination, not the NAR bytes.
///     Relay is the FALLBACK when the hole punch fails (symmetric NAT).
///   * `relay` - circuit-v2 SERVER: this node relays for OTHERS. Run BY DEFAULT so any node
///     that happens to be public automatically helps NAT'd peers with NO dedicated relay
///     infrastructure (the decentralized property); a NAT'd node's own relay server is simply
///     never reached. Its caps are set EXPLICITLY (see [`relay_server_config`] / the
///     `RELAY_*` constants) rather than left to the library default, so a shipped home node
///     relays only BOUNDED traffic (a small number of concurrent circuits, each byte- and
///     time-capped) and is not an open, unbounded amplifier. A deployment that does not want
///     to serve as a relay at all sets [`NodeConfig::with_relay_server(false)`], which makes
///     this field a disabled [`Toggle`] (the server behaviour is absent, so no reservation or
///     circuit is ever accepted) while leaving `relay_client` / `autonat` / `dcutr` intact so
///     the node can still USE other relays. (TASK-208.)
///
/// CRITICAL (AC#9 / `check-discovery-no-shortcut.py`): these are DIAL-ASSISTANCE /
/// CONNECTIVITY, NOT discovery substitutes. They help us CONNECT to a peer we ALREADY
/// discovered via kad; none of them enumerates providers or tells us WHO holds content.
/// Discovery stays kad-EXCLUSIVE; NAT traversal only changes HOW we dial an
/// already-discovered peer. The guard permits this trio but keeps forbidding the real
/// discovery substitutes (LAN-multicast / central-tracker / pubsub-flooding behaviours).
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct Behaviour {
    /// The outbound-dial VETO that confines a no-allowlist `lan-share` node's egress to LAN peer
    /// addresses (TASK-280 mitigation #1), wrapped in a [`Toggle`] so it is DEFAULT OFF: disabled =
    /// `Toggle::from(None)`, the guard is ABSENT and dialing is unrestricted (public-share /
    /// consume-only). Enabled ([`NodeConfig::with_lan_confinement`]), the derived `NetworkBehaviour`
    /// runs its `handle_established_outbound_connection` on EVERY behaviour-initiated dial — including
    /// kad's autonomous by-`PeerId` dials of query-learned addresses, which never pass through
    /// `add_address` — and denies any concrete address without LAN provenance. See [`LanDialGuard`]
    /// for why the per-address (established) hook, not (only) the pending hook, is the real chokepoint.
    ///
    /// ORDER IS LOAD-BEARING (TASK-280 #5): this field is declared FIRST, so the `#[derive]`-generated
    /// `handle_established_outbound_connection` calls the guard BEFORE any sibling (kad/identify/nar
    /// stream) can build a handler for the connection — the derive chains fields in declaration order
    /// with `?`, so a first-field deny short-circuits the rest. It cannot suppress the pre-deny Noise
    /// session (the swarm upgrades the transport before ANY behaviour hook runs), but it guarantees no
    /// sibling behaviour ever acts on a non-LAN connection.
    pub lan_dial_guard: Toggle<LanDialGuard>,
    pub kad: kad::Behaviour<MemoryStore>,
    pub identify: identify::Behaviour,
    pub stream: libp2p_stream::Behaviour,
    pub autonat: autonat::Behaviour,
    /// The circuit-v2 relay SERVER, wrapped in a [`Toggle`] so a node can decline to relay
    /// for others ([`NodeConfig::with_relay_server`]). Disabled = `Toggle::from(None)`: the
    /// behaviour is absent from the swarm, so the node accepts no reservation and forwards no
    /// circuit, yet still USES relays via `relay_client`/`dcutr`. Enabled, it carries the
    /// EXPLICIT bounds from [`relay_server_config`] (never the library default). (TASK-208.)
    pub relay: Toggle<relay::Behaviour>,
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    /// LAN peer-ADDRESS discovery over mDNS link-local multicast (TASK-257), wrapped in a
    /// [`Toggle`] so it is DEFAULT OFF: disabled = `Toggle::from(None)`, the behaviour is
    /// ABSENT from the swarm, so the node opens no multicast socket and emits ZERO mDNS
    /// packets (the axis-1-local-discovery opt-in, TASK-120: enabling it implies NOTHING
    /// about serving/announcing/public participation). Enabled ([`NodeConfig::with_mdns`]),
    /// its `Discovered` events feed the discovered LAN peer's address to `kad.add_address` (see
    /// `on_event`) - a peer ADDRESS hint into the SAME bootstrap/address path `identify` uses, never
    /// a content-discovery route. Discovered peers are admitted through a BOUNDED per-window cap
    /// ([`MdnsAdmission`], TASK-257 F-1) so an unauthenticated LAN flood cannot admit an UNBOUNDED
    /// set of generated PeerIds - the routing skew a malicious LAN host can induce is bounded.
    ///
    /// SCOPE ISOLATION + the BOUNDED RESIDUAL (TASK-257 F-2). A CROSS-scope neighbour can never
    /// complete this node's scoped `/nix-p2p/<scope>/kad` handshake, so it NEVER JOINS this node's
    /// content DHT: content discovery stays kad-EXCLUSIVE and a cross-scope peer can neither answer
    /// nor be resolved for "who holds hash X?" (proven by the e2e scope-mismatch control, where the
    /// cross-scope consumer resolves nothing and falls back to upstream). HONEST RESIDUAL: a
    /// cross-scope mDNS peer that was `add_address`'d occupies at most `cap` routing slots as a
    /// DECAYING DEAD-END - it answers no scoped query, costs at most one wasted dial, leaks nothing
    /// new, and is bounded by the F-1 admission cap (not unbounded). This matches the product TCB
    /// ("never a bad store path; a cross peer costs a retry"), not a stricter routing-purity
    /// invariant; full deterministic cross-scope eviction is deferred to a follow-up.
    /// `check-discovery-no-shortcut.py` bites if an mDNS event is ever wired to
    /// `find_providers`/`get_providers`.
    pub mdns: Toggle<mdns::tokio::Behaviour>,
}

/// The live transport path to a peer, derived from the swarm's own `ConnectionEstablished` /
/// `ConnectionClosed` bookkeeping (TASK-242). `Relay` iff the peer is reachable ONLY over a
/// relayed (`/p2p-circuit`) connection right now; `Direct` iff at least one non-relayed connection
/// is open (a direct connection, or a relayed one that dcutr has since upgraded); `None` iff the
/// worker holds no open connection to the peer. It reads the SAME connection ledger `is_connected`
/// answers from, so the two can never disagree about whether a peer is connected. A fabric-native
/// type: the daemon layer maps it onto its operator-facing `PeerPath` (fabric-libp2p never depends
/// on `daemon-core`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnPath {
    /// At least one DIRECT (non-relayed) connection to the peer is open.
    Direct,
    /// The peer is reachable, but ONLY over a relayed (`/p2p-circuit`) connection.
    Relay,
    /// No open connection to the peer.
    None,
}

/// A command sent to the swarm worker. Each carries a oneshot the worker replies on
/// once the corresponding swarm event arrives (or immediately, for synchronous ops).
pub enum Command {
    Listen {
        addr: Multiaddr,
        reply: oneshot::Sender<Result<(), String>>,
    },
    ListenAddrs {
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    AddAddress {
        peer: PeerId,
        addr: Multiaddr,
    },
    /// Advertise `addr` as an EXTERNALLY-reachable address of THIS node (TASK-168). A node
    /// that knows a public address for itself (config, or a public relay/bootstrap) must
    /// announce it so identify propagates it and the relay SERVER can hand it back in
    /// reservation vouchers - without a confirmed external address a relay answers a
    /// reservation with `NoAddressesInReservation` and the NAT'd client cannot build its
    /// circuit listen address. On a NAT'd node the reachability verdict comes from autonat
    /// instead; this is the explicit-knowledge path.
    AddExternalAddress {
        addr: Multiaddr,
    },
    Dial {
        addr: Multiaddr,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Dial `peer` using exactly these ephemeral addresses. The caller already knows the
    /// [`ConnectionId`] from `options`, so a dropped wait can tombstone that exact attempt.
    /// Addresses stay in `DialOpts` and never enter kad or a provider-keyed side cache.
    DialExact {
        peer: PeerId,
        options: DialOpts,
        permitted_relays: BTreeSet<PeerId>,
        reply: oneshot::Sender<Result<AuthorizedConnection, String>>,
    },
    Bootstrap {
        reply: oneshot::Sender<Result<(), String>>,
    },
    RoutingPeers {
        reply: oneshot::Sender<usize>,
    },
    /// Is there a fully-ESTABLISHED connection to `peer` right now? (TASK-198 F3). `true` iff the
    /// swarm has an open connection whose upgrade — the Noise handshake and yamux muxer
    /// negotiation — has already completed (i.e. a `ConnectionEstablished` has fired and no
    /// matching close since). A caller polls this after `dial` to confirm the handshake is DONE
    /// before it starts a wall-clock it wants to exclude the handshake from. Read-only; touches no
    /// wire framing.
    IsConnected {
        peer: PeerId,
        reply: oneshot::Sender<bool>,
    },
    /// What is the live transport path to `peer` right now — direct, relay-only, or not connected?
    /// (TASK-242). Answered from the worker's connection ledger, which mirrors the swarm's
    /// `ConnectionEstablished`/`ConnectionClosed` events (each carries the `ConnectedPoint`, whose
    /// `is_relayed()` is the direct-vs-`/p2p-circuit` discriminator). Read-only; touches no wire
    /// framing. The operator status surface uses it to report `peer_path=direct|relay` honestly for
    /// a NAT'd/relayed node instead of a hardcoded placeholder.
    ConnectionPath {
        peer: PeerId,
        reply: oneshot::Sender<ConnPath>,
    },
    /// Relay identities currently carrying connections to `peer`, for read-only attribution.
    ConnectionRelays {
        peer: PeerId,
        reply: oneshot::Sender<Vec<PeerId>>,
    },
    /// Choose one exact live connection authorized by the current offer-derived relay set.
    /// Direct wins; otherwise only an exact permitted relay is eligible. No connection is closed.
    AuthorizedConnection {
        peer: PeerId,
        permitted_relays: BTreeSet<PeerId>,
        reply: oneshot::Sender<Option<AuthorizedConnection>>,
    },
    StartProviding {
        key: kad::RecordKey,
        reply: oneshot::Sender<Result<(), String>>,
    },
    StopProviding {
        key: kad::RecordKey,
    },
    PutRecord {
        key: kad::RecordKey,
        value: Vec<u8>,
        /// When the stored record expires (the record's own `expiry`, so the store
        /// enforces MIN(record.expiry, its own TTL) - the AC#6 reconciliation).
        expires: Option<Instant>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    GetProviders {
        key: kad::RecordKey,
        /// The consumer fan-out bound (TASK-154 AC#1 / B1): the worker retains at most this
        /// many providers as `FoundProviders` events stream in (the `max_peers` smallest by
        /// RANK under a fresh per-query salt, TASK-214), so a sybil flood costs O(max_peers)
        /// memory at the SOURCE, not O(N) then a post-hoc truncate. `0` retains none (a caller
        /// that budgeted zero peers).
        max_peers: usize,
        /// The worker replies here with the started query's [`kad::QueryId`] BEFORE the
        /// result, so the caller can cancel the query (via the lossless cancel channel) if it
        /// abandons the wait (TASK-154 S4 work bound).
        id_reply: oneshot::Sender<kad::QueryId>,
        reply: oneshot::Sender<Result<ProviderFanOut, QueryFail>>,
    },
    GetRecord {
        key: kad::RecordKey,
        /// See [`Command::GetProviders::id_reply`] (TASK-154).
        id_reply: oneshot::Sender<kad::QueryId>,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, QueryFail>>,
    },
    /// Resolve `peer`'s dialable addresses THROUGH kad peer-routing: an iterative
    /// `get_closest_peers` to the `peer`'s own key. The k-closest set the query converges
    /// on carries the addresses intermediate nodes (a shared bootstrap that learned them
    /// via identify) reported for `peer`, so the reply is the addresses the DHT knows -
    /// no address was injected out of band. `Ok(empty)` means the query completed but the
    /// DHT knows no address (a healthy `Miss`); `Err` means it could not be consulted.
    /// TASK-159: the [`crate::locator::Libp2pNodeLocator`] active-resolution path.
    LocatePeer {
        peer: PeerId,
        /// See [`Command::GetProviders::id_reply`] (TASK-154).
        id_reply: oneshot::Sender<kad::QueryId>,
        reply: oneshot::Sender<Result<(Vec<Multiaddr>, QueryReach), QueryFail>>,
    },
}

/// Cancels the underlying kad query if this guard is dropped BEFORE the query terminated
/// (TASK-154 S4 work bound). Armed for the whole time a caller awaits a query result; a
/// normal completion [`disarm`](CancelOnDrop::disarm)s it so nothing is sent. When the
/// caller's future is instead DROPPED mid-wait - the directory's `find_providers` deadline
/// firing is the load-bearing case - this `Drop` signals the worker to stop the kad walk now
/// rather than running it to `query_timeout`.
///
/// The cancel travels on a DEDICATED UNBOUNDED channel (`cancels`), NOT the bounded command
/// channel (TASK-154 B3): `Drop` cannot `.await`, and the previous best-effort `try_send` on
/// the bounded command channel SILENTLY DROPPED the cancel whenever that channel was full (a
/// cancel storm), leaving the query to run to its full timeout - the very case the work bound
/// exists to stop. An unbounded `send` from `Drop` is non-blocking AND lossless: it only fails
/// if the worker is already gone (nothing left to cancel).
struct CancelOnDrop {
    cancels: mpsc::UnboundedSender<kad::QueryId>,
    id: kad::QueryId,
    armed: bool,
}

impl CancelOnDrop {
    fn new(cancels: mpsc::UnboundedSender<kad::QueryId>, id: kad::QueryId) -> Self {
        CancelOnDrop {
            cancels,
            id,
            armed: true,
        }
    }

    /// The query terminated normally; do NOT cancel on drop.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed && self.cancels.send(self.id).is_err() {
            // The only way an unbounded send fails is a closed receiver = the worker task is
            // already gone, so there is no live query left to cancel. Never a full-channel drop.
            tracing::debug!(
                "fabric-libp2p: query-cancel not delivered because the swarm worker is gone \
                 (nothing to cancel)"
            );
        }
    }
}

/// Lossless cancellation guard for one exact outbound dial. If the caller times out or its
/// enclosing fetch future is dropped, the worker tombstones this [`ConnectionId`] until libp2p
/// emits its terminal success/error event. A late success is closed and never admitted to the
/// usable route ledger.
struct CancelExactDialOnDrop {
    cancels: mpsc::UnboundedSender<(PeerId, ConnectionId)>,
    peer: PeerId,
    connection: ConnectionId,
    /// Owned so Drop can close reply delivery before publishing cancellation. The worker may
    /// select the cancellation channel before its bounded command channel; it must nevertheless
    /// observe a closed waiter if that command later establishes successfully.
    receiver: Option<oneshot::Receiver<Result<AuthorizedConnection, String>>>,
    armed: bool,
}

impl CancelExactDialOnDrop {
    fn new(
        cancels: mpsc::UnboundedSender<(PeerId, ConnectionId)>,
        peer: PeerId,
        connection: ConnectionId,
        receiver: oneshot::Receiver<Result<AuthorizedConnection, String>>,
    ) -> Self {
        Self {
            cancels,
            peer,
            connection,
            receiver: Some(receiver),
            armed: true,
        }
    }

    async fn receive(&mut self) -> Result<AuthorizedConnection, String> {
        let receiver = self.receiver.as_mut().ok_or_else(|| {
            "exact authorized dial reply receiver was already consumed".to_string()
        })?;
        receiver.await.unwrap_or_else(|_| {
            Err("swarm worker is gone during exact authorized dial".to_string())
        })
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelExactDialOnDrop {
    fn drop(&mut self) {
        // Close reply delivery first. This gives cancellation a stable happens-before fact even
        // when another runtime thread handles the unbounded cancel immediately.
        drop(self.receiver.take());
        if self.armed && self.cancels.send((self.peer, self.connection)).is_err() {
            tracing::debug!(
                peer = %self.peer,
                connection = %self.connection,
                "fabric-libp2p: exact-dial cancel not delivered because the worker is gone"
            );
        }
    }
}

/// A cloneable handle to the worker. Every capability holds one of these; a dropped
/// last handle ends the worker loop (the mpsc closes).
///
/// It also carries the byte-transfer surface (TASK-157), which does NOT go through the
/// worker command loop: a [`libp2p_stream::Control`] to open outbound NAR streams, the NAR
/// [`StreamProtocol`], and the shared [`ServeSlot`] the accept loop reads. Keeping the byte
/// path off the command loop is what lets a large fetch/serve run without touching the swarm
/// poll loop.
#[derive(Clone)]
pub struct SwarmHandle {
    tx: mpsc::Sender<Command>,
    /// The LOSSLESS query-cancel channel (TASK-154 B3): a dropped [`CancelOnDrop`] guard sends
    /// the abandoned query's [`kad::QueryId`] here. Unbounded + dedicated so a cancel is never
    /// dropped by a full command channel (the previous best-effort `try_send` bug).
    cancels: mpsc::UnboundedSender<kad::QueryId>,
    /// Lossless exact-dial cancellation/tombstoning channel. Separate from the bounded command
    /// channel because a future's `Drop` cannot await capacity.
    exact_dial_cancels: mpsc::UnboundedSender<(PeerId, ConnectionId)>,
    /// Opens outbound NAR substreams. Production offer fetches use the vendored exact-connection
    /// method; peer-only auto-dial remains only for lower-level measurement/test callers.
    control: Control,
    /// The Bao-authenticated NAR protocol name (`/nix-p2p/<scope>/nar/4`).
    nar_protocol: StreamProtocol,
    /// The installed serve gate (or `None`); read by the accept loop, written by install /
    /// uninstall. See [`ServeSlot`].
    serve_slot: ServeSlot,
}

/// Measurement-facing result for one successful `/nar/4` fetch. Byte counts are exact NAR
/// substream protocol bytes; timings share the instant immediately before request writing.
/// They intentionally exclude TCP/IP, Noise/yamux overhead, retransmissions, discovery and dial.
#[derive(Debug, Clone)]
pub struct StreamedFetch {
    /// The decoded, BLAKE3-verified NAR bytes (uncompressed).
    pub bytes: Vec<u8>,
    /// Exact component accounting and asserted totals for the successful exchange.
    pub wire: crate::NarV4WireAccounting,
    /// Request flush completion relative to the shared request-write origin.
    pub request_complete_ns: u128,
    /// First response byte relative to the shared request-write origin.
    pub first_response_byte_ns: u128,
    /// First Bao-authenticated raw leaf relative to the same origin. This is not absolute
    /// TTFB: v4 proof preparation occurs before the provider's first response byte.
    pub authenticated_first_leaf_ns: u128,
    /// COMPLETE, clean FIN and final authentication relative to the same origin.
    pub total_fetch_ns: u128,
    /// Codec byte actually selected by the provider and validated against the
    /// request accept mask. Measurements must not infer this from the offer.
    pub selected_codec: WireCodec,
}

/// Immutable data for one attributed NAR stream request. Keeping the content contract and its
/// timing/codec policy together prevents the peer-wide and exact-connection entry points from
/// drifting as fields are added.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NarFetchRequest {
    content: Blake3Digest,
    expected_size: Option<u64>,
    dial_timeout: Duration,
    body_idle_timeout: Duration,
    offer_zstd: bool,
}

impl NarFetchRequest {
    pub(crate) fn new(
        content: Blake3Digest,
        expected_size: Option<u64>,
        dial_timeout: Duration,
        body_idle_timeout: Duration,
        offer_zstd: bool,
    ) -> Self {
        Self {
            content,
            expected_size,
            dial_timeout,
            body_idle_timeout,
            offer_zstd,
        }
    }
}

/// The ATTRIBUTED outcome of a streaming NAR fetch (TASK-218): whether a failure happened
/// BEFORE the substream opened or AFTER. This distinction is load-bearing for the
/// relay-reachability oracle - only a `NotOpened` failure means the provider was UNREACHABLE.
///
///   * [`FetchOutcome::Ok`] - the NAR was fetched and Bao-authenticated.
///   * [`FetchOutcome::NotOpened`] - the substream was NEVER opened: `open_stream` returned an
///     error or the dial timed out. Over a relay this is a dial / circuit-establishment failure
///     (the provider was NOT reached at any resolved dial address). This, and ONLY this, is an
///     "unreachable" failure.
///   * [`FetchOutcome::OpenedThenFailed`] - the substream OPENED (the provider WAS reached and
///     `/nar/4` negotiated), but the transfer then failed: `NotHeld` / `Declined`, a declared-size
///     rejection, Bao authentication/framing failure, a mid-body idle timeout, or
///     a post-open write error. The relay WORKED here - conflating this with `NotOpened` would
///     falsely blame the relay for a reachable provider that merely does not hold the content.
#[derive(Debug)]
pub enum FetchOutcome {
    Ok(StreamedFetch),
    NotOpened(TransferError),
    /// The peer was reached, but does not implement wholesale `/nar/4`.
    /// This is an offer-compatibility failure, never an unreachability signal,
    /// and there is deliberately no `/nar/3` downgrade attempt.
    ProtocolIncompatible(TransferError),
    OpenedThenFailed(TransferError),
}

/// A pass-through [`AsyncRead`] that counts exact `/nar/4` response protocol bytes and records
/// first response byte against the request-write origin. Measurement-only; not a network-layer
/// byte counter (Noise/yamux/TCP overhead and retransmissions are outside this unit).
struct CountingReader<'a, R> {
    inner: &'a mut R,
    count: u64,
    request_started: Instant,
    first_response_byte_ns: Option<u128>,
}

impl<'a, R> CountingReader<'a, R> {
    fn new(inner: &'a mut R, request_started: Instant) -> Self {
        CountingReader {
            inner,
            count: 0,
            request_started,
            first_response_byte_ns: None,
        }
    }

    fn count(&self) -> u64 {
        self.count
    }

    fn first_response_byte_ns(&self) -> Option<u128> {
        self.first_response_byte_ns
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<'_, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut *self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(n)) => {
                self.count += n as u64;
                if n != 0 && self.first_response_byte_ns.is_none() {
                    self.first_response_byte_ns = Some(self.request_started.elapsed().as_nanos());
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
}

impl SwarmHandle {
    async fn send(&self, command: Command) {
        // The worker outlives every handle in normal operation; a send failure means
        // the worker task is already gone (shutdown), which the awaiting oneshot below
        // will surface as a dropped sender. Log it rather than swallow it silently.
        if self.tx.send(command).await.is_err() {
            tracing::error!("fabric-libp2p swarm worker is gone; command dropped");
        }
    }

    /// Start listening on `addr`; resolves only after the matching [`ListenerId`] emits
    /// `NewListenAddr`, never merely because `Swarm::listen_on` accepted registration.
    pub async fn listen(&self, addr: Multiaddr) -> Result<(), String> {
        self.listen_many(vec![addr], DEFAULT_LISTEN_READY_TIMEOUT)
            .await
    }

    /// Register every address before awaiting any of them, then require all corresponding
    /// listeners to become live under one absolute integer timeout. This matters for multiple
    /// circuit reservations: waiting for R1 before even registering R2 would serialize the
    /// readiness budget and could prevent the full configured set from ever being installed.
    pub async fn listen_many(
        &self,
        addresses: Vec<Multiaddr>,
        timeout: Duration,
    ) -> Result<(), String> {
        if addresses.is_empty() {
            return Ok(());
        }
        let requested = addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let install = async {
            let mut waits = Vec::with_capacity(addresses.len());
            for address in addresses {
                let (reply, receiver) = oneshot::channel();
                self.send(Command::Listen {
                    addr: address.clone(),
                    reply,
                })
                .await;
                waits.push((address, receiver));
            }
            for (address, receiver) in waits {
                receiver.await.map_err(|_| {
                    format!("swarm worker is gone while waiting for listener {address}")
                })??;
            }
            Ok(())
        };
        tokio::time::timeout(timeout, install).await.map_err(|_| {
            format!("libp2p listener(s) did not emit NewListenAddr within {timeout:?}: {requested}")
        })?
    }

    /// The concrete addresses the node is listening on (for a peer to dial).
    pub async fn listen_addrs(&self) -> Vec<Multiaddr> {
        self.try_listen_addrs().await.unwrap_or_else(|reason| {
            tracing::error!(%reason, "fabric-libp2p: cannot read current listen addresses");
            Vec::new()
        })
    }

    /// The concrete addresses the node is listening on, preserving worker failure instead of
    /// collapsing it to an empty set. Production record signing uses this form: "no live relay"
    /// and "the swarm is gone" are materially different truths and must not produce the same
    /// signed offer.
    pub async fn try_listen_addrs(&self) -> Result<Vec<Multiaddr>, String> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::ListenAddrs { reply }).await;
        rx.await
            .map_err(|_| "swarm worker is gone while reading listen addresses".to_string())
    }

    /// Teach kad how to reach `peer` at `addr` (a bootstrap/entry peer).
    pub async fn add_address(&self, peer: PeerId, addr: Multiaddr) {
        self.send(Command::AddAddress { peer, addr }).await;
    }

    /// Advertise `addr` as an externally-reachable address of THIS node (TASK-168). Use it
    /// on a node with a known-public address (a relay/bootstrap, or a config-supplied
    /// address): identify propagates it and the relay SERVER can cite it in reservation
    /// vouchers so NAT'd clients can build their circuit listen address.
    pub async fn add_external_address(&self, addr: Multiaddr) {
        self.send(Command::AddExternalAddress { addr }).await;
    }

    /// Dial `addr` (used to establish the initial connection to a bootstrap peer).
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Dial { addr, reply }).await;
        rx.await.unwrap_or_else(|_| Err("worker gone".into()))
    }

    /// Establish or reuse one exact DIRECT connection to `peer`.
    pub(crate) async fn connect_direct(
        &self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        timeout: Duration,
    ) -> Result<AuthorizedConnection, String> {
        if addresses.iter().any(is_circuit_address) {
            return Err("direct dial was given a /p2p-circuit address".to_string());
        }
        self.connect_authorized(peer, addresses, BTreeSet::new(), timeout)
            .await
    }

    /// Establish or reuse one exact connection authorized by a bounded circuit candidate set.
    ///
    /// Unlike [`add_address`](Self::add_address), this does not persist a provider -> address
    /// association in kad. Direct is always preferred; otherwise a live relayed connection is
    /// eligible only when its observed relay occurs in these exact candidates. Unrelated routes
    /// remain open but cannot carry the request because the returned [`ConnectionId`] is passed
    /// through to the exact stream-open API.
    pub(crate) async fn connect_transient(
        &self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        timeout: Duration,
    ) -> Result<AuthorizedConnection, String> {
        if addresses.is_empty() {
            return Err("transient dial requires at least one address".to_string());
        }
        let permitted_relays: BTreeSet<PeerId> =
            addresses.iter().filter_map(circuit_relay_peer).collect();
        if permitted_relays.is_empty()
            || addresses.iter().any(|address| !is_circuit_address(address))
        {
            return Err(
                "transient circuit dial requires only /p2p/<relay>/p2p-circuit addresses"
                    .to_string(),
            );
        }
        self.connect_authorized(peer, addresses, permitted_relays, timeout)
            .await
    }

    async fn connect_authorized(
        &self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        permitted_relays: BTreeSet<PeerId>,
        timeout: Duration,
    ) -> Result<AuthorizedConnection, String> {
        let connect = async {
            if let Some(connection) = self.authorized_connection(peer, &permitted_relays).await? {
                return Ok(connection);
            }
            if addresses.is_empty() {
                return Err(format!(
                    "no live authorized connection to {peer} and no exact dial addresses"
                ));
            }

            // `addresses(...)` keeps extend_addresses_through_behaviour=false, so kad cannot add
            // ambient provider coordinates to this exact authorized attempt.
            let options = DialOpts::peer_id(peer)
                .condition(PeerCondition::Always)
                .addresses(addresses)
                .build();
            let connection = options.connection_id();
            let (reply, receiver) = oneshot::channel();
            // Reserve bounded command capacity before arming cancellation. Once the guard exists,
            // enqueue is synchronous: an exact-dial command can never become visible to the
            // worker without its caller already having a lossless cancellation path. If this
            // future is dropped while waiting for capacity, no command was enqueued and therefore
            // no dial exists to cancel.
            let permit = self.tx.reserve().await.map_err(|_| {
                "swarm worker is gone before exact authorized dial registration".to_string()
            })?;
            let mut cancel = CancelExactDialOnDrop::new(
                self.exact_dial_cancels.clone(),
                peer,
                connection,
                receiver,
            );
            permit.send(Command::DialExact {
                peer,
                options,
                permitted_relays,
                reply,
            });
            let result = cancel.receive().await;
            cancel.disarm();
            result
        };
        tokio::time::timeout(timeout, connect).await.map_err(|_| {
            format!(
                "exact authorized dial to {peer} did not establish a connection within {timeout:?}"
            )
        })?
    }

    /// Run the kad bootstrap self-lookup to populate the routing table.
    pub async fn bootstrap(&self) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Bootstrap { reply }).await;
        rx.await.unwrap_or_else(|_| Err("worker gone".into()))
    }

    /// How many peers are currently in the kad routing table. `0` means the lookup
    /// mechanism is not on the network for this key (`InsufficientRouting`).
    pub async fn routing_peers(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        self.send(Command::RoutingPeers { reply }).await;
        rx.await.unwrap_or(0)
    }

    /// Is there a fully-established connection to `peer` right now (Noise + yamux upgrade already
    /// complete)? (TASK-198 F3). A `dial` only INITIATES a connection and returns before the
    /// handshake finishes; a caller that must EXCLUDE the handshake from a wall-clock polls this
    /// until it returns `true`, at which point `ConnectionEstablished` has fired and the timed
    /// window that follows contains no handshake. A dropped worker answers `false` (not connected).
    pub async fn is_connected(&self, peer: PeerId) -> bool {
        let (reply, rx) = oneshot::channel();
        self.send(Command::IsConnected { peer, reply }).await;
        rx.await.unwrap_or(false)
    }

    /// The live transport path to `peer` — direct, relay-only, or not connected (TASK-242). Reads
    /// the worker's connection ledger (fed by `ConnectionEstablished`/`ConnectionClosed`), so it is
    /// consistent with [`is_connected`](Self::is_connected): `ConnPath::None` iff not connected,
    /// exactly when `is_connected` is `false`. A dropped worker answers `None` (not connected).
    pub async fn connection_path(&self, peer: PeerId) -> ConnPath {
        let (reply, rx) = oneshot::channel();
        self.send(Command::ConnectionPath { peer, reply }).await;
        rx.await.unwrap_or(ConnPath::None)
    }

    /// Relay identities carrying live connections to `peer`, derived from the exact current
    /// `ConnectedPoint`s. Sorted and unique; empty for direct-only/disconnected peers. This is a
    /// read-only observability fact, not an address book or dial input.
    pub async fn connection_relay_peers(&self, peer: PeerId) -> Vec<PeerId> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::ConnectionRelays { peer, reply }).await;
        rx.await.unwrap_or_default()
    }

    /// Select one exact currently-live connection: direct first, then an exact permitted relay.
    /// Unrelated live connections coexist and are never closed or used as fallbacks.
    async fn authorized_connection(
        &self,
        peer: PeerId,
        permitted_relays: &BTreeSet<PeerId>,
    ) -> Result<Option<AuthorizedConnection>, String> {
        let (reply, receiver) = oneshot::channel();
        self.send(Command::AuthorizedConnection {
            peer,
            permitted_relays: permitted_relays.clone(),
            reply,
        })
        .await;
        receiver
            .await
            .map_err(|_| "swarm worker is gone while selecting an authorized route".to_string())
    }

    /// Bounded DIRECT-reachability probe (TASK-221): is `peer` reachable by a DIRECT
    /// (non-relayed) connection at one of `targets` within `budget`?
    ///
    /// The locator uses this to distinguish a provider that kad could only place at a PRIVATE
    /// (RFC1918) address that is on OUR OWN LAN (directly reachable — compose NO relay circuit
    /// and record NO Relay disclosure, the TASK-221 privacy win) from one across a NAT (never
    /// directly reachable — compose the circuit, the real-NAT cornerstone). The decision is by
    /// OBSERVED reachability, not an address/subnet heuristic, so it cannot be fooled by two NATs
    /// that number their LANs identically (RFC1918 collision).
    ///
    /// FAST PATH: returns `true` immediately if a DIRECT connection to `peer` already exists (the
    /// kad walk may already have connected same-LAN). Otherwise it INITIATES a dial to each target
    /// and polls [`connection_path`](Self::connection_path) until it observes
    /// [`ConnPath::Direct`] or `budget` elapses. A same-LAN provider connects within a few RTT; a
    /// cross-NAT provider is never reached directly, so the probe spends the full (short, bounded)
    /// `budget` then returns `false` — a too-short budget therefore only costs the privacy win
    /// (fall back to composing the circuit), NEVER correctness. A `true` verdict is a genuine
    /// DIRECT L3 path: a `true` requires [`ConnPath::Direct`], and a relayed dial reads as
    /// [`ConnPath::Relay`], so dialing a target that happens to be circuit-shaped can never trip a
    /// false positive (the caller passes direct targets, but the verdict is robust regardless). A
    /// dial that fails to INITIATE is ignored (its async failure surfaces as a swarm event, leaving
    /// `connection_path` at its current non-Direct value — exactly the cross-NAT outcome).
    ///
    /// The `budget` HARD-bounds the WHOLE call (F4): the entire fast-path check + sequential dials +
    /// poll loop run inside a single `tokio::time::timeout(budget, ..)`, so even command-channel
    /// congestion or a large `targets` set cannot overrun it — the call resolves `false` the moment
    /// `budget` elapses, whatever it was waiting on.
    pub async fn probe_direct_reachable(
        &self,
        peer: PeerId,
        targets: &[Multiaddr],
        budget: Duration,
    ) -> bool {
        let probe = async {
            if self.connection_path(peer).await == ConnPath::Direct {
                return true;
            }
            for addr in targets {
                let _ = self.dial(addr.clone()).await;
            }
            loop {
                if self.connection_path(peer).await == ConnPath::Direct {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        // On timeout the provider was not reached DIRECTLY within the budget -> not directly
        // reachable (compose the circuit). `budget` is the whole-call ceiling.
        (tokio::time::timeout(budget, probe).await).unwrap_or(false)
    }

    /// Join the network through a SET of independently-operated bootstrap peers. Pass
    /// `>=3` so NO single bootstrap is load-bearing: this teaches kad every bootstrap's
    /// address, dials them all (not just the first), runs ONE bootstrap self-lookup, then
    /// waits until the routing table holds at least `min_peers`. Losing any single
    /// bootstrap after a successful join still leaves the node routable - that is the
    /// bootstrap-independence property (TASK-153; `tests/bootstrap_independence.rs`).
    ///
    /// It composes the same [`add_address`](Self::add_address) + [`dial`](Self::dial) +
    /// [`bootstrap`](Self::bootstrap) + poll-`routing_peers` idiom the single-bootstrap
    /// join used, generalized to a set. This is the reusable helper the multi-node tests
    /// use; the daemon composition root (`daemon/src/source_libp2p.rs`) currently
    /// hand-rolls a COLD-START variant of the same idiom that returns BEFORE the routing
    /// table converges (it starts serving immediately and falls back to HTTP until kad
    /// fills; TASK-163). Unifying the two behind one readiness contract is that task's
    /// job - until then this helper deliberately WAITS for `min_peers`, which the daemon's
    /// path intentionally does not.
    ///
    /// Fail-fast, never a silent stall: an EMPTY set is a caller error (`Err`); if EVERY
    /// dial fails to INITIATE the join is doomed and returns `Err` immediately with the
    /// aggregated per-dial reasons (rather than spinning the poll for the full `timeout`);
    /// a PARTIAL dial failure is logged and tolerated (another bootstrap may still admit
    /// us - the routing-table poll is the real readiness oracle); and if the routing table
    /// never reaches `min_peers` within `timeout` that is a real join failure returned as
    /// `Err` with context.
    pub async fn join_bootstraps(
        &self,
        bootstraps: &[(PeerId, Multiaddr)],
        min_peers: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        if bootstraps.is_empty() {
            return Err("join_bootstraps needs at least one bootstrap peer".to_string());
        }

        // Teach kad every bootstrap address and dial them ALL, so the join does not funnel
        // through a single entry node. A dial only INITIATES the connection; collect the
        // ones that failed to even initiate so an all-dead set fails fast and loud.
        let mut dial_errors = Vec::new();
        for (peer, addr) in bootstraps {
            self.add_address(*peer, addr.clone()).await;
            if let Err(why) = self.dial(addr.clone()).await {
                dial_errors.push(format!("{peer} @ {addr}: {why}"));
            }
        }
        if dial_errors.len() == bootstraps.len() {
            // Every dial failed to initiate: the join cannot make progress. Fail now with
            // the real root cause instead of misattributing it to slow convergence after a
            // full-timeout poll.
            return Err(format!(
                "every bootstrap dial failed to initiate ({} peer(s)); cannot join: {}",
                bootstraps.len(),
                dial_errors.join("; ")
            ));
        }
        if !dial_errors.is_empty() {
            tracing::warn!(
                failed = dial_errors.len(),
                total = bootstraps.len(),
                reasons = %dial_errors.join("; "),
                "fabric-libp2p: some bootstrap dials failed to initiate; continuing on the rest"
            );
        }

        // One bootstrap self-lookup populates the routing table from whichever bootstraps
        // answered. The poll below is the authoritative readiness signal, but the
        // self-lookup error is logged (not swallowed) so a failure stays traceable.
        if let Err(why) = self.bootstrap().await {
            tracing::debug!(
                %why,
                "fabric-libp2p: kad bootstrap self-lookup returned an error; \
                 relying on the routing-table poll for readiness"
            );
        }

        let deadline = Instant::now() + timeout;
        loop {
            if self.routing_peers().await >= min_peers {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "routing table did not reach {min_peers} peer(s) within {timeout:?} \
                     after dialing {} bootstrap(s)",
                    bootstraps.len()
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Announce this node as a provider of `key` (the multi-provider index).
    ///
    /// SEALED `pub(crate)` (TASK-100 codex BLOCKER, AC#6): the ONLY sanctioned publisher
    /// is [`crate::Libp2pAvailabilityAnnouncer`], which VERIFIES the record's signature
    /// (and, per TASK-231, its publication eligibility) BEFORE publishing. Exposing this
    /// raw write publicly - reachable via the public [`crate::Libp2pFabric::handle`] -
    /// would let a library caller publish an unverifiable value to the kad DHT while
    /// skipping that check. Keeping it crate-private makes the verified announcer the
    /// only path to `put_record`/`start_providing`.
    pub(crate) async fn start_providing(&self, key: kad::RecordKey) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::StartProviding { key, reply }).await;
        rx.await.unwrap_or_else(|_| Err("worker gone".into()))
    }

    /// Stop announcing this node as a provider of `key` (best-effort withdrawal).
    pub async fn stop_providing(&self, key: kad::RecordKey) {
        self.send(Command::StopProviding { key }).await;
    }

    /// Store `value` under `key` in the DHT value store (the signed record), expiring
    /// at `expires` (the record's own expiry, reconciled with the store TTL).
    ///
    /// SEALED `pub(crate)` (TASK-100 codex BLOCKER, AC#6), as [`SwarmHandle::start_providing`]:
    /// the verified [`crate::Libp2pAvailabilityAnnouncer`] is the only publisher, so no
    /// public raw-publish can skip the signature/eligibility check.
    pub(crate) async fn put_record(
        &self,
        key: kad::RecordKey,
        value: Vec<u8>,
        expires: Option<Instant>,
    ) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::PutRecord {
            key,
            value,
            expires,
            reply,
        })
        .await;
        rx.await.unwrap_or_else(|_| Err("worker gone".into()))
    }

    /// Resolve the set of providers of `key` from the DHT, together with the
    /// [`QueryReach`] the iterative query achieved (so an EMPTY provider set can be
    /// classified as an authoritative `Miss` vs a could-not-consult
    /// `InsufficientRouting` - TASK-174).
    pub async fn get_providers(
        &self,
        key: kad::RecordKey,
        max_peers: u32,
    ) -> Result<ProviderFanOut, QueryFail> {
        let (reply, rx) = oneshot::channel();
        let (id_reply, id_rx) = oneshot::channel();
        self.send(Command::GetProviders {
            key,
            max_peers: max_peers as usize,
            id_reply,
            reply,
        })
        .await;
        // Learn the started query's id, then arm cancel-on-drop so an ABANDONED wait (the
        // outer find_providers deadline dropping this future) cancels the kad walk rather
        // than letting it run to its own query_timeout (TASK-154 S4). If the caller is
        // dropped BEFORE the id even arrives, the worker's `id_reply.send` fails and the
        // worker finishes the query itself (TASK-154 B3a) - so no query leaks in that window.
        let Ok(id) = id_rx.await else {
            return Err(QueryFail::Backend("worker gone".into()));
        };
        let mut cancel = CancelOnDrop::new(self.cancels.clone(), id);
        let out = rx
            .await
            .unwrap_or_else(|_| Err(QueryFail::Backend("worker gone".into())));
        cancel.disarm();
        out
    }

    /// Fetch the value stored under `key` from the DHT, if any.
    pub async fn get_record(&self, key: kad::RecordKey) -> Result<Option<Vec<u8>>, QueryFail> {
        let (reply, rx) = oneshot::channel();
        let (id_reply, id_rx) = oneshot::channel();
        self.send(Command::GetRecord {
            key,
            id_reply,
            reply,
        })
        .await;
        let Ok(id) = id_rx.await else {
            return Err(QueryFail::Backend("worker gone".into()));
        };
        let mut cancel = CancelOnDrop::new(self.cancels.clone(), id);
        let out = rx
            .await
            .unwrap_or_else(|_| Err(QueryFail::Backend("worker gone".into())));
        cancel.disarm();
        out
    }

    /// Resolve `peer`'s dialable addresses through kad peer-routing (an active
    /// `get_closest_peers` query). The addresses reach us through the DHT/identify, never
    /// injected. Drives the [`crate::locator::Libp2pNodeLocator`] PublicInfrastructure
    /// path. `Ok((empty, reach))` = the query knew no address; the [`QueryReach`] then
    /// separates an authoritative `Miss` (reached responding peers) from a
    /// could-not-consult `InsufficientRouting` (reached nobody). `Err` = could not be
    /// consulted at all (timeout / backend). TASK-174.
    pub async fn locate_peer(
        &self,
        peer: PeerId,
    ) -> Result<(Vec<Multiaddr>, QueryReach), QueryFail> {
        let (reply, rx) = oneshot::channel();
        let (id_reply, id_rx) = oneshot::channel();
        self.send(Command::LocatePeer {
            peer,
            id_reply,
            reply,
        })
        .await;
        let Ok(id) = id_rx.await else {
            return Err(QueryFail::Backend("worker gone".into()));
        };
        let mut cancel = CancelOnDrop::new(self.cancels.clone(), id);
        let out = rx
            .await
            .unwrap_or_else(|_| Err(QueryFail::Backend("worker gone".into())));
        cancel.disarm();
        out
    }

    /// Fetch `content` from `peer` over the Bao-authenticated `/nar/4` substream,
    /// returning collected, authenticated raw NAR bytes. The full envelope is enforced INSIDE:
    ///
    ///   * `dial_timeout` bounds opening the stream (`open_stream` auto-dials `peer` off the
    ///     kad-known address the transport resolved and `add_address`'d before calling here);
    ///   * `body_idle_timeout` bounds each inter-chunk read (a stalled peer aborts);
    ///   * the response's declared raw size is checked against `expected_size` before tree
    ///     allocation;
    ///   * each decoded raw leaf is authenticated against `content`, and the final leaf is
    ///     released only after COMPLETE plus clean FIN in [`nar::read_response_streamed`].
    ///
    /// The requester keeps its write half OPEN for the whole transfer (the server's
    /// still-interested signal). The transport wraps this in the coarse `total_timeout`.
    pub async fn fetch_nar_streaming(
        &self,
        peer: PeerId,
        content: Blake3Digest,
        expected_size: Option<u64>,
        dial_timeout: Duration,
        body_idle_timeout: Duration,
    ) -> Result<Vec<u8>, TransferError> {
        // The shipped fetch always offers BOTH codecs (raw mandatory, zstd optional); the server
        // picks within that set with raw the guaranteed fallback (TASK-99, AC#5).
        Ok(self
            .fetch_nar_streaming_measured(
                peer,
                content,
                expected_size,
                dial_timeout,
                body_idle_timeout,
                true,
            )
            .await?
            .bytes)
    }

    /// Measurement-facing fetch (TASK-198): like [`fetch_nar_streaming`], but lets the caller
    /// choose whether to OFFER zstd (`offer_zstd = false` sends the raw-only accept set, the
    /// mandatory floor a compliant fetcher always includes) and reports exact successful v4
    /// protocol-byte components alongside the Bao-authenticated NAR.
    ///
    /// It exists so the shaped-link harness can transfer the SAME nar RAW vs ZSTD over the SAME
    /// link and compare like-for-like. Both arms use exact response-protocol totals from
    /// [`crate::NarV4WireAccounting`]: header, Bao proofs, optional per-leaf length prefixes,
    /// encoded leaves, and COMPLETE. It changes no wire framing: the same request and
    /// [`nar::read_response_streamed`] reader are used; only the offered `accept` byte differs.
    /// Not on the hot path.
    pub async fn fetch_nar_streaming_measured(
        &self,
        peer: PeerId,
        content: Blake3Digest,
        expected_size: Option<u64>,
        dial_timeout: Duration,
        body_idle_timeout: Duration,
        offer_zstd: bool,
    ) -> Result<StreamedFetch, TransferError> {
        // Flatten the attribution: measurement callers only care Ok vs error, not WHERE it
        // failed. The `NotOpened` / `OpenedThenFailed` distinction is for the transport's
        // reachability oracle (TASK-218), which calls `fetch_nar_streaming_attributed` directly.
        match self
            .fetch_nar_streaming_attributed(
                peer,
                content,
                expected_size,
                dial_timeout,
                body_idle_timeout,
                offer_zstd,
            )
            .await
        {
            FetchOutcome::Ok(fetch) => Ok(fetch),
            FetchOutcome::NotOpened(error)
            | FetchOutcome::ProtocolIncompatible(error)
            | FetchOutcome::OpenedThenFailed(error) => Err(error),
        }
    }

    /// Streaming NAR fetch that ATTRIBUTES the failure to BEFORE vs AFTER the substream opened
    /// (TASK-218). The split point is `open_stream`: an error/timeout there is a dial /
    /// circuit-establishment failure ([`FetchOutcome::NotOpened`] — the provider was UNREACHABLE
    /// at every resolved dial address); once the stream is open the provider WAS reached and
    /// every subsequent failure (a `NotHeld`/`Declined` reply, declared-size rejection, Bao
    /// `AuthenticationFailed`, malformed/truncated framing, a body-idle timeout, or a post-open
    /// write error) is
    /// [`FetchOutcome::OpenedThenFailed`]. The transport uses this to log "UNREACHABLE" ONLY on
    /// a genuine dial failure, never for a reachable provider that merely does not hold the NAR.
    pub async fn fetch_nar_streaming_attributed(
        &self,
        peer: PeerId,
        content: Blake3Digest,
        expected_size: Option<u64>,
        dial_timeout: Duration,
        body_idle_timeout: Duration,
        offer_zstd: bool,
    ) -> FetchOutcome {
        self.fetch_nar_streaming_attributed_inner(
            peer,
            None,
            NarFetchRequest::new(
                content,
                expected_size,
                dial_timeout,
                body_idle_timeout,
                offer_zstd,
            ),
        )
        .await
    }

    /// Production offer fetch: open the NAR protocol only on `connection`. The vendored stream
    /// control atomically verifies `(connection, peer)` and has no random peer-wide selection,
    /// auto-dial, or fallback. A route that closes between authorization and this call is an
    /// honest pre-open `NotConnected` failure.
    pub(crate) async fn fetch_nar_streaming_attributed_on_connection(
        &self,
        peer: PeerId,
        connection: ConnectionId,
        request: NarFetchRequest,
    ) -> FetchOutcome {
        self.fetch_nar_streaming_attributed_inner(peer, Some(connection), request)
            .await
    }

    async fn fetch_nar_streaming_attributed_inner(
        &self,
        peer: PeerId,
        connection: Option<ConnectionId>,
        request: NarFetchRequest,
    ) -> FetchOutcome {
        let NarFetchRequest {
            content,
            expected_size,
            dial_timeout,
            body_idle_timeout,
            offer_zstd,
        } = request;
        // Clone the Control per fetch: `open_stream` takes `&mut self` and opens one stream
        // at a time, so a fresh clone is the natural unit of concurrency here.
        let mut control = self.control.clone();
        let protocol = self.nar_protocol.clone();
        let open = async {
            match connection {
                Some(connection) => {
                    control
                        .open_stream_on_connection(peer, connection, protocol)
                        .await
                }
                None => control.open_stream(peer, protocol).await,
            }
        };
        // THE ATTRIBUTION BOUNDARY: a failure to open/dial the substream means the provider was
        // never reached (unreachable). Everything past this point is a post-open transfer error.
        let mut stream = match tokio::time::timeout(dial_timeout, open).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(libp2p_stream::OpenStreamError::UnsupportedProtocol(protocol))) => {
                return FetchOutcome::ProtocolIncompatible(TransferError::Unavailable(format!(
                    "peer {peer} does not support required {protocol}; /nar/3 downgrade is forbidden"
                )));
            }
            Ok(Err(error)) => {
                return FetchOutcome::NotOpened(TransferError::Unavailable(format!(
                    "libp2p could not open a NAR stream to {peer}: {error}"
                )));
            }
            Err(_elapsed) => {
                return FetchOutcome::NotOpened(TransferError::Unavailable(format!(
                    "libp2p dialing/opening a NAR stream to {peer} exceeded the dial timeout \
                     {dial_timeout:?}"
                )));
            }
        };
        let accept = if offer_zstd {
            peer_fabric::ACCEPT_RAW_AND_ZSTD
        } else {
            peer_fabric::ACCEPT_RAW
        };
        let request_started = std::time::Instant::now();
        // The substream is OPEN — the provider was REACHED. From here, failures are post-open.
        if let Err(error) = nar::write_request(&mut stream, &content, accept).await {
            return FetchOutcome::OpenedThenFailed(TransferError::Unavailable(format!(
                "libp2p failed to send the NAR request to {peer}: {error}"
            )));
        }
        let request_complete_ns = request_started.elapsed().as_nanos();
        // Count the exact successful response protocol bytes and timestamp its first byte at
        // the same request-write origin used by first-authenticated-leaf and total-fetch.
        let mut counting = CountingReader::new(&mut stream, request_started);
        match nar::read_response_streamed_since(
            &mut counting,
            expected_size,
            body_idle_timeout,
            &content,
            request_started,
            accept,
        )
        .await
        {
            Ok(authenticated) => {
                let wire = match crate::NarV4WireAccounting::from_response_protocol_bytes(
                    authenticated.bytes.len() as u64,
                    authenticated.selected_codec,
                    counting.count(),
                ) {
                    Ok(wire) => wire,
                    Err(error) => {
                        return FetchOutcome::OpenedThenFailed(TransferError::Unavailable(
                            format!("invalid /nar/4 byte accounting for {content}: {error}"),
                        ));
                    }
                };
                let Some(first_response_byte_ns) = counting.first_response_byte_ns() else {
                    return FetchOutcome::OpenedThenFailed(TransferError::Unavailable(format!(
                        "successful /nar/4 response for {content} had no first-byte timestamp"
                    )));
                };
                FetchOutcome::Ok(StreamedFetch {
                    bytes: authenticated.bytes,
                    wire,
                    request_complete_ns,
                    first_response_byte_ns,
                    authenticated_first_leaf_ns: authenticated.authenticated_first_leaf_ns,
                    total_fetch_ns: authenticated.total_fetch_ns,
                    selected_codec: authenticated.selected_codec,
                })
            }
            Err(error) => FetchOutcome::OpenedThenFailed(error),
        }
    }

    /// Install (or replace) the serve gate; inbound NAR requests are then admitted and
    /// answered through it by the accept loop. Synchronous slot write (TASK-157): the byte
    /// path no longer routes through the worker command loop.
    pub async fn install_serve(&self, gate: Arc<ServeGate>) {
        *self.serve_slot.lock().expect("serve slot poisoned") = Some(gate);
    }

    /// Best-effort, non-blocking uninstall of the serve gate, callable from a `Drop` (which
    /// cannot await). The AUTHORITATIVE stop-admitting signal is the gate's own `active` flag
    /// (flipped synchronously by the teardown guard); this only clears the slot so a fresh
    /// serve replaces cleanly. Clears ONLY if the slot still holds EXACTLY `gate` (`Arc`
    /// identity), so a STALE teardown from a superseded session cannot clobber a live
    /// successor installed before the old handle dropped (the re-serve handoff).
    pub fn uninstall_serve_nonblocking(&self, gate: Arc<ServeGate>) {
        let mut slot = self.serve_slot.lock().expect("serve slot poisoned");
        if slot.as_ref().is_some_and(|held| Arc::ptr_eq(held, &gate)) {
            *slot = None;
        } else {
            tracing::debug!(
                "fabric-libp2p: stale serve uninstall ignored (a successor session owns the slot)"
            );
        }
    }
}

/// A query awaiting its terminal kad event.
enum Pending {
    Simple(oneshot::Sender<Result<(), String>>),
    Bootstrap(oneshot::Sender<Result<(), String>>),
    GetProviders {
        /// The BOUNDED aggregation set (TASK-154 B1): at most `max_peers` providers, keyed by
        /// `(rank, PeerId)` and holding the smallest by RANK under this query's `salt`
        /// (TASK-214), maintained by [`retain_bounded_provider`] as each `FoundProviders` event
        /// arrives - never the full unbounded flood.
        found: BTreeSet<(u64, PeerId)>,
        /// The consumer fan-out bound this query aggregates under.
        max_peers: usize,
        /// The FRESH per-query fan-out salt (TASK-214), drawn once when this query started. Fixes
        /// the rank order [`retain_bounded_provider`] selects by for THIS query; a retry is a new
        /// query with a new salt, which is what makes the retained subset non-grindable and
        /// self-healing across retries.
        salt: FanOutSalt,
        /// Set once the `max_peers` bound has discarded any named provider (the result is a
        /// strict subset). Carried out so the directory can distinguish a bounded result from
        /// a complete one (TASK-154 B2 Miss-vs-Unavailable).
        truncated: bool,
        /// TASK-283 discovery-latency anchor: the instant this `get_providers` walk was issued.
        /// The kad latency is `started.elapsed()` in INTEGER ms, emitted at info on the terminal
        /// event (surfaces under `RUST_LOG=info`). Provenance only — never a decision input.
        started: Instant,
        /// TASK-283 provenance: the exact content key this walk resolves ("which query key"),
        /// carried so the emitted latency marker names WHAT was discovered, not just how long.
        key: kad::RecordKey,
        reply: oneshot::Sender<Result<ProviderFanOut, QueryFail>>,
    },
    GetRecord {
        reply: oneshot::Sender<Result<Option<Vec<u8>>, QueryFail>>,
    },
    /// A kad peer-routing lookup awaiting its terminal `GetClosestPeers` event. `target`
    /// is the PeerId we are resolving; on completion we return the addresses the query
    /// learned for exactly that peer, plus the [`QueryReach`] (TASK-174).
    GetClosestPeers {
        target: PeerId,
        reply: oneshot::Sender<Result<(Vec<Multiaddr>, QueryReach), QueryFail>>,
    },
}

impl Pending {
    /// True when the caller awaiting this query's result has DROPPED its receiver, so the
    /// terminal reply would go nowhere. This is how the worker detects an ABANDONED query
    /// (TASK-154 B3). The load-bearing case: a caller dropped in the BUFFERED-ID WINDOW - after
    /// the worker `id_reply.send(id)` succeeds but BEFORE the caller polls `id_rx` and arms its
    /// [`CancelOnDrop`] - leaves a `Pending` here with NO cancel signal wired. The `id`-arm race
    /// (`id_reply.send` failing) does not cover it because the send SUCCEEDED into a buffered
    /// channel. Observing the closed reply (on the next kad event or the periodic sweep) lets the
    /// worker cancel the walk instead of running it to its full `kad_query_timeout`.
    ///
    /// A normally-waiting caller holds its receiver, so this is `false` until the reply is sent
    /// or the caller genuinely goes away - a healthy query is never reaped.
    fn reply_is_closed(&self) -> bool {
        match self {
            Pending::Simple(reply) | Pending::Bootstrap(reply) => reply.is_closed(),
            Pending::GetProviders { reply, .. } => reply.is_closed(),
            Pending::GetRecord { reply } => reply.is_closed(),
            Pending::GetClosestPeers { reply, .. } => reply.is_closed(),
        }
    }
}

/// The [`kad::QueryId`]s in `pending` whose caller has ABANDONED the query (dropped its
/// receiver). Pure SELECTION, split from the swarm-touching cancel ([`Worker::cancel_query`]) so
/// the abandoned-query reap can be unit-proven network-free (TASK-154 B3): the worker feeds the
/// result to `cancel_query`, which finishes the kad walk and drops the entry.
fn abandoned_query_ids(pending: &HashMap<kad::QueryId, Pending>) -> Vec<kad::QueryId> {
    pending
        .iter()
        .filter(|(_, p)| p.reply_is_closed())
        .map(|(id, _)| *id)
        .collect()
}

/// Bounded admission control for mDNS-discovered LAN peers (TASK-257 F-1). mDNS advertisements
/// are UNAUTHENTICATED and UNCAPPED: any LAN host can multicast arbitrary (PeerId, addr, TTL)
/// pairs, so a single malicious host emitting many generated PeerIds could flood us into dialing
/// (and, for same-scope-speaking floods, admitting) an unbounded number of peers - a routing-table
/// eclipse/skew vector. This gate caps the number of DISTINCT mDNS peers we ACT ON (dial) per
/// fixed integer-seconds window, so a flood is bounded, not unbounded. All quantities are INTEGERS
/// (a count and an integer-seconds window; owner no-floats rule) and the state is bounded (the
/// admitted set is cleared each window, so its size is <= `cap`). A same-window re-advertisement of
/// an already-admitted peer is free (it refreshes, never re-charges the cap), so legitimate churn
/// within the cap is unaffected; the (N - cap) surplus of a burst is dropped.
struct MdnsAdmission {
    /// Max DISTINCT mDNS peers admitted (dialed) per window. INTEGER.
    cap: usize,
    /// The window length. Integer seconds (constructed from an integer-seconds constant).
    window: Duration,
    /// Start of the current window; the admitted set is cleared when `window` elapses.
    window_start: Instant,
    /// The mDNS peers already admitted in THIS window (bounded by `cap`).
    admitted: std::collections::HashSet<PeerId>,
}

impl MdnsAdmission {
    fn new(cap: usize, window: Duration, now: Instant) -> Self {
        MdnsAdmission {
            cap,
            window,
            window_start: now,
            admitted: std::collections::HashSet::new(),
        }
    }

    /// Decide whether to ACT ON (dial) an mDNS-discovered `peer` now. Returns `true` iff admitted.
    /// Rolls the window (clearing the admitted set) when `window` has elapsed. An already-admitted
    /// peer this window is admitted again for free (refresh); an unseen peer is admitted only while
    /// `admitted.len() < cap`, so at most `cap` DISTINCT peers are admitted per window.
    fn admit(&mut self, peer: PeerId, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= self.window {
            self.window_start = now;
            self.admitted.clear();
        }
        if self.admitted.contains(&peer) {
            return true;
        }
        if self.admitted.len() >= self.cap {
            return false;
        }
        self.admitted.insert(peer);
        true
    }
}

/// The worker: owns the swarm, drives it, and matches kad query terminals back to the
/// oneshot the command carried. The NAR byte transfer is NOT here (TASK-157): it runs on
/// the accept loop + per-stream tasks through the [`libp2p_stream::Control`], off this loop.
struct Worker {
    swarm: Swarm<Behaviour>,
    commands: mpsc::Receiver<Command>,
    /// The LOSSLESS query-cancel channel (TASK-154 B3): abandoned-query [`kad::QueryId`]s from
    /// dropped [`CancelOnDrop`] guards. Drained every loop iteration and routed to
    /// [`Worker::cancel_query`]. Dedicated + unbounded so a cancel is never lost to command
    /// channel backpressure.
    cancels: mpsc::UnboundedReceiver<kad::QueryId>,
    /// Lossless cancellation notices from dropped exact-dial waiters. Each notice converts the
    /// pending entry to a tombstone; it never deletes authority while a late success is possible.
    exact_dial_cancels: mpsc::UnboundedReceiver<(PeerId, ConnectionId)>,
    pending: HashMap<kad::QueryId, Pending>,
    /// Listener registrations waiting for their exact ListenerId's first `NewListenAddr` event.
    pending_listens: HashMap<ListenerId, PendingListen>,
    /// Exact authorized dials awaiting terminal success/error. A dropped caller becomes a
    /// tombstone, retained until that terminal event; the hard admission cap bounds memory.
    pending_exact_dials: HashMap<ConnectionId, PendingExactDial>,
    /// Exact live ConnectionId -> route provenance per peer. Derived and retired with connection
    /// events; never populated from offers or routing results, so it is live transport fact rather
    /// than a provider cache. Needed because libp2p-stream may choose any peer connection.
    conn_routes: HashMap<PeerId, HashMap<ConnectionId, ConnectionRoute>>,
    /// Bounded admission control for mDNS-discovered peers (TASK-257 F-1): caps how many distinct
    /// LAN advertisements we act on per window, so an unauthenticated mDNS flood cannot skew routing.
    mdns_admission: MdnsAdmission,
    /// The LAN-confinement live view (TASK-280): `Some` ONLY on the no-allowlist `lan-share` path.
    /// Its presence is the SINGLE source of truth for LAN confinement in the worker — it both (a)
    /// gates the `identify`/`mDNS` `add_address` callsites to LAN-only addresses (k-bucket hygiene)
    /// and (b) records each connection's LAN provenance for the accept loop's serve gate. `None` for
    /// every other profile (unrestricted dialing + serving).
    lan_serve_conns: Option<LanServeConns>,
    /// This node's scoped identify `protocol_version` string (`/nix-p2p/<scope>/id/1.0.0`). Identify
    /// negotiates the FIXED libp2p name `/ipfs/id/1.0.0`, so the scope split alone does NOT stop a
    /// cross-scope peer from completing identify — the scope rides only in this metadata string. Under
    /// confinement (`lan_serve_conns.is_some()`, the single confinement source) the identify receive
    /// path REJECTS a peer whose advertised `protocol_version` differs from this (TASK-280 #4),
    /// dropping its addresses. Plain data (always known); its USE is gated on confinement.
    id_protocol: String,
    /// TASK-283 discovery-latency anchor: the instant the worker was constructed (node start).
    /// The mDNS "time-to-first-peer" latency is measured against this and emitted ONCE at
    /// info level (surfaces under `RUST_LOG=info`). It is the honest discovery-latency floor:
    /// elapsed from node start to the first LAN peer this node acts on (`add_address`).
    started_at: Instant,
    /// TASK-283: set true after the first mDNS peer's latency has been reported, so the
    /// `DISCOVERY-LATENCY-MDNS` marker is emitted exactly once per node (time-to-first-peer),
    /// not once per re-advertised record.
    first_mdns_reported: bool,
}

struct PendingListen {
    requested: Multiaddr,
    reply: oneshot::Sender<Result<(), String>>,
}

enum PendingExactDial {
    Active {
        peer: PeerId,
        permitted_relays: BTreeSet<PeerId>,
        reply: oneshot::Sender<Result<AuthorizedConnection, String>>,
    },
    Tombstone {
        peer: PeerId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactDialCancelTransition {
    /// No pending attempt or admitted route exists. This includes cancellation winning the
    /// worker's select race before its already-enqueued command; the command then carries a
    /// closed reply, so a later success is rejected by [`apply_connection_established`].
    None,
    /// The dial is in flight. Its authority was replaced by a tombstone and must remain until
    /// libp2p reports the exact attempt's terminal success or error.
    AwaitTerminal,
    /// The exact connection was admitted just before cancellation arrived. Its route was removed
    /// and a tombstone installed; the worker must close precisely this [`ConnectionId`].
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionEstablishedTransition {
    Keep,
    Close(ExactConnectionCloseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactConnectionCloseReason {
    Cancelled,
    UnauthorizedRoute,
    WaiterGone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionRoute {
    Direct,
    Relayed { relay: PeerId },
    RelayedUnknown,
}

/// The exact live connection selected for one offer. The transport passes `id` unchanged into
/// `Control::open_stream_on_connection`; `route` drives event-accurate exposure accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorizedConnection {
    pub(crate) id: ConnectionId,
    pub(crate) route: ConnectionRoute,
}

impl AuthorizedConnection {
    pub(crate) fn relay_peer(self) -> Option<PeerId> {
        match self.route {
            ConnectionRoute::Relayed { relay } => Some(relay),
            ConnectionRoute::Direct | ConnectionRoute::RelayedUnknown => None,
        }
    }
}

/// Whether this live route may carry a request whose exact offer permits `relays`.
/// Direct is always preferred/allowed. A circuit is allowed only when its observed relay
/// identity occurs in the current offer-derived set; an unparseable circuit fails closed.
fn connection_route_allowed(route: &ConnectionRoute, relays: &BTreeSet<PeerId>) -> bool {
    match route {
        ConnectionRoute::Direct => true,
        ConnectionRoute::Relayed { relay } => relays.contains(relay),
        ConnectionRoute::RelayedUnknown => false,
    }
}

/// Remove one exact route and prune only its now-empty peer bucket. Other connections to the
/// same peer are deliberately untouched: they may be carrying concurrent requests authorized by
/// a different offer.
fn remove_connection_route(
    conn_routes: &mut HashMap<PeerId, HashMap<ConnectionId, ConnectionRoute>>,
    peer: PeerId,
    connection: ConnectionId,
) -> bool {
    let removed = conn_routes
        .get_mut(&peer)
        .is_some_and(|routes| routes.remove(&connection).is_some());
    if conn_routes.get(&peer).is_some_and(HashMap::is_empty) {
        conn_routes.remove(&peer);
    }
    removed
}

/// Apply one lossless cancellation notice without touching the swarm. The returned transition is
/// the complete side-effect contract for the worker: only [`ExactDialCancelTransition::Close`]
/// requires a libp2p close operation.
fn apply_exact_dial_cancel(
    pending_exact_dials: &mut HashMap<ConnectionId, PendingExactDial>,
    conn_routes: &mut HashMap<PeerId, HashMap<ConnectionId, ConnectionRoute>>,
    peer: PeerId,
    connection: ConnectionId,
) -> ExactDialCancelTransition {
    if let Some(pending) = pending_exact_dials.get_mut(&connection) {
        let expected_peer = match pending {
            PendingExactDial::Active { peer, .. } | PendingExactDial::Tombstone { peer } => *peer,
        };
        *pending = PendingExactDial::Tombstone {
            peer: expected_peer,
        };
        return ExactDialCancelTransition::AwaitTerminal;
    }

    if remove_connection_route(conn_routes, peer, connection) {
        pending_exact_dials.insert(connection, PendingExactDial::Tombstone { peer });
        ExactDialCancelTransition::Close
    } else {
        ExactDialCancelTransition::None
    }
}

/// Apply one `ConnectionEstablished` event to the exact-dial authority state and route ledger.
///
/// For a valid active attempt, delivery of the exact [`AuthorizedConnection`] is the admission
/// linearization point: the route is inserted only when `reply.send` succeeds. A closed waiter can
/// therefore never leave a selectable route behind, even if it closes between an earlier status
/// check and the send. The worker performs the returned close operation after this state change.
fn apply_connection_established(
    pending_exact_dials: &mut HashMap<ConnectionId, PendingExactDial>,
    conn_routes: &mut HashMap<PeerId, HashMap<ConnectionId, ConnectionRoute>>,
    peer_id: PeerId,
    connection_id: ConnectionId,
    route: ConnectionRoute,
) -> ConnectionEstablishedTransition {
    match pending_exact_dials.remove(&connection_id) {
        Some(PendingExactDial::Tombstone { .. }) => {
            ConnectionEstablishedTransition::Close(ExactConnectionCloseReason::Cancelled)
        }
        Some(PendingExactDial::Active {
            peer,
            permitted_relays,
            reply,
        }) if peer != peer_id || !connection_route_allowed(&route, &permitted_relays) => {
            let _ = reply.send(Err(format!(
                "exact dial {connection_id} expected authorized route to {peer}, but established peer {peer_id} via {route:?}"
            )));
            ConnectionEstablishedTransition::Close(ExactConnectionCloseReason::UnauthorizedRoute)
        }
        Some(PendingExactDial::Active { reply, .. }) => {
            let authorized = AuthorizedConnection {
                id: connection_id,
                route,
            };
            if reply.send(Ok(authorized)).is_err() {
                ConnectionEstablishedTransition::Close(ExactConnectionCloseReason::WaiterGone)
            } else {
                conn_routes
                    .entry(peer_id)
                    .or_default()
                    .insert(connection_id, route);
                ConnectionEstablishedTransition::Keep
            }
        }
        None => {
            conn_routes
                .entry(peer_id)
                .or_default()
                .insert(connection_id, route);
            ConnectionEstablishedTransition::Keep
        }
    }
}

/// Derive the aggregate operator-facing path from the one exact route ledger. Direct dominates so
/// a hole-punched peer reports direct even while a relay circuit coexists.
fn connection_path_from_routes(
    routes: Option<&HashMap<ConnectionId, ConnectionRoute>>,
) -> ConnPath {
    let mut saw_relay = false;
    for route in routes.into_iter().flat_map(HashMap::values) {
        match route {
            ConnectionRoute::Direct => return ConnPath::Direct,
            ConnectionRoute::Relayed { .. } | ConnectionRoute::RelayedUnknown => saw_relay = true,
        }
    }
    if saw_relay {
        ConnPath::Relay
    } else {
        ConnPath::None
    }
}

/// Select deterministically from current fact: lowest direct ConnectionId first, otherwise the
/// lowest ConnectionId carried by a relay authorized by the current exact offer.
fn select_authorized_connection(
    routes: Option<&HashMap<ConnectionId, ConnectionRoute>>,
    relays: &BTreeSet<PeerId>,
) -> Option<AuthorizedConnection> {
    let routes = routes?;
    routes
        .iter()
        .filter(|(_, route)| matches!(route, ConnectionRoute::Direct))
        .min_by_key(|(connection, _)| *connection)
        .or_else(|| {
            routes
                .iter()
                .filter(|(_, route)| connection_route_allowed(route, relays))
                .min_by_key(|(connection, _)| *connection)
        })
        .map(|(id, route)| AuthorizedConnection {
            id: *id,
            route: *route,
        })
}

/// The relay in a standard circuit-v2 address is the `/p2p/<relay>` component immediately before
/// `/p2p-circuit`. Reject other shapes instead of guessing from some unrelated PeerId component.
fn circuit_relay_peer(address: &Multiaddr) -> Option<PeerId> {
    let mut previous_peer = None;
    for protocol in address.iter() {
        if matches!(protocol, libp2p::multiaddr::Protocol::P2pCircuit) {
            return previous_peer;
        }
        previous_peer = match protocol {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
            _ => None,
        };
    }
    None
}

fn is_circuit_address(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::P2pCircuit))
}

fn endpoint_relay_peer(endpoint: &ConnectedPoint) -> Option<PeerId> {
    let address = match endpoint {
        ConnectedPoint::Dialer { address, .. } => address,
        ConnectedPoint::Listener { local_addr, .. } => local_addr,
    };
    circuit_relay_peer(address)
}

fn connection_route(endpoint: &ConnectedPoint) -> ConnectionRoute {
    if !endpoint.is_relayed() {
        ConnectionRoute::Direct
    } else if let Some(relay) = endpoint_relay_peer(endpoint) {
        ConnectionRoute::Relayed { relay }
    } else {
        ConnectionRoute::RelayedUnknown
    }
}

impl Worker {
    async fn run(mut self) {
        // TASK-154 B3: periodic abandoned-query sweep. The eager reap at the top of `on_query`
        // cancels a query the instant its NEXT event arrives, but a query abandoned in the
        // buffered-id window that then emits NO further event (a stalled walk) would still sit
        // until `kad_query_timeout`. This tick bounds that residual to at most one interval.
        // First tick fires immediately (a no-op on an empty pending map); `Delay` avoids a
        // catch-up burst if the loop was busy.
        let mut sweep = tokio::time::interval(ABANDONED_QUERY_SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                command = self.commands.recv() => match command {
                    Some(command) => self.on_command(command),
                    None => {
                        tracing::debug!("fabric-libp2p: all handles dropped, worker exiting");
                        break;
                    }
                },
                // A dropped caller's abandoned query (TASK-154 B3): cancel it promptly so it
                // does not run to its full `query_timeout`. `recv()` yields `None` only once
                // every handle (and thus every cancel sender) is dropped, in which case the
                // command branch above also closes and ends the loop - so a `None` here is a
                // harmless no-op, not a busy spin.
                Some(id) = self.cancels.recv() => self.cancel_query(id),
                Some((peer, connection)) = self.exact_dial_cancels.recv() => {
                    self.tombstone_exact_dial(peer, connection);
                },
                // TASK-154 B3: reap any query whose caller went away in the buffered-id window
                // (no CancelOnDrop armed) even if it never emits another event.
                _ = sweep.tick() => {
                    self.reap_abandoned();
                    self.reap_abandoned_listens();
                    self.tombstone_abandoned_exact_dials();
                },
                event = self.swarm.select_next_some() => self.on_event(event),
            }
        }
    }

    /// Cancel every abandoned in-flight query (TASK-154 B3): any [`Pending`] whose caller dropped
    /// its receiver. Runs on the periodic sweep so a query abandoned in the buffered-id window is
    /// reaped even if it emits no further kad event. The selection is the pure
    /// [`abandoned_query_ids`]; the effect is [`Worker::cancel_query`] (finish the walk + drop the
    /// entry), which is idempotent and panic-free on an already-terminated id.
    fn reap_abandoned(&mut self) {
        for id in abandoned_query_ids(&self.pending) {
            tracing::debug!(
                ?id,
                "fabric-libp2p: reaping abandoned kad query (caller dropped)"
            );
            self.cancel_query(id);
        }
    }

    /// Stop an abandoned in-flight kad query (TASK-154 S4/B3). `finish()` makes kad terminate
    /// the walk at the next poll instead of running it to `query_timeout`; dropping the pending
    /// entry discards the terminal reply. Both are no-ops for an id that already terminated (or
    /// was never inserted), so a late/duplicate/never-pending cancel is safe - never a panic.
    fn cancel_query(&mut self, id: kad::QueryId) {
        if let Some(mut query) = self.swarm.behaviour_mut().kad.query_mut(&id) {
            query.finish();
        }
        self.pending.remove(&id);
    }

    fn reap_abandoned_listens(&mut self) {
        let abandoned: Vec<ListenerId> = self
            .pending_listens
            .iter()
            .filter_map(|(id, pending)| pending.reply.is_closed().then_some(*id))
            .collect();
        for id in abandoned {
            if let Some(pending) = self.pending_listens.remove(&id) {
                tracing::debug!(
                    listener = ?id,
                    requested = %pending.requested,
                    "fabric-libp2p: removing listener whose bounded readiness waiter expired"
                );
                self.swarm.remove_listener(id);
            }
        }
    }

    fn tombstone_abandoned_exact_dials(&mut self) {
        let abandoned: Vec<(PeerId, ConnectionId)> = self
            .pending_exact_dials
            .iter()
            .filter_map(|(id, pending)| match pending {
                PendingExactDial::Active { peer, reply, .. } if reply.is_closed() => {
                    Some((*peer, *id))
                }
                PendingExactDial::Active { .. } | PendingExactDial::Tombstone { .. } => None,
            })
            .collect();
        for (peer, id) in abandoned {
            self.tombstone_exact_dial(peer, id);
        }
    }

    fn tombstone_exact_dial(&mut self, peer: PeerId, connection: ConnectionId) {
        let expected_peer =
            self.pending_exact_dials
                .get(&connection)
                .map(|pending| match pending {
                    PendingExactDial::Active { peer, .. }
                    | PendingExactDial::Tombstone { peer } => *peer,
                });
        if let Some(expected) = expected_peer.filter(|expected| *expected != peer) {
            tracing::error!(
                %peer,
                expected_peer = %expected,
                %connection,
                "fabric-libp2p: exact-dial cancel named the wrong peer; retaining authority tombstone"
            );
        }

        match apply_exact_dial_cancel(
            &mut self.pending_exact_dials,
            &mut self.conn_routes,
            peer,
            connection,
        ) {
            ExactDialCancelTransition::None => {}
            ExactDialCancelTransition::AwaitTerminal => {
                tracing::debug!(
                    %peer,
                    %connection,
                    "fabric-libp2p: exact dial cancelled; awaiting its terminal event"
                );
            }
            ExactDialCancelTransition::Close => {
                self.swarm.close_connection(connection);
                tracing::debug!(
                    %peer,
                    %connection,
                    "fabric-libp2p: closing exact dial that succeeded after its caller expired"
                );
            }
        }
    }

    fn on_command(&mut self, command: Command) {
        // `kad` is reborrowed per-arm (not bound once at the top) so the arms that drive
        // OTHER behaviours (the NAR request-response) or plain swarm ops do not conflict
        // with a long-lived `&mut kad` borrow of the swarm.
        match command {
            Command::Listen { addr, reply } => match self.swarm.listen_on(addr.clone()) {
                Ok(listener) => {
                    self.pending_listens.insert(
                        listener,
                        PendingListen {
                            requested: addr,
                            reply,
                        },
                    );
                }
                Err(error) => {
                    let _ = reply.send(Err(format!(
                        "registering libp2p listener {addr} failed: {error}"
                    )));
                }
            },
            Command::ListenAddrs { reply } => {
                // Derive from the swarm's own listener set rather than a parallel Vec:
                // it is always current (pruned on ListenerClosed/ExpiredListenAddr) and
                // is the single source of truth for what is bound.
                let _ = reply.send(self.swarm.listeners().cloned().collect());
            }
            Command::AddExternalAddress { addr } => {
                // Mark this address as an externally-reachable address of ours: identify
                // advertises it and the relay server can cite it in reservation vouchers.
                self.swarm.add_external_address(addr);
            }
            Command::AddAddress { peer, addr } => {
                self.swarm.behaviour_mut().kad.add_address(&peer, addr);
            }
            Command::Dial { addr, reply } => {
                let result = self.swarm.dial(addr).map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            Command::DialExact {
                peer,
                options,
                permitted_relays,
                reply,
            } => {
                let connection_id = options.connection_id();
                if self.pending_exact_dials.len() >= MAX_PENDING_EXACT_DIALS {
                    let _ = reply.send(Err(format!(
                        "refusing exact dial to {peer}: {} active/tombstoned attempts reached hard cap {}",
                        self.pending_exact_dials.len(),
                        MAX_PENDING_EXACT_DIALS
                    )));
                    return;
                }
                // Insert before dialing so every successfully registered exact attempt has an
                // authority entry. The worker cannot poll a terminal event until this command
                // returns, so there is no event-before-insert race.
                self.pending_exact_dials.insert(
                    connection_id,
                    PendingExactDial::Active {
                        peer,
                        permitted_relays,
                        reply,
                    },
                );
                if let Err(error) = self.swarm.dial(options)
                    && let Some(PendingExactDial::Active { reply, .. }) =
                        self.pending_exact_dials.remove(&connection_id)
                {
                    let _ = reply.send(Err(format!(
                        "registering exact authorized dial {connection_id} to {peer} failed: {error}"
                    )));
                }
            }
            Command::Bootstrap { reply } => match self.swarm.behaviour_mut().kad.bootstrap() {
                Ok(id) => {
                    self.pending.insert(id, Pending::Bootstrap(reply));
                }
                Err(e) => {
                    let _ = reply.send(Err(e.to_string()));
                }
            },
            Command::RoutingPeers { reply } => {
                let count: usize = self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .kbuckets()
                    .map(|bucket| bucket.num_entries())
                    .sum();
                let _ = reply.send(count);
            }
            Command::IsConnected { peer, reply } => {
                // `Swarm::is_connected` is true only once a connection's upgrade (Noise + yamux)
                // has completed and `ConnectionEstablished` fired — exactly the post-handshake
                // signal the F3 caller polls for before starting its timed window.
                let _ = reply.send(self.swarm.is_connected(&peer));
            }
            Command::ConnectionPath { peer, reply } => {
                let path = connection_path_from_routes(self.conn_routes.get(&peer));
                let _ = reply.send(path);
            }
            Command::ConnectionRelays { peer, reply } => {
                let mut relays: Vec<PeerId> = self
                    .conn_routes
                    .get(&peer)
                    .into_iter()
                    .flat_map(|routes| routes.values())
                    .filter_map(|route| match route {
                        ConnectionRoute::Relayed { relay } => Some(*relay),
                        ConnectionRoute::Direct | ConnectionRoute::RelayedUnknown => None,
                    })
                    .collect();
                relays.sort_unstable();
                relays.dedup();
                let _ = reply.send(relays);
            }
            Command::AuthorizedConnection {
                peer,
                permitted_relays,
                reply,
            } => {
                let selected =
                    select_authorized_connection(self.conn_routes.get(&peer), &permitted_relays);
                let _ = reply.send(selected);
            }
            Command::StartProviding { key, reply } => {
                match self.swarm.behaviour_mut().kad.start_providing(key) {
                    Ok(id) => {
                        self.pending.insert(id, Pending::Simple(reply));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e.to_string()));
                    }
                }
            }
            Command::StopProviding { key } => {
                self.swarm.behaviour_mut().kad.stop_providing(&key);
            }
            Command::PutRecord {
                key,
                value,
                expires,
                reply,
            } => {
                let mut record = kad::Record::new(key, value);
                // Reconcile the record's own expiry with the store TTL (AC#6): setting
                // `expires` makes the store hold it no longer than the provider signed.
                record.expires = expires;
                match self
                    .swarm
                    .behaviour_mut()
                    .kad
                    .put_record(record, kad::Quorum::One)
                {
                    Ok(id) => {
                        self.pending.insert(id, Pending::Simple(reply));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e.to_string()));
                    }
                }
            }
            Command::GetProviders {
                key,
                max_peers,
                id_reply,
                reply,
            } => {
                // TASK-283: clone the key for the latency marker's provenance BEFORE it is
                // moved into the walk; the clone is a short Vec (the content key), off the
                // hot path (one per discovery, not per byte).
                let key_provenance = key.clone();
                let started = Instant::now();
                let id = self.swarm.behaviour_mut().kad.get_providers(key);
                // Hand the id back BEFORE the result so the caller can cancel this query on an
                // abandoned wait (TASK-154 S4). If the caller ALREADY went away (dropped before
                // even learning the id), `id_reply.send` fails - so instead of inserting a
                // Pending that runs to `query_timeout` replying into a dead receiver, finish
                // the query NOW (TASK-154 B3a: close the enqueue-to-id race window).
                if id_reply.send(id).is_err() {
                    self.cancel_query(id);
                    return;
                }
                // TASK-214: draw a FRESH salt for THIS query from the OS CSPRNG. Because it is
                // chosen here - AFTER any attacker's PeerIds are already minted - and re-drawn on
                // every retry (each retry is a new GetProviders command), the retained fan-out
                // subset is a fresh pseudo-random sample, not the fixed grindable
                // smallest-by-PeerId. A u64 (no float enters the selection decision).
                let salt: FanOutSalt = rand::random();
                self.pending.insert(
                    id,
                    Pending::GetProviders {
                        found: BTreeSet::new(),
                        max_peers,
                        salt,
                        truncated: false,
                        started,
                        key: key_provenance,
                        reply,
                    },
                );
            }
            Command::GetRecord {
                key,
                id_reply,
                reply,
            } => {
                let id = self.swarm.behaviour_mut().kad.get_record(key);
                if id_reply.send(id).is_err() {
                    self.cancel_query(id);
                    return;
                }
                self.pending.insert(id, Pending::GetRecord { reply });
            }
            Command::LocatePeer {
                peer,
                id_reply,
                reply,
            } => {
                // Iterative peer-routing to `peer`'s own key: the query walks the DHT and
                // the k-closest set it converges on carries the addresses a shared
                // bootstrap reported for `peer` (learned via identify). This is what lets
                // the resolver dial without an injected address.
                let id = self.swarm.behaviour_mut().kad.get_closest_peers(peer);
                // Same abandoned-before-id guard as GetProviders (TASK-154 B3a): if the caller
                // is already gone, finish the query now rather than let it run to timeout.
                if id_reply.send(id).is_err() {
                    self.cancel_query(id);
                    return;
                }
                self.pending.insert(
                    id,
                    Pending::GetClosestPeers {
                        target: peer,
                        reply,
                    },
                );
            }
        }
    }

    fn on_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                tracing::debug!(%address, "fabric-libp2p: listening");
                if let Some(pending) = self.pending_listens.remove(&listener_id) {
                    let _ = pending.reply.send(Ok(()));
                }
            }
            SwarmEvent::ListenerError { listener_id, error } => {
                let requested = self
                    .pending_listens
                    .get(&listener_id)
                    .map(|pending| pending.requested.to_string())
                    .unwrap_or_else(|| "already-ready listener".to_string());
                // libp2p documents ListenerError as non-terminal; keep waiting for either a
                // concrete NewListenAddr or terminal ListenerClosed under the caller's bound.
                tracing::warn!(
                    listener = ?listener_id,
                    %requested,
                    %error,
                    "fabric-libp2p: listener reported a non-terminal error while awaiting readiness"
                );
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } => {
                if let Some(pending) = self.pending_listens.remove(&listener_id) {
                    let detail = reason.map_or_else(
                        |error| error.to_string(),
                        |()| "listener closed without an error".to_string(),
                    );
                    let _ = pending.reply.send(Err(format!(
                        "libp2p listener {} ({listener_id:?}) closed before NewListenAddr: {detail}",
                        pending.requested
                    )));
                }
            }
            // One live ConnectionId ledger is the SSOT for route selection, exposure attribution,
            // and aggregate status. Exact-dial terminal events additionally enforce their
            // offer-derived route authority before admission.
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                let route = connection_route(&endpoint);
                if let ConnectionEstablishedTransition::Close(reason) = apply_connection_established(
                    &mut self.pending_exact_dials,
                    &mut self.conn_routes,
                    peer_id,
                    connection_id,
                    route,
                ) {
                    self.swarm.close_connection(connection_id);
                    tracing::debug!(
                        %peer_id,
                        %connection_id,
                        ?route,
                        ?reason,
                        "fabric-libp2p: closing exact connection rejected by authority transition"
                    );
                } else if let Some(lan_conns) = &self.lan_serve_conns {
                    // LAN confinement (TASK-280 mitigation #2): record this KEPT connection's LAN
                    // provenance for the accept loop's serve gate. The remote address is the DIALED
                    // address for an outbound connection and the observed `send_back_addr` for an
                    // inbound one; a relayed (`/p2p-circuit`) endpoint classifies NON-LAN. Only
                    // LAN-provenance connections are recorded, so a serve over an outbound connection
                    // to a non-LAN peer (the bidirectional-serve leg) finds no entry and is refused.
                    let remote = endpoint.get_remote_address();
                    if multiaddr_lan_provenance(remote) {
                        lan_conns
                            .lock()
                            .expect("lan serve conns poisoned")
                            .entry(peer_id)
                            .or_default()
                            .insert(connection_id);
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                peer_id,
                error,
            } => match self.pending_exact_dials.remove(&connection_id) {
                Some(PendingExactDial::Active { peer, reply, .. }) => {
                    let target = peer_id.unwrap_or(peer);
                    let _ = reply.send(Err(format!(
                        "exact authorized dial {connection_id} to {target} failed: {error}"
                    )));
                }
                Some(PendingExactDial::Tombstone { peer }) => {
                    tracing::debug!(
                        %peer,
                        %connection_id,
                        %error,
                        "fabric-libp2p: cancelled exact dial reached its terminal error"
                    );
                }
                None => {}
            },
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                ..
            } => {
                if let Some(PendingExactDial::Active { reply, .. }) =
                    self.pending_exact_dials.remove(&connection_id)
                {
                    let _ = reply.send(Err(format!(
                        "exact authorized connection {connection_id} to {peer_id} closed before it became usable"
                    )));
                }
                remove_connection_route(&mut self.conn_routes, peer_id, connection_id);
                // Retire this connection from the LAN-provenance serve view (TASK-280). Remove by
                // id (no need to re-classify the endpoint); prune the peer's now-empty bucket so a
                // peer with zero live LAN connections is no longer serve-eligible.
                if let Some(lan_conns) = &self.lan_serve_conns {
                    let mut map = lan_conns.lock().expect("lan serve conns poisoned");
                    if let Some(conns) = map.get_mut(&peer_id) {
                        conns.remove(&connection_id);
                        if conns.is_empty() {
                            map.remove(&peer_id);
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                // Identify tells us a peer's real listen addresses; feed them into kad
                // routing so iterative lookups can reach it. Under LAN confinement (TASK-280),
                // admit ONLY LAN-provenance addresses into the k-buckets (hygiene): the dial
                // VETO is the real chokepoint (it also stops query-learned addresses that never
                // reach `add_address`), but keeping non-LAN addresses out of routing avoids
                // wasted denied-dial churn.
                let confined = self.lan_serve_conns.is_some();
                // TASK-280 #4 (cross-scope identify): identify negotiates the FIXED /ipfs/id/1.0.0
                // name, so a cross-scope (e.g. public v1) peer completes identify with us even though
                // it can never complete our SCOPED kad/nar handshakes. The scope rides only in the
                // `protocol_version` METADATA. The COMPLETE gate — the cross-scope protocol_version
                // REJECT and the per-address LAN-provenance FILTER — lives in the pure
                // `identify_admitted_addresses`; this handler only APPLIES its result (adds exactly
                // the returned addresses to kad routing), so it holds NO gate logic of its own and a
                // mutation of EITHER sub-gate is caught by the unit test that drives that function
                // (codex TEST-QUALITY: the earlier test was a string-equality on the protocol_version
                // predicate and never exercised the address filter / production apply at all).
                let admitted = identify_admitted_addresses(
                    confined,
                    &info.protocol_version,
                    &self.id_protocol,
                    info.listen_addrs.iter().cloned(),
                );
                if confined && admitted.is_empty() && !info.listen_addrs.is_empty() {
                    tracing::debug!(
                        %peer_id,
                        advertised = %info.protocol_version,
                        expected = %self.id_protocol,
                        "fabric-libp2p: lan-share confinement admitted NO identify addresses \
                         (cross-scope protocol_version and/or no LAN-provenance address); none added \
                         to kad routing"
                    );
                }
                let kad = &mut self.swarm.behaviour_mut().kad;
                for addr in admitted {
                    kad.add_address(&peer_id, addr);
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                id,
                result,
                stats,
                step,
                ..
            })) => self.on_query(id, result, stats, step.last),
            // NAT traversal (TASK-168): we do not DRIVE these from the poll loop (libp2p
            // handles the probing/reservation/hole-punch state machines internally), but we
            // LOG them (fail verbosely) so a "fails behind NAT" incident is diagnosable - the
            // reachability verdict, the relay reservation, and each hole-punch outcome.
            SwarmEvent::Behaviour(BehaviourEvent::Autonat(autonat::Event::StatusChanged {
                old,
                new,
            })) => {
                // The reachability verdict flipping to `Private` is the signal a node is behind
                // NAT and must rely on a relay/hole-punch to be dialed - the load-bearing state.
                tracing::info!(?old, ?new, "fabric-libp2p: autonat reachability changed");
            }
            SwarmEvent::Behaviour(BehaviourEvent::RelayClient(ev)) => {
                // A reservation accepted / circuit established is how a NAT'd node becomes
                // reachable through a relay; surface it at info so the harness can attribute it.
                tracing::info!(?ev, "fabric-libp2p: relay client (circuit-v2)");
            }
            SwarmEvent::Behaviour(BehaviourEvent::Relay(ev)) => {
                // This node acting AS a relay for others; debug (routine housekeeping).
                tracing::debug!(?ev, "fabric-libp2p: relay server (circuit-v2)");
            }
            SwarmEvent::Behaviour(BehaviourEvent::Dcutr(ev)) => match &ev.result {
                Ok(_) => tracing::info!(
                    peer = %ev.remote_peer_id,
                    "fabric-libp2p: dcutr hole-punch upgraded a relayed connection to DIRECT"
                ),
                Err(e) => tracing::warn!(
                    peer = %ev.remote_peer_id,
                    error = %e,
                    "fabric-libp2p: dcutr hole-punch FAILED - staying on the relay circuit (fallback)"
                ),
            },
            // LAN peer-ADDRESS discovery over mDNS (TASK-257). mDNS carries a peer's
            // (PeerId, Multiaddr) pairs; we feed them into the SAME kad routing/bootstrap
            // ADDRESS path `identify` uses above (`kad.add_address`) so a node with NO
            // --libp2p-bootstrap can still converge its DHT from a LAN neighbour. This is
            // the ADDRESS path ONLY: mDNS is NEVER consulted for "who holds hash X?" - that
            // stays kad-EXCLUSIVE (find_providers), and `check-discovery-no-shortcut.py`
            // bites if an mDNS event is ever wired to get_providers/find_providers. Scope
            // isolation is NOT re-checked here (mDNS cannot see a peer's kad protocol name):
            // a cross-scope neighbour is `add_address`'d but can never complete the scoped
            // `/nix-p2p/<scope>/kad` handshake, so it never joins - the scoped protocol name
            // is the isolation, proven by the e2e scope-mismatch negative control.
            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                // TASK-257 F-1 (FLOOD BOUND): admit at most a bounded, INTEGER number of DISTINCT
                // mDNS peers to ACT ON per window, so an unauthenticated LAN flood of generated
                // PeerIds cannot make us admit an unbounded set. F-2 (SCOPE / ROUTING): `add_address`
                // makes the peer routable/dialable (needed so a lone-genesis provider's put_record has
                // a target and a consumer's find_providers has a peer to query). A CROSS-scope peer is
                // add_address'd but can NEVER complete the scoped `/nix-p2p/<scope>/kad` handshake, so
                // it answers no scoped query: it occupies at most `cap` routing slots as a decaying
                // dead-end (BOUNDED by F-1), never resolves scoped content (proven by the 7/7 e2e
                // content-isolation control), and costs at most one wasted dial - inside the "a cross
                // peer costs a retry" guarantee. Deterministic event-driven cross-scope eviction is
                // deferred to TASK-262 (the earlier timing-sweep was flaky + above the product line).
                // This is the ADDRESS/bootstrap path ONLY: mDNS is never consulted for "who holds hash
                // X?" (that stays kad-EXCLUSIVE; `check-discovery-no-shortcut.py` bites if it feeds
                // find_providers).
                let now = Instant::now();
                let confined = self.lan_serve_conns.is_some();
                // TASK-283 discovery-latency: capture the anchor + this node's identity BEFORE the
                // kad borrow (local_peer_id borrows the swarm immutably; kad borrows it mutably).
                let started_at = self.started_at;
                let local_peer = *self.swarm.local_peer_id();
                let kad = &mut self.swarm.behaviour_mut().kad;
                for (peer_id, addr) in peers {
                    if !self.mdns_admission.admit(peer_id, now) {
                        tracing::debug!(
                            %peer_id, %addr,
                            "fabric-libp2p: mDNS admission cap reached this window; dropping surplus \
                             LAN advertisement (flood bound, TASK-257 F-1)"
                        );
                        continue;
                    }
                    // Under LAN confinement (TASK-280), keep non-LAN mDNS-advertised addresses out
                    // of the k-buckets (hygiene). mDNS is link-local so its addresses are normally
                    // LAN already, but a malicious LAN host can multicast a peer record naming a
                    // GLOBAL address; the dial veto would deny the dial regardless, this just avoids
                    // seeding routing with an address we would never dial.
                    if confined && !multiaddr_lan_provenance(&addr) {
                        tracing::debug!(
                            %peer_id, %addr,
                            "fabric-libp2p: lan-share confinement dropping non-LAN mDNS address \
                             (not added to kad routing)"
                        );
                        continue;
                    }
                    // TASK-283 discovery-latency: report the time-to-first-mDNS-peer ONCE, in
                    // INTEGER ms (no floats), at the moment this node acts on (routes) its first
                    // LAN peer. `RUST_LOG=info` surfaces it; provenance names this node + the peer.
                    if !self.first_mdns_reported {
                        self.first_mdns_reported = true;
                        // u64 ms (integer; no float). `try_from` keeps it exact; the saturating
                        // fallback is unreachable (would need ~5.8e8 years of uptime).
                        let elapsed_ms =
                            u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
                        tracing::info!(
                            %local_peer,
                            %peer_id,
                            %addr,
                            elapsed_ms,
                            "DISCOVERY-LATENCY-MDNS first LAN peer discovered (elapsed since node start)"
                        );
                    }
                    kad.add_address(&peer_id, addr);
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                // A LAN peer's mDNS record aged out. We do NOT evict on TTL expiry: an expiry is
                // periodic (mDNS re-advertises), NOT a departure, and a same-scope peer's kad
                // membership should outlive one TTL. kad's own liveness (failed queries) evicts
                // genuinely-dead peers; cross-scope peers are bounded by the F-1 admission cap
                // (deterministic eviction is TASK-262).
                for (peer_id, addr) in peers {
                    tracing::debug!(
                        %peer_id, %addr,
                        "fabric-libp2p: mDNS record expired (TTL); leaving kad routing to its own \
                         liveness + the scope-verification sweep"
                    );
                }
            }
            // The stream behaviour emits no events we act on (its `ToSwarm` is `()`); the
            // NAR byte transfer is driven off this loop through the Control (TASK-157).
            _ => {}
        }
    }

    fn on_query(
        &mut self,
        id: kad::QueryId,
        result: kad::QueryResult,
        stats: kad::QueryStats,
        last: bool,
    ) {
        use kad::{
            AddProviderOk, GetClosestPeersError, GetClosestPeersOk, GetProvidersOk, GetRecordOk,
            PutRecordOk, QueryResult,
        };
        // TASK-154 B3: eager abandoned-query reap. If the caller dropped its receiver after the
        // worker buffered the QueryId but before it armed CancelOnDrop, no cancel signal exists;
        // this query's next event observes the closed reply. Cancel the walk and drop the entry
        // NOW rather than run it to `kad_query_timeout` (the periodic sweep is the backstop for a
        // query that emits no further event). Closes the buffered-id window regardless of id-arm
        // timing.
        if self.pending.get(&id).is_some_and(Pending::reply_is_closed) {
            self.cancel_query(id);
            return;
        }
        match result {
            QueryResult::StartProviding(res) => {
                if let Some(Pending::Simple(reply)) = self.pending.remove(&id) {
                    let _ = reply.send(match res {
                        Ok(AddProviderOk { .. }) => Ok(()),
                        Err(e) => Err(e.to_string()),
                    });
                }
            }
            QueryResult::PutRecord(res) => {
                if let Some(Pending::Simple(reply)) = self.pending.remove(&id) {
                    let _ = reply.send(match res {
                        Ok(PutRecordOk { .. }) => Ok(()),
                        Err(e) => Err(e.to_string()),
                    });
                }
            }
            QueryResult::Bootstrap(res) => {
                // Bootstrap progresses in several steps; answer on the last one.
                if last && let Some(Pending::Bootstrap(reply)) = self.pending.remove(&id) {
                    let _ = reply.send(match res {
                        Ok(_) => Ok(()),
                        Err(e) => Err(e.to_string()),
                    });
                }
            }
            QueryResult::GetProviders(res) => {
                if let Some(Pending::GetProviders {
                    found,
                    max_peers,
                    salt,
                    truncated,
                    ..
                }) = self.pending.get_mut(&id)
                    && let Ok(GetProvidersOk::FoundProviders { providers, .. }) = &res
                {
                    // TASK-154 B1: fold each advertised provider into a set BOUNDED at
                    // `max_peers`, so a sybil flood never grows the retained set past the
                    // budget (O(max_peers) memory). TASK-214: the set is ordered by RANK under
                    // this query's fresh `salt`, so which subset is retained is non-grindable.
                    for peer in providers.iter().copied() {
                        retain_bounded_provider(found, *max_peers, *salt, truncated, peer);
                    }
                }
                let failed = res.is_err();
                if (last || failed)
                    && let Some(Pending::GetProviders {
                        found,
                        truncated,
                        started,
                        key,
                        reply,
                        ..
                    }) = self.pending.remove(&id)
                {
                    // TASK-283 discovery-latency: emit the kad `get_providers` wall-clock in
                    // INTEGER ms (no floats — project rule), labelled with this node's PeerId and
                    // the exact content key, so `RUST_LOG=info` surfaces the REAL shipped-path
                    // latency. Off the byte path (one marker per completed discovery walk). u64 ms
                    // is exact via `try_from`; the saturating fallback is unreachable at any
                    // realistic uptime.
                    let elapsed_ms =
                        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let key_hex: String = key.as_ref().iter().map(|b| format!("{b:02x}")).collect();
                    let local_peer = *self.swarm.local_peer_id();
                    let outcome = if failed { "timeout" } else { "resolved" };
                    tracing::info!(
                        %local_peer,
                        key = %key_hex,
                        providers = found.len() as u64,
                        answered = stats.num_successes() as u64,
                        elapsed_ms,
                        outcome,
                        "DISCOVERY-LATENCY-KAD get_providers terminal (elapsed since query issued)"
                    );
                    // The terminal-step stats are cumulative for the whole query, so
                    // `num_successes` is how many peers answered the walk toward the key
                    // (TASK-174: the near-key bar for an EMPTY provider set). The `found`
                    // BTreeSet is keyed by `(rank, PeerId)` (TASK-214); drop the rank and present
                    // the retained peers in ascending `PeerId` order - the MEMBERSHIP is the
                    // salt-dependent selection, the ORDER is a salt-independent presentation (the
                    // directory fetches all retained providers concurrently).
                    let reach = QueryReach {
                        answered: stats.num_successes(),
                    };
                    let mut providers: Vec<PeerId> =
                        found.into_iter().map(|(_rank, peer)| peer).collect();
                    providers.sort_unstable();
                    let _ = reply.send(match res {
                        Ok(_) => Ok(ProviderFanOut {
                            providers,
                            truncated,
                            reach,
                        }),
                        Err(kad::GetProvidersError::Timeout { .. }) => Err(QueryFail::Timeout),
                    });
                }
            }
            QueryResult::GetRecord(res) => match res {
                Ok(GetRecordOk::FoundRecord(peer_record)) => {
                    // First record wins; reply and stop the query early.
                    if let Some(Pending::GetRecord { reply }) = self.pending.remove(&id) {
                        let _ = reply.send(Ok(Some(peer_record.record.value)));
                    }
                    if let Some(mut query) = self.swarm.behaviour_mut().kad.query_mut(&id) {
                        query.finish();
                    }
                }
                Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => {
                    if let Some(Pending::GetRecord { reply }) = self.pending.remove(&id) {
                        let _ = reply.send(Ok(None));
                    }
                }
                Err(e) => {
                    if let Some(Pending::GetRecord { reply }) = self.pending.remove(&id) {
                        let _ = reply.send(match e {
                            kad::GetRecordError::NotFound { .. }
                            | kad::GetRecordError::QuorumFailed { .. } => Ok(None),
                            kad::GetRecordError::Timeout { .. } => Err(QueryFail::Timeout),
                        });
                    }
                }
            },
            QueryResult::GetClosestPeers(res) => {
                // Peer-routing terminates in a single terminal event (`get_closest_peers`
                // has no per-step progress), so resolve on the first (and only) result.
                if let Some(Pending::GetClosestPeers { target, reply }) = self.pending.remove(&id) {
                    // How far the peer-routing walk reached (TASK-174): an EMPTY address
                    // result with `answered == 0` is a could-not-consult, not a Miss.
                    let reach = QueryReach {
                        answered: stats.num_successes(),
                    };
                    let result = match res {
                        // The converged closest set: pull out the addresses the DHT learned
                        // for EXACTLY the target peer. If the target is absent from the set,
                        // or present with no address, that is "no address known" (empty
                        // Vec); the locator then maps it to Miss vs InsufficientRouting on
                        // `reach`, never guessing.
                        Ok(GetClosestPeersOk { peers, .. }) => Ok((
                            peers
                                .into_iter()
                                .find(|info| info.peer_id == target)
                                .map(|info| info.addrs)
                                .unwrap_or_default(),
                            reach,
                        )),
                        // A timed-out query could not be consulted: the lookup was not
                        // authoritative, so this must surface as Unavailable, never an
                        // (empty) Miss.
                        Err(GetClosestPeersError::Timeout { .. }) => Err(QueryFail::Timeout),
                    };
                    let _ = reply.send(result);
                }
            }
            _ => {}
        }
    }
}

/// The inbound-serve accept loop (TASK-157): pull each inbound NAR substream the
/// [`libp2p_stream::Control`] accepts and hand it to a spawned per-stream task. This runs
/// entirely OFF the swarm poll loop, so a large or slow serve never stalls kad / identify.
/// Reads the CURRENT serve gate from the shared slot per stream, so an install/uninstall
/// between requests takes effect without racing the poll loop. The loop ends when the swarm
/// shuts down (the behaviour drops, closing `incoming`).
///
/// Task-count backpressure: each spawned [`nar::serve_stream`] is itself DEADLINE-BOUND in
/// every phase (it self-terminates within the serve deadline), and inbound substreams are
/// capped per connection by yamux, so parked tasks cannot accumulate without bound. A global
/// concurrent-serve semaphore (a stricter cap than the request-response carrier's built-in
/// inbound limit) is a possible future hardening, not needed for the current trust model.
/// The LAN-confinement SERVE gate (TASK-280 mitigation #2). `true` = this stream may be served:
///   * off the lan-share path (`lan_serve_conns` is `None`) every stream is permitted (public-share
///     serves per its allowlist; a consumer never serves);
///   * on the lan-share path the stream must have arrived on THIS EXACT connection AND that
///     connection must be recorded as LAN-provenance by the worker. Gating on the exact
///     `(PeerId, ConnectionId)` — not "the peer has SOME LAN connection" (codex CRITICAL #2) — closes
///     the connection-confusion leg: a peer with one LAN connection AND a second connection over a
///     non-LAN address (e.g. an OUTBOUND connection we opened to it, or a relay circuit) cannot be
///     served over the non-LAN connection, because that connection's id is absent from the LAN set.
///     FAIL-CLOSED: an unrecorded connection is denied (a genuine LAN stream whose
///     `ConnectionEstablished` has not yet been processed simply retries — within the "a peer costs a
///     retry" TCB). Extracted as a pure function so the gate is unit-mutation-provable.
///
/// The libp2p-identify default per-peer address cache size (libp2p-identify 0.47, `Config::new`
/// installs `cache_size: 100`). Named here so [`identify_cache_size`] returns the SAME value on the
/// unconfined path rather than a magic literal, and so the mutation test can assert the confined
/// path differs from it.
const IDENTIFY_DEFAULT_CACHE_SIZE: usize = 100;

/// TASK-280 mitigation #4 — the identify INTERNAL address-cache leg (distinct from the
/// receive-gate below). libp2p-identify 0.47 internally caches every advertised listen address
/// (default 100) and, for each, emits a `ToSwarm::NewExternalAddrOfPeer` our event handler cannot
/// cancel — seeding the swarm address book so a cross-scope peer's GLOBAL address survives as a
/// dial candidate the app-level receive-gate never sees. Under LAN confinement the cache is DISABLED
/// (size 0, `PeerCache::disabled`) so the internal cache never fires; off the confined path we keep
/// the library default so public nodes still learn peers' addresses via identify. SINGLE SOURCE used
/// by BOTH [`build_identify_config`] (production) and its mutation test, so reverting the
/// `if lan_confinement { 0 }` reddens `identify_config_disables_address_cache_under_confinement`.
fn identify_cache_size(lan_confinement: bool) -> usize {
    if lan_confinement {
        0
    } else {
        IDENTIFY_DEFAULT_CACHE_SIZE
    }
}

/// Build the node's [`identify::Config`], applying the confinement address-cache mitigation via the
/// single-source [`identify_cache_size`]. Extracted from the swarm-builder closure (was an inline
/// `.with_cache_size(0)` with NO test, so deleting it stayed green — codex TASK-282 (a)) so the
/// mutation test can inspect the REAL config it produces via `identify::Config::cache_size()`.
fn build_identify_config(
    id_protocol: String,
    public_key: libp2p::identity::PublicKey,
    lan_confinement: bool,
) -> identify::Config {
    identify::Config::new(id_protocol, public_key)
        .with_cache_size(identify_cache_size(lan_confinement))
}

/// TASK-280 #4 (cross-scope identify receive-gate). Whether a peer's identify-advertised addresses
/// may seed our kad routing, based on its advertised identify `protocol_version`:
///   * off the lan-share path (`confined == false`) — always yes (public participation);
///   * under confinement — ONLY if `advertised == expected` (our `/nix-p2p/<scope>/id/1.0.0`). Because
///     identify negotiates the FIXED `/ipfs/id/1.0.0` name (scope lives only in this metadata), a
///     cross-scope peer completes identify with us; this predicate is what keeps its addresses out of
///     routing. Pure so the gate is unit-mutation-provable.
fn identify_protocol_version_admitted(confined: bool, advertised: &str, expected: &str) -> bool {
    !confined || advertised == expected
}

/// The addresses from a peer's identify record that may seed our kad routing under the current
/// confinement (TASK-280 #4). This is the COMPLETE identify address gate — BOTH the cross-scope
/// `protocol_version` reject AND the per-address LAN-provenance filter — so the production handler is
/// a thin `for addr in identify_admitted_addresses(...) { kad.add_address(...) }` with NO gate logic
/// of its own; mutating either sub-gate reddens the unit test that drives THIS function:
///   * off the lan-share path (`confined == false`): every advertised address is admitted (public
///     participation — identify discovery is how public nodes learn each other's addresses);
///   * under confinement: EMPTY if the advertised protocol_version is not our scoped id string (a
///     cross-scope peer's addresses never seed routing); otherwise ONLY the LAN-provenance addresses
///     (a same-scope peer that advertises a global address still cannot seed a non-LAN dial target).
fn identify_admitted_addresses(
    confined: bool,
    advertised_protocol_version: &str,
    expected_protocol_version: &str,
    listen_addrs: impl IntoIterator<Item = Multiaddr>,
) -> Vec<Multiaddr> {
    if !identify_protocol_version_admitted(
        confined,
        advertised_protocol_version,
        expected_protocol_version,
    ) {
        return Vec::new();
    }
    listen_addrs
        .into_iter()
        .filter(|addr| !confined || multiaddr_lan_provenance(addr))
        .collect()
}

fn lan_serve_permitted(
    lan_serve_conns: &Option<LanServeConns>,
    peer: &PeerId,
    connection: ConnectionId,
) -> bool {
    match lan_serve_conns {
        None => true,
        Some(lan_conns) => lan_conns
            .lock()
            .expect("lan serve conns poisoned")
            .get(peer)
            .is_some_and(|conns| conns.contains(&connection)),
    }
}

/// The PRODUCTION accept-loop body, generic over the stream ITEM so a unit test can drive the EXACT
/// control flow with sentinel items (a real `libp2p_swarm::Stream` cannot be constructed off a live
/// connection, so the earlier test called `lan_serve_permitted` in isolation — deleting the gate here
/// stayed green, i.e. the "mutation proof" was decoration; codex TEST-QUALITY finding). Here the
/// TASK-280 #2 serve gate is the ONLY gate in the loop and every accepted item flows through it: an
/// item is handed to `serve` iff `lan_serve_permitted` admits its exact `(PeerId, ConnectionId)`;
/// otherwise it is dropped. Deleting the `if !lan_serve_permitted` guard makes a non-LAN item reach
/// `serve`, which `accept_loop_serves_only_lan_provenance_connections` observes and reddens.
async fn accept_loop_core<St, T, F>(
    mut incoming: St,
    lan_serve_conns: Option<LanServeConns>,
    mut serve: F,
) where
    St: futures::Stream<Item = (PeerId, ConnectionId, T)> + Unpin,
    F: FnMut(PeerId, ConnectionId, T),
{
    while let Some((peer, connection, item)) = incoming.next().await {
        // LAN-confinement serve gate (TASK-280 mitigation #2): see `lan_serve_permitted`. The gate
        // keys on the EXACT connection the stream arrived on, so a non-LAN connection of an otherwise
        // LAN-connected peer is refused.
        if !lan_serve_permitted(&lan_serve_conns, &peer, connection) {
            tracing::warn!(
                %peer,
                %connection,
                "fabric-libp2p: lan-share confinement REFUSING NAR serve — this connection has no \
                 recorded LAN provenance (serving only same-LAN connections; dropping stream)"
            );
            drop(item);
            continue;
        }
        serve(peer, connection, item);
    }
    tracing::debug!("fabric-libp2p: NAR accept loop ended (swarm shut down)");
}

async fn run_accept_loop(
    incoming: IncomingStreams,
    serve_slot: ServeSlot,
    lan_serve_conns: Option<LanServeConns>,
) {
    accept_loop_core(incoming, lan_serve_conns, |peer, _connection, stream| {
        // A brief lock, off the poll loop, to snapshot the current gate (an `Arc` clone or
        // `None`); never held across the serve `.await`.
        let gate = serve_slot.lock().expect("serve slot poisoned").clone();
        tracing::trace!(%peer, "fabric-libp2p: inbound NAR stream accepted");
        tokio::spawn(nar::serve_stream(stream, gate));
    })
    .await;
}

/// Default kad iterative-query timeout (the per-query deadline libp2p-kad enforces on a
/// `get_providers`/`get_closest_peers`/`get_record` walk).
///
/// WHY 30s, and why configurable (TASK-210, informed by TASK-209's shaped-link RTT sweep):
/// TASK-209 measured single-shot kad DISCOVERY latency growing steeply with link RTT
/// (one-way delay -> observed discovery time): 20ms -> ~0.65s, 100ms -> ~3.6s,
/// 250ms -> ~8.5s. At 500ms one-way (~1.7s RTT) the FIRST query already exceeded the old
/// hardcoded 10s and needed an application retry; the old 10s therefore covered only up to
/// ~250ms one-way. GEO-satellite peers sit at ~600ms one-way (~1.2s RTT) — squarely past
/// the old ceiling — so a one-shot consumer lookup on a satellite uplink silently
/// DeadlineExceeded. Extrapolating the measured near-linear ~34ms-per-one-way-ms slope
/// beyond baseline (250ms -> 8.5s) puts a single query at 600ms one-way near ~20s; 30s
/// clears that with margin (covers roughly up to ~800ms one-way single-shot).
///
/// TRADEOFF — a higher timeout is NOT free, and does NOT make satellite discovery FAST,
/// only POSSIBLE: on a fast link a genuine `Miss`/`Unavailable` (a key that truly has no
/// provider, or a peer that cannot be located) now takes up to 30s to surface instead of
/// 10s, because the negative answer is exactly the timeout firing. It does NOT slow
/// SUCCESSFUL discovery on residential/WAN links (20–250ms): those queries complete in
/// well under 10s and return the moment they resolve, untouched by the raised ceiling. The
/// cost is borne only on the failure path. Links slower than ~800ms one-way still need a
/// larger configured timeout and/or application-level retry — which is why this is
/// configurable rather than a bigger magic number.
pub const DEFAULT_KAD_QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Absolute bound for one or many listener registrations to emit their first concrete address.
/// Circuit-v2 reservation refusal surfaces as ListenerClosed before this; a stalled transport is
/// cut off here instead of letting provider startup wait forever.
pub const DEFAULT_LISTEN_READY_TIMEOUT: Duration = Duration::from_secs(20);

/// Hard cap across active exact dials and cancellation tombstones. Tombstones cannot be evicted
/// before a terminal libp2p event without making a very-late success usable, so admission is
/// bounded fail-closed instead of allowing attacker-driven state growth.
const MAX_PENDING_EXACT_DIALS: usize = 64;

/// How often the worker sweeps for abandoned queries (TASK-154 B3). The eager reap at the top of
/// [`Worker::on_query`] cancels a query the instant its next event arrives; this periodic sweep
/// is the backstop that bounds the reap latency for a query abandoned in the buffered-id window
/// that then emits NO further event (a stalled walk) to at most this interval - far under
/// [`DEFAULT_KAD_QUERY_TIMEOUT`], so an abandoned query no longer costs a full query_timeout of
/// wasted work. Integer `Duration` (no-float rule).
const ABANDONED_QUERY_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------------------
// Circuit-v2 relay SERVER bounds (TASK-208).
//
// The swarm runs a circuit-v2 relay server BY DEFAULT (the permissionless-swarm intent:
// any public node helps NAT'd peers with no dedicated infra). But a SHIPPED node is a home
// / residential machine, NOT public relay infrastructure, so it must relay only BOUNDED
// traffic. We set every cap EXPLICITLY rather than trusting `relay::Config::default()`
// (whose values target a dedicated relay: 128 reservations, 16 circuits, 1h reservations).
//
// The knobs bound the abuse surface along three axes:
//   * SLOTS: how many NAT'd peers we hold state for (`MAX_RESERVATIONS`) and how many
//     concurrent forwarding circuits we run (`MAX_CIRCUITS`), plus per-peer caps so one
//     peer cannot monopolize the node.
//   * DATA: a hard per-circuit byte ceiling (`MAX_CIRCUIT_BYTES`). A relay circuit here is
//     DIAL-ASSISTANCE - dcutr upgrades a relayed connection to DIRECT for the bulk NAR
//     transfer, so the relay itself should carry only the hole-punch handshake and small
//     control, never a full NAR. The ceiling caps worst-case forwarded volume at roughly
//     `MAX_CIRCUITS * MAX_CIRCUIT_BYTES`.
//   * TIME: a reservation lifetime (`RESERVATION_DURATION`) and a per-circuit lifetime
//     (`MAX_CIRCUIT_DURATION`), so stale slots free themselves and no circuit lingers.
//
// All values are integers / integer `Duration`s (no-float rule). We keep the library's
// per-peer / per-IP RATE limiters (from `relay::Config::default()`) unchanged and only
// tighten these hard caps; see `relay_server_config`.

/// Max concurrent reservations the relay server holds (NAT'd peers listening via us).
/// 32, vs the library default 128: a home node should not pin state for a public-relay-scale
/// crowd. A reservation is cheap state, so this is generous relative to the circuit cap while
/// still an order of magnitude below "open infrastructure".
pub const RELAY_MAX_RESERVATIONS: usize = 32;

/// Max reservations any SINGLE peer may hold (default is 4). 2 is enough for a peer to hold a
/// reservation while renewing, without letting one peer consume many of our 32 slots.
pub const RELAY_MAX_RESERVATIONS_PER_PEER: usize = 2;

/// How long a reservation stays valid before the client must renew. 10 minutes, vs the
/// library's 1 hour: a home node frees a departed peer's slot quickly rather than pinning it
/// for an hour. libp2p's default renewal cadence is well under this, so a live client renews
/// transparently; the shorter lifetime only bounds how long a STALE reservation lingers.
pub const RELAY_RESERVATION_DURATION: Duration = Duration::from_secs(10 * 60);

/// Max concurrent forwarding circuits (active relayed connections). 8, vs the library default
/// 16: the load-bearing bandwidth cap. With `MAX_CIRCUIT_BYTES` this bounds worst-case
/// concurrently-forwarded volume to ~1 MiB (8 * 128 KiB) of in-flight relayed data.
pub const RELAY_MAX_CIRCUITS: usize = 8;

/// Max concurrent circuits sourced from any SINGLE peer (default is 4). 2 keeps one peer from
/// taking most of our 8 circuit slots.
pub const RELAY_MAX_CIRCUITS_PER_PEER: usize = 2;

/// Max lifetime of a single forwarding circuit. Kept at the library default of 2 minutes: a
/// relay circuit is a SHORT-LIVED hole-punch fallback (dcutr should upgrade to direct well
/// inside this window), not a long-lived tunnel, so no circuit should outlive it.
pub const RELAY_MAX_CIRCUIT_DURATION: Duration = Duration::from_secs(2 * 60);

/// Hard per-circuit total-byte ceiling. Kept at the library default of 128 KiB (`1 << 17`):
/// the relay carries the hole-punch handshake + small control, NOT the bulk NAR (dcutr
/// upgrades to a direct connection for that). This is the value that stops the node being an
/// unbounded byte amplifier; it is deliberately small because a home relay proxies dialing,
/// not payloads.
pub const RELAY_MAX_CIRCUIT_BYTES: u64 = 1 << 17;

/// The EXPLICIT circuit-v2 relay-server config for a shipped node (TASK-208).
///
/// Starts from [`relay::Config::default()`] to inherit its sensible per-peer / per-IP RATE
/// limiters, then overrides every hard CAP with the `RELAY_*` constants above so a home node
/// relays only bounded traffic. We do NOT rely on the library's cap defaults (which target a
/// dedicated public relay). See each constant for its justification.
pub fn relay_server_config() -> relay::Config {
    relay::Config {
        max_reservations: RELAY_MAX_RESERVATIONS,
        max_reservations_per_peer: RELAY_MAX_RESERVATIONS_PER_PEER,
        reservation_duration: RELAY_RESERVATION_DURATION,
        max_circuits: RELAY_MAX_CIRCUITS,
        max_circuits_per_peer: RELAY_MAX_CIRCUITS_PER_PEER,
        max_circuit_duration: RELAY_MAX_CIRCUIT_DURATION,
        max_circuit_bytes: RELAY_MAX_CIRCUIT_BYTES,
        ..relay::Config::default()
    }
}

/// Whether a node runs the circuit-v2 relay SERVER by default (TASK-208). `true`: a public
/// node helps NAT'd peers with no dedicated relay infra (the permissionless-swarm intent).
/// Override off with [`NodeConfig::with_relay_server`].
pub const DEFAULT_RELAY_SERVER_ENABLED: bool = true;

/// Whether a node runs Kademlia in SERVER mode by default (TASK-120 fix A). `true`: the node
/// STORES records and ANSWERS DHT queries for others (the decentralized-directory intent, needed
/// by a PROVIDER). A CONSUMER overrides this to `false` (kad CLIENT: issues queries, answers
/// none), and an upstream-only node runs no participating swarm at all. Override with
/// [`NodeConfig::with_kad_server`].
pub const DEFAULT_KAD_SERVER: bool = true;

/// Whether a node runs LAN mDNS peer-ADDRESS discovery by default (TASK-257). `false`:
/// the mDNS behaviour is ABSENT (a disabled [`Toggle`]), so the node opens no multicast
/// socket and emits ZERO mDNS packets - the fail-safe, off-by-default posture the
/// operator opts into with `--libp2p-mdns` / [`NodeConfig::with_mdns`]. This is TASK-120
/// axis-1 (local discovery) only: enabling it NEVER implies serving, announcing, or public
/// participation.
pub const DEFAULT_MDNS_ENABLED: bool = false;

/// Whether a node confines its egress + serving to LAN peers by default (TASK-280). `false`: the
/// [`LanDialGuard`] is ABSENT and dialing/serving are unrestricted. The composition root sets it
/// `true` ([`NodeConfig::with_lan_confinement`]) ONLY for a no-allowlist `lan-share` node, whose
/// public-isolation guarantee it holds end-to-end.
pub const DEFAULT_LAN_CONFINEMENT: bool = false;

/// The bounded admission cap for mDNS-discovered LAN peers (TASK-257 F-1): at most this many
/// DISTINCT mDNS peers are dialed per [`MDNS_ADMISSION_WINDOW_SECS`] window. INTEGER. A real
/// LAN/org pool rarely presents more than a few dozen distinct nodes in a window; a burst beyond
/// this is a flood and its surplus is dropped, bounding the routing-table skew a malicious LAN host
/// can induce. Large enough not to throttle a genuine deployment, finite so a flood cannot be
/// unbounded.
pub const MDNS_ADMISSION_CAP: usize = 64;

/// The mDNS admission window, in INTEGER seconds (TASK-257 F-1). The admitted-peer set is cleared
/// each window, so at most [`MDNS_ADMISSION_CAP`] distinct mDNS peers are admitted per window and
/// the tracking state stays bounded. No float ever enters the cap or the window.
pub const MDNS_ADMISSION_WINDOW_SECS: u64 = 30;

// ---------------------------------------------------------------------------------------
// kad MemoryStore STORAGE bounds (TASK-154 AC#1).
//
// The kad value/provider store is where a hostile peer's records LAND: because a node runs
// in `kad::Mode::Server` it accepts records other peers PUT toward the keys it is k-closest
// to, and provider announcements for those keys. Left at `MemoryStoreConfig::default()`
// (1024 records, 65 KiB/value, 1024 provided keys, k=20 providers/key) these are LIBRARY
// defaults, not a decision. A SHIPPED home node needs EXPLICIT, defensible caps so a
// poisoning / amplification / sybil flood costs BOUNDED memory, never an OOM - and never at
// the price of integrity (Nix re-verifies every fetched byte; a cap only limits how much
// UNTRUSTED hint state we hold, never whether an answer is trusted).
//
// The bounds are picked with HEADROOM so a legitimate record is never refused (the proven
// decentralized-discovery / record-lifecycle tests hold a handful of records each - orders
// of magnitude under these caps):
//
//   * VALUE SIZE is the tightest, most load-bearing cap. Every value we store is the FROZEN
//     provider-record / withdrawal encoding, itself capped at
//     `peer_fabric::MAX_PROVIDER_RECORD_BYTES` (1024 B, worst case ~324 B). We set
//     `max_value_bytes` to 2 KiB: strictly ABOVE the 1024-B frozen cap (so a valid record is
//     always accepted - the store's check is `len >= max`, so the ceiling must exceed the
//     largest legal record) yet ~32x BELOW the library's 65 KiB, so a peer cannot park 64 KiB
//     of junk per key on us. This is the value that stops per-record amplification.
//   * RECORD COUNT bounds total distinct value-store keys we hold. 4096 (vs the 1024 default,
//     raised for real-network headroom) * the 2 KiB value ceiling bounds the worst-case
//     VALUE-PAYLOAD bytes at ~8 MiB (4096 * 2 KiB). This is a bound on the record VALUES only:
//     it EXCLUDES the record keys, the store's index maps, the separate provider+address
//     records (see PROVIDERS-PER-KEY / PROVIDED KEYS below), and per-entry allocator overhead,
//     so TOTAL store memory is larger than 8 MiB by those addends. Every one of those addends
//     is ALSO independently bounded (see below), so total store memory stays hard-bounded -
//     just not AT 8 MiB. Do not read ~8 MiB as the whole-store figure; it is the value-payload
//     component, the most DIRECTLY attacker-controllable one (a peer sets the value bytes
//     directly), NOT necessarily the largest component - the provider/address store's byte size
//     is not quantified here (see the AMPLIFICATION note), so no ordering between them is claimed.
//   * PROVIDERS-PER-KEY is the DIRECT sybil-flood cap libp2p itself documents ("if the
//     providers list is full, we ignore the new provider ... can mitigate Sybil attacks"). We
//     pin it EXPLICITLY at the kad replication factor 20 (k) so the anti-sybil intent is a
//     decision, not an inherited default. Note this caps providers ONE node stores per key;
//     the consumer-side fan-out cap (`find_providers`, `DiscoveryBudget.max_peers`) bounds how
//     many of the aggregated providers a lookup then chases.
//   * PROVIDED KEYS bounds how many keys WE announce as a provider (our own store paths),
//     kept at 1024 explicitly.
//
// All values are integers (no-float rule).
//
// ADVERSARIAL MODEL & HONEST LIMITS (TASK-154 AC#2). What these bounds DO and, as
// importantly, what they do NOT do - so no reader mistakes a resource bound for a
// defeated attack:
//
//   * POISONING (a forged/replayed value record). The store cap does NOT decide trust -
//     it only limits how much untrusted hint state we HOLD. Trust is enforced elsewhere
//     and is total: every fetched provider record is ed25519-verified against the frozen
//     codec, bound to the announcing PeerId, and floored by the monotonic/withdrawal
//     `admit` gate (directory.rs); a forged value costs one skipped provider, never a bad
//     answer, and Nix re-verifies every fetched byte regardless. The cap's job is only to
//     stop a poisoning FLOOD from costing unbounded memory.
//   * AMPLIFICATION (junk parked to inflate our memory/serve cost). `STORE_MAX_VALUE_BYTES`
//     (per record) and `STORE_MAX_RECORDS` (count) hard-bound the value-PAYLOAD memory (~8 MiB
//     worst case - values ONLY). The provider/address store is a SEPARATE structure bounded by
//     its OWN caps: at most `STORE_MAX_PROVIDERS_PER_KEY` * `STORE_MAX_PROVIDED_KEYS`
//     (20 * 1024 = 20480) provider records, each itself size-limited by libp2p's internal
//     per-record address-list cap. That bounds its record COUNT; we do NOT quantify its BYTE
//     size here (a provider record's bytes derive from libp2p's address cap, not one of OUR
//     frozen value caps) and make NO claim it is "smaller" than the value payload - only that it
//     is separately and independently bounded, never unbounded. Likewise the record keys and the
//     store's index maps grow only with the (bounded) record/key counts. The consumer fan-out
//     cap (`DiscoveryBudget.max_peers`, directory.rs) bounds how many providers ONE lookup
//     chases, so a flooded index cannot turn a lookup into one round trip per forged provider.
//     These bound COST; they do not stop a peer from TRYING.
//   * SYBIL (many fake identities flooding one key). `STORE_MAX_PROVIDERS_PER_KEY` caps how
//     many providers we store per key (libp2p's own documented Sybil mitigation), so a
//     flood cannot evict a legitimate provider past the cap. This RAISES the cost of a
//     sybil flood; it does NOT by itself distinguish a real provider from a fake one.
//   * ECLIPSE (surrounding a node with adversarial peers so its view is controlled). This
//     is the one these bounds DO NOT defeat. A determined adversary who can occupy a node's
//     routing neighborhood can still bias what it sees; the bounds only ensure that doing
//     so costs bounded RESOURCES on our side and cannot escalate to an OOM or an unbounded
//     fan-out. A real eclipse defense needs diverse/rate-limited routing-table admission
//     and multi-path lookups this single-node view does not have (the residual false-`Miss`
//     window is documented on `crate::QueryReach`).
//
// These are SOURCE-level bounds + unit proofs, NOT an adversarial FIELD proof. Whether the
// private DHT actually withstands a determined multi-node sybil/eclipse swarm is a separate
// claim that needs an adversarial harness - deferred to TASK-205. Do not read this block as
// "sybil/eclipse solved"; read it as "the resource cost of attempting them is bounded, and
// integrity never depends on these bounds".

/// Max distinct value-store records this node holds for OTHER peers' keys (it is k-closest
/// to). 4096, vs the library default 1024: real-network headroom, still hard-bounded. With
/// [`STORE_MAX_VALUE_BYTES`] this caps the worst-case VALUE-PAYLOAD memory at ~8 MiB (4096 * 2
/// KiB) - the record values ONLY. Keys, index maps and the provider/address store are separate
/// structures, each independently bounded by its own cap (the provider store by
/// [`STORE_MAX_PROVIDERS_PER_KEY`] * [`STORE_MAX_PROVIDED_KEYS`] records); total store memory is
/// larger than 8 MiB but still hard-bounded, and no per-structure byte figure is claimed here.
pub const STORE_MAX_RECORDS: usize = 4096;

/// Hard per-value byte ceiling for the kad value store. 2 KiB (`2 * 1024`): strictly ABOVE
/// the frozen `peer_fabric::MAX_PROVIDER_RECORD_BYTES` (1024 B) so a legitimate record is
/// never refused (the store rejects `len >= max`), and ~32x BELOW the library's 65 KiB so a
/// peer cannot park junk. The load-bearing anti-amplification cap.
pub const STORE_MAX_VALUE_BYTES: usize = 2 * 1024;

/// Max provider records stored per key. 20 = the kad replication factor `k`. libp2p ignores
/// providers past this ("can mitigate Sybil attacks, in which an attacker floods the network
/// with fake provider records"); we pin it EXPLICITLY so the anti-sybil bound is a decision.
pub const STORE_MAX_PROVIDERS_PER_KEY: usize = 20;

/// Max keys for which THIS node is itself a provider (our own announced store paths). Kept at
/// the library default 1024, set explicitly.
pub const STORE_MAX_PROVIDED_KEYS: usize = 1024;

/// The EXPLICIT kad [`MemoryStoreConfig`] for a shipped node (TASK-154 AC#1): every cap is
/// threaded from a `STORE_*` constant rather than left to `MemoryStoreConfig::default()`, so
/// a poisoning / amplification / sybil flood against the store costs only BOUNDED memory. See
/// each constant for its justification and headroom argument.
pub fn content_store_config() -> MemoryStoreConfig {
    MemoryStoreConfig {
        max_records: STORE_MAX_RECORDS,
        max_value_bytes: STORE_MAX_VALUE_BYTES,
        max_providers_per_key: STORE_MAX_PROVIDERS_PER_KEY,
        max_provided_keys: STORE_MAX_PROVIDED_KEYS,
    }
}

/// COMPILE-TIME pin of the value-size HEADROOM invariant (TASK-154 AC#1): the store's per-
/// value ceiling MUST exceed the largest legal frozen record, or the store would reject a
/// LEGITIMATE provider record (the store's own check is `len >= max_value_bytes`). This fails
/// the build the moment someone lowers the cap below the frozen record size - the "a bound
/// mis-set that rejects a legitimate record is a regression" guard, caught at compile time.
const _: () = assert!(
    STORE_MAX_VALUE_BYTES > peer_fabric::MAX_PROVIDER_RECORD_BYTES,
    "the kad value-store per-value ceiling must exceed the largest legal frozen provider \
     record, or a legitimate record would be refused by the store"
);

/// Configuration for one libp2p node.
pub struct NodeConfig {
    /// The 32-byte ed25519 secret that IS this node's identity and record-signing key.
    pub identity_seed: [u8; 32],
    /// The kad/identify protocol suffix scope (in-process tests isolate networks by
    /// using distinct scopes). The concrete protocol names are
    /// `/nix-p2p/<scope>/kad/1.0.0` and `/nix-p2p/<scope>/id/1.0.0`.
    pub network_scope: String,
    /// The kad iterative-query timeout threaded into `kad::Config::set_query_timeout`
    /// (TASK-210). Bounds every DHT discovery/locate walk (`get_providers`,
    /// `get_closest_peers`, `get_record`); on elapse the query returns
    /// [`QueryFail::Timeout`]. Defaults to [`DEFAULT_KAD_QUERY_TIMEOUT`]; raise it for
    /// high-RTT (e.g. GEO-satellite) peers, at the cost of a slower negative answer. An
    /// integer [`Duration`] — no fractional/float timeouts.
    pub kad_query_timeout: Duration,
    /// Whether this node runs the circuit-v2 relay SERVER (relays for OTHER peers). Defaults
    /// to [`DEFAULT_RELAY_SERVER_ENABLED`] (`true`) — the permissionless-swarm intent that any
    /// public node helps NAT'd peers with no dedicated relay infra. Set `false`
    /// ([`NodeConfig::with_relay_server`]) to DECLINE serving as a relay: the server behaviour
    /// is not installed (a disabled [`Toggle`]), so the node accepts no reservation and
    /// forwards no circuit, while `relay_client` / `autonat` / `dcutr` stay active so it can
    /// still USE relays to be reached. When enabled, the server's caps come from
    /// [`relay_server_config`] (explicit bounds, never the library default). (TASK-208.)
    pub relay_server_enabled: bool,
    /// Whether this node runs Kademlia in SERVER mode (TASK-120 fix A): a kad SERVER STORES
    /// records and ANSWERS `FIND_NODE`/`GET_PROVIDERS`/`GET_RECORD` for OTHER peers - it
    /// PARTICIPATES in the DHT infrastructure. `false` puts kad in CLIENT mode: the node still
    /// ISSUES queries (it can discover + fetch) but answers NONE for others and stores no
    /// records, so it provides no DHT infrastructure. Defaults to [`DEFAULT_KAD_SERVER`]
    /// (`true`). The operator contract sets this from the participation profile: a PROVIDER
    /// (lan-share/public-share) is a server; a CONSUMER (consume-only) is a client; an
    /// upstream-only node runs no participating swarm at all. This is what makes a node's
    /// reported `public_dht_participation` match what it actually does on the wire.
    pub kad_server: bool,
    /// Whether this node runs LAN mDNS peer-ADDRESS discovery (TASK-257). Defaults to
    /// [`DEFAULT_MDNS_ENABLED`] (`false`): the mDNS behaviour is a disabled [`Toggle`], ABSENT
    /// from the swarm, so the node opens no multicast socket and emits ZERO mDNS packets. Set
    /// `true` ([`NodeConfig::with_mdns`]) to install the behaviour: its `Discovered` events feed
    /// discovered LAN peers' addresses into the SAME `kad.add_address` bootstrap/address path
    /// `identify` uses, so a node with NO configured bootstrap can converge its DHT from a
    /// same-scope LAN neighbour. It is a peer-ADDRESS bootstrap only - NEVER a content-discovery
    /// mechanism (content discovery stays kad-EXCLUSIVE) - and it is TASK-120 axis-1 (local
    /// discovery) only: enabling it implies NOTHING about serving/announcing/public participation.
    /// Scope isolation is orthogonal and already enforced by the scoped kad/identify protocol
    /// names, so a cross-scope mDNS neighbour never joins this node's DHT.
    pub mdns_enabled: bool,
    /// The statically-configured peer address book consulted LOCALLY under
    /// [`ResolutionPolicy::ExplicitPeersOnly`](peer_fabric::ResolutionPolicy::ExplicitPeersOnly)
    /// (TASK-168 AC#2). Maps a provider's ed25519 [`NodeId`] to the [`Multiaddr`]es it is
    /// dialable at. Resolving one of these peers is a pure LOCAL map lookup: it makes NO
    /// network query and discloses NOTHING to any third party (contrast the kad
    /// peer-routing path, which reveals OUR identity - and the queried NodeId - to the DHT
    /// nodes it contacts). That zero-disclosure property is the whole point of the explicit
    /// policy. Empty by default (a node given no explicit peers genuinely knows no address,
    /// so an explicit-peers resolution is an honest [`Lookup::Miss`], never a fabricated
    /// address). This book is a pure LOCATOR concern: it never enters the swarm and does
    /// not affect discovery, dialing, or the kad routing table.
    pub peer_address_book: BTreeMap<NodeId, Vec<Multiaddr>>,
    /// Legacy provider-independent relays known from bootstrap/relay config (each a libp2p
    /// [`PeerId`] + its direct transport [`Multiaddr`], e.g. `/ip4/…/tcp/…`). The primary
    /// TASK-219 path reads the provider's bounded, signature-bound relay identities from its
    /// exact record and resolves each relay address through raw kad. This flat config set is
    /// consulted only for an actually empty legacy hint set, preserving TASK-218 rollout
    /// compatibility with the original single-shared-relay deployment without overriding signed
    /// authority. It is never indexed by provider or
    /// content and never becomes a mutable provider-address cache. Empty by default.
    pub known_relays: Vec<(PeerId, Multiaddr)>,
    /// The node's PUBLICATION-ELIGIBILITY authority (TASK-231, AC#2): the per-fabric
    /// [`PublicationEligibility`] the announcer consults FAIL-CLOSED before publishing any
    /// record. It IS the node's audience/policy, singular per fabric (one fabric = one kad DHT
    /// membership = one audience): a PUBLIC provider injects the `PublicNarAllowlist`-backed
    /// decision; a genuinely-isolated LAN node an explicit [`AdmitAllPublication`]
    /// ([`with_admit_all_publication`](NodeConfig::with_admit_all_publication)); a pure consumer
    /// leaves the default. The DEFAULT is [`RefusePublication`] - fail-closed: a node that did
    /// not EXPLICITLY choose a publication policy announces NOTHING (an `AdmitAll` default would
    /// silently reopen the bypass). This is the ONE place the announcer's authority is set; it
    /// never enters the swarm.
    pub publication_eligibility: Arc<dyn PublicationEligibility>,
    /// LAN CONFINEMENT (TASK-280): when `true`, this node's egress and serving are restricted to
    /// LAN peers, holding the no-allowlist `lan-share` public-isolation GUARANTEE end-to-end. It
    /// (1) installs the [`LanDialGuard`] outbound-dial veto so the node opens NO usable connection
    /// to a non-LAN address (covering kad's autonomous by-`PeerId` dials of query-learned
    /// addresses), (2) gates the `identify`/`mDNS` `add_address` callsites to LAN-only addresses,
    /// and (3) refuses to serve NAR bytes over any connection lacking LAN provenance (closing the
    /// bidirectional-serve leg). Defaults to [`DEFAULT_LAN_CONFINEMENT`] (`false`): every other
    /// profile dials and serves unrestricted. Set by the composition root ONLY for a
    /// [`PublicationPlan::Lan`](../../daemon_libp2p/enum.PublicationPlan.html)-equivalent
    /// `lan-share` node; `public-share` (allowlist-gated) and `consume-only` never set it.
    pub lan_confinement: bool,
}

impl NodeConfig {
    /// A config for `seed` on the default network scope with the default
    /// [`DEFAULT_KAD_QUERY_TIMEOUT`].
    pub fn new(identity_seed: [u8; 32]) -> Self {
        NodeConfig {
            identity_seed,
            network_scope: "v1".to_string(),
            kad_query_timeout: DEFAULT_KAD_QUERY_TIMEOUT,
            relay_server_enabled: DEFAULT_RELAY_SERVER_ENABLED,
            kad_server: DEFAULT_KAD_SERVER,
            mdns_enabled: DEFAULT_MDNS_ENABLED,
            peer_address_book: BTreeMap::new(),
            known_relays: Vec::new(),
            // Fail-closed default (TASK-231, AC#2): a node that did not explicitly choose a
            // publication policy refuses to publish anything. A publishing node opts in with
            // `with_admit_all_publication` (isolated LAN) or `with_publication_eligibility`
            // (the allowlist-backed public authority).
            publication_eligibility: Arc::new(RefusePublication),
            lan_confinement: DEFAULT_LAN_CONFINEMENT,
        }
    }

    /// Override the network scope (builder style).
    pub fn with_network_scope(mut self, scope: impl Into<String>) -> Self {
        self.network_scope = scope.into();
        self
    }

    /// Override the kad iterative-query timeout (TASK-210, builder style). See
    /// [`NodeConfig::kad_query_timeout`] for the tradeoff of a larger value.
    pub fn with_kad_query_timeout(mut self, timeout: Duration) -> Self {
        self.kad_query_timeout = timeout;
        self
    }

    /// Choose whether this node serves as a circuit-v2 relay for OTHER peers (TASK-208,
    /// builder style). Default is `true` ([`DEFAULT_RELAY_SERVER_ENABLED`]); pass `false` to
    /// opt OUT of relaying while still USING relays (see [`NodeConfig::relay_server_enabled`]).
    pub fn with_relay_server(mut self, enabled: bool) -> Self {
        self.relay_server_enabled = enabled;
        self
    }

    /// Choose whether this node runs Kademlia in SERVER mode (TASK-120 fix A, builder style).
    /// Default is `true` ([`DEFAULT_KAD_SERVER`]); pass `false` for CLIENT mode (issue queries,
    /// answer none, store nothing - a consumer that provides no DHT infrastructure). See
    /// [`NodeConfig::kad_server`].
    pub fn with_kad_server(mut self, enabled: bool) -> Self {
        self.kad_server = enabled;
        self
    }

    /// Choose whether this node runs LAN mDNS peer-ADDRESS discovery (TASK-257, builder style).
    /// Default is `false` ([`DEFAULT_MDNS_ENABLED`]): the behaviour is absent and the node emits
    /// zero mDNS multicast. Pass `true` to install it so same-scope LAN neighbours are discovered
    /// with NO configured bootstrap; discovered addresses feed the SAME kad bootstrap/address path
    /// and NEVER content discovery. See [`NodeConfig::mdns_enabled`].
    pub fn with_mdns(mut self, enabled: bool) -> Self {
        self.mdns_enabled = enabled;
        self
    }

    /// Confine this node's egress + serving to LAN peers (TASK-280, builder style). Default is
    /// `false` ([`DEFAULT_LAN_CONFINEMENT`]): dialing and serving are unrestricted. Pass `true`
    /// ONLY for a no-allowlist `lan-share` node — it installs the [`LanDialGuard`] outbound-dial
    /// veto, gates the `identify`/`mDNS` `add_address` callsites to LAN-only addresses, and refuses
    /// to serve NAR bytes over any non-LAN-provenance connection. See [`NodeConfig::lan_confinement`].
    pub fn with_lan_confinement(mut self, enabled: bool) -> Self {
        self.lan_confinement = enabled;
        self
    }

    /// Register a provider `node`'s dial `addrs` in the static peer address book consulted
    /// under [`ResolutionPolicy::ExplicitPeersOnly`](peer_fabric::ResolutionPolicy::ExplicitPeersOnly)
    /// (TASK-168 AC#2, builder style). Repeated calls for the SAME `node` APPEND (a peer may
    /// be dialable at several addresses); pass every address you know. Resolving a
    /// so-configured peer is a pure LOCAL lookup that discloses nothing to any third party.
    /// See [`NodeConfig::peer_address_book`].
    pub fn with_explicit_peer(
        mut self,
        node: NodeId,
        addrs: impl IntoIterator<Item = Multiaddr>,
    ) -> Self {
        self.peer_address_book
            .entry(node)
            .or_default()
            .extend(addrs);
        self
    }

    /// Register a relay this node knows from bootstrap/relay config (TASK-218, builder
    /// style): `peer` is the relay's libp2p [`PeerId`] and `addr` its direct transport
    /// [`Multiaddr`] (e.g. `/ip4/…/tcp/…`). The node-locator uses these to CONSTRUCT a
    /// `/p2p-circuit` dial-address for a NAT'd provider it discovered via kad (see
    /// [`NodeConfig::known_relays`]). Repeated calls APPEND. Passing the consumer's
    /// bootstrap peers here is the intended wiring (a shared bootstrap relay is exactly
    /// what a NAT'd provider reserves on).
    pub fn with_known_relay(mut self, peer: PeerId, addr: Multiaddr) -> Self {
        self.known_relays.push((peer, addr));
        self
    }

    /// Set this node's publication-eligibility authority (TASK-231, AC#2, builder style). The
    /// PUBLIC provider path injects the `PublicNarAllowlist`-backed decision here so the
    /// announcer refuses any record the single TASK-102 allowlist did not approve. See
    /// [`NodeConfig::publication_eligibility`].
    pub fn with_publication_eligibility(
        mut self,
        eligibility: Arc<dyn PublicationEligibility>,
    ) -> Self {
        self.publication_eligibility = eligibility;
        self
    }

    /// Declare this a GENUINELY-ISOLATED-LAN (or test) node whose announcer admits EVERY record
    /// (TASK-231, AC#3, builder style): an EXPLICIT [`AdmitAllPublication`], never a silent
    /// bypass. Use ONLY for a node provably not joined to any public substrate (no bootstrap, no
    /// provider-addr, a loopback/link-local listen - the `lan_isolation_or_refuse` policy), or a
    /// test fabric. A public-reachable node must instead inject the allowlist authority via
    /// [`with_publication_eligibility`](NodeConfig::with_publication_eligibility); the default
    /// ([`RefusePublication`]) fails closed.
    pub fn with_admit_all_publication(self) -> Self {
        self.with_publication_eligibility(Arc::new(AdmitAllPublication))
    }
}

/// Why a node could not be started.
#[derive(Debug)]
pub enum NodeError {
    /// The transport/swarm could not be constructed.
    Build(String),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Build(why) => write!(f, "libp2p swarm build failed: {why}"),
        }
    }
}

impl std::error::Error for NodeError {}

/// A started libp2p node: its identity and a [`SwarmHandle`] to drive it. The worker
/// runs on a spawned tokio task held alive by `_worker` (aborted on drop).
pub struct Node {
    pub handle: SwarmHandle,
    pub node_id: NodeId,
    pub peer_id: PeerId,
    _worker: abort::AbortOnDropHandle,
    /// The inbound-serve accept loop (TASK-157), aborted on drop alongside the worker so a
    /// dropped node tears down both its poll loop and its stream-accept task (RAII).
    _accept: abort::AbortOnDropHandle,
}

/// A tokio JoinHandle wrapper that aborts the worker when the node is dropped, so a
/// dropped fabric tears its swarm down (RAII), never leaking a background task.
pub mod abort {
    pub struct AbortOnDropHandle(tokio::task::JoinHandle<()>);
    impl AbortOnDropHandle {
        pub fn new(handle: tokio::task::JoinHandle<()>) -> Self {
            AbortOnDropHandle(handle)
        }
    }
    impl Drop for AbortOnDropHandle {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
}

/// Build the shipped node's Kademlia behaviour: the PRIVATE, scope-namespaced kad DHT.
///
/// This is the SINGLE construction site for the node's `kad::Behaviour`, called by
/// [`Node::start`] in production AND asserted directly by the AC#3 semantic guard test
/// (`kad_speaks_only_the_private_scoped_protocol_never_the_public_ipfs_dht`, TASK-154). Binding
/// the test to THIS function — it inspects [`kad::Behaviour::protocol_names`] on the object
/// returned here — is what makes the AC#3 oracle SEMANTIC and unbypassable by source-text decoys
/// (the TASK-154 F2 non-converging regex whack-a-mole). A regression swapping
/// `kad::Behaviour::with_config` / `kad::Config::new(kad_protocol)` for the default
/// `kad::Behaviour::new` / `kad::Config::default()` preset would silently advertise the PUBLIC
/// IPFS default kad protocol (rejoining the global IPFS DHT); that flips the protocol set the
/// test observes on the constructed runtime object and BITES, no matter what the surrounding
/// source text says. The `check-public-dht-isolation.py` scan is retained only as a cheap
/// secondary lint for the accidental case.
///
/// `kad_protocol` is the caller-built `/nix-p2p/<scope>/kad/1.0.0` [`StreamProtocol`]. The store
/// carries the EXPLICIT anti-amplification caps (TASK-154 AC#1, see [`content_store_config`]); the
/// query timeout is the configurable per-query deadline (TASK-210).
fn build_kad_behaviour(
    peer_id: PeerId,
    kad_protocol: StreamProtocol,
    kad_query_timeout: Duration,
    kad_server: bool,
) -> kad::Behaviour<MemoryStore> {
    // EXPLICIT storage caps for a shipped home node (TASK-154 AC#1), never the library
    // defaults - a poisoning/amplification/sybil flood against the store costs only bounded
    // memory. See `content_store_config`.
    let store = MemoryStore::with_config(peer_id, content_store_config());
    let mut kad_config = kad::Config::new(kad_protocol);
    // Configurable per-query deadline (TASK-210). Was a hardcoded 10s, which TASK-209's RTT
    // sweep showed covers only up to ~250ms one-way and silently DeadlineExceeds GEO-satellite
    // (~600ms one-way) peers. See `DEFAULT_KAD_QUERY_TIMEOUT` for the default's justification.
    kad_config.set_query_timeout(kad_query_timeout);
    let mut kad = kad::Behaviour::with_config(peer_id, store, kad_config);
    // TASK-120 fix A: the kad MODE derives from the operator's participation profile.
    //   * SERVER: this node STORES records and ANSWERS queries for others - a PROVIDER
    //     participates in the DHT infrastructure (needed for a decentralized directory).
    //   * CLIENT: this node ISSUES queries (still discovers + fetches) but answers NONE and
    //     stores nothing - a CONSUMER provides no DHT infrastructure. An upstream-only node
    //     runs no participating swarm at all (it never reaches this constructor).
    // Making the mode reflect the profile is what keeps a node's REPORTED
    // `public_dht_participation` honest against what it actually does on the wire.
    let mode = if kad_server {
        kad::Mode::Server
    } else {
        kad::Mode::Client
    };
    kad.set_mode(Some(mode));
    kad
}

/// The library DEFAULT kad protocol preset — the PUBLIC IPFS DHT protocol(s) a
/// `kad::Behaviour::new` / `kad::Config::default()` construction advertises.
///
/// Derived at RUNTIME from a throwaway default-preset behaviour (never added to a swarm, never
/// dialed — a `kad::Behaviour` is inert until polled) rather than hardcoding the `/ipfs/kad`
/// literal. Two reasons, both load-bearing: (a) the literal is a FORBIDDEN token for
/// `check-public-dht-isolation.py`, so writing it here would trip our own lint; (b) deriving it
/// keeps the comparison correct if libp2p ever renames its default protocol. This is the same
/// technique the AC#3 semantic test uses via `bare_kad()`, lifted into production so the
/// fail-fast startup invariant ([`assert_private_kad_isolation`]) can compare against it.
fn default_preset_protocol_names(peer_id: PeerId) -> Vec<StreamProtocol> {
    let default_preset = kad::Behaviour::new(peer_id, MemoryStore::new(peer_id));
    default_preset.protocol_names().to_vec()
}

/// FAIL-FAST public-DHT isolation invariant, asserted by [`Node::start`] on the ACTUAL
/// constructed kad behaviour (`swarm.behaviour().kad`) BEFORE the node is allowed to run.
///
/// This is the PRODUCTION-PATH binding of TASK-154 AC#3 (F2). The AC#3 semantic test
/// (`kad_speaks_only_the_private_scoped_protocol_never_the_public_ipfs_dht`) binds to the
/// `build_kad_behaviour` HELPER; that leaves a gap — `Node::start` could regress to inline
/// `kad::Behaviour::new` / `kad::Config::default()` (the PUBLIC IPFS DHT preset) while the helper
/// stays a passing decoy, so both the test and the source scan still pass. This function closes
/// that gap: `Node::start` calls it UNCONDITIONALLY on `swarm.behaviour().kad.protocol_names()`,
/// the protocol set the node will actually advertise, so a regression cannot even BOOT — it makes
/// the node REFUSE TO START ([`NodeError::Build`]) rather than silently rejoin the global DHT.
/// Unbypassable by a test-helper decoy or a source-scan decoy: the assertion runs on the object
/// production ships, not on any separately-constructed stand-in.
///
/// The invariant, over the ADVERTISED protocol set:
///   (a) the private `/nix-p2p/<scope>/kad/1.0.0` protocol (for the configured `scope`) IS
///       present — the node speaks the private DHT; AND
///   (b) the set is DISJOINT from the library default preset (the PUBLIC IPFS DHT), derived at
///       runtime by [`default_preset_protocol_names`] — the node does NOT speak the global DHT.
///
/// A default-preset regression flips `protocol_names()` to exactly `default_preset`, failing both
/// (a) and (b); the bite is proven by feeding this same function the default-preset object's
/// protocol set (test `production_isolation_invariant_bites_the_default_preset_regression`).
///
/// Pure and network-free (takes the already-constructed protocol slice) so it is unit-testable
/// directly on the production-constructed behaviour without a running swarm.
fn assert_private_kad_isolation(
    advertised: &[StreamProtocol],
    scope: &str,
    peer_id: PeerId,
) -> Result<(), String> {
    let expected_private = format!("/nix-p2p/{scope}/kad/1.0.0");
    let advertised_names: Vec<String> = advertised.iter().map(|p| p.to_string()).collect();
    let default_preset: Vec<String> = default_preset_protocol_names(peer_id)
        .iter()
        .map(|p| p.to_string())
        .collect();

    // (a) the private scoped protocol MUST be advertised.
    if !advertised_names.iter().any(|n| n == &expected_private) {
        return Err(format!(
            "kad public-DHT isolation invariant VIOLATED (refusing to start): the constructed kad \
             behaviour does NOT advertise the private {expected_private} protocol \
             (advertised {advertised_names:?}). A default kad::Behaviour::new / \
             kad::Config::default() regression in Node::start would rejoin the PUBLIC IPFS DHT — \
             the node must not boot."
        ));
    }
    // (b) the advertised set MUST be DISJOINT from the library default (public IPFS DHT) preset.
    if let Some(shared) = advertised_names.iter().find(|n| default_preset.contains(n)) {
        return Err(format!(
            "kad public-DHT isolation invariant VIOLATED (refusing to start): the constructed kad \
             behaviour advertises {shared:?}, which is in the library DEFAULT preset \
             {default_preset:?} (the PUBLIC IPFS DHT). The private DHT must share NO protocol with \
             the global network — the node must not boot."
        ));
    }
    Ok(())
}

impl Node {
    /// Build the swarm for `config` and spawn its worker. The node is not yet
    /// listening or bootstrapped; the caller drives that via the [`SwarmHandle`].
    pub fn start(config: NodeConfig) -> Result<Node, NodeError> {
        let keypair = keypair_from_seed(&config.identity_seed);
        let node_id = node_id_of(&keypair);
        let peer_id = keypair.public().to_peer_id();
        let scope = config.network_scope;
        // The configurable kad iterative-query timeout (TASK-210). `Duration` is `Copy`, so
        // capture it before the behaviour closure moves other config out.
        let kad_query_timeout = config.kad_query_timeout;
        // TASK-120 fix A: the kad server/client mode derives from the participation profile.
        let kad_server = config.kad_server;
        // The relay-server opt-out (TASK-208). `bool` is `Copy`; capture it before the
        // behaviour closure so it can decide whether to install the relay SERVER behaviour.
        let relay_server_enabled = config.relay_server_enabled;
        // The LAN mDNS peer-ADDRESS discovery opt-in (TASK-257). `bool` is `Copy`; capture it
        // before the behaviour closure so it can decide whether to install the mDNS behaviour
        // (a disabled `Toggle` when off = zero multicast, the default).
        let mdns_enabled = config.mdns_enabled;
        // LAN confinement (TASK-280). `bool` is `Copy`; capture it before the behaviour closure so
        // it can decide whether to install the `LanDialGuard` outbound-dial veto, and so the worker
        // + accept loop can be wired with the LAN-provenance serve view.
        let lan_confinement = config.lan_confinement;

        let kad_protocol = StreamProtocol::try_from_owned(format!("/nix-p2p/{scope}/kad/1.0.0"))
            .map_err(|e| NodeError::Build(format!("invalid kad protocol name: {e:?}")))?;
        let id_protocol = format!("/nix-p2p/{scope}/id/1.0.0");
        // Same string, kept for the worker's identify receive-gate (the closure below moves
        // `id_protocol` into `identify::Config`). One formula, so the advertised and the
        // gate-expected `protocol_version` cannot drift (TASK-280 #4).
        let worker_id_protocol = id_protocol.clone();
        // `/nar/4` is a wholesale security bump: fixed 64-KiB Bao leaves,
        // response-global raw/per-leaf-zstd codec, exact raw_size, COMPLETE and
        // clean FIN. Only v4 is registered; accepting v3 would silently discard
        // per-leaf authentication.
        let nar_protocol = StreamProtocol::try_from_owned(format!("/nix-p2p/{scope}/nar/4"))
            .map_err(|e| NodeError::Build(format!("invalid nar protocol name: {e:?}")))?;

        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| NodeError::Build(e.to_string()))?
            .with_quic()
            // NAT traversal (TASK-168): install the relay-client TRANSPORT so a `/p2p-circuit`
            // listen/dial actually routes through a relay. The builder hands the constructed
            // `relay::client::Behaviour` to the behaviour closure below so the transport and the
            // behaviour stay in lock-step (the one place the client behaviour can be built).
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| NodeError::Build(e.to_string()))?
            .with_behaviour(
                |key,
                 relay_client|
                 -> Result<Behaviour, Box<dyn std::error::Error + Send + Sync>> {
                    let peer_id = key.public().to_peer_id();
                    // The node's Kademlia behaviour is built by the SINGLE shared constructor
                    // `build_kad_behaviour` (see its doc): the PRIVATE, scope-namespaced
                    // `/nix-p2p/<scope>/kad/1.0.0` DHT with EXPLICIT store caps (TASK-154 AC#1)
                    // and the configurable query timeout (TASK-210). The AC#3 SEMANTIC guard test
                    // asserts `.protocol_names()` on exactly this construction, so a swap to the
                    // default `kad::Behaviour::new` (the PUBLIC IPFS DHT preset) bites (TASK-154 F2).
                    let kad =
                        build_kad_behaviour(peer_id, kad_protocol, kad_query_timeout, kad_server);
                    // TASK-280 #4 (codex fix-review BLOCKER): the identify RECEIVE-gate below only
                    // suppresses the app's explicit `kad.add_address`, but libp2p-identify 0.47
                    // INTERNALLY caches every advertised listen address (default cache 100) and emits
                    // `ToSwarm::NewExternalAddrOfPeer` (queued alongside the Received event) as a swarm
                    // event our handler cannot cancel — seeding the
                    // swarm address book so a cross-scope peer's GLOBAL address stays a dial candidate
                    // for a later kad by-PeerId dial (the dial VETO denies it, but only AFTER a
                    // transport connect). Under LAN confinement, build identify with `cache_size(0)`
                    // (`PeerCache::disabled`): the internal cache never fires, so a mismatched-scope
                    // peer's advertised address is never a dial candidate at all. Off the lan-share
                    // path we keep the library default (public nodes rely on identify address
                    // discovery for connectivity). The receive-gate is KEPT as defence in depth.
                    // TASK-280 #4 + TASK-282 (a): the identify config (protocol_version + the
                    // confinement address-cache mitigation) is built by the single-source
                    // `build_identify_config`, so `identify_config_disables_address_cache_under_confinement`
                    // bites the REAL config a revert of `.with_cache_size(0)` would produce.
                    let identify = identify::Behaviour::new(build_identify_config(
                        id_protocol,
                        key.public(),
                        lan_confinement,
                    ));
                    // The RAW-STREAM NAR byte-transfer substrate (TASK-157): opened and
                    // accepted through a Control on tasks OFF this poll loop. It is
                    // protocol-agnostic here; the concrete `/nar/4` name is registered on the
                    // accept side below.
                    let stream = libp2p_stream::Behaviour::new();
                    // NAT traversal (TASK-168). See the `Behaviour` doc for the role of each.
                    // `autonat` needs identify's observed-address signal (present above) to know
                    // which of OUR addresses to probe. The `relay` SERVER runs BY DEFAULT so
                    // any public node helps NAT'd peers with no dedicated infra, but with
                    // EXPLICIT bounds (`relay_server_config`, TASK-208) - never the library
                    // default caps - and it can be opted OUT entirely (a disabled `Toggle`),
                    // in which case this node still USES relays via `relay_client`/`dcutr`.
                    // `dcutr` upgrades a relayed connection to a direct one (hole punch); relay
                    // is the fallback. `relay_client` is the builder-constructed circuit-v2
                    // client.
                    let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());
                    let relay: Toggle<relay::Behaviour> = relay_server_enabled
                        .then(|| relay::Behaviour::new(peer_id, relay_server_config()))
                        .into();
                    let dcutr = dcutr::Behaviour::new(peer_id);
                    // LAN peer-ADDRESS discovery (TASK-257): install the mDNS behaviour ONLY
                    // when opted in. Off = `Toggle::from(None)`: the behaviour is absent, so no
                    // multicast socket is opened and ZERO mDNS packets are emitted (the default,
                    // and what keeps an upstream-only / unflagged node link-local-silent). On =
                    // the tokio-runtime mDNS behaviour, whose `Discovered` events feed the kad
                    // address/bootstrap path (never content discovery). Construction opens the
                    // multicast socket and can fail (returns `io::Result`); that error is
                    // propagated as a build error rather than silently swallowed (fail verbosely).
                    let mdns: Toggle<mdns::tokio::Behaviour> = if mdns_enabled {
                        Some(mdns::tokio::Behaviour::new(
                            mdns::Config::default(),
                            peer_id,
                        )?)
                    } else {
                        None
                    }
                    .into();
                    // LAN confinement (TASK-280): install the outbound-dial VETO ONLY on the
                    // no-allowlist `lan-share` path. Off = `Toggle::from(None)`: the guard is absent
                    // and dialing is unrestricted. On, the derived `NetworkBehaviour` runs its
                    // per-address veto on every behaviour-initiated dial (see [`LanDialGuard`]).
                    let lan_dial_guard: Toggle<LanDialGuard> =
                        lan_confinement.then_some(LanDialGuard).into();
                    Ok(Behaviour {
                        kad,
                        identify,
                        stream,
                        autonat,
                        relay,
                        relay_client,
                        dcutr,
                        mdns,
                        lan_dial_guard,
                    })
                },
            )
            .map_err(|e| NodeError::Build(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // TASK-154 F2 (AC#3) — PRODUCTION-PATH fail-fast public-DHT isolation invariant.
        // Assert the kad behaviour THIS node will actually run (`swarm.behaviour().kad`, the
        // object shipped into the worker below, NOT a separately-built helper) advertises the
        // private scope-namespaced `/nix-p2p/<scope>/kad/1.0.0` protocol AND shares nothing with
        // the library default preset (the PUBLIC IPFS DHT). If `Node::start` ever regressed to
        // inline `kad::Behaviour::new` / `kad::Config::default()` — bypassing `build_kad_behaviour`
        // — this REFUSES TO START (`NodeError::Build`) instead of silently rejoining the global
        // DHT. Binding the invariant to the constructed runtime object is what makes it
        // unbypassable by a test-helper or source-scan decoy (see `assert_private_kad_isolation`).
        assert_private_kad_isolation(swarm.behaviour().kad.protocol_names(), &scope, peer_id)
            .map_err(NodeError::Build)?;

        // The raw-stream NAR surface (TASK-157). One Control drives both directions: it
        // registers the inbound `/nar/4` protocol (once) via `accept`, and opens outbound
        // NAR streams for fetches. The accept loop runs the SERVE half entirely off the poll
        // loop, reading the current gate from the shared slot.
        let mut control = swarm.behaviour().stream.new_control();
        let incoming = control.accept(nar_protocol.clone()).map_err(|e| {
            NodeError::Build(format!("failed to register the NAR stream protocol: {e}"))
        })?;
        let serve_slot: ServeSlot = Arc::new(Mutex::new(None));
        // The LAN-provenance serve view (TASK-280 mitigation #2): `Some` ONLY under LAN
        // confinement. Shared between the worker (writer, on connection events) and the accept loop
        // (reader, per inbound stream). `None` off the lan-share path -> unrestricted serving.
        let lan_serve_conns: Option<LanServeConns> =
            lan_confinement.then(|| Arc::new(Mutex::new(HashMap::new())));
        let accept_join = tokio::spawn(run_accept_loop(
            incoming,
            Arc::clone(&serve_slot),
            lan_serve_conns.clone(),
        ));

        let (tx, rx) = mpsc::channel(64);
        // The dedicated LOSSLESS query-cancel channel (TASK-154 B3), separate from the bounded
        // command channel so an abandoned-query cancel is never dropped under command
        // backpressure.
        let (cancel_tx, cancel_rx) = mpsc::unbounded_channel();
        let (exact_dial_cancel_tx, exact_dial_cancel_rx) = mpsc::unbounded_channel();
        let worker = Worker {
            swarm,
            commands: rx,
            cancels: cancel_rx,
            exact_dial_cancels: exact_dial_cancel_rx,
            pending: HashMap::new(),
            pending_listens: HashMap::new(),
            pending_exact_dials: HashMap::new(),
            conn_routes: HashMap::new(),
            mdns_admission: MdnsAdmission::new(
                MDNS_ADMISSION_CAP,
                Duration::from_secs(MDNS_ADMISSION_WINDOW_SECS),
                Instant::now(),
            ),
            lan_serve_conns,
            id_protocol: worker_id_protocol,
            started_at: Instant::now(),
            first_mdns_reported: false,
        };
        let join = tokio::spawn(worker.run());

        Ok(Node {
            handle: SwarmHandle {
                tx,
                cancels: cancel_tx,
                exact_dial_cancels: exact_dial_cancel_tx,
                control,
                nar_protocol,
                serve_slot,
            },
            node_id,
            peer_id,
            _worker: abort::AbortOnDropHandle::new(join),
            _accept: abort::AbortOnDropHandle::new(accept_join),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::AsyncReadExt as _;
    use proc_supervisor::TaskSupervisor;
    use std::ffi::OsString;
    use std::path::PathBuf;

    /// TASK-257 F-1: the mDNS admission gate bounds how many DISTINCT LAN peers we act on per
    /// window, so an unauthenticated flood cannot make us dial/admit an unbounded set. BITE: emit
    /// N > cap distinct mDNS PeerIds in ONE window -> exactly `cap` admitted, the surplus dropped.
    /// MUTATION: removing the `admitted.len() >= cap` check (always admit) -> all N admitted ->
    /// this reddens. Also proves an already-admitted peer refreshes for free and the window rolls.
    #[test]
    fn mdns_admission_caps_a_flood_and_refreshes_within_the_cap() {
        let cap = 4usize;
        let window = Duration::from_secs(30);
        let t0 = Instant::now();
        let mut gate = MdnsAdmission::new(cap, window, t0);

        // A flood of N = cap + 6 DISTINCT peers in ONE window: exactly `cap` admitted.
        let flood: Vec<PeerId> = (0..cap + 6).map(|_| PeerId::random()).collect();
        let admitted = flood.iter().filter(|p| gate.admit(**p, t0)).count();
        assert_eq!(
            admitted,
            cap,
            "a burst of {} distinct mDNS peers must admit exactly cap={cap}, not all of them",
            flood.len()
        );

        // An already-admitted peer re-advertising THIS window is admitted again for free (refresh),
        // never re-charging the cap.
        assert!(
            gate.admit(flood[0], t0),
            "an already-admitted peer must refresh for free"
        );

        // The window rolls: after `window` elapses the set clears, so a fresh distinct peer is
        // admitted again (legitimate churn across windows is unaffected).
        let later = t0 + window + Duration::from_secs(1);
        let fresh = PeerId::random();
        assert!(
            gate.admit(fresh, later),
            "after the window rolls, a fresh peer is admitted again"
        );
    }

    struct ProcessProbe {
        content: Blake3Digest,
        body: PathBuf,
        counter: PathBuf,
        pass2_ready: PathBuf,
        pass2_release: PathBuf,
    }

    impl nar::CatalogProbe for ProcessProbe {
        fn probe(&self, content: &Blake3Digest) -> Option<nar::ProbedSupply> {
            (content == &self.content).then(|| {
                let script = "n=$(cat \"$1\" 2>/dev/null || printf 0); n=$((n + 1)); \
                     printf %s \"$n\" > \"$1\"; \
                     if [ \"$n\" -eq 1 ]; then cat \"$2\"; exit $?; fi; \
                     head -c 65536 \"$2\"; : > \"$3\"; \
                     while [ ! -e \"$4\" ]; do sleep 0.01; done; \
                     tail -c +65537 \"$2\"";
                nar::ProbedSupply {
                    declared_size: std::fs::metadata(&self.body)
                        .expect("test NAR exists")
                        .len(),
                    source: nar::ProbedSource::Process {
                        program: PathBuf::from("sh"),
                        args: vec![
                            OsString::from("-c"),
                            OsString::from(script),
                            OsString::from("nar4-real-two-node"),
                            self.counter.clone().into_os_string(),
                            self.body.clone().into_os_string(),
                            self.pass2_ready.clone().into_os_string(),
                            self.pass2_release.clone().into_os_string(),
                        ],
                    },
                }
            })
        }
    }

    struct Nar4TestFiles(Vec<PathBuf>);

    impl Drop for Nar4TestFiles {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    fn nar4_test_nonce() -> String {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        format!("{}-{time}", std::process::id())
    }

    fn nar4_test_path(stem: &str, nonce: &str) -> PathBuf {
        std::env::temp_dir().join(format!("nix-p2p-nar4-{stem}-{nonce}"))
    }

    // TASK-242: derive aggregate status from the exact ConnectionId route SSOT. Direct remains
    // dominant for a hole-punched peer with a lingering circuit, and no routes means disconnected.
    #[test]
    fn exact_routes_classify_direct_dominant() {
        assert_eq!(connection_path_from_routes(None), ConnPath::None);

        let relay = PeerId::random();
        let mut routes = HashMap::from([(
            ConnectionId::new_unchecked(1),
            ConnectionRoute::Relayed { relay },
        )]);
        assert_eq!(connection_path_from_routes(Some(&routes)), ConnPath::Relay);

        routes.insert(ConnectionId::new_unchecked(2), ConnectionRoute::Direct);
        assert_eq!(connection_path_from_routes(Some(&routes)), ConnPath::Direct);
    }

    /// TASK-219 route authority is current connection fact plus the exact offer-derived relay set.
    /// MUTATIONS: accepting every relayed route fails the wrong-relay assertion; rejecting direct
    /// fails the direct assertion. The integration overlap arm additionally bites peer-wide close.
    #[test]
    fn route_authorization_allows_direct_or_exact_relay_only() {
        let signed_relay = PeerId::random();
        let wrong_relay = PeerId::random();
        let permitted = BTreeSet::from([signed_relay]);

        assert!(connection_route_allowed(
            &ConnectionRoute::Direct,
            &permitted
        ));
        assert!(connection_route_allowed(
            &ConnectionRoute::Relayed {
                relay: signed_relay
            },
            &permitted
        ));
        assert!(!connection_route_allowed(
            &ConnectionRoute::Relayed { relay: wrong_relay },
            &permitted
        ));
        assert!(!connection_route_allowed(
            &ConnectionRoute::RelayedUnknown,
            &permitted
        ));
        assert!(connection_route_allowed(
            &ConnectionRoute::Direct,
            &BTreeSet::new()
        ));
    }

    /// A live connection through R2 must not satisfy an offer authorizing only R1. When both
    /// coexist, exact selection returns R1's ConnectionId; R2 remains in the ledger untouched.
    #[test]
    fn exact_selection_uses_authorized_relay_without_closing_conflicting_route() {
        let r1 = PeerId::random();
        let r2 = PeerId::random();
        let r1_connection = ConnectionId::new_unchecked(11);
        let r2_connection = ConnectionId::new_unchecked(12);
        let routes = HashMap::from([
            (r2_connection, ConnectionRoute::Relayed { relay: r2 }),
            (r1_connection, ConnectionRoute::Relayed { relay: r1 }),
        ]);

        let selected = select_authorized_connection(Some(&routes), &BTreeSet::from([r1]))
            .expect("R1 is live and authorized");
        assert_eq!(selected.id, r1_connection);
        assert_eq!(selected.route, ConnectionRoute::Relayed { relay: r1 });
        assert_eq!(
            routes.get(&r2_connection),
            Some(&ConnectionRoute::Relayed { relay: r2 }),
            "selection is read-only: conflicting R2 remains live for concurrent work"
        );
        assert!(
            select_authorized_connection(Some(&routes), &BTreeSet::new()).is_none(),
            "neither relayed connection is usable without an authorized hint"
        );
    }

    /// Cancellation after command registration replaces the active authority with a tombstone.
    /// A late success must request an exact close and must never enter the route ledger.
    #[test]
    fn cancelled_exact_dial_closes_late_success_without_route_admission() {
        let peer = PeerId::random();
        let connection = ConnectionId::new_unchecked(21);
        let (reply, _receiver) = oneshot::channel::<Result<AuthorizedConnection, String>>();
        let mut pending = HashMap::from([(
            connection,
            PendingExactDial::Active {
                peer,
                permitted_relays: BTreeSet::new(),
                reply,
            },
        )]);
        let mut routes = HashMap::new();

        assert_eq!(
            apply_exact_dial_cancel(&mut pending, &mut routes, peer, connection),
            ExactDialCancelTransition::AwaitTerminal
        );
        assert!(matches!(
            pending.get(&connection),
            Some(PendingExactDial::Tombstone { peer: tombstoned_peer })
                if *tombstoned_peer == peer
        ));
        assert_eq!(
            apply_connection_established(
                &mut pending,
                &mut routes,
                peer,
                connection,
                ConnectionRoute::Direct,
            ),
            ConnectionEstablishedTransition::Close(ExactConnectionCloseReason::Cancelled)
        );
        assert!(!pending.contains_key(&connection));
        assert!(
            routes.is_empty(),
            "a cancelled late success is never admitted"
        );
    }

    /// The cancellation channel and bounded command channel are independently selected. If the
    /// cancel wins before the already-enqueued command, it sees no state; the later command's
    /// closed waiter remains the authority and makes establishment close instead of admit.
    #[test]
    fn cancel_overtaking_exact_command_still_closes_late_success() {
        let peer = PeerId::random();
        let connection = ConnectionId::new_unchecked(22);
        let mut pending = HashMap::new();
        let mut routes = HashMap::new();

        assert_eq!(
            apply_exact_dial_cancel(&mut pending, &mut routes, peer, connection),
            ExactDialCancelTransition::None
        );

        let (reply, receiver) = oneshot::channel::<Result<AuthorizedConnection, String>>();
        drop(receiver);
        pending.insert(
            connection,
            PendingExactDial::Active {
                peer,
                permitted_relays: BTreeSet::new(),
                reply,
            },
        );
        assert_eq!(
            apply_connection_established(
                &mut pending,
                &mut routes,
                peer,
                connection,
                ConnectionRoute::Direct,
            ),
            ConnectionEstablishedTransition::Close(ExactConnectionCloseReason::WaiterGone)
        );
        assert!(
            routes.is_empty(),
            "the closed reply cannot authorize admission"
        );
    }

    /// A success can linearize at reply delivery just before its cancel is observed. That cancel
    /// removes and closes only the exact R2 connection; a conflicting live R1 route survives and
    /// remains selectable for its own signed offer.
    #[test]
    fn cancel_after_success_removes_only_its_exact_connection() {
        let provider = PeerId::random();
        let r1 = PeerId::random();
        let r2 = PeerId::random();
        let r1_connection = ConnectionId::new_unchecked(23);
        let r2_connection = ConnectionId::new_unchecked(24);
        let mut routes = HashMap::from([(
            provider,
            HashMap::from([(r1_connection, ConnectionRoute::Relayed { relay: r1 })]),
        )]);
        let (reply, receiver) = oneshot::channel::<Result<AuthorizedConnection, String>>();
        let mut pending = HashMap::from([(
            r2_connection,
            PendingExactDial::Active {
                peer: provider,
                permitted_relays: BTreeSet::from([r2]),
                reply,
            },
        )]);

        assert_eq!(
            apply_connection_established(
                &mut pending,
                &mut routes,
                provider,
                r2_connection,
                ConnectionRoute::Relayed { relay: r2 },
            ),
            ConnectionEstablishedTransition::Keep
        );
        // `Keep` proves the success send linearized. Leave that buffered success unpolled, then
        // model the timeout/drop racing immediately afterward: production has not consumed the
        // reply and therefore has not disarmed its guard yet.
        drop(receiver);
        assert_eq!(
            apply_exact_dial_cancel(&mut pending, &mut routes, provider, r2_connection),
            ExactDialCancelTransition::Close
        );
        assert_eq!(
            routes.get(&provider),
            Some(&HashMap::from([(
                r1_connection,
                ConnectionRoute::Relayed { relay: r1 },
            )])),
            "cancelling R2 must preserve the concurrent R1 connection"
        );
        assert_eq!(
            select_authorized_connection(routes.get(&provider), &BTreeSet::from([r1])),
            Some(AuthorizedConnection {
                id: r1_connection,
                route: ConnectionRoute::Relayed { relay: r1 },
            })
        );
    }

    /// This is the former `is_closed`/`send` TOCTOU in isolation. Admission is conditional on the
    /// authoritative send itself, so a receiver that closes immediately before that send yields
    /// Close and leaves no derived route behind.
    #[test]
    fn closed_exact_waiter_send_failure_is_never_admitted() {
        let peer = PeerId::random();
        let relay = PeerId::random();
        let connection = ConnectionId::new_unchecked(25);
        let (reply, receiver) = oneshot::channel::<Result<AuthorizedConnection, String>>();
        drop(receiver);
        let mut pending = HashMap::from([(
            connection,
            PendingExactDial::Active {
                peer,
                permitted_relays: BTreeSet::from([relay]),
                reply,
            },
        )]);
        let mut routes = HashMap::new();

        assert_eq!(
            apply_connection_established(
                &mut pending,
                &mut routes,
                peer,
                connection,
                ConnectionRoute::Relayed { relay },
            ),
            ConnectionEstablishedTransition::Close(ExactConnectionCloseReason::WaiterGone)
        );
        assert!(routes.is_empty());
        assert!(!pending.contains_key(&connection));
    }

    /// Drop is the lossless cancellation boundary. An armed guard emits the exact peer/id once;
    /// normal completion disarms it and emits nothing.
    #[test]
    fn exact_dial_cancel_guard_emits_only_while_armed() {
        let peer = PeerId::random();
        let armed_connection = ConnectionId::new_unchecked(26);
        let disarmed_connection = ConnectionId::new_unchecked(27);
        let (cancels, mut received) = mpsc::unbounded_channel();

        let (armed_reply, armed_receiver) =
            oneshot::channel::<Result<AuthorizedConnection, String>>();
        {
            let _armed =
                CancelExactDialOnDrop::new(cancels.clone(), peer, armed_connection, armed_receiver);
        }
        assert!(
            armed_reply.is_closed(),
            "the reply receiver must close before cancellation becomes observable"
        );
        assert_eq!(received.try_recv(), Ok((peer, armed_connection)));

        let (_disarmed_reply, disarmed_receiver) =
            oneshot::channel::<Result<AuthorizedConnection, String>>();
        {
            let mut disarmed =
                CancelExactDialOnDrop::new(cancels, peer, disarmed_connection, disarmed_receiver);
            disarmed.disarm();
        }
        assert!(matches!(
            received.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
    }

    /// Only the `/p2p/<relay>` component immediately before `/p2p-circuit` is authority.
    /// Some other PeerId elsewhere in an address must not be guessed as the relay.
    #[test]
    fn circuit_relay_parser_requires_the_immediate_peer_component() {
        let relay = PeerId::random();
        let provider = PeerId::random();
        let valid: Multiaddr =
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{provider}")
                .parse()
                .unwrap();
        assert_eq!(circuit_relay_peer(&valid), Some(relay));

        let missing: Multiaddr = format!("/ip4/127.0.0.1/tcp/4001/p2p-circuit/p2p/{provider}")
            .parse()
            .unwrap();
        assert_eq!(circuit_relay_peer(&missing), None);

        let non_adjacent: Multiaddr = format!("/p2p/{relay}/tcp/4001/p2p-circuit/p2p/{provider}")
            .parse()
            .unwrap();
        assert_eq!(circuit_relay_peer(&non_adjacent), None);
    }

    // The pure near-key mapping (TASK-174), deterministic and network-free. The
    // integration test `tests/near_key_routing_bar.rs` proves the same boundary end to
    // end (a live query that reaches nobody) and bites the OLD total-routing bar.
    #[test]
    fn absence_from_reach_maps_answered_to_miss_and_zero_to_insufficient_routing() {
        // Reached >=1 responding peer near the key -> an empty result is authoritative.
        assert!(matches!(
            absence_from_reach::<()>(QueryReach { answered: 1 }),
            Lookup::Miss
        ));
        // Reached nobody -> could-not-consult, never a (false) Miss.
        assert!(matches!(
            absence_from_reach::<()>(QueryReach { answered: 0 }),
            Lookup::Unavailable(Unavailable::InsufficientRouting)
        ));
        // `reached_neighborhood` is the same predicate the classifier is built on.
        assert!(QueryReach { answered: 1 }.reached_neighborhood());
        assert!(!QueryReach { answered: 0 }.reached_neighborhood());
    }

    // TASK-208: the explicit relay-server bounds actually reach `relay::Config`, and are
    // the tightened home-node values - NOT the library defaults. Bite: a revert to
    // `relay::Config::default()` (128 reservations / 16 circuits / 1h) fails these asserts.
    #[test]
    fn relay_server_config_carries_explicit_bounds_not_library_defaults() {
        let cfg = relay_server_config();
        // Every hard cap is threaded from its `RELAY_*` constant.
        assert_eq!(cfg.max_reservations, RELAY_MAX_RESERVATIONS);
        assert_eq!(
            cfg.max_reservations_per_peer,
            RELAY_MAX_RESERVATIONS_PER_PEER
        );
        assert_eq!(cfg.reservation_duration, RELAY_RESERVATION_DURATION);
        assert_eq!(cfg.max_circuits, RELAY_MAX_CIRCUITS);
        assert_eq!(cfg.max_circuits_per_peer, RELAY_MAX_CIRCUITS_PER_PEER);
        assert_eq!(cfg.max_circuit_duration, RELAY_MAX_CIRCUIT_DURATION);
        assert_eq!(cfg.max_circuit_bytes, RELAY_MAX_CIRCUIT_BYTES);

        // And they are strictly TIGHTER than the library defaults for a home node - so the
        // node is not left as an open, public-relay-scale amplifier.
        let default = relay::Config::default();
        assert!(
            cfg.max_reservations < default.max_reservations,
            "home-node reservation cap must be below the library default"
        );
        assert!(
            cfg.max_circuits < default.max_circuits,
            "home-node circuit cap must be below the library default"
        );
        assert!(
            cfg.reservation_duration < default.reservation_duration,
            "home-node reservation lifetime must be below the library default"
        );
        // No-float rule: byte cap is an integer; duration caps are integer `Duration`s (no
        // sub-second fraction) - assert the byte ceiling is the exact integer we intend.
        assert_eq!(cfg.max_circuit_bytes, 1 << 17);
    }

    // TASK-208: the opt-out is honored at the config layer (default ON; builder flips it
    // OFF). The behavioral proof that OFF actually removes the server (no reservation
    // accepted) lives in `tests/nat_traversal.rs::relay_server_opt_out_*`.
    #[test]
    fn relay_server_opt_out_threads_through_node_config() {
        assert!(
            NodeConfig::new([9u8; 32]).relay_server_enabled,
            "default is server ON (permissionless-swarm intent)"
        );
        assert!(
            !NodeConfig::new([9u8; 32])
                .with_relay_server(false)
                .relay_server_enabled,
            "with_relay_server(false) opts the node out of relaying"
        );
    }

    // ============================ TASK-154 AC#1 store caps ============================
    // The kad MemoryStore is where a hostile peer's records LAND. These prove the caps are
    // (a) EXPLICIT decisions (not blind library defaults) and (b) actually BITE on the wire
    // of the store API - an oversized value is refused and a per-key provider flood is bounded.

    #[test]
    fn store_config_carries_explicit_caps_not_blind_library_defaults() {
        let cfg = content_store_config();
        // Every field is threaded from its `STORE_*` constant - a decision, not a default.
        assert_eq!(cfg.max_records, STORE_MAX_RECORDS);
        assert_eq!(cfg.max_value_bytes, STORE_MAX_VALUE_BYTES);
        assert_eq!(cfg.max_providers_per_key, STORE_MAX_PROVIDERS_PER_KEY);
        assert_eq!(cfg.max_provided_keys, STORE_MAX_PROVIDED_KEYS);
        // The load-bearing anti-amplification value cap is far TIGHTER than the 65 KiB
        // library default, yet keeps headroom over the largest legal frozen record (so a
        // legitimate provider record is never refused). Both halves are compile-time
        // invariants (the second mirrors the production `const _` guard), pinned here as a
        // `const` block so a cap edit that breaks either fails the build, not just the test.
        const {
            assert!(
                STORE_MAX_VALUE_BYTES < 65 * 1024,
                "value cap must be tighter than the library default so junk cannot be parked"
            );
            assert!(
                STORE_MAX_VALUE_BYTES > peer_fabric::MAX_PROVIDER_RECORD_BYTES,
                "value cap must exceed the largest legal frozen record (headroom)"
            );
        }
    }

    #[test]
    fn store_rejects_oversized_value_but_accepts_a_legitimate_record() {
        use libp2p::kad::store::{Error, RecordStore};
        let peer = PeerId::random();
        let mut store = MemoryStore::with_config(peer, content_store_config());
        let key = kad::RecordKey::new(&b"k".to_vec());
        // A value AT the ceiling is refused (the store's check is `len >= max_value_bytes`).
        // Lower `STORE_MAX_VALUE_BYTES` past the frozen record size and the headroom assert
        // above (and the compile-time guard) bite; delete the cap and THIS stops biting.
        let oversized = kad::Record::new(key.clone(), vec![0u8; STORE_MAX_VALUE_BYTES]);
        assert!(
            matches!(store.put(oversized), Err(Error::ValueTooLarge)),
            "a value at/over the cap must be refused - the anti-amplification bite"
        );
        // A legitimate frozen-size record (<= MAX_PROVIDER_RECORD_BYTES) is ACCEPTED.
        let legit = kad::Record::new(key, vec![0u8; peer_fabric::MAX_PROVIDER_RECORD_BYTES]);
        assert!(
            store.put(legit).is_ok(),
            "a legitimate frozen-size record must be accepted (the cap has headroom)"
        );
    }

    #[test]
    fn store_caps_providers_per_key_to_bound_a_sybil_flood() {
        use libp2p::kad::store::RecordStore;
        let peer = PeerId::random();
        let mut store = MemoryStore::with_config(peer, content_store_config());
        let key = kad::RecordKey::new(&b"contended".to_vec());
        // Flood one key with more DISTINCT providers than the cap. libp2p ignores providers
        // past `max_providers_per_key` (its documented Sybil mitigation); our explicit cap
        // pins the bound. Raise the flood count freely - the stored set stays at the cap.
        for _ in 0..(STORE_MAX_PROVIDERS_PER_KEY + 5) {
            let rec = kad::ProviderRecord::new(key.clone(), PeerId::random(), Vec::new());
            let _ = store.add_provider(rec);
        }
        assert_eq!(
            store.providers(&key).len(),
            STORE_MAX_PROVIDERS_PER_KEY,
            "the per-key provider set must not grow past the explicit anti-sybil cap"
        );
    }

    // ============ TASK-154 AC#3 SEMANTIC public-DHT-isolation oracle ============
    // The unbypassable half of AC#3 (the source scan `check-public-dht-isolation.py` is the
    // cheap secondary lint). Unlike a text scan — which a same-file decoy `with_config` kept
    // defeating (the F2 non-converging regex whack-a-mole) — this binds to the RUNTIME object:
    // it calls the SINGLE production constructor `build_kad_behaviour` and asserts the actual
    // `protocol_names()` the swarm will advertise. A regression swapping `Behaviour::with_config`
    // /`Config::new` for the default `Behaviour::new`/`Config::default()` preset flips this set
    // to the PUBLIC IPFS default preset and BITES here regardless of any source-text decoy.

    #[test]
    fn kad_speaks_only_the_private_scoped_protocol_never_the_public_ipfs_dht() {
        let peer = PeerId::random();
        let scope = "unit-test-scope";
        // The protocol is built exactly as `Node::start` builds it, then handed to the SAME
        // production constructor the shipped node uses. We inspect what that construction
        // actually advertises — not what the source says it advertises.
        let kad_protocol = StreamProtocol::try_from_owned(format!("/nix-p2p/{scope}/kad/1.0.0"))
            .expect("the scoped kad protocol name is valid");
        let kad = build_kad_behaviour(peer, kad_protocol, DEFAULT_KAD_QUERY_TIMEOUT, true);
        let names: Vec<String> = kad.protocol_names().iter().map(|p| p.to_string()).collect();

        // The library DEFAULT preset (`kad::Behaviour::new` / `kad::Config::default()`) — the
        // exact thing a regression would swap to — is derived at RUNTIME from `bare_kad()` rather
        // than hardcoding the public token. This (a) keeps the forbidden public token out of our
        // source so `check-public-dht-isolation.py`'s raw-text arm does not false-positive on this
        // very test, and (b) stays correct if libp2p ever renames its default protocol.
        let public_default: Vec<String> = bare_kad()
            .protocol_names()
            .iter()
            .map(|p| p.to_string())
            .collect();

        // The private scoped protocol IS the kad protocol this node speaks.
        assert!(
            names
                .iter()
                .any(|n| n == &format!("/nix-p2p/{scope}/kad/1.0.0")),
            "the constructed kad Behaviour must advertise the private /nix-p2p/<scope>/kad \
             protocol, got {names:?}"
        );
        // It shares NOTHING with the public default preset. This is the bite: a swap to the
        // default `kad::Behaviour::new`/`kad::Config::default()` preset makes `protocol_names()`
        // equal `public_default` (the public IPFS DHT), failing every assertion here (proven by
        // mutation: swap the ctor in `build_kad_behaviour` and this test fails, observing the
        // public protocol set).
        assert!(
            names.iter().all(|n| !public_default.contains(n)),
            "the constructed kad Behaviour must NOT advertise ANY protocol from the public \
             default preset (a default `Behaviour::new`/`Config::default()` regression rejoined \
             the global IPFS DHT), got {names:?} vs default {public_default:?}"
        );
        assert_ne!(
            names, public_default,
            "the constructed kad protocol set must DIFFER from the library default preset"
        );
        // Belt-and-braces: the ONLY protocol is the private one (single-protocol kad::Config),
        // so nothing else slipped in either.
        assert_eq!(
            names,
            vec![format!("/nix-p2p/{scope}/kad/1.0.0")],
            "the constructed kad Behaviour must advertise ONLY the private scoped protocol"
        );
    }

    // ======== TASK-154 F2 (AC#3) PRODUCTION-PATH fail-fast isolation invariant ========
    // The semantic test above binds to the `build_kad_behaviour` HELPER; these three bind to the
    // PRODUCTION path. `assert_private_kad_isolation` is the smallest production function
    // `Node::start` calls UNCONDITIONALLY on the real `swarm.behaviour().kad.protocol_names()`, so
    // testing it directly on the production-constructed behaviour (and on the default-preset object
    // a regression would produce) proves the invariant `Node::start` runs both ACCEPTS the
    // legitimate node and REFUSES the regression — even a `Node::start` that inlined
    // `Behaviour::new` (bypassing the helper) cannot skip this assertion, so a regression cannot
    // boot. The full `Node::start` boot is exercised too, so nothing decouples the check from the
    // shipped construction.

    #[test]
    fn production_isolation_invariant_accepts_the_real_private_kad() {
        // Feed the invariant the protocol set of the ACTUAL production constructor. This is the
        // exact `protocol_names()` slice `Node::start` hands `assert_private_kad_isolation`, so the
        // legitimate node MUST pass — if this Err'd, every node would refuse to start.
        let peer = PeerId::random();
        let scope = "prod-path-scope";
        let kad_protocol = StreamProtocol::try_from_owned(format!("/nix-p2p/{scope}/kad/1.0.0"))
            .expect("the scoped kad protocol name is valid");
        let kad = build_kad_behaviour(peer, kad_protocol, DEFAULT_KAD_QUERY_TIMEOUT, true);
        assert_private_kad_isolation(kad.protocol_names(), scope, peer)
            .expect("the real private-scoped production kad must satisfy the startup invariant");
    }

    #[test]
    fn production_isolation_invariant_bites_the_default_preset_regression() {
        // The BITE. Construct the library DEFAULT preset (`kad::Behaviour::new` /
        // `kad::Config::default()`) — EXACTLY what a `Node::start` regression that inlined the
        // default ctor would ship into the swarm — and feed ITS `protocol_names()` to the SAME
        // production invariant `Node::start` runs. It MUST return the refuse-to-start Err: this is
        // the proof that a default-preset regression makes the node fail to boot, observed through
        // the production assertion (not a helper). `bare_kad()` is that default-preset object; its
        // `protocol_names()` is the public IPFS DHT preset.
        let peer = PeerId::random();
        let scope = "prod-path-scope";
        let regressed = bare_kad();
        let err = assert_private_kad_isolation(regressed.protocol_names(), scope, peer).expect_err(
            "a default-preset (public IPFS DHT) kad MUST fail the startup invariant — \
                 Node::start must REFUSE TO START on this regression, not silently rejoin the \
                 global DHT",
        );
        // The refuse-to-start message names the violated invariant (fail-fast, verbose).
        assert!(
            err.contains("isolation invariant VIOLATED") && err.contains("refusing to start"),
            "the refuse-to-start error must name the violated isolation invariant, got: {err}"
        );
    }

    #[tokio::test]
    async fn production_node_start_passes_the_public_dht_isolation_invariant() {
        // End-to-end proof that the invariant does NOT reject the legitimate production
        // construction: drive the REAL `Node::start` (which runs `assert_private_kad_isolation` on
        // `swarm.behaviour().kad` after `.build()`). A wrongly-tightened invariant would turn this
        // into `Err(NodeError::Build(..))` and every node would fail to boot; it must return Ok.
        let seed = [7u8; 32];
        let node = Node::start(NodeConfig::new(seed).with_network_scope("prod-path-scope"))
            .expect("the legitimate private-scope node must pass the startup isolation invariant");
        // Sanity: the node came up with the identity we seeded (the invariant ran on ITS behaviour).
        let _ = node.peer_id;
    }

    // ===================== TASK-280 LAN confinement (mitigations #1 + #2) =====================

    #[tokio::test]
    async fn lan_confinement_dial_veto_is_wired_only_on_the_lan_share_path() {
        // PROVES mitigation #1 is WIRED into the production swarm on the confined path ONLY: a
        // LAN-confined node REFUSES an outbound dial to a GLOBAL address (the LanDialGuard's
        // pre-transport pending hook denies it synchronously) and ADMITS a LAN address; an
        // UNCONFINED node admits the global dial (guard absent). The confined-vs-unconfined
        // contrast IS the attribution — flip `with_lan_confinement(true)` to `false` (or drop the
        // guard's veto) and the first assertion turns Ok.
        let confined = Node::start(
            NodeConfig::new([21u8; 32])
                .with_network_scope("lan-veto-test")
                .with_lan_confinement(true),
        )
        .expect("confined node starts");
        // A GLOBAL address: denied before any transport dial -> synchronous Err.
        assert!(
            confined
                .handle
                .dial("/ip4/8.8.8.8/tcp/4001".parse().unwrap())
                .await
                .is_err(),
            "a LAN-confined node must REFUSE an outbound dial to a global address"
        );
        // A LAN address: admitted by the guard (the async transport attempt then fails to connect,
        // but the dial CALL is accepted) -> Ok.
        assert!(
            confined
                .handle
                .dial("/ip4/127.0.0.1/tcp/1".parse().unwrap())
                .await
                .is_ok(),
            "a LAN-confined node must ADMIT an outbound dial to a LAN address"
        );

        // Control: without confinement the guard is absent, so the global dial is admitted.
        let open = Node::start(NodeConfig::new([22u8; 32]).with_network_scope("lan-veto-test"))
            .expect("unconfined node starts");
        assert!(
            open.handle
                .dial("/ip4/8.8.8.8/tcp/4001".parse().unwrap())
                .await
                .is_ok(),
            "an UNCONFINED node admits a global dial (the guard is not installed)"
        );
    }

    #[test]
    fn lan_serve_gate_permits_only_lan_provenance_peers() {
        // PROVES mitigation #2's serve gate decision. MUTATION: invert `lan_serve_permitted` (or
        // drop the accept-loop `if !lan_serve_permitted` guard) and the confined-empty / confined-
        // non-LAN assertions flip to permitting a serve.
        let peer = PeerId::random();
        let lan_conn = ConnectionId::new_unchecked(7);

        // Off the lan-share path (None): serving is unrestricted (the connection id is irrelevant).
        assert!(
            lan_serve_permitted(&None, &peer, lan_conn),
            "with no confinement, every stream may be served"
        );

        // On the lan-share path with NO recorded LAN connection for the peer: REFUSED (fail-closed).
        let map: LanServeConns = Arc::new(Mutex::new(HashMap::new()));
        assert!(
            !lan_serve_permitted(&Some(map.clone()), &peer, lan_conn),
            "a confined node must REFUSE a stream on a connection with no LAN provenance"
        );

        // After recording a LAN-provenance connection (as the ConnectionEstablished handler does):
        // a stream on THAT connection is PERMITTED.
        map.lock()
            .unwrap()
            .entry(peer)
            .or_default()
            .insert(lan_conn);
        assert!(
            lan_serve_permitted(&Some(map.clone()), &peer, lan_conn),
            "a confined node must PERMIT a stream on the recorded LAN-provenance connection"
        );

        // After the connection retires (ConnectionClosed prunes the empty bucket): REFUSED again.
        {
            let mut m = map.lock().unwrap();
            let conns = m.get_mut(&peer).unwrap();
            conns.remove(&lan_conn);
            if conns.is_empty() {
                m.remove(&peer);
            }
        }
        assert!(
            !lan_serve_permitted(&Some(map), &peer, lan_conn),
            "once the peer's last LAN connection closes it is no longer serve-eligible"
        );
    }

    #[test]
    fn identify_gate_rejects_cross_scope_protocol_version_under_confinement() {
        // codex HIGH #4: identify negotiates the FIXED /ipfs/id/1.0.0 name, so a v1 (or any
        // other-scope) peer completes identify with a lan-share node; the scope lives only in the
        // protocol_version metadata. Under confinement we admit its addresses ONLY on an exact match.
        // MUTATION: change `advertised == expected` to `true` (or drop the confined check) and the
        // cross-scope-reject assertion flips to admit.
        let expected = "/nix-p2p/lan-share.v1/id/1.0.0";
        // Off the lan-share path: any protocol_version is admitted (public participation).
        assert!(identify_protocol_version_admitted(
            false,
            "/nix-p2p/v1/id/1.0.0",
            expected
        ));
        // Confined + exact match: admitted.
        assert!(identify_protocol_version_admitted(true, expected, expected));
        // Confined + cross-scope (public v1): REJECTED.
        assert!(!identify_protocol_version_admitted(
            true,
            "/nix-p2p/v1/id/1.0.0",
            expected
        ));
        // Confined + an empty/garbage protocol_version: REJECTED.
        assert!(!identify_protocol_version_admitted(true, "", expected));
    }

    #[test]
    fn identify_config_disables_address_cache_under_confinement() {
        // codex TASK-282 (a): the `.with_cache_size(0)` confinement mitigation (the identify INTERNAL
        // address cache leg — separate from the receive-gate) had NO test, so reverting the real
        // construction stayed green. This drives the PRODUCTION `build_identify_config` (the swarm
        // builder calls exactly this) and inspects the REAL config via `identify::Config::cache_size()`.
        // MUTATION: delete `if lan_confinement { 0 }` in `identify_cache_size` (or drop the
        // `.with_cache_size(...)` in `build_identify_config`) -> the confined config keeps the library
        // default 100 -> the `== 0` assertion reddens. Restore -> GREEN.
        let public_key = libp2p::identity::Keypair::generate_ed25519().public();
        let id_protocol = "/nix-p2p/lan-share.v1/id/1.0.0".to_string();

        let confined = build_identify_config(id_protocol.clone(), public_key.clone(), true);
        assert_eq!(
            confined.cache_size(),
            0,
            "a LAN-confined node DISABLES the identify internal address cache (with_cache_size(0)) so a \
             cross-scope peer's advertised global address never becomes a NewExternalAddrOfPeer dial \
             candidate"
        );

        let unconfined = build_identify_config(id_protocol, public_key, false);
        assert_eq!(
            unconfined.cache_size(),
            IDENTIFY_DEFAULT_CACHE_SIZE,
            "off the confined path the library default cache is kept (public nodes rely on identify \
             address discovery); IDENTIFY_DEFAULT_CACHE_SIZE tracks libp2p-identify's own default"
        );
        // Non-vacuity: the two paths are actually DIFFERENT, so the mitigation is load-bearing.
        assert_ne!(
            identify_cache_size(true),
            identify_cache_size(false),
            "the confinement branch must change the cache size, else the mitigation is a no-op"
        );
    }

    #[test]
    fn lan_serve_gate_refuses_a_non_lan_connection_of_a_lan_peer() {
        // codex CRITICAL #2 (connection-confusion): a peer with ONE recorded LAN connection must
        // still be REFUSED a serve that arrives on a DIFFERENT (non-LAN) connection. This is
        // impossible to express under the old per-PEER gate — that is exactly why the gate keys on
        // the exact ConnectionId. MUTATION: change `conns.contains(&connection)` back to
        // `!conns.is_empty()` (per-peer) and the non-LAN-connection assertion flips to permit.
        let peer = PeerId::random();
        let lan_conn = ConnectionId::new_unchecked(11); // recorded as LAN provenance
        let non_lan_conn = ConnectionId::new_unchecked(12); // e.g. an outbound conn to a public addr

        let map: LanServeConns = Arc::new(Mutex::new(HashMap::new()));
        map.lock()
            .unwrap()
            .entry(peer)
            .or_default()
            .insert(lan_conn);

        // The LAN connection serves.
        assert!(
            lan_serve_permitted(&Some(map.clone()), &peer, lan_conn),
            "the recorded LAN connection is serve-eligible"
        );
        // The SAME peer's non-LAN connection is REFUSED, even though the peer HAS a LAN connection.
        assert!(
            !lan_serve_permitted(&Some(map), &peer, non_lan_conn),
            "a stream on a non-LAN connection of a LAN-connected peer must be REFUSED \
             (the bidirectional/connection-confusion serve leg)"
        );
    }

    #[tokio::test]
    async fn accept_loop_serves_only_lan_provenance_connections() {
        // codex TEST-QUALITY (#4): the predicate tests above call `lan_serve_permitted` in isolation,
        // so DELETING the accept-loop `if !lan_serve_permitted` guard stayed GREEN — the mutation
        // proof was decoration. This drives the ACTUAL production loop body (`accept_loop_core`, the
        // one `run_accept_loop` delegates to) with sentinel items and observes which reach the serve
        // sink. MUTATION: delete the `if !lan_serve_permitted { drop; continue }` guard in
        // `accept_loop_core` -> the non-LAN item is served too -> `served == [lan_conn, non_lan_conn]`
        // and the length assertion reddens. Restore -> GREEN.
        let peer = PeerId::random();
        let lan_conn = ConnectionId::new_unchecked(7);
        let non_lan_conn = ConnectionId::new_unchecked(8); // e.g. an outbound conn we opened to a public addr

        let map: LanServeConns = Arc::new(Mutex::new(HashMap::new()));
        map.lock()
            .unwrap()
            .entry(peer)
            .or_default()
            .insert(lan_conn);

        // Two accepted streams (T = &str sentinel, so no real libp2p Stream is needed): one on the
        // recorded LAN connection, one on a non-LAN connection of the SAME peer.
        let incoming = futures::stream::iter(vec![
            (peer, lan_conn, "lan"),
            (peer, non_lan_conn, "non-lan"),
        ]);
        let served = Arc::new(Mutex::new(Vec::new()));
        let sink = served.clone();
        accept_loop_core(incoming, Some(map), move |_peer, connection, tag| {
            sink.lock().unwrap().push((connection, tag));
        })
        .await;

        let served = served.lock().unwrap();
        assert_eq!(
            served.len(),
            1,
            "exactly the LAN-provenance stream is served; the non-LAN stream is dropped by the gate \
             (mutation: delete the accept-loop guard -> both are served -> this reddens)"
        );
        assert_eq!(
            served[0],
            (lan_conn, "lan"),
            "the served stream is the one on the recorded LAN-provenance connection"
        );
    }

    #[test]
    fn identify_gate_admits_only_lan_addresses_of_same_scope_under_confinement() {
        // codex TEST-QUALITY (#4): the identify predicate test above is string-equality only and
        // never exercises the per-address LAN filter or the production APPLY. This drives
        // `identify_admitted_addresses` — the COMPLETE gate the handler applies verbatim — so a
        // mutation of EITHER sub-gate reddens it: (a) make the protocol_version check always-admit
        // -> the cross-scope case returns the addresses; (b) drop the `multiaddr_lan_provenance`
        // filter -> the global address is admitted. Restore -> GREEN.
        let expected = "/nix-p2p/lan-share.v1/id/1.0.0";
        let lan: Multiaddr = "/ip4/192.168.1.5/tcp/4001".parse().unwrap();
        let global: Multiaddr = "/ip4/8.8.8.8/tcp/4001".parse().unwrap();
        let addrs = || vec![lan.clone(), global.clone()];

        // Off the lan-share path: every advertised address is admitted (public participation),
        // regardless of protocol_version.
        assert_eq!(
            identify_admitted_addresses(false, "/nix-p2p/v1/id/1.0.0", expected, addrs()),
            addrs(),
            "unconfined: all identify addresses are admitted"
        );

        // Confined + SAME scope: ONLY the LAN-provenance address is admitted; the global one is
        // filtered out (mutation: drop the LAN filter -> `global` appears -> reddens).
        assert_eq!(
            identify_admitted_addresses(true, expected, expected, addrs()),
            vec![lan.clone()],
            "confined same-scope: only the LAN-provenance address seeds routing"
        );

        // Confined + CROSS scope (public v1): EMPTY — not even the LAN-looking address is admitted,
        // because the whole record is rejected on protocol_version (mutation: always-admit the
        // protocol_version -> returns [lan] -> reddens).
        assert!(
            identify_admitted_addresses(true, "/nix-p2p/v1/id/1.0.0", expected, addrs()).is_empty(),
            "confined cross-scope: NO addresses admitted (record rejected on protocol_version)"
        );
    }

    // ===================== TASK-154 S4 query-cancel (work bound) =====================
    // A real `kad::QueryId` is obtained network-free: `get_providers` registers a query on a
    // bare `kad::Behaviour` synchronously and returns its id (no swarm/loopback needed). That
    // lets us prove the RAII guard and the worker's Cancel arm directly.

    fn bare_kad() -> kad::Behaviour<MemoryStore> {
        let peer = PeerId::random();
        kad::Behaviour::new(peer, MemoryStore::with_config(peer, content_store_config()))
    }

    #[test]
    fn cancel_on_drop_fires_when_armed_and_disarm_suppresses() {
        let mut kad = bare_kad();
        let armed_id = kad.get_providers(kad::RecordKey::new(&b"a".to_vec()));
        let disarmed_id = kad.get_providers(kad::RecordKey::new(&b"b".to_vec()));

        // The LOSSLESS dedicated cancel channel (TASK-154 B3): a dropped guard sends the
        // abandoned query's id here, unbounded so it is never dropped under backpressure.
        let (tx, mut rx) = mpsc::unbounded_channel::<kad::QueryId>();

        // ARMED: dropping the guard mid-wait (the abandoned find_providers deadline case)
        // sends a cancel for its query. Delete the Drop send and this receives nothing.
        {
            let _guard = CancelOnDrop::new(tx.clone(), armed_id);
        }
        match rx.try_recv() {
            Ok(id) => assert_eq!(id, armed_id, "cancel must carry the armed query's id"),
            Err(_) => panic!("armed drop must send a cancel, but nothing was sent"),
        }

        // DISARMED: a query that completed normally calls disarm(); dropping sends NOTHING,
        // so a healthy query is never cancelled. Remove `disarm()`'s effect and this bites.
        {
            let mut guard = CancelOnDrop::new(tx.clone(), disarmed_id);
            guard.disarm();
        }
        assert!(
            rx.try_recv().is_err(),
            "a disarmed (normally-completed) query must NOT be cancelled"
        );
    }

    #[test]
    fn cancel_on_drop_is_lossless_even_when_many_cancels_queue_up() {
        // TASK-154 B3: the OLD guard used `try_send` on the BOUNDED command channel, which
        // SILENTLY DROPPED a cancel whenever the channel was full (a cancel storm) - leaving
        // that query to run to its full timeout, the very case the work bound exists to stop.
        // The dedicated UNBOUNDED cancel channel never drops: queue far more cancels than any
        // bounded channel would hold and prove EVERY id arrives. Revert to a bounded try_send
        // and this loses cancels past the capacity.
        let mut kad = bare_kad();
        let (tx, mut rx) = mpsc::unbounded_channel::<kad::QueryId>();
        let mut expected = Vec::new();
        for i in 0..1000u32 {
            let id = kad.get_providers(kad::RecordKey::new(&i.to_be_bytes().to_vec()));
            expected.push(id);
            drop(CancelOnDrop::new(tx.clone(), id)); // armed drop -> lossless send
        }
        let mut got = Vec::new();
        while let Ok(id) = rx.try_recv() {
            got.push(id);
        }
        assert_eq!(
            got, expected,
            "every armed-drop cancel must be delivered in order - no cancel is ever dropped"
        );
    }

    #[test]
    fn cancel_arm_finishing_a_live_and_unknown_query_never_panics() {
        // The worker's Cancel arm does `query_mut(&id).finish()` then drops the pending entry.
        // Prove both halves are panic-free and idempotent - a late/duplicate Cancel for an
        // id that already terminated must never crash the single worker task.
        let mut kad = bare_kad();
        let live = kad.get_providers(kad::RecordKey::new(&b"live".to_vec()));

        // LIVE id: finish() terminates the walk at the next poll. Calling it TWICE (a
        // duplicate Cancel) must not panic - idempotent.
        if let Some(mut q) = kad.query_mut(&live) {
            q.finish();
        }
        if let Some(mut q) = kad.query_mut(&live) {
            q.finish();
        }

        // UNKNOWN id: a behaviour with an EMPTY query pool resolves NO id, so the cancel path
        // is a safe no-op (the already-terminated case). This is what makes `cancel_query`
        // fail-safe for a query that finished before its cancel arrived.
        let mut empty = bare_kad();
        assert!(
            empty.query_mut(&live).is_none(),
            "an unknown/terminated id must not resolve - cancel is a safe no-op"
        );
    }

    #[test]
    fn reply_is_closed_tracks_caller_abandonment_across_every_variant() {
        // The reap primitive (TASK-154 B3): reply_is_closed() is true IFF the caller dropped its
        // receiver, for EVERY Pending variant - so a future variant added without wiring here is
        // caught. A dropped rx => the caller is gone (reap); a held rx => a normally-waiting
        // caller (never reap).
        let dropped_simple = {
            let (tx, rx) = oneshot::channel::<Result<(), String>>();
            drop(rx);
            tx
        };
        assert!(Pending::Simple(dropped_simple).reply_is_closed());
        let (held_simple, _rx) = oneshot::channel::<Result<(), String>>();
        assert!(!Pending::Simple(held_simple).reply_is_closed());

        let dropped_boot = {
            let (tx, rx) = oneshot::channel::<Result<(), String>>();
            drop(rx);
            tx
        };
        assert!(Pending::Bootstrap(dropped_boot).reply_is_closed());

        let dropped_get_providers = {
            let (tx, rx) = oneshot::channel::<Result<ProviderFanOut, QueryFail>>();
            drop(rx);
            tx
        };
        assert!(
            Pending::GetProviders {
                found: BTreeSet::new(),
                max_peers: 16,
                salt: 0,
                truncated: false,
                started: std::time::Instant::now(),
                key: kad::RecordKey::new(&b"t".to_vec()),
                reply: dropped_get_providers,
            }
            .reply_is_closed()
        );
        let (held_get_providers, _rx2) = oneshot::channel::<Result<ProviderFanOut, QueryFail>>();
        assert!(
            !Pending::GetProviders {
                found: BTreeSet::new(),
                max_peers: 16,
                salt: 0,
                truncated: false,
                started: std::time::Instant::now(),
                key: kad::RecordKey::new(&b"t".to_vec()),
                reply: held_get_providers,
            }
            .reply_is_closed()
        );

        let dropped_get_record = {
            let (tx, rx) = oneshot::channel::<Result<Option<Vec<u8>>, QueryFail>>();
            drop(rx);
            tx
        };
        assert!(
            Pending::GetRecord {
                reply: dropped_get_record
            }
            .reply_is_closed()
        );

        let dropped_closest = {
            let (tx, rx) = oneshot::channel::<Result<(Vec<Multiaddr>, QueryReach), QueryFail>>();
            drop(rx);
            tx
        };
        assert!(
            Pending::GetClosestPeers {
                target: PeerId::random(),
                reply: dropped_closest,
            }
            .reply_is_closed()
        );
    }

    #[test]
    fn abandoned_query_in_the_buffered_id_window_is_selected_for_reaping_not_the_live_one() {
        // TASK-154 B3 - the residual codex flagged: after `id_reply.send(id)` SUCCEEDS the id can
        // sit BUFFERED while the caller is dropped BEFORE it polls `id_rx` and arms CancelOnDrop.
        // The worker then holds a Pending with NO cancel signal, and the id-arm race (send
        // failing) does NOT fire because the send succeeded. The close of the abandoned window is
        // the worker detecting the dropped RECEIVER on the reply channel and reaping. Prove the
        // SELECTION network-free: an abandoned Pending (receiver dropped) is chosen; a live one
        // (receiver held) is left running. Revert the reap and this returns an empty/at-most-live
        // set. Real QueryIds without a swarm via `bare_kad`.
        let mut kad = bare_kad();
        let abandoned_id = kad.get_providers(kad::RecordKey::new(&b"gone".to_vec()));
        let live_id = kad.get_providers(kad::RecordKey::new(&b"here".to_vec()));

        let mut pending: HashMap<kad::QueryId, Pending> = HashMap::new();

        // Abandoned: the caller dropped its receiver in the buffered-id window.
        let (abandoned_reply, abandoned_rx) =
            oneshot::channel::<Result<ProviderFanOut, QueryFail>>();
        drop(abandoned_rx);
        pending.insert(
            abandoned_id,
            Pending::GetProviders {
                found: BTreeSet::new(),
                max_peers: 16,
                salt: 0,
                truncated: false,
                started: std::time::Instant::now(),
                key: kad::RecordKey::new(&b"gone".to_vec()),
                reply: abandoned_reply,
            },
        );

        // Live: the caller still awaits (rx HELD open) - must NOT be reaped.
        let (live_reply, _live_rx) = oneshot::channel::<Result<ProviderFanOut, QueryFail>>();
        pending.insert(
            live_id,
            Pending::GetProviders {
                found: BTreeSet::new(),
                max_peers: 16,
                salt: 0,
                truncated: false,
                started: std::time::Instant::now(),
                key: kad::RecordKey::new(&b"here".to_vec()),
                reply: live_reply,
            },
        );

        let reap = abandoned_query_ids(&pending);
        assert_eq!(
            reap,
            vec![abandoned_id],
            "only the abandoned (caller-dropped) query is reaped; a live waiting caller's query \
             is left running untouched"
        );

        // The reap ACTION (cancel_query) on the selected id is idempotent + panic-free even for a
        // query that already terminated - proven separately by
        // `cancel_arm_finishing_a_live_and_unknown_query_never_panics`.
    }

    // ============ TASK-154 B1: bounded, deterministic provider fan-out aggregation ============
    // `retain_bounded_provider` is the pure fold the worker applies to EVERY advertised
    // provider as `FoundProviders` events stream in. Testing it directly proves the memory
    // bound and the deterministic selection WITHOUT a live swarm.

    #[test]
    fn retain_bounded_provider_holds_at_most_max_peers_regardless_of_flood() {
        // A sybil flood advertises N >> max_peers providers. The retained set MUST never exceed
        // max_peers AT ANY POINT (the O(max_peers) memory bound) - the anti-amplification bite:
        // the OLD code accumulated all N into a HashSet then sorted+truncated (O(N) memory /
        // O(N log N) work in the forged count). Delete the trim and `len` blows past max_peers.
        let max_peers = 16usize;
        let salt: FanOutSalt = 0x1234_5678_9abc_def0;
        let mut found = BTreeSet::new();
        let mut truncated = false;
        for _ in 0..10_000 {
            retain_bounded_provider(
                &mut found,
                max_peers,
                salt,
                &mut truncated,
                PeerId::random(),
            );
            assert!(
                found.len() <= max_peers,
                "retained set must never exceed max_peers - the bounded-memory invariant"
            );
        }
        assert_eq!(
            found.len(),
            max_peers,
            "a flood fills the set to exactly the bound"
        );
        assert!(
            truncated,
            "discarding any provider past the bound sets truncated"
        );
    }

    #[test]
    fn retain_bounded_provider_keeps_the_max_peers_smallest_by_rank_order_independently() {
        // TASK-214: WITHIN a single query (a fixed salt) the retained subset MUST be exactly the
        // max_peers smallest by RANK under that salt, and independent of `FoundProviders` arrival
        // order (the same order-independence the old PeerId order had, now under the rank order).
        // Fold the SAME ids forward and reverse; both must converge on the identical set, equal to
        // the max_peers smallest by `provider_rank(salt, .)`. (That the subset VARIES with the
        // salt - the non-grindability - is the separate `..._varies_with_salt` bite below.)
        let ids: Vec<PeerId> = (0..64).map(|_| PeerId::random()).collect();
        let max_peers = 10usize;
        let salt: FanOutSalt = 0xdead_beef_0000_0001;

        let fold = |order: &[PeerId]| -> BTreeSet<(u64, PeerId)> {
            let mut found = BTreeSet::new();
            let mut truncated = false;
            for &p in order {
                retain_bounded_provider(&mut found, max_peers, salt, &mut truncated, p);
            }
            found
        };
        let forward = fold(&ids);
        let mut rev = ids.clone();
        rev.reverse();
        let backward = fold(&rev);
        assert_eq!(forward, backward, "selection must be order-independent");

        let mut by_rank: Vec<(u64, PeerId)> =
            ids.iter().map(|p| (provider_rank(salt, p), *p)).collect();
        by_rank.sort_unstable();
        let expected: BTreeSet<(u64, PeerId)> = by_rank.into_iter().take(max_peers).collect();
        assert_eq!(
            forward, expected,
            "the retained set must be the max_peers smallest by rank under this salt"
        );
    }

    #[test]
    fn retain_bounded_provider_max_peers_zero_retains_none_but_marks_truncated() {
        // The degenerate budget: a caller that budgeted zero peers retains NO provider, yet a
        // non-empty index must still mark the result truncated so the directory does NOT read
        // an empty fan-out as an authoritative Miss (TASK-154 B2).
        let mut found = BTreeSet::new();
        let mut truncated = false;
        retain_bounded_provider(&mut found, 0, 42, &mut truncated, PeerId::random());
        assert!(found.is_empty(), "max_peers=0 retains no provider");
        assert!(
            truncated,
            "but discarding the named provider marks truncated"
        );
    }

    #[test]
    fn retain_bounded_provider_duplicate_is_not_a_discard() {
        // Re-advertising an already-retained provider (kad can report a provider more than once
        // across steps) leaves the set unchanged and does NOT falsely set truncated.
        let mut found = BTreeSet::new();
        let mut truncated = false;
        let p = PeerId::random();
        retain_bounded_provider(&mut found, 4, 7, &mut truncated, p);
        retain_bounded_provider(&mut found, 4, 7, &mut truncated, p);
        assert_eq!(found.len(), 1, "a duplicate does not grow the set");
        assert!(!truncated, "a duplicate is not a discard");
    }

    // ================= TASK-214: non-grindable, self-healing fan-out selection =================
    // The old rule kept the max_peers smallest-by-PeerId - a FIXED, grindable subset: an attacker
    // grinds PeerIds below a victim's, PERMANENTLY owns the retained slots for a CHOSEN key, and a
    // deterministic retry re-chases the identical dead subset (never self-heals). These bites
    // prove the rank-under-fresh-salt selection (a) VARIES the retained subset across salts
    // (non-grindable) and (b) SELF-HEALS: a victim out-competed on one query IS selected within a
    // bounded number of independent-salt retries. Both are MUTATION-PROVEN: pin the salt to a
    // constant (revert to a deterministic subset) and each reddens.

    /// The retained subset a query with `salt` would keep from `providers`, as the pure fold the
    /// worker runs. Mirrors the worker's `retain_bounded_provider` loop exactly.
    fn retained_under_salt(
        providers: &[PeerId],
        max_peers: usize,
        salt: FanOutSalt,
    ) -> BTreeSet<PeerId> {
        let mut found = BTreeSet::new();
        let mut truncated = false;
        for &p in providers {
            retain_bounded_provider(&mut found, max_peers, salt, &mut truncated, p);
        }
        found.into_iter().map(|(_rank, peer)| peer).collect()
    }

    #[test]
    fn fan_out_selection_varies_with_salt_not_grindable_to_a_fixed_subset() {
        // AC#1: the retained subset is NOT a fixed function of the PeerIds - it changes with the
        // per-query salt, so no grind of PeerIds owns the slots across queries. Over many salts
        // the same provider set must yield MORE THAN ONE distinct retained subset (a determinism
        // that pinned the subset would yield exactly one). MUTATION: make `provider_rank` ignore
        // the salt (e.g. `let mut h = FNV_OFFSET;`) and every salt yields the SAME subset ->
        // `distinct == 1` -> this reddens.
        let providers: Vec<PeerId> = (0..40).map(|_| PeerId::random()).collect();
        let max_peers = 16usize;
        let distinct: BTreeSet<Vec<PeerId>> = (0u64..64)
            .map(|salt| {
                retained_under_salt(&providers, max_peers, salt)
                    .into_iter()
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            distinct.len() > 1,
            "the retained subset must VARY across salts (non-grindable); got a single fixed \
             subset across 64 salts - the selection is salt-independent (grindable)"
        );
    }

    #[test]
    fn out_competed_victim_self_heals_within_bounded_retries_but_never_under_a_pinned_salt() {
        // AC#2, the biting self-heal test. Model an attacker that mints S forged providers plus
        // ONE legit victim on a CHOSEN key. Under a PINNED salt (the old deterministic rule) the
        // victim is selected iff it makes the fixed smallest-max_peers cut - and if it does not,
        // NO retry ever selects it (perpetual Unavailable(truncated)); this is the RED the fix
        // must remove. Under fresh per-query salts the victim IS selected within a bounded number
        // of retries.
        //
        // The pinned salt is 0 ON PURPOSE. `provider_rank(0, .)` seeds the FNV with `FNV_OFFSET ^
        // 0 == FNV_OFFSET`, which is EXACTLY what the natural revert-mutation (drop the `^ salt`
        // seed, `let mut h = FNV_OFFSET`) makes EVERY salt compute. So under that mutation ALL of
        // the GREEN arm's independently-drawn salts collapse onto salt-0 behaviour, the victim is
        // out-competed under every one of them, `healed` is false, and this test REDDENS - the
        // required mutation-proof that the self-heal depends on the salt actually varying selection.
        let max_peers = 16usize;
        let sybils: Vec<PeerId> = (0..200).map(|_| PeerId::random()).collect();
        let pinned_salt: FanOutSalt = 0;

        // Find a legit victim that the PINNED salt does NOT retain (out-competed on query 0). With
        // 200 sybils vs a 16-slot cut this is the overwhelmingly likely case; loop to be certain.
        let victim = (0u64..10_000)
            .map(|_| PeerId::random())
            .find(|v| {
                let mut all = sybils.clone();
                all.push(*v);
                !retained_under_salt(&all, max_peers, pinned_salt).contains(v)
            })
            .expect("a victim out-competed under the pinned salt must exist against 200 sybils");

        let mut all = sybils.clone();
        all.push(victim);

        // RED arm: a deterministic (pinned-salt) retry re-chases the identical dead subset - the
        // victim is NEVER selected, no matter how many times we retry. This is the pre-fix vector.
        let pinned_ever = (0u64..256)
            .any(|_retry| retained_under_salt(&all, max_peers, pinned_salt).contains(&victim));
        assert!(
            !pinned_ever,
            "a pinned-salt (deterministic) selection must NEVER heal the out-competed victim - \
             if this trips, the test victim was not actually out-competed"
        );

        // GREEN arm: production draws a FRESH INDEPENDENT `rand::random()` salt for EVERY query,
        // and a retry is a new query - so this arm must model INDEPENDENT per-query salts, not a
        // deterministic `1,2,3..` sequence (which is neither independent nor a faithful model of
        // the per-query renewal, and would not license the (185/201)^R miss math). We draw the
        // salts from a FIXED-SEED `StdRng`: the draws are genuinely independent u64s (so the flake
        // bound below is real), yet the seed is fixed so the SALT sequence is reproducible run-to-
        // run. This is NOT literally zero-flake - the providers use `PeerId::random()` and the
        // self-heal is probabilistic - but the residual miss probability is the ~4e-19 bound below,
        // negligible for CI. Each drawn salt is fed through the SAME `retain_bounded_provider` fold
        // the worker runs (`retained_under_salt`), so this exercises the production selection path.
        //
        // Honest flake bound: with T = S+1 = 201 named providers and max_peers = 16, the modeled
        // (idealized-uniform) per-retry miss probability is 1 - 16/201 = 185/201 ~ 0.9204. Over
        // R = 512 INDEPENDENT retries the probability the victim is never healed is ~
        // (185/201)^512 ~ 4e-19 - an arbitrary seed essentially never fails, so the fixed seed
        // below is not a cherry-picked lucky one. (The rank hash is not a proven-uniform PRF, so
        // 4e-19 is a model estimate, not an exact guarantee; the assertion itself is exact.)
        use rand::{RngCore, SeedableRng};
        let retries = 512usize;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5A17_0214_C0FF_EE00);
        let healed = (0..retries).any(|_| {
            let salt: FanOutSalt = rng.next_u64();
            retained_under_salt(&all, max_peers, salt).contains(&victim)
        });
        assert!(
            healed,
            "fresh INDEPENDENT-salt retries must self-heal the out-competed victim within {retries} \
             retries; it was never selected - the per-query salt is not renewing the selection"
        );
    }

    /// AC#6 real-network oracle: two production `Node` swarms negotiate only `/nar/4`.
    /// The provider's second supervised dump writes exactly one raw leaf and then blocks
    /// before its later bytes and EOF. The consumer must receive that leaf from the
    /// bounded verifier while the release marker is still absent; waiting for EOF or the
    /// whole NAR would deadlock this test.
    #[tokio::test]
    async fn real_two_node_process_serve_exposes_first_authenticated_leaf_before_later_eof() {
        let body = (0..((64 * 1024) + 37))
            .map(|index| (index as u8).wrapping_mul(31))
            .collect::<Vec<_>>();
        let content = Blake3Digest::from_raw_nar(&body);
        let nonce = nar4_test_nonce();
        let body_path = nar4_test_path("body", &nonce);
        let counter = nar4_test_path("counter", &nonce);
        let pass2_ready = nar4_test_path("pass2-ready", &nonce);
        let pass2_release = nar4_test_path("pass2-release", &nonce);
        let _cleanup = Nar4TestFiles(vec![
            body_path.clone(),
            counter.clone(),
            pass2_ready.clone(),
            pass2_release.clone(),
        ]);
        std::fs::write(&body_path, &body).expect("write test NAR");

        let scope = format!("nar4-real-two-node-{nonce}");
        let provider = Node::start(
            NodeConfig::new([0xa1; 32])
                .with_network_scope(scope.clone())
                .with_relay_server(false),
        )
        .expect("start provider node");
        let consumer = Node::start(
            NodeConfig::new([0xb2; 32])
                .with_network_scope(scope)
                .with_relay_server(false),
        )
        .expect("start consumer node");
        provider
            .handle
            .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .await
            .expect("provider listens");
        let provider_addr = provider
            .handle
            .listen_addrs()
            .await
            .into_iter()
            .next()
            .expect("provider has a concrete listener")
            .with(libp2p::multiaddr::Protocol::P2p(provider.peer_id));

        let supervisor = TaskSupervisor::new();
        let supplier = Arc::new(nar::CatalogNarSupplier::new(
            ProcessProbe {
                content,
                body: body_path.clone(),
                counter: counter.clone(),
                pass2_ready: pass2_ready.clone(),
                pass2_release: pass2_release.clone(),
            },
            "unused-helper",
        ));
        let gate = Arc::new(ServeGate::new(
            peer_fabric::ServeBudget {
                max_nar_bytes_uncompressed_nar: 1 << 20,
                max_inflight_bytes_uncompressed_nar: 1 << 20,
                max_serve_duration: Duration::from_secs(10),
            },
            supplier,
            supervisor.handle(),
        ));
        provider.handle.install_serve(Arc::clone(&gate)).await;

        consumer
            .handle
            .dial(provider_addr)
            .await
            .expect("consumer connects to provider");
        let mut control = consumer.handle.control.clone();
        let mut stream = control
            .open_stream(provider.peer_id, consumer.handle.nar_protocol.clone())
            .await
            .expect("open the required /nar/4 stream");
        nar::write_request(&mut stream, &content, peer_fabric::ACCEPT_RAW)
            .await
            .expect("write v4 request");

        let mut header = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
            .await
            .expect("provider prepares the proof and sends the v4 header")
            .expect("read v4 header");
        assert_eq!(header[0], 1, "STATUS_NAR");
        assert_eq!(header[1], WireCodec::Raw.wire());
        assert_eq!(
            u64::from_le_bytes(header[2..].try_into().unwrap()),
            body.len() as u64
        );

        let (wire_sink, mut verified) =
            nar::verified_nar_stream(content, body.len() as u64, WireCodec::Raw).await;
        let pump = nar::pump_bao_wire(&mut stream, wire_sink, Duration::from_secs(5), &content);
        tokio::pin!(pump);
        let first_leaf = tokio::select! {
            leaf = verified.next_leaf() => leaf.expect("one authenticated full leaf"),
            result = &mut pump => panic!("wire ended before an early authenticated leaf: {result:?}"),
            () = tokio::time::sleep(Duration::from_secs(5)) => {
                panic!("first authenticated leaf waited for pass-2 EOF")
            }
        };
        assert_eq!(&first_leaf[..], &body[..64 * 1024]);
        assert!(
            pass2_ready.exists(),
            "provider reached the intentional pass-2 block"
        );
        assert!(
            !pass2_release.exists(),
            "the first authenticated leaf crossed before later stdout/EOF was released"
        );

        std::fs::write(&pass2_release, []).expect("release pass 2");
        let drain = async {
            let mut tail = Vec::new();
            while let Some(leaf) = verified.next_leaf().await {
                tail.extend_from_slice(&leaf);
            }
            tail
        };
        let (pump_result, tail) = tokio::join!(&mut pump, drain);
        pump_result.expect("COMPLETE and clean FIN");
        assert_eq!(verified.finish().await.unwrap(), body.len() as u64);
        let mut received = first_leaf.to_vec();
        received.extend_from_slice(&tail);
        assert_eq!(received, body);
        assert_eq!(
            std::fs::read_to_string(&counter).unwrap().trim(),
            "2",
            "exactly two process regenerations"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while supervisor.process_jobs().active_len() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both process groups are reaped");
        assert_eq!(gate.counters().admitted, 1);
    }
}
