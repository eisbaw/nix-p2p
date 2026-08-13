//! The libp2p [`Swarm`] worker: a single task owns the swarm (which is `!Sync` and
//! must be polled from one place), and the directory / announcer talk to it over
//! tokio channels - an mpsc of [`Command`]s in, a oneshot reply per command out. This
//! is the standard rust-libp2p driver shape; it keeps the async capability traits free
//! of the swarm's single-threaded ownership.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::kad::store::MemoryStore;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, identify, kad, noise, tcp, yamux};
use tokio::sync::{mpsc, oneshot};

use crate::keys::{keypair_from_seed, node_id_of};
use crate::nar::{NarCodec, NarRequest, NarResponse, Serve, ServeGate};
use peer_fabric::{Blake3Digest, Lookup, NodeId, Unavailable};

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

/// The combined behaviour: Kademlia (the DHT content discovery) plus Identify (so peers
/// learn each other's listen addresses and feed them into kad routing) plus the NAR
/// request-response protocol (TASK-151: the byte-transfer half, over the SAME swarm).
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct Behaviour {
    pub kad: kad::Behaviour<MemoryStore>,
    pub identify: identify::Behaviour,
    pub nar: request_response::Behaviour<NarCodec>,
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
    Dial {
        addr: Multiaddr,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Bootstrap {
        reply: oneshot::Sender<Result<(), String>>,
    },
    RoutingPeers {
        reply: oneshot::Sender<usize>,
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
        reply: oneshot::Sender<Result<(HashSet<PeerId>, QueryReach), QueryFail>>,
    },
    GetRecord {
        key: kad::RecordKey,
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
        reply: oneshot::Sender<Result<(Vec<Multiaddr>, QueryReach), QueryFail>>,
    },
    /// Fetch a NAR by digest from `peer` over the request-response protocol. The reply
    /// carries the peer's [`NarResponse`], or a transport-level failure string.
    FetchNar {
        peer: PeerId,
        content: Blake3Digest,
        reply: oneshot::Sender<Result<NarResponse, String>>,
    },
    /// Install (or replace) the serve gate: from now on inbound NAR requests are
    /// admitted and answered through it. Sent by [`crate::server::Libp2pServer::serve`].
    InstallServe {
        gate: Arc<ServeGate>,
    },
    /// Remove the serve gate IFF the worker still holds exactly `gate`. Sent best-effort
    /// by the serve teardown guard (the synchronous stop is the gate's own `active` flag;
    /// this just lets the worker drop its `Arc`). Carries the gate identity so a STALE
    /// teardown cannot clobber a live SUCCESSOR session that was installed before the old
    /// handle dropped (re-serve handoff).
    UninstallServe {
        gate: Arc<ServeGate>,
    },
}

/// A cloneable handle to the worker. Every capability holds one of these; a dropped
/// last handle ends the worker loop (the mpsc closes).
#[derive(Clone)]
pub struct SwarmHandle {
    tx: mpsc::Sender<Command>,
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

    /// Start listening on `addr`; resolves once a listen address is bound.
    pub async fn listen(&self, addr: Multiaddr) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Listen { addr, reply }).await;
        rx.await.unwrap_or_else(|_| Err("worker gone".into()))
    }

    /// The concrete addresses the node is listening on (for a peer to dial).
    pub async fn listen_addrs(&self) -> Vec<Multiaddr> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::ListenAddrs { reply }).await;
        rx.await.unwrap_or_default()
    }

    /// Teach kad how to reach `peer` at `addr` (a bootstrap/entry peer).
    pub async fn add_address(&self, peer: PeerId, addr: Multiaddr) {
        self.send(Command::AddAddress { peer, addr }).await;
    }

    /// Dial `addr` (used to establish the initial connection to a bootstrap peer).
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Dial { addr, reply }).await;
        rx.await.unwrap_or_else(|_| Err("worker gone".into()))
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
    pub async fn start_providing(&self, key: kad::RecordKey) -> Result<(), String> {
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
    pub async fn put_record(
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
    ) -> Result<(HashSet<PeerId>, QueryReach), QueryFail> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::GetProviders { key, reply }).await;
        rx.await
            .unwrap_or_else(|_| Err(QueryFail::Backend("worker gone".into())))
    }

    /// Fetch the value stored under `key` from the DHT, if any.
    pub async fn get_record(&self, key: kad::RecordKey) -> Result<Option<Vec<u8>>, QueryFail> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::GetRecord { key, reply }).await;
        rx.await
            .unwrap_or_else(|_| Err(QueryFail::Backend("worker gone".into())))
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
        self.send(Command::LocatePeer { peer, reply }).await;
        rx.await
            .unwrap_or_else(|_| Err(QueryFail::Backend("worker gone".into())))
    }

    /// Request `content` from `peer` over the NAR request-response protocol, resolving
    /// with the peer's [`NarResponse`] (or a transport-level failure string). The swarm
    /// auto-dials `peer` if an address for it is known (fed in via `add_address` /
    /// identify). Time-bounding and BLAKE3 verification are the transport's job.
    pub async fn fetch_nar(
        &self,
        peer: PeerId,
        content: Blake3Digest,
    ) -> Result<NarResponse, String> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::FetchNar {
            peer,
            content,
            reply,
        })
        .await;
        rx.await.unwrap_or_else(|_| Err("worker gone".into()))
    }

    /// Install (or replace) the serve gate on the worker; inbound NAR requests are then
    /// admitted and answered through it.
    pub async fn install_serve(&self, gate: Arc<ServeGate>) {
        self.send(Command::InstallServe { gate }).await;
    }

    /// Best-effort, non-blocking uninstall of the serve gate, callable from a `Drop`
    /// (which cannot await). The AUTHORITATIVE stop-admitting signal is the gate's own
    /// `active` flag (flipped synchronously by the teardown guard); this command only
    /// lets the worker drop its `Arc<ServeGate>`, so a full channel or a gone worker is
    /// harmless.
    pub fn uninstall_serve_nonblocking(&self, gate: Arc<ServeGate>) {
        if self.tx.try_send(Command::UninstallServe { gate }).is_err() {
            tracing::debug!("fabric-libp2p: serve uninstall not delivered (worker busy or gone)");
        }
    }
}

/// A query awaiting its terminal kad event.
enum Pending {
    Simple(oneshot::Sender<Result<(), String>>),
    Bootstrap(oneshot::Sender<Result<(), String>>),
    GetProviders {
        found: HashSet<PeerId>,
        reply: oneshot::Sender<Result<(HashSet<PeerId>, QueryReach), QueryFail>>,
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

/// The worker: owns the swarm, drives it, and matches kad query terminals back to the
/// oneshot the command carried.
struct Worker {
    swarm: Swarm<Behaviour>,
    commands: mpsc::Receiver<Command>,
    pending: HashMap<kad::QueryId, Pending>,
    /// Outbound NAR fetches awaiting their response, keyed by request-response id.
    nar_pending: HashMap<OutboundRequestId, oneshot::Sender<Result<NarResponse, String>>>,
    /// The installed serve gate, or `None` when this node is not serving (inbound NAR
    /// requests are then answered `NotHeld`). Set by `InstallServe`.
    serve: Option<Arc<ServeGate>>,
    /// Backchannel for OFF-loop NAR production (TASK-193): a spawned task produces a
    /// Process source's bytes then hands `(channel, response)` BACK here, so the poll loop
    /// (which alone owns `&mut Behaviour`) performs `send_response`. The worker keeps a
    /// `tx` clone, so `nar_response_rx` never closes while the worker runs.
    nar_response_tx: mpsc::Sender<(ResponseChannel<NarResponse>, NarResponse)>,
    nar_response_rx: mpsc::Receiver<(ResponseChannel<NarResponse>, NarResponse)>,
}

impl Worker {
    async fn run(mut self) {
        loop {
            tokio::select! {
                command = self.commands.recv() => match command {
                    Some(command) => self.on_command(command),
                    None => {
                        tracing::debug!("fabric-libp2p: all handles dropped, worker exiting");
                        break;
                    }
                },
                event = self.swarm.select_next_some() => self.on_event(event),
                // A finished OFF-loop NAR production (TASK-193): deliver it now, on the
                // poll loop, which alone owns `&mut Behaviour` for `send_response`. The
                // worker holds a `nar_response_tx` clone, so `recv` cannot yield `None`
                // while this loop runs; a `None` is ignored defensively.
                produced = self.nar_response_rx.recv() => {
                    if let Some((channel, response)) = produced {
                        self.deliver_nar_response(channel, response);
                    }
                },
            }
        }
    }

    fn on_command(&mut self, command: Command) {
        // `kad` is reborrowed per-arm (not bound once at the top) so the arms that drive
        // OTHER behaviours (the NAR request-response) or plain swarm ops do not conflict
        // with a long-lived `&mut kad` borrow of the swarm.
        match command {
            Command::Listen { addr, reply } => {
                let result = self
                    .swarm
                    .listen_on(addr)
                    .map(|_| ())
                    .map_err(|e| e.to_string());
                // If binding failed, answer now; if it succeeded, the concrete address
                // arrives via NewListenAddr - but listen_on returning Ok already means
                // the listener is registered, so answering here is correct and callers
                // read the concrete addr via listen_addrs() afterwards.
                let _ = reply.send(result);
            }
            Command::ListenAddrs { reply } => {
                // Derive from the swarm's own listener set rather than a parallel Vec:
                // it is always current (pruned on ListenerClosed/ExpiredListenAddr) and
                // is the single source of truth for what is bound.
                let _ = reply.send(self.swarm.listeners().cloned().collect());
            }
            Command::AddAddress { peer, addr } => {
                self.swarm.behaviour_mut().kad.add_address(&peer, addr);
            }
            Command::Dial { addr, reply } => {
                let result = self.swarm.dial(addr).map_err(|e| e.to_string());
                let _ = reply.send(result);
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
            Command::GetProviders { key, reply } => {
                let id = self.swarm.behaviour_mut().kad.get_providers(key);
                self.pending.insert(
                    id,
                    Pending::GetProviders {
                        found: HashSet::new(),
                        reply,
                    },
                );
            }
            Command::GetRecord { key, reply } => {
                let id = self.swarm.behaviour_mut().kad.get_record(key);
                self.pending.insert(id, Pending::GetRecord { reply });
            }
            Command::LocatePeer { peer, reply } => {
                // Iterative peer-routing to `peer`'s own key: the query walks the DHT and
                // the k-closest set it converges on carries the addresses a shared
                // bootstrap reported for `peer` (learned via identify). This is what lets
                // the resolver dial without an injected address.
                let id = self.swarm.behaviour_mut().kad.get_closest_peers(peer);
                self.pending.insert(
                    id,
                    Pending::GetClosestPeers {
                        target: peer,
                        reply,
                    },
                );
            }
            Command::FetchNar {
                peer,
                content,
                reply,
            } => {
                let id = self
                    .swarm
                    .behaviour_mut()
                    .nar
                    .send_request(&peer, NarRequest(content));
                self.nar_pending.insert(id, reply);
            }
            Command::InstallServe { gate } => {
                tracing::debug!("fabric-libp2p: NAR serve gate installed");
                self.serve = Some(gate);
            }
            Command::UninstallServe { gate } => {
                // Clear ONLY if the worker still holds exactly this gate: a stale
                // teardown from a superseded session must not drop a live successor
                // (which was installed before the old handle dropped). Identity is the
                // Arc, not a value compare.
                if self
                    .serve
                    .as_ref()
                    .is_some_and(|held| Arc::ptr_eq(held, &gate))
                {
                    tracing::debug!("fabric-libp2p: NAR serve gate uninstalled");
                    self.serve = None;
                } else {
                    tracing::debug!(
                        "fabric-libp2p: stale serve uninstall ignored (a successor session owns the slot)"
                    );
                }
            }
        }
    }

    fn on_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::debug!(%address, "fabric-libp2p: listening");
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                // Identify tells us a peer's real listen addresses; feed them into kad
                // routing so iterative lookups can reach it.
                let kad = &mut self.swarm.behaviour_mut().kad;
                for addr in info.listen_addrs {
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
            SwarmEvent::Behaviour(BehaviourEvent::Nar(event)) => self.on_nar_event(event),
            _ => {}
        }
    }

    /// Handle a NAR request-response event: serve an inbound request through the
    /// installed [`ServeGate`], or route an outbound response/failure back to the
    /// waiting `fetch_nar` caller.
    fn on_nar_event(&mut self, event: request_response::Event<NarRequest, NarResponse>) {
        use request_response::{Event, Message};
        match event {
            Event::Message {
                message:
                    Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                // Admit on the poll loop; the `&self.serve` borrow ends here, BEFORE any
                // `&mut swarm` use (the borrow-split invariant). A `Now` outcome answers
                // inline; a Process source is produced OFF the loop so a slow
                // `nix-store --dump` never stalls kad / identify / other requests (TASK-193).
                let admission = match &self.serve {
                    Some(gate) => gate.admit(&request.0),
                    None => Serve::Now(NarResponse::NotHeld),
                };
                match admission {
                    Serve::Now(response) => self.deliver_nar_response(channel, response),
                    Serve::OffLoop {
                        plan,
                        content,
                        declared,
                    } => {
                        // The spawned task holds OWNED clones (the gate's Arc - its atomics
                        // + supervisor handle - and the backchannel) and OWNS the
                        // ResponseChannel across the `.await`. It NEVER touches `&mut self`
                        // / the swarm; it hands the finished response back to the poll loop.
                        let gate = Arc::clone(
                            self.serve
                                .as_ref()
                                .expect("admit returned OffLoop, so a gate is installed"),
                        );
                        let tx = self.nar_response_tx.clone();
                        tokio::spawn(async move {
                            let response = tokio::select! {
                                biased;
                                // The inbound request went away (peer disconnect / the
                                // request-response inbound substream timed out): the channel
                                // closes. Dropping the produce future signals caller-
                                // abandonment, which SIGKILL-reaps the supervised process
                                // group. Nothing left to deliver on a dead channel.
                                () = wait_response_channel_closed(&channel) => return,
                                response = gate.produce_admitted(plan, content, declared) => {
                                    response
                                }
                            };
                            if tx.send((channel, response)).await.is_err() {
                                tracing::debug!(
                                    "fabric-libp2p: worker gone before off-loop NAR response delivered"
                                );
                            }
                        });
                    }
                }
            }
            Event::Message {
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(reply) = self.nar_pending.remove(&request_id) {
                    let _ = reply.send(Ok(response));
                }
            }
            Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(reply) = self.nar_pending.remove(&request_id) {
                    let _ = reply.send(Err(error.to_string()));
                }
            }
            Event::InboundFailure { error, .. } => {
                tracing::debug!(%error, "fabric-libp2p: NAR inbound request failed");
            }
            Event::ResponseSent { .. } => {}
        }
    }

    /// Send a NAR response on the poll loop, which alone owns `&mut Behaviour`. Used for
    /// both the inline answer and an OFF-loop production handed back over the backchannel
    /// (TASK-193). A closed channel (peer gone / timed out) is logged, not fatal.
    fn deliver_nar_response(
        &mut self,
        channel: ResponseChannel<NarResponse>,
        response: NarResponse,
    ) {
        if self
            .swarm
            .behaviour_mut()
            .nar
            .send_response(channel, response)
            .is_err()
        {
            tracing::debug!("fabric-libp2p: NAR response channel closed before send");
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
                if let Some(Pending::GetProviders { found, .. }) = self.pending.get_mut(&id)
                    && let Ok(GetProvidersOk::FoundProviders { providers, .. }) = &res
                {
                    found.extend(providers.iter().copied());
                }
                let failed = res.is_err();
                if (last || failed)
                    && let Some(Pending::GetProviders { found, reply }) = self.pending.remove(&id)
                {
                    // The terminal-step stats are cumulative for the whole query, so
                    // `num_successes` is how many peers answered the walk toward the key
                    // (TASK-174: the near-key bar for an EMPTY provider set).
                    let reach = QueryReach {
                        answered: stats.num_successes(),
                    };
                    let _ = reply.send(match res {
                        Ok(_) => Ok((found, reach)),
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

/// Await the closing of an inbound request's [`ResponseChannel`] (TASK-193): the peer went
/// away, or the request-response inbound substream timed out, so no response can be
/// delivered. Polls `is_open` on a coarse interval; the off-loop producer races this so a
/// dropped inbound request CANCELS (and thereby reaps) its supervised production instead of
/// running to completion for a consumer that is no longer waiting.
async fn wait_response_channel_closed(channel: &ResponseChannel<NarResponse>) {
    while channel.is_open() {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Configuration for one libp2p node.
pub struct NodeConfig {
    /// The 32-byte ed25519 secret that IS this node's identity and record-signing key.
    pub identity_seed: [u8; 32],
    /// The kad/identify protocol suffix scope (in-process tests isolate networks by
    /// using distinct scopes). The concrete protocol names are
    /// `/nix-p2p/<scope>/kad/1.0.0` and `/nix-p2p/<scope>/id/1.0.0`.
    pub network_scope: String,
}

impl NodeConfig {
    /// A config for `seed` on the default network scope.
    pub fn new(identity_seed: [u8; 32]) -> Self {
        NodeConfig {
            identity_seed,
            network_scope: "v1".to_string(),
        }
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

impl Node {
    /// Build the swarm for `config` and spawn its worker. The node is not yet
    /// listening or bootstrapped; the caller drives that via the [`SwarmHandle`].
    pub fn start(config: NodeConfig) -> Result<Node, NodeError> {
        let keypair = keypair_from_seed(&config.identity_seed);
        let node_id = node_id_of(&keypair);
        let peer_id = keypair.public().to_peer_id();
        let scope = config.network_scope;

        let kad_protocol = StreamProtocol::try_from_owned(format!("/nix-p2p/{scope}/kad/1.0.0"))
            .map_err(|e| NodeError::Build(format!("invalid kad protocol name: {e:?}")))?;
        let id_protocol = format!("/nix-p2p/{scope}/id/1.0.0");
        let nar_protocol = StreamProtocol::try_from_owned(format!("/nix-p2p/{scope}/nar/1"))
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
            .with_behaviour(
                |key| -> Result<Behaviour, Box<dyn std::error::Error + Send + Sync>> {
                    let peer_id = key.public().to_peer_id();
                    let store = MemoryStore::new(peer_id);
                    let mut kad_config = kad::Config::new(kad_protocol);
                    kad_config.set_query_timeout(Duration::from_secs(10));
                    let mut kad = kad::Behaviour::with_config(peer_id, store, kad_config);
                    // Server mode: this node STORES records and ANSWERS queries. Without
                    // it a node stays a client that never holds provider/value records,
                    // so the DHT could not answer - fatal for a decentralized directory.
                    kad.set_mode(Some(kad::Mode::Server));
                    let identify =
                        identify::Behaviour::new(identify::Config::new(id_protocol, key.public()));
                    // The NAR byte-transfer protocol shares this swarm (TASK-151). Both
                    // ends support it (Full): a node both fetches and serves.
                    let nar = request_response::Behaviour::with_codec(
                        NarCodec,
                        [(nar_protocol, request_response::ProtocolSupport::Full)],
                        request_response::Config::default(),
                    );
                    Ok(Behaviour { kad, identify, nar })
                },
            )
            .map_err(|e| NodeError::Build(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        let (tx, rx) = mpsc::channel(64);
        // The OFF-loop NAR production backchannel (TASK-193): spawned producers hand their
        // finished response back for the poll loop to `send_response`.
        let (nar_response_tx, nar_response_rx) = mpsc::channel(64);
        let worker = Worker {
            swarm,
            commands: rx,
            pending: HashMap::new(),
            nar_pending: HashMap::new(),
            serve: None,
            nar_response_tx,
            nar_response_rx,
        };
        let join = tokio::spawn(worker.run());

        Ok(Node {
            handle: SwarmHandle { tx },
            node_id,
            peer_id,
            _worker: abort::AbortOnDropHandle::new(join),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
