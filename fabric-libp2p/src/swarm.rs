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
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm, identify, kad, noise, tcp, yamux};
use tokio::sync::{mpsc, oneshot};

use crate::keys::{keypair_from_seed, node_id_of};
use crate::nar::{NarCodec, NarRequest, NarResponse, ServeGate};
use peer_fabric::{Blake3Digest, NodeId};

/// Why a kad query did not return a healthy answer. Mapped to
/// [`peer_fabric::Unavailable`] by the directory.
#[derive(Debug, Clone)]
pub enum QueryFail {
    /// The query timed out inside kad before completing.
    Timeout,
    /// A backend-specific failure, carried verbatim for the log.
    Backend(String),
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
        reply: oneshot::Sender<Result<HashSet<PeerId>, QueryFail>>,
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
        reply: oneshot::Sender<Result<Vec<Multiaddr>, QueryFail>>,
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
    /// This is the standard, reusable "join through all of them" the composition root and
    /// tests share; it composes the same [`add_address`](Self::add_address) +
    /// [`dial`](Self::dial) + [`bootstrap`](Self::bootstrap) + poll-`routing_peers` idiom
    /// the single-bootstrap join used, generalized to a set.
    ///
    /// Fail-fast, never a silent stall: an EMPTY set is a caller error (`Err`); a dial
    /// that fails to INITIATE is logged but not fatal on its own (another bootstrap may
    /// still admit us - the routing-table poll is the real readiness oracle); and if the
    /// routing table never reaches `min_peers` within `timeout` that is a real join
    /// failure returned as `Err` with context.
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
        // through a single entry node.
        for (peer, addr) in bootstraps {
            self.add_address(*peer, addr.clone()).await;
            if let Err(why) = self.dial(addr.clone()).await {
                tracing::warn!(
                    %peer, %addr, %why,
                    "fabric-libp2p: a bootstrap dial failed to initiate; continuing with the rest"
                );
            }
        }

        // One bootstrap self-lookup populates the routing table from whichever bootstraps
        // answered; tolerate its immediate result and rely on the poll below as readiness.
        let _ = self.bootstrap().await;

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

    /// Resolve the set of providers of `key` from the DHT.
    pub async fn get_providers(&self, key: kad::RecordKey) -> Result<HashSet<PeerId>, QueryFail> {
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
    /// path. `Ok(empty)` = the DHT knows no address (Miss); `Err` = could-not-consult.
    pub async fn locate_peer(&self, peer: PeerId) -> Result<Vec<Multiaddr>, QueryFail> {
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
        reply: oneshot::Sender<Result<HashSet<PeerId>, QueryFail>>,
    },
    GetRecord {
        reply: oneshot::Sender<Result<Option<Vec<u8>>, QueryFail>>,
    },
    /// A kad peer-routing lookup awaiting its terminal `GetClosestPeers` event. `target`
    /// is the PeerId we are resolving; on completion we return the addresses the query
    /// learned for exactly that peer.
    GetClosestPeers {
        target: PeerId,
        reply: oneshot::Sender<Result<Vec<Multiaddr>, QueryFail>>,
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
                step,
                ..
            })) => self.on_query(id, result, step.last),
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
                // Compute the response first (this drops the `&self.serve` borrow) so the
                // subsequent `&mut swarm` borrow to send it does not conflict.
                let response = match &self.serve {
                    Some(gate) => gate.respond(&request.0),
                    None => NarResponse::NotHeld,
                };
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

    fn on_query(&mut self, id: kad::QueryId, result: kad::QueryResult, last: bool) {
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
                    let _ = reply.send(match res {
                        Ok(_) => Ok(found),
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
                    let result = match res {
                        // The converged closest set: pull out the addresses the DHT learned
                        // for EXACTLY the target peer. If the target is absent from the set,
                        // or present with no address, that is a healthy "no address known"
                        // (empty Vec) - the locator maps it to Miss, never Unavailable.
                        Ok(GetClosestPeersOk { peers, .. }) => Ok(peers
                            .into_iter()
                            .find(|info| info.peer_id == target)
                            .map(|info| info.addrs)
                            .unwrap_or_default()),
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
        let worker = Worker {
            swarm,
            commands: rx,
            pending: HashMap::new(),
            nar_pending: HashMap::new(),
            serve: None,
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
