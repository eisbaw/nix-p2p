//! [`Libp2pTransport`] - the libp2p [`NarTransfer`]: fetch a NAR from a provider peer by
//! streaming it over the shared swarm's Bao-authenticated `/nix-p2p/<scope>/nar/4`
//! libp2p-stream protocol. It honours the [`SafetyEnvelope`] and signed NarSize header,
//! and exposes only leaves authenticated against the requested BLAKE3. TASK-62 inc3 adds the
//! true-streaming [`NarTransfer::fetch_stream`] override (leaves reach the HTTP body as they
//! authenticate); the legacy collecting [`NarTransfer::fetch`] `Vec` path remains for callers
//! not yet migrated off it.
//!
//! # ADR (TASK-156): native libp2p dispatch + rollout-only legacy reader
//!
//! [`Libp2pTransport`] is registered under its real [`TransportTag::Libp2p`] and
//! accepts only [`TransportOffer::Libp2p`]. This lets one registry hold real iroh and
//! libp2p backends simultaneously under distinct keys.
//!
//! Coordinated rollout still has to consume records written before tag 2 existed.
//! [`LegacyIrohTagLibp2pAdapter`] is the explicit, internal reader for those records:
//! it translates the old self-serve NodeId locator into a libp2p offer with no relay
//! hints, then calls the native transport. It does NOT implement iroh and is never
//! installed as a native backend. [`peer_fabric::TransferRegistry`] stores it in a
//! separate compatibility-fallback namespace where a future real iroh backend always
//! wins, independent of registration order. New records are never written through
//! this adapter.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use libp2p::PeerId;
use peer_fabric::{
    Blake3Digest, InflightMeter, Lookup, NarStream, NarTransfer, NodeId, RelayHints,
    SafetyEnvelope, TransferError, TransportOffer, TransportTag,
};

use crate::keys::peer_id_of_provider;
use crate::locator::Libp2pNodeLocator;
use crate::swarm::{
    AuthorizedConnection, FetchOutcome, NarFetchRequest, NarStreamOutcome, SwarmHandle,
};

/// The libp2p [`NarTransfer`]. Holds a [`SwarmHandle`] to drive the shared swarm's NAR
/// request-response protocol, and the in-fabric [`Libp2pNodeLocator`] so every dial is
/// driven by the current offer plus explicit DHT resolution, never by an unqualified
/// provider address an earlier query happened to leave in the shared routing table.
pub struct Libp2pTransport {
    handle: SwarmHandle,
    /// The SAME locator instance the fabric exposes on its `node_locator()` axis (a
    /// shared [`Arc`], so it appends to the fabric's ONE [`peer_fabric::ExposureLedger`]).
    /// Reusing it keeps the `DialInfo` inside the fabric (the seam keeps it out of the
    /// serving layer, `peer-fabric/src/capabilities.rs`) and keeps the OurNodeId->DhtNode
    /// exposure accounting in one place rather than re-threading the ledger here.
    locator: Arc<Libp2pNodeLocator>,
}

impl Libp2pTransport {
    /// A transport driving `handle`, resolving provider dial addresses through `locator`.
    pub fn new(handle: SwarmHandle, locator: Arc<Libp2pNodeLocator>) -> Self {
        Libp2pTransport { handle, locator }
    }

    /// Resolve WHERE `node` (libp2p `peer`) is dialable and establish ONE exact authorized
    /// connection, returning it plus the remaining stream-open budget. Shared by the collecting
    /// [`fetch`](NarTransfer::fetch) and the streaming [`fetch_stream`](NarTransfer::fetch_stream)
    /// so BOTH dial identically: one absolute `dial_timeout` covers route establishment AND the
    /// exact stream-open (spending it independently on each would silently double the caller's
    /// latency bound), and no caller injects the provider or relay address. A locator
    /// miss/unavailable or a failed connect is a pre-open `NotOpened`-class
    /// [`TransferError::Unavailable`] - the provider was UNREACHABLE at every resolved candidate.
    async fn establish_authorized_route(
        &self,
        node: NodeId,
        relay_hints: RelayHints,
        peer: PeerId,
        dial_timeout: Duration,
    ) -> Result<(AuthorizedConnection, Duration), TransferError> {
        match self.locator.locate_libp2p_offer(&node, relay_hints).await {
            Lookup::Found(plan) => {
                let addresses: Vec<String> = plan
                    .direct
                    .iter()
                    .chain(plan.circuits.iter())
                    .map(ToString::to_string)
                    .collect();
                tracing::info!(
                    provider = %node,
                    addresses = %addresses.join(", "),
                    direct_candidates = plan.direct.len(),
                    transient_circuit_candidates = plan.circuits.len(),
                    "fabric-libp2p: resolved provider dial address(es); establishing an exact authorized route"
                );

                // One absolute budget covers BOTH route establishment and exact stream-open.
                // Explicit DialOpts carry the candidate addresses and disable behaviour extension,
                // so neither direct nor circuit coordinates are persisted as ambient provider
                // routing state.
                let dial_deadline = tokio::time::Instant::now() + dial_timeout;
                let connect_budget =
                    dial_deadline.saturating_duration_since(tokio::time::Instant::now());
                let connected = if plan.circuits.is_empty() {
                    self.handle
                        .connect_direct(peer, plan.direct, connect_budget)
                        .await
                } else {
                    self.handle
                        .connect_transient(peer, plan.circuits, connect_budget)
                        .await
                };
                let connection = match connected {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::warn!(
                            provider = %node,
                            %peer,
                            error = %error,
                            addresses = %addresses.join(", "),
                            "fabric-libp2p: NAR fetch UNREACHABLE - no exact authorized route established, so the NAR substream was NotOpened"
                        );
                        return Err(TransferError::Unavailable(format!(
                            "libp2p NAR substream was NotOpened: exact authorized route to provider {node} failed at every resolved candidate: {error}"
                        )));
                    }
                };
                if let Some(relay) = connection.relay_peer() {
                    self.locator.record_selected_relay(peer, relay);
                }
                tracing::debug!(
                    provider = %node,
                    %peer,
                    connection = %connection.id,
                    route = ?connection.route,
                    "fabric-libp2p: selected exact authorized connection for NAR fetch"
                );

                let stream_budget =
                    dial_deadline.saturating_duration_since(tokio::time::Instant::now());
                Ok((connection, stream_budget))
            }
            Lookup::Miss => Err(TransferError::Unavailable(format!(
                "libp2p NAR substream was NotOpened: node-locator knows no DHT dial \
                 address for provider {node} right now (kad peer-routing miss)"
            ))),
            Lookup::Unavailable(why) => Err(TransferError::Unavailable(format!(
                "libp2p NAR substream was NotOpened: node-locator could not resolve \
                 provider {node}: {why}"
            ))),
        }
    }
}

#[async_trait]
impl NarTransfer for Libp2pTransport {
    fn tag(&self) -> TransportTag {
        TransportTag::Libp2p
    }

    async fn fetch(
        &self,
        content: &Blake3Digest,
        offer: &TransportOffer,
        expected_size: Option<u64>,
        envelope: &SafetyEnvelope,
    ) -> Result<Vec<u8>, TransferError> {
        // The locator is the provider's ed25519 NodeId; derive its libp2p PeerId.
        let (node, relay_hints) = match offer {
            TransportOffer::Libp2p { node, relay_hints } => (*node, *relay_hints),
            other => {
                return Err(TransferError::WrongOffer {
                    expected: TransportTag::Libp2p,
                    got: other.tag(),
                });
            }
        };
        let peer = peer_id_of_provider(&node).ok_or_else(|| {
            TransferError::Unavailable(format!(
                "provider {node} is not a valid ed25519 peer id, cannot dial over libp2p"
            ))
        })?;

        // Resolve WHERE the provider is dialable inside the fabric. The locator first queries the
        // provider through raw kad and retains only direct coordinates. A reachable direct route
        // wins and performs no relay-hint queries. Otherwise it reads the exact offer's bounded,
        // signature-bound RelayHints, resolves each relay address through raw kad, and constructs
        // transient circuit candidates; the provider-independent known-relay set is rollout-only
        // fallback for an actually empty legacy hint set. No caller injects the provider or relay
        // address.
        //
        // Neither direct nor circuit candidates enter kad: exact DialOpts carry them for this one
        // route establishment, and the resulting ConnectionId's observed route is checked against
        // current offer authority. This prevents an ambient unsigned circuit from satisfying the
        // request while preserving every unrelated connection for concurrent transfers.
        // Miss/Unavailable fail verbosely so the fetch driver can continue to another offer or
        // upstream.
        //
        // Resolution runs per FETCH (i.e. per offer), so a record with N libp2p offers
        // would record N OurNodeId disclosures for the same provider; libp2p is one offer
        // per record today, so this is once-per-provider in practice.
        //
        // TOTAL-TIMEOUT SCOPE (TASK-157, codex DEEP-gate finding): the envelope's total bound
        // wraps the WHOLE remote operation - DHT resolution AND the dial+stream - so a hanging
        // kad resolution is bounded too. Previously it wrapped only the transfer, so a stuck
        // `locate` escaped the envelope (bounded only by kad's own query timeout) and the whole
        // `NarTransfer::fetch` could run for that PLUS `total_timeout`. `dial_timeout` and
        // `body_idle_timeout` remain the finer-grained bounds enforced INSIDE the transfer.
        let content = *content;
        let total_timeout = envelope.total_timeout;
        let dial_timeout = envelope.dial_timeout;
        let body_idle_timeout = envelope.body_idle_timeout;
        let remote = async {
            // STREAM the NAR over the exact route authorized by `establish_authorized_route`.
            // The connection ID is passed unchanged into the vendored libp2p-stream control;
            // there is no peer-wide random selection, auto-dial, or fallback to an ambient
            // wrong-relay connection.
            let (connection, stream_budget) = self
                .establish_authorized_route(node, relay_hints, peer, dial_timeout)
                .await?;
            match self
                .handle
                .fetch_nar_streaming_attributed_on_connection(
                    peer,
                    connection.id,
                    NarFetchRequest::new(
                        content,
                        expected_size,
                        stream_budget,
                        body_idle_timeout,
                        true,
                    ),
                )
                .await
            {
                FetchOutcome::Ok(fetch) => Ok(fetch.bytes),
                FetchOutcome::NotOpened(err) => {
                    tracing::warn!(
                        provider = %node, %peer, error = %err,
                        connection = %connection.id,
                        route = ?connection.route,
                        "fabric-libp2p: NAR fetch UNREACHABLE - the exact authorized NAR substream never opened"
                    );
                    Err(err)
                }
                FetchOutcome::ProtocolIncompatible(err) => {
                    tracing::info!(
                        provider = %node, %peer, error = %err,
                        connection = %connection.id,
                        route = ?connection.route,
                        "fabric-libp2p: provider reached but required /nar/4 is unsupported; no /nar/3 downgrade"
                    );
                    Err(err)
                }
                FetchOutcome::OpenedThenFailed(err) => {
                    tracing::info!(
                        provider = %node, %peer, error = %err,
                        connection = %connection.id,
                        route = ?connection.route,
                        "fabric-libp2p: NAR fetch reached the provider on the exact authorized connection but the transfer failed - NOT an unreachability"
                    );
                    Err(err)
                }
            }
        };

        match tokio::time::timeout(total_timeout, remote).await {
            Ok(result) => result,
            Err(_elapsed) => Err(TransferError::Unavailable(format!(
                "libp2p fetch exceeded the total timeout {total_timeout:?}"
            ))),
        }
    }

    /// TASK-62 AC#6: the TRUE-STREAMING override. Dial identically to [`fetch`](Self::fetch),
    /// but instead of collecting the whole NAR into a `Vec`, hand the OWNED substream to the
    /// promoted [`nar::open_nar_response_stream`](crate::nar) reader and return a
    /// [`NarStream`] whose Bao-authenticated leaves are pulled by the HTTP body as they arrive.
    /// So `PeerFabricNarSource` commits the `200` and begins the body BEFORE the final peer
    /// leaf arrives (time-to-first-byte overlap; fetcher RSS decouples from NarSize).
    async fn fetch_stream(
        &self,
        content: &Blake3Digest,
        offer: &TransportOffer,
        expected_size: Option<u64>,
        envelope: &SafetyEnvelope,
    ) -> Result<NarStream, TransferError> {
        let (node, relay_hints) = match offer {
            TransportOffer::Libp2p { node, relay_hints } => (*node, *relay_hints),
            other => {
                return Err(TransferError::WrongOffer {
                    expected: TransportTag::Libp2p,
                    got: other.tag(),
                });
            }
        };
        let peer = peer_id_of_provider(&node).ok_or_else(|| {
            TransferError::Unavailable(format!(
                "provider {node} is not a valid ed25519 peer id, cannot dial over libp2p"
            ))
        })?;
        let content = *content;
        let total_timeout = envelope.total_timeout;
        let dial_timeout = envelope.dial_timeout;
        let body_idle_timeout = envelope.body_idle_timeout;
        // The in-flight meter for THIS transfer's fetch->HTTP handoff (AC#2/AC#7). The
        // depth-bounded channel inside `open_nar_response_stream` is what actually caps
        // resident bytes; the meter records the high-water mark for the backpressure oracle.
        let meter = Arc::new(InflightMeter::new());

        // The total timeout bounds ONLY the header phase (route establishment + response
        // header). Unlike the collecting `fetch`, the body is consumed lazily by the HTTP
        // client AFTER this returns, so it cannot live inside this timeout; `body_idle_timeout`
        // (inside the producer) plus the server's own request envelope bound the streamed body.
        let established = async {
            let (connection, stream_budget) = self
                .establish_authorized_route(node, relay_hints, peer, dial_timeout)
                .await?;
            match self
                .handle
                .open_nar_stream_attributed_on_connection(
                    peer,
                    connection.id,
                    NarFetchRequest::new(
                        content,
                        expected_size,
                        stream_budget,
                        body_idle_timeout,
                        true,
                    ),
                    Arc::clone(&meter),
                )
                .await
            {
                NarStreamOutcome::Ok(metered) => Ok(metered),
                NarStreamOutcome::NotOpened(err) => {
                    tracing::warn!(
                        provider = %node, %peer, error = %err,
                        "fabric-libp2p: NAR stream UNREACHABLE - the exact authorized NAR substream never opened"
                    );
                    Err(err)
                }
                NarStreamOutcome::ProtocolIncompatible(err) => {
                    tracing::info!(
                        provider = %node, %peer, error = %err,
                        "fabric-libp2p: provider reached but required /nar/4 is unsupported; no /nar/3 downgrade"
                    );
                    Err(err)
                }
                NarStreamOutcome::OpenedThenFailed(err) => {
                    tracing::info!(
                        provider = %node, %peer, error = %err,
                        "fabric-libp2p: NAR stream reached the provider but the header phase failed - NOT an unreachability"
                    );
                    Err(err)
                }
            }
        };
        let metered = match tokio::time::timeout(total_timeout, established).await {
            Ok(result) => result?,
            Err(_elapsed) => {
                return Err(TransferError::Unavailable(format!(
                    "libp2p fetch_stream header phase exceeded the total timeout {total_timeout:?}"
                )));
            }
        };
        let declared_size = metered.declared_size;
        Ok(NarStream::new(declared_size, Box::new(metered)))
    }
}

/// Rollout-only reader for pre-TASK-156 records whose libp2p provider was encoded
/// using the historical `Iroh { node }` offer. This adapter performs libp2p I/O;
/// its name and logs keep that fact explicit. It is registered only in the
/// compatibility-fallback namespace, never under the native backend map.
pub(crate) struct LegacyIrohTagLibp2pAdapter {
    native: Arc<Libp2pTransport>,
}

impl LegacyIrohTagLibp2pAdapter {
    pub(crate) fn new(native: Arc<Libp2pTransport>) -> Self {
        Self { native }
    }
}

#[async_trait]
impl NarTransfer for LegacyIrohTagLibp2pAdapter {
    fn tag(&self) -> TransportTag {
        // This is the legacy OFFER tag consumed by the adapter, not the transport it
        // runs. The real backend remains registered as TransportTag::Libp2p.
        TransportTag::Iroh
    }

    async fn fetch(
        &self,
        content: &Blake3Digest,
        offer: &TransportOffer,
        expected_size: Option<u64>,
        envelope: &SafetyEnvelope,
    ) -> Result<Vec<u8>, TransferError> {
        let node = match offer {
            TransportOffer::Iroh { node } => *node,
            other => {
                return Err(TransferError::WrongOffer {
                    expected: TransportTag::Iroh,
                    got: other.tag(),
                });
            }
        };
        tracing::debug!(
            provider = %node,
            "fabric-libp2p: reading legacy Iroh-tag provider record through the rollout-only libp2p adapter"
        );
        self.native
            .fetch(
                content,
                &TransportOffer::Libp2p {
                    node,
                    relay_hints: RelayHints::empty(),
                },
                expected_size,
                envelope,
            )
            .await
    }
}
