//! [`Libp2pTransport`] - the libp2p [`NarTransfer`]: fetch a NAR from a provider peer by
//! STREAMING it over the shared swarm's `/nix-p2p/<scope>/nar/3` raw libp2p-stream protocol
//! (TASK-157), gate-1 BLAKE3-verify it, and honour the [`SafetyEnvelope`] (dial / body-idle /
//! total bounds) and the signed NarSize as a true mid-stream size abort.
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

use async_trait::async_trait;
use libp2p::Multiaddr;

use peer_fabric::{
    Blake3Digest, Lookup, NarTransfer, NodeLocator, RelayHints, ResolutionPolicy, SafetyEnvelope,
    TransferError, TransportOffer, TransportTag,
};

use crate::keys::peer_id_of_provider;
use crate::locator::Libp2pNodeLocator;
use crate::swarm::{FetchOutcome, SwarmHandle};

/// The libp2p [`NarTransfer`]. Holds a [`SwarmHandle`] to drive the shared swarm's NAR
/// request-response protocol, and the in-fabric [`Libp2pNodeLocator`] so the dial is
/// driven by an EXPLICIT DHT resolution (TASK-169), never by whatever addresses an
/// earlier, unrelated query happened to leave in the shared routing table.
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
        // TASK-156 freezes and authenticates the final relay-hint wire shape, while
        // TASK-219 owns deriving live hints and resolving them through kad. Writers in
        // this cycle emit none. A record from a newer coordinated writer may carry
        // validated hints; this reader still tries the provider's ordinary kad-resolved
        // addresses and falls back normally if unreachable. It never treats hint bytes
        // as addresses or silently truncates them.
        if !relay_hints.is_empty() {
            tracing::debug!(
                provider = %node,
                relay_hint_count = relay_hints.len(),
                "fabric-libp2p: signed relay hints present; TASK-156 reader uses the direct kad locator path"
            );
        }
        let peer = peer_id_of_provider(&node).ok_or_else(|| {
            TransferError::Unavailable(format!(
                "provider {node} is not a valid ed25519 peer id, cannot dial over libp2p"
            ))
        })?;

        // TASK-169: resolve WHERE the provider is dialable THROUGH the DHT (kad
        // peer-routing) and seed this resolution's address(es) into the swarm's kad routing
        // table EXPLICITLY before dialing. This is the root-cause fix for the rejected
        // side-effect design (the daemon calling locate() only for its routing-table side
        // effect and discarding the DialInfo): the resolve-then-dial now lives INSIDE the
        // fabric, where the `DialInfo` is allowed to be (the seam keeps it out of the
        // serving layer), and the address is fed to the dial EXPLICITLY rather than left to
        // whatever an earlier query incidentally populated. `add_address` of a DHT-RESOLVED
        // address is NOT injection - it came from the DHT, not the caller - and the shared
        // locator records the OurNodeId->DhtNode disclosure to the fabric ledger.
        //
        // HONEST LIMIT (carried to TASK-161): `add_address` feeds the SAME shared kad
        // routing table that prior queries also feed, and `fetch_nar` auto-dials off that
        // shared table - so on a small loopback DHT the request-response fetch can reuse a
        // connection an earlier discovery query already opened to the provider, and the
        // byte path cannot attribute the dial to THIS resolution. What is established here:
        // no address was injected out of band, resolution is CONSULTED before every dial,
        // and a failed resolution refuses the dial. A Miss (healthy, no address known), an
        // Unavailable (could-not-consult / empty routing), or a Found whose addresses are
        // all unparseable all map to a typed `Unavailable` so the fetch driver falls
        // through to the next offer/record (ultimately upstream) rather than silently
        // dialing on stale routing state.
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
            match self
                .locator
                .locate(&node, &ResolutionPolicy::PublicInfrastructure)
                .await
            {
                Lookup::Found(dial_info) => {
                    let mut added = 0usize;
                    for location in &dial_info.locations {
                        match location.parse::<Multiaddr>() {
                            Ok(addr) => {
                                self.handle.add_address(peer, addr).await;
                                added += 1;
                            }
                            Err(why) => {
                                // A DHT-reported location that does not parse as a Multiaddr is
                                // anomalous (the locator built each from a real Multiaddr's
                                // `to_string`); log and skip it rather than dial a malformed
                                // address.
                                tracing::warn!(
                                    %location, %why,
                                    "fabric-libp2p: skipping unparseable DHT-resolved dial address"
                                );
                            }
                        }
                    }
                    if added == 0 {
                        return Err(TransferError::Unavailable(format!(
                            "libp2p resolved provider {node} but none of its DHT-reported \
                             addresses parsed as a dialable Multiaddr"
                        )));
                    }
                    // Fail-verbose observability (TASK-218 finding 1): record WHICH addresses
                    // we resolved and are about to dial. A NAT'd provider's set includes a
                    // `/p2p-circuit` candidate, so this makes the circuit-dial ATTEMPT
                    // observable - the B2 relay-down oracle uses it to confirm the consumer
                    // still resolved the provider (and a circuit) before the fetch failed.
                    tracing::info!(
                        provider = %node,
                        addresses = %dial_info.locations.join(", "),
                        "fabric-libp2p: resolved provider dial address(es); dialing"
                    );
                }
                Lookup::Miss => {
                    return Err(TransferError::Unavailable(format!(
                        "libp2p node-locator knows no DHT dial address for provider {node} \
                         right now (kad peer-routing miss)"
                    )));
                }
                Lookup::Unavailable(why) => {
                    return Err(TransferError::Unavailable(format!(
                        "libp2p node-locator could not resolve provider {node}: {why}"
                    )));
                }
            }

            // STREAM the NAR over a raw libp2p substream (TASK-157). The envelope's fine-grained
            // bounds are enforced INSIDE `fetch_nar_streaming`: `dial_timeout` on opening the
            // stream, `body_idle_timeout` as a real inter-chunk stall guard, and the running
            // mid-stream SIZE abort at exactly `expected_size` (the signed uncompressed NarSize,
            // NEVER the compressed FileSize) plus the gate-1 BLAKE3 verify - so a lying provider
            // is cut off at ~expected_size mid-transfer, and a corrupt one fails gate-1, never
            // wrong bytes handed upward (Nix's sha256 gate remains the trust anchor downstream).
            // ATTRIBUTED fetch (TASK-218 finding 1): only a failure BEFORE the substream opened
            // (a dial / circuit-establishment failure) is "unreachable". A reachable provider
            // that opens the stream and then replies NotHeld/Declined/TooLarge/etc. must NOT be
            // logged UNREACHABLE - otherwise the B2 relay-down oracle would pass even though the
            // relay WORKED. The `offer_zstd = true` matches the shipped `fetch_nar_streaming`.
            match self
                .handle
                .fetch_nar_streaming_attributed(
                    peer,
                    content,
                    expected_size,
                    dial_timeout,
                    body_idle_timeout,
                    true,
                )
                .await
            {
                FetchOutcome::Ok(fetch) => Ok(fetch.bytes),
                FetchOutcome::NotOpened(err) => {
                    // The provider was DISCOVERED and RESOLVED (a Found above, addresses dialed)
                    // but the NAR substream NEVER OPENED at any resolved dial address - a genuine
                    // dial / relay-circuit REACHABILITY failure. This DISTINCT marker is what the
                    // B2 relay-down oracle greps to attribute the failure to the severed relay
                    // circuit (with the direct path B1-blocked), never to a discovery miss.
                    tracing::warn!(
                        provider = %node, %peer, error = %err,
                        "fabric-libp2p: NAR fetch UNREACHABLE - the NAR substream never opened \
                         (dial / relay-circuit establishment failed) at any resolved dial address"
                    );
                    Err(err)
                }
                FetchOutcome::OpenedThenFailed(err) => {
                    // The provider WAS REACHED (the substream opened and the /nar/3 protocol
                    // negotiated) but the transfer then failed. The relay/dial WORKED, so this is
                    // NOT logged UNREACHABLE - the info line keeps it diagnosable.
                    tracing::info!(
                        provider = %node, %peer, error = %err,
                        "fabric-libp2p: NAR fetch reached the provider (substream opened) but the \
                         transfer failed - NOT an unreachability"
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
