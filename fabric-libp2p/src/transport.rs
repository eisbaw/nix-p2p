//! [`Libp2pTransport`] - the libp2p [`NarTransfer`]: fetch a NAR from a provider peer
//! over the shared swarm's `/nix-p2p/<scope>/nar/1` request-response protocol, gate-1
//! BLAKE3-verify it, and honour the [`SafetyEnvelope`] and the signed NarSize bound.
//!
//! # ADR (TASK-151): why this services the `Iroh` tag (offer-driven dispatch)
//!
//! Two facts force `tag() == TransportTag::Iroh` this cycle:
//!
//!   1. A [`ProviderRecord`](peer_fabric::ProviderRecord) can only carry the FROZEN
//!      offer variants, and the only reachability offer is self-serve
//!      [`TransportOffer::Iroh`]`{ node: NodeId }` - the provider's ed25519 identity
//!      (TASK-103/126). `NodeId` is transport-blind, and a libp2p `PeerId` derives from
//!      that SAME ed25519 key ([`crate::keys::peer_id_of_provider`]), so a libp2p daemon
//!      MUST consume that offer to fetch anything discovered through existing records.
//!   2. Dispatch is OFFER-DRIVEN: the fetch driver computes `offer.tag()`
//!      (= `TransportTag::of(offer)`) and looks up the registry by it. For an `Iroh`
//!      offer that is always `TransportTag::Iroh`. So a transport that wants to be
//!      dispatched for the existing offer has NO CHOICE but to register under `Iroh` -
//!      this is mechanical, not a claim that the tag "means a NodeId locator".
//!
//! In a SINGLE-STACK libp2p build there is exactly one transport per tag, so no
//! collision arises. The tag string still literally reads `"iroh"` (the frozen type's
//! own SSOT), which is a known cosmetic wart in a libp2p-only process; it is not
//! reinterpreted here.
//!
//! DUAL-STACK LIMITATION (the transport tournament, both transfers in one process):
//! because dispatch is offer-driven, a bare `TransportTag::Libp2p` would NEVER be
//! selected for an `Iroh` offer - the tournament genuinely needs a distinct
//! `TransportOffer::Libp2p` on the FROZEN wire (additive `OFFER_LIBP2P` in the record
//! codec), and until then registering both transfers would SILENTLY clobber one under
//! the shared `Iroh` tag ([`peer_fabric::TransferRegistry::register`] overwrites).
//! Filed as TASK-156 (frozen-seam change with wire review); NOT attempted here.

use async_trait::async_trait;

use peer_fabric::{
    Blake3Digest, NarTransfer, SafetyEnvelope, TransferError, TransportOffer, TransportTag,
};

use crate::keys::peer_id_of_provider;
use crate::nar::NarResponse;
use crate::swarm::SwarmHandle;

/// The libp2p [`NarTransfer`]. Holds a [`SwarmHandle`] to drive the shared swarm's NAR
/// request-response protocol.
pub struct Libp2pTransport {
    handle: SwarmHandle,
}

impl Libp2pTransport {
    /// A transport driving `handle`.
    pub fn new(handle: SwarmHandle) -> Self {
        Libp2pTransport { handle }
    }
}

#[async_trait]
impl NarTransfer for Libp2pTransport {
    fn tag(&self) -> TransportTag {
        // Services the NodeId-locator offer; see the module ADR (TASK-156 tracks a
        // distinct Libp2p tag for the dual-stack tournament).
        TransportTag::Iroh
    }

    async fn fetch(
        &self,
        content: &Blake3Digest,
        offer: &TransportOffer,
        expected_size: Option<u64>,
        envelope: &SafetyEnvelope,
    ) -> Result<Vec<u8>, TransferError> {
        // The locator is the provider's ed25519 NodeId; derive its libp2p PeerId.
        let node = match offer {
            TransportOffer::Iroh { node } => *node,
            other => {
                return Err(TransferError::WrongOffer {
                    expected: TransportTag::Iroh,
                    got: other.tag(),
                });
            }
        };
        let peer = peer_id_of_provider(&node).ok_or_else(|| {
            TransferError::Unavailable(format!(
                "provider {node} is not a valid ed25519 peer id, cannot dial over libp2p"
            ))
        })?;

        // Time-bound the whole dial+transfer by the envelope's TOTAL bound. The per-call
        // dial/idle split is a follow-up (request-response carries a single
        // request_timeout; a raw-stream transport is needed for a true idle guard) -
        // TASK-157. total_timeout is the never-hang backstop that matters here.
        let fetch = self.handle.fetch_nar(peer, *content);
        let response = match tokio::time::timeout(envelope.total_timeout, fetch).await {
            Ok(Ok(response)) => response,
            Ok(Err(why)) => return Err(TransferError::Unavailable(why)),
            Err(_elapsed) => {
                return Err(TransferError::Unavailable(format!(
                    "libp2p fetch exceeded the total timeout {:?}",
                    envelope.total_timeout
                )));
            }
        };

        let bytes = match response {
            NarResponse::Nar(bytes) => bytes,
            NarResponse::NotHeld => return Err(TransferError::NotHeld(*content)),
            NarResponse::Declined(reason) => {
                return Err(TransferError::Unavailable(format!(
                    "provider declined to serve {content}: {reason}"
                )));
            }
        };

        // Size abort against the signed NarSize (uncompressed raw NAR, NEVER the
        // compressed FileSize). The codec already capped the wire read at
        // MAX_NAR_RESPONSE_BYTES so a lying length never allocated unbounded; here we
        // reject a response that overran the PER-CALL signed bound. A true mid-stream
        // abort at exactly `expected_size` is TASK-157.
        if let Some(limit) = expected_size
            && bytes.len() as u64 > limit
        {
            return Err(TransferError::TooLarge {
                limit,
                streamed: bytes.len() as u64,
            });
        }

        // Gate 1: BLAKE3-verify the bytes against the requested identity (SSOT recipe
        // peer_fabric::Blake3Digest::from_raw_nar). A corrupt or lying provider yields an
        // error here, never wrong bytes handed upward (Nix's sha256 gate remains the
        // trust anchor downstream).
        let actual = Blake3Digest::from_raw_nar(&bytes);
        if &actual != content {
            return Err(TransferError::IntegrityMismatch {
                expected: *content,
                actual,
            });
        }

        Ok(bytes)
    }
}
