//! The daemon-side `Transport` bridge over the iroh `NarTransfer` seam impl.
//!
//! TASK-148 increment 2 moved `transport_iroh` BELOW the `peer_fabric` seam into the
//! `fabric-iroh` backend crate, where [`fabric_iroh::IrohTransport`] IS a native
//! [`peer_fabric::NarTransfer`]. But the daemon's existing fetch path still drives its
//! OWN [`Transport`] trait (`transport_fetch::{TransportRegistry, fetch_via_offers,
//! TransportNarSource}`), keyed on the claim-wire [`KnownTransport`] offer. This module
//! is the thin adapter that lets the daemon register the iroh transport into that path
//! unchanged.
//!
//! ## Why the bridge lives HERE, not in `fabric-iroh`
//!
//! It names daemon serving-core types the backend crate must NOT depend on
//! ([`Transport`]/[`TransportError`] from `transport_fetch`, [`KnownTransport`] from
//! `claim`); the crate edge is daemon -> fabric-iroh, never the reverse
//! (`check-independence.py`). Rust's orphan rule permits it: [`Transport`] is a LOCAL
//! (daemon) trait, so the daemon may implement it for the foreign
//! [`fabric_iroh::IrohTransport`]. The bridge holds NO transfer logic - it converts the
//! wire offer to a seam [`TransportOffer`](peer_fabric::TransportOffer), hands the
//! transport's configured envelope through [`IrohTransport::seam_envelope`], delegates
//! to the native [`NarTransfer::fetch`], and maps the seam [`TransferError`] back to the
//! daemon [`TransportError`] (the two enums are variant-for-variant identical).
//!
//! Retiring this bridge entirely - moving the daemon fetch path onto a PeerFabric
//! `IrohNarSource`, as `source_libp2p.rs` already does for libp2p - is TASK-144.

use async_trait::async_trait;
use fabric_iroh::transport_iroh::IrohTransport;
use peer_fabric::{NarTransfer, TransferError};

use crate::claim::KnownTransport;
use crate::content_id::Blake3Digest;
use crate::transport_fetch::{Transport, TransportError, TransportTag};

#[async_trait]
impl Transport for IrohTransport {
    fn tag(&self) -> TransportTag {
        TransportTag::Iroh
    }

    async fn fetch(
        &self,
        content: &Blake3Digest,
        offer: &KnownTransport,
        expected_size: Option<u64>,
    ) -> Result<Vec<u8>, TransportError> {
        // The daemon `Transport` carries no per-call envelope; use the transport's
        // configured one, handed across the seam as `peer_fabric::SafetyEnvelope`. UFCS
        // disambiguates the seam `NarTransfer::fetch` from THIS `Transport::fetch` (both
        // are named `fetch` on the same type).
        let seam_offer = offer.to_offer();
        let envelope = self.seam_envelope();
        NarTransfer::fetch(self, content, &seam_offer, expected_size, &envelope)
            .await
            .map_err(transfer_error_to_transport_error)
    }
}

/// Map the seam [`TransferError`] to the daemon [`TransportError`]. The two enums are
/// variant-for-variant identical (same names, fields and `Display`); this is the
/// mechanical bridge that lets the seam-native fetch core report through the daemon
/// trait until the daemon fetch path itself adopts `NarTransfer` (TASK-144).
fn transfer_error_to_transport_error(error: TransferError) -> TransportError {
    match error {
        TransferError::NotHeld(id) => TransportError::NotHeld(id),
        TransferError::IntegrityMismatch { expected, actual } => {
            TransportError::IntegrityMismatch { expected, actual }
        }
        TransferError::WrongOffer { expected, got } => TransportError::WrongOffer { expected, got },
        TransferError::Unavailable(why) => TransportError::Unavailable(why),
        TransferError::TooLarge { limit, streamed } => TransportError::TooLarge { limit, streamed },
    }
}
