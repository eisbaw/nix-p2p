//! The daemon-side `Transport` bridge over the iroh `NarTransfer` seam impl.
//!
//! [`fabric_iroh::transport_iroh::IrohTransport`] IS a native [`peer_fabric::NarTransfer`].
//! The daemon's fetch path drives its OWN [`Transport`] trait (this crate's `transport_fetch`
//! module: `TransportRegistry`, `fetch_via_offers`, `TransportNarSource`), keyed on the
//! claim-wire [`KnownTransport`] offer. This module is the thin adapter that lets the daemon
//! register the iroh transport into that path unchanged.
//!
//! ## Why the bridge lives HERE (orphan rule)
//!
//! It implements the daemon-local [`Transport`] trait (in this crate's `transport_fetch`) for
//! the foreign [`IrohTransport`] - permitted because the TRAIT is local. Post the daemon-core
//! split (TASK-146) the serving-core types it names ([`KnownTransport`], [`Blake3Digest`]) live
//! in `daemon-core`, but `Transport`/`TransportError` stay in this composite crate with the
//! iroh fetch path, so the direct impl remains valid. The bridge holds NO transfer logic - it
//! converts the wire offer to a seam [`TransportOffer`](peer_fabric::TransportOffer), hands the
//! transport's configured envelope through [`IrohTransport::seam_envelope`], delegates to the
//! native [`NarTransfer::fetch`], and maps the seam [`TransferError`] back to the daemon
//! [`TransportError`] (the two enums are variant-for-variant identical).
//!
//! Retiring this bridge entirely - moving the daemon fetch path onto a PeerFabric
//! `IrohNarSource`, as `daemon_core::PeerFabricNarSource` already does for libp2p - is TASK-144.

use async_trait::async_trait;
use fabric_iroh::transport_iroh::IrohTransport;
use peer_fabric::{NarTransfer, TransferError};

use crate::transport_fetch::{Transport, TransportError, TransportTag};
use daemon_core::claim::KnownTransport;
use daemon_core::content_id::Blake3Digest;

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
        // The daemon `Transport` carries no per-call envelope; use the transport's configured
        // one, handed across the seam as `peer_fabric::SafetyEnvelope`. UFCS disambiguates the
        // seam `NarTransfer::fetch` from THIS `Transport::fetch` (both named `fetch` on the
        // same type).
        let seam_offer = offer.to_offer();
        let envelope = self.seam_envelope();
        NarTransfer::fetch(self, content, &seam_offer, expected_size, &envelope)
            .await
            .map_err(transfer_error_to_transport_error)
    }
}

/// Map the seam [`TransferError`] to the daemon [`TransportError`]. The two enums are
/// variant-for-variant identical (same names, fields and `Display`); this is the mechanical
/// bridge that lets the seam-native fetch core report through the daemon trait until the
/// daemon fetch path itself adopts `NarTransfer` (TASK-144).
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
