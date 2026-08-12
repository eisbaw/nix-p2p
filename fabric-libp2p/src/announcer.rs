//! [`Libp2pAvailabilityAnnouncer`] - publishes an already-signed
//! [`ProviderRecord`] into the DHT (the HYBRID: `start_providing` the index +
//! `put_record` the signed value). Eligibility and signing are decided ABOVE the seam;
//! the announcer only encodes the frozen record and publishes it under its budget.

use std::sync::Arc;

use async_trait::async_trait;
use libp2p::PeerId;
use peer_fabric::{
    AnnounceBudget, AnnounceError, AvailabilityAnnouncer, ContentKey, Disclosed, Exposure,
    ExposureLedger, ExposureSurface, NodeId, ProviderRecord, Receipt, Recipient,
    encode_provider_record,
};

use crate::keys::{provider_index_key, provider_value_key};
use crate::swarm::SwarmHandle;

/// The kad-backed [`AvailabilityAnnouncer`].
pub struct Libp2pAvailabilityAnnouncer {
    handle: SwarmHandle,
    ledger: Arc<ExposureLedger>,
    /// This node's identity - the announcer only publishes ITS OWN records (self-serve
    /// v1). The `peer_id` keys the value store; `node_id` is checked against the
    /// record's `provider`.
    node_id: NodeId,
    peer_id: PeerId,
}

impl Libp2pAvailabilityAnnouncer {
    /// An announcer driving `handle` for the node identified by `node_id`/`peer_id`.
    pub fn new(
        handle: SwarmHandle,
        ledger: Arc<ExposureLedger>,
        node_id: NodeId,
        peer_id: PeerId,
    ) -> Self {
        Libp2pAvailabilityAnnouncer {
            handle,
            ledger,
            node_id,
            peer_id,
        }
    }
}

#[async_trait]
impl AvailabilityAnnouncer for Libp2pAvailabilityAnnouncer {
    async fn announce(
        &self,
        record: &ProviderRecord,
        budget: &AnnounceBudget,
    ) -> Result<Receipt, AnnounceError> {
        // Self-serve v1: a node publishes only records it itself signed, or the
        // composite value key (derived from OUR peer id) would not match what a
        // resolver computes from the provider `get_providers` returns. Fail fast on a
        // caller that hands us someone else's record.
        if record.provider != self.node_id {
            return Err(AnnounceError::Rejected(format!(
                "record provider {} is not this node {} (self-serve v1)",
                record.provider, self.node_id
            )));
        }

        // Encode the FROZEN wire form (rejects an over-cap / non-canonical record on
        // the sender - fail fast before publishing).
        let value =
            encode_provider_record(record).map_err(|e| AnnounceError::Rejected(e.to_string()))?;

        self.ledger.record_all([
            Exposure::new(Recipient::DhtNode, Disclosed::ContentKey),
            Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId),
            Exposure::new(Recipient::DhtNode, Disclosed::OurAddress),
        ]);

        let key = record.key;
        let index_key = provider_index_key(&key);
        let value_key = provider_value_key(&key, &self.peer_id);

        let publish = async {
            // The multi-provider index (so a resolver's get_providers finds us).
            self.handle
                .start_providing(index_key)
                .await
                .map_err(AnnounceError::Unreachable)?;
            // The signed record in the value store (learnable offline).
            self.handle
                .put_record(value_key, value)
                .await
                .map_err(AnnounceError::Unreachable)?;
            Ok(Receipt::new("libp2p-kad"))
        };

        match tokio::time::timeout(budget.deadline, publish).await {
            Ok(result) => result,
            Err(_elapsed) => Err(AnnounceError::DeadlineExceeded),
        }
    }

    async fn withdraw(&self, key: &ContentKey) -> Result<Receipt, AnnounceError> {
        // Best-effort withdrawal: stop announcing ourselves as a provider. A fully
        // propagated SIGNED withdrawal tombstone (ProviderWithdrawal, so other nodes'
        // caches expire the record) is hardening deferred to TASK-152; here we retract
        // our own provider entry and let the value record expire on its TTL.
        self.handle.stop_providing(provider_index_key(key)).await;
        Ok(Receipt::new("libp2p-kad-withdraw"))
    }

    fn declared_exposure(&self) -> ExposureSurface {
        ExposureSurface::from_exposures([
            Exposure::new(Recipient::DhtNode, Disclosed::ContentKey),
            Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId),
            Exposure::new(Recipient::DhtNode, Disclosed::OurAddress),
            Exposure::new(Recipient::Bootstrap, Disclosed::OurNodeId),
        ])
    }
}
