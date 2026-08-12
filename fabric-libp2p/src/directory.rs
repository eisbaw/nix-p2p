//! [`Libp2pProviderDirectory`] - the kad-backed exact-key content directory (the
//! cornerstone). `find_providers` resolves a [`ContentKey`] to the signed
//! [`ProviderRecord`]s of every provider, purely through the DHT, and distinguishes a
//! healthy `Miss` from a could-not-consult `Unavailable`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use peer_fabric::{
    ContentKey, Disclosed, DiscoveryBudget, Exposure, ExposureLedger, ExposureSurface, Lookup,
    ProviderAssertion, ProviderDirectory, ProviderRecord, Recipient, RecordDecodeError,
    Unavailable, decode_provider_assertion,
};

use crate::keys::{provider_index_key, provider_value_key};
use crate::swarm::{QueryFail, SwarmHandle};

/// The kad-backed [`ProviderDirectory`]. See the crate ADR for the HYBRID mapping.
pub struct Libp2pProviderDirectory {
    handle: SwarmHandle,
    ledger: Arc<ExposureLedger>,
}

impl Libp2pProviderDirectory {
    /// A directory driving `handle`, recording disclosures to `ledger`.
    pub fn new(handle: SwarmHandle, ledger: Arc<ExposureLedger>) -> Self {
        Libp2pProviderDirectory { handle, ledger }
    }

    /// The two-phase resolve, WITHOUT the outer deadline (the trait method wraps this
    /// in the budget timeout). Returns the same [`Lookup`] arms.
    async fn resolve(&self, key: &ContentKey) -> Lookup<Vec<ProviderRecord>> {
        // A lookup over an empty routing table is not authoritative: a `Miss` would be
        // a lie (we simply are not on the network for this key). Fail it as
        // Unavailable, distinct from a healthy empty result.
        if self.handle.routing_peers().await == 0 {
            return Lookup::Unavailable(Unavailable::InsufficientRouting);
        }

        // Phase 1: the multi-provider index.
        let providers = match self.handle.get_providers(provider_index_key(key)).await {
            Ok(set) => set,
            Err(QueryFail::Timeout) => return Lookup::Unavailable(Unavailable::DeadlineExceeded),
            Err(QueryFail::Backend(why)) => return Lookup::Unavailable(Unavailable::Backend(why)),
        };
        if providers.is_empty() {
            // A healthy, completed index lookup that found no provider: authoritative
            // absence (AC#7 "MISS only after a healthy completed lookup").
            return Lookup::Miss;
        }

        // Phase 2: fetch each provider's signed record from the value store and verify
        // it with the FROZEN codec (self-verifying ed25519 + SSOT key match + expiry).
        let now = unix_now();
        let mut records = Vec::new();
        for provider in providers {
            match self
                .handle
                .get_record(provider_value_key(key, &provider))
                .await
            {
                Ok(Some(bytes)) => match decode_provider_assertion(&bytes, key, now) {
                    Ok(ProviderAssertion::Provide(record)) => records.push(record),
                    Ok(ProviderAssertion::Withdraw(_)) => {
                        // A signed tombstone: the provider retracted. Not a positive
                        // record; skip it.
                        tracing::debug!(%provider, "provider record is a withdrawal, skipping");
                    }
                    Err(RecordDecodeError::Stale { expiry, now }) => {
                        tracing::debug!(%provider, expiry, now, "provider record expired, skipping");
                    }
                    Err(why) => {
                        // Untrusted hint infrastructure: a malformed/forged value costs
                        // us skipping this provider, never a bad answer (Nix re-verifies).
                        tracing::warn!(%provider, %why, "rejecting invalid provider record");
                    }
                },
                Ok(None) => {
                    // Indexed as a provider but no retrievable value record. Skip.
                    tracing::debug!(%provider, "no value record for indexed provider, skipping");
                }
                Err(_) => {
                    tracing::debug!(%provider, "value-record fetch failed, skipping provider");
                }
            }
        }

        if records.is_empty() {
            // The index named providers but no valid signed record was retrievable
            // (withdrawn / expired / unfetchable). No positive provider stands: a
            // healthy absence of a valid record.
            return Lookup::Miss;
        }
        Lookup::Found(records)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[async_trait]
impl ProviderDirectory for Libp2pProviderDirectory {
    async fn find_providers(
        &self,
        key: &ContentKey,
        budget: &DiscoveryBudget,
    ) -> Lookup<Vec<ProviderRecord>> {
        // A find discloses the queried content key and our own node id to the DHT nodes
        // we consult (axis-6 leakage).
        self.ledger.record_all([
            Exposure::new(Recipient::DhtNode, Disclosed::ContentKey),
            Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId),
        ]);
        match tokio::time::timeout(budget.deadline, self.resolve(key)).await {
            Ok(lookup) => lookup,
            Err(_elapsed) => Lookup::Unavailable(Unavailable::DeadlineExceeded),
        }
    }

    fn declared_exposure(&self) -> ExposureSurface {
        ExposureSurface::from_exposures([
            Exposure::new(Recipient::DhtNode, Disclosed::ContentKey),
            Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId),
            Exposure::new(Recipient::Bootstrap, Disclosed::OurNodeId),
        ])
    }
}
