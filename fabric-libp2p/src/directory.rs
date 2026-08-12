//! [`Libp2pProviderDirectory`] - the kad-backed exact-key content directory (the
//! cornerstone). `find_providers` resolves a [`ContentKey`] to the signed
//! [`ProviderRecord`]s of every provider, purely through the DHT, and distinguishes a
//! healthy `Miss` from a could-not-consult `Unavailable`.

use std::sync::Arc;

use async_trait::async_trait;
use peer_fabric::{
    ContentKey, Disclosed, DiscoveryBudget, Exposure, ExposureLedger, ExposureSurface, Lookup,
    ProviderAssertion, ProviderDirectory, ProviderRecord, Recipient, RecordDecodeError,
    Unavailable, decode_provider_assertion,
};

use crate::keys::{peer_id_of_provider, provider_index_key, provider_value_key};
use crate::swarm::{QueryFail, SwarmHandle};

/// The kad-backed [`ProviderDirectory`]. See the crate ADR for the HYBRID mapping.
pub struct Libp2pProviderDirectory {
    handle: SwarmHandle,
    ledger: Arc<ExposureLedger>,
}

/// Classify the outcome of the value-store phase (a PURE decision, unit-tested to bite
/// the Miss/Unavailable boundary the seam is built on).
///
///   * any positive record -> `Found`;
///   * no positive record but a value fetch could NOT be consulted -> `Unavailable`,
///     NEVER `Miss` (the index named providers; we simply could not fetch their
///     records - a caller must not cache this as authoritative absence);
///   * no positive record and every skip was HEALTHY (withdrawn / expired / genuinely
///     absent) -> `Miss`.
fn classify(records: Vec<ProviderRecord>, consult_failed: bool) -> Lookup<Vec<ProviderRecord>> {
    if !records.is_empty() {
        Lookup::Found(records)
    } else if consult_failed {
        Lookup::Unavailable(Unavailable::Backend(
            "provider index named providers but their value records could not be consulted"
                .to_string(),
        ))
    } else {
        Lookup::Miss
    }
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
        // Unavailable, distinct from a healthy empty result. NOTE (honest limit): this
        // is a TOTAL-routing bar, not a "peers near the key" bar - a node holding only
        // a bootstrap could still report Miss where InsufficientRouting is more honest.
        // Raising it to a near-key/query-stats bar is TASK-153.
        if self.handle.routing_peers().await == 0 {
            return Lookup::Unavailable(Unavailable::InsufficientRouting);
        }

        // We are about to actually consult the DHT: record the disclosure HERE, after
        // the short-circuit, so an InsufficientRouting lookup that never touched the
        // network does not pollute the ledger with a DHT disclosure.
        self.ledger.record_all([
            Exposure::new(Recipient::DhtNode, Disclosed::ContentKey),
            Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId),
        ]);

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

        // Phase 2: fetch each provider's signed record from the value store CONCURRENTLY
        // (resolve latency is the max of the fetches, not their sum - which keeps a
        // multi-provider lookup inside its budget). Each is verified with the FROZEN
        // codec (self-verifying ed25519 + SSOT key match + expiry).
        let now = crate::unix_now();
        let fetches = providers.into_iter().map(|peer| {
            let handle = self.handle.clone();
            let key = *key;
            async move {
                let outcome = handle.get_record(provider_value_key(&key, &peer)).await;
                (peer, outcome)
            }
        });
        let results = futures::future::join_all(fetches).await;

        let mut records = Vec::new();
        let mut consult_failed = false;
        for (peer, outcome) in results {
            match outcome {
                Ok(Some(bytes)) => match decode_provider_assertion(&bytes, key, now) {
                    Ok(ProviderAssertion::Provide(record)) => {
                        // Bind the signed record's provider to the index entry it was
                        // fetched under: reject a peer that re-stored a THIRD party's
                        // record at its own composite key (index spoofing). The forward
                        // derivation (verifying key -> PeerId) is always available.
                        if peer_id_of_provider(&record.provider) == Some(peer) {
                            records.push(record);
                        } else {
                            tracing::warn!(
                                %peer, provider = %record.provider,
                                "record provider does not derive to the index PeerId; \
                                 rejecting (possible index spoof)"
                            );
                        }
                    }
                    Ok(ProviderAssertion::Withdraw(_)) => {
                        tracing::debug!(%peer, "provider record is a withdrawal, skipping");
                    }
                    Err(RecordDecodeError::Stale { expiry, now }) => {
                        tracing::debug!(%peer, expiry, now, "provider record expired, skipping");
                    }
                    Err(why) => {
                        // Untrusted hint infrastructure: a malformed/forged value costs
                        // skipping this provider, never a bad answer (Nix re-verifies).
                        tracing::warn!(%peer, %why, "rejecting invalid provider record");
                    }
                },
                Ok(None) => {
                    tracing::debug!(%peer, "no value record for indexed provider, skipping");
                }
                Err(fail) => {
                    // Could-not-consult: this must NOT let an empty result become Miss.
                    consult_failed = true;
                    tracing::debug!(%peer, ?fail, "value-record consultation failed");
                }
            }
        }

        classify(records, consult_failed)
    }
}

#[async_trait]
impl ProviderDirectory for Libp2pProviderDirectory {
    async fn find_providers(
        &self,
        key: &ContentKey,
        budget: &DiscoveryBudget,
    ) -> Lookup<Vec<ProviderRecord>> {
        // The deadline is enforced at THIS async boundary. On elapse the resolve future
        // is dropped, but the underlying kad query already handed to the worker is NOT
        // cancelled - it runs to its own query_timeout, then replies into a dropped
        // receiver (bounded wasted work, no leak). An explicit Cancel(QueryId) path
        // (threading the id back out of SwarmHandle) is a work-bound follow-up: TASK-154.
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

#[cfg(test)]
mod tests {
    use super::*;
    use peer_fabric::{Blake3Digest, NodeId};

    fn a_record() -> ProviderRecord {
        ProviderRecord {
            key: ContentKey::from_bytes([0x01; 32]),
            content: Blake3Digest::from_bytes([0x02; 32]),
            provider: NodeId::from_bytes([0x03; 32]),
            offers: vec![],
            sequence: 1,
            issued_at: 0,
            expiry: 1,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn classify_found_when_any_positive_record() {
        assert!(matches!(
            classify(vec![a_record()], false),
            Lookup::Found(records) if records.len() == 1
        ));
        // Even if a consultation ALSO failed, a positive record is still Found.
        assert!(classify(vec![a_record()], true).is_found());
    }

    #[test]
    fn classify_miss_only_when_healthy_and_empty() {
        // No records, no consultation failure -> authoritative absence.
        assert!(matches!(classify(Vec::new(), false), Lookup::Miss));
    }

    #[test]
    fn classify_unavailable_when_consultation_failed_and_empty() {
        // THE B1 BITE: an empty result that included a consultation FAILURE must be
        // Unavailable, never Miss - or a caller would cache "no provider" for content
        // that is in the DHT. Delete the `consult_failed` branch and this fails.
        match classify(Vec::new(), true) {
            Lookup::Unavailable(Unavailable::Backend(_)) => {}
            other => panic!("expected Unavailable(Backend), got {other:?}"),
        }
    }
}
