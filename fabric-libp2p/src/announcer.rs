//! [`Libp2pAvailabilityAnnouncer`] - publishes an already-signed
//! [`ProviderRecord`] into the DHT (the HYBRID: `start_providing` the index +
//! `put_record` the signed value). Eligibility and signing of the POSITIVE record are
//! decided ABOVE the seam; the announcer only encodes the frozen record and publishes
//! it under its budget.
//!
//! WITHDRAWAL is different (TASK-152, AC#1): the seam's [`AvailabilityAnnouncer::withdraw`]
//! is handed only a [`ContentKey`], not a signed tombstone, so the backend must MINT the
//! signed [`ProviderWithdrawal`] itself. It can, because this is self-serve v1: a node's
//! libp2p identity IS the ed25519 secret that signs its records, so the announcer holds
//! the exact key material to sign a withdrawal of ITS OWN record - and it only ever
//! withdraws records it itself announced. The tombstone is `put_record`-ed on the SAME
//! composite value key the record lives under, so other nodes' cached value records are
//! ACTIVELY retracted (a resolver's `get_record` now returns the tombstone, not the
//! record) rather than left to age out on TTL.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use libp2p::PeerId;
use peer_fabric::{
    AnnounceBudget, AnnounceError, AvailabilityAnnouncer, ContentKey, Disclosed, Exposure,
    ExposureLedger, ExposureSurface, NodeId, ProviderRecord, ProviderWithdrawal, Receipt,
    Recipient, encode_provider_record, encode_provider_withdrawal, sign_provider_withdrawal,
};

use crate::keys::{provider_index_key, provider_value_key};
use crate::swarm::SwarmHandle;

/// The floor lifetime, in seconds, a minted withdrawal tombstone is given when the
/// retracted record's own remaining TTL is shorter (or the record is unknown to this
/// announcer). A tombstone must OUTLIVE the record it retracts, or a cache could resurrect
/// the record after the tombstone lapsed but before the record's own expiry; giving the
/// tombstone at least this long keeps the retraction effective for a meaningful window.
const MIN_TOMBSTONE_TTL_SECS: u64 = 3600;

/// The kad-backed [`AvailabilityAnnouncer`].
pub struct Libp2pAvailabilityAnnouncer {
    handle: SwarmHandle,
    ledger: Arc<ExposureLedger>,
    /// This node's identity - the announcer only publishes ITS OWN records (self-serve
    /// v1). The `peer_id` keys the value store; `node_id` is checked against the
    /// record's `provider`.
    node_id: NodeId,
    peer_id: PeerId,
    /// The ed25519 secret that IS this node's identity, used to SIGN withdrawal
    /// tombstones (AC#1). Same key whose verifying key equals `node_id`.
    signing_key: SigningKey,
    /// The last `(sequence, expiry)` this announcer published per key, so a withdrawal
    /// can be minted at a STRICTLY NEWER sequence than the record it retracts (the frozen
    /// monotonic rule) and given a tombstone lifetime that covers the record's remaining
    /// TTL. In-memory: a restart loses it (the honest durability limit the record_store
    /// module doc names - a restarted provider re-derives its floor from a fresh
    /// announce). Guarded by a std Mutex; only ever held for the synchronous update.
    announced: Mutex<HashMap<ContentKey, LastPublished>>,
}

/// The `(sequence, expiry)` of the last positive record this announcer published for a
/// key - the basis for minting a strictly-newer, long-enough withdrawal.
#[derive(Debug, Clone, Copy)]
struct LastPublished {
    sequence: u64,
    expiry: u64,
}

impl Libp2pAvailabilityAnnouncer {
    /// An announcer driving `handle` for the node identified by `node_id`/`peer_id`,
    /// signing its own withdrawals with `signing_key` (whose verifying key MUST equal
    /// `node_id` - a debug-asserted self-serve invariant).
    pub fn new(
        handle: SwarmHandle,
        ledger: Arc<ExposureLedger>,
        node_id: NodeId,
        peer_id: PeerId,
        signing_key: SigningKey,
    ) -> Self {
        debug_assert_eq!(
            NodeId::from_bytes(signing_key.verifying_key().to_bytes()),
            node_id,
            "announcer signing key must be this node's identity (self-serve v1)"
        );
        Libp2pAvailabilityAnnouncer {
            handle,
            ledger,
            node_id,
            peer_id,
            signing_key,
            announced: Mutex::new(HashMap::new()),
        }
    }

    /// Mint a SIGNED withdrawal tombstone that STRICTLY SUPERSEDES the last record this
    /// announcer published for `key` (AC#1), reading the tracked floor under the lock.
    fn mint_withdrawal(&self, key: &ContentKey, now: u64) -> ProviderWithdrawal {
        let last = self
            .announced
            .lock()
            .expect("announced-sequence mutex poisoned")
            .get(key)
            .copied();
        mint_withdrawal(&self.signing_key, key, last, now)
    }
}

/// Mint a SIGNED withdrawal tombstone that strictly supersedes `last` (the last record
/// published for `key`, or `None` if never published). PURE over its inputs, so the
/// sequence/expiry choice is unit-testable without a live DHT or a swarm handle:
///   * sequence = `last.sequence + 1` (or 1 if never published), which the frozen
///     record_store requires to be strictly newer than the record it retracts;
///   * expiry = MAX(the retracted record's own expiry, `now + MIN_TOMBSTONE_TTL_SECS`),
///     so the tombstone both OUTLIVES the record it retracts AND is never itself
///     already-expired (which the frozen decode/apply would reject as Stale).
fn mint_withdrawal(
    signing_key: &SigningKey,
    key: &ContentKey,
    last: Option<LastPublished>,
    now: u64,
) -> ProviderWithdrawal {
    let sequence = last.map(|l| l.sequence + 1).unwrap_or(1);
    let expiry = last
        .map(|l| l.expiry)
        .unwrap_or(0)
        .max(now + MIN_TOMBSTONE_TTL_SECS);
    // `sign_provider_withdrawal` overwrites `provider` from the key, so the unsigned
    // template leaves it zero; the result names the signer and is self-verifying.
    sign_provider_withdrawal(
        signing_key,
        &ProviderWithdrawal {
            key: *key,
            provider: NodeId::from_bytes([0u8; 32]),
            sequence,
            issued_at: now,
            expiry,
            signature: [0u8; 64],
        },
    )
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

        // Reconcile the record's expiry with the store TTL (AC#6): the stored value
        // must not outlive what the provider signed. Reject an already-expired record
        // on the sender (fail fast) - publishing a stale value is a caller bug.
        let now = crate::unix_now();
        if record.expiry <= now {
            return Err(AnnounceError::Rejected(format!(
                "record already expired (expiry {} <= now {})",
                record.expiry, now
            )));
        }
        let expires = Some(Instant::now() + Duration::from_secs(record.expiry - now));

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
            // The signed record in the value store (learnable offline), expiring no
            // later than the provider signed.
            self.handle
                .put_record(value_key, value, expires)
                .await
                .map_err(AnnounceError::Unreachable)?;
            Ok(Receipt::new("libp2p-kad"))
        };

        match tokio::time::timeout(budget.deadline, publish).await {
            Ok(Ok(receipt)) => {
                // Remember what we published so a later withdrawal can supersede it at a
                // strictly-newer sequence with a long-enough tombstone (AC#1). Recorded
                // only after a successful publish - we never tombstone-plan a record that
                // did not land. A concurrent re-announce takes the MAX sequence so the
                // withdrawal floor never regresses.
                let mut announced = self
                    .announced
                    .lock()
                    .expect("announced-sequence mutex poisoned");
                let slot = announced.entry(key).or_insert(LastPublished {
                    sequence: record.sequence,
                    expiry: record.expiry,
                });
                if record.sequence >= slot.sequence {
                    *slot = LastPublished {
                        sequence: record.sequence,
                        expiry: record.expiry,
                    };
                }
                Ok(receipt)
            }
            Ok(Err(e)) => Err(e),
            Err(_elapsed) => Err(AnnounceError::DeadlineExceeded),
        }
    }

    async fn withdraw(&self, key: &ContentKey) -> Result<Receipt, AnnounceError> {
        // AC#1: propagate a SIGNED withdrawal tombstone, not just a local stop_providing.
        // Two acts, in this order:
        //   1. put_record the signed ProviderWithdrawal on the SAME composite value key
        //      the record lives under, so other nodes' cached value records are ACTIVELY
        //      retracted before their natural TTL - a resolver's get_record returns the
        //      tombstone, the frozen record_store applies it as Withdrawn, and the
        //      provider stops being returned (and cannot be resurrected by a replay of
        //      the old record, whose sequence is now below the tombstone floor).
        //   2. stop_providing our multi-provider INDEX entry so get_providers stops
        //      naming us (the index has no signed value; this is the local retraction).
        let now = crate::unix_now();
        let withdrawal = self.mint_withdrawal(key, now);
        let value = encode_provider_withdrawal(&withdrawal)
            .map_err(|e| AnnounceError::Rejected(e.to_string()))?;
        // The tombstone should live at least as long as the record it retracts could
        // remain cached; its own `expiry` bounds that, so hand the store the same instant.
        let expires =
            Some(Instant::now() + Duration::from_secs(withdrawal.expiry.saturating_sub(now)));

        self.ledger.record_all([
            Exposure::new(Recipient::DhtNode, Disclosed::ContentKey),
            Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId),
        ]);

        let value_key = provider_value_key(key, &self.peer_id);
        self.handle
            .put_record(value_key, value, expires)
            .await
            .map_err(AnnounceError::Unreachable)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use peer_fabric::{ApplyOutcome, ProviderRecordSet, decode_provider_assertion};

    fn key(seed: u8) -> ContentKey {
        ContentKey::from_bytes([seed; 32])
    }
    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn minted_withdrawal_supersedes_the_last_announced_record() {
        // BITE for AC#1's sequence rule: a withdrawal minted AFTER announcing seq 5 must
        // land as a strictly-newer tombstone (seq 6) that the frozen record_store applies
        // as Withdrawn. If mint used a sequence <= the record's, the store would
        // RejectStale and the record would never be retracted.
        let sk = signer(7);
        let k = key(1);
        let now = 1_000;
        let last = Some(LastPublished {
            sequence: 5,
            expiry: now + 10_000,
        });
        let withdrawal = mint_withdrawal(&sk, &k, last, now);
        assert_eq!(withdrawal.sequence, 6, "strictly newer than the record");
        assert!(
            withdrawal.expiry >= now + 10_000,
            "tombstone outlives the record it retracts"
        );
        assert_eq!(
            withdrawal.provider,
            NodeId::from_bytes(sk.verifying_key().to_bytes()),
            "the minted tombstone names the signer"
        );

        // It decodes (self-verifying) and applies as a fresh tombstone.
        let bytes = encode_provider_withdrawal(&withdrawal).unwrap();
        let assertion = decode_provider_assertion(&bytes, &k, now).expect("valid withdrawal");
        let mut set = ProviderRecordSet::new();
        assert_eq!(set.apply(&assertion, now), ApplyOutcome::Withdrawn);
    }

    #[test]
    fn minted_withdrawal_for_unknown_key_is_fresh_and_not_expired() {
        // A withdrawal for a key never announced still yields a valid, non-expired
        // tombstone (sequence 1, expiry now + floor TTL) - so a stale cache held elsewhere
        // can still be retracted. BITE: if expiry were left at 0 it would decode as Stale
        // and never propagate.
        let sk = signer(8);
        let k = key(2);
        let now = 5_000;
        let withdrawal = mint_withdrawal(&sk, &k, None, now);
        assert_eq!(withdrawal.sequence, 1);
        assert_eq!(withdrawal.expiry, now + MIN_TOMBSTONE_TTL_SECS);
        let bytes = encode_provider_withdrawal(&withdrawal).unwrap();
        assert!(
            decode_provider_assertion(&bytes, &k, now).is_ok(),
            "a minted tombstone must be fresh and self-verifying"
        );
    }
}
