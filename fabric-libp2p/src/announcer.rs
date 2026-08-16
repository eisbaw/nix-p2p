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
//! composite value key the record lives under, so a resolver's `get_record` returns the
//! tombstone, the frozen record_store applies it as Withdrawn, and the provider stops
//! being returned.
//!
//! ## Retraction: what TASK-176 built, and what it does NOT yet guarantee
//!
//! Two MECHANISMS were added; read their scope precisely (the TASK-152 limits are
//! narrowed on the SENDER side, not closed end-to-end on the network):
//!   * DURABLE SEQUENCE (TASK-176 #1) - PRODUCTION-WIRED (TASK-185). The per-key sequence
//!     floor is persisted (the `durable` constructor) so a restarted provider re-seeds it and
//!     allocates `last.sequence + 1` rather than losing at sequence 1. The shipped
//!     `daemon-libp2p` now routes to the durable announcer whenever `--libp2p-state-dir` is
//!     set, and mints POSITIVE records at a durably-allocated sequence
//!     ([`Libp2pFabric::next_announce_sequence`](crate::Libp2pFabric::next_announce_sequence)),
//!     NOT a hardcoded `1`, so a restarted provider's withdrawal supersedes. And announce is
//!     SAVE-BEFORE-PUBLISH: the floor is persisted fail-closed BEFORE the DHT publish (AC#3),
//!     so a crash cannot expose a record whose sequence was not durably recorded.
//!   * TTL CAP + TOMBSTONE ARITHMETIC (TASK-176 #2) - a SENDER POLICY + a LOCAL pin, NOT a
//!     network invariant. `announce` REJECTS a record whose own TTL exceeds
//!     [`MAX_RECORD_TTL_SECS`], and a compile-time assert pins
//!     `MIN_TOMBSTONE_TTL_SECS >= MAX_RECORD_TTL_SECS`, so a tombstone THIS announcer mints
//!     outlives any record THIS announcer published. That is the whole guarantee. It is NOT
//!     an end-to-end no-resurrection invariant: CONSUMERS do not enforce the cap, so a
//!     non-conforming (or malicious) provider can `put_record` a value with a `>cap` expiry
//!     that this node's fixed tombstone floor does NOT outlive. Consumer-side cap
//!     enforcement is TASK-188 (F5, the record-lifecycle hardening follow-up). `withdraw`
//!     returns `Ok` meaning "the tombstone was published", never "every cache is provably
//!     retracted".

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use libp2p::PeerId;
use peer_fabric::{
    AnnounceBudget, AnnounceError, AvailabilityAnnouncer, ContentKey, Disclosed, Exposure,
    ExposureLedger, ExposureSurface, NodeId, ProviderRecord, ProviderWithdrawal, Receipt,
    Recipient, decode_provider_assertion, encode_provider_record, encode_provider_withdrawal,
    sign_provider_withdrawal,
};

use crate::keys::{provider_index_key, provider_value_key};
use crate::swarm::SwarmHandle;

/// The maximum record TTL (`expiry - now`) THIS announce will publish, in seconds
/// (TASK-176 #2). This is a SENDER-SIDE policy only: `announce` REJECTS (fail fast) a
/// record whose TTL exceeds it, because the record is SIGNED above the seam and the
/// backend cannot clamp its expiry without invalidating the signature. 24h is a generous
/// refresh cadence for a stable provider (well above kad's own republish interval). It
/// makes the tombstone floor below outlive any record THIS announcer published - it does
/// NOT bind other providers: a CONSUMER does not enforce this cap, so a non-conforming
/// provider can still `put_record` a `>cap` expiry (consumer-side enforcement is TASK-188).
pub const MAX_RECORD_TTL_SECS: u64 = 86_400;

/// The FLOOR lifetime, in seconds, a minted withdrawal tombstone is given when the
/// retracted record's own remaining TTL is shorter or unknown. A tombstone should outlive
/// the record it retracts, else a cache resurrects the record after the tombstone lapses
/// but before the record's own expiry. Set to [`MAX_RECORD_TTL_SECS`] so that FOR RECORDS
/// THIS ANNOUNCER PUBLISHED the bound holds: such a record announced at `t0` has
/// `expiry <= t0 + MAX_RECORD_TTL_SECS` (the announce cap), and a withdrawal at `now >= t0`
/// mints a tombstone with `expiry >= now + MAX_RECORD_TTL_SECS >= record.expiry` - even
/// POST-RESTART. This narrows the TASK-152 resurrection window ON THE SENDER SIDE. It does
/// NOT close it network-wide: a record put by a provider that did NOT honor the cap has an
/// expiry this fixed floor need not outlive (TASK-188).
const MIN_TOMBSTONE_TTL_SECS: u64 = MAX_RECORD_TTL_SECS;

/// COMPILE-TIME pin of the LOCAL tombstone-arithmetic invariant (TASK-176 #2): the
/// tombstone floor must be `>=` the record-TTL cap, or a max-TTL record THIS announcer
/// published just before a post-restart withdrawal would outlive its own tombstone. This
/// pins the SENDER-SIDE arithmetic (not a network guarantee - consumers do not enforce the
/// cap; TASK-188); it fails the build the moment someone lowers the floor below the cap.
const _: () = assert!(
    MIN_TOMBSTONE_TTL_SECS >= MAX_RECORD_TTL_SECS,
    "the withdrawal tombstone floor must outlive the longest record TTL, or a \
     post-restart withdrawal leaves a resurrection window against a max-TTL record"
);

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
    /// TTL. DURABLY backed by `seq_path` when set (TASK-176 #1): a restarted provider
    /// re-seeds this map from disk, so its withdrawal supersedes (rather than losing at
    /// sequence 1 to) a consumer already at the record's real sequence. When `seq_path`
    /// is `None` it is in-memory only (a restart loses it). Guarded by a std Mutex; only
    /// ever held for the synchronous update.
    announced: Mutex<HashMap<ContentKey, LastPublished>>,
    /// The durable per-key sequence file, or `None` for an in-memory announcer.
    seq_path: Option<PathBuf>,
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
        Self::build(handle, ledger, node_id, peer_id, signing_key, None)
    }

    /// An announcer whose per-key sequence floor is DURABLY backed by `seq_path`
    /// (TASK-176 #1): re-seeded at startup and re-flushed on every announce/withdraw, so
    /// a restarted provider's withdrawal is network-effective instead of silently losing
    /// at sequence 1.
    pub fn durable(
        handle: SwarmHandle,
        ledger: Arc<ExposureLedger>,
        node_id: NodeId,
        peer_id: PeerId,
        signing_key: SigningKey,
        seq_path: PathBuf,
    ) -> Self {
        Self::build(
            handle,
            ledger,
            node_id,
            peer_id,
            signing_key,
            Some(seq_path),
        )
    }

    fn build(
        handle: SwarmHandle,
        ledger: Arc<ExposureLedger>,
        node_id: NodeId,
        peer_id: PeerId,
        signing_key: SigningKey,
        seq_path: Option<PathBuf>,
    ) -> Self {
        // HARD assert (not debug_assert): this is a signing surface on a data-integrity
        // path. A mismatched key would sign tombstones whose `provider` does not derive to
        // the composite value key's PeerId, so every consumer's binding check rejects them
        // and withdrawals SILENTLY never work - a fail-closed we must catch in release too,
        // at construction, not discover as an inexplicable non-retraction in the field.
        assert_eq!(
            NodeId::from_bytes(signing_key.verifying_key().to_bytes()),
            node_id,
            "announcer signing key must be this node's identity (self-serve v1)"
        );
        // Re-seed the per-key sequence floor from disk (empty if none / unreadable).
        let mut announced = HashMap::new();
        if let Some(path) = &seq_path {
            for (key, sequence, expiry) in crate::persist::load_seqs(path) {
                announced.insert(key, LastPublished { sequence, expiry });
            }
        }
        Libp2pAvailabilityAnnouncer {
            handle,
            ledger,
            node_id,
            peer_id,
            signing_key,
            announced: Mutex::new(announced),
            seq_path,
        }
    }

    /// The next durably-allocated POSITIVE sequence for `key` (TASK-185, AC#2): strictly
    /// greater than the last record this announcer published for it, or 1 if it never
    /// published for `key`. In the DURABLE case the floor was re-seeded from disk at
    /// construction, so a RESTARTED provider allocates `last + 1` and its next record is
    /// strictly newer than every record it previously published - the production monotonic
    /// allocator that replaces the daemon's hardcoded `sequence: 1` mint (which self-rolled-
    /// back after a restart, the F3 defect). PURE read; the actual reservation happens when
    /// [`announce`](AvailabilityAnnouncer::announce) persists the floor before publishing.
    pub fn next_sequence(&self, key: &ContentKey) -> u64 {
        self.announced
            .lock()
            .expect("announced-sequence mutex poisoned")
            .get(key)
            .map(|last| last.sequence + 1)
            .unwrap_or(1)
    }

    /// Snapshot the per-key floor for serialization (taken under the lock, written outside).
    fn snapshot_announced(&self) -> Vec<(ContentKey, u64, u64)> {
        self.announced
            .lock()
            .expect("announced-sequence mutex poisoned")
            .iter()
            .map(|(key, last)| (*key, last.sequence, last.expiry))
            .collect()
    }

    /// Flush the per-key sequence floor to disk (atomic) when durable, LOGGING any error.
    /// Used on the withdraw path where a failed flush costs only that a later same-process
    /// withdraw re-mints the same tombstone sequence (idempotent), not a rollback.
    fn persist_announced(&self) {
        let Some(path) = &self.seq_path else {
            return;
        };
        crate::persist::save_seqs(path, &self.snapshot_announced());
    }

    /// Flush the per-key sequence floor to disk, PROPAGATING any I/O error (TASK-185, AC#3).
    /// The announce path uses this to FAIL-CLOSED (no DHT publish) when the sequence cannot
    /// be durably recorded. A `None` seq_path (non-durable announcer) is `Ok(())` - there is
    /// nothing to persist and nothing to fail on.
    fn persist_announced_checked(&self) -> std::io::Result<()> {
        let Some(path) = &self.seq_path else {
            return Ok(());
        };
        crate::persist::save_seqs_checked(path, &self.snapshot_announced())
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
///     record_store requires to be strictly newer than the record it retracts. Note the
///     `None` case (post-restart) mints sequence 1, which is NOT newer than a record a
///     consumer already observed at a higher sequence - see the module-doc limit;
///   * expiry = MAX(the retracted record's own expiry, `now + MIN_TOMBSTONE_TTL_SECS`),
///     so the tombstone is never itself already-expired (the frozen decode/apply would
///     reject a stale one) AND, when `last` is known, outlives the record it retracts.
///     When `last` is `None` this is only the best-effort floor (module-doc limit).
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
        // Bound the record TTL (TASK-176 #2): an over-cap expiry is REJECTED, not clamped
        // - the record is signed above the seam, so clamping would invalidate the
        // signature. Fail fast on the sender with the cap, so the caller re-signs a
        // shorter-lived record. This SENDER-SIDE bound is what lets the tombstone floor
        // (>= the cap) outlive any record THIS node published; it does NOT bind other
        // providers (consumers do not enforce the cap - TASK-188).
        if record.expiry - now > MAX_RECORD_TTL_SECS {
            return Err(AnnounceError::Rejected(format!(
                "record TTL {}s exceeds the {}s cap (expiry {} at now {}); \
                 sign a shorter-lived record",
                record.expiry - now,
                MAX_RECORD_TTL_SECS,
                record.expiry,
                now
            )));
        }
        let expires = Some(Instant::now() + Duration::from_secs(record.expiry - now));

        // Encode the FROZEN wire form (rejects an over-cap / non-canonical record on
        // the sender - fail fast before publishing).
        let value =
            encode_provider_record(record).map_err(|e| AnnounceError::Rejected(e.to_string()))?;

        // TASK-100 (codex BLOCKER, AC#6 half): VERIFY the record's ed25519 signature BEFORE
        // publishing, so a zero-signature / unverifiable self-provider record can never reach
        // the kad DHT (`start_providing`/`put_record` below). The encode step copies the
        // signature verbatim without checking it; here we re-parse the encoded value through
        // the FROZEN self-verifying decoder (`verify_strict` over the signing preimage, keyed
        // by the provider NodeId that MUST equal this node). A bad/zero signature fails closed
        // as `Rejected`, not published. This is an adapter INVARIANT: no announce path (public
        // or LAN) can publish an unsigned record, regardless of how it was routed here.
        decode_provider_assertion(&value, &record.key, now).map_err(|e| {
            AnnounceError::Rejected(format!("record failed signature self-verification: {e}"))
        })?;

        self.ledger.record_all([
            Exposure::new(Recipient::DhtNode, Disclosed::ContentKey),
            Exposure::new(Recipient::DhtNode, Disclosed::OurNodeId),
            Exposure::new(Recipient::DhtNode, Disclosed::OurAddress),
        ]);

        let key = record.key;
        let index_key = provider_index_key(&key);
        let value_key = provider_value_key(&key, &self.peer_id);

        // AC#3 (TASK-185) SAVE-BEFORE-PUBLISH: record this positive record's (sequence,
        // expiry) into the per-key floor and PERSIST it FAIL-CLOSED *before* announcing to
        // the DHT. A crash after publish must never expose a record whose sequence we did not
        // durably record - else a restart re-seeds a floor below it, re-mints an already-
        // published sequence, and the provider self-rolls-back (the F3 hazard). We advance to
        // MAX(existing, record) so a concurrent re-announce never regresses the floor.
        //
        // The floor is advanced even if the publish below then fails or times out: a
        // persisted-but-unpublished sequence is only ever SKIPPED (a gap), never reused - the
        // monotonic allocator's safe direction. (Previously this map was updated only AFTER a
        // successful publish, which is exactly the publish-before-save ordering TASK-185
        // closes.)
        {
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
        }
        if let Err(why) = self.persist_announced_checked() {
            // Fail-closed: the record and network may be fine, but publishing a record whose
            // sequence is not on disk is the F3 rollback hazard, so we refuse rather than
            // announce non-durably in silence.
            return Err(AnnounceError::Persist(why.to_string()));
        }

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

        // The per-key floor was already advanced and durably persisted above (save-before-
        // publish), so a successful publish needs no further bookkeeping.
        match tokio::time::timeout(budget.deadline, publish).await {
            Ok(Ok(receipt)) => Ok(receipt),
            Ok(Err(e)) => Err(e),
            Err(_elapsed) => Err(AnnounceError::DeadlineExceeded),
        }
    }

    async fn withdraw(&self, key: &ContentKey) -> Result<Receipt, AnnounceError> {
        // AC#1: propagate a SIGNED withdrawal tombstone, not just a local stop_providing.
        // Two acts, in this order:
        //   1. put_record the signed ProviderWithdrawal on the SAME composite value key the
        //      record lives under - a resolver's get_record returns the tombstone, the
        //      frozen record_store applies it as Withdrawn, and the provider stops being
        //      returned (a replay of the old record is now below the tombstone floor). This
        //      is EFFECTIVE within the same process; see the module doc for the post-restart
        //      / long-TTL limits (Ok = "tombstone published", not "provably retracted").
        //   2. stop_providing our multi-provider INDEX entry so get_providers stops naming
        //      us (the index has no signed value; this is the local retraction).
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
        // Advance our own per-key floor to the tombstone, so a LATER same-process withdraw
        // mints something strictly newer still and never regresses. This `announced` map is
        // the SHARED durable per-key sequence floor for BOTH announce and withdraw (TASK-185):
        // `announce` now WRITES it (the save-before-publish reserve) and `next_sequence` READS
        // it to allocate the next positive sequence. What `announce` still does NOT do is
        // REJECT-ON-FLOOR: it does not compare a positive record against this map and refuse a
        // stale one (the caller owns record sequencing above the seam - the rollback test
        // relies on a stale re-put being admitted at the substrate). So this map is an
        // allocation + withdrawal-sequencing floor, not an announce-time monotonicity GATE.
        {
            let mut announced = self
                .announced
                .lock()
                .expect("announced-sequence mutex poisoned");
            let slot = announced.entry(*key).or_insert(LastPublished {
                sequence: withdrawal.sequence,
                expiry: withdrawal.expiry,
            });
            if withdrawal.sequence >= slot.sequence {
                *slot = LastPublished {
                    sequence: withdrawal.sequence,
                    expiry: withdrawal.expiry,
                };
            }
        }
        // Persist the advanced per-key floor so a restart mints the NEXT withdrawal
        // strictly newer still (TASK-176 #1).
        self.persist_announced();
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

    #[test]
    fn a_post_restart_tombstone_outlives_any_capped_record() {
        // TASK-176 #2 BITE: the WORST case for resurrection is a post-restart withdrawal
        // (`last` unknown -> the tombstone gets only the floor TTL) racing a record
        // published at the MAXIMUM allowed TTL just before `now`. The tombstone must still
        // outlive it. Because MIN_TOMBSTONE_TTL_SECS == MAX_RECORD_TTL_SECS, it does.
        // Mutation: drop MIN_TOMBSTONE_TTL_SECS below MAX_RECORD_TTL_SECS and this fails
        // (and the compile-time `const _` pin refuses to build) - the invariant bites two
        // ways.
        let sk = signer(9);
        let k = key(3);
        let now = 1_000_000;
        // A max-TTL record published at t0 <= now: its expiry is at most t0 + cap <= now + cap.
        let worst_case_record_expiry = now + MAX_RECORD_TTL_SECS;
        let tombstone = mint_withdrawal(&sk, &k, None, now); // post-restart: last unknown
        assert!(
            tombstone.expiry >= worst_case_record_expiry,
            "a post-restart tombstone (expiry {}) must outlive a max-TTL record \
             (expiry {})",
            tombstone.expiry,
            worst_case_record_expiry
        );
        // (The MIN_TOMBSTONE_TTL_SECS >= MAX_RECORD_TTL_SECS invariant itself is pinned at
        // COMPILE TIME by the `const _` assertion above, so it is not restated here as a
        // runtime const-assert.)
    }
}
