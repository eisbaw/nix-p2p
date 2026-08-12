//! The FROZEN provider-record VALIDATION rules (TASK-126, AC#3), as a pure in-memory
//! oracle - NOT a running DHT (that is TASK-103).
//!
//! This is the [`ProviderRecordSet`]: the per-`(key, provider)` state machine that
//! decides whether an already-decoded, already-signature-VERIFIED
//! [`ProviderAssertion`] is APPLIED, is an idempotent no-op, or is REJECTED. It is the
//! salvaged core of the hand-rolled Kademlia work, kept as a test oracle (a
//! `FakeProviderDirectory`-grade double) rather than shipped infrastructure. The
//! adopted backend (TASK-103) enforces the SAME rules over the real network; freezing
//! them here, provable by unit test, is what lets that adoption be a swap and not a
//! redesign.
//!
//! ## What "verified" means here (the trust boundary)
//!
//! [`ProviderRecordSet::apply`] ASSUMES its input came from
//! [`crate::record_codec::decode_provider_assertion`], which already checked the
//! signature, the `key == storage_key` SSOT invariant, the version, and that the
//! record was not already expired at decode time. So this module never touches
//! cryptography; it owns only the TEMPORAL and SEQUENCE rules over trusted assertions.
//! Keeping the two apart is deliberate: authenticity is a codec property, liveness is
//! a store property, and mixing them is how one grows a hole the other was supposed to
//! cover.
//!
//! ## The rules (AC#3), and why each is a rule
//!
//!   * MONOTONIC SEQUENCE - a `(key, provider)` slot only moves FORWARD. An assertion
//!     with a sequence `<=` the slot's current is REJECTED. This is what makes replay
//!     impossible: a captured old record re-injected later has a stale sequence.
//!   * IDEMPOTENT REFRESH - re-applying the byte-identical current record is a no-op
//!     ([`ApplyOutcome::Idempotent`]), so a provider periodically re-announcing the
//!     same record neither errors nor duplicates. A DIFFERENT record at the same
//!     sequence is a conflict and is rejected (one sequence names one record).
//!   * EXPLICIT SIGNED WITHDRAWAL - a provider removes itself with a
//!     [`crate::record_codec::ProviderWithdrawal`], which lands a TOMBSTONE carrying
//!     the withdrawal's sequence. It must be strictly newer than the record it
//!     retracts.
//!   * EXPIRY - [`ProviderRecordSet::find_providers`] never returns a record whose
//!     `expiry <= now`, and `apply` refuses an assertion already expired at `now`
//!     (belt to the codec's braces, since the store's `now` may differ from decode's).
//!   * REPLAY REJECTION - falls out of monotonic sequence: an old record OR an old
//!     withdrawal re-applied after a newer one is stale.
//!   * CONCURRENT-PROVIDER MERGE - two DIFFERENT providers for the same key coexist;
//!     applying one never disturbs the other. A key maps to a SET of providers.
//!   * NO EXPIRED / WITHDRAWN RESURRECTION - once a slot is tombstoned (or a record
//!     lapses), only a STRICTLY NEWER assertion can re-activate it. A replay of the
//!     old record - the classic resurrection - has a stale sequence and is rejected.
//!     The tombstone's sequence floor is retained (a real DHT GCs it by TTL; that is
//!     the backend's job, and this oracle keeps the floor so the resurrection rule is
//!     testable in isolation).
//!
//! ## Handed to the backend (TASK-103) - obligations this oracle assumes, not enforces
//!
//!   * DURABLE SEQUENCE. `sequence` is provider-chosen and must be *durably* monotonic
//!     per `(key, provider)`: a provider that restarts and loses its counter emits a
//!     lower sequence and is `RejectedStale`, unable to refresh until it re-exceeds the
//!     last-seen value. TASK-103 must persist the counter (or derive it from a
//!     monotonic clock source), or a restart is a self-inflicted outage.
//!   * PER-KEY PROVIDER BOUND. This oracle bounds offers-per-record and record-bytes,
//!     but providers-per-key is UNBOUNDED here (many keypairs -> one key = a memory /
//!     flooding vector). A shipped directory needs a per-key provider cap as a DoS
//!     control; it is a backend policy number (TASK-120/103), not a frozen wire rule,
//!     so it is named here rather than encoded.

use std::collections::HashMap;
use std::collections::hash_map::Entry as MapEntry;

use crate::content::{ContentKey, ProviderRecord};
use crate::ids::NodeId;
use crate::record_codec::ProviderAssertion;

/// What [`ProviderRecordSet::apply`] did with an assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// A new or strictly-newer positive record is now the active record for the slot.
    Applied,
    /// A strictly-newer withdrawal tombstoned the slot.
    Withdrawn,
    /// The byte-identical current record was re-applied; nothing changed.
    Idempotent,
    /// The assertion's sequence was not newer than the slot's current (a replay, a
    /// stale record, or a conflicting record/withdrawal at the same sequence).
    RejectedStale { current: u64, offered: u64 },
    /// The assertion was already expired at `now` (`expiry <= now`).
    RejectedExpired { expiry: u64, now: u64 },
}

/// The current state of one `(key, provider)` slot.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Slot {
    /// A live positive record.
    Active(ProviderRecord),
    /// A withdrawal tombstone: the highest sequence seen and when the tombstone
    /// itself lapses. Retained as a monotonic floor so a replayed old record cannot
    /// resurrect the slot.
    Withdrawn { sequence: u64, expiry: u64 },
}

impl Slot {
    fn sequence(&self) -> u64 {
        match self {
            Slot::Active(r) => r.sequence,
            Slot::Withdrawn { sequence, .. } => *sequence,
        }
    }
}

/// The in-memory provider directory oracle: `key -> (provider -> slot)`. Enforces the
/// AC#3 validation rules over verified [`ProviderAssertion`]s.
#[derive(Debug, Default, Clone)]
pub struct ProviderRecordSet {
    by_key: HashMap<ContentKey, HashMap<NodeId, Slot>>,
}

impl ProviderRecordSet {
    /// A fresh empty set.
    pub fn new() -> Self {
        ProviderRecordSet::default()
    }

    /// Apply a verified assertion under the frozen rules, returning what happened.
    /// `now` is the current Unix time for the expiry gate.
    pub fn apply(&mut self, assertion: &ProviderAssertion, now: u64) -> ApplyOutcome {
        // An assertion already expired at `now` is never admitted - not as a record,
        // not as a tombstone. This is the resurrection guard's first line: a replayed
        // old record whose expiry has passed cannot even enter.
        let expiry = assertion.expiry();
        if expiry <= now {
            return ApplyOutcome::RejectedExpired { expiry, now };
        }
        let key = *assertion.key();
        let provider = *assertion.provider();
        let offered = assertion.sequence();

        let providers = self.by_key.entry(key).or_default();
        match providers.entry(provider) {
            MapEntry::Vacant(slot) => {
                // First assertion for this (key, provider).
                match assertion {
                    ProviderAssertion::Provide(record) => {
                        slot.insert(Slot::Active(record.clone()));
                        ApplyOutcome::Applied
                    }
                    ProviderAssertion::Withdraw(w) => {
                        // A withdrawal with no prior record still sets a monotonic
                        // floor, so a later replay of an old record below it is stale.
                        slot.insert(Slot::Withdrawn {
                            sequence: w.sequence,
                            expiry: w.expiry,
                        });
                        ApplyOutcome::Withdrawn
                    }
                }
            }
            MapEntry::Occupied(mut slot) => {
                let current = slot.get().sequence();
                // Same-sequence IDEMPOTENT REFRESH: re-applying the identical current
                // assertion is a no-op - for BOTH a re-announced record and a
                // re-broadcast withdrawal (a provider periodically restating its
                // current state must not be logged as a conflict). Any OTHER
                // same-sequence assertion is a genuine conflict (one sequence names one
                // state), rejected as stale.
                if offered == current {
                    return match (assertion, slot.get()) {
                        (ProviderAssertion::Provide(record), Slot::Active(existing))
                            if record == existing =>
                        {
                            ApplyOutcome::Idempotent
                        }
                        (ProviderAssertion::Withdraw(w), Slot::Withdrawn { sequence, expiry })
                            if w.sequence == *sequence && w.expiry == *expiry =>
                        {
                            ApplyOutcome::Idempotent
                        }
                        _ => ApplyOutcome::RejectedStale { current, offered },
                    };
                }
                if offered < current {
                    // Replay / stale / resurrection attempt.
                    return ApplyOutcome::RejectedStale { current, offered };
                }
                // Strictly newer: it supersedes whatever is there (active or tombstone).
                match assertion {
                    ProviderAssertion::Provide(record) => {
                        slot.insert(Slot::Active(record.clone()));
                        ApplyOutcome::Applied
                    }
                    ProviderAssertion::Withdraw(w) => {
                        slot.insert(Slot::Withdrawn {
                            sequence: w.sequence,
                            expiry: w.expiry,
                        });
                        ApplyOutcome::Withdrawn
                    }
                }
            }
        }
    }

    /// Every LIVE provider record for `key`: active, unexpired, not withdrawn. This is
    /// the concurrent-provider MERGE - all distinct providers that currently serve the
    /// key. Order is unspecified (a set), so callers must not depend on it.
    pub fn find_providers(&self, key: &ContentKey, now: u64) -> Vec<ProviderRecord> {
        let Some(providers) = self.by_key.get(key) else {
            return Vec::new();
        };
        providers
            .values()
            .filter_map(|slot| match slot {
                Slot::Active(record) if record.expiry > now => Some(record.clone()),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{NAR_HASH_LEN, PROVIDER_SIGNATURE_LEN};
    use crate::ids::{Blake3Digest, TransportOffer};
    use crate::record_codec::ProviderWithdrawal;

    fn key(seed: u8) -> ContentKey {
        ContentKey::derive_from_signed_nar_hash(&[seed; NAR_HASH_LEN])
    }
    fn provider(seed: u8) -> NodeId {
        NodeId::from_bytes([seed; 32])
    }

    // These oracle tests operate on VERIFIED assertions, so the signature is a
    // don't-care (apply never inspects it): the codec's own tests prove verification.
    fn record(k: ContentKey, p: NodeId, sequence: u64, expiry: u64) -> ProviderRecord {
        ProviderRecord {
            key: k,
            content: Blake3Digest::from_bytes([0xaa; 32]),
            provider: p,
            offers: vec![TransportOffer::Iroh { node: p }],
            sequence,
            issued_at: 0,
            expiry,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        }
    }
    fn provide(k: ContentKey, p: NodeId, sequence: u64, expiry: u64) -> ProviderAssertion {
        ProviderAssertion::Provide(record(k, p, sequence, expiry))
    }
    fn withdraw(k: ContentKey, p: NodeId, sequence: u64, expiry: u64) -> ProviderAssertion {
        ProviderAssertion::Withdraw(ProviderWithdrawal {
            key: k,
            provider: p,
            sequence,
            issued_at: 0,
            expiry,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        })
    }

    #[test]
    fn a_fresh_provide_is_applied_and_found() {
        let mut set = ProviderRecordSet::new();
        let (k, p) = (key(1), provider(1));
        assert_eq!(
            set.apply(&provide(k, p, 1, 1_000), 0),
            ApplyOutcome::Applied
        );
        let found = set.find_providers(&k, 500);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].provider, p);
    }

    #[test]
    fn monotonic_sequence_rejects_an_older_record() {
        // BITE for replay rejection + monotonic sequence: apply seq 5, then a replay
        // at seq 3 is stale and does NOT overwrite. Remove the `offered < current`
        // guard and the older record would clobber the newer one.
        let mut set = ProviderRecordSet::new();
        let (k, p) = (key(1), provider(1));
        set.apply(&provide(k, p, 5, 1_000), 0);
        assert_eq!(
            set.apply(&provide(k, p, 3, 1_000), 0),
            ApplyOutcome::RejectedStale {
                current: 5,
                offered: 3
            }
        );
        // The slot still holds seq 5's record (offers unchanged).
        assert_eq!(set.find_providers(&k, 500)[0].sequence, 5);
    }

    #[test]
    fn a_strictly_newer_record_supersedes() {
        let mut set = ProviderRecordSet::new();
        let (k, p) = (key(1), provider(1));
        set.apply(&provide(k, p, 1, 1_000), 0);
        assert_eq!(
            set.apply(&provide(k, p, 2, 2_000), 0),
            ApplyOutcome::Applied
        );
        let found = set.find_providers(&k, 1_500);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].expiry, 2_000,
            "the newer record's expiry took effect"
        );
    }

    #[test]
    fn idempotent_refresh_is_a_no_op_but_a_same_seq_conflict_is_rejected() {
        // BITE for idempotent refresh: the identical record re-applied is Idempotent;
        // a DIFFERENT record at the same sequence is RejectedStale. Remove the
        // `record == existing` arm and the identical re-apply would be reported as a
        // conflict (or, if inverted, a conflict would be silently accepted).
        let mut set = ProviderRecordSet::new();
        let (k, p) = (key(1), provider(1));
        let r = provide(k, p, 4, 1_000);
        set.apply(&r, 0);
        assert_eq!(set.apply(&r, 0), ApplyOutcome::Idempotent);
        // Same sequence, different content -> conflict.
        let mut conflicting = record(k, p, 4, 1_000);
        conflicting.content = Blake3Digest::from_bytes([0xcc; 32]);
        assert_eq!(
            set.apply(&ProviderAssertion::Provide(conflicting), 0),
            ApplyOutcome::RejectedStale {
                current: 4,
                offered: 4
            }
        );
    }

    #[test]
    fn a_signed_withdrawal_removes_the_provider() {
        // BITE for explicit withdrawal: a strictly-newer withdrawal tombstones the
        // slot so find_providers no longer returns it.
        let mut set = ProviderRecordSet::new();
        let (k, p) = (key(1), provider(1));
        set.apply(&provide(k, p, 1, 10_000), 0);
        assert_eq!(
            set.apply(&withdraw(k, p, 2, 10_000), 0),
            ApplyOutcome::Withdrawn
        );
        assert!(
            set.find_providers(&k, 500).is_empty(),
            "a withdrawn provider is not returned"
        );
    }

    #[test]
    fn an_identical_re_broadcast_withdrawal_is_idempotent() {
        // Finding #7: a provider periodically re-broadcasting its UNCHANGED withdrawal
        // (same sequence, same expiry) is a no-op, not a RejectedStale conflict.
        let mut set = ProviderRecordSet::new();
        let (k, p) = (key(1), provider(1));
        set.apply(&provide(k, p, 1, 10_000), 0);
        let w = withdraw(k, p, 2, 10_000);
        assert_eq!(set.apply(&w, 0), ApplyOutcome::Withdrawn);
        assert_eq!(
            set.apply(&w, 0),
            ApplyOutcome::Idempotent,
            "an identical re-broadcast withdrawal must be idempotent, not a conflict"
        );
        // ...but a DIFFERENT withdrawal at the same sequence is still a conflict.
        let conflicting = withdraw(k, p, 2, 20_000); // same seq, different expiry
        assert_eq!(
            set.apply(&conflicting, 0),
            ApplyOutcome::RejectedStale {
                current: 2,
                offered: 2
            }
        );
    }

    #[test]
    fn a_replayed_old_withdrawal_is_rejected() {
        // Replay rejection across kinds: after a re-announce at seq 3, replaying the
        // seq-2 withdrawal must not re-tombstone.
        let mut set = ProviderRecordSet::new();
        let (k, p) = (key(1), provider(1));
        set.apply(&provide(k, p, 1, 10_000), 0);
        set.apply(&withdraw(k, p, 2, 10_000), 0);
        set.apply(&provide(k, p, 3, 10_000), 0); // legitimate re-join, strictly newer
        assert!(!set.find_providers(&k, 500).is_empty());
        assert_eq!(
            set.apply(&withdraw(k, p, 2, 10_000), 0),
            ApplyOutcome::RejectedStale {
                current: 3,
                offered: 2
            }
        );
        assert!(
            !set.find_providers(&k, 500).is_empty(),
            "the stale withdrawal must not resurrect the tombstone"
        );
    }

    #[test]
    fn no_expired_record_resurrection() {
        // BITE for the resurrection rule: withdraw at seq 5, then replay the seq-1
        // record. It is both older (stale) AND, if we backdate its expiry, expired -
        // either way it must NOT bring the provider back.
        let mut set = ProviderRecordSet::new();
        let (k, p) = (key(1), provider(1));
        set.apply(&provide(k, p, 1, 10_000), 0);
        set.apply(&withdraw(k, p, 5, 10_000), 0);
        // Stale replay of the original record.
        assert_eq!(
            set.apply(&provide(k, p, 1, 10_000), 0),
            ApplyOutcome::RejectedStale {
                current: 5,
                offered: 1
            }
        );
        assert!(set.find_providers(&k, 500).is_empty(), "still withdrawn");
        // An already-expired assertion cannot enter at all.
        assert_eq!(
            set.apply(&provide(k, p, 9, 100), 200),
            ApplyOutcome::RejectedExpired {
                expiry: 100,
                now: 200
            }
        );
        assert!(set.find_providers(&k, 500).is_empty());
    }

    #[test]
    fn expired_records_are_not_returned() {
        // BITE for expiry: a live record stops being found once `now >= expiry`.
        let mut set = ProviderRecordSet::new();
        let (k, p) = (key(1), provider(1));
        set.apply(&provide(k, p, 1, 1_000), 0);
        assert_eq!(set.find_providers(&k, 999).len(), 1);
        assert!(
            set.find_providers(&k, 1_000).is_empty(),
            "an expired record is not returned"
        );
    }

    #[test]
    fn concurrent_providers_merge() {
        // BITE for concurrent-provider merge: two different providers for one key
        // coexist; applying one does not disturb the other, and both are returned.
        let mut set = ProviderRecordSet::new();
        let k = key(1);
        set.apply(&provide(k, provider(1), 1, 1_000), 0);
        set.apply(&provide(k, provider(2), 1, 1_000), 0);
        let found = set.find_providers(&k, 500);
        assert_eq!(found.len(), 2);
        let mut providers: Vec<_> = found.iter().map(|r| r.provider).collect();
        providers.sort();
        assert_eq!(providers, vec![provider(1), provider(2)]);

        // Withdrawing one leaves the other untouched.
        set.apply(&withdraw(k, provider(1), 2, 1_000), 0);
        let found = set.find_providers(&k, 500);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].provider, provider(2));
    }

    #[test]
    fn different_keys_are_independent() {
        let mut set = ProviderRecordSet::new();
        set.apply(&provide(key(1), provider(1), 1, 1_000), 0);
        set.apply(&provide(key(2), provider(1), 1, 1_000), 0);
        assert_eq!(set.find_providers(&key(1), 500).len(), 1);
        assert_eq!(set.find_providers(&key(2), 500).len(), 1);
        assert!(set.find_providers(&key(3), 500).is_empty());
    }
}
