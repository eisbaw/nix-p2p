//! [`FloorStore`] - the BOUNDED anti-rollback floor the directory keeps across queries
//! (TASK-176 #3). It wraps the frozen [`peer_fabric::ProviderRecordSet`] (the validation
//! oracle) with a hard entry CAP + LRU/TTL eviction, closing the memory/DoS vector
//! TASK-152 documented as an honest limit: the set never evicted, and `provider` is
//! attacker-choosable (anyone may announce under any key), so resolving attacker-chosen
//! keys grew it without bound.
//!
//! The frozen module explicitly HANDS GC to the backend ("a real DHT GCs it by TTL; that
//! is the backend's job"), so the bound lives HERE, over the store's GC primitives
//! ([`ProviderRecordSet::evict_expired`] / [`ProviderRecordSet::remove_slot`] /
//! [`ProviderRecordSet::slot_count`]), not inside the frozen oracle.
//!
//! ## The bound, and what it costs
//!
//! `slot_count()` is capped at [`DEFAULT_STORE_CAP`]. A NEW slot that would exceed the
//! cap first triggers a TTL sweep (expired slots guard nothing - the frozen decode
//! rejects any at-or-below-sequence replay of an expired record as `Stale`), then, if
//! still over, evicts the LEAST-recently-touched live slot. Evicting a live floor
//! DEGRADES that one `(key, provider)` to session-fresh - the SAME anti-rollback residue
//! a restart has (a rollback below it is not caught until the newer sequence is
//! re-observed). That residue is the price of a hard memory bound against an attacker who
//! controls keys, providers, sequences AND TTLs; a pure TTL sweep cannot bound memory
//! within the TTL window, so the hard cap + LRU is load-bearing, not decorative.

use std::collections::VecDeque;
use std::path::PathBuf;

use libp2p::PeerId;
use peer_fabric::{ContentKey, NodeId, ProviderAssertion, ProviderRecord, ProviderRecordSet};

use crate::directory::{Admitted, admit};
use crate::persist;

/// The hard cap on `(key, provider)` slots the consumer floor retains. A slot is a few
/// fixed fields plus <= 4 small offers (worst case ~324 bytes in the frozen record), so
/// 4096 slots is a few MB of headroom - generous for honest use, and a firm ceiling an
/// attacker flooding distinct keys cannot breach. It is a BACKEND policy number (not a
/// frozen wire rule), tunable here without touching the oracle.
pub const DEFAULT_STORE_CAP: usize = 4096;

/// The bounded anti-rollback floor. Wraps the frozen [`ProviderRecordSet`] and an LRU
/// order over its live slots, with OPTIONAL on-disk durability (TASK-176 #1): when a
/// `path` is configured, the floor is loaded at construction and re-flushed whenever it
/// advances, so a restarted consumer still rejects a rolled-back record.
pub struct FloorStore {
    inner: ProviderRecordSet,
    /// LRU order of the live slots, LEAST-recently-touched at the front (the eviction
    /// end). Kept in sync with `inner`: every touch moves a slot to the back, every
    /// eviction pops the front, and a TTL sweep reconciles what it dropped.
    order: VecDeque<(ContentKey, NodeId)>,
    cap: usize,
    /// The durable-floor file, or `None` for an in-memory (session-scoped) floor.
    path: Option<PathBuf>,
}

impl FloorStore {
    /// A bounded, IN-MEMORY floor at [`DEFAULT_STORE_CAP`] (no cross-restart durability).
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_STORE_CAP)
    }

    /// A bounded in-memory floor with an explicit cap (tests drive a small cap to prove
    /// the bound). A cap of 0 is nonsensical for a floor that must hold at least the slot
    /// it just admitted, so it is raised to 1.
    pub fn with_cap(cap: usize) -> Self {
        FloorStore {
            inner: ProviderRecordSet::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
            path: None,
        }
    }

    /// A bounded floor DURABLY backed by `path`: any existing floor is loaded (so a
    /// restart re-seeds its anti-rollback state), and every advance is re-flushed. Load
    /// failures degrade to an empty (session-fresh) floor and are logged, never fatal.
    pub fn durable(path: PathBuf, cap: usize) -> Self {
        let mut store = FloorStore {
            inner: ProviderRecordSet::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
            path: Some(path.clone()),
        };
        for (key, provider, floor) in persist::load_floors(&path) {
            store.inner.restore_floor(key, provider, floor);
            store.order.push_back((key, provider));
        }
        store
    }

    /// Apply one fetched, decoded `assertion` (from DHT provider `peer`) against the
    /// bounded floor, returning the live record IFF it is admitted (see [`admit`] for the
    /// per-assertion decision). Enforces the entry cap around the admit so the retained
    /// set never exceeds `cap`, and re-flushes the durable floor when it advanced.
    pub fn admit(
        &mut self,
        peer: PeerId,
        assertion: ProviderAssertion,
        now: u64,
    ) -> Option<ProviderRecord> {
        let key = *assertion.key();
        let provider = *assertion.provider();

        let Admitted {
            record,
            floor_advanced,
        } = admit(&mut self.inner, peer, assertion, now);

        // Track LRU position for whatever slot now exists at (key, provider): a fresh
        // apply created it, a refresh updated it, a spoof left a pre-existing one intact.
        // Moving it to the back (MRU) keeps a just-touched slot safe from the eviction
        // that follows.
        if self.inner.contains_slot(&key, &provider) {
            self.touch(key, provider);
        }
        let evicted = self.enforce_cap(now);
        // Persist only when the durable state actually changed: an advanced floor, or an
        // eviction that dropped a persisted slot. Idempotent refreshes and rejected
        // replays (the steady-state majority) leave the file untouched, so a busy
        // consumer is not writing on every resolve.
        if self.path.is_some() && (floor_advanced || evicted) {
            self.persist();
        }
        record
    }

    /// Move `(key, provider)` to the MRU end of the LRU order (removing any stale copy).
    /// O(n) in the retained set, which the cap keeps small, and only on a touched slot.
    fn touch(&mut self, key: ContentKey, provider: NodeId) {
        self.order.retain(|slot| *slot != (key, provider));
        self.order.push_back((key, provider));
    }

    /// Bring `slot_count` back to `<= cap`: sweep expired slots first (they guard
    /// nothing), then LRU-evict live floors from the front until under the cap. Returns
    /// whether anything was removed (so the caller knows a durable re-flush is due).
    fn enforce_cap(&mut self, now: u64) -> bool {
        if self.inner.slot_count() <= self.cap {
            return false;
        }
        let mut removed = self.inner.evict_expired(now) > 0;
        if removed {
            self.order.retain(|(k, p)| self.inner.contains_slot(k, p));
        }
        while self.inner.slot_count() > self.cap {
            match self.order.pop_front() {
                Some((k, p)) => {
                    self.inner.remove_slot(&k, &p);
                    removed = true;
                }
                // Order desynced (should not happen): nothing left to evict by LRU, so
                // stop rather than spin. The cap is still honored on the next admit.
                None => break,
            }
        }
        removed
    }

    /// Flush the full (bounded) floor to disk atomically. Called only when a `path` is
    /// set and the floor changed.
    fn persist(&self) {
        if let Some(path) = &self.path {
            persist::save_floors(path, &self.inner.export_floors());
        }
    }
}

impl Default for FloorStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::peer_id_of_provider;
    use ed25519_dalek::SigningKey;
    use peer_fabric::{Blake3Digest, TransportOffer, sign_provider_record};

    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn provider_of(sk: &SigningKey) -> NodeId {
        NodeId::from_bytes(sk.verifying_key().to_bytes())
    }
    fn peer_of(sk: &SigningKey) -> PeerId {
        peer_id_of_provider(&provider_of(sk)).expect("valid ed25519 identity")
    }
    /// A signed self-serve provide from `sk` under a DISTINCT content key per `nth`.
    fn signed_provide(sk: &SigningKey, nth: u64, sequence: u64, expiry: u64) -> ProviderAssertion {
        let provider = provider_of(sk);
        // Distinct key per index: a fresh (key, provider) slot each time.
        let key = ContentKey::derive_from_signed_nar_hash(&(nth).to_be_bytes_padded());
        let record = ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; 32]),
            provider,
            offers: vec![TransportOffer::Iroh { node: provider }],
            sequence,
            issued_at: 0,
            expiry,
            signature: [0u8; 64],
        };
        ProviderAssertion::Provide(sign_provider_record(sk, &record))
    }

    // Small helper: derive a 32-byte nar-hash from a counter.
    trait Padded {
        fn to_be_bytes_padded(self) -> [u8; 32];
    }
    impl Padded for u64 {
        fn to_be_bytes_padded(self) -> [u8; 32] {
            let mut out = [0u8; 32];
            out[24..].copy_from_slice(&self.to_be_bytes());
            out
        }
    }

    #[test]
    fn resolving_many_distinct_keys_never_exceeds_the_cap() {
        // THE #3 DoS BITE: a bounded floor with cap 4, flooded with 100 distinct
        // attacker-chosen keys (same provider - one signer). The retained set must NEVER
        // exceed the cap. Remove the enforce_cap eviction and slot_count climbs to 100 -
        // the assertion fails on the first admit past the cap.
        let mut store = FloorStore::with_cap(4);
        let sk = signer(3);
        let peer = peer_of(&sk);
        for nth in 0..100u64 {
            let admitted = store.admit(peer, signed_provide(&sk, nth, 1, 1_000_000), 0);
            assert!(admitted.is_some(), "each fresh honest record is admitted");
            assert!(
                store.inner.slot_count() <= 4,
                "the bounded floor must never exceed its cap (at nth={nth}, count={})",
                store.inner.slot_count()
            );
        }
        assert_eq!(
            store.inner.slot_count(),
            4,
            "the floor holds exactly the cap at rest"
        );
    }

    #[test]
    fn expired_slots_are_swept_before_live_floors_are_evicted() {
        // At the cap, a NEW admit first drops an EXPIRED slot (which guards nothing)
        // rather than a live floor. Seed the cap with soon-expiring slots, advance `now`
        // past them, then admit a fresh long-lived one: the sweep reclaims space so the
        // live newcomer lands and the count stays at the cap.
        let mut store = FloorStore::with_cap(2);
        let sk = signer(4);
        let peer = peer_of(&sk);
        store.admit(peer, signed_provide(&sk, 0, 1, 100), 0);
        store.admit(peer, signed_provide(&sk, 1, 1, 100), 0);
        assert_eq!(store.inner.slot_count(), 2);
        // now=200 is past both seeds' expiry; a fresh long-lived record admits.
        let admitted = store.admit(peer, signed_provide(&sk, 2, 1, 10_000), 200);
        assert!(admitted.is_some());
        assert!(store.inner.slot_count() <= 2);
    }

    #[test]
    fn a_refresh_of_an_existing_slot_does_not_grow_the_set() {
        let mut store = FloorStore::with_cap(8);
        let sk = signer(5);
        let peer = peer_of(&sk);
        store.admit(peer, signed_provide(&sk, 0, 1, 10_000), 0);
        store.admit(peer, signed_provide(&sk, 0, 2, 20_000), 0); // same key, newer seq
        assert_eq!(
            store.inner.slot_count(),
            1,
            "a refresh updates, never grows"
        );
    }

    #[test]
    fn a_durable_floor_survives_a_restart_and_still_rejects_a_rollback() {
        // THE #1 RESTART BITE: a durable store admits seq 5 (its floor advances and is
        // flushed to disk), is DROPPED (a process restart), then a fresh durable store on
        // the SAME path re-seeds the floor from disk - so a rolled-back seq-3 record is
        // still rejected. Mutation A: skip the persist() flush -> the file is empty ->
        // the restart re-seeds nothing -> seq 3 is admitted. Mutation B: skip the
        // load_floors re-seed in `durable` -> same. Either way the assertion fails.
        let path = std::env::temp_dir().join(format!(
            "nix-p2p-floor-restart-{}-{:?}.txt",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);

        let sk = signer(6);
        let peer = peer_of(&sk);

        {
            let mut store = FloorStore::durable(path.clone(), 64);
            assert!(
                store
                    .admit(peer, signed_provide(&sk, 0, 5, 1_000_000), 0)
                    .is_some(),
                "seq 5 is admitted and its floor persisted"
            );
        } // dropped == restart

        let mut restarted = FloorStore::durable(path.clone(), 64);
        // THE ROLLBACK IS TESTED FIRST, with NO re-observation this session: a seq-3
        // record is rejected PURELY by the floor re-seeded from disk. (Re-observing seq 5
        // first would rebuild the floor in-memory and mask a missing persist - the trap
        // this ordering avoids.)
        assert!(
            restarted
                .admit(peer, signed_provide(&sk, 0, 3, 1_000_000), 0)
                .is_none(),
            "a rollback below the persisted floor is rejected after a restart"
        );
        // And the current record still serves (idempotent against the restored floor).
        assert!(
            restarted
                .admit(peer, signed_provide(&sk, 0, 5, 1_000_000), 0)
                .is_some(),
            "the current record is still served after a restart"
        );

        let _ = std::fs::remove_file(&path);
    }
}
