//! [`Libp2pProviderDirectory`] - the kad-backed exact-key content directory (the
//! cornerstone). `find_providers` resolves a [`ContentKey`] to the signed
//! [`ProviderRecord`]s of every provider, purely through the DHT, and distinguishes a
//! healthy `Miss` from a could-not-consult `Unavailable`.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use libp2p::PeerId;
use peer_fabric::{
    ApplyOutcome, ContentKey, DirectoryCapabilities, Disclosed, DiscoveryBudget, Exposure,
    ExposureLedger, ExposureSurface, Lookup, ProviderAssertion, ProviderDirectory, ProviderRecord,
    ProviderRecordSet, Recipient, RecordDecodeError, Unavailable, decode_provider_assertion,
};

use crate::floor_store::FloorStore;
use crate::keys::{peer_id_of_provider, provider_index_key, provider_value_key};
use crate::swarm::{ProviderFanOut, QueryFail, QueryReach, SwarmHandle, absence_from_reach};

/// The kad-backed [`ProviderDirectory`]. See the crate ADR for the HYBRID mapping.
pub struct Libp2pProviderDirectory {
    handle: SwarmHandle,
    ledger: Arc<ExposureLedger>,
    /// The per-`(ContentKey, provider)` monotonic floor (TASK-152, AC#3), wired from the
    /// frozen `peer_fabric::record_store` oracle. EVERY fetched, decoded, provider-bound
    /// assertion is `apply`-ed here before it can be returned, so a replayed-old /
    /// rolled-back / stale / withdrawn record that passes the codec but LOSES to a floor
    /// this node HOLDS is never surfaced as a live provider - catching a value the DHT
    /// rolled back between two lookups by the sequence this node already saw.
    ///
    /// HONEST LIMITS (do not over-read this as global, permanent, or production-durable
    /// anti-rollback):
    ///   * THE FLOOR DOES NOT ONLY MOVE FORWARD. It is BOUNDED (TASK-176 #3): [`FloorStore`]
    ///     caps the retained slots and EVICTS by TTL/LRU. An evicted slot's floor is
    ///     FORGOTTEN, so a later replay below it is admitted again (a rollback if the
    ///     evicted floor was Active, a resurrection if it was a live tombstone) - a bounded
    ///     session-fresh residue, the price of the hard memory bound. A fail-closed bound
    ///     that never drops a live floor is TASK-188.
    ///   * SESSION-SCOPED, not global. The guarantee is "no rollback BELOW a sequence THIS
    ///     node still holds", not "no rollback the network ever saw": a fresh consumer that
    ///     never saw the newer record cannot detect a rollback to an older-but-valid one.
    ///   * CROSS-RESTART DURABILITY IS PRODUCTION-WIRED (TASK-185), gated on a state dir.
    ///     [`FloorStore`] persists the floor on disk ([`FloorStore::durable`], TASK-176 #1),
    ///     and the `daemon-libp2p` production binary routes to
    ///     [`crate::Libp2pFabric::start_durable`] whenever `--libp2p-state-dir` is configured,
    ///     so the shipped consumer RELOADS its floor on restart through the production code
    ///     path (`start_durable`, not a test-only constructor). A node started WITHOUT a state
    ///     dir keeps the session-fresh (empty-on-restart) behaviour by choice. HONEST COVERAGE
    ///     NOTE: the TASK-185 restart integration test exercises the PROVIDER announce-sequence
    ///     across a restart end to end; the CONSUMER floor RELOAD across a restart is proven by
    ///     the `FloorStore::durable` unit test (`a_durable_floor_survives_a_restart_...`), not
    ///     yet by a consumer-restart arm through `run()`.
    ///
    /// A std Mutex is fine: it is only ever held for the SYNCHRONOUS apply loop, never
    /// across an `.await` (all `get_record` fetches complete first).
    store: Mutex<FloorStore>,
}

/// The outcome of [`admit`]: the live record IFF admitted, plus whether the durable
/// floor ADVANCED (a strictly-newer positive record or a withdrawal tombstone), which is
/// the signal a persistent backend uses to decide it must re-flush its on-disk floor. An
/// idempotent refresh or a rejected replay leaves the floor unchanged, so it does not.
pub(crate) struct Admitted {
    /// The live record to return for this slot, or `None` (spoof / tombstone / lost to
    /// the floor / expired).
    pub record: Option<ProviderRecord>,
    /// Whether this admit MOVED the monotonic floor forward (persist-worthy).
    pub floor_advanced: bool,
}

/// Apply one fetched, decoded `assertion` (from the DHT provider `peer`) against the
/// durable floor and the PeerId<->provider binding, returning the live record IFF it is
/// admitted (see [`Admitted`]). `record` is `None` when the assertion is a
/// foreign-provider spoof (AC#4), a withdrawal tombstone, or LOSES to the monotonic floor
/// (replay / rollback / stale / already-expired, AC#3). PURE over `store`, so the whole
/// lifecycle decision is unit-testable without a live DHT.
pub(crate) fn admit(
    store: &mut ProviderRecordSet,
    peer: PeerId,
    assertion: ProviderAssertion,
    now: u64,
) -> Admitted {
    // AC#4: bind the signed record's provider to the index entry it was fetched under -
    // reject a peer that re-stored a THIRD party's record at its own composite key (index
    // spoofing). The forward derivation (verifying key -> PeerId) is always available.
    // Done BEFORE apply so a spoof never even reaches the durable floor.
    if peer_id_of_provider(assertion.provider()) != Some(peer) {
        tracing::warn!(
            %peer, provider = %assertion.provider(),
            "record provider does not derive to the index PeerId; \
             rejecting (possible index spoof)"
        );
        return Admitted {
            record: None,
            floor_advanced: false,
        };
    }
    match store.apply(&assertion, now) {
        // A positive record that is new/strictly-newer (Applied) or the byte-identical
        // current one re-fetched (Idempotent) is the live record for the slot. Only
        // Applied ADVANCES the floor; Idempotent leaves it byte-identical.
        outcome @ (ApplyOutcome::Applied | ApplyOutcome::Idempotent) => Admitted {
            record: match assertion {
                ProviderAssertion::Provide(record) => Some(record),
                // A withdrawal never becomes a positive record; an Idempotent re-broadcast
                // of the current tombstone stays withdrawn.
                ProviderAssertion::Withdraw(_) => None,
            },
            floor_advanced: outcome == ApplyOutcome::Applied,
        },
        ApplyOutcome::Withdrawn => {
            tracing::debug!(%peer, "provider withdrawal tombstoned the slot; not returning");
            Admitted {
                record: None,
                floor_advanced: true,
            }
        }
        ApplyOutcome::RejectedStale { current, offered } => {
            tracing::debug!(
                %peer, current, offered,
                "provider record lost to the monotonic floor \
                 (replay / rollback / stale); skipping"
            );
            Admitted {
                record: None,
                floor_advanced: false,
            }
        }
        ApplyOutcome::RejectedExpired { expiry, now } => {
            tracing::debug!(%peer, expiry, now, "provider record already expired; skipping");
            Admitted {
                record: None,
                floor_advanced: false,
            }
        }
    }
}

/// The RETRYABLE outcome for a lookup whose fan-out was TRUNCATED by the consumer `max_peers`
/// bound and yielded no live record (TASK-154 B2). This is NOT an authoritative absence: the
/// index named MORE providers than `max_peers`, we chased only the retained subset, and a
/// DISCARDED provider may have held the valid record. Returning `Miss` here would cross the
/// project TCB boundary ("a hostile/broken peer costs a retry, never a wrong answer") and would
/// poison negative caching - so a truncated-and-empty result is `Unavailable` (retryable with a
/// larger budget), never `Miss`. Carried as `Backend` (a catch-all the caller already treats as
/// non-absence) with a message that names the budget as the cause.
fn truncated_unavailable() -> Unavailable {
    Unavailable::Backend(
        "provider index named more providers than the max_peers fan-out budget; the consulted \
         subset held no live record but a discarded provider may be valid - retry with a larger \
         budget (not an authoritative absence)"
            .to_string(),
    )
}

/// Classify a GENUINELY empty provider index (the walk named nobody WE retained), a PURE
/// decision (TASK-154 B2). If nothing was discarded, defer to the near-key [`QueryReach`]
/// (Miss vs `InsufficientRouting`, TASK-174). But if the `max_peers` bound discarded EVERY
/// named provider (the degenerate `max_peers == 0` over a non-empty index), the empty fan-out
/// is NOT an authoritative absence - return the retryable outcome, never `Miss`.
fn classify_empty_index<T>(reach: QueryReach, truncated: bool) -> Lookup<T> {
    if truncated {
        Lookup::Unavailable(truncated_unavailable())
    } else {
        absence_from_reach(reach)
    }
}

/// Classify the outcome of the value-store phase (a PURE decision, unit-tested to bite
/// the Miss/Unavailable boundary the seam is built on).
///
///   * any positive record -> `Found`;
///   * no positive record but a value fetch could NOT be consulted -> `Unavailable`,
///     NEVER `Miss` (the index named providers; we simply could not fetch their
///     records - a caller must not cache this as authoritative absence);
///   * no positive record, none discarded, and every skip was HEALTHY (withdrawn / expired /
///     genuinely absent) -> `Miss`;
///   * no positive record but the fan-out was TRUNCATED by `max_peers` -> `Unavailable`
///     (TASK-154 B2): a discarded provider may have been valid, so a `Miss` would be a lie.
fn classify(
    records: Vec<ProviderRecord>,
    consult_failed: bool,
    truncated: bool,
) -> Lookup<Vec<ProviderRecord>> {
    if !records.is_empty() {
        Lookup::Found(records)
    } else if consult_failed {
        Lookup::Unavailable(Unavailable::Backend(
            "provider index named providers but their value records could not be consulted"
                .to_string(),
        ))
    } else if truncated {
        Lookup::Unavailable(truncated_unavailable())
    } else {
        Lookup::Miss
    }
}

impl Libp2pProviderDirectory {
    /// A directory driving `handle`, recording disclosures to `ledger`, with an
    /// IN-MEMORY (session-scoped) anti-rollback floor.
    pub fn new(handle: SwarmHandle, ledger: Arc<ExposureLedger>) -> Self {
        Self::with_floor(handle, ledger, FloorStore::new())
    }

    /// A directory whose anti-rollback floor is DURABLY backed by `floor_path`
    /// (TASK-176 #1): the floor is re-seeded from disk at startup and re-flushed as it
    /// advances, so a restarted consumer still rejects a rolled-back record.
    pub fn durable(
        handle: SwarmHandle,
        ledger: Arc<ExposureLedger>,
        floor_path: std::path::PathBuf,
    ) -> Self {
        Self::with_floor(
            handle,
            ledger,
            FloorStore::durable(floor_path, crate::floor_store::DEFAULT_STORE_CAP),
        )
    }

    fn with_floor(handle: SwarmHandle, ledger: Arc<ExposureLedger>, store: FloorStore) -> Self {
        Libp2pProviderDirectory {
            handle,
            ledger,
            store: Mutex::new(store),
        }
    }

    /// The two-phase resolve, WITHOUT the outer deadline (the trait method wraps this
    /// in the budget timeout). Returns the same [`Lookup`] arms.
    ///
    /// AC#3 - BootstrapOutage vs Partition (TASK-153): the [`Unavailable`] enum carries
    /// both a [`Unavailable::BootstrapOutage`] ("never entered the network") and a
    /// [`Unavailable::Partition`] ("was on the network, now cut off from the answering
    /// keyspace") reason, and the AC asks to distinguish them WHERE DETECTABLE. At THIS
    /// layer they are NOT cleanly detectable, and we deliberately do not fake the
    /// distinction:
    ///   * An empty routing table (below) is ambiguous between "bootstrap never admitted
    ///     us" (BootstrapOutage) and "we were admitted and every peer has since aged out"
    ///     (a total Partition). kad exposes only the k-bucket count, not WHY it is empty,
    ///     so we map the whole empty-routing case to `InsufficientRouting` - the honest
    ///     "not authoritative for this key" reason, and the one the cornerstone test
    ///     pins. (Where the JOIN itself fails, `SwarmHandle::join_bootstraps` returns a
    ///     join error at the connectivity layer - a stringly-typed "every bootstrap dial
    ///     failed" today, not the typed `BootstrapOutage`; that connectivity boundary is
    ///     where a bootstrap-outage signal belongs, not here on the read path. Promoting
    ///     it to the typed `Unavailable::BootstrapOutage` is a connectivity-layer
    ///     follow-up, not a read-path detection.)
    ///   * A query `Timeout` over a POPULATED table (mapped to `DeadlineExceeded` below)
    ///     is indistinguishable, at this layer, between a genuine partition, transient
    ///     congestion, and a too-tight budget. Emitting `Partition` there would MISLABEL
    ///     a slow-but-healthy network, so we do not. A real partition detector would need
    ///     reachability/connection-liveness signals this directory does not have.
    ///
    /// This is the AC's sanctioned "not distinguishable here, here is why" outcome.
    ///
    /// The Miss-vs-`InsufficientRouting` boundary is gated on TWO signals (TASK-174):
    ///
    ///   1. a cheap PRE-CHECK `routing_peers() == 0` short-circuits a TOTALLY empty
    ///      routing table to `InsufficientRouting` before issuing any query - it avoids a
    ///      doomed query and a spurious ledger disclosure; and
    ///   2. after the index query, an EMPTY provider set is classified on the NEAR-KEY
    ///      [`QueryReach`] the query actually achieved (how many peers answered the walk
    ///      toward the key), NOT on the total routing count.
    ///
    /// (2) is what raises the old TOTAL-routing bar: a node whose routing table holds
    /// only DEAD entries passes the pre-check (`routing_peers() > 0`) yet reaches nobody
    /// (`answered == 0`), so its empty result is the honest `InsufficientRouting`, not a
    /// false `Miss`. A completed query that DID reach responding peers near the key and
    /// still found no provider is classified as a `Miss` - subject to the partition /
    /// eclipse false-`Miss` limit `crate::QueryReach` documents (reaching this node's
    /// REACHABLE subgraph is not proof of reaching the key's global custodians; that
    /// residue is inherent to a single-node view and is not newly introduced here).
    async fn resolve(&self, key: &ContentKey, max_peers: u32) -> Lookup<Vec<ProviderRecord>> {
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

        // Phase 1: the multi-provider index. AC#1 CONSUMER FAN-OUT BOUND (TASK-154 B1): the
        // kad index walk AGGREGATES provider records from every peer it reaches near the key,
        // so a sybil flood (many forged provider records for one key) can name far more
        // providers than we should chase. The bound is enforced AT THE SOURCE inside the worker
        // (`retain_bounded_provider`): `get_providers` returns at most `max_peers` providers -
        // the smallest-by-RANK subset under a FRESH per-query salt (TASK-214: non-grindable and
        // self-healing across retries, NOT the fixed smallest-by-PeerId a griefer could own for a
        // chosen key) - plus a `truncated` flag telling us whether any named provider was
        // DISCARDED by the bound. So a single lookup costs a
        // bounded number of `get_record` round trips (and bounded exposure) regardless of how
        // many providers were named, and the worker's retained memory is O(max_peers), not
        // O(flood). This is the read-path complement to the store-side
        // `STORE_MAX_PROVIDERS_PER_KEY`. Integrity is untouched - every kept record is still
        // ed25519-verified downstream.
        let ProviderFanOut {
            providers,
            truncated,
            reach,
        } = match self
            .handle
            .get_providers(provider_index_key(key), max_peers)
            .await
        {
            Ok(found) => found,
            Err(QueryFail::Timeout) => return Lookup::Unavailable(Unavailable::DeadlineExceeded),
            Err(QueryFail::Backend(why)) => return Lookup::Unavailable(Unavailable::Backend(why)),
        };
        if providers.is_empty() {
            // A completed index lookup that named no provider WE retained. If nothing was
            // discarded this turns on the NEAR-KEY bar: did the walk reach a responding peer
            // near the key? (TASK-174 - Miss vs InsufficientRouting.) But if the `max_peers`
            // bound discarded EVERY named provider (the degenerate max_peers==0 over a
            // non-empty index), an empty fan-out is NOT an authoritative absence - it is
            // retryable, never a Miss (TASK-154 B2).
            return classify_empty_index(reach, truncated);
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
        {
            // Lock the durable floor for the whole SYNCHRONOUS apply loop (no `.await`
            // inside - every fetch already completed above). Each fetched assertion is
            // decoded by the FROZEN codec, then run through `admit`, which enforces the
            // PeerId<->provider binding (AC#4) and the monotonic/withdrawal/expiry floor
            // (AC#3) before it can contribute a live record.
            let mut store = self.store.lock().expect("record-store mutex poisoned");
            for (peer, outcome) in results {
                match outcome {
                    Ok(Some(bytes)) => match decode_provider_assertion(&bytes, key, now) {
                        Ok(assertion) => {
                            if let Some(record) = store.admit(peer, assertion, now) {
                                records.push(record);
                            }
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
        }

        classify(records, consult_failed, truncated)
    }
}

#[async_trait]
impl ProviderDirectory for Libp2pProviderDirectory {
    async fn find_providers(
        &self,
        key: &ContentKey,
        budget: &DiscoveryBudget,
    ) -> Lookup<Vec<ProviderRecord>> {
        // The deadline is enforced at THIS async boundary. On elapse the resolve future is
        // dropped - and now (TASK-154 S4/B3) that drop CANCELS the underlying kad query rather
        // than leaking it: `SwarmHandle::get_providers`/`get_record` hold a `CancelOnDrop`
        // guard armed for the whole `rx.await`, so dropping this future mid-wait sends the
        // query's `QueryId` on the LOSSLESS cancel channel and the worker `finish()`es the kad
        // walk instead of letting it run to its own `query_timeout` and reply into a dropped
        // receiver. If the future is dropped in the narrow window BEFORE the QueryId even
        // arrives, the worker finishes the query itself (it sees the id-reply receiver closed).
        // The fan-out bound (`budget.max_peers`) is enforced at the source inside the worker
        // (`retain_bounded_provider`) and threaded through `resolve` (see there).
        match tokio::time::timeout(budget.deadline, self.resolve(key, budget.max_peers)).await {
            Ok(lookup) => lookup,
            Err(_elapsed) => Lookup::Unavailable(Unavailable::DeadlineExceeded),
        }
    }

    fn capabilities(&self) -> DirectoryCapabilities {
        // The kad directory is GLOBAL exact-key discovery (a value store that answers
        // WITHOUT the provider online), and it measures its consultation latency (the
        // trait's default batch path times the wall clock). It resolves each key with
        // an independent kad walk under the total deadline rather than a single batched
        // wire round trip, so `batched_roundtrip` is false; it does not yet count its
        // control-plane bytes (`measures_control_bytes` false - an honest "not
        // instrumented", not a claim of zero cost).
        DirectoryCapabilities {
            global: true,
            batched_roundtrip: false,
            measures_latency: true,
            measures_control_bytes: false,
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
            classify(vec![a_record()], false, false),
            Lookup::Found(records) if records.len() == 1
        ));
        // Even if a consultation ALSO failed, a positive record is still Found.
        assert!(classify(vec![a_record()], true, false).is_found());
        // And a positive record wins even if the fan-out was truncated (we found a live one).
        assert!(classify(vec![a_record()], false, true).is_found());
    }

    #[test]
    fn classify_miss_only_when_healthy_and_empty_and_not_truncated() {
        // No records, no consultation failure, NOTHING discarded -> authoritative absence.
        // This is the only path that may return Miss (TASK-154 B2 direction (b): a genuinely
        // complete, empty lookup still returns Miss - the fix must NOT over-correct into never
        // returning Miss). The proven decentralized_discovery / record_lifecycle negative paths
        // ride exactly this: their budgets (max_peers 20/32) never truncate the handful of
        // providers they hold, so truncated is false and an un-announced key stays a Miss.
        assert!(matches!(classify(Vec::new(), false, false), Lookup::Miss));
    }

    #[test]
    fn classify_unavailable_when_consultation_failed_and_empty() {
        // An empty result that included a consultation FAILURE must be Unavailable, never Miss
        // - or a caller would cache "no provider" for content that is in the DHT. Delete the
        // `consult_failed` branch and this fails.
        match classify(Vec::new(), true, false) {
            Lookup::Unavailable(Unavailable::Backend(_)) => {}
            other => panic!("expected Unavailable(Backend), got {other:?}"),
        }
    }

    #[test]
    fn classify_unavailable_when_truncated_and_all_retained_stale() {
        // TASK-154 B2 direction (a): 17 providers, max_peers=16, the retained 16 all stale /
        // missing but a DISCARDED provider may have been valid. An empty-but-TRUNCATED result
        // must be the RETRYABLE Unavailable, NEVER an authoritative Miss (which would poison
        // negative caching and cross the TCB "a broken peer costs a retry, never a wrong
        // answer" boundary). Delete the `truncated` branch in `classify` and this returns Miss
        // and fails here.
        match classify(Vec::new(), false, true) {
            Lookup::Unavailable(Unavailable::Backend(_)) => {}
            other => panic!("truncated+empty must be retryable Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn classify_empty_index_defers_to_reach_only_when_not_truncated() {
        // The empty-INDEX decision (the walk retained no provider at all).
        //  * genuinely empty (nothing discarded) + reached a peer near the key -> Miss.
        assert!(matches!(
            classify_empty_index::<Vec<ProviderRecord>>(QueryReach { answered: 1 }, false),
            Lookup::Miss
        ));
        //  * genuinely empty + reached nobody -> InsufficientRouting (TASK-174), still not Miss.
        assert!(matches!(
            classify_empty_index::<Vec<ProviderRecord>>(QueryReach { answered: 0 }, false),
            Lookup::Unavailable(Unavailable::InsufficientRouting)
        ));
        //  * the degenerate max_peers==0 over a NON-empty index: providers empty but truncated,
        //    so NOT an authoritative absence even though the walk reached peers. This is the
        //    "max_peers=0 makes every nonempty index an instant Miss" bug (TASK-154 B2). Without
        //    the truncated guard this would be a Miss (answered>0); the guard makes it retryable.
        match classify_empty_index::<Vec<ProviderRecord>>(QueryReach { answered: 5 }, true) {
            Lookup::Unavailable(Unavailable::Backend(_)) => {}
            other => panic!("empty+truncated index must be retryable, got {other:?}"),
        }
    }

    // --- `admit` lifecycle-floor tests (TASK-152 AC#3/#4/#1-consume). Each crafts the
    // assertions a fetch would yield and drives the SAME durable `ProviderRecordSet` the
    // resolver keeps across queries, so a mutation to the guard under test changes the
    // returned record and fails the test.

    use ed25519_dalek::SigningKey;
    use peer_fabric::{
        ProviderRecordSet, ProviderWithdrawal, TransportOffer, sign_provider_record,
        sign_provider_withdrawal,
    };

    fn a_key() -> ContentKey {
        ContentKey::derive_from_signed_nar_hash(&[0x11; 32])
    }
    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn provider_of(sk: &SigningKey) -> NodeId {
        NodeId::from_bytes(sk.verifying_key().to_bytes())
    }
    /// A signed provide from `sk` over `key`, with the native self-serve libp2p offer.
    fn signed_provide(
        sk: &SigningKey,
        key: ContentKey,
        sequence: u64,
        expiry: u64,
    ) -> ProviderAssertion {
        let provider = provider_of(sk);
        let record = ProviderRecord {
            key,
            content: Blake3Digest::from_bytes([0xaa; 32]),
            provider,
            offers: vec![TransportOffer::libp2p(provider)],
            sequence,
            issued_at: 0,
            expiry,
            signature: [0u8; 64],
        };
        ProviderAssertion::Provide(sign_provider_record(sk, &record))
    }
    fn signed_withdraw(
        sk: &SigningKey,
        key: ContentKey,
        sequence: u64,
        expiry: u64,
    ) -> ProviderAssertion {
        ProviderAssertion::Withdraw(sign_provider_withdrawal(
            sk,
            &ProviderWithdrawal {
                key,
                provider: provider_of(sk),
                sequence,
                issued_at: 0,
                expiry,
                signature: [0u8; 64],
            },
        ))
    }
    fn peer_of(sk: &SigningKey) -> PeerId {
        peer_id_of_provider(&provider_of(sk)).expect("valid ed25519 identity")
    }

    #[test]
    fn admit_returns_a_fresh_provider_record() {
        let mut store = ProviderRecordSet::new();
        let sk = signer(3);
        let key = a_key();
        let admitted = admit(
            &mut store,
            peer_of(&sk),
            signed_provide(&sk, key, 1, 1_000),
            0,
        );
        assert!(admitted.floor_advanced, "a fresh record advances the floor");
        assert_eq!(admitted.record.expect("admitted").sequence, 1);
    }

    #[test]
    fn admit_rejects_a_foreign_provider_spoof() {
        // AC#4 BITE: a record legitimately signed by A, but fetched under B's index entry
        // (B re-stored A's record at B's own composite key). admit must reject it -
        // remove the peer<->provider binding and the spoofed record would be returned.
        let mut store = ProviderRecordSet::new();
        let alice = signer(3);
        let bob = signer(4);
        let key = a_key();
        let foreign = signed_provide(&alice, key, 1, 1_000); // signed by Alice
        assert!(
            admit(&mut store, peer_of(&bob), foreign, 0)
                .record
                .is_none(),
            "a third-party record stored under the wrong provider key is rejected"
        );
    }

    #[test]
    fn admit_rejects_a_replayed_or_rolled_back_record() {
        // AC#3 BITE: the durable floor advances to seq 5; a later fetch of the OLD seq-3
        // record (a replay / rollback the DHT served) loses to the floor and is not
        // returned. Remove the store.apply gate and the stale record would be returned.
        let mut store = ProviderRecordSet::new();
        let sk = signer(3);
        let peer = peer_of(&sk);
        let key = a_key();
        assert!(
            admit(&mut store, peer, signed_provide(&sk, key, 5, 1_000), 0)
                .record
                .is_some()
        );
        assert!(
            admit(&mut store, peer, signed_provide(&sk, key, 3, 1_000), 0)
                .record
                .is_none(),
            "a replayed / rolled-back older record must lose to the monotonic floor"
        );
        // And the newer record's floor persists: re-fetching seq 5 (identical) is still live.
        assert!(
            admit(&mut store, peer, signed_provide(&sk, key, 5, 1_000), 0)
                .record
                .is_some()
        );
    }

    #[test]
    fn admit_tombstones_on_withdrawal_and_blocks_resurrection() {
        // AC#1-consume + AC#3 BITE: after a fetched withdrawal (seq 2) tombstones the slot,
        // the provider is no longer returned AND a replay of the old seq-1 record cannot
        // resurrect it. Mutation: make the Withdrawn arm return the record and the
        // withdrawn provider is still Found; drop the floor and the replay resurrects.
        let mut store = ProviderRecordSet::new();
        let sk = signer(3);
        let peer = peer_of(&sk);
        let key = a_key();
        assert!(
            admit(&mut store, peer, signed_provide(&sk, key, 1, 10_000), 0)
                .record
                .is_some()
        );
        assert!(
            admit(&mut store, peer, signed_withdraw(&sk, key, 2, 10_000), 0)
                .record
                .is_none(),
            "a withdrawal is a tombstone, not a live record"
        );
        assert!(
            admit(&mut store, peer, signed_provide(&sk, key, 1, 10_000), 0)
                .record
                .is_none(),
            "a replay of the pre-withdrawal record must NOT resurrect the provider"
        );
    }

    #[test]
    fn admit_is_idempotent_on_refresh() {
        // A provider periodically re-announcing the byte-identical current record keeps
        // being returned (Idempotent -> live), not dropped as a conflict.
        let mut store = ProviderRecordSet::new();
        let sk = signer(3);
        let peer = peer_of(&sk);
        let key = a_key();
        assert!(
            admit(&mut store, peer, signed_provide(&sk, key, 4, 1_000), 0)
                .record
                .is_some()
        );
        assert!(
            admit(&mut store, peer, signed_provide(&sk, key, 4, 1_000), 0)
                .record
                .is_some(),
            "an idempotent refresh stays live"
        );
    }
}
