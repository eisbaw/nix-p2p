//! TASK-100 AC#1/AC#2/AC#3 - the batch-resolution contract, exercised through the
//! `ProviderDirectory` seam with substrate-free fakes.
//!
//! Every test here is a BITE: it fails if the contract regresses in a specific,
//! named way (a dead mechanism reading as a Miss, a batch losing single-key
//! compatibility, the total deadline not producing a typed partial, latency reported
//! as anything other than a measured value).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use peer_fabric::{
    BatchResolveRequest, ContentKey, DirectoryCapabilities, DiscoveryBudget, ExposureSurface,
    FakeFabric, FakeProviderDirectory, Lookup, NodeId, ProviderDirectory, ProviderRecord,
    Recipient, ResourceOutcome, TransportOffer, Unavailable,
};
use peer_fabric::{Blake3Digest, ControlBytes, Disclosed, Exposure};

fn key(seed: u8) -> ContentKey {
    ContentKey::from_bytes([seed; 32])
}

fn provider(seed: u8) -> NodeId {
    NodeId::from_bytes([seed; 32])
}

fn record(k: ContentKey, p: NodeId) -> ProviderRecord {
    ProviderRecord {
        key: k,
        content: Blake3Digest::from_bytes([0x42; 32]),
        provider: p,
        offers: vec![TransportOffer::Iroh { node: p }],
        sequence: 1,
        issued_at: 100,
        expiry: 200,
        signature: [0u8; 64],
    }
}

fn directory(
    result: Lookup<Vec<ProviderRecord>>,
    ledger: Arc<peer_fabric::ExposureLedger>,
) -> FakeProviderDirectory {
    FakeProviderDirectory::new(result, vec![], ExposureSurface::none(), ledger)
}

// AC#1: the seam BATCH-resolves named keys to MULTIPLE holders per key, and a
// single-key batch is byte-identical to the single-key find_providers path.
#[tokio::test]
async fn batch_resolves_named_keys_to_multiple_holders_with_single_key_compat() {
    let fabric = FakeFabric::upstream_only(provider(0x01));
    let ledger = fabric.shared_ledger();

    // Key A holds TWO providers; key B is a healthy Miss.
    let a = key(0xa0);
    let b = key(0xb0);
    let both = vec![record(a, provider(0x11)), record(a, provider(0x22))];
    let dir = directory(Lookup::Miss, ledger).with_key_result(a, Lookup::Found(both.clone()));

    let request = BatchResolveRequest::new([a, b]);
    let budget = DiscoveryBudget::new(Duration::from_secs(5), 16);
    let resolution = dir.resolve_batch(&request, &budget).await;

    let pairs: Vec<_> = resolution
        .aligned_with(&request)
        .expect("aligned to the asked keys")
        .collect();
    assert_eq!(pairs.len(), 2);
    // A -> multiple holders (a Vec, not a single record).
    let holders = pairs[0].1.holders().expect("A is Found");
    assert_eq!(holders.len(), 2, "batch answer must carry MULTIPLE holders");
    assert_eq!(holders, both.as_slice());
    // B -> healthy Miss.
    assert!(pairs[1].1.is_miss());

    // Single-key compatibility: a 1-key batch == the single-key path.
    let single = BatchResolveRequest::single(a);
    let single_res = dir.resolve_batch(&single, &budget).await;
    let single_holders = single_res.outcomes()[0].holders().expect("A Found");
    let direct = dir.find_providers(&a, &budget).await;
    assert_eq!(
        Lookup::Found(single_holders.to_vec()),
        direct,
        "a single-key batch must equal the single-key find_providers answer"
    );
}

// AC#2: MISS, UNAVAILABLE(reason) and NotAttempted are typed and observable, and a
// DEAD mechanism is distinguishable from a genuine MISS. THE bite: if the default
// batch mapped Unavailable to Miss, the `is_unavailable()` assertion below reddens.
#[tokio::test]
async fn a_dead_mechanism_is_distinguishable_from_a_genuine_miss() {
    let fabric = FakeFabric::upstream_only(provider(0x02));
    let ledger = fabric.shared_ledger();

    let found = key(0x10);
    let absent = key(0x20);
    let dead = key(0x30);
    let dir = directory(Lookup::Miss, ledger)
        .with_key_result(found, Lookup::Found(vec![record(found, provider(0x99))]))
        .with_key_result(absent, Lookup::Miss)
        .with_key_result(dead, Lookup::Unavailable(Unavailable::BootstrapOutage));

    let request = BatchResolveRequest::new([found, absent, dead]);
    let resolution = dir
        .resolve_batch(&request, &DiscoveryBudget::new(Duration::from_secs(5), 16))
        .await;
    let out = resolution.outcomes();

    assert!(out[0].is_found(), "the held key is Found");
    assert!(out[1].is_miss(), "the absent key is a healthy Miss");
    assert!(
        out[2].is_unavailable(),
        "the DEAD mechanism must be Unavailable, never a Miss"
    );
    assert!(
        !out[2].is_miss(),
        "a dead/unreachable mechanism cannot silently read as nobody-has-it (AC#2)"
    );
    // The batch is PARTIAL: one key never reached an authoritative verdict.
    assert!(resolution.is_partial());
}

// AC#3: the caller's TOTAL deadline is enforced; a spent deadline yields typed
// NotAttempted keys and a DeadlineCut resource outcome - NOT a false Miss.
#[tokio::test]
async fn a_spent_total_deadline_yields_typed_partial_not_a_miss() {
    let fabric = FakeFabric::upstream_only(provider(0x03));
    let ledger = fabric.shared_ledger();
    let dir = directory(Lookup::Found(vec![record(key(1), provider(1))]), ledger);

    // A zero total deadline: nothing may be attempted.
    let request = BatchResolveRequest::new([key(1), key(2), key(3)]);
    let zero = DiscoveryBudget::new(Duration::ZERO, 16);
    let resolution = dir.resolve_batch(&request, &zero).await;

    assert!(
        resolution.outcomes().iter().all(|o| o.is_not_attempted()),
        "a spent deadline marks keys NotAttempted, never Miss (safe partial)"
    );
    assert!(
        !resolution.outcomes().iter().any(|o| o.is_miss()),
        "the deadline must not fabricate an authoritative absence"
    );
    assert_eq!(
        resolution.measurement().resource,
        ResourceOutcome::DeadlineCut
    );
    assert!(resolution.is_partial());
}

/// A directory that SLEEPS a fixed duration per key and IGNORES the budget (it never
/// checks the deadline), so it models a budget-ignoring / hostile mechanism. Used for
/// both the AC#3 "measured latency" and the AC#3 "overrun is CUT" bites.
struct SlowDirectory {
    per_key: Duration,
}

#[async_trait]
impl ProviderDirectory for SlowDirectory {
    async fn find_providers(
        &self,
        _key: &ContentKey,
        _budget: &DiscoveryBudget,
    ) -> Lookup<Vec<ProviderRecord>> {
        tokio::time::sleep(self.per_key).await;
        Lookup::Miss
    }

    fn declared_exposure(&self) -> ExposureSurface {
        ExposureSurface::none()
    }
}

// AC#3 (deadline ENFORCED, not just passed down): a budget-IGNORING adapter that
// overruns the caller's total deadline is CUT by an outer timeout - it does NOT run to
// its own completion. THE deepened bite: without the outer timeout the SlowDirectory
// sleeps the full 200ms and returns Miss (elapsed ~200ms, outcome Miss); WITH it, the
// batch returns in ~50ms with a typed DeadlineExceeded, never a false Miss.
#[tokio::test]
async fn an_overrunning_adapter_is_cut_at_the_deadline() {
    let dir = SlowDirectory {
        per_key: Duration::from_millis(200),
    };
    let request = BatchResolveRequest::single(key(0x77));
    let started = std::time::Instant::now();
    let resolution = dir
        .resolve_batch(
            &request,
            &DiscoveryBudget::new(Duration::from_millis(50), 16),
        )
        .await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(150),
        "the overrunning adapter must be CUT near the 50ms deadline, not run its full \
         200ms - took {elapsed:?}"
    );
    assert!(
        matches!(
            resolution.outcomes()[0],
            peer_fabric::KeyResolution::Unavailable(Unavailable::DeadlineExceeded)
        ),
        "a deadline-cut key is a typed DeadlineExceeded, never a false Miss - got {:?}",
        resolution.outcomes()[0]
    );
    assert_eq!(
        resolution.measurement().resource,
        ResourceOutcome::DeadlineCut
    );
    assert!(resolution.is_partial());
}

// AC#4 + round-4 blocker #1 (DIRECT non-batch path): the shipped direct callers use the
// find_providers_bound choke-point (a free function an adapter cannot override), which
// funnels through classify_lookup. A find_providers adapter that, queried for X, returns
// a record for Y (a WRONG-KEY answer) must NOT leak Y as a Found AND must NOT read as a
// false Miss - it is a backend fault, so it is Unavailable(Backend). THE bite: the old
// bind_found dropped the record to a Miss; a caller would then cache an authoritative
// absence that was really a misbehaving mechanism.
#[tokio::test]
async fn find_providers_bound_wrong_key_is_unavailable_not_miss_on_the_direct_path() {
    let fabric = FakeFabric::upstream_only(provider(0x0a));
    let ledger = fabric.shared_ledger();
    let asked = key(0x40);
    let unasked = key(0x50);
    let honest = key(0x60);
    // For `asked` the adapter answers with a record for a DIFFERENT (un-asked) key; for
    // `honest` it answers with a correctly-keyed record.
    let dir = directory(Lookup::Miss, ledger)
        .with_key_result(asked, Lookup::Found(vec![record(unasked, provider(0x99))]))
        .with_key_result(honest, Lookup::Found(vec![record(honest, provider(0x99))]));
    let budget = DiscoveryBudget::new(Duration::from_secs(5), 16);

    // The un-asked-key record does not leak AND is not a false Miss -> Unavailable(Backend).
    let bound = peer_fabric::find_providers_bound(&dir, &asked, &budget).await;
    assert!(
        matches!(bound, Lookup::Unavailable(Unavailable::Backend(_))),
        "a wrong-key answer must be Unavailable(Backend), never a false Miss - got {bound:?}"
    );
    assert!(
        !bound.is_found(),
        "the direct path must not leak un-named holdings"
    );
    assert!(
        !bound.is_miss(),
        "a wrong-key answer must never read as an authoritative absence"
    );

    // Control (not vacuous): a correctly-keyed record passes through as Found.
    let bound_ok = peer_fabric::find_providers_bound(&dir, &honest, &budget).await;
    assert!(
        bound_ok.is_found(),
        "a record keyed to the asked key is kept"
    );
}

// AC#4 + round-4 blocker #1 (default path): a mechanism that returns holders of an
// UN-ASKED key for a queried position cannot leak them - classify_lookup drops records
// not keyed to the queried key, and a set that is empty after the filter (a wrong-key
// answer) is a backend fault, NEVER a false Miss and NEVER a Found. THE bite: the old
// bind_found returned Miss, which a stop-condition/caller would trust as absence.
#[tokio::test]
async fn the_default_path_maps_an_unasked_key_answer_to_unavailable_not_miss() {
    let fabric = FakeFabric::upstream_only(provider(0x08));
    let ledger = fabric.shared_ledger();
    let asked = key(0x10);
    let unasked = key(0x20);
    // Configure the fake to answer the ASKED key with holders of a DIFFERENT (un-asked) key.
    let dir = directory(Lookup::Miss, ledger)
        .with_key_result(asked, Lookup::Found(vec![record(unasked, provider(0x99))]));

    let request = BatchResolveRequest::single(asked);
    let resolution = dir
        .resolve_batch(&request, &DiscoveryBudget::new(Duration::from_secs(5), 16))
        .await;

    assert!(
        resolution.outcomes()[0].is_unavailable(),
        "holders of an un-asked key are a backend fault (Unavailable), never a false Miss \
         or a Found - got {:?}",
        resolution.outcomes()[0]
    );
    assert!(
        !resolution.outcomes()[0].is_found(),
        "the default path must not leak un-named holdings"
    );
    assert!(
        !resolution.outcomes()[0].is_miss(),
        "a wrong-key answer must never read as an authoritative absence"
    );
    // A batch whose only key is Unavailable is not Completed (round-4 blocker #4).
    assert_eq!(
        resolution.measurement().resource,
        ResourceOutcome::MechanismDown
    );
    assert!(resolution.is_partial());
}

// AC#3: latency is a MEASURED value (integer nanoseconds), not a timeless class. A
// consultation that provably took >= 5 ms reports a latency comfortably over a 3 ms
// floor (huge margin -> robust on a loaded box). The default path honestly reports
// control bytes as NotInstrumented rather than a fabricated zero.
#[tokio::test]
async fn latency_is_a_measured_value_and_control_bytes_are_typed() {
    let dir = SlowDirectory {
        per_key: Duration::from_millis(5),
    };
    let request = BatchResolveRequest::single(key(7));
    let resolution = dir
        .resolve_batch(&request, &DiscoveryBudget::new(Duration::from_secs(5), 16))
        .await;

    let m = resolution.measurement();
    assert!(
        m.observed_latency_ns >= 3_000_000,
        "a >=5ms consultation must report a measured latency over 3ms, got {} ns",
        m.observed_latency_ns
    );
    assert_eq!(
        m.control_bytes,
        ControlBytes::NotInstrumented,
        "the default path does not see wire bytes; it must say so, not report a fake 0"
    );
    assert_eq!(m.resource, ResourceOutcome::Completed);
}

// AC#3: capabilities are declared a-priori and overridable; the default is
// conservative, a global directory declares itself global.
#[tokio::test]
async fn capabilities_are_declared_and_overridable() {
    let fabric = FakeFabric::upstream_only(provider(0x04));
    let ledger = fabric.shared_ledger();

    let plain = directory(Lookup::Miss, Arc::clone(&ledger));
    assert_eq!(plain.capabilities(), DirectoryCapabilities::conservative());
    assert!(!plain.capabilities().global);

    let global = directory(Lookup::Miss, ledger).with_capabilities(DirectoryCapabilities {
        global: true,
        batched_roundtrip: false,
        measures_latency: true,
        measures_control_bytes: false,
    });
    assert!(global.capabilities().global);
}

// AC#3 (exposure still recorded on the batch path): a batch consultation records its
// disclosure to the fabric's single ledger, once per attempted key, exactly as the
// single-key path does.
#[tokio::test]
async fn a_batch_records_its_exposure_to_the_single_ledger() {
    let fabric = FakeFabric::upstream_only(provider(0x05));
    let ledger = fabric.shared_ledger();
    let dir = FakeProviderDirectory::new(
        Lookup::Miss,
        vec![Exposure::new(Recipient::DhtNode, Disclosed::ContentKey)],
        ExposureSurface::from_exposures([Exposure::new(Recipient::DhtNode, Disclosed::ContentKey)]),
        Arc::clone(&ledger),
    );

    let request = BatchResolveRequest::new([key(1), key(2)]);
    let _ = dir
        .resolve_batch(&request, &DiscoveryBudget::new(Duration::from_secs(5), 16))
        .await;
    // One disclosure per attempted key -> two entries in the one sink.
    assert_eq!(ledger.len(), 2);
}
