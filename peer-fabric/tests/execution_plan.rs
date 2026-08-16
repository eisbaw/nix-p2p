//! TASK-100 AC#5 - the explicit, versioned resolver execution plan, and the proof
//! that NEITHER the seam NOR the registry selects a production default before the
//! TASK-123 holdout.
//!
//! Two kinds of bite:
//!   * behavioural - the `MechanismRegistry` consults mechanisms in the caller plan's
//!     order (registration order under the baseline), honours the stop condition, and
//!     fails fast on a parallelism the baseline executor does not run; and
//!   * structural - a source guard (with a negative-mutation self-test) that the plan
//!     type exposes no `Default` and no production/cheapest/fastest/iroh-first
//!     constructor, so a production preference cannot slip in as a convenience.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use std::time::Instant;

use async_trait::async_trait;
use peer_fabric::{
    BatchResolution, BatchResolveRequest, ContentKey, DiscoveryBudget, ExecutionPlan,
    ExposureSurface, KeyResolution, Lookup, MechanismId, MechanismMeasurement, MechanismRegistry,
    Parallelism, PlanExecError, ProviderDirectory, ProviderRecord, ResourceOutcome, StopCondition,
    Unavailable,
};
use peer_fabric::{Blake3Digest, NodeId, TransportOffer};

fn key(seed: u8) -> ContentKey {
    ContentKey::from_bytes([seed; 32])
}

fn record(k: ContentKey) -> ProviderRecord {
    let p = NodeId::from_bytes([0x33; 32]);
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

/// A directory that records, into a shared log, the [`MechanismId`] it was consulted
/// under - so a test can assert the ORDER the registry consulted mechanisms in, and
/// whether a mechanism was consulted at all (the stop-condition bite).
struct RecordingDirectory {
    id: MechanismId,
    answer: Lookup<Vec<ProviderRecord>>,
    log: Arc<Mutex<Vec<MechanismId>>>,
}

#[async_trait]
impl ProviderDirectory for RecordingDirectory {
    async fn find_providers(
        &self,
        _key: &ContentKey,
        _budget: &DiscoveryBudget,
    ) -> Lookup<Vec<ProviderRecord>> {
        self.log.lock().unwrap().push(self.id);
        self.answer.clone()
    }

    fn declared_exposure(&self) -> ExposureSurface {
        ExposureSurface::none()
    }
}

fn budget() -> DiscoveryBudget {
    DiscoveryBudget::new(Duration::from_secs(5), 16)
}

// AC#5: the registry consults mechanisms in REGISTRATION order under the baseline
// plan - it expresses no preference of its own. THE bite: a registry that reshuffled
// by a hardcoded cost/preference would consult them in a different order, flipping the
// recorded order below.
#[tokio::test]
async fn the_registry_consults_in_registration_order_under_the_baseline() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let k = key(1);
    let mut registry = MechanismRegistry::new();
    registry
        .register(
            MechanismId::GlobalDirectory,
            Arc::new(RecordingDirectory {
                id: MechanismId::GlobalDirectory,
                answer: Lookup::Miss,
                log: Arc::clone(&log),
            }),
        )
        .register(
            MechanismId::DirectHoldQuery,
            Arc::new(RecordingDirectory {
                id: MechanismId::DirectHoldQuery,
                answer: Lookup::Found(vec![record(k)]),
                log: Arc::clone(&log),
            }),
        );

    let request = BatchResolveRequest::single(k);
    let resolution = registry
        .resolve(&request, &budget(), &ExecutionPlan::fixed_baseline_v1())
        .await
        .expect("the baseline plan is executable");

    // Registration order, not a preference reshuffle.
    assert_eq!(
        *log.lock().unwrap(),
        vec![MechanismId::GlobalDirectory, MechanismId::DirectHoldQuery]
    );
    // The second mechanism held the key; the batch resolves it.
    assert!(resolution.outcomes()[0].is_found());
}

// AC#5: FirstHolder stops as soon as a holder is found - the first mechanism answering
// Found means the second is never consulted (bite: a plan ignoring the stop condition
// would consult both).
#[tokio::test]
async fn first_holder_stops_at_the_first_answering_mechanism() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let k = key(2);
    let mut registry = MechanismRegistry::new();
    registry
        .register(
            MechanismId::GlobalDirectory,
            Arc::new(RecordingDirectory {
                id: MechanismId::GlobalDirectory,
                answer: Lookup::Found(vec![record(k)]),
                log: Arc::clone(&log),
            }),
        )
        .register(
            MechanismId::DirectHoldQuery,
            Arc::new(RecordingDirectory {
                id: MechanismId::DirectHoldQuery,
                answer: Lookup::Found(vec![record(k)]),
                log: Arc::clone(&log),
            }),
        );

    let request = BatchResolveRequest::single(k);
    let _ = registry
        .resolve(&request, &budget(), &ExecutionPlan::fixed_baseline_v1())
        .await
        .unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec![MechanismId::GlobalDirectory],
        "FirstHolder must not consult the second mechanism once the key is held"
    );
}

// AC#5: an EXPLICIT caller ordering is honoured verbatim - the preference is the
// caller's, named in the plan, never invented by the registry.
#[tokio::test]
async fn an_explicit_caller_order_is_honoured() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let k = key(3);
    let mut registry = MechanismRegistry::new();
    registry
        .register(
            MechanismId::GlobalDirectory,
            Arc::new(RecordingDirectory {
                id: MechanismId::GlobalDirectory,
                answer: Lookup::Miss,
                log: Arc::clone(&log),
            }),
        )
        .register(
            MechanismId::DirectHoldQuery,
            Arc::new(RecordingDirectory {
                id: MechanismId::DirectHoldQuery,
                answer: Lookup::Miss,
                log: Arc::clone(&log),
            }),
        );

    // Ask in the REVERSE of registration order, explicitly.
    let plan = ExecutionPlan::with_explicit_order(vec![
        MechanismId::DirectHoldQuery,
        MechanismId::GlobalDirectory,
    ]);
    let request = BatchResolveRequest::single(k);
    let _ = registry.resolve(&request, &budget(), &plan).await.unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec![MechanismId::DirectHoldQuery, MechanismId::GlobalDirectory],
        "the caller's explicit order must be consulted verbatim"
    );
}

// AC#5: the baseline executor RUNS ONLY Sequential plans - a parallelism it does not
// execute is refused BY NAME (fail-fast), never silently run as sequential. The plan
// can EXPRESS a fan-out (a caller choice); the baseline refuses to run it.
#[tokio::test]
async fn a_non_sequential_plan_is_refused_not_silently_degraded() {
    let registry = MechanismRegistry::new();
    let request = BatchResolveRequest::single(key(4));
    let fanout = ExecutionPlan::fixed_baseline_v1()
        .with_parallelism(Parallelism::BoundedFanout { max_concurrent: 4 });
    let refused = registry.resolve(&request, &budget(), &fanout).await;
    assert_eq!(
        refused,
        Err(PlanExecError::UnsupportedParallelism(
            Parallelism::BoundedFanout { max_concurrent: 4 }
        )),
        "a fan-out must be refused by name, not silently degraded to sequential"
    );
}

// AC#5: the stop condition is a property of the caller's PLAN, not the registry. Under
// AllMechanisms the registry consults EVERY mechanism even after a holder is found
// (the diagnostic mode), where FirstHolder would have stopped at the first.
#[tokio::test]
async fn the_stop_condition_comes_from_the_plan_not_the_registry() {
    let k = key(5);
    let make_registry = |log: &Arc<Mutex<Vec<MechanismId>>>| {
        let mut registry = MechanismRegistry::new();
        registry
            .register(
                MechanismId::GlobalDirectory,
                Arc::new(RecordingDirectory {
                    id: MechanismId::GlobalDirectory,
                    answer: Lookup::Found(vec![record(k)]),
                    log: Arc::clone(log),
                }),
            )
            .register(
                MechanismId::DirectHoldQuery,
                Arc::new(RecordingDirectory {
                    id: MechanismId::DirectHoldQuery,
                    answer: Lookup::Miss,
                    log: Arc::clone(log),
                }),
            );
        registry
    };
    let request = BatchResolveRequest::single(k);

    // FirstHolder: stop at the first mechanism that answers Found.
    let first_log = Arc::new(Mutex::new(Vec::new()));
    let _ = make_registry(&first_log)
        .resolve(&request, &budget(), &ExecutionPlan::fixed_baseline_v1())
        .await
        .unwrap();
    assert_eq!(
        *first_log.lock().unwrap(),
        vec![MechanismId::GlobalDirectory]
    );

    // AllMechanisms: consult BOTH, even though the first already held the key.
    let all_log = Arc::new(Mutex::new(Vec::new()));
    let all_plan = ExecutionPlan::fixed_baseline_v1().with_stop(StopCondition::AllMechanisms);
    let _ = make_registry(&all_log)
        .resolve(&request, &budget(), &all_plan)
        .await
        .unwrap();
    assert_eq!(
        *all_log.lock().unwrap(),
        vec![MechanismId::GlobalDirectory, MechanismId::DirectHoldQuery],
        "AllMechanisms must consult every mechanism (the stop comes from the plan)"
    );
}

/// A directory that IGNORES the budget entirely: its resolve_batch sleeps past any
/// deadline before answering, so ONLY the registry's own outer timeout can cut it (its
/// own default per-key timeout is bypassed by the override). This is what forces the
/// registry deadline-cut path (not the mechanism's inner timeout).
struct OverrunDirectory;

#[async_trait]
impl ProviderDirectory for OverrunDirectory {
    async fn find_providers(
        &self,
        _key: &ContentKey,
        _budget: &DiscoveryBudget,
    ) -> Lookup<Vec<ProviderRecord>> {
        Lookup::Miss
    }
    async fn resolve_batch(
        &self,
        request: &BatchResolveRequest,
        _budget: &DiscoveryBudget,
    ) -> BatchResolution {
        // Budget-ignoring overrun: sleep well past any caller deadline, THEN answer.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let outcomes = request.keys().iter().map(|_| KeyResolution::Miss).collect();
        BatchResolution::for_request(
            request,
            outcomes,
            MechanismMeasurement::completed_unmetered(0),
        )
        .expect("Miss outcomes carry no keys")
    }
    fn declared_exposure(&self) -> ExposureSurface {
        ExposureSurface::none()
    }
}

/// A directory that overrides resolve_batch to return NotAttempted for EVERY asked key
/// (a mechanism that did not authoritatively answer), so a cross-mechanism
/// NotAttempted+Miss can be exercised through the registry.
struct NotAttemptedDirectory;

#[async_trait]
impl ProviderDirectory for NotAttemptedDirectory {
    async fn find_providers(
        &self,
        _key: &ContentKey,
        _budget: &DiscoveryBudget,
    ) -> Lookup<Vec<ProviderRecord>> {
        Lookup::Miss // unused (resolve_batch is overridden)
    }
    async fn resolve_batch(
        &self,
        request: &BatchResolveRequest,
        _budget: &DiscoveryBudget,
    ) -> BatchResolution {
        let outcomes = request
            .keys()
            .iter()
            .map(|_| KeyResolution::NotAttempted)
            .collect();
        BatchResolution::for_request(
            request,
            outcomes,
            MechanismMeasurement::completed_unmetered(0),
        )
        .expect("NotAttempted outcomes carry no keys, so binding trivially holds")
    }
    fn declared_exposure(&self) -> ExposureSurface {
        ExposureSurface::none()
    }
}

// AC#3 (BLOCKER, REGISTRY path — codex): a registry deadline-cut marks every still-pending
// key Unavailable(DeadlineExceeded), NEVER a false Miss, and the batch is not Completed.
// A earlier bite only exercised the default resolve_batch; this exercises MechanismRegistry:
// mechanism A Misses fast, mechanism B overruns -> the keys A Missed become Unavailable
// (DeadlineExceeded) because B never authoritatively answered before the cut.
#[tokio::test]
async fn the_registry_deadline_cut_marks_pending_keys_unavailable_not_miss() {
    let k1 = key(0x71);
    let k2 = key(0x72);
    let mut registry = MechanismRegistry::new();
    registry
        // A: Misses both keys quickly.
        .register(
            MechanismId::GlobalDirectory,
            Arc::new(RecordingDirectory {
                id: MechanismId::GlobalDirectory,
                answer: Lookup::Miss,
                log: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        // B: overruns the deadline for the still-pending keys.
        .register(MechanismId::DirectHoldQuery, Arc::new(OverrunDirectory));

    let started = Instant::now();
    let res = registry
        .resolve(
            &BatchResolveRequest::new([k1, k2]),
            &DiscoveryBudget::new(std::time::Duration::from_millis(100), 16),
            &ExecutionPlan::fixed_baseline_v1(),
        )
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed < std::time::Duration::from_millis(300),
        "the registry must be CUT near the 100ms deadline, not run B's 400ms - took {elapsed:?}"
    );
    for (i, o) in res.outcomes().iter().enumerate() {
        assert!(
            matches!(o, KeyResolution::Unavailable(Unavailable::DeadlineExceeded)),
            "key {i} must be Unavailable(DeadlineExceeded) after a cut, not a false Miss - got {o:?}"
        );
    }
    assert!(!res.is_complete(), "a deadline-cut batch is not Completed");
    assert_eq!(res.measurement().resource, ResourceOutcome::DeadlineCut);
}

// AC#2 (BLOCKER, generalized, REGISTRY path — codex): a key that mechanism A did NOT
// authoritatively answer (NotAttempted) plus a genuine Miss from B is NOT an
// authoritative Miss - it stays partial. THE bite the rank fold failed (Miss ranked
// above NotAttempted): the key collapsed to Miss/Completed.
#[tokio::test]
async fn a_not_attempted_plus_miss_across_mechanisms_is_not_a_miss() {
    let k = key(0x73);
    let mut registry = MechanismRegistry::new();
    registry
        // A: does not authoritatively answer (NotAttempted).
        .register(
            MechanismId::GlobalDirectory,
            Arc::new(NotAttemptedDirectory),
        )
        // B: genuinely Misses.
        .register(
            MechanismId::DirectHoldQuery,
            Arc::new(RecordingDirectory {
                id: MechanismId::DirectHoldQuery,
                answer: Lookup::Miss,
                log: Arc::new(Mutex::new(Vec::new())),
            }),
        );

    let res = registry
        .resolve(
            &BatchResolveRequest::single(k),
            &budget(),
            &ExecutionPlan::fixed_baseline_v1(),
        )
        .await
        .unwrap();

    assert!(
        !res.outcomes()[0].is_miss(),
        "NotAttempted(A) + Miss(B) is NOT an authoritative Miss - got {:?}",
        res.outcomes()[0]
    );
    assert!(
        !res.outcomes()[0].is_authoritative(),
        "the key is partial (not authoritatively resolved), not Completed"
    );
    assert!(!res.is_complete());
}

// AC#2 (deepened, registry precedence): a mechanism that is DEAD for key X is NEVER
// overwritten into a Miss by a later mechanism that genuinely Misses X. THE bite: the
// old max-authoritative fold let global=Unavailable(X) + tracker=Miss(X) collapse to
// X=Miss, is_complete()=true, resource=Completed - exactly the dead->Miss defect codex
// found. Now X stays Unavailable, the batch is partial, resource=MechanismDown.
#[tokio::test]
async fn a_dead_mechanism_for_a_key_is_not_overwritten_by_a_later_miss() {
    let x = key(0x51);
    let y = key(0x52);
    let mut registry = MechanismRegistry::new();
    registry
        // global: dead for BOTH keys (Unavailable).
        .register(
            MechanismId::GlobalDirectory,
            Arc::new(RecordingDirectory {
                id: MechanismId::GlobalDirectory,
                answer: Lookup::Unavailable(Unavailable::BootstrapOutage),
                log: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        // tracker: genuinely Misses everything.
        .register(
            MechanismId::Tracker,
            Arc::new(RecordingDirectory {
                id: MechanismId::Tracker,
                answer: Lookup::Miss,
                log: Arc::new(Mutex::new(Vec::new())),
            }),
        );

    let res = registry
        .resolve(
            &BatchResolveRequest::new([x, y]),
            &budget(),
            // AllMechanisms so both mechanisms are consulted for every key.
            &ExecutionPlan::fixed_baseline_v1().with_stop(StopCondition::AllMechanisms),
        )
        .await
        .unwrap();

    assert!(
        res.outcomes()[0].is_unavailable(),
        "key X must stay Unavailable (dead mechanism), NOT be overwritten to Miss - got {:?}",
        res.outcomes()[0]
    );
    assert!(
        !res.outcomes()[0].is_miss(),
        "a dead-for-X mechanism must never read as a Miss (AC#2)"
    );
    assert!(
        !res.is_complete(),
        "a batch with an Unavailable is not Completed"
    );
    assert_eq!(res.measurement().resource, ResourceOutcome::MechanismDown);
}

// AC#3/#5: the registry's reported `resource` is a REAL event, consistent with
// is_complete()/is_partial() - not inferred from verdict flags (mped-architect #2).
// Three pinned cases: spent budget -> DeadlineCut; clean all-Miss -> Completed; a
// healthy mixed Found+Unavailable envelope with budget to spare -> MechanismDown
// (NOT a false DeadlineCut).
#[tokio::test]
async fn the_registry_resource_outcome_reflects_the_real_envelope() {
    let k = key(6);

    // (a) A spent total deadline with a mechanism present -> DeadlineCut, all NotAttempted.
    let mut spent = MechanismRegistry::new();
    spent.register(
        MechanismId::GlobalDirectory,
        Arc::new(RecordingDirectory {
            id: MechanismId::GlobalDirectory,
            answer: Lookup::Found(vec![record(k)]),
            log: Arc::new(Mutex::new(Vec::new())),
        }),
    );
    let zero = DiscoveryBudget::new(Duration::ZERO, 16);
    let res = spent
        .resolve(
            &BatchResolveRequest::single(k),
            &zero,
            &ExecutionPlan::fixed_baseline_v1(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.measurement().resource,
        ResourceOutcome::DeadlineCut,
        "a spent budget must be DeadlineCut, not a false Completed"
    );
    assert!(res.is_partial());

    // (b) A clean all-Miss consultation with budget to spare -> Completed.
    let mut clean = MechanismRegistry::new();
    clean.register(
        MechanismId::GlobalDirectory,
        Arc::new(RecordingDirectory {
            id: MechanismId::GlobalDirectory,
            answer: Lookup::Miss,
            log: Arc::new(Mutex::new(Vec::new())),
        }),
    );
    let res = clean
        .resolve(
            &BatchResolveRequest::single(k),
            &budget(),
            &ExecutionPlan::fixed_baseline_v1(),
        )
        .await
        .unwrap();
    assert_eq!(res.measurement().resource, ResourceOutcome::Completed);
    assert!(res.is_complete());

    // (c) A mixed Found + Unavailable envelope, budget to spare -> MechanismDown, NOT a
    // false DeadlineCut (no deadline event occurred). One mechanism Founds A and is
    // Unavailable for B, so the aggregate has an authoritative Found AND a live
    // Unavailable with the envelope intact.
    let a = key(0x61);
    let b = key(0x62);
    let mut mixed = MechanismRegistry::new();
    mixed.register(
        MechanismId::GlobalDirectory,
        Arc::new(KeyedDirectory {
            found_key: a,
            record: record(a),
        }),
    );
    let res = mixed
        .resolve(
            &BatchResolveRequest::new([a, b]),
            &budget(),
            &ExecutionPlan::fixed_baseline_v1(),
        )
        .await
        .unwrap();
    assert!(res.outcomes()[0].is_found(), "A is Found");
    assert!(res.outcomes()[1].is_unavailable(), "B stayed Unavailable");
    assert_eq!(
        res.measurement().resource,
        ResourceOutcome::MechanismDown,
        "a healthy mixed envelope with a down mechanism is MechanismDown, not DeadlineCut"
    );
}

/// A directory that Founds exactly one key and is Unavailable for every other key - so
/// a mixed Found+Unavailable aggregate can be built deterministically without a
/// deadline event.
struct KeyedDirectory {
    found_key: ContentKey,
    record: ProviderRecord,
}

#[async_trait]
impl ProviderDirectory for KeyedDirectory {
    async fn find_providers(
        &self,
        key: &ContentKey,
        _budget: &DiscoveryBudget,
    ) -> Lookup<Vec<ProviderRecord>> {
        if *key == self.found_key {
            Lookup::Found(vec![self.record.clone()])
        } else {
            Lookup::Unavailable(Unavailable::BootstrapOutage)
        }
    }

    fn declared_exposure(&self) -> ExposureSurface {
        ExposureSurface::none()
    }
}

// AC#5 (finding #1): an Explicit plan naming an UNREGISTERED mechanism does not abort -
// the registry consults the mechanisms it does hold, skipping the unknown one (which is
// surfaced on stderr, not silently ignored in the result).
#[tokio::test]
async fn an_unknown_mechanism_in_an_explicit_plan_is_skipped_not_fatal() {
    let k = key(9);
    let mut registry = MechanismRegistry::new();
    registry.register(
        MechanismId::GlobalDirectory,
        Arc::new(RecordingDirectory {
            id: MechanismId::GlobalDirectory,
            answer: Lookup::Found(vec![record(k)]),
            log: Arc::new(Mutex::new(Vec::new())),
        }),
    );
    // The plan names Tracker (not registered) then GlobalDirectory (registered).
    let plan = ExecutionPlan::with_explicit_order(vec![
        MechanismId::Tracker,
        MechanismId::GlobalDirectory,
    ]);
    let res = registry
        .resolve(&BatchResolveRequest::single(k), &budget(), &plan)
        .await
        .expect("an unknown mechanism is non-fatal");
    assert!(
        res.outcomes()[0].is_found(),
        "the registered mechanism still resolves the key; the unknown id is skipped"
    );
}

// Round-4 blocker #2 (REGISTRY path): an Explicit plan naming an UNREGISTERED mechanism
// must NOT be silently dropped and let another mechanism's Miss finalize as an
// authoritative absence. The unregistered mechanism did NOT answer, so it might have held
// the key: a key the registered mechanism only Missed becomes Unavailable, the batch is
// partial, and the resource is MechanismDown - never a Miss/Completed. THE bite: dropping
// the unknown mechanism (the pre-redesign behaviour) leaves the key a clean Miss and the
// batch Completed, so both assertions redden.
#[tokio::test]
async fn an_unregistered_planned_mechanism_blocks_an_authoritative_miss() {
    let k = key(0x81);
    let mut registry = MechanismRegistry::new();
    // Only GlobalDirectory is registered, and it genuinely Misses the key.
    registry.register(
        MechanismId::GlobalDirectory,
        Arc::new(RecordingDirectory {
            id: MechanismId::GlobalDirectory,
            answer: Lookup::Miss,
            log: Arc::new(Mutex::new(Vec::new())),
        }),
    );
    // The plan names GlobalDirectory (registered, Miss) THEN Tracker (NOT registered).
    let plan = ExecutionPlan::with_explicit_order(vec![
        MechanismId::GlobalDirectory,
        MechanismId::Tracker,
    ]);

    let res = registry
        .resolve(&BatchResolveRequest::single(k), &budget(), &plan)
        .await
        .expect("an unknown mechanism is non-fatal to execution");

    assert!(
        res.outcomes()[0].is_unavailable(),
        "a key the registered mechanism Missed, with a PLANNED mechanism that could not be \
         consulted, is NOT an authoritative Miss - got {:?}",
        res.outcomes()[0]
    );
    assert!(
        !res.outcomes()[0].is_miss(),
        "the un-consulted planned mechanism might have held the key; the Miss is not authoritative"
    );
    assert!(!res.is_complete(), "the batch is partial, not Completed");
    assert_eq!(res.measurement().resource, ResourceOutcome::MechanismDown);
}

// The control for the blocker above (not vacuous): when the registered mechanism FINDS
// the key, the un-consulted planned mechanism is irrelevant (FirstHolder already stopped),
// so the key stays Found - the phantom-mechanism taint must not clobber a real Found.
#[tokio::test]
async fn an_unregistered_planned_mechanism_does_not_clobber_a_found() {
    let k = key(0x82);
    let mut registry = MechanismRegistry::new();
    registry.register(
        MechanismId::GlobalDirectory,
        Arc::new(RecordingDirectory {
            id: MechanismId::GlobalDirectory,
            answer: Lookup::Found(vec![record(k)]),
            log: Arc::new(Mutex::new(Vec::new())),
        }),
    );
    let plan = ExecutionPlan::with_explicit_order(vec![
        MechanismId::GlobalDirectory,
        MechanismId::Tracker,
    ]);
    let res = registry
        .resolve(&BatchResolveRequest::single(k), &budget(), &plan)
        .await
        .unwrap();
    assert!(
        res.outcomes()[0].is_found(),
        "a real Found must survive the un-consulted-planned-mechanism taint - got {:?}",
        res.outcomes()[0]
    );
    assert!(res.is_complete(), "an all-Found batch is Completed");
}

// AC#5 STRUCTURAL: the plan type exposes NO production default. A source guard over
// resolve.rs, with a negative-mutation self-test proving it BITES.
const RESOLVE_SRC: &str = include_str!("../src/resolve.rs");

/// The forbidden shapes: a `Default` for the plan, or a constructor that would present
/// a production preference. Matching is on the plan's own type/impl surface.
fn forbidden_plan_default_hits(src: &str) -> Vec<String> {
    // Only look at NON-comment lines, so the docs (which discuss "no production
    // default", "cheapest_first", "iroh_first" by name to explain their ABSENCE) do
    // not trip the scan.
    let code: String = src
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let needles = [
        (
            "impl Default for ExecutionPlan",
            "a Default plan is a hidden production default",
        ),
        (
            "fn production",
            "a production() constructor presents a production default",
        ),
        (
            "fn cheapest",
            "a cheapest-first constructor is a hardcoded preference",
        ),
        (
            "fn fastest",
            "a fastest-first constructor is a hardcoded preference",
        ),
        (
            "fn iroh_first",
            "an iroh-first constructor is a hardcoded preference",
        ),
        (
            "fn default_plan",
            "a default_plan() constructor is a production default",
        ),
    ];
    let mut hits = Vec::new();
    for (needle, why) in needles {
        if code.contains(needle) {
            hits.push(format!("{needle:?}: {why}"));
        }
    }
    hits
}

#[test]
fn the_plan_type_exposes_no_production_default() {
    let hits = forbidden_plan_default_hits(RESOLVE_SRC);
    assert!(
        hits.is_empty(),
        "resolve.rs must present NO production default (AC#5); found:\n  {}",
        hits.join("\n  ")
    );
}

#[test]
fn the_no_production_default_guard_bites() {
    // Negative mutation: source that ADDS a Default plan / a cheapest-first ctor MUST
    // be flagged, or the guard proves nothing.
    let hostile = r#"
        impl Default for ExecutionPlan {
            fn default() -> Self { ExecutionPlan::fixed_baseline_v1() }
        }
        impl ExecutionPlan {
            pub fn cheapest_first() -> Self { ExecutionPlan::fixed_baseline_v1() }
        }
    "#;
    let hits = forbidden_plan_default_hits(hostile);
    assert!(
        hits.iter()
            .any(|h| h.contains("impl Default for ExecutionPlan")),
        "the guard must catch an added Default plan"
    );
    assert!(
        hits.iter().any(|h| h.contains("fn cheapest")),
        "the guard must catch a cheapest-first constructor"
    );
    // The control: the REAL source, whose comments mention these names to explain
    // their absence, must NOT trip (proven by the sibling test passing).
    assert!(forbidden_plan_default_hits(RESOLVE_SRC).is_empty());
}
