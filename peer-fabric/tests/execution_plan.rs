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

use async_trait::async_trait;
use peer_fabric::{
    BatchResolveRequest, ContentKey, DiscoveryBudget, ExecutionPlan, ExposureSurface, Lookup,
    MechanismId, MechanismRegistry, Parallelism, PlanExecError, ProviderDirectory, ProviderRecord,
    StopCondition,
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
