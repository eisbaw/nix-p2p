//! The BATCH content-resolution contract and the resolver EXECUTION PLAN (TASK-100).
//!
//! This module hardens the `ProviderDirectory` seam from a single-key/single-answer
//! consultation into a mechanism-neutral discovery domain boundary, without changing
//! any frozen wire format. It carries four contract pieces, one per acceptance
//! criterion:
//!
//!   * **Batch resolution (AC#1/AC#2/AC#4).** [`BatchResolveRequest`] names the keys
//!     the asker already possesses; [`BatchResolution`] answers POSITIONALLY over
//!     exactly those keys, one [`KeyResolution`] each, carrying NO keys of its own.
//!     Each key's outcome is TYPED - a healthy [`KeyResolution::Found`] holder set, a
//!     healthy authoritative [`KeyResolution::Miss`], a [`KeyResolution::Unavailable`]
//!     mechanism failure (a dead mechanism can NEVER read as nobody-has-it), or a
//!     [`KeyResolution::NotAttempted`] key the total deadline was spent before reaching
//!     (the PARTIAL marker).
//!   * **Measurement, not a class (AC#3).** [`MechanismMeasurement`] reports the
//!     OBSERVED integer-nanosecond latency, the control bytes (a typed
//!     [`ControlBytes`] - measured or honestly not-instrumented, never a fabricated
//!     zero), and the [`ResourceOutcome`], alongside a-priori [`DirectoryCapabilities`].
//!     There are NO floats anywhere here: latency is `u64` ns, bytes are `u64`.
//!   * **Explicit versioned execution plan, no production default (AC#5).**
//!     [`ExecutionPlan`] is the caller-supplied, versioned policy that names mechanism
//!     ordering, parallelism and stop condition. It has NO `Default` and NO production
//!     constructor; the ONLY plan available before the TASK-123 holdout is the
//!     [`ExecutionPlan::fixed_baseline_v1`] NAMED BASELINE, which encodes NO
//!     cheapest-first / Iroh-first / fastest-first preference. The [`MechanismRegistry`]
//!     that consults several mechanisms REQUIRES a plan and never picks one itself.
//!
//! ## Why a positional batch is not a listing (the structural no-enumeration invariant)
//!
//! The PRD privacy invariant is "a peer cannot be asked what it holds". A
//! [`BatchResolution`] looks superficially like a listing (a vector of answers), but it
//! is not one BY CONSTRUCTION: it is positional over the asker's own
//! [`BatchResolveRequest`] keys and carries no key of its own, so detached from the
//! request an answer is a bare typed outcome about nothing. The ONLY way to read it is
//! [`BatchResolution::aligned_with`], which pairs each answer back to the key the ASKER
//! named and fails fast on any count mismatch. There is deliberately NO method that
//! returns holdings the caller did not name; `tests/no_enumeration_seam.rs` is the
//! structural guard, with a negative-mutation self-test that a synthetic `list_all`
//! affordance is rejected.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::content::{ContentKey, ProviderRecord};
use crate::outcome::Unavailable;

// -------------------------------------------------------------------------
// AC#1/AC#4 - the positional, asker-named batch request.
// -------------------------------------------------------------------------

/// The keys an asker wants resolved, in the asker's order. This is the WHOLE input
/// to a batch resolution: a responder can answer only about keys named here, so a
/// batch can never be an inventory request (AC#4, structural).
///
/// It mirrors [`PeerHoldRequest`](crate::PeerHoldRequest) on the direct-probe axis:
/// the answer is POSITIONAL over exactly these keys and carries no keys of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchResolveRequest {
    /// The content keys being resolved, in the asker's order. The
    /// [`BatchResolution`] is aligned to THIS order and has THIS length.
    keys: Vec<ContentKey>,
}

impl BatchResolveRequest {
    /// A request naming `keys` (the asker's own keys; there is no "everything" form).
    pub fn new(keys: impl IntoIterator<Item = ContentKey>) -> Self {
        BatchResolveRequest {
            keys: keys.into_iter().collect(),
        }
    }

    /// A single-key request - the compatibility bridge that lets the batch contract
    /// subsume the single-key [`find_providers`](crate::ProviderDirectory::find_providers)
    /// path without a second shape (AC#1).
    pub fn single(key: ContentKey) -> Self {
        BatchResolveRequest { keys: vec![key] }
    }

    /// The keys asked, in order. Read-only: a request is an immutable statement of
    /// what the asker named.
    pub fn keys(&self) -> &[ContentKey] {
        &self.keys
    }

    /// How many keys were asked.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key was asked (an empty batch resolves to an empty resolution).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// -------------------------------------------------------------------------
// AC#2 - the typed per-key outcome.
// -------------------------------------------------------------------------

/// One positional answer inside a [`BatchResolution`]: the mechanism's TYPED verdict
/// about the key at the SAME index in the [`BatchResolveRequest`]. It deliberately
/// does NOT carry the key it answers - that is what keeps a batch from being a listing
/// (AC#4): detached from the request it is a bare outcome.
///
/// The four variants are the AC#2 distinctions, each observable and non-collapsible:
/// a dead or unreachable mechanism ([`Unavailable`](KeyResolution::Unavailable)) can
/// NEVER be read as an authoritative "nobody has it" ([`Miss`](KeyResolution::Miss)),
/// and a key the total deadline was spent before reaching
/// ([`NotAttempted`](KeyResolution::NotAttempted)) is neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyResolution {
    /// The mechanism ran to completion and found these holders (never empty - an
    /// empty holder set is a [`Miss`](KeyResolution::Miss), not a `Found([])`).
    Found(Vec<ProviderRecord>),
    /// The mechanism ran to completion and authoritatively found NO holder for this
    /// key. A caller may trust this as absence.
    Miss,
    /// The mechanism could not produce a healthy answer for this key (bootstrap
    /// outage, partition, this key's own deadline, insufficient routing, backend
    /// fault). NOT absence: a caller must not read it as "no holder" and must not
    /// cache it as a negative. This is the variant that makes a dead mechanism
    /// distinguishable from a genuine [`Miss`](KeyResolution::Miss).
    Unavailable(Unavailable),
    /// The batch's TOTAL deadline was spent before this key was attempted - a PARTIAL
    /// result. Distinct from [`Miss`](KeyResolution::Miss) (nothing was concluded
    /// about this key) and from [`Unavailable`](KeyResolution::Unavailable) (no
    /// mechanism failed for this key; it was simply never reached).
    NotAttempted,
}

impl KeyResolution {
    /// The holders if this is a [`Found`](KeyResolution::Found), else `None`. A
    /// convenience that FLATTENS the Miss/Unavailable/NotAttempted distinction, so use
    /// the variant directly where that distinction matters.
    pub fn holders(&self) -> Option<&[ProviderRecord]> {
        match self {
            KeyResolution::Found(records) => Some(records),
            _ => None,
        }
    }

    /// `true` only for [`Found`](KeyResolution::Found).
    pub fn is_found(&self) -> bool {
        matches!(self, KeyResolution::Found(_))
    }

    /// `true` only for [`Miss`](KeyResolution::Miss) - a healthy, authoritative absence.
    pub fn is_miss(&self) -> bool {
        matches!(self, KeyResolution::Miss)
    }

    /// `true` only for [`Unavailable`](KeyResolution::Unavailable) - could-not-consult.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, KeyResolution::Unavailable(_))
    }

    /// `true` only for [`NotAttempted`](KeyResolution::NotAttempted) - the deadline
    /// was spent before this key was reached.
    pub fn is_not_attempted(&self) -> bool {
        matches!(self, KeyResolution::NotAttempted)
    }

    /// Whether this key reached an AUTHORITATIVE verdict - a `Found` holder set or a
    /// healthy `Miss`. Unavailable and NotAttempted are non-authoritative: the batch
    /// is partial while any key is one of them.
    pub fn is_authoritative(&self) -> bool {
        matches!(self, KeyResolution::Found(_) | KeyResolution::Miss)
    }
}

// -------------------------------------------------------------------------
// AC#3 - measurement (not a timeless cheap/expensive class) and capabilities.
// -------------------------------------------------------------------------

/// The control-plane bytes a consultation spent, TYPED so an adapter that does not
/// instrument its wire is HONEST about it rather than reporting a fabricated zero
/// (which would be indistinguishable from a genuinely free consultation). Integer
/// bytes only - no floats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlBytes {
    /// The adapter observed exactly this many control-plane bytes on the wire.
    Measured(u64),
    /// The adapter does not count its control-plane bytes. A truthful "unknown", not
    /// a claim of zero cost.
    NotInstrumented,
}

/// How a consultation's resource envelope ended - the OUTCOME axis of a measurement,
/// distinct from the per-key verdicts. A caller reads this to know whether the numbers
/// describe a completed consultation or one cut short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceOutcome {
    /// The consultation ran to completion within the caller's total deadline.
    Completed,
    /// The caller's TOTAL deadline stopped the consultation before every key was
    /// attempted (a partial result - some keys are [`NotAttempted`](KeyResolution::NotAttempted)).
    DeadlineCut,
    /// The mechanism could not be consulted at all (every attempted key is
    /// [`Unavailable`](KeyResolution::Unavailable)).
    MechanismDown,
}

/// The MEASURED cost of one batch consultation (AC#3). These are OBSERVATIONS, not a
/// timeless cheap/expensive class label: `observed_latency_ns` is wall-clock latency
/// this adapter actually took, in integer nanoseconds. No floats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MechanismMeasurement {
    /// Wall-clock latency of the whole consultation, in integer nanoseconds.
    pub observed_latency_ns: u64,
    /// Control-plane bytes spent, or an honest "not instrumented".
    pub control_bytes: ControlBytes,
    /// How the resource envelope ended.
    pub resource: ResourceOutcome,
}

impl MechanismMeasurement {
    /// A completed consultation of `latency_ns`, with control bytes not instrumented.
    /// The shape the default batch path produces (it times the wall clock but cannot
    /// see wire bytes without backend plumbing).
    pub fn completed_unmetered(latency_ns: u64) -> Self {
        MechanismMeasurement {
            observed_latency_ns: latency_ns,
            control_bytes: ControlBytes::NotInstrumented,
            resource: ResourceOutcome::Completed,
        }
    }
}

/// What a [`ProviderDirectory`](crate::ProviderDirectory) mechanism CAN do, declared
/// a-priori for TASK-120 preflight and for a resolver plan to reason about ordering.
/// These are static capabilities, not per-call measurements (which live in
/// [`MechanismMeasurement`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryCapabilities {
    /// Whether this is GLOBAL exact-key discovery (a DHT that answers without the
    /// provider online) rather than an in-process/direct mechanism.
    pub global: bool,
    /// Whether the adapter performs a TRUE batched wire round trip, versus resolving
    /// each key independently under one total deadline (the default-path shape).
    pub batched_roundtrip: bool,
    /// Whether the adapter reports an OBSERVED latency in its measurement.
    pub measures_latency: bool,
    /// Whether the adapter reports OBSERVED control bytes (vs. `NotInstrumented`).
    pub measures_control_bytes: bool,
}

impl DirectoryCapabilities {
    /// The conservative default a mechanism declares when it says nothing more: not
    /// global, no true batched round trip, latency measured (the default batch path
    /// always times the wall clock), control bytes not instrumented.
    pub fn conservative() -> Self {
        DirectoryCapabilities {
            global: false,
            batched_roundtrip: false,
            measures_latency: true,
            measures_control_bytes: false,
        }
    }
}

// -------------------------------------------------------------------------
// AC#1/AC#2/AC#4 - the batch resolution (positional, carries no keys of its own).
// -------------------------------------------------------------------------

/// The reply carried a different number of outcomes than the request named. A
/// protocol/impl fault: because the outcomes are positional, a different count means
/// every outcome after the gap is about the wrong key, so the WHOLE resolution is
/// unusable (never a shifted prefix). Mirrors
/// [`HoldMisalignment`](crate::HoldMisalignment) on the direct-probe axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchMisalignment {
    /// How many keys the request named.
    pub asked: usize,
    /// How many outcomes the resolution carried.
    pub answered: usize,
}

impl std::fmt::Display for BatchMisalignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "batch resolution carries {} outcomes for {} keys asked (positional \
             outcomes; a mismatch mis-assigns every later key)",
            self.answered, self.asked
        )
    }
}

impl std::error::Error for BatchMisalignment {}

/// The answer to a [`BatchResolveRequest`]: one [`KeyResolution`] per asked key, in
/// the asker's order, plus the [`MechanismMeasurement`] of the consultation. It
/// carries NO keys of its own (AC#4): it is meaningless without the request, and the
/// ONLY safe way to read it is [`aligned_with`](BatchResolution::aligned_with), which
/// re-pairs each outcome with the key the ASKER named and fails fast on a count
/// mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchResolution {
    /// Positionally aligned with the request's `keys`. Carries no keys of its own.
    outcomes: Vec<KeyResolution>,
    /// The measured cost of producing this resolution.
    measurement: MechanismMeasurement,
}

impl BatchResolution {
    /// Build a resolution from positional `outcomes` and its `measurement`. The
    /// outcomes MUST be in the request's key order and have the request's length;
    /// [`aligned_with`](BatchResolution::aligned_with) re-checks that at read time.
    pub fn new(outcomes: Vec<KeyResolution>, measurement: MechanismMeasurement) -> Self {
        BatchResolution {
            outcomes,
            measurement,
        }
    }

    /// The positional outcomes, in the request's key order. Prefer
    /// [`aligned_with`](BatchResolution::aligned_with) so the positional invariant is
    /// a checked precondition of reading.
    pub fn outcomes(&self) -> &[KeyResolution] {
        &self.outcomes
    }

    /// The measured cost of this consultation.
    pub fn measurement(&self) -> &MechanismMeasurement {
        &self.measurement
    }

    /// Pair each outcome with the request key it answers, or fail fast with a
    /// [`BatchMisalignment`] if the counts differ. The ONLY safe way to consume a
    /// resolution: it makes the positional invariant a checked precondition, so a
    /// length mismatch cannot silently shift every key onto the wrong outcome. This is
    /// also WHY a resolution is not a listing (AC#4): the keys come from the ASKER's
    /// request, never from the answer.
    pub fn aligned_with<'a>(
        &'a self,
        request: &'a BatchResolveRequest,
    ) -> Result<impl Iterator<Item = (&'a ContentKey, &'a KeyResolution)>, BatchMisalignment> {
        if self.outcomes.len() != request.keys.len() {
            return Err(BatchMisalignment {
                asked: request.keys.len(),
                answered: self.outcomes.len(),
            });
        }
        Ok(request.keys.iter().zip(self.outcomes.iter()))
    }

    /// Whether every key reached an AUTHORITATIVE verdict (Found or Miss). A complete
    /// resolution has no Unavailable and no NotAttempted key.
    pub fn is_complete(&self) -> bool {
        self.outcomes.iter().all(KeyResolution::is_authoritative)
    }

    /// Whether this is a PARTIAL result (AC#2): at least one key is Unavailable or
    /// NotAttempted, so the batch did not authoritatively resolve every asked key.
    pub fn is_partial(&self) -> bool {
        !self.is_complete()
    }
}

// -------------------------------------------------------------------------
// AC#5 - the explicit, versioned execution plan (no production default).
// -------------------------------------------------------------------------

/// The versioned identity of an [`ExecutionPlan`] shape. A resolver plan is a POLICY
/// ARTIFACT; pinning its version means a change to what "the baseline" means is a
/// visible version bump, not a silent drift (mirrors the frozen-artifact discipline
/// the tournament contract requires).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionPlanVersion {
    /// The schema/name namespace of the plan (e.g. the resolver-plan family).
    pub schema: &'static str,
    /// The integer version within that schema.
    pub version: u32,
}

/// The identity of ONE discovery mechanism, so an explicit ordering can name it. These
/// are the PRD's independent content-discovery mechanisms (§598-611); the enum is
/// mechanism-neutral (no stack names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MechanismId {
    /// Global exact-key content discovery (the DHT `ProviderDirectory`).
    GlobalDirectory,
    /// Direct named-key hold-query of a specific peer.
    DirectHoldQuery,
    /// LAN-scoped discovery.
    LanDiscovery,
    /// The optional centralized tracker comparator.
    Tracker,
    /// In-process (same-node) resolution.
    InProcess,
}

impl std::fmt::Display for MechanismId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MechanismId::GlobalDirectory => "global_directory",
            MechanismId::DirectHoldQuery => "direct_hold_query",
            MechanismId::LanDiscovery => "lan_discovery",
            MechanismId::Tracker => "tracker",
            MechanismId::InProcess => "in_process",
        };
        f.write_str(s)
    }
}

/// The ORDER in which a plan consults mechanisms. Deliberately has NO "cheapest-first"
/// / "fastest-first" / "Iroh-first" variant: those are production preferences the
/// TASK-123 holdout must justify, and encoding one here would BE the hardcoded default
/// AC#5 forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MechanismOrder {
    /// Consult mechanisms in the order they were REGISTERED - a neutral order that
    /// expresses no preference between mechanisms. The baseline uses this.
    AsRegistered,
    /// Consult mechanisms in this EXPLICIT caller-supplied order. Any preference is
    /// the CALLER's, named here, never implied by the seam or registry.
    Explicit(Vec<MechanismId>),
}

/// How many mechanisms a plan consults at once. The baseline is strictly sequential
/// (TASK-106's deliberate decision); racing/bounded fan-out are REPRESENTABLE so a
/// future versioned plan can name them, but the baseline executor does not run them
/// (it fails fast rather than silently degrading - see [`MechanismRegistry`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parallelism {
    /// One mechanism at a time, in plan order.
    Sequential,
    /// Up to `max_concurrent` mechanisms consulted concurrently (a future plan shape;
    /// the baseline executor rejects it rather than guessing a fan-out).
    BoundedFanout {
        /// The concurrency bound (integer; a fan-out of 0 or 1 is degenerate).
        max_concurrent: u32,
    },
}

/// When a plan STOPS consulting further mechanisms for a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopCondition {
    /// Stop as soon as any mechanism yields a holder for the key (the cheapest
    /// correct stop; it expresses no preference BETWEEN mechanisms, only "enough").
    FirstHolder,
    /// Consult every mechanism even after a holder is found (e.g. to compare
    /// mechanisms during the tournament). More costly; a diagnostic choice.
    AllMechanisms,
}

/// WHERE a plan came from - the provenance that distinguishes a testable NAMED
/// BASELINE from a TASK-123 holdout-frozen production plan. Before the holdout, only
/// [`NamedBaseline`](PlanProvenance::NamedBaseline) exists;
/// [`HoldoutSelected`](PlanProvenance::HoldoutSelected) is reserved so a production
/// plan cannot masquerade as a baseline (or vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanProvenance {
    /// An explicit, named, NON-production baseline - testable, but making no claim
    /// about what production should do.
    NamedBaseline,
    /// A production plan selected by the TASK-123 holdout. Reserved: no constructor
    /// mints one yet, so nothing in this crate can present a production default.
    HoldoutSelected,
}

/// The caller-supplied, versioned resolver policy (AC#5): mechanism ordering,
/// parallelism, and stop condition. It has NO `Default` and NO production constructor
/// on purpose - the ONLY plan available before the TASK-123 holdout is
/// [`fixed_baseline_v1`](ExecutionPlan::fixed_baseline_v1), a NAMED BASELINE that
/// encodes no cheapest-first/Iroh-first/fastest-first preference. Neither the seam nor
/// the [`MechanismRegistry`] selects a plan; a caller must name one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    version: ExecutionPlanVersion,
    order: MechanismOrder,
    parallelism: Parallelism,
    stop: StopCondition,
    provenance: PlanProvenance,
}

impl ExecutionPlan {
    /// The named FIXED baseline (AC#5): registration-order, strictly sequential,
    /// stop-at-first-holder. It is a DIAGNOSTIC baseline
    /// ([`PlanProvenance::NamedBaseline`]), explicitly NOT a production default - it
    /// makes no claim about which mechanism or transport should win; TASK-123 owns
    /// that. Its shape matches TASK-106's deliberate sequential decision.
    ///
    /// This is the only constructor. There is intentionally no `Default`, no
    /// `production()`, no `cheapest_first()` and no `iroh_first()`: a production
    /// preference must come from the holdout, not from a convenience method here.
    pub fn fixed_baseline_v1() -> Self {
        ExecutionPlan {
            version: ExecutionPlanVersion {
                schema: "nix-p2p/resolver-plan",
                version: 1,
            },
            order: MechanismOrder::AsRegistered,
            parallelism: Parallelism::Sequential,
            stop: StopCondition::FirstHolder,
            provenance: PlanProvenance::NamedBaseline,
        }
    }

    /// A plan with an explicit caller-supplied ordering, sequential, first-holder.
    /// The ordering is the CALLER's stated preference (named in `order`), not a
    /// default the seam invented; provenance stays [`NamedBaseline`](PlanProvenance::NamedBaseline)
    /// because no holdout selected it.
    pub fn with_explicit_order(order: Vec<MechanismId>) -> Self {
        ExecutionPlan {
            order: MechanismOrder::Explicit(order),
            ..ExecutionPlan::fixed_baseline_v1()
        }
    }

    /// The caller's chosen parallelism, on top of an existing plan. The plan can
    /// EXPRESS a fan-out this way, but the baseline executor still refuses to RUN
    /// anything but [`Parallelism::Sequential`] (fail-fast, see [`MechanismRegistry`]);
    /// provenance is unchanged (a caller choice is not a holdout selection).
    pub fn with_parallelism(mut self, parallelism: Parallelism) -> Self {
        self.parallelism = parallelism;
        self
    }

    /// The caller's chosen stop condition, on top of an existing plan. Provenance is
    /// unchanged.
    pub fn with_stop(mut self, stop: StopCondition) -> Self {
        self.stop = stop;
        self
    }

    /// The plan's versioned identity.
    pub fn version(&self) -> ExecutionPlanVersion {
        self.version
    }

    /// The mechanism consultation order.
    pub fn order(&self) -> &MechanismOrder {
        &self.order
    }

    /// The parallelism policy.
    pub fn parallelism(&self) -> Parallelism {
        self.parallelism
    }

    /// The stop condition.
    pub fn stop(&self) -> StopCondition {
        self.stop
    }

    /// Where this plan came from (baseline vs holdout-selected).
    pub fn provenance(&self) -> PlanProvenance {
        self.provenance
    }

    /// Whether this plan is a production plan selected by the holdout. Always `false`
    /// before TASK-123 - there is no constructor that mints a
    /// [`HoldoutSelected`](PlanProvenance::HoldoutSelected) plan, so nothing here can
    /// present a production default.
    pub fn is_production(&self) -> bool {
        matches!(self.provenance, PlanProvenance::HoldoutSelected)
    }
}

// -------------------------------------------------------------------------
// AC#5 - the registry that consults several mechanisms UNDER a caller plan.
// -------------------------------------------------------------------------

use crate::budget::DiscoveryBudget;
use crate::capabilities::ProviderDirectory;

/// Why the baseline executor could not run a plan. Fail-fast (never a silent degrade):
/// the baseline runs only the shapes it can honour, and refuses the rest by NAME so a
/// future plan that needs racing is a loud error, not a quietly-sequential lie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanExecError {
    /// The plan asked for a parallelism the baseline executor does not run (anything
    /// other than [`Parallelism::Sequential`]). The production racing executor is
    /// TASK-123's; this baseline refuses rather than pretending.
    UnsupportedParallelism(Parallelism),
    /// An explicit ordering named a mechanism that is not registered. Not fatal to
    /// correctness (it is skipped), but reported so a misconfigured plan is visible.
    UnknownMechanism(MechanismId),
}

impl std::fmt::Display for PlanExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanExecError::UnsupportedParallelism(p) => write!(
                f,
                "the baseline resolver executor runs only Sequential plans; {p:?} is \
                 the production racing executor's job (TASK-123), refused not degraded"
            ),
            PlanExecError::UnknownMechanism(m) => {
                write!(f, "plan named unregistered mechanism {m}")
            }
        }
    }
}

impl std::error::Error for PlanExecError {}

/// A set of content-discovery mechanisms, held in REGISTRATION ORDER, consulted UNDER
/// a caller-supplied [`ExecutionPlan`] (AC#5). The registry itself expresses NO
/// preference between mechanisms and picks NO plan: `resolve` REQUIRES the plan as an
/// argument, so a production default cannot slip in here.
///
/// Each mechanism is a [`ProviderDirectory`] tagged with a [`MechanismId`] so an
/// explicit plan ordering can name it. The baseline plan
/// ([`ExecutionPlan::fixed_baseline_v1`]) consults them in registration order.
#[derive(Default)]
pub struct MechanismRegistry {
    mechanisms: Vec<(MechanismId, Arc<dyn ProviderDirectory>)>,
}

impl MechanismRegistry {
    /// An empty registry (no mechanism, no implicit default).
    pub fn new() -> Self {
        MechanismRegistry {
            mechanisms: Vec::new(),
        }
    }

    /// Register `mechanism` under `id`, APPENDING it - so `AsRegistered` order is the
    /// registration order, deterministic and preference-free.
    pub fn register(
        &mut self,
        id: MechanismId,
        mechanism: Arc<dyn ProviderDirectory>,
    ) -> &mut Self {
        self.mechanisms.push((id, mechanism));
        self
    }

    /// How many mechanisms are registered.
    pub fn len(&self) -> usize {
        self.mechanisms.len()
    }

    /// Whether no mechanism is registered.
    pub fn is_empty(&self) -> bool {
        self.mechanisms.is_empty()
    }

    /// The mechanisms to consult, in the order `plan` names. `AsRegistered` yields the
    /// registration order; `Explicit` yields exactly the named, registered mechanisms
    /// in the named order (unknown ids are collected as [`PlanExecError::UnknownMechanism`]
    /// but do not abort - correctness does not depend on a missing mechanism).
    fn ordered<'a>(
        &'a self,
        plan: &ExecutionPlan,
        warnings: &mut Vec<PlanExecError>,
    ) -> Vec<&'a Arc<dyn ProviderDirectory>> {
        match plan.order() {
            MechanismOrder::AsRegistered => self.mechanisms.iter().map(|(_, m)| m).collect(),
            MechanismOrder::Explicit(ids) => {
                let mut ordered = Vec::new();
                for id in ids {
                    match self.mechanisms.iter().find(|(mid, _)| mid == id) {
                        Some((_, m)) => ordered.push(m),
                        None => warnings.push(PlanExecError::UnknownMechanism(*id)),
                    }
                }
                ordered
            }
        }
    }

    /// Resolve `request` across the registered mechanisms UNDER `plan`, within
    /// `budget` (AC#5). The plan is REQUIRED - there is no default-plan overload - so
    /// neither the seam nor this registry selects a production preference.
    ///
    /// The baseline executor runs only [`Parallelism::Sequential`]: for each asked
    /// key, mechanisms are consulted in plan order until the plan's
    /// [`StopCondition`] is met ([`FirstHolder`](StopCondition::FirstHolder) stops at
    /// the first mechanism that Founds the key; [`AllMechanisms`](StopCondition::AllMechanisms)
    /// consults every mechanism). A non-Sequential plan is REFUSED with
    /// [`PlanExecError::UnsupportedParallelism`] - fail-fast, never a silent sequential
    /// substitution.
    pub async fn resolve(
        &self,
        request: &BatchResolveRequest,
        budget: &DiscoveryBudget,
        plan: &ExecutionPlan,
    ) -> Result<BatchResolution, PlanExecError> {
        if plan.parallelism() != Parallelism::Sequential {
            return Err(PlanExecError::UnsupportedParallelism(plan.parallelism()));
        }

        let start = Instant::now();
        let mut warnings = Vec::new();
        let ordered = self.ordered(plan, &mut warnings);

        // Per-key aggregation across mechanisms, in plan order. Each mechanism is asked
        // the SAME positional batch (asker-named keys only), and its per-key outcome is
        // folded in: a Found wins for that key; otherwise a Miss is authoritative-but-
        // absent and an Unavailable is remembered so a dead mechanism never reads as a
        // Miss (AC#2). NotAttempted keys (a mechanism's deadline ran out) fold like an
        // absence-with-no-conclusion and let a later mechanism still answer.
        let mut aggregated: Vec<KeyResolution> =
            vec![KeyResolution::NotAttempted; request.keys().len()];
        let mut any_found = false;
        let mut any_unavailable = false;

        for mechanism in ordered {
            // Under FirstHolder, once every key has a holder there is nothing left to ask.
            if plan.stop() == StopCondition::FirstHolder
                && aggregated.iter().all(KeyResolution::is_found)
                && !aggregated.is_empty()
            {
                break;
            }
            let remaining = budget
                .deadline
                .checked_sub(start.elapsed())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                break;
            }
            let sub_budget = DiscoveryBudget::new(remaining, budget.max_peers);
            let resolution = mechanism.resolve_batch(request, &sub_budget).await;
            for (slot, outcome) in aggregated.iter_mut().zip(resolution.outcomes().iter()) {
                match outcome {
                    KeyResolution::Found(records) => {
                        // FirstHolder: keep the first mechanism's holders for a key. Under
                        // AllMechanisms we still keep the first Found (merging holder sets
                        // across mechanisms is a policy the holdout owns, not the baseline).
                        if !slot.is_found() {
                            *slot = KeyResolution::Found(records.clone());
                        }
                        any_found = true;
                    }
                    KeyResolution::Miss => {
                        // A healthy absence only upgrades a not-yet-authoritative slot.
                        if !slot.is_authoritative() {
                            *slot = KeyResolution::Miss;
                        }
                    }
                    KeyResolution::Unavailable(why) => {
                        any_unavailable = true;
                        if !slot.is_authoritative() {
                            *slot = KeyResolution::Unavailable(why.clone());
                        }
                    }
                    KeyResolution::NotAttempted => {}
                }
            }
        }

        let latency_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let complete = aggregated.iter().all(KeyResolution::is_authoritative);
        let resource = if complete {
            ResourceOutcome::Completed
        } else if any_found {
            // Some keys resolved, others did not: a partial consultation cut by the
            // total deadline / an unavailable mechanism.
            ResourceOutcome::DeadlineCut
        } else if any_unavailable {
            ResourceOutcome::MechanismDown
        } else {
            ResourceOutcome::Completed
        };
        Ok(BatchResolution::new(
            aggregated,
            MechanismMeasurement {
                observed_latency_ns: latency_ns,
                control_bytes: ControlBytes::NotInstrumented,
                resource,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::CONTENT_KEY_LEN;

    fn key(seed: u8) -> ContentKey {
        ContentKey::from_bytes([seed; CONTENT_KEY_LEN])
    }

    fn record(k: ContentKey) -> ProviderRecord {
        use crate::content::PROVIDER_SIGNATURE_LEN;
        use crate::ids::{Blake3Digest, NodeId, TransportOffer};
        let provider = NodeId::from_bytes([0x33; 32]);
        ProviderRecord {
            key: k,
            content: Blake3Digest::from_bytes([0x42; 32]),
            provider,
            offers: vec![TransportOffer::Iroh { node: provider }],
            sequence: 1,
            issued_at: 100,
            expiry: 200,
            signature: [0u8; PROVIDER_SIGNATURE_LEN],
        }
    }

    // AC#2: the four per-key outcomes are distinct, non-collapsible values. A dead
    // mechanism (Unavailable) is NOT a Miss, and a not-reached key (NotAttempted) is
    // neither - the property that keeps a dead mechanism from reading as nobody-has-it.
    #[test]
    fn key_resolution_variants_are_distinct_and_typed() {
        let found = KeyResolution::Found(vec![record(key(1))]);
        let miss = KeyResolution::Miss;
        let unavail = KeyResolution::Unavailable(Unavailable::BootstrapOutage);
        let pending = KeyResolution::NotAttempted;

        assert!(found.is_found() && found.is_authoritative());
        assert!(miss.is_miss() && miss.is_authoritative());
        assert!(unavail.is_unavailable() && !unavail.is_authoritative());
        assert!(pending.is_not_attempted() && !pending.is_authoritative());

        // The load-bearing AC#2 distinction: Unavailable != Miss, NotAttempted != Miss.
        assert_ne!(unavail, miss);
        assert_ne!(pending, miss);
        assert!(
            !unavail.is_miss(),
            "a dead mechanism must never read as a Miss"
        );
        assert!(found.holders().is_some());
        assert!(miss.holders().is_none() && unavail.holders().is_none());
    }

    // AC#2/AC#4: a resolution is positional over the asker's keys; aligned_with is the
    // only reader and fails fast on a count mismatch (it carries no keys of its own).
    #[test]
    fn resolution_is_positional_and_alignment_is_checked() {
        let request = BatchResolveRequest::new([key(1), key(2), key(3)]);
        let resolution = BatchResolution::new(
            vec![
                KeyResolution::Found(vec![record(key(1))]),
                KeyResolution::Miss,
                KeyResolution::Unavailable(Unavailable::Partition),
            ],
            MechanismMeasurement::completed_unmetered(10),
        );

        let pairs: Vec<_> = resolution
            .aligned_with(&request)
            .expect("counts match")
            .collect();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].0, &key(1));
        assert!(pairs[0].1.is_found());
        assert!(pairs[1].1.is_miss());
        assert!(pairs[2].1.is_unavailable());

        // A short/long resolution against the asked count fails fast - never a shift.
        let short = BatchResolution::new(
            vec![KeyResolution::Miss],
            MechanismMeasurement::completed_unmetered(1),
        );
        let err = short
            .aligned_with(&request)
            .err()
            .expect("mismatch rejected");
        assert_eq!(
            err,
            BatchMisalignment {
                asked: 3,
                answered: 1
            }
        );
    }

    // AC#2: is_partial/is_complete observe the partial-vs-complete distinction.
    #[test]
    fn partial_is_observable() {
        let complete = BatchResolution::new(
            vec![
                KeyResolution::Found(vec![record(key(1))]),
                KeyResolution::Miss,
            ],
            MechanismMeasurement::completed_unmetered(1),
        );
        assert!(complete.is_complete() && !complete.is_partial());

        for partial_tail in [
            KeyResolution::Unavailable(Unavailable::DeadlineExceeded),
            KeyResolution::NotAttempted,
        ] {
            let partial = BatchResolution::new(
                vec![KeyResolution::Found(vec![record(key(1))]), partial_tail],
                MechanismMeasurement::completed_unmetered(1),
            );
            assert!(partial.is_partial() && !partial.is_complete());
        }
    }

    // AC#3: control bytes are a TYPED measurement, so "not instrumented" is honest and
    // distinct from a genuine zero-cost consultation.
    #[test]
    fn control_bytes_not_instrumented_is_not_a_zero() {
        assert_ne!(ControlBytes::NotInstrumented, ControlBytes::Measured(0));
        assert_eq!(ControlBytes::Measured(42), ControlBytes::Measured(42));
    }

    // AC#5: the baseline plan is versioned, is a NAMED BASELINE (not a production
    // selection), and encodes NO mechanism preference. This is the mutation target:
    // changing the baseline to an Iroh-first / explicit preference reddens here.
    #[test]
    fn baseline_plan_is_versioned_named_and_preference_free() {
        let plan = ExecutionPlan::fixed_baseline_v1();
        assert_eq!(plan.version().schema, "nix-p2p/resolver-plan");
        assert_eq!(plan.version().version, 1);
        assert_eq!(
            *plan.order(),
            MechanismOrder::AsRegistered,
            "the baseline must express NO cheapest-first/Iroh-first preference"
        );
        assert_eq!(plan.parallelism(), Parallelism::Sequential);
        assert_eq!(plan.stop(), StopCondition::FirstHolder);
        assert_eq!(plan.provenance(), PlanProvenance::NamedBaseline);
        assert!(
            !plan.is_production(),
            "no plan constructor may present a production default before TASK-123"
        );
    }

    // AC#5: an explicit ordering is the CALLER's stated preference, named in the plan,
    // never invented by the seam. Provenance stays NamedBaseline (no holdout selected it).
    #[test]
    fn explicit_order_is_caller_supplied() {
        let plan = ExecutionPlan::with_explicit_order(vec![
            MechanismId::GlobalDirectory,
            MechanismId::DirectHoldQuery,
        ]);
        assert_eq!(
            *plan.order(),
            MechanismOrder::Explicit(vec![
                MechanismId::GlobalDirectory,
                MechanismId::DirectHoldQuery
            ])
        );
        assert_eq!(plan.provenance(), PlanProvenance::NamedBaseline);
        assert!(!plan.is_production());
    }
}
