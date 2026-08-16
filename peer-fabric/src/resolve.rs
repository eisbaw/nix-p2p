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
use crate::outcome::{Lookup, Unavailable};

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
// THE FINALIZER CHOKE-POINT (TASK-100 systematic redesign).
//
// Four codex rounds each found the SAME defect class on a DIFFERENT path:
// outcome-finalization treated a NON-authoritative result as authoritative (a false
// `Miss` or a false `Completed`). The fix is NOT to patch each site again but to route
// EVERY resolution path through ONE finalizer that applies THE ONE RULE by
// construction:
//
//   * a key is an authoritative `Miss` ONLY if EVERY mechanism that was supposed to
//     answer it authoritatively Missed;
//   * a batch is `ResourceOutcome::Completed` ONLY if EVERY key is authoritative
//     (a non-empty `Found` or an authoritative `Miss`) AND no non-authoritative event
//     (deadline cut, dead mechanism, un-consulted planned mechanism, malformed answer)
//     occurred.
//
// The three funnel points are [`classify_lookup`] (a mechanism's raw `Lookup` answer to
// a typed per-key outcome - where a wrong-key / empty `Found` becomes `Unavailable`,
// never a `Miss`), [`KeyAcc`] (the per-key cross-mechanism fold), and
// [`finalize_batch`] (the per-key + batch resource decision). The default
// `resolve_batch`, the [`MechanismRegistry`] and `find_providers_bound` all use these;
// none computes finalization or a `ResourceOutcome` on its own.
// -------------------------------------------------------------------------

/// Classify ONE mechanism's raw [`Lookup`] answer for `key` into a typed per-key
/// [`KeyResolution`], under the Found-never-empty / wrong-key-is-a-fault rule. This is
/// the SINGLE place that decides what an empty or wrong-key `Found` means, shared by the
/// default [`resolve_batch`](crate::ProviderDirectory::resolve_batch) and by
/// [`find_providers_bound`](crate::find_providers_bound):
///
///   * a `Found` is FILTERED to records whose own [`ProviderRecord::key`] IS `key`, so a
///     mechanism cannot smuggle holders of an un-asked key into this position (AC#4);
///   * if that filter empties a NON-empty answer (the mechanism returned holders, but
///     none for `key` - a WRONG-KEY answer) OR the answer was already `Found(vec![])`
///     (an EMPTY `Found` - `Found` is never empty), the mechanism gave a MALFORMED
///     answer. That is a backend fault, NOT an authoritative absence: it becomes
///     [`Unavailable`](KeyResolution::Unavailable), NEVER a [`Miss`](KeyResolution::Miss)
///     and NEVER a stop-worthy [`Found`](KeyResolution::Found). A caller must not read it
///     as "nobody has it".
pub(crate) fn classify_lookup(
    key: &ContentKey,
    answer: Lookup<Vec<ProviderRecord>>,
) -> KeyResolution {
    match answer {
        Lookup::Found(records) => {
            let had_records = !records.is_empty();
            let bound: Vec<ProviderRecord> =
                records.into_iter().filter(|r| r.key == *key).collect();
            if !bound.is_empty() {
                KeyResolution::Found(bound)
            } else if had_records {
                // Wrong-key: the mechanism returned holders, but none for the asked key.
                // A protocol/impl fault - treat as could-not-consult, never a Miss.
                KeyResolution::Unavailable(Unavailable::Backend(
                    "directory returned holders for un-asked key(s) only (wrong-key answer)"
                        .to_string(),
                ))
            } else {
                // Empty Found: Found is never empty. A malformed answer, not an
                // authoritative absence.
                KeyResolution::Unavailable(Unavailable::Backend(
                    "directory returned an empty Found (Found is never empty)".to_string(),
                ))
            }
        }
        Lookup::Miss => KeyResolution::Miss,
        Lookup::Unavailable(why) => KeyResolution::Unavailable(why),
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

/// A [`BatchResolution`] could not be bound to its request. Structural no-enumeration
/// (AC#4): a resolution's outcomes must be POSITIONALLY BOUND to the asker's request
/// keys, and a `Found` outcome may name ONLY holders of the key at that position - an
/// adapter that ignores the request and returns holders for an un-named key is
/// REJECTED at construction, not merely length-checked, so it cannot smuggle inventory
/// the caller did not ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchBindError {
    /// The outcomes count differs from the request key count (positional mismatch).
    LengthMismatch {
        /// Keys the request named.
        asked: usize,
        /// Outcomes offered.
        answered: usize,
    },
    /// A `Found` outcome at position `index` named a holder record whose own
    /// [`ProviderRecord::key`](crate::ProviderRecord) is NOT the key the asker put at
    /// that position - an un-asked holding. The whole resolution is rejected.
    FoundUnaskedKey {
        /// The position whose Found carried an un-asked key.
        index: usize,
    },
    /// A `Found` outcome at position `index` carried NO holders (`Found(vec![])`).
    /// `Found` is never empty by invariant: an empty holder set is an authoritative
    /// [`Miss`](KeyResolution::Miss) (nobody holds it) or a backend fault
    /// ([`Unavailable`](KeyResolution::Unavailable)), never a `Found`. Admitting an empty
    /// `Found` here would let a stop-condition treat "nothing" as "found something", so it
    /// is rejected at construction.
    EmptyFound {
        /// The position whose Found carried no holders.
        index: usize,
    },
}

impl std::fmt::Display for BatchBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchBindError::LengthMismatch { asked, answered } => write!(
                f,
                "batch resolution carries {answered} outcomes for {asked} keys asked"
            ),
            BatchBindError::FoundUnaskedKey { index } => write!(
                f,
                "batch resolution position {index} names holders of a key the asker did \
                 not name (an un-asked holding) - rejected"
            ),
            BatchBindError::EmptyFound { index } => write!(
                f,
                "batch resolution position {index} carries an empty Found (Found is never \
                 empty; an empty holder set is a Miss or a backend fault) - rejected"
            ),
        }
    }
}

impl std::error::Error for BatchBindError {}

/// The answer to a [`BatchResolveRequest`]: one [`KeyResolution`] per asked key, in
/// the asker's order, plus the [`MechanismMeasurement`] of the consultation. It
/// carries NO keys of its own (AC#4): it is meaningless without the request, and the
/// ONLY safe way to read it is [`aligned_with`](BatchResolution::aligned_with), which
/// re-pairs each outcome with the key the ASKER named and fails fast on a count
/// mismatch.
///
/// The ONLY way an external adapter can build one is
/// [`for_request`](BatchResolution::for_request), which BINDS each outcome to the
/// request key at its position and REJECTS a `Found` whose holder records do not
/// correspond to that key - so an ignore-the-request adapter cannot construct a
/// resolution that names un-asked holdings (structural no-enumeration, AC#4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchResolution {
    /// Positionally aligned with the request's `keys`. Carries no keys of its own.
    outcomes: Vec<KeyResolution>,
    /// The measured cost of producing this resolution.
    measurement: MechanismMeasurement,
}

impl BatchResolution {
    /// Raw constructor, `pub(crate)`: the seam's own construction points use it AFTER
    /// they have bound each outcome to its request key (the default `resolve_batch` and
    /// the registry build outcomes per queried key). External adapters cannot reach it;
    /// they must use [`for_request`](BatchResolution::for_request), which does the
    /// binding check. Kept crate-private so the structural AC#4 guarantee cannot be
    /// bypassed by an outside caller handing arbitrary outcomes.
    pub(crate) fn new(outcomes: Vec<KeyResolution>, measurement: MechanismMeasurement) -> Self {
        BatchResolution {
            outcomes,
            measurement,
        }
    }

    /// Build a resolution BOUND to `request` (AC#4 structural). Verifies (1) one outcome
    /// per asked key, in order, and (2) every `Found` outcome names ONLY holders of the
    /// key at that position - a `Found` whose records carry a different
    /// [`ProviderRecord::key`](crate::ProviderRecord) is an un-asked holding and is
    /// REJECTED with [`BatchBindError::FoundUnaskedKey`]. This is the ONLY public
    /// constructor, so a resolution that names inventory the caller did not ask for is
    /// impossible to construct (not merely detectable after the fact).
    pub fn for_request(
        request: &BatchResolveRequest,
        outcomes: Vec<KeyResolution>,
        measurement: MechanismMeasurement,
    ) -> Result<Self, BatchBindError> {
        if outcomes.len() != request.keys.len() {
            return Err(BatchBindError::LengthMismatch {
                asked: request.keys.len(),
                answered: outcomes.len(),
            });
        }
        for (index, (key, outcome)) in request.keys.iter().zip(outcomes.iter()).enumerate() {
            if let KeyResolution::Found(records) = outcome {
                // Found is never empty (an empty holder set is a Miss / backend fault).
                if records.is_empty() {
                    return Err(BatchBindError::EmptyFound { index });
                }
                // A Found may name ONLY holders of the key at its position.
                if records.iter().any(|r| r.key != *key) {
                    return Err(BatchBindError::FoundUnaskedKey { index });
                }
            }
        }
        Ok(BatchResolution {
            outcomes,
            measurement,
        })
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
        // Surface a misconfigured plan (an Explicit order naming an unregistered
        // mechanism) rather than silently dropping it - fail verbosely. Non-fatal:
        // correctness does not depend on a mechanism the registry does not hold, so the
        // consultation continues with the mechanisms it does have.
        for warning in &warnings {
            eprintln!("peer-fabric: resolver plan warning: {warning}");
        }

        // Per-key aggregation across mechanisms (AC#2, generalized). A key is an
        // AUTHORITATIVE Miss ONLY if EVERY mechanism authoritatively Missed it. Every
        // NON-authoritative outcome - Unavailable, NotAttempted, or a deadline cut -
        // means "not authoritatively resolved", so it BLOCKS a Miss and keeps the key
        // partial. A dead mechanism can never read as a Miss; and neither can a key one
        // mechanism Missed but another never authoritatively answered.
        let len = request.keys().len();
        let mut acc: Vec<KeyAcc> = vec![KeyAcc::default(); len];
        // Track whether THIS registry's total deadline actually cut the loop, so the
        // reported `resource` is a real event, consistent with is_complete()/is_partial().
        let mut deadline_cut = false;

        for (index, mechanism) in ordered.iter().enumerate() {
            // Under FirstHolder, ask each subsequent mechanism ONLY about keys not yet
            // held - never re-send an already-resolved key (MEDIUM: FirstHolder must not
            // forward resolved keys). Under AllMechanisms, always ask about every key.
            let pending: Vec<usize> = match plan.stop() {
                StopCondition::FirstHolder => (0..len).filter(|&i| !acc[i].is_found()).collect(),
                StopCondition::AllMechanisms => (0..len).collect(),
            };
            if pending.is_empty() {
                // FirstHolder: every key already has a holder - stop.
                break;
            }
            let remaining = budget
                .deadline
                .checked_sub(start.elapsed())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                deadline_cut = true;
                break;
            }
            // A positional sub-request of ONLY the still-pending, asker-named keys.
            let sub_request = BatchResolveRequest::new(pending.iter().map(|&i| request.keys()[i]));
            let sub_budget = DiscoveryBudget::new(remaining, budget.max_peers);
            // ENFORCE the total deadline with a real outer timeout (AC#3): a mechanism
            // that IGNORES its budget and overruns is CUT here, it does not hang the loop.
            let resolution = match tokio::time::timeout(
                remaining,
                mechanism.resolve_batch(&sub_request, &sub_budget),
            )
            .await
            {
                Ok(resolution) => resolution,
                Err(_elapsed) => {
                    // The overrun cut the loop: the still-pending keys were NOT
                    // authoritatively resolved by this mechanism, so they stay partial
                    // (handled fail-closed below), never a fabricated Miss.
                    deadline_cut = true;
                    break;
                }
            };
            let sub_outcomes = resolution.outcomes();
            // Alignment (MEDIUM): a mechanism whose reply does not have one outcome per
            // asked key is protocol-broken; do NOT zip a shifted/short reply. Treat the
            // whole misaligned reply as this mechanism being Unavailable for the pending
            // keys (never a fabricated Miss), and surface it.
            if sub_outcomes.len() != pending.len() {
                eprintln!(
                    "peer-fabric: mechanism #{index} returned {} outcomes for {} asked keys \
                     (misaligned) - treating as unavailable, not folding a shifted reply",
                    sub_outcomes.len(),
                    pending.len()
                );
                for &i in &pending {
                    acc[i].note_unavailable(Unavailable::Backend("misaligned batch reply".into()));
                }
                continue;
            }
            for (pos, &i) in pending.iter().enumerate() {
                acc[i].note(&sub_outcomes[pos]);
            }
        }

        // A planned mechanism that could NOT be consulted (an explicit plan named an
        // UNREGISTERED mechanism) did not answer, so it cannot be silently dropped and
        // let another mechanism's Miss finalize as authoritative absence (round-4
        // blocker #2). Record it as a non-authoritative event on EVERY key: a key a
        // registered mechanism only Missed becomes Unavailable (the un-consulted
        // mechanism might have held it), while a key another mechanism FOUND stays Found
        // (Found is terminal). `note_unavailable` is first-wins, so a genuine mechanism
        // failure already recorded in the loop keeps its own, more specific reason.
        for warning in &warnings {
            let PlanExecError::UnknownMechanism(id) = warning else {
                continue;
            };
            for a in acc.iter_mut() {
                a.note_unavailable(Unavailable::Backend(format!(
                    "planned mechanism {id} is not registered, so it could not be consulted"
                )));
            }
        }

        // AC#3 (BLOCKER, registry path): on a deadline cut, EVERY still-pending (not
        // Found) key is Unavailable(DeadlineExceeded) - the envelope was cut before it
        // could be authoritatively resolved. This overrides any Miss a mechanism gave it
        // (a Miss is authoritative only if the WHOLE consultation completed), so a cut
        // never leaves a false Miss/Completed.
        if deadline_cut {
            for a in acc.iter_mut() {
                if !a.is_found() {
                    a.note_unavailable(Unavailable::DeadlineExceeded);
                }
            }
        }

        // THE ONE finalizer: per-key resolution AND the batch ResourceOutcome are decided
        // here, not by this method. The aggregate is bound per queried key (each Found came
        // from a for_request-bound sub-resolution mapped to its position).
        let latency_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Ok(finalize_batch(
            request,
            acc,
            deadline_cut,
            latency_ns,
            ControlBytes::NotInstrumented,
        ))
    }
}

/// THE batch finalizer (TASK-100 systematic redesign): the SINGLE place that turns the
/// per-key cross-mechanism accumulators plus the batch-level `deadline_cut` flag into
/// BOTH the per-key [`KeyResolution`]s AND the batch [`ResourceOutcome`], under THE ONE
/// RULE. Every resolution path (the default
/// [`resolve_batch`](crate::ProviderDirectory::resolve_batch) and the
/// [`MechanismRegistry`]) funnels through here; none computes a `ResourceOutcome` itself.
///
/// The resource decision is CONSISTENT with [`BatchResolution::is_complete`] by
/// construction: a batch is `Completed` IFF every key is authoritative and no deadline
/// cut occurred; a cut is `DeadlineCut`; anything else non-authoritative is
/// `MechanismDown`. There is no branch that reports `Completed` while a key is
/// non-authoritative (round-4 blocker #4).
pub(crate) fn finalize_batch(
    request: &BatchResolveRequest,
    acc: Vec<KeyAcc>,
    deadline_cut: bool,
    latency_ns: u64,
    control_bytes: ControlBytes,
) -> BatchResolution {
    debug_assert_eq!(
        acc.len(),
        request.keys().len(),
        "the finalizer accumulators are positional over the request keys"
    );
    let outcomes: Vec<KeyResolution> = acc.into_iter().map(KeyAcc::finalize).collect();
    let all_authoritative = outcomes.iter().all(KeyResolution::is_authoritative);
    // THE ONE RULE for the envelope: a cut is never Completed; Completed requires EVERY
    // key authoritative; everything else non-authoritative is a down mechanism (partial).
    let resource = if deadline_cut {
        ResourceOutcome::DeadlineCut
    } else if all_authoritative {
        ResourceOutcome::Completed
    } else {
        ResourceOutcome::MechanismDown
    };
    // The outcomes are bound per queried key (each Found was classified against its key by
    // `classify_lookup` or a for_request-bound sub-resolution), so `new` is safe here.
    BatchResolution::new(
        outcomes,
        MechanismMeasurement {
            observed_latency_ns: latency_ns,
            control_bytes,
            resource,
        },
    )
}

/// Per-key cross-mechanism accumulator (AC#2). It records the DISTINCT facts each
/// mechanism reported about a key and finalizes them by the rule "authoritative Miss
/// only if EVERY mechanism authoritatively Missed". Unlike a precedence-max fold, it
/// cannot let a Miss win over a NotAttempted: any non-authoritative outcome blocks the
/// Miss and keeps the key partial.
#[derive(Clone, Default)]
pub(crate) struct KeyAcc {
    /// The first Found holder set for this key (a Found is terminal - it wins).
    found: Option<Vec<ProviderRecord>>,
    /// The first Unavailable reason a mechanism reported (a dead/cut mechanism).
    unavailable: Option<Unavailable>,
    /// At least one mechanism authoritatively Missed this key.
    saw_miss: bool,
    /// At least one mechanism did NOT authoritatively answer (returned NotAttempted).
    saw_not_authoritative: bool,
}

impl KeyAcc {
    pub(crate) fn is_found(&self) -> bool {
        self.found.is_some()
    }

    /// Fold one mechanism's outcome for this key.
    pub(crate) fn note(&mut self, outcome: &KeyResolution) {
        match outcome {
            KeyResolution::Found(records) => {
                if self.found.is_none() {
                    self.found = Some(records.clone());
                }
            }
            KeyResolution::Unavailable(why) => self.note_unavailable(why.clone()),
            KeyResolution::Miss => self.saw_miss = true,
            KeyResolution::NotAttempted => self.saw_not_authoritative = true,
        }
    }

    pub(crate) fn note_unavailable(&mut self, why: Unavailable) {
        if self.unavailable.is_none() {
            self.unavailable = Some(why);
        }
    }

    /// Decide the key's final outcome. Found wins; else any Unavailable reason (a dead
    /// or cut mechanism); else a NON-authoritative gap (NotAttempted) keeps it partial;
    /// else an authoritative Miss (every mechanism Missed); else never consulted.
    pub(crate) fn finalize(self) -> KeyResolution {
        if let Some(records) = self.found {
            KeyResolution::Found(records)
        } else if let Some(why) = self.unavailable {
            KeyResolution::Unavailable(why)
        } else if self.saw_not_authoritative {
            // A mechanism did not authoritatively answer, so this is NOT an authoritative
            // Miss - it is partial (a caller must not read it as absence).
            KeyResolution::NotAttempted
        } else if self.saw_miss {
            KeyResolution::Miss
        } else {
            KeyResolution::NotAttempted
        }
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

    // AC#4 STRUCTURAL: for_request is the only public constructor and it BINDS each
    // outcome to the request key at its position. A Found naming holders of an UN-ASKED
    // key is REJECTED at construction - an ignore-the-request adapter cannot build a
    // resolution that leaks inventory the caller did not name. THE bite: removing the
    // key-correspondence check would let this construction succeed.
    #[test]
    fn for_request_binds_found_to_the_queried_key() {
        let request = BatchResolveRequest::new([key(1), key(2)]);

        // Honest: Found at position 0 names holders of key(1) (the asked key) -> accepted.
        let ok = BatchResolution::for_request(
            &request,
            vec![
                KeyResolution::Found(vec![record(key(1))]),
                KeyResolution::Miss,
            ],
            MechanismMeasurement::completed_unmetered(1),
        );
        assert!(ok.is_ok(), "a Found bound to the asked key is accepted");

        // Hostile: position 0 (asked key(1)) returns holders of key(9) - an UN-ASKED key.
        // Rejected structurally, not merely length-checked (lengths match).
        let leaked = BatchResolution::for_request(
            &request,
            vec![
                KeyResolution::Found(vec![record(key(9))]),
                KeyResolution::Miss,
            ],
            MechanismMeasurement::completed_unmetered(1),
        );
        assert_eq!(
            leaked,
            Err(BatchBindError::FoundUnaskedKey { index: 0 }),
            "a Found naming an un-asked key must be REJECTED (structural no-enumeration)"
        );

        // A length mismatch is also rejected.
        let short = BatchResolution::for_request(
            &request,
            vec![KeyResolution::Miss],
            MechanismMeasurement::completed_unmetered(1),
        );
        assert_eq!(
            short,
            Err(BatchBindError::LengthMismatch {
                asked: 2,
                answered: 1
            })
        );
    }

    // AC#2 (generalized): KeyAcc makes a key Miss ONLY if EVERY mechanism authoritatively
    // Missed. Any non-authoritative outcome - Unavailable OR NotAttempted - blocks the
    // Miss and keeps the key partial. THE bite the old rank fold failed: Miss + NotAttempted.
    #[test]
    fn key_acc_miss_requires_every_mechanism_to_authoritatively_miss() {
        // Miss + NotAttempted -> NOT an authoritative Miss (the rank fold wrongly gave Miss).
        let mut a = KeyAcc::default();
        a.note(&KeyResolution::Miss);
        a.note(&KeyResolution::NotAttempted);
        assert!(
            !a.clone().finalize().is_miss(),
            "a key one mechanism Missed and another did not authoritatively answer is NOT a Miss"
        );
        assert!(!a.finalize().is_authoritative());

        // Miss + Unavailable -> Unavailable (a dead mechanism never reads as a Miss).
        let mut a = KeyAcc::default();
        a.note(&KeyResolution::Miss);
        a.note(&KeyResolution::Unavailable(Unavailable::BootstrapOutage));
        assert!(a.finalize().is_unavailable());

        // Miss by EVERY mechanism -> an authoritative Miss.
        let mut a = KeyAcc::default();
        a.note(&KeyResolution::Miss);
        a.note(&KeyResolution::Miss);
        assert!(a.finalize().is_miss());

        // Found wins over everything.
        let mut a = KeyAcc::default();
        a.note(&KeyResolution::Miss);
        a.note(&KeyResolution::Unavailable(Unavailable::Partition));
        a.note(&KeyResolution::Found(vec![record(key(1))]));
        assert!(a.finalize().is_found());
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

    // =====================================================================
    // THE EXHAUSTIVE FINALIZER TEST (TASK-100 systematic redesign).
    //
    // The four codex rounds all found ONE defect class - a NON-authoritative result
    // finalized as authoritative (a false Miss / a false Completed) - on four different
    // paths. Rather than one example per path, this enumerates the finalizer's whole
    // input space and asserts (per-key KeyResolution, batch ResourceOutcome) against an
    // INDEPENDENT reference oracle for every combination. The three funnel points are
    // classify_lookup, the KeyAcc fold, and finalize_batch; every resolution path uses
    // exactly these, so a correct table here pins every path. Each round-4 blocker is a
    // specific row (marked below) that reddens if THE ONE RULE is reverted.
    // =====================================================================

    /// The kinds of per-key observation a mechanism can contribute to the fold.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Obs {
        Found,
        Miss,
        Unavailable,
        NotAttempted,
    }

    impl Obs {
        fn as_resolution(self, k: ContentKey) -> KeyResolution {
            match self {
                Obs::Found => KeyResolution::Found(vec![record(k)]),
                Obs::Miss => KeyResolution::Miss,
                Obs::Unavailable => KeyResolution::Unavailable(Unavailable::BootstrapOutage),
                Obs::NotAttempted => KeyResolution::NotAttempted,
            }
        }
    }

    const ALL_OBS: [Obs; 4] = [Obs::Found, Obs::Miss, Obs::Unavailable, Obs::NotAttempted];

    fn resolution_kind(r: &KeyResolution) -> Obs {
        match r {
            KeyResolution::Found(_) => Obs::Found,
            KeyResolution::Miss => Obs::Miss,
            KeyResolution::Unavailable(_) => Obs::Unavailable,
            KeyResolution::NotAttempted => Obs::NotAttempted,
        }
    }

    /// THE ONE RULE for a single key's fold, computed INDEPENDENTLY of the
    /// implementation (a reference oracle): Found wins; else any Unavailable; else any
    /// NotAttempted (a non-authoritative gap BLOCKS a Miss); else an authoritative Miss
    /// requires that EVERY observation was a Miss; else (no observation) NotAttempted.
    fn expected_fold(obs: &[Obs]) -> Obs {
        if obs.contains(&Obs::Found) {
            Obs::Found
        } else if obs.contains(&Obs::Unavailable) {
            Obs::Unavailable
        } else if obs.contains(&Obs::NotAttempted) {
            Obs::NotAttempted
        } else if !obs.is_empty() && obs.iter().all(|o| *o == Obs::Miss) {
            Obs::Miss
        } else {
            Obs::NotAttempted
        }
    }

    // classify_lookup, EXHAUSTIVE over the answer kinds a mechanism can return. The
    // wrong-key and empty-Found rows are ROUND-4 BLOCKER #1: a malformed answer must be
    // Unavailable, NEVER a Miss and NEVER a stop-worthy Found.
    #[test]
    fn classify_lookup_is_exhaustive_and_never_turns_a_fault_into_a_miss() {
        let asked = key(1);
        let other = key(2);

        // Right-key, non-empty -> Found (filtered to the asked key).
        let r = classify_lookup(&asked, Lookup::Found(vec![record(asked)]));
        assert!(matches!(&r, KeyResolution::Found(v) if v.len() == 1 && v[0].key == asked));

        // Mixed right+wrong -> Found keeps ONLY the asked key's records (drops the rest).
        let r = classify_lookup(&asked, Lookup::Found(vec![record(asked), record(other)]));
        assert!(matches!(&r, KeyResolution::Found(v) if v.len() == 1 && v[0].key == asked));

        // ROUND-4 BLOCKER #1 - wrong-key ONLY -> Unavailable(Backend), never Miss/Found.
        let r = classify_lookup(&asked, Lookup::Found(vec![record(other)]));
        assert!(
            matches!(r, KeyResolution::Unavailable(Unavailable::Backend(_))),
            "a wrong-key answer is a backend fault, not a Miss - got {r:?}"
        );

        // Empty Found -> Unavailable(Backend), never Miss (Found is never empty).
        let r = classify_lookup(&asked, Lookup::Found(vec![]));
        assert!(
            matches!(r, KeyResolution::Unavailable(Unavailable::Backend(_))),
            "an empty Found is a backend fault, not a Miss - got {r:?}"
        );

        // Genuine Miss / Unavailable pass through as themselves.
        assert!(classify_lookup(&asked, Lookup::Miss).is_miss());
        assert!(matches!(
            classify_lookup(&asked, Lookup::Unavailable(Unavailable::Partition)),
            KeyResolution::Unavailable(Unavailable::Partition)
        ));
    }

    // The KeyAcc fold, EXHAUSTIVE over every singleton and every ordered pair of
    // observations (cross-mechanism). The Miss-only-if-EVERY-mechanism-Missed rule
    // (ROUND-4 BLOCKER #2 / AC#2) is checked for all 16 pairs against the oracle; a fold
    // that ranked Miss above NotAttempted would flip (Miss, NotAttempted) -> Miss and
    // redden here. Both orders are exercised, so the variant is proven order-independent.
    #[test]
    fn key_acc_fold_is_exhaustive_over_observation_combinations() {
        let k = key(7);
        for o in ALL_OBS {
            let mut acc = KeyAcc::default();
            acc.note(&o.as_resolution(k));
            assert_eq!(
                resolution_kind(&acc.finalize()),
                expected_fold(&[o]),
                "singleton fold of {o:?}"
            );
        }
        for a in ALL_OBS {
            for b in ALL_OBS {
                let mut acc = KeyAcc::default();
                acc.note(&a.as_resolution(k));
                acc.note(&b.as_resolution(k));
                assert_eq!(
                    resolution_kind(&acc.finalize()),
                    expected_fold(&[a, b]),
                    "fold of ({a:?}, {b:?}) violated THE ONE RULE"
                );
            }
        }
        // The empty acc (never consulted) is NotAttempted, never a Miss.
        assert_eq!(
            resolution_kind(&KeyAcc::default().finalize()),
            Obs::NotAttempted
        );
    }

    // finalize_batch, EXHAUSTIVE over 2-key batches ({F,M,U,N}^2) x deadline_cut. Asserts
    // (a) each key's finalized kind is preserved; (b) NO deadline-cut envelope is ever
    // Completed; (c) with no cut, resource == Completed IFF every key is authoritative,
    // consistent with is_complete(). Row (c) is ROUND-4 BLOCKER #4: e.g. (Miss,
    // NotAttempted) must be MechanismDown, not the pre-redesign false Completed.
    #[test]
    fn finalize_batch_is_exhaustive_over_two_key_batches() {
        for a in ALL_OBS {
            for b in ALL_OBS {
                for cut in [false, true] {
                    let ka = key(0x10);
                    let kb = key(0x20);
                    let request = BatchResolveRequest::new([ka, kb]);
                    let mut acc_a = KeyAcc::default();
                    acc_a.note(&a.as_resolution(ka));
                    let mut acc_b = KeyAcc::default();
                    acc_b.note(&b.as_resolution(kb));
                    let res = finalize_batch(
                        &request,
                        vec![acc_a, acc_b],
                        cut,
                        0,
                        ControlBytes::NotInstrumented,
                    );

                    // (a) per-key kind is preserved (finalize_batch never rewrites a key's
                    // fold; the deadline injection is the caller path's job, done before).
                    assert_eq!(
                        resolution_kind(&res.outcomes()[0]),
                        a,
                        "key A kind, cut={cut}"
                    );
                    assert_eq!(
                        resolution_kind(&res.outcomes()[1]),
                        b,
                        "key B kind, cut={cut}"
                    );

                    let all_authoritative =
                        [a, b].iter().all(|k| matches!(k, Obs::Found | Obs::Miss));
                    assert_eq!(res.is_complete(), all_authoritative);
                    if cut {
                        // (b) a cut is DeadlineCut and can NEVER be Completed.
                        assert_eq!(res.measurement().resource, ResourceOutcome::DeadlineCut);
                        assert_ne!(res.measurement().resource, ResourceOutcome::Completed);
                    } else {
                        // (c) Completed IFF all-authoritative; else MechanismDown.
                        let expected = if all_authoritative {
                            ResourceOutcome::Completed
                        } else {
                            ResourceOutcome::MechanismDown
                        };
                        assert_eq!(
                            res.measurement().resource,
                            expected,
                            "resource for ({a:?},{b:?}) no-cut"
                        );
                        assert_eq!(
                            res.measurement().resource == ResourceOutcome::Completed,
                            all_authoritative,
                            "Completed must mean every key authoritative ({a:?},{b:?})"
                        );
                    }
                }
            }
        }
    }

    // ROUND-4 BLOCKER #3: the public batch constructor rejects an empty Found (Found is
    // never empty) AND an un-asked-key Found, positionally; a well-formed resolution is
    // accepted.
    #[test]
    fn for_request_rejects_empty_and_unasked_found() {
        let request = BatchResolveRequest::new([key(1), key(2)]);

        let empty = BatchResolution::for_request(
            &request,
            vec![KeyResolution::Found(vec![]), KeyResolution::Miss],
            MechanismMeasurement::completed_unmetered(1),
        );
        assert_eq!(
            empty,
            Err(BatchBindError::EmptyFound { index: 0 }),
            "an empty Found must be rejected (Found is never empty)"
        );

        let unasked = BatchResolution::for_request(
            &request,
            vec![
                KeyResolution::Miss,
                KeyResolution::Found(vec![record(key(9))]),
            ],
            MechanismMeasurement::completed_unmetered(1),
        );
        assert_eq!(unasked, Err(BatchBindError::FoundUnaskedKey { index: 1 }));

        let ok = BatchResolution::for_request(
            &request,
            vec![
                KeyResolution::Found(vec![record(key(1))]),
                KeyResolution::Miss,
            ],
            MechanismMeasurement::completed_unmetered(1),
        );
        assert!(ok.is_ok());
    }
}
