//! The seven capability traits (AC#1): WHAT the daemon wants of any peer
//! substrate, one trait per intention, each mapped to a PRD Wave-2c participation
//! axis. None of them names iroh, libp2p, or any stack.
//!
//! ## Mapping to the PRD's six participation axes
//!
//! The PRD (§ participation axes) names six distinct configuration/evidence axes;
//! the seven traits realise them without overlap:
//!
//! | PRD axis | trait(s) |
//! |---|---|
//! | 1. Local discovery | [`LocalPeerDiscovery`] |
//! | 2. Node/address discovery | [`NodeLocator`] |
//! | 3. Content discovery | [`ProviderDirectory`] (global exact-key) + [`PeerHoldQuery`] (direct named-key) |
//! | 4. Publication | [`AvailabilityAnnouncer`] |
//! | 5. Serving | [`NarServer`] |
//! | 6. Lookup leakage | cross-cutting: every consultation records to the
//!   [`ExposureLedger`](crate::ExposureLedger) and declares its
//!   [`ExposureSurface`](crate::ExposureSurface) |
//!
//! Fetching a NAR ([`NarTransfer`]) is the seventh trait and is NOT one of the six
//! participation axes: it is the byte-transfer mechanism the fetch path uses once a
//! provider is known, a legitimately-runtime tag-keyed axis (a claim carries
//! several offers; the transport is chosen at request time - see
//! [`crate::TransferRegistry`] and AC#5), not a participation choice.
//!
//! Axis 2 ([`NodeLocator`]) is its OWN gate-able trait, not buried inside fetch: the
//! policy choice (explicit peer list vs pkarr/Mainline/DNS) and the exposure it
//! incurs are first-class, so an operator can turn address discovery off
//! independently of everything else.

use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::budget::{AnnounceBudget, DiscoveryBudget, SafetyEnvelope, ServeBudget};
use crate::content::{ContentKey, DialInfo, ProviderRecord, ResolutionPolicy};
use crate::exposure::ExposureSurface;
use crate::ids::{Blake3Digest, NodeId, TransportOffer, TransportTag};
use crate::outcome::{Lookup, Unavailable};
use crate::resolve::{
    BatchResolution, BatchResolveRequest, ControlBytes, DirectoryCapabilities, KeyAcc,
    KeyResolution, classify_lookup, finalize_batch,
};

/// The BOUND single-key discovery path (AC#4, structural). This is the ONLY sanctioned
/// way to consume [`ProviderDirectory::find_providers`] directly: it is a FREE FUNCTION,
/// not a trait method, so a buggy or hostile adapter CANNOT override it to skip the
/// classification. It queries the directory for exactly `key` and funnels the raw answer
/// through [`classify_lookup`] - the SAME choke-point the batch path uses - so a record
/// whose own [`ProviderRecord::key`] is not `key` is DROPPED (a direct caller can never
/// learn holders of a key it did not name), and a WRONG-KEY or EMPTY `Found` becomes
/// [`Unavailable`](Lookup::Unavailable) (a backend fault), NEVER a false
/// [`Miss`](Lookup::Miss). A genuine `Miss`/`Unavailable` passes through unchanged.
/// Shipped direct callers (the daemon's NAR source and raw-serve probe) use THIS, not the
/// raw trait method, so the same structural no-enumeration + no-false-miss guarantee the
/// batch path enforces holds on the direct path.
pub async fn find_providers_bound(
    directory: &dyn ProviderDirectory,
    key: &ContentKey,
    budget: &DiscoveryBudget,
) -> Lookup<Vec<ProviderRecord>> {
    match classify_lookup(key, directory.find_providers(key, budget).await) {
        KeyResolution::Found(bound) => Lookup::Found(bound),
        KeyResolution::Miss => Lookup::Miss,
        KeyResolution::Unavailable(why) => Lookup::Unavailable(why),
        // classify_lookup never yields NotAttempted (it maps a completed single-key
        // answer); treat it defensively as could-not-consult rather than panicking.
        KeyResolution::NotAttempted => Lookup::Unavailable(Unavailable::Backend(
            "classify_lookup produced an unexpected NotAttempted on the direct path".to_string(),
        )),
    }
}

// -------------------------------------------------------------------------
// Axis 3a - global exact-key content discovery.
// -------------------------------------------------------------------------

/// "Find who can give me this NAR." Decentralized, exact-key, no enumeration.
///
/// Backed by a Kademlia VALUE store (`put_record`/`get_record`, NOT `get_providers`)
/// on every backend, so the signed [`ProviderRecord`] - who, how, until when - is
/// learnable WITHOUT the provider being online (AC#6). Exact-key only: you look up a
/// [`ContentKey`] you already have; there is no "list what's out there".
///
/// Returns [`Lookup<Vec<ProviderRecord>>`] so a healthy "no provider holds this"
/// ([`Lookup::Miss`](crate::Lookup::Miss)) is distinct from "the DHT could not be
/// consulted" ([`Lookup::Unavailable`](crate::Lookup::Unavailable)). Disclosures the
/// lookup makes are recorded to the fabric's
/// [`ExposureLedger`](crate::ExposureLedger).
#[async_trait]
pub trait ProviderDirectory: Send + Sync {
    /// Look up the providers of `key`, within `budget`. Records its exposure to the
    /// fabric ledger as it consults.
    async fn find_providers(
        &self,
        key: &ContentKey,
        budget: &DiscoveryBudget,
    ) -> Lookup<Vec<ProviderRecord>>;

    /// BATCH-resolve every asker-named key in `request` to its holders, within the
    /// caller's TOTAL `budget` (TASK-100 AC#1). The answer is a positional
    /// [`BatchResolution`] over exactly the request's keys, carrying no keys of its own
    /// (AC#4), one TYPED [`KeyResolution`] each (AC#2), plus the consultation's
    /// [`MechanismMeasurement`](crate::MechanismMeasurement) (AC#3).
    ///
    /// The DEFAULT implementation resolves each key with the single-key
    /// [`find_providers`](ProviderDirectory::find_providers) primitive under the
    /// REMAINING share of the caller's total deadline, so a batch is bounded IN TOTAL
    /// (AC#3, composing with TASK-106's total-deadline discipline rather than
    /// double-bounding it) and a single-key batch is byte-for-byte the single-key path
    /// (AC#1 compatibility). Keys reached after the total deadline is spent are typed
    /// [`KeyResolution::NotAttempted`] - a PARTIAL result, never a false
    /// [`Miss`](KeyResolution::Miss). A backend with a true batched wire round trip may
    /// override this and declare [`DirectoryCapabilities::batched_roundtrip`].
    async fn resolve_batch(
        &self,
        request: &BatchResolveRequest,
        budget: &DiscoveryBudget,
    ) -> BatchResolution {
        let start = Instant::now();
        // One accumulator per asked key. Each key's single-mechanism outcome is folded
        // in exactly like a registry mechanism's, so the default path and the registry
        // funnel through the SAME finalizer (round-4 unification) rather than each
        // computing its own resolution and ResourceOutcome.
        let mut acc: Vec<KeyAcc> = vec![KeyAcc::default(); request.keys().len()];
        let mut cut = false;
        for (i, key) in request.keys().iter().enumerate() {
            if cut {
                // The total deadline is already spent: every remaining key is a typed
                // PARTIAL marker, distinct from an authoritative Miss.
                acc[i].note(&KeyResolution::NotAttempted);
                continue;
            }
            let remaining = budget
                .deadline
                .checked_sub(start.elapsed())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                cut = true;
                acc[i].note(&KeyResolution::NotAttempted);
                continue;
            }
            // Bound THIS key by the REMAINING total budget, so the sum is bounded by the
            // caller's deadline (never per-key deadline * N). ENFORCE it with a real outer
            // timeout so a budget-IGNORING or hostile adapter that overruns is CUT at the
            // deadline rather than hanging the build path (AC#3) - the deadline is not
            // merely passed down and trusted.
            let sub_budget = DiscoveryBudget::new(remaining, budget.max_peers);
            let outcome = match tokio::time::timeout(
                remaining,
                self.find_providers(key, &sub_budget),
            )
            .await
            {
                // The SINGLE classifier: a wrong-key / empty Found becomes Unavailable
                // (backend fault), never a false Miss (round-4 blocker #1).
                Ok(answer) => classify_lookup(key, answer),
                // The outer timeout fired: this key was CUT by the caller's total deadline.
                // Typed as DeadlineExceeded (attempted, cut), never a false Miss; the rest
                // are NotAttempted.
                Err(_elapsed) => {
                    cut = true;
                    KeyResolution::Unavailable(Unavailable::DeadlineExceeded)
                }
            };
            acc[i].note(&outcome);
        }
        // THE ONE finalizer decides both the per-key resolutions and the ResourceOutcome.
        let latency_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        finalize_batch(request, acc, cut, latency_ns, ControlBytes::NotInstrumented)
    }

    /// What this directory CAN do, declared a-priori (AC#3): whether it is global,
    /// whether it batches on the wire, and which measurements it reports. The default
    /// is [`DirectoryCapabilities::conservative`]; a real backend overrides it (e.g. a
    /// DHT directory declares itself global).
    fn capabilities(&self) -> DirectoryCapabilities {
        DirectoryCapabilities::conservative()
    }

    /// The a-priori exposure this directory WILL incur when enabled (AC#3), for
    /// TASK-120 preflight - computed from config, discloses nothing itself.
    fn declared_exposure(&self) -> ExposureSurface;
}

// -------------------------------------------------------------------------
// Axis 4 - publication.
// -------------------------------------------------------------------------

/// A receipt for an accepted publication/withdrawal - opaque proof the operation
/// was admitted by the substrate, for the caller's log/audit. Its contents are a
/// backend detail; the seam only needs that it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// A backend-specific identifier for the accepted operation (empty if the
    /// backend has none).
    pub token: String,
}

impl Receipt {
    /// A receipt carrying `token`.
    pub fn new(token: impl Into<String>) -> Self {
        Receipt {
            token: token.into(),
        }
    }
}

/// Why an announce/withdraw could not be admitted. Distinct variants so a log line
/// tells a rejected record from an unreachable substrate from a budget overrun.
#[derive(Debug)]
pub enum AnnounceError {
    /// The substrate rejected the record (malformed, over its size cap, bad
    /// signature - a record-level fault).
    Rejected(String),
    /// The publication substrate could not be reached (bootstrap/partition).
    Unreachable(String),
    /// The [`AnnounceBudget`] deadline elapsed before the publish completed.
    DeadlineExceeded,
    /// The backend could not DURABLY persist the record's allocated sequence before
    /// publishing, so it FAIL-CLOSED and did not announce (TASK-185, AC#3). Distinct from
    /// [`Rejected`](AnnounceError::Rejected) (a record-level fault) and
    /// [`Unreachable`](AnnounceError::Unreachable) (a network fault): here the record and the
    /// network are fine, but announcing a record whose sequence is not on disk would let a
    /// restart re-mint an already-published sequence and self-rollback, so the announce is
    /// refused rather than made non-durable silently.
    Persist(String),
    /// The node's publication-eligibility decision (TASK-102) REFUSED this record, so the
    /// publish-capable adapter emitted nothing (TASK-100 AC#6). Distinct from
    /// [`Rejected`](AnnounceError::Rejected) (the substrate rejected a well-formed record):
    /// here the LOCAL policy forbade publishing it at all. Fail-closed - the record never
    /// reached the wire.
    Ineligible(crate::eligibility::IneligibleReason),
}

impl std::fmt::Display for AnnounceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnnounceError::Rejected(why) => write!(f, "publication rejected: {why}"),
            AnnounceError::Unreachable(why) => {
                write!(f, "publication substrate unreachable: {why}")
            }
            AnnounceError::DeadlineExceeded => f.write_str("announce deadline exceeded"),
            AnnounceError::Persist(why) => {
                write!(f, "durable sequence persist failed, not published: {why}")
            }
            AnnounceError::Ineligible(reason) => {
                write!(f, "publication refused by eligibility decision: {reason}")
            }
        }
    }
}

impl std::error::Error for AnnounceError {}

/// "Tell the network I can serve this NAR." Eligibility - WHETHER this content may be
/// published at all - is the single TASK-102 decision; `announce` takes a
/// [`PublicationWitness`](crate::PublicationWitness) rather than a bare
/// [`ProviderRecord`] (TASK-231, AC#1), so a caller cannot ask the announcer to publish a
/// record that did not pass a [`PublicationEligibility`](crate::PublicationEligibility)
/// `admit` - an un-consulted publish is UNREPRESENTABLE at the seam. A publish-capable
/// backend ALSO consults its own per-fabric authority fail-closed before it emits any record
/// (the load-bearing adapter invariant), so a witness minted by a permissive authority and
/// handed to a stricter announcer is still refused. Records its exposure to the fabric ledger.
#[async_trait]
pub trait AvailabilityAnnouncer: Send + Sync {
    /// Publish the record carried by `witness` under its [`ContentKey`], within `budget`. The
    /// witness proves the record passed an eligibility decision (AC#1); the backend re-consults
    /// its own authority before publishing (AC#2).
    async fn announce(
        &self,
        witness: &crate::PublicationWitness,
        budget: &AnnounceBudget,
    ) -> Result<Receipt, AnnounceError>;

    /// Withdraw this node's record for `key` (best-effort; a withdrawn record also
    /// expires on its own [`ProviderRecord::expiry`]).
    async fn withdraw(&self, key: &ContentKey) -> Result<Receipt, AnnounceError>;

    /// The a-priori exposure publication WILL incur when enabled (AC#3).
    fn declared_exposure(&self) -> ExposureSurface;
}

// -------------------------------------------------------------------------
// Axis 2 - node/address discovery.
// -------------------------------------------------------------------------

/// "Learn how to dial this NodeId." PRD axis 2 as its OWN gate-able seam - NOT
/// buried inside fetch. It is used BY transfer/announce internally, but the
/// [`DialInfo`] it yields stays inside the fabric and never reaches the serving
/// core; what surfaces to policy is the [`ResolutionPolicy`] chosen (explicit peer
/// list vs public infrastructure) and the exposure the resolution incurs (recorded
/// to the fabric ledger).
///
/// Returns [`Lookup<DialInfo>`] so "no address known for this node right now"
/// ([`Miss`](crate::Lookup::Miss)) is distinct from "the resolution mechanism could
/// not be consulted" ([`Unavailable`](crate::Lookup::Unavailable)).
#[async_trait]
pub trait NodeLocator: Send + Sync {
    /// Resolve `node` to dial coordinates under `policy`. Records its exposure to
    /// the fabric ledger (an explicit-peers-only policy discloses nothing; public
    /// infrastructure discloses the queried `NodeId`).
    async fn locate(&self, node: &NodeId, policy: &ResolutionPolicy) -> Lookup<DialInfo>;

    /// The a-priori exposure address resolution WILL incur when enabled (AC#3).
    fn declared_exposure(&self) -> ExposureSurface;
}

// -------------------------------------------------------------------------
// Fetch (runtime tag-keyed axis, not a participation axis).
// -------------------------------------------------------------------------

/// Why one [`NarTransfer::fetch`] attempt did not yield gate-1-verified bytes. A
/// per-offer failure: the fetch driver records it and tries the next offer, except
/// [`TooLarge`](TransferError::TooLarge), which is a deliberate abort that
/// short-circuits (every offer addresses the same oversized content).
#[derive(Debug)]
pub enum TransferError {
    /// The holder does not have this content identity.
    NotHeld(Blake3Digest),
    /// Gate 1 fired: the transferred bytes do not hash to the requested identity.
    /// A corrupt or lying holder. Fail closed - never hand these bytes upward. The
    /// bytes returned by a successful fetch are ALWAYS BLAKE3-verified against the
    /// requested `content`; Nix's sha256 gate (gate 2) remains the trust anchor.
    IntegrityMismatch {
        expected: Blake3Digest,
        actual: Blake3Digest,
    },
    /// The offer handed to this transport is not the variant it services (a
    /// registry-dispatch bug; guarded defensively).
    WrongOffer {
        expected: TransportTag,
        got: TransportTag,
    },
    /// A transport-specific failure (dial refused, timeout, reset): this holder is
    /// unusable, try the next offer.
    Unavailable(String),
    /// The size abort: the holder streamed MORE than the signed NarSize bound
    /// (uncompressed raw NAR, NEVER the compressed FileSize). A deliberate abort of
    /// a lying claim, not a "try the next holder" signal.
    TooLarge { limit: u64, streamed: u64 },
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferError::NotHeld(id) => write!(f, "holder does not hold {id}"),
            TransferError::IntegrityMismatch { expected, actual } => write!(
                f,
                "transport-integrity gate failed: got bytes hashing to {actual}, expected {expected}"
            ),
            TransferError::WrongOffer { expected, got } => {
                write!(
                    f,
                    "offer is a {got} locator but this transport services {expected}"
                )
            }
            TransferError::Unavailable(why) => write!(f, "transport unavailable: {why}"),
            TransferError::TooLarge { limit, streamed } => write!(
                f,
                "size abort: holder streamed {streamed} bytes, over the signed NarSize bound {limit}"
            ),
        }
    }
}

impl std::error::Error for TransferError {}

/// "Get the bytes from a provider." Returns gate-1-verified (BLAKE3) raw NAR bytes,
/// time-bounded by the [`SafetyEnvelope`] and size-bounded by the signed NarSize.
/// This is the daemon's existing `Transport` intention, and it is a
/// legitimately-RUNTIME axis: a claim carries several [`TransportOffer`]s and the
/// transport is selected at request time by [`TransportTag`], so transfers live in a
/// [`TransferRegistry`](crate::TransferRegistry), not as a single compile-time
/// choice (AC#5). It carries no `declared_exposure`: fetching from an
/// already-discovered provider makes no NEW axis-6 leakage disclosure beyond what
/// discovery already recorded (the direct transaction with the counterparty is
/// outside axis-6's incidental-disclosure scope, not "zero disclosure").
#[async_trait]
pub trait NarTransfer: Send + Sync {
    /// Which offer variant this transport services (its registration key).
    fn tag(&self) -> TransportTag;

    /// Fetch `content` using `offer`'s locator, returning gate-1-verified raw NAR
    /// bytes. Time-bounded by `envelope`; size-bounded by `expected_size` (the
    /// signed NarSize from the record/claim - UNCOMPRESSED raw-NAR bytes, NEVER the
    /// compressed FileSize; `None` when no signed bound is known, e.g. a cold-start
    /// fallback). The size abort ([`TransferError::TooLarge`]) fires DURING the
    /// stream the instant cumulative bytes exceed `expected_size`, never post-hoc -
    /// which is why the bound is a per-call INPUT and not construction config. Its
    /// absence in an earlier draft left `TransferError::TooLarge.limit` unsourced.
    async fn fetch(
        &self,
        content: &Blake3Digest,
        offer: &TransportOffer,
        expected_size: Option<u64>,
        envelope: &SafetyEnvelope,
    ) -> Result<Vec<u8>, TransferError>;
}

// -------------------------------------------------------------------------
// Axis 5 - serving.
// -------------------------------------------------------------------------

// ADR (TASK-150): WHERE THE SUPPLY OF SERVED BYTES LIVES - BELOW THIS SEAM.
//
// An earlier draft of this seam carried a `NarSupplier { async fn supply(content)
// -> Option<Vec<u8>> }` and had [`NarServer::serve`] take `Arc<dyn NarSupplier>`.
// That shape is UNSAFE for a real serving backend and has been removed:
//
//   * It produces bytes EAGERLY and declares no size, so a faithful iroh
//     [`NarServer`] could not preserve the task-72 GAP-1 defense (learn a NAR's
//     declared_size WITHOUT producing its bytes, so a 3 GiB request costs a `stat`,
//     not a 3 GiB allocation - the peer-triggerable-OOM guard). Wrapping `supply()`
//     and allocating first REINTRODUCES exactly that OOM.
//   * It admits an arbitrary synchronous producer, which an absolute async shutdown
//     deadline cannot kill (an unkillable `spawn_blocking`) - it cannot express the
//     cancellation-safety the real supply path needs (owned process group,
//     `TaskSupervisor::execute_process`).
//
// Both properties (declared-size-before-production, cancellation-safe production)
// belong to the RUNTIME layer that can actually enforce them. So the supplier is
// bound to the concrete server AT CONSTRUCTION and stays a substrate-internal detail
// (the backend's own SEALED, plan-based supplier, e.g. `fabric-iroh`'s
// `SupplyPlan{declared_size, Process/Memory/RegularFile source}`), never a type that
// crosses this seam. [`NarServer::serve`] therefore takes no supplier: the server it
// is called on already holds one. This keeps `peer_fabric` substrate-neutral (no
// process/memory/plan/size machinery leaks up) while the invariants stay provable
// where they are enforced.

/// A live serve session's handle: dropping it INITIATES teardown (RAII). A
/// lifecycle, returned by [`NarServer::serve`], not a per-request value.
///
/// ## What "teardown" guarantees (and what it does not)
///
/// Dropping the handle stops the session ADMITTING new requests. It does NOT
/// promise that transfers ALREADY in flight are cancelled: whether they are aborted
/// or allowed to DRAIN is backend-defined, and teardown is BEST-EFFORT and
/// ASYNCHRONOUS - dropping the handle does not block until the session has quiesced,
/// nor does it hand back a "stopped" signal. A frontend that needs to know serving
/// has fully stopped must observe the backend, not the drop.
///
/// The concrete `fabric-iroh` backend, for one, aborts its serve DRIVER on drop (no
/// new admissions) while any in-flight transfer keeps running under the node runtime
/// until it completes or hits its serve-duration bound - so a caller must not treat
/// drop as an immediate hard stop or as reclaiming in-flight budget.
///
/// The `label` is for logs/status; the teardown is carried by an OPAQUE guard the
/// backend attaches with [`with_teardown`](ServeHandle::with_teardown) - a task
/// abort-handle, a listener, a `Drop`-guard. It is boxed and type-erased so the seam
/// stays stack-neutral: the frontend holds the handle alive and drops it to stop
/// accepting work, without naming what the guard is. A bare label alone would tear
/// nothing down; the guard slot is what makes the "dropping stops admission" contract
/// real.
pub struct ServeHandle {
    /// A backend-specific label for the running session (for logs/status).
    pub label: String,
    /// The opaque teardown guard; dropped with the handle. `None` for a fake/no-op
    /// session that owns nothing to reclaim.
    _teardown: Option<Box<dyn Send + Sync>>,
}

impl std::fmt::Debug for ServeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The guard is type-erased and not `Debug`, so render only the label and
        // whether a guard is attached.
        f.debug_struct("ServeHandle")
            .field("label", &self.label)
            .field("has_teardown", &self._teardown.is_some())
            .finish()
    }
}

impl ServeHandle {
    /// A handle labelled `label` owning no teardown guard (a fake/no-op session).
    pub fn new(label: impl Into<String>) -> Self {
        ServeHandle {
            label: label.into(),
            _teardown: None,
        }
    }

    /// A handle labelled `label` owning `guard`; dropping the handle drops the guard
    /// and so initiates teardown (stops admitting new requests; see the type doc for
    /// the best-effort/asynchronous semantics). A backend passes its
    /// listener/task-abort here.
    pub fn with_teardown(label: impl Into<String>, guard: Box<dyn Send + Sync>) -> Self {
        ServeHandle {
            label: label.into(),
            _teardown: Some(guard),
        }
    }
}

/// Why a serve session could not be established.
#[derive(Debug)]
pub enum ServeError {
    /// The listener/endpoint could not be bound.
    Bind(String),
    /// A backend-specific setup failure.
    Backend(String),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeError::Bind(why) => write!(f, "serve bind failed: {why}"),
            ServeError::Backend(why) => write!(f, "serve backend failure: {why}"),
        }
    }
}

impl std::error::Error for ServeError {}

/// "Hand out bytes to whoever asks, within budget." A lifecycle, not a call: it
/// starts a session serving under `budget` and returns a [`ServeHandle`] that keeps
/// it alive; dropping the handle stops the session admitting new requests (see
/// [`ServeHandle`] for the exact - best-effort, asynchronous, in-flight may drain -
/// teardown semantics). Admission (declining an over-budget request BEFORE any bytes
/// are produced) is the [`ServeBudget`]'s job; eligibility of WHAT may be served is
/// decided above the seam.
///
/// The SOURCE of served bytes is bound to the concrete server at construction and is
/// NOT passed here - see the ADR above [`ServeHandle`] for why the supply seam lives
/// below this trait (declared-size-before-production + cancellation-safety are
/// runtime-layer invariants).
#[async_trait]
pub trait NarServer: Send + Sync {
    /// Start serving, bounded by `budget`, from the supplier the server was built
    /// with. Returns a [`ServeHandle`] whose `Drop` stops the session admitting new
    /// requests (teardown is best-effort/asynchronous; in-flight transfers may drain).
    async fn serve(&self, budget: ServeBudget) -> Result<ServeHandle, ServeError>;
}

// -------------------------------------------------------------------------
// Axis 3b - direct named-key hold-query (no enumeration).
// -------------------------------------------------------------------------

/// A direct probe of ONE peer: "of these named content keys, which do you hold?".
/// Named-key ONLY, by construction: the asker lists every [`ContentKey`], so a peer
/// cannot be asked to ENUMERATE its holdings (enumeration would leak the secret
/// store-path names a node holds - the PRD privacy invariant). The batch form asks
/// a whole closure in one round trip; the answer is POSITIONAL over exactly these
/// keys and carries no keys of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHoldRequest {
    /// The content keys being probed, in the asker's order. The reply is aligned to
    /// THIS order and has THIS length.
    pub keys: Vec<ContentKey>,
}

impl PeerHoldRequest {
    /// A request naming `keys`.
    pub fn new(keys: impl IntoIterator<Item = ContentKey>) -> Self {
        PeerHoldRequest {
            keys: keys.into_iter().collect(),
        }
    }
}

/// One positional answer inside a [`PeerHoldReply`]: the peer's yes/no about the key
/// at the SAME index in the [`PeerHoldRequest`]. It deliberately does NOT carry the
/// key it answers - that is what keeps a batch answer from being a listing: detached
/// from the query it is a bare yes/no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldAnswer {
    /// "Yes": the single content identity for the queried key, plus pure-locator
    /// offers to fetch it.
    Have {
        content: Blake3Digest,
        offers: Vec<TransportOffer>,
    },
    /// "No, I do not hold the key at this position."
    Absent,
}

/// The reply to a [`PeerHoldRequest`]: one [`HoldAnswer`] per queried key, in the
/// query's order. `answers.len()` MUST equal the number of keys asked - a mismatch
/// mis-assigns every later key.
///
/// That invariant sits on a TRUST BOUNDARY (the answering peer may be buggy or
/// hostile), so it is not left to prose: pair the reply back to its request through
/// [`aligned_with`](PeerHoldReply::aligned_with), which FAILS FAST on a length
/// mismatch rather than letting a caller `zip` two raw parallel arrays and silently
/// shift every key onto the wrong answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHoldReply {
    /// Positionally aligned with the request's `keys`. Carries no keys of its own.
    pub answers: Vec<HoldAnswer>,
}

/// The reply carried a different number of answers than the request named. A
/// protocol fault by the responder: because the answers are positional, a different
/// count means every answer after the gap is about the wrong key, so the WHOLE reply
/// is unusable (never a shifted prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldMisalignment {
    /// How many keys the request named.
    pub asked: usize,
    /// How many answers the reply carried.
    pub answered: usize,
}

impl std::fmt::Display for HoldMisalignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "hold reply carries {} answers for {} keys asked (positional answers; a \
             mismatch mis-assigns every later key)",
            self.answered, self.asked
        )
    }
}

impl std::error::Error for HoldMisalignment {}

impl PeerHoldReply {
    /// Pair each answer with the request key it answers, or fail fast with a
    /// [`HoldMisalignment`] if the counts differ. The ONLY safe way to consume a
    /// reply: it makes the positional invariant a checked precondition of reading
    /// the pairs, so a length mismatch cannot be used unchecked.
    pub fn aligned_with<'a>(
        &'a self,
        request: &'a PeerHoldRequest,
    ) -> Result<impl Iterator<Item = (&'a ContentKey, &'a HoldAnswer)>, HoldMisalignment> {
        if self.answers.len() != request.keys.len() {
            return Err(HoldMisalignment {
                asked: request.keys.len(),
                answered: self.answers.len(),
            });
        }
        Ok(request.keys.iter().zip(self.answers.iter()))
    }
}

/// "Ask THIS peer, directly, whether it holds these NARs." Named-key only (see
/// [`PeerHoldRequest`]); the direct, non-global half of content discovery (PRD axis
/// 3). Returns [`Lookup<PeerHoldReply>`] so "the peer answered, here is its
/// positional yes/no" is distinct from "the peer could not be reached"
/// ([`Unavailable`](crate::Lookup::Unavailable)). Records its exposure to the fabric
/// ledger.
#[async_trait]
pub trait PeerHoldQuery: Send + Sync {
    /// Probe `peer` for every key in `query`, within `budget`.
    async fn ask_holds(
        &self,
        peer: &NodeId,
        query: &PeerHoldRequest,
        budget: &DiscoveryBudget,
    ) -> Lookup<PeerHoldReply>;

    /// The a-priori exposure a direct hold-query WILL incur when enabled (AC#3).
    fn declared_exposure(&self) -> ExposureSurface;
}

// -------------------------------------------------------------------------
// Axis 1 - local (LAN) peer discovery.
// -------------------------------------------------------------------------

/// "Notice peers near me." LAN-scoped (mDNS and the like); admitted only after the
/// global gate (PRD execution order: global Iroh discovery before LAN). Records its
/// exposure to the fabric ledger - even passive LAN presence discloses this node to
/// [`Recipient::LanPeer`](crate::Recipient::LanPeer).
#[async_trait]
pub trait LocalPeerDiscovery: Send + Sync {
    /// The peers currently noticed on the local network.
    async fn nearby_peers(&self) -> Vec<NodeId>;

    /// The a-priori exposure LAN discovery WILL incur when enabled (AC#3).
    fn declared_exposure(&self) -> ExposureSurface;
}
