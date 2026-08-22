//! The frozen, JCS-canonicalized, content-hashed per-profile operator budget artifact
//! (TASK-120 AC#10 — the out-of-box org/LAN cornerstone).
//!
//! ## What this is
//!
//! [`artifacts/profile-budget-v1.json`](../../../artifacts/profile-budget-v1.json) is the ONE
//! FROZEN source of truth for the numeric operator budget of EVERY [`SharingProfile`]. It
//! is a versioned JSON document of TYPED INTEGER, unit-suffixed fields (bytes/octets/counts/ns —
//! never a float). The daemon EMBEDS it and, before serving, verifies it against these independent
//! oracles, any of which FAIL-CLOSES startup:
//!
//! 1. **Content hash (freeze/identity — NOT human authorization)** — the daemon recomputes
//!    `BLAKE3(JCS(artifact))` and compares it to the checked-in [`EXPECTED_PROFILE_BUDGET_HASH`].
//!    This pins the artifact's CANONICAL JCS CONTENT: any content drift from the frozen value fails
//!    closed ([`BudgetError::HashDrift`]) — incidental whitespace/key-order reformatting is invariant
//!    by design (the hash is over the canonical form, not the raw bytes). Revising a budget forces a
//!    deliberate re-freeze of the
//!    constant (a reviewable one-line diff). It proves IDENTITY/immutability, NOT that a human
//!    approved the numbers — a content hash cannot attest human authorization. Treating the frozen
//!    hash as a proxy for "owner sign-off" would overclaim; a real attestation (signed approval) is
//!    a separate mechanism not built here.
//! 2. **Normative envelope** — every profile's single/inflight served NarSize and serve duration
//!    are checked against the PRD.md:839-842 admission envelope inherited by every sharing profile:
//!    **256 MiB single, 1 GiB inflight, 120 s**. The artifact may not even DECLARE a looser
//!    envelope than these normative constants. A profile at 512 MiB / 300 s FAILS
//!    ([`BudgetError::EnvelopeExceeded`]) — this is the bite AC#10 mandates.
//! 3. **Runtime parity** — the artifact's admission-envelope fields must equal the binary's frozen
//!    [`ResourceCaps::default`] SSOT, so the frozen document and the code's defaults cannot
//!    silently diverge ([`BudgetError::ParityMismatch`]). The tunable serve fields are additionally
//!    guarded post-override in step 2; parity itself is the default↔artifact check.
//!
//! An empty-input [`load`] yields [`BudgetError::Missing`], whose token is
//! `PROFILE_BUDGET_ARTIFACT_MISSING` (PRD.md:945) — never a zero or "unbounded" default. NOTE on
//! reachability (be precise): the SHIPPED daemon `include_str!`s the artifact, so a genuinely missing
//! file is a BUILD-TIME compile error (strictly stronger than a runtime check) and the embedded
//! string is never empty. There is NO filesystem/path-based loader in the repo today: [`load`] and
//! [`verify_raw`] take a raw string, and the `Missing` variant is exercised ONLY by in-module unit
//! tests (empty input). `PROFILE_BUDGET_ARTIFACT_MISSING` therefore has NO production caller yet — it
//! is the fail-closed contract a future filesystem/Stage-B loader (PRD.md:944) would use, not a path
//! that runs in the shipped daemon. Stated plainly so the doc does not imply a loader that isn't
//! there.
//!
//! ## Canonicalization (RFC 8785 JSON Canonicalization Scheme)
//!
//! The hash is taken over a CANONICAL byte form, not the pretty on-disk text, so a reviewer may
//! keep the file human-readable without perturbing the hash. The canonical form is compact JSON
//! (no insignificant whitespace) with object keys sorted lexicographically — produced by parsing to
//! [`serde_json::Value`] (whose object map is a sorted `BTreeMap`) and re-serializing. RFC 8785's
//! float-formatting and non-ASCII-escaping clauses are VACUOUS here by construction: every value is
//! a `u64` integer or an ASCII string, enforced by the typed [`ProfileBudgetArtifact`] schema (a
//! `1.0` fails `u64` deserialization and fails closed) and re-asserted by the
//! `every_field_is_an_integer_no_floats` test. We therefore implement the
//! integer/ASCII-string/object/array subset of JCS, which is exact for this document.
//!
//! LIMITATION: that subset is exact ONLY while every object key is ASCII and every value is an
//! integer/ASCII string — then serde_json's UTF-8 byte-order key sort coincides with JCS's UTF-16
//! order. A future non-ASCII key or a non-integer value would break the equivalence and demand a
//! real RFC 8785 implementation; the typed schema keeps that out today.
//!
//! ## Unit discipline (the recurring NarSize-vs-FileSize trap)
//!
//! `*_bytes_uncompressed_nar` fields are NarSize (addressed, uncompressed) and `*_compressed_wire`
//! fields are transport (compressed) octets — DIFFERENT UNITS. Parity and envelope checks compare
//! `bytes_uncompressed_nar` against `bytes_uncompressed_nar` ONLY; the compressed-wire upload fields
//! are a SEPARATE WIRE-OCTET axis and are never compared to a NarSize. The upload-RATE and its window
//! are runtime-enforced on that wire-octet axis by the TASK-299 shaper (below), which charges ACTUAL
//! wire octets — still never compared to a NarSize; the upload payload/total fields on that axis stay
//! declared-only.
//!
//! ## No floats (owner rule)
//!
//! Every field is a `u64`. There is no float anywhere in the schema, the artifact, or any
//! comparison/decision path here. Displaying a MiB figure to a human is a terminal concern of the
//! status/preflight surface, not of this module.
//!
//! ## Declared-only fields and where each is (or is not) enforced
//!
//! The artifact declares every profile budget, but only a SUBSET carries a limiter keyed to that
//! exact field. The honesty rule (inherited from [`ResourceCaps`]: no phantom bounds) is that a field
//! is advertised as ENFORCED only where a REAL bound — in-process, a runtime shaper/semaphore, OR a
//! shipped OS rlimit — actually caps against it, AND its effective value is surfaced. FOUR kinds of
//! enforced field exist, with DIFFERENT markers so a label never overclaims:
//!
//! ENVELOPE-ENFORCED (profile-invariant, parity-checked against [`ResourceCaps::default`];
//! [`ENFORCED_MARKER`]):
//!
//! * `single_nar_bytes_uncompressed_nar`, `inflight_nar_bytes_uncompressed_nar`, `serve_duration_ns`
//!   — enforced by `peer_fabric::ServeBudget` on the serve path (per-NAR decline + in-flight-BYTE
//!   CAS reservation + serve deadline), parity-checked against [`ResourceCaps::default`] and
//!   post-override envelope-guarded ([`check_serve_within_envelope`]).
//! * `discovery_deadline_ns` — enforced by `DiscoveryBudget` (non-tunable; default-parity-checked).
//!   Production INSTALLS this value from `ResourceCaps` (the discovery SSOT, TASK-120 AC#3), so the
//!   deadline in force cannot diverge from the one this surface advertises.
//!
//! SHAPER-ENFORCED (PROFILE-VARYING, NOT parity-checked against the flat `ResourceCaps` — the cap is
//! the per-profile frozen value itself, read from the verified artifact and enforced by a runtime
//! shaper; [`ENFORCED_SHAPER_MARKER`]):
//!
//! * `upload_rate_bytes_compressed_wire_per_window`, `upload_rate_window_ns` — enforced on the
//!   LIBP2P `/nar` SERVE-BODY EGRESS by `daemon_core::UploadRateLedger` (TASK-299). HONEST STRENGTH
//!   (codex #7): this is a COARSE, NON-RESERVING ADMISSION THRESHOLD, not an exact per-window byte
//!   ceiling — `admit_upload` is level-triggered (`used < cap`) and reserves nothing, so a window can
//!   overshoot `cap` by the concurrently-admitted volume (itself bounded by the enforced in-flight
//!   ceiling), enforcing a long-run rate AT MOST a hair above `cap/window` (see `upload_ledger.rs`).
//!   HONEST SCOPE: bounds the amplifying NAR-BODY egress on the libp2p serve path only — NOT the tiny
//!   request-gated protocol-control responses, NOT a non-serving profile (0 cap = no serve axis), NOT
//!   the iroh serve path (TASK-299 is libp2p-only). The `_compressed_wire` unit is transport octets,
//!   never a NarSize.
//!
//! SEMAPHORE-ENFORCED (PROFILE-VARYING, NOT parity-checked; [`ENFORCED_SEMAPHORE_MARKER`]):
//!
//! * `concurrent_serves_count` — enforced by the serve gate's ADMISSION-time count CAS (TASK-120
//!   AC#3): `fabric_libp2p::ServeGate::admit_plan` holds an in-flight-serve COUNT (a SERVER-owned
//!   counter shared across teardown→re-serve handoff) and DECLINES `Busy` once `n` serves are in
//!   flight, wired from this verified artifact via [`serve_concurrency`] →
//!   `Libp2pFabric::set_serve_concurrency` on BOTH shipped binaries. A COUNT bound DISTINCT from the
//!   in-flight-BYTE ceiling: a flood of tiny NARs slips under the byte cap but is bounded here. HONEST
//!   SCOPE: the CAS fires AFTER the request digest is read, so it bounds PARSED+ADMITTED serves, not
//!   the accept loop — pre-admission accepted streams are bounded only by transport connection/substream
//!   limits (a true accept-path semaphore is filed as hardening, not claimed). 0 for a non-serving
//!   profile (which installs no serve gate), 64 for the serving profiles (= the Bao serve-worker pool).
//!
//! OS-ENFORCEABLE (bounded AT the declared value by a shipped OS mechanism UNDER the nix-p2p unit;
//! live in-force state surfaced; [`ENFORCED_OS_MARKER`]):
//!
//! * `open_fds_count` — the shipped systemd unit (`nixos/nix-p2p.nix`) sets `LimitNOFILE` from this
//!   profile's frozen value, capping the process's HARD `RLIMIT_NOFILE` AT the declared value (far
//!   below systemd's ~512K default) — a REAL kernel bound. Distinct from the advisory RAM/disk figures:
//!   this OS mechanism enforces THE DECLARED VALUE exactly. But only UNDER the unit — a binary launched
//!   directly keeps the default rlimit, which is NOT this bound (codex P2). The preflight line resolves
//!   that by SURFACING the live effective hard `RLIMIT_NOFILE` AND whether it is IN FORCE (effective ≤
//!   declared), so the operator never reads a claimed-but-absent ceiling.
//!
//! And `announce_count` is none of these: runtime-limited by the announce limiter but OPERATOR-CHOSEN
//! and NOT a safety envelope ([`ANNOUNCE_TUNABLE_MARKER`]).
//!
//! Every OTHER field (ten of them) is DECLARED-ONLY: a frozen, content-hashed contract BUDGET with no
//! runtime shaper/limiter of its own. It is surfaced in preflight with [`DECLARED_ONLY_MARKER`] and is
//! NOT parity-checked (advertising a parity we do not enforce would be a phantom bound). A
//! field-by-field review found that none clears the "tractable AND net-positive AND mutation-biteable"
//! bar for a dedicated in-process shaper, and — decisively — for all but the lone advisory figure the
//! underlying RESOURCE is ALREADY bounded by an ENFORCED sibling. Each carries a RECORDED TERMINAL
//! DECISION ([`Disposition`]), not a deferral. AC#3 asks that each RESOURCE be "bounded, documented
//! and visible"; a resource is honestly bounded when SOMETHING provably caps its growth, which need
//! not be a limiter keyed to that exact JSON field.
//!
//! The two terminal dispositions (see [`Disposition`] and [`DECLARED_ONLY_FIELD_DISPOSITIONS`]):
//!
//! * [`Disposition::CapacityOnly`] — an ADVISORY planning figure with NO limiter enforcing it AT the
//!   declared value, surfaced honestly as advisory and NEVER implying a bound exists there. The
//!   underlying RESOURCE may be bounded by an enforced control, but that control sits FAR from this
//!   declared figure (a different unit, or orders of magnitude away), so the declared VALUE is not
//!   enforced (codex P2: "redundant" would overstate). Five members:
//!   * `upload_total_bytes_compressed_wire` — LIFETIME egress: no in-process limiter AND no shipped OS
//!     knob bounds it (a rate over unbounded uptime is an unbounded total); enforced NOWHERE.
//!   * `upload_payload_bytes_compressed_wire` — a per-serve compressed-WIRE octet figure with no
//!     limiter keyed to it. NOT a NarSize and NOT equated to `single_nar` (the NarSize-vs-wire trap).
//!     Only INDIRECTLY bounded (the single_nar magnitude of the one NAR a serve streams, cross-unit;
//!     and the long-run rate shaper, which does NOT contain a single serve — at an empty window a serve
//!     can stream its full body past one window's rate cap, payload 256 MiB > rate 128 MiB/window).
//!   * `transient_ram_bytes_ram` — the LOAD-BEARING transient RAM (the in-flight NAR buffer) IS bounded
//!     by the enforced in-flight-byte ceiling (`ServeBudget`, 1 GiB) + the 256 KiB fetch-handoff window,
//!     and TOTAL process RSS by the shipped `systemd` `MemoryMax` cgroup backstop (2x the inflight
//!     envelope, when run under the nix-p2p unit; effective `memory.max` SURFACED on the preflight
//!     line) — but BOTH bound the resource FAR ABOVE this declared working-set figure, not at it, so the
//!     declared value is advisory (no in-process RSS accounting enforces it; `MemoryMax` deliberately is
//!     not set to a working-set figure below the inflight ceiling, which would OOM the daemon).
//!   * `apparent_disk_bytes_ondisk`, `allocated_disk_bytes_ondisk` — the serve path holds NOTHING at
//!     rest (regenerates on demand); the narinfo cache is entry-count capped, but at ~195 GiB (100k
//!     entries × ≤ 2 MiB) — FAR above the declared budget, so it does not bound it — and with
//!     `--libp2p-state-dir` the durable announced-key floor (`DurableSeqFloor`) persists WITHOUT
//!     eviction (an at-rest growth vector no byte cap bounds, TASK-188). Advisory; an aggregate on-disk
//!     byte quota is an operator OS choice nix-p2p does not ship.
//! * [`Disposition::Politeness`] — operator-tunable self-limiting volume, or coarsely bounded by an
//!   enforced deadline/count; octet-precision is not a safety envelope:
//!   * `discovery_work_octets`, `discovery_control_octets` — a consultation is already bounded by the
//!     enforced `discovery_deadline_ns` + `discovery_max_peers`; octet-precise shaping adds no safety
//!     bound over the deadline/peer cap.
//!   * `announce_wire_octets`, `announce_rate_octets_per_window`, `announce_rate_window_ns` —
//!     announce volume is operator-tunable via `announce_count` (`--libp2p-announce-budget`) and
//!     deadline-bounded (the announcer's publish timeout); per-announce octet shaping is self-limiting
//!     politeness, not a network-safety ceiling. `announce_count` ONLY bounds announce-AFTER-FETCH
//!     growth (the static-seed and re-sign announce loops do not consult it), so it is scoped honestly
//!     as that, not a total-announce-volume bound.
//!
//! [`DECLARED_ONLY_FIELD_DISPOSITIONS`] is the machine-readable form of these decisions, and
//! `declared_only_routing_is_locked` (with `declared_only_dispositions_are_terminal`) is the
//! mutation-biting test that fails if a field is silently reclassified (a phantom bound) without
//! wiring, or if its terminal disposition drifts.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::operator::{ResourceCaps, SharingProfile};

/// The frozen artifact, embedded at build time via `include_str!` (a missing file is a compile
/// error). The path-based [`load`] entry point / fail-closed `Missing` semantics have NO production
/// caller today — they are exercised only by unit tests and are the fail-closed contract a future
/// filesystem/Stage-B loader would use; the daemon uses the embedded copy so it can never ship
/// without its budget contract.
pub const PROFILE_BUDGET_ARTIFACT_JSON: &str =
    include_str!("../../artifacts/profile-budget-v1.json");

/// The relative repo path of the frozen artifact (for status/preflight display + tooling).
pub const PROFILE_BUDGET_ARTIFACT_PATH: &str = "artifacts/profile-budget-v1.json";

/// The frozen content hash: `BLAKE3(JCS(artifact))`, lowercase hex. It pins the artifact's CANONICAL
/// JCS CONTENT — a human who revises a budget re-runs [`content_hash`] and updates this constant, and
/// the daemon fail-closes on any content drift (incidental whitespace/key-order reformatting is
/// invariant by design). It proves the content has not changed since this value was frozen; it does
/// NOT prove a human reviewed or authorized the numbers (a content hash cannot attest that).
pub const EXPECTED_PROFILE_BUDGET_HASH: &str =
    "66f5c2878ffea0faad8cb5de42346445664d729541913ace8d40d1235a9d39ae";

/// The stable fail-closed token for a missing artifact (PRD.md:945). Emitted in the
/// [`BudgetError::Missing`] display so an operator/harness sees exactly this string.
pub const PROFILE_BUDGET_ARTIFACT_MISSING: &str = "PROFILE_BUDGET_ARTIFACT_MISSING";

// --- The normative admission envelope (PRD.md:839-842) ----------------------
// INTEGER ceilings inherited by EVERY sharing profile. Not floats, not derived at runtime.

/// Max single served NarSize: 256 MiB (uncompressed NAR bytes).
pub const ENVELOPE_MAX_SINGLE_NAR_BYTES: u64 = 256 * 1024 * 1024;
/// Max aggregate in-flight served NarSize: 1 GiB (uncompressed NAR bytes).
pub const ENVELOPE_MAX_INFLIGHT_NAR_BYTES: u64 = 1024 * 1024 * 1024;
/// Max serve duration: 120 s, expressed in nanoseconds (the artifact's `_ns` unit).
pub const ENVELOPE_MAX_SERVE_DURATION_NS: u64 = 120 * 1_000_000_000;

/// One profile's complete typed budget. Every field is a `u64` with a unit suffix. Missing or
/// unknown fields FAIL CLOSED (`deny_unknown_fields`; serde requires every field present).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileBudget {
    /// Per-serve compressed transport payload ceiling (octets on the wire, NOT NarSize).
    pub upload_payload_bytes_compressed_wire: u64,
    /// Aggregate compressed transport upload ceiling (octets on the wire).
    pub upload_total_bytes_compressed_wire: u64,
    /// Upload shaper ceiling: compressed octets per [`upload_rate_window_ns`](ProfileBudget) window.
    pub upload_rate_bytes_compressed_wire_per_window: u64,
    /// The upload-rate window, ns (an explicit integer window — never a float rate).
    pub upload_rate_window_ns: u64,
    /// Concurrent serves permitted (a COUNT).
    pub concurrent_serves_count: u64,
    /// Single served NarSize ceiling (uncompressed NAR bytes). Bounded by the envelope.
    pub single_nar_bytes_uncompressed_nar: u64,
    /// Aggregate in-flight served NarSize ceiling (uncompressed NAR bytes). Bounded by the envelope.
    pub inflight_nar_bytes_uncompressed_nar: u64,
    /// Transient RAM ceiling (bytes).
    pub transient_ram_bytes_ram: u64,
    /// Apparent on-disk footprint ceiling (bytes).
    pub apparent_disk_bytes_ondisk: u64,
    /// Allocated (block-rounded) on-disk footprint ceiling (bytes).
    pub allocated_disk_bytes_ondisk: u64,
    /// Open file-descriptor ceiling (a COUNT).
    pub open_fds_count: u64,
    /// Discovery/hold-query WORK payload ceiling per consultation (octets).
    pub discovery_work_octets: u64,
    /// Discovery/hold-query CONTROL overhead ceiling per consultation (octets).
    pub discovery_control_octets: u64,
    /// Discovery consultation deadline, ns.
    pub discovery_deadline_ns: u64,
    /// Distinct announced paths ceiling (a COUNT).
    pub announce_count: u64,
    /// Announce wire ceiling per announce (octets).
    pub announce_wire_octets: u64,
    /// Announce shaper ceiling: octets per [`announce_rate_window_ns`](ProfileBudget) window.
    pub announce_rate_octets_per_window: u64,
    /// The announce-rate window, ns.
    pub announce_rate_window_ns: u64,
    /// Serve reservation duration ceiling, ns. Bounded by the envelope.
    pub serve_duration_ns: u64,
}

/// The declared normative envelope inside the artifact. The daemon refuses an artifact whose
/// declared envelope does not EQUAL the [`ENVELOPE_MAX_*`](ENVELOPE_MAX_SINGLE_NAR_BYTES) constants,
/// so the artifact cannot weaken the ceiling it is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormativeEnvelope {
    /// Must equal [`ENVELOPE_MAX_SINGLE_NAR_BYTES`].
    pub max_single_nar_bytes_uncompressed_nar: u64,
    /// Must equal [`ENVELOPE_MAX_INFLIGHT_NAR_BYTES`].
    pub max_inflight_nar_bytes_uncompressed_nar: u64,
    /// Must equal [`ENVELOPE_MAX_SERVE_DURATION_NS`].
    pub max_serve_duration_ns: u64,
}

/// The freeze/revision marker (documentary; not part of any budget comparison, and NOT a human
/// authorization — the hash proves the canonical JCS content is frozen, not that anyone approved it).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewMarker {
    /// A human-readable revision label bumped on each deliberate re-freeze.
    pub reviewed_revision: String,
    /// A human-readable note describing what the freeze hash does (and does not) attest.
    pub reviewed_note: String,
}

/// The whole frozen artifact.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileBudgetArtifact {
    /// The schema version (bumped on any incompatible field change).
    pub schema_version: u32,
    /// The freeze/revision marker.
    pub review: ReviewMarker,
    /// The declared normative envelope (must equal the `ENVELOPE_MAX_*` constants).
    pub envelope: NormativeEnvelope,
    /// Per-profile budgets, keyed by the [`SharingProfile::as_str`] token. A `BTreeMap` so the key
    /// order is canonical.
    pub profiles: BTreeMap<String, ProfileBudget>,
}

/// A fail-closed budget-artifact violation. NONE of these may be swallowed into a default: a bad or
/// absent budget contract must block startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetError {
    /// The artifact bytes are absent/empty. Token: `PROFILE_BUDGET_ARTIFACT_MISSING`.
    Missing,
    /// The artifact did not parse as the typed schema (bad field, wrong type, a float, an unknown
    /// key, a missing field).
    Parse(String),
    /// The recomputed content hash disagrees with [`EXPECTED_PROFILE_BUDGET_HASH`].
    HashDrift {
        /// The expected (frozen) hash.
        expected: String,
        /// The hash recomputed from the artifact's canonical JCS content.
        actual: String,
    },
    /// The artifact's DECLARED envelope does not equal the normative `ENVELOPE_MAX_*` constants.
    EnvelopeMismatch {
        /// Which envelope field disagrees.
        field: &'static str,
        /// The normative constant.
        normative: u64,
        /// The value the artifact declared.
        declared: u64,
    },
    /// A profile's budget exceeds the normative envelope (e.g. 512 MiB single / 300 s serve). THE
    /// AC#10 BITE.
    EnvelopeExceeded {
        /// The offending profile token.
        profile: String,
        /// Which field exceeded (`single_nar_bytes_uncompressed_nar`, `serve_duration_ns`, ...).
        field: &'static str,
        /// The declared value.
        value: u64,
        /// The normative ceiling it exceeded.
        ceiling: u64,
    },
    /// A named profile expected by the runtime is absent from the artifact.
    ProfileAbsent {
        /// The missing profile token.
        profile: String,
    },
    /// The artifact's enforced field disagrees with the live [`ResourceCaps`].
    ParityMismatch {
        /// The offending profile token.
        profile: String,
        /// Which enforced field disagrees.
        field: &'static str,
        /// The value the artifact froze.
        artifact: u64,
        /// The value the runtime caps enforce.
        runtime: u64,
    },
    /// An EFFECTIVE (post-CLI-override) serve budget value exceeds the frozen normative envelope.
    /// This is the runtime-bypass guard: an operator override may only TIGHTEN the frozen ceiling,
    /// never loosen it, so whatever value actually reaches `ServeBudget` is provably within the
    /// envelope on every serve path.
    OverrideExceedsEnvelope {
        /// Which effective field exceeded (`single_nar_bytes_uncompressed_nar`, ...).
        field: &'static str,
        /// The effective (override) value.
        value: u64,
        /// The frozen normative ceiling it exceeded.
        ceiling: u64,
    },
    /// An internal integer overflow while converting a runtime cap to `_ns` for comparison
    /// (fail-closed rather than wrap).
    Overflow {
        /// What was being computed.
        what: &'static str,
    },
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetError::Missing => write!(f, "{PROFILE_BUDGET_ARTIFACT_MISSING}"),
            BudgetError::Parse(e) => write!(f, "profile budget artifact did not parse: {e}"),
            BudgetError::HashDrift { expected, actual } => write!(
                f,
                "profile budget artifact hash drift: frozen {expected}, got {actual} \
                 (recompute and re-freeze EXPECTED_PROFILE_BUDGET_HASH)"
            ),
            BudgetError::EnvelopeMismatch {
                field,
                normative,
                declared,
            } => write!(
                f,
                "profile budget artifact declares a non-normative envelope: {field} normative \
                 {normative}, declared {declared}"
            ),
            BudgetError::EnvelopeExceeded {
                profile,
                field,
                value,
                ceiling,
            } => write!(
                f,
                "profile '{profile}' budget field {field}={value} exceeds normative ceiling \
                 {ceiling}"
            ),
            BudgetError::ProfileAbsent { profile } => {
                write!(f, "profile budget artifact has no entry for '{profile}'")
            }
            BudgetError::ParityMismatch {
                profile,
                field,
                artifact,
                runtime,
            } => write!(
                f,
                "profile '{profile}' budget field {field}: artifact froze {artifact} but runtime \
                 caps enforce {runtime} (divergence)"
            ),
            BudgetError::OverrideExceedsEnvelope {
                field,
                value,
                ceiling,
            } => write!(
                f,
                "effective serve override {field}={value} exceeds the frozen normative ceiling \
                 {ceiling} (an override may only tighten the envelope, never loosen it)"
            ),
            BudgetError::Overflow { what } => {
                write!(f, "integer overflow computing {what}")
            }
        }
    }
}

impl std::error::Error for BudgetError {}

/// The canonical (JCS-subset) byte form of a JSON document: compact, object keys sorted. Exact for
/// the integer/ASCII-string/object/array subset this artifact lives in.
fn canonicalize(raw: &str) -> Result<Vec<u8>, BudgetError> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| BudgetError::Parse(e.to_string()))?;
    // serde_json::Value's object map is a sorted BTreeMap (no preserve_order feature), so
    // to_vec emits compact, lexicographically key-sorted JSON — the canonical form we hash.
    serde_json::to_vec(&value).map_err(|e| BudgetError::Parse(e.to_string()))
}

/// The content hash of a raw artifact string: `BLAKE3(JCS(raw))`, lowercase hex.
pub fn content_hash(raw: &str) -> Result<String, BudgetError> {
    let canonical = canonicalize(raw)?;
    Ok(blake3::hash(&canonical).to_hex().to_string())
}

/// Parse raw artifact bytes into the typed schema. Empty/whitespace-only input is
/// [`BudgetError::Missing`] (`PROFILE_BUDGET_ARTIFACT_MISSING`); a float, unknown key, missing
/// field or wrong type is [`BudgetError::Parse`]. Does NOT hash/envelope/parity-check — see
/// [`verify`].
pub fn load(raw: &str) -> Result<ProfileBudgetArtifact, BudgetError> {
    if raw.trim().is_empty() {
        return Err(BudgetError::Missing);
    }
    serde_json::from_str(raw).map_err(|e| BudgetError::Parse(e.to_string()))
}

/// Check that the artifact's declared envelope equals the normative constants AND that no profile
/// exceeds them. THE AC#10 BITE lives here: a 512 MiB single or 300 s serve fails.
pub fn validate_envelope(artifact: &ProfileBudgetArtifact) -> Result<(), BudgetError> {
    let env = &artifact.envelope;
    if env.max_single_nar_bytes_uncompressed_nar != ENVELOPE_MAX_SINGLE_NAR_BYTES {
        return Err(BudgetError::EnvelopeMismatch {
            field: "max_single_nar_bytes_uncompressed_nar",
            normative: ENVELOPE_MAX_SINGLE_NAR_BYTES,
            declared: env.max_single_nar_bytes_uncompressed_nar,
        });
    }
    if env.max_inflight_nar_bytes_uncompressed_nar != ENVELOPE_MAX_INFLIGHT_NAR_BYTES {
        return Err(BudgetError::EnvelopeMismatch {
            field: "max_inflight_nar_bytes_uncompressed_nar",
            normative: ENVELOPE_MAX_INFLIGHT_NAR_BYTES,
            declared: env.max_inflight_nar_bytes_uncompressed_nar,
        });
    }
    if env.max_serve_duration_ns != ENVELOPE_MAX_SERVE_DURATION_NS {
        return Err(BudgetError::EnvelopeMismatch {
            field: "max_serve_duration_ns",
            normative: ENVELOPE_MAX_SERVE_DURATION_NS,
            declared: env.max_serve_duration_ns,
        });
    }
    for (profile, b) in &artifact.profiles {
        // Compare like-units ONLY: NarSize against NarSize, ns against ns.
        if b.single_nar_bytes_uncompressed_nar > ENVELOPE_MAX_SINGLE_NAR_BYTES {
            return Err(BudgetError::EnvelopeExceeded {
                profile: profile.clone(),
                field: "single_nar_bytes_uncompressed_nar",
                value: b.single_nar_bytes_uncompressed_nar,
                ceiling: ENVELOPE_MAX_SINGLE_NAR_BYTES,
            });
        }
        if b.inflight_nar_bytes_uncompressed_nar > ENVELOPE_MAX_INFLIGHT_NAR_BYTES {
            return Err(BudgetError::EnvelopeExceeded {
                profile: profile.clone(),
                field: "inflight_nar_bytes_uncompressed_nar",
                value: b.inflight_nar_bytes_uncompressed_nar,
                ceiling: ENVELOPE_MAX_INFLIGHT_NAR_BYTES,
            });
        }
        if b.serve_duration_ns > ENVELOPE_MAX_SERVE_DURATION_NS {
            return Err(BudgetError::EnvelopeExceeded {
                profile: profile.clone(),
                field: "serve_duration_ns",
                value: b.serve_duration_ns,
                ceiling: ENVELOPE_MAX_SERVE_DURATION_NS,
            });
        }
    }
    Ok(())
}

/// The frozen budget for one profile, or [`BudgetError::ProfileAbsent`].
pub fn budget_for(
    artifact: &ProfileBudgetArtifact,
    profile: SharingProfile,
) -> Result<&ProfileBudget, BudgetError> {
    artifact
        .profiles
        .get(profile.as_str())
        .ok_or_else(|| BudgetError::ProfileAbsent {
            profile: profile.as_str().to_string(),
        })
}

/// Milliseconds -> nanoseconds, fail-closed on overflow (never wrap).
fn ms_to_ns(ms: u64, what: &'static str) -> Result<u64, BudgetError> {
    ms.checked_mul(1_000_000)
        .ok_or(BudgetError::Overflow { what })
}

/// Parity: the artifact's admission-envelope fields must equal the binary's frozen
/// [`ResourceCaps::default`] for `profile` — the single / inflight served NarSize, the serve duration
/// and the discovery deadline. This proves the code's FROZEN DEFAULTS match the frozen artifact. The
/// served-NarSize and serve-duration fields ARE operator-tunable via `--iroh-max-serve-*` and are
/// additionally guarded post-override so an override can only tighten them
/// ([`check_serve_within_envelope`]); the discovery deadline is non-tunable (always the default). A
/// divergence of the defaults here is a code bug the gate must bite.
///
/// The distinct-announce COUNT is deliberately NOT parity-checked: it is an OPERATOR-TUNABLE budget
/// (`daemon-libp2p --libp2p-announce-budget` overrides `caps.announce_distinct_paths_budget`), so a
/// legitimate operator override would falsely trip a runtime parity. The artifact's `announce_count`
/// is the frozen DEFAULT; that it equals the code default is asserted separately in a test
/// (`artifact_announce_count_matches_the_code_default`) against [`ResourceCaps::default`], the SSOT
/// check that belongs at build/test time, not at every startup. The compressed-wire upload
/// PAYLOAD/TOTAL fields, RAM and disk are DECLARED-ONLY contract budgets not wired to a runtime
/// limiter keyed to that field (see the module doc's "Declared-only fields" section and
/// [`DECLARED_ONLY_FIELD_DISPOSITIONS`] for each field's terminal disposition), so they too are not
/// parity-checked against `caps` — advertising a parity we do not enforce would be the phantom-bound
/// dishonesty `ResourceCaps` already refuses. The upload-RATE/window fields (TASK-299 shaper) and
/// `concurrent_serves_count` (the serve-gate semaphore, TASK-120 AC#3) ARE runtime-enforced but are
/// STILL not parity-checked here: they are profile-VARYING, so the enforced cap is the frozen
/// per-profile value itself (read from the verified artifact), with no profile-invariant
/// `ResourceCaps` SSOT to parity against. `open_fds_count` is enforced by the shipped systemd
/// `LimitNOFILE` rlimit (an OS mechanism, not a `caps` field), likewise not parity-checked here.
pub fn parity_with_caps(
    profile: SharingProfile,
    budget: &ProfileBudget,
    caps: &ResourceCaps,
) -> Result<(), BudgetError> {
    let token = profile.as_str().to_string();
    if budget.single_nar_bytes_uncompressed_nar != caps.max_nar_bytes_uncompressed {
        return Err(BudgetError::ParityMismatch {
            profile: token,
            field: "single_nar_bytes_uncompressed_nar",
            artifact: budget.single_nar_bytes_uncompressed_nar,
            runtime: caps.max_nar_bytes_uncompressed,
        });
    }
    if budget.inflight_nar_bytes_uncompressed_nar != caps.max_inflight_bytes_uncompressed {
        return Err(BudgetError::ParityMismatch {
            profile: token,
            field: "inflight_nar_bytes_uncompressed_nar",
            artifact: budget.inflight_nar_bytes_uncompressed_nar,
            runtime: caps.max_inflight_bytes_uncompressed,
        });
    }
    let caps_serve_ns = ms_to_ns(caps.serve_duration_ms, "serve_duration_ns")?;
    if budget.serve_duration_ns != caps_serve_ns {
        return Err(BudgetError::ParityMismatch {
            profile: token,
            field: "serve_duration_ns",
            artifact: budget.serve_duration_ns,
            runtime: caps_serve_ns,
        });
    }
    let caps_disc_ns = ms_to_ns(caps.discovery_deadline_ms, "discovery_deadline_ns")?;
    if budget.discovery_deadline_ns != caps_disc_ns {
        return Err(BudgetError::ParityMismatch {
            profile: token,
            field: "discovery_deadline_ns",
            artifact: budget.discovery_deadline_ns,
            runtime: caps_disc_ns,
        });
    }
    // announce_count is intentionally NOT parity-checked here — it is operator-tunable (see doc).
    Ok(())
}

/// The runtime-bypass guard (codex #1): the EFFECTIVE serve budget that will actually reach
/// [`peer_fabric::ServeBudget`] — AFTER any CLI override — must be within the frozen normative
/// envelope. An override may only TIGHTEN it. A `single`/`inflight`/`serve_duration_ns` above the
/// frozen ceiling fails closed with [`BudgetError::OverrideExceedsEnvelope`], so a
/// `--iroh-max-serve-nar-bytes 536870912` (512 MiB) can never widen the shipped 256 MiB ceiling.
/// Call this at startup with the SAME values the binary will hand to `ServeBudget`, on every serve
/// path.
pub fn check_serve_within_envelope(
    single_nar_bytes_uncompressed_nar: u64,
    inflight_nar_bytes_uncompressed_nar: u64,
    serve_duration_ns: u64,
) -> Result<(), BudgetError> {
    if single_nar_bytes_uncompressed_nar > ENVELOPE_MAX_SINGLE_NAR_BYTES {
        return Err(BudgetError::OverrideExceedsEnvelope {
            field: "single_nar_bytes_uncompressed_nar",
            value: single_nar_bytes_uncompressed_nar,
            ceiling: ENVELOPE_MAX_SINGLE_NAR_BYTES,
        });
    }
    if inflight_nar_bytes_uncompressed_nar > ENVELOPE_MAX_INFLIGHT_NAR_BYTES {
        return Err(BudgetError::OverrideExceedsEnvelope {
            field: "inflight_nar_bytes_uncompressed_nar",
            value: inflight_nar_bytes_uncompressed_nar,
            ceiling: ENVELOPE_MAX_INFLIGHT_NAR_BYTES,
        });
    }
    if serve_duration_ns > ENVELOPE_MAX_SERVE_DURATION_NS {
        return Err(BudgetError::OverrideExceedsEnvelope {
            field: "serve_duration_ns",
            value: serve_duration_ns,
            ceiling: ENVELOPE_MAX_SERVE_DURATION_NS,
        });
    }
    Ok(())
}

/// [`check_serve_within_envelope`] taking serve duration in MILLISECONDS (the CLI unit), converting
/// fail-closed to ns (a huge ms value saturates and therefore correctly EXCEEDS the ceiling).
pub fn check_serve_ms_within_envelope(
    single_nar_bytes_uncompressed_nar: u64,
    inflight_nar_bytes_uncompressed_nar: u64,
    serve_duration_ms: u64,
) -> Result<(), BudgetError> {
    let serve_duration_ns = serve_duration_ms.saturating_mul(1_000_000);
    check_serve_within_envelope(
        single_nar_bytes_uncompressed_nar,
        inflight_nar_bytes_uncompressed_nar,
        serve_duration_ns,
    )
}

/// The runtime EGRESS (upload-rate) budget the active `profile` enforces on the serve path
/// (TASK-299), sourced from the VERIFIED frozen artifact — so the cap the shaper enforces has the
/// same provenance as every other budget number: the content-hashed, envelope-checked,
/// parity-checked artifact, and a serve can never run on an unverified cap (this fail-closes on the
/// same checks as [`verify`]). The cap is the profile's frozen
/// `upload_rate_bytes_compressed_wire_per_window`; the window is its `upload_rate_window_ns`
/// (integer nanoseconds → [`std::time::Duration`], never a float).
///
/// PROFILE-VARYING by design (this is why it is sourced here, not from the flat, profile-invariant
/// `ResourceCaps`): 0 for a non-serving profile (upstream-only/consume-only/router — no serve axis,
/// so a 0 cap means "serve nothing", the safe direction), 128 MiB / 1 s window for
/// lan-share/public-share. The composition root builds a `daemon_core::UploadRateLedger` from this
/// and wires it onto the serve gate.
pub fn upload_budget(
    profile: SharingProfile,
    caps: &ResourceCaps,
) -> Result<peer_fabric::UploadBudget, BudgetError> {
    let artifact = verify(profile, caps)?;
    let b = budget_for(&artifact, profile)?;
    Ok(peer_fabric::UploadBudget {
        max_bytes_per_window: b.upload_rate_bytes_compressed_wire_per_window,
        window: std::time::Duration::from_nanos(b.upload_rate_window_ns),
    })
}

/// The runtime CONCURRENT-SERVE COUNT ceiling the active `profile` enforces on the serve path
/// (TASK-120 AC#3), sourced from the VERIFIED frozen artifact — so the count the serve gate's
/// admission semaphore enforces has the same provenance as every other budget number: the
/// content-hashed, envelope-checked, parity-checked artifact (this fail-closes on the same checks as
/// [`verify`]). The cap is the profile's frozen `concurrent_serves_count`. PROFILE-VARYING like the
/// upload budget: `0` for a non-serving profile (which installs no serve gate anyway), `64` for
/// lan-share/public-share. The composition root wires this onto the serve gate via
/// `fabric_libp2p::Libp2pFabric::set_serve_concurrency`, so the `n+1`th concurrent serve is DECLINED.
pub fn serve_concurrency(profile: SharingProfile, caps: &ResourceCaps) -> Result<u64, BudgetError> {
    let artifact = verify(profile, caps)?;
    let b = budget_for(&artifact, profile)?;
    Ok(b.concurrent_serves_count)
}

/// The full fail-closed verification for a running binary: load the EMBEDDED artifact, verify its
/// content hash against the frozen [`EXPECTED_PROFILE_BUDGET_HASH`], check the normative envelope
/// for every profile, then parity-check `profile`'s enforced fields against `caps`. Returns the
/// verified artifact on success; ANY failure blocks startup.
pub fn verify(
    profile: SharingProfile,
    caps: &ResourceCaps,
) -> Result<ProfileBudgetArtifact, BudgetError> {
    verify_raw(
        PROFILE_BUDGET_ARTIFACT_JSON,
        EXPECTED_PROFILE_BUDGET_HASH,
        profile,
        caps,
    )
}

/// [`verify`] against explicit raw bytes + expected hash (the testable core; `verify` supplies the
/// embedded artifact and the frozen hash).
pub fn verify_raw(
    raw: &str,
    expected_hash: &str,
    profile: SharingProfile,
    caps: &ResourceCaps,
) -> Result<ProfileBudgetArtifact, BudgetError> {
    let artifact = load(raw)?;
    let actual = content_hash(raw)?;
    if actual != expected_hash {
        return Err(BudgetError::HashDrift {
            expected: expected_hash.to_string(),
            actual,
        });
    }
    validate_envelope(&artifact)?;
    let budget = budget_for(&artifact, profile)?;
    parity_with_caps(profile, budget, caps)?;
    Ok(artifact)
}

/// The preflight/status lines that make the frozen artifact VISIBLE (AC#3/#10): the artifact path,
/// its content hash, and the selected profile's typed integer FROZEN CEILING budget. Integers only —
/// a human MiB gloss is a terminal display concern, not stored here. This surfaces the frozen
/// artifact (the CEILING), which is separate from the caller's "effective resource controls" display
/// (the values actually in force, possibly a tightened override). Verification here is the
/// artifact↔frozen-DEFAULT SSOT (against [`ResourceCaps::default`]), independent of any runtime
/// override — a tightening override must not make this fail. Fail-closed: if the embedded artifact
/// does not verify, the lines say so loudly rather than pretending a budget exists.
pub fn preflight_lines(profile: SharingProfile) -> Vec<String> {
    let mut out = Vec::new();
    match verify(profile, &ResourceCaps::default()) {
        Ok(artifact) => {
            out.push(format!(
                "frozen profile-budget artifact: {PROFILE_BUDGET_ARTIFACT_PATH} \
                 (schema v{}, blake3={})",
                artifact.schema_version, EXPECTED_PROFILE_BUDGET_HASH
            ));
            out.push(format!(
                "  normative envelope: single_nar={} inflight_nar={} serve_duration_ns={} \
                 (256 MiB / 1 GiB / 120 s)",
                ENVELOPE_MAX_SINGLE_NAR_BYTES,
                ENVELOPE_MAX_INFLIGHT_NAR_BYTES,
                ENVELOPE_MAX_SERVE_DURATION_NS
            ));
            match budget_for(&artifact, profile) {
                Ok(b) => {
                    for line in budget_lines(b) {
                        out.push(format!("  {line}"));
                    }
                }
                Err(e) => out.push(format!("  BUDGET ERROR: {e}")),
            }
        }
        Err(e) => {
            // Fail-closed and LOUD: a running binary refuses to start on this; preflight prints it.
            out.push(format!(
                "profile-budget artifact FAILED verification ({PROFILE_BUDGET_ARTIFACT_PATH}): {e}"
            ));
        }
    }
    out
}

/// The marker appended to a declared-but-not-runtime-shaped budget line so an operator is never
/// misled into reading it as a ceiling enforced by a limiter keyed to that field (the
/// `effective_lines` honesty rule extended to the artifact surface). It is followed on the same line
/// by the field's TERMINAL [`Disposition`] class + the recorded reason (see
/// [`DECLARED_ONLY_FIELD_DISPOSITIONS`] and the module-level "Declared-only fields" section): the
/// underlying resource IS bounded (by an enforced sibling field, an in-process concurrency bound, or
/// — for the pure lifetime-egress planning figure — states plainly that nothing bounds it), just not
/// by a shaper on this exact JSON field. Says "declared BUDGET", never "declared ceiling": a member
/// (lifetime egress) has NO mechanism at all, so "ceiling" would overclaim a bound that does not
/// exist — the neutral "budget" plus the per-field disposition label carries the exact truth.
const DECLARED_ONLY_MARKER: &str = "  [declared budget — not runtime-shaped on this field]";
/// The marker for the per-profile CONCURRENT-SERVE COUNT ceiling (`concurrent_serves_count`,
/// TASK-120 AC#3): PROFILE-VARYING, enforced against its OWN frozen per-profile value — NOT
/// envelope-bounded and NOT parity-checked against the flat `ResourceCaps` (there is no separate SSOT:
/// the enforced cap IS the frozen value).
///
/// HONEST SCOPE (codex): the bound is at serve ADMISSION, NOT the accept loop. `fabric_libp2p`'s
/// accept loop (`swarm.rs`) still spawns every accepted stream; the `n`-permit ceiling is a CAS on the
/// in-flight-serve count in `ServeGate::admit_plan`, which fires AFTER the request digest is read — so
/// it bounds PARSED+ADMITTED serves (the amplifying regenerate/stream work), and once `n` are in flight
/// the next admission is DECLINED `Busy`. PRE-admission accepted streams (a peer that connects but has
/// not yet sent an admissible request) are bounded only by the transport's connection/substream
/// limits, not by this count — a true accept-path semaphore is filed as hardening, not claimed here.
/// Kept mutually NON-SUBSTRING with the other markers so the single-marker classifier ([`tag_of`](self))
/// stays unambiguous.
const ENFORCED_SEMAPHORE_MARKER: &str = "  [enforced at serve ADMISSION — CAS bound on parsed+admitted serves, N from the active profile]";
/// The marker for a field OS-ENFORCEABLE by a SHIPPED mechanism (`open_fds_count`, TASK-120 AC#3): the
/// systemd unit `nixos/nix-p2p.nix` sets `LimitNOFILE` from this profile's frozen `open_fds_count`,
/// capping the process's hard `RLIMIT_NOFILE` AT the declared value (far below systemd's ~512K default)
/// — a REAL kernel bound, not a suggestion. Says "OS-enforceable ... UNDER the nix-p2p unit", not an
/// unconditional "enforced": a binary launched WITHOUT the unit (dev/direct) keeps the default rlimit,
/// which is not this bound (codex P2). The preflight line resolves that ambiguity by SURFACING the live
/// effective hard `RLIMIT_NOFILE` AND whether it is actually IN FORCE (effective ≤ declared) — so the
/// operator sees reality, never a claimed-but-absent bound. Kept mutually NON-SUBSTRING with the other
/// markers.
const ENFORCED_OS_MARKER: &str = "  [OS-enforceable via systemd LimitNOFILE under the nix-p2p unit — live rlimit + in-force state surfaced]";
/// The marker for a frozen, ENVELOPE-BOUNDED field. The post-override-guarded fields — single/inflight
/// served NarSize and serve duration ([`check_serve_within_envelope`]) — may be tightened by an
/// override but never loosened past the frozen ceiling. The discovery deadline is also frozen and
/// envelope-bound, but non-tunable: it is enforced by default-parity alone (there is no override to
/// guard). All are default-parity-checked against the artifact.
const ENFORCED_MARKER: &str = "  [enforced — envelope-bounded]";
/// The marker for `announce_count`: it IS applied by the runtime announce limiter, but its value is
/// OPERATOR-CHOSEN (`--libp2p-announce-budget`) and is NOT bounded by the safety envelope — it is
/// self-limiting politeness (how much this node advertises of what it fetched), not a network-safety
/// ceiling. HONEST SCOPE (codex #4): it bounds the announce-AFTER-FETCH growth only; the static-seed
/// and re-sign announce loops (`daemon-libp2p`) do NOT consult it, so it is NOT a total-announce-volume
/// bound. Labelled so it is not read as a frozen envelope bound nor a total-volume cap.
const ANNOUNCE_TUNABLE_MARKER: &str = "  [operator-overridable announce-after-fetch budget — runtime-limited, not a total-volume envelope]";
/// The marker for a PROFILE-VARYING field enforced by a runtime SHAPER against its OWN frozen
/// per-profile value (TASK-299) — NOT envelope-bounded and NOT parity-checked against the flat
/// `ResourceCaps` (there is no separate SSOT: the enforced cap IS the frozen value). Today this is
/// the upload-rate/window pair, enforced on the LIBP2P `/nar` SERVE-BODY EGRESS by
/// `daemon_core::UploadRateLedger`.
///
/// HONEST STRENGTH (codex #7): this is a COARSE, NON-RESERVING ADMISSION THRESHOLD, not an exact
/// per-window byte ceiling. `admit_upload` is level-triggered (`used < cap`) and reserves nothing, so
/// concurrently-arriving serves at an empty-window instant all pass and then charge — the window can
/// OVERSHOOT `cap` by the compressed-wire volume admitted in that instant (itself bounded by the
/// enforced in-flight ceiling). So the enforced long-run rate is AT MOST a hair above `cap/window`,
/// never below (see `upload_ledger.rs`); the label says "admission threshold", not "ceiling". Worded
/// to name the exact enforced path (libp2p `/nar` serve body, on a serving node) so it does NOT
/// overclaim: a non-serving profile (cap 0) runs no shaper, the iroh serve path is out of TASK-299
/// scope, and tiny protocol-control responses are outside the shaped envelope. Kept mutually
/// NON-SUBSTRING with the other markers so the single-marker classifier ([`tag_of`](self)) stays
/// unambiguous.
const ENFORCED_SHAPER_MARKER: &str =
    "  [enforced on libp2p /nar serve-body egress — coarse per-profile admission threshold]";

/// The TERMINAL disposition of a DECLARED-ONLY budget field: WHY it carries no dedicated in-process
/// shaper, and WHAT actually bounds the underlying resource. This is a RECORDED DECISION (TASK-120
/// AC#3 close-out / TASK-299 inc2), NOT a deferral — there is deliberately no `Deferred`/`FutureTask`
/// variant, so "we decided, we did not punt" is unrepresentable-otherwise and is asserted total over
/// the ten declared-only fields by `declared_only_dispositions_are_terminal`. (The
/// `concurrent_serves_count` and `open_fds_count` fields are NOT declared-only — they are now
/// runtime/OS-enforced, so they carry [`FieldTag::EnforcedSemaphore`]/[`FieldTag::EnforcedOs`], not a
/// disposition.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// An ADVISORY planning figure with NO limiter enforcing it AT the declared value. The underlying
    /// RESOURCE may be bounded by an enforced control (the inflight-byte ceiling for transient RAM, the
    /// narinfo entry-count eviction + the systemd MemoryMax backstop for disk/total-RSS, the single_nar
    /// magnitude + rate shaper for a per-serve wire body) — but those bounds sit FAR from this declared
    /// figure (a different unit, or orders of magnitude above it), so the declared VALUE is not
    /// enforced. Some members (lifetime egress) have NO mechanism at all. Surfaced honestly as advisory,
    /// NEVER advertised as a bound that exists at the declared value. Deliberately NOT called
    /// "redundant": codex showed the enforced siblings (1 GiB inflight, ~195 GiB narinfo cap, 128 MiB/s
    /// rate) do not make a 256 MiB / 400 MiB / 256 MiB declared figure redundant — they bound a DIFFERENT
    /// point.
    CapacityOnly,
    /// Operator-tunable self-limiting volume, or coarsely bounded by an enforced deadline/count;
    /// octet-precision is politeness, not a safety envelope.
    Politeness,
}

impl Disposition {
    /// The short, stable class token shown on the preflight declared-only line (after
    /// [`DECLARED_ONLY_MARKER`]). Kept free of any other honesty-marker substring so the
    /// single-marker classifier ([`tag_of`](self)) stays unambiguous.
    fn label(self) -> &'static str {
        match self {
            // Class-only token: the reason carries the detail (which enforced control bounds the
            // resource elsewhere, or that nothing does). Says "advisory", never implying a bound at
            // the declared value.
            Disposition::CapacityOnly => {
                "advisory (planning figure — not enforced at this value, see reason)"
            }
            Disposition::Politeness => "politeness",
        }
    }
}

/// The machine-readable TERMINAL DECISION for every DECLARED-ONLY field: `(field, disposition,
/// reason)`. ONE table (SSOT) — the disposition class and the prose reason live together so they
/// cannot drift. It exists so the classification cannot silently rot: `declared_only_routing_is_locked`
/// asserts this set is EXACTLY the set of fields tagged [`FieldTag::DeclaredOnly`] in [`budget_lines`]
/// (flipping a field to [`FieldTag::Enforced`] without removing it here — a phantom bound — or vice
/// versa fails the gate), and `declared_only_dispositions_are_terminal` asserts every entry resolves
/// to a terminal [`Disposition`] with a non-empty reason. `reason` is prose; the LOCKS are on the
/// field SET and the disposition classes.
const DECLARED_ONLY_FIELD_DISPOSITIONS: &[(&str, Disposition, &str)] = &[
    (
        "upload_payload_bytes_compressed_wire",
        Disposition::CapacityOnly,
        "a per-serve compressed-WIRE octet figure with NO limiter keyed to it at the declared value. \
         It is NOT a NarSize and is NOT equated to single_nar (different units — the NarSize-vs-wire \
         trap). The per-serve egress is only INDIRECTLY bounded: one serve streams ONE NAR whose \
         UNCOMPRESSED source is capped by the enforced single_nar (a cross-unit MAGNITUDE relation — \
         the wire body is that NAR compressed, same order modulo framing — NOT an exact per-serve wire \
         cap), and the TASK-299 rate shaper bounds SUSTAINED long-run egress (NOT a single serve, \
         which at an empty window can stream its full body PAST one window's rate cap: payload 256 MiB \
         > rate 128 MiB/window). So it is an advisory declared figure, not an enforced per-serve wire \
         ceiling",
    ),
    (
        "upload_total_bytes_compressed_wire",
        Disposition::CapacityOnly,
        "ADVISORY PLANNING FIGURE, not a ceiling — NO in-process limiter AND NO OS knob bounds \
         lifetime egress (a rate over unbounded uptime is an unbounded total); a lifetime egress quota \
         is an operator capacity-planning choice, enforced NOWHERE. Surfaced only so the operator sees \
         the planning intent, never implying a bound exists",
    ),
    (
        "transient_ram_bytes_ram",
        Disposition::CapacityOnly,
        "an ADVISORY per-profile working-set figure with NO limiter enforcing it AT the declared value. \
         The load-bearing transient RAM (the in-flight NAR buffer, the peer-triggerable-OOM surface) IS \
         bounded — by the enforced inflight-byte ceiling (ServeBudget, 1 GiB) + the 256 KiB \
         fetch-handoff window (InflightMeter) — and TOTAL process RSS by the shipped systemd MemoryMax \
         cgroup backstop (2x the inflight envelope = 2 GiB, when run under the nix-p2p unit; the \
         effective cgroup memory.max is surfaced on this line). But BOTH bound the resource FAR ABOVE \
         this declared figure (e.g. 256 MiB), NOT at it — no in-process RSS accounting enforces the \
         declared value (glibc-arena RSS is an unreliable oracle), and MemoryMax is deliberately not set \
         to it (a working-set figure below the 1 GiB inflight ceiling would OOM the daemon). So the \
         declared value is advisory capacity planning, not an enforced ceiling",
    ),
    (
        "apparent_disk_bytes_ondisk",
        Disposition::CapacityOnly,
        "an ADVISORY on-disk figure with NO limiter enforcing it AT the declared value. The libp2p serve \
         path holds NOTHING at rest (regenerates each NAR on demand); the narinfo cache is entry-count \
         capped (narinfo_cache_max_entries), but that cap is ~195 GiB (100k entries x <=2 MiB) — FAR \
         above this declared budget, so it does not bound it — and with --libp2p-state-dir the durable \
         announced-key floor (DurableSeqFloor) persists WITHOUT eviction (an at-rest growth vector no \
         byte cap bounds, TASK-188). An aggregate on-disk byte quota is an operator OS choice nix-p2p \
         does not ship; the declared value is advisory",
    ),
    (
        "allocated_disk_bytes_ondisk",
        Disposition::CapacityOnly,
        "block-rounded on-disk footprint; same as apparent_disk_bytes_ondisk — an ADVISORY figure with \
         no limiter at the declared value: nothing held at rest, the narinfo entry-count cap is ~195 \
         GiB (far above this budget), and the durable announced-key floor grows without eviction \
         (TASK-188). An aggregate byte quota is an operator OS choice not shipped",
    ),
    (
        "discovery_work_octets",
        Disposition::Politeness,
        "a consultation is already bounded by the enforced discovery_deadline_ns + discovery_max_peers; \
         octet-precise WORK shaping adds no safety bound over the deadline/peer cap",
    ),
    (
        "discovery_control_octets",
        Disposition::Politeness,
        "control overhead of a consultation already bounded by the enforced discovery_deadline_ns + \
         discovery_max_peers; octet-precise CONTROL shaping adds no safety bound",
    ),
    (
        "announce_wire_octets",
        Disposition::Politeness,
        "announce volume is operator-tunable via announce_count (--libp2p-announce-budget) and \
         deadline-bounded (announce_deadline_ms); per-announce octet shaping is self-limiting \
         politeness, not a network-safety ceiling",
    ),
    (
        "announce_rate_octets_per_window",
        Disposition::Politeness,
        "the announce octet RATE is politeness over the operator-tunable announce_count + \
         announce_deadline_ms bounds; not a safety envelope",
    ),
    (
        "announce_rate_window_ns",
        Disposition::Politeness,
        "the window for the announce octet-rate politeness figure; tied to announce_rate_octets_per_window, \
         not a safety envelope",
    ),
];

/// The terminal disposition + recorded reason for a DECLARED-ONLY field, or `None` for a field that
/// is not declared-only. Looked up by [`budget_lines`] so the preflight surface shows an operator not
/// just THAT a field carries no dedicated shaper but the TERMINAL DECISION and what actually bounds
/// the resource — the honest, visible answer to AC#3's "bounded, documented".
fn declared_only_disposition(field: &str) -> Option<(Disposition, &'static str)> {
    DECLARED_ONLY_FIELD_DISPOSITIONS
        .iter()
        .find(|(name, _, _)| *name == field)
        .map(|(_, disposition, reason)| (*disposition, *reason))
}

/// How a budget field's runtime status is surfaced on the preflight line, so a label never lies.
#[derive(Clone, Copy)]
enum FieldTag {
    /// Frozen, parity-checked, effective value envelope-guarded.
    Enforced,
    /// PROFILE-VARYING, enforced by a runtime SHAPER against its own frozen per-profile value
    /// (NOT envelope-bounded, NOT parity-checked against the flat `ResourceCaps`). Today the
    /// upload-rate/window pair, enforced on serve egress by `daemon_core::UploadRateLedger`
    /// (TASK-299).
    EnforcedShaper,
    /// PROFILE-VARYING, enforced by the serve gate's ADMISSION-time count CAS against its own frozen
    /// per-profile value (NOT envelope-bounded, NOT parity-checked): `concurrent_serves_count`
    /// (TASK-120 AC#3). The `n+1`th ADMITTED serve is DECLINED `Busy` by
    /// `fabric_libp2p::ServeGate::admit_plan` — a bound on parsed+admitted serves, not the accept loop.
    EnforcedSemaphore,
    /// OS-ENFORCEABLE at the declared value by a SHIPPED mechanism, not an in-process limiter:
    /// `open_fds_count`, capped by the systemd unit's `LimitNOFILE` rlimit UNDER the nix-p2p unit
    /// (TASK-120 AC#3). The preflight line SURFACES the live hard `RLIMIT_NOFILE` from
    /// `/proc/self/limits` AND whether it is in force (effective ≤ declared), so a direct launch
    /// without the unit reads honestly as "not installed", never a phantom bound (codex P2).
    EnforcedOs,
    /// Applied at runtime but operator-chosen and not envelope-bounded (announce_count).
    AnnounceTunable,
    /// Frozen + hashed budget with no runtime shaper keyed to this field. It is NOT enforced on any
    /// shipped path by a limiter on itself; each such field carries a TERMINAL [`Disposition`]
    /// naming what DOES bound the resource (see [`DECLARED_ONLY_FIELD_DISPOSITIONS`]) — a recorded
    /// decision, not a deferral.
    DeclaredOnly,
}

/// One `key=value` integer line per artifact field, stable order — greppable/diffable. Each line is
/// tagged so the surface cannot advertise a phantom bound as if it were an enforced envelope ceiling.
fn budget_lines(b: &ProfileBudget) -> Vec<String> {
    use FieldTag::{
        AnnounceTunable, DeclaredOnly, Enforced, EnforcedOs, EnforcedSemaphore, EnforcedShaper,
    };
    let rows: [(String, FieldTag); 19] = [
        (
            format!(
                "upload_payload_bytes_compressed_wire={}",
                b.upload_payload_bytes_compressed_wire
            ),
            DeclaredOnly,
        ),
        (
            format!(
                "upload_total_bytes_compressed_wire={}",
                b.upload_total_bytes_compressed_wire
            ),
            DeclaredOnly,
        ),
        (
            format!(
                "upload_rate_bytes_compressed_wire_per_window={}",
                b.upload_rate_bytes_compressed_wire_per_window
            ),
            EnforcedShaper,
        ),
        (
            format!("upload_rate_window_ns={}", b.upload_rate_window_ns),
            EnforcedShaper,
        ),
        (
            format!("concurrent_serves_count={}", b.concurrent_serves_count),
            EnforcedSemaphore,
        ),
        (
            format!(
                "single_nar_bytes_uncompressed_nar={}",
                b.single_nar_bytes_uncompressed_nar
            ),
            Enforced,
        ),
        (
            format!(
                "inflight_nar_bytes_uncompressed_nar={}",
                b.inflight_nar_bytes_uncompressed_nar
            ),
            Enforced,
        ),
        (
            format!("transient_ram_bytes_ram={}", b.transient_ram_bytes_ram),
            DeclaredOnly,
        ),
        (
            format!(
                "apparent_disk_bytes_ondisk={}",
                b.apparent_disk_bytes_ondisk
            ),
            DeclaredOnly,
        ),
        (
            format!(
                "allocated_disk_bytes_ondisk={}",
                b.allocated_disk_bytes_ondisk
            ),
            DeclaredOnly,
        ),
        (format!("open_fds_count={}", b.open_fds_count), EnforcedOs),
        (
            format!("discovery_work_octets={}", b.discovery_work_octets),
            DeclaredOnly,
        ),
        (
            format!("discovery_control_octets={}", b.discovery_control_octets),
            DeclaredOnly,
        ),
        (
            format!("discovery_deadline_ns={}", b.discovery_deadline_ns),
            Enforced,
        ),
        (
            format!("announce_count={}", b.announce_count),
            AnnounceTunable,
        ),
        (
            format!("announce_wire_octets={}", b.announce_wire_octets),
            DeclaredOnly,
        ),
        (
            format!(
                "announce_rate_octets_per_window={}",
                b.announce_rate_octets_per_window
            ),
            DeclaredOnly,
        ),
        (
            format!("announce_rate_window_ns={}", b.announce_rate_window_ns),
            DeclaredOnly,
        ),
        (
            format!("serve_duration_ns={}", b.serve_duration_ns),
            Enforced,
        ),
    ];
    rows.into_iter()
        .map(|(line, tag)| {
            let marker = match tag {
                Enforced => ENFORCED_MARKER,
                EnforcedShaper => ENFORCED_SHAPER_MARKER,
                EnforcedSemaphore => ENFORCED_SEMAPHORE_MARKER,
                EnforcedOs => ENFORCED_OS_MARKER,
                AnnounceTunable => ANNOUNCE_TUNABLE_MARKER,
                DeclaredOnly => DECLARED_ONLY_MARKER,
            };
            // For a declared-only budget, append its TERMINAL disposition class + recorded reason so
            // the surface tells an operator not merely THAT the field carries no dedicated shaper but
            // the DECISION and what actually bounds the resource — the "bounded, documented + visible"
            // of AC#3 without advertising a phantom bound. For the OS-enforced fd ceiling, append the
            // EFFECTIVE rlimit read from the LIVE process (`/proc/self/limits`), so an operator sees
            // the bound actually in force, not the declared suggestion. The appended text never
            // contains another marker constant, so the classification stays unambiguous.
            let field = field_key(&line);
            let suffix = match tag {
                DeclaredOnly => {
                    let disposition = declared_only_disposition(field)
                        .map(|(d, reason)| format!(" [{}] {reason}", d.label()))
                        .unwrap_or_default();
                    // transient_ram additionally SURFACES the live total-RSS backstop (the shipped
                    // systemd MemoryMax cgroup cap read from the live process), so the operator sees
                    // the total-RSS bound actually in force — parallel to the fd rlimit surfacing.
                    // This is the total-RSS BACKSTOP, explicitly NOT the declared working-set value.
                    let backstop = if field == "transient_ram_bytes_ram" {
                        format!(
                            " effective total-RSS backstop cgroup memory.max={}",
                            effective_memory_max_display()
                        )
                    } else {
                        String::new()
                    };
                    format!("{disposition}{backstop}")
                }
                // The fd ceiling: surface the LIVE effective hard RLIMIT_NOFILE AND whether it is
                // actually IN FORCE (effective ≤ this profile's declared value). Launched under the
                // nix-p2p unit, LimitNOFILE=open_fds_count so effective == declared (in force);
                // launched directly, the effective default (~512K) EXCEEDS the declared value, so the
                // bound is NOT installed — say so plainly rather than claim an absent bound (codex P2).
                EnforcedOs => nofile_in_force_suffix(field_value(&line)),
                Enforced | EnforcedShaper | EnforcedSemaphore | AnnounceTunable => String::new(),
            };
            format!("{line}{marker}{suffix}")
        })
        .collect()
}

/// The preflight suffix for the `open_fds_count` line: the LIVE effective hard `RLIMIT_NOFILE` AND
/// whether it is actually IN FORCE for this profile's `declared` value (codex P2). The bound is in
/// force iff the effective hard limit is FINITE and `<=` the declared ceiling (the systemd unit's
/// `LimitNOFILE=open_fds_count` gives exactly that). A binary launched WITHOUT the unit keeps the
/// default (`~512K` or `unlimited`), which EXCEEDS the declared value — the bound is NOT installed, and
/// this says so plainly rather than claim an absent ceiling. `declared` is `None` only if the line's
/// value did not parse (never in practice). Reflects whatever set the rlimit — no fabricated value;
/// `"unknown"` when `/proc/self/limits` is unreadable (non-Linux/sandbox). Integer display only.
fn nofile_in_force_suffix(declared: Option<u64>) -> String {
    match read_proc_self_limit_max_open_files() {
        Some(Some(n)) => {
            let in_force = declared.is_some_and(|d| n <= d);
            if in_force {
                format!(" effective RLIMIT_NOFILE={n} (in force — bounds the declared ceiling)")
            } else {
                format!(
                    " effective RLIMIT_NOFILE={n} (NOT installed on this launch — the declared \
                     ceiling is enforced only under the nix-p2p systemd unit's LimitNOFILE)"
                )
            }
        }
        Some(None) => {
            " effective RLIMIT_NOFILE=unlimited (NOT installed on this launch — the declared \
                        ceiling is enforced only under the nix-p2p systemd unit's LimitNOFILE)"
                .to_string()
        }
        None => " effective RLIMIT_NOFILE=unknown".to_string(),
    }
}

/// The integer VALUE of a `field=value` budget line (after the first `=`), or `None` if it is not an
/// integer. Used to compare a declared ceiling against the live effective OS limit.
fn field_value(line: &str) -> Option<u64> {
    line.split_once('=')
        .and_then(|(_, v)| v.parse::<u64>().ok())
}

/// The live effective hard `RLIMIT_NOFILE` of THIS process, for the LIVE STATUS surface (AC#3
/// "visible in effective configuration"). Read from the RUNNING daemon's own `/proc/self/limits` — so
/// the status endpoint (served BY the daemon service, under the systemd unit's `LimitNOFILE`) reports
/// the DAEMON's actual effective limit, not a launching shell's. Integer, or `"unlimited"`/`"unknown"`
/// (fail-soft, never fabricated).
pub(crate) fn effective_rlimit_nofile_display() -> String {
    match read_proc_self_limit_max_open_files() {
        Some(Some(n)) => n.to_string(),
        Some(None) => "unlimited".to_string(),
        None => "unknown".to_string(),
    }
}

/// The live effective cgroup `memory.max` of THIS process, for the LIVE STATUS surface — the running
/// daemon's own total-RSS backstop (the systemd unit's `MemoryMax`), read from its own cgroup. Integer
/// bytes, or `"unlimited"`/`"unknown"` (fail-soft).
pub(crate) fn effective_cgroup_memory_max_display() -> String {
    effective_memory_max_display()
}

/// Parse the HARD `Max open files` limit out of `/proc/self/limits`. `Some(Some(n))` = a finite hard
/// cap of `n`; `Some(None)` = the kernel reports `unlimited`; `None` = the file/field could not be
/// read (non-Linux, sandbox). No panic, no fabricated value — the fail-soft "unknown" path.
fn read_proc_self_limit_max_open_files() -> Option<Option<u64>> {
    let text = std::fs::read_to_string("/proc/self/limits").ok()?;
    // Format: "Max open files            <soft>    <hard>    files". The HARD limit is the ceiling a
    // process cannot exceed (it may lower its soft limit but not raise the hard limit), so it is the
    // real bound the LimitNOFILE rlimit installs.
    let line = text.lines().find(|l| l.starts_with("Max open files"))?;
    let hard = line.split_whitespace().nth(4)?;
    if hard == "unlimited" {
        return Some(None);
    }
    hard.parse::<u64>().ok().map(Some)
}

/// The EFFECTIVE cgroup `memory.max` in force on THIS process, read from the live cgroup-v2 hierarchy,
/// rendered for the preflight `transient_ram_bytes_ram` line so an operator sees the total-RSS BACKSTOP
/// actually applied (the systemd unit's `MemoryMax`), not a suggestion. `"unlimited"` when the cgroup
/// reports no cap (`max`), `"unknown"` when the cgroup/file is unavailable (non-Linux, cgroup-v1,
/// sandbox) — never a fabricated value. Integer display only (no float).
fn effective_memory_max_display() -> String {
    match read_cgroup_v2_memory_max() {
        Some(Some(n)) => n.to_string(),
        Some(None) => "unlimited".to_string(),
        None => "unknown".to_string(),
    }
}

/// Read the effective cgroup-v2 `memory.max` for THIS process. `Some(Some(n))` = a finite cap of `n`
/// bytes; `Some(None)` = the cgroup reports `max` (no cap); `None` = could not be read (non-Linux,
/// cgroup-v1, or a sandbox that hides `/sys/fs/cgroup`). Fail-soft: no panic, no fabricated value.
fn read_cgroup_v2_memory_max() -> Option<Option<u64>> {
    // cgroup v2 unified hierarchy: /proc/self/cgroup has a single "0::<relpath>" line, and this
    // process's memory.max lives at /sys/fs/cgroup<relpath>/memory.max.
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let relpath = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let path = format!("/sys/fs/cgroup{relpath}/memory.max");
    let value = std::fs::read_to_string(&path).ok()?;
    let value = value.trim();
    if value == "max" {
        return Some(None);
    }
    value.parse::<u64>().ok().map(Some)
}

/// The field key of a `field=value` budget line (everything before the first `=`).
fn field_key(line: &str) -> &str {
    line.split('=').next().unwrap_or(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_profile() -> [SharingProfile; 5] {
        [
            SharingProfile::UpstreamOnly,
            SharingProfile::ConsumeOnly,
            SharingProfile::LanShare,
            SharingProfile::PublicShare,
            SharingProfile::Router,
        ]
    }

    #[test]
    fn embedded_artifact_loads_and_covers_every_profile() {
        let a = load(PROFILE_BUDGET_ARTIFACT_JSON).expect("embedded artifact must load");
        for p in every_profile() {
            budget_for(&a, p).unwrap_or_else(|e| panic!("profile {} absent: {e}", p.as_str()));
        }
        assert_eq!(a.profiles.len(), 5, "exactly the five profiles are frozen");
    }

    #[test]
    fn embedded_artifact_hash_is_frozen() {
        // Freeze pin: if this reddens, a budget changed — recompute and update
        // EXPECTED_PROFILE_BUDGET_HASH (a deliberate, reviewable one-line diff). The hash proves the
        // canonical JCS content is frozen; it is NOT a human authorization of the numbers.
        let actual = content_hash(PROFILE_BUDGET_ARTIFACT_JSON).expect("hashable");
        assert_eq!(
            actual, EXPECTED_PROFILE_BUDGET_HASH,
            "profile-budget artifact hash drifted; recompute and re-freeze"
        );
    }

    #[test]
    fn every_field_is_an_integer_no_floats() {
        // Structural no-floats guard at the JSON level (the typed schema already rejects a float
        // via u64 deserialization; this also catches a float in a not-yet-typed position).
        let v: serde_json::Value =
            serde_json::from_str(PROFILE_BUDGET_ARTIFACT_JSON).expect("parses");
        fn walk(v: &serde_json::Value) {
            match v {
                serde_json::Value::Number(n) => {
                    assert!(
                        n.is_u64(),
                        "artifact carries a non-integer number {n} (no floats allowed)"
                    );
                }
                serde_json::Value::Array(a) => a.iter().for_each(walk),
                serde_json::Value::Object(o) => o.values().for_each(walk),
                _ => {}
            }
        }
        walk(&v);
    }

    #[test]
    fn embedded_envelope_is_normative_and_within_ceilings() {
        let a = load(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        validate_envelope(&a).expect("frozen artifact must be within the normative envelope");
    }

    #[test]
    fn embedded_artifact_parity_holds_with_default_caps() {
        let a = load(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        let caps = ResourceCaps::default();
        for p in every_profile() {
            let b = budget_for(&a, p).unwrap();
            parity_with_caps(p, b, &caps)
                .unwrap_or_else(|e| panic!("parity broke for {}: {e}", p.as_str()));
        }
    }

    #[test]
    fn preflight_lines_mark_enforced_vs_declared_only() {
        let lines = preflight_lines(SharingProfile::PublicShare).join("\n");
        // Enforced admission-envelope fields carry the enforced marker.
        assert!(lines.contains(&format!(
            "single_nar_bytes_uncompressed_nar=268435456{ENFORCED_MARKER}"
        )));
        assert!(lines.contains(&format!("serve_duration_ns=120000000000{ENFORCED_MARKER}")));
        // Declared-but-not-runtime-shaped budgets are explicitly marked declared-only (no phantom
        // bound). concurrent_serves_count + open_fds_count are NO LONGER here — they are now
        // runtime/OS-enforced (asserted separately below).
        for declared in [
            "transient_ram_bytes_ram",
            "apparent_disk_bytes_ondisk",
            // upload_payload/total remain declared-only: the TASK-299 shaper enforces the RATE, not
            // a per-serve payload cap nor a lifetime total.
            "upload_payload_bytes_compressed_wire",
            "upload_total_bytes_compressed_wire",
        ] {
            let line = lines
                .lines()
                .find(|l| l.trim_start().starts_with(declared))
                .unwrap_or_else(|| panic!("{declared} line missing"));
            assert!(
                line.contains(DECLARED_ONLY_MARKER),
                "{declared} must be marked declared-only, got: {line}"
            );
        }
        // TASK-120 AC#3: concurrent_serves_count is now ENFORCED by the serve gate's admission
        // semaphore — it carries the semaphore marker, NOT declared-only.
        let serves = lines
            .lines()
            .find(|l| l.trim_start().starts_with("concurrent_serves_count"))
            .expect("concurrent_serves_count line");
        assert!(
            serves.contains(ENFORCED_SEMAPHORE_MARKER) && !serves.contains(DECLARED_ONLY_MARKER),
            "concurrent_serves_count must carry the semaphore-enforced marker, got: {serves}"
        );
        // TASK-120 AC#3: open_fds_count is now ENFORCED via the shipped systemd LimitNOFILE rlimit and
        // SURFACES the effective limit read from the live process — the OS marker, NOT declared-only.
        let fds = lines
            .lines()
            .find(|l| l.trim_start().starts_with("open_fds_count"))
            .expect("open_fds_count line");
        assert!(
            fds.contains(ENFORCED_OS_MARKER) && !fds.contains(DECLARED_ONLY_MARKER),
            "open_fds_count must carry the OS-enforced marker, got: {fds}"
        );
        assert!(
            fds.contains("effective RLIMIT_NOFILE="),
            "open_fds_count must surface the effective rlimit from the live process, got: {fds}"
        );
        // The TASK-299 upload-rate shaper fields carry the distinct shaper-enforced marker — NOT the
        // declared-only marker (they are now runtime-enforced on serve egress) and NOT the
        // envelope-enforced marker (they are profile-varying and not parity-checked). public-share's
        // upload_rate is 128 MiB / 1 s window.
        for shaper in [
            "upload_rate_bytes_compressed_wire_per_window",
            "upload_rate_window_ns",
        ] {
            let line = lines
                .lines()
                .find(|l| l.trim_start().starts_with(shaper))
                .unwrap_or_else(|| panic!("{shaper} line missing"));
            assert!(
                line.contains(ENFORCED_SHAPER_MARKER),
                "{shaper} must carry the shaper-enforced marker, got: {line}"
            );
            assert!(
                !line.contains(DECLARED_ONLY_MARKER) && !line.contains(ENFORCED_MARKER),
                "{shaper} must NOT claim declared-only or envelope-enforced, got: {line}"
            );
        }
        // announce_count is operator-overridable, NOT envelope-bounded — its label must say so and
        // must NOT claim the enforced-envelope marker (codex #2: label == reality).
        let announce = lines
            .lines()
            .find(|l| l.trim_start().starts_with("announce_count"))
            .expect("announce_count line");
        assert!(
            announce.contains(ANNOUNCE_TUNABLE_MARKER),
            "announce_count must be labelled operator-overridable, got: {announce}"
        );
        assert!(
            !announce.contains(ENFORCED_MARKER),
            "announce_count must NOT claim the enforced-envelope marker, got: {announce}"
        );
    }

    /// Classify one preflight budget line by its trailing honesty marker. Matches the FULL marker
    /// constant (never a fragment: "envelope-bounded" is a substring of BOTH the enforced and the
    /// "not envelope-bounded" announce marker, so a fragment match would misclassify). Exactly one
    /// marker must match, or the surface has an untagged/ambiguously-tagged field.
    fn tag_of(line: &str) -> FieldTag {
        let hits: Vec<FieldTag> = [
            (ENFORCED_MARKER, FieldTag::Enforced),
            (ENFORCED_SHAPER_MARKER, FieldTag::EnforcedShaper),
            (ENFORCED_SEMAPHORE_MARKER, FieldTag::EnforcedSemaphore),
            (ENFORCED_OS_MARKER, FieldTag::EnforcedOs),
            (ANNOUNCE_TUNABLE_MARKER, FieldTag::AnnounceTunable),
            (DECLARED_ONLY_MARKER, FieldTag::DeclaredOnly),
        ]
        .into_iter()
        .filter(|(marker, _)| line.contains(marker))
        .map(|(_, tag)| tag)
        .collect();
        assert_eq!(
            hits.len(),
            1,
            "budget line must carry EXACTLY one honesty marker, got {}: {line}",
            hits.len()
        );
        hits[0]
    }

    /// THE HONESTY LOCK (TASK-264/299): the enforced-vs-declared classification of every budget field
    /// cannot silently drift. A field is advertised ENFORCED only where a shipped path actually caps
    /// against it; every other field is DECLARED-ONLY and given a terminal decision in
    /// [`DECLARED_ONLY_FIELD_DISPOSITIONS`]. This test pins all four sets EXACTLY, so:
    ///
    /// * flipping a declared-only field to `Enforced` in `budget_lines` WITHOUT wiring a limiter
    ///   (a phantom bound) reddens both the enforced-set and the declared-set assertion;
    /// * adding a runtime limiter and flipping a field to `Enforced` WITHOUT removing it from
    ///   `DECLARED_ONLY_FIELD_DISPOSITIONS` (stale table) reddens the declared-set assertion;
    /// * adding a NEW artifact field without classifying + disposing it reddens the totals.
    ///
    /// MUTATION-PROVEN: change any field's `FieldTag` in `budget_lines`, or drop/add an entry in
    /// `DECLARED_ONLY_FIELD_DISPOSITIONS`, and this bites.
    #[test]
    fn declared_only_routing_is_locked() {
        use std::collections::BTreeSet;
        let a = load(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        // public-share exercises every field with representative non-zero values.
        let b = budget_for(&a, SharingProfile::PublicShare).unwrap();
        let lines = budget_lines(b);

        let mut enforced = BTreeSet::new();
        let mut enforced_shaper = BTreeSet::new();
        let mut enforced_semaphore = BTreeSet::new();
        let mut enforced_os = BTreeSet::new();
        let mut announce_tunable = BTreeSet::new();
        let mut declared_only = BTreeSet::new();
        for line in &lines {
            let name = field_key(line).to_string();
            match tag_of(line) {
                FieldTag::Enforced => assert!(enforced.insert(name), "dup enforced: {line}"),
                FieldTag::EnforcedShaper => {
                    assert!(enforced_shaper.insert(name), "dup enforced-shaper: {line}")
                }
                FieldTag::EnforcedSemaphore => {
                    assert!(
                        enforced_semaphore.insert(name),
                        "dup enforced-semaphore: {line}"
                    )
                }
                FieldTag::EnforcedOs => {
                    assert!(enforced_os.insert(name), "dup enforced-os: {line}")
                }
                FieldTag::AnnounceTunable => {
                    assert!(announce_tunable.insert(name), "dup announce: {line}")
                }
                FieldTag::DeclaredOnly => {
                    assert!(declared_only.insert(name), "dup declared: {line}")
                }
            }
        }

        // The ENVELOPE-ENFORCED set is EXACTLY the profile-invariant admission-envelope fields that a
        // shipped path (ServeBudget / DiscoveryBudget) caps against AND that `parity_with_caps` checks
        // against the flat `ResourceCaps` (+ the serve fields `check_serve_within_envelope` guards
        // post-override) — no more (no phantom bound), no fewer. The upload-rate shaper fields are
        // DELIBERATELY NOT here: they are profile-VARYING and enforced against their own frozen value,
        // not parity-checked, so folding them in would break the "enforced == parity/envelope" invariant.
        let expected_enforced: BTreeSet<String> = [
            "single_nar_bytes_uncompressed_nar",
            "inflight_nar_bytes_uncompressed_nar",
            "discovery_deadline_ns",
            "serve_duration_ns",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(
            enforced, expected_enforced,
            "the ENVELOPE-ENFORCED-marked set drifted from the fields a shipped path caps against AND \
             parity-checks (a phantom bound, or a newly-wired field not reflected here)"
        );

        // The SHAPER-ENFORCED set is EXACTLY the profile-varying fields the TASK-299 upload-rate
        // shaper enforces on serve egress — the rate and its window. It is a SEPARATE set from
        // `expected_enforced` precisely because these are NOT parity-checked (the enforced cap is the
        // frozen per-profile value itself); flipping one back to declared-only, or adding a third
        // shaper field, bites here and mismatches the totals below.
        let expected_shaper: BTreeSet<String> = [
            "upload_rate_bytes_compressed_wire_per_window",
            "upload_rate_window_ns",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(
            enforced_shaper, expected_shaper,
            "the SHAPER-ENFORCED set drifted from the fields UploadRateLedger actually enforces \
             (a phantom shaper bound, or a shaper field not reflected here)"
        );

        // The SEMAPHORE-ENFORCED set is EXACTLY the concurrent-serve COUNT ceiling (TASK-120 AC#3),
        // enforced by the serve gate's admission CAS against its own frozen per-profile value.
        // Flipping it back to declared-only (removing the real semaphore) reddens here + mismatches
        // the totals.
        let expected_semaphore: BTreeSet<String> = ["concurrent_serves_count"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(
            enforced_semaphore, expected_semaphore,
            "the SEMAPHORE-ENFORCED set drifted from concurrent_serves_count (a phantom bound, or the \
             real serve-gate semaphore was removed)"
        );

        // The OS-ENFORCED set is EXACTLY the open-FD ceiling, bounded by the shipped systemd
        // LimitNOFILE rlimit and surfaced from the live process. Flipping it back to declared-only
        // (implying the rlimit is not shipped) reddens here.
        let expected_os: BTreeSet<String> =
            ["open_fds_count"].into_iter().map(String::from).collect();
        assert_eq!(
            enforced_os, expected_os,
            "the OS-ENFORCED set drifted from open_fds_count (the shipped LimitNOFILE rlimit)"
        );

        // announce_count is runtime-limited politeness, operator-chosen — its OWN tag, never enforced.
        let expected_announce: BTreeSet<String> =
            ["announce_count"].into_iter().map(String::from).collect();
        assert_eq!(announce_tunable, expected_announce);

        // The DECLARED-ONLY set is EXACTLY the disposition table's field set: every declared-only
        // field has a terminal decision, and every disposed field is still declared-only (not
        // silently wired to a phantom limiter).
        let disposed: BTreeSet<String> = DECLARED_ONLY_FIELD_DISPOSITIONS
            .iter()
            .map(|(field, _, _)| (*field).to_string())
            .collect();
        assert_eq!(
            declared_only, disposed,
            "the DECLARED-ONLY set and DECLARED_ONLY_FIELD_DISPOSITIONS diverged: a field was \
             reclassified without updating its disposition, or vice versa"
        );

        // Totals: every one of the 19 artifact fields is tagged exactly once, none untagged.
        // 4 envelope-enforced + 2 shaper-enforced + 1 semaphore-enforced + 1 OS-enforced
        // + 1 announce-tunable + 10 declared-only = 19.
        assert_eq!(
            enforced.len()
                + enforced_shaper.len()
                + enforced_semaphore.len()
                + enforced_os.len()
                + announce_tunable.len()
                + declared_only.len(),
            19,
            "every budget field must be classified exactly once"
        );
        assert_eq!(enforced.len(), 4, "exactly four envelope-enforced fields");
        assert_eq!(
            enforced_shaper.len(),
            2,
            "exactly two shaper-enforced fields"
        );
        assert_eq!(
            enforced_semaphore.len(),
            1,
            "exactly one semaphore-enforced field"
        );
        assert_eq!(enforced_os.len(), 1, "exactly one OS-enforced field");
        assert_eq!(declared_only.len(), 10, "exactly ten declared-only fields");
    }

    /// THE TERMINAL-DECISION LOCK (TASK-120 AC#3 close-out / TASK-299 inc2): every declared-only
    /// field resolves to its recorded TERMINAL [`Disposition`] with a non-empty reason — so AC#3 is
    /// CLOSED by decision, never left as a deferral. There is no `Deferred` variant to represent a
    /// punt: the enum makes "we decided" the only representable state. The check is against an
    /// INDEPENDENT per-field expected map (not derived from the table under test), so it bites on ANY
    /// per-field reclassification — including a COMPENSATING SWAP between two classes that keeps the
    /// aggregate counts constant (which a distribution-only lock would miss) — and on a per-field
    /// mislabel of the operator-facing `--preflight` surface. The count assertions are a redundant
    /// cross-check.
    ///
    /// MUTATION-PROVEN: change any field's `Disposition` in `DECLARED_ONLY_FIELD_DISPOSITIONS`
    /// (including swapping two fields' classes), or blank a reason string, and this reddens.
    #[test]
    fn declared_only_dispositions_are_terminal() {
        let a = load(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        let b = budget_for(&a, SharingProfile::PublicShare).unwrap();

        // The INDEPENDENT expected PER-FIELD assignment (not derived from the table under test), so a
        // compensating swap between two classes — which keeps the aggregate counts constant — still
        // BITES. This is the load-bearing "the operator-facing class of THIS field is X" lock; the
        // count assertions below are a redundant cross-check.
        let expected: &[(&str, Disposition)] = &[
            (
                "upload_payload_bytes_compressed_wire",
                Disposition::CapacityOnly,
            ),
            (
                "upload_total_bytes_compressed_wire",
                Disposition::CapacityOnly,
            ),
            ("transient_ram_bytes_ram", Disposition::CapacityOnly),
            ("apparent_disk_bytes_ondisk", Disposition::CapacityOnly),
            ("allocated_disk_bytes_ondisk", Disposition::CapacityOnly),
            ("discovery_work_octets", Disposition::Politeness),
            ("discovery_control_octets", Disposition::Politeness),
            ("announce_wire_octets", Disposition::Politeness),
            ("announce_rate_octets_per_window", Disposition::Politeness),
            ("announce_rate_window_ns", Disposition::Politeness),
        ];
        assert_eq!(
            expected.len(),
            DECLARED_ONLY_FIELD_DISPOSITIONS.len(),
            "the independent expected map must cover exactly the disposition table"
        );

        // Every declared-only field maps to its EXPECTED terminal disposition with a substantive
        // reason — checked against the independent map, so a per-field mislabel bites.
        let (mut capacity_only, mut politeness) = (0u32, 0u32);
        for (field, want) in expected {
            let (looked_up, reason) = declared_only_disposition(field)
                .unwrap_or_else(|| panic!("{field} missing from disposition lookup"));
            assert_eq!(
                looked_up, *want,
                "{field} disposition drifted from its recorded decision"
            );
            assert!(
                reason.len() > 24,
                "{field} disposition reason is too thin to be a real decision: {reason:?}"
            );
            match want {
                Disposition::CapacityOnly => capacity_only += 1,
                Disposition::Politeness => politeness += 1,
            }
        }
        // CapacityOnly (advisory, no limiter at the declared value): upload_total (no mechanism) +
        // upload_payload (cross-unit, no per-serve wire cap) + transient_ram (inflight/MemoryMax bound
        // the resource far above the declared value) + apparent/allocated disk (narinfo cap ~195 GiB +
        // durable floor grows) = 5.
        // Politeness: the four discovery/announce octet fields + announce_rate_window = 5. 5 + 5 = 10.
        assert_eq!(
            capacity_only, 5,
            "exactly five CapacityOnly (advisory) declared-only fields"
        );
        assert_eq!(
            politeness, 5,
            "exactly five Politeness declared-only fields"
        );
        assert_eq!(capacity_only + politeness, 10);

        // SURFACING: each declared-only preflight line carries the class label of its EXPECTED
        // disposition (from the independent map, NOT the table under test), so a per-field mislabel on
        // the operator-facing --preflight surface is caught, not just an aggregate drift.
        let lines = budget_lines(b);
        for (field, want) in expected {
            let line = lines
                .iter()
                .find(|l| field_key(l) == *field)
                .unwrap_or_else(|| panic!("{field} line missing"));
            assert!(
                line.contains(DECLARED_ONLY_MARKER) && line.contains(want.label()),
                "{field} must surface its expected disposition class {:?}, got: {line}",
                want.label()
            );
        }
    }

    // ---- codex #1 BITE: an effective over-envelope serve OVERRIDE must fail closed ----

    #[test]
    fn effective_serve_override_over_envelope_fails_closed() {
        // The shipped defaults are within the envelope.
        check_serve_within_envelope(
            ENVELOPE_MAX_SINGLE_NAR_BYTES,
            ENVELOPE_MAX_INFLIGHT_NAR_BYTES,
            ENVELOPE_MAX_SERVE_DURATION_NS,
        )
        .expect("the frozen defaults are within the envelope");
        // A 512 MiB single-NAR override exceeds the frozen 256 MiB ceiling → fail closed.
        match check_serve_within_envelope(
            512 * 1024 * 1024,
            ENVELOPE_MAX_INFLIGHT_NAR_BYTES,
            ENVELOPE_MAX_SERVE_DURATION_NS,
        ) {
            Err(BudgetError::OverrideExceedsEnvelope {
                field,
                value,
                ceiling,
            }) => {
                assert_eq!(field, "single_nar_bytes_uncompressed_nar");
                assert_eq!(value, 512 * 1024 * 1024);
                assert_eq!(ceiling, ENVELOPE_MAX_SINGLE_NAR_BYTES);
            }
            other => panic!("512 MiB serve override must fail closed, got {other:?}"),
        }
        // An inflight override above 1 GiB fails closed.
        assert!(matches!(
            check_serve_within_envelope(
                ENVELOPE_MAX_SINGLE_NAR_BYTES,
                2 * 1024 * 1024 * 1024,
                ENVELOPE_MAX_SERVE_DURATION_NS,
            ),
            Err(BudgetError::OverrideExceedsEnvelope {
                field: "inflight_nar_bytes_uncompressed_nar",
                ..
            })
        ));
        // A 300 s serve-duration override (via the ms entry point) fails closed.
        match check_serve_ms_within_envelope(
            ENVELOPE_MAX_SINGLE_NAR_BYTES,
            ENVELOPE_MAX_INFLIGHT_NAR_BYTES,
            300_000,
        ) {
            Err(BudgetError::OverrideExceedsEnvelope { field, ceiling, .. }) => {
                assert_eq!(field, "serve_duration_ns");
                assert_eq!(ceiling, ENVELOPE_MAX_SERVE_DURATION_NS);
            }
            other => panic!("300 s serve override must fail closed, got {other:?}"),
        }
        // A huge ms value saturates rather than wrapping, and still fails closed.
        assert!(matches!(
            check_serve_ms_within_envelope(
                ENVELOPE_MAX_SINGLE_NAR_BYTES,
                ENVELOPE_MAX_INFLIGHT_NAR_BYTES,
                u64::MAX,
            ),
            Err(BudgetError::OverrideExceedsEnvelope {
                field: "serve_duration_ns",
                ..
            })
        ));
        // Tightening (a SMALLER override) is allowed.
        check_serve_ms_within_envelope(64 * 1024 * 1024, 128 * 1024 * 1024, 30_000)
            .expect("a tighter override must be allowed");
    }

    #[test]
    fn full_verify_of_embedded_artifact_succeeds() {
        let caps = ResourceCaps::default();
        for p in every_profile() {
            verify(p, &caps).unwrap_or_else(|e| panic!("verify failed for {}: {e}", p.as_str()));
        }
    }

    // ---- THE AC#10 BITE: 512 MiB / 300 s must FAIL --------------------------

    #[test]
    fn envelope_bites_on_512mib_single() {
        let mut a = load(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        // Mutate the shipped 256 MiB back to the old 512 MiB on a serving profile.
        a.profiles
            .get_mut("public-share")
            .unwrap()
            .single_nar_bytes_uncompressed_nar = 512 * 1024 * 1024;
        match validate_envelope(&a) {
            Err(BudgetError::EnvelopeExceeded {
                profile,
                field,
                value,
                ceiling,
            }) => {
                assert_eq!(profile, "public-share");
                assert_eq!(field, "single_nar_bytes_uncompressed_nar");
                assert_eq!(value, 512 * 1024 * 1024);
                assert_eq!(ceiling, ENVELOPE_MAX_SINGLE_NAR_BYTES);
            }
            other => panic!("512 MiB single must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn envelope_bites_on_300s_serve_duration() {
        let mut a = load(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        a.profiles
            .get_mut("public-share")
            .unwrap()
            .serve_duration_ns = 300 * 1_000_000_000;
        match validate_envelope(&a) {
            Err(BudgetError::EnvelopeExceeded { field, ceiling, .. }) => {
                assert_eq!(field, "serve_duration_ns");
                assert_eq!(ceiling, ENVELOPE_MAX_SERVE_DURATION_NS);
            }
            other => panic!("300 s serve must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn envelope_bites_on_declared_envelope_weakening() {
        let mut a = load(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        // Try to smuggle a looser ceiling into the artifact's declared envelope.
        a.envelope.max_single_nar_bytes_uncompressed_nar = 512 * 1024 * 1024;
        match validate_envelope(&a) {
            Err(BudgetError::EnvelopeMismatch { field, .. }) => {
                assert_eq!(field, "max_single_nar_bytes_uncompressed_nar");
            }
            other => panic!("a weakened declared envelope must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn parity_bites_when_runtime_caps_diverge() {
        let a = load(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        let b = budget_for(&a, SharingProfile::PublicShare).unwrap();
        let caps = ResourceCaps {
            max_nar_bytes_uncompressed: 512 * 1024 * 1024, // runtime drifted to 512 MiB
            ..ResourceCaps::default()
        };
        match parity_with_caps(SharingProfile::PublicShare, b, &caps) {
            Err(BudgetError::ParityMismatch {
                field,
                artifact,
                runtime,
                ..
            }) => {
                assert_eq!(field, "single_nar_bytes_uncompressed_nar");
                assert_eq!(artifact, 256 * 1024 * 1024);
                assert_eq!(runtime, 512 * 1024 * 1024);
            }
            other => panic!("caps divergence must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn artifact_announce_count_matches_the_code_default() {
        // SSOT at build/test time: the frozen announce_count (serving profiles) equals the code
        // default announce budget. If the default changes without re-freezing the artifact, this
        // bites — the check that belongs at test time, not at every startup (the budget is tunable).
        let a = load(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        let default_budget = ResourceCaps::default().announce_distinct_paths_budget;
        for p in [SharingProfile::LanShare, SharingProfile::PublicShare] {
            let b = budget_for(&a, p).unwrap();
            assert_eq!(
                b.announce_count,
                default_budget,
                "{} announce_count must equal the code default",
                p.as_str()
            );
        }
    }

    #[test]
    fn discovery_budget_is_ssot_wired_from_resource_caps() {
        // TASK-120 AC#3 (discovery SSOT): the discovery budget production INSTALLS
        // (`ResourceCaps::default().discovery_budget()`, used by BOTH binaries' source configs) has
        // the SAME deadline the frozen artifact declares and `preflight_lines` advertises — so
        // mutating one can no longer diverge from the other by an independent literal (the old
        // production `DiscoveryBudget::default()` matched it only by duplication). Every profile's
        // frozen `discovery_deadline_ns` must equal the caps-derived deadline in nanoseconds.
        let installed = ResourceCaps::default().discovery_budget();
        let installed_ns =
            u64::try_from(installed.deadline.as_nanos()).expect("5 s deadline fits u64 ns");
        let a = load(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        for p in every_profile() {
            let b = budget_for(&a, p).unwrap();
            assert_eq!(
                b.discovery_deadline_ns,
                installed_ns,
                "{}: the frozen discovery_deadline_ns must equal the caps-derived budget production \
                 installs (the SSOT preflight advertises)",
                p.as_str()
            );
        }
        // The RETAINED test-convenience `DiscoveryBudget::default()` must stay EQUAL to that SSOT, so
        // tests using the default exercise the same value production runs — no test/prod drift.
        let def = peer_fabric::DiscoveryBudget::default();
        assert_eq!(def.deadline, installed.deadline);
        assert_eq!(def.max_peers, installed.max_peers);
    }

    #[test]
    fn operator_announce_budget_override_does_not_trip_parity() {
        // Regression guard for the announce-budget override hazard: an operator tuning the announce
        // budget down (a legitimate `--libp2p-announce-budget`) must NOT fail the startup budget
        // verify, because announce_count is operator-tunable, not a frozen-envelope invariant.
        let a = load(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        let b = budget_for(&a, SharingProfile::PublicShare).unwrap();
        let tuned = ResourceCaps {
            announce_distinct_paths_budget: 10,
            ..ResourceCaps::default()
        };
        parity_with_caps(SharingProfile::PublicShare, b, &tuned)
            .expect("an operator announce-budget override must not trip parity");
    }

    // ---- fail-closed: missing / drifted / float ----------------------------

    #[test]
    fn missing_artifact_is_fail_closed() {
        assert_eq!(load(""), Err(BudgetError::Missing));
        assert_eq!(load("   \n  "), Err(BudgetError::Missing));
        assert_eq!(
            format!("{}", BudgetError::Missing),
            PROFILE_BUDGET_ARTIFACT_MISSING
        );
    }

    #[test]
    fn hash_drift_is_fail_closed() {
        let caps = ResourceCaps::default();
        let wrong = "1111111111111111111111111111111111111111111111111111111111111111";
        match verify_raw(
            PROFILE_BUDGET_ARTIFACT_JSON,
            wrong,
            SharingProfile::LanShare,
            &caps,
        ) {
            Err(BudgetError::HashDrift { expected, .. }) => assert_eq!(expected, wrong),
            other => panic!("a wrong expected hash must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn a_float_field_fails_to_parse() {
        let raw = PROFILE_BUDGET_ARTIFACT_JSON
            .replace("\"open_fds_count\": 1024", "\"open_fds_count\": 1024.5");
        match load(&raw) {
            Err(BudgetError::Parse(_)) => {}
            other => panic!("a float field must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_field_fails_closed() {
        let raw = PROFILE_BUDGET_ARTIFACT_JSON.replace(
            "\"schema_version\": 1,",
            "\"schema_version\": 1, \"smuggled\": 7,",
        );
        match load(&raw) {
            Err(BudgetError::Parse(_)) => {}
            other => panic!("an unknown field must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn canonicalization_is_whitespace_and_key_order_invariant() {
        // The hash is over the canonical form, so reformatting the source must not change it.
        let reflowed: serde_json::Value =
            serde_json::from_str(PROFILE_BUDGET_ARTIFACT_JSON).unwrap();
        let pretty = serde_json::to_string_pretty(&reflowed).unwrap();
        assert_eq!(
            content_hash(PROFILE_BUDGET_ARTIFACT_JSON).unwrap(),
            content_hash(&pretty).unwrap(),
            "canonical hash must be invariant to whitespace/formatting"
        );
    }
}
