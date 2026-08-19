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
//! are a SEPARATE declared axis and are never compared to a NarSize.
//!
//! ## No floats (owner rule)
//!
//! Every field is a `u64`. There is no float anywhere in the schema, the artifact, or any
//! comparison/decision path here. Displaying a MiB figure to a human is a terminal concern of the
//! status/preflight surface, not of this module.

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
    "d5d71004f97f3ea59cc515830a0316fa877782cec433d067c5c568083e31665e";

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
/// check that belongs at build/test time, not at every startup. The compressed-wire upload fields,
/// RAM, disk and fd ceilings are DECLARED contract ceilings not yet wired to a runtime shaper (see
/// the module doc and residual TASK-264), so they too are not parity-checked against `caps` —
/// advertising a parity we do not enforce would be the phantom-bound dishonesty `ResourceCaps`
/// already refuses.
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

/// The marker appended to a declared-but-not-yet-runtime-enforced budget line so an operator is
/// never misled into reading it as an enforced ceiling (the `effective_lines` honesty rule extended
/// to the artifact surface).
const DECLARED_ONLY_MARKER: &str = "  [declared ceiling — not yet runtime-enforced; TASK-264]";
/// The marker for a frozen, ENVELOPE-BOUNDED field. The post-override-guarded fields — single/inflight
/// served NarSize and serve duration ([`check_serve_within_envelope`]) — may be tightened by an
/// override but never loosened past the frozen ceiling. The discovery deadline is also frozen and
/// envelope-bound, but non-tunable: it is enforced by default-parity alone (there is no override to
/// guard). All are default-parity-checked against the artifact.
const ENFORCED_MARKER: &str = "  [enforced — envelope-bounded]";
/// The marker for `announce_count`: it IS applied by the runtime announce limiter, but its value is
/// OPERATOR-CHOSEN (`--libp2p-announce-budget`) and is NOT bounded by the safety envelope — it is
/// self-limiting politeness (how much this node advertises of what it fetched), not a network-safety
/// ceiling. Labelled honestly so it is not read as a frozen envelope bound.
const ANNOUNCE_TUNABLE_MARKER: &str =
    "  [operator-overridable — runtime-limited, not envelope-bounded]";

/// How a budget field's runtime status is surfaced on the preflight line, so a label never lies.
#[derive(Clone, Copy)]
enum FieldTag {
    /// Frozen, parity-checked, effective value envelope-guarded.
    Enforced,
    /// Applied at runtime but operator-chosen and not envelope-bounded (announce_count).
    AnnounceTunable,
    /// Frozen + hashed ceiling with no runtime limiter yet (TASK-264).
    DeclaredOnly,
}

/// One `key=value` integer line per artifact field, stable order — greppable/diffable. Each line is
/// tagged so the surface cannot advertise a phantom bound as if it were an enforced envelope ceiling.
fn budget_lines(b: &ProfileBudget) -> Vec<String> {
    use FieldTag::{AnnounceTunable, DeclaredOnly, Enforced};
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
            DeclaredOnly,
        ),
        (
            format!("upload_rate_window_ns={}", b.upload_rate_window_ns),
            DeclaredOnly,
        ),
        (
            format!("concurrent_serves_count={}", b.concurrent_serves_count),
            DeclaredOnly,
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
        (format!("open_fds_count={}", b.open_fds_count), DeclaredOnly),
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
                AnnounceTunable => ANNOUNCE_TUNABLE_MARKER,
                DeclaredOnly => DECLARED_ONLY_MARKER,
            };
            format!("{line}{marker}")
        })
        .collect()
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
        // Not-yet-enforced ceilings are explicitly marked declared-only (no phantom bound).
        for declared in [
            "transient_ram_bytes_ram",
            "open_fds_count",
            "concurrent_serves_count",
            "apparent_disk_bytes_ondisk",
            "upload_rate_bytes_compressed_wire_per_window",
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
