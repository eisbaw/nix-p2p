//! The public-NAR allowlist (TASK-102): the ONE place that decides which NAR
//! identities this node may publicly announce, and the ONLY writer of that list.
//!
//! ## What problem this solves (privacy, publication safety)
//!
//! A decentralized publisher (the DHT announce path, TASK-103) makes a node's
//! holdings DISCOVERABLE to strangers. Announcing a NAR the node holds because it
//! built something private, or fetched from a private substituter, leaks that the
//! user holds it. The invariant this module enforces is narrow and fail-CLOSED:
//! **a NAR identity may be published only if a trusted public cache
//! (cache.nixos.org) CRYPTOGRAPHICALLY PROVED it public** - its Nix ed25519
//! signature over the fingerprint `1;StorePath;NarHash;NarSize;References` verifies
//! against a configured trusted key. Local, unsigned, or privately-signed content
//! NEVER enters the list, so it can never be announced.
//!
//! ## KISS: learned PASSIVELY from requests, never crawled
//!
//! The list is populated as a SIDE EFFECT of the daemon serving a
//! `<hash>.narinfo` request: when the exact-key cache.nixos.org 200 response is
//! proven public ([`prove_public`]), its `(NarHash, NarSize)` is appended ONCE
//! ([`PublicNarAllowlist::learn`]). There is NO `/nix/store` census and NO separate
//! discovery crawl - the only thing that ever adds an entry is a narinfo the daemon
//! was ALREADY going to fetch on the request path. A duplicate request is
//! idempotent: the entry is already present, so nothing is appended and no second
//! network request is made (the caller had already fetched the narinfo anyway).
//!
//! ## The single enforcement point (AC#1)
//!
//! [`PublicNarAllowlist`] owns BOTH sides:
//!   * the WRITE side ([`learn`](PublicNarAllowlist::learn)) - the only path that
//!     appends, and only after verification; and
//!   * the READ side that a publisher consults - [`approve`](PublicNarAllowlist::approve),
//!     which mints a [`PublicNarClaim`]. A `PublicNarClaim` has private fields and
//!     NO public constructor, so - by the type system - it can be obtained ONLY by
//!     passing the allowlist's `contains` check. A public publisher that consumes
//!     `&[PublicNarClaim]` therefore cannot, by construction, announce a NAR the
//!     allowlist did not approve (the same closed-by-construction discipline
//!     `daemon-libp2p`'s `StoreProvision` uses for its verification gate). Absence
//!     is a NAMED, fail-closed [`PublicationRejected`], never a silent skip.
//!
//! ## No enumeration surface (AC#5)
//!
//! The read side is a caller-NAMED probe: `contains`/`approve`/`approved_size` all
//! take a `NarHashKey` the caller already holds - there is no `list`/`iter`/`keys`
//! method and no remote API that would let a peer learn WHICH NARs are allowlisted.
//! [`status`](PublicNarAllowlist::status) returns only the aggregate COUNT and total
//! NarSize - never a `StorePath`, a `NarHash`, or a per-entry inventory. The on-disk
//! file likewise contains NO `StorePath`: only `<NarHash> <NarSize>` pairs. This
//! matches the availability index's no-enumeration invariant.
//!
//! HONEST LIMIT (documented so it is a known property, not a surprise): being ON the
//! allowlist does not make a NAR secret, and PUBLISHING one still fingerprints the
//! set of PUBLIC packages this node holds to whoever it announces to (a DHT node
//! learns "this node offers cache.nixos.org path X"). The allowlist bounds
//! publication to provably-public content; it does not make participation
//! unobservable. That is the axis-6 lookup-leakage story (see
//! `peer-fabric::exposure`), a separate gate.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::claim::NarHashKey;
use crate::source::StoreHash;

// -------------------------------------------------------------------------
// Trusted keys: the AUTHORITY that decides "public".
// -------------------------------------------------------------------------

/// The trusted Nix public keys a narinfo signature is checked against - the
/// AUTHORITY for "this NAR is public". Keyed by the Nix key NAME (`cache.nixos.org-1`,
/// the fixture's `nix-p2p-test-1`), each mapping to its 32-byte ed25519 verifying key.
///
/// The verifying key comes ONLY from here (configured trust), NEVER from the narinfo:
/// a narinfo carries a key NAME and a signature, not a public key, so an attacker
/// cannot supply their own key. This is what makes "wrong authority" a STRUCTURAL
/// guard - an unknown key name has no key to verify against and is refused
/// ([`PublicProofReject::UntrustedKey`]), it does not fall through to some default.
#[derive(Debug, Clone, Default)]
pub struct TrustedNarKeys {
    keys: BTreeMap<String, VerifyingKey>,
}

/// Why a `name:<base64>` trusted-key line could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedKeyError {
    /// The line was not `name:<base64>`.
    Malformed(String),
    /// The base64 body did not decode to 32 ed25519 verifying-key bytes.
    BadKey(String),
}

impl fmt::Display for TrustedKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustedKeyError::Malformed(l) => {
                write!(f, "trusted key line is not name:<base64>: {l:?}")
            }
            TrustedKeyError::BadKey(l) => write!(f, "trusted key is not a valid ed25519 key: {l}"),
        }
    }
}

impl std::error::Error for TrustedKeyError {}

impl TrustedNarKeys {
    /// No trusted keys: every narinfo is refused as [`PublicProofReject::UntrustedKey`],
    /// so a node with no configured authority appends NOTHING (fail-closed default).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build from `name:<base64 ed25519 pubkey>` lines (the Nix `trusted-public-keys`
    /// format), e.g. `cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=`.
    pub fn from_lines<I, S>(lines: I) -> Result<Self, TrustedKeyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut keys = Self::empty();
        for line in lines {
            keys.insert_line(line.as_ref())?;
        }
        Ok(keys)
    }

    /// Add one `name:<base64>` trusted key. A malformed line fails LOUD rather than
    /// silently trusting nothing (a mistyped operator key must not degrade to
    /// fail-open-later - here it degrades to fail-CLOSED, but visibly).
    pub fn insert_line(&mut self, line: &str) -> Result<(), TrustedKeyError> {
        let (name, b64) = line
            .split_once(':')
            .ok_or_else(|| TrustedKeyError::Malformed(line.to_string()))?;
        if name.is_empty() {
            return Err(TrustedKeyError::Malformed(line.to_string()));
        }
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| TrustedKeyError::BadKey(format!("{name}: base64: {e}")))?;
        let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            TrustedKeyError::BadKey(format!("{name}: expected 32 bytes, got {}", raw.len()))
        })?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| TrustedKeyError::BadKey(format!("{name}: {e}")))?;
        self.keys.insert(name.to_string(), key);
        Ok(())
    }

    /// The verifying key configured under `name`, if any.
    fn get(&self, name: &str) -> Option<&VerifyingKey> {
        self.keys.get(name)
    }

    /// Whether any trusted key is configured. An empty set can prove nothing public.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// How many trusted keys are configured.
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

// -------------------------------------------------------------------------
// prove_public: the cryptographic gate (AC#2 verify, AC#3 fail-closed).
// -------------------------------------------------------------------------

/// The canonical, trust-anchored identity a verified-public narinfo yields: exactly
/// the `(NarHash, NarSize)` that the trusted signature COVERED, plus the 32-char store
/// hash of the signed `StorePath` so the caller can correlate it to the EXACT request
/// that produced this narinfo (a signed narinfo for path B must never be admitted as
/// the answer to a request for path A). Only `(NarHash, NarSize)` is ever APPENDED - the
/// `store_hash` is a request-correlation witness, never persisted (no `StorePath` on disk).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPublicNar {
    /// The signed `NarHash`, parsed to the strict wire key (`sha256:<52 nix-base32>`).
    pub nar_hash: NarHashKey,
    /// The signed `NarSize` - the UNCOMPRESSED NAR length (never a compressed FileSize).
    pub nar_size: u64,
    /// The nixbase32 store-hash component of the signed `StorePath` (`<hash>` in
    /// `/nix/store/<hash>-<name>`). The append site checks this equals the requested
    /// `<hash>.narinfo` key before learning, so a mis-correlated response is rejected.
    pub store_hash: String,
}

/// Why a narinfo did NOT prove a NAR public. EACH variant is a distinct fail-closed
/// guard (AC#3): a mutation that neuters the check producing it lets a crafted narinfo
/// append when it must not, so a negative test asserting the variant BITES that mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicProofReject {
    /// A field required to build the signed fingerprint (or the structurally-required
    /// `URL`) was absent (malformed metadata). Mirrors Nix's `nar-info.cc` parser
    /// refusing a narinfo that lacks a mandatory field.
    MissingField(&'static str),
    /// A single-line field required to occur AT MOST ONCE occurred twice. A duplicated
    /// signed field is ambiguous (which value did the signature cover?) - Nix's parser
    /// rejects it, and admitting one lets a first-vs-last split smuggle an unsigned value.
    DuplicateField(&'static str),
    /// The narinfo body did not end in a final newline. Nix writes/parses line-terminated
    /// narinfos; a body without a trailing newline is a truncated / non-canonical response.
    MissingFinalNewline,
    /// `NarSize` parsed but was zero. A real NAR is never zero bytes; a zero size is
    /// structurally invalid (and would let a degenerate record onto the list).
    ZeroNarSize,
    /// `NarHash` was present but not a canonical `sha256:<52 nix-base32>` (hash guard).
    MalformedNarHash(String),
    /// `NarSize` was present but not a base-10 `u64` (size guard).
    MalformedNarSize(String),
    /// The `Sig` line was not `name:<base64>` or did not decode to 64 signature bytes.
    MalformedSig(String),
    /// No `Sig` names a TRUSTED key: the signer's key name is not configured. This is
    /// the WRONG-AUTHORITY / unsigned / local-build / private-upstream case - such a
    /// narinfo carries no signature from an authority we trust, so nothing is appended.
    UntrustedKey(String),
    /// A `Sig` named a trusted key, but its ed25519 signature did NOT verify over the
    /// reconstructed fingerprint (`verify_strict`). This is the INTEGRITY guard: a
    /// tampered StorePath / NarHash / NarSize / References, or a forged signature, all
    /// change what must be signed and land here.
    BadSignature,
}

impl fmt::Display for PublicProofReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicProofReject::MissingField(name) => {
                write!(
                    f,
                    "narinfo lacks required field {name:?}; cannot prove public"
                )
            }
            PublicProofReject::DuplicateField(name) => {
                write!(
                    f,
                    "narinfo has a duplicate {name:?} field; ambiguous, refusing"
                )
            }
            PublicProofReject::MissingFinalNewline => {
                write!(f, "narinfo body is not terminated by a final newline")
            }
            PublicProofReject::ZeroNarSize => write!(f, "narinfo NarSize is zero"),
            PublicProofReject::MalformedNarHash(v) => write!(f, "malformed NarHash {v:?}"),
            PublicProofReject::MalformedNarSize(v) => write!(f, "malformed NarSize {v:?}"),
            PublicProofReject::MalformedSig(v) => write!(f, "malformed Sig {v:?}"),
            PublicProofReject::UntrustedKey(name) => {
                write!(
                    f,
                    "no Sig from a trusted key (saw {name:?}); not proven public"
                )
            }
            PublicProofReject::BadSignature => {
                write!(f, "a trusted-key Sig did not verify over the fingerprint")
            }
        }
    }
}

impl std::error::Error for PublicProofReject {}

/// The nixbase32 store-hash component of a `StorePath` (`<hash>` in
/// `/nix/store/<hash>-<name>`): the basename up to the FIRST `-`. Used only to correlate a
/// verified narinfo back to the `<hash>.narinfo` request that produced it; never persisted.
fn store_hash_of(store_path: &str) -> String {
    let basename = store_path.rsplit('/').next().unwrap_or(store_path);
    match basename.split_once('-') {
        Some((hash, _)) => hash.to_string(),
        None => basename.to_string(),
    }
}

/// The single value of `key` in the narinfo (values are single-line), rejecting a
/// DUPLICATE occurrence. Nix's narinfo is a map: a signed field occurs exactly once, and
/// a well-formed cache narinfo never repeats one. Returning `Err(())` on a second
/// occurrence is what unifies the field semantics across the codebase - proof
/// ([`prove_public`]) and correlation ([`crate::catalog::parse_correlation`]) both refuse
/// duplicates, so there is no first-vs-last gap for an unsigned value to slip through.
fn field<'a>(text: &'a str, key: &str) -> Result<Option<&'a str>, ()> {
    let mut found = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix(key) {
            if found.is_some() {
                return Err(());
            }
            found = Some(value.trim());
        }
    }
    Ok(found)
}

/// Rebuild the exact string Nix signs: `1;<StorePath>;<NarHash>;<NarSize>;<refs>`, in
/// Nix's CANONICAL spelling (`path-info.cc` `ValidPathInfo::fingerprint`):
///   * `nar_hash` is the PARSED canonical `sha256:<52 nix-base32>` (not the raw field
///     spelling), so a non-canonical hash spelling cannot change what we record;
///   * `nar_size` is the DECIMAL of the parsed `u64` (so a leading-zero `NarSize` like
///     `0408` fingerprints as `408`, matching what Nix signed);
///   * `refs` are the `References` basenames re-prefixed with the store directory and
///     SORTED (Nix's fingerprint is over a `StorePathSet`, which is ordered), so a
///     REORDERED `References` field yields the same fingerprint - a reorder cannot make a
///     legitimately-signed NAR fail nor an illegitimate one pass.
///
/// Getting any of this wrong yields a fingerprint that verifies NOWHERE, so the positive
/// control (a real fixture signature) proves it correct.
fn fingerprint(store_path: &str, nar_hash: &str, nar_size: u64, references: &str) -> String {
    // The store directory is the StorePath's parent (e.g. `/nix/store`).
    let store_dir = store_path
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .unwrap_or("");
    let mut refs: Vec<String> = references
        .split_whitespace()
        .filter(|r| !r.is_empty())
        .map(|r| format!("{store_dir}/{r}"))
        .collect();
    refs.sort();
    format!("1;{store_path};{nar_hash};{nar_size};{}", refs.join(","))
}

/// CRYPTOGRAPHICALLY prove a narinfo names a PUBLIC NAR: its trusted-key Nix ed25519
/// signature over `1;StorePath;NarHash;NarSize;References` verifies. On success returns
/// the canonical `(NarHash, NarSize)` the signature covered; on ANY failure returns a
/// NAMED [`PublicProofReject`] and the caller appends NOTHING (fail-closed, AC#3).
///
/// Multiple `Sig:` lines are permitted (a multi-signed narinfo): the NAR is proven
/// public if ANY `Sig` names a trusted key AND verifies. A narinfo with only untrusted
/// signatures is [`PublicProofReject::UntrustedKey`]; one whose trusted-named signature
/// fails to verify is [`PublicProofReject::BadSignature`].
pub fn prove_public(
    narinfo: &[u8],
    trusted: &TrustedNarKeys,
) -> Result<VerifiedPublicNar, PublicProofReject> {
    let text =
        std::str::from_utf8(narinfo).map_err(|_| PublicProofReject::MissingField("StorePath"))?;

    // STRUCTURAL validity (matching Nix's `nar-info.cc` parser strictness): the body must
    // be newline-terminated, and each single-line field must occur AT MOST once. A missing
    // final newline is a truncated / non-canonical response; a duplicated field is
    // ambiguous. Both are refused BEFORE any crypto so a malformed body cannot reach append.
    if !narinfo.ends_with(b"\n") {
        return Err(PublicProofReject::MissingFinalNewline);
    }

    // The four signed fingerprint fields, plus the structurally-required `URL` (a narinfo
    // with no `URL:` is not a servable cache response - Nix's parser requires it). Each is
    // fetched with duplicate-rejection. `References:` may be EMPTY (a leaf path), so only
    // its PRESENCE is required - an absent line is malformed metadata.
    let store_path = field(text, "StorePath:")
        .map_err(|_| PublicProofReject::DuplicateField("StorePath"))?
        .ok_or(PublicProofReject::MissingField("StorePath"))?;
    if store_path.is_empty() {
        return Err(PublicProofReject::MissingField("StorePath"));
    }
    let url = field(text, "URL:")
        .map_err(|_| PublicProofReject::DuplicateField("URL"))?
        .ok_or(PublicProofReject::MissingField("URL"))?;
    if url.is_empty() {
        return Err(PublicProofReject::MissingField("URL"));
    }
    let nar_hash_str = field(text, "NarHash:")
        .map_err(|_| PublicProofReject::DuplicateField("NarHash"))?
        .ok_or(PublicProofReject::MissingField("NarHash"))?;
    let nar_size_str = field(text, "NarSize:")
        .map_err(|_| PublicProofReject::DuplicateField("NarSize"))?
        .ok_or(PublicProofReject::MissingField("NarSize"))?;
    let references = field(text, "References:")
        .map_err(|_| PublicProofReject::DuplicateField("References"))?
        .ok_or(PublicProofReject::MissingField("References"))?;

    // Parse the canonical identity we will record. A NarHash that is not
    // `sha256:<52 nix-base32>` is refused (hash guard); a non-`u64` NarSize is refused
    // (size guard); a ZERO NarSize is structurally invalid (a real NAR is never empty).
    let nar_hash: NarHashKey = nar_hash_str
        .parse()
        .map_err(|_| PublicProofReject::MalformedNarHash(nar_hash_str.to_string()))?;
    let nar_size: u64 = nar_size_str
        .parse()
        .map_err(|_| PublicProofReject::MalformedNarSize(nar_size_str.to_string()))?;
    if nar_size == 0 {
        return Err(PublicProofReject::ZeroNarSize);
    }

    // Fingerprint over the CANONICAL spelling (parsed hash, decimal size, sorted refs), so
    // a leading-zero size or reordered references cannot change what the signature must
    // cover. The recorded identity is precisely what the trusted signature bound.
    let fp = fingerprint(store_path, &nar_hash.to_string(), nar_size, references);
    let store_hash = store_hash_of(store_path);

    // Try every Sig line. Track whether we ever SAW a trusted-named signature so the
    // rejection distinguishes "wrong authority" (no trusted signer at all) from "bad
    // signature" (a trusted signer whose bytes did not verify).
    let mut saw_trusted_named = false;
    let mut last_untrusted_name = String::new();
    for line in text.lines() {
        let Some(sig_value) = line.strip_prefix("Sig:").map(str::trim) else {
            continue;
        };
        let Some((name, b64)) = sig_value.split_once(':') else {
            return Err(PublicProofReject::MalformedSig(sig_value.to_string()));
        };
        let Some(verifying_key) = trusted.get(name) else {
            last_untrusted_name = name.to_string();
            continue;
        };
        saw_trusted_named = true;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| PublicProofReject::MalformedSig(format!("{name}: base64: {e}")))?;
        let sig_bytes: [u8; 64] = raw.as_slice().try_into().map_err(|_| {
            PublicProofReject::MalformedSig(format!(
                "{name}: expected 64 sig bytes, got {}",
                raw.len()
            ))
        })?;
        let signature = Signature::from_bytes(&sig_bytes);
        // `verify_strict`: the SAME strict policy peer-fabric's record codec uses
        // (rejects small-order A/R and non-canonical S), so the two implementations
        // agree on which signatures are valid.
        if verifying_key
            .verify_strict(fp.as_bytes(), &signature)
            .is_ok()
        {
            return Ok(VerifiedPublicNar {
                nar_hash,
                nar_size,
                store_hash,
            });
        }
    }

    if saw_trusted_named {
        // A trusted key was named but its signature did not verify over the
        // fingerprint - tampered signed metadata or a forged signature.
        Err(PublicProofReject::BadSignature)
    } else {
        // No signature from any trusted authority: unsigned / local build / private
        // upstream / signed only by an untrusted key.
        Err(PublicProofReject::UntrustedKey(last_untrusted_name))
    }
}

// -------------------------------------------------------------------------
// The persisted store seam (AC#4).
// -------------------------------------------------------------------------

/// Why loading or appending to the persisted allowlist failed. A load error is LOUD
/// (a corrupt COMMITTED record is never silently skipped); an append error is
/// propagated so `learn` reports it rather than pretending an entry was recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistPersistError(pub String);

impl fmt::Display for AllowlistPersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "public allowlist persistence failed: {}", self.0)
    }
}

impl std::error::Error for AllowlistPersistError {}

/// A hard cap on the on-disk allowlist file: refuse to load a file larger than this
/// rather than buffer an unbounded amount into memory (a corrupt/hostile file must not
/// OOM the daemon). 64 MiB is ~500k records at ~130 B each - far above any real node.
pub(crate) const MAX_ALLOWLIST_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// A hard cap on the number of COMMITTED records loaded, a second bound independent of the
/// byte cap (a file of many tiny lines is still bounded).
pub(crate) const MAX_ALLOWLIST_RECORDS: usize = 1_000_000;

/// The blake3 domain-separation context the per-node allowlist MAC key is derived under.
/// Distinct context => the MAC key is unusable for any other purpose even given the same
/// identity seed, and a key from a DIFFERENT context cannot forge an allowlist line.
pub(crate) const ALLOWLIST_MAC_CONTEXT: &str = "nix-p2p public-allowlist record MAC v1";

/// Derive the per-node allowlist MAC key from a durable secret (the libp2p identity seed).
/// Domain-separated via [`ALLOWLIST_MAC_CONTEXT`], so the returned key is unusable for any
/// other purpose and a foreign node's key (a different seed) cannot forge a record line.
/// The caller passes the result to [`PublicNarAllowlist::open_file`].
pub fn derive_allowlist_mac_key(identity_seed: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(ALLOWLIST_MAC_CONTEXT, identity_seed)
}

/// Persists the append-only allowlist so it survives a restart. The SOURCE OF TRUTH is the
/// sequence of `(NarHash, NarSize)` records ever verified public; a duplicate is never
/// appended (the in-memory set dedups before the store is touched).
///
/// SEALED (TASK-102 security fix). This trait, its implementations, and
/// [`PublicNarAllowlist::open`] are `pub(crate)`: external code CANNOT name the trait, so
/// it cannot implement a forged store nor pass one to `open`. The ONLY ways an external
/// caller obtains a [`PublicNarAllowlist`] are the sealed constructors
/// ([`PublicNarAllowlist::disabled`], [`PublicNarAllowlist::in_memory`],
/// [`PublicNarAllowlist::open_file`]). This closes the forged-store bypass: previously
/// `open(empty_trusted, forged_store)` then `approve()` could mint a claim for an entry
/// that never passed `learn`'s signature check.
pub(crate) trait AllowlistStore: Send + Sync {
    /// Load every COMMITTED record (empty if the file does not exist yet). A record that
    /// was fully written (terminated) but does not parse OR whose MAC does not verify is
    /// CORRUPTION/TAMPERING and fails LOUD; a torn FINAL record (no terminator) is dropped.
    fn load(&self) -> Result<Vec<(NarHashKey, u64)>, AllowlistPersistError>;

    /// Durably APPEND one record. Crash-safe: a torn append loses at most this record and
    /// never creates eligibility (an unterminated tail is dropped on load / truncated on
    /// the next append).
    fn append(&self, nar_hash: &NarHashKey, nar_size: u64) -> Result<(), AllowlistPersistError>;
}

/// An in-memory store: the allowlist does not survive a restart. Used by the DISABLED
/// allowlist (an empty-trusted-keys no-op) and by tests that do not exercise persistence.
#[derive(Debug, Default)]
pub(crate) struct NullAllowlistStore;

impl AllowlistStore for NullAllowlistStore {
    fn load(&self) -> Result<Vec<(NarHashKey, u64)>, AllowlistPersistError> {
        Ok(Vec::new())
    }
    fn append(&self, _nar_hash: &NarHashKey, _nar_size: u64) -> Result<(), AllowlistPersistError> {
        Ok(())
    }
}

/// The canonical MAC-covered bytes of one record: `<NarHash> <NarSize>`. The MAC binds
/// exactly what we record; the on-disk line is `<canonical> <mac-hex>\n`.
fn record_canonical(nar_hash: &NarHashKey, nar_size: u64) -> String {
    format!("{nar_hash} {nar_size}")
}

/// The keyed-blake3 MAC over a record's canonical bytes, as 64 lowercase hex chars.
/// A modified/injected/foreign line (a flipped nixbase32 char, a size edit, or a line
/// written under a different node's key) recomputes to a DIFFERENT MAC and fails on load.
fn record_mac(mac_key: &[u8; 32], nar_hash: &NarHashKey, nar_size: u64) -> String {
    blake3::keyed_hash(mac_key, record_canonical(nar_hash, nar_size).as_bytes())
        .to_hex()
        .to_string()
}

/// The real store: a single APPEND-ONLY, integrity-protected text file, one record per
/// line: `sha256:<52 nix-base32> <nar_size> <mac-hex>\n`. No `StorePath`, so the file
/// cannot be an inventory of what the node BUILT - only which public NARs it may announce.
///
/// INTEGRITY (TASK-102 security fix, AC#4). Each line carries a keyed-blake3 MAC over its
/// `<NarHash> <NarSize>` under a PER-NODE secret ([`FileAllowlistStore::new`]'s `mac_key`,
/// derived from the durable identity seed). A line that was modified in place (a flipped
/// nixbase32 char, an edited size), injected, or copied from another node fails its MAC on
/// load - it can no longer fabricate eligibility for a NAR that never passed `learn`. The
/// valid MAC is the integrity COMMIT MARKER (not a bare newline): a committed line is
/// trusted only if its MAC verifies.
///
/// CRASH SAFETY (AC#4). Append holds an exclusive `flock` and, before writing, TRUNCATES
/// any torn tail (an unterminated final line from a prior crashed append) so a new record
/// is never concatenated onto a partial one. The write is one line + `sync_all`; the parent
/// directory is fsynced on first creation. A crash mid-append leaves a torn tail that
/// [`Self::load`] drops and the next append truncates.
///
/// STRICT FILE CHECKS (AC#4). The file is opened `O_NOFOLLOW` (a symlink in its place is
/// refused) and `fstat`ed on every open: it must be a REGULAR file with exactly ONE hard
/// link (`st_nlink == 1`), OWNED by this process's euid, and mode `0600` (no group/other
/// bits at all - the NarHash inventory must not be group/world-readable). Its PARENT
/// directory is opened `O_DIRECTORY|O_NOFOLLOW` (a symlinked parent is refused) and checked
/// to be owned by this euid and not group/other-writable. A cross-process `flock` serialises
/// writers. A file that fails any check is refused (fail-closed) rather than trusted.
pub(crate) struct FileAllowlistStore {
    path: PathBuf,
    /// The per-node MAC secret (derived from the durable identity seed by the caller).
    mac_key: [u8; 32],
}

/// How [`FileAllowlistStore::open_strict`] should open the file.
enum OpenMode {
    /// Read-only (`load`): `O_RDONLY`. A missing file yields `Ok(None)`.
    Read,
    /// Read-write for the truncate-then-append cycle: `O_RDWR|O_CREAT`.
    ReadWrite,
}

impl FileAllowlistStore {
    /// Persist to `path`, MAC-protected under `mac_key` (a per-node secret). The parent
    /// directory is created on first append if absent.
    pub(crate) fn new(path: impl Into<PathBuf>, mac_key: [u8; 32]) -> Self {
        FileAllowlistStore {
            path: path.into(),
            mac_key,
        }
    }

    /// Open the file with the strict owner/mode/type/link/nlink checks. Returns `Ok(None)`
    /// only for a non-existent file in [`OpenMode::Read`] (a first-boot empty allowlist).
    fn open_strict(&self, mode: OpenMode) -> Result<Option<std::fs::File>, AllowlistPersistError> {
        use rustix::fs::{FileType, Mode, OFlags};

        let mut flags = OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let create = match mode {
            OpenMode::Read => {
                flags |= OFlags::RDONLY;
                false
            }
            OpenMode::ReadWrite => {
                flags |= OFlags::RDWR | OFlags::CREATE;
                true
            }
        };
        // 0600: owner read/write only. Applies only when CREATE actually makes the file.
        let fd = match rustix::fs::open(&self.path, flags, Mode::RUSR | Mode::WUSR) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
            Err(e) => {
                return Err(AllowlistPersistError(format!(
                    "opening {}: {e}",
                    self.path.display()
                )));
            }
        };
        let stat = rustix::fs::fstat(&fd).map_err(|e| {
            AllowlistPersistError(format!("inspecting {}: {e}", self.path.display()))
        })?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(AllowlistPersistError(format!(
                "{} is not a regular file",
                self.path.display()
            )));
        }
        if stat.st_nlink != 1 {
            return Err(AllowlistPersistError(format!(
                "{} has {} hard links (expected 1); refusing a possibly-shared inode",
                self.path.display(),
                stat.st_nlink
            )));
        }
        let euid = rustix::process::geteuid().as_raw();
        if stat.st_uid != euid {
            return Err(AllowlistPersistError(format!(
                "{} is owned by uid {}, not this process ({euid}); refusing to trust it",
                self.path.display(),
                stat.st_uid
            )));
        }
        if stat.st_mode & 0o077 != 0 {
            return Err(AllowlistPersistError(format!(
                "{} is group/other-accessible (mode {:o}); the NarHash inventory must be 0600",
                self.path.display(),
                stat.st_mode & 0o777
            )));
        }
        Ok(Some(std::fs::File::from(fd)))
    }

    /// The parent directory the file lives in (`.` for a bare filename).
    fn parent(&self) -> PathBuf {
        match self.path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        }
    }

    /// Validate the immediate parent directory: opened `O_DIRECTORY|O_NOFOLLOW` (a symlinked
    /// parent is refused), owned by this euid, and not group/other-writable. HONEST LIMIT:
    /// only the IMMEDIATE parent is checked here, not every ancestor component; a fully
    /// symlink-safe ancestor walk (openat from a trusted root) is a follow-up.
    fn check_parent(&self) -> Result<(), AllowlistPersistError> {
        use rustix::fs::{FileType, Mode, OFlags};
        let parent = self.parent();
        let fd = rustix::fs::open(
            &parent,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            AllowlistPersistError(format!(
                "opening parent dir {} (O_NOFOLLOW): {e}",
                parent.display()
            ))
        })?;
        let stat = rustix::fs::fstat(&fd).map_err(|e| {
            AllowlistPersistError(format!("inspecting parent dir {}: {e}", parent.display()))
        })?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(AllowlistPersistError(format!(
                "{} is not a directory",
                parent.display()
            )));
        }
        let euid = rustix::process::geteuid().as_raw();
        if stat.st_uid != euid {
            return Err(AllowlistPersistError(format!(
                "parent dir {} is owned by uid {}, not this process ({euid}); refusing",
                parent.display(),
                stat.st_uid
            )));
        }
        if stat.st_mode & 0o022 != 0 {
            return Err(AllowlistPersistError(format!(
                "parent dir {} is group/other-writable (mode {:o}); refusing",
                parent.display(),
                stat.st_mode & 0o777
            )));
        }
        Ok(())
    }

    /// Parse the loaded bytes into records, verifying each committed line's MAC. Shared by
    /// `load` and by `append`'s torn-tail detection.
    fn parse_committed(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<(NarHashKey, u64)>, AllowlistPersistError> {
        let text = std::str::from_utf8(bytes).map_err(|e| {
            AllowlistPersistError(format!("{} is not valid UTF-8: {e}", self.path.display()))
        })?;
        let mut out = Vec::new();
        // `split_inclusive` keeps each line's `\n`. A final segment WITHOUT a trailing `\n`
        // is a TORN append - drop it (never eligibility). Every COMMITTED line must parse
        // AND its MAC must verify.
        for segment in text.split_inclusive('\n') {
            let Some(line) = segment.strip_suffix('\n') else {
                break; // torn/uncommitted tail
            };
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            if out.len() >= MAX_ALLOWLIST_RECORDS {
                return Err(AllowlistPersistError(format!(
                    "{} exceeds the {MAX_ALLOWLIST_RECORDS}-record bound",
                    self.path.display()
                )));
            }
            let mut parts = line.splitn(3, ' ');
            let hash_str = parts.next().unwrap_or("");
            let size_str = parts.next().ok_or_else(|| {
                AllowlistPersistError(format!(
                    "{} has a committed line missing the size field: {line:?}",
                    self.path.display()
                ))
            })?;
            let mac_str = parts.next().ok_or_else(|| {
                AllowlistPersistError(format!(
                    "{} has a committed line missing the MAC field: {line:?}",
                    self.path.display()
                ))
            })?;
            let nar_hash: NarHashKey = hash_str.parse().map_err(|e| {
                AllowlistPersistError(format!(
                    "{} has a non-canonical NarHash {hash_str:?}: {e}",
                    self.path.display()
                ))
            })?;
            let nar_size: u64 = size_str.parse().map_err(|e| {
                AllowlistPersistError(format!(
                    "{} has a non-u64 NarSize {size_str:?}: {e}",
                    self.path.display()
                ))
            })?;
            // Integrity: recompute the MAC over the canonical bytes and compare. A modified,
            // injected, or foreign line fails HERE and the whole load fails LOUD.
            let expected = record_mac(&self.mac_key, &nar_hash, nar_size);
            if !constant_time_eq(mac_str.as_bytes(), expected.as_bytes()) {
                return Err(AllowlistPersistError(format!(
                    "{} has a committed line whose MAC does not verify (modified, injected, \
                     or written by another node): {line:?}",
                    self.path.display()
                )));
            }
            out.push((nar_hash, nar_size));
        }
        Ok(out)
    }
}

/// A length-checked, timing-independent byte comparison for the MAC (both operands are
/// fixed-length hex here, so timing is a defence-in-depth nicety, not load-bearing).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl AllowlistStore for FileAllowlistStore {
    fn load(&self) -> Result<Vec<(NarHashKey, u64)>, AllowlistPersistError> {
        use std::io::Read as _;
        let Some(file) = self.open_strict(OpenMode::Read)? else {
            return Ok(Vec::new());
        };
        // Shared lock: a concurrent writer's append is serialised against this read.
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockShared).map_err(|e| {
            AllowlistPersistError(format!("locking {} for read: {e}", self.path.display()))
        })?;
        let stat = rustix::fs::fstat(&file)
            .map_err(|e| AllowlistPersistError(format!("sizing {}: {e}", self.path.display())))?;
        if stat.st_size as u64 > MAX_ALLOWLIST_FILE_BYTES {
            return Err(AllowlistPersistError(format!(
                "{} is {} bytes, over the {MAX_ALLOWLIST_FILE_BYTES}-byte bound; refusing to load",
                self.path.display(),
                stat.st_size
            )));
        }
        let mut bytes = Vec::new();
        // Bounded read (defence-in-depth against a file that grew past the stat).
        (&file)
            .take(MAX_ALLOWLIST_FILE_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|e| AllowlistPersistError(format!("reading {}: {e}", self.path.display())))?;
        self.parse_committed(&bytes)
    }

    fn append(&self, nar_hash: &NarHashKey, nar_size: u64) -> Result<(), AllowlistPersistError> {
        use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
        let parent = self.parent();
        let existed = self.path.exists();
        if !existed {
            std::fs::create_dir_all(&parent).map_err(|e| {
                AllowlistPersistError(format!("creating {}: {e}", parent.display()))
            })?;
        }
        // Strict parent-directory checks (symlinked/foreign/writable parent refused).
        self.check_parent()?;

        let mut file = self
            .open_strict(OpenMode::ReadWrite)?
            .expect("open_strict(ReadWrite) never returns None");
        // Exclusive cross-process writer lock: two daemons sharing a state dir cannot
        // interleave appends (and a reader takes a shared lock).
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive).map_err(|e| {
            AllowlistPersistError(format!("locking {} for append: {e}", self.path.display()))
        })?;

        // TRUNCATE any torn tail before appending, so the new record is never concatenated
        // onto a partial line (which would make BOTH fail their MAC). The committed prefix
        // is everything up to and including the last newline.
        let mut existing = Vec::new();
        (&file)
            .take(MAX_ALLOWLIST_FILE_BYTES)
            .read_to_end(&mut existing)
            .map_err(|e| AllowlistPersistError(format!("reading {}: {e}", self.path.display())))?;
        let committed_len = match existing.iter().rposition(|b| *b == b'\n') {
            Some(i) => i + 1,
            None => 0,
        };
        if committed_len as u64 != existing.len() as u64 {
            rustix::fs::ftruncate(&file, committed_len as u64).map_err(|e| {
                AllowlistPersistError(format!(
                    "truncating torn tail of {}: {e}",
                    self.path.display()
                ))
            })?;
        }
        file.seek(SeekFrom::Start(committed_len as u64))
            .map_err(|e| AllowlistPersistError(format!("seeking {}: {e}", self.path.display())))?;

        let mac = record_mac(&self.mac_key, nar_hash, nar_size);
        let line = format!("{} {mac}\n", record_canonical(nar_hash, nar_size));
        file.write_all(line.as_bytes()).map_err(|e| {
            AllowlistPersistError(format!("appending to {}: {e}", self.path.display()))
        })?;
        file.sync_all()
            .map_err(|e| AllowlistPersistError(format!("fsyncing {}: {e}", self.path.display())))?;
        // On first creation, fsync the parent directory so the new file's name->inode link
        // is itself durable. Do NOT silently discard the error: a failed parent fsync means
        // the file could vanish on a crash, so surface it (fail-verbose).
        if !existed {
            let dir = std::fs::File::open(&parent).map_err(|e| {
                AllowlistPersistError(format!(
                    "opening parent dir {} to fsync: {e}",
                    parent.display()
                ))
            })?;
            dir.sync_all().map_err(|e| {
                AllowlistPersistError(format!("fsyncing parent dir {}: {e}", parent.display()))
            })?;
        }
        Ok(())
    }
}

// -------------------------------------------------------------------------
// The allowlist: single enforcement point (AC#1), status (AC#5).
// -------------------------------------------------------------------------

/// Aggregate status of the allowlist (AC#5). Deliberately carries ONLY the count and
/// the total NarSize - no `StorePath`, no `NarHash`, no per-entry inventory - so
/// reporting it cannot leak WHICH NARs the node may announce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowlistStatus {
    /// How many distinct NAR identities are allowlisted.
    pub count: usize,
    /// The sum of their NarSizes, in UNCOMPRESSED NAR bytes.
    pub total_nar_size_bytes: u64,
}

/// The outcome of a [`PublicNarAllowlist::learn`] on one narinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LearnOutcome {
    /// Newly proven public and appended this call.
    Appended { nar_hash: NarHashKey, nar_size: u64 },
    /// Already allowlisted (idempotent): nothing appended, no second network request.
    AlreadyPresent { nar_hash: NarHashKey },
    /// Not proven public (a NAMED fail-closed guard): nothing appended.
    Rejected(PublicProofReject),
    /// The narinfo PROVED a NAR public, but its signed `StorePath` does not correspond to
    /// the `<hash>.narinfo` that was requested (a mis-correlated response: request A,
    /// received a signed narinfo for B). Nothing appended - only the exact requested key's
    /// verified narinfo may learn, so a hostile/misrouted upstream cannot inject B.
    RequestMismatch { requested: String, signed: String },
    /// Proven public, but persisting the append failed: nothing was admitted in-memory
    /// either, so disk and memory agree (a restart simply re-verifies on the next request).
    PersistFailed(AllowlistPersistError),
}

/// An UNFORGEABLE proof that a NAR identity is allowlisted for PUBLIC announcement.
///
/// Its fields are private and it has NO public constructor: the ONLY way to obtain one
/// is [`PublicNarAllowlist::approve`], which mints it exactly when the allowlist's
/// `contains` check passes. A public publisher that consumes `&[PublicNarClaim]`
/// therefore CANNOT, by the type system, announce a NAR the allowlist did not approve -
/// the same closed-by-construction gate `StoreProvision` gives the verification path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicNarClaim {
    nar_hash: NarHashKey,
    nar_size: u64,
}

impl PublicNarClaim {
    /// The allowlisted NAR identity a publisher may announce.
    pub fn nar_hash(&self) -> &NarHashKey {
        &self.nar_hash
    }

    /// Its approved UNCOMPRESSED NarSize.
    pub fn nar_size(&self) -> u64 {
        self.nar_size
    }
}

/// Why a publication was refused (fail-closed). Absence from the allowlist is the
/// normal case; a size mismatch is a defensive guard against a caller announcing a
/// different NarSize than the one proven public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationRejected {
    /// The NAR identity is not allowlisted (never proven public), so it may not be
    /// announced. THE fail-closed default.
    NotAllowlisted(NarHashKey),
    /// The NAR is allowlisted, but the caller's NarSize disagrees with the approved one.
    SizeMismatch {
        nar_hash: NarHashKey,
        approved: u64,
        requested: u64,
    },
}

impl fmt::Display for PublicationRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicationRejected::NotAllowlisted(h) => {
                write!(
                    f,
                    "{h} is not allowlisted (never proven public); refusing to announce"
                )
            }
            PublicationRejected::SizeMismatch {
                nar_hash,
                approved,
                requested,
            } => write!(
                f,
                "{nar_hash} is allowlisted at NarSize {approved} but announce requested {requested}"
            ),
        }
    }
}

impl std::error::Error for PublicationRejected {}

/// The ONE public-NAR allowlist: the single writer (`learn`) and the single authority
/// a publisher consults (`approve`/`contains`). See the module docs.
pub struct PublicNarAllowlist {
    /// The trusted authority that decides "public". Empty => a DISABLED allowlist that
    /// proves nothing and appends nothing.
    trusted: TrustedNarKeys,
    /// `NarHash -> NarSize`. The in-memory dedup + query set, guarded by a Mutex held
    /// across check->append->insert so a concurrent duplicate learn cannot double-append.
    entries: Mutex<BTreeMap<NarHashKey, u64>>,
    /// The durable backing.
    store: Box<dyn AllowlistStore>,
}

impl PublicNarAllowlist {
    /// Build an allowlist over `trusted` and `store`, loading any persisted records so it
    /// survives a restart. A corrupt/tampered persisted file fails LOUD here (never a silent
    /// empty allowlist). SEALED (`pub(crate)`): external code cannot pass a forged store -
    /// it reaches this only through [`Self::in_memory`] / [`Self::open_file`] / [`Self::disabled`].
    pub(crate) fn open(
        trusted: TrustedNarKeys,
        store: Box<dyn AllowlistStore>,
    ) -> Result<Self, AllowlistPersistError> {
        let loaded = store.load()?;
        let entries = loaded.into_iter().collect();
        Ok(PublicNarAllowlist {
            trusted,
            entries: Mutex::new(entries),
            store,
        })
    }

    /// An IN-MEMORY allowlist over `trusted`: it learns and enforces for this process but
    /// does not persist. The sealed replacement for `open(trusted, NullAllowlistStore)` now
    /// that the store seam is `pub(crate)`.
    pub fn in_memory(trusted: TrustedNarKeys) -> Self {
        // Load of a NullAllowlistStore is infallible, so unwrap is total.
        Self::open(trusted, Box::new(NullAllowlistStore))
            .expect("NullAllowlistStore load is infallible")
    }

    /// A FILE-BACKED allowlist over `trusted`, integrity-protected under `mac_key` (a
    /// per-node secret the caller derives from the durable identity seed, e.g. via
    /// [`derive_allowlist_mac_key`]). Loads any persisted records (failing LOUD on a
    /// tampered/foreign file). The sealed replacement for constructing a `FileAllowlistStore`
    /// externally - external code cannot name the store type.
    pub fn open_file(
        trusted: TrustedNarKeys,
        path: impl Into<PathBuf>,
        mac_key: [u8; 32],
    ) -> Result<Self, AllowlistPersistError> {
        Self::open(trusted, Box::new(FileAllowlistStore::new(path, mac_key)))
    }

    /// A DISABLED allowlist: no trusted keys, in-memory only. Every `learn` is refused
    /// [`PublicProofReject::UntrustedKey`], so it appends NOTHING - the safe default for
    /// a daemon with no configured publication authority (and for tests that do not
    /// exercise learning). `contains` is always false, so nothing may be published.
    pub fn disabled() -> Self {
        PublicNarAllowlist {
            trusted: TrustedNarKeys::empty(),
            entries: Mutex::new(BTreeMap::new()),
            store: Box::new(NullAllowlistStore),
        }
    }

    /// LEARN from a narinfo the daemon is serving in response to a `<requested>.narinfo`
    /// request: if the narinfo PROVES a NAR public AND its signed `StorePath` correlates to
    /// the EXACT `requested` store hash, append its `(NarHash, NarSize)` ONCE. Idempotent -
    /// a duplicate is [`LearnOutcome::AlreadyPresent`] with no append and no second network
    /// request. This is the ONLY path that writes the allowlist (AC#1/#2). Fail-closed on
    /// every rejection (AC#3) and on a request/response mismatch (AC#3 correlation): a signed
    /// narinfo for a path OTHER than the one requested is refused, so a hostile or misrouted
    /// upstream cannot answer "request A" with "here is signed-public B" and get B learned.
    pub fn learn(&self, requested: &StoreHash, narinfo: &[u8]) -> LearnOutcome {
        let verified = match prove_public(narinfo, &self.trusted) {
            Ok(v) => v,
            Err(reject) => return LearnOutcome::Rejected(reject),
        };
        // EXACT-request correlation: the verified narinfo must be the response to the key we
        // asked for. Compare the signed StorePath's store hash to the requested `<hash>`.
        if verified.store_hash != requested.as_str() {
            return LearnOutcome::RequestMismatch {
                requested: requested.as_str().to_string(),
                signed: verified.store_hash,
            };
        }
        let mut entries = self.entries.lock().expect("allowlist mutex poisoned");
        if let Some(&existing) = entries.get(&verified.nar_hash) {
            // Idempotent. A verified duplicate must carry the same size (the signature
            // binds NarHash and NarSize together), so we do not need to reconcile it.
            debug_assert_eq!(existing, verified.nar_size);
            return LearnOutcome::AlreadyPresent {
                nar_hash: verified.nar_hash,
            };
        }
        // Persist FIRST, then admit in-memory, so a persist failure leaves disk and
        // memory in agreement (nothing admitted) - never an in-memory entry the next
        // boot would lose. Holding the map lock across the append makes check+append+insert
        // atomic, so a concurrent duplicate learn cannot double-append.
        if let Err(e) = self.store.append(&verified.nar_hash, verified.nar_size) {
            return LearnOutcome::PersistFailed(e);
        }
        entries.insert(verified.nar_hash, verified.nar_size);
        LearnOutcome::Appended {
            nar_hash: verified.nar_hash,
            nar_size: verified.nar_size,
        }
    }

    /// Whether `nar_hash` is allowlisted (proven public). A caller-NAMED probe - there
    /// is no method that lists the allowlist, so this is not an enumeration surface (AC#5).
    pub fn contains(&self, nar_hash: &NarHashKey) -> bool {
        self.entries
            .lock()
            .expect("allowlist mutex poisoned")
            .contains_key(nar_hash)
    }

    /// The approved NarSize for `nar_hash`, if allowlisted. Caller-named, like `contains`.
    pub fn approved_size(&self, nar_hash: &NarHashKey) -> Option<u64> {
        self.entries
            .lock()
            .expect("allowlist mutex poisoned")
            .get(nar_hash)
            .copied()
    }

    /// CONSULT the allowlist for a NAR a publisher intends to announce, minting an
    /// unforgeable [`PublicNarClaim`] iff it is allowlisted. Fail-closed: an
    /// un-allowlisted NAR is [`PublicationRejected::NotAllowlisted`] and NO claim is
    /// minted, so a publisher that consumes only `PublicNarClaim`s cannot announce it.
    ///
    /// `expected_size` is the size the publisher intends to advertise; it must match the
    /// approved size (a defensive guard so a claim can never carry a size the allowlist
    /// did not prove). Pass `None` to accept the approved size as-is.
    pub fn approve(
        &self,
        nar_hash: &NarHashKey,
        expected_size: Option<u64>,
    ) -> Result<PublicNarClaim, PublicationRejected> {
        let approved = self
            .approved_size(nar_hash)
            .ok_or(PublicationRejected::NotAllowlisted(*nar_hash))?;
        if let Some(requested) = expected_size
            && requested != approved
        {
            return Err(PublicationRejected::SizeMismatch {
                nar_hash: *nar_hash,
                approved,
                requested,
            });
        }
        Ok(PublicNarClaim {
            nar_hash: *nar_hash,
            nar_size: approved,
        })
    }

    /// The aggregate status (AC#5): count + total NarSize, NEVER an inventory.
    pub fn status(&self) -> AllowlistStatus {
        let entries = self.entries.lock().expect("allowlist mutex poisoned");
        AllowlistStatus {
            count: entries.len(),
            total_nar_size_bytes: entries.values().copied().sum(),
        }
    }
}

impl fmt::Debug for PublicNarAllowlist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NEVER print the entries (that would be an inventory in a log). Only the
        // aggregate status, matching the no-enumeration invariant.
        let status = self.status();
        f.debug_struct("PublicNarAllowlist")
            .field("trusted_keys", &self.trusted.len())
            .field("count", &status.count)
            .field("total_nar_size_bytes", &status.total_nar_size_bytes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The committed fixture public key (fixtures/out/generations/.../test-key.pub) and a
    // REAL signed narinfo from that generation (the `app` path, which has a NON-EMPTY
    // References field - so it exercises the reference part of the fingerprint that an
    // empty-reference path cannot). If the fingerprint reconstruction were wrong, this
    // real signature would not verify and the positive control below would fail.
    const FIXTURE_PUBKEY: &str = "nix-p2p-test-1:empdFBu9wVZG12rPKToHMOTsU1qzWzeCcLdq/KQH0JQ=";

    const APP_NARINFO: &[u8] = b"StorePath: /nix/store/l30jg5xg904s62jvw5znmr682xpr993c-nix-p2p-fixture-app\n\
URL: nar/15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7.nar.xz\n\
Compression: xz\n\
FileHash: sha256:15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7\n\
FileSize: 260\n\
NarHash: sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm\n\
NarSize: 408\n\
References: 0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib\n\
Deriver: 3135ldqj1kl5wxkrrdnf4dfxiqakjz0z-nix-p2p-fixture-app.drv\n\
Sig: nix-p2p-test-1:Xqf1bjNJ1ReFahm86zY+hv80+7QeJer5V/HjlEAvP39yJEK8w8jHG9WH5lM7mN9WCIbdH/DDx81dmsjVObMqAQ==\n";

    // The store hash of APP_NARINFO's StorePath (the `<hash>.narinfo` a client requests).
    const APP_STORE_HASH: &str = "l30jg5xg904s62jvw5znmr682xpr993c";
    const APP_NAR_HASH: &str = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";

    // The `lib` path with an EMPTY References field (a leaf) - proves the empty-refs
    // fingerprint (`...;<narsize>;` with a trailing empty segment) is right too.
    const LIB_NARINFO: &[u8] = b"StorePath: /nix/store/0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib\n\
URL: nar/06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb.nar\n\
Compression: none\n\
FileHash: sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb\n\
FileSize: 66048\n\
NarHash: sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb\n\
NarSize: 66048\n\
References: \n\
Deriver: g7hlrj8ys2w9i9d9zm6v4zxw7hpws0a7-nix-p2p-fixture-lib.drv\n\
Sig: nix-p2p-test-1:kvRtCi6KujoW6x7esqgP8QdiaaVX4OL1beI/xmfobVHzM/tSSqmy7jcnI7QDognLkmkwaSgA6vraWOYN0kiICw==\n";

    const LIB_STORE_HASH: &str = "0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz";

    // A deterministic per-node MAC key for the file-store tests.
    const TEST_MAC_KEY: [u8; 32] = [0x42u8; 32];

    fn trusted() -> TrustedNarKeys {
        TrustedNarKeys::from_lines([FIXTURE_PUBKEY]).expect("fixture pubkey parses")
    }

    fn app_hash() -> StoreHash {
        StoreHash::new(APP_STORE_HASH)
    }

    fn lib_hash() -> StoreHash {
        StoreHash::new(LIB_STORE_HASH)
    }

    fn app_nar_hash() -> NarHashKey {
        APP_NAR_HASH.parse().unwrap()
    }

    // A second, DIFFERENT valid keypair used as an UNTRUSTED signer. Deterministic seed.
    fn untrusted_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    // ---- prove_public: positive controls (real fixture signatures) --------

    #[test]
    fn real_fixture_narinfo_with_references_proves_public() {
        // POSITIVE CONTROL: a real cache-shaped narinfo, its real trusted signature,
        // verifies over the reconstructed CANONICAL fingerprint. This proves the reference
        // re-prefixing + sorting in `fingerprint` is correct (the app path has a reference).
        let v = prove_public(APP_NARINFO, &trusted()).expect("app narinfo proves public");
        assert_eq!(v.nar_hash.to_string(), APP_NAR_HASH);
        assert_eq!(v.nar_size, 408);
        assert_eq!(v.store_hash, APP_STORE_HASH);
    }

    #[test]
    fn real_fixture_narinfo_with_empty_references_proves_public() {
        let v = prove_public(LIB_NARINFO, &trusted()).expect("lib narinfo proves public");
        assert_eq!(v.nar_size, 66048);
        assert_eq!(v.store_hash, LIB_STORE_HASH);
    }

    // ---- prove_public: each fail-closed guard BITES (AC#3) ----------------
    // Each negative differs from the positive control in EXACTLY ONE dimension, and the
    // guard producing its reject is the ONLY thing standing between it and an append.

    #[test]
    fn guard_untrusted_key_bites_wrong_authority() {
        let empty = TrustedNarKeys::empty();
        assert!(matches!(
            prove_public(APP_NARINFO, &empty),
            Err(PublicProofReject::UntrustedKey(_))
        ));
    }

    #[test]
    fn guard_untrusted_key_bites_a_valid_but_untrusted_signer() {
        // A narinfo VALIDLY signed by a real second keypair that is NOT trusted.
        let sk = untrusted_signing_key();
        let store_path = "/nix/store/0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib";
        let nar_hash = "sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb";
        let nar_size = 66048u64;
        let fp = fingerprint(store_path, nar_hash, nar_size, "");
        let sig = ed25519_dalek::Signer::sign(&sk, fp.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let narinfo = format!(
            "StorePath: {store_path}\nURL: nar/x.nar\nCompression: none\n\
             FileHash: {nar_hash}\nFileSize: {nar_size}\nNarHash: {nar_hash}\n\
             NarSize: {nar_size}\nReferences: \nSig: evil-key-1:{sig_b64}\n"
        );
        let out = prove_public(narinfo.as_bytes(), &trusted());
        assert_eq!(
            out,
            Err(PublicProofReject::UntrustedKey("evil-key-1".into()))
        );
    }

    #[test]
    fn guard_bad_signature_bites_a_tampered_narhash() {
        let tampered = String::from_utf8(APP_NARINFO.to_vec()).unwrap().replace(
            "NarHash: sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm",
            "NarHash: sha256:1pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm",
        );
        assert_eq!(
            prove_public(tampered.as_bytes(), &trusted()),
            Err(PublicProofReject::BadSignature)
        );
    }

    #[test]
    fn guard_bad_signature_bites_a_tampered_narsize() {
        let tampered = String::from_utf8(APP_NARINFO.to_vec())
            .unwrap()
            .replace("NarSize: 408", "NarSize: 409");
        assert_eq!(
            prove_public(tampered.as_bytes(), &trusted()),
            Err(PublicProofReject::BadSignature)
        );
    }

    #[test]
    fn guard_bad_signature_bites_tampered_references() {
        let tampered = String::from_utf8(APP_NARINFO.to_vec()).unwrap().replace(
            "References: 0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib",
            "References: ",
        );
        assert_eq!(
            prove_public(tampered.as_bytes(), &trusted()),
            Err(PublicProofReject::BadSignature)
        );
    }

    #[test]
    fn guard_bad_signature_bites_forged_sig_bytes() {
        let forged_b64 = base64::engine::general_purpose::STANDARD.encode([0x11u8; 64]);
        let tampered = String::from_utf8(APP_NARINFO.to_vec()).unwrap().replace(
            "Sig: nix-p2p-test-1:Xqf1bjNJ1ReFahm86zY+hv80+7QeJer5V/HjlEAvP39yJEK8w8jHG9WH5lM7mN9WCIbdH/DDx81dmsjVObMqAQ==",
            &format!("Sig: nix-p2p-test-1:{forged_b64}"),
        );
        assert_eq!(
            prove_public(tampered.as_bytes(), &trusted()),
            Err(PublicProofReject::BadSignature)
        );
    }

    #[test]
    fn guard_missing_field_bites_absent_references() {
        let no_refs = String::from_utf8(APP_NARINFO.to_vec())
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("References:"))
            .collect::<Vec<_>>()
            .join("\n");
        // Re-terminate (the join drops the trailing newline; the newline guard is tested
        // separately, so keep this a pure missing-References bite).
        let no_refs = format!("{no_refs}\n");
        assert_eq!(
            prove_public(no_refs.as_bytes(), &trusted()),
            Err(PublicProofReject::MissingField("References"))
        );
    }

    #[test]
    fn guard_missing_field_bites_absent_url() {
        // A narinfo with no URL: is structurally invalid (Nix requires it).
        let no_url = String::from_utf8(APP_NARINFO.to_vec())
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("URL:"))
            .collect::<Vec<_>>()
            .join("\n");
        let no_url = format!("{no_url}\n");
        assert_eq!(
            prove_public(no_url.as_bytes(), &trusted()),
            Err(PublicProofReject::MissingField("URL"))
        );
    }

    #[test]
    fn guard_duplicate_field_bites() {
        // Duplicating a signed field is ambiguous; refuse it (unifies first-vs-last).
        let dup = String::from_utf8(APP_NARINFO.to_vec())
            .unwrap()
            .replace("NarSize: 408\n", "NarSize: 408\nNarSize: 999\n");
        assert_eq!(
            prove_public(dup.as_bytes(), &trusted()),
            Err(PublicProofReject::DuplicateField("NarSize"))
        );
    }

    #[test]
    fn guard_missing_final_newline_bites() {
        let mut body = APP_NARINFO.to_vec();
        assert_eq!(body.pop(), Some(b'\n'));
        assert_eq!(
            prove_public(&body, &trusted()),
            Err(PublicProofReject::MissingFinalNewline)
        );
    }

    #[test]
    fn guard_zero_narsize_bites() {
        // A validly-signed narinfo whose NarSize is 0 is structurally refused BEFORE crypto.
        let sk = untrusted_signing_key();
        let store_path = "/nix/store/0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib";
        let nar_hash = "sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb";
        let fp = fingerprint(store_path, nar_hash, 0, "");
        let sig = ed25519_dalek::Signer::sign(&sk, fp.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let narinfo = format!(
            "StorePath: {store_path}\nURL: nar/x.nar\nCompression: none\n\
             FileHash: {nar_hash}\nFileSize: 0\nNarHash: {nar_hash}\n\
             NarSize: 0\nReferences: \nSig: nix-p2p-test-1:{sig_b64}\n"
        );
        assert_eq!(
            prove_public(narinfo.as_bytes(), &trusted()),
            Err(PublicProofReject::ZeroNarSize)
        );
    }

    #[test]
    fn reordered_references_do_not_change_the_fingerprint() {
        // Canonicalisation bite: sorting references means a reordered References field
        // yields the SAME fingerprint. Build a 2-ref fingerprint two ways and compare.
        let sp = "/nix/store/aaaa-x";
        let a = fingerprint(sp, "sha256:zz", 10, "bbbb-b cccc-c");
        let b = fingerprint(sp, "sha256:zz", 10, "cccc-c bbbb-b");
        assert_eq!(
            a, b,
            "reference order must not change the canonical fingerprint"
        );
    }

    #[test]
    fn leading_zero_narsize_canonicalises_to_decimal() {
        // A NarSize of `0408` fingerprints as `408` (decimal of the parsed u64).
        let sp = "/nix/store/aaaa-x";
        assert!(fingerprint(sp, "sha256:zz", 408, "").contains(";408;"));
    }

    #[test]
    fn guard_malformed_narhash_bites() {
        let bad = String::from_utf8(APP_NARINFO.to_vec()).unwrap().replace(
            "NarHash: sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm",
            "NarHash: not-a-sha256",
        );
        assert!(matches!(
            prove_public(bad.as_bytes(), &trusted()),
            Err(PublicProofReject::MalformedNarHash(_))
        ));
    }

    #[test]
    fn guard_malformed_narsize_bites() {
        let bad = String::from_utf8(APP_NARINFO.to_vec())
            .unwrap()
            .replace("NarSize: 408", "NarSize: not-a-number");
        assert!(matches!(
            prove_public(bad.as_bytes(), &trusted()),
            Err(PublicProofReject::MalformedNarSize(_))
        ));
    }

    #[test]
    fn guard_malformed_sig_bites_non_base64() {
        let bad = String::from_utf8(APP_NARINFO.to_vec()).unwrap().replace(
            "Sig: nix-p2p-test-1:Xqf1bjNJ1ReFahm86zY+hv80+7QeJer5V/HjlEAvP39yJEK8w8jHG9WH5lM7mN9WCIbdH/DDx81dmsjVObMqAQ==",
            "Sig: nix-p2p-test-1:@@@not-base64@@@",
        );
        assert!(matches!(
            prove_public(bad.as_bytes(), &trusted()),
            Err(PublicProofReject::MalformedSig(_))
        ));
    }

    #[test]
    fn guard_unsigned_narinfo_is_untrusted_not_appended() {
        let unsigned = String::from_utf8(APP_NARINFO.to_vec())
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("Sig:"))
            .collect::<Vec<_>>()
            .join("\n");
        let unsigned = format!("{unsigned}\n");
        assert!(matches!(
            prove_public(unsigned.as_bytes(), &trusted()),
            Err(PublicProofReject::UntrustedKey(_))
        ));
    }

    // ---- learn: append-once, idempotent, request-correlation (AC#1/#2/#3) --

    fn open_mem(trusted: TrustedNarKeys) -> PublicNarAllowlist {
        PublicNarAllowlist::in_memory(trusted)
    }

    #[test]
    fn learn_appends_once_and_is_idempotent() {
        let list = open_mem(trusted());
        let key = app_nar_hash();
        assert!(!list.contains(&key));

        match list.learn(&app_hash(), APP_NARINFO) {
            LearnOutcome::Appended { nar_size, .. } => assert_eq!(nar_size, 408),
            other => panic!("expected Appended, got {other:?}"),
        }
        assert!(list.contains(&key));
        assert_eq!(list.status().count, 1);
        assert_eq!(list.status().total_nar_size_bytes, 408);

        assert!(matches!(
            list.learn(&app_hash(), APP_NARINFO),
            LearnOutcome::AlreadyPresent { .. }
        ));
        assert_eq!(
            list.status().count,
            1,
            "duplicate must not append a second entry"
        );
    }

    #[test]
    fn learn_rejects_a_mismatched_request_correlation() {
        // THE request-correlation bite: request A (the LIB hash) but the upstream returns a
        // signed narinfo for B (the APP path). The signature is perfectly valid, but the
        // response does not correlate to the requested key, so NOTHING is learned.
        // (Neuter: drop the `verified.store_hash != requested` check and B is appended.)
        let list = open_mem(trusted());
        match list.learn(&lib_hash(), APP_NARINFO) {
            LearnOutcome::RequestMismatch { requested, signed } => {
                assert_eq!(requested, LIB_STORE_HASH);
                assert_eq!(signed, APP_STORE_HASH);
            }
            other => panic!("expected RequestMismatch, got {other:?}"),
        }
        assert_eq!(
            list.status().count,
            0,
            "a mis-correlated response must not learn"
        );
        assert!(!list.contains(&app_nar_hash()));
    }

    #[test]
    fn rejected_narinfo_appends_nothing() {
        let list = open_mem(trusted());
        let unsigned = String::from_utf8(APP_NARINFO.to_vec())
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("Sig:"))
            .collect::<Vec<_>>()
            .join("\n");
        let unsigned = format!("{unsigned}\n");
        assert!(matches!(
            list.learn(&app_hash(), unsigned.as_bytes()),
            LearnOutcome::Rejected(_)
        ));
        assert_eq!(list.status().count, 0);
    }

    #[test]
    fn disabled_allowlist_learns_nothing() {
        let list = PublicNarAllowlist::disabled();
        assert!(matches!(
            list.learn(&app_hash(), APP_NARINFO),
            LearnOutcome::Rejected(PublicProofReject::UntrustedKey(_))
        ));
        assert_eq!(list.status().count, 0);
    }

    // ---- approve: the closed-by-construction publication gate (AC#1) ------

    #[test]
    fn approve_mints_a_claim_only_for_allowlisted_nars() {
        let list = open_mem(trusted());
        let key = app_nar_hash();

        assert_eq!(
            list.approve(&key, None),
            Err(PublicationRejected::NotAllowlisted(key))
        );

        list.learn(&app_hash(), APP_NARINFO);
        let claim = list.approve(&key, Some(408)).expect("allowlisted -> claim");
        assert_eq!(claim.nar_hash(), &key);
        assert_eq!(claim.nar_size(), 408);

        assert!(matches!(
            list.approve(&key, Some(409)),
            Err(PublicationRejected::SizeMismatch { .. })
        ));
    }

    #[test]
    fn an_operator_seeded_local_fixture_cannot_be_published() {
        // A purely-local NAR (never proven public) mints NO claim - the closed-by-construction
        // public door can never announce it. This is also the FORGED-STORE story: the ONLY
        // writer of `entries` is `learn` (signature-verified), and the store seam is SEALED
        // (`pub(crate)`), so external code cannot inject an entry then `approve` a forged claim.
        let list = open_mem(trusted());
        let local_only: NarHashKey = "sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa"
            .parse()
            .unwrap();
        assert!(!list.contains(&local_only));
        assert_eq!(
            list.approve(&local_only, None),
            Err(PublicationRejected::NotAllowlisted(local_only))
        );
    }

    // ---- persistence + crash safety + strict file + MAC (AC#4) ------------

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nixp2p-allowlist-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // Compose a VALID committed line for a record under TEST_MAC_KEY.
    fn mac_line(nar_hash: &str, nar_size: u64) -> String {
        let key: NarHashKey = nar_hash.parse().unwrap();
        let mac = record_mac(&TEST_MAC_KEY, &key, nar_size);
        format!("{nar_hash} {nar_size} {mac}\n")
    }

    fn set_0600(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn survives_restart_via_file_store() {
        let dir = temp_dir("restart");
        let path = dir.join("public-allowlist");

        {
            let list = PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY).unwrap();
            assert!(matches!(
                list.learn(&app_hash(), APP_NARINFO),
                LearnOutcome::Appended { .. }
            ));
            assert!(matches!(
                list.learn(&lib_hash(), LIB_NARINFO),
                LearnOutcome::Appended { .. }
            ));
        }
        let reopened = PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY).unwrap();
        assert_eq!(reopened.status().count, 2);
        assert!(reopened.contains(&app_nar_hash()));
        assert!(matches!(
            reopened.learn(&app_hash(), APP_NARINFO),
            LearnOutcome::AlreadyPresent { .. }
        ));
        assert_eq!(reopened.status().count, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_flipped_mac_covered_char_is_rejected_on_load() {
        // THE flipped-char bite (AC#4 integrity). Write one VALID committed record, then flip
        // a single nixbase32 char of its NarHash IN PLACE (the record still parses). Its MAC
        // no longer verifies, so load fails LOUD - the never-learned NAR is NOT eligible.
        // (Neuter: drop the MAC check in `parse_committed` and the flipped NAR loads.)
        let dir = temp_dir("flip");
        let path = dir.join("public-allowlist");
        let good = mac_line(APP_NAR_HASH, 408);
        let flipped = good.replacen(
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm",
            "sha256:1pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm",
            1,
        );
        assert_ne!(good, flipped, "the flip must actually change the line");
        std::fs::write(&path, &flipped).unwrap();
        set_0600(&path);
        let err = PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY);
        assert!(
            err.is_err(),
            "a flipped MAC-covered char must be rejected on load"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_line_from_another_nodes_key_is_rejected_on_load() {
        // A line MAC'd under a DIFFERENT node's key (injected / copied from elsewhere) fails
        // load: the MAC recomputed under THIS node's key does not match.
        let dir = temp_dir("foreign");
        let path = dir.join("public-allowlist");
        let foreign_key = [0x99u8; 32];
        let key: NarHashKey = APP_NAR_HASH.parse().unwrap();
        let foreign_mac = record_mac(&foreign_key, &key, 408);
        std::fs::write(&path, format!("{APP_NAR_HASH} 408 {foreign_mac}\n")).unwrap();
        set_0600(&path);
        assert!(
            PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY).is_err(),
            "a line written under another node's MAC key must be refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_replayed_valid_line_dedups_and_fabricates_no_new_eligibility() {
        // MAC probe - REPLAY (fix cycle #2). Duplicating a VALID committed line is NOT a
        // fabrication vector: a valid line for NAR X can only exist if X was already learned
        // (the MAC key is a per-node secret), so replaying it re-adds X (already eligible) and
        // nothing else. It therefore loads CLEANLY (identical bytes carry an identical, valid MAC)
        // and dedups to ONE entry - it can never make a NEVER-LEARNED NAR eligible.
        // HONEST: an exact replay does NOT fail loud (it is cryptographically indistinguishable
        // from a legitimately re-written identical record); the invariant it cannot break is the
        // one that matters - eligibility for un-learned content.
        let dir = temp_dir("replay");
        let path = dir.join("public-allowlist");
        let good = mac_line(APP_NAR_HASH, 408);
        std::fs::write(&path, format!("{good}{good}")).unwrap(); // the SAME valid line, twice
        set_0600(&path);
        let list = PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY)
            .expect("a replayed valid line is cryptographically valid and loads");
        assert_eq!(
            list.status().count,
            1,
            "a replayed line dedups to one entry"
        );
        assert!(list.contains(&app_nar_hash()));
        // The replay fabricated NO new eligibility: the lib NAR (never learned) stays out.
        let lib_nar: NarHashKey = "sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb"
            .parse()
            .unwrap();
        assert!(
            !list.contains(&lib_nar),
            "replay must not fabricate eligibility"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_positionally_swapped_record_is_rejected_on_load() {
        // MAC probe - SWAP (positions). Exchanging the NarHash and NarSize columns yields
        // `<NarSize> <NarHash> <mac>`; the first column no longer parses as a canonical NarHash,
        // so load fails LOUD before the MAC is even consulted (the fields are strictly typed).
        let dir = temp_dir("swap-pos");
        let path = dir.join("public-allowlist");
        let key: NarHashKey = APP_NAR_HASH.parse().unwrap();
        let mac = record_mac(&TEST_MAC_KEY, &key, 408);
        std::fs::write(&path, format!("408 {APP_NAR_HASH} {mac}\n")).unwrap();
        set_0600(&path);
        assert!(
            PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY).is_err(),
            "a record with NarHash/NarSize columns swapped must be refused on load"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_mac_reused_under_a_different_size_is_rejected_on_load() {
        // MAC probe - the SWAP concern's essence: the MAC must bind BOTH fields jointly, so a
        // valid MAC computed over (NarHash, 408) cannot be pasted onto a line that CLAIMS a
        // different NarSize. Here the columns still parse (a real NarHash, a real u64), so this
        // bites the MAC binding specifically (not the type parser): the recomputed MAC over
        // (NarHash, 409) differs from the stored MAC over (NarHash, 408) -> load fails LOUD.
        let dir = temp_dir("swap-size");
        let path = dir.join("public-allowlist");
        let key: NarHashKey = APP_NAR_HASH.parse().unwrap();
        let mac_for_408 = record_mac(&TEST_MAC_KEY, &key, 408);
        std::fs::write(&path, format!("{APP_NAR_HASH} 409 {mac_for_408}\n")).unwrap();
        set_0600(&path);
        assert!(
            PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY).is_err(),
            "a MAC bound to NarSize 408 must not validate a line claiming NarSize 409"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_narinfo_missing_url_does_not_learn() {
        // Correlation/structural probe: a signed narinfo with no `URL:` is structurally invalid
        // (Nix requires it), so `learn` refuses it and appends NOTHING - the correlation/append
        // path never admits a NAR from a malformed response.
        let list = open_mem(trusted());
        let no_url = String::from_utf8(APP_NARINFO.to_vec())
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("URL:"))
            .collect::<Vec<_>>()
            .join("\n");
        let no_url = format!("{no_url}\n");
        assert!(matches!(
            list.learn(&app_hash(), no_url.as_bytes()),
            LearnOutcome::Rejected(PublicProofReject::MissingField("URL"))
        ));
        assert_eq!(list.status().count, 0);
    }

    #[test]
    fn torn_final_append_is_truncated_and_next_append_is_clean() {
        // One committed record + a torn tail (a partial line, no trailing newline). A NEW
        // append must TRUNCATE the torn tail (not concatenate onto it), so the file ends with
        // two clean committed records and both verify.
        let dir = temp_dir("torn");
        let path = dir.join("public-allowlist");
        let mut content = mac_line(APP_NAR_HASH, 408);
        content.push_str("sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bcz"); // torn
        std::fs::write(&path, &content).unwrap();
        set_0600(&path);

        // Load drops the torn tail: only the committed record is eligible.
        let list = PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY).unwrap();
        assert_eq!(list.status().count, 1);
        assert!(list.contains(&app_nar_hash()));

        // A fresh append truncates the torn tail first, then writes a clean record.
        assert!(matches!(
            list.learn(&lib_hash(), LIB_NARINFO),
            LearnOutcome::Appended { .. }
        ));
        // Reopen: exactly the two committed records, no corruption from the old torn tail.
        let reopened = PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY).unwrap();
        assert_eq!(reopened.status().count, 2);
        assert!(reopened.contains(&app_nar_hash()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_committed_record_fails_loud() {
        let dir = temp_dir("corrupt");
        let path = dir.join("public-allowlist");
        // A fully-terminated line whose size does not parse: real corruption, fail LOUD.
        std::fs::write(&path, format!("{APP_NAR_HASH} not-a-size deadbeef\n")).unwrap();
        set_0600(&path);
        assert!(PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn group_or_other_accessible_file_is_refused() {
        let dir = temp_dir("mode");
        let path = dir.join("public-allowlist");
        std::fs::write(&path, "").unwrap();
        set_0600(&path);
        // 0644: group/other-READABLE. The NarHash inventory must be 0600.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY).is_err(),
            "a group/other-readable allowlist must be refused (0600 only)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlinked_file_is_refused() {
        use std::os::unix::fs::symlink;
        let dir = temp_dir("symlink");
        let real = dir.join("real");
        std::fs::write(&real, mac_line(APP_NAR_HASH, 408)).unwrap();
        set_0600(&real);
        let link = dir.join("public-allowlist");
        symlink(&real, &link).unwrap();
        // O_NOFOLLOW refuses to open a symlink in the file's place.
        assert!(PublicNarAllowlist::open_file(trusted(), &link, TEST_MAC_KEY).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_contains_no_store_path() {
        // AC#5: the on-disk form is NarHash + NarSize + MAC only, never a StorePath.
        let dir = temp_dir("nostore");
        let path = dir.join("public-allowlist");
        let list = PublicNarAllowlist::open_file(trusted(), &path, TEST_MAC_KEY).unwrap();
        list.learn(&app_hash(), APP_NARINFO);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains("/nix/store"),
            "the allowlist file must not contain any StorePath: {on_disk:?}"
        );
        assert!(on_disk.contains(&format!("{APP_NAR_HASH} 408 ")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_different_mac_key_derives_from_a_different_seed() {
        // Domain separation: two seeds yield different MAC keys, so a file from node A cannot
        // be trusted by node B (covered behaviourally by the foreign-key test above).
        let a = derive_allowlist_mac_key(&[1u8; 32]);
        let b = derive_allowlist_mac_key(&[2u8; 32]);
        assert_ne!(a, b);
    }
}
