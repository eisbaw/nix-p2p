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
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::claim::NarHashKey;

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
/// the `(NarHash, NarSize)` that the trusted signature COVERED. Nothing else is
/// carried - no `StorePath`, no references - because nothing else is appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPublicNar {
    /// The signed `NarHash`, parsed to the strict wire key (`sha256:<52 nix-base32>`).
    pub nar_hash: NarHashKey,
    /// The signed `NarSize` - the UNCOMPRESSED NAR length (never a compressed FileSize).
    pub nar_size: u64,
}

/// Why a narinfo did NOT prove a NAR public. EACH variant is a distinct fail-closed
/// guard (AC#3): a mutation that neuters the check producing it lets a crafted narinfo
/// append when it must not, so a negative test asserting the variant BITES that mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicProofReject {
    /// A field required to build the signed fingerprint was absent (malformed metadata).
    MissingField(&'static str),
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

/// The FIRST value of `key:` in the narinfo (values are single-line). Signed fields
/// occur once; taking the first is deterministic for a well-formed cache narinfo.
fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(key).map(str::trim))
}

/// Rebuild the exact string Nix signs: `1;<StorePath>;<NarHash>;<NarSize>;<refs>`,
/// where `refs` are the `References` basenames re-prefixed with the store directory
/// (derived from the `StorePath`'s own parent, so a non-`/nix/store` store is handled)
/// and joined by `,`. Getting the reference prefixing wrong yields a fingerprint that
/// verifies NOWHERE, so the positive control (a real fixture signature) is what proves
/// this correct. Mirrors `scripts/fixturelib.py::fingerprint`.
fn fingerprint(store_path: &str, nar_hash: &str, nar_size: &str, references: &str) -> String {
    // The store directory is the StorePath's parent (e.g. `/nix/store`).
    let store_dir = store_path
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .unwrap_or("");
    let refs = references
        .split_whitespace()
        .filter(|r| !r.is_empty())
        .map(|r| format!("{store_dir}/{r}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("1;{store_path};{nar_hash};{nar_size};{refs}")
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

    // The four signed fingerprint fields. `References:` may be EMPTY (a leaf path), so
    // only its PRESENCE is required - an absent line is malformed metadata.
    let store_path =
        field(text, "StorePath:").ok_or(PublicProofReject::MissingField("StorePath"))?;
    if store_path.is_empty() {
        return Err(PublicProofReject::MissingField("StorePath"));
    }
    let nar_hash_str = field(text, "NarHash:").ok_or(PublicProofReject::MissingField("NarHash"))?;
    let nar_size_str = field(text, "NarSize:").ok_or(PublicProofReject::MissingField("NarSize"))?;
    let references = text
        .lines()
        .find_map(|line| line.strip_prefix("References:"))
        .ok_or(PublicProofReject::MissingField("References"))?
        .trim();

    // Parse the canonical identity we will record. A NarHash that is not
    // `sha256:<52 nix-base32>` is refused (hash guard); a non-`u64` NarSize is refused
    // (size guard). These are the EXACT strings the fingerprint uses, so the recorded
    // identity is precisely what the signature bound.
    let nar_hash: NarHashKey = nar_hash_str
        .parse()
        .map_err(|_| PublicProofReject::MalformedNarHash(nar_hash_str.to_string()))?;
    let nar_size: u64 = nar_size_str
        .parse()
        .map_err(|_| PublicProofReject::MalformedNarSize(nar_size_str.to_string()))?;

    let fp = fingerprint(store_path, nar_hash_str, nar_size_str, references);

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
            return Ok(VerifiedPublicNar { nar_hash, nar_size });
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

/// Persists the append-only allowlist so it survives a restart. The SOURCE OF TRUTH
/// is the sequence of `(NarHash, NarSize)` records ever verified public; a duplicate
/// is never appended (the in-memory set dedups before the store is touched). A SEAM so
/// a test can persist to a temp file or use an in-memory store.
pub trait AllowlistStore: Send + Sync {
    /// Load every COMMITTED record (empty if the file does not exist yet). A record
    /// that was fully written (terminated) but does not parse is CORRUPTION and fails
    /// LOUD; a torn FINAL record (no terminator) is dropped (see [`FileAllowlistStore`]).
    fn load(&self) -> Result<Vec<(NarHashKey, u64)>, AllowlistPersistError>;

    /// Durably APPEND one record. Crash-safe: a torn append loses at most this record
    /// and never creates eligibility (an unterminated tail is dropped on load).
    fn append(&self, nar_hash: &NarHashKey, nar_size: u64) -> Result<(), AllowlistPersistError>;
}

/// An in-memory store: the allowlist does not survive a restart. Used by the DISABLED
/// allowlist (an empty-trusted-keys no-op) and by tests that do not exercise persistence.
#[derive(Debug, Default)]
pub struct NullAllowlistStore;

impl AllowlistStore for NullAllowlistStore {
    fn load(&self) -> Result<Vec<(NarHashKey, u64)>, AllowlistPersistError> {
        Ok(Vec::new())
    }
    fn append(&self, _nar_hash: &NarHashKey, _nar_size: u64) -> Result<(), AllowlistPersistError> {
        Ok(())
    }
}

/// The real store: a single APPEND-ONLY text file, one record per line:
/// `sha256:<52 nix-base32> <nar_size>\n`. No `StorePath`, so the file cannot be an
/// inventory of what the node BUILT - only which public NARs it may announce (AC#5).
///
/// CRASH SAFETY (AC#4). Each record is one small `O_APPEND` write followed by
/// `sync_all` (fdatasync of the file). A crash mid-append can leave a TORN final line
/// (no trailing `\n`); [`Self::load`] drops any unterminated tail, so a torn append
/// loses at most that one uncommitted record and NEVER admits a partial/garbage entry
/// as eligible. A COMMITTED line (ends in `\n`) that fails to parse is real corruption
/// and fails LOUD rather than being skipped. The file's directory entry is fsynced when
/// the file is first created, so the file itself survives a crash.
///
/// STRICT FILE CHECKS (AC#4). The file is opened `O_NOFOLLOW` (a symlink in its place
/// is refused - the "link" check) and `fstat`ed on every open: it must be a REGULAR
/// file, OWNED by this process's euid, and NOT writable by group or other. A file that
/// fails any check is refused (fail-closed) rather than trusted.
pub struct FileAllowlistStore {
    path: PathBuf,
}

impl FileAllowlistStore {
    /// Persist to `path` (its parent directory is created on first append if absent).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileAllowlistStore { path: path.into() }
    }

    /// Open the file with the strict owner/mode/type/link checks. `create` opens
    /// `O_APPEND|O_CREAT` for writing; otherwise read-only. Returns `Ok(None)` only for
    /// a non-existent file when NOT creating (a first-boot empty allowlist).
    fn open_strict(&self, create: bool) -> Result<Option<std::fs::File>, AllowlistPersistError> {
        use rustix::fs::{FileType, Mode, OFlags};

        let mut flags = OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if create {
            flags |= OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE;
        } else {
            flags |= OFlags::RDONLY;
        }
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
        let euid = rustix::process::geteuid().as_raw();
        if stat.st_uid != euid {
            return Err(AllowlistPersistError(format!(
                "{} is owned by uid {}, not this process ({euid}); refusing to trust it",
                self.path.display(),
                stat.st_uid
            )));
        }
        if stat.st_mode & 0o022 != 0 {
            return Err(AllowlistPersistError(format!(
                "{} is group/other-writable (mode {:o}); refusing to trust it",
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
}

impl AllowlistStore for FileAllowlistStore {
    fn load(&self) -> Result<Vec<(NarHashKey, u64)>, AllowlistPersistError> {
        let Some(mut file) = self.open_strict(false)? else {
            return Ok(Vec::new());
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| AllowlistPersistError(format!("reading {}: {e}", self.path.display())))?;
        let text = std::str::from_utf8(&bytes).map_err(|e| {
            AllowlistPersistError(format!("{} is not valid UTF-8: {e}", self.path.display()))
        })?;

        let mut out = Vec::new();
        // `split_inclusive` keeps each line's `\n`. A final segment WITHOUT a trailing
        // `\n` is a TORN append (crash between write and the newline never happens, but
        // a crash mid-write does) - drop it. Every COMMITTED line must parse strictly.
        for segment in text.split_inclusive('\n') {
            let Some(line) = segment.strip_suffix('\n') else {
                // Unterminated tail: torn/uncommitted. Drop it (never eligibility).
                break;
            };
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            let (hash_str, size_str) = line.split_once(' ').ok_or_else(|| {
                AllowlistPersistError(format!(
                    "{} has a committed line with no ' ' separator: {line:?}",
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
            out.push((nar_hash, nar_size));
        }
        Ok(out)
    }

    fn append(&self, nar_hash: &NarHashKey, nar_size: u64) -> Result<(), AllowlistPersistError> {
        let parent = self.parent();
        let existed = self.path.exists();
        if !existed {
            std::fs::create_dir_all(&parent).map_err(|e| {
                AllowlistPersistError(format!("creating {}: {e}", parent.display()))
            })?;
        }
        let mut file = self
            .open_strict(true)?
            .expect("open_strict(create=true) never returns None");
        // One atomic-ish append. The line is small; `O_APPEND` makes the write land at
        // the current end even under concurrent appenders. `sync_all` flushes it before
        // we report success, so a reported append is durable.
        let line = format!("{nar_hash} {nar_size}\n");
        file.write_all(line.as_bytes()).map_err(|e| {
            AllowlistPersistError(format!("appending to {}: {e}", self.path.display()))
        })?;
        file.sync_all()
            .map_err(|e| AllowlistPersistError(format!("fsyncing {}: {e}", self.path.display())))?;
        // On first creation, fsync the parent directory so the new file's name->inode
        // link is itself durable (the same discipline the availability index uses).
        if !existed
            && let Ok(dir) = std::fs::File::open(&parent)
        {
            let _ = dir.sync_all();
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
    /// Build an allowlist over `trusted` and `store`, loading any persisted records so
    /// it survives a restart. A corrupt persisted file fails LOUD here (never a silent
    /// empty allowlist).
    pub fn open(
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

    /// LEARN from a narinfo the daemon is serving: if it PROVES a NAR public, append its
    /// `(NarHash, NarSize)` ONCE. Idempotent - a duplicate is [`LearnOutcome::AlreadyPresent`]
    /// with no append and no second network request. This is the ONLY path that writes
    /// the allowlist (AC#1/#2). Fail-closed on every rejection (AC#3).
    pub fn learn(&self, narinfo: &[u8]) -> LearnOutcome {
        let verified = match prove_public(narinfo, &self.trusted) {
            Ok(v) => v,
            Err(reject) => return LearnOutcome::Rejected(reject),
        };
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

    fn trusted() -> TrustedNarKeys {
        TrustedNarKeys::from_lines([FIXTURE_PUBKEY]).expect("fixture pubkey parses")
    }

    // A second, DIFFERENT valid keypair used as an UNTRUSTED signer. Deterministic seed.
    fn untrusted_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    // ---- prove_public: positive controls (real fixture signatures) --------

    #[test]
    fn real_fixture_narinfo_with_references_proves_public() {
        // POSITIVE CONTROL: a real cache-shaped narinfo, its real trusted signature,
        // verifies over the reconstructed fingerprint. This proves the reference
        // re-prefixing in `fingerprint` is correct (the app path has a reference).
        let v = prove_public(APP_NARINFO, &trusted()).expect("app narinfo proves public");
        assert_eq!(
            v.nar_hash.to_string(),
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm"
        );
        assert_eq!(v.nar_size, 408);
    }

    #[test]
    fn real_fixture_narinfo_with_empty_references_proves_public() {
        let v = prove_public(LIB_NARINFO, &trusted()).expect("lib narinfo proves public");
        assert_eq!(v.nar_size, 66048);
    }

    // ---- prove_public: each fail-closed guard BITES (AC#3) ----------------
    // Each negative differs from the positive control in EXACTLY ONE dimension, and the
    // guard producing its reject is the ONLY thing standing between it and an append.
    // Neutering that guard (accept the malformed field / skip the trust or verify step)
    // flips the outcome to Ok -> the matching assert below fails. That is the bite.

    #[test]
    fn guard_untrusted_key_bites_wrong_authority() {
        // Same narinfo, but NO trusted key configured for its signer -> wrong authority.
        // (Neuter: if `learn`/`prove_public` accepted an unknown key name, this appends.)
        let empty = TrustedNarKeys::empty();
        assert!(matches!(
            prove_public(APP_NARINFO, &empty),
            Err(PublicProofReject::UntrustedKey(_))
        ));
    }

    #[test]
    fn guard_untrusted_key_bites_a_valid_but_untrusted_signer() {
        // A narinfo VALIDLY signed by a real second keypair that is NOT trusted. The
        // signature is cryptographically fine; the AUTHORITY is wrong. This is the
        // strongest wrong-authority bite: only the trust-membership check refuses it.
        let sk = untrusted_signing_key();
        let store_path = "/nix/store/0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib";
        let nar_hash = "sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb";
        let nar_size = "66048";
        let fp = fingerprint(store_path, nar_hash, nar_size, "");
        let sig = ed25519_dalek::Signer::sign(&sk, fp.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let narinfo = format!(
            "StorePath: {store_path}\nURL: nar/x.nar\nCompression: none\n\
             FileHash: {nar_hash}\nFileSize: {nar_size}\nNarHash: {nar_hash}\n\
             NarSize: {nar_size}\nReferences: \nSig: evil-key-1:{sig_b64}\n"
        );
        // Trust only the fixture key, NOT evil-key-1.
        let out = prove_public(narinfo.as_bytes(), &trusted());
        assert_eq!(
            out,
            Err(PublicProofReject::UntrustedKey("evil-key-1".into()))
        );
    }

    #[test]
    fn guard_bad_signature_bites_a_tampered_narhash() {
        // Flip one base32 char of the NarHash. It still parses (canonical base32) and is
        // still signed by the TRUSTED key name, but the fingerprint no longer matches the
        // signature -> BadSignature. (Neuter: skip verify_strict and this appends a NAR
        // whose signature does not cover its recorded hash.)
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
        // Change the signed NarSize; the signature no longer covers it -> BadSignature.
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
        // Drop the reference. The fingerprint's refs segment changes -> BadSignature.
        // This is the bite that proves references are actually IN the fingerprint.
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
        // Replace the signature bytes with a valid-length but wrong 64-byte blob.
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
        assert_eq!(
            prove_public(no_refs.as_bytes(), &trusted()),
            Err(PublicProofReject::MissingField("References"))
        );
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
        // A LOCAL build / private path: no Sig line at all -> UntrustedKey (nothing to
        // trust). Proves local/unsigned content NEVER enters the list.
        let unsigned = String::from_utf8(APP_NARINFO.to_vec())
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("Sig:"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(matches!(
            prove_public(unsigned.as_bytes(), &trusted()),
            Err(PublicProofReject::UntrustedKey(_))
        ));
    }

    // ---- learn: append-once, idempotent, status (AC#1/#2/#5) --------------

    fn open_mem(trusted: TrustedNarKeys) -> PublicNarAllowlist {
        PublicNarAllowlist::open(trusted, Box::new(NullAllowlistStore)).unwrap()
    }

    #[test]
    fn learn_appends_once_and_is_idempotent() {
        let list = open_mem(trusted());
        let key: NarHashKey = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm"
            .parse()
            .unwrap();
        assert!(!list.contains(&key));

        match list.learn(APP_NARINFO) {
            LearnOutcome::Appended { nar_size, .. } => assert_eq!(nar_size, 408),
            other => panic!("expected Appended, got {other:?}"),
        }
        assert!(list.contains(&key));
        assert_eq!(list.status().count, 1);
        assert_eq!(list.status().total_nar_size_bytes, 408);

        // A duplicate request: idempotent, no second append.
        assert!(matches!(
            list.learn(APP_NARINFO),
            LearnOutcome::AlreadyPresent { .. }
        ));
        assert_eq!(
            list.status().count,
            1,
            "duplicate must not append a second entry"
        );
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
        assert!(matches!(
            list.learn(unsigned.as_bytes()),
            LearnOutcome::Rejected(_)
        ));
        assert_eq!(list.status().count, 0);
    }

    #[test]
    fn disabled_allowlist_learns_nothing() {
        let list = PublicNarAllowlist::disabled();
        assert!(matches!(
            list.learn(APP_NARINFO),
            LearnOutcome::Rejected(PublicProofReject::UntrustedKey(_))
        ));
        assert_eq!(list.status().count, 0);
    }

    // ---- approve: the closed-by-construction publication gate (AC#1) ------

    #[test]
    fn approve_mints_a_claim_only_for_allowlisted_nars() {
        let list = open_mem(trusted());
        let key: NarHashKey = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm"
            .parse()
            .unwrap();

        // BEFORE learning: fail-closed, NO claim minted (the bite for the publish gate).
        assert_eq!(
            list.approve(&key, None),
            Err(PublicationRejected::NotAllowlisted(key))
        );

        list.learn(APP_NARINFO);
        // AFTER learning: a claim is minted, carrying the approved size.
        let claim = list.approve(&key, Some(408)).expect("allowlisted -> claim");
        assert_eq!(claim.nar_hash(), &key);
        assert_eq!(claim.nar_size(), 408);

        // A wrong intended size is refused (defensive size guard).
        assert!(matches!(
            list.approve(&key, Some(409)),
            Err(PublicationRejected::SizeMismatch { .. })
        ));
    }

    #[test]
    fn an_operator_seeded_local_fixture_cannot_be_published() {
        // The seam story (mped-architect must-have #2): a purely-local NAR the operator
        // named for a provider mode is NOT on the (empty) allowlist, so `approve` refuses
        // it and mints NO claim - the closed-by-construction public door can never
        // announce it. Neuter the `contains`/`approved_size` check and this goes green
        // (a claim is minted) -> the guard bites.
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

    // ---- persistence + crash safety + strict file checks (AC#4) -----------

    #[test]
    fn survives_restart_via_file_store() {
        let dir = std::env::temp_dir().join(format!("nixp2p-allowlist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("public-allowlist");

        {
            let list =
                PublicNarAllowlist::open(trusted(), Box::new(FileAllowlistStore::new(&path)))
                    .unwrap();
            assert!(matches!(
                list.learn(APP_NARINFO),
                LearnOutcome::Appended { .. }
            ));
            assert!(matches!(
                list.learn(LIB_NARINFO),
                LearnOutcome::Appended { .. }
            ));
        }
        // Reopen: the two records reload.
        let reopened =
            PublicNarAllowlist::open(trusted(), Box::new(FileAllowlistStore::new(&path))).unwrap();
        assert_eq!(reopened.status().count, 2);
        let app: NarHashKey = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm"
            .parse()
            .unwrap();
        assert!(reopened.contains(&app));
        // A duplicate learn after restart does NOT re-append.
        assert!(matches!(
            reopened.learn(APP_NARINFO),
            LearnOutcome::AlreadyPresent { .. }
        ));
        assert_eq!(reopened.status().count, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_final_append_loses_only_that_record_and_never_creates_eligibility() {
        let dir =
            std::env::temp_dir().join(format!("nixp2p-allowlist-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("public-allowlist");

        // One committed record + a torn tail (a partial line with NO trailing newline).
        std::fs::write(
            &path,
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm 408\n\
             sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bcz",
        )
        .unwrap();

        let list =
            PublicNarAllowlist::open(trusted(), Box::new(FileAllowlistStore::new(&path))).unwrap();
        // Only the COMMITTED record loads; the torn tail is dropped, so it never becomes
        // eligible (a partial NarHash cannot even parse to a key).
        assert_eq!(list.status().count, 1);
        let committed: NarHashKey = "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm"
            .parse()
            .unwrap();
        assert!(list.contains(&committed));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_committed_record_fails_loud() {
        let dir =
            std::env::temp_dir().join(format!("nixp2p-allowlist-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("public-allowlist");
        // A fully-terminated line that does not parse: real corruption, must fail LOUD.
        std::fs::write(
            &path,
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm not-a-size\n",
        )
        .unwrap();
        assert!(
            PublicNarAllowlist::open(trusted(), Box::new(FileAllowlistStore::new(&path))).is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn group_or_other_writable_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("nixp2p-allowlist-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("public-allowlist");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        // A world-writable allowlist is untrusted -> load fails closed.
        assert!(FileAllowlistStore::new(&path).load().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_contains_no_store_path() {
        // AC#5: the on-disk form is NarHash + NarSize only, never a StorePath.
        let dir =
            std::env::temp_dir().join(format!("nixp2p-allowlist-nostore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("public-allowlist");
        let list =
            PublicNarAllowlist::open(trusted(), Box::new(FileAllowlistStore::new(&path))).unwrap();
        list.learn(APP_NARINFO);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains("/nix/store"),
            "the allowlist file must not contain any StorePath: {on_disk:?}"
        );
        assert!(
            on_disk.contains("sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm 408")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
