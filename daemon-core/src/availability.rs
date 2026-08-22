//! The local AVAILABILITY INDEX and the claim PRODUCER (task-50).
//!
//! Every module before this one CONSUMES claims (the wire format in
//! [`crate::claim`], the transports in [`crate::transport_fetch`] /
//! [`crate::transport_iroh`], discovery in task-40). This module is where a claim
//! is BORN: it is how a node KNOWS which NarHashes it holds and can hand a peer a
//! COMPLETE offer to fetch one from its real `/nix/store`.
//!
//! ## What it maps, and what is derived (data design first)
//!
//! The durable state is a REGISTRATION plus, once verified, its derived binding:
//!
//! ```text
//!   NarHashKey  ->  (StorePath, Blake3Digest, NarSize)   (persisted; task-82)
//! ```
//!
//! The `StorePath` is the SOURCE OF TRUTH ("I hold this NAR, here"). The
//! `Blake3Digest` + `NarSize` are DERIVED from it (`nix-store --dump` +
//! [`Blake3Digest::from_raw_nar`]), and the general rule of this module is that
//! derived state is NOT stored (single source of truth, no duplicated derived
//! state). Task-82 makes ONE earned exception, spelled out where it is taken (see
//! [`DerivedNar`] and [`AvailabilityIndex::open`]): persisting the digest+size is
//! safe here ONLY because a `/nix/store` path's content is IMMUTABLE, so
//! `BLAKE3(dump(path))` is time-invariant and cannot go stale for that path -
//! the exception the "caching invites staleness" rule is deliberately violated
//! under. Everything else stays derived-on-demand:
//!
//!   * the addressed unit `BLAKE3(RawNarV1)` is `nix-store --dump <path>` piped
//!     through the frozen [`Blake3Digest::from_raw_nar`] recipe. It is a PURE
//!     function of the NAR bytes, computed ON DEMAND under a single-flight lock.
//!     Once a probe has VERIFIED it (task-56: `sha256(dump) == key`), that verified
//!     digest+size is also written to disk (task-82) so a restarted node can serve
//!     a previously-announced digest with NO re-dump and NO hold-query first
//!     (closing the task-61 "seeding gap"). A pre-task-82 snapshot that lacks the
//!     derived fields still loads and simply re-derives - the persisted binding is
//!     an optimisation of WHEN the digest is available, never a second source of
//!     truth: the serve path re-dumps and re-checks `BLAKE3 == announced` before
//!     handing over bytes, so a persisted digest can only ever cost a wrong CLAIM
//!     (a wasted dial), never a wrong BYTE. For an immutable `/nix/store` path even
//!     the claim cannot go stale; the one case where a persisted claim CAN be wrong
//!     (and durably so) is a rewritten raw-file-backed path, spelled out in honest
//!     limit (b).
//!   * AVAILABILITY (does the store path still exist?) is read from the filesystem
//!     at query time. A GC'd path therefore DROPS from availability with no active
//!     bookkeeping - the filesystem is the source of truth for existence, and a
//!     stale registration is pruned lazily when a query observes the gap.
//!
//! ## The two query shapes (yes/no ONLY - never enumeration)
//!
//!   * [`AvailabilityIndex::hold`] answers "do I hold this ONE NarHash?" -> a
//!     [`HoldAnswer`] (`Have{blake3, offers}` or `Absent`). [`AvailabilityIndex::answer_for_peer`]
//!     wraps it in the versioned [`HoldResponse`] envelope for the wire.
//!     [`AvailabilityIndex::answer_batch_for_peer`] (task-91) answers the same question
//!     about MANY caller-named keys in one call - a positional yes/no vector, not
//!     a listing: every element is about a key the caller supplied.
//!   * [`AvailabilityIndex::claim`] / [`AvailabilityIndex::publish`] produce the
//!     COMPLETE [`Claim`] a peer needs to FETCH: the BLAKE3 to address the blob
//!     (`payload = WholeNar`) AND the holder [`NodeId`] to dial (`holders` +
//!     an `Iroh` transport offer). This is precisely what task-40 discovery serves
//!     and what task-39's provider seeds from.
//!
//! There is, by construction, NO method that lists a node's holdings. Enumeration
//! would leak the secret store-path names a node holds (the PRD privacy invariant,
//! the wave-1 AC#5 spirit): the API can only be probed with a concrete NarHash it
//! either has or lacks.
//!
//! ## Single-flight hashing (the real correctness point)
//!
//! Re-hashing a 100 MiB NAR N times because N peers probed the same uncomputed key
//! at once is a genuine resource bug. The digest lives behind a per-entry
//! `Mutex<Option<Blake3Digest>>` that is computed UNDER THE LOCK: the first caller
//! runs `nix-store --dump` + BLAKE3 exactly once while the others block on the same
//! lock and then observe the cached `Some`. Distinct keys hold distinct locks, so
//! they still hash in parallel. A failed dump leaves the slot `None`, so the next
//! caller retries rather than caching an error. The [`NarDumper`] seam lets a test
//! count invocations and prove the "exactly once under N callers" bite.
//!
//! ## Supply (task-72): the index is also what a peer is SERVED from
//!
//! Answering "yes" used to be free of any obligation - the provider could only
//! serve blobs that had been eagerly seeded into it, so a positive answer for one
//! of 108k registered paths meant dial-then-fail. The inert [`SupplyCatalogHandle`]
//! closes that: a yes publishes a regenerable provider record before it returns.
//! [`AvailabilityIndex::supply_size_cancellable`] and
//! [`AvailabilityIndex::supply_raw_nar_cancellable`] expose the same mapping to
//! synchronous availability consumers.
//!
//! ## Honest limits (forward-carried)
//!
//!   * [`CommandNarDumper`] BUFFERS the whole `nix-store --dump` stream to apply the
//!     frozen one-shot recipe as the single source of truth. For the wave-2 whole
//!     `/nix/store` a streaming `blake3::Hasher` over the child's stdout would bound
//!     memory; deferred as hardening (the recipe stays identical either way).
//!   * [`JsonFileStore`] rewrites the WHOLE snapshot (serialise -> write+fsync a temp
//!     file -> atomic rename -> fsync the parent dir - the durable-write recipe, so a
//!     crash never publishes a torn/zero-length index) under the global map lock on
//!     every mutation, and task-82 adds the FIRST SERVE
//!     of each key as one more mutation trigger (it persists the newly verified
//!     derived binding once per key). Be honest about the magnitude: each write is
//!     O(N_total entries), so warming a cold/legacy snapshot by serving a K-path
//!     closure is K full rewrites of an N-entry file, serialised under the lock,
//!     before the store stabilises (e.g. a 200-path closure over an 89k-entry index
//!     = 200 rewrites of the whole file). It is bounded and ONCE-ever - a subsequent
//!     boot warms every entry from disk, so `freshly_derived` is false and nothing
//!     re-persists - but the constant is not free. This is the SAME scale limit the
//!     whole-snapshot design already carries; an append-log / sqlite is the answer
//!     for both. On-disk BYTE cost of the added derived fields is measured in
//!     `tests/availability_persisted_digest.rs` (AC#3).
//!   * The verified derived value is deliberately DUPLICATED in three places - the
//!     `DeriveOutcome::Verified` digest slot, the `persisted_derived` leaf mirror,
//!     and the disk snapshot. This is not free (it is derived state held thrice, the
//!     smell this module usually avoids); it is the accepted price of NOT taking a
//!     `digest` lock (which can be held across a dump) under the map lock during a
//!     snapshot. The disk copy is the durable one; the two in-memory copies are
//!     single-flight/serialisation caches of it and cannot outlive the process.
//!   * The index is synchronous and holds the entry lock across the (blocking) dump.
//!     A caller on an async runtime should drive it via `spawn_blocking`. Making the
//!     dump itself async is deferred with the streaming change.
//!   * The `key -> store_path` binding IS now verified at the source (task-56,
//!     CLOSED). `derive` re-derives `sha256(--dump)` from the SAME buffer it
//!     BLAKE3s and asserts it equals `key`; a mismatch QUARANTINES the entry (a
//!     typed [`NarHashMismatch`], never a false `Have`). Nix's gate 2 still
//!     backstops a bad INSTALL, but a mis-registration now fails loud HERE instead
//!     of becoming a wasted-dial false claim. Remaining honest limits: (a) the
//!     quarantine verdict lives in the in-memory digest slot, so after a restart
//!     the first probe re-dumps and re-checks (correct, just not persisted) - a
//!     persisted quarantine is a possible optimisation, not a correctness gap; and
//!     (b) the cached `Verified` derivation assumes the backing bytes are IMMUTABLE
//!     between verification and serve - and task-82 now PERSISTS that verified
//!     derivation and WARMS it at boot, so the assumption is relied on across a
//!     restart too, not only in-process. For a real `/nix/store` path that holds
//!     unconditionally (the store is immutable and GC only drops it to `Absent`,
//!     never rewrites it), which is why persisting the digest is sound (see the
//!     "data design" section) - the claim can never go stale. A RAW-FILE-backed path
//!     ([`RegularFileNarDumper`], a non-store file, NON-PRODUCTION - only examples
//!     and tests use it) COULD be rewritten after verification (or while the daemon
//!     is down). When it is, the warmed `Verified` slot is NOT self-correcting:
//!     [`Self::derive`] short-circuits on a `Verified` slot and nothing re-derives a
//!     still-present path, so [`Self::hold`] keeps answering `Have{old digest}` and
//!     [`Self::publish`] keeps RE-ANNOUNCING the old digest - a DURABLE wrong CLAIM
//!     (now persisted across restarts, strictly worse than the pre-task-82 in-memory
//!     window) that clears only on an explicit re-`register` or a GC. Its cost is
//!     repeated WASTED DIALS + DHT pollution, bounded by the lying-claim accounting.
//!     It is NOT a serve-integrity hole: the supply path
//!     ([`AvailabilityIndex::supply_raw_nar_cancellable`]) re-dumps and re-checks
//!     `BLAKE3(dump) == announced` at serve time and fails loud on drift, and the
//!     consumer's Nix gate-2 independently re-verifies, so a peer NEVER receives
//!     wrong bytes under a right name. Store paths (the production case) make the
//!     whole hazard moot; the durable-wrong-claim raw-file case is the stated
//!     exception, and it is exactly what task-82's AC#2 changed-path bite exercises.
//!     (A size probe [`Self::supply_size_cancellable`] likewise trusts the persisted
//!     `NarSize` for such a path without a recheck - see that method's note.)
//!   * SEEDING (the eager kind) is external by design: producing a claim's `Iroh` offer does NOT put
//!     the blob into this node's iroh-blobs store. task-39's [`crate::transport_iroh::IrohProvider::seed`]
//!     is fed FROM this index (task-39/40/41 wire it); until then an announced offer
//!     is data-complete but a peer cannot yet fetch it end-to-end. [`AnnounceSink::announce`]
//!     also returns `()`, so a real discovery layer's announce FAILURE has no channel
//!     here - both are forward-carried to the task-40 discovery wiring.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::claim::{
    BatchHoldAnswer, BatchHoldQuery, BatchHoldResponse, CLAIM_SCHEMA_VERSION, Claim,
    ClaimCodecError, HoldAnswer, HoldQuery, HoldResponse, KnownPayload, KnownTransport,
    MAX_BATCH_HOLD_KEYS, NarHashKey, QUERY_SCHEMA_VERSION, check_batch_keys,
};
use crate::content_id::Blake3Digest;
use crate::derive_ledger::{DeriveAdmission, PeerDeriveLedger};
use crate::supply_catalog::{
    NarProductionSource, SupplyCatalog, SupplyCatalogHandle, SupplyCatalogRecord,
    SupplyRegistration,
};
use crate::transport::NodeId;
use proc_supervisor::process_group::{ProcessJob, ProcessJobSpec};

// -------------------------------------------------------------------------
// StorePath: a local /nix/store path this node holds.
// -------------------------------------------------------------------------

/// A local Nix store path (`/nix/store/<hash>-<name>`) whose NAR this node can
/// serve. A thin newtype so it can never be confused with an arbitrary path or a
/// URL token, and so existence (materialisation) is asked in exactly one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePath(PathBuf);

impl StorePath {
    /// Wrap a filesystem path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        StorePath(path.into())
    }

    /// The underlying path, for `nix-store --dump` and existence checks.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Whether the path still exists on disk. `false` after a GC - the signal that
    /// drops it from availability (materialisation/cleanup).
    pub fn exists(&self) -> bool {
        self.0.exists()
    }
}

impl fmt::Display for StorePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

// -------------------------------------------------------------------------
// Errors: fail fast, name the exact fault.
// -------------------------------------------------------------------------

/// Why producing the raw NAR for a store path failed (the `nix-store --dump` step).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpError(pub String);

impl fmt::Display for DumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nix-store --dump failed: {}", self.0)
    }
}

impl std::error::Error for DumpError {}

/// Why loading or saving the persisted registration set failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistError(pub String);

impl fmt::Display for PersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "availability index persistence failed: {}", self.0)
    }
}

impl std::error::Error for PersistError {}

/// A registered `key -> store_path` binding whose stored NAR does NOT hash to the
/// key it was registered under: `sha256(nix-store --dump store_path)` differs from
/// the registered [`NarHashKey`]. The path was MIS-REGISTERED - key X bound to a
/// path whose real NarHash is Y (task-56).
///
/// This is surfaced LOUDLY, never as a silent `Absent`, because it is exactly the
/// fault that would otherwise make this node answer a FALSE `Have` for X and then
/// hand a peer Y: the consumer re-verifies at its own NarHash gate and rejects it,
/// so the whole exchange is a WASTED DIAL that pollutes honest offload accounting
/// and feeds the lying-claim pathological cost. The offending registration is
/// QUARANTINED - never announced, never served, never a positive hold - until it
/// is re-registered under the correct key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarHashMismatch {
    /// The NarHash the caller CLAIMED this path has (the registration key).
    pub registered: NarHashKey,
    /// The NarHash the path ACTUALLY dumps to (sha256 of the real `--dump` bytes).
    pub computed: NarHashKey,
    /// The store path whose real content does not match its registered key.
    pub store_path: StorePath,
}

impl fmt::Display for NarHashMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NarHash mismatch: {} was registered under {} but its NAR dumps to {}; \
             the binding is quarantined (never announced or served)",
            self.store_path, self.registered, self.computed
        )
    }
}

impl std::error::Error for NarHashMismatch {}

/// Aggregate error surfaced by the index query path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvailabilityError {
    /// The store path could not be dumped/hashed.
    Dump(DumpError),
    /// The registration set could not be persisted.
    Persist(PersistError),
    /// The registered path's real NarHash does not equal its registration key
    /// (task-56): a mis-registration, quarantined rather than answered as a false
    /// `Have`. Loud, never a silent `Absent`.
    NarHashMismatch(NarHashMismatch),
}

impl fmt::Display for AvailabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AvailabilityError::Dump(e) => write!(f, "{e}"),
            AvailabilityError::Persist(e) => write!(f, "{e}"),
            AvailabilityError::NarHashMismatch(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AvailabilityError {}

impl From<DumpError> for AvailabilityError {
    fn from(e: DumpError) -> Self {
        AvailabilityError::Dump(e)
    }
}

impl From<NarHashMismatch> for AvailabilityError {
    fn from(e: NarHashMismatch) -> Self {
        AvailabilityError::NarHashMismatch(e)
    }
}

impl From<PersistError> for AvailabilityError {
    fn from(e: PersistError) -> Self {
        AvailabilityError::Persist(e)
    }
}

// -------------------------------------------------------------------------
// The NarDumper seam: produce RawNarV1 bytes for a store path.
// -------------------------------------------------------------------------

/// Produces the exact `nix-store --dump <path>` byte stream (RawNarV1) for a store
/// path. A SEAM so the expensive real dump is swappable: production uses
/// [`CommandNarDumper`]; a test injects a synthetic-NAR producer that COUNTS its
/// invocations (to prove single-flight) without needing nix or a real store.
///
/// It returns the RAW bytes rather than a digest on purpose: the frozen recipe
/// [`Blake3Digest::from_raw_nar`] is then applied in EXACTLY ONE place (the index),
/// so the addressed-unit recipe is never re-implemented per dumper.
pub trait CancellationCheck: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

struct NeverCancelled;

impl CancellationCheck for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

mod nar_dumper_sealed {
    use super::{NarProductionSource, StorePath};

    pub trait Sealed {
        fn production_source(&self, path: &StorePath) -> NarProductionSource;
    }
}

/// Closed NAR-production boundary.
///
/// This trait is public so callers can pass daemon-owned dumpers through the
/// availability API, but it is sealed: arbitrary in-process implementations
/// cannot enter the provider's supervised blocking pool. Every implementation
/// below either checks cancellation while doing bounded regular-file reads or
/// owns a killable process group and reaps it before returning.
pub trait NarDumper: nar_dumper_sealed::Sealed + Send + Sync {
    /// Dump the store path's uncompressed NAR (the addressed unit's input bytes).
    fn dump(
        &self,
        path: &StorePath,
        cancellation: &dyn CancellationCheck,
    ) -> Result<Vec<u8>, DumpError>;

    /// The UNCOMPRESSED NAR byte size (NarSize) this path WOULD dump to, answered
    /// WITHOUT dumping (TASK-229 R1). This is the size a byte budget is seeded from so
    /// a responder can REFUSE a hold-query probe BEFORE it spends a whole
    /// `nix-store --dump` + BLAKE3 on it: the production dumper reads `narSize` from the
    /// store DB (`nix-store -q --size`, a cheap O(1) query, NOT a dump), so an
    /// over-budget cold probe costs a stat, not a multi-GB hash.
    ///
    /// The unit is NarSize - UNCOMPRESSED NAR bytes, the exact hashing-work unit and the
    /// same unit [`DumpError`]-free [`dump`](Self::dump) produces - NEVER the compressed
    /// FileSize a narinfo carries (the recurring unit trap). For an immutable
    /// `/nix/store` path this equals the eventual `dump().len()` exactly; for a
    /// raw-file-backed non-production path it is the file length, which the serve-time
    /// `BLAKE3 == announced` recheck still backstops if the file changed.
    fn nar_size(
        &self,
        path: &StorePath,
        cancellation: &dyn CancellationCheck,
    ) -> Result<u64, DumpError>;
}

/// The REAL dumper: shells out to `nix-store --dump <path>` and returns its stdout
/// (the uncompressed `nix-archive-1` stream). The program defaults to `nix-store`
/// resolved on `PATH` (the dev shell / a NixOS host provides it); a caller may pin
/// an explicit binary.
///
/// Buffering note: this collects the whole dump to feed the one-shot recipe. See
/// the module-level honest limits - streaming is a hardening follow-up, not a
/// recipe change.
pub struct CommandNarDumper {
    program: PathBuf,
}

impl nar_dumper_sealed::Sealed for CommandNarDumper {
    fn production_source(&self, path: &StorePath) -> NarProductionSource {
        NarProductionSource::Process {
            program: self.program.clone(),
            args: vec![OsString::from("--dump"), path.as_path().as_os_str().into()],
        }
    }
}

impl CommandNarDumper {
    /// Use `nix-store` from `PATH`.
    pub fn from_path() -> Self {
        CommandNarDumper {
            program: PathBuf::from("nix-store"),
        }
    }

    /// Use an explicit `nix-store` binary (e.g. a pinned nix).
    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        CommandNarDumper {
            program: program.into(),
        }
    }
}

impl NarDumper for CommandNarDumper {
    fn dump(
        &self,
        path: &StorePath,
        cancellation: &dyn CancellationCheck,
    ) -> Result<Vec<u8>, DumpError> {
        if cancellation.is_cancelled() {
            return Err(DumpError(format!(
                "{} --dump {} cancelled before spawn",
                self.program.display(),
                path
            )));
        }
        let job = ProcessJob::standalone(
            format!("{} --dump {}", self.program.display(), path),
            ProcessJobSpec {
                program: self.program.clone(),
                args: vec![OsString::from("--dump"), path.as_path().as_os_str().into()],
                environment: Vec::new(),
                stdout_limit: None,
                stderr_limit: 64 * 1024,
            },
        )
        .map_err(|error| DumpError(format!("starting supervised dump: {error}")))?;
        let output = loop {
            if cancellation.is_cancelled() {
                job.cancel();
                let cleaned = job.wait().map_err(|error| {
                    DumpError(format!(
                        "{} --dump {} cancellation cleanup failed: {error}",
                        self.program.display(),
                        path
                    ))
                })?;
                return Err(DumpError(format!(
                    "{} --dump {} cancelled; process group killed and reaped (status {})",
                    self.program.display(),
                    path,
                    cleaned.status
                )));
            }
            if let Some(result) = job.try_take_result() {
                break result.map_err(|error| DumpError(error.to_string()))?;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DumpError(format!(
                "{} --dump {} exited {}: {}",
                self.program.display(),
                path,
                output.status,
                stderr.trim()
            )));
        }
        Ok(output.stdout)
    }

    fn nar_size(
        &self,
        path: &StorePath,
        cancellation: &dyn CancellationCheck,
    ) -> Result<u64, DumpError> {
        // `nix-store -q --size <path>` prints the store DB's `narSize` (UNCOMPRESSED
        // NAR bytes) as a single integer line - a cheap O(1) metadata query, NOT a
        // dump. Same binary the dump path uses, so no new tool dependency. This is the
        // R1 "answer the byte budget's question without producing the bytes" query.
        if cancellation.is_cancelled() {
            return Err(DumpError(format!(
                "{} -q --size {} cancelled before spawn",
                self.program.display(),
                path
            )));
        }
        let job = ProcessJob::standalone(
            format!("{} -q --size {}", self.program.display(), path),
            ProcessJobSpec {
                program: self.program.clone(),
                args: vec![
                    OsString::from("--query"),
                    OsString::from("--size"),
                    path.as_path().as_os_str().into(),
                ],
                environment: Vec::new(),
                // A NarSize is a small integer line; bound stdout tightly so a broken
                // nix cannot flood us on the metadata path.
                stdout_limit: Some(4 * 1024),
                stderr_limit: 64 * 1024,
            },
        )
        .map_err(|error| DumpError(format!("starting supervised size query: {error}")))?;
        let output = loop {
            if cancellation.is_cancelled() {
                job.cancel();
                let cleaned = job.wait().map_err(|error| {
                    DumpError(format!(
                        "{} -q --size {} cancellation cleanup failed: {error}",
                        self.program.display(),
                        path
                    ))
                })?;
                return Err(DumpError(format!(
                    "{} -q --size {} cancelled; process group killed and reaped (status {})",
                    self.program.display(),
                    path,
                    cleaned.status
                )));
            }
            if let Some(result) = job.try_take_result() {
                break result.map_err(|error| DumpError(error.to_string()))?;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DumpError(format!(
                "{} -q --size {} exited {}: {}",
                self.program.display(),
                path,
                output.status,
                stderr.trim()
            )));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let first = text.split_whitespace().next().ok_or_else(|| {
            DumpError(format!(
                "{} -q --size {} produced no size line",
                self.program.display(),
                path
            ))
        })?;
        first.parse::<u64>().map_err(|error| {
            DumpError(format!(
                "{} -q --size {} produced a non-integer NarSize {first:?}: {error}",
                self.program.display(),
                path
            ))
        })
    }
}

/// Deterministic, cancellation-aware dumper for tests and in-memory probes.
///
/// Keeping this implementation in the closed set lets integration tests ground
/// single-flight behavior without reopening the arbitrary-worker escape hatch.
pub struct MemoryNarDumper {
    bytes: Arc<Vec<u8>>,
    calls: AtomicUsize,
    delay: Duration,
}

impl MemoryNarDumper {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(bytes),
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
        }
    }

    pub fn with_delay(bytes: Vec<u8>, delay: Duration) -> Self {
        Self {
            bytes: Arc::new(bytes),
            calls: AtomicUsize::new(0),
            delay,
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl nar_dumper_sealed::Sealed for MemoryNarDumper {
    fn production_source(&self, _path: &StorePath) -> NarProductionSource {
        NarProductionSource::Memory(Arc::clone(&self.bytes))
    }
}

impl NarDumper for MemoryNarDumper {
    fn dump(
        &self,
        _path: &StorePath,
        cancellation: &dyn CancellationCheck,
    ) -> Result<Vec<u8>, DumpError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let deadline = std::time::Instant::now() + self.delay;
        while std::time::Instant::now() < deadline {
            if cancellation.is_cancelled() {
                return Err(DumpError("in-memory NAR dump cancelled".into()));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if cancellation.is_cancelled() {
            return Err(DumpError("in-memory NAR dump cancelled".into()));
        }
        Ok(self.bytes.as_ref().clone())
    }

    fn nar_size(
        &self,
        _path: &StorePath,
        cancellation: &dyn CancellationCheck,
    ) -> Result<u64, DumpError> {
        // The in-memory NAR's length IS its NarSize; no dump, and crucially NO `calls`
        // increment - the size query is not a dump, so a test that counts dumps sees the
        // R1 refuse-before-dump property directly (a refused probe leaves `calls`
        // unchanged).
        if cancellation.is_cancelled() {
            return Err(DumpError("in-memory NAR size query cancelled".into()));
        }
        Ok(self.bytes.len() as u64)
    }
}

/// Read a store path that is itself a raw-NAR regular file.
///
/// The descriptor is opened nonblocking and no-follow, then validated before
/// any read. A path replaced with a FIFO, device, socket or symlink therefore
/// fails immediately instead of parking an unkillable in-process worker.
pub struct RegularFileNarDumper;

impl nar_dumper_sealed::Sealed for RegularFileNarDumper {
    fn production_source(&self, path: &StorePath) -> NarProductionSource {
        NarProductionSource::RegularFile(path.as_path().to_path_buf())
    }
}

impl NarDumper for RegularFileNarDumper {
    fn dump(
        &self,
        path: &StorePath,
        cancellation: &dyn CancellationCheck,
    ) -> Result<Vec<u8>, DumpError> {
        use rustix::fs::{FileType, Mode, OFlags};

        if cancellation.is_cancelled() {
            return Err(DumpError(format!("reading {path} cancelled before open")));
        }
        let fd = rustix::fs::open(
            path.as_path(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| DumpError(format!("opening raw NAR {path}: {error}")))?;
        let stat = rustix::fs::fstat(&fd)
            .map_err(|error| DumpError(format!("inspecting raw NAR {path}: {error}")))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(DumpError(format!("raw NAR {path} is not a regular file")));
        }
        let mut file = std::fs::File::from(fd);
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        loop {
            if cancellation.is_cancelled() {
                return Err(DumpError(format!("reading raw NAR {path} cancelled")));
            }
            let read = file
                .read(&mut chunk)
                .map_err(|error| DumpError(format!("reading raw NAR {path}: {error}")))?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        Ok(bytes)
    }

    fn nar_size(
        &self,
        path: &StorePath,
        cancellation: &dyn CancellationCheck,
    ) -> Result<u64, DumpError> {
        use rustix::fs::{FileType, Mode, OFlags};

        // The file IS the raw NAR, so its byte length is its NarSize - answered with a
        // single fstat, no read (R1: no bytes produced). The same NOFOLLOW/regular-file
        // validation as `dump`, so a path swapped for a FIFO/device/symlink fails here
        // too rather than reporting a bogus size.
        if cancellation.is_cancelled() {
            return Err(DumpError(format!("sizing {path} cancelled before open")));
        }
        let fd = rustix::fs::open(
            path.as_path(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| DumpError(format!("opening raw NAR {path} for size: {error}")))?;
        let stat = rustix::fs::fstat(&fd)
            .map_err(|error| DumpError(format!("inspecting raw NAR {path} for size: {error}")))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(DumpError(format!("raw NAR {path} is not a regular file")));
        }
        Ok(stat.st_size.max(0) as u64)
    }
}

// -------------------------------------------------------------------------
// The IndexStore seam: persist the registration set (source of truth).
// -------------------------------------------------------------------------

/// One persisted holding: the SOURCE-OF-TRUTH `key -> store_path` binding, plus -
/// once a probe has VERIFIED it (task-56/82) - the derived `Blake3Digest` + `NarSize`.
///
/// `derived` is `None` for a registration that has never been served (its digest
/// is still uncomputed) and for a legacy pre-task-82 snapshot that predates the
/// field; both simply re-derive on demand. It is written ONLY for a VERIFIED
/// binding - never a quarantined one - so a mis-registration can never be made
/// durable across a restart (the exact trap task-82's source note warned about).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedRegistration {
    pub key: NarHashKey,
    pub store_path: StorePath,
    pub derived: Option<DerivedNar>,
}

/// Persists the registration set so the index survives a restart. The SOURCE OF
/// TRUTH is the `key -> store_path` binding; task-82 additionally persists the
/// VERIFIED derived `Blake3Digest` + `NarSize` (see [`PersistedRegistration`] and
/// the module docs for why caching that derived value on disk is safe HERE). A
/// SEAM so a test can persist to a temp file (proving restart) or use a no-op store.
pub trait IndexStore: Send + Sync {
    /// Load the persisted registrations (empty if none yet). A malformed store is
    /// an ERROR, not silently-empty: a corrupt index must fail loud, not lose data.
    fn load(&self) -> Result<Vec<PersistedRegistration>, PersistError>;

    /// Atomically replace the persisted registrations with `entries`.
    fn save(&self, entries: &[PersistedRegistration]) -> Result<(), PersistError>;
}

/// The on-disk VALUE for one key. FORWARD/BACKWARD compatible by shape: a
/// pre-task-82 snapshot wrote a bare path STRING (the [`StoredValue::PathOnly`] arm
/// still loads it and re-derives), while task-82 writes the
/// [`StoredValue::WithDerived`] OBJECT carrying the verified derived binding. A
/// future reader that does not know a later field ignores it rather than crashing
/// (the inner object is not `deny_unknown_fields`), and a future writer that omits
/// the object still round-trips through `PathOnly`.
///
/// NarSize is stored under an explicitly-named `nar_size_uncompressed_nar` field:
/// the persisted number is the UNCOMPRESSED `--dump` length, never a compressed
/// narinfo `FileSize` (the unit trap this project has hit repeatedly).
///
/// `Deserialize` is HAND-WRITTEN rather than `#[serde(untagged)]` deliberately:
/// untagged collapses a malformed object (a corrupt `blake3` string, an
/// out-of-range size) into a useless "data did not match any variant" message,
/// discarding the real cause - which would make the one corruption class task-82
/// newly introduces fail the LEAST verbosely, against this module's fail-loud
/// contract. The visitor below dispatches on the JSON shape (string vs object) and
/// delegates the object to a derived inner struct, so a bad field surfaces its OWN
/// error (e.g. the [`Blake3Digest`] parse error) all the way up.
#[derive(Debug, Clone)]
enum StoredValue {
    /// Legacy / not-yet-derived: just the store path. Derived binding re-derived.
    PathOnly(String),
    /// The registration WITH its verified derived binding (task-82).
    WithDerived {
        store_path: String,
        blake3: Blake3Digest,
        nar_size_uncompressed_nar: u64,
    },
}

impl serde::Serialize for StoredValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            // Legacy shape: a bare path string, byte-for-byte what a pre-82 node wrote.
            StoredValue::PathOnly(path) => serializer.serialize_str(path),
            StoredValue::WithDerived {
                store_path,
                blake3,
                nar_size_uncompressed_nar,
            } => {
                use serde::ser::SerializeStruct;
                let mut st = serializer.serialize_struct("StoredValue", 3)?;
                st.serialize_field("store_path", store_path)?;
                st.serialize_field("blake3", blake3)?;
                st.serialize_field("nar_size_uncompressed_nar", nar_size_uncompressed_nar)?;
                st.end()
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for StoredValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StoredValueVisitor;

        impl<'de> serde::de::Visitor<'de> for StoredValueVisitor {
            type Value = StoredValue;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a store-path string (legacy) or an object \
                     {store_path, blake3, nar_size_uncompressed_nar}",
                )
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<StoredValue, E> {
                Ok(StoredValue::PathOnly(value.to_string()))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<StoredValue, E> {
                Ok(StoredValue::PathOnly(value))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<StoredValue, A::Error> {
                // A derived inner struct so a corrupt field reports its REAL cause
                // (the [`Blake3Digest`] / u64 parse error), not a generic message.
                #[derive(serde::Deserialize)]
                struct Derived {
                    store_path: String,
                    blake3: Blake3Digest,
                    nar_size_uncompressed_nar: u64,
                }
                let derived = <Derived as serde::Deserialize>::deserialize(
                    serde::de::value::MapAccessDeserializer::new(map),
                )?;
                Ok(StoredValue::WithDerived {
                    store_path: derived.store_path,
                    blake3: derived.blake3,
                    nar_size_uncompressed_nar: derived.nar_size_uncompressed_nar,
                })
            }
        }

        deserializer.deserialize_any(StoredValueVisitor)
    }
}

/// A no-op store: the index is in-memory only (does not survive restart). Useful
/// for a node that re-derives its registrations from another source each boot.
pub struct NullStore;

impl IndexStore for NullStore {
    fn load(&self) -> Result<Vec<PersistedRegistration>, PersistError> {
        Ok(Vec::new())
    }
    fn save(&self, _entries: &[PersistedRegistration]) -> Result<(), PersistError> {
        Ok(())
    }
}

/// The real store: a single JSON file mapping the canonical `sha256:<base32>` key
/// to its [`StoredValue`] (a bare path string, or the object carrying the verified
/// derived binding). A `BTreeMap` so the on-disk form is SORTED and stable (a
/// clean diff, greppable), and the write is ATOMIC AND DURABLE (write + fsync a temp
/// file, rename it over the target, then fsync the parent dir - see [`Self::save`]),
/// so a crash mid-write never leaves a torn or zero-length index.
pub struct JsonFileStore {
    path: PathBuf,
}

impl JsonFileStore {
    /// Persist to `path` (its parent directory is created on save if absent).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        JsonFileStore { path: path.into() }
    }
}

impl IndexStore for JsonFileStore {
    fn load(&self) -> Result<Vec<PersistedRegistration>, PersistError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            // Absent file == an empty index (first boot), not an error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(PersistError(format!(
                    "reading {}: {e}",
                    self.path.display()
                )));
            }
        };
        let raw: BTreeMap<String, StoredValue> = serde_json::from_slice(&bytes).map_err(|e| {
            PersistError(format!(
                "{} is not a valid index file: {e}",
                self.path.display()
            ))
        })?;
        let mut out = Vec::with_capacity(raw.len());
        for (key_str, value) in raw {
            // Fail loud on a corrupt key rather than silently dropping a holding.
            let key: NarHashKey = key_str.parse().map_err(|e| {
                PersistError(format!(
                    "{} holds a non-canonical NarHash key {key_str:?}: {e}",
                    self.path.display()
                ))
            })?;
            let (path_str, derived) = match value {
                StoredValue::PathOnly(path_str) => (path_str, None),
                StoredValue::WithDerived {
                    store_path,
                    blake3,
                    nar_size_uncompressed_nar,
                } => (
                    store_path,
                    Some(DerivedNar {
                        blake3,
                        nar_size_uncompressed_nar,
                    }),
                ),
            };
            out.push(PersistedRegistration {
                key,
                store_path: StorePath::new(path_str),
                derived,
            });
        }
        Ok(out)
    }

    fn save(&self, entries: &[PersistedRegistration]) -> Result<(), PersistError> {
        let mut map = BTreeMap::new();
        for entry in entries {
            // A non-UTF8 store path fails loud rather than being lossily corrupted.
            let path_str = entry
                .store_path
                .as_path()
                .to_str()
                .ok_or_else(|| {
                    PersistError(format!(
                        "store path {} is not valid UTF-8",
                        entry.store_path
                    ))
                })?
                .to_string();
            let value = match entry.derived {
                // Persist the VERIFIED derived binding alongside the source path.
                Some(derived) => StoredValue::WithDerived {
                    store_path: path_str,
                    blake3: derived.blake3,
                    nar_size_uncompressed_nar: derived.nar_size_uncompressed_nar,
                },
                // Not yet derived (or a legacy holding): store only the source path.
                None => StoredValue::PathOnly(path_str),
            };
            map.insert(entry.key.to_string(), value);
        }
        let json = serde_json::to_vec_pretty(&map)
            .map_err(|e| PersistError(format!("serialising the index: {e}")))?;

        // The parent directory the file (and its temp sibling) live in. A bare
        // filename has an empty parent, which means the current directory.
        let parent = match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        std::fs::create_dir_all(&parent)
            .map_err(|e| PersistError(format!("creating {}: {e}", parent.display())))?;

        // ATOMIC + DURABLE replace (the standard fsync recipe; mirrors the task-185
        // identity-seed write). Durability is LOAD-BEARING for task-82: warm-load's
        // whole soundness argument is "trust what we DURABLY wrote", so the write
        // must actually reach stable storage, not just the page cache.
        //   1. write the temp file, then fsync ITS data+metadata;
        //   2. rename it over the target (atomic on POSIX);
        //   3. fsync the PARENT DIRECTORY so the rename (the name->inode link) is
        //      itself durable.
        // Skipping (1) lets a crash after the rename expose a zero-length / torn
        // index on a delayed-allocation fs; skipping (3) lets the rename be lost
        // even though the bytes hit the platter. A torn/empty file still fails LOUD
        // at load (`PersistError`, never silently-empty), which bounds the blast
        // radius. The whole-file rewrite + per-write fsync is O(N) per mutation;
        // folding it into a single append/durable state file is task-189.
        let tmp = self
            .path
            .with_extension(format!("tmp-{}", std::process::id()));
        {
            let mut file = std::fs::File::create(&tmp)
                .map_err(|e| PersistError(format!("creating {}: {e}", tmp.display())))?;
            file.write_all(&json)
                .map_err(|e| PersistError(format!("writing {}: {e}", tmp.display())))?;
            // fsync the temp file's contents BEFORE the rename so a crash can never
            // publish a name that points at unflushed (zero/garbage) bytes.
            file.sync_all()
                .map_err(|e| PersistError(format!("fsyncing {}: {e}", tmp.display())))?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            // Best-effort cleanup so a failed rename does not litter temp files.
            let _ = std::fs::remove_file(&tmp);
            PersistError(format!(
                "renaming {} -> {}: {e}",
                tmp.display(),
                self.path.display()
            ))
        })?;
        // fsync the directory so the rename itself survives a crash (opening a dir
        // read-only and `sync_all`ing it is the portable way to fsync a directory).
        let dir = std::fs::File::open(&parent)
            .map_err(|e| PersistError(format!("opening {} to fsync: {e}", parent.display())))?;
        dir.sync_all()
            .map_err(|e| PersistError(format!("fsyncing directory {}: {e}", parent.display())))?;
        Ok(())
    }
}

// -------------------------------------------------------------------------
// The AnnounceSink seam: announce-on-demand.
// -------------------------------------------------------------------------

/// Where a produced [`Claim`] is announced when a path is available
/// (announce-on-demand). An in-memory sink is enough for wave-2a; task-40 wires a
/// real discovery layer behind this same seam.
pub trait AnnounceSink: Send + Sync {
    /// A complete, fetchable claim this node can serve is available.
    fn announce(&self, claim: Claim);
}

/// A sink that discards announcements (the default when no discovery is wired).
pub struct NullAnnounce;

impl AnnounceSink for NullAnnounce {
    fn announce(&self, _claim: Claim) {}
}

// -------------------------------------------------------------------------
// The index.
// -------------------------------------------------------------------------

/// The most FRESH `nix-store --dump` derivations one BATCHED hold-query
/// ([`AvailabilityIndex::answer_batch_for_peer`]) may trigger on the responder (task-104).
///
/// WHY THIS EXISTS. task-91 caps a batch at [`crate::claim::MAX_BATCH_HOLD_KEYS`]
/// = 256 keys, which bounds the NUMBER of probes one message demands but NOT the
/// derivation work: on a COLD responder each of those 256 probes can cost one
/// `nix-store --dump` of a large unhashed NAR, so ONE batch message could make this
/// node dump up to 256 large NARs. This bounds that AMPLIFICATION to a fixed count
/// per message. The bound is on a COUNT of fresh dumps, never on a clock: raising
/// the probe timeout instead would put unbounded latency back into the build path,
/// the exact property task-40 forbids.
///
/// WHAT IT DOES NOT BOUND (be honest). This is a bound on the NUMBER of dumps, NOT
/// on the BYTES hashed: 16 dumps of multi-GB closures is still unbounded bytes, so
/// one message can still cost minutes of I/O. A true per-byte bound is achievable -
/// a store path's NAR size is in the store DB (`nix path-info -S`), so a byte budget
/// seeded from path-info could refuse before dumping - and is the real root-cause
/// follow-up; it is NOT done here. Nor does this per-MESSAGE bound stop a hostile
/// peer: the peer chooses the message boundaries, so it can send 16 batches (or
/// 4 096 single-key probes, which take the UNLIMITED [`AvailabilityIndex::hold`]
/// path) to drive the same total. A per-PEER aggregate limit on concurrent/total
/// dumps is the DoS defense and is also a follow-up (task-72's serve budget bounds
/// bytes SERVED, not bytes HASHED). What this closes is the single-message
/// amplification, not adversarial resource exhaustion.
///
/// WHAT IT DOES. A batch answers freely from what is ALREADY derived (warm keys
/// cost no dump and spend no budget) and triggers at most this many FRESH dumps;
/// once spent, further COLD keys answer `Absent` WITHOUT dumping - today's safe
/// direction (the asker falls back upstream, never a wrong byte). It is a per-
/// MESSAGE policy knob, deliberately `<<` [`crate::claim::MAX_BATCH_HOLD_KEYS`]:
/// larger warms more per probe at more work per message. The value 16 is not
/// derived from a disk/CPU target - it is a conservative placeholder well below the
/// 256-key cap and above the largest batch any current test holds; tune it when a
/// deployment gives a real per-message I/O ceiling. It is a tunable integer, not a
/// wire constant, so changing it is not a wire change. See
/// [`AvailabilityIndex::answer_batch_for_peer`] for the residual under-report and how the
/// responder cache warms `MAX_BATCH_DERIVE_WORK` cold keys per probe.
pub const MAX_BATCH_DERIVE_WORK: u32 = 16;

/// A per-BATCH allowance of FRESH derivations (task-104). [`AvailabilityIndex::answer_batch_for_peer`]
/// starts it at [`MAX_BATCH_DERIVE_WORK`]; every key that triggers a real
/// `nix-store --dump` spends one unit. A key that is already derived (warm),
/// unregistered, or GC'd triggers no dump and so spends NO unit. The single-key
/// [`AvailabilityIndex::hold`] path uses [`BatchDeriveAllowance::unlimited`], preserving
/// its pre-task-104 behaviour exactly (it can never defer on the COUNT axis).
///
/// This is the per-MESSAGE COUNT bound. It is DISTINCT from - and composed with - the
/// cross-message, per-authenticated-peer BYTE+count [`PeerDeriveLedger`](crate::derive_ledger::PeerDeriveLedger)
/// (task-229), which is what actually bounds a hostile peer that picks the message
/// boundaries. Both are consulted in [`AvailabilityIndex::derive`]; the tighter bites.
struct BatchDeriveAllowance {
    /// `None` = unlimited (the single-key path). `Some(n)` = `n` fresh dumps remain.
    remaining: Option<u32>,
}

impl BatchDeriveAllowance {
    /// No per-message COUNT bound: the single-key path (the per-peer ledger still bounds
    /// it across messages).
    fn unlimited() -> Self {
        Self { remaining: None }
    }

    /// At most `n` fresh dumps in this one message: the batched path.
    fn limited(n: u32) -> Self {
        Self { remaining: Some(n) }
    }

    /// Reserve permission for ONE fresh dump. `true` (and, for a limited allowance,
    /// consumes one unit) when a dump is permitted; `false` when a limited allowance
    /// is spent. Unlimited never consumes and never refuses.
    ///
    /// The allowance itself is not shared between threads - it is a `&mut` threaded
    /// through one `answer_batch` loop, which is the only mutator, so a batch cannot
    /// race PAST ITS OWN allowance (there is no intra-batch concurrency). Call this only
    /// after the `None` (cold) check UNDER the digest lock so that (a) each reserved
    /// unit maps 1:1 to a real dump - the lock's single-flight guard means the slot
    /// cannot flip to `Verified` between the check and the dump - and (b) a warm key
    /// never consumes a unit.
    fn try_reserve(&mut self) -> bool {
        match &mut self.remaining {
            None => true,
            Some(0) => false,
            Some(n) => {
                *n -= 1;
                true
            }
        }
    }
}

/// The full RESPONDER derivation gate threaded through one hold-query answer (task-229):
/// the per-MESSAGE count allowance (task-104) PLUS, for a peer-attributed answer, the
/// authenticated asker identity and the shared cross-message [`PeerDeriveLedger`].
///
/// A LOCAL self-probe ([`AvailabilityIndex::hold`], used by `claim`/`publish`/post-fetch
/// learning) is node-initiated, not peer-driven, and must always answer truthfully, so
/// it carries [`DeriveGate::local`] (unlimited count, no ledger, no byte check). A
/// RESPONDER answer to a remote peer carries [`DeriveGate::for_peer`], so every cold key
/// is admitted against BOTH the per-message count AND the per-peer/global byte ledger,
/// seeded by the path's NarSize queried WITHOUT dumping (R1: refuse before dump).
struct DeriveGate<'a> {
    /// The per-message fresh-dump COUNT allowance (task-104).
    batch: BatchDeriveAllowance,
    /// `Some((asker, ledger))` for a peer-attributed responder answer (task-229);
    /// `None` for a local self-probe, which is never bounded or byte-checked.
    peer: Option<(&'a NodeId, &'a PeerDeriveLedger)>,
}

impl<'a> DeriveGate<'a> {
    /// The LOCAL self-probe gate: unlimited count, no per-peer ledger. Never refuses a
    /// cold key on either axis - a self-initiated probe must always answer truthfully.
    fn local() -> Self {
        DeriveGate {
            batch: BatchDeriveAllowance::unlimited(),
            peer: None,
        }
    }

    /// A peer-attributed responder gate with the given per-message count allowance,
    /// bounded across messages by `ledger` keyed on the authenticated `asker`.
    fn for_peer(
        batch: BatchDeriveAllowance,
        asker: &'a NodeId,
        ledger: &'a PeerDeriveLedger,
    ) -> Self {
        DeriveGate {
            batch,
            peer: Some((asker, ledger)),
        }
    }
}

/// The outcome of a budget-aware per-key resolution ([`AvailabilityIndex::hold_budgeted`]).
enum BudgetedHold {
    /// The key is held and derived; answer `Have`.
    Have {
        blake3: Blake3Digest,
        offers: Vec<KnownTransport>,
    },
    /// The key is genuinely not held (unregistered or GC'd), or its cached verdict
    /// is a quarantine handled by the caller; answer `Absent`.
    Absent,
    /// The key is COLD (a fresh dump would be needed) but the batch's derivation
    /// budget is spent, so NO dump happened. Answered `Absent` on the wire (today's
    /// behaviour) and counted as a deferral for the self-heal / under-report note.
    Deferred,
}

/// The outcome of [`AvailabilityIndex::derive`] under a [`DeriveBudget`].
enum DeriveStep {
    /// Derived (from the cache or a fresh dump). `(derivation, freshly_derived)`.
    Derived(DerivedNar, bool),
    /// Cold and the budget is spent: no dump happened (task-104). The caller answers
    /// Absent for this key and the entry warms on a later, budget-bearing probe.
    Deferred,
}

/// What ONE `nix-store --dump` derived: the addressed unit AND the NarSize that
/// produced it. They are kept together because they come from the same bytes in
/// the same pass - deriving the size separately would be a second source of truth
/// for one fact, and the unit would be the first thing to drift (NarSize, the
/// uncompressed dump length, is not the compressed FileSize a narinfo carries).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedNar {
    /// The frozen addressed unit, `BLAKE3(RawNarV1)`.
    pub blake3: Blake3Digest,
    /// The exact length of the dump, in UNCOMPRESSED NAR bytes. NEVER a FileSize.
    pub nar_size_uncompressed_nar: u64,
}

/// The cached outcome of an entry's one-shot dump+hash. Either the VERIFIED
/// derivation, or a QUARANTINE verdict because `sha256(--dump)` did not equal the
/// registration key (task-56, a mis-registration).
///
/// A dump *failure* is deliberately NOT represented here: it leaves the slot
/// `None` so the next caller retries (a transient nix error must not be cached).
/// Only a COMPLETED dump with a definite verdict lands in the slot, so a
/// deterministic mismatch is computed exactly once and then answered cheaply on
/// every subsequent probe instead of re-dumping a NAR that can only fail again.
enum DeriveOutcome {
    /// The dump hashed to its registered NarHash; safe to serve/announce.
    Verified(DerivedNar),
    /// The dump did NOT hash to its registered NarHash; quarantined.
    Quarantined(NarHashMismatch),
}

/// One registered holding: the store path (source of truth) and the single-flight
/// cache of what its dump derives.
struct Entry {
    store_path: StorePath,
    /// Scalar writer capability for this exact registration. It is never
    /// cloned into a provider record.
    supply_registration: SupplyRegistration,
    /// The [`DeriveOutcome`], computed UNDER this lock exactly once. The lock IS
    /// the single-flight guard: concurrent callers block here while the first one
    /// dumps + hashes + verifies.
    digest: Mutex<Option<DeriveOutcome>>,
    /// The VERIFIED derived binding, mirrored out of the `digest` slot into a pure
    /// LEAF mutex so [`AvailabilityIndex::persist_locked`] can snapshot it while
    /// holding the entries map lock WITHOUT ever taking a `digest` lock there - a
    /// `digest` lock can be held for a whole NAR dump, and blocking the map lock on
    /// a dump is exactly the head-of-line stall this index is built to avoid. This
    /// mutex is only ever locked to copy the small [`DerivedNar`] in or out; nothing
    /// else is acquired while it is held, so it introduces no lock cycle. It holds
    /// `Some` ONLY for a VERIFIED derivation (never a quarantine), which is the sole
    /// thing task-82 persists.
    persisted_derived: Mutex<Option<DerivedNar>>,
}

/// A node's local availability index and claim producer. See the module docs.
pub struct AvailabilityIndex {
    /// This node's iroh identity, embedded into every offer/holder it produces.
    node_id: NodeId,
    /// `NarHashKey -> Entry`. `Arc<Entry>` so a query clones the handle out and
    /// releases this map lock BEFORE taking the per-entry digest lock. The map lock
    /// is held only for map mutations and the persist snapshot - NEVER across a NAR
    /// dump (those run under the per-entry digest lock, so a 100 MiB hash for one key
    /// never stalls queries for other keys). It is deliberately never acquired while
    /// a digest lock is held, so the two locks have a strict order (map, then digest)
    /// and cannot deadlock. The persist snapshot IS written under this lock, so a
    /// mutation's disk write briefly serialises other mutations - an accepted
    /// latency-coupling limit for a small index (see the module-level honest limits).
    entries: Mutex<HashMap<NarHashKey, Arc<Entry>>>,
    /// Provider-facing SUPPLY direction (task-72 AC#2). The catalog contains
    /// inert records keyed by digest and scalar registration identity. It never
    /// contains `Arc<Entry>` or an index callback, and is rebuilt on demand.
    ///
    /// WHY IT EXISTS AT ALL. Before task-72 the index could answer "do you hold
    /// NarHash k?" for every registered path while the provider could only serve
    /// what had been eagerly seeded - so a positive answer did not imply a
    /// servable blob, and in deployment that is dial-then-fail. A peer fetches by
    /// BLAKE3, so making the two sets equal means being able to go BACK from the
    /// digest to the path. Nothing here can be listed: it is probed with a digest
    /// the caller already has, exactly like [`AvailabilityIndex::hold`], so the
    /// no-enumeration invariant is unchanged.
    ///
    /// It is PRUNED with the registration it came from ([`Self::retire_supply_registration`]),
    /// so supply can never outlive hold. Without that, a store path that was
    /// un-registered but still present on disk stayed fully servable - supply
    /// strictly larger than hold, which is AC#2 failing in the one direction that
    /// matters (announcing a serve the index has disowned).
    ///
    /// TASK-82 (the task-61 seeding gap, RESOLVED): this map is still in-memory, but
    /// it is now WARMED AT BOOT from the persisted VERIFIED derived binding (see
    /// [`Self::open`]), WITHOUT re-dumping - a previously-announced digest is
    /// suppliable immediately after a restart, no hold-query first. Only a
    /// registration that was never served (its digest still uncomputed) is absent
    /// until its first probe, exactly as before.
    supply_catalog: SupplyCatalog,
    dumper: Arc<dyn NarDumper>,
    store: Arc<dyn IndexStore>,
    announce: Arc<dyn AnnounceSink>,
}

impl AvailabilityIndex {
    /// Build an index, loading any persisted registrations so it survives restart.
    /// `node_id` is this node's iroh identity (the locator its offers carry).
    ///
    /// WARMING THE DERIVED BINDING (task-82, AC#1). For every loaded registration
    /// that carries a VERIFIED persisted `Blake3Digest` + `NarSize`, this pre-seeds
    /// the single-flight `digest` slot with `Verified(..)` AND publishes the
    /// supply-catalog record, so the node can REVERSE-MAP and serve a
    /// previously-announced digest immediately - with NO hold-query and NO re-dump.
    /// That closes the task-61 seeding gap: before task-82 the supply catalog was
    /// empty at boot, so a claim already on the DHT naming a digest this node could
    /// no longer reverse-map was undiallable until some hold-query re-derived it.
    ///
    /// WHY PRE-SEEDING A PERSISTED DERIVED VALUE IS SOUND (the earned exception to
    /// this module's "do not persist derived state, it goes stale" rule). The digest
    /// is `BLAKE3(nix-store --dump path)`. For a `/nix/store` path the content is
    /// IMMUTABLE (write-once; GC only removes it, never rewrites it), so that digest
    /// is a TIME-INVARIANT function of the path and CANNOT go stale - persisting it
    /// is not caching a value that may drift, it is recording a value that provably
    /// will not. The ONE case where a backing path CAN change is a raw-file-backed
    /// non-store path ([`RegularFileNarDumper`], non-production), which could be
    /// rewritten while the daemon is down; the WRONG BYTES that would then dump are
    /// caught NOT here but at the serve boundary, where
    /// [`Self::supply_raw_nar_cancellable`] re-dumps and asserts
    /// `BLAKE3(dump) == announced` before handing over a byte, failing loud on drift.
    /// So a warmed-but-since-changed binding never yields a wrong BYTE - but note
    /// (honest limit (b)) that the wrong CLAIM itself is DURABLE for such a path (the
    /// `Verified` slot is terminal until a re-`register`/GC), not self-healing.
    /// Existence is likewise re-checked at every query, so a path GC'd during
    /// downtime warms into the catalog but resolves to `Absent`/`None` the instant it
    /// is probed.
    ///
    /// TRUSTED-STATE NOTE (what pre-seeding does NOT re-check). Seeding the slot with
    /// `Verified` trusts the on-disk verdict WITHOUT re-running task-56's source check
    /// `sha256(dump) == key` (doing so would mean re-dumping at boot, defeating the
    /// whole point). This is sound because: (a) the record was written ONLY after that
    /// check passed for a genuine dump (`derive` persists from its `Verified` branch
    /// alone, never a quarantine); (b) the index file is LOCAL daemon state, inside the
    /// trust boundary - an attacker who can rewrite it can do worse, and it is not the
    /// p2p TCB; and (c) even a tampered `key -> blake3` binding cannot deliver wrong
    /// bytes: the serve-time `BLAKE3(dump) == announced` recheck and the CONSUMER's Nix
    /// gate-2 (`sha256(nar) == NarHash`) both still fire, so the worst reachable outcome
    /// is a wasted dial, never an accepted wrong NAR. A persisted quarantine verdict is
    /// therefore still an optional optimisation, not a correctness requirement (honest
    /// limit (a)).
    ///
    /// THE PRECEDENT, stated so it is not misread later: task-82 makes only
    /// AVAILABILITY / claim-accuracy depend on local persisted state (a wrong local
    /// binding costs bounded WASTED DIALS), NEVER byte-integrity. Byte-integrity stays
    /// anchored where the design demands it - on the serve-time `BLAKE3(dump) ==
    /// announced` recheck and the CONSUMER's unmodified-Nix NarHash gate - so that "a
    /// hostile/corrupt input costs a retry, never a bad store path" (README) holds
    /// even if this on-disk file is tampered. Integrity must never depend on the
    /// daemon (PRD:157); this change does not move that line.
    pub fn open(
        node_id: NodeId,
        dumper: Arc<dyn NarDumper>,
        store: Arc<dyn IndexStore>,
        announce: Arc<dyn AnnounceSink>,
    ) -> Result<Self, PersistError> {
        let loaded = store.load()?;
        let supply_catalog = SupplyCatalog::default();
        let mut entries = HashMap::with_capacity(loaded.len());
        for reg in loaded {
            let supply_registration = supply_catalog.register();
            // Warm the supply direction from the persisted VERIFIED derivation so a
            // previously-announced digest is suppliable with no hold-query first.
            if let Some(derived) = reg.derived {
                let record = SupplyCatalogRecord {
                    declared_size: derived.nar_size_uncompressed_nar,
                    source: nar_dumper_sealed::Sealed::production_source(
                        dumper.as_ref(),
                        &reg.store_path,
                    ),
                    store_path: reg.store_path.as_path().to_path_buf(),
                };
                supply_catalog.publish(&supply_registration, derived.blake3, record);
            }
            entries.insert(
                reg.key,
                Arc::new(Entry {
                    store_path: reg.store_path,
                    supply_registration,
                    // Pre-seed the single-flight cache with the VERIFIED derivation
                    // so the first post-restart probe answers Have without a re-dump.
                    digest: Mutex::new(reg.derived.map(DeriveOutcome::Verified)),
                    persisted_derived: Mutex::new(reg.derived),
                }),
            );
        }
        Ok(AvailabilityIndex {
            node_id,
            entries: Mutex::new(entries),
            supply_catalog,
            dumper,
            store,
            announce,
        })
    }

    /// Register that this node holds `key` at `store_path`, persisting it so it
    /// survives a restart. Idempotent: re-registering the same key/path is a no-op;
    /// re-registering with a NEW path replaces it (a later copy of the same content)
    /// with a fresh, uncomputed digest slot - the BLAKE3 is simply recomputed on the
    /// next probe. (An earlier cut carried the old digest across the path change to
    /// avoid a re-hash; that both took the per-entry digest lock UNDER the map lock -
    /// a head-of-line-blocking hazard - and silently ASSUMED the new path is the same
    /// content, which is exactly the binding this method does not verify. Dropping the
    /// carry is free: BLAKE3 is cheap-to-recompute derived state.)
    ///
    /// TRUST NOTE (source-side verification, task-56): `register` binds
    /// `key -> store_path` on the caller's word and does NOT dump here (it never
    /// takes a digest lock, keeping the map lock cheap). The binding is instead
    /// VERIFIED at first `derive`/serve: that path re-derives `sha256(--dump)` from
    /// the same buffer it BLAKE3s and asserts it equals `key`, QUARANTINING a
    /// mismatch (a typed [`NarHashMismatch`]) so a mis-registration can never become
    /// a positive `Have`/announced claim. So a wrong `key` registers without error
    /// but is caught the first time the content is actually derived - the false
    /// claim is never emitted. (Nix's gate 2 still independently re-verifies
    /// `sha256(nar) == NarHash` on the consumer, the trust anchor; the daemon is
    /// outside the TCB, see `content_id`.)
    ///
    /// Persist ordering (Low): on a persist failure the in-memory map is already
    /// mutated while disk is not, so a restart reloads the pre-mutation set. The
    /// caller sees the `Err` and can retry; the divergence is transient and bounded.
    /// This HARD-errors on a persist failure because the `key -> store_path` binding
    /// is the SOURCE OF TRUTH and losing it silently would be data loss; contrast the
    /// first-serve derived-binding persist in [`Self::hold`], which is best-effort
    /// (logs and continues) precisely because the derived value is an optimisation,
    /// not a source of truth. The asymmetry is deliberate, not an oversight.
    pub fn register(&self, key: NarHashKey, store_path: StorePath) -> Result<(), PersistError> {
        {
            let mut entries = self.entries.lock().expect("entries mutex");
            if entries
                .get(&key)
                .is_some_and(|existing| existing.store_path == store_path)
            {
                // Nothing changed; do not rewrite the snapshot.
                return Ok(());
            }
            // New key OR a moved path: a fresh entry with an uncomputed digest. Never
            // touches a digest lock, so the map lock is never held over one.
            let replaced = entries.insert(
                key,
                Arc::new(Entry {
                    store_path,
                    supply_registration: self.supply_catalog.register(),
                    digest: Mutex::new(None),
                    // A fresh (or moved-path) registration has no verified derivation
                    // yet; it is computed + persisted on the first serve, and any old
                    // persisted derived value for a replaced path is dropped by the
                    // snapshot rebuild below (the new entry contributes `None`).
                    persisted_derived: Mutex::new(None),
                }),
            );
            // The supply direction must follow the registration. A replaced entry
            // whose digest was already derived would otherwise stay servable under
            // the OLD path forever - supply would be a superset of hold, which is
            // the AC#2 equality failing in the direction that matters (announcing a
            // serve for content the index has disowned).
            if let Some(replaced) = replaced {
                self.retire_supply_registration(&replaced);
            }
            self.persist_locked(&entries)?;
        }
        Ok(())
    }

    /// Answer "do I hold this ONE NarHash?" from the real store: `Have{blake3,
    /// offers}` with the COMPLETE offer, or `Absent`. A registered-but-GC'd path
    /// resolves to `Absent` and is pruned (materialisation/cleanup). There is no
    /// enumeration counterpart - only this per-key probe.
    pub fn hold(&self, key: &NarHashKey) -> Result<HoldAnswer, AvailabilityError> {
        // The single-key LOCAL self-probe path is UNBOUNDED (no per-message count cap,
        // no per-peer ledger): it is node-initiated (claim/publish/post-fetch learning),
        // must always answer truthfully, and a local gate can never return `Deferred`,
        // so the mapping below is total. The RESPONDER single-key path is
        // `answer_for_peer`, which IS bounded (task-229).
        match self.hold_budgeted(key, &mut DeriveGate::local())? {
            BudgetedHold::Have { blake3, offers } => Ok(HoldAnswer::Have { blake3, offers }),
            BudgetedHold::Absent => Ok(HoldAnswer::Absent),
            // Unreachable: a local gate never defers. Fail LOUD in debug so a future
            // caller that wrongly routes a bounded gate through the single-key LOCAL
            // path is caught, while still degrading to the SAFE `Absent` in release
            // (a spurious miss falls back upstream; it never serves a wrong answer).
            BudgetedHold::Deferred => {
                debug_assert!(false, "hold() uses a local gate and must never defer");
                Ok(HoldAnswer::Absent)
            }
        }
    }

    /// The gate-aware core of [`Self::hold`] (task-104/229). Resolves ONE key while
    /// spending at most what `gate` permits on FRESH derivations: a warm key
    /// (already derived) or an absent key costs no dump and no budget; a cold key
    /// dumps only while BOTH the per-message count allowance AND (for a peer-attributed
    /// gate) the per-peer/global byte ledger allow, otherwise answers
    /// [`BudgetedHold::Deferred`] (no dump). [`Self::answer_batch_for_peer`] passes a
    /// [`BatchDeriveAllowance::limited`] count with a bounded ledger; [`Self::hold`]
    /// passes [`DeriveGate::local`], so its behaviour is exactly as before.
    fn hold_budgeted(
        &self,
        key: &NarHashKey,
        gate: &mut DeriveGate,
    ) -> Result<BudgetedHold, AvailabilityError> {
        loop {
            let entry = {
                let entries = self.entries.lock().expect("entries mutex");
                match entries.get(key) {
                    Some(entry) => Arc::clone(entry),
                    None => return Ok(BudgetedHold::Absent),
                }
            };

            // Materialisation check: a GC'd path is no longer available. Prune the
            // stale registration lazily. If a concurrent registration won, retry
            // that new entry instead of returning a stale answer about the old one.
            if !entry.store_path.exists() {
                self.drop_if_same(key, &entry)?;
                let entries = self.entries.lock().expect("entries mutex");
                if entries.get(key).is_none() {
                    return Ok(BudgetedHold::Absent);
                }
                continue;
            }

            let (derived, freshly_derived) = match self.derive(key, &entry, gate) {
                // A cold key the batch cannot afford to dump right now. No dump
                // happened, so nothing is published and no unit was spent; the caller
                // answers Absent. This warms nothing, so it is a later, budget-bearing
                // probe reaching this key that finally dumps and caches it.
                Ok(DeriveStep::Deferred) => return Ok(BudgetedHold::Deferred),
                Ok(DeriveStep::Derived(derived, freshly_derived)) => (derived, freshly_derived),
                Err(error) => {
                    let entries = self.entries.lock().expect("entries mutex");
                    if entries
                        .get(key)
                        .is_some_and(|current| Arc::ptr_eq(current, &entry))
                    {
                        return Err(error);
                    }
                    drop(entries);
                    continue;
                }
            };
            let record = SupplyCatalogRecord {
                declared_size: derived.nar_size_uncompressed_nar,
                source: nar_dumper_sealed::Sealed::production_source(
                    self.dumper.as_ref(),
                    &entry.store_path,
                ),
                store_path: entry.store_path.as_path().to_path_buf(),
            };

            // Reacquire the registration map after the potentially slow dump.
            // Replacement/prune and publication all use entries->catalog order.
            // Pointer identity prevents a stale derivation from resurrecting a
            // retired provider record.
            let entries = self.entries.lock().expect("entries mutex");
            let still_current = entries
                .get(key)
                .is_some_and(|current| Arc::ptr_eq(current, &entry));
            if !still_current {
                drop(entries);
                continue;
            }
            if !self
                .supply_catalog
                .publish(&entry.supply_registration, derived.blake3, record)
            {
                return Err(AvailabilityError::Dump(DumpError(format!(
                    "active registration for {key} was retired before supply publication"
                ))));
            }
            // Persist the newly VERIFIED derived binding (task-82) so a restart can
            // serve this digest with no re-dump. Done ONCE, on the fresh transition,
            // while we already hold the map lock (correct map->... order); it reads
            // each entry's leaf `persisted_derived`, never a digest lock, so it never
            // blocks the map lock on a dump. Best-effort: the derived value is an
            // optimisation, not a source of truth, so a persist failure is logged
            // LOUD but does NOT fail the serve - the node can still hand over these
            // bytes; the only cost is a re-derive on the next boot (pre-task-82
            // behaviour). The in-memory warm state is unaffected.
            if freshly_derived && let Err(error) = self.persist_locked(&entries) {
                eprintln!(
                    "daemon: availability index: persisting the verified derived binding \
                     for {key} failed ({error}); it will be re-derived after a restart"
                );
            }
            drop(entries);
            return Ok(BudgetedHold::Have {
                blake3: derived.blake3,
                offers: vec![self.iroh_offer()],
            });
        }
    }

    /// The NarSize this node would produce for `blake3`, answered WITHOUT
    /// producing it - the admission question a serve budget asks. `None` means
    /// this node cannot supply it.
    ///
    /// The materialisation check is repeated here, not assumed from the cached
    /// derivation: a path GC'd since the digest was computed must drop out of
    /// SUPPLY at the same instant it drops out of [`Self::hold`], or the two sets
    /// diverge again in the one direction that matters (we would promise a serve
    /// we cannot perform).
    ///
    /// STALE-SIZE NOTE (task-82, the honest-limit (b) envelope). Only EXISTENCE is
    /// re-checked here; the returned size is the persisted/derived `declared_size`,
    /// trusted WITHOUT a recheck - rechecking would mean a dump, defeating the whole
    /// "answer without producing" point. For an immutable `/nix/store` path that is
    /// always exact. For a rewritten raw-file-backed path (the non-production
    /// exception) it can be a STALE size, so a serve budget could admit against the
    /// wrong number. That stays inside the same envelope as the wrong-claim limit: it
    /// never yields wrong BYTES, because the actual byte serve
    /// ([`Self::supply_raw_nar_cancellable`]) re-dumps and fails loud on
    /// `BLAKE3 != announced` before a byte leaves. Accepted for the prototype;
    /// tightening it (an mtime guard / a bounded re-stat) is a follow-up, not a
    /// correctness gap.
    pub fn supply_size_cancellable(
        &self,
        blake3: &Blake3Digest,
        cancellation: &dyn CancellationCheck,
    ) -> Result<Option<u64>, AvailabilityError> {
        if cancellation.is_cancelled() {
            return Err(AvailabilityError::Dump(DumpError(
                "NAR size probe cancelled".into(),
            )));
        }
        let Some(record) = self.supply_catalog.read_handle().probe_record(blake3) else {
            return Ok(None);
        };
        match std::fs::metadata(&record.store_path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(AvailabilityError::Dump(DumpError(format!(
                    "checking store path {} for supply: {error}",
                    record.store_path.display()
                ))));
            }
        }
        if cancellation.is_cancelled() {
            return Err(AvailabilityError::Dump(DumpError(
                "NAR size probe cancelled".into(),
            )));
        }
        Ok(Some(record.declared_size))
    }

    /// Regenerate the exact `RawNarV1` bytes for `blake3` from the real store.
    /// This is the task-61 supply model's producer: no copy is retained, the dump
    /// happens now.
    ///
    /// FAILS LOUD on a mismatch. A store path that no longer dumps to the digest
    /// it was announced under is not "close enough" - serving it would hand a peer
    /// the wrong blob under the right name, and the caller must decline rather
    /// than let iroh-blobs discover it mid-stream.
    pub fn supply_raw_nar_cancellable(
        &self,
        blake3: &Blake3Digest,
        cancellation: &dyn CancellationCheck,
    ) -> Result<Vec<u8>, AvailabilityError> {
        if cancellation.is_cancelled() {
            return Err(AvailabilityError::Dump(DumpError(
                "NAR supply cancelled".into(),
            )));
        }
        let record = self
            .supply_catalog
            .read_handle()
            .probe_record(blake3)
            .ok_or_else(|| {
                AvailabilityError::Dump(DumpError(format!(
                    "no registered holding supplies {blake3}"
                )))
            })?;
        let store_path = StorePath::new(record.store_path);
        let raw_nar = self.dumper.dump(&store_path, cancellation)?;
        if cancellation.is_cancelled() {
            return Err(AvailabilityError::Dump(DumpError(
                "NAR supply cancelled".into(),
            )));
        }
        let actual = Blake3Digest::from_raw_nar(&raw_nar);
        if actual != *blake3 {
            return Err(AvailabilityError::Dump(DumpError(format!(
                "{} now dumps to {actual}, not the announced {blake3}",
                store_path
            ))));
        }
        Ok(raw_nar)
    }

    /// Withdraw every supply binding that points at `gone`, so a registration the
    /// index has disowned stops being servable at the same instant.
    ///
    /// By POINTER IDENTITY, not by digest: the caller holds the exact `Arc` that
    /// was removed, and matching on the digest would mean recomputing it (a dump)
    /// on a path whose whole purpose is to forget. Called with the `entries` lock
    /// held, which fixes the lock order as entries-then-by_digest everywhere.
    fn retire_supply_registration(&self, gone: &Arc<Entry>) {
        self.supply_catalog.retire(&gone.supply_registration);
    }

    /// Return the inert, read-only provider catalog. It cannot derive, mutate,
    /// persist, announce, or reach an [`AvailabilityIndex`] entry.
    pub fn supply_catalog(&self) -> SupplyCatalogHandle {
        self.supply_catalog.read_handle()
    }

    /// The versioned wire envelope for a single [`HoldQuery`] probe from an
    /// authenticated `asker`, bounded by the per-peer/global `ledger` (task-229). The
    /// RESPONDER single-key path: unlike [`hold`](Self::hold) (the LOCAL self-probe,
    /// which is never bounded), a single-key probe FROM A PEER draws the same per-peer
    /// byte+count budget the batch path does, so a single-key `hold`-query FLOOD is
    /// bounded, not unlimited. A cold key past the asker's budget is answered `Absent`
    /// (the safe direction), never a false `Have`.
    ///
    /// `asker` is the AUTHENTICATED remote peer identity (the libp2p `PeerId` / iroh
    /// [`NodeId`], the cryptographic connection identity the fabric hands the responder),
    /// so the bound is keyed on an identity a peer cannot forge.
    pub fn answer_for_peer(
        &self,
        query: &HoldQuery,
        asker: &NodeId,
        ledger: &PeerDeriveLedger,
    ) -> Result<HoldResponse, AvailabilityError> {
        // PRECONDITION: `query` is a DECODED, version-checked probe - the wire path
        // gates it in `decode_hold_query`, so by construction its version is current.
        // This is a `debug_assert` (not a hard reject) because `answer` has no version
        // error to return and is not itself the wire boundary; a caller must not hand
        // it a raw, unvalidated query. The response is always emitted at this build's
        // `QUERY_SCHEMA_VERSION`.
        debug_assert_eq!(query.schema_version, QUERY_SCHEMA_VERSION);
        // A single-key probe triggers at most one dump, so the per-message COUNT
        // allowance is unlimited; the per-peer LEDGER is what bounds a single-key flood.
        let mut gate = DeriveGate::for_peer(BatchDeriveAllowance::unlimited(), asker, ledger);
        let answer = match self.hold_budgeted(&query.key, &mut gate)? {
            BudgetedHold::Have { blake3, offers } => HoldAnswer::Have { blake3, offers },
            // Genuinely absent OR deferred past the asker's per-peer/global budget: both
            // answer `Absent` on the wire (the safe direction - never a false `Have`).
            BudgetedHold::Absent | BudgetedHold::Deferred => HoldAnswer::Absent,
        };
        Ok(HoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            answer,
        })
    }

    /// Answer a BATCHED probe (task-91): one positional yes/no per key asked, in
    /// the asker's order, plus this node's transport offers hoisted out of them.
    ///
    /// NO ENUMERATION, and it is worth being explicit because the shape resembles
    /// a listing: every element of the returned vector is derived from a key the
    /// CALLER supplied, and the vector carries no keys of its own. There is still
    /// no method here - or on any type this module exposes - that yields the
    /// index's keys, its length, or any holding the caller did not name.
    ///
    /// WHY THERE IS NO ERROR CHANNEL. A per-key fault (a `nix-store --dump`
    /// failure, a persist failure while pruning a GC'd path) answers `Absent` for
    /// THAT key and is logged. This is deliberate and it is not error-swallowing:
    /// it keeps the blast radius of a fault exactly what it is on the single-key
    /// path, where a failed probe costs that one key and no other. Propagating
    /// instead would let one broken store path deny a peer a whole 200-path
    /// closure - a strictly worse outcome created by batching, which is precisely
    /// what batching must not do. `Absent` is also the SAFE direction: it can only
    /// cost a p2p hit (the fetch falls back upstream), never a wrong byte.
    ///
    /// THE CAP IS ENFORCED HERE, NOT ASSUMED. It used to be a `debug_assert`, i.e.
    /// a caller precondition that vanishes in a release build - so a single wrong
    /// call site could make this node do 12 000 `nix-store --dump`s for one
    /// message. It is now a hard refusal reusing the wire's own rule
    /// ([`crate::claim::check_batch_keys`] via `encode_batch_hold_query`'s error
    /// type), because the bound belongs to the message, not to the politeness of
    /// whoever calls this. There is no truncation: answering the first 256 keys of
    /// a 300-key batch would be a silent wrong "no" for the other 44.
    ///
    /// The per-KEY fault policy above is unchanged and is deliberately NOT this
    /// error channel: a broken store path degrades one key to `Absent`, while a
    /// malformed batch is refused whole.
    ///
    /// THE DERIVATION BUDGET (task-104). The key cap bounds how many probes a
    /// message demands, but on a COLD responder each probe can cost one
    /// `nix-store --dump` of a large NAR, so a 256-key batch could otherwise make
    /// this node dump 256 large NARs for ONE message. This method therefore answers
    /// freely from what is ALREADY derived and triggers at most
    /// [`MAX_BATCH_DERIVE_WORK`] FRESH dumps per batch (a bound on the COUNT of dumps,
    /// never on a clock - raising the probe timeout is forbidden by task-40; see the
    /// const docs for what a dump COUNT does and does not bound). Once the budget is
    /// spent, further COLD keys answer `Absent` WITHOUT dumping - the same safe
    /// direction a miss already takes, and NO wire change (Absent is an existing
    /// answer; the frozen claim wire and its golden vectors are untouched).
    ///
    /// THE UNDER-REPORT, MEASURED (AC#2, honestly). A wholly-cold `N`-key batch
    /// answers at most [`MAX_BATCH_DERIVE_WORK`] keys truthfully and under-reports the
    /// other `N - MAX_BATCH_DERIVE_WORK` as `Absent` (bounded, safe direction). It is
    /// NOT silent - the deferral count is logged. It does NOT self-heal for the ASKER
    /// of this probe: [`crate::discovery::DirectDiscovery::resolve_many`] treats
    /// `Absent` as a miss and falls back UPSTREAM; it does not re-probe the deferred
    /// keys. What heals is the RESPONDER'S cache: this probe dumps and caches
    /// [`MAX_BATCH_DERIVE_WORK`] cold keys, so a LATER organic query of those paths
    /// (a subsequent build, or the same closure re-queried) finds them warm. A single
    /// asker that keeps re-querying the same closure sees the warm frontier advance
    /// ~[`MAX_BATCH_DERIVE_WORK`] keys per probe, so all `N` are warm after
    /// ~`ceil(N / MAX_BATCH_DERIVE_WORK)` probes - but nothing in the resolver drives
    /// that re-query, so treat it as cache warming for future traffic, not as
    /// first-contact healing. RESIDUAL: this per-MESSAGE bound does not cap the
    /// aggregate dumps many messages from one peer can start (the peer picks the
    /// message boundaries) - a per-peer aggregate limit is the follow-up (task-72's
    /// serve budget bounds bytes served, not bytes hashed).
    ///
    /// task-229: `asker` is the AUTHENTICATED remote peer, and `ledger` bounds its
    /// AGGREGATE derivation across ALL the messages it sends (bytes hashed AND dump
    /// count, over a TUMBLING window — cap per window in steady state, up to 2x cap
    /// across a boundary; true sliding window is TASK-243) plus a GLOBAL ceiling across all peers. So the
    /// per-MESSAGE [`MAX_BATCH_DERIVE_WORK`] count above is only the inner cap; the
    /// cross-message per-peer/global bound is what actually stops a hostile peer that
    /// picks the message boundaries. Each cold key is refused BEFORE dumping when its
    /// NarSize would exceed the remaining budget (R1). An over-budget key answers
    /// `Absent` exactly like the per-message deferral - same safe direction, no false
    /// `Have`, no wire change.
    pub fn answer_batch_for_peer(
        &self,
        query: &BatchHoldQuery,
        asker: &NodeId,
        ledger: &PeerDeriveLedger,
    ) -> Result<BatchHoldResponse, ClaimCodecError> {
        let (response, notes) = self.answer_batch_reporting(query, asker, ledger)?;
        // Emit the AGGREGATED operator notes (task-107 M3). At most one line per
        // fault CLASS for the WHOLE message, never one per key: a responder whose
        // store was GC'd out from under it - or a peer deliberately naming keys it
        // knows will fault - could otherwise make ONE 91-byte query print up to
        // MAX_BATCH_HOLD_KEYS near-identical lines (log amplification a remote peer
        // provokes). The decision of WHICH bounded set of lines to emit lives in
        // `answer_batch_reporting`, which RETURNS them so it can be tested in
        // process; this method is only the effect.
        for note in &notes {
            eprintln!("{note}");
        }
        Ok(response)
    }

    /// The core of [`Self::answer_batch_for_peer`] that RETURNS the operator notes instead
    /// of printing them (task-107 M3). Separating the DECISION (which bounded set
    /// of lines a batch should log) from the EFFECT (the `eprintln!`s) is what makes
    /// the "at most one line per fault class, never one per key" property testable
    /// without capturing stderr: a test provokes many per-key faults and asserts the
    /// returned `notes.len()` stays small. `notes` is empty on the happy path (a
    /// `Vec::new()` allocates nothing until a fault or deferral pushes), so the
    /// aggregation costs nothing when every key is answered cleanly.
    fn answer_batch_reporting(
        &self,
        query: &BatchHoldQuery,
        asker: &NodeId,
        ledger: &PeerDeriveLedger,
    ) -> Result<(BatchHoldResponse, Vec<String>), ClaimCodecError> {
        debug_assert_eq!(query.schema_version, QUERY_SCHEMA_VERSION);
        check_batch_keys(&query.keys)?;

        // One gate for the WHOLE batch: a per-MESSAGE fresh-dump count allowance
        // (task-104) plus the peer-attributed cross-message byte/count ledger (task-229).
        // Every key in this message draws down BOTH; the tighter one defers.
        let mut gate = DeriveGate::for_peer(
            BatchDeriveAllowance::limited(MAX_BATCH_DERIVE_WORK),
            asker,
            ledger,
        );
        let mut answers = Vec::with_capacity(query.keys.len().min(MAX_BATCH_HOLD_KEYS));
        let mut any_have = false;
        let mut deferred: u32 = 0;
        // AGGREGATE the per-key faults (task-107 M3): count them and keep only the
        // FIRST offender's context, so the whole message costs ONE summary line, not
        // one eprintln per faulting key.
        let mut faulted: u32 = 0;
        let mut first_fault: Option<String> = None;
        for key in &query.keys {
            match self.hold_budgeted(key, &mut gate) {
                Ok(BudgetedHold::Have { blake3, .. }) => {
                    any_have = true;
                    // This node speaks exactly one transport, so every Have points
                    // at the single dictionary entry below. The INDEX is what binds
                    // a locator to a key: when a second transport arrives (task-75
                    // BitTorrent, whose infohash is per-CONTENT, not per-peer) each
                    // Have gains its own entry here and nothing else changes.
                    answers.push(BatchHoldAnswer::Have {
                        blake3,
                        offer_indices: vec![0],
                    });
                }
                Ok(BudgetedHold::Absent) => answers.push(BatchHoldAnswer::Absent {}),
                // COLD but the batch's derivation budget is spent: NOT dumped, answered
                // Absent on the wire (todays behaviour), counted so the deferral is
                // reported rather than silent. It warms on a subsequent probe.
                Ok(BudgetedHold::Deferred) => {
                    deferred = deferred.saturating_add(1);
                    answers.push(BatchHoldAnswer::Absent {});
                }
                Err(err) => {
                    // Loud, but AGGREGATED (task-107 M3): record the count and the
                    // first offender's context here, and emit ONE summary line for the
                    // whole batch below - never one eprintln per key, which a remote
                    // peer could otherwise provoke up to MAX_BATCH_HOLD_KEYS times with
                    // a single message.
                    faulted = faulted.saturating_add(1);
                    if first_fault.is_none() {
                        first_fault = Some(format!("{key} ({err})"));
                    }
                    answers.push(BatchHoldAnswer::Absent {});
                }
            }
        }

        // The bounded operator notes: at most one line per fault CLASS, each naming
        // its COUNT (and, for faults, the first offender), so a 256-key message that
        // faults on every key still logs a fixed, small number of lines.
        let mut notes = Vec::new();
        if faulted > 0 {
            notes.push(format!(
                "daemon: batch hold-query: {faulted} key(s) could not be answered \
                 (answered Absent for each); first: {}",
                first_fault.as_deref().unwrap_or("<unknown>")
            ));
        }
        if deferred > 0 {
            // LOUD, not silent (the task-104 point): the operator sees that this batch
            // under-reported `deferred` COLD key(s) because it hit a derivation bound -
            // either the per-message count (MAX_BATCH_DERIVE_WORK) or the per-peer/global
            // byte+count ledger (task-229). Those keys were NOT dumped this time; a later
            // probe that reaches them dumps and caches them, so a subsequent organic
            // query finds them warm (the asker of THIS probe falls back upstream).
            notes.push(format!(
                "daemon: batch hold-query: {deferred} cold key(s) exceeded a derivation \
                 bound (per-message MAX_BATCH_DERIVE_WORK={MAX_BATCH_DERIVE_WORK} or the \
                 per-peer/global byte budget); answered Absent without dumping - they warm \
                 the responder cache on a later, budget-bearing probe"
            ));
        }

        let response = BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            // This node's iroh locator is genuinely peer-scoped, so it appears
            // ONCE and every Have indexes it - and only when at least one answer is
            // a Have, because a dictionary entry no answer references is rejected
            // by the codec precisely so an all-absent response cannot volunteer a
            // locator for content the asker never named.
            offers: if any_have {
                vec![self.iroh_offer()]
            } else {
                Vec::new()
            },
            answers,
        };
        Ok((response, notes))
    }

    /// Produce the COMPLETE claim for `key` if this node holds it: the BLAKE3 to
    /// address the blob PLUS this node as holder and an `Iroh` transport offer, so a
    /// downstream fetch has everything (the task-40 review finding: a resolve must
    /// return the whole offer, not merely a holder). `None` if not held.
    pub fn claim(&self, key: &NarHashKey) -> Result<Option<Claim>, AvailabilityError> {
        match self.hold(key)? {
            HoldAnswer::Have { blake3, offers } => Ok(Some(Claim {
                schema_version: CLAIM_SCHEMA_VERSION,
                key: *key,
                payload: Some(KnownPayload::WholeNar { blake3 }),
                holders: vec![self.node_id],
                transports: offers,
                relay: None,
                signatures: vec![],
            })),
            HoldAnswer::Absent => Ok(None),
        }
    }

    /// announce-on-demand: if `key` is available, produce its complete claim and
    /// hand it to the announce sink, returning the claim. `None` (and no announce)
    /// if not held. task-40's discovery drives this when a path lands.
    pub fn publish(&self, key: &NarHashKey) -> Result<Option<Claim>, AvailabilityError> {
        match self.claim(key)? {
            Some(claim) => {
                self.announce.announce(claim.clone());
                Ok(Some(claim))
            }
            None => Ok(None),
        }
    }

    /// Drop a registration UNCONDITIONALLY (e.g. an operator retiring a holding) and
    /// persist the removal. For the lazy GC-prune on the read path use
    /// [`drop_if_same`](Self::drop_if_same), which will not clobber a concurrently
    /// re-registered entry. Persist-ordering caveat as in [`register`](Self::register):
    /// on a save failure the in-memory removal has already happened while disk still
    /// has the entry, so a restart reloads it; the caller sees the `Err`.
    pub fn unregister(&self, key: &NarHashKey) -> Result<(), PersistError> {
        let mut entries = self.entries.lock().expect("entries mutex");
        if let Some(removed) = entries.remove(key) {
            self.retire_supply_registration(&removed);
            self.persist_locked(&entries)?;
        }
        Ok(())
    }

    /// TASK-297 HIGH-B (self-heal the supply half of reconcile): drop `key`'s registration - and its
    /// supply-catalog record - IFF its store path has been GC'd since publication. Unlike the
    /// unconditional [`unregister`](Self::unregister), this is IDENTITY-SAFE against a concurrent
    /// re-register: the entry is observed under the lock, `exists()` is stat'd OUTSIDE the lock (as
    /// the read path does, so a stat never blocks the index), and the removal goes through the same
    /// pointer-identity [`drop_if_same`](Self::drop_if_same) the lazy read-path prune uses - so a path
    /// re-materialised into a FRESH entry between the observation and here is left alone (its path
    /// exists, or it is a different `Arc`). This lets the libp2p GC reconcile retire a stale supply
    /// record on a pure-direct-serve node, which never drives the responder `hold` path that would
    /// otherwise prune it lazily (without this, such a record persists inert-but-unbounded until
    /// restart).
    pub fn prune_if_gone(&self, key: &NarHashKey) -> Result<(), PersistError> {
        let observed = {
            let entries = self.entries.lock().expect("entries mutex");
            entries.get(key).map(Arc::clone)
        };
        if let Some(observed) = observed
            && !observed.store_path.exists()
        {
            self.drop_if_same(key, &observed)?;
        }
        Ok(())
    }

    /// Prune `key` ONLY if its current entry is still the exact `Arc` the caller
    /// observed (pointer identity), so a concurrent [`register`](Self::register) that
    /// swapped in a fresh, materialised entry between the observation and here is not
    /// clobbered. This is the safe lazy-GC prune used by [`hold`](Self::hold).
    fn drop_if_same(&self, key: &NarHashKey, observed: &Arc<Entry>) -> Result<(), PersistError> {
        let mut entries = self.entries.lock().expect("entries mutex");
        match entries.get(key) {
            Some(current) if Arc::ptr_eq(current, observed) => {
                entries.remove(key);
                self.retire_supply_registration(observed);
                self.persist_locked(&entries)?;
            }
            // A concurrent register replaced (or a concurrent drop already removed)
            // the entry: leave the newer state alone.
            _ => {}
        }
        Ok(())
    }

    /// The single-flight compute: return the cached outcome or, exactly once,
    /// `dump` + hash + VERIFY it UNDER the entry lock. Concurrent callers for the
    /// same uncomputed key block here and observe the cached `Some`; distinct keys
    /// use distinct locks and hash in parallel. A dump failure leaves the slot
    /// `None` so the next caller retries; a definite verdict (verified OR
    /// quarantined) is cached.
    ///
    /// task-56 SOURCE-SIDE VERIFICATION: `key` is the registered Nix NarHash. The
    /// NarHash is `sha256(RawNarV1)` over the EXACT `--dump` bytes we already have
    /// buffered for BLAKE3, so we re-derive it here IN THE SAME PASS (no second
    /// dump - per-serve RSS is a concern, see task-72/157/158) and assert it equals
    /// `key`. If it does not, the caller bound key X to a path whose real NarHash is
    /// Y: we must NOT answer a positive `Have` for X (that is the false claim that
    /// costs a peer a wasted dial), so the entry is QUARANTINED and every probe of
    /// it fails loudly with a typed [`NarHashMismatch`]. The comparison is raw-byte
    /// (`NarHashKey == NarHashKey`), so there is no encoding to get wrong.
    /// Returns [`DeriveStep::Derived`] with the derivation and whether it was FRESHLY
    /// computed on this call (`true`) or served from the single-flight cache / a
    /// warmed persisted binding (`false`); the caller ([`Self::hold_budgeted`]) uses
    /// the flag to persist the verified derived binding to disk exactly ONCE - on the
    /// fresh transition - rather than rewriting the whole snapshot on every probe.
    ///
    /// task-104: a COLD key (its digest slot is `None`, so answering it needs a fresh
    /// dump) reserves one unit of the per-message COUNT allowance ATOMICALLY under the
    /// digest lock right before dumping. If it is spent, [`DeriveStep::Deferred`]
    /// WITHOUT dumping - so the number of `nix-store --dump`s one batch triggers is
    /// hard-capped at the allowance, not the batch's key count.
    ///
    /// task-229: for a PEER-ATTRIBUTED gate a cold key is ALSO admitted against the
    /// per-peer/global byte+count [`PeerDeriveLedger`], seeded by the NarSize this path
    /// WOULD dump to - queried WITHOUT dumping ([`NarDumper::nar_size`]) - so an
    /// over-budget probe is REFUSED for a COST OF A STAT, never a multi-GB hash (R1:
    /// refuse before dump). The ledger keys on the authenticated asker and carries a
    /// global ceiling, so a cross-message per-peer flood and a many-identity Sybil flood
    /// are both bounded (R2 + the Sybil floor). Order under the digest lock: NarSize
    /// query, then count allowance, then ledger admission; any refusal defers WITHOUT
    /// dumping. A WARM key (Verified or Quarantined) returns from the cache before ANY
    /// of this, so it neither dumps, spends a count unit, nor draws byte budget - warm
    /// answers are free, exactly as the serve gate only charges bytes actually served. A
    /// LOCAL self-probe gate carries no ledger and an unlimited count, so it never
    /// defers.
    fn derive(
        &self,
        key: &NarHashKey,
        entry: &Entry,
        gate: &mut DeriveGate,
    ) -> Result<DeriveStep, AvailabilityError> {
        let mut slot = entry.digest.lock().expect("digest mutex");
        match &*slot {
            Some(DeriveOutcome::Verified(derived)) => {
                return Ok(DeriveStep::Derived(*derived, false));
            }
            Some(DeriveOutcome::Quarantined(mismatch)) => {
                return Err(AvailabilityError::NarHashMismatch(mismatch.clone()));
            }
            None => {}
        }
        // COLD: a fresh dump is required. Gate it HERE - under the digest lock,
        // immediately before the dump - so the decision and the dump are atomic. A
        // refusal on ANY axis defers WITHOUT dumping (the safe direction: the caller
        // answers Absent, the key warms on a later, budget-bearing probe).
        //
        // The per-message COUNT allowance (task-104) is reserved FIRST, so it bounds not
        // just the dumps but also the NarSize queries below: a 256-key cold batch does at
        // most MAX_BATCH_DERIVE_WORK size-queries + dumps, never one per key. (If this
        // reserve succeeds but the ledger below refuses, the unit is spent without a dump
        // - a harmless under-count in the SAFE direction, fewer dumps this message.)
        if !gate.batch.try_reserve() {
            return Ok(DeriveStep::Deferred);
        }
        // R1 (task-229): for a peer-attributed gate, learn the NarSize the path WOULD dump
        // to WITHOUT dumping it, so the byte budget can REFUSE BEFORE the expensive dump.
        // The ledger keys on the authenticated asker (per-peer aggregate across messages)
        // and carries a global ceiling (the Sybil floor); on any refusal NOTHING is
        // charged and NO dump happens. A LOCAL self-probe (`gate.peer == None`) skips this
        // entirely - it is node-initiated, not peer-driven, and must always answer truly.
        if let Some((asker, ledger)) = gate.peer {
            let nar_size = self.dumper.nar_size(&entry.store_path, &NeverCancelled)?;
            if !matches!(ledger.try_admit(asker, nar_size), DeriveAdmission::Admitted) {
                return Ok(DeriveStep::Deferred);
            }
        }
        let raw_nar = self.dumper.dump(&entry.store_path, &NeverCancelled)?;
        // Verify the caller's binding BEFORE trusting the dump. sha256 of the same
        // buffer that BLAKE3 will hash: honest registration => this equals `key`.
        let computed = NarHashKey::from_raw_nar(&raw_nar);
        if computed != *key {
            let mismatch = NarHashMismatch {
                registered: *key,
                computed,
                store_path: entry.store_path.clone(),
            };
            // Cache the QUARANTINE (a deterministic verdict), so a mis-registered
            // key is not re-dumped on every probe. Loud, typed, never a false Have.
            // A quarantine is NEVER mirrored into `persisted_derived` and NEVER
            // persisted (task-82): persisting an unverified binding would make a
            // mis-registration durable across a restart, the exact trap to avoid.
            *slot = Some(DeriveOutcome::Quarantined(mismatch.clone()));
            return Err(AvailabilityError::NarHashMismatch(mismatch));
        }
        // The frozen recipe, applied in exactly one place: BLAKE3(RawNarV1), plain
        // and unkeyed, over the uncompressed dump - matches the task-48 golden. The
        // NarSize is read off the SAME buffer rather than stat'ed separately, so it
        // cannot describe different bytes than the digest does.
        let derived = DerivedNar {
            blake3: Blake3Digest::from_raw_nar(&raw_nar),
            nar_size_uncompressed_nar: raw_nar.len() as u64,
        };
        *slot = Some(DeriveOutcome::Verified(derived));
        // Mirror the VERIFIED derivation into the leaf field so `persist_locked` can
        // snapshot it under the map lock without ever taking a digest lock. Locking
        // the leaf here (while holding `digest`) is the digest->leaf order; the leaf
        // is a pure sink that acquires nothing, so no cycle is possible.
        *entry
            .persisted_derived
            .lock()
            .expect("persisted-derived mutex") = Some(derived);
        Ok(DeriveStep::Derived(derived, true))
    }

    /// This node's iroh transport offer (a pure locator: just the NodeId).
    fn iroh_offer(&self) -> KnownTransport {
        KnownTransport::Iroh { node: self.node_id }
    }

    /// Persist the current registration set. Called with the entries map lock held
    /// so a concurrent register/drop cannot interleave a torn snapshot.
    ///
    /// The VERIFIED derived binding for each entry is read from the LEAF
    /// `persisted_derived` mutex - NEVER the `digest` slot - so this never blocks the
    /// map lock on an in-flight NAR dump (a `digest` lock can be held for the whole
    /// dump). An entry whose digest is still uncomputed, or was quarantined,
    /// contributes `derived: None` and persists only its source path.
    ///
    /// TASK-189 (durable-state-file hardening, defense-in-depth beyond the TCB line -
    /// explicitly NOT a task-82 gate): a per-binding integrity check (checksum/MAC)
    /// so tamper/corruption FAILS LOUD at load instead of warm-loading as `Verified`;
    /// a one-way downgrade-compat guard for the [`StoredValue`] shape (a new-format
    /// snapshot cannot be silently mis-read by an old binary); a persisted quarantine
    /// verdict (currently in-memory only, an optimisation); and folding this whole-
    /// snapshot O(N)-per-mutation rewrite into a single atomic durable-state file.
    fn persist_locked(
        &self,
        entries: &HashMap<NarHashKey, Arc<Entry>>,
    ) -> Result<(), PersistError> {
        let snapshot: Vec<PersistedRegistration> = entries
            .iter()
            .map(|(key, entry)| PersistedRegistration {
                key: *key,
                store_path: entry.store_path.clone(),
                derived: *entry
                    .persisted_derived
                    .lock()
                    .expect("persisted-derived mutex"),
            })
            .collect();
        self.store.save(&snapshot)
    }
}

impl Drop for AvailabilityIndex {
    fn drop(&mut self) {
        // A provider may retain a read handle after the index owner is dropped.
        // Explicitly retire every current registration so that handle becomes
        // inert instead of extending availability state by accident.
        let entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => poisoned.into_inner(),
        };
        for entry in entries.values() {
            self.supply_catalog.retire(&entry.supply_registration);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temp file that EXISTS (so the index does not short-circuit a probe to
    /// `Absent` on a missing path) and removes itself on drop.
    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(tag: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "nixp2p-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock after epoch")
                    .as_nanos()
            ));
            std::fs::write(&path, b"present").expect("write temp file");
            TempFile(path)
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn node() -> NodeId {
        NodeId::from_bytes([0x11; 32])
    }

    fn asker() -> NodeId {
        NodeId::from_bytes([0x22; 32])
    }

    /// TASK-297 HIGH-B (reconcile self-heals the supply half): `prune_if_gone` drops a registration
    /// whose store path has been GC'd since publication, so a stale supply record does not persist on
    /// a pure-direct-serve node (which never drives the responder `hold` path that would prune it
    /// lazily). Observed on the `entries` map directly, so hold's own lazy prune cannot mask it.
    ///
    /// MUTATION: make `prune_if_gone` a no-op (or drop its `!store_path.exists()` -> `drop_if_same`
    /// removal) and the GC'd entry survives here - RED.
    #[test]
    fn prune_if_gone_drops_a_gc_removed_registration() {
        let present = TempFile::new("prune-gone");
        let index = AvailabilityIndex::open(
            node(),
            Arc::new(MemoryNarDumper::new(b"unused".to_vec())),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("open index");
        let key = NarHashKey::from_sha256_bytes([0x7c; 32]);
        index
            .register(key, StorePath::new(present.0.clone()))
            .expect("register");
        assert!(
            index.entries.lock().expect("entries").contains_key(&key),
            "the registration exists while its store path exists"
        );

        // GC the store path, then reconcile-prune the registration.
        std::fs::remove_file(&present.0).expect("simulate GC");
        index
            .prune_if_gone(&key)
            .expect("prune a GC'd registration");
        assert!(
            !index.entries.lock().expect("entries").contains_key(&key),
            "prune_if_gone must drop a registration whose store path was GC'd"
        );
    }

    /// TASK-297 HIGH-B (identity/existence-safety): `prune_if_gone` must NOT drop a registration whose
    /// store path still EXISTS - the guard against clobbering a concurrent re-register. This is the
    /// direct mutation bite mped-architect required: swap the identity-safe body for the unconditional
    /// [`AvailabilityIndex::unregister`] and a live registration is wrongly dropped here - RED.
    #[test]
    fn prune_if_gone_keeps_a_live_registration() {
        let present = TempFile::new("prune-live");
        let index = AvailabilityIndex::open(
            node(),
            Arc::new(MemoryNarDumper::new(b"unused".to_vec())),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("open index");
        let key = NarHashKey::from_sha256_bytes([0x4d; 32]);
        index
            .register(key, StorePath::new(present.0.clone()))
            .expect("register");

        index
            .prune_if_gone(&key)
            .expect("prune is a no-op for a live path");
        assert!(
            index.entries.lock().expect("entries").contains_key(&key),
            "prune_if_gone must leave a registration whose store path still exists (a re-materialised \
             path must survive; unconditional unregister would clobber it)"
        );
    }

    /// TASK-107 M3 bite: a batch that FAULTS on many keys must emit a BOUNDED number
    /// of log lines - one aggregate per fault class - not one line per key.
    ///
    /// The fault provoked is a `NarHash` MISMATCH (a registered key that does not
    /// equal the sha256 of the dumped bytes): the index quarantines it and the
    /// per-key path returns `Err`, which is exactly the arm task-107 M3 aggregates.
    /// Every faulting key points at the SAME existing file dumped by an in-memory
    /// dumper, so each independently mismatches. The per-batch derivation budget
    /// (`MAX_BATCH_DERIVE_WORK`) caps how many keys actually dump-and-fault, so we
    /// register a few MORE than the budget: the surplus defers, giving us BOTH fault
    /// classes in one message.
    ///
    /// MUTATION PROOF: revert `answer_batch_reporting` to push one note per faulting
    /// key (the pre-fix `eprintln!`-per-key amplification) and `notes` grows to
    /// `MAX_BATCH_DERIVE_WORK` fault lines instead of one, failing the `== 1` assert.
    #[test]
    fn batch_fault_logging_is_aggregated_not_one_line_per_key() {
        let present = TempFile::new("m3-fault");
        let dumped = b"in-memory nar bytes the lied keys do not hash to".to_vec();
        let honest_key = NarHashKey::from_raw_nar(&dumped);

        let index = AvailabilityIndex::open(
            node(),
            Arc::new(MemoryNarDumper::new(dumped)),
            Arc::new(NullStore),
            Arc::new(NullAnnounce),
        )
        .expect("open index");

        // More faulting keys than the derivation budget, so some fault (dump then
        // mismatch) and the rest defer (budget spent) - both fault classes at once.
        let total = (MAX_BATCH_DERIVE_WORK + 4) as usize;
        let mut keys = Vec::with_capacity(total);
        for i in 0..total {
            // A distinct, LIED key: from_sha256_bytes([tag; 32]) cannot equal the
            // sha256 of `dumped` (asserted once via honest_key), so every key
            // mismatches when dumped.
            let key = NarHashKey::from_sha256_bytes([(i as u8).wrapping_add(1); 32]);
            assert_ne!(key, honest_key, "the test key must be a LIED key");
            index
                .register(key, StorePath::new(present.0.clone()))
                .expect("register lied key");
            keys.push(key);
        }

        let query = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys,
        };
        // An UNLIMITED ledger so ONLY the per-message count (MAX_BATCH_DERIVE_WORK) bites
        // here - this bite is about task-107 log aggregation, not the task-229 ledger.
        let ledger = PeerDeriveLedger::unlimited();
        let (response, notes) = index
            .answer_batch_reporting(&query, &asker(), &ledger)
            .expect("a batch of faulting keys still returns a well-formed response");

        // Behaviour preserved: a faulting/deferred key answers Absent, never a false
        // Have, and an all-absent batch volunteers no locator.
        assert!(
            response
                .answers
                .iter()
                .all(|a| matches!(a, BatchHoldAnswer::Absent {})),
            "every faulting/deferred key must answer Absent: {:?}",
            response.answers
        );
        assert!(
            response.offers.is_empty(),
            "all-absent batch offers nothing"
        );

        // The BITE: the log is bounded to one line per fault CLASS (here: one fault
        // aggregate + one deferral aggregate = 2), NOT ~N. Without aggregation the
        // fault arm alone would emit MAX_BATCH_DERIVE_WORK lines.
        assert!(
            notes.len() <= 2,
            "the batch path must log at most one line per fault class, not per key; \
             got {} lines: {notes:?}",
            notes.len()
        );
        let fault_lines: Vec<&String> = notes
            .iter()
            .filter(|n| n.contains("could not be answered"))
            .collect();
        assert_eq!(
            fault_lines.len(),
            1,
            "exactly ONE aggregated fault line for the whole message: {notes:?}"
        );
        // The count is REPORTED (the aggregate is meaningful, not just quieter): the
        // budget bounds the faults at MAX_BATCH_DERIVE_WORK.
        assert!(
            fault_lines[0].contains(&format!("{MAX_BATCH_DERIVE_WORK} key(s)")),
            "the aggregate line must report the fault COUNT: {}",
            fault_lines[0]
        );
    }
}
