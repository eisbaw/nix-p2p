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
//! The ONE piece of durable state is a REGISTRATION:
//!
//! ```text
//!   NarHashKey  ->  StorePath          (persisted: "I hold this NAR, here")
//! ```
//!
//! Everything else is DERIVED from that registration plus the filesystem, and is
//! therefore NOT stored (single source of truth, no duplicated derived state):
//!
//!   * the addressed unit `BLAKE3(RawNarV1)` is `nix-store --dump <path>` piped
//!     through the frozen [`Blake3Digest::from_raw_nar`] recipe. It is a PURE
//!     function of the NAR bytes, so it is computed ON DEMAND, cached in memory
//!     under a single-flight lock, and simply recomputed after a restart. It is
//!     deliberately not persisted: caching a derived value invites staleness, and
//!     a warm-cache-on-disk is a later optimisation (see the honest limits below),
//!     not a correctness requirement.
//!   * AVAILABILITY (does the store path still exist?) is read from the filesystem
//!     at query time. A GC'd path therefore DROPS from availability with no active
//!     bookkeeping - the filesystem is the source of truth for existence, and a
//!     stale registration is pruned lazily when a query observes the gap.
//!
//! ## The two query shapes (yes/no ONLY - never enumeration)
//!
//!   * [`AvailabilityIndex::hold`] answers "do I hold this ONE NarHash?" -> a
//!     [`HoldAnswer`] (`Have{blake3, offers}` or `Absent`). [`AvailabilityIndex::answer`]
//!     wraps it in the versioned [`HoldResponse`] envelope for the wire.
//!     [`AvailabilityIndex::answer_batch`] (task-91) answers the same question
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
//! of 108k registered paths meant dial-then-fail. [`AvailabilityIndex::supply_size`]
//! and [`AvailabilityIndex::supply_raw_nar`] close that: a yes now implies a
//! regenerable NAR, because both are answered from the same registration through
//! the same materialisation check. Both are per-digest probes; nothing lists.
//!
//! ## Honest limits (forward-carried)
//!
//!   * [`CommandNarDumper`] BUFFERS the whole `nix-store --dump` stream to apply the
//!     frozen one-shot recipe as the single source of truth. For the wave-2 whole
//!     `/nix/store` a streaming `blake3::Hasher` over the child's stdout would bound
//!     memory; deferred as hardening (the recipe stays identical either way).
//!   * [`JsonFileStore`] rewrites the whole snapshot on every mutation. Fine for a
//!     test-scoped store; an append-log / sqlite is the scale answer.
//!   * The index is synchronous and holds the entry lock across the (blocking) dump.
//!     A caller on an async runtime should drive it via `spawn_blocking`. Making the
//!     dump itself async is deferred with the streaming change.
//!   * The `key -> store_path` binding is NOT verified at the source: `derive`
//!     computes only the BLAKE3, never re-derives `sha256(dump)` to assert it equals
//!     `key` (see [`AvailabilityIndex::register`]). Nix's gate 2 backstops it, but a
//!     source-side check would make a mis-registration fail loud here. Forward-carried
//!     (wants a sha256 pass over the NAR).
//!   * SEEDING (the eager kind) is external by design: producing a claim's `Iroh` offer does NOT put
//!     the blob into this node's iroh-blobs store. task-39's [`crate::transport_iroh::IrohProvider::seed`]
//!     is fed FROM this index (task-39/40/41 wire it); until then an announced offer
//!     is data-complete but a peer cannot yet fetch it end-to-end. [`AnnounceSink::announce`]
//!     also returns `()`, so a real discovery layer's announce FAILURE has no channel
//!     here - both are forward-carried to the task-40 discovery wiring.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::claim::{
    BatchHoldAnswer, BatchHoldQuery, BatchHoldResponse, CLAIM_SCHEMA_VERSION, Claim, HoldAnswer,
    HoldQuery, HoldResponse, KnownPayload, KnownTransport, MAX_BATCH_HOLD_KEYS, NarHashKey,
    QUERY_SCHEMA_VERSION,
};
use crate::content_id::Blake3Digest;
use crate::transport::NodeId;

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

/// Aggregate error surfaced by the index query path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvailabilityError {
    /// The store path could not be dumped/hashed.
    Dump(DumpError),
    /// The registration set could not be persisted.
    Persist(PersistError),
}

impl fmt::Display for AvailabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AvailabilityError::Dump(e) => write!(f, "{e}"),
            AvailabilityError::Persist(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AvailabilityError {}

impl From<DumpError> for AvailabilityError {
    fn from(e: DumpError) -> Self {
        AvailabilityError::Dump(e)
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
pub trait NarDumper: Send + Sync {
    /// Dump the store path's uncompressed NAR (the addressed unit's input bytes).
    fn dump(&self, path: &StorePath) -> Result<Vec<u8>, DumpError>;
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
    fn dump(&self, path: &StorePath) -> Result<Vec<u8>, DumpError> {
        let output = std::process::Command::new(&self.program)
            .arg("--dump")
            .arg(path.as_path())
            .output()
            .map_err(|e| {
                DumpError(format!(
                    "could not spawn {} --dump {}: {e}",
                    self.program.display(),
                    path
                ))
            })?;
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
}

// -------------------------------------------------------------------------
// The IndexStore seam: persist the registration set (source of truth).
// -------------------------------------------------------------------------

/// Persists the registration set `NarHashKey -> StorePath` so the index survives a
/// restart. Only the SOURCE OF TRUTH is stored; the derived BLAKE3 is not (it is
/// recomputed on demand). A SEAM so a test can persist to a temp file (proving
/// restart) or use a no-op store.
pub trait IndexStore: Send + Sync {
    /// Load the persisted registrations (empty if none yet). A malformed store is
    /// an ERROR, not silently-empty: a corrupt index must fail loud, not lose data.
    fn load(&self) -> Result<Vec<(NarHashKey, StorePath)>, PersistError>;

    /// Atomically replace the persisted registrations with `entries`.
    fn save(&self, entries: &[(NarHashKey, StorePath)]) -> Result<(), PersistError>;
}

/// A no-op store: the index is in-memory only (does not survive restart). Useful
/// for a node that re-derives its registrations from another source each boot.
pub struct NullStore;

impl IndexStore for NullStore {
    fn load(&self) -> Result<Vec<(NarHashKey, StorePath)>, PersistError> {
        Ok(Vec::new())
    }
    fn save(&self, _entries: &[(NarHashKey, StorePath)]) -> Result<(), PersistError> {
        Ok(())
    }
}

/// The real store: a single JSON file mapping the canonical `sha256:<base32>` key
/// to the store path. A `BTreeMap` so the on-disk form is SORTED and stable (a
/// clean diff, greppable), and the write is ATOMIC (temp file + rename) so a crash
/// mid-write never leaves a torn index.
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
    fn load(&self) -> Result<Vec<(NarHashKey, StorePath)>, PersistError> {
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
        let raw: BTreeMap<String, String> = serde_json::from_slice(&bytes).map_err(|e| {
            PersistError(format!(
                "{} is not a valid index file: {e}",
                self.path.display()
            ))
        })?;
        let mut out = Vec::with_capacity(raw.len());
        for (key_str, path_str) in raw {
            // Fail loud on a corrupt key rather than silently dropping a holding.
            let key: NarHashKey = key_str.parse().map_err(|e| {
                PersistError(format!(
                    "{} holds a non-canonical NarHash key {key_str:?}: {e}",
                    self.path.display()
                ))
            })?;
            out.push((key, StorePath::new(path_str)));
        }
        Ok(out)
    }

    fn save(&self, entries: &[(NarHashKey, StorePath)]) -> Result<(), PersistError> {
        let mut map = BTreeMap::new();
        for (key, path) in entries {
            // A non-UTF8 store path fails loud rather than being lossily corrupted.
            let path_str = path
                .as_path()
                .to_str()
                .ok_or_else(|| PersistError(format!("store path {path} is not valid UTF-8")))?;
            map.insert(key.to_string(), path_str.to_string());
        }
        let json = serde_json::to_vec_pretty(&map)
            .map_err(|e| PersistError(format!("serialising the index: {e}")))?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| PersistError(format!("creating {}: {e}", parent.display())))?;
        }
        // Atomic replace: write a sibling temp file, then rename over the target.
        let tmp = self
            .path
            .with_extension(format!("tmp-{}", std::process::id()));
        std::fs::write(&tmp, &json)
            .map_err(|e| PersistError(format!("writing {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            // Best-effort cleanup so a failed rename does not litter temp files.
            let _ = std::fs::remove_file(&tmp);
            PersistError(format!(
                "renaming {} -> {}: {e}",
                tmp.display(),
                self.path.display()
            ))
        })?;
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

/// One registered holding: the store path (source of truth) and the single-flight
/// cache of what its dump derives.
struct Entry {
    store_path: StorePath,
    /// The derived [`DerivedNar`], computed UNDER this lock exactly once. The
    /// lock IS the single-flight guard: concurrent callers block here while the
    /// first one dumps + hashes.
    digest: Mutex<Option<DerivedNar>>,
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
    /// `Blake3Digest -> Entry`: the SUPPLY direction (task-72 AC#2). It is the
    /// same entries, indexed the other way, and it is DERIVED - populated as a
    /// side effect of computing a digest, never persisted, rebuilt on demand.
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
    /// It is PRUNED with the registration it came from ([`Self::forget_supply_bindings`]),
    /// so supply can never outlive hold. Without that, a store path that was
    /// un-registered but still present on disk stayed fully servable - supply
    /// strictly larger than hold, which is AC#2 failing in the one direction that
    /// matters (announcing a serve the index has disowned).
    ///
    /// STATED LIMIT (the task-61 seeding gap, filed as task-82): this map is
    /// in-memory, so after a restart a digest is unsuppliable until some
    /// hold-query re-derives it. Warming it at boot would mean re-dumping the
    /// whole store.
    by_digest: Mutex<HashMap<Blake3Digest, Arc<Entry>>>,
    dumper: Arc<dyn NarDumper>,
    store: Arc<dyn IndexStore>,
    announce: Arc<dyn AnnounceSink>,
}

impl AvailabilityIndex {
    /// Build an index, loading any persisted registrations so it survives restart.
    /// `node_id` is this node's iroh identity (the locator its offers carry).
    pub fn open(
        node_id: NodeId,
        dumper: Arc<dyn NarDumper>,
        store: Arc<dyn IndexStore>,
        announce: Arc<dyn AnnounceSink>,
    ) -> Result<Self, PersistError> {
        let loaded = store.load()?;
        let mut entries = HashMap::with_capacity(loaded.len());
        for (key, store_path) in loaded {
            entries.insert(
                key,
                Arc::new(Entry {
                    store_path,
                    digest: Mutex::new(None),
                }),
            );
        }
        Ok(AvailabilityIndex {
            node_id,
            entries: Mutex::new(entries),
            by_digest: Mutex::new(HashMap::new()),
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
    /// TRUST ASSUMPTION (fail-fast-at-source gap, deliberately deferred): this binds
    /// `key -> store_path` on the CALLER's word. `derive` later computes only the
    /// BLAKE3 of the dump; it does NOT re-derive `sha256(dump)` and assert it equals
    /// `key`. So a mis-registration yields a well-formed but FALSE claim. It cannot
    /// cause a bad install - the Nix client re-verifies `sha256(nar) == NarHash`
    /// (gate 2, the trust anchor; the daemon is outside the TCB, see `content_id`) -
    /// but a node could advertise content it does not truly hold. Verifying the
    /// sha256 alongside the blake3 from the same dump would close this at the source;
    /// it is forward-carried (it wants a sha256 dep and a second hash pass over the
    /// NAR, both out of scope for this feature cut).
    ///
    /// Persist ordering (Low): on a persist failure the in-memory map is already
    /// mutated while disk is not, so a restart reloads the pre-mutation set. The
    /// caller sees the `Err` and can retry; the divergence is transient and bounded.
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
                    digest: Mutex::new(None),
                }),
            );
            // The supply direction must follow the registration. A replaced entry
            // whose digest was already derived would otherwise stay servable under
            // the OLD path forever - supply would be a superset of hold, which is
            // the AC#2 equality failing in the direction that matters (announcing a
            // serve for content the index has disowned).
            if let Some(replaced) = replaced {
                self.forget_supply_bindings(&replaced);
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
        let entry = {
            let entries = self.entries.lock().expect("entries mutex");
            match entries.get(key) {
                Some(entry) => Arc::clone(entry),
                None => return Ok(HoldAnswer::Absent),
            }
        };

        // Materialisation check: a GC'd path is no longer available. Prune the stale
        // registration lazily and answer Absent. The prune is guarded by pointer
        // identity: if a concurrent `register` replaced this key's entry (a fresh,
        // possibly-materialised path) between the clone above and here, we must NOT
        // delete that newer registration on the strength of the OLD entry's absence.
        if !entry.store_path.exists() {
            self.drop_if_same(key, &entry)?;
            return Ok(HoldAnswer::Absent);
        }

        let derived = self.derive(&entry)?;
        // THE SUPPLY BINDING (task-72 AC#2). A positive hold-answer now also makes
        // the content SERVABLE: the provider fetches by BLAKE3, and this is the
        // only way back from that digest to the path it is regenerated from. The
        // two sets - "what I answer yes about" and "what I can serve" - are made
        // equal HERE, at the single place a yes is produced.
        self.by_digest
            .lock()
            .expect("by-digest mutex")
            .insert(derived.blake3, Arc::clone(&entry));
        Ok(HoldAnswer::Have {
            blake3: derived.blake3,
            offers: vec![self.iroh_offer()],
        })
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
    pub fn supply_size(&self, blake3: &Blake3Digest) -> Option<u64> {
        let entry = self.entry_for_digest(blake3)?;
        if !entry.store_path.exists() {
            return None;
        }
        entry
            .digest
            .lock()
            .expect("digest mutex")
            .map(|derived| derived.nar_size_uncompressed_nar)
    }

    /// Regenerate the exact `RawNarV1` bytes for `blake3` from the real store.
    /// This is the task-61 supply model's producer: no copy is retained, the dump
    /// happens now.
    ///
    /// FAILS LOUD on a mismatch. A store path that no longer dumps to the digest
    /// it was announced under is not "close enough" - serving it would hand a peer
    /// the wrong blob under the right name, and the caller must decline rather
    /// than let iroh-blobs discover it mid-stream.
    pub fn supply_raw_nar(&self, blake3: &Blake3Digest) -> Result<Vec<u8>, AvailabilityError> {
        let entry = self.entry_for_digest(blake3).ok_or_else(|| {
            AvailabilityError::Dump(DumpError(format!(
                "no registered holding supplies {blake3}"
            )))
        })?;
        let raw_nar = self.dumper.dump(&entry.store_path)?;
        let actual = Blake3Digest::from_raw_nar(&raw_nar);
        if actual != *blake3 {
            return Err(AvailabilityError::Dump(DumpError(format!(
                "{} now dumps to {actual}, not the announced {blake3}",
                entry.store_path
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
    fn forget_supply_bindings(&self, gone: &Arc<Entry>) {
        self.by_digest
            .lock()
            .expect("by-digest mutex")
            .retain(|_, entry| !Arc::ptr_eq(entry, gone));
    }

    /// The reverse lookup, and the ONLY way into `by_digest`. Deliberately private
    /// and deliberately per-digest: there is no method that yields the map, its
    /// keys or its length, so the no-enumeration invariant survives the addition
    /// of a supply path.
    fn entry_for_digest(&self, blake3: &Blake3Digest) -> Option<Arc<Entry>> {
        self.by_digest
            .lock()
            .expect("by-digest mutex")
            .get(blake3)
            .map(Arc::clone)
    }

    /// The versioned wire envelope for a [`HoldQuery`] probe: the same yes/no
    /// [`hold`](Self::hold) answer, wrapped for transmission. There is deliberately
    /// no query that lists holdings.
    pub fn answer(&self, query: &HoldQuery) -> Result<HoldResponse, AvailabilityError> {
        // PRECONDITION: `query` is a DECODED, version-checked probe - the wire path
        // gates it in `decode_hold_query`, so by construction its version is current.
        // This is a `debug_assert` (not a hard reject) because `answer` has no version
        // error to return and is not itself the wire boundary; a caller must not hand
        // it a raw, unvalidated query. The response is always emitted at this build's
        // `QUERY_SCHEMA_VERSION`.
        debug_assert_eq!(query.schema_version, QUERY_SCHEMA_VERSION);
        Ok(HoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            answer: self.hold(&query.key)?,
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
    /// PRECONDITION: `query` is a decoded, version- and cap-checked probe (the
    /// wire path gates it in [`crate::claim::decode_batch_hold_query`]). The
    /// answer allocation is bounded by [`MAX_BATCH_HOLD_KEYS`] regardless, so a
    /// caller that hands in an over-cap query cannot make this node pre-allocate
    /// an unbounded vector.
    pub fn answer_batch(&self, query: &BatchHoldQuery) -> BatchHoldResponse {
        debug_assert_eq!(query.schema_version, QUERY_SCHEMA_VERSION);
        debug_assert!(query.keys.len() <= MAX_BATCH_HOLD_KEYS);

        let mut answers = Vec::with_capacity(query.keys.len().min(MAX_BATCH_HOLD_KEYS));
        let mut any_have = false;
        for key in &query.keys {
            match self.hold(key) {
                Ok(HoldAnswer::Have { blake3, .. }) => {
                    any_have = true;
                    answers.push(BatchHoldAnswer::Have { blake3 });
                }
                Ok(HoldAnswer::Absent) => answers.push(BatchHoldAnswer::Absent),
                Err(err) => {
                    // Loud, not silent: the operator sees exactly which key
                    // degraded and why.
                    eprintln!(
                        "daemon: batch hold-query: {key} could not be answered ({err}); \
                         answering Absent for it"
                    );
                    answers.push(BatchHoldAnswer::Absent);
                }
            }
        }
        BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            // The offers describe THIS node, so they are emitted once - and only
            // when at least one answer is a Have, so an all-absent response says
            // nothing at all about this node beyond "no".
            offers: if any_have {
                vec![self.iroh_offer()]
            } else {
                Vec::new()
            },
            answers,
        }
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
    pub fn drop(&self, key: &NarHashKey) -> Result<(), PersistError> {
        let mut entries = self.entries.lock().expect("entries mutex");
        if let Some(removed) = entries.remove(key) {
            self.forget_supply_bindings(&removed);
            self.persist_locked(&entries)?;
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
                self.forget_supply_bindings(observed);
                self.persist_locked(&entries)?;
            }
            // A concurrent register replaced (or a concurrent drop already removed)
            // the entry: leave the newer state alone.
            _ => {}
        }
        Ok(())
    }

    /// The single-flight compute: return the cached digest or, exactly once,
    /// `dump` + hash it UNDER the entry lock. Concurrent callers for the same
    /// uncomputed key block here and observe the cached `Some`; distinct keys use
    /// distinct locks and hash in parallel. A dump failure leaves the slot `None`
    /// so the next caller retries.
    fn derive(&self, entry: &Entry) -> Result<DerivedNar, AvailabilityError> {
        let mut slot = entry.digest.lock().expect("digest mutex");
        if let Some(derived) = *slot {
            return Ok(derived);
        }
        let raw_nar = self.dumper.dump(&entry.store_path)?;
        // The frozen recipe, applied in exactly one place: BLAKE3(RawNarV1), plain
        // and unkeyed, over the uncompressed dump - matches the task-48 golden. The
        // NarSize is read off the SAME buffer rather than stat'ed separately, so it
        // cannot describe different bytes than the digest does.
        let derived = DerivedNar {
            blake3: Blake3Digest::from_raw_nar(&raw_nar),
            nar_size_uncompressed_nar: raw_nar.len() as u64,
        };
        *slot = Some(derived);
        Ok(derived)
    }

    /// This node's iroh transport offer (a pure locator: just the NodeId).
    fn iroh_offer(&self) -> KnownTransport {
        KnownTransport::Iroh { node: self.node_id }
    }

    /// Persist the current registration set. Called with the entries lock held so a
    /// concurrent register/drop cannot interleave a torn snapshot.
    fn persist_locked(
        &self,
        entries: &HashMap<NarHashKey, Arc<Entry>>,
    ) -> Result<(), PersistError> {
        let snapshot: Vec<(NarHashKey, StorePath)> = entries
            .iter()
            .map(|(key, entry)| (*key, entry.store_path.clone()))
            .collect();
        self.store.save(&snapshot)
    }
}
