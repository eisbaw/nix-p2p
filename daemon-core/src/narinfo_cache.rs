//! Persistent narinfo disk cache layered UNDER [`NarinfoSource`] (task-8).
//!
//! First real module layering: `NarinfoDiskCache` wraps any inner
//! [`NarinfoSource`] (wave-1: [`crate::upstream::UpstreamHttp`]) and turns it
//! into disk-cache-over-upstream. The serving layer is untouched - it still sees
//! one `NarinfoSource` - which is the whole point of the seam.
//!
//! Design commitments (TESTING.md + task-8 ACs):
//!   * BYTE-VERBATIM (AC#3). What is stored and served is the ORIGINAL upstream
//!     narinfo bytes, never a parsed-then-reserialised struct. The bytes live in
//!     a framed entry file (a small text header + the verbatim body, delimited by
//!     a blank line and length-checked), so odd field ordering, unknown fields,
//!     multiple `Sig:` lines, absent `Deriver`, empty `References` and CRLF all
//!     survive - on disk and across a restart. We MAY parse a read-only COPY to
//!     derive the correlation index (below); we never mutate what we serve.
//!   * NIX TTL SEMANTICS (AC#2). Positive entries (200) live [`POSITIVE_TTL`]
//!     (30 days, Nix default); negative entries (404) live [`NEGATIVE_TTL`]
//!     (3600 s, Nix default). Only 200 and 404 are cached - a 403/5xx/transport
//!     error is transient and passes straight through, exactly as Nix treats it.
//!     Time comes from an injected [`Clock`] so tests drive expiry deterministically.
//!   * VALIDATE-THEN-ATOMIC-RENAME (AC#4). An upstream narinfo is validated
//!     ([`is_well_formed_narinfo`]) BEFORE it is written; a truncated/short body
//!     fails validation and never enters the cache. The entry is written to a
//!     unique tmp file under `<root>/.tmp`, fsynced, then atomically renamed into
//!     place, so a reader (or a crash - task-7) never sees a partial file. A
//!     cache entry that fails to parse or re-validate on READ is discarded and
//!     refetched, never served. Fail-closed: an incomplete input resolves to
//!     refetch, never to a "valid" entry.
//!
//! Correlation persistence (task-4's deferred steady-state, implemented here):
//! `NarinfoDiskCache` also implements [`crate::catalog::CorrelationStore`]. A
//! warm Nix client skips the narinfo GET (30-day client cache) and, after a
//! daemon restart, sends only `GET /nar/<token>` - the in-memory
//! [`crate::catalog::NarCatalog`] is cold and has no correlation. The server then
//! consults THIS store, which derives `token -> (NarHash, NarSize)` by a
//! READ-ONLY parse of the cached narinfo bytes, so the daemon can still dispatch
//! [`crate::source::NarKey::SignedNarHash`] from persisted state. The correlation
//! is a DERIVED VIEW of the byte-verbatim cache (never a separately-persisted map
//! that could drift): a `token -> store_hash` index accelerates the lookup, but
//! the returned meta is always re-read and re-parsed from the actual entry file,
//! so it cannot diverge from the bytes. Forward-only (`token -> hash`), as a NAR
//! request needs - never the lossy reverse map task-4 rejected.
//!
//! Signed-upstream scope (wave-1 limit, be explicit): [`is_well_formed_narinfo`]
//! requires a `Sig:` line, so an UNSIGNED narinfo (a private/unsigned
//! substituter) is never cached - it is passed through but refetched on every
//! request. This is deliberate for wave 1, whose trust chain and only deployment
//! target are SIGNED caches (cache.nixos.org-style, `require-sigs` on per
//! TESTING.md): requiring `Sig` makes the truncation guard strong (a trailing
//! truncation typically severs the last-line `Sig`). Decoupling truncation
//! detection from signature presence - so unsigned upstreams cache too - is a
//! filed wave-2 follow-up, not an accident.
//!
//! Bounds + eviction (TASK-27). The on-disk cache is BOUNDED by an integer
//! `max_entries` COUNT (a constructor parameter; [`NarinfoDiskCache::new`] applies
//! [`DEFAULT_MAX_ENTRIES`], [`NarinfoDiskCache::with_max_entries`] takes an
//! explicit cap). Count (not bytes) because each entry is already per-entry
//! byte-capped at [`crate::source::MAX_NARINFO_BYTES`], so a count cap bounds disk
//! within a known factor while keeping the eviction ordering key an integer.
//! When an install pushes the live-entry count over the cap, the OLDEST entries
//! by `fetched_at` (an integer Unix-seconds stamp; ties broken by store-hash for
//! determinism) are evicted - an LRU-by-fetch-time policy. Eviction NEVER causes
//! a wrong serve: an evicted entry is simply a cache MISS that re-fetches upstream
//! (which Nix re-verifies sig+NarHash regardless), never a stale/wrong narinfo.
//!
//! Restart warm-up (TASK-27 AC#2). Steady-state startup reads a single compact
//! sidecar index file (`<root>/index`), one line per live entry
//! (`store_hash \t fetched_at \t token`), and populates the in-memory bookkeeping
//! from that ONE file read - it does NOT open, frame-decode and re-validate every
//! `.nic` as the old `rebuild_index` did. The sidecar is rewritten atomically on
//! every mutation. It is a DERIVED CACHE, never authoritative: serving reads
//! `<hash>.nic` directly by hash (never via the index) and re-validates, and
//! correlation re-parses the actual `.nic`, so a stale/absent/corrupt sidecar can
//! never produce a wrong serve - at worst it costs an extra refetch. A cache dir
//! with entries but no sidecar (a legacy dir, or a torn write) is bootstrapped
//! ONCE by a full scan and then persisted, so the next restart is cheap again.
//!
//! Cap honesty (be explicit): the count cap holds exactly in steady state, but it
//! is reconciled against the actual `.nic` files ONLY when the sidecar is absent or
//! corrupt (the rescan path). A crash between the `.nic` rename and the sidecar
//! rewrite - or a sidecar-write failure - can leave orphan `.nic` files that
//! `book` never counts and eviction never reaps, so across repeated crashes the
//! on-disk count can drift ABOVE `max_entries`. This never causes a wrong serve
//! (an orphan is a valid entry; a phantom is a miss); it only weakens the bound
//! until the next absent/corrupt-sidecar rescan. Tightening this would need a
//! periodic reconciliation (e.g. rescan when a cheap dir-entry count disagrees
//! with `book`), deliberately not added here.
//!
//! I/O note (filed follow-up): reads/writes use blocking `std::fs` on the async
//! fetch path. The reads and small writes are cheap; the sharp edge is the
//! `sync_all()` fsync in [`write_durably`], which can stall a Tokio worker for
//! milliseconds under load - so the `spawn_blocking`/`tokio::fs` move should land
//! before the cache is enabled by default, not after. Sharper still: the MISS-path
//! sidecar rewrite (one bounded atomic write + fsync + a dir fsync) runs while
//! holding the EXCLUSIVE bookkeeping lock, so it serialises other installs and
//! blocks `meta_for_token` correlation readers for that fsync. Serving HITs are
//! lock-free and unaffected; still, this is the first thing to move off-worker
//! before the cache is enabled by default.

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use http_body_util::BodyExt;

use crate::catalog::{CorrelationStore, NarMeta};
use crate::source::{NarHash, NarinfoSource, SourceError, StoreHash, UpstreamResponse};

/// The Nix base32 alphabet: `[0-9a-z]` MINUS `e o u t` (32 symbols). A store-path
/// hash is EXACTLY 32 of these. Used to reject a hostile or malformed cache key
/// before it can name a file (task-13: the "non-base32 rejected" claim, made true).
const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Length of a Nix store-path hash in base32 characters.
const STORE_HASH_LEN: usize = 32;

/// Positive narinfo TTL: 30 days, matching Nix's default `narinfo-cache-positive-ttl`.
pub const POSITIVE_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// Negative narinfo TTL: 3600 s, matching Nix's default `narinfo-cache-negative-ttl`.
pub const NEGATIVE_TTL: Duration = Duration::from_secs(3600);

/// Default on-disk entry cap when the caller does not pass one to
/// [`NarinfoDiskCache::new`]. Chosen so the cache is bounded by default (never
/// unbounded on disk) while being ample for a workstation substituter: at the
/// per-entry [`crate::source::MAX_NARINFO_BYTES`] ceiling this is a loose upper
/// bound, and real narinfos are ~1 KiB, so the steady-state footprint is far
/// smaller. An operator who wants a different cap uses
/// [`NarinfoDiskCache::with_max_entries`].
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Filename of the compact sidecar index under `<root>`. Not a `.nic` file, so the
/// entry scan skips it and [`safe_key`] would reject it as a store hash anyway.
const INDEX_FILE: &str = "index";

/// Magic first line of the sidecar index; a version bump invalidates an old
/// sidecar (it fails to parse -> a one-time full rescan rebuilds and rewrites it).
const INDEX_MAGIC: &str = "NIXP2P-NARINFO-INDEX\t1";

/// Injected time source, so TTL expiry is deterministic under test.
///
/// A trait (not a hardcoded `SystemTime::now()`) because AC#2 requires driving a
/// 404 across its 3600 s TTL and a 200 across its 30-day TTL without sleeping.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now_unix_secs(&self) -> u64;
}

/// Wall-clock time for production.
#[derive(Debug, Default, Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            // A clock before the epoch is absurd; treat as time zero rather than
            // panicking on the request path.
            .unwrap_or(0)
    }
}

/// Where the narinfo disk cache ended up once the daemon reconciled its two CLI
/// flags (`--narinfo-cache-dir`, `--no-narinfo-cache`) with the environment
/// (TASK-29 AC#1). The four outcomes are kept DISTINCT — rather than collapsing
/// to `Option<PathBuf>` — so the daemon can log precisely WHY it is (or is not)
/// caching, and so the failure policy can differ: a DEFAULT dir that will not open
/// is a warning (the operator did not ask for it), whereas an EXPLICIT dir that
/// will not open is fatal (they did).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NarinfoCacheChoice {
    /// The operator opted out with `--no-narinfo-cache`. Run pure-upstream.
    Disabled,
    /// The operator named a directory with `--narinfo-cache-dir DIR`. A failure to
    /// open THIS path must be fatal — they asked for it explicitly.
    Explicit(PathBuf),
    /// No flag was given, so the cache defaults ON at the XDG state path (AC#1).
    /// A failure to open a DEFAULT path is a warning, not fatal: a convenience
    /// default must never brick a daemon that would otherwise serve fine.
    Default(PathBuf),
    /// No flag, and neither `HOME` nor `XDG_STATE_HOME` is set, so there is nowhere
    /// sensible to root a default. Run pure-upstream with a warning rather than
    /// guess an absolute path.
    NoDefault,
}

/// Resolve the EFFECTIVE narinfo cache directory from the two CLI flags and an
/// injected environment lookup (TASK-29 AC#1). Pure and env-injected so the
/// precedence is unit-tested without touching real process env vars or disk; the
/// daemon passes `|k| std::env::var(k).ok()`.
///
/// Precedence, highest first:
///   1. `disabled` (`--no-narinfo-cache`) → [`NarinfoCacheChoice::Disabled`]. The
///      caller rejects the contradictory `--narinfo-cache-dir` + `--no-narinfo-cache`
///      combination up front, so an opt-out here is unambiguous.
///   2. `explicit` (`--narinfo-cache-dir DIR`) → [`NarinfoCacheChoice::Explicit`],
///      honoured verbatim.
///   3. neither → the XDG default: `$XDG_STATE_HOME/nix-p2p/narinfo`, falling back
///      to `$HOME/.local/state/nix-p2p/narinfo` when `XDG_STATE_HOME` is unset,
///      empty, or (spec-invalid) relative. If neither yields an ABSOLUTE base,
///      [`NarinfoCacheChoice::NoDefault`].
///
/// XDG *state* (not *cache*) is deliberate: the entries back the persistent
/// `token → NarHash` correlation a warm daemon dispatches after an in-memory-cold
/// restart — state that should survive a reboot — even though it is re-derivable
/// and count-capped (TASK-27), which is exactly why a missing default is only
/// best-effort rather than fatal. NOTE (privacy scope): enabling this by default
/// means WHICH narinfos an operator fetched are now recorded on local disk. That is
/// a LOCAL cache (re-derivable, count-capped, off-worker per TASK-28), not a network
/// disclosure; the operator-contract task (TASK-120) will refine the state-dir/mode.
pub fn resolve_narinfo_cache_dir(
    explicit: Option<&str>,
    disabled: bool,
    getenv: impl Fn(&str) -> Option<String>,
) -> NarinfoCacheChoice {
    if disabled {
        return NarinfoCacheChoice::Disabled;
    }
    if let Some(dir) = explicit {
        return NarinfoCacheChoice::Explicit(PathBuf::from(dir));
    }
    // A usable base must be an ABSOLUTE path. XDG_STATE_HOME is required by the XDG
    // spec to be absolute; a relative or empty value is ignored in favour of HOME.
    let absolute = |s: String| -> Option<PathBuf> {
        let p = PathBuf::from(s);
        p.is_absolute().then_some(p)
    };
    let base = getenv("XDG_STATE_HOME")
        .filter(|s| !s.is_empty())
        .and_then(absolute)
        .or_else(|| {
            getenv("HOME")
                .filter(|s| !s.is_empty())
                .and_then(absolute)
                .map(|home| home.join(".local").join("state"))
        });
    match base {
        Some(base) => NarinfoCacheChoice::Default(base.join("nix-p2p").join("narinfo")),
        None => NarinfoCacheChoice::NoDefault,
    }
}

/// The error string both daemon binaries emit when `--narinfo-cache-dir` and
/// `--no-narinfo-cache` are passed together. Shared here so the two parse-time
/// guards cannot drift their wording (SSOT).
pub const NARINFO_CACHE_FLAG_CONFLICT: &str =
    "--narinfo-cache-dir and --no-narinfo-cache are contradictory; pass at most one";

/// The result of turning a resolved [`NarinfoCacheChoice`] into a live narinfo
/// layer. Built once in [`build_narinfo_layer`] and shared by BOTH daemon binaries,
/// so the fatal-explicit / soft-fail-default policy and the (source, correlation)
/// wiring live in ONE place rather than being copy-pasted and left to drift. The
/// caller owns only the LOGGING and the process-exit decision — everything that
/// decides WHICH source to serve is here.
pub enum NarinfoLayer {
    /// The cache is active. `narinfo` is disk-cache-over-upstream, `correlation` the
    /// matching persistent store, `dir` the resolved directory (for the log line).
    Cached {
        narinfo: std::sync::Arc<dyn NarinfoSource>,
        correlation: std::sync::Arc<dyn CorrelationStore>,
        dir: PathBuf,
    },
    /// No cache: pure-upstream passthrough. `reason` records WHY so the caller logs
    /// the precise cause without re-deriving it.
    PassThrough {
        narinfo: std::sync::Arc<dyn NarinfoSource>,
        correlation: std::sync::Arc<dyn CorrelationStore>,
        reason: PassThroughReason,
    },
    /// An EXPLICIT `--narinfo-cache-dir` could not be opened. The operator asked for
    /// it, so this is FATAL: the caller logs the error and aborts (fail-fast).
    ExplicitOpenFailed { dir: PathBuf, err: std::io::Error },
}

/// Why a [`NarinfoLayer::PassThrough`] carries no cache — kept distinct so the
/// caller emits the right (and only the right) log line.
pub enum PassThroughReason {
    /// `--no-narinfo-cache`: the operator opted out.
    Disabled,
    /// No flag and no `HOME`/`XDG_STATE_HOME` to root a default.
    NoDefault,
    /// A DEFAULT dir that would not open. Best-effort: the caller WARNS (naming the
    /// `dir` and `err`) and serves pure-upstream rather than bricking a daemon that
    /// would otherwise serve fine.
    DefaultOpenFailed { dir: PathBuf, err: std::io::Error },
}

/// Turn a resolved [`NarinfoCacheChoice`] into a [`NarinfoLayer`], applying the ONE
/// failure policy both binaries share: a DEFAULT dir that will not open soft-fails
/// to pure-upstream, an EXPLICIT one is fatal. Pure w.r.t. the environment (the
/// choice is resolved by [`resolve_narinfo_cache_dir`] beforehand); it does touch
/// the filesystem via [`NarinfoDiskCache::new`], exactly as the daemon start-up must.
pub fn build_narinfo_layer(
    choice: NarinfoCacheChoice,
    upstream: std::sync::Arc<dyn NarinfoSource>,
    clock: std::sync::Arc<dyn Clock>,
) -> NarinfoLayer {
    let pass_through = |reason| NarinfoLayer::PassThrough {
        narinfo: upstream.clone(),
        correlation: std::sync::Arc::new(crate::catalog::NullCorrelation),
        reason,
    };
    let (dir, is_default) = match choice {
        NarinfoCacheChoice::Disabled => return pass_through(PassThroughReason::Disabled),
        NarinfoCacheChoice::NoDefault => return pass_through(PassThroughReason::NoDefault),
        NarinfoCacheChoice::Explicit(dir) => (dir, false),
        NarinfoCacheChoice::Default(dir) => (dir, true),
    };
    match NarinfoDiskCache::new(&dir, upstream.clone(), clock) {
        Ok(cache) => {
            let cache = std::sync::Arc::new(cache);
            NarinfoLayer::Cached {
                narinfo: cache.clone(),
                correlation: cache,
                dir,
            }
        }
        Err(err) if is_default => pass_through(PassThroughReason::DefaultOpenFailed { dir, err }),
        Err(err) => NarinfoLayer::ExplicitOpenFailed { dir, err },
    }
}

/// What kind of cached outcome an entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    /// A 200 with a verbatim narinfo body.
    Positive,
    /// A 404 (path absent upstream) - no body.
    Negative,
}

/// A parsed cache entry: the framed header fields plus the verbatim body.
struct Entry {
    kind: EntryKind,
    fetched_at: u64,
    /// Verbatim narinfo bytes (empty for a negative entry).
    body: Vec<u8>,
}

/// Magic line identifying our framed entry format; a version bump invalidates
/// old entries (they fail to parse -> treated as a miss -> refetched).
const ENTRY_MAGIC: &str = "NIXP2P-NARINFO-CACHE\t1";

impl Entry {
    /// Serialise to the on-disk frame: a text header, a blank line, then the
    /// verbatim body. `body_len` lets the reader length-check for truncation.
    fn encode(&self) -> Vec<u8> {
        let status = match self.kind {
            EntryKind::Positive => 200u16,
            EntryKind::Negative => 404u16,
        };
        let header = format!(
            "{ENTRY_MAGIC}\nfetched_at\t{}\nstatus\t{}\nbody_len\t{}\n\n",
            self.fetched_at,
            status,
            self.body.len()
        );
        let mut out = header.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse a frame, returning `None` for ANY corruption (bad magic, malformed
    /// header, or a body whose length disagrees with `body_len` - the on-disk
    /// truncation signal). A `None` here means "discard and refetch", never serve.
    fn decode(raw: &[u8]) -> Option<Entry> {
        // Header ends at the first blank line; the body follows verbatim.
        let sep = find_subslice(raw, b"\n\n")?;
        let header = std::str::from_utf8(&raw[..sep]).ok()?;
        let body = &raw[sep + 2..];

        let mut fetched_at = None;
        let mut status = None;
        let mut body_len = None;
        let mut lines = header.lines();
        if lines.next()? != ENTRY_MAGIC {
            return None;
        }
        for line in lines {
            let (key, value) = line.split_once('\t')?;
            match key {
                "fetched_at" => fetched_at = value.parse::<u64>().ok(),
                "status" => status = value.parse::<u16>().ok(),
                "body_len" => body_len = value.parse::<usize>().ok(),
                _ => {}
            }
        }
        let fetched_at = fetched_at?;
        let status = status?;
        let body_len = body_len?;
        // Truncation guard: the stored body must be EXACTLY the promised length.
        if body.len() != body_len {
            return None;
        }
        let kind = match status {
            200 => EntryKind::Positive,
            404 => EntryKind::Negative,
            _ => return None,
        };
        // A positive entry must still hold a well-formed narinfo, or it is a
        // corrupt entry to discard (AC#4 read side).
        if kind == EntryKind::Positive && !is_well_formed_narinfo(body) {
            return None;
        }
        Some(Entry {
            kind,
            fetched_at,
            body: body.to_vec(),
        })
    }
}

/// One tracked entry's eviction/correlation metadata. The bytes live in the
/// `.nic` file; this is only what eviction and correlation need in memory.
struct Record {
    /// Integer Unix-seconds stamp the entry was fetched at - the LRU key.
    fetched_at: u64,
    /// The narinfo's NAR token, for positive entries whose body parsed a
    /// correlation; `None` for negatives and un-parseable positives.
    token: Option<String>,
}

/// In-memory bookkeeping for the on-disk cache: the single source of truth for
/// what is live, the LRU order, and the `token -> store_hash` correlation. All
/// three move together under one lock so they cannot race apart. Every field is a
/// DERIVED VIEW of the `.nic` files on disk (re-derivable by a full scan); it is
/// held in memory, and mirrored to the sidecar index, purely to make restart and
/// eviction cheap.
#[derive(Default)]
struct Bookkeeping {
    /// `store_hash -> Record` for every live entry.
    records: HashMap<String, Record>,
    /// `(fetched_at, store_hash)` ordered for O(log n) oldest-first eviction.
    lru: BTreeSet<(u64, String)>,
    /// `token -> store_hash` correlation (positive entries only).
    token_index: HashMap<String, String>,
}

impl Bookkeeping {
    /// Drop `store_hash` from all three views. A no-op if absent. The token map is
    /// only cleared when it still points at THIS hash, so replacing an entry never
    /// unlinks a token that a newer entry has taken over.
    fn remove(&mut self, store_hash: &str) {
        if let Some(rec) = self.records.remove(store_hash) {
            self.lru.remove(&(rec.fetched_at, store_hash.to_string()));
            if let Some(token) = rec.token
                && self
                    .token_index
                    .get(&token)
                    .is_some_and(|h| h == store_hash)
            {
                self.token_index.remove(&token);
            }
        }
    }

    /// Insert (or replace) `store_hash`'s record across all three views. Callers
    /// [`Bookkeeping::remove`] first when replacing so no stale LRU/token lingers.
    fn insert(&mut self, store_hash: &str, fetched_at: u64, token: Option<String>) {
        self.lru.insert((fetched_at, store_hash.to_string()));
        if let Some(token) = &token {
            self.token_index
                .insert(token.clone(), store_hash.to_string());
        }
        self.records
            .insert(store_hash.to_string(), Record { fetched_at, token });
    }
}

/// Disk + bookkeeping state, split out of [`NarinfoDiskCache`] so the blocking
/// `std::fs` work - ESPECIALLY the fsync-heavy `write_durably`/sidecar path - can
/// be handed to [`tokio::task::spawn_blocking`] and never runs on a Tokio worker
/// thread (TASK-28). Every method on `Shared` is synchronous blocking I/O; the
/// async [`NarinfoSource`]/[`CorrelationStore`] layer on [`NarinfoDiskCache`] owns
/// the `.await`. Held behind an `Arc` so a blocking closure can capture it
/// `'static` and outlive the poll that dispatched it.
struct Shared {
    root: PathBuf,
    clock: std::sync::Arc<dyn Clock>,
    positive_ttl: Duration,
    negative_ttl: Duration,
    /// Integer COUNT cap on live on-disk entries (AC#1). A constructor parameter,
    /// never a float; eviction keeps the live count at or below this.
    max_entries: NonZeroUsize,
    /// Monotonic counter for unique tmp names (a request never collides with a
    /// concurrent one mid-write).
    tmp_seq: AtomicU64,
    /// The single in-memory source of truth for liveness, LRU order and
    /// correlation. A derived view of the `.nic` files, mirrored to the sidecar.
    book: RwLock<Bookkeeping>,
}

/// Persistent narinfo cache over an inner source. The async facade: it fronts the
/// blocking [`Shared`] disk state, dispatching every disk touch (read+validate,
/// the durable install, the correlation re-parse) onto
/// [`tokio::task::spawn_blocking`] so the `sync_all` fsync never stalls a Tokio
/// worker (TASK-28). The `inner` async source stays here (it is `.await`ed, not
/// blocking), so only the pure-disk state moves behind the `Arc`.
pub struct NarinfoDiskCache {
    shared: std::sync::Arc<Shared>,
    inner: std::sync::Arc<dyn NarinfoSource>,
}

impl NarinfoDiskCache {
    /// Build a cache rooted at `root`, fronting `inner`, timed by `clock`, bounded
    /// by [`DEFAULT_MAX_ENTRIES`]. See [`NarinfoDiskCache::with_max_entries`] to
    /// choose the cap.
    pub fn new(
        root: impl Into<PathBuf>,
        inner: std::sync::Arc<dyn NarinfoSource>,
        clock: std::sync::Arc<dyn Clock>,
    ) -> std::io::Result<Self> {
        let max_entries =
            NonZeroUsize::new(DEFAULT_MAX_ENTRIES).expect("DEFAULT_MAX_ENTRIES is nonzero");
        Self::with_max_entries(root, inner, clock, max_entries)
    }

    /// Build a cache with an explicit integer entry cap (AC#1). Loads the compact
    /// sidecar index once to warm bookkeeping from a previous process (the cheap
    /// restart path); if the sidecar is absent or unreadable it falls back to a
    /// one-time full scan and then writes the sidecar. Fails fast if `root` cannot
    /// be created.
    ///
    /// This runs at WIRING time (once, at daemon start), NOT on the async fetch
    /// path, so its blocking directory setup + one-shot index warm-up are kept
    /// synchronous on purpose: TASK-28 moves the PER-REQUEST disk work off-worker
    /// (read/install/correlation), not this one-time construction cost.
    pub fn with_max_entries(
        root: impl Into<PathBuf>,
        inner: std::sync::Arc<dyn NarinfoSource>,
        clock: std::sync::Arc<dyn Clock>,
        max_entries: NonZeroUsize,
    ) -> std::io::Result<Self> {
        let root = root.into();
        // DELIBERATELY plain `create_dir_all` + later plain `File` opens - NO
        // O_NOFOLLOW parent check like `public_allowlist.rs` uses. This is required,
        // not an oversight: under the NixOS module's `DynamicUser` + `StateDirectory`,
        // the default root `/var/lib/nix-p2p` is itself a systemd-managed SYMLINK into
        // `/var/lib/private/…`, so an O_NOFOLLOW-on-parent check would REFUSE the
        // module's own default. It is also safe to omit: the narinfo cache is not a
        // trust input - every entry is re-derivable, well-formedness-checked on read,
        // and the served NAR is signature/hash-verified downstream by nix - so a
        // symlink swap costs at most a refetch, never a bad serve (unlike the
        // allowlist, which gates a public announce and therefore IS hardened).
        std::fs::create_dir_all(&root)?;
        let tmp_dir = root.join(".tmp");
        std::fs::create_dir_all(&tmp_dir)?;
        // Reap orphaned tmp files a previous crash left BETWEEN write and rename
        // (task-7 crash hygiene). They are never valid entries - a completed
        // write is always renamed out of `.tmp` - so removing them is safe and
        // stops the staging area leaking across restarts.
        if let Ok(dir) = std::fs::read_dir(&tmp_dir) {
            for entry in dir.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let shared = std::sync::Arc::new(Shared {
            root,
            clock,
            positive_ttl: POSITIVE_TTL,
            negative_ttl: NEGATIVE_TTL,
            max_entries,
            tmp_seq: AtomicU64::new(0),
            book: RwLock::new(Bookkeeping::default()),
        });
        shared.load_index();
        Ok(NarinfoDiskCache { shared, inner })
    }
}

impl Shared {
    /// Path of the sidecar index file.
    fn index_path(&self) -> PathBuf {
        self.root.join(INDEX_FILE)
    }

    /// Warm bookkeeping at startup. Prefer the compact sidecar (ONE file read +
    /// line-parse, no per-entry `.nic` decode); if it is missing or corrupt,
    /// rebuild from a full scan and persist a fresh sidecar so the NEXT restart is
    /// cheap. This is the AC#2 restart path.
    fn load_index(&self) {
        let rescanned = match self.read_sidecar() {
            Some(records) => {
                let mut book = self.book.write().expect("book poisoned");
                for (store_hash, fetched_at, token) in records {
                    book.insert(&store_hash, fetched_at, token);
                }
                false
            }
            None => {
                self.rebuild_from_scan();
                true
            }
        };
        // Honour the current cap even if a previous run used a larger one or a
        // legacy dir was over-cap; (re)write the sidecar only when the loaded state
        // actually changed, so a normal in-cap restart stays write-free.
        let trimmed = self.trim_to_cap();
        if rescanned || trimmed {
            self.persist_sidecar();
        }
    }

    /// Read + parse the sidecar index. Returns `None` (fall back to a full scan)
    /// for ANY problem: absent file, bad magic, or a malformed line. A `None` here
    /// is never a wrong serve - it only forces the one-time rescan path.
    fn read_sidecar(&self) -> Option<Vec<(String, u64, Option<String>)>> {
        let raw = std::fs::read(self.index_path()).ok()?;
        let text = std::str::from_utf8(&raw).ok()?;
        let mut lines = text.lines();
        if lines.next()? != INDEX_MAGIC {
            return None;
        }
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            // `store_hash \t fetched_at \t token` (token may be empty).
            let mut cols = line.split('\t');
            let store_hash = cols.next()?;
            let fetched_at = cols.next()?.parse::<u64>().ok()?;
            let token = cols.next()?;
            // A store hash that is not a safe key is corruption - reject the whole
            // sidecar rather than trust a partially-valid one.
            safe_key(store_hash)?;
            // A duplicate hash would desync `lru` from `records` on load (a dangling
            // BTreeSet tuple), so reject the whole sidecar - same stance as a bad key.
            if !seen.insert(store_hash.to_string()) {
                return None;
            }
            let token = if token.is_empty() {
                None
            } else {
                Some(token.to_string())
            };
            out.push((store_hash.to_string(), fetched_at, token));
        }
        Some(out)
    }

    /// Serialise the current bookkeeping to sidecar bytes, oldest-first (the LRU
    /// order), so the file is deterministic and greppable.
    fn serialize_sidecar(book: &Bookkeeping) -> Vec<u8> {
        let mut out = String::from(INDEX_MAGIC);
        out.push('\n');
        for (fetched_at, store_hash) in &book.lru {
            let token = book
                .records
                .get(store_hash)
                .and_then(|r| r.token.as_deref())
                .unwrap_or("");
            out.push_str(store_hash);
            out.push('\t');
            out.push_str(&fetched_at.to_string());
            out.push('\t');
            out.push_str(token);
            out.push('\n');
        }
        out.into_bytes()
    }

    /// Atomically write the sidecar from the current bookkeeping. Best-effort: a
    /// failure is logged, not fatal - the sidecar is only an accelerator and a
    /// missing one is recovered by the next-restart rescan.
    fn persist_sidecar(&self) {
        let bytes = {
            let book = self.book.read().expect("book poisoned");
            Self::serialize_sidecar(&book)
        };
        self.write_sidecar_bytes(&bytes);
    }

    /// Atomically install sidecar `bytes` via tmp + fsync + rename.
    fn write_sidecar_bytes(&self, bytes: &[u8]) {
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .root
            .join(".tmp")
            .join(format!("index.{}.{}.tmp", std::process::id(), seq));
        if let Err(err) = write_durably(&tmp, bytes) {
            eprintln!("narinfo-cache: write sidecar tmp {tmp:?}: {err}");
            let _ = std::fs::remove_file(&tmp);
            return;
        }
        if let Err(err) = std::fs::rename(&tmp, self.index_path()) {
            eprintln!(
                "narinfo-cache: rename sidecar into {:?}: {err}",
                self.index_path()
            );
            let _ = std::fs::remove_file(&tmp);
            return;
        }
        // Make the sidecar rename durable across a crash (task-7).
        fsync_dir(&self.root);
    }

    /// Path of the entry file for a store hash, or `None` if the hash is not a
    /// safe filename (a path-traversal or otherwise hostile key is never written
    /// or read - it simply bypasses the cache).
    fn entry_path(&self, store_hash: &str) -> Option<PathBuf> {
        let key = safe_key(store_hash)?;
        Some(self.root.join(format!("{key}.nic")))
    }

    /// Read and validate an entry from disk, honouring its TTL. Returns `None`
    /// (a miss) if absent, corrupt, or expired - and removes a corrupt/expired
    /// file so it is refetched cleanly. Never returns a stale or partial entry.
    fn read_fresh(&self, store_hash: &str) -> Option<Entry> {
        let path = self.entry_path(store_hash)?;
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(err) => {
                // A missing file is a normal cache miss (silent). Any OTHER error
                // (permissions, I/O fault on an existing file) is a real problem
                // that would otherwise degrade silently into perpetual refetch -
                // surface it (fail-verbose; this is a path task-7's crash suite
                // exercises).
                if err.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("narinfo-cache: read {path:?}: {err}");
                }
                return None;
            }
        };
        let Some(entry) = Entry::decode(&raw) else {
            // Corrupt entry: discard so the next fetch repopulates it cleanly.
            // Logged, not silent - a corrupt entry is a signal, not routine.
            eprintln!(
                "narinfo-cache: discarding corrupt entry {path:?} ({} bytes); will refetch",
                raw.len()
            );
            let _ = std::fs::remove_file(&path);
            return None;
        };
        let ttl = match entry.kind {
            EntryKind::Positive => self.positive_ttl,
            EntryKind::Negative => self.negative_ttl,
        };
        let now = self.clock.now_unix_secs();
        // saturating_sub: a clock that went backwards must not underflow into a
        // huge "age" that wrongly expires everything.
        if now.saturating_sub(entry.fetched_at) >= ttl.as_secs() {
            return None;
        }
        Some(entry)
    }

    /// Validate then atomically install an entry. The body is validated by the
    /// CALLER before this is reached; here we only guarantee the write is atomic
    /// and durable. Best-effort: a write failure is logged and the fetch still
    /// serves the upstream bytes (caching is an optimisation, never a hard
    /// dependency of correctness).
    fn install(&self, store_hash: &str, entry: &Entry) {
        // Validate the key ONCE: a hostile hash never reaches the filesystem, and
        // the same validated key names both the tmp file and the final path (no
        // dead-defensive fallback).
        let Some(key) = safe_key(store_hash) else {
            return;
        };
        let final_path = self.root.join(format!("{key}.nic"));
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .root
            .join(".tmp")
            .join(format!("{key}.{}.{}.tmp", std::process::id(), seq));
        let bytes = entry.encode();
        if let Err(err) = write_durably(&tmp, &bytes) {
            eprintln!("narinfo-cache: write tmp {tmp:?}: {err}");
            // A mid-write failure (e.g. ENOSPC) leaves a partial tmp; remove it
            // now rather than wait for the next startup reap (task-13 hygiene).
            let _ = std::fs::remove_file(&tmp);
            return;
        }
        if let Err(err) = std::fs::rename(&tmp, &final_path) {
            eprintln!("narinfo-cache: rename into {final_path:?}: {err}");
            let _ = std::fs::remove_file(&tmp);
            return;
        }
        // Make the rename itself durable (task-7): fsync the directory it landed in.
        fsync_dir(&self.root);
        // Record the freshly-installed entry, evict the oldest over-cap entries,
        // and mirror the result to the sidecar. Serving never consults this
        // bookkeeping, so an eviction can only turn a later request into a MISS
        // (refetch), never a wrong serve.
        let token = if entry.kind == EntryKind::Positive {
            crate::catalog::parse_correlation(&entry.body).map(|c| c.token.as_str().to_string())
        } else {
            None
        };
        self.record_and_evict(store_hash, entry.fetched_at, token);
    }

    /// Insert `store_hash` into bookkeeping, evict the oldest (coldest by
    /// `fetched_at`) entries while the live count exceeds `max_entries`, rewrite
    /// the sidecar, then delete the evicted `.nic` files. The just-installed hash
    /// is never itself an eviction victim, so the cap is enforced by dropping COLD
    /// entries (AC#3). An evicted entry becomes a plain cache MISS on its next
    /// request and is re-fetched (never served stale).
    fn record_and_evict(&self, store_hash: &str, fetched_at: u64, token: Option<String>) {
        let victims = {
            let mut book = self.book.write().expect("book poisoned");
            book.remove(store_hash);
            book.insert(store_hash, fetched_at, token);
            // Spare the just-installed hash so the cap is met by dropping COLD
            // entries (AC#3) - the newest always survives.
            let victims = evict_over_cap(&mut book, self.max_entries.get(), Some(store_hash));
            // Mirror the post-eviction state while still holding the lock, so the
            // sidecar matches memory exactly at steady state.
            let bytes = Self::serialize_sidecar(&book);
            self.write_sidecar_bytes(&bytes);
            victims
        };
        self.delete_entry_files(victims);
    }

    /// Evict the oldest entries until the live count is at or below `max_entries`,
    /// deleting their `.nic` files. Used at startup to honour a lowered cap or trim
    /// a legacy over-cap dir. Returns whether anything was evicted (so the caller
    /// can decide to rewrite the sidecar). Unlike [`record_and_evict`] there is no
    /// just-installed entry to spare - it trims the plain oldest.
    fn trim_to_cap(&self) -> bool {
        let victims = {
            let mut book = self.book.write().expect("book poisoned");
            evict_over_cap(&mut book, self.max_entries.get(), None)
        };
        let evicted = !victims.is_empty();
        self.delete_entry_files(victims);
        evicted
    }

    /// Delete the `.nic` files for a set of evicted store hashes. Called after the
    /// hashes are already gone from bookkeeping, so it cannot double-evict; a
    /// missing file (a crash window) is fine.
    fn delete_entry_files(&self, victims: Vec<String>) {
        for victim in victims {
            if let Some(path) = self.entry_path(&victim) {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => eprintln!("narinfo-cache: evict {path:?}: {err}"),
                }
            }
        }
    }

    /// Rebuild bookkeeping from a full scan of every `.nic` (the cold/legacy path,
    /// used ONLY when the sidecar is absent or corrupt). O(entries) - the very cost
    /// the sidecar exists to spare a normal restart. Records positive AND negative
    /// entries so both count toward the cap.
    fn rebuild_from_scan(&self) {
        let Ok(dir) = std::fs::read_dir(&self.root) else {
            return;
        };
        let mut book = self.book.write().expect("book poisoned");
        for entry in dir.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "nic") {
                continue;
            }
            let Some(store_hash) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if safe_key(store_hash).is_none() {
                continue;
            }
            let Ok(raw) = std::fs::read(&path) else {
                continue;
            };
            let Some(decoded) = Entry::decode(&raw) else {
                continue;
            };
            let token = if decoded.kind == EntryKind::Positive {
                crate::catalog::parse_correlation(&decoded.body)
                    .map(|c| c.token.as_str().to_string())
            } else {
                None
            };
            book.remove(store_hash);
            book.insert(store_hash, decoded.fetched_at, token);
        }
    }

    /// Blocking core of [`CorrelationStore::meta_for_token`]: the `token -> hash`
    /// index gives a candidate store_hash, and the authoritative answer is
    /// re-parsed from the actual `.nic` on disk so it cannot drift from the bytes.
    /// The `std::fs::read` + decode here is the disk I/O the async trait impl runs
    /// off-worker (TASK-28).
    fn meta_for_token(&self, token: &str) -> Option<NarMeta> {
        // TTL ASYMMETRY (intentional): unlike `fetch`, correlation does NOT honour
        // the positive TTL - a present positive entry yields correlation even past
        // 30 days. `token -> NarHash` is effectively immutable (the token embeds
        // the content-addressed FileHash), so the mapping does not go stale; and
        // expiring it would drop a warm daemon back to the `UpstreamPath` fallback,
        // which a p2p-only wave-2 NarSource cannot resolve. So we keep it available.
        // See `warm_on_disk_correlation_survives_past_positive_ttl` for the guard.
        let store_hash = self
            .book
            .read()
            .expect("book poisoned")
            .token_index
            .get(token)
            .cloned()?;
        let path = self.entry_path(&store_hash)?;
        let raw = std::fs::read(&path).ok()?;
        let entry = Entry::decode(&raw)?;
        if entry.kind != EntryKind::Positive {
            return None;
        }
        let c = crate::catalog::parse_correlation(&entry.body)?;
        // Confirm the file really carries THIS token (guards a stale index entry).
        if c.token.as_str() != token {
            return None;
        }
        Some(NarMeta {
            nar_hash: NarHash::new(c.nar_hash.as_str()),
            nar_size: c.nar_size,
            transport: c.transport,
        })
    }
}

#[async_trait]
impl NarinfoSource for NarinfoDiskCache {
    async fn fetch(&self, store_hash: &StoreHash) -> Result<UpstreamResponse, SourceError> {
        // A budget-less fetch (lone daemon / no downstream chain client): the
        // MISS path seeds the inner upstream from its own header_timeout.
        self.fetch_within(store_hash, None).await
    }

    async fn fetch_within(
        &self,
        store_hash: &StoreHash,
        budget: Option<std::time::Duration>,
    ) -> Result<UpstreamResponse, SourceError> {
        // 1. Disk hit (fresh, valid): serve verbatim, upstream untouched. A HIT
        // issues NO upstream request, so the chain budget does not apply here.
        // The read + frame-decode + TTL check is blocking `std::fs`, so it runs
        // OFF the Tokio worker on a `spawn_blocking` thread (TASK-28) - the worker
        // stays free to poll other connections while a slow disk answers.
        let hit = {
            let shared = std::sync::Arc::clone(&self.shared);
            let key = store_hash.as_str().to_string();
            tokio::task::spawn_blocking(move || shared.read_fresh(&key))
                .await
                .expect("narinfo cache read task panicked")
        };
        if let Some(entry) = hit {
            return Ok(match entry.kind {
                EntryKind::Positive => positive_response(entry.body),
                EntryKind::Negative => negative_response(),
            });
        }

        // 2. Miss: go to the inner source, FORWARDING the composing chain budget
        // (TASK-33) so the wrapped upstream shares the end-to-end deadline rather
        // than starting a fresh per-hop timeout behind the cache.
        let resp = self.inner.fetch_within(store_hash, budget).await?;
        let status = resp.status;

        if status == 404 {
            // Negative cache the absence off-worker (the install fsyncs), then
            // return a fresh 404. The `fetched_at` stamp is read here (cheap, in
            // memory) BEFORE the blocking install so ordering is unchanged.
            let entry = Entry {
                kind: EntryKind::Negative,
                fetched_at: self.shared.clock.now_unix_secs(),
                body: Vec::new(),
            };
            let shared = std::sync::Arc::clone(&self.shared);
            let key = store_hash.as_str().to_string();
            tokio::task::spawn_blocking(move || shared.install(&key, &entry))
                .await
                .expect("narinfo cache install task panicked");
            return Ok(negative_response());
        }

        if status != 200 {
            // 403/5xx are transient; never cached, forwarded verbatim.
            return Ok(resp);
        }

        // A 200: buffer the body so we can validate before caching AND serve it.
        // Bounded (codex re-gate): the `Limited` READER stops at MAX_NARINFO_BYTES,
        // so the cache layer bounds memory too (its inner source may stream). This
        // is the CACHE-LAYER guard, independent of the serving layer.
        let headers = resp.headers.clone();
        let bytes = http_body_util::Limited::new(resp.body, crate::source::MAX_NARINFO_BYTES)
            .collect()
            .await
            .map_err(|e| {
                SourceError::Upstream(format!(
                    "reading narinfo body (or exceeds {} B): {e}",
                    crate::source::MAX_NARINFO_BYTES
                ))
            })?
            .to_bytes();

        // VALIDATE-THEN-RENAME: a truncated/short narinfo is not well-formed, so
        // it never enters the cache. It is still passed through to the client
        // (which re-verifies), but the next request refetches rather than serving
        // poison from disk.
        //
        // NEVER cache a response the serving layer will FAIL CLOSED on (codex
        // re-gate): a 200 the server turns into a 502 (unsupported transfer-coding
        // OR a malformed Connection header) must not be cached, or request #2 would
        // be a HIT serving 200 - an error response smuggled in as a positive. The
        // synthesised cache-hit response drops those headers, which is exactly how
        // the divergence would leak. Gate insertion on the SAME predicate the
        // server uses, so a fully-received, well-formed, servable 200 - and only
        // that - is cached.
        let cacheable = is_well_formed_narinfo(&bytes)
            && !crate::source::has_unsupported_transfer_coding(&headers)
            && !crate::source::connection_header_is_malformed(&headers)
            && !crate::source::has_ambiguous_framing(&headers);
        if cacheable {
            // The durable install (tmp write + `sync_all` fsync + rename + parent-
            // dir fsync + the sidecar rewrite under the book lock) is the sharp
            // edge TASK-28 targets: run it OFF the worker. The exact same ordered
            // sequence executes inside the closure - only the THREAD changes.
            let entry = Entry {
                kind: EntryKind::Positive,
                fetched_at: self.shared.clock.now_unix_secs(),
                body: bytes.to_vec(),
            };
            let shared = std::sync::Arc::clone(&self.shared);
            let key = store_hash.as_str().to_string();
            tokio::task::spawn_blocking(move || shared.install(&key, &entry))
                .await
                .expect("narinfo cache install task panicked");
        } else {
            eprintln!(
                "narinfo-cache: upstream narinfo for {} not cacheable ({} bytes); not caching",
                store_hash.as_str(),
                bytes.len()
            );
        }

        // Serve the upstream bytes verbatim regardless of caching outcome,
        // preserving the upstream headers.
        Ok(UpstreamResponse {
            status: 200,
            headers,
            body: crate::body::full(bytes),
        })
    }
}

#[async_trait]
impl CorrelationStore for NarinfoDiskCache {
    async fn meta_for_token(&self, token: &str) -> Option<NarMeta> {
        // The correlation lookup re-reads and re-parses the `.nic` from disk, so
        // it runs OFF the Tokio worker (TASK-28): a slow disk here must not stall
        // the `/nar/<token>` request path. The blocking core lives on `Shared`;
        // the semantics (index candidate -> authoritative re-parse, TTL-immune)
        // are unchanged - only the thread differs.
        let shared = std::sync::Arc::clone(&self.shared);
        let token = token.to_string();
        tokio::task::spawn_blocking(move || shared.meta_for_token(&token))
            .await
            .expect("narinfo cache correlation task panicked")
    }
}

/// Whether `body` is a well-formed narinfo: all mandatory signed/transport
/// fields present and parseable. A mid-body truncation drops trailing fields
/// (typically `Sig:`), so it fails here - which is exactly the poisoning guard.
///
/// `References:` may be empty (a leaf path) so only its PRESENCE is required.
/// `Deriver:`/`CA:`/`Compression:`/`FileHash:`/`FileSize:` are optional and not
/// checked. We do NOT verify the signature cryptographically (the client is the
/// arbiter, S1) - but we DO require a `Sig:` line to be PRESENT: it is the last
/// line of a cache.nixos.org-style narinfo, so its presence is the cheapest
/// reliable "not truncated at the tail" signal for the signed upstreams wave 1
/// targets. Consequence (documented in the module header): a legitimately
/// UNSIGNED narinfo fails here and is never cached. Decoupling the two is a
/// wave-2 follow-up.
pub fn is_well_formed_narinfo(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    let mut store_path = false;
    let mut url = false;
    let mut nar_hash = false;
    let mut nar_size = false;
    let mut references = false;
    let mut sig = false;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("StorePath:") {
            store_path |= !v.trim().is_empty();
        } else if let Some(v) = line.strip_prefix("URL:") {
            url |= !v.trim().is_empty();
        } else if let Some(v) = line.strip_prefix("NarHash:") {
            nar_hash |= v.trim().starts_with("sha256:") && v.trim().len() > "sha256:".len();
        } else if let Some(v) = line.strip_prefix("NarSize:") {
            nar_size |= v.trim().parse::<u64>().is_ok();
        } else if line.strip_prefix("References:").is_some() {
            references = true;
        } else if let Some(v) = line.strip_prefix("Sig:") {
            sig |= !v.trim().is_empty();
        }
    }
    store_path && url && nar_hash && nar_size && references && sig
}

/// Reject a store hash that is not a valid Nix store-path hash. A real hash is
/// EXACTLY [`STORE_HASH_LEN`] characters from the [`NIX_BASE32`] alphabet, so any
/// separator, dot, wrong length, NUL, non-base32 letter (`e o u t`), uppercase or
/// non-ASCII is hostile or malformed and bypasses the cache (task-13: the
/// containment guard AND the "non-base32 / wrong-length rejected" claim). Enforced
/// here rather than approximated with `[0-9a-z]` so the claim is exactly true.
fn safe_key(store_hash: &str) -> Option<String> {
    let bytes = store_hash.as_bytes();
    if bytes.len() != STORE_HASH_LEN {
        return None;
    }
    if bytes.iter().all(|b| NIX_BASE32.contains(b)) {
        Some(store_hash.to_string())
    } else {
        None
    }
}

/// Write `bytes` to `path` and fsync the FILE's contents, so a rename that
/// follows can never publish a name pointing at unflushed (zero/garbage) bytes.
/// The caller must [`fsync_dir`] the parent directory AFTER the rename to make the
/// rename itself durable across a crash - this is the same task-7 recipe the rest
/// of the crate uses (see `availability.rs`/`public_allowlist.rs`).
fn write_durably(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// fsync a directory so a rename INTO it survives a crash: opening the dir
/// read-only and `sync_all`ing it is the portable way to fsync a directory. This
/// completes the durable-rename recipe [`write_durably`] starts. Best-effort - a
/// failure is logged, never fatal, since the cache is an optimisation and a lost
/// entry after a crash is a miss (refetch), never a wrong serve.
fn fsync_dir(dir: &Path) {
    match std::fs::File::open(dir) {
        Ok(handle) => {
            if let Err(err) = handle.sync_all() {
                eprintln!("narinfo-cache: fsync dir {dir:?}: {err}");
            }
        }
        Err(err) => eprintln!("narinfo-cache: open dir {dir:?} to fsync: {err}"),
    }
}

/// Evict the oldest entries (smallest `(fetched_at, store_hash)`) from `book`
/// until its live count is at or below `cap`, returning the evicted store hashes
/// so the caller can delete their `.nic` files. `spare` (the just-installed hash,
/// or `None` at startup trim) is never chosen as a victim, so an install's own new
/// entry always survives its own eviction pass. The `.nic` deletion is the
/// caller's job (done outside the lock); this only mutates `book`.
fn evict_over_cap(book: &mut Bookkeeping, cap: usize, spare: Option<&str>) -> Vec<String> {
    let mut victims = Vec::new();
    while book.records.len() > cap {
        let Some(victim) = book
            .lru
            .iter()
            .find(|(_, h)| spare != Some(h.as_str()))
            .cloned()
        else {
            break; // only the spared entry remains
        };
        book.remove(&victim.1);
        victims.push(victim.1);
    }
    victims
}

/// First index of `needle` in `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Build a 200 response carrying the verbatim narinfo body.
///
/// Header asymmetry, stated so it is not mistaken for a bug: a disk HIT
/// synthesises minimal headers here, whereas a cache MISS forwards the upstream
/// headers. This is immaterial to narinfo semantics - byte-verbatimness is a
/// property of the BODY (which is exactly preserved), and the serving layer
/// re-derives `Content-Length` from the bytes it emits regardless.
fn positive_response(body: Vec<u8>) -> UpstreamResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        "text/x-nix-narinfo".parse().unwrap(),
    );
    headers.insert(http::header::CONTENT_LENGTH, body.len().into());
    UpstreamResponse {
        status: 200,
        headers,
        body: crate::body::full(bytes::Bytes::from(body)),
    }
}

/// Build a 404 response for a negatively-cached absent path.
fn negative_response() -> UpstreamResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
    UpstreamResponse {
        status: 404,
        headers,
        body: crate::body::empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &[u8] = b"StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
URL: nar/1abc.nar.xz\n\
Compression: xz\n\
FileHash: sha256:0000\n\
FileSize: 100\n\
NarHash: sha256:1b2c3d\n\
NarSize: 4096\n\
References: \n\
Sig: k:AAAA==\n";

    #[test]
    fn well_formed_accepts_a_complete_narinfo() {
        assert!(is_well_formed_narinfo(GOOD));
    }

    // ---- TASK-29: default-on cache-dir resolution -------------------------

    #[test]
    fn resolve_disabled_beats_an_explicit_dir_and_the_env() {
        // `--no-narinfo-cache` wins over everything (the caller has already
        // rejected the contradictory combination, so this is an honest opt-out).
        let env = |_: &str| Some("/home/u".to_string());
        assert_eq!(
            resolve_narinfo_cache_dir(Some("/srv/cache"), true, env),
            NarinfoCacheChoice::Disabled
        );
    }

    #[test]
    fn resolve_explicit_dir_is_honoured_verbatim() {
        // An explicit dir is used as-is and does NOT consult the environment.
        let env = |_: &str| panic!("explicit dir must not read the environment");
        assert_eq!(
            resolve_narinfo_cache_dir(Some("/srv/cache"), false, env),
            NarinfoCacheChoice::Explicit(PathBuf::from("/srv/cache"))
        );
    }

    #[test]
    fn resolve_default_prefers_xdg_state_home() {
        let env = |k: &str| match k {
            "XDG_STATE_HOME" => Some("/xdg/state".to_string()),
            "HOME" => Some("/home/u".to_string()),
            _ => None,
        };
        assert_eq!(
            resolve_narinfo_cache_dir(None, false, env),
            NarinfoCacheChoice::Default(PathBuf::from("/xdg/state/nix-p2p/narinfo"))
        );
    }

    #[test]
    fn resolve_default_falls_back_to_home_local_state() {
        let env = |k: &str| match k {
            "HOME" => Some("/home/u".to_string()),
            _ => None,
        };
        assert_eq!(
            resolve_narinfo_cache_dir(None, false, env),
            NarinfoCacheChoice::Default(PathBuf::from("/home/u/.local/state/nix-p2p/narinfo"))
        );
    }

    #[test]
    fn resolve_ignores_relative_or_empty_xdg_state_home() {
        // A relative (spec-invalid) or empty XDG_STATE_HOME must not be trusted;
        // fall back to HOME rather than root a cache at a relative path.
        for bad in ["relative/state", ""] {
            let env = move |k: &str| match k {
                "XDG_STATE_HOME" => Some(bad.to_string()),
                "HOME" => Some("/home/u".to_string()),
                _ => None,
            };
            assert_eq!(
                resolve_narinfo_cache_dir(None, false, env),
                NarinfoCacheChoice::Default(PathBuf::from("/home/u/.local/state/nix-p2p/narinfo")),
                "bad XDG_STATE_HOME {bad:?} must fall back to HOME"
            );
        }
    }

    #[test]
    fn resolve_relative_home_yields_no_default() {
        // A relative HOME is as untrustworthy as a relative XDG base.
        let env = |k: &str| match k {
            "HOME" => Some("relative/home".to_string()),
            _ => None,
        };
        assert_eq!(
            resolve_narinfo_cache_dir(None, false, env),
            NarinfoCacheChoice::NoDefault
        );
    }

    #[test]
    fn resolve_no_home_no_xdg_yields_no_default() {
        // Nowhere sensible to put a default -> run pure-upstream (never guess).
        let env = |_: &str| None;
        assert_eq!(
            resolve_narinfo_cache_dir(None, false, env),
            NarinfoCacheChoice::NoDefault
        );
    }

    // ---- TASK-29: choice -> live layer, the shared fatal/soft-fail policy --------

    fn a_upstream() -> std::sync::Arc<dyn NarinfoSource> {
        std::sync::Arc::new(NoopSource)
    }
    fn a_clock() -> std::sync::Arc<dyn Clock> {
        std::sync::Arc::new(SystemClock)
    }
    fn unique_tmp(tag: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "nixp2p-layer-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn build_layer_disabled_and_no_default_pass_through() {
        assert!(matches!(
            build_narinfo_layer(NarinfoCacheChoice::Disabled, a_upstream(), a_clock()),
            NarinfoLayer::PassThrough {
                reason: PassThroughReason::Disabled,
                ..
            }
        ));
        assert!(matches!(
            build_narinfo_layer(NarinfoCacheChoice::NoDefault, a_upstream(), a_clock()),
            NarinfoLayer::PassThrough {
                reason: PassThroughReason::NoDefault,
                ..
            }
        ));
    }

    #[test]
    fn build_layer_default_dir_opens_to_cached() {
        let dir = unique_tmp("ok");
        let layer = build_narinfo_layer(
            NarinfoCacheChoice::Default(dir.clone()),
            a_upstream(),
            a_clock(),
        );
        match layer {
            NarinfoLayer::Cached { dir: got, .. } => assert_eq!(got, dir),
            other => panic!(
                "expected Cached, got a different variant: {other:?}",
                other = variant(&other)
            ),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_layer_default_dir_that_cannot_open_soft_fails() {
        // Root the "dir" UNDER a regular file: create_dir_all fails (ENOTDIR), and a
        // DEFAULT dir must soft-fail to pure-upstream rather than abort.
        let file = unique_tmp("file");
        std::fs::write(&file, b"x").unwrap();
        let bogus = file.join("subdir");
        assert!(matches!(
            build_narinfo_layer(NarinfoCacheChoice::Default(bogus), a_upstream(), a_clock()),
            NarinfoLayer::PassThrough {
                reason: PassThroughReason::DefaultOpenFailed { .. },
                ..
            }
        ));
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn build_layer_explicit_dir_that_cannot_open_is_fatal() {
        // The SAME un-openable path, but EXPLICIT, is fatal (the operator asked).
        let file = unique_tmp("file");
        std::fs::write(&file, b"x").unwrap();
        let bogus = file.join("subdir");
        assert!(matches!(
            build_narinfo_layer(NarinfoCacheChoice::Explicit(bogus), a_upstream(), a_clock()),
            NarinfoLayer::ExplicitOpenFailed { .. }
        ));
        let _ = std::fs::remove_file(&file);
    }

    /// A tiny variant label so a failed `build_layer_*` assertion prints WHICH
    /// variant it got (the layer holds trait objects, so it is not `Debug`).
    fn variant(layer: &NarinfoLayer) -> &'static str {
        match layer {
            NarinfoLayer::Cached { .. } => "Cached",
            NarinfoLayer::PassThrough { .. } => "PassThrough",
            NarinfoLayer::ExplicitOpenFailed { .. } => "ExplicitOpenFailed",
        }
    }

    #[test]
    fn well_formed_rejects_a_mid_body_truncation() {
        // Cut off before the Sig line: the poisoning case AC#4 guards.
        let truncated = b"StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
URL: nar/1abc.nar.xz\n\
NarHash: sha256:1b2c3d\n\
NarSize: 40";
        assert!(!is_well_formed_narinfo(truncated));
    }

    #[test]
    fn frame_roundtrips_verbatim_including_the_body() {
        let entry = Entry {
            kind: EntryKind::Positive,
            fetched_at: 123,
            body: GOOD.to_vec(),
        };
        let decoded = Entry::decode(&entry.encode()).expect("decodes");
        assert_eq!(
            decoded.body, GOOD,
            "body must survive the frame byte-for-byte"
        );
        assert_eq!(decoded.fetched_at, 123);
        assert_eq!(decoded.kind, EntryKind::Positive);
    }

    #[test]
    fn frame_rejects_a_length_mismatch() {
        let mut raw = Entry {
            kind: EntryKind::Positive,
            fetched_at: 1,
            body: GOOD.to_vec(),
        }
        .encode();
        // Lop a byte off the body: body_len no longer matches -> corrupt.
        raw.pop();
        assert!(Entry::decode(&raw).is_none());
    }

    // A canonical valid 32-char nix-base32 store hash (no e/o/u/t).
    const VALID_KEY: &str = "0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz";

    #[test]
    fn safe_key_rejects_traversal() {
        assert!(safe_key("../etc/passwd").is_none());
        assert!(safe_key("a/b").is_none());
        assert!(safe_key("a.b").is_none());
        assert!(safe_key("UPPER").is_none());
        assert_eq!(safe_key(VALID_KEY).as_deref(), Some(VALID_KEY));
    }

    #[test]
    fn safe_key_enforces_nix_base32_alphabet_and_length() {
        assert_eq!(VALID_KEY.len(), STORE_HASH_LEN);
        assert!(safe_key(VALID_KEY).is_some());
        // Wrong length (a store hash is EXACTLY 32): reject shorter and longer.
        assert!(safe_key(&VALID_KEY[..31]).is_none(), "31 chars must reject");
        assert!(
            safe_key(&format!("{VALID_KEY}0")).is_none(),
            "33 chars must reject"
        );
        // Non-base32 letters e/o/u/t (correct length) must reject.
        for bad in ['e', 'o', 'u', 't'] {
            let key: String = std::iter::once(bad)
                .chain(VALID_KEY.chars().skip(1))
                .collect();
            assert_eq!(key.len(), STORE_HASH_LEN);
            assert!(safe_key(&key).is_none(), "nix-base32 must reject {bad:?}");
        }
        // NUL, uppercase and unicode (correct length) must reject.
        assert!(safe_key(&format!("{}\0", &VALID_KEY[..31])).is_none());
        assert!(safe_key(&VALID_KEY.to_uppercase()).is_none());
        let unicode: String = std::iter::once('é')
            .chain(VALID_KEY.chars().skip(1))
            .collect();
        assert!(safe_key(&unicode).is_none(), "non-ascii must reject");
    }

    // ---- AC#3 fuzz: cache-key path traversal must never escape root ---------

    /// A tiny deterministic PRNG (xorshift64*) so the fuzz is seeded and
    /// reproducible - no `rand`/`proptest` dependency, no Date/entropy flakiness.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Build one hostile cache-key candidate from the seed: traversal sequences,
    /// absolute paths, separators, NULs, dots, uppercase, unicode, and absurd
    /// lengths - the AC#3 "path-traversal fuzz on cache keys" corpus.
    fn hostile_key(rng: &mut Rng) -> String {
        const POISON: &[&str] = &[
            "..",
            "../",
            "..%2f",
            "..\\",
            "/",
            "//",
            "/etc/passwd",
            ".",
            "./",
            "a/b",
            "a.b",
            "\0",
            "%00",
            "UP",
            "ﬁ",
            "é",
            " ",
            "\n",
            "\t",
            ":",
            "*",
            "nar/x",
            "..;/",
        ];
        let mut s = String::new();
        let parts = 1 + rng.below(6);
        for _ in 0..parts {
            match rng.below(3) {
                // a legit base32 fragment ...
                0 => {
                    for _ in 0..rng.below(8) {
                        let alphabet = b"0123456789abcdefghijklmnpqrsvwxyz";
                        s.push(alphabet[rng.below(alphabet.len())] as char);
                    }
                }
                // ... spliced with a poison token (the traversal attempt) ...
                1 => s.push_str(POISON[rng.below(POISON.len())]),
                // ... or an absurdly long run.
                _ => s.push_str(&"a".repeat(rng.below(600))),
            }
        }
        s
    }

    #[test]
    fn fuzz_hostile_cache_keys_never_escape_root() {
        let root = PathBuf::from("/var/cache/nixp2p-narinfo");
        let shared = Shared {
            root: root.clone(),
            clock: std::sync::Arc::new(SystemClock),
            positive_ttl: POSITIVE_TTL,
            negative_ttl: NEGATIVE_TTL,
            max_entries: NonZeroUsize::new(DEFAULT_MAX_ENTRIES).unwrap(),
            tmp_seq: AtomicU64::new(0),
            book: RwLock::new(Bookkeeping::default()),
        };
        let mut rng = Rng(0x1234_5678_9abc_def0);
        let mut accepted = 0usize;
        for _ in 0..20_000 {
            let key = hostile_key(&mut rng);
            match shared.entry_path(&key) {
                None => {} // rejected: never touches the filesystem
                Some(path) => {
                    accepted += 1;
                    // If accepted, safe_key already guaranteed a single ascii
                    // [0-9a-z] component. Prove containment structurally: the
                    // parent is exactly root and the file name has no separators
                    // and no traversal component.
                    assert_eq!(
                        path.parent(),
                        Some(root.as_path()),
                        "accepted key {key:?} escaped root: {path:?}"
                    );
                    assert_eq!(
                        path.components().count(),
                        root.components().count() + 1,
                        "accepted key {key:?} added more than one component: {path:?}"
                    );
                    let name = path.file_name().unwrap().to_str().unwrap();
                    assert!(name.ends_with(".nic"));
                    assert!(!name.contains('/') && !name.contains('\\') && name != "..");
                    assert!(path.starts_with(&root));
                }
            }
        }
        // Non-vacuous: a valid base32 key IS accepted (the fuzz can produce one).
        assert_eq!(
            shared
                .entry_path("0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz")
                .unwrap(),
            root.join("0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz.nic"),
        );
        // And the corpus really did probe both branches.
        assert!(
            accepted < 20_000,
            "fuzz must reject SOME hostile keys (else vacuous), accepted {accepted}"
        );
    }

    // ---- AC#3 fuzz: arbitrary well-formed narinfos survive byte-identical ---

    /// Generate a well-formed narinfo with random field ORDERING, random unknown
    /// fields, multiple `Sig:` lines, empty `References`, and mixed line endings.
    /// This extends task-8's byte-verbatim property to a fuzzed corpus.
    ///
    /// SCOPE (codex re-gate): this is a UNIT-level identity fuzz over the two
    /// transforms the daemon applies to a narinfo - `rewrite::apply` (identity in
    /// wave 1) and the disk-cache frame encode/decode. It does NOT fetch through a
    /// daemon chain. CHAIN-level byte-identity of a real narinfo (and its NAR)
    /// through daemon x N is covered by the e2e `chain-s1-and-counts` scenario,
    /// which asserts the client-side NarHash matches the signed manifest through
    /// three hops. The two together cover "arbitrary fields survive" (here) and
    /// "survives the real chain" (e2e) without overclaiming either.
    fn random_narinfo(rng: &mut Rng) -> Vec<u8> {
        let mut fields: Vec<String> = vec![
            "StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".into(),
            "URL: nar/1abc.nar.xz".into(),
            "NarHash: sha256:1b2c3d4e5f".into(),
            format!("NarSize: {}", rng.next() % 1_000_000),
            "References: ".into(),
            "Sig: nix-p2p-test-1:AAAA==".into(),
        ];
        // Random unknown fields (must survive verbatim).
        for _ in 0..rng.below(4) {
            fields.push(format!(
                "X-Unknown-{}: value {}",
                rng.next() % 99,
                rng.next() % 99
            ));
        }
        // Occasionally a second Sig line (multi-sig narinfos are valid).
        if rng.below(2) == 0 {
            fields.push("Sig: other-key-1:BBBB==".into());
        }
        // Optional transport fields in random spots.
        if rng.below(2) == 0 {
            fields.push("Compression: xz".into());
            fields.push("FileHash: sha256:9999".into());
            fields.push("FileSize: 1234".into());
        }
        // Shuffle (Fisher-Yates) so ordering is arbitrary.
        for i in (1..fields.len()).rev() {
            let j = rng.below(i + 1);
            fields.swap(i, j);
        }
        // Mixed line endings, but a trailing newline so the last field is intact.
        let sep = if rng.below(2) == 0 { "\n" } else { "\r\n" };
        let mut body = fields.join(sep);
        body.push('\n');
        body.into_bytes()
    }

    #[test]
    fn fuzz_well_formed_narinfos_roundtrip_byte_identical() {
        let mut rng = Rng(0xdead_beef_cafe_0001);
        let mut well_formed = 0usize;
        for _ in 0..5_000 {
            let body = random_narinfo(&mut rng);
            // The rewrite allowlist is identity (wave 1): bytes must be untouched.
            assert_eq!(
                crate::rewrite::apply(&body).as_ref(),
                body.as_slice(),
                "rewrite must be identity for {:?}",
                String::from_utf8_lossy(&body)
            );
            // Framed disk round-trip must preserve the body byte-for-byte.
            let entry = Entry {
                kind: EntryKind::Positive,
                fetched_at: 42,
                body: body.clone(),
            };
            let decoded =
                Entry::decode(&entry.encode()).expect("a well-formed narinfo frame must decode");
            assert_eq!(
                decoded.body, body,
                "body must survive the frame byte-for-byte"
            );
            if is_well_formed_narinfo(&body) {
                well_formed += 1;
            }
        }
        // Non-vacuous: the generator really does produce cacheable narinfos.
        assert!(
            well_formed > 0,
            "fuzz produced no well-formed narinfos - the property is vacuous"
        );
    }

    /// A no-op inner source so the fuzz can build a `NarinfoDiskCache` without a
    /// live upstream (it only exercises `entry_path`, never `fetch`).
    struct NoopSource;
    #[async_trait]
    impl NarinfoSource for NoopSource {
        async fn fetch(&self, _hash: &StoreHash) -> Result<UpstreamResponse, SourceError> {
            Err(SourceError::Upstream("noop".into()))
        }
    }

    // ---- AC#2 bite: restart warms bookkeeping from the SIDECAR, not a .nic scan -

    /// The load path must warm `book` from the compact sidecar ALONE. Seed a fresh
    /// root with ONLY a sidecar (zero `.nic` bodies) and construct the cache: the
    /// two entries must appear in `book` even though there is nothing to scan. This
    /// is the biting oracle for AC#2 - a mutation that ignores the sidecar and
    /// always calls `rebuild_from_scan` would find ZERO `.nic` files, leave `book`
    /// empty, and redden every assertion below. (An integration test that keeps the
    /// `.nic` files cannot distinguish the two paths; this one can.)
    #[test]
    fn load_index_warms_book_from_sidecar_without_any_nic_file() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "nixp2p-nic-sidecar-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();

        // A positive entry (with a token) and a negative entry (empty token), and
        // NO `.nic` files at all.
        let key_a = VALID_KEY;
        let key_b = "1a0lslqb6gbqnj6xqjlaljjqg6kgb3wz"; // distinct, still valid base32
        let sidecar = format!("{INDEX_MAGIC}\n{key_a}\t100\ttok-a.nar.xz\n{key_b}\t200\t\n");
        std::fs::write(root.join(INDEX_FILE), sidecar).unwrap();

        let cache = NarinfoDiskCache::with_max_entries(
            &root,
            std::sync::Arc::new(NoopSource),
            std::sync::Arc::new(SystemClock),
            NonZeroUsize::new(10).unwrap(),
        )
        .unwrap();

        {
            let book = cache.shared.book.read().unwrap();
            assert_eq!(
                book.records.len(),
                2,
                "both entries warmed from the sidecar with NO .nic present"
            );
            assert_eq!(book.lru.len(), 2, "lru mirrors records exactly");
            assert_eq!(
                book.token_index.get("tok-a.nar.xz").map(String::as_str),
                Some(key_a),
                "the positive entry's token->hash correlation was loaded from the sidecar"
            );
            assert!(
                !book.token_index.contains_key(""),
                "the negative entry's empty token is not indexed"
            );
        }

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The sidecar-reject stance: a duplicate `store_hash` line is corruption and
    /// rejects the WHOLE sidecar (forcing the safe rescan), rather than desyncing
    /// `lru` from `records`. RED if `read_sidecar` accepts duplicates.
    #[test]
    fn read_sidecar_rejects_a_duplicate_hash_line() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "nixp2p-nic-dup-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        // Construct over an EMPTY dir first (construction would otherwise normalise
        // a corrupt sidecar by rescanning + rewriting it), then plant the duplicate
        // and read it directly.
        let cache = NarinfoDiskCache::with_max_entries(
            &root,
            std::sync::Arc::new(NoopSource),
            std::sync::Arc::new(SystemClock),
            NonZeroUsize::new(10).unwrap(),
        )
        .unwrap();
        let dup = format!("{INDEX_MAGIC}\n{VALID_KEY}\t100\t\n{VALID_KEY}\t200\t\n");
        std::fs::write(root.join(INDEX_FILE), dup).unwrap();
        assert!(
            cache.shared.read_sidecar().is_none(),
            "a duplicate-hash sidecar must be rejected wholesale"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ---- AC#1 bite: cache disk I/O runs OFF the Tokio worker ------------------

    /// A `Clock` whose `now_unix_secs()` blocks for `sleep` once `armed`, standing
    /// in for a slow disk/fsync. It returns a CONSTANT time (so TTL freshness is
    /// unaffected - the entry never expires); only the WALL-CLOCK cost is injected.
    /// `read_fresh` calls the clock AFTER decoding the entry, so the block lands
    /// exactly inside the region TASK-28 moves onto `spawn_blocking`.
    struct ArmableSlowClock {
        armed: std::sync::atomic::AtomicBool,
        sleep: Duration,
    }
    impl Clock for ArmableSlowClock {
        fn now_unix_secs(&self) -> u64 {
            if self.armed.load(Ordering::Relaxed) {
                std::thread::sleep(self.sleep);
            }
            1000
        }
    }

    /// THE AC#1 BITE. On a SINGLE-worker (`current_thread`) runtime the cache
    /// serves a disk HIT whose read deliberately blocks for 800 ms (the armed
    /// clock stands in for a slow fsync/disk). A concurrent 50 ms task is started
    /// alongside it. If the blocking read runs OFF the worker (`spawn_blocking`,
    /// TASK-28) the lone worker stays free to poll the 50 ms task, which finishes
    /// FIRST. If the read runs ON the worker (the pre-TASK-28 code, or a mutation
    /// that reverts the `spawn_blocking`) the single thread is stuck in
    /// `thread::sleep(800ms)` and the 50 ms task cannot even start until the fetch
    /// returns - so the fetch records FIRST and the assertion goes RED.
    ///
    /// MUTATION-PROOF: replace the `spawn_blocking(move || shared.read_fresh(&key))`
    /// in `fetch_within` with a direct `self.shared.read_fresh(store_hash.as_str())`
    /// and this test reddens (order becomes `["A", "B"]`).
    #[test]
    fn ac1_cache_read_runs_off_the_tokio_worker() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "nixp2p-nic-offworker-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();

        let clock = std::sync::Arc::new(ArmableSlowClock {
            armed: std::sync::atomic::AtomicBool::new(false),
            sleep: Duration::from_millis(800),
        });
        let cache = std::sync::Arc::new(
            NarinfoDiskCache::with_max_entries(
                &root,
                std::sync::Arc::new(NoopSource), // never consulted on a HIT
                clock.clone(),
                NonZeroUsize::new(10).unwrap(),
            )
            .unwrap(),
        );

        // Populate one valid, fresh entry directly (sync install; the clock is not
        // armed yet, so this is fast). A later fetch of this key is a disk HIT.
        cache.shared.install(
            VALID_KEY,
            &Entry {
                kind: EntryKind::Positive,
                fetched_at: 1000,
                body: GOOD.to_vec(),
            },
        );
        assert!(
            root.join(format!("{VALID_KEY}.nic")).exists(),
            "entry must be on disk so the fetch is a HIT (read_fresh reaches the clock)"
        );

        // Arm the clock so the HIT's `read_fresh` blocks 800 ms inside its read.
        clock.armed.store(true, Ordering::Relaxed);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let order: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        rt.block_on(async {
            let a_cache = cache.clone();
            let a_order = order.clone();
            let a = tokio::spawn(async move {
                let _ = a_cache.fetch(&StoreHash::new(VALID_KEY)).await;
                a_order.lock().unwrap().push("A"); // the slow blocking fetch
            });
            // Let A be polled once so it dispatches its blocking read to the
            // blocking pool and yields (returns Pending) before B starts timing.
            tokio::task::yield_now().await;
            // B: a fast concurrent task. Off-worker -> ~50 ms; on-worker it cannot
            // run until A's 800 ms fetch completes.
            tokio::time::sleep(Duration::from_millis(50)).await;
            order.lock().unwrap().push("B");
            a.await.unwrap();
        });

        let seq = order.lock().unwrap().clone();
        assert_eq!(
            seq.first().copied(),
            Some("B"),
            "the cache read + its blocking clock/fsync must run OFF the worker: a \
             concurrent 50ms task must finish before the 800ms-blocked fetch. Got \
             {seq:?} (\"A\" first == the blocking read starved the worker)"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }
}
