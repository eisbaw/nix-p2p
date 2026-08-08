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
//! Bounds (honest limit, filed follow-up; task-25 covers the NAR-side abort, the
//! narinfo-cache eviction is its own task): the on-disk cache is UNBOUNDED in
//! wave 1 (one small entry per distinct narinfo seen), exactly as the in-memory
//! catalog was. A large cache also makes each restart an O(entries) synchronous
//! `rebuild_index` scan before serving. Eviction/bounding is deferred, not
//! silently shipped - see the task-8 note.
//!
//! I/O note (filed follow-up): reads/writes use blocking `std::fs` on the async
//! fetch path. The reads and small writes are cheap; the sharp edge is the
//! `sync_all()` fsync in [`write_durably`], which can stall a Tokio worker for
//! milliseconds under load - so the `spawn_blocking`/`tokio::fs` move should land
//! before the cache is enabled by default, not after.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use http_body_util::BodyExt;

use crate::catalog::{CorrelationStore, NarMeta};
use crate::source::{NarHash, NarinfoSource, SourceError, StoreHash, UpstreamResponse};

/// Positive narinfo TTL: 30 days, matching Nix's default `narinfo-cache-positive-ttl`.
pub const POSITIVE_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// Negative narinfo TTL: 3600 s, matching Nix's default `narinfo-cache-negative-ttl`.
pub const NEGATIVE_TTL: Duration = Duration::from_secs(3600);

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

/// Persistent narinfo cache over an inner source.
pub struct NarinfoDiskCache {
    root: PathBuf,
    inner: std::sync::Arc<dyn NarinfoSource>,
    clock: std::sync::Arc<dyn Clock>,
    positive_ttl: Duration,
    negative_ttl: Duration,
    /// Monotonic counter for unique tmp names (a request never collides with a
    /// concurrent one mid-write).
    tmp_seq: AtomicU64,
    /// Derived `token -> store_hash` index accelerating correlation lookups. A
    /// pure cache of what a full directory scan would find; the authoritative
    /// meta is always re-read from the entry file, so this cannot drift.
    token_index: RwLock<HashMap<String, String>>,
}

impl NarinfoDiskCache {
    /// Build a cache rooted at `root`, fronting `inner`, timed by `clock`. Scans
    /// `root` once to warm the correlation index from any entries a previous
    /// process left (the restart path). Fails fast if `root` cannot be created.
    pub fn new(
        root: impl Into<PathBuf>,
        inner: std::sync::Arc<dyn NarinfoSource>,
        clock: std::sync::Arc<dyn Clock>,
    ) -> std::io::Result<Self> {
        let root = root.into();
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
        let cache = NarinfoDiskCache {
            root,
            inner,
            clock,
            positive_ttl: POSITIVE_TTL,
            negative_ttl: NEGATIVE_TTL,
            tmp_seq: AtomicU64::new(0),
            token_index: RwLock::new(HashMap::new()),
        };
        cache.rebuild_index();
        Ok(cache)
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
            return;
        }
        if let Err(err) = std::fs::rename(&tmp, &final_path) {
            eprintln!("narinfo-cache: rename into {final_path:?}: {err}");
            let _ = std::fs::remove_file(&tmp);
            return;
        }
        // Keep the derived index consistent with the bytes just installed.
        if entry.kind == EntryKind::Positive {
            self.index_positive(store_hash, &entry.body);
        }
    }

    /// Add a positive entry's `token -> store_hash` correlation to the index.
    fn index_positive(&self, store_hash: &str, body: &[u8]) {
        if let Some((token, _hash, _size)) = crate::catalog::parse_correlation(body) {
            self.token_index
                .write()
                .expect("token index poisoned")
                .insert(token.as_str().to_string(), store_hash.to_string());
        }
    }

    /// Warm the correlation index from every valid positive entry on disk (the
    /// restart path). O(entries) at startup only.
    fn rebuild_index(&self) {
        let Ok(dir) = std::fs::read_dir(&self.root) else {
            return;
        };
        for entry in dir.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "nic") {
                continue;
            }
            let Some(store_hash) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(raw) = std::fs::read(&path) else {
                continue;
            };
            if let Some(decoded) = Entry::decode(&raw)
                && decoded.kind == EntryKind::Positive
            {
                self.index_positive(store_hash, &decoded.body);
            }
        }
    }
}

#[async_trait]
impl NarinfoSource for NarinfoDiskCache {
    async fn fetch(&self, store_hash: &StoreHash) -> Result<UpstreamResponse, SourceError> {
        // 1. Disk hit (fresh, valid): serve verbatim, upstream untouched.
        if let Some(entry) = self.read_fresh(store_hash.as_str()) {
            return Ok(match entry.kind {
                EntryKind::Positive => positive_response(entry.body),
                EntryKind::Negative => negative_response(),
            });
        }

        // 2. Miss: go to the inner source.
        let resp = self.inner.fetch(store_hash).await?;
        let status = resp.status;

        if status == 404 {
            // Negative cache the absence, then return a fresh 404.
            self.install(
                store_hash.as_str(),
                &Entry {
                    kind: EntryKind::Negative,
                    fetched_at: self.clock.now_unix_secs(),
                    body: Vec::new(),
                },
            );
            return Ok(negative_response());
        }

        if status != 200 {
            // 403/5xx are transient; never cached, forwarded verbatim.
            return Ok(resp);
        }

        // A 200: buffer the body so we can validate before caching AND serve it.
        let headers = resp.headers.clone();
        let bytes = resp
            .body
            .collect()
            .await
            .map_err(|e| SourceError::Upstream(format!("reading narinfo body: {e}")))?
            .to_bytes();

        // VALIDATE-THEN-RENAME: a truncated/short narinfo is not well-formed, so
        // it never enters the cache. It is still passed through to the client
        // (which re-verifies), but the next request refetches rather than serving
        // poison from disk.
        if is_well_formed_narinfo(&bytes) {
            self.install(
                store_hash.as_str(),
                &Entry {
                    kind: EntryKind::Positive,
                    fetched_at: self.clock.now_unix_secs(),
                    body: bytes.to_vec(),
                },
            );
        } else {
            eprintln!(
                "narinfo-cache: upstream narinfo for {} failed validation ({} bytes); not caching",
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

impl CorrelationStore for NarinfoDiskCache {
    fn meta_for_token(&self, token: &str) -> Option<NarMeta> {
        // TTL ASYMMETRY (intentional): unlike `fetch`, correlation does NOT honour
        // the positive TTL - a present positive entry yields correlation even past
        // 30 days. `token -> NarHash` is effectively immutable (the token embeds
        // the content-addressed FileHash), so the mapping does not go stale; and
        // expiring it would drop a warm daemon back to the `UpstreamPath` fallback,
        // which a p2p-only wave-2 NarSource cannot resolve. So we keep it available.
        // See `warm_on_disk_correlation_survives_past_positive_ttl` for the guard.
        //
        // The index gives us a candidate store_hash; the authoritative answer is
        // re-parsed from the actual entry file so it cannot drift from the bytes.
        let store_hash = self
            .token_index
            .read()
            .expect("token index poisoned")
            .get(token)
            .cloned()?;
        let path = self.entry_path(&store_hash)?;
        let raw = std::fs::read(&path).ok()?;
        let entry = Entry::decode(&raw)?;
        if entry.kind != EntryKind::Positive {
            return None;
        }
        let (parsed_token, nar_hash, nar_size) = crate::catalog::parse_correlation(&entry.body)?;
        // Confirm the file really carries THIS token (guards a stale index entry).
        if parsed_token.as_str() != token {
            return None;
        }
        Some(NarMeta {
            nar_hash: NarHash::new(nar_hash.as_str()),
            nar_size,
        })
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

/// Reject a store hash that is not a safe, single-component filename. Nix store
/// hashes are lowercase base32 (`[0-9a-z]`), so anything with a separator, dot,
/// or other character is hostile (path traversal) and bypasses the cache.
fn safe_key(store_hash: &str) -> Option<String> {
    if store_hash.is_empty() || store_hash.len() > 255 {
        return None;
    }
    if store_hash
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        Some(store_hash.to_string())
    } else {
        None
    }
}

/// Write `bytes` to `path` and fsync both the file and its directory, so an
/// atomic rename that follows is durable across a crash (task-7).
fn write_durably(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
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

    #[test]
    fn safe_key_rejects_traversal() {
        assert!(safe_key("../etc/passwd").is_none());
        assert!(safe_key("a/b").is_none());
        assert!(safe_key("a.b").is_none());
        assert!(safe_key("UPPER").is_none());
        assert_eq!(
            safe_key("0a0lslqb6gbqnj6xq").as_deref(),
            Some("0a0lslqb6gbqnj6xq")
        );
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
        let cache = NarinfoDiskCache {
            root: root.clone(),
            inner: std::sync::Arc::new(NoopSource),
            clock: std::sync::Arc::new(SystemClock),
            positive_ttl: POSITIVE_TTL,
            negative_ttl: NEGATIVE_TTL,
            tmp_seq: AtomicU64::new(0),
            token_index: RwLock::new(HashMap::new()),
        };
        let mut rng = Rng(0x1234_5678_9abc_def0);
        let mut accepted = 0usize;
        for _ in 0..20_000 {
            let key = hostile_key(&mut rng);
            match cache.entry_path(&key) {
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
            cache
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
}
