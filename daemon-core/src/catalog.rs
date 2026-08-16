//! In-memory NAR correlation catalog: the minimal "learn NarHash at narinfo
//! time" mechanism the seam needs (PRD prefetch design, smallest honest form).
//!
//! When a narinfo passes through the daemon, the server records the mapping from
//! its `URL:` token to its signed `NarHash:` (+ `NarSize:`) here. When a
//! `GET /nar/<token>` then arrives, the server consults the catalog to build a
//! [`crate::source::NarKey::SignedNarHash`] on a hit - so the signed hash, the
//! wave-2 lookup key, actually flows across the seam on the normal path - or
//! falls back to `UpstreamPath` on a miss.
//!
//! It is a FORWARD map only (`token -> NarHash+NarSize`). There is deliberately
//! NO reverse `NarHash -> token` map: that mapping is one-to-MANY (two narinfos
//! with the same uncompressed NAR but different compression share a NarHash while
//! having different tokens), so a reverse lookup would serve the wrong compressed
//! bytes for a request. Wave-1 delivery instead carries the exact requested token
//! as `upstream_hint` in the `SignedNarHash` key, so `UpstreamHttp` never
//! consults this catalog at all - it fetches the hint verbatim.
//!
//! Scope, stated so the freeze is honest:
//!   * IN-MEMORY and UNBOUNDED. A long-running daemon accumulates one small entry
//!     per distinct narinfo seen; task-8 (narinfo disk cache) is where this gains
//!     persistence and bounding. Wave-1 correctness does not depend on eviction.
//!   * NOT a claims index and NOT prefetch scheduling - just the correlation map.
//!     The wave-2 DHT/claims resolution replaces the reverse (hash -> transport)
//!     lookup entirely; this catalog is wave-1's stand-in for it.
//!   * How OFTEN the correlated `SignedNarHash` path actually runs in production
//!     (do not over-read "normal path"): only when the daemon SAW the narinfo
//!     this process lifetime. A WARM Nix client skips the narinfo GET entirely
//!     (30-day client cache, PRD risk 2), so repeat/steady-state paths fall to
//!     `UpstreamPath` until task-8 persists narinfos across restarts. The
//!     correlated path is exercised on first-sight-within-a-lifetime; it is what
//!     PROVES the seam can carry the signed hash, which is the point of the
//!     freeze, not a claim about steady-state hit rate.

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;

use crate::source::{NarCompression, NarHash, NarPathToken, NarinfoTransport};

/// What the catalog remembers about one NAR, learned from its narinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarMeta {
    pub nar_hash: NarHash,
    /// Signed `NarSize` (uncompressed NAR bytes) - the wave-2 abort bound.
    pub nar_size: u64,
    /// The narinfo's UNSIGNED transport descriptor (`Compression` only - `FileSize`
    /// is deliberately NOT carried, see [`NarinfoTransport`]) - so the HTTP-delivery
    /// path bounds the on-wire body in the right unit (TASK-25).
    pub transport: NarinfoTransport,
}

/// A PERSISTED correlation source consulted on an in-memory catalog miss.
///
/// task-4 froze the seam with an in-memory [`NarCatalog`] populated at
/// narinfo-serve time; its honest limit was that a WARM Nix client skips the
/// narinfo GET, so after a daemon restart a bare `GET /nar/<token>` had no
/// correlation and fell back to `UpstreamPath`. task-8 closes that: the narinfo
/// disk cache implements this trait, deriving `token -> (NarHash, NarSize)` from
/// the persisted (byte-verbatim) narinfos, so the daemon can still dispatch
/// `SignedNarHash` from a cold-in-memory-but-warm-on-disk state.
///
/// FORWARD-ONLY (`token -> meta`), like [`NarCatalog`]: a NAR request has the
/// token and needs the hash. The lossy reverse map is deliberately not revived.
///
/// ASYNC (TASK-28): the disk-backed implementation re-reads and re-parses a
/// `.nic` file, which is blocking `std::fs`. Making the trait method `async` lets
/// that impl push the read onto `spawn_blocking` so a `/nar/<token>` request never
/// stalls a Tokio worker on a slow disk. In-memory implementations (e.g.
/// [`NullCorrelation`]) simply return without awaiting anything.
#[async_trait]
pub trait CorrelationStore: Send + Sync {
    /// The correlation persisted for this URL token, if any.
    async fn meta_for_token(&self, token: &str) -> Option<NarMeta>;
}

/// A [`CorrelationStore`] that knows nothing - the default when no persistent
/// narinfo cache is wired (pure-upstream daemon, and the fake-source tests that
/// do not exercise persistence). A miss here just yields the `UpstreamPath`
/// fallback, exactly as before task-8.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullCorrelation;

#[async_trait]
impl CorrelationStore for NullCorrelation {
    async fn meta_for_token(&self, _token: &str) -> Option<NarMeta> {
        None
    }
}

/// Forward token -> signed-NarHash+NarSize map, learned as narinfos pass through.
/// FORWARD-ONLY on purpose: see the module docs for why there is no reverse map.
#[derive(Debug, Default)]
pub struct NarCatalog {
    inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// URL token -> (signed NarHash, NarSize). The server reads this at
    /// nar-request time to decide `SignedNarHash` vs `UpstreamPath` and to attach
    /// the signed hash to the request.
    by_token: HashMap<String, NarMeta>,
}

impl NarCatalog {
    pub fn new() -> Self {
        NarCatalog::default()
    }

    /// Record the correlation learned from a narinfo. Idempotent: re-seeing the
    /// same narinfo overwrites with identical data.
    pub fn record(
        &self,
        token: NarPathToken,
        nar_hash: NarHash,
        nar_size: u64,
        transport: NarinfoTransport,
    ) {
        let mut inner = self.inner.write().expect("catalog lock poisoned");
        inner.by_token.insert(
            token.as_str().to_string(),
            NarMeta {
                nar_hash,
                nar_size,
                transport,
            },
        );
    }

    /// Look up what a narinfo told us about this URL token, if we saw it.
    pub fn meta_for_token(&self, token: &str) -> Option<NarMeta> {
        self.inner
            .read()
            .expect("catalog lock poisoned")
            .by_token
            .get(token)
            .cloned()
    }
}

/// The correlation a narinfo yields: the token to key on, the signed identity +
/// size, and the UNSIGNED transport descriptor the HTTP-delivery path needs to
/// bound the on-wire body in the right unit (TASK-25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correlation {
    /// `URL:` with any leading `nar/` stripped - the `/nar/<token>` key.
    pub token: NarPathToken,
    /// Signed `NarHash:` (trust anchor / p2p lookup key).
    pub nar_hash: NarHash,
    /// Signed `NarSize:` (UNCOMPRESSED NAR bytes).
    pub nar_size: u64,
    /// UNSIGNED transport descriptor - the AUTHORITATIVE `Compression:` (raw-vs-compressed).
    pub transport: NarinfoTransport,
}

/// Parse the correlation out of a narinfo body. Returns `None` (recording skipped)
/// unless the MANDATORY trio `URL`/`NarHash`/`NarSize` are all present and
/// well-formed - a malformed narinfo simply falls back to `UpstreamPath` on its NAR
/// request, which is safe.
///
/// The UNSIGNED `Compression` is parsed into [`Correlation::transport`] but is NOT
/// mandatory: absent, unparseable, or DUPLICATED it degrades to `NarCompression::Unknown`
/// (fail-safe to NOT-raw, so the uncompressed NarSize is never applied to a
/// possibly-compressed on-wire body) - it does NOT reject the whole correlation, because
/// the signed trio still lets the normal SignedNarHash path work. `Compression` is the
/// AUTHORITATIVE raw-vs-compressed signal (TASK-25); the daemon must never re-derive it
/// from the URL suffix (a spec-valid narinfo may be `URL: nar/x.nar` + `Compression: xz`).
pub fn parse_correlation(body: &[u8]) -> Option<Correlation> {
    let text = String::from_utf8_lossy(body);
    // FIRST-occurrence, DUPLICATE-REJECTING for the SIGNED trio - the SAME canonical field
    // rule as the publication proof (`public_allowlist::field`), so correlation and proof
    // can never disagree about which value a field carries (the first-vs-last split codex
    // flagged). A duplicated signed field is ambiguous -> no correlation (safe
    // `UpstreamPath` fallback). A duplicated Compression degrades to Unknown (below).
    let mut url: Option<&str> = None;
    let mut nar_hash: Option<&str> = None;
    let mut nar_size_str: Option<&str> = None;
    let mut compression: Option<&str> = None;
    let mut compression_dup = false;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("URL:") {
            if url.is_some() {
                return None;
            }
            url = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("NarHash:") {
            if nar_hash.is_some() {
                return None;
            }
            nar_hash = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("NarSize:") {
            if nar_size_str.is_some() {
                return None;
            }
            nar_size_str = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("Compression:") {
            if compression.is_some() {
                compression_dup = true;
            } else {
                compression = Some(value.trim());
            }
        }
    }
    let url = url?;
    let nar_hash = nar_hash?;
    let nar_size = nar_size_str?.parse::<u64>().ok()?;
    let token = url.strip_prefix("nar/").unwrap_or(url);

    // AUTHORITATIVE raw-vs-compressed (TASK-25): `Compression: none` is raw; any other
    // value is compressed; absent or DUPLICATED (ambiguous) is Unknown -> NOT raw, so the
    // signed NarSize is never applied to the on-wire body. Never inferred from the suffix.
    let compression = if compression_dup {
        NarCompression::Unknown
    } else {
        match compression {
            Some("none") => NarCompression::Raw,
            Some(_) => NarCompression::Compressed,
            None => NarCompression::Unknown,
        }
    };

    Some(Correlation {
        token: NarPathToken::new(token),
        nar_hash: NarHash::new(nar_hash),
        nar_size,
        transport: NarinfoTransport { compression },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NARINFO: &[u8] = b"StorePath: /nix/store/aaaa-x\n\
URL: nar/1abc.nar.xz\n\
Compression: xz\n\
FileHash: sha256:0000\n\
FileSize: 100\n\
NarHash: sha256:1b2c3d\n\
NarSize: 4096\n\
References: \n\
Sig: k:AAAA==\n";

    #[test]
    fn parses_the_three_correlation_fields_and_strips_nar_prefix() {
        let c = parse_correlation(NARINFO).unwrap();
        assert_eq!(c.token.as_str(), "1abc.nar.xz");
        assert_eq!(c.nar_hash.as_str(), "sha256:1b2c3d");
        assert_eq!(c.nar_size, 4096);
        // The UNSIGNED transport descriptor is captured authoritatively.
        assert_eq!(c.transport.compression, NarCompression::Compressed);
    }

    #[test]
    fn compression_is_authoritative_not_the_url_suffix() {
        // THE 6th-recurrence ANTI-TRAP at the parse layer: a spec-valid narinfo whose
        // URL ends `.nar` but whose Compression is `xz` is COMPRESSED - the suffix lies,
        // the Compression field is authoritative.
        let raw_suffix_xz = b"URL: nar/deadbeef.nar\nCompression: xz\nFileSize: 42\n\
NarHash: sha256:abc\nNarSize: 100\n";
        let c = parse_correlation(raw_suffix_xz).unwrap();
        assert_eq!(c.token.as_str(), "deadbeef.nar");
        assert_eq!(
            c.transport.compression,
            NarCompression::Compressed,
            "Compression: xz is COMPRESSED even though the URL ends .nar"
        );

        // Compression: none is Raw (the genuinely-uncompressed endpoint).
        let raw = b"URL: nar/deadbeef.nar\nCompression: none\nFileSize: 100\n\
NarHash: sha256:abc\nNarSize: 100\n";
        assert_eq!(
            parse_correlation(raw).unwrap().transport.compression,
            NarCompression::Raw
        );

        // Absent or DUPLICATED Compression degrades to Unknown (fail-safe NOT-raw),
        // without rejecting the signed-trio correlation.
        let absent = b"URL: nar/deadbeef.nar\nNarHash: sha256:abc\nNarSize: 100\n";
        assert_eq!(
            parse_correlation(absent).unwrap().transport.compression,
            NarCompression::Unknown
        );
        let dup = b"URL: nar/deadbeef.nar\nCompression: none\nCompression: xz\n\
NarHash: sha256:abc\nNarSize: 100\n";
        let c = parse_correlation(dup).unwrap();
        assert_eq!(
            c.transport.compression,
            NarCompression::Unknown,
            "a duplicated Compression is ambiguous -> Unknown, but correlation still stands"
        );
        assert_eq!(c.nar_size, 100);
    }

    #[test]
    fn missing_field_skips_recording() {
        let no_hash = b"URL: nar/1abc.nar.xz\nNarSize: 10\n";
        assert!(parse_correlation(no_hash).is_none());
    }

    #[test]
    fn duplicate_field_skips_recording() {
        // Correlation probe (TASK-102 fix cycle #2): a DUPLICATED single-line field is ambiguous,
        // so `parse_correlation` refuses it (returns None) - the SAME first-occurrence +
        // duplicate-reject rule `public_allowlist::field` enforces, so correlation and the
        // publication proof can never disagree about which value a field carries. Neuter the
        // `is_some() -> None` guard and a first-vs-last split re-opens.
        let dup_url = b"URL: nar/1abc.nar.xz\nURL: nar/evil.nar.xz\n\
NarHash: sha256:1b2c3d\nNarSize: 4096\n";
        assert!(
            parse_correlation(dup_url).is_none(),
            "a duplicate URL is ambiguous and must not correlate"
        );
        let dup_size = b"URL: nar/1abc.nar.xz\nNarHash: sha256:1b2c3d\n\
NarSize: 4096\nNarSize: 1\n";
        assert!(
            parse_correlation(dup_size).is_none(),
            "a duplicate NarSize is ambiguous and must not correlate"
        );
    }

    #[test]
    fn records_and_looks_up_by_token() {
        let catalog = NarCatalog::new();
        let c = parse_correlation(NARINFO).unwrap();
        let hash = c.nar_hash.clone();
        catalog.record(c.token, c.nar_hash, c.nar_size, c.transport);

        let meta = catalog.meta_for_token("1abc.nar.xz").unwrap();
        assert_eq!(meta.nar_hash, hash);
        assert_eq!(meta.nar_size, 4096);
        assert_eq!(meta.transport.compression, NarCompression::Compressed);
        // An unknown token is a miss, not a panic.
        assert!(catalog.meta_for_token("unknown.nar").is_none());
    }

    #[test]
    fn two_tokens_sharing_a_nar_hash_are_both_retained_distinctly() {
        // The one-to-many case that sank the reverse map: same uncompressed NAR
        // (same NarHash), different compression -> different tokens. Each token
        // must resolve to ITS OWN entry so the daemon fetches the right token.
        let catalog = NarCatalog::new();
        let hash = NarHash::new("sha256:sharedhash");
        catalog.record(
            NarPathToken::new("aaaa.nar.xz"),
            hash.clone(),
            4096,
            NarinfoTransport::default(),
        );
        catalog.record(
            NarPathToken::new("bbbb.nar.zst"),
            hash.clone(),
            4096,
            NarinfoTransport::default(),
        );

        // Both forward entries survive carrying the shared hash - neither
        // overwrote the other (a reverse NarHash->token map could not do this).
        assert_eq!(
            catalog.meta_for_token("aaaa.nar.xz").unwrap().nar_hash,
            hash
        );
        assert_eq!(
            catalog.meta_for_token("bbbb.nar.zst").unwrap().nar_hash,
            hash
        );
    }
}
