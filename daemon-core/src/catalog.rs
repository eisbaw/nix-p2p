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

use crate::source::{NarHash, NarPathToken};

/// What the catalog remembers about one NAR, learned from its narinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarMeta {
    pub nar_hash: NarHash,
    /// Signed `NarSize` (uncompressed NAR bytes) - the wave-2 abort bound.
    pub nar_size: u64,
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
pub trait CorrelationStore: Send + Sync {
    /// The correlation persisted for this URL token, if any.
    fn meta_for_token(&self, token: &str) -> Option<NarMeta>;
}

/// A [`CorrelationStore`] that knows nothing - the default when no persistent
/// narinfo cache is wired (pure-upstream daemon, and the fake-source tests that
/// do not exercise persistence). A miss here just yields the `UpstreamPath`
/// fallback, exactly as before task-8.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullCorrelation;

impl CorrelationStore for NullCorrelation {
    fn meta_for_token(&self, _token: &str) -> Option<NarMeta> {
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
    pub fn record(&self, token: NarPathToken, nar_hash: NarHash, nar_size: u64) {
        let mut inner = self.inner.write().expect("catalog lock poisoned");
        inner
            .by_token
            .insert(token.as_str().to_string(), NarMeta { nar_hash, nar_size });
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

/// Parse the correlation fields out of a narinfo body: `(url-token, NarHash,
/// NarSize)`. Returns `None` (recording is skipped) unless all three are
/// present and well-formed - a malformed narinfo simply falls back to
/// `UpstreamPath` on its NAR request, which is safe.
///
/// The URL token is the `URL:` value with any leading `nar/` stripped, so it
/// matches the `/nar/<token>` the client later requests.
pub fn parse_correlation(body: &[u8]) -> Option<(NarPathToken, NarHash, u64)> {
    let text = String::from_utf8_lossy(body);
    // FIRST-occurrence, DUPLICATE-REJECTING - the SAME canonical field rule as the
    // publication proof (`public_allowlist::field`), so correlation and proof can never
    // disagree about which value a field carries (the first-vs-last split codex flagged).
    // A duplicated single-line field is ambiguous; a narinfo carrying one simply does not
    // correlate (it falls back to `UpstreamPath`, which is safe).
    let mut url: Option<&str> = None;
    let mut nar_hash: Option<&str> = None;
    let mut nar_size_str: Option<&str> = None;
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
        }
    }
    let url = url?;
    let nar_hash = nar_hash?;
    let nar_size = nar_size_str?.parse::<u64>().ok()?;
    let token = url.strip_prefix("nar/").unwrap_or(url);
    Some((NarPathToken::new(token), NarHash::new(nar_hash), nar_size))
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
        let (token, hash, size) = parse_correlation(NARINFO).unwrap();
        assert_eq!(token.as_str(), "1abc.nar.xz");
        assert_eq!(hash.as_str(), "sha256:1b2c3d");
        assert_eq!(size, 4096);
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
        let (token, hash, size) = parse_correlation(NARINFO).unwrap();
        catalog.record(token, hash.clone(), size);

        let meta = catalog.meta_for_token("1abc.nar.xz").unwrap();
        assert_eq!(meta.nar_hash, hash);
        assert_eq!(meta.nar_size, 4096);
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
        catalog.record(NarPathToken::new("aaaa.nar.xz"), hash.clone(), 4096);
        catalog.record(NarPathToken::new("bbbb.nar.zst"), hash.clone(), 4096);

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
