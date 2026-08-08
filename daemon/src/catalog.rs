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
//! `UpstreamHttp` also consults it in reverse (signed NarHash -> URL token) to
//! know which upstream URL to fetch for a `SignedNarHash` key, so the seam value
//! stays content-identity while the transport detail lives here and inside
//! `UpstreamHttp`.
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

/// Bidirectional token <-> signed-NarHash map, learned as narinfos pass through.
#[derive(Debug, Default)]
pub struct NarCatalog {
    inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// URL token -> (signed NarHash, NarSize). Server reads this at nar-request
    /// time to decide `SignedNarHash` vs `UpstreamPath`.
    by_token: HashMap<String, NarMeta>,
    /// Derived reverse index of `by_token` (signed NarHash -> URL token), written
    /// together with it under one lock in `record` so the two cannot diverge.
    /// `UpstreamHttp` reads this to fetch a `SignedNarHash` key from the HTTP
    /// upstream.
    token_by_hash: HashMap<String, NarPathToken>,
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
            .token_by_hash
            .insert(nar_hash.as_str().to_string(), token.clone());
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

    /// The URL token to fetch for a signed NarHash, if known. Used by
    /// `UpstreamHttp` to serve a `SignedNarHash` key over HTTP.
    pub fn token_for_hash(&self, nar_hash: &NarHash) -> Option<NarPathToken> {
        self.inner
            .read()
            .expect("catalog lock poisoned")
            .token_by_hash
            .get(nar_hash.as_str())
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
    let mut url = None;
    let mut nar_hash = None;
    let mut nar_size = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("URL:") {
            url = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("NarHash:") {
            nar_hash = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("NarSize:") {
            nar_size = value.trim().parse::<u64>().ok();
        }
    }
    let url = url?;
    let nar_hash = nar_hash?;
    let nar_size = nar_size?;
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
    fn round_trips_both_directions() {
        let catalog = NarCatalog::new();
        let (token, hash, size) = parse_correlation(NARINFO).unwrap();
        catalog.record(token.clone(), hash.clone(), size);

        let meta = catalog.meta_for_token("1abc.nar.xz").unwrap();
        assert_eq!(meta.nar_hash, hash);
        assert_eq!(meta.nar_size, 4096);
        assert_eq!(catalog.token_for_hash(&hash), Some(token));
        // Unknown lookups are misses, not panics.
        assert!(catalog.meta_for_token("unknown.nar").is_none());
        assert!(
            catalog
                .token_for_hash(&NarHash::new("sha256:zzz"))
                .is_none()
        );
    }
}
