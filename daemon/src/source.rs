//! The capability seams the whole daemon grows behind.
//!
//! Two capability traits, each with one `UpstreamHttp` impl in wave 1:
//!   * [`NarinfoSource`] - narinfo lookup (upstream HTTP now; disk cache in
//!     task-8; p2p relay in v2).
//!   * [`NarSource`] - resolve a NAR *by content identity* to a verified byte
//!     stream (upstream HTTP now; iroh whole-blob in v2).
//!
//! Load-bearing shape (codex NO-GO on the first task-4 cut - fixed here):
//! [`NarSource::resolve`] takes a [`NarKey`] + an expected-size bound, NEVER a
//! URL. `NarKey` is a TYPED enum, not an erased string, so the value crossing
//! the seam declares what it is:
//!   * [`NarKey::SignedNarHash`] - the signed `NarHash` from the narinfo. THIS
//!     is the wave-2 p2p lookup key (a claims index / DHT resolves a NAR by its
//!     signed NarHash, with no upstream URL). It is the identity that flows on
//!     the NORMAL request path.
//!   * [`NarKey::UpstreamPath`] - the raw `nar/`-relative URL token
//!     (FileHash/compression-derived, NOT a signed hash). A degenerate wave-1
//!     fallback used ONLY when the daemon never saw the narinfo this lifetime
//!     (cold start; Nix's 30-day narinfo cache skipped the GET - PRD risk 2).
//!
//! How the signed NarHash reaches the seam (the PRD "learn NarHash at narinfo
//! time" design, minimal form): when a narinfo passes through, the server records
//! `url-token -> (signed NarHash, NarSize)` in an in-memory [`crate::catalog`].
//! When `GET /nar/<token>` then arrives, the server looks the token up and
//! resolves via `SignedNarHash` on a hit - so the normal path carries the signed
//! hash, proving wave-2's key actually flows - or falls back to `UpstreamPath` on
//! a miss. `UpstreamHttp` maps either key to a concrete upstream URL (consulting
//! the same catalog for the `SignedNarHash` case); a wave-2 `IrohNarSource`
//! handles `SignedNarHash` directly and rejects `UpstreamPath`. No serving-layer
//! change is needed for that swap. `tests/nar_source_seam.rs` proves a fake p2p
//! source keyed purely on NarHash (zero URL knowledge) resolves the normal path
//! and rejects the fallback.
//!
//! [`RawUpstream`] is deliberately NOT a capability seam: it is the wave-1
//! transparent-proxy passthrough for path kinds that are neither narinfo nor
//! NAR (`log/*`, `*.ls`, `debuginfo/*`). It is a trait only so that all HTTP
//! client code stays confined to `upstream.rs` (AC#5). A pure-p2p wave-2 daemon
//! may not passthrough arbitrary paths at all; this trait can then go away
//! without touching the two capability seams.

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderMap;
use http_body_util::combinators::BoxBody;

/// Streaming body type shared by upstream responses and client responses.
///
/// Boxed so a 110 MiB NAR never sits whole in memory, and so a fake source and
/// the real client return the *same* type - the seam is only honest if both
/// sides of the swap are interchangeable at the type level.
pub type NarBody = BoxBody<Bytes, std::io::Error>;

/// The `<hash>` component of a `<hash>.narinfo` request target.
///
/// An opaque store-path hash to the serving layer; only `UpstreamHttp` turns it
/// into an upstream URL (`/<hash>.narinfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreHash(String);

impl StoreHash {
    pub fn new(value: impl Into<String>) -> Self {
        StoreHash(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The signed `NarHash` of a NAR (e.g. `sha256:1b2c...`), verbatim from the
/// narinfo's `NarHash:` field.
///
/// This is the trust-anchored content identity: the value Nix signs, the value a
/// wave-2 claims index / DHT keys on, and the value the client re-verifies. It is
/// NOT the URL token (that is [`NarPathToken`], FileHash-derived and rewritten
/// away in wave 2). Kept as a distinct newtype so the two can never be confused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NarHash(String);

impl NarHash {
    pub fn new(value: impl Into<String>) -> Self {
        NarHash(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `nar/`-relative URL path token as it appears on the wire (e.g.
/// `1abc...nar.xz`, WITH any compression suffix). FileHash-derived for
/// cache.nixos.org; a transport detail, NOT a signed hash. Only meaningful to an
/// HTTP upstream, which is why a p2p source rejects it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NarPathToken(String);

impl NarPathToken {
    pub fn new(value: impl Into<String>) -> Self {
        NarPathToken(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The identity a NAR request carries across the seam. A TYPED enum, not an
/// erased string, so the source can dispatch on what the value actually is (the
/// erasure codex flagged in the first cut).
///
/// The variant is the seam's honesty: `SignedNarHash` is the normal,
/// correlated path (the wave-2 p2p key); `UpstreamPath` is the wave-1 cold-start
/// fallback that only an HTTP upstream can resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NarKey {
    /// Correlated at narinfo time: the signed NarHash. The wave-2 lookup key.
    SignedNarHash(NarHash),
    /// Un-correlated cold-start fallback: the raw URL token. HTTP-only.
    UpstreamPath(NarPathToken),
}

/// One upstream response, uniform across narinfo, NAR and passthrough.
///
/// `status` is carried verbatim so the serving layer can honour status fidelity
/// (AC#4): a 404 upstream stays a 404 to the client, a 403 stays a 403. Mapping
/// either to a 5xx would make Nix mark the whole substituter failed instead of
/// "this path is absent here, fall back".
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: NarBody,
}

/// Why an upstream access could not produce a response at all.
///
/// Distinct from a non-200 *response* (which is an `UpstreamResponse` with that
/// status): these are transport failures the serving layer turns into a fast,
/// clean gateway error so Nix falls back quickly (S2 / AC#6 - no hangs on the
/// build path).
#[derive(Debug)]
pub enum SourceError {
    /// Could not reach the upstream (connect refused/timeout, reset before
    /// headers). Mapped to a fast 502.
    Unreachable(String),
    /// The transfer exceeds the signed size bound (PRD risk 6, claim-spam abort).
    /// Produced by a wave-2 p2p `NarSource` transferring the raw NAR against its
    /// signed NarSize (task-25). Wave-1 `UpstreamHttp` does NOT produce it: its
    /// upstream is the trusted CDN (no claim-spam), and it downloads the
    /// compressed file, for which NarSize is the wrong unit.
    TooLarge { limit: u64, declared: u64 },
    /// Any other upstream/protocol error. Mapped to a fast 502.
    Upstream(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::Unreachable(why) => write!(f, "upstream unreachable: {why}"),
            SourceError::TooLarge { limit, declared } => {
                write!(f, "declared size {declared} exceeds bound {limit}")
            }
            SourceError::Upstream(why) => write!(f, "upstream error: {why}"),
        }
    }
}

impl std::error::Error for SourceError {}

/// Narinfo lookup. Wave-1 impl fetches upstream HTTP; task-8 layers a disk
/// cache in front; v2 adds a p2p relay - all behind this one method.
#[async_trait]
pub trait NarinfoSource: Send + Sync {
    async fn fetch(&self, store_hash: &StoreHash) -> Result<UpstreamResponse, SourceError>;
}

/// NAR resolution by content identity ([`NarKey`]) to a verified byte stream.
///
/// `expected_size` is the signed NarSize bound on the raw NAR (`Some` on a
/// correlated request, `None` on the cold-start fallback). It crosses the seam so
/// a wave-2 raw-NAR source can enforce the risk-6 abort (task-25). Wave-1
/// `UpstreamHttp` deliberately ignores it - see [`crate::upstream`] for why
/// (trusted upstream, and NarSize is the wrong unit for the compressed download).
///
/// "Verified" is contract, not yet cryptographic in wave 1: the wave-1
/// `UpstreamHttp` relays upstream bytes faithfully, and the Nix client remains
/// the ultimate arbiter of NarHash (S1). A wave-2 iroh source verifies BLAKE3
/// incrementally before returning bytes, and it handles
/// [`NarKey::SignedNarHash`] while rejecting [`NarKey::UpstreamPath`] (it has no
/// URL to fetch).
#[async_trait]
pub trait NarSource: Send + Sync {
    async fn resolve(
        &self,
        key: &NarKey,
        expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError>;
}

/// Wave-1-only transparent passthrough for path kinds that are neither narinfo
/// nor NAR (`log/*`, `*.ls`, `debuginfo/*`). Not a capability seam - see the
/// module docs. Exists so `nix log` and friends never break (AC#4) while
/// keeping every HTTP-client call inside `upstream.rs`.
#[async_trait]
pub trait RawUpstream: Send + Sync {
    async fn get(&self, path: &str) -> Result<UpstreamResponse, SourceError>;
}
