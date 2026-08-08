//! The capability seams the whole daemon grows behind.
//!
//! Two capability traits, each with one `UpstreamHttp` impl in wave 1:
//!   * [`NarinfoSource`] - narinfo lookup (upstream HTTP now; disk cache in
//!     task-8; p2p relay in v2).
//!   * [`NarSource`] - resolve a NAR *by content identity* to a verified byte
//!     stream (upstream HTTP now; iroh whole-blob in v2).
//!
//! Load-bearing shape (codex flagged this on task-1): [`NarSource::resolve`]
//! takes a [`NarLocator`] + an expected-size bound, NEVER a URL. The mapping
//! from that identity to a concrete upstream URL lives inside `UpstreamHttp` and
//! nowhere else, proven by `tests/no_direct_upstream.rs`.
//! `tests/nar_source_seam.rs` proves a fake `NarSource` with zero URL knowledge
//! satisfies the server - that swappability IS the product of wave 0.
//!
//! What survives the wave-2 iroh swap, stated precisely so it is not over-read:
//! the trait BOUNDARY (identity in, verified bytes out) is stable, and an
//! `IrohNarSource` implementing it needs no serving-layer change. The CALLER
//! does gain work in wave 2, so this is not a free swap: it must correlate the
//! NAR request to the cached narinfo to populate `expected_size` (the risk-6
//! abort bound, `None` today - see [`crate::server`]), and the URL rewrite in
//! [`crate::rewrite`] must fire so the inbound locator is a raw-NAR identity iroh
//! can resolve. The method signature is frozen; the wiring around it is not.
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

/// Opaque content identity of a NAR, as it appears on the binary-cache wire.
///
/// Named a LOCATOR, not a hash, on purpose: in wave 1 it holds the `nar/`
/// -relative URL path token INCLUDING any compression suffix (e.g.
/// `1abc...nar.xz`), which for cache.nixos.org is FileHash-derived - it is NOT
/// the signed `NarHash:` field (a different sha256 value). It is `AC#1`'s
/// `nar_hash` parameter under a truthful name.
///
/// This is the whole point of the seam. To the serving layer the locator is
/// OPAQUE - the server never constructs a URL from it and never assumes an HTTP
/// scheme. `UpstreamHttp` is the only code that interprets it, mapping it back to
/// `/<nar/-relative path>` on the upstream. In wave 2, once the narinfo URL
/// rewrite fires (see [`crate::rewrite`]), the inbound token becomes the raw-NAR
/// BLAKE3 and an `IrohNarSource` resolves it over p2p - same trait, same server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarLocator(String);

impl NarLocator {
    pub fn new(value: impl Into<String>) -> Self {
        NarLocator(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
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
    /// The declared transfer exceeds the caller-supplied bound (PRD risk 6,
    /// claim-spam abort). Dormant in wave-1 passthrough where no bound is known.
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

/// NAR resolution by content identity to a verified byte stream.
///
/// `expected_size` bounds the transfer (PRD risk 6). It is `None` in wave-1
/// passthrough, where the daemon serves a NAR request statelessly and has no
/// narinfo in hand; wave 2 fills it from the signed `NarSize`/`FileSize`.
///
/// "Verified" is contract, not yet cryptographic in wave 1: the wave-1
/// `UpstreamHttp` relays upstream bytes faithfully and enforces the size bound,
/// and the Nix client remains the ultimate arbiter of NarHash (S1). Wave 2's
/// iroh source verifies BLAKE3 incrementally before returning bytes.
#[async_trait]
pub trait NarSource: Send + Sync {
    async fn resolve(
        &self,
        locator: &NarLocator,
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
