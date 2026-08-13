//! `UpstreamHttp`: the impl of all three upstream traits over plain HTTP AND, as
//! of TASK-24, TLS (`https://`). THE ONLY MODULE IN THE DAEMON THAT SPEAKS TO A
//! NETWORK UPSTREAM.
//!
//! TLS (TASK-24): an `https://` base wraps the same TCP connection in a
//! rustls-validated session (over the `ring` provider) BEFORE the hyper http1
//! handshake, so everything below - the verbatim byte forwarding, the
//! no-auto-decompression discipline, the HTTP/1.1-only ceiling - holds
//! unchanged; rustls is a byte transport, not a decoding layer. Certificate
//! validation uses rustls's default `WebPkiServerVerifier` (chain + validity +
//! hostname/SNI) against the compiled-in Mozilla roots ([`webpki_root_store`])
//! or caller-supplied roots ([`UpstreamHttp::with_root_store`]); there is NO
//! insecure-skip-verify path in any production API (the one dangerous verifier
//! lives under `#[cfg(test)]`). The connect+handshake sequence is bounded by the
//! FROZEN [`TlsBudget`] `tls-upstream-v1` (10 s total, connect/handshake ≤ 5 s
//! each), so a stalled TLS peer fails within the bound as a typed [`SourceError`]
//! and Nix falls back - never a hang.
//!
//! AC#5 (the compile-time seam) is enforced by keeping every HTTP-client call -
//! TCP connect, hyper handshake, `send_request` - inside this file. The serving
//! layer (`server.rs`) depends only on the trait objects, never on hyper's
//! client. `tests/no_direct_upstream.rs` greps the source to keep it that way.
//!
//! Byte-fidelity discipline (carried lesson, codex/scout): this client sends NO
//! `Accept-Encoding` and hyper's low-level client does NOT auto-decompress, so
//! an upstream `Content-Encoding: gzip` NAR is forwarded verbatim - bytes,
//! `Content-Encoding` header and `Content-Length` all intact - and the Nix
//! client decompresses and verifies FileHash itself (AC#6). The reqwest-style
//! "silently gunzip and strip the header while forwarding the compressed
//! Content-Length" trap cannot occur here because no decoding layer exists.
//!
//! Protocol scope (HTTP/2 gap, task-13 hardening audit - stated so it is a
//! known ceiling, not a latent surprise): this client speaks HTTP/1.1 ONLY
//! (`hyper::client::conn::http1`, and the `daemon` crate enables only hyper's
//! `http1` feature). The real cache.nixos.org (Fastly) negotiates HTTP/2 over
//! TLS/ALPN but ALSO serves HTTP/1.1 on the same origin, so an h1.1 client
//! reaches it correctly - the daemon does not NEED h2 for wave-1's plain-HTTP
//! upstreams. What it CANNOT do is talk to an h2-ONLY (prior-knowledge/h2c)
//! upstream: the h1 handshake writes an HTTP/1.1 request line and then fails to
//! parse the peer's HTTP/2 frames, which surfaces as a fast, clean
//! [`SourceError`] (a 502 to Nix), never a hang or a mis-decode. That
//! fail-closed behaviour is pinned by `daemon/tests/header_hygiene.rs`
//! (`h2_only_upstream_fails_closed_not_hang`). TASK-24 added TLS but NOT
//! h2/ALPN: the daemon still negotiates no ALPN protocol and speaks h1.1 over
//! TLS, which cache.nixos.org accepts. Adding h2 remains a later concern.
//!
//! Fast-failure discipline (AC#6 / S2): a down upstream must not hang the build
//! path. Connect and header reads are each bounded by a short timeout so a
//! dead/black-holed upstream yields a clean 502 well within 2 s, letting Nix
//! fall back.
//!
//! Wave-1 simplifications, sound for the transparent proxy and documented so
//! they are not mistaken for bugs:
//!   * one upstream connection per request (`Connection: close` semantics via a
//!     fresh handshake). No pooling; Nix reconnects anyway. Pooling is a
//!     measurable-first optimisation, not correctness.
//!   * HTTP/1.1 only, over both plain and TLS. cache.nixos.org serves h1.1 on
//!     the same origin, so the daemon reaches it; an h2-ONLY upstream still fails
//!     closed (above). h2/ALPN negotiation remains a later concern.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http::Uri;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::source::{
    MAX_NARINFO_BYTES, NarKey, NarSource, NarinfoSource, RawUpstream, SourceError, StoreHash,
    UpstreamResponse,
};

/// Upper bound on a buffered (narinfo) body, applied by the `Limited` READER so
/// the read STOPS at the cap (codex re-gate #6): the memory bound is real, not an
/// oversized pre-buffer with a late guard. Shared `MAX_NARINFO_BYTES` so the
/// upstream read, the serving layer and the disk cache all cap at the same value.
const MAX_BUFFERED_BODY: usize = MAX_NARINFO_BYTES;

// ---------------------------------------------------------------------------
// FROZEN `tls-upstream-v1` connect budget (TASK-24 AC#5).
//
// ONE 10 s total covers the whole "reach the TLS peer" sequence - DNS
// resolution, the TCP connect, and the TLS handshake - with the TCP connect and
// the handshake EACH capped at 5 s INSIDE that total. A stalled stage therefore
// fails within the bound and the failure is a typed [`SourceError`], which the
// serving layer turns into a fast 502 so Nix falls back (never a crash or a
// hang). The name is frozen: the production path consumes exactly these values
// (see [`TlsBudget::tls_upstream_v1`], asserted `== default` by a test).
//
// Monotonic timing tests may allow up to `SCHEDULER_GRACE` of scheduler slop on
// top of the configured deadline WITHOUT relaxing the configuration itself.
// ---------------------------------------------------------------------------

/// `tls-upstream-v1`: total wall-clock for DNS + TCP connect + TLS handshake.
pub const TLS_UPSTREAM_TOTAL_MS: u64 = 10_000;
/// `tls-upstream-v1`: cap on the DNS + TCP connect stage, inside the total.
pub const TLS_UPSTREAM_CONNECT_MS: u64 = 5_000;
/// `tls-upstream-v1`: cap on the TLS handshake stage, inside the total.
pub const TLS_UPSTREAM_HANDSHAKE_MS: u64 = 5_000;
/// `tls-upstream-v1`: max scheduler grace a monotonic test may add to the
/// configured deadline before asserting it fired. NOT part of the deadline.
pub const TLS_UPSTREAM_SCHEDULER_GRACE_MS: u64 = 1_000;

/// The frozen `tls-upstream-v1` connect budget: a whole-operation `total`
/// deadline (DNS + TCP connect + TLS handshake) with per-stage caps on the
/// `connect` and `handshake` legs. Each stage waits at most
/// `min(stage_cap, total - elapsed)` so neither the per-stage cap nor the total
/// can be exceeded (see [`stage_budget`]).
#[derive(Debug, Clone, Copy)]
pub struct TlsBudget {
    /// DNS + TCP connect + TLS handshake, end to end.
    pub total: Duration,
    /// DNS + TCP connect stage cap.
    pub connect: Duration,
    /// TLS handshake stage cap.
    pub handshake: Duration,
}

impl TlsBudget {
    /// The FROZEN `tls-upstream-v1` values. The production https path uses these
    /// unchanged; tests may inject a shrunk budget to bite the deadline quickly
    /// on a shared/loaded box (see [`UpstreamHttp::with_tls_budget`]).
    pub const fn tls_upstream_v1() -> Self {
        TlsBudget {
            total: Duration::from_millis(TLS_UPSTREAM_TOTAL_MS),
            connect: Duration::from_millis(TLS_UPSTREAM_CONNECT_MS),
            handshake: Duration::from_millis(TLS_UPSTREAM_HANDSHAKE_MS),
        }
    }
}

impl Default for TlsBudget {
    fn default() -> Self {
        Self::tls_upstream_v1()
    }
}

/// Time a single stage may wait: the smaller of its per-stage cap and whatever
/// remains of the whole-operation `total` after `elapsed`. Saturating, so a
/// total already spent yields `0` (the stage fails immediately rather than
/// waiting a wrapped-around eternity). Pure, so the connect/handshake/total
/// interplay is unit-tested without a network stall.
fn stage_budget(total: Duration, elapsed: Duration, stage_cap: Duration) -> Duration {
    total.saturating_sub(elapsed).min(stage_cap)
}

/// How `UpstreamHttp` reaches the wire: plain TCP, or TCP wrapped in a
/// rustls-validated TLS session. The `Tls` variant carries the validated
/// `server_name` SEPARATELY from the TCP target (`host`/`port`) so the daemon
/// always validates the name it was asked to front, and so tests can point the
/// TCP leg at a loopback fixture while validating the certificate's real name.
/// In every PRODUCTION constructor the two are the same URL host.
#[derive(Debug, Clone)]
enum Transport {
    /// Plain HTTP (the wave-1 path). No handshake stage; the existing short
    /// `connect_timeout`/`header_timeout` govern it unchanged.
    Plain,
    /// HTTPS: a rustls client config (default `WebPkiServerVerifier` - full
    /// chain + hostname/SNI validation, NO skip-verify) plus the validated name.
    Tls {
        config: Arc<rustls::ClientConfig>,
        server_name: ServerName<'static>,
    },
}

/// The Mozilla public-CA trust anchors, compiled in (no filesystem read, so it
/// works identically inside the Nix build sandbox and against the real CDN).
/// These are the roots that chain to cache.nixos.org's Fastly certificate.
fn webpki_root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// Build a rustls client config over the `ring` provider that VALIDATES the
/// server certificate against `roots` using rustls's default
/// `WebPkiServerVerifier` (chain + validity + hostname/SNI). There is
/// deliberately no parameter, method or feature here that swaps in a
/// verification-disabled verifier: the only `dangerous()` verifier in this crate
/// lives under `#[cfg(test)]` and is unreachable in a production build (AC#3).
fn client_config_with_roots(roots: RootCertStore) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        // Infallible for the ring provider with the tls12/tls13 features we
        // compile; a startup panic here would mean a mis-built binary, not a
        // runtime condition, so fail loud rather than thread a Result nobody can
        // act on.
        .expect("ring provider supports the default TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Transparent HTTP(S) client to a single upstream binary cache.
///
/// `http://` connects in plain TCP (the wave-1 path); `https://` wraps the same
/// connection in a rustls-validated TLS session (TASK-24) BEFORE hyper's http1
/// handshake, so the verbatim-forwarding / no-auto-decompression discipline is
/// identical on both - rustls is a byte transport and hyper's low-level client
/// has no decoding layer to gunzip a `Content-Encoding: gzip` NAR.
#[derive(Debug, Clone)]
pub struct UpstreamHttp {
    /// TCP connect target host (an IP or DNS name). For TLS this is also the
    /// validated name in every production constructor.
    host: String,
    port: u16,
    /// Precomputed value for the `Host:` header - `host` for a scheme-default
    /// port (80/443), else `host:port`.
    authority: String,
    connect_timeout: Duration,
    header_timeout: Duration,
    transport: Transport,
    /// The frozen `tls-upstream-v1` connect budget; used only on the TLS path.
    tls_budget: TlsBudget,
}

/// `host:port`, dropping the port when it is the scheme default (80 for http,
/// 443 for https) so the `Host:` header matches what a browser sends to the CDN.
fn authority_for(host: &str, port: u16, default_port: u16) -> String {
    if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

impl UpstreamHttp {
    /// Build a client for `base`, e.g. `http://127.0.0.1:8080` or
    /// `https://cache.nixos.org`. Fails fast on a malformed base rather than
    /// deferring the error to the first request. An `https://` base validates
    /// against the compiled-in Mozilla public-CA roots (the anchors that reach
    /// the real CDN); use [`with_root_store`](Self::with_root_store) to supply a
    /// private/operator trust anchor set instead.
    ///
    /// Needs no catalog: for a [`NarKey::SignedNarHash`] the request already
    /// carries the exact URL token as `upstream_hint`, which this client fetches
    /// verbatim - it never reconstructs a token from the hash.
    pub fn new(base: &str) -> Result<Self, String> {
        let (scheme, host, port) = parse_authority(base)?;
        match scheme {
            Scheme::Http => Ok(Self::plain(host, port)),
            Scheme::Https => Self::tls(host, port, webpki_root_store()),
        }
    }

    /// Build an `https://` client validating the certificate chain against the
    /// caller-supplied `roots` (the "configured roots" path, AC#3) instead of
    /// the system/Mozilla bundle. Still uses rustls's default
    /// `WebPkiServerVerifier` - chain, validity AND hostname/SNI are all
    /// enforced; there is no verification-disabled variant. Rejects an
    /// `http://`/portless base, which cannot carry a validated name.
    pub fn with_root_store(base: &str, roots: RootCertStore) -> Result<Self, String> {
        let (scheme, host, port) = parse_authority(base)?;
        match scheme {
            Scheme::Https => Self::tls(host, port, roots),
            Scheme::Http => Err(format!("with_root_store needs an https base, got {base:?}")),
        }
    }

    fn plain(host: String, port: u16) -> Self {
        UpstreamHttp {
            authority: authority_for(&host, port, 80),
            host,
            port,
            // Short by design (AC#6): a down upstream fails clean, fast.
            connect_timeout: Duration::from_millis(1000),
            header_timeout: Duration::from_millis(1000),
            transport: Transport::Plain,
            tls_budget: TlsBudget::tls_upstream_v1(),
        }
    }

    fn tls(host: String, port: u16, roots: RootCertStore) -> Result<Self, String> {
        // The validated name IS the URL host in every production path.
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| format!("invalid TLS server name {host:?}: {e}"))?;
        Ok(UpstreamHttp {
            authority: authority_for(&host, port, 443),
            host,
            port,
            connect_timeout: Duration::from_millis(1000),
            header_timeout: Duration::from_millis(1000),
            transport: Transport::Tls {
                config: Arc::new(client_config_with_roots(roots)),
                server_name,
            },
            tls_budget: TlsBudget::tls_upstream_v1(),
        })
    }

    /// Override the `tls-upstream-v1` connect budget. The DEFAULT is the frozen
    /// v1 values; this exists so a test can shrink the deadline to bite quickly
    /// on a loaded box, and so TASK-111 can tune real-HTTPS timeouts later. It
    /// does NOT weaken verification - only timing.
    pub fn with_tls_budget(mut self, budget: TlsBudget) -> Self {
        self.tls_budget = budget;
        self
    }

    /// Override the per-hop upstream header timeout (default 1000 ms).
    ///
    /// KNOWN CEILING (task-33, characterised by the task-13 fault x depth
    /// matrix): this is a FIXED per-hop deadline - each daemon starts its own
    /// clock when IT sends its upstream request. It does NOT compose across a
    /// daemon chain: inner hops fetch serially, so at depth the deepest
    /// upstream's effective deadline is the OUTERMOST hop's timeout minus the
    /// accumulated per-hop connect/send overhead. Relationship: an upstream
    /// whose header latency is L is served iff L + (depth-1)*overhead <
    /// header_timeout at every hop, so the OUTERMOST hop is the first to 502 as
    /// L approaches the timeout. On a loopback chain the per-hop overhead is
    /// sub-millisecond, so the observable flip is governed by L vs
    /// `header_timeout` (depth-composition is real but WAN-scale, below the
    /// loopback noise floor - see TESTING.md). Making the deadline budget-aware
    /// across hops (and validating it at real WAN RTT) is wave-2 work owned by
    /// task-15 (re-plan) and task-33/task-35 (the reopened finding + real-upstream
    /// re-measure); exposing this knob lets an operator (and the e2e boundary pin)
    /// move the L-vs-T ceiling deliberately.
    pub fn with_header_timeout(mut self, header_timeout: Duration) -> Self {
        self.header_timeout = header_timeout;
        self
    }

    /// Open a fresh connection, send a GET for `path`, and return the response
    /// with its body still unread (streamed lazily by the caller). Dispatches on
    /// the transport: plain TCP, or TCP + rustls-validated TLS.
    async fn send(
        &self,
        path: &str,
    ) -> Result<hyper::Response<hyper::body::Incoming>, SourceError> {
        match &self.transport {
            Transport::Plain => {
                let stream = timeout(
                    self.connect_timeout,
                    TcpStream::connect((self.host.as_str(), self.port)),
                )
                .await
                .map_err(|_| {
                    SourceError::Unreachable(format!("connect timed out to {}", self.authority))
                })?
                .map_err(|e| {
                    SourceError::Unreachable(format!("connect to {}: {e}", self.authority))
                })?;
                self.send_over(TokioIo::new(stream), path).await
            }
            Transport::Tls {
                config,
                server_name,
            } => {
                // FROZEN tls-upstream-v1: one `total` deadline over DNS + TCP
                // connect + TLS handshake, with each stage additionally capped.
                // A stalled stage fails within the bound as a typed error, so the
                // serving layer 502s and Nix falls back - never a hang.
                let start = Instant::now();
                let connect_cap = stage_budget(
                    self.tls_budget.total,
                    Duration::ZERO,
                    self.tls_budget.connect,
                );
                let stream = timeout(
                    connect_cap,
                    TcpStream::connect((self.host.as_str(), self.port)),
                )
                .await
                .map_err(|_| {
                    SourceError::Unreachable(format!("tls connect timed out to {}", self.authority))
                })?
                .map_err(|e| {
                    SourceError::Unreachable(format!("tls connect to {}: {e}", self.authority))
                })?;

                let handshake_cap = stage_budget(
                    self.tls_budget.total,
                    start.elapsed(),
                    self.tls_budget.handshake,
                );
                let connector = TlsConnector::from(config.clone());
                let tls = timeout(
                    handshake_cap,
                    connector.connect(server_name.clone(), stream),
                )
                .await
                .map_err(|_| {
                    SourceError::Unreachable(format!(
                        "tls handshake timed out to {}",
                        self.authority
                    ))
                })?
                // A verification failure (untrusted/self-signed, wrong host,
                // expired) surfaces HERE, before any request byte is sent or
                // any response byte is read/cached.
                .map_err(|e| {
                    SourceError::Upstream(format!("tls handshake to {}: {e}", self.authority))
                })?;
                self.send_over(TokioIo::new(tls), path).await
            }
        }
    }

    /// The hyper http1 handshake + request send, shared by both transports. `IO`
    /// is `TokioIo<TcpStream>` (plain) or `TokioIo<TlsStream<TcpStream>>` (TLS);
    /// neither adds a decoding layer, so byte forwarding is identical (AC#2).
    async fn send_over<IO>(
        &self,
        io: IO,
        path: &str,
    ) -> Result<hyper::Response<hyper::body::Incoming>, SourceError>
    where
        IO: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    {
        let (mut sender, conn) = http1::handshake(io)
            .await
            .map_err(|e| SourceError::Upstream(format!("handshake: {e}")))?;
        // The connection driver must run concurrently with body streaming; it
        // ends when the body is fully read or dropped.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let uri: Uri = path
            .parse()
            .map_err(|e| SourceError::Upstream(format!("bad upstream path {path:?}: {e}")))?;
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(uri)
            .header(hyper::header::HOST, &self.authority)
            .body(Empty::<Bytes>::new())
            .map_err(|e| SourceError::Upstream(format!("build request: {e}")))?;

        let response = timeout(self.header_timeout, sender.send_request(request))
            .await
            .map_err(|_| {
                SourceError::Unreachable(format!("no response headers from {}", self.authority))
            })?
            .map_err(|e| SourceError::Upstream(format!("send request: {e}")))?;
        Ok(response)
    }

    /// Fetch a small body in full (narinfo): needed so the rewrite allowlist can
    /// be applied and byte-fidelity asserted. Bounded by [`MAX_BUFFERED_BODY`].
    async fn fetch_buffered(&self, path: &str) -> Result<UpstreamResponse, SourceError> {
        let response = self.send(path).await?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let collected = Limited::new(response.into_body(), MAX_BUFFERED_BODY)
            .collect()
            .await
            .map_err(|e| SourceError::Upstream(format!("reading body from {path}: {e}")))?;
        let bytes = collected.to_bytes();
        Ok(UpstreamResponse {
            status,
            headers,
            body: crate::body::full(bytes),
        })
    }

    /// Fetch a body by streaming it straight through (NAR, passthrough): the
    /// body never sits whole in memory.
    ///
    /// `expected_size` is deliberately NOT enforced here (see `_expected_size`).
    /// The PRD-risk-6 abort is a defense against *untrusted peers* claiming a huge
    /// blob; wave-1's upstream is the trusted cache.nixos.org, which poses no such
    /// threat. Worse, the bound would be wrong-unit: `expected_size` is the signed
    /// NarSize (the raw, uncompressed NAR - the wave-2 addressed unit), but this
    /// HTTP path downloads the *compressed* file, whose length is FileSize.
    /// FileSize can exceed NarSize for tiny/incompressible NARs (container
    /// overhead), so enforcing NarSize here would 502 legitimate content. The
    /// abort belongs to the wave-2 NarSource, which transfers the raw NAR and for
    /// which NarSize is the right bound (task-25). `expected_size` still crosses
    /// the seam so that source has it.
    ///
    /// Scope limit (honest gap): `connect_timeout`/`header_timeout` bound connect
    /// and header arrival, but NOTHING here bounds an upstream that sends headers
    /// then stalls the body indefinitely - the response to Nix would hang. The
    /// fault suite exercises only terminating faults (reset/truncate/latency), so
    /// the open-ended stall is untested. A per-read/idle timeout (and the wave-2
    /// throughput-abort hedge) is filed as task-25; wave-1 "no hang on the build
    /// path" therefore holds for connect/header failures, not body stalls.
    async fn fetch_streaming(
        &self,
        path: &str,
        _expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        let response = self.send(path).await?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.into_body().map_err(std::io::Error::other).boxed();
        Ok(UpstreamResponse {
            status,
            headers,
            body,
        })
    }
}

/// Upstream URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

/// Split `https://host[:port]`, `http://host[:port]` (or a bare `host[:port]`,
/// treated as http) into scheme + host + port. The port defaults to the scheme
/// default when absent: 80 for http, 443 for https (TASK-24 accepts https).
fn parse_authority(base: &str) -> Result<(Scheme, String, u16), String> {
    let (scheme, rest) = if let Some(rest) = base.strip_prefix("https://") {
        (Scheme::Https, rest)
    } else if let Some(rest) = base.strip_prefix("http://") {
        (Scheme::Http, rest)
    } else {
        (Scheme::Http, base)
    };
    let default_port = match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    let authority = rest.trim_end_matches('/');
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .map_err(|_| format!("bad port in upstream {base:?}"))?;
            Ok((scheme, host.to_string(), port))
        }
        None => Ok((scheme, authority.to_string(), default_port)),
    }
}

#[async_trait]
impl NarinfoSource for UpstreamHttp {
    async fn fetch(&self, store_hash: &StoreHash) -> Result<UpstreamResponse, SourceError> {
        // The store hash is the only thing the serving layer knows; THIS is
        // where it becomes a URL, and the only place.
        self.fetch_buffered(&format!("/{}.narinfo", store_hash.as_str()))
            .await
    }
}

#[async_trait]
impl NarSource for UpstreamHttp {
    async fn resolve(
        &self,
        key: &NarKey,
        expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        // The content identity becomes an upstream URL HERE and nowhere else -
        // the seam that lets wave 2 swap in an iroh source (which resolves the
        // SignedNarHash over p2p, and rejects UpstreamPath) behind the same
        // trait. This HTTP impl fetches by the URL token in either case, and
        // crucially fetches the EXACT token the request carried - never one
        // reconstructed from the hash (which is one-to-many across compression).
        let token = match key {
            NarKey::SignedNarHash { upstream_hint, .. } => upstream_hint.as_str(),
            NarKey::UpstreamPath(token) => token.as_str(),
        };
        self.fetch_streaming(&format!("/nar/{token}"), expected_size)
            .await
    }
}

#[async_trait]
impl RawUpstream for UpstreamHttp {
    async fn get(&self, path: &str) -> Result<UpstreamResponse, SourceError> {
        self.fetch_streaming(path, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_upstream_forms() {
        assert_eq!(
            parse_authority("http://127.0.0.1:8080").unwrap(),
            (Scheme::Http, "127.0.0.1".to_string(), 8080)
        );
        assert_eq!(
            parse_authority("example.com").unwrap(),
            (Scheme::Http, "example.com".to_string(), 80)
        );
    }

    #[test]
    fn https_base_defaults_to_443_and_is_accepted() {
        // AC#1: an https base is accepted (no longer the wave-1 rejection) and
        // defaults to port 443.
        assert_eq!(
            parse_authority("https://cache.nixos.org").unwrap(),
            (Scheme::Https, "cache.nixos.org".to_string(), 443)
        );
        let client = UpstreamHttp::new("https://cache.nixos.org").expect("https base accepted");
        assert!(matches!(client.transport, Transport::Tls { .. }));
        // Host header drops the default 443.
        assert_eq!(client.authority, "cache.nixos.org");
    }

    #[test]
    fn rejects_bad_port() {
        assert!(UpstreamHttp::new("http://host:notaport").is_err());
    }

    #[test]
    fn stage_budget_caps_by_stage_and_by_total() {
        let total = Duration::from_millis(10_000);
        // Fresh: the connect cap bites (5 s < 10 s remaining).
        assert_eq!(
            stage_budget(total, Duration::ZERO, Duration::from_millis(5_000)),
            Duration::from_millis(5_000)
        );
        // Late in the operation: the TOTAL remaining bites (2 s < 5 s cap).
        assert_eq!(
            stage_budget(
                total,
                Duration::from_millis(8_000),
                Duration::from_millis(5_000)
            ),
            Duration::from_millis(2_000)
        );
        // Total already spent: the stage gets zero, failing at once.
        assert_eq!(
            stage_budget(
                total,
                Duration::from_millis(12_000),
                Duration::from_millis(5_000)
            ),
            Duration::ZERO
        );
    }

    #[test]
    fn tls_upstream_v1_budget_is_frozen() {
        // AC#5: the production path consumes tls-upstream-v1 UNCHANGED.
        let v1 = TlsBudget::tls_upstream_v1();
        assert_eq!(v1.total, Duration::from_millis(10_000));
        assert_eq!(v1.connect, Duration::from_millis(5_000));
        assert_eq!(v1.handshake, Duration::from_millis(5_000));
        assert_eq!(TLS_UPSTREAM_SCHEDULER_GRACE_MS, 1_000);
        // Each stage cap fits inside the total, and the two stages together
        // cannot exceed it.
        assert!(v1.connect <= v1.total);
        assert!(v1.handshake <= v1.total);
        assert!(v1.connect + v1.handshake <= v1.total);
        // Default == v1 (a new UpstreamHttp gets the frozen budget).
        let default = TlsBudget::default();
        assert_eq!(default.total, v1.total);
        assert_eq!(default.connect, v1.connect);
        assert_eq!(default.handshake, v1.handshake);
    }
}

/// End-to-end TLS cert-validation bites (TASK-24 AC#1-#5).
///
/// A `rcgen` fixture CA issues a VALID-hostname leaf plus the three negatives
/// (untrusted self-signed, wrong-hostname, expired). Each is presented by an
/// in-process `tokio-rustls` server on loopback; the client validates against a
/// root store containing ONLY the fixture CA, exactly as production validates
/// against the Mozilla bundle. The negatives each carry their OWN bite control:
/// swapping in the `#[cfg(test)]`-only insecure verifier makes the SAME server
/// succeed, proving the rejection is caused by certificate validation and not by
/// unrelated plumbing. That insecure verifier is compiled ONLY under
/// `#[cfg(test)]` and is unreachable from any production API (AC#3).
#[cfg(test)]
mod tls_tests {
    use super::*;

    use std::net::SocketAddr;

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use http_body_util::BodyExt;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, date_time_ymd,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::Write as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    // --- fixture CA + leaf issuance ---------------------------------------

    /// A self-signed fixture CA: returns its DER (for the client root store) and
    /// an `Issuer` (owning the CA params + key) that signs leaves.
    fn fixture_ca() -> (CertificateDer<'static>, Issuer<'static, KeyPair>) {
        let ca_key = KeyPair::generate().expect("ca keypair");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "nix-p2p fixture CA");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = params.self_signed(&ca_key).expect("self-sign ca");
        let ca_der = ca_cert.der().clone();
        let issuer = Issuer::new(params, ca_key);
        (ca_der, issuer)
    }

    /// A serverAuth leaf for `san`, signed by the fixture CA. `expired` narrows
    /// the (very wide) rcgen default validity to 2000..2001 so the verifier's
    /// validity check bites.
    fn leaf_signed_by(
        issuer: &Issuer<'static, KeyPair>,
        san: &str,
        expired: bool,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().expect("leaf keypair");
        let mut params = CertificateParams::new(vec![san.to_string()]).expect("leaf params");
        params.distinguished_name.push(DnType::CommonName, san);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if expired {
            params.not_before = date_time_ymd(2000, 1, 1);
            params.not_after = date_time_ymd(2001, 1, 1);
        }
        let cert = params.signed_by(&key, issuer).expect("sign leaf");
        (
            cert.der().clone(),
            PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
    }

    /// A serverAuth leaf for `san` signed by its OWN key (untrusted: chains to no
    /// CA in the client root store).
    fn self_signed_leaf(san: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().expect("keypair");
        let mut params = CertificateParams::new(vec![san.to_string()]).expect("params");
        params.distinguished_name.push(DnType::CommonName, san);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.self_signed(&key).expect("self-sign");
        (
            cert.der().clone(),
            PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
    }

    fn roots_with(ca: &CertificateDer<'static>) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone()).expect("add fixture CA");
        roots
    }

    // --- in-process servers ------------------------------------------------

    /// One canned HTTP/1.1 200 response with `body` and an optional
    /// `Content-Encoding` (used to prove the byte-verbatim / no-decompress path).
    fn http_response(body: &[u8], content_encoding: Option<&str>) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/x-nix-nar\r\ncontent-length: {}\r\n",
            body.len()
        );
        if let Some(ce) = content_encoding {
            head.push_str(&format!("content-encoding: {ce}\r\n"));
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// Read a request's headers, then write `response`. Generic over the stream so
    /// the SAME responder serves both the TLS and the plain-HTTP legs of the
    /// verbatim comparison.
    async fn serve_response<S>(mut stream: S, response: Vec<u8>)
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let mut acc = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => {
                    acc.extend_from_slice(&buf[..n]);
                    if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => return,
            }
        }
        let _ = stream.write_all(&response).await;
        let _ = stream.flush().await;
        // Ordered close (TLS close_notify then FIN) so the client reads the whole
        // body before EOF.
        let _ = stream.shutdown().await;
    }

    fn server_config(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> rustls::ServerConfig {
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring server protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("valid server cert/key")
    }

    /// Loops accepting TLS connections, serving `response` on each (a failed
    /// handshake just drops). Loops so a rejected-then-insecure retry both land.
    async fn spawn_https(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        response: Vec<u8>,
    ) -> SocketAddr {
        let acceptor = TlsAcceptor::from(Arc::new(server_config(chain, key)));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let response = response.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(sock).await {
                        serve_response(tls, response).await;
                    }
                });
            }
        });
        addr
    }

    async fn spawn_http(response: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let response = response.clone();
                tokio::spawn(async move {
                    serve_response(sock, response).await;
                });
            }
        });
        addr
    }

    /// Accepts TCP connections and HOLDS them without ever speaking TLS, so the
    /// client's handshake stalls until its deadline fires.
    async fn spawn_tcp_blackhole() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                match listener.accept().await {
                    Ok((sock, _)) => held.push(sock),
                    Err(_) => return,
                }
            }
        });
        addr
    }

    // --- client wiring -----------------------------------------------------

    /// A TLS `UpstreamHttp` whose TCP target is `addr` (loopback) while it
    /// VALIDATES `validated_name` - the split needed to exercise wrong-hostname
    /// deterministically. Production constructors always set the two equal.
    fn tls_client(
        addr: SocketAddr,
        validated_name: &str,
        config: Arc<rustls::ClientConfig>,
        budget: TlsBudget,
    ) -> UpstreamHttp {
        UpstreamHttp {
            host: addr.ip().to_string(),
            port: addr.port(),
            authority: validated_name.to_string(),
            connect_timeout: Duration::from_millis(1000),
            header_timeout: Duration::from_millis(1000),
            transport: Transport::Tls {
                config,
                server_name: ServerName::try_from(validated_name.to_string())
                    .expect("valid server name"),
            },
            tls_budget: budget,
        }
    }

    fn secure_config(ca: &CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
        Arc::new(client_config_with_roots(roots_with(ca)))
    }

    /// The ONLY verification-disabled verifier in the crate. `#[cfg(test)]`, so it
    /// cannot exist in a production build; used solely to PROVE the negative bites.
    #[derive(Debug)]
    struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    fn insecure_config() -> Arc<rustls::ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("ring protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        Arc::new(cfg)
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).expect("gzip write");
        enc.finish().expect("gzip finish")
    }

    /// A negative with its bite control: the real verifier REJECTS (no bytes),
    /// and the SAME server ACCEPTS once verification is neutralized.
    async fn assert_rejected_with_bite(
        addr: SocketAddr,
        validated_name: &str,
        ca: &CertificateDer<'static>,
    ) {
        let secure = tls_client(
            addr,
            validated_name,
            secure_config(ca),
            TlsBudget::default(),
        );
        assert!(
            secure.get("/nar/x").await.is_err(),
            "the real WebPkiServerVerifier must reject this cert before any byte is forwarded"
        );
        let insecure = tls_client(
            addr,
            validated_name,
            insecure_config(),
            TlsBudget::default(),
        );
        let resp = insecure
            .get("/nar/x")
            .await
            .expect("bite: with verification neutralized the SAME cert now connects");
        assert_eq!(
            resp.status, 200,
            "the rejection above was caused by cert validation, not plumbing"
        );
    }

    // --- tests -------------------------------------------------------------

    /// AC#1 + AC#2: an https base connects over TLS against a fixture-CA valid
    /// hostname, and the gzip body comes back byte-identical to the plain-HTTP
    /// leg with `Content-Encoding: gzip` intact (no auto-decompression).
    #[tokio::test]
    async fn tls_valid_hostname_forwards_bytes_verbatim_like_plain_http() {
        let (ca, issuer) = fixture_ca();
        let (leaf, key) = leaf_signed_by(&issuer, "valid.test", false);
        let body = gzip(b"a nix NAR payload the daemon must NOT decode on the way through");
        let response = http_response(&body, Some("gzip"));

        let tls_addr = spawn_https(vec![leaf], key, response.clone()).await;
        let http_addr = spawn_http(response).await;

        let tls = tls_client(
            tls_addr,
            "valid.test",
            secure_config(&ca),
            TlsBudget::default(),
        );
        let tls_resp = tls
            .get("/nar/x")
            .await
            .expect("valid fixture-CA cert connects over TLS");
        assert_eq!(tls_resp.status, 200);
        assert_eq!(
            tls_resp
                .headers
                .get("content-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("gzip"),
            "Content-Encoding must survive the TLS hop verbatim"
        );
        let tls_bytes = tls_resp
            .body
            .collect()
            .await
            .expect("collect tls")
            .to_bytes();

        let plain = UpstreamHttp::new(&format!("http://{http_addr}")).expect("http base");
        let plain_bytes = plain
            .get("/nar/x")
            .await
            .expect("plain http")
            .body
            .collect()
            .await
            .expect("collect http")
            .to_bytes();

        assert_eq!(
            tls_bytes.as_ref(),
            body.as_slice(),
            "bytes over TLS are the raw gzip body, not gunzipped"
        );
        assert_eq!(
            tls_bytes, plain_bytes,
            "bytes over TLS must equal bytes over plain HTTP for the same body (AC#2)"
        );
    }

    /// AC#4: an untrusted self-signed cert (chains to no root in the store) is
    /// rejected before any byte; the insecure control proves it is the chain
    /// check that rejects.
    #[tokio::test]
    async fn tls_untrusted_self_signed_is_rejected() {
        let (ca, _issuer) = fixture_ca();
        let (leaf, key) = self_signed_leaf("valid.test");
        let addr = spawn_https(vec![leaf], key, http_response(b"secret", None)).await;
        assert_rejected_with_bite(addr, "valid.test", &ca).await;
    }

    /// AC#4: a cert whose SAN is `wrong.test` is rejected when the client
    /// validates `valid.test`, even though the chain and validity are fine.
    #[tokio::test]
    async fn tls_wrong_hostname_is_rejected() {
        let (ca, issuer) = fixture_ca();
        let (leaf, key) = leaf_signed_by(&issuer, "wrong.test", false);
        let addr = spawn_https(vec![leaf], key, http_response(b"secret", None)).await;
        assert_rejected_with_bite(addr, "valid.test", &ca).await;
    }

    /// AC#4: an expired cert (validity 2000..2001) is rejected though its chain
    /// and hostname are fine.
    #[tokio::test]
    async fn tls_expired_cert_is_rejected() {
        let (ca, issuer) = fixture_ca();
        let (leaf, key) = leaf_signed_by(&issuer, "valid.test", true);
        let addr = spawn_https(vec![leaf], key, http_response(b"secret", None)).await;
        assert_rejected_with_bite(addr, "valid.test", &ca).await;
    }

    /// AC#5: a server that accepts TCP but never completes the TLS handshake must
    /// fail within the (shrunk-for-speed) handshake deadline + scheduler grace,
    /// as a typed `Unreachable` so Nix falls back - never a hang. Load-tolerant:
    /// the upper bound includes the full 1000 ms grace.
    #[tokio::test]
    async fn tls_handshake_stall_fails_within_budget_and_preserves_fallback() {
        let (ca, _issuer) = fixture_ca();
        let addr = spawn_tcp_blackhole().await;
        // Same budget SHAPE as v1 (total >= per-stage caps); only the handshake
        // cap is shrunk so the bite is fast on a shared box.
        let budget = TlsBudget {
            total: Duration::from_millis(10_000),
            connect: Duration::from_millis(5_000),
            handshake: Duration::from_millis(300),
        };
        let client = tls_client(addr, "valid.test", secure_config(&ca), budget);

        let started = Instant::now();
        let res = client.get("/nar/x").await;
        let elapsed = started.elapsed();

        assert!(
            matches!(res, Err(SourceError::Unreachable(_))),
            "a stalled handshake must fail as a typed Unreachable (fallback preserved), got Ok"
        );
        let grace = Duration::from_millis(TLS_UPSTREAM_SCHEDULER_GRACE_MS);
        assert!(
            elapsed <= budget.handshake + grace,
            "deadline must fire within handshake+grace ({:?}); took {elapsed:?}",
            budget.handshake + grace
        );
        assert!(
            elapsed >= budget.handshake,
            "must actually wait out the handshake deadline (not fail instantly for another reason); took {elapsed:?}"
        );
    }

    /// AC#4 (optional, NETWORK-GATED): the PRODUCTION `new("https://...")` path,
    /// validating against the compiled-in Mozilla roots, reaches the REAL
    /// cache.nixos.org over TLS and fetches its signed `nix-cache-info`. `#[ignore]`d
    /// so the deterministic gate never depends on the network (and never reports a
    /// vacuous pass): run explicitly with
    /// `cargo test -p daemon-core --lib -- --ignored tls_real_cache`.
    #[tokio::test]
    #[ignore = "network: hits the real cache.nixos.org; run with --ignored"]
    async fn tls_real_cache_nixos_org_over_https() {
        let client = UpstreamHttp::new("https://cache.nixos.org").expect("https base");
        let resp = client
            .get("/nix-cache-info")
            .await
            .expect("real cache.nixos.org reachable over validated TLS");
        assert_eq!(resp.status, 200, "cache.nixos.org served nix-cache-info");
        let body = resp.body.collect().await.expect("collect").to_bytes();
        assert!(
            std::str::from_utf8(&body)
                .unwrap_or("")
                .contains("StoreDir"),
            "nix-cache-info body must carry StoreDir, got {} bytes",
            body.len()
        );
    }
}
