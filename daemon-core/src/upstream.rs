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

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use http::Uri;
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::{Instant as TokioInstant, Sleep, timeout};
use tokio_rustls::TlsConnector;

use crate::source::{
    MAX_NARINFO_BYTES, NarCompression, NarKey, NarSource, NarinfoSource, NarinfoTransport,
    RawUpstream, SourceError, StoreHash, UpstreamResponse,
};

/// Upper bound on a buffered (narinfo) body, applied by the `Limited` READER so
/// the read STOPS at the cap (codex re-gate #6): the memory bound is real, not an
/// oversized pre-buffer with a late guard. Shared `MAX_NARINFO_BYTES` so the
/// upstream read, the serving layer and the disk cache all cap at the same value.
const MAX_BUFFERED_BODY: usize = MAX_NARINFO_BYTES;

// ---------------------------------------------------------------------------
// TASK-33: the COMPOSING per-hop header budget.
//
// The wave-1 header timeout was a FIXED per-hop constant: each daemon in a chain
// started its OWN full `header_timeout` clock when IT sent its upstream request.
// Across a chain that does NOT compose - the whole chain had no single end-to-end
// deadline, so a downstream daemon with a LARGER local timeout would keep waiting
// (and holding a connection) long after the entry hop the client is actually
// waiting on had already given up.
//
// The fix is a request-carried REMAINING-BUDGET header. The chain ENTRY (the hop
// the client talks to; the client sends no budget) seeds the budget from its own
// `header_timeout`. Every hop then waits at most `min(header_timeout, budget -
// setup_elapsed)` for its upstream's response headers and PROPAGATES that
// decremented remainder to its own upstream. A RELATIVE remaining-ms value (not
// an absolute instant) is used deliberately: absolute deadlines would need
// synchronised clocks across hosts, which a decentralised chain does not have.
//
// HONEST INVARIANT (what this actually guarantees - narrower than "one deadline
// no hop ever waits past"): the propagated budget is MONOTONE NON-INCREASING down
// the chain (a hop can only shorten it, never extend it - a hostile-large inbound
// value is clamped by each hop's local `header_timeout` via `composed_header_wait`)
// and each hop's CONNECT + header-wait (and, on TLS, connect + handshake) are
// capped by the remaining budget. It does NOT bound every wall-clock segment: the
// entry hop's own connection setup is not pre-charged to the budget it seeds
// (`setup_elapsed` is ignored for the entry so lone-daemon timing is unchanged),
// and request transmission, per-hop admission/queueing and BODY streaming are not
// deducted. So the budget bounds the header-arrival path, not the whole response.
//
// HONEST SCOPE (the reopened-NO-GO lesson): this does NOT remove the inherent
// serial-chain admission penalty. The ENTRY hop is always the binding constraint
// at exactly its own budget, so an upstream whose header latency L approaches T
// is still served iff `L + (depth-1)*per_hop_overhead < T` - the outermost hop
// 502s first. On pod loopback `per_hop_overhead` is sub-millisecond, so that term
// is below the noise floor and cannot be separated by depth here (WAN-scale;
// TASK-35/TASK-111). What DOES compose, and is unit/integration-pinned below, is
// the shared end-to-end budget: a tighter downstream budget caps a hop that has a
// larger local `header_timeout`, and the propagated budget only ever shrinks (see
// the HONEST INVARIANT above for exactly which segments it bounds).
// ---------------------------------------------------------------------------

/// Request header carrying the remaining end-to-end header-wait budget, in
/// INTEGER milliseconds, propagated DOWN a daemon chain (TASK-33). Lower-case so
/// it is a valid `HeaderName::from_static`. A hop reads it as the budget its
/// downstream client will wait; it writes the decremented remainder to its own
/// upstream. Absent = "you are the entry, seed from your own `header_timeout`".
pub const HOP_BUDGET_HEADER: &str = "x-nix-p2p-hop-budget-ms";

/// The time THIS hop may wait for its upstream's RESPONSE HEADERS, composing the
/// hop's own configured `header_timeout` with any remaining end-to-end `budget`
/// propagated by a downstream chain client, after `setup_elapsed` has already
/// been spent connecting.
///
///   * `None` budget - this hop is the chain ENTRY (the client sent no budget):
///     it waits its full `header_timeout`, exactly as a lone wave-1 daemon did.
///     `setup_elapsed` is intentionally ignored so single-daemon timing is
///     byte-for-byte unchanged (the header wait is measured from AFTER connect).
///   * `Some(b)` budget - an inner chain hop: it waits `min(header_timeout, b -
///     setup_elapsed)`, so a tighter downstream budget caps a hop with a larger
///     local timeout, and a budget already spent on connect yields ZERO (fail at
///     once rather than wait a fresh full timeout the chain has no time for).
///
/// Integer-`Duration` and saturating throughout - no floats in the timeout math.
fn composed_header_wait(
    header_timeout: Duration,
    budget: Option<Duration>,
    setup_elapsed: Duration,
) -> Duration {
    match budget {
        None => header_timeout,
        Some(b) => header_timeout.min(b.saturating_sub(setup_elapsed)),
    }
}

/// The connect deadline for this hop: the configured `connect_timeout`, additionally
/// capped by any remaining end-to-end `budget` so a chain with little time left
/// does not spend it all waiting to connect. A DOWN upstream therefore still fails
/// FAST (via `connect_timeout`) regardless of the budget - only a connected,
/// slow-but-alive upstream consumes the composed header wait.
fn composed_connect_cap(connect_timeout: Duration, budget: Option<Duration>) -> Duration {
    match budget {
        None => connect_timeout,
        Some(b) => connect_timeout.min(b),
    }
}

/// Additionally cap a TLS-setup stage cap by the remaining end-to-end `budget`
/// (TASK-33 F2). `base` is the stage's own upper bound (the frozen
/// `tls-upstream-v1` [`stage_budget`], left UNCHANGED as the maximum); this layers
/// the inbound chain budget on top so a tight downstream deadline shortens TLS
/// connect/handshake exactly as [`composed_connect_cap`] shortens the plain-HTTP
/// connect. `hop_elapsed` is the time already spent on THIS hop (measured from the
/// shared hop clock), subtracted from the budget so each successive stage sees the
/// dwindling remainder.
///
///   * `None` budget - this hop is the chain ENTRY: the stage keeps its full
///     frozen `base`, so single-daemon / entry-hop TLS timing is unchanged.
///   * `Some(b)` budget - an inner chain hop: the stage waits at most
///     `min(base, b - hop_elapsed)`, saturating to `0` when the budget is spent
///     (a DEAD/blackhole TLS upstream then fails within the budget, not the full
///     frozen 5 s/10 s).
///
/// Integer-`Duration` and saturating - no floats in the timeout math.
fn tls_stage_cap(base: Duration, budget: Option<Duration>, hop_elapsed: Duration) -> Duration {
    match budget {
        None => base,
        Some(b) => base.min(b.saturating_sub(hop_elapsed)),
    }
}

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

/// Default per-read NAR body-idle timeout (TASK-25 AC#1). Bounds the time the
/// daemon will wait for the NEXT body frame from a connected-but-silent upstream
/// before aborting the stream with a clean error, so a mid-body stall (an upstream
/// that sends headers then freezes the NAR body, no RST/FIN) fails FAST at the
/// daemon boundary instead of hanging the daemon->Nix response indefinitely. It is
/// deliberately generous (30 s) so a slow-but-alive WAN transfer of a large NAR is
/// never mistaken for a stall - it caps a STALL (no bytes at all), not throughput.
/// Independent of the TASK-33 header-wait budget, which bounds header ARRIVAL, not
/// body streaming (see the composing-budget module note). Tests inject a short value
/// via [`UpstreamHttp::with_body_idle_timeout`] to bite quickly.
pub const BODY_IDLE_TIMEOUT_MS: u64 = 30_000;

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
    /// Per-read NAR body-idle timeout (TASK-25 AC#1): the max wait for the NEXT
    /// streamed body frame before the transfer is aborted as a stalled body. Bounds
    /// a mid-body stall at the daemon boundary; see [`BODY_IDLE_TIMEOUT_MS`].
    body_idle_timeout: Duration,
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
            body_idle_timeout: Duration::from_millis(BODY_IDLE_TIMEOUT_MS),
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
            body_idle_timeout: Duration::from_millis(BODY_IDLE_TIMEOUT_MS),
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

    /// Override this hop's header timeout (default 1000 ms).
    ///
    /// SEMANTICS (TASK-33, composing budget): for the chain ENTRY (the hop the
    /// client talks to) this is the end-to-end header-wait budget seeded for the
    /// WHOLE chain - it is propagated down every hop as a shrinking
    /// remaining-budget (`HOP_BUDGET_HEADER`) rather than re-granted afresh at
    /// each hop. The propagated budget is MONOTONE NON-INCREASING and caps each
    /// hop's connect + header-wait ONLY - it does NOT bound the entry hop's own
    /// connection setup, request transmission, per-hop admission/queueing, or body
    /// streaming (see the HONEST INVARIANT module note and [`composed_header_wait`]).
    /// For an inner hop it is the local ceiling on the wait, capped further by
    /// whatever budget the downstream client propagated.
    ///
    /// KNOWN CEILING (unchanged by the composing budget - honest scope): the
    /// entry hop is always the binding constraint at its own budget, so an
    /// upstream of header latency L is served iff `L + (depth-1)*per_hop_overhead
    /// < budget` and the OUTERMOST hop 502s first as L approaches the budget. On
    /// pod loopback `per_hop_overhead` is sub-millisecond, so the observable flip
    /// is governed by L vs the budget; the raw depth-composition term is WAN-scale
    /// (below the loopback noise floor) and its validation against a real
    /// cache.nixos.org RTT is deferred to TASK-35 / TASK-111. This knob lets an
    /// operator (and the e2e boundary pin) move the L-vs-budget ceiling.
    pub fn with_header_timeout(mut self, header_timeout: Duration) -> Self {
        self.header_timeout = header_timeout;
        self
    }

    /// Override the per-read NAR body-idle timeout (default [`BODY_IDLE_TIMEOUT_MS`]).
    /// Exists so a test can shrink it to bite a mid-body stall quickly, and so an
    /// operator can tune the stall bound. It bounds only the wait for the NEXT body
    /// frame - not total transfer time - so a large, slow-but-alive NAR is unaffected
    /// as long as bytes keep arriving within the window (TASK-25 AC#1).
    pub fn with_body_idle_timeout(mut self, body_idle_timeout: Duration) -> Self {
        self.body_idle_timeout = body_idle_timeout;
        self
    }

    /// Open a fresh connection, send a GET for `path`, and return the response
    /// with its body still unread (streamed lazily by the caller). Dispatches on
    /// the transport: plain TCP, or TCP + rustls-validated TLS.
    ///
    /// `budget` is the remaining end-to-end header-wait time propagated by a
    /// downstream chain client, or `None` when this hop is the chain ENTRY. It
    /// composes with this hop's own `header_timeout` (see [`composed_header_wait`])
    /// to bound the wait for the upstream's response headers, and the decremented
    /// remainder is propagated to the upstream via [`HOP_BUDGET_HEADER`]. A DOWN
    /// upstream still fails FAST on connect regardless of the budget.
    async fn send(
        &self,
        path: &str,
        budget: Option<Duration>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, SourceError> {
        // Anchor the end-to-end budget clock at the START of this hop's work so
        // the header wait we grant the upstream is decremented by our own connect
        // setup - a genuine shrinking shared deadline, not a fresh full timeout.
        let hop_start = Instant::now();
        match &self.transport {
            Transport::Plain => {
                let stream = timeout(
                    composed_connect_cap(self.connect_timeout, budget),
                    TcpStream::connect((self.host.as_str(), self.port)),
                )
                .await
                .map_err(|_| {
                    SourceError::Unreachable(format!("connect timed out to {}", self.authority))
                })?
                .map_err(|e| {
                    SourceError::Unreachable(format!("connect to {}: {e}", self.authority))
                })?;
                self.send_over(TokioIo::new(stream), path, budget, hop_start)
                    .await
            }
            Transport::Tls {
                config,
                server_name,
            } => {
                // FROZEN tls-upstream-v1: one `total` deadline over DNS + TCP
                // connect + TLS handshake, with each stage capped at its frozen
                // per-stage maximum. A stalled stage fails within the bound as a
                // typed error, so the serving layer 502s and Nix falls back - never
                // a hang. TASK-33 F2: each stage is ADDITIONALLY capped by the
                // remaining inbound HOP budget (via `tls_stage_cap`), so a tight
                // downstream deadline shortens TLS setup just like it shortens the
                // plain-HTTP connect - a DEAD TLS upstream then fails within the
                // budget, not the full frozen 5 s/10 s. The frozen values stay the
                // MAXIMA (entry hop, no budget, is byte-for-byte unchanged).
                let start = Instant::now();
                let connect_cap = tls_stage_cap(
                    stage_budget(
                        self.tls_budget.total,
                        Duration::ZERO,
                        self.tls_budget.connect,
                    ),
                    budget,
                    hop_start.elapsed(),
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

                let handshake_cap = tls_stage_cap(
                    stage_budget(
                        self.tls_budget.total,
                        start.elapsed(),
                        self.tls_budget.handshake,
                    ),
                    budget,
                    hop_start.elapsed(),
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
                self.send_over(TokioIo::new(tls), path, budget, hop_start)
                    .await
            }
        }
    }

    /// The hyper http1 handshake + request send, shared by both transports. `IO`
    /// is `TokioIo<TcpStream>` (plain) or `TokioIo<TlsStream<TcpStream>>` (TLS);
    /// neither adds a decoding layer, so byte forwarding is identical (AC#2).
    ///
    /// `budget`/`hop_start` carry the composing end-to-end deadline (TASK-33): the
    /// wait for the upstream's response headers is `composed_header_wait(header_timeout,
    /// budget, setup_elapsed)`, and that same remaining value is written to the
    /// upstream on [`HOP_BUDGET_HEADER`] so the NEXT hop inherits the shrunk budget.
    async fn send_over<IO>(
        &self,
        io: IO,
        path: &str,
        budget: Option<Duration>,
        hop_start: Instant,
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

        // Compose the header wait from our own timeout and the downstream budget,
        // decremented by whatever setup (connect + handshake) we already spent, and
        // PROPAGATE that remainder so the upstream hop shares the same deadline.
        let header_wait = composed_header_wait(self.header_timeout, budget, hop_start.elapsed());
        let hop_budget_ms = u64::try_from(header_wait.as_millis()).unwrap_or(u64::MAX);
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(uri)
            .header(hyper::header::HOST, &self.authority)
            .header(
                http::HeaderName::from_static(HOP_BUDGET_HEADER),
                hop_budget_ms,
            )
            .body(Empty::<Bytes>::new())
            .map_err(|e| SourceError::Upstream(format!("build request: {e}")))?;

        let response = timeout(header_wait, sender.send_request(request))
            .await
            .map_err(|_| {
                SourceError::Unreachable(format!("no response headers from {}", self.authority))
            })?
            .map_err(|e| SourceError::Upstream(format!("send request: {e}")))?;
        Ok(response)
    }

    /// Fetch a small body in full (narinfo): needed so the rewrite allowlist can
    /// be applied and byte-fidelity asserted. Bounded by [`MAX_BUFFERED_BODY`].
    ///
    /// KNOWN GAP (TASK-225): unlike [`Self::fetch_streaming`], this buffered read has
    /// NO body-idle timeout - an upstream that sends narinfo headers then stalls the
    /// body would hang `collect()`. Lower severity (narinfo is ~1 KB, size-capped),
    /// but the same S2 no-hang bound belongs here; filed as TASK-225.
    async fn fetch_buffered(
        &self,
        path: &str,
        budget: Option<Duration>,
    ) -> Result<UpstreamResponse, SourceError> {
        let response = self.send(path, budget).await?;
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

    /// Fetch a body by streaming it straight through (NAR, passthrough): the body
    /// never sits whole in memory. The returned body is wrapped in a [`BoundedBody`]
    /// that enforces two bounds AS BYTES ARRIVE (TASK-25):
    ///
    /// AC#1 - a per-read BODY-IDLE TIMEOUT ([`Self::body_idle_timeout`]): a connected
    /// upstream that sends headers then STALLS the body (no RST/FIN - a cgroup-freeze
    /// / black-hole) is aborted with a clean bounded error at the daemon boundary,
    /// so the daemon->Nix response never hangs. `connect_timeout`/`header_timeout`
    /// only bounded connect + header arrival before this.
    ///
    /// AC#2 - a per-chunk TRANSPORT-BYTE cap (the PRD-risk-6 oversized-transfer abort):
    /// cumulative ON-WIRE body bytes are bounded, and a transfer that streams MORE is
    /// cut off mid-stream (not merely a Content-Length PRE-check, which cannot catch a
    /// body that lies by streaming past its own declared length).
    ///
    /// THE UNIT (the NarSize-vs-FileSize trap - recurred 6x; read [`compute_transport_cap`]):
    /// the streamed body is the ON-WIRE TRANSPORT representation, whose byte-unit is
    /// FileSize (COMPRESSED when the narinfo `Compression` is xz/zstd; equal to NarSize
    /// only when `Compression: none`). The cap is a TRANSPORT-unit quantity, and whether
    /// the signed NarSize (`expected_size`) may bound the on-wire body is decided by the
    /// AUTHORITATIVE narinfo `Compression` field carried in `transport` - NEVER by the
    /// URL suffix (a spec-valid narinfo may be `URL: nar/x.nar` + `Compression: xz`, whose
    /// on-wire bytes are xz-compressed despite the `.nar` suffix). A COMPRESSED body is
    /// NEVER bounded by the signed NarSize here (the recurred bug); its signed uncompressed
    /// guarantee is enforced DOWNSTREAM by Nix's NarHash/NarSize gate, and for untrusted
    /// p2p peers - who stream the RAW nar - by the fabric's mid-stream NarSize abort
    /// (`peer-fabric`/`fabric-libp2p`), where NarSize IS the on-wire unit.
    async fn fetch_streaming(
        &self,
        path: &str,
        expected_size: Option<u64>,
        transport: NarinfoTransport,
        budget: Option<Duration>,
    ) -> Result<UpstreamResponse, SourceError> {
        let response = self.send(path, budget).await?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        // TASK-25 AC#2: the TRANSPORT-unit streaming byte cap (integer bytes; no floats).
        let byte_cap = compute_transport_cap(&headers, transport, expected_size);
        let inner = response.into_body().map_err(std::io::Error::other);
        let body = BoundedBody::new(
            inner,
            self.body_idle_timeout,
            byte_cap,
            self.authority.clone(),
        )
        .boxed();
        Ok(UpstreamResponse {
            status,
            headers,
            body,
        })
    }
}

/// The ON-WIRE TRANSPORT-unit streaming byte cap for a NAR/passthrough body
/// (TASK-25 AC#2), computed like-for-like so the NarSize-vs-FileSize trap cannot
/// recur (6th recurrence: the fix uses the AUTHORITATIVE narinfo `Compression`,
/// NOT the URL suffix). Returns `None` when no same-unit bound is available (an
/// unbounded stream is then bounded only by the body-idle timeout and by Nix
/// downstream). Every quantity is a whole byte count (no floats).
///
/// `expected_size` is the SIGNED NarSize (UNCOMPRESSED). `transport` is the narinfo's
/// UNSIGNED descriptor: `compression` (authoritative raw-vs-compressed) and `file_size`
/// (the COMPRESSED transport byte count). The unit of the on-wire body is decided by
/// `transport.compression` COMBINED with any HTTP `Content-Encoding` (a SEPARATE transform
/// the HTTP layer may add on top of the narinfo file):
///
///   * RAW on-wire (`Compression: none` AND no non-identity HTTP `Content-Encoding`): the
///     on-wire byte IS the raw-NAR byte, so the signed NarSize is a like-for-like bound.
///     cap = `min(Content-Length, NarSize)`.
///   * COMPRESSED archive on-wire (`Compression != none`): the on-wire byte is a FileSize
///     (compressed transport) byte - the signed NarSize is the WRONG unit and is NEVER
///     used. cap = the on-wire `Content-Length`; when it is ABSENT (chunked) there is NO
///     cap (Nix's NarHash gate + the fabric abort cover a runaway).
///   * HTTP CONTENT-CODED on top (any `Compression`): the on-wire bytes are the HTTP-encoded
///     form (neither NarSize nor FileSize), so again ONLY `Content-Length` counts them.
///
/// The compressed/coded cases collapse to the SAME rule (Content-Length only), so they
/// share one branch below.
///
/// WHY NOT the narinfo `FileSize` as a compressed cap (and why it is not even carried in
/// [`NarinfoTransport`]): it is UNSIGNED and comes from a DIFFERENT response (the narinfo)
/// than the NAR body. Enforcing it here would abort a transfer that the NAR's OWN
/// `Content-Length` permits whenever the narinfo's declared FileSize and the actual transfer
/// disagree - which is legitimate (the CLIENT, not the daemon, is the arbiter of
/// FileHash/FileSize). `tests/nar_hash_collision` is exactly such a case (FileSize: 100, body
/// 160B) and a `min(CL, FileSize)` cap wrongly aborted it. So the on-wire `Content-Length`
/// is the sole compressed transport bound.
///
/// Authoritativeness (the 6th-recurrence fix): the raw decision is `Compression == none`
/// from the narinfo transport fields the daemon parsed at narinfo time, NOT
/// `token.ends_with(".nar")`. A spec-valid `URL: nar/x.nar` + `Compression: xz` narinfo is
/// therefore correctly classified COMPRESSED and never capped by the uncompressed NarSize.
fn compute_transport_cap(
    headers: &http::HeaderMap,
    transport: NarinfoTransport,
    expected_size: Option<u64>,
) -> Option<u64> {
    let content_length = content_length_of(headers);
    let http_encoded = is_content_encoded(headers);
    let narinfo_raw = transport.compression == NarCompression::Raw;

    if narinfo_raw && !http_encoded {
        // ON-WIRE == raw NAR (unit NarSize == FileSize). NarSize is like-for-like.
        min_opt(content_length, expected_size)
    } else {
        // ON-WIRE == a COMPRESSED archive and/or HTTP-encoded form (transport unit).
        // Bound ONLY by the on-wire Content-Length; NEVER the uncompressed NarSize, and
        // never the narinfo FileSize (see the doc). No Content-Length -> NO cap.
        content_length
    }
}

/// True if the response declares a NON-identity `Content-Encoding` - an ACTUAL on-wire
/// transform that makes the body no longer the raw NAR. Absent, empty, or exactly
/// `identity` (the RFC no-op coding) is NOT encoded, so a raw `.nar` body stays raw and
/// keeps its signed-NarSize bound. Any other token (`gzip`, `br`, ...), or a comma list
/// that contains one, means encoded. Mirrors [`crate::source::has_unsupported_transfer_coding`]'s
/// tokenisation so the two agree on what a coding token is.
fn is_content_encoded(headers: &http::HeaderMap) -> bool {
    for value in headers.get_all(http::header::CONTENT_ENCODING) {
        for token in value.as_bytes().split(|&b| b == b',') {
            let t = crate::source::ascii_lower_trim(token);
            if !t.is_empty() && t.as_slice() != b"identity" {
                return true;
            }
        }
    }
    false
}

/// The upstream response's declared `Content-Length` in bytes - the ON-WIRE
/// TRANSPORT byte count (the narinfo FileSize for a compressed NAR) - or `None`
/// when absent/malformed (e.g. a chunked response). This is the like-for-like
/// unit for the streamed on-wire body regardless of compression.
fn content_length_of(headers: &http::HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// The tighter of two OPTIONAL like-for-like byte caps (integer bytes; no floats).
/// `None` means "no cap from this source"; the result is the min of whichever are
/// present, or `None` when neither is.
fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}

/// A streamed upstream body wrapped with two AS-BYTES-ARRIVE bounds (TASK-25):
///
///   * a per-read IDLE timeout (`idle`): if the next frame does not arrive within
///     `idle`, the stream aborts with a `TimedOut` error (AC#1 - a mid-body stall
///     fails fast at the daemon boundary, never a hang);
///   * a cumulative TRANSPORT-byte cap (`byte_cap`, in the SAME on-wire unit as the
///     streamed bytes - see [`compute_transport_cap`]): the instant cumulative body
///     bytes EXCEED it, the stream aborts with an oversized-transfer error and the
///     over-cap frame is dropped rather than forwarded (AC#2).
///
/// Both are streaming aborts: once one fires the body ends. The daemon has already
/// sent the 200 + partial body to Nix, so an abort surfaces as a truncated/failed
/// download that Nix retries / falls back on (S2) - never wrong or unbounded bytes.
struct BoundedBody<B> {
    inner: B,
    idle: Duration,
    /// Re-armed on each delivered frame; fires on `idle` of silence.
    deadline: Pin<Box<Sleep>>,
    /// Lazily armed on the first poll so the construct->first-poll scheduling gap
    /// is not mistaken for upstream silence.
    armed: bool,
    /// TRANSPORT-unit cumulative-byte cap, or `None` for no size bound.
    byte_cap: Option<u64>,
    /// Cumulative ON-WIRE body bytes seen so far (same unit as `byte_cap`).
    seen: u64,
    /// For the error message: which upstream stalled / overflowed.
    authority: String,
    /// Fuse: once an abort fires (or the inner body ends), stay ended.
    ended: bool,
}

impl<B> BoundedBody<B> {
    fn new(inner: B, idle: Duration, byte_cap: Option<u64>, authority: String) -> Self {
        BoundedBody {
            inner,
            idle,
            // Armed lazily on the first poll (see `armed`); this initial deadline is
            // overwritten there, so its value is immaterial.
            deadline: Box::pin(tokio::time::sleep(idle)),
            armed: false,
            byte_cap,
            seen: 0,
            authority,
            ended: false,
        }
    }
}

impl<B> Body for BoundedBody<B>
where
    B: Body<Data = Bytes, Error = std::io::Error> + Unpin,
{
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        // Arm the idle clock at the first poll (not at construction) so scheduling
        // latency before the first poll is not counted as upstream silence.
        if !this.armed {
            this.deadline
                .as_mut()
                .reset(TokioInstant::now() + this.idle);
            this.armed = true;
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // Progress: re-arm the idle clock for the wait until the NEXT frame.
                this.deadline
                    .as_mut()
                    .reset(TokioInstant::now() + this.idle);
                if let Some(data) = frame.data_ref() {
                    let n = data.remaining() as u64;
                    this.seen = this.seen.saturating_add(n);
                    if let Some(cap) = this.byte_cap
                        && this.seen > cap
                    {
                        // Over the TRANSPORT bound: abort mid-stream and DROP the
                        // over-cap frame (never forward oversized bytes). LOG it
                        // (fail-verbose): the serving-layer success line was already
                        // emitted on the 200 headers, and an upstream streaming past
                        // its declared/signed size is exactly the PRD-risk-6 signal an
                        // operator must see - hyper does not surface a body-stream error.
                        this.ended = true;
                        let msg = format!(
                            "upstream {} streamed {} on-wire body bytes, over the \
                             {}-byte transport bound (declared Content-Length / signed \
                             raw NarSize); aborting mid-stream (TASK-25 PRD-risk-6)",
                            this.authority, this.seen, cap
                        );
                        eprintln!("daemon: {msg}");
                        return Poll::Ready(Some(Err(std::io::Error::other(msg))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.ended = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => {
                // No frame ready: enforce the per-read idle bound.
                match this.deadline.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.ended = true;
                        // Fail-verbose: the 200 success line was already logged on the
                        // headers, so log the stall abort too or it is invisible.
                        let msg = format!(
                            "upstream {} stalled mid-body: no data for {} ms \
                             (TASK-25 body-idle timeout)",
                            this.authority,
                            this.idle.as_millis()
                        );
                        eprintln!("daemon: {msg}");
                        Poll::Ready(Some(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            msg,
                        ))))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended
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
        // A lone/entry fetch carries no downstream budget: seed from header_timeout.
        self.fetch_within(store_hash, None).await
    }

    async fn fetch_within(
        &self,
        store_hash: &StoreHash,
        budget: Option<Duration>,
    ) -> Result<UpstreamResponse, SourceError> {
        // The store hash is the only thing the serving layer knows; THIS is
        // where it becomes a URL, and the only place.
        self.fetch_buffered(&format!("/{}.narinfo", store_hash.as_str()), budget)
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
        self.resolve_within(key, expected_size, None).await
    }

    async fn resolve_within(
        &self,
        key: &NarKey,
        expected_size: Option<u64>,
        budget: Option<Duration>,
    ) -> Result<UpstreamResponse, SourceError> {
        // The content identity becomes an upstream URL HERE and nowhere else -
        // the seam that lets wave 2 swap in an iroh source (which resolves the
        // SignedNarHash over p2p, and rejects UpstreamPath) behind the same
        // trait. This HTTP impl fetches by the URL token in either case, and
        // crucially fetches the EXACT token the request carried - never one
        // reconstructed from the hash (which is one-to-many across compression).
        // The AUTHORITATIVE narinfo transport (TASK-25): only the correlated
        // SignedNarHash path carries it. An UpstreamPath cold-start request has NO
        // narinfo, so its transport is Unknown -> the on-wire body is NEVER treated as
        // raw and the uncompressed NarSize is never applied to it (fail-safe).
        let (token, transport) = match key {
            NarKey::SignedNarHash {
                upstream_hint,
                transport,
                ..
            } => (upstream_hint.as_str(), *transport),
            NarKey::UpstreamPath(token) => (token.as_str(), NarinfoTransport::default()),
        };
        self.fetch_streaming(&format!("/nar/{token}"), expected_size, transport, budget)
            .await
    }
}

#[async_trait]
impl RawUpstream for UpstreamHttp {
    async fn get(&self, path: &str) -> Result<UpstreamResponse, SourceError> {
        self.get_within(path, None).await
    }

    async fn get_within(
        &self,
        path: &str,
        budget: Option<Duration>,
    ) -> Result<UpstreamResponse, SourceError> {
        // Passthrough (log/*, *.ls, debuginfo/*): no narinfo, no size bound -> Unknown
        // transport, so the on-wire body is capped only by its own Content-Length.
        self.fetch_streaming(path, None, NarinfoTransport::default(), budget)
            .await
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
    fn composed_header_wait_seeds_and_shrinks_across_hops() {
        // TASK-33: the composing budget arithmetic, integer + saturating.
        let t = |ms| Duration::from_millis(ms);

        // ENTRY (no downstream budget): waits its FULL header_timeout, and the
        // setup already spent is intentionally IGNORED so single-daemon timing is
        // byte-for-byte the wave-1 behaviour (header wait measured after connect).
        assert_eq!(composed_header_wait(t(1000), None, t(7)), t(1000));

        // A downstream budget LARGER than our own timeout: our timeout binds (we
        // never wait longer than our local ceiling).
        assert_eq!(composed_header_wait(t(1000), Some(t(2000)), t(10)), t(1000));

        // THE COMPOSING PROPERTY: a TIGHTER downstream budget caps a hop that has
        // a much larger local header_timeout - the shared end-to-end deadline wins.
        assert_eq!(composed_header_wait(t(5000), Some(t(200)), t(10)), t(190));

        // A budget already spent on connect setup yields ZERO -> fail at once,
        // never a fresh full timeout the chain has no time left for.
        assert_eq!(
            composed_header_wait(t(1000), Some(t(300)), t(350)),
            Duration::ZERO
        );

        // A downstream that says "expired" (0 ms) yields ZERO regardless.
        assert_eq!(
            composed_header_wait(t(1000), Some(Duration::ZERO), t(0)),
            Duration::ZERO
        );
    }

    #[test]
    fn composed_connect_cap_keeps_dead_hops_fast() {
        let t = |ms| Duration::from_millis(ms);
        // No budget: the configured connect_timeout governs (wave-1 fast-fail).
        assert_eq!(composed_connect_cap(t(1000), None), t(1000));
        // A budget smaller than connect_timeout caps connect too (a chain with
        // little time left does not spend it all connecting).
        assert_eq!(composed_connect_cap(t(1000), Some(t(200))), t(200));
        // A budget larger than connect_timeout leaves connect fast (connect_timeout
        // still bounds a DOWN upstream).
        assert_eq!(composed_connect_cap(t(1000), Some(t(9000))), t(1000));
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

    // --- TASK-25 AC#2: the TRANSPORT-unit cap arithmetic, unit-labelled ---------

    fn headers_with(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    /// A `Compression: none` (raw) transport descriptor.
    fn raw_transport() -> NarinfoTransport {
        NarinfoTransport {
            compression: NarCompression::Raw,
        }
    }

    /// A compressed (`Compression: xz`) transport descriptor.
    fn compressed_transport() -> NarinfoTransport {
        NarinfoTransport {
            compression: NarCompression::Compressed,
        }
    }

    #[test]
    fn min_opt_takes_the_tighter_present_cap() {
        assert_eq!(min_opt(Some(10), Some(4)), Some(4));
        assert_eq!(min_opt(Some(4), Some(10)), Some(4));
        assert_eq!(min_opt(Some(7), None), Some(7));
        assert_eq!(min_opt(None, Some(7)), Some(7));
        assert_eq!(min_opt(None, None), None);
    }

    #[test]
    fn transport_cap_never_uses_narsize_on_a_compressed_body() {
        // THE 6th-recurrence ANTI-TRAP: the on-wire body is COMPRESSED per the
        // AUTHORITATIVE narinfo `Compression` (NOT the URL suffix). Its FileSize (300)
        // EXCEEDS the signed NarSize (100). NarSize must NEVER bound it.
        let h = headers_with(&[("content-length", "300")]);
        assert_eq!(
            compute_transport_cap(&h, compressed_transport(), Some(100)),
            Some(300),
            "a compressed body is bounded by its on-wire Content-Length, never the uncompressed NarSize"
        );
        // The narinfo FileSize is NOT a transfer cap (it is unsigned, from a different
        // response, and the CLIENT verifies it): a FileSize (260) BELOW the on-wire
        // Content-Length (300) must NOT tighten the cap and abort a valid transfer.
        let h = headers_with(&[("content-length", "300")]);
        assert_eq!(
            compute_transport_cap(&h, compressed_transport(), Some(100)),
            Some(300),
            "narinfo FileSize must not override the on-wire Content-Length (nar_hash_collision regression)"
        );
        // No Content-Length (chunked, compressed): NO cap - NarSize is the wrong unit,
        // and FileSize is NOT used as a lone cap (Nix + fabric cover a runaway).
        assert_eq!(
            compute_transport_cap(&http::HeaderMap::new(), compressed_transport(), Some(100)),
            None
        );
        // `Unknown` compression (uncorrelated / ambiguous) is treated as NOT raw too.
        assert_eq!(
            compute_transport_cap(
                &http::HeaderMap::new(),
                NarinfoTransport::default(),
                Some(100)
            ),
            None
        );
    }

    #[test]
    fn transport_cap_admits_narsize_only_for_a_raw_body() {
        // Compression: none (raw): FileSize == NarSize, so the signed NarSize IS a
        // like-for-like bound. With no Content-Length (chunked raw) the NarSize is
        // the cap - this is where the SIGNED bound bites at the HTTP layer.
        assert_eq!(
            compute_transport_cap(&http::HeaderMap::new(), raw_transport(), Some(100)),
            Some(100)
        );
        // With BOTH present the tighter wins (both are the on-wire unit here).
        let h = headers_with(&[("content-length", "120")]);
        assert_eq!(
            compute_transport_cap(&h, raw_transport(), Some(100)),
            Some(100)
        );
        let h = headers_with(&[("content-length", "80")]);
        assert_eq!(
            compute_transport_cap(&h, raw_transport(), Some(100)),
            Some(80)
        );
    }

    #[test]
    fn transport_cap_rejects_narsize_when_a_raw_narinfo_is_http_content_encoded() {
        // A `Compression: none` narinfo but the upstream slapped an HTTP Content-Encoding
        // on the wire -> the on-wire bytes are NO LONGER raw NAR bytes (they are the
        // HTTP-encoded form), so NarSize is not their unit. Only Content-Length may bound.
        let h = headers_with(&[("content-length", "50"), ("content-encoding", "gzip")]);
        assert_eq!(
            compute_transport_cap(&h, raw_transport(), Some(100)),
            Some(50)
        );
        let h = headers_with(&[("content-encoding", "gzip")]);
        assert_eq!(compute_transport_cap(&h, raw_transport(), Some(100)), None);
        // `identity` is the RFC no-op coding: the body is STILL raw, so the NarSize
        // bound is KEPT (a real like-for-like bound must not be discarded).
        let h = headers_with(&[("content-encoding", "identity")]);
        assert_eq!(
            compute_transport_cap(&h, raw_transport(), Some(100)),
            Some(100)
        );
        // A comma list containing a real coding is encoded -> bound dropped.
        let h = headers_with(&[("content-encoding", "identity, gzip")]);
        assert_eq!(compute_transport_cap(&h, raw_transport(), Some(100)), None);
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
            body_idle_timeout: Duration::from_millis(BODY_IDLE_TIMEOUT_MS),
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

    /// TASK-33 F2: the inbound HOP budget must ALSO bound TLS setup, not just the
    /// post-handshake header wait. Here the FROZEN `tls-upstream-v1` budget is left
    /// UNCHANGED (handshake cap 5 s, total 10 s) - the ONLY thing shortening the
    /// stalled handshake is the 300 ms inbound budget. Before F2 the handshake used
    /// only the frozen 5 s cap and this call would take ~5 s; with F2 it fails within
    /// the budget. THE BITE: reverting F2 (dropping the `tls_stage_cap` on the
    /// handshake/connect stages) makes `elapsed` jump to ~5 s and this fails.
    #[tokio::test]
    async fn dead_tls_upstream_fails_within_the_inbound_budget_not_the_frozen_5s() {
        let (ca, _issuer) = fixture_ca();
        let addr = spawn_tcp_blackhole().await;
        // FROZEN v1: connect 5 s, handshake 5 s, total 10 s. NOT shrunk.
        let client = tls_client(addr, "valid.test", secure_config(&ca), TlsBudget::default());

        let inbound_budget = Duration::from_millis(300);
        let started = Instant::now();
        // A downstream chain hop propagated a 300 ms remaining budget; the TLS
        // handshake to the blackhole must abort within it, not the frozen 5 s.
        let res = client.get_within("/nar/x", Some(inbound_budget)).await;
        let elapsed = started.elapsed();

        assert!(
            matches!(res, Err(SourceError::Unreachable(_))),
            "a stalled TLS handshake under a tight inbound budget must fail as a typed Unreachable"
        );
        let grace = Duration::from_millis(TLS_UPSTREAM_SCHEDULER_GRACE_MS);
        assert!(
            elapsed <= inbound_budget + grace,
            "TLS setup must fail within the INBOUND budget+grace ({:?}), NOT the frozen 5 s \
             handshake cap; took {elapsed:?} (if ~5 s, F2 is missing)",
            inbound_budget + grace
        );
        assert!(
            elapsed >= Duration::from_millis(200),
            "must actually wait out the ~300ms budget, not fail instantly for another reason; took {elapsed:?}"
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

/// TASK-33: the composing per-hop header budget, exercised end-to-end against an
/// in-process loopback HTTP server. These bite the BEHAVIOUR the wave-1 fixed
/// per-hop timeout could not deliver: the budget is PROPAGATED to the upstream and
/// it BOUNDS the header wait below a larger local `header_timeout`. Every assertion
/// has a mutation control (an entry vs an inner hop, served vs timed-out) so it
/// cannot pass on a daemon that ignores the budget. No podman, no floats.
#[cfg(test)]
mod budget_tests {
    use super::*;

    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Extract the integer `x-nix-p2p-hop-budget-ms` value a request carried, or
    /// `None` if absent/unparsable - the exact wire value the NEXT hop would read.
    fn recorded_budget(raw: &[u8]) -> Option<u64> {
        let text = std::str::from_utf8(raw).ok()?;
        for line in text.split("\r\n") {
            if let Some((name, value)) = line.split_once(':')
                && name.trim().eq_ignore_ascii_case(HOP_BUDGET_HEADER)
            {
                return value.trim().parse().ok();
            }
        }
        None
    }

    /// A loopback HTTP/1.1 server that (1) RECORDS the inbound
    /// `x-nix-p2p-hop-budget-ms` of each request (proving propagation) and (2)
    /// delays its response HEADERS by `delay` before replying 200 (so a
    /// budget-vs-delay race proves the wait is bounded by the propagated budget).
    async fn spawn_recording_http(delay: Duration) -> (SocketAddr, Arc<Mutex<Vec<Option<u64>>>>) {
        let seen: Arc<Mutex<Vec<Option<u64>>>> = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen_task = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let seen = seen_task.clone();
                tokio::spawn(async move {
                    let mut acc = Vec::new();
                    let mut buf = [0u8; 1024];
                    loop {
                        match sock.read(&mut buf).await {
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
                    seen.lock().expect("seen lock").push(recorded_budget(&acc));
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let body = b"ok";
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                    let _ = sock.flush().await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (addr, seen)
    }

    /// The chain ENTRY (no inbound budget) SEEDS the propagated budget from its own
    /// `header_timeout`, exactly - the monotone-non-increasing header-wait budget starts here.
    #[tokio::test]
    async fn entry_hop_seeds_and_propagates_its_header_timeout() {
        let (addr, seen) = spawn_recording_http(Duration::ZERO).await;
        let client = UpstreamHttp::new(&format!("http://{addr}"))
            .expect("http base")
            .with_header_timeout(Duration::from_millis(1234));
        // RawUpstream::get -> get_within(None): the entry seeds budget = header_timeout.
        let resp = client.get("/nar/x").await.expect("served");
        assert_eq!(resp.status, 200);
        let recorded = seen.lock().expect("seen").clone();
        assert_eq!(recorded.len(), 1, "exactly one upstream request");
        assert_eq!(
            recorded[0],
            Some(1234),
            "entry propagates its full header_timeout as the seed budget (setup ignored for the entry)"
        );
    }

    /// An INNER hop caps the propagated budget to the SMALLER of the incoming
    /// budget and its own timeout, and forwards the decremented remainder - the
    /// shared deadline shrinks monotonically down the chain.
    #[tokio::test]
    async fn inner_hop_caps_to_incoming_budget_and_forwards_remainder() {
        let (addr, seen) = spawn_recording_http(Duration::ZERO).await;
        let client = UpstreamHttp::new(&format!("http://{addr}"))
            .expect("http base")
            .with_header_timeout(Duration::from_millis(1234));
        // Simulate a downstream client that propagated an 800ms remaining budget.
        let resp = client
            .get_within("/nar/x", Some(Duration::from_millis(800)))
            .await
            .expect("served");
        assert_eq!(resp.status, 200);
        let forwarded = seen.lock().expect("seen").clone()[0].expect("budget header present");
        // min(1234, 800 - sub-ms loopback setup): capped by the incoming budget,
        // decremented by our own setup (so <= 800, and within a wide grace of it).
        assert!(
            (750..=800).contains(&forwarded),
            "inner hop forwards the incoming budget minus its setup; got {forwarded}ms (want ~800)"
        );
    }

    /// THE BITE: a TIGHTER downstream budget bounds this hop's header wait BELOW
    /// its own (large) `header_timeout`. With the wave-1 fixed per-hop timeout the
    /// budget was ignored and this same call would wait 5000ms and SERVE; the
    /// composing budget makes it fail near the 150ms budget instead. The served
    /// control (same upstream, no budget) proves the upstream is alive.
    #[tokio::test]
    async fn a_tighter_downstream_budget_bounds_the_wait_below_the_local_timeout() {
        let (addr, _seen) = spawn_recording_http(Duration::from_millis(400)).await;
        let client = UpstreamHttp::new(&format!("http://{addr}"))
            .expect("http base")
            .with_header_timeout(Duration::from_millis(5000));

        // CONTROL: no downstream budget -> the 5000ms local timeout waits out the
        // 400ms header delay -> served. Proves the upstream is alive and the delay
        // is below the local timeout. (Map to status: UpstreamResponse is not Debug.)
        let served = client.get("/nar/x").await.map(|r| r.status);
        assert_eq!(
            served.as_ref().ok().copied(),
            Some(200),
            "a 5000ms header_timeout serves a 400ms-slow upstream, got {served:?}"
        );

        // BITE: a 150ms downstream budget (< the 400ms delay) caps the wait below
        // the 5000ms local timeout -> times out fast as a typed Unreachable.
        let started = Instant::now();
        let bounded = client
            .get_within("/nar/x", Some(Duration::from_millis(150)))
            .await
            .map(|r| r.status);
        let elapsed = started.elapsed();
        assert!(
            matches!(bounded, Err(SourceError::Unreachable(_))),
            "a tight downstream budget must time out, got {bounded:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(150),
            "must actually wait out the budget, not fail instantly for another reason; took {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(2000),
            "must fail near the 150ms budget, NOT the 5000ms local timeout (the composing bite); took {elapsed:?}"
        );
    }

    /// The required invariant (task brief): a DOWN upstream still fails FAST on
    /// connect even with a generous budget - only a connected, slow-but-alive
    /// upstream consumes the composed header wait.
    #[tokio::test]
    async fn down_upstream_fails_fast_even_with_a_generous_budget() {
        // Bind then immediately drop the listener so the port is CLOSED: connect
        // is refused near-instantly, independent of any budget.
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            l.local_addr().expect("addr")
        };
        let client = UpstreamHttp::new(&format!("http://{addr}"))
            .expect("http base")
            .with_header_timeout(Duration::from_millis(5000));
        let started = Instant::now();
        let res = client
            .get_within("/nar/x", Some(Duration::from_millis(5000)))
            .await
            .map(|r| r.status);
        let elapsed = started.elapsed();
        assert!(
            matches!(res, Err(SourceError::Unreachable(_))),
            "a down upstream is a typed Unreachable, got {res:?}"
        );
        assert!(
            elapsed < Duration::from_millis(2000),
            "a dead hop fails fast on connect, NOT after the 5000ms budget; took {elapsed:?}"
        );
    }
}

/// TASK-25: the streamed-body bounds (`fetch_streaming` / [`BoundedBody`]) proven
/// against IN-PROCESS mock upstreams on loopback - the daemon-boundary oracle for a
/// mid-body stall (AC#1) and an oversized/lying transfer (AC#2). These drive the
/// PLAIN transport (the loopback fixtures below speak raw HTTP/1.1) with a shrunk
/// `body_idle_timeout` so a stall bites in milliseconds. Each abort carries its OWN
/// bite control (remove the bound -> the body flows / hangs) so the tests fail if
/// the bound is decorative.
#[cfg(test)]
mod streaming_bounds_tests {
    use super::*;

    use std::net::SocketAddr;

    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A PLAIN `UpstreamHttp` pointed at loopback `addr`, with `idle` as its
    /// body-idle timeout. Constructed field-by-field (like `tls_client`) so tests
    /// can inject a short timeout the public constructors do not expose.
    fn plain_client(addr: SocketAddr, idle: Duration) -> UpstreamHttp {
        UpstreamHttp {
            host: addr.ip().to_string(),
            port: addr.port(),
            authority: "mock-upstream".to_string(),
            connect_timeout: Duration::from_millis(1000),
            header_timeout: Duration::from_millis(1000),
            body_idle_timeout: idle,
            transport: Transport::Plain,
            tls_budget: TlsBudget::tls_upstream_v1(),
        }
    }

    /// Read a request's headers off `sock` (up to the blank line) and discard them.
    async fn read_request<S: AsyncReadExt + Unpin>(sock: &mut S) {
        let mut acc = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => {
                    acc.extend_from_slice(&buf[..n]);
                    if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }

    /// A loopback upstream that answers with a CHUNKED body of exactly `total`
    /// bytes (in 512-byte chunks), then the terminating chunk + ordered close. No
    /// `Content-Length` - so the ONLY size bound is the caller's transport cap.
    async fn spawn_chunked_bytes(total: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            read_request(&mut sock).await;
            if sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-nix-nar\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )
                .await
                .is_err()
            {
                return;
            }
            let payload = [b'x'; 512];
            let mut remaining = total;
            while remaining > 0 {
                let n = remaining.min(512);
                let hdr = format!("{n:x}\r\n");
                if sock.write_all(hdr.as_bytes()).await.is_err()
                    || sock.write_all(&payload[..n]).await.is_err()
                    || sock.write_all(b"\r\n").await.is_err()
                {
                    return; // client aborted (the cap fired) - stop writing.
                }
                remaining -= n;
            }
            let _ = sock.write_all(b"0\r\n\r\n").await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        });
        addr
    }

    /// A loopback upstream that sends response headers + ONE chunk of `prefix`
    /// bytes, then STALLS: it holds the socket open forever, sending nothing more
    /// and never closing (no RST/FIN) - the SIGSTOP-style silent mid-body stall.
    async fn spawn_stall(prefix: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            read_request(&mut sock).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await;
            let _ = sock
                .write_all(format!("{:x}\r\n", prefix.len()).as_bytes())
                .await;
            let _ = sock.write_all(&prefix).await;
            let _ = sock.write_all(b"\r\n").await;
            let _ = sock.flush().await;
            // Silent stall: hold the connection open, send nothing, never close.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            drop(sock);
        });
        addr
    }

    /// Drain a body to completion, counting bytes; return the first body error.
    async fn drain(body: crate::source::NarBody) -> Result<usize, std::io::Error> {
        let mut body = body;
        let mut total = 0usize;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            if let Some(data) = frame.data_ref() {
                total += data.len();
            }
        }
        Ok(total)
    }

    /// Drain a body, returning the bytes ACTUALLY FORWARDED to the consumer before
    /// any error, plus that error if the stream aborted. Distinguishes "forwarded the
    /// valid prefix then aborted, dropping the crossing frame" from "errored before
    /// forwarding anything" (Finding 2).
    async fn drain_counting(body: crate::source::NarBody) -> (usize, Option<std::io::Error>) {
        let mut body = body;
        let mut total = 0usize;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        total += data.len();
                    }
                }
                Err(e) => return (total, Some(e)),
            }
        }
        (total, None)
    }

    /// A `Compression: none` (raw) transport descriptor for the on-wire body.
    fn raw_t() -> NarinfoTransport {
        NarinfoTransport {
            compression: NarCompression::Raw,
        }
    }

    /// A compressed (`Compression: xz`) transport descriptor.
    fn compressed_t() -> NarinfoTransport {
        NarinfoTransport {
            compression: NarCompression::Compressed,
        }
    }

    /// A loopback upstream that answers with a CHUNKED body of the given FRAME sizes
    /// (one HTTP chunk per size, each a distinct fill byte so frame boundaries are
    /// observable), sleeping `gap` between frames. No `Content-Length`. Used to prove
    /// the per-read idle RESET (paced body, Finding 3) and exact frame accounting.
    async fn spawn_chunked_frames(sizes: Vec<usize>, gap: Duration) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            read_request(&mut sock).await;
            if sock
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            for (i, size) in sizes.iter().enumerate() {
                if i > 0 && !gap.is_zero() {
                    tokio::time::sleep(gap).await;
                }
                let fill = b'a' + (i % 26) as u8;
                let chunk = vec![fill; *size];
                if sock
                    .write_all(format!("{size:x}\r\n").as_bytes())
                    .await
                    .is_err()
                    || sock.write_all(&chunk).await.is_err()
                    || sock.write_all(b"\r\n").await.is_err()
                {
                    return; // client aborted (a cap fired) - stop writing.
                }
                let _ = sock.flush().await;
            }
            let _ = sock.write_all(b"0\r\n\r\n").await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        });
        addr
    }

    #[tokio::test]
    async fn body_idle_timeout_bounds_a_midstream_stall() {
        // AC#1: an upstream that sends headers + partial body then STALLS yields a
        // clean bounded error at the daemon boundary, not a hang.
        let addr = spawn_stall(b"nix-archive-1 partial NAR".to_vec()).await;
        let client = plain_client(addr, Duration::from_millis(200));
        let resp = client
            .fetch_streaming("/nar/abc.nar.xz", None, NarinfoTransport::default(), None)
            .await
            .expect("headers arrive before the stall");
        assert_eq!(resp.status, 200);

        let start = std::time::Instant::now();
        let drained = drain(resp.body).await;
        let elapsed = start.elapsed();

        let err = drained.expect_err("a mid-body stall must abort, not hang");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "the abort must be the body-idle timeout, got: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "the 200ms idle timeout must bound the stall; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn without_the_idle_timeout_the_same_stall_would_hang() {
        // BITE CONTROL for AC#1: the SAME silent stall, but with the idle timeout
        // effectively disabled, does NOT complete within a generous window - proving
        // the short timeout in the sibling test is what bounds the stall, not the
        // mock closing on its own.
        let addr = spawn_stall(b"partial".to_vec()).await;
        let client = plain_client(addr, Duration::from_secs(3600));
        let resp = client
            .fetch_streaming("/nar/abc.nar.xz", None, NarinfoTransport::default(), None)
            .await
            .expect("headers arrive");
        let outcome = tokio::time::timeout(Duration::from_millis(800), drain(resp.body)).await;
        assert!(
            outcome.is_err(),
            "with the idle timeout disabled the stalled body must still be pending, \
             not aborted/closed"
        );
    }

    #[tokio::test]
    async fn raw_nar_body_over_signed_narsize_is_aborted_midstream() {
        // AC#2 (unit-correct): a RAW `.nar` on-wire body streaming MORE raw bytes
        // than the signed NarSize is cut off mid-stream. On-wire bytes ARE raw-NAR
        // bytes here, so NarSize is the like-for-like bound (FileSize == NarSize).
        let nar_size = 1000u64;
        let oversize = 4096usize;

        let addr = spawn_chunked_bytes(oversize).await;
        let client = plain_client(addr, Duration::from_secs(30));
        let resp = client
            .fetch_streaming("/nar/deadbeef.nar", Some(nar_size), raw_t(), None)
            .await
            .expect("headers arrive");
        let drained = drain(resp.body).await;
        assert!(
            drained.is_err(),
            "a raw body exceeding the signed NarSize must abort mid-stream, got {drained:?}"
        );

        // BITE CONTROL: the SAME oversize body with NO cap -> every byte flows through.
        let addr2 = spawn_chunked_bytes(oversize).await;
        let client2 = plain_client(addr2, Duration::from_secs(30));
        let resp2 = client2
            .fetch_streaming("/nar/deadbeef.nar", None, raw_t(), None)
            .await
            .expect("headers arrive");
        let n = drain(resp2.body)
            .await
            .expect("no cap -> whole body streams");
        assert_eq!(
            n, oversize,
            "without the cap the entire oversize body streams through (the cap is not decorative)"
        );
    }

    #[tokio::test]
    async fn raw_nar_body_of_exactly_narsize_streams_uncut() {
        // The strict `>` boundary: a raw body of EXACTLY the signed NarSize must
        // stream to completion, never aborted (guards the strict `>` against a future
        // `>=` regression that would 502 legitimate exactly-sized content).
        let nar_size = 2048u64;
        let addr = spawn_chunked_bytes(nar_size as usize).await;
        let client = plain_client(addr, Duration::from_secs(30));
        let resp = client
            .fetch_streaming("/nar/deadbeef.nar", Some(nar_size), raw_t(), None)
            .await
            .expect("headers arrive");
        let n = drain(resp.body)
            .await
            .expect("a raw body of exactly NarSize must NOT abort");
        assert_eq!(
            n, nar_size as usize,
            "the exactly-at-cap body streams uncut"
        );
    }

    #[tokio::test]
    async fn compressed_nar_body_is_not_bounded_by_uncompressed_narsize() {
        // THE ANTI-TRAP end to end: a `.nar.xz` on-wire body whose COMPRESSED
        // FileSize (3072) exceeds the signed uncompressed NarSize (1000). Comparing
        // compressed on-wire bytes to the uncompressed NarSize is the 5x-recurred bug
        // and would falsely abort. It must stream verbatim; the signed guarantee is
        // enforced by Nix downstream. (No Content-Length here, so the only candidate
        // cap is the - correctly rejected - NarSize.)
        let nar_size = 1000u64;
        let on_wire = 3072usize;
        let addr = spawn_chunked_bytes(on_wire).await;
        let client = plain_client(addr, Duration::from_secs(30));
        let resp = client
            .fetch_streaming("/nar/deadbeef.nar.xz", Some(nar_size), compressed_t(), None)
            .await
            .expect("headers arrive");
        let n = drain(resp.body)
            .await
            .expect("a compressed body must NOT be capped by the uncompressed NarSize");
        assert_eq!(
            n, on_wire,
            "compressed on-wire bytes stream verbatim; NarSize is the wrong unit for them"
        );
    }

    #[tokio::test]
    async fn nar_suffix_url_with_compression_xz_is_not_capped_by_narsize() {
        // THE 6th-recurrence ANTI-TRAP end to end (codex Finding 1): the URL ends
        // `.nar` (the old suffix heuristic would call it RAW and cap at NarSize) but the
        // AUTHORITATIVE narinfo `Compression` is xz -> the on-wire body is a compressed
        // archive whose FileSize legitimately EXCEEDS the uncompressed NarSize. It MUST
        // stream verbatim. The mutation is built in: pass `raw_t()` instead of
        // `compressed_t(..)` and the on-wire bytes (3072) exceed NarSize (1000) -> abort.
        let nar_size = 1000u64;
        let on_wire = 3072usize;
        let addr = spawn_chunked_bytes(on_wire).await;
        let client = plain_client(addr, Duration::from_secs(30));
        let resp = client
            // Compression: xz carried in the transport, DESPITE the `.nar` URL suffix.
            .fetch_streaming("/nar/deadbeef.nar", Some(nar_size), compressed_t(), None)
            .await
            .expect("headers arrive");
        let n = drain(resp.body)
            .await
            .expect("a Compression: xz body must NOT be capped by NarSize even at a .nar URL");
        assert_eq!(
            n, on_wire,
            "the authoritative Compression, not the URL suffix, decides the unit"
        );
    }

    #[tokio::test]
    async fn oversize_abort_forwards_the_valid_prefix_then_drops_the_crossing_frame() {
        // Finding 2: prove the abort forwards the prior VALID frames and DROPS the frame
        // that crosses the cap (never forwards oversized bytes), rather than erroring
        // before delivering anything or forwarding the over-cap frame.
        let cap = 1000u64;
        // Three 400-byte frames: after two (800) we are under cap; the third crosses to
        // 1200 > 1000 and must be DROPPED. A small inter-frame gap (well under the idle
        // bound) keeps hyper from coalescing the reads. Assert a RANGE, not an exact 800, so
        // the property does not pin hyper's chunking granularity:
        //   delivered > 0    => the valid prefix WAS forwarded (not "errored before anything")
        //   delivered <= 800 => the crossing frame (which would reach 1200) was NOT forwarded
        let addr = spawn_chunked_frames(vec![400, 400, 400], Duration::from_millis(10)).await;
        let client = plain_client(addr, Duration::from_secs(30));
        let resp = client
            .fetch_streaming("/nar/deadbeef.nar", Some(cap), raw_t(), None)
            .await
            .expect("headers arrive");
        let (delivered, err) = drain_counting(resp.body).await;
        assert!(
            err.is_some(),
            "the oversize transfer must abort with an error"
        );
        assert!(
            delivered > 0 && delivered <= 800,
            "the valid prefix was forwarded and the crossing frame (->1200B) DROPPED, \
             got {delivered} bytes (must be 1..=800, never the oversized 1200)"
        );
    }

    #[tokio::test]
    async fn paced_body_within_idle_gap_succeeds_even_when_total_exceeds_the_bound() {
        // Finding 3: mutation-prove the PER-READ RESET. Five 100-byte frames, each
        // arriving 120ms after the last (below the 300ms idle bound), so the TOTAL
        // transfer (~480ms) EXCEEDS the idle bound. A per-read-reset timeout SUCCEEDS
        // (each gap is under bound); a TOTAL deadline would wrongly abort. Deleting the
        // re-arm on progress turns this green test red.
        let idle = Duration::from_millis(300);
        let gap = Duration::from_millis(120);
        let frames = vec![100usize; 5];
        let expected: usize = frames.iter().sum();
        let addr = spawn_chunked_frames(frames, gap).await;
        let client = plain_client(addr, idle);
        let resp = client
            .fetch_streaming("/nar/deadbeef.nar", None, raw_t(), None)
            .await
            .expect("headers arrive");
        let n = drain(resp.body)
            .await
            .expect("a paced body whose inter-frame gaps stay under the idle bound must SUCCEED");
        assert_eq!(
            n, expected,
            "the full body arrives; the idle timeout resets on each frame, it is not a total deadline"
        );
    }
}
