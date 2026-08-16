//! The HTTP serving layer: routing, header hygiene, and response building.
//!
//! This module depends ONLY on the trait objects in [`crate::source`] - never
//! on an HTTP client. That is the compile-time seam (AC#5): swap the trait impls
//! and the wire behaviour changes with the serving layer untouched.
//!
//! Routing mirrors the tiny Nix binary-cache API:
//!   * `GET/HEAD /nix-cache-info` -> generated locally ([`crate::cacheinfo`]);
//!   * `GET/HEAD /<hash>.narinfo` -> [`NarinfoSource`], body verbatim through the
//!     (empty) rewrite allowlist (AC#3);
//!   * `GET/HEAD /nar/<...>`      -> [`NarSource`], streamed verbatim (AC#6);
//!   * anything else              -> [`RawUpstream`] passthrough (`log/*`,
//!     `*.ls`, `debuginfo/*`) so `nix log` never breaks (AC#4).
//!
//! Status fidelity (AC#4): a non-200 upstream *response* is forwarded with its
//! exact status. Only a transport *failure* ([`SourceError`]) becomes a 502, and
//! it is produced fast so Nix falls back without hanging (S2).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{HeaderMap, HeaderName};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::body::{empty, full};
use crate::cacheinfo::CacheInfo;
use crate::catalog::{CorrelationStore, NarCatalog, parse_correlation};
use crate::rewrite;
use crate::source::{
    NarBody, NarCompression, NarHash, NarKey, NarPathToken, NarSource, NarinfoSource,
    NarinfoTransport, RawUpstream, SourceError, StoreHash, UpstreamResponse,
};
use proc_supervisor::TaskSupervisorHandle;

/// Everything a request needs, injected so tests can swap any source for a fake.
pub struct App {
    pub narinfo: Arc<dyn NarinfoSource>,
    pub nar: Arc<dyn NarSource>,
    pub passthrough: Arc<dyn RawUpstream>,
    pub cache_info: CacheInfo,
    /// Correlation state owned by the server (UpstreamHttp holds no catalog):
    /// narinfos populate it, NAR requests read it to carry the signed NarHash
    /// across the seam.
    pub catalog: Arc<NarCatalog>,
    /// The daemon's CONFIGURED upstream, echoed verbatim as `source=` in the
    /// per-substitution log line. Presentation-only (never used to build a
    /// request), so the server layer keeps depending on the trait objects alone
    /// and not on a concrete HTTP client. This is the `--upstream` string as
    /// given; in wave-1 (no redirects) it is also the host actually dialed.
    pub upstream_label: String,
    /// PERSISTED correlation, consulted only on an in-memory catalog MISS. In
    /// production this is the narinfo disk cache, which derives `token -> meta`
    /// from cached narinfos so a warm-on-disk-but-cold-in-memory daemon (post
    /// restart, warm Nix client that skipped the narinfo GET) still dispatches
    /// `SignedNarHash` (task-8; task-4's deferred steady-state). Defaults to
    /// [`crate::catalog::NullCorrelation`] when no cache is wired.
    pub correlation: Arc<dyn CorrelationStore>,
    /// Decides, per NarHash, whether the daemon will serve the RAW nar itself and
    /// therefore rewrite the narinfo's transport fields to raw (task-49). MUST be
    /// coupled with a raw-capable `nar` source: a `true` here without one hands the
    /// client a raw narinfo the daemon cannot back. The wave-1 binary wires
    /// [`crate::rewrite::NoRawServe`] (never rewrite -> verbatim upstream narinfo +
    /// compressed nar, the S2 path); task-41 wires the availability-backed decision
    /// alongside a raw NAR source.
    pub raw_serve: Arc<dyn rewrite::RawServeDecision>,
    /// The public-NAR allowlist (TASK-102): the SINGLE writer of which NAR identities
    /// this node may publicly announce. `respond_narinfo` calls `learn` on the exact
    /// cache.nixos.org response; only a narinfo whose trusted-key Nix signature verifies
    /// appends its `(NarHash, NarSize)`. A daemon with no configured publication
    /// authority uses [`crate::PublicNarAllowlist::disabled`], which learns nothing.
    pub public_allowlist: Arc<crate::public_allowlist::PublicNarAllowlist>,
}

/// Serve on an already-bound listener until it errors. Binding is the caller's
/// job so tests can grab an OS-assigned port (`127.0.0.1:0`) and read it back.
pub async fn serve(
    listener: TcpListener,
    app: Arc<App>,
    supervisor: TaskSupervisorHandle,
) -> std::io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let app = Arc::clone(&app);
        let registration = supervisor.spawn("http-connection", async move {
            let service = service_fn(move |req| {
                let app = Arc::clone(&app);
                async move { Ok::<_, Infallible>(handle(req, app).await) }
            });
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                // A client hanging up mid-response is normal traffic, not a
                // fault; surface only unexpected server errors.
                if !err.is_incomplete_message() {
                    eprintln!("daemon: connection error: {err}");
                }
            }
        });
        if let Err(error) = registration {
            if error.is_capacity_exhausted() {
                // The accepted stream is owned by the rejected future and is
                // dropped here, giving this connection an immediate EOF while
                // keeping the listener available for recovery.
                eprintln!("HTTP-CONNECTION-DECLINED reason=busy error={error}");
                continue;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("HTTP task supervisor is unavailable: {error}"),
            ));
        }
    }
}

/// How a request target maps onto the cache API.
enum Route {
    CacheInfo,
    Narinfo(StoreHash),
    /// The `nar/`-relative URL token; correlation to a signed NarHash happens in
    /// `handle`, not here.
    Nar(NarPathToken),
    /// `log/*`, `*.ls`, `debuginfo/*`, and anything else - passthrough.
    Other,
}

/// Classify the request path. The daemon parses its OWN inbound path here (an
/// HTTP server must); it never constructs an *upstream* URL - that lives in
/// `UpstreamHttp`.
///
/// The `/nar/` prefix is checked before the `.narinfo` suffix so a pathological
/// `/nar/foo.narinfo` routes as a NAR, not a narinfo (no such cache-API path
/// exists, but the order removes the ambiguity rather than relying on it).
fn classify(path: &str) -> Route {
    if path == "/nix-cache-info" {
        Route::CacheInfo
    } else if let Some(token) = path.strip_prefix("/nar/") {
        Route::Nar(NarPathToken::new(token))
    } else if let Some(rest) = path.strip_suffix(".narinfo") {
        Route::Narinfo(StoreHash::new(rest.trim_start_matches('/')))
    } else {
        Route::Other
    }
}

async fn handle(req: Request<Incoming>, app: Arc<App>) -> Response<NarBody> {
    let method = req.method().clone();
    if method != Method::GET && method != Method::HEAD {
        return text_status(StatusCode::METHOD_NOT_ALLOWED, "only GET/HEAD");
    }
    let is_head = method == Method::HEAD;
    let path = req.uri().path().to_string();
    // TASK-33: the remaining end-to-end header-wait budget propagated by a
    // DOWNSTREAM daemon in a chain, or `None` when this hop is the ENTRY (a
    // plain client - e.g. Nix - sends no such header). Passed to the budget-aware
    // source methods so the whole chain shares ONE shrinking deadline instead of
    // each hop re-granting a fresh `header_timeout`.
    let hop_budget = parse_hop_budget(req.headers());

    // Wave-1 choice: HEAD is answered by fetching upstream via GET (the source
    // traits carry no method) and dropping the body. Status/headers are correct,
    // but a HEAD narinfo still buffers the upstream body and a HEAD NAR still
    // opens the stream. Threading the method through the traits is a wave-2
    // refinement; documented here so it is a choice, not an oversight.
    match classify(&path) {
        Route::CacheInfo => respond_cache_info(&app.cache_info, is_head),
        Route::Narinfo(hash) => {
            let fetched = app.narinfo.fetch_within(&hash, hop_budget).await;
            respond_narinfo(
                fetched,
                &hash,
                &app.catalog,
                app.raw_serve.as_ref(),
                app.public_allowlist.as_ref(),
                is_head,
            )
            .await
        }
        Route::Nar(token) => {
            // Correlate: if the daemon saw this NAR's narinfo, carry the SIGNED
            // NarHash (the wave-2 lookup key) across the seam, plus the EXACT
            // requested token as the wave-1 transport hint and the signed NarSize
            // for the wave-2 abort bound (wave-1 UpstreamHttp ignores the size).
            // The hint is the inbound token itself, never derived from the hash,
            // so byte-identity survives a NarHash shared across compressions.
            // On an in-memory miss, consult PERSISTED correlation (task-8): the
            // narinfo disk cache derives token -> (hash, size) from cached
            // narinfos, so a warm-on-disk-but-cold-in-memory daemon still carries
            // the signed hash. Only when BOTH miss do we fall back to the raw URL
            // token - the documented cold-start degenerate (PRD risk 2).
            let correlated = app
                .catalog
                .meta_for_token(token.as_str())
                .or_else(|| app.correlation.meta_for_token(token.as_str()));
            // Capture the inbound token for the log's `path=` before it is moved
            // into the key; it is the exact NAR locator the client asked for.
            let nar_token = token.as_str().to_string();
            let (key, expected_size) = match correlated {
                Some(meta) => (
                    NarKey::SignedNarHash {
                        hash: meta.nar_hash,
                        upstream_hint: token,
                        // The AUTHORITATIVE narinfo transport descriptor (TASK-25): the
                        // HTTP source bounds the on-wire body by NarSize ONLY when this
                        // says Compression: none - never by the URL suffix.
                        transport: meta.transport,
                    },
                    Some(meta.nar_size),
                ),
                None => (NarKey::UpstreamPath(token), None),
            };
            let started = Instant::now();
            let result = app
                .nar
                .resolve_within(&key, expected_size, hop_budget)
                .await;
            // Log BEFORE `forward` moves `result`: the ordering is load-bearing.
            log_substitution(&app.upstream_label, &nar_token, &result, started.elapsed());
            forward(result, is_head)
        }
        Route::Other => forward(app.passthrough.get_within(&path, hop_budget).await, is_head),
    }
}

/// Parse the remaining end-to-end header-wait budget from the inbound request's
/// [`crate::upstream::HOP_BUDGET_HEADER`] (integer milliseconds), propagated by a
/// downstream daemon in a chain (TASK-33).
///
///   * ABSENT / unparsable / non-numeric -> `None`: treat this hop as the chain
///     ENTRY and seed the budget from its own `header_timeout`. Failing OPEN on a
///     garbled header is safe - the worst case is a hop uses its full local
///     timeout, i.e. the wave-1 behaviour.
///   * `0` -> `Some(0)`: the downstream says its deadline is already spent, so
///     this hop must fail fast rather than start a fresh full timeout.
///
/// A hostile/oversized value cannot make this hop wait longer than its own
/// `header_timeout`: [`crate::upstream::composed_header_wait`] takes the MIN, so
/// no clamp is needed here.
fn parse_hop_budget(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers.get(crate::upstream::HOP_BUDGET_HEADER)?;
    let ms: u64 = raw.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_millis(ms))
}

/// Serve the locally-generated cache-info body (never proxied).
fn respond_cache_info(info: &CacheInfo, is_head: bool) -> Response<NarBody> {
    let body = info.render().into_bytes();
    let len = body.len();
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/x-nix-cache-info")
        .header(http::header::CONTENT_LENGTH, len);
    let body = if is_head { empty() } else { full(body.into()) };
    builder
        .body(body)
        .expect("cache-info response is well-formed")
}

/// Narinfo: buffered so the (empty, wave-1) rewrite allowlist runs and
/// byte-fidelity is guaranteed. Non-200 statuses forward verbatim (AC#4).
///
/// This is also where correlation and the task-49 transport rewrite happen: on a
/// 200 we learn the `url-token -> (signed NarHash, NarSize)` mapping from the
/// narinfo body and, if `raw_serve` says the daemon will serve this NarHash's RAW
/// nar, rewrite the UNSIGNED transport fields to describe that raw nar and
/// correlate the REWRITTEN token. Otherwise the upstream narinfo is served
/// verbatim (the S2 path) and the original token is correlated.
async fn respond_narinfo(
    result: Result<UpstreamResponse, SourceError>,
    requested: &StoreHash,
    catalog: &NarCatalog,
    raw_serve: &dyn rewrite::RawServeDecision,
    public_allowlist: &crate::public_allowlist::PublicNarAllowlist,
    is_head: bool,
) -> Response<NarBody> {
    let resp = match result {
        Ok(resp) => resp,
        Err(err) => return gateway_error(&err),
    };
    // A non-200 (404/403/...) forwards verbatim - status fidelity.
    if resp.status != 200 {
        return forward(Ok(resp), is_head);
    }
    // Fail closed on a response we cannot faithfully forward (codex re-gate):
    // an unsupported transfer-coding (buffering + recomputing Content-Length over
    // an undecoded body would emit a Content-Length that disagrees with the coded
    // bytes) or a malformed Connection header we cannot safely parse.
    if must_fail_closed(&resp.headers) {
        eprintln!("daemon: refusing narinfo (unsupported coding / malformed Connection)");
        return text_status(StatusCode::BAD_GATEWAY, "upstream unavailable");
    }

    let UpstreamResponse { headers, body, .. } = resp;
    // Bound the buffered narinfo body (codex re-gate): a narinfo is ~1 KB;
    // anything past MAX_NARINFO_BYTES is a misbehaving upstream, not a narinfo.
    // Fail closed rather than buffer unboundedly. Defence-in-depth: the upstream
    // read is ALSO capped at this value, so no layer pre-buffers more.
    let bytes = match http_body_util::Limited::new(body, crate::source::MAX_NARINFO_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            eprintln!(
                "daemon: reading narinfo body (or exceeds {} B): {err}",
                crate::source::MAX_NARINFO_BYTES
            );
            return text_status(StatusCode::BAD_GATEWAY, "upstream unavailable");
        }
    };

    // TASK-102: LEARN whether this exact cache.nixos.org response PROVES the NAR public.
    // `learn` verifies the trusted-key Nix signature over `1;StorePath;NarHash;NarSize;
    // References` and, only on success, appends `(NarHash, NarSize)` to the public-NAR
    // allowlist ONCE (idempotent). This is the SINGLE append site (AC#2): it runs on the
    // ORIGINAL upstream bytes (the signed fields are byte-identical before any rewrite),
    // and only a 200 that survived the framing checks above reaches here - a MISS/outage/
    // timeout returned earlier, so a non-public path appends nothing (AC#3). A daemon with
    // no configured trusted keys uses a disabled allowlist and this is a cheap no-op.
    // `learn` also correlates the signed StorePath to the EXACT `<requested>.narinfo` key,
    // so a response for a DIFFERENT path than the one requested appends nothing.
    match public_allowlist.learn(requested, &bytes) {
        crate::public_allowlist::LearnOutcome::Appended { nar_hash, nar_size } => {
            println!("daemon: public-allowlist appended narhash={nar_hash} nar_size={nar_size}");
        }
        crate::public_allowlist::LearnOutcome::PersistFailed(err) => {
            // Fail-verbose: the entry was NOT admitted (disk and memory agree), so a
            // later request simply re-verifies. Surface it rather than degrade silently.
            eprintln!("daemon: public-allowlist append failed (not admitted): {err}");
        }
        crate::public_allowlist::LearnOutcome::RequestMismatch { requested, signed } => {
            // A response whose signed StorePath does not match the requested key: never
            // learned. Surface it - it is either a misrouted cache or a hostile upstream.
            eprintln!(
                "daemon: public-allowlist ignored a mis-correlated narinfo \
                 (requested {requested}, signed {signed})"
            );
        }
        // AlreadyPresent (idempotent duplicate) and Rejected (not proven public - the
        // common case for a non-cache upstream or an unsigned path) are normal and silent.
        _ => {}
    }

    // Learn the token -> signed-NarHash correlation, and decide whether to rewrite
    // the narinfo's transport fields to describe the RAW nar (task-49). A malformed
    // narinfo yields no correlation, is never rewritten, and its NAR request falls
    // back to UpstreamPath - safe, never a hard failure. The rewrite decision is
    // keyed on the SIGNED NarHash the correlation carries.
    let correlation = parse_correlation(&bytes);
    // The rewrite decision is ASYNC: for a decentralized backend "will I serve this
    // raw?" is a discovery probe (TASK-164), not a static lookup. Await it only when
    // the narinfo actually correlated (a malformed narinfo is never rewritten).
    let rewrite_to_raw = match correlation.as_ref() {
        Some(c) => raw_serve.will_serve_raw(c.nar_hash.as_str()).await,
        None => false,
    };

    let (out_bytes, rewrote) = if rewrite_to_raw {
        match rewrite::to_raw(&bytes) {
            Ok(rw) => {
                // Correlate the REWRITTEN URL token (what the client requests next)
                // back to the signed NarHash, so GET /nar/<token> dispatches
                // SignedNarHash to the raw NAR source rather than 404 on a stale
                // compressed token. FileHash == NarHash and FileSize == NarSize by
                // construction (Compression: none), so the client's transport gate
                // passes against the raw bytes and its NarHash gate passes unchanged.
                catalog.record(
                    NarPathToken::new(rw.url_token),
                    NarHash::new(rw.nar_hash),
                    rw.nar_size,
                    // The rewritten narinfo is `Compression: none`, so the follow-up raw
                    // NAR fetch is bounded by the signed NarSize (like-for-like) - the
                    // authoritative transport for the raw token.
                    NarinfoTransport {
                        compression: NarCompression::Raw,
                    },
                );
                (rw.body, true)
            }
            Err(err) => {
                // Fail SAFE, never half-rewritten: a narinfo will_serve_raw accepted
                // but to_raw could not rewrite is served VERBATIM. Record NO
                // correlation, so the follow-up NAR request takes the UpstreamPath
                // fallback and fetches the actual COMPRESSED bytes this verbatim
                // narinfo describes - never a rewritten token that a raw-only source
                // would mis-serve as raw under a Compression: xz narinfo. Should not
                // occur for a well-formed cache narinfo, so it is logged.
                eprintln!("daemon: narinfo rewrite-to-raw skipped ({err}); serving verbatim");
                (rewrite::apply(&bytes).into_owned(), false)
            }
        }
    } else {
        // Normal (non-peer) path: byte-identical passthrough - unknown fields, odd
        // ordering and multiple Sig lines all survive (AC#3).
        if let Some(c) = correlation {
            catalog.record(c.token, c.nar_hash, c.nar_size, c.transport);
        }
        (rewrite::apply(&bytes).into_owned(), false)
    };
    let len = out_bytes.len();

    let builder = Response::builder().status(StatusCode::OK);
    let mut response = builder
        .body(if is_head {
            empty()
        } else {
            full(out_bytes.into())
        })
        .expect("narinfo response is well-formed");
    forward_headers(response.headers_mut(), &headers);
    if rewrote {
        // The emitted body differs from upstream, so upstream validators no longer
        // describe it. Drop them rather than forward an ETag/Last-Modified for bytes
        // we did not send - byte-fidelity at the fidelity layer. nix verifies via
        // Sig/NarHash, not these, so nothing depends on them.
        let map = response.headers_mut();
        map.remove(http::header::ETAG);
        map.remove(http::header::LAST_MODIFIED);
    }
    // Content-Length must match the bytes we actually emit.
    let map = response.headers_mut();
    map.remove(http::header::CONTENT_LENGTH);
    map.insert(http::header::CONTENT_LENGTH, len.into());
    response
}

/// One comprehensible line per NAR substitution the daemon serves, so an
/// operator tailing the daemon sees WHAT moved, FROM WHERE, HOW MUCH, and HOW
/// LONG. Emitted only for a 200 (an actual substitution); a 404 or a transport
/// error is not a substitution and is reported by the error paths, not here.
///
/// `bytes` is the upstream `Content-Length` - the COMPRESSED on-wire transfer
/// size - or `unknown` when the upstream sent none (a chunked response). It is
/// deliberately NOT the signed NarSize: NarSize is the UNCOMPRESSED size, a
/// different quantity for any compressed NAR, so guessing with it would print a
/// wrong-unit number. Absence is reported honestly as `unknown`.
///
/// WAVE-1 LIMITATION (filed TASK-31): `duration_ms` is the time to the upstream
/// RESPONSE HEADERS, not the full body drain - the NAR body streams verbatim
/// AFTER this point - and `bytes` is `Content-Length`, not a counted drain, so a
/// truncated transfer would still log its advertised length. Full-drain
/// accounting is a wave-2 refinement that TASK-9's measurement layer consumes.
fn log_substitution(
    source: &str,
    nar_token: &str,
    result: &Result<UpstreamResponse, SourceError>,
    elapsed: Duration,
) {
    let Ok(resp) = result else { return };
    if resp.status != 200 {
        return;
    }
    let bytes = match content_length(&resp.headers) {
        Some(n) => n.to_string(),
        None => "unknown".to_string(),
    };
    println!(
        "daemon: substituted path=/nar/{nar_token} source={source} bytes={bytes} duration_ms={}",
        elapsed.as_millis()
    );
}

/// Parse an upstream `Content-Length` into bytes, or `None` when absent or
/// malformed (chunked transfers, which then fall back to the signed NarSize).
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Forward a streaming upstream response (NAR / passthrough) verbatim.
fn forward(result: Result<UpstreamResponse, SourceError>, is_head: bool) -> Response<NarBody> {
    let resp = match result {
        Ok(resp) => resp,
        Err(err) => return gateway_error(&err),
    };
    // Fail closed on a response we cannot faithfully forward (codex re-gate):
    // an unsupported transfer-coding (hyper strips only the final `chunked`, so a
    // `gzip, chunked` or `chunked, chunked` body streams out mis-framed) or a
    // malformed Connection header.
    if must_fail_closed(&resp.headers) {
        eprintln!("daemon: refusing response (unsupported coding / malformed Connection)");
        return text_status(StatusCode::BAD_GATEWAY, "upstream unavailable");
    }
    let UpstreamResponse {
        status,
        headers,
        body,
    } = resp;
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response = Response::builder()
        .status(status)
        .body(if is_head { empty() } else { body })
        .expect("forwarded response is well-formed");
    // Verbatim transport headers - INCLUDING Content-Encoding and
    // Content-Length - are the crux of AC#6: a gzip NAR is relayed unchanged
    // for the client to decompress and verify.
    forward_headers(response.headers_mut(), &headers);
    response
}

/// The daemon's forwarded/stripped header allowlist, documented so it is a
/// deliberate policy and asserted by `daemon/tests/header_hygiene.rs` (task-13).
/// The daemon is a TRANSPARENT proxy, so the policy is deny-a-fixed-set,
/// forward-everything-else - the inverse of a curated allowlist, because the
/// content-integrity fields the client verifies (`Content-Encoding`,
/// `Content-Length`, `ETag`, and every end-to-end header) must survive verbatim
/// and enumerating them would silently drop any we forgot.
///
/// Three classes:
///   * STRIP (never relayed) - the RFC 7230 §6.1 hop-by-hop headers below, PLUS
///     any field-name listed in a `Connection:` header value. These describe a
///     single TCP hop (this client<->that server) and are meaningless, or
///     actively wrong, one hop further on.
///   * FORWARD verbatim (everything else) - crucially `Content-Encoding` (a gzip
///     NAR relays unchanged for the client to decompress + verify, AC#6),
///     `Content-Type`, `ETag`, `Last-Modified`, `Cache-Control`, `Accept-Ranges`
///     and any `X-*`. The daemon adds NO decoding layer, so these pass byte-exact.
///   * NEVER TOUCH - the narinfo BODY (the signed fingerprint) and the NAR bytes.
///     Header hygiene here concerns the response HEADER MAP only; `Content-Length`
///     is the one header the serving layer RECOMPUTES, and only for the buffered
///     narinfo path where it must equal the bytes actually emitted (see
///     `respond_narinfo`). On the streamed NAR path even `Content-Length` is
///     forwarded verbatim.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Copy every header except hop-by-hop ones (which belong to a single
/// connection and must not be relayed). Honours the `Connection:` header's own
/// token list per RFC 7230 §6.1: `Connection: X-Foo` marks `X-Foo` hop-by-hop
/// for this message, so it is stripped too - a keep-alive/desync hazard the
/// long-chain hardening (task-11/task-13) specifically guards against.
fn forward_headers(dst: &mut HeaderMap, src: &HeaderMap) {
    let connection_tokens = connection_listed_tokens(src);
    for (name, value) in src {
        if is_hop_by_hop(name) || connection_tokens.contains(name.as_str().as_bytes()) {
            continue;
        }
        dst.append(name.clone(), value.clone());
    }
}

/// The lower-cased field-names named in any well-formed `Connection:` header
/// value. A MALFORMED Connection value (obs-text/control token) never reaches
/// here: `connection_header_is_malformed` fails the whole response closed at the
/// serving-layer gate before `forward_headers` runs. For a well-formed value we
/// parse the raw bytes and add EVERY listed token, incl `close`/`keep-alive`:
/// those are connection directives with no legitimate end-to-end header of the
/// same name, so stripping a same-named header is harmless and strictly safer.
fn connection_listed_tokens(src: &HeaderMap) -> std::collections::HashSet<Vec<u8>> {
    let mut tokens = std::collections::HashSet::new();
    for value in src.get_all(http::header::CONNECTION) {
        for token in value.as_bytes().split(|&b| b == b',') {
            let token = crate::source::ascii_lower_trim(token);
            if !token.is_empty() {
                tokens.insert(token);
            }
        }
    }
    tokens
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
}

/// The serving-layer fail-closed gate: a response the daemon cannot faithfully
/// forward (an unsupported transfer-coding, or a malformed `Connection` header we
/// cannot safely parse) becomes a clean 502 rather than a mislabeled/leaky
/// forward. Applied before building EVERY forwarded response (codex re-gate).
fn must_fail_closed(headers: &HeaderMap) -> bool {
    crate::source::has_unsupported_transfer_coding(headers)
        || crate::source::connection_header_is_malformed(headers)
        || crate::source::has_ambiguous_framing(headers)
}

/// Map a transport failure to a fast, clean gateway error so Nix falls back.
fn gateway_error(err: &SourceError) -> Response<NarBody> {
    eprintln!("daemon: {err}");
    text_status(StatusCode::BAD_GATEWAY, "upstream unavailable")
}

fn text_status(status: StatusCode, message: &str) -> Response<NarBody> {
    let body = format!("{message}\n").into_bytes();
    let len = body.len();
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain")
        .header(http::header::CONTENT_LENGTH, len)
        .body(full(body.into()))
        .expect("status response is well-formed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_covers_the_cache_api() {
        assert!(matches!(classify("/nix-cache-info"), Route::CacheInfo));
        assert!(matches!(classify("/abc123.narinfo"), Route::Narinfo(_)));
        assert!(matches!(classify("/nar/1xyz.nar.xz"), Route::Nar(_)));
        assert!(matches!(classify("/log/foo"), Route::Other));
        assert!(matches!(classify("/foo.ls"), Route::Other));
    }

    #[test]
    fn narinfo_hash_is_extracted_without_extension() {
        match classify("/0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz.narinfo") {
            Route::Narinfo(h) => assert_eq!(h.as_str(), "0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz"),
            _ => panic!("expected narinfo route"),
        }
    }

    #[test]
    fn nar_locator_keeps_its_suffix() {
        match classify("/nar/1abcd.nar.xz") {
            Route::Nar(h) => assert_eq!(h.as_str(), "1abcd.nar.xz"),
            _ => panic!("expected nar route"),
        }
    }

    #[tokio::test]
    async fn none_narinfo_without_filehash_correlates_and_dispatches_p2p() {
        // TASK-220 biting integration test at the serving layer. A `Compression: none`
        // narinfo that OMITS FileHash arrives on the p2p-discovery HIT path
        // (will_serve_raw = true). The daemon MUST rewrite it to raw AND record the
        // token -> SignedNarHash correlation, so the follow-up GET /nar/<token>
        // dispatches the SignedNarHash (p2p) source - NOT the URL-less UpstreamPath.
        //
        // BITE: before the rewrite fix, to_raw returned MissingField(FileHash), so
        // respond_narinfo took the verbatim else-branch that records NO correlation;
        // meta_for_token would then be None and Route::Nar would fall to UpstreamPath.
        // The assertions below hold only once to_raw stops over-rejecting this class.
        let digest = "06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb";
        let body = format!(
            "StorePath: /nix/store/0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib\n\
URL: nar/{digest}.nar\n\
Compression: none\n\
NarHash: sha256:{digest}\n\
NarSize: 66048\n\
References: \n\
Sig: nix-p2p-test-1:kvRtCi6KujoW6x7esqgP8QdiaaVX4OL1beI/xmfobVHzM/tSSqmy7jcnI7QDognLkmkwaSgA6vraWOYN0kiICw==\n"
        );
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, body.len().into());
        let resp = UpstreamResponse {
            status: 200,
            headers,
            body: full(bytes::Bytes::from(body.into_bytes())),
        };

        let catalog = NarCatalog::new();
        // will_serve_raw = YES for this NarHash: the p2p-discovery HIT that triggers
        // the rewrite-to-raw branch (the exact path where the bug lived).
        let raw_serve = rewrite::AllowlistRawServe::new([format!("sha256:{digest}")]);
        let public = crate::public_allowlist::PublicNarAllowlist::disabled();
        let requested = StoreHash::new("0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz");

        let response =
            respond_narinfo(Ok(resp), &requested, &catalog, &raw_serve, &public, false).await;
        assert_eq!(response.status(), StatusCode::OK);

        // The token the client requests next (the rewritten raw URL token).
        let token = format!("{digest}.nar");
        let meta = catalog.meta_for_token(&token).expect(
            "correlation MUST be recorded for a Compression: none narinfo lacking FileHash - \
             without it the NAR request falls to the URL-less UpstreamPath and p2p is disabled",
        );
        // Route::Nar dispatches the SignedNarHash (p2p) source IFF meta_for_token is
        // Some; prove the recorded meta carries the SIGNED nar identity and the
        // authoritative raw transport (NarSize, not a compressed unit).
        assert_eq!(meta.nar_hash.as_str(), format!("sha256:{digest}"));
        assert_eq!(meta.nar_size, 66048);
        assert_eq!(meta.transport.compression, NarCompression::Raw);
    }

    #[test]
    fn hop_by_hop_headers_are_dropped() {
        let mut src = HeaderMap::new();
        src.insert("content-encoding", "gzip".parse().unwrap());
        src.insert("connection", "close".parse().unwrap());
        src.insert("transfer-encoding", "chunked".parse().unwrap());
        let mut dst = HeaderMap::new();
        forward_headers(&mut dst, &src);
        assert_eq!(dst.get("content-encoding").unwrap(), "gzip");
        assert!(dst.get("connection").is_none());
        assert!(dst.get("transfer-encoding").is_none());
    }
}
