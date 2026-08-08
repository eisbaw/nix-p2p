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
    NarBody, NarKey, NarPathToken, NarSource, NarinfoSource, RawUpstream, SourceError, StoreHash,
    UpstreamResponse,
};

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
}

/// Serve on an already-bound listener until it errors. Binding is the caller's
/// job so tests can grab an OS-assigned port (`127.0.0.1:0`) and read it back.
pub async fn serve(listener: TcpListener, app: Arc<App>) -> std::io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let app = Arc::clone(&app);
        tokio::spawn(async move {
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

    // Wave-1 choice: HEAD is answered by fetching upstream via GET (the source
    // traits carry no method) and dropping the body. Status/headers are correct,
    // but a HEAD narinfo still buffers the upstream body and a HEAD NAR still
    // opens the stream. Threading the method through the traits is a wave-2
    // refinement; documented here so it is a choice, not an oversight.
    match classify(&path) {
        Route::CacheInfo => respond_cache_info(&app.cache_info, is_head),
        Route::Narinfo(hash) => {
            respond_narinfo(app.narinfo.fetch(&hash).await, &app.catalog, is_head).await
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
                    },
                    Some(meta.nar_size),
                ),
                None => (NarKey::UpstreamPath(token), None),
            };
            let started = Instant::now();
            let result = app.nar.resolve(&key, expected_size).await;
            // Log BEFORE `forward` moves `result`: the ordering is load-bearing.
            log_substitution(&app.upstream_label, &nar_token, &result, started.elapsed());
            forward(result, is_head)
        }
        Route::Other => forward(app.passthrough.get(&path).await, is_head),
    }
}

/// Upper bound on a buffered narinfo body (codex, task-13). A real narinfo is a
/// few hundred bytes to low KB; 2 MiB is a generous ceiling past which the
/// response is not a narinfo. Buffering past it is refused (fail closed).
const MAX_NARINFO_BYTES: usize = 2 * 1024 * 1024;

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
/// This is also where correlation happens: on a 200 we learn the
/// `url-token -> (signed NarHash, NarSize)` mapping from the narinfo body and
/// record it in the catalog, so the NAR request that follows carries the signed
/// hash across the seam. Recording is done on the ORIGINAL upstream bytes,
/// before the (wave-1 identity) rewrite.
async fn respond_narinfo(
    result: Result<UpstreamResponse, SourceError>,
    catalog: &NarCatalog,
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
    // Fail closed on a transfer-coding we cannot honestly re-frame (codex, task-13):
    // buffering + recomputing Content-Length over an undecoded gzip/… body would
    // emit a Content-Length that disagrees with the actual coded bytes.
    if has_unsupported_transfer_coding(&resp.headers) {
        eprintln!("daemon: refusing narinfo with unsupported Transfer-Encoding");
        return text_status(StatusCode::BAD_GATEWAY, "upstream unavailable");
    }

    let UpstreamResponse { headers, body, .. } = resp;
    // Bound the buffered narinfo body (codex, task-13): a narinfo is a few hundred
    // bytes to low KB; anything past MAX_NARINFO_BYTES is a misbehaving upstream,
    // not a narinfo. Fail closed rather than buffer unboundedly into OOM. The
    // UpstreamHttp source is already Limited, but the serving layer enforces its
    // own bound so ANY NarinfoSource (cache, future p2p) is covered here too.
    let bytes = match http_body_util::Limited::new(body, MAX_NARINFO_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            eprintln!("daemon: reading narinfo body (or exceeds {MAX_NARINFO_BYTES} B): {err}");
            return text_status(StatusCode::BAD_GATEWAY, "upstream unavailable");
        }
    };

    // Learn the token -> signed-NarHash correlation. A malformed narinfo (any
    // missing field) is simply not recorded, so its NAR request falls back to
    // UpstreamPath - safe, never a hard failure.
    if let Some((token, nar_hash, nar_size)) = parse_correlation(&bytes) {
        catalog.record(token, nar_hash, nar_size);
    }
    // Wave 1: the allowlist is empty, so this is byte-identical - unknown
    // fields, odd ordering and multiple Sig lines all survive (AC#3).
    let out_bytes = rewrite::apply(&bytes).into_owned();
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
    // Fail closed on a transfer-coding we cannot faithfully forward (codex,
    // task-13): hyper strips only the final `chunked` framing, so a `gzip,
    // chunked` body would stream out still-gzipped with the coding erased.
    if has_unsupported_transfer_coding(&resp.headers) {
        eprintln!("daemon: refusing response with unsupported Transfer-Encoding");
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

/// The lower-cased field-names named in any `Connection:` header value (the
/// connection-specific fields the sender marked as not-to-be-forwarded).
///
/// Parses the RAW BYTES, not `to_str()` (codex finding, task-13): a `Connection`
/// value may legally carry obs-text (bytes 0x80-0xFF), on which `to_str()` fails,
/// and a silent skip there would FORWARD the fields the header named
/// (`Connection: X-Hop, \xff` leaks `X-Hop`). Byte parsing still extracts
/// `x-hop` from such a value, so the strip is fail-closed. EVERY listed token is
/// added, including `close`/`keep-alive`: those are connection directives with no
/// legitimate end-to-end header of the same name, so stripping a same-named
/// header is harmless and strictly safer than exempting it.
fn connection_listed_tokens(src: &HeaderMap) -> std::collections::HashSet<Vec<u8>> {
    let mut tokens = std::collections::HashSet::new();
    for value in src.get_all(http::header::CONNECTION) {
        for token in value.as_bytes().split(|&b| b == b',') {
            let token = ascii_lower_trim(token);
            if !token.is_empty() {
                tokens.insert(token);
            }
        }
    }
    tokens
}

/// Trim ASCII whitespace and lower-case ASCII letters of a raw header token,
/// leaving any non-ASCII (obs-text) bytes as-is so a garbage token cannot
/// accidentally collide with a real header name.
fn ascii_lower_trim(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace());
    let end = bytes.iter().rposition(|b| !b.is_ascii_whitespace());
    match (start, end) {
        (Some(s), Some(e)) => bytes[s..=e]
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .collect(),
        _ => Vec::new(),
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
}

/// True if the upstream `Transfer-Encoding` names any coding beyond `chunked`/
/// `identity` (e.g. `gzip, chunked`). hyper's http1 layer strips only the final
/// `chunked` FRAMING; a `gzip` transfer-coding underneath it is left applied,
/// so the bytes hyper hands us are still gzip-coded with that fact ERASED once we
/// drop the hop-by-hop `Transfer-Encoding` header. We could neither re-frame it
/// faithfully nor honestly `Content-Length` it (the buffered narinfo path would
/// count undecoded bytes), so the daemon FAILS CLOSED on such a response rather
/// than forward a mislabeled body (codex finding, task-13). The invariant: never
/// emit a body whose declared coding disagrees with its actual bytes.
fn has_unsupported_transfer_coding(headers: &HeaderMap) -> bool {
    for value in headers.get_all(http::header::TRANSFER_ENCODING) {
        for token in value.as_bytes().split(|&b| b == b',') {
            let token = ascii_lower_trim(token);
            if !token.is_empty() && token != b"chunked" && token != b"identity" {
                return true;
            }
        }
    }
    false
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
