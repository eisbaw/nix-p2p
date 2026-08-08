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
use crate::rewrite;
use crate::source::{
    NarBody, NarLocator, NarSource, NarinfoSource, RawUpstream, SourceError, StoreHash,
    UpstreamResponse,
};

/// Everything a request needs, injected so tests can swap any source for a fake.
pub struct App {
    pub narinfo: Arc<dyn NarinfoSource>,
    pub nar: Arc<dyn NarSource>,
    pub passthrough: Arc<dyn RawUpstream>,
    pub cache_info: CacheInfo,
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
    Nar(NarLocator),
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
    } else if let Some(locator) = path.strip_prefix("/nar/") {
        Route::Nar(NarLocator::new(locator))
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
        Route::Narinfo(hash) => respond_narinfo(app.narinfo.fetch(&hash).await, is_head).await,
        Route::Nar(hash) => forward(app.nar.resolve(&hash, None).await, is_head),
        Route::Other => forward(app.passthrough.get(&path).await, is_head),
    }
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
async fn respond_narinfo(
    result: Result<UpstreamResponse, SourceError>,
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

    let UpstreamResponse { headers, body, .. } = resp;
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            eprintln!("daemon: reading narinfo body: {err}");
            return text_status(StatusCode::BAD_GATEWAY, "upstream unavailable");
        }
    };
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

/// Forward a streaming upstream response (NAR / passthrough) verbatim.
fn forward(result: Result<UpstreamResponse, SourceError>, is_head: bool) -> Response<NarBody> {
    let resp = match result {
        Ok(resp) => resp,
        Err(err) => return gateway_error(&err),
    };
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

/// Copy every header except hop-by-hop ones (which belong to a single
/// connection and must not be relayed).
fn forward_headers(dst: &mut HeaderMap, src: &HeaderMap) {
    for (name, value) in src {
        if is_hop_by_hop(name) {
            continue;
        }
        dst.append(name.clone(), value.clone());
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
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
    HOP_BY_HOP.contains(&name.as_str())
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
