//! `UpstreamHttp`: the wave-1 impl of all three upstream traits over plain
//! HTTP. THE ONLY MODULE IN THE DAEMON THAT SPEAKS TO A NETWORK UPSTREAM.
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
//!   * plain HTTP only. Fronting cache.nixos.org directly needs TLS, out of
//!     wave-1 scope (all tests front the mock/testproxy over loopback HTTP).
//!     Tracked as task-24 rather than pulling a TLS stack in now.

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Uri};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::source::{
    NarLocator, NarSource, NarinfoSource, RawUpstream, SourceError, StoreHash, UpstreamResponse,
};

/// Upper bound on a buffered (narinfo) body. A narinfo is a few hundred bytes;
/// anything past this is a misbehaving upstream, not a narinfo, and is rejected
/// rather than buffered unboundedly.
const MAX_BUFFERED_BODY: usize = 8 * 1024 * 1024;

/// Transparent HTTP client to a single upstream binary cache.
#[derive(Debug, Clone)]
pub struct UpstreamHttp {
    host: String,
    port: u16,
    /// Precomputed `host:port` for the `Host:` header.
    authority: String,
    connect_timeout: Duration,
    header_timeout: Duration,
}

impl UpstreamHttp {
    /// Build a client for `base`, e.g. `http://127.0.0.1:8080`. Fails fast on a
    /// malformed base rather than deferring the error to the first request.
    pub fn new(base: &str) -> Result<Self, String> {
        let (host, port) = parse_authority(base)?;
        let authority = format!("{host}:{port}");
        Ok(UpstreamHttp {
            host,
            port,
            authority,
            // Short by design (AC#6): a down upstream fails clean, fast.
            connect_timeout: Duration::from_millis(1000),
            header_timeout: Duration::from_millis(1000),
        })
    }

    /// Open a fresh connection, send a GET for `path`, and return the response
    /// with its body still unread (streamed lazily by the caller).
    async fn send(
        &self,
        path: &str,
    ) -> Result<hyper::Response<hyper::body::Incoming>, SourceError> {
        let stream = timeout(
            self.connect_timeout,
            TcpStream::connect((self.host.as_str(), self.port)),
        )
        .await
        .map_err(|_| SourceError::Unreachable(format!("connect timed out to {}", self.authority)))?
        .map_err(|e| SourceError::Unreachable(format!("connect to {}: {e}", self.authority)))?;

        let io = TokioIo::new(stream);
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
    /// body never sits whole in memory. If `expected_size` is set and the
    /// upstream declares a larger `Content-Length`, abort before downloading
    /// (PRD risk 6 early guard).
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
        expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        let response = self.send(path).await?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();

        // Dormant in wave 1: `expected_size` is always None here (the daemon
        // serves NARs statelessly, with no narinfo in hand), so this early guard
        // never fires. Populating it from the signed NarSize and adding the
        // per-chunk streaming abort is task-25 (PRD risk 6, claim-spam DoS).
        if let (Some(limit), Some(declared)) = (expected_size, content_length(&headers))
            && declared > limit
        {
            return Err(SourceError::TooLarge { limit, declared });
        }

        let body = response.into_body().map_err(std::io::Error::other).boxed();
        Ok(UpstreamResponse {
            status,
            headers,
            body,
        })
    }
}

/// The upstream `Content-Length`, if present and parseable.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(hyper::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Split `http://host:port` (or `host:port`, or `http://host`) into host+port.
/// Defaults to port 80 when absent. TLS (`https://`) is out of wave-1 scope.
fn parse_authority(base: &str) -> Result<(String, u16), String> {
    let authority = base
        .strip_prefix("http://")
        .unwrap_or(base)
        .trim_end_matches('/');
    if base.starts_with("https://") {
        return Err(format!("https upstream not supported in wave 1: {base:?}"));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse()
                .map_err(|_| format!("bad port in upstream {base:?}"))?;
            Ok((host.to_string(), port))
        }
        None => Ok((authority.to_string(), 80)),
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
        locator: &NarLocator,
        expected_size: Option<u64>,
    ) -> Result<UpstreamResponse, SourceError> {
        // The NAR locator becomes an upstream URL HERE and nowhere else - the
        // seam that lets wave 2 swap in an iroh source (which resolves the
        // locator over p2p instead) behind the same trait.
        self.fetch_streaming(&format!("/nar/{}", locator.as_str()), expected_size)
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
            ("127.0.0.1".to_string(), 8080)
        );
        assert_eq!(
            parse_authority("example.com").unwrap(),
            ("example.com".to_string(), 80)
        );
    }

    #[test]
    fn rejects_https_in_wave_1() {
        assert!(UpstreamHttp::new("https://cache.nixos.org").is_err());
    }

    #[test]
    fn rejects_bad_port() {
        assert!(UpstreamHttp::new("http://host:notaport").is_err());
    }
}
