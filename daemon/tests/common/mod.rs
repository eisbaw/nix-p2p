//! Shared harness for the daemon's in-process integration tests.
//!
//! Nothing here touches the gitignored generated fixture tree (absent in a Nix
//! sandbox and forbidden to Rust by the source guard): each test synthesises its
//! own tiny in-memory cache. Two building blocks:
//!   * [`MockUpstream`] - a std-threaded static origin whose per-request handler
//!     the test supplies, so upstream behaviour (status, headers, body) is
//!     defined precisely at the call site. It records every request path so
//!     tests can assert exact hit counts (the request-count oracle).
//!   * [`spawn_app`] / [`spawn_daemon`] - run the real `daemon` serving stack on
//!     an OS-assigned loopback port and hand back the address.
//!
//! The client is a raw async HTTP/1.1 reader so a truncated or reset transfer is
//! observable (short body / no status), exactly as Nix would see it.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use daemon::{
    App, CacheInfo, NarCatalog, NarSource, NarinfoSource, NullCorrelation, RawUpstream,
    TaskSupervisor, UpstreamHttp, serve,
};
use flate2::Compression;
use flate2::read::{GzDecoder, GzEncoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---- mock upstream (static origin with a test-supplied handler) -------------

/// One canned upstream response. `Content-Length` is always sent as the true
/// body length; `headers` carry everything else verbatim (e.g. a
/// `Content-Encoding: gzip` the daemon must forward untouched).
#[derive(Clone)]
pub struct MockResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl MockResponse {
    pub fn ok(content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        MockResponse {
            status: 200,
            headers: vec![("Content-Type".to_string(), content_type.to_string())],
            body: body.into(),
        }
    }
    pub fn status(code: u16) -> Self {
        MockResponse {
            status: code,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            body: format!("status {code}\n").into_bytes(),
        }
    }
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// A live static origin. Records every requested `(method, path)`.
pub struct MockUpstream {
    pub addr: SocketAddr,
    hits: Arc<Mutex<Vec<(String, String)>>>,
    stop: Arc<AtomicBool>,
}

impl MockUpstream {
    /// Start an origin whose handler maps `(method, path)` to a response.
    pub fn start<F>(handler: F) -> MockUpstream
    where
        F: Fn(&str, &str) -> MockResponse + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("origin binds");
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(handler);
        let hits_thread = Arc::clone(&hits);
        let stop_thread = Arc::clone(&stop);
        thread::spawn(move || {
            for incoming in listener.incoming() {
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = incoming else { continue };
                let handler = Arc::clone(&handler);
                let hits = Arc::clone(&hits_thread);
                thread::spawn(move || serve_origin_conn(stream, &*handler, &hits));
            }
        });
        MockUpstream { addr, hits, stop }
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn hits(&self) -> Vec<(String, String)> {
        self.hits.lock().unwrap().clone()
    }

    /// Number of requests whose path exactly equals `path`.
    pub fn count_path(&self, path: &str) -> usize {
        self.hits().iter().filter(|(_, p)| p == path).count()
    }

    /// Number of `*.narinfo` requests seen.
    pub fn count_narinfo(&self) -> usize {
        self.hits()
            .iter()
            .filter(|(_, p)| p.ends_with(".narinfo"))
            .count()
    }

    /// Number of `nar/*` requests seen.
    pub fn count_nar(&self) -> usize {
        self.hits()
            .iter()
            .filter(|(_, p)| p.starts_with("/nar/"))
            .count()
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock accept().
        let _ = TcpStream::connect(self.addr);
    }
}

fn serve_origin_conn<F>(mut stream: TcpStream, handler: &F, hits: &Mutex<Vec<(String, String)>>)
where
    F: Fn(&str, &str) -> MockResponse,
{
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return,
            Ok(_) => {
                raw.push(byte[0]);
                if raw.ends_with(b"\r\n\r\n") {
                    break;
                }
                if raw.len() > 64 * 1024 {
                    return;
                }
            }
            Err(_) => return,
        }
    }
    let head = String::from_utf8_lossy(&raw);
    let mut parts = head.lines().next().unwrap_or("").split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let path = target.split('?').next().unwrap_or("").to_string();

    hits.lock().unwrap().push((method.clone(), path.clone()));

    let resp = handler(&method, &path);
    let is_head = method.eq_ignore_ascii_case("HEAD");
    let mut out = format!("HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status));
    for (name, value) in &resp.headers {
        // The mock owns Content-Length so it always matches the body.
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    out.push_str("Connection: close\r\n\r\n");
    let _ = stream.write_all(out.as_bytes());
    if !is_head {
        let _ = stream.write_all(&resp.body);
    }
    let _ = stream.flush();
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

// ---- running the real daemon ------------------------------------------------

/// A running daemon; aborts its serve task on drop.
pub struct DaemonHandle {
    serve: tokio::task::JoinHandle<()>,
    supervisor: TaskSupervisor,
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        self.supervisor.cancel_now();
        self.serve.abort();
    }
}

/// Run an arbitrary [`App`] (used to inject fakes) and return its address.
pub async fn spawn_app(app: Arc<App>) -> (SocketAddr, DaemonHandle) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("daemon binds");
    let addr = listener.local_addr().unwrap();
    let supervisor = TaskSupervisor::new();
    let task_handle = supervisor.handle();
    let handle = tokio::spawn(async move {
        let _ = serve(listener, app, task_handle).await;
    });
    (
        addr,
        DaemonHandle {
            serve: handle,
            supervisor,
        },
    )
}

/// Run a daemon whose three sources are all the real `UpstreamHttp` for
/// `upstream_url`, with a default cache-info.
pub async fn spawn_daemon(upstream_url: &str) -> (SocketAddr, DaemonHandle) {
    spawn_daemon_with(upstream_url, CacheInfo::default()).await
}

/// The upstream header timeout the in-process HARNESS runs with.
///
/// TASK-109 / TASK-111. `UpstreamHttp::new`'s PRODUCT default header timeout is now
/// `HEADER_TIMEOUT_MS` = 15 s (TASK-111 raised it from a WAN-hostile 1000 ms so a
/// slow-but-healthy upstream is not 502'd as if dead). The harness pins its OWN value
/// regardless, for two reasons: (1) it must be INDEPENDENT of future product-default
/// changes so a tuning of the product number never silently alters test timing, and
/// (2) it wants a value that is "long enough that only a genuine hang reaches it" yet
/// bites a real hang a little sooner in CI than the 15 s product default would.
///
/// Ten seconds is not a tuned value - it is exactly that "only a genuine hang reaches
/// it" property, the only one the harness needs. Tests that exercise the timeout
/// ITSELF must set their own value explicitly rather than leaning on this one.
pub const HARNESS_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// As [`spawn_daemon`] but with a caller-chosen cache-info (for AC#5 priority).
pub async fn spawn_daemon_with(
    upstream_url: &str,
    cache_info: CacheInfo,
) -> (SocketAddr, DaemonHandle) {
    // The catalog is the server's correlation state; UpstreamHttp needs none.
    let catalog = Arc::new(NarCatalog::new());
    let upstream = Arc::new(
        UpstreamHttp::new(upstream_url)
            .expect("valid upstream")
            .with_header_timeout(HARNESS_HEADER_TIMEOUT),
    );
    let app = app_from_upstream(upstream, catalog, cache_info);
    spawn_app(app).await
}

/// Assemble an [`App`] from one `UpstreamHttp` behind all three seams, with the
/// server's correlation `catalog`.
pub fn app_from_upstream(
    upstream: Arc<UpstreamHttp>,
    catalog: Arc<NarCatalog>,
    cache_info: CacheInfo,
) -> Arc<App> {
    Arc::new(App {
        narinfo: upstream.clone() as Arc<dyn NarinfoSource>,
        nar: upstream.clone() as Arc<dyn NarSource>,
        passthrough: upstream as Arc<dyn RawUpstream>,
        cache_info,
        catalog,
        upstream_label: "test-upstream".to_string(),
        // No persistent narinfo cache in the plain-upstream harness: a NAR
        // request that misses the in-memory catalog takes the UpstreamPath
        // fallback, exactly as before task-8.
        correlation: Arc::new(NullCorrelation),
        // The plain-upstream harness never serves raw, so narinfos relay verbatim.
        raw_serve: Arc::new(daemon::NoRawServe),
        public_allowlist: Arc::new(daemon::PublicNarAllowlist::disabled()),

        post_fetch_announce: None,
    })
}

// ---- raw async HTTP/1.1 client ----------------------------------------------

/// A parsed response. `status == None` means the connection produced no valid
/// HTTP response (a reset). `complete` is false when the body was shorter than
/// the advertised `Content-Length` (a truncated transfer).
pub struct RawResp {
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub content_length: Option<u64>,
    pub complete: bool,
}

impl RawResp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

pub async fn get(addr: SocketAddr, path: &str) -> RawResp {
    request(addr, "GET", path).await
}

pub async fn head(addr: SocketAddr, path: &str) -> RawResp {
    request(addr, "HEAD", path).await
}

pub async fn request(addr: SocketAddr, method: &str, path: &str) -> RawResp {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to daemon");
    let req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    stream.flush().await.ok();

    let mut raw = Vec::new();
    // A reset shows up as an error; treat it as "no response".
    let reset = stream.read_to_end(&mut raw).await.is_err();
    parse_response(&raw, reset)
}

fn parse_response(raw: &[u8], reset: bool) -> RawResp {
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return RawResp {
            status: None,
            headers: vec![],
            body: raw.to_vec(),
            content_length: None,
            complete: false,
        };
    };
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok());
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let content_length = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok());
    let body = raw[split + 4..].to_vec();
    let complete = match content_length {
        Some(len) => body.len() as u64 == len && !reset,
        None => !reset,
    };
    RawResp {
        status,
        headers,
        body,
        content_length,
        complete,
    }
}

// ---- gzip helpers for the AC#6 verbatim-forwarding bite ---------------------

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(data, Compression::default());
    let mut out = Vec::new();
    encoder.read_to_end(&mut out).expect("gzip");
    out
}

pub fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).expect("gunzip");
    out
}
