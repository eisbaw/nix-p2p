//! Minimal hand-rolled HTTP/1.1 for the fixture: request parsing, response
//! writing, and a tiny upstream client.
//!
//! Why hand-rolled instead of a server crate (`tiny_http`, `hyper`, ...): two
//! of the seven fault modes - connection reset and truncated-NAR - require the
//! fixture to abandon a response mid-flight at the socket level, which a
//! framing library deliberately hides. Owning the wire also makes the fixture
//! the *independent witness* PRD round 5 asks for - it shares no HTTP logic
//! with the daemon because it depends on no HTTP crate at all. The surface is
//! genuinely small: GET/HEAD, a status line, a handful of headers, a body.
//!
//! Simplifications, all sound for a localhost test fixture and documented so a
//! reader does not mistake them for bugs:
//!   * one request per connection (`Connection: close`); no keep-alive or
//!     pipelining. Nix reconnects, so this costs a socket per request and buys
//!     a parser with no framing state.
//!   * request bodies are ignored (the cache API is GET/HEAD only).
//!   * the upstream client speaks HTTP over plain TCP AND, as of TASK-22, TLS
//!     (`https://`) so it can front the real cache.nixos.org. TLS wraps the same
//!     blocking `TcpStream` in a `native-tls` (openssl-backed) `TlsStream` BEFORE
//!     the hand-rolled request/response, so the byte-verbatim, no-decompression
//!     discipline is identical on both - TLS is a byte transport with no decoding
//!     layer. native-tls is deliberately DISJOINT from the daemon's rustls
//!     (TASK-24) so the fixture stays an independent wire witness (enforced by
//!     `scripts/check-independence.py`). See [`upstream_get`] / [`fetch_https`]
//!     for the full-verification (chain, validity, hostname/SNI) default with no
//!     production skip-verify (AC#3), and [`TlsBudget`] for the frozen
//!     `tls-upstream-v1` connect budget that stops a stalled peer hanging.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use native_tls::TlsConnector;

/// A parsed request line + headers. Bodies are intentionally not read.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// The raw request target, e.g. `/nar/abc.nar` or `/x.narinfo?foo=1`.
    pub target: String,
    /// Lower-cased header names mapped to their values.
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// The path portion of the target, with any `?query` stripped.
    pub fn path(&self) -> &str {
        match self.target.split_once('?') {
            Some((path, _)) => path,
            None => &self.target,
        }
    }

    /// The raw `?query` string (without the `?`), if any.
    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, q)| q)
    }

    pub fn is_head(&self) -> bool {
        self.method.eq_ignore_ascii_case("HEAD")
    }
}

/// Read one request (line + headers) from `stream`.
///
/// Reads a byte at a time until the `\r\n\r\n` header terminator so it never
/// over-reads into a following request's bytes - unnecessary here (one request
/// per connection) but it keeps the parser honest and self-contained. Returns
/// `Ok(None)` on a cleanly closed / empty connection.
pub fn parse_request(stream: &mut TcpStream) -> io::Result<Option<Request>> {
    let mut raw = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte)? {
            0 => {
                if raw.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid-request",
                ));
            }
            _ => {
                raw.push(byte[0]);
                if raw.ends_with(b"\r\n\r\n") {
                    break;
                }
                // A request head this large is not our client; fail fast rather
                // than grow unboundedly on a hostile or broken peer.
                if raw.len() > 64 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request head exceeds 64 KiB",
                    ));
                }
            }
        }
    }

    let text = String::from_utf8_lossy(&raw);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    if method.is_empty() || target.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }

    Ok(Some(Request {
        method,
        target,
        headers,
    }))
}

/// Reason phrases for the handful of statuses the fixture emits.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

/// Write status line + the given headers + a blank line. Body (if any) is the
/// caller's to stream afterwards. `Connection: close` is always sent because
/// the fixture serves one request per connection.
pub fn write_head<W: Write>(
    writer: &mut W,
    status: u16,
    headers: &[(&str, String)],
) -> io::Result<()> {
    write!(writer, "HTTP/1.1 {} {}\r\n", status, reason(status))?;
    for (name, value) in headers {
        write!(writer, "{name}: {value}\r\n")?;
    }
    writer.write_all(b"Connection: close\r\n\r\n")
}

/// Write a complete small response (status + body) in one shot. Used for
/// metadata, admin JSON and error pages - never for NAR payloads, which stream.
pub fn write_response<W: Write>(
    writer: &mut W,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let headers = [
        ("Content-Type", content_type.to_string()),
        ("Content-Length", body.len().to_string()),
    ];
    write_head(writer, status, &headers)?;
    writer.write_all(body)?;
    writer.flush()
}

/// A streaming response from the upstream cache: status, headers, and a body
/// reader that must be consumed without being buffered whole (NARs are large).
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Box<dyn Read + Send>,
}

impl UpstreamResponse {
    /// The upstream `Content-Length`, if present and parseable.
    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length").and_then(|v| v.parse().ok())
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

// ---------------------------------------------------------------------------
// FROZEN `tls-upstream-v1` connect budget (TASK-22 AC#5; the SAME values the
// daemon froze in TASK-24, so the two witnesses bound the wire identically).
//
// ONE 10 s total covers the whole "reach the TLS peer" sequence - DNS
// resolution, the TCP connect, and the TLS handshake - with the TCP connect and
// the handshake EACH capped at 5 s INSIDE that total. A stalled stage therefore
// fails within the bound as an `io::Error` (which every `upstream_get` caller
// turns into a 502 so Nix falls back - never a crash or a hang). The name is
// frozen: the production https path consumes exactly these values (asserted
// `== default` by a test). Monotonic timing tests may add up to `SCHEDULER_GRACE`
// of scheduler slop on top of the configured deadline WITHOUT relaxing the
// configuration itself.
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
    /// on a loaded box.
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
/// total already spent yields `0` (the stage fails at once rather than waiting a
/// wrapped-around eternity). Pure, so the connect/handshake/total interplay is
/// unit-tested without a network stall.
fn stage_budget(total: Duration, elapsed: Duration, stage_cap: Duration) -> Duration {
    total.saturating_sub(elapsed).min(stage_cap)
}

/// Upstream URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

/// A connection to the upstream that can be both written (the request) and read
/// (the response): a plain `TcpStream`, or a `native_tls::TlsStream<TcpStream>`.
/// The blanket impl lets [`fetch_over`] parse the response identically on both,
/// so TLS adds no decoding layer and bytes pass through verbatim.
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// Fetch `path` from the upstream cache at `base`.
///
/// `http://` connects in plain TCP (the wave-1 path); `https://` wraps the same
/// connection in a native-tls-validated TLS session (TASK-22) BEFORE the
/// hand-rolled request/response, bounded by the FROZEN `tls-upstream-v1` budget.
/// The response body is returned as a lazy reader (leftover header-buffer bytes
/// chained ahead of the live connection) so the caller streams it straight
/// through to the client and the disk cache without ever holding a whole NAR in
/// memory - the same for TLS, since native-tls is a byte transport.
pub fn upstream_get(base: &str, path: &str) -> io::Result<UpstreamResponse> {
    let (scheme, host, port) = parse_authority(base)?;
    match scheme {
        Scheme::Http => {
            let stream = TcpStream::connect((host.as_str(), port))?;
            // A dead-slow upstream must not hang the fixture forever; the
            // "unreachable" fault models a down upstream cleanly, this just
            // bounds pathological hangs.
            stream.set_read_timeout(Some(Duration::from_secs(60)))?;
            fetch_over(Box::new(stream), &format!("{host}:{port}"), path)
        }
        Scheme::Https => {
            // Production TLS: native-tls's DEFAULT connector validates the chain
            // against the SYSTEM trust roots AND the hostname/SNI. There is no
            // `danger_accept_invalid_*` here or anywhere on a production path
            // (AC#3); the only accept-invalid connector is built under
            // `#[cfg(test)]` to prove the negatives bite.
            let connector = TlsConnector::new()
                .map_err(|e| io::Error::other(format!("build tls connector: {e}")))?;
            fetch_https(&host, port, &connector, &host, TlsBudget::default(), path)
        }
    }
}

/// Establish a validated TLS connection to `connect_host:port`, bounded by
/// `budget`, then send the request and parse the response over it. `server_name`
/// is the hostname VALIDATED against the certificate (SNI + hostname check); in
/// every production call it equals `connect_host`, but the tests split the two
/// so a wrong-hostname cert can be exercised against a loopback fixture. The
/// `connector` carries the trust roots and verification policy: `upstream_get`
/// passes native-tls's default (system-roots, fully-verifying) connector; ONLY
/// tests inject a fixture-CA or an accept-invalid connector, so no
/// verification-disabled path exists in a production build (AC#3).
fn fetch_https(
    connect_host: &str,
    port: u16,
    connector: &TlsConnector,
    server_name: &str,
    budget: TlsBudget,
    path: &str,
) -> io::Result<UpstreamResponse> {
    let start = Instant::now();

    // Stage 1: DNS + TCP connect, bounded by min(connect cap, remaining total).
    let connect_cap = stage_budget(budget.total, Duration::ZERO, budget.connect);
    let tcp = connect_within(connect_host, port, connect_cap)?;

    // Stage 2: TLS handshake, bounded by an ABSOLUTE deadline of
    // min(handshake cap, remaining total) - NOT a per-read idle timeout.
    //
    // native-tls handshakes with BLOCKING reads on the underlying socket. A
    // per-socket `set_read_timeout` is only an IDLE timeout: a SLOW-DRIP peer
    // that emits a byte before each idle window resets the timer forever and
    // pins this thread indefinitely (never reaching the frozen 5 s/10 s caps).
    // So instead a watchdog thread holds a cloned socket handle and, at the
    // absolute `handshake_cap` deadline, shuts the socket down - the blocked (or
    // dripping) read returns at once and the handshake fails within the bound.
    // This mirrors TASK-24's async `timeout(handshake_future)` absolute
    // semantics on the blocking port. The watchdog is cancelled on either
    // outcome BEFORE any body read, so it can never tear down a live response.
    let handshake_cap = stage_budget(budget.total, start.elapsed(), budget.handshake);
    if handshake_cap.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "tls budget exhausted before handshake",
        ));
    }
    let watch = tcp.try_clone()?;
    let fired = Arc::new(AtomicBool::new(false));
    let fired_watch = Arc::clone(&fired);
    let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        if matches!(
            cancel_rx.recv_timeout(handshake_cap),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            fired_watch.store(true, Ordering::SeqCst);
            // Force the blocked/dripping handshake read to return immediately.
            let _ = watch.shutdown(std::net::Shutdown::Both);
        }
    });

    let handshake = connector.connect(server_name, tcp);
    let _ = cancel_tx.send(());
    let _ = watchdog.join();

    let tls = match handshake {
        Ok(tls) => tls,
        Err(e) => {
            // The deadline shutdown and a genuine verification failure both
            // surface HERE, before any request byte is sent or any response byte
            // is read/cached; `fired` distinguishes the two for the operator.
            if fired.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("tls handshake to {server_name} exceeded budget"),
                ));
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tls handshake to {server_name}: {e}"),
            ));
        }
    };
    // Handshake done: bound a dead-slow body the way the plain path does.
    tls.get_ref()
        .set_read_timeout(Some(Duration::from_secs(60)))?;
    tls.get_ref().set_write_timeout(None)?;

    // Drop the port from the Host header when it is the https default, so a
    // request to the real CDN carries `Host: cache.nixos.org` like a browser.
    let host_header = if port == 443 {
        server_name.to_string()
    } else {
        format!("{server_name}:{port}")
    };
    fetch_over(Box::new(tls), &host_header, path)
}

/// DNS-resolve `host:port` and TCP-connect, bounding the COMBINED resolve +
/// connect within `cap`. std's `to_socket_addrs` (blocking getaddrinfo) has no
/// timeout, so the resolve+connect runs on a worker thread and the caller waits
/// at most `cap`: a stalled DNS or a black-holed connect both fail within the
/// budget instead of hanging. The inner `connect_timeout` bounds the worker
/// itself so a stalled connect cannot leak the thread indefinitely.
fn connect_within(host: &str, port: u16, cap: Duration) -> io::Result<TcpStream> {
    if cap.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "connect budget exhausted",
        ));
    }
    let (tx, rx) = mpsc::sync_channel(1);
    let host = host.to_string();
    thread::spawn(move || {
        let _ = tx.send(resolve_and_connect(&host, port, cap));
    });
    match rx.recv_timeout(cap) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "dns/connect exceeded budget",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("connect worker vanished"))
        }
    }
}

fn resolve_and_connect(host: &str, port: u16, cap: Duration) -> io::Result<TcpStream> {
    let mut last_err = io::Error::new(
        io::ErrorKind::NotFound,
        format!("no address for {host}:{port}"),
    );
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, cap) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = err,
        }
    }
    Err(last_err)
}

/// Send `GET path` over an already-connected (plain or TLS) `conn` and parse the
/// response into an [`UpstreamResponse`] whose body lazily chains the leftover
/// header-buffer bytes ahead of the live connection. Shared by both transports,
/// which is what guarantees TLS forwards bytes verbatim (AC#1): the byte path is
/// identical; only the transport under `conn` differs.
fn fetch_over(
    mut conn: Box<dyn ReadWrite + Send>,
    host_header: &str,
    path: &str,
) -> io::Result<UpstreamResponse> {
    write!(
        conn,
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
    )?;
    conn.flush()?;

    // Read up to and including the header terminator, keeping any body bytes
    // that arrived in the same read for the chained body reader.
    let mut head = Vec::with_capacity(512);
    let mut buf = [0u8; 4096];
    let body_start;
    loop {
        let n = conn.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream closed before response headers completed",
            ));
        }
        head.extend_from_slice(&buf[..n]);
        if let Some(pos) = find_subslice(&head, b"\r\n\r\n") {
            body_start = pos + 4;
            break;
        }
        if head.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream response head exceeds 64 KiB",
            ));
        }
    }

    let leftover = head[body_start..].to_vec();
    let head_text = String::from_utf8_lossy(&head[..body_start]);
    let mut lines = head_text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = parse_status(status_line)?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }

    let body = Box::new(io::Cursor::new(leftover).chain(conn));
    Ok(UpstreamResponse {
        status,
        headers,
        body,
    })
}

fn parse_status(status_line: &str) -> io::Result<u16> {
    // "HTTP/1.1 200 OK"
    status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unparseable status line"))
}

/// Split `https://host[:port]`, `http://host[:port]` (or a bare `host[:port]`,
/// treated as http) into scheme + host + port. The port defaults to the scheme
/// default when absent: 80 for http, 443 for https.
fn parse_authority(base: &str) -> io::Result<(Scheme, String, u16)> {
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
            let port = port.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("bad port in {base:?}"))
            })?;
            Ok((scheme, host.to_string(), port))
        }
        None => Ok((scheme, authority.to_string(), default_port)),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_splits_path_and_query() {
        let req = Request {
            method: "GET".into(),
            target: "/x.narinfo?priority=10".into(),
            headers: vec![],
        };
        assert_eq!(req.path(), "/x.narinfo");
        assert_eq!(req.query(), Some("priority=10"));
    }

    #[test]
    fn authority_parses_forms() {
        assert_eq!(
            parse_authority("http://127.0.0.1:8080").unwrap(),
            (Scheme::Http, "127.0.0.1".into(), 8080)
        );
        assert_eq!(
            parse_authority("http://example.com/").unwrap(),
            (Scheme::Http, "example.com".into(), 80)
        );
        assert!(parse_authority("http://host:notaport").is_err());
    }

    #[test]
    fn https_authority_defaults_to_443() {
        // AC#1: an https base is accepted and defaults to port 443.
        assert_eq!(
            parse_authority("https://cache.nixos.org").unwrap(),
            (Scheme::Https, "cache.nixos.org".into(), 443)
        );
        assert_eq!(
            parse_authority("https://example.com:8443/").unwrap(),
            (Scheme::Https, "example.com".into(), 8443)
        );
    }

    #[test]
    fn status_line_parses() {
        assert_eq!(parse_status("HTTP/1.1 404 Not Found").unwrap(), 404);
        assert!(parse_status("garbage").is_err());
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
        // AC#5: the production path consumes tls-upstream-v1 UNCHANGED, and it is
        // the SAME shape the daemon (TASK-24) froze.
        let v1 = TlsBudget::tls_upstream_v1();
        assert_eq!(v1.total, Duration::from_millis(10_000));
        assert_eq!(v1.connect, Duration::from_millis(5_000));
        assert_eq!(v1.handshake, Duration::from_millis(5_000));
        assert_eq!(TLS_UPSTREAM_SCHEDULER_GRACE_MS, 1_000);
        // Each stage cap fits inside the total, and the two together cannot
        // exceed it (so the per-stage caps alone bound the whole operation).
        assert!(v1.connect <= v1.total);
        assert!(v1.handshake <= v1.total);
        assert!(v1.connect + v1.handshake <= v1.total);
        let default = TlsBudget::default();
        assert_eq!(default.total, v1.total);
        assert_eq!(default.connect, v1.connect);
        assert_eq!(default.handshake, v1.handshake);
    }
}

/// End-to-end TLS cert-validation bites (TASK-22 AC#1/#3/#4/#5), the fixture's
/// independent mirror of the daemon's TASK-24 suite - but built on native-tls,
/// NOT rustls, so the two witnesses stay disjoint. An `rcgen` fixture CA issues a
/// VALID-hostname leaf plus the three negatives (untrusted self-signed,
/// wrong-hostname, expired). Each is presented by an in-process native-tls server
/// on loopback; the client validates against a connector trusting ONLY the
/// fixture CA, exactly as production validates against the system bundle. The
/// negatives each carry their OWN bite control: swapping in the
/// `#[cfg(test)]`-only accept-invalid connector makes the SAME server succeed,
/// proving the rejection is caused by certificate validation and not by unrelated
/// plumbing. That accept-invalid connector is compiled ONLY under `#[cfg(test)]`
/// and is unreachable from any production API (AC#3).
#[cfg(test)]
mod tls_tests {
    use super::*;

    use std::net::{SocketAddr, TcpListener};

    use native_tls::{Identity, TlsAcceptor};
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, date_time_ymd,
    };

    // --- fixture CA + leaf issuance ---------------------------------------

    /// A self-signed fixture CA: returns its DER (for the client trust root) and
    /// an `Issuer` (owning the CA params + key) that signs leaves.
    fn fixture_ca() -> (Vec<u8>, Issuer<'static, KeyPair>) {
        let ca_key = KeyPair::generate().expect("ca keypair");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "nix-p2p testproxy fixture CA");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = params.self_signed(&ca_key).expect("self-sign ca");
        let ca_der = ca_cert.der().to_vec();
        let issuer = Issuer::new(params, ca_key);
        (ca_der, issuer)
    }

    /// A serverAuth leaf for `san`, signed by the fixture CA, returned as
    /// (cert PEM, key PKCS8 PEM) for a native-tls `Identity`. `expired` narrows
    /// the (very wide) rcgen default validity to 2000..2001 so the verifier's
    /// validity check bites.
    fn leaf_signed_by(issuer: &Issuer<'static, KeyPair>, san: &str, expired: bool) -> Identity {
        let key = KeyPair::generate().expect("leaf keypair");
        let mut params = CertificateParams::new(vec![san.to_string()]).expect("leaf params");
        params.distinguished_name.push(DnType::CommonName, san);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if expired {
            params.not_before = date_time_ymd(2000, 1, 1);
            params.not_after = date_time_ymd(2001, 1, 1);
        }
        let cert = params.signed_by(&key, issuer).expect("sign leaf");
        identity(&cert.pem(), &key.serialize_pem())
    }

    /// A serverAuth leaf for `san` signed by its OWN key (untrusted: chains to no
    /// CA in the client trust store).
    fn self_signed_leaf(san: &str) -> Identity {
        let key = KeyPair::generate().expect("keypair");
        let mut params = CertificateParams::new(vec![san.to_string()]).expect("params");
        params.distinguished_name.push(DnType::CommonName, san);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.self_signed(&key).expect("self-sign");
        identity(&cert.pem(), &key.serialize_pem())
    }

    fn identity(cert_pem: &str, key_pem: &str) -> Identity {
        Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes()).expect("native-tls identity")
    }

    // --- connectors --------------------------------------------------------

    /// A connector trusting ONLY the fixture CA (built-in roots disabled), so the
    /// "valid" case proves it is the fixture CA doing the trusting, and the
    /// negatives cannot be rescued by a system root.
    fn secure_connector(ca_der: &[u8]) -> TlsConnector {
        let ca = native_tls::Certificate::from_der(ca_der).expect("parse fixture CA");
        TlsConnector::builder()
            .disable_built_in_roots(true)
            .add_root_certificate(ca)
            .build()
            .expect("secure connector")
    }

    /// The ONLY verification-disabled connector in the crate. `#[cfg(test)]`, so
    /// it cannot exist in a production build; used solely to PROVE the negatives
    /// bite (neutralizing verification makes the SAME cert connect).
    fn insecure_connector() -> TlsConnector {
        TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .expect("insecure connector")
    }

    // --- in-process servers (std threads, blocking) ------------------------

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

    /// Read a request's headers off a connected stream, then write `response`.
    fn serve_response<S: Read + Write>(stream: &mut S, response: &[u8]) {
        let mut acc = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    acc.extend_from_slice(&buf[..n]);
                    if find_subslice(&acc, b"\r\n\r\n").is_some() {
                        break;
                    }
                }
                Err(_) => return,
            }
        }
        let _ = stream.write_all(response);
        let _ = stream.flush();
    }

    /// Loops accepting TLS connections, serving `response` on each (a failed
    /// handshake just drops). Loops so a rejected-then-insecure retry both land.
    fn spawn_https(identity: Identity, response: Vec<u8>) -> SocketAddr {
        let acceptor = TlsAcceptor::new(identity).expect("tls acceptor");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(sock) = sock else { return };
                let acceptor = acceptor.clone();
                let response = response.clone();
                thread::spawn(move || {
                    if let Ok(mut tls) = acceptor.accept(sock) {
                        serve_response(&mut tls, &response);
                        // Ordered close (close_notify then FIN) so the client
                        // reads the whole body before EOF.
                        let _ = tls.shutdown();
                    }
                });
            }
        });
        addr
    }

    fn spawn_http(response: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(mut sock) = sock else { return };
                let response = response.clone();
                thread::spawn(move || {
                    serve_response(&mut sock, &response);
                    let _ = sock.shutdown(std::net::Shutdown::Write);
                });
            }
        });
        addr
    }

    /// Accepts TCP connections and HOLDS them without ever speaking TLS, so the
    /// client's handshake stalls until its deadline fires.
    fn spawn_tcp_blackhole() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            let mut held = Vec::new();
            for sock in listener.incoming() {
                match sock {
                    Ok(sock) => held.push(sock),
                    Err(_) => return,
                }
            }
        });
        addr
    }

    /// A SLOW-DRIP TLS peer: it reads the ClientHello, writes a WELL-FORMED TLS
    /// record header announcing a large handshake record, then dribbles the
    /// record body ONE byte per `interval` for `drips` bytes before closing. The
    /// well-formed header keeps OpenSSL WAITING for the (never-completed) body
    /// instead of erroring on a malformed record, and `interval < handshake_cap`
    /// means a per-read IDLE timeout would reset on every byte and NEVER fire -
    /// so only an ABSOLUTE deadline bounds it. This is the oracle that separates
    /// an idle timeout (RED: fails only at the far-off EOF) from an absolute
    /// deadline (GREEN: fails at the cap). Timing is server-controlled, so the
    /// bite is deterministic, not load-flaky.
    fn spawn_tls_slow_drip(interval: Duration, drips: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            for sock in listener.incoming() {
                let Ok(mut sock) = sock else { return };
                thread::spawn(move || {
                    // Consume (part of) the ClientHello so the client's write side
                    // completes and it blocks reading our response.
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf);
                    // TLS record: handshake (0x16), TLS 1.2 (0x0303), length 8192.
                    // 8192 dwarfs anything we dribble, so OpenSSL keeps waiting.
                    if sock.write_all(&[0x16, 0x03, 0x03, 0x20, 0x00]).is_err() {
                        return;
                    }
                    let _ = sock.flush();
                    for _ in 0..drips {
                        thread::sleep(interval);
                        if sock.write_all(&[0u8]).is_err() {
                            return; // client already gave up (the absolute bound)
                        }
                        let _ = sock.flush();
                    }
                });
            }
        });
        addr
    }

    // --- helpers -----------------------------------------------------------

    fn get_over_tls(
        addr: SocketAddr,
        validated_name: &str,
        connector: &TlsConnector,
        budget: TlsBudget,
    ) -> io::Result<UpstreamResponse> {
        // TCP target is the loopback fixture; the VALIDATED name is separate, so
        // wrong-hostname is exercised deterministically.
        fetch_https(
            &addr.ip().to_string(),
            addr.port(),
            connector,
            validated_name,
            budget,
            "/nar/x",
        )
    }

    /// A negative with its bite control: the real verifier REJECTS (no bytes are
    /// read/returned), and the SAME server ACCEPTS once verification is
    /// neutralized - proving the rejection is cert validation, not plumbing.
    fn assert_rejected_with_bite(addr: SocketAddr, validated_name: &str, ca_der: &[u8]) {
        let secure = secure_connector(ca_der);
        assert!(
            get_over_tls(addr, validated_name, &secure, TlsBudget::default()).is_err(),
            "the real verifier must reject this cert before any byte is forwarded"
        );
        let insecure = insecure_connector();
        let resp = get_over_tls(addr, validated_name, &insecure, TlsBudget::default())
            .expect("bite: with verification neutralized the SAME cert now connects");
        assert_eq!(
            resp.status, 200,
            "the rejection above was caused by cert validation, not plumbing"
        );
    }

    fn read_body(mut resp: UpstreamResponse) -> Vec<u8> {
        let mut bytes = Vec::new();
        resp.body.read_to_end(&mut bytes).expect("read body");
        bytes
    }

    // --- tests -------------------------------------------------------------

    /// AC#1 + verbatim: an https base connects over TLS against a fixture-CA valid
    /// hostname, and the body comes back byte-identical to the plain-HTTP leg with
    /// `Content-Encoding: gzip` intact (no auto-decompression). A raw
    /// gzip-magic-prefixed binary body stands in for a compressed NAR - nothing in
    /// this client decodes it, so real gzip is unnecessary to prove the point.
    #[test]
    fn tls_valid_hostname_forwards_bytes_verbatim_like_plain_http() {
        let (ca, issuer) = fixture_ca();
        let leaf = leaf_signed_by(&issuer, "valid.test", false);
        // gzip magic (0x1f 0x8b) + arbitrary non-text bytes: if any decode layer
        // existed it would mangle these; the assertion below pins that it does not.
        let body: &[u8] = &[0x1f, 0x8b, 0x08, 0x00, 0x00, 0xff, 0xfe, 0x42, 0x00, 0x13];
        let response = http_response(body, Some("gzip"));

        let tls_addr = spawn_https(leaf, response.clone());
        let http_addr = spawn_http(response);

        let secure = secure_connector(&ca);
        let tls_resp = get_over_tls(tls_addr, "valid.test", &secure, TlsBudget::default())
            .expect("valid fixture-CA cert connects over TLS");
        assert_eq!(tls_resp.status, 200);
        assert_eq!(
            tls_resp.header("content-encoding"),
            Some("gzip"),
            "Content-Encoding must survive the TLS hop verbatim"
        );
        let tls_bytes = read_body(tls_resp);

        let plain_resp =
            upstream_get(&format!("http://{http_addr}"), "/nar/x").expect("plain http");
        let plain_bytes = read_body(plain_resp);

        assert_eq!(
            tls_bytes, body,
            "bytes over TLS are the raw body, not transformed"
        );
        assert_eq!(
            tls_bytes, plain_bytes,
            "bytes over TLS must equal bytes over plain HTTP for the same body (AC#1)"
        );
    }

    /// AC#4: an untrusted self-signed cert (chains to no trusted root) is rejected
    /// before any byte; the insecure control proves it is the chain check.
    #[test]
    fn tls_untrusted_self_signed_is_rejected() {
        let (ca, _issuer) = fixture_ca();
        let leaf = self_signed_leaf("valid.test");
        let addr = spawn_https(leaf, http_response(b"secret", None));
        assert_rejected_with_bite(addr, "valid.test", &ca);
    }

    /// AC#4: a cert whose SAN is `wrong.test` is rejected when the client
    /// validates `valid.test`, though its chain and validity are fine.
    #[test]
    fn tls_wrong_hostname_is_rejected() {
        let (ca, issuer) = fixture_ca();
        let leaf = leaf_signed_by(&issuer, "wrong.test", false);
        let addr = spawn_https(leaf, http_response(b"secret", None));
        assert_rejected_with_bite(addr, "valid.test", &ca);
    }

    /// AC#4: an expired cert (validity 2000..2001) is rejected though its chain
    /// and hostname are fine.
    #[test]
    fn tls_expired_cert_is_rejected() {
        let (ca, issuer) = fixture_ca();
        let leaf = leaf_signed_by(&issuer, "valid.test", true);
        let addr = spawn_https(leaf, http_response(b"secret", None));
        assert_rejected_with_bite(addr, "valid.test", &ca);
    }

    /// AC#5: a server that accepts TCP but never completes the TLS handshake must
    /// FAIL within the (shrunk-for-speed) handshake deadline + scheduler grace, so
    /// the caller 502s / falls back - never a hang. Load-tolerant: the upper bound
    /// includes the full 1000 ms grace; the shrunk cap keeps the same budget SHAPE
    /// as v1 (total >= per-stage caps).
    #[test]
    fn tls_handshake_stall_fails_within_budget() {
        let (ca, _issuer) = fixture_ca();
        let addr = spawn_tcp_blackhole();
        let budget = TlsBudget {
            total: Duration::from_millis(10_000),
            connect: Duration::from_millis(5_000),
            handshake: Duration::from_millis(300),
        };
        let secure = secure_connector(&ca);

        let started = Instant::now();
        let res = get_over_tls(addr, "valid.test", &secure, budget);
        let elapsed = started.elapsed();

        assert!(
            res.is_err(),
            "a stalled handshake must fail (fallback preserved), got Ok"
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

    /// AC#5 (the stronger oracle): a SLOW-DRIP handshake - a peer that emits a
    /// byte every 200 ms, each interval well INSIDE the 500 ms handshake cap -
    /// must still fail at the ABSOLUTE deadline, not be kept alive forever by the
    /// activity. With a per-read idle timeout this hangs until the server's EOF
    /// (~4 s here, far past the bound); with the absolute watchdog it fails at the
    /// cap. Load-tolerant: the upper bound includes the full 1000 ms grace, and
    /// the drip timing is server-controlled so the bite is deterministic.
    #[test]
    fn tls_slow_drip_handshake_fails_at_absolute_deadline() {
        let (ca, _issuer) = fixture_ca();
        // 20 drips * 200 ms = 4 s of activity: an idle timeout (500 ms) would
        // never fire (200 < 500), so only the absolute deadline bounds this.
        let addr = spawn_tls_slow_drip(Duration::from_millis(200), 20);
        let budget = TlsBudget {
            total: Duration::from_millis(10_000),
            connect: Duration::from_millis(5_000),
            handshake: Duration::from_millis(500),
        };
        let secure = secure_connector(&ca);

        let started = Instant::now();
        let res = get_over_tls(addr, "valid.test", &secure, budget);
        let elapsed = started.elapsed();

        assert!(
            res.is_err(),
            "a slow-drip handshake must fail at the absolute deadline, not hang"
        );
        let grace = Duration::from_millis(TLS_UPSTREAM_SCHEDULER_GRACE_MS);
        assert!(
            elapsed <= budget.handshake + grace,
            "absolute deadline must fire within handshake+grace ({:?}); took {elapsed:?} (a per-read idle timeout would let the drip run to ~4s)",
            budget.handshake + grace
        );
        assert!(
            elapsed >= budget.handshake,
            "must wait out the absolute handshake deadline; took {elapsed:?}"
        );
    }

    /// AC#1 (optional, NETWORK-GATED): the PRODUCTION `upstream_get("https://...")`
    /// path, validating against the SYSTEM trust roots, reaches the REAL
    /// cache.nixos.org over TLS and fetches its signed `nix-cache-info`.
    /// `#[ignore]`d so the deterministic gate never depends on the network; run
    /// with `cargo test -p testproxy -- --ignored tls_real_cache`.
    #[test]
    #[ignore = "network: hits the real cache.nixos.org; run with --ignored"]
    fn tls_real_cache_nixos_org_over_https() {
        let resp = upstream_get("https://cache.nixos.org", "/nix-cache-info")
            .expect("real cache.nixos.org reachable over validated TLS");
        assert_eq!(resp.status, 200, "cache.nixos.org served nix-cache-info");
        let body = read_body(resp);
        assert!(
            std::str::from_utf8(&body)
                .unwrap_or("")
                .contains("StoreDir"),
            "nix-cache-info body must carry StoreDir, got {} bytes",
            body.len()
        );
    }
}
