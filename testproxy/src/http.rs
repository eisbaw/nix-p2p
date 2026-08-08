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
//!   * the upstream client speaks plain HTTP. Fronting cache.nixos.org over
//!     TLS is out of wave-1 scope (all tests use the local mock upstream); see
//!     the TODO on [`upstream_get`].

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

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

/// Fetch `path` from the upstream cache at `base` (e.g. `http://127.0.0.1:8080`).
///
/// The response body is returned as a lazy reader (leftover header-buffer bytes
/// chained ahead of the live socket) so the caller streams it straight through
/// to the client and the disk cache without ever holding a whole NAR in memory.
///
/// TODO(task-22): plain HTTP only. Fronting cache.nixos.org directly needs TLS,
/// which is deliberately out of wave-1 scope (all tests use the local mock
/// upstream). Tracked as a backlog follow-up rather than pulling a TLS stack
/// into the fixture now.
pub fn upstream_get(base: &str, path: &str) -> io::Result<UpstreamResponse> {
    let (host, port) = parse_authority(base)?;
    let mut stream = TcpStream::connect((host.as_str(), port))?;
    // A dead-slow upstream must not hang the fixture forever; the "unreachable"
    // fault models a down upstream cleanly, this just bounds pathological hangs.
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;

    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()?;

    // Read up to and including the header terminator, keeping any body bytes
    // that arrived in the same read for the chained body reader.
    let mut head = Vec::with_capacity(512);
    let mut buf = [0u8; 4096];
    let body_start;
    loop {
        let n = stream.read(&mut buf)?;
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

    let body = Box::new(io::Cursor::new(leftover).chain(stream));
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

/// Split `http://host:port` (or `host:port`, or `http://host`) into host+port.
fn parse_authority(base: &str) -> io::Result<(String, u16)> {
    let authority = base
        .strip_prefix("http://")
        .or_else(|| base.strip_prefix("https://"))
        .unwrap_or(base)
        .trim_end_matches('/');
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("bad port in {base:?}"))
            })?;
            Ok((host.to_string(), port))
        }
        None => Ok((authority.to_string(), 80)),
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
            ("127.0.0.1".into(), 8080)
        );
        assert_eq!(
            parse_authority("http://example.com/").unwrap(),
            ("example.com".into(), 80)
        );
        assert!(parse_authority("http://host:notaport").is_err());
    }

    #[test]
    fn status_line_parses() {
        assert_eq!(parse_status("HTTP/1.1 404 Not Found").unwrap(), 404);
        assert!(parse_status("garbage").is_err());
    }
}
