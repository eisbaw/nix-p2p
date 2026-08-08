//! A plain static-file HTTP origin - the mock upstream the fixture caches in
//! front of.
//!
//! Task-3 ships the real signed fixture cache as a static tree; `just
//! fixtures-serve` serves it with Python. This origin is the same idea in-
//! process, used by the integration bite tests so they exercise the real wire
//! path (proxy -> upstream over TCP) without touching the gitignored generated
//! fixture output tree (which is absent inside a Nix build sandbox - the
//! source guard forbids Rust referencing it). Tests build their own tiny cache
//! tree in a temp dir and point this at it.

use crate::http::{self, Request};
use crate::server::{self, Server};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};

/// Serve `root` as a static binary cache on `127.0.0.1:port` (`port` 0 =
/// OS-assigned). Returns the running server; read its `addr` for the base URL.
pub fn spawn(root: PathBuf, port: u16) -> io::Result<Server> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    server::spawn(addr, move |request, stream| {
        handle(&root, request, stream);
    })
}

fn handle(root: &Path, request: Request, mut stream: TcpStream) {
    let relative = request.path().strip_prefix('/').unwrap_or("");
    // Same traversal guard as the cache: refuse anything that could escape.
    if relative.is_empty()
        || relative
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        let _ = http::write_response(&mut stream, 404, "text/plain", b"not found\n");
        return;
    }

    let path = root.join(relative);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => {
            let _ = http::write_response(&mut stream, 404, "text/plain", b"not found\n");
            return;
        }
    };

    let content_type = content_type_for(relative);
    if request.is_head() {
        let headers = [
            ("Content-Type", content_type.to_string()),
            ("Content-Length", bytes.len().to_string()),
        ];
        let _ = http::write_head(&mut stream, 200, &headers);
    } else {
        let _ = http::write_response(&mut stream, 200, content_type, &bytes);
    }
}

fn content_type_for(path: &str) -> &'static str {
    if path == "nix-cache-info" {
        "text/x-nix-cache-info"
    } else if path.ends_with(".narinfo") {
        "text/x-nix-narinfo"
    } else if path.contains("/nar/") || path.starts_with("nar/") {
        "application/x-nix-nar"
    } else {
        "application/octet-stream"
    }
}

/// The base URL a proxy should use to reach a server on `addr`.
pub fn base_url(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

/// Convenience for tests/manual use: fetch a full response body over HTTP.
/// Returns `(status, body)`. Small-response helper - not for NAR streaming.
pub fn get(addr: SocketAddr, path: &str) -> io::Result<(u16, Vec<u8>)> {
    use std::io::{Read, Write};
    let mut stream = TcpStream::connect(addr)?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no header terminator"))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no status"))?;
    Ok((status, raw[split + 4..].to_vec()))
}
