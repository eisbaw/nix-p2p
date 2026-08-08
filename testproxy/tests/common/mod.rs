//! Shared harness for the integration bite tests.
//!
//! Each test builds a real two-hop wire path - a static `origin` (mock
//! upstream) and the `testproxy` in front of it - and drives it with a raw TCP
//! client. Nothing here touches the gitignored generated fixture output tree
//! (absent in a Nix build sandbox and forbidden to Rust by the source guard); the
//! tests synthesise their own tiny cache tree in a temp dir. That is what makes
//! these bites able to run under `nix build .#testproxy`'s checkPhase.

#![allow(dead_code)]

use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use testproxy::{Config, Server, State, origin};

static UNIQUE: AtomicU64 = AtomicU64::new(0);

/// A live origin + proxy pair with temp directories cleaned up on drop.
pub struct Fixture {
    pub origin_addr: SocketAddr,
    pub proxy_addr: SocketAddr,
    pub state: Arc<State>,
    pub origin_dir: PathBuf,
    pub cache_dir: PathBuf,
    _origin: Server,
    _proxy: Server,
}

impl Fixture {
    /// Build a fixture whose origin already serves `nix-cache-info`, one
    /// narinfo and its NAR of `nar_size` bytes. The NAR is filled with a
    /// non-trivial pattern so corruption is detectable.
    pub fn with_nar(nar_size: usize) -> Fixture {
        let id = UNIQUE.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("testproxy-it-{}-{}", std::process::id(), id));
        let origin_dir = base.join("origin");
        let cache_dir = base.join("cache");
        fs::create_dir_all(origin_dir.join("nar")).unwrap();
        fs::create_dir_all(&cache_dir).unwrap();

        // nix-cache-info: Priority/WantMassQuery exactly as task-3's fixture
        // advertises, so a passthrough test can prove they survive verbatim.
        fs::write(
            origin_dir.join("nix-cache-info"),
            b"StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n",
        )
        .unwrap();

        let nar_bytes: Vec<u8> = (0..nar_size).map(|i| (i % 251) as u8).collect();
        fs::write(origin_dir.join("nar/testnar.nar"), &nar_bytes).unwrap();

        let narinfo = format!(
            "StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
             URL: nar/testnar.nar\n\
             Compression: none\n\
             FileHash: sha256:0000000000000000000000000000000000000000000000000000\n\
             FileSize: {size}\n\
             NarHash: sha256:1111111111111111111111111111111111111111111111111111\n\
             NarSize: {size}\n\
             References: \n\
             Sig: nix-p2p-test-1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==\n",
            size = nar_size,
        );
        fs::write(origin_dir.join("test.narinfo"), narinfo.as_bytes()).unwrap();

        let _origin = origin::spawn(origin_dir.clone(), 0).expect("origin binds");
        let origin_addr = _origin.addr;

        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream: origin::base_url(origin_addr),
            cache_dir: cache_dir.clone(),
        };
        let (proxy, state) = testproxy::spawn(config).expect("proxy binds");
        let proxy_addr = proxy.addr;

        Fixture {
            origin_addr,
            proxy_addr,
            state,
            origin_dir,
            cache_dir,
            _origin,
            _proxy: proxy,
        }
    }

    /// The canonical NAR bytes the origin serves.
    pub fn origin_nar(&self) -> Vec<u8> {
        fs::read(self.origin_dir.join("nar/testnar.nar")).unwrap()
    }

    /// The NAR bytes currently in the proxy's disk cache, if cached.
    pub fn cached_nar(&self) -> Option<Vec<u8>> {
        fs::read(self.cache_dir.join("nar/testnar.nar")).ok()
    }

    /// Set faults via the admin endpoint (as the e2e harness will).
    pub fn set_faults(&self, query: &str) {
        let resp = raw_request(
            self.proxy_addr,
            "POST",
            &format!("/__testproxy/faults?{query}"),
        )
        .expect("faults endpoint reachable");
        assert_eq!(
            resp.status,
            Some(200),
            "faults not accepted: {:?}",
            resp.body_string()
        );
    }

    pub fn clear_faults(&self) {
        raw_request(self.proxy_addr, "POST", "/__testproxy/faults/clear").unwrap();
    }

    pub fn reset_log(&self) {
        raw_request(self.proxy_addr, "POST", "/__testproxy/reset").unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(root) = self.origin_dir.parent() {
            let _ = fs::remove_dir_all(root);
        }
    }
}

/// A parsed HTTP response, plus whether the socket delivered fewer body bytes
/// than `Content-Length` promised (the truncation signal) or no valid HTTP
/// response at all (the reset signal, `status == None`).
pub struct RawResponse {
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub content_length: Option<u64>,
    /// True if the connection closed / reset before a full response was read.
    pub short: bool,
}

impl RawResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// The body length matches the advertised Content-Length.
    pub fn complete(&self) -> bool {
        match self.content_length {
            Some(len) => self.body.len() as u64 == len,
            None => !self.short,
        }
    }
}

/// Issue a request and read the whole response (until the server closes the
/// connection). Never panics on a reset - that is a valid observation here.
pub fn raw_request(addr: SocketAddr, method: &str, target: &str) -> io::Result<RawResponse> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()?;

    let mut raw = Vec::new();
    // A reset shows up as ConnectionReset; treat it as "no response".
    match stream.read_to_end(&mut raw) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {
            return Ok(RawResponse {
                status: None,
                headers: vec![],
                body: vec![],
                content_length: None,
                short: true,
            });
        }
        Err(err) => return Err(err),
    }

    Ok(parse_response(&raw))
}

/// Convenience GET.
pub fn get(addr: SocketAddr, target: &str) -> io::Result<RawResponse> {
    raw_request(addr, "GET", target)
}

fn parse_response(raw: &[u8]) -> RawResponse {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n");
    let Some(split) = split else {
        // No header terminator: the server closed without a valid response.
        return RawResponse {
            status: None,
            headers: vec![],
            body: raw.to_vec(),
            content_length: None,
            short: true,
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
    let short = match content_length {
        Some(len) => (body.len() as u64) < len,
        None => false,
    };
    RawResponse {
        status,
        headers,
        body,
        content_length,
        short,
    }
}
