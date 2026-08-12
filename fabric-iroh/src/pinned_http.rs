//! Minimal HTTP/1 transport pinned to one explicit recipient socket.
//!
//! This deliberately has no URL resolver, proxy integration, redirect
//! handling, cookie jar, credential store, or ambient client defaults.  The
//! configured `Host` is an application/trust label; TCP always connects to the
//! separately validated [`SocketAddr`].

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::iroh_node_record::normalize_socket_addr;

const MAX_HEADER_BYTES: usize = 8192;
pub(crate) const MAX_HTTP_BODY_BYTES: usize = 1104;
pub(crate) const MAX_RELAY_PAYLOAD_BYTES: usize = MAX_HTTP_BODY_BYTES - 32;
pub(crate) const RECORD_PATH_PREFIX: &str = "/pkarr/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PinnedHttpEndpoint {
    recipient: SocketAddr,
    host: String,
}

impl PinnedHttpEndpoint {
    pub(crate) fn new(
        recipient: SocketAddr,
        host: impl Into<String>,
    ) -> Result<Self, PinnedHttpError> {
        let recipient = normalize_socket_addr(recipient);
        validate_recipient_socket(recipient)?;
        let host = host.into();
        validate_host(&host)?;
        Ok(Self { recipient, host })
    }

    pub(crate) fn recipient(&self) -> SocketAddr {
        self.recipient
    }

    pub(crate) async fn put_record(
        &self,
        signer_z32: &str,
        body: &[u8],
        deadline: Duration,
    ) -> Result<PinnedHttpResponse, PinnedHttpError> {
        let packet = iroh_dns::pkarr::SignedPacket::from_bytes(body).map_err(|error| {
            PinnedHttpError::new(format!("PUT input is not a signed pkarr packet: {error}"))
        })?;
        if packet.public_key().to_z32() != signer_z32 {
            return Err(PinnedHttpError::new(
                "PUT packet signer does not match pinned request path",
            ));
        }
        self.request("PUT", signer_z32, &packet.to_relay_payload(), deadline)
            .await
    }

    pub(crate) async fn get_record(
        &self,
        signer_z32: &str,
        deadline: Duration,
    ) -> Result<PinnedHttpResponse, PinnedHttpError> {
        let response = self.request("GET", signer_z32, &[], deadline).await?;
        if response.status != 200 {
            return Ok(response);
        }
        let key = iroh::PublicKey::from_z32(signer_z32).map_err(|error| {
            PinnedHttpError::new(format!("GET signer is not a public key: {error}"))
        })?;
        let packet = iroh_dns::pkarr::SignedPacket::from_relay_payload(&key, &response.body)
            .map_err(|error| {
                PinnedHttpError::new(format!(
                    "GET response is not a valid pkarr relay payload: {error}"
                ))
            })?;
        Ok(PinnedHttpResponse {
            status: response.status,
            body: packet.as_bytes().to_vec(),
            elapsed: response.elapsed,
        })
    }

    /// Fetch one relay payload for an already-typed signer without interpreting
    /// it.  Node lookup must verify the response against the asker-supplied key
    /// itself so signature failures remain distinct from signed-record failures.
    /// The caller supplies the absolute operation deadline; DNS decoding and
    /// replay validation therefore consume the same ten-second budget as TCP.
    pub(crate) async fn get_record_raw_until(
        &self,
        signer: &iroh::PublicKey,
        absolute_deadline: Instant,
    ) -> Result<PinnedHttpResponse, PinnedHttpError> {
        self.request_until("GET", &signer.to_z32(), &[], absolute_deadline)
            .await
    }

    async fn request(
        &self,
        method: &'static str,
        signer_z32: &str,
        body: &[u8],
        total_deadline: Duration,
    ) -> Result<PinnedHttpResponse, PinnedHttpError> {
        if total_deadline.is_zero() {
            return Err(PinnedHttpError::configuration(
                "HTTP deadline must be positive",
            ));
        }
        let absolute_deadline = Instant::now()
            .checked_add(total_deadline)
            .ok_or_else(|| PinnedHttpError::configuration("HTTP deadline overflows Instant"))?;
        self.request_until(method, signer_z32, body, absolute_deadline)
            .await
    }

    async fn request_until(
        &self,
        method: &'static str,
        signer_z32: &str,
        body: &[u8],
        absolute_deadline: Instant,
    ) -> Result<PinnedHttpResponse, PinnedHttpError> {
        if absolute_deadline <= Instant::now() {
            return Err(PinnedHttpError::deadline(format!(
                "{method} to pinned recipient {} has no remaining deadline",
                self.recipient
            )));
        }
        validate_signer_path(signer_z32)?;
        let endpoint = self.clone();
        let signer_z32 = signer_z32.to_string();
        let body = body.to_vec();
        tokio::time::timeout_at(absolute_deadline, async move {
            endpoint.request_inner(method, &signer_z32, &body).await
        })
        .await
        .map_err(|_| {
            PinnedHttpError::deadline(format!(
                "{method} to pinned recipient {} exceeded its absolute deadline",
                self.recipient
            ))
        })?
    }

    async fn request_inner(
        &self,
        method: &str,
        signer_z32: &str,
        body: &[u8],
    ) -> Result<PinnedHttpResponse, PinnedHttpError> {
        let started = Instant::now();
        let mut stream = TcpStream::connect(self.recipient).await.map_err(|error| {
            let kind = if error.kind() == std::io::ErrorKind::ConnectionRefused {
                PinnedHttpErrorKind::ConnectionRefused
            } else {
                PinnedHttpErrorKind::Connect
            };
            PinnedHttpError::with_kind(
                kind,
                format!("connecting to pinned recipient {}: {error}", self.recipient),
            )
        })?;
        let path = format!("{RECORD_PATH_PREFIX}{signer_z32}");
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-pkarr-signed-packet\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.host,
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| PinnedHttpError::write(format!("writing request headers: {error}")))?;
        if !body.is_empty() {
            stream.write_all(body).await.map_err(|error| {
                PinnedHttpError::write(format!("writing request body: {error}"))
            })?;
        }
        stream
            .flush()
            .await
            .map_err(|error| PinnedHttpError::write(format!("flushing request: {error}")))?;

        let mut received = Vec::with_capacity(2048);
        let header_end = loop {
            if let Some(position) = find_header_end(&received) {
                if position + 4 > MAX_HEADER_BYTES {
                    return Err(PinnedHttpError::new(format!(
                        "response headers exceed {MAX_HEADER_BYTES} bytes"
                    )));
                }
                break position;
            }
            if received.len() >= MAX_HEADER_BYTES {
                return Err(PinnedHttpError::new(format!(
                    "response headers exceed {MAX_HEADER_BYTES} bytes"
                )));
            }
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk).await.map_err(|error| {
                PinnedHttpError::read(format!("reading response headers: {error}"))
            })?;
            if read == 0 {
                return Err(PinnedHttpError::new(
                    "response ended before complete headers",
                ));
            }
            received.extend_from_slice(&chunk[..read]);
        };
        let headers = std::str::from_utf8(&received[..header_end])
            .map_err(|_| PinnedHttpError::new("response headers are not UTF-8/ASCII"))?;
        let parsed = parse_response_headers(headers)?;
        if (300..400).contains(&parsed.status) {
            return Err(PinnedHttpError::new(format!(
                "redirect status {} rejected; pinned recipients are never widened",
                parsed.status
            )));
        }
        if parsed.content_length > MAX_RELAY_PAYLOAD_BYTES {
            return Err(PinnedHttpError::new(format!(
                "response body length {} exceeds {MAX_RELAY_PAYLOAD_BYTES}",
                parsed.content_length
            )));
        }
        let mut response_body = received[(header_end + 4)..].to_vec();
        if response_body.len() > parsed.content_length {
            return Err(PinnedHttpError::new(
                "response carried bytes beyond Content-Length",
            ));
        }
        while response_body.len() < parsed.content_length {
            let remaining = parsed.content_length - response_body.len();
            let mut chunk = [0u8; 1024];
            let chunk_len = remaining.min(chunk.len());
            let read = stream
                .read(&mut chunk[..chunk_len])
                .await
                .map_err(|error| {
                    PinnedHttpError::read(format!("reading response body: {error}"))
                })?;
            if read == 0 {
                return Err(PinnedHttpError::new(format!(
                    "response body ended at {} of {} bytes",
                    response_body.len(),
                    parsed.content_length
                )));
            }
            response_body.extend_from_slice(&chunk[..read]);
        }
        let mut proof = [0u8; 1];
        let extra = stream.read(&mut proof).await.map_err(|error| {
            PinnedHttpError::read(format!("checking response framing: {error}"))
        })?;
        if extra != 0 {
            return Err(PinnedHttpError::new(
                "response carried bytes beyond Content-Length",
            ));
        }
        Ok(PinnedHttpResponse {
            status: parsed.status,
            body: response_body,
            elapsed: started.elapsed(),
        })
    }
}

fn validate_recipient_socket(recipient: SocketAddr) -> Result<(), PinnedHttpError> {
    if recipient.port() == 0
        || recipient.ip().is_unspecified()
        || recipient.ip().is_multicast()
        || matches!(recipient.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::BROADCAST)
        || matches!(recipient, SocketAddr::V6(address) if address.ip().is_unicast_link_local() && address.scope_id() == 0)
    {
        return Err(PinnedHttpError::configuration(format!(
            "HTTP recipient {recipient} must be a concrete unicast socket with nonzero port"
        )));
    }
    Ok(())
}

pub(crate) fn validate_host(host: &str) -> Result<(), PinnedHttpError> {
    fn invalid() -> PinnedHttpError {
        PinnedHttpError::configuration(
            "HTTP Host must be a canonical lowercase ASCII hostname, IPv4, or bracketed IPv6, optionally followed by a canonical nonzero numeric port",
        )
    }

    fn validate_port(raw: &str) -> Result<(), PinnedHttpError> {
        let port = raw.parse::<u16>().map_err(|_| invalid())?;
        if port == 0 || port.to_string() != raw {
            return Err(invalid());
        }
        Ok(())
    }

    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err(invalid());
    }
    if let Some(bracketed) = host.strip_prefix('[') {
        let Some((literal, suffix)) = bracketed.split_once(']') else {
            return Err(invalid());
        };
        if literal.is_empty() || suffix.contains(']') {
            return Err(invalid());
        }
        let address = literal.parse::<Ipv6Addr>().map_err(|_| invalid())?;
        if address.to_string() != literal {
            return Err(invalid());
        }
        match suffix.strip_prefix(':') {
            Some(port) => validate_port(port)?,
            None if suffix.is_empty() => {}
            None => return Err(invalid()),
        }
        return Ok(());
    }
    if host.contains(['[', ']']) || host.matches(':').count() > 1 {
        return Err(invalid());
    }
    let (name, port) = match host.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    if let Some(port) = port {
        validate_port(port)?;
    }
    if name
        .parse::<Ipv4Addr>()
        .is_ok_and(|ip| ip.to_string() == name)
    {
        return Ok(());
    }
    if name.is_empty()
        || name.starts_with('.')
        || name.ends_with('.')
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_signer_path(signer: &str) -> Result<(), PinnedHttpError> {
    let key = iroh::PublicKey::from_z32(signer).map_err(|error| {
        PinnedHttpError::new(format!(
            "record path signer is not a z-base-32 public key: {error}"
        ))
    })?;
    if key.to_z32() != signer {
        return Err(PinnedHttpError::new(
            "record path signer is not canonical z-base-32",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PinnedHttpResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
    pub(crate) elapsed: Duration,
}

struct ParsedResponseHeaders {
    status: u16,
    content_length: usize,
}

fn parse_response_headers(raw: &str) -> Result<ParsedResponseHeaders, PinnedHttpError> {
    let mut lines = raw.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| PinnedHttpError::new("response status line is missing"))?;
    let mut status_parts = status_line.split_ascii_whitespace();
    if status_parts.next() != Some("HTTP/1.1") {
        return Err(PinnedHttpError::new("response is not canonical HTTP/1.1"));
    }
    let status: u16 = status_parts
        .next()
        .ok_or_else(|| PinnedHttpError::new("response status is missing"))?
        .parse()
        .map_err(|error| PinnedHttpError::new(format!("invalid response status: {error}")))?;
    if !(200..=599).contains(&status) {
        return Err(PinnedHttpError::new(format!(
            "unsupported HTTP response status {status}"
        )));
    }
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(PinnedHttpError::new("malformed response header"));
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(PinnedHttpError::new(
                "Transfer-Encoding is rejected; exact bounded Content-Length is required",
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(PinnedHttpError::new("duplicate Content-Length"));
            }
            content_length = Some(value.trim().parse().map_err(|error| {
                PinnedHttpError::new(format!("invalid Content-Length: {error}"))
            })?);
        }
    }
    Ok(ParsedResponseHeaders {
        status,
        content_length: match (status, content_length) {
            (204, None) => 0,
            (_, Some(length)) => length,
            _ => {
                return Err(PinnedHttpError::new("response Content-Length is missing"));
            }
        },
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinnedHttpErrorKind {
    Configuration,
    ConnectionRefused,
    Connect,
    Write,
    Read,
    Protocol,
    Deadline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PinnedHttpError {
    kind: PinnedHttpErrorKind,
    message: String,
}

impl PinnedHttpError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self::with_kind(PinnedHttpErrorKind::Protocol, message)
    }

    pub(crate) fn with_kind(kind: PinnedHttpErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn configuration(message: impl Into<String>) -> Self {
        Self::with_kind(PinnedHttpErrorKind::Configuration, message)
    }

    pub(crate) fn write(message: impl Into<String>) -> Self {
        Self::with_kind(PinnedHttpErrorKind::Write, message)
    }

    pub(crate) fn read(message: impl Into<String>) -> Self {
        Self::with_kind(PinnedHttpErrorKind::Read, message)
    }

    pub(crate) fn deadline(message: impl Into<String>) -> Self {
        Self::with_kind(PinnedHttpErrorKind::Deadline, message)
    }

    pub(crate) fn kind(&self) -> PinnedHttpErrorKind {
        self.kind
    }
}

impl fmt::Display for PinnedHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PinnedHttpError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iroh_publication_authority::{AuthoritySignerAdmission, PublicationAuthorityConfig};
    use tokio::net::TcpListener;

    async fn serve_once(
        response: Vec<u8>,
        delay: Duration,
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let header_end = loop {
                if let Some(position) = find_header_end(&request) {
                    break position;
                }
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                if read == 0 {
                    return request;
                }
                request.extend_from_slice(&chunk[..read]);
            };
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            let content_length = headers
                .split("\r\n")
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            let expected = header_end + 4 + content_length;
            while request.len() < expected {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
            request
        });
        (address, task)
    }

    #[test]
    fn endpoint_rejects_widening_inputs() {
        assert!(PinnedHttpEndpoint::new("0.0.0.0:80".parse().unwrap(), "authority.test").is_err());
        assert!(PinnedHttpEndpoint::new("127.0.0.1:0".parse().unwrap(), "authority.test").is_err());
        assert!(
            PinnedHttpEndpoint::new("127.0.0.1:80".parse().unwrap(), "authority.test/path")
                .is_err()
        );
        assert!(PinnedHttpEndpoint::new("127.0.0.1:80".parse().unwrap(), "a..test").is_err());
        for host in [
            ":",
            "[]",
            "authority.test:abc",
            "authority.test:0",
            "authority.test:080",
            "2001:db8::1",
            "[2001:db8::1",
            "2001:db8::1]",
            "[2001:0db8::1]",
            "Authority.test",
            "-authority.test",
            "authority-.test",
        ] {
            assert!(
                PinnedHttpEndpoint::new("127.0.0.1:80".parse().unwrap(), host).is_err(),
                "malformed/noncanonical Host {host:?} was accepted"
            );
        }
        for host in [
            "authority.test",
            "authority.test:8443",
            "127.0.0.1",
            "127.0.0.1:8443",
            "[2001:db8::1]",
            "[2001:db8::1]:8443",
        ] {
            PinnedHttpEndpoint::new("127.0.0.1:80".parse().unwrap(), host).unwrap();
        }
        assert!(
            PinnedHttpEndpoint::new("[::ffff:0.0.0.0]:80".parse().unwrap(), "authority.test")
                .is_err()
        );
        assert_eq!(
            PinnedHttpEndpoint::new("[::ffff:192.0.2.1]:80".parse().unwrap(), "authority.test")
                .unwrap()
                .recipient(),
            "192.0.2.1:80".parse().unwrap()
        );
    }

    #[test]
    fn authority_and_pinned_client_share_the_exact_host_grammar() {
        let config_for = |host: &str| PublicationAuthorityConfig {
            listen: "127.0.0.1:18080".parse().unwrap(),
            state_dir: std::path::PathBuf::from("unused-host-validation-state"),
            namespace: "run-host-validation".into(),
            signed_recipient: "authority.test:v1".into(),
            expected_host: host.into(),
            owner: "test operator".into(),
            signer_admission: AuthoritySignerAdmission::TestOnlyUnrestricted,
        };
        for host in [
            "authority.test",
            "authority.test:8443",
            "127.0.0.1:8443",
            "[2001:db8::1]:8443",
        ] {
            config_for(host).validate().unwrap();
            PinnedHttpEndpoint::new("127.0.0.1:18080".parse().unwrap(), host).unwrap();
        }
        for host in [
            ":",
            "[]",
            "authority.test:not-a-port",
            "authority.test:0",
            "authority.test:080",
            "2001:db8::1",
            "[2001:db8::1",
            "Authority.test",
        ] {
            assert!(
                config_for(host).validate().is_err(),
                "authority accepted {host:?}"
            );
            assert_eq!(
                PinnedHttpEndpoint::new("127.0.0.1:18080".parse().unwrap(), host)
                    .unwrap_err()
                    .kind(),
                PinnedHttpErrorKind::Configuration
            );
        }
    }

    #[test]
    fn response_parser_requires_one_bounded_length() {
        assert!(parse_response_headers("HTTP/1.1 200 OK\r\nContent-Length: 3").is_ok());
        assert!(parse_response_headers("HTTP/1.1 200 OK").is_err());
        assert!(parse_response_headers("HTTP/1.1 204 No Content").is_ok());
        assert!(
            parse_response_headers(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3"
            )
            .is_err()
        );
        assert!(
            parse_response_headers("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3")
                .is_err()
        );
    }

    #[tokio::test]
    async fn request_is_pinned_to_exact_socket_host_and_signer_path() {
        let key = iroh::SecretKey::generate();
        let signer = key.public().to_z32();
        let response =
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
        let (address, server) = serve_once(response, Duration::ZERO).await;
        let endpoint = PinnedHttpEndpoint::new(address, "authority.test:8443").unwrap();
        let result = endpoint
            .get_record(&signer, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(result.status, 404);
        let request = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(request.starts_with(&format!("GET /pkarr/{signer} HTTP/1.1\r\n")));
        assert!(request.contains("\r\nHost: authority.test:8443\r\n"));
        assert!(!request.to_ascii_lowercase().contains("proxy"));

        let production = include_str!("pinned_http.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for ambient in ["std::env", "reqwest", "hyper", "Location:"] {
            assert!(
                !production.contains(ambient),
                "pinned transport gained ambient/widening dependency {ambient}"
            );
        }
    }

    #[tokio::test]
    async fn redirect_oversize_and_malformed_framing_are_rejected_on_wire() {
        let signer = iroh::SecretKey::generate().public().to_z32();
        let cases = [
            (
                "redirect",
                b"HTTP/1.1 302 Found\r\nLocation: http://elsewhere.test/\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ),
            (
                "oversize-body",
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    MAX_RELAY_PAYLOAD_BYTES + 1
                )
                .into_bytes(),
            ),
            (
                "transfer-encoding",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ),
            (
                "duplicate-length",
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ),
            (
                "truncated-body",
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".to_vec(),
            ),
            (
                "extra-body",
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabcd".to_vec(),
            ),
        ];
        for (label, response) in cases {
            let (address, server) = serve_once(response, Duration::ZERO).await;
            let endpoint = PinnedHttpEndpoint::new(address, "authority.test").unwrap();
            assert!(
                endpoint
                    .get_record(&signer, Duration::from_secs(1))
                    .await
                    .is_err(),
                "wire case {label} was accepted"
            );
            server.await.unwrap();
        }

        let mut overlong = b"HTTP/1.1 200 OK\r\nX-Fill: ".to_vec();
        overlong.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES));
        overlong.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let (address, server) = serve_once(overlong, Duration::ZERO).await;
        let endpoint = PinnedHttpEndpoint::new(address, "authority.test").unwrap();
        assert!(
            endpoint
                .get_record(&signer, Duration::from_secs(1))
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn one_total_deadline_bounds_connect_request_and_response() {
        let signer = iroh::SecretKey::generate().public().to_z32();
        let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (address, server) = serve_once(response, Duration::from_millis(150)).await;
        let endpoint = PinnedHttpEndpoint::new(address, "authority.test").unwrap();
        let started = Instant::now();
        let error = endpoint
            .get_record(&signer, Duration::from_millis(25))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeded"));
        assert!(started.elapsed() < Duration::from_millis(100));
        server.await.unwrap();
    }
}
