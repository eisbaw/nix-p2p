//! Feature-gated adversarial pkarr GET fixture for routed Task138 evidence.
//!
//! The real Task137 authority is used for the positive arm. This fixture exists
//! only for records that authority correctly refuses to store (bad signature,
//! stale/conflicting replay, expiry, live-without-locations) and for a bounded
//! hanging response.

use std::env;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use daemon::{
    NODE_PUBLICATION_SCHEMA, NodeId, NodeLocation, PublicationState, encode_node_record,
    validate_namespace, validate_recipient,
};
use iroh::SecretKey;
use iroh_dns::pkarr::{SignedPacket, Timestamp};
use serde_json::json;
use simple_dns::{CLASS, Name, Packet, ResourceRecord, rdata::RData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const FIXTURE_LIFETIME: Duration = Duration::from_secs(20);
const IO_DEADLINE: Duration = Duration::from_secs(2);
const HANG_DURATION: Duration = Duration::from_secs(12);
const SURPLUS_OBSERVATION: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Hanging,
    BadSignature,
    Stale,
    EqualConflict,
    Expired,
    LiveEmpty,
}

impl Scenario {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "hanging" => Ok(Self::Hanging),
            "bad-signature" => Ok(Self::BadSignature),
            "stale" => Ok(Self::Stale),
            "equal-conflict" => Ok(Self::EqualConflict),
            "expired" => Ok(Self::Expired),
            "live-empty" => Ok(Self::LiveEmpty),
            _ => Err(format!("unsupported --scenario {raw:?}")),
        }
    }

    fn request_count(self) -> usize {
        match self {
            Self::Stale | Self::EqualConflict => 2,
            _ => 1,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Hanging => "hanging",
            Self::BadSignature => "bad-signature",
            Self::Stale => "stale",
            Self::EqualConflict => "equal-conflict",
            Self::Expired => "expired",
            Self::LiveEmpty => "live-empty",
        }
    }
}

#[derive(Debug)]
struct Config {
    listen: SocketAddr,
    namespace: String,
    recipient: String,
    expected_host: String,
    scenario: Scenario,
    run_id: String,
    owner: String,
    image_revision: String,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut listen = None;
        let mut namespace = None;
        let mut recipient = None;
        let mut expected_host = None;
        let mut scenario = None;
        let mut run_id = None;
        let mut owner = None;
        let mut image_revision = None;
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| format!("missing value after {flag:?}"))?;
            match flag.as_str() {
                "--listen" => set_once(
                    &mut listen,
                    value
                        .parse()
                        .map_err(|error| format!("invalid --listen: {error}"))?,
                    &flag,
                )?,
                "--namespace" => set_once(&mut namespace, value, &flag)?,
                "--recipient" => set_once(&mut recipient, value, &flag)?,
                "--expected-host" => set_once(&mut expected_host, value, &flag)?,
                "--scenario" => set_once(&mut scenario, Scenario::parse(&value)?, &flag)?,
                "--run-id" => set_once(&mut run_id, value, &flag)?,
                "--owner" => set_once(&mut owner, value, &flag)?,
                "--image-revision" => set_once(&mut image_revision, value, &flag)?,
                _ => return Err(format!("unknown argument {flag:?}")),
            }
        }
        let config = Self {
            listen: required(listen, "--listen")?,
            namespace: required(namespace, "--namespace")?,
            recipient: required(recipient, "--recipient")?,
            expected_host: required(expected_host, "--expected-host")?,
            scenario: required(scenario, "--scenario")?,
            run_id: required(run_id, "--run-id")?,
            owner: required(owner, "--owner")?,
            image_revision: required(image_revision, "--image-revision")?,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        validate_fixture_socket(self.listen)?;
        validate_namespace(&self.namespace).map_err(|error| error.to_string())?;
        validate_recipient(&self.recipient).map_err(|error| error.to_string())?;
        validate_host(&self.expected_host)?;
        if !canonical_run_id(&self.run_id)
            || !self.namespace.ends_with(&format!("-{}", self.run_id))
        {
            return Err(
                "--run-id must be a canonical production-shaped identity bound into --namespace"
                    .into(),
            );
        }
        if self.owner.trim() != self.owner
            || self.owner.is_empty()
            || self.owner.len() > 128
            || self.owner.chars().any(char::is_control)
        {
            return Err("--owner must be 1..=128 trimmed non-control characters".into());
        }
        if !matches!(self.image_revision.len(), 40 | 64)
            || !self
                .image_revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(
                "--image-revision must be a clean 40- or 64-digit lowercase hex revision".into(),
            );
        }
        Ok(())
    }
}

fn canonical_run_id(value: &str) -> bool {
    (8..=48).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_fixture_socket(socket: SocketAddr) -> Result<(), String> {
    let local = match socket.ip() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unicast_link_local() || (ip.segments()[0] & 0xfe00 == 0xfc00)
        }
    };
    let unscoped_link_local = matches!(
        socket,
        SocketAddr::V6(address)
            if address.ip().is_unicast_link_local() && address.scope_id() == 0
    );
    if socket.port() == 0
        || socket.ip().is_unspecified()
        || socket.ip().is_multicast()
        || !local
        || unscoped_link_local
    {
        return Err(
            "--listen must be a concrete private/local unicast socket with nonzero port".into(),
        );
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<(), String> {
    fn port(raw: &str) -> bool {
        raw.parse::<u16>()
            .is_ok_and(|parsed| parsed != 0 && parsed.to_string() == raw)
    }
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err("--expected-host is not canonical".into());
    }
    if let Some(rest) = host.strip_prefix('[') {
        let Some((literal, suffix)) = rest.split_once(']') else {
            return Err("--expected-host has unbalanced IPv6 brackets".into());
        };
        let parsed = literal
            .parse::<Ipv6Addr>()
            .map_err(|_| "--expected-host has invalid IPv6")?;
        if parsed.to_string() != literal
            || !(suffix.is_empty() || suffix.strip_prefix(':').is_some_and(port))
        {
            return Err("--expected-host has a noncanonical IPv6 host or port".into());
        }
        return Ok(());
    }
    if host.contains(['[', ']']) || host.matches(':').count() > 1 {
        return Err("--expected-host has raw/bracket-malformed IPv6".into());
    }
    let (name, suffix) = host
        .split_once(':')
        .map_or((host, None), |(name, raw)| (name, Some(raw)));
    if suffix.is_some_and(|raw| !port(raw)) {
        return Err("--expected-host has a noncanonical port".into());
    }
    if name
        .parse::<Ipv4Addr>()
        .is_ok_and(|ip| ip.to_string() == name)
    {
        return Ok(());
    }
    if name.is_empty()
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
        return Err("--expected-host has a noncanonical DNS hostname".into());
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate {flag}"));
    }
    Ok(())
}

fn required<T>(slot: Option<T>, flag: &str) -> Result<T, String> {
    slot.ok_or_else(|| format!("required argument {flag} is missing"))
}

fn now_micros() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("wall clock before Unix epoch: {error}"))?
        .as_micros()
        .try_into()
        .map_err(|_| "wall clock exceeds u64 microseconds".to_string())
}

#[derive(Debug)]
struct PlannedResponse {
    status: Option<u16>,
    body: Option<Vec<u8>>,
    sequence: Option<u64>,
    ttl_seconds: Option<u32>,
    expires_unix_micros: Option<u64>,
    state: Option<&'static str>,
    locations: Vec<String>,
}

fn payload(
    key: &SecretKey,
    config: &Config,
    sequence: u64,
    ttl: u32,
    state: PublicationState,
    location: Option<&str>,
) -> Result<Vec<u8>, String> {
    let locations = location
        .map(|address| {
            address
                .parse()
                .map_err(|error| format!("fixture socket parse: {error}"))
                .and_then(|address| {
                    NodeLocation::direct(address).map_err(|error| error.to_string())
                })
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    encode_node_record(
        key,
        &config.namespace,
        &config.recipient,
        ttl,
        sequence,
        sequence + u64::from(ttl) * 1_000_000,
        state,
        &locations,
    )
    .map(|packet| packet.to_relay_payload())
    .map_err(|error| error.to_string())
}

fn add_txt(
    packet: &mut Packet<'_>,
    relative: &str,
    origin: &str,
    ttl: u32,
    value: &str,
) -> Result<(), String> {
    let name = Name::new(&format!("{relative}.{origin}"))
        .map_err(|error| format!("building fixture DNS name: {error}"))?
        .into_owned();
    let mut txt = simple_dns::rdata::TXT::new();
    txt.add_string(value)
        .map_err(|error| format!("building fixture DNS TXT: {error}"))?;
    packet.answers.push(ResourceRecord::new(
        name,
        CLASS::IN,
        ttl,
        RData::TXT(txt.into_owned()),
    ));
    Ok(())
}

fn live_empty_payload(
    key: &SecretKey,
    config: &Config,
    sequence: u64,
    ttl: u32,
) -> Result<Vec<u8>, String> {
    let signer = key.public().to_z32();
    let expiry = sequence + u64::from(ttl) * 1_000_000;
    let metadata = [
        format!("schema={NODE_PUBLICATION_SCHEMA}"),
        format!("namespace={}", config.namespace),
        format!("signer={signer}"),
        format!("node-id={}", NodeId::from_bytes(*key.public().as_bytes())),
        format!("recipient={}", config.recipient),
        format!("ttl-seconds={ttl}"),
        format!("sequence={sequence}"),
        format!("expires-unix-micros={expiry}"),
        "state=live".to_string(),
    ];
    let mut dns = Packet::new_reply(0);
    for value in metadata {
        add_txt(&mut dns, "_nix-p2p-iroh", &signer, ttl, &value)?;
    }
    let encoded = dns
        .build_bytes_vec_compressed()
        .map_err(|error| format!("encoding live-empty DNS: {error}"))?;
    let mut signable = format!("3:seqi{sequence}e1:v{}:", encoded.len()).into_bytes();
    signable.extend_from_slice(&encoded);
    let signature = key.sign(&signable);
    let mut signed = Vec::with_capacity(104 + encoded.len());
    signed.extend_from_slice(key.public().as_bytes());
    signed.extend_from_slice(&signature.to_bytes());
    signed.extend_from_slice(&Timestamp::from_micros(sequence).to_be_bytes());
    signed.extend_from_slice(&encoded);
    SignedPacket::from_bytes(&signed)
        .map(|packet| packet.to_relay_payload())
        .map_err(|error| format!("verifying live-empty signed packet: {error}"))
}

fn planned(
    body: Vec<u8>,
    sequence: u64,
    ttl_seconds: u32,
    state: &'static str,
    locations: &[&str],
) -> PlannedResponse {
    PlannedResponse {
        status: Some(200),
        body: Some(body),
        sequence: Some(sequence),
        ttl_seconds: Some(ttl_seconds),
        expires_unix_micros: Some(sequence + u64::from(ttl_seconds) * 1_000_000),
        state: Some(state),
        locations: locations.iter().map(|value| (*value).to_string()).collect(),
    }
}

fn responses(config: &Config, key: &SecretKey) -> Result<Vec<PlannedResponse>, String> {
    let now = now_micros()?;
    let recent = now.saturating_sub(100_000);
    let result = match config.scenario {
        Scenario::Hanging => vec![PlannedResponse {
            status: None,
            body: None,
            sequence: None,
            ttl_seconds: None,
            expires_unix_micros: None,
            state: None,
            locations: Vec::new(),
        }],
        Scenario::BadSignature => {
            let address = "192.0.2.20:4433";
            let mut body = payload(
                key,
                config,
                recent,
                30,
                PublicationState::Live,
                Some(address),
            )?;
            body[0] ^= 0x80;
            vec![planned(body, recent, 30, "live", &[address])]
        }
        Scenario::Stale => vec![
            planned(
                payload(
                    key,
                    config,
                    recent,
                    30,
                    PublicationState::Live,
                    Some("192.0.2.21:4433"),
                )?,
                recent,
                30,
                "live",
                &["192.0.2.21:4433"],
            ),
            planned(
                payload(
                    key,
                    config,
                    recent.saturating_sub(1),
                    30,
                    PublicationState::Live,
                    Some("192.0.2.21:4433"),
                )?,
                recent.saturating_sub(1),
                30,
                "live",
                &["192.0.2.21:4433"],
            ),
        ],
        Scenario::EqualConflict => vec![
            planned(
                payload(
                    key,
                    config,
                    recent,
                    30,
                    PublicationState::Live,
                    Some("192.0.2.22:4433"),
                )?,
                recent,
                30,
                "live",
                &["192.0.2.22:4433"],
            ),
            planned(
                payload(
                    key,
                    config,
                    recent,
                    30,
                    PublicationState::Live,
                    Some("192.0.2.23:4433"),
                )?,
                recent,
                30,
                "live",
                &["192.0.2.23:4433"],
            ),
        ],
        Scenario::Expired => {
            let sequence = now.saturating_sub(2_000_000);
            vec![planned(
                payload(
                    key,
                    config,
                    sequence,
                    1,
                    PublicationState::Live,
                    Some("192.0.2.24:4433"),
                )?,
                sequence,
                1,
                "live",
                &["192.0.2.24:4433"],
            )]
        }
        Scenario::LiveEmpty => vec![planned(
            live_empty_payload(key, config, recent, 30)?,
            recent,
            30,
            "live",
            &[],
        )],
    };
    Ok(result)
}

fn plan_json(config: &Config, key: &SecretKey, responses: &[PlannedResponse]) -> serde_json::Value {
    let entries = responses
        .iter()
        .enumerate()
        .map(|(index, response)| {
            let payload = response.body.as_deref();
            json!({
                "ordinal": index + 1,
                "status": response.status,
                "hang": response.status.is_none(),
                "relay_payload_bytes": payload.map(<[u8]>::len),
                "relay_payload_blake3_hex": payload.map(|body| blake3::hash(body).to_hex().to_string()),
                "relay_payload_hex": payload.map(hex_bytes),
                "sequence": response.sequence,
                "ttl_seconds": response.ttl_seconds,
                "expires_unix_micros": response.expires_unix_micros,
                "state": response.state,
                "locations": response.locations,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema": "iroh-node-lookup-fixture-plan-v1",
        "run_id": config.run_id,
        "owner": config.owner,
        "image_revision": config.image_revision,
        "namespace": config.namespace,
        "recipient": config.recipient,
        "expected_host": config.expected_host,
        "scenario": config.scenario.as_str(),
        "node_id": NodeId::from_bytes(*key.public().as_bytes()),
        "signer": key.public().to_z32(),
        "responses": entries,
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0xf) as usize] as char);
    }
    result
}

async fn read_request(
    stream: &mut TcpStream,
    deadline: tokio::time::Instant,
) -> Result<String, String> {
    let mut request = Vec::new();
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        if request.len() >= 8192 {
            return Err("request headers exceed 8192 bytes".into());
        }
        let mut chunk = [0u8; 1024];
        let read = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| "reading request exceeded its absolute deadline".to_string())?
            .map_err(|error| format!("reading request: {error}"))?;
        if read == 0 {
            return Err("request ended before complete headers".into());
        }
        request.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(request).map_err(|error| format!("request is not UTF-8: {error}"))
}

async fn observe_hanging_cancellation(
    stream: &mut TcpStream,
    lifetime_deadline: tokio::time::Instant,
) -> Result<u128, String> {
    let started = tokio::time::Instant::now();
    let expected_cancel_deadline = std::cmp::min(lifetime_deadline, started + HANG_DURATION);
    let mut byte = [0u8; 1];
    match tokio::time::timeout_at(expected_cancel_deadline, stream.read(&mut byte)).await {
        Ok(Ok(0)) => Ok(started.elapsed().as_millis()),
        Ok(Ok(_)) => Err("hanging client sent surplus bytes after its canonical GET".into()),
        Ok(Err(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(started.elapsed().as_millis())
        }
        Ok(Err(error)) => Err(format!("observing hanging client cancellation: {error}")),
        Err(_) => {
            Err("hanging client did not close its connection after the 10s lookup deadline".into())
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let started = tokio::time::Instant::now();
    let lifetime_deadline = started + FIXTURE_LIFETIME;
    let config = match Config::parse() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("iroh_node_lookup_fixture_error stage=config error={error:?}");
            return ExitCode::from(2);
        }
    };
    let key = SecretKey::generate();
    let node_id = NodeId::from_bytes(*key.public().as_bytes());
    let responses = match responses(&config, &key) {
        Ok(responses) => responses,
        Err(error) => {
            eprintln!("iroh_node_lookup_fixture_error stage=record error={error:?}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match TcpListener::bind(config.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("iroh_node_lookup_fixture_error stage=bind error={error:?}");
            return ExitCode::FAILURE;
        }
    };
    println!("{}", plan_json(&config, &key, &responses));
    println!(
        "iroh_node_lookup_fixture_ready scenario={} listen={} node_id={} signer={} requests={}",
        config.scenario.as_str(),
        listener.local_addr().unwrap(),
        node_id,
        key.public().to_z32(),
        config.scenario.request_count(),
    );
    let _ = std::io::stdout().flush();
    let mut observed_requests = 0usize;
    for (index, response) in responses.into_iter().enumerate() {
        let (mut stream, _) =
            match tokio::time::timeout_at(lifetime_deadline, listener.accept()).await {
                Ok(Ok(connection)) => connection,
                Ok(Err(error)) => {
                    eprintln!("iroh_node_lookup_fixture_error stage=accept error={error:?}");
                    return ExitCode::FAILURE;
                }
                Err(_) => {
                    eprintln!(
                        "iroh_node_lookup_fixture_error stage=accept error={:?}",
                        "fixture absolute lifetime expired while waiting for expected request"
                    );
                    return ExitCode::FAILURE;
                }
            };
        let io_deadline =
            std::cmp::min(lifetime_deadline, tokio::time::Instant::now() + IO_DEADLINE);
        let request = match read_request(&mut stream, io_deadline).await {
            Ok(request) => request,
            Err(error) => {
                eprintln!("iroh_node_lookup_fixture_error stage=request error={error:?}");
                return ExitCode::FAILURE;
            }
        };
        let expected = format!(
            "GET /pkarr/{} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-pkarr-signed-packet\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            key.public().to_z32(),
            config.expected_host,
        );
        if request != expected {
            eprintln!(
                "iroh_node_lookup_fixture_error stage=request error={:?}",
                "request was not the exact canonical zero-body signer GET"
            );
            return ExitCode::FAILURE;
        }
        observed_requests += 1;
        println!(
            "iroh_node_lookup_fixture_request scenario={} attempt={}",
            config.scenario.as_str(),
            index + 1,
        );
        let _ = std::io::stdout().flush();
        if response.status.is_none() {
            let cancelled_ms =
                match observe_hanging_cancellation(&mut stream, lifetime_deadline).await {
                    Ok(elapsed) => elapsed,
                    Err(error) => {
                        eprintln!("iroh_node_lookup_fixture_error stage=hang error={error:?}");
                        return ExitCode::FAILURE;
                    }
                };
            println!(
                "iroh_node_lookup_fixture_cancelled scenario={} attempt={} observed_after_ms={cancelled_ms}",
                config.scenario.as_str(),
                index + 1,
            );
            let _ = std::io::stdout().flush();
            continue;
        }
        let status = response.status.expect("non-hanging status");
        let body = response.body.expect("non-hanging response body");
        let reason = if status == 200 { "OK" } else { "Not Found" };
        let headers = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let write = async {
            stream.write_all(headers.as_bytes()).await?;
            stream.write_all(&body).await?;
            stream.shutdown().await
        };
        if !matches!(
            tokio::time::timeout_at(io_deadline, write).await,
            Ok(Ok(()))
        ) {
            eprintln!(
                "iroh_node_lookup_fixture_error stage=response attempt={} error={:?}",
                index + 1,
                "writing response failed"
            );
            return ExitCode::FAILURE;
        }
    }
    match tokio::time::timeout(SURPLUS_OBSERVATION, listener.accept()).await {
        Err(_) => {}
        Ok(Ok((_stream, peer))) => {
            eprintln!(
                "iroh_node_lookup_fixture_error stage=surplus peer={peer} observed_requests={observed_requests} expected_requests={}",
                config.scenario.request_count()
            );
            return ExitCode::FAILURE;
        }
        Ok(Err(error)) => {
            eprintln!("iroh_node_lookup_fixture_error stage=surplus error={error:?}");
            return ExitCode::FAILURE;
        }
    }
    println!(
        "iroh_node_lookup_fixture_complete scenario={} observed_requests={} expected_requests={} surplus_observation_ms={}",
        config.scenario.as_str(),
        observed_requests,
        config.scenario.request_count(),
        SURPLUS_OBSERVATION.as_millis(),
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(scenario: Scenario) -> Config {
        Config {
            listen: "127.0.0.1:18080".parse().unwrap(),
            namespace: "task138-evidence-r1234567".into(),
            recipient: "task138-authority:v1".into(),
            expected_host: "task138-authority.invalid".into(),
            scenario,
            run_id: "r1234567".into(),
            owner: "task138-test".into(),
            image_revision: "1".repeat(40),
        }
    }

    #[test]
    fn live_empty_is_validly_signed_but_typed_as_no_dialable_candidate() {
        let config = config(Scenario::LiveEmpty);
        config.validate().unwrap();
        let key = SecretKey::generate();
        let response = responses(&config, &key).unwrap().pop().unwrap();
        let packet =
            SignedPacket::from_relay_payload(&key.public(), response.body.as_deref().unwrap())
                .unwrap();
        let error = daemon::decode_node_record(packet.as_bytes()).unwrap_err();
        assert_eq!(
            error.kind(),
            daemon::NodeRecordErrorKind::NoDialableCandidate
        );
    }

    #[test]
    fn fixture_configuration_is_private_canonical_and_run_bound() {
        let mut valid = config(Scenario::Hanging);
        valid.validate().unwrap();
        valid.listen = "192.0.2.1:18080".parse().unwrap();
        assert!(valid.validate().is_err());
        valid = config(Scenario::Hanging);
        valid.listen = "[fe80::1]:18080".parse().unwrap();
        assert!(valid.validate().is_err());
        valid = config(Scenario::Hanging);
        valid.namespace = "unbound-namespace".into();
        assert!(valid.validate().is_err());
        valid = config(Scenario::Hanging);
        valid.expected_host = ":".into();
        assert!(valid.validate().is_err());
        valid = config(Scenario::Hanging);
        valid.image_revision.push_str("-dirty");
        assert!(valid.validate().is_err());
    }
}
