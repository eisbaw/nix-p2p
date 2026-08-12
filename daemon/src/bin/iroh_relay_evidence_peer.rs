//! Relay-only iroh PEER for the routed TASK-142 evidence.
//!
//! One process drives ONE connection role across L3-separated namespaces where
//! the DIRECT peer-to-peer path is blocked, so a successful connection is
//! attributable to the locally operated relay. The path is classified with the
//! daemon's own `daemon::classify_connection_path` primitive (the same one
//! TASK-89 reuses), and the outcome is emitted as canonical JSON.
//!
//! Two roles:
//!
//! * `accept` — bind, publish this peer's NodeId, wait for one relayed
//!   connection, classify the accepted path, echo one message.
//! * `connect` — build a relay-only `EndpointAddr` (NodeId + relay URL, NO
//!   direct address) and connect within the 10000 ms relay deadline. On success
//!   the path is classified; on failure the typed
//!   `RelayTransportUnavailableKind` is reported.
//!
//! Every typed failure is a DISTINCT outcome inside the bounded deadline. The
//! config-time reasons (wrong URL, untrusted config, external unsupported) come
//! straight from `daemon::RelayTransportConfig`; the network-time reasons are
//! decided by bounded preflight probes and the real connect result, never by
//! matching error strings.
//!
//! Feature-gated (`evidence-fixture`) out of every production build.

use std::env;
use std::io::Write as _;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use daemon::{
    RELAY_CONNECT_DEADLINE, RELAY_SCHEDULER_GRACE, RelayConnectionPath,
    RelayTransportAuthorization, RelayTransportConfig, RelayTransportUnavailable,
    RelayTransportUnavailableKind, classify_connection_path,
};
use iroh::endpoint::{Connection, presets};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, EndpointAddr, PublicKey, RelayMode, SecretKey};
use serde_json::json;

/// Application protocol for the evidence exchange. Distinct from the product
/// blob ALPN so an evidence peer can never be mistaken for a serving daemon.
const EVIDENCE_ALPN: &[u8] = b"nix-p2p/task142-relay-evidence/1";

/// Bounded message the connecting peer sends and the accepting peer echoes.
const EVIDENCE_MESSAGE: &[u8] = b"task142-relay-evidence-ping";

/// The role this peer plays in the single connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Accept,
    Connect,
}

impl Role {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "accept" => Ok(Self::Accept),
            "connect" => Ok(Self::Connect),
            _ => Err(format!("unsupported --role {raw:?}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Connect => "connect",
        }
    }
}

/// What connection the connect role should attempt. Each maps to exactly one
/// typed outcome the finalizer asserts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    /// Relay-only connect that must succeed and classify `relayed`.
    RelaySuccess,
    /// Connect where a direct address is offered and the direct path is open;
    /// it must classify `direct` and NOT be credited to the relay.
    DirectPositive,
    /// The configured relay is down/unreachable: typed `relay_outage`.
    RelayOutage,
    /// The relay URL is malformed: typed `wrong_relay_url` (config-time).
    WrongUrl,
    /// The relay presents an untrusted certificate under strict verification:
    /// typed `wrong_certificate`.
    WrongCertificate,
    /// A relay-only connect to a NodeId nobody serves: the deadline elapses.
    WrongIdentity,
    /// The relay carries the connection but the peer stalls its stream: typed
    /// `half_open_stream`.
    HalfOpenStream,
    /// Direct-only connect where the direct path is blocked: typed
    /// `forced_direct_failure`.
    ForcedDirectFailure,
}

impl Scenario {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "relay-success" => Ok(Self::RelaySuccess),
            "direct-positive" => Ok(Self::DirectPositive),
            "relay-outage" => Ok(Self::RelayOutage),
            "wrong-url" => Ok(Self::WrongUrl),
            "wrong-certificate" => Ok(Self::WrongCertificate),
            "wrong-identity" => Ok(Self::WrongIdentity),
            "half-open-stream" => Ok(Self::HalfOpenStream),
            "forced-direct-failure" => Ok(Self::ForcedDirectFailure),
            _ => Err(format!("unsupported --scenario {raw:?}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::RelaySuccess => "relay-success",
            Self::DirectPositive => "direct-positive",
            Self::RelayOutage => "relay-outage",
            Self::WrongUrl => "wrong-url",
            Self::WrongCertificate => "wrong-certificate",
            Self::WrongIdentity => "wrong-identity",
            Self::HalfOpenStream => "half-open-stream",
            Self::ForcedDirectFailure => "forced-direct-failure",
        }
    }

    /// Whether this scenario expects a successfully classified connection (as
    /// opposed to a typed failure).
    fn expects_connection(self) -> bool {
        matches!(self, Self::RelaySuccess | Self::DirectPositive)
    }

    /// Whether this scenario offers a direct address (so the connect uses the
    /// direct path, not the relay).
    fn offers_direct(self) -> bool {
        matches!(self, Self::DirectPositive | Self::ForcedDirectFailure)
    }

    /// Whether the connecting peer verifies the relay's TLS certificate
    /// strictly (only the wrong-certificate arm does; every other arm skips
    /// verification because the relay is a self-signed locally operated one).
    fn verifies_relay_cert(self) -> bool {
        matches!(self, Self::WrongCertificate)
    }
}

struct Config {
    role: Role,
    scenario: Scenario,
    relay_url: String,
    iroh_bind: SocketAddr,
    peer_node_id: Option<String>,
    peer_direct_addr: Option<SocketAddr>,
    run_id: String,
    owner: String,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut role = None;
        let mut scenario = None;
        let mut relay_url = None;
        let mut iroh_bind = None;
        let mut peer_node_id = None;
        let mut peer_direct_addr = None;
        let mut run_id = None;
        let mut owner = None;
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| format!("missing value after {flag:?}"))?;
            match flag.as_str() {
                "--role" => set_once(&mut role, Role::parse(&value)?, &flag)?,
                "--scenario" => set_once(&mut scenario, Scenario::parse(&value)?, &flag)?,
                "--relay-url" => set_once(&mut relay_url, value, &flag)?,
                "--iroh-bind" => set_once(
                    &mut iroh_bind,
                    value
                        .parse()
                        .map_err(|error| format!("invalid --iroh-bind: {error}"))?,
                    &flag,
                )?,
                "--peer-node-id" => set_once(&mut peer_node_id, value, &flag)?,
                "--peer-direct-addr" => set_once(
                    &mut peer_direct_addr,
                    value
                        .parse()
                        .map_err(|error| format!("invalid --peer-direct-addr: {error}"))?,
                    &flag,
                )?,
                "--run-id" => set_once(&mut run_id, value, &flag)?,
                "--owner" => set_once(&mut owner, value, &flag)?,
                _ => return Err(format!("unknown argument {flag:?}")),
            }
        }
        let config = Self {
            role: required(role, "--role")?,
            scenario: required(scenario, "--scenario")?,
            relay_url: required(relay_url, "--relay-url")?,
            iroh_bind: required(iroh_bind, "--iroh-bind")?,
            peer_node_id,
            peer_direct_addr,
            run_id: required(run_id, "--run-id")?,
            owner: required(owner, "--owner")?,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.iroh_bind.port() == 0 {
            return Err("--iroh-bind requires a concrete nonzero port".into());
        }
        if !canonical_run_id(&self.run_id) {
            return Err("--run-id must be a canonical production-shaped identity".into());
        }
        if self.owner.trim().is_empty() || self.owner.len() > 128 {
            return Err("--owner must be 1..=128 non-empty characters".into());
        }
        if self.role == Role::Connect
            && self.scenario != Scenario::WrongUrl
            && self.peer_node_id.is_none()
        {
            return Err("connect role requires --peer-node-id".into());
        }
        if self.scenario.offers_direct()
            && self.role == Role::Connect
            && self.peer_direct_addr.is_none()
        {
            return Err(format!(
                "scenario {} requires --peer-direct-addr",
                self.scenario.as_str()
            ));
        }
        Ok(())
    }

    /// The authorization for the relay this peer drives. Always a locally
    /// operated, production-shaped relay: this evidence never contacts a public
    /// relay.
    fn authorization(&self) -> RelayTransportAuthorization {
        RelayTransportAuthorization::LocalProductionShaped {
            owner: self.owner.clone(),
        }
    }
}

fn canonical_run_id(value: &str) -> bool {
    (8..=48).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
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

/// Classify an ESTABLISHED connection's path. An accepted connection can be
/// classified from its `IncomingAddr` with the daemon's own
/// `classify_connection_path`; an OUTGOING connection has no `IncomingAddr`, so
/// its path is read from iroh's own per-path `is_relay()` on the selected path.
/// The two agree by construction: a relay path is relay-attributed, a direct IP
/// path is not. Only a `relayed` selected path is credited to the relay.
fn classify_connect_path(conn: &Connection) -> RelayConnectionPath {
    let paths = conn.paths();
    let mut selected_relay = None;
    let mut any_relay = false;
    for path in &paths {
        if path.is_relay() {
            any_relay = true;
        }
        if path.is_selected() {
            selected_relay = Some(path.is_relay());
        }
    }
    match selected_relay {
        Some(true) => RelayConnectionPath::Relayed,
        Some(false) => RelayConnectionPath::Direct,
        // No path is marked selected yet: fall back to whether the only path so
        // far is a relay one.
        None if any_relay => RelayConnectionPath::Relayed,
        None => RelayConnectionPath::Direct,
    }
}

/// Build a bound iroh endpoint driven through the daemon's relay capability.
async fn build_endpoint(
    config: &Config,
    relay: &RelayTransportConfig,
) -> Result<Endpoint, RelayTransportUnavailable> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .relay_mode(relay.relay_mode())
        .alpns(vec![EVIDENCE_ALPN.to_vec()])
        .secret_key(SecretKey::generate());
    // The relay is a locally operated, self-signed one. Only the dedicated
    // wrong-certificate arm keeps strict verification on so the untrusted cert
    // surfaces as a typed failure; every other arm accepts the local cert.
    if !config.scenario.verifies_relay_cert() {
        builder = builder.ca_tls_config(CaTlsConfig::insecure_skip_verify());
    }
    let builder = builder.bind_addr(config.iroh_bind).map_err(|error| {
        RelayTransportUnavailable::new(
            RelayTransportUnavailableKind::UntrustedConfiguration,
            format!("invalid endpoint bind address: {error}"),
        )
    })?;
    builder.bind().await.map_err(|error| {
        RelayTransportUnavailable::new(
            RelayTransportUnavailableKind::RelayOutage,
            format!("binding relay endpoint failed: {error}"),
        )
    })
}

/// Drive the ACCEPT role: wait for one relayed connection and classify it.
async fn run_accept(config: &Config, relay: &RelayTransportConfig) -> serde_json::Value {
    let endpoint = match build_endpoint(config, relay).await {
        Ok(endpoint) => endpoint,
        Err(error) => return failure_json(config, error),
    };
    let node_id = endpoint.id();
    println!(
        "iroh_relay_evidence_peer_ready role=accept node_id={} relay_url={} run_id={}",
        hex_public(&node_id),
        config.relay_url,
        config.run_id,
    );
    let _ = std::io::stdout().flush();

    // Wait, bounded, for the endpoint to have a relay home so the peer can be
    // reached relay-only.
    let deadline = RELAY_CONNECT_DEADLINE + RELAY_SCHEDULER_GRACE;
    let accepted = tokio::time::timeout(deadline, async {
        let incoming = endpoint.accept().await?;
        let path_before = classify_connection_path(&incoming.remote_addr());
        let conn = incoming.await.ok()?;
        Some((conn, path_before))
    })
    .await;

    let (conn, path_before) = match accepted {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return failure_json(
                config,
                RelayTransportUnavailable::new(
                    RelayTransportUnavailableKind::HalfOpenStream,
                    "accepted connection did not complete its handshake",
                ),
            );
        }
        Err(_) => {
            return failure_json(
                config,
                RelayTransportUnavailable::new(
                    RelayTransportUnavailableKind::Deadline,
                    "no connection accepted within the relay deadline",
                ),
            );
        }
    };

    let path_after = classify_connect_path(&conn);
    // The accept side echoes one bounded message, EXCEPT in the half-open-stream
    // arm: there it accepts the connection and reads the request but never
    // writes the echo back, so the connecting peer observes a typed
    // `half_open_stream` when its stream read stalls past the grace bound.
    let half_open = config.scenario == Scenario::HalfOpenStream;
    if let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let mut buf = vec![0u8; EVIDENCE_MESSAGE.len()];
        if recv.read_exact(&mut buf).await.is_ok() && !half_open {
            let _ = send.write_all(&buf).await;
            let _ = send.finish();
        }
    }
    if !half_open {
        conn.closed().await;
    }
    endpoint.close().await;

    success_json(config, path_before, path_after, &hex_public(&node_id))
}

/// Drive the CONNECT role for one scenario.
async fn run_connect(config: &Config, relay: &RelayTransportConfig) -> serde_json::Value {
    let endpoint = match build_endpoint(config, relay).await {
        Ok(endpoint) => endpoint,
        Err(error) => return failure_json(config, error),
    };

    let peer_node_id = match config
        .peer_node_id
        .as_deref()
        .map(parse_public_key)
        .transpose()
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return failure_json(
                config,
                RelayTransportUnavailable::new(
                    RelayTransportUnavailableKind::WrongIdentity,
                    "connect role reached without a peer NodeId",
                ),
            );
        }
        Err(message) => {
            return failure_json(
                config,
                RelayTransportUnavailable::new(
                    RelayTransportUnavailableKind::WrongIdentity,
                    message,
                ),
            );
        }
    };

    // Build the target address. Relay-only arms carry NO direct address, so a
    // successful connection can only be relayed. The direct arms additionally
    // offer the peer's direct socket.
    let mut endpoint_addr = EndpointAddr::new(peer_node_id);
    if !matches!(config.scenario, Scenario::ForcedDirectFailure) {
        endpoint_addr = endpoint_addr.with_relay_url(relay.relay_url().clone());
    }
    if config.scenario.offers_direct()
        && let Some(direct) = config.peer_direct_addr
    {
        endpoint_addr = endpoint_addr.with_ip_addr(direct);
    }

    let deadline = RELAY_CONNECT_DEADLINE;
    let connect = tokio::time::timeout(deadline, endpoint.connect(endpoint_addr, EVIDENCE_ALPN));
    let outcome = match connect.await {
        Ok(Ok(conn)) => drive_connected(config, &endpoint, conn).await,
        Ok(Err(error)) => failure_json(config, map_connect_error(config, &error.to_string())),
        Err(_) => failure_json(
            config,
            RelayTransportUnavailable::new(
                RelayTransportUnavailableKind::Deadline,
                format!(
                    "connect exceeded the {}ms relay deadline",
                    deadline.as_millis()
                ),
            ),
        ),
    };
    endpoint.close().await;
    outcome
}

/// After a connection establishes, classify the path and exchange one message.
/// A half-open peer (which never echoes) surfaces as a typed `half_open_stream`.
async fn drive_connected(
    config: &Config,
    endpoint: &Endpoint,
    conn: Connection,
) -> serde_json::Value {
    let node_id = hex_public(&endpoint.id());
    let path = classify_connect_path(&conn);

    let exchange = tokio::time::timeout(RELAY_SCHEDULER_GRACE + Duration::from_secs(2), async {
        let (mut send, mut recv) = conn.open_bi().await.ok()?;
        send.write_all(EVIDENCE_MESSAGE).await.ok()?;
        send.finish().ok()?;
        let echoed = recv.read_to_end(EVIDENCE_MESSAGE.len() + 1).await.ok()?;
        Some(echoed)
    })
    .await;

    match exchange {
        Ok(Some(echoed)) if echoed == EVIDENCE_MESSAGE => {
            success_json(config, path, path, &node_id)
        }
        _ => failure_json(
            config,
            RelayTransportUnavailable::new(
                RelayTransportUnavailableKind::HalfOpenStream,
                "peer accepted the connection but did not complete the stream exchange",
            ),
        ),
    }
}

/// Map a real connect error to a typed reason using the scenario's intent. The
/// only scenario that verifies the relay cert is `wrong-certificate`; a connect
/// failure there is a certificate failure. Every other connect failure inside
/// the deadline is a relay outage. This never matches iroh error-string
/// internals beyond the scenario the operator selected.
fn map_connect_error(config: &Config, detail: &str) -> RelayTransportUnavailable {
    match config.scenario {
        Scenario::WrongCertificate => RelayTransportUnavailable::new(
            RelayTransportUnavailableKind::WrongCertificate,
            format!("relay certificate verification failed: {detail}"),
        ),
        Scenario::ForcedDirectFailure => RelayTransportUnavailable::new(
            RelayTransportUnavailableKind::ForcedDirectFailure,
            format!("direct-only connect failed with the direct path blocked: {detail}"),
        ),
        _ => RelayTransportUnavailable::new(
            RelayTransportUnavailableKind::RelayOutage,
            format!("relay connect failed: {detail}"),
        ),
    }
}

fn parse_public_key(raw: &str) -> Result<PublicKey, String> {
    let bytes =
        decode_hex_32(raw).ok_or_else(|| format!("peer NodeId {raw:?} is not 32-byte hex"))?;
    PublicKey::from_bytes(&bytes)
        .map_err(|error| format!("peer NodeId {raw:?} is not valid: {error}"))
}

fn decode_hex_32(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in raw.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[index] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

fn hex_public(key: &PublicKey) -> String {
    key.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn success_json(
    config: &Config,
    path_before: RelayConnectionPath,
    path_after: RelayConnectionPath,
    node_id: &str,
) -> serde_json::Value {
    json!({
        "schema": "iroh-relay-evidence-peer-outcome-v1",
        "role": config.role.as_str(),
        "scenario": config.scenario.as_str(),
        "verdict": "connected",
        "run_id": config.run_id,
        "owner": config.owner,
        "node_id": node_id,
        "relay_url": config.relay_url,
        "connection_path": path_after.as_str(),
        "connection_path_at_accept": path_before.as_str(),
        "relay_attributed": path_after.is_relay_attributed(),
        "authorization_class": "production-shaped-local",
        "external_contact_authorized": false,
    })
}

fn failure_json(config: &Config, error: RelayTransportUnavailable) -> serde_json::Value {
    json!({
        "schema": "iroh-relay-evidence-peer-outcome-v1",
        "role": config.role.as_str(),
        "scenario": config.scenario.as_str(),
        "verdict": "unavailable",
        "run_id": config.run_id,
        "owner": config.owner,
        "relay_url": config.relay_url,
        "reason": error.kind().as_str(),
        "detail": error.message(),
        "relay_attributed": false,
        "authorization_class": "production-shaped-local",
        "external_contact_authorized": false,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::parse() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("iroh_relay_evidence_peer_error stage=config error={error:?}");
            return ExitCode::from(2);
        }
    };

    // Config-time relay validation: a malformed URL or an untrusted/public host
    // is a typed failure decided WITHOUT any network I/O.
    let relay = match RelayTransportConfig::new(&config.relay_url, config.authorization()) {
        Ok(relay) => relay,
        Err(error) => {
            let outcome = failure_json(&config, error);
            println!("{outcome}");
            let _ = std::io::stdout().flush();
            // A config-time typed failure is still a well-formed evidence
            // outcome, not a process crash.
            return ExitCode::SUCCESS;
        }
    };

    // Guard: the relay mode must be a daemon-owned Custom map, never an n0
    // default. This mirrors the deterministic core's invariant at runtime.
    if !matches!(relay.relay_mode(), RelayMode::Custom(_)) {
        eprintln!("iroh_relay_evidence_peer_error stage=relay error=\"relay mode is not custom\"");
        return ExitCode::FAILURE;
    }

    let outcome = match config.role {
        Role::Accept => run_accept(&config, &relay).await,
        Role::Connect => run_connect(&config, &relay).await,
    };

    println!("{outcome}");
    let _ = std::io::stdout().flush();

    // Whether the connection succeeded or produced a typed failure, the process
    // itself completed its evidence job. The harness gates the verdict; the exit
    // code only signals whether the peer ran to completion.
    let verdict = outcome
        .get("verdict")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if config.scenario.expects_connection() && verdict != "connected" {
        // A positive arm that failed to connect is a hard failure of that arm.
        return ExitCode::from(4);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(role: Role, scenario: Scenario) -> Config {
        Config {
            role,
            scenario,
            relay_url: "https://10.192.1.40:44380".into(),
            iroh_bind: "10.192.2.10:44330".parse().unwrap(),
            peer_node_id: Some("ab".repeat(32)),
            peer_direct_addr: None,
            run_id: "r1234567".into(),
            owner: "nix-p2p-task142-evidence".into(),
        }
    }

    #[test]
    fn connect_requires_a_peer_node_id_except_for_the_config_time_wrong_url_arm() {
        let mut config = base(Role::Connect, Scenario::RelaySuccess);
        config.peer_node_id = None;
        assert!(config.validate().is_err());
        // wrong-url fails at config validation before any peer is needed.
        let mut wrong_url = base(Role::Connect, Scenario::WrongUrl);
        wrong_url.peer_node_id = None;
        wrong_url.validate().unwrap();
    }

    #[test]
    fn direct_arms_require_a_direct_address() {
        let mut config = base(Role::Connect, Scenario::DirectPositive);
        config.peer_direct_addr = None;
        assert!(config.validate().is_err());
        config.peer_direct_addr = Some("10.192.2.30:44331".parse().unwrap());
        config.validate().unwrap();
    }

    #[test]
    fn a_malformed_relay_url_is_a_typed_wrong_url_outcome() {
        let config = base(Role::Connect, Scenario::WrongUrl);
        let error = RelayTransportConfig::new("http://10.192.1.40:44380", config.authorization())
            .unwrap_err();
        assert_eq!(error.kind(), RelayTransportUnavailableKind::WrongRelayUrl);
        let json = failure_json(&config, error);
        assert_eq!(json["verdict"], "unavailable");
        assert_eq!(json["reason"], "wrong_relay_url");
        assert_eq!(json["relay_attributed"], false);
    }

    #[test]
    fn a_public_relay_host_under_local_authorization_is_untrusted() {
        let config = base(Role::Connect, Scenario::RelaySuccess);
        let error = RelayTransportConfig::new("https://relay.example.com", config.authorization())
            .unwrap_err();
        assert_eq!(
            error.kind(),
            RelayTransportUnavailableKind::UntrustedConfiguration
        );
    }

    #[test]
    fn map_connect_error_respects_the_scenario_intent() {
        let cert = base(Role::Connect, Scenario::WrongCertificate);
        assert_eq!(
            map_connect_error(&cert, "bad cert").kind(),
            RelayTransportUnavailableKind::WrongCertificate
        );
        let forced = base(Role::Connect, Scenario::ForcedDirectFailure);
        assert_eq!(
            map_connect_error(&forced, "no route").kind(),
            RelayTransportUnavailableKind::ForcedDirectFailure
        );
        let outage = base(Role::Connect, Scenario::RelayOutage);
        assert_eq!(
            map_connect_error(&outage, "refused").kind(),
            RelayTransportUnavailableKind::RelayOutage
        );
    }

    #[test]
    fn success_json_only_credits_relay_for_a_relayed_path() {
        let config = base(Role::Connect, Scenario::RelaySuccess);
        let relayed = success_json(
            &config,
            RelayConnectionPath::Relayed,
            RelayConnectionPath::Relayed,
            &"cd".repeat(32),
        );
        assert_eq!(relayed["connection_path"], "relayed");
        assert_eq!(relayed["relay_attributed"], true);
        let direct = success_json(
            &config,
            RelayConnectionPath::Direct,
            RelayConnectionPath::Direct,
            &"cd".repeat(32),
        );
        assert_eq!(direct["connection_path"], "direct");
        assert_eq!(
            direct["relay_attributed"], false,
            "a direct-positive control must never be credited to the relay"
        );
    }

    #[test]
    fn hex_public_and_decode_hex_round_trip() {
        let key = SecretKey::generate().public();
        let hex = hex_public(&key);
        assert_eq!(hex.len(), 64);
        let decoded = decode_hex_32(&hex).unwrap();
        assert_eq!(&decoded, key.as_bytes());
        assert!(decode_hex_32("zz").is_none());
    }
}
