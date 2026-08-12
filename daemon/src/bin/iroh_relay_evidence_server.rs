//! Locally operated iroh relay SERVER runner for the routed TASK-142 evidence.
//!
//! This binary spawns exactly ONE `iroh_relay::server::Server` bound to a
//! concrete private/routed address with a self-signed certificate, so two peers
//! on L3-separated namespaces can rendezvous through it while their DIRECT path
//! is blocked. It contacts no n0/public relay and performs no discovery; it is
//! the locally operated relay whose evidence is labelled `production-shaped`.
//!
//! It is feature-gated (`evidence-fixture`) out of every production build: the
//! relay-server dependency tree never enters the daemon closure.
//!
//! Lifecycle: bind, print a canonical plan JSON + a `ready` line carrying the
//! exact https relay URL, then serve until either the bounded lifetime elapses
//! or SIGTERM/SIGINT arrives, at which point it shuts the server down cleanly.

use std::env;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use iroh_relay::server::{
    CertConfig, QuicConfig, RelayConfig, Server, ServerConfig, TlsConfig,
    testing::self_signed_tls_certs_and_config,
};
use serde_json::json;
use tokio::signal::unix::{SignalKind, signal};

/// Hard ceiling on how long the relay stays up, so a leaked container process
/// cannot outlive its evidence run.
const MAX_LIFETIME: Duration = Duration::from_secs(120);

struct Config {
    https_bind: SocketAddr,
    http_bind: SocketAddr,
    quic_bind: Option<SocketAddr>,
    lifetime: Duration,
    run_id: String,
    owner: String,
    image_revision: String,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut https_bind = None;
        let mut http_bind = None;
        let mut quic_bind = None;
        let mut lifetime_secs = None;
        let mut run_id = None;
        let mut owner = None;
        let mut image_revision = None;
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| format!("missing value after {flag:?}"))?;
            match flag.as_str() {
                "--https-bind" => set_once(&mut https_bind, parse_socket(&value)?, &flag)?,
                "--http-bind" => set_once(&mut http_bind, parse_socket(&value)?, &flag)?,
                "--quic-bind" => set_once(&mut quic_bind, parse_socket(&value)?, &flag)?,
                "--lifetime-secs" => set_once(
                    &mut lifetime_secs,
                    value
                        .parse::<u64>()
                        .map_err(|error| format!("invalid --lifetime-secs: {error}"))?,
                    &flag,
                )?,
                "--run-id" => set_once(&mut run_id, value, &flag)?,
                "--owner" => set_once(&mut owner, value, &flag)?,
                "--image-revision" => set_once(&mut image_revision, value, &flag)?,
                _ => return Err(format!("unknown argument {flag:?}")),
            }
        }
        let https_bind = required(https_bind, "--https-bind")?;
        let http_bind = http_bind.unwrap_or_else(|| SocketAddr::new(https_bind.ip(), 0));
        let lifetime = Duration::from_secs(required(lifetime_secs, "--lifetime-secs")?);
        let config = Self {
            https_bind,
            http_bind,
            quic_bind,
            lifetime,
            run_id: required(run_id, "--run-id")?,
            owner: required(owner, "--owner")?,
            image_revision: required(image_revision, "--image-revision")?,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        // The https bind must be a CONCRETE private/routed socket so the derived
        // relay URL is deterministic and dialable by the peer. An unspecified
        // (0.0.0.0) or public address is refused: a production-shaped relay is a
        // locally operated routed address, never a public one.
        validate_relay_socket(self.https_bind, "--https-bind")?;
        // The http bind may be ephemeral (:0); when concrete it must be local.
        if self.http_bind.port() != 0 {
            validate_relay_socket(self.http_bind, "--http-bind")?;
        } else if is_public_ip(self.http_bind.ip()) {
            return Err("--http-bind address is public".into());
        }
        if let Some(quic) = self.quic_bind {
            validate_relay_socket(quic, "--quic-bind")?;
        }
        if self.lifetime.is_zero() || self.lifetime > MAX_LIFETIME {
            return Err(format!(
                "--lifetime-secs must be 1..={}",
                MAX_LIFETIME.as_secs()
            ));
        }
        if !canonical_run_id(&self.run_id) {
            return Err("--run-id must be a canonical production-shaped identity".into());
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
            return Err("--image-revision must be a clean 40- or 64-digit lowercase hex".into());
        }
        Ok(())
    }

    fn relay_url(&self) -> String {
        format!("https://{}", self.https_bind)
    }
}

fn canonical_run_id(value: &str) -> bool {
    (8..=48).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn parse_socket(raw: &str) -> Result<SocketAddr, String> {
    raw.parse()
        .map_err(|error| format!("invalid socket {raw:?}: {error}"))
}

/// Mirrors the node-lookup fixture policy: a relay socket must be a concrete,
/// private/local unicast address with a nonzero port. Public, unspecified,
/// multicast, or unscoped link-local addresses are refused.
fn validate_relay_socket(socket: SocketAddr, flag: &str) -> Result<(), String> {
    let unscoped_link_local = matches!(
        socket,
        SocketAddr::V6(address)
            if address.ip().is_unicast_link_local() && address.scope_id() == 0
    );
    if socket.port() == 0
        || socket.ip().is_unspecified()
        || socket.ip().is_multicast()
        || is_public_ip(socket.ip())
        || unscoped_link_local
    {
        return Err(format!(
            "{flag} must be a concrete private/local unicast socket with nonzero port"
        ));
    }
    Ok(())
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip == Ipv4Addr::UNSPECIFIED)
        }
        IpAddr::V6(ip) => {
            let unique_local = ip.segments()[0] & 0xfe00 == 0xfc00;
            !(ip.is_loopback()
                || ip.is_unicast_link_local()
                || unique_local
                || ip == Ipv6Addr::UNSPECIFIED)
        }
    }
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

fn plan_json(config: &Config) -> serde_json::Value {
    json!({
        "schema": "iroh-relay-evidence-server-plan-v1",
        "run_id": config.run_id,
        "owner": config.owner,
        "image_revision": config.image_revision,
        "https_bind": config.https_bind.to_string(),
        "http_bind": config.http_bind.to_string(),
        "quic_bind": config.quic_bind.map(|addr| addr.to_string()),
        "relay_url": config.relay_url(),
        "lifetime_secs": config.lifetime.as_secs(),
        "authorization_class": "production-shaped-local",
        "external_contact_authorized": false,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::parse() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("iroh_relay_evidence_server_error stage=config error={error:?}");
            return ExitCode::from(2);
        }
    };

    let (_certs, rustls_server_config) = self_signed_tls_certs_and_config();
    let tls = TlsConfig::new(
        config.https_bind,
        CertConfig::Manual {
            server_config: rustls_server_config,
        },
    );
    let mut relay = RelayConfig::new(config.http_bind);
    relay.tls = Some(tls);
    relay.key_cache_capacity = Some(1024);

    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay);
    server_config.quic = config.quic_bind.map(QuicConfig::new);

    let mut server = match Server::spawn(server_config).await {
        Ok(server) => server,
        Err(error) => {
            eprintln!("iroh_relay_evidence_server_error stage=spawn error={error:?}");
            return ExitCode::FAILURE;
        }
    };

    let Some(https_addr) = server.https_addr() else {
        eprintln!("iroh_relay_evidence_server_error stage=bind error=\"no https address bound\"");
        return ExitCode::FAILURE;
    };

    println!("{}", plan_json(&config));
    println!(
        "iroh_relay_evidence_server_ready relay_url={} https_addr={} quic_addr={:?} run_id={} owner={}",
        config.relay_url(),
        https_addr,
        server.quic_addr(),
        config.run_id,
        config.owner,
    );
    let _ = std::io::stdout().flush();

    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("iroh_relay_evidence_server_error stage=signal error={error:?}");
            return ExitCode::FAILURE;
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("iroh_relay_evidence_server_error stage=signal error={error:?}");
            return ExitCode::FAILURE;
        }
    };

    let stop_reason = tokio::select! {
        () = tokio::time::sleep(config.lifetime) => "lifetime",
        _ = sigterm.recv() => "sigterm",
        _ = sigint.recv() => "sigint",
        result = server.join() => {
            eprintln!("iroh_relay_evidence_server_error stage=supervisor result={result:?}");
            return ExitCode::FAILURE;
        }
    };

    match server.shutdown().await {
        Ok(()) => {
            println!("iroh_relay_evidence_server_complete stop_reason={stop_reason}");
            let _ = std::io::stdout().flush();
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("iroh_relay_evidence_server_error stage=shutdown error={error:?}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        Config {
            https_bind: "10.192.1.40:44380".parse().unwrap(),
            http_bind: "10.192.1.40:0".parse().unwrap(),
            quic_bind: None,
            lifetime: Duration::from_secs(30),
            run_id: "r1234567".into(),
            owner: "nix-p2p-task142-evidence".into(),
            image_revision: "1".repeat(40),
        }
    }

    #[test]
    fn a_concrete_private_https_bind_is_accepted_and_yields_a_deterministic_url() {
        let config = base();
        config.validate().unwrap();
        assert_eq!(config.relay_url(), "https://10.192.1.40:44380");
    }

    #[test]
    fn public_unspecified_and_zero_port_binds_are_refused() {
        for bad in ["8.8.8.8:44380", "0.0.0.0:44380", "10.192.1.40:0"] {
            let mut config = base();
            config.https_bind = bad.parse().unwrap();
            assert!(
                config.validate().is_err(),
                "{bad:?} must be rejected as a relay https bind"
            );
        }
    }

    #[test]
    fn lifetime_is_bounded_and_run_id_owner_revision_are_canonical() {
        let mut config = base();
        config.lifetime = Duration::from_secs(0);
        assert!(config.validate().is_err());
        config = base();
        config.lifetime = MAX_LIFETIME + Duration::from_secs(1);
        assert!(config.validate().is_err());
        config = base();
        config.run_id = "BAD".into();
        assert!(config.validate().is_err());
        config = base();
        config.owner = String::new();
        assert!(config.validate().is_err());
        config = base();
        config.image_revision.push_str("-dirty");
        assert!(config.validate().is_err());
    }

    #[test]
    fn plan_json_advertises_a_production_shaped_local_relay() {
        let plan = plan_json(&base());
        assert_eq!(plan["authorization_class"], "production-shaped-local");
        assert_eq!(plan["external_contact_authorized"], false);
        assert_eq!(plan["relay_url"], "https://10.192.1.40:44380");
    }
}
