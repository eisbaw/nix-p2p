//! Standalone, explicitly-scoped authority for Iroh node-address publication.
//!
//! Keeping this process separate lets routed evidence place publishers and the
//! authority in different network namespaces. It deliberately exposes only the
//! pkarr PUT/GET store: no node lookup, content discovery, relay, or wildcard
//! signer admission is implied by running it.

use std::collections::BTreeSet;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use daemon::{AuthoritySignerAdmission, NodeId, PublicationAuthority, PublicationAuthorityConfig};

#[derive(Debug)]
struct Config {
    listen: SocketAddr,
    state_dir: PathBuf,
    namespace: String,
    recipient: String,
    expected_host: String,
    owner: String,
    authorized_signers: BTreeSet<String>,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut listen = None;
        let mut state_dir = None;
        let mut namespace = None;
        let mut recipient = None;
        let mut expected_host = None;
        let mut owner = None;
        let mut authorized_signers = BTreeSet::new();
        let mut arguments = env::args().skip(1);

        while let Some(flag) = arguments.next() {
            if flag == "--help" || flag == "-h" {
                return Err(usage());
            }
            let value = arguments
                .next()
                .ok_or_else(|| format!("missing value after {flag:?}\n{}", usage()))?;
            match flag.as_str() {
                "--listen" => set_once(&mut listen, parse_socket(&value, &flag)?, &flag)?,
                "--state-dir" => set_once(&mut state_dir, PathBuf::from(value), &flag)?,
                "--namespace" => set_once(&mut namespace, value, &flag)?,
                "--recipient" => set_once(&mut recipient, value, &flag)?,
                "--expected-host" => set_once(&mut expected_host, value, &flag)?,
                "--owner" => set_once(&mut owner, value, &flag)?,
                "--authorized-signer" => {
                    insert_signer(&mut authorized_signers, value, &flag)?;
                }
                "--authorized-node-id" => {
                    insert_signer(&mut authorized_signers, signer_from_node_id(&value)?, &flag)?;
                }
                _ => return Err(format!("unknown argument {flag:?}\n{}", usage())),
            }
        }

        Ok(Self {
            listen: required(listen, "--listen")?,
            state_dir: required(state_dir, "--state-dir")?,
            namespace: required(namespace, "--namespace")?,
            recipient: required(recipient, "--recipient")?,
            expected_host: required(expected_host, "--expected-host")?,
            owner: required(owner, "--owner")?,
            authorized_signers,
        })
    }

    fn authority_config(&self) -> Result<PublicationAuthorityConfig, String> {
        let signer_admission =
            AuthoritySignerAdmission::explicit(self.authorized_signers.iter().cloned())
                .map_err(|error| error.to_string())?;
        let config = PublicationAuthorityConfig {
            listen: self.listen,
            state_dir: self.state_dir.clone(),
            namespace: self.namespace.clone(),
            signed_recipient: self.recipient.clone(),
            expected_host: self.expected_host.clone(),
            owner: self.owner.clone(),
            signer_admission,
        };
        config.validate().map_err(|error| error.to_string())?;
        Ok(config)
    }
}

fn required<T>(value: Option<T>, flag: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("required argument {flag} is missing\n{}", usage()))
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("argument {flag} may be supplied only once"));
    }
    Ok(())
}

fn parse_socket(value: &str, flag: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|error| format!("invalid {flag} socket {value:?}: {error}"))
}

fn insert_signer(signers: &mut BTreeSet<String>, signer: String, flag: &str) -> Result<(), String> {
    if !signers.insert(signer.clone()) {
        return Err(format!(
            "duplicate authorized identity from {flag} value {signer:?} is ambiguous"
        ));
    }
    Ok(())
}

fn signer_from_node_id(raw: &str) -> Result<String, String> {
    let node_id = raw
        .parse::<NodeId>()
        .map_err(|error| format!("invalid --authorized-node-id {raw:?}: {error}"))?;
    let public_key = iroh::PublicKey::from_bytes(node_id.as_bytes())
        .map_err(|error| format!("invalid Ed25519 --authorized-node-id {raw:?}: {error}"))?;
    Ok(public_key.to_z32())
}

fn usage() -> String {
    "usage: iroh-node-authority \
      --listen <concrete-unicast:port> \
      --state-dir <directory> \
      --namespace <run-unique-namespace> \
      --recipient <signed-recipient> \
      --expected-host <http-host-header> \
      --owner <operator-name> \
      (--authorized-signer <canonical-z32> | --authorized-node-id <canonical-hex>) ..."
        .to_string()
}

async fn shutdown_signal() -> Result<&'static str, String> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|error| format!("installing SIGTERM handler: {error}"))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|error| format!("waiting for SIGINT: {error}"))?;
                Ok("sigint")
            }
            _ = terminate.recv() => Ok("sigterm"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| format!("waiting for shutdown signal: {error}"))?;
        Ok("interrupt")
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::parse().and_then(|config| {
        let authority = config.authority_config()?;
        Ok((config, authority))
    }) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("iroh_node_authority_error stage=config error={error:?}");
            return ExitCode::from(2);
        }
    };

    let (process_config, authority_config) = config;
    let authority = match PublicationAuthority::bind(authority_config).await {
        Ok(authority) => authority,
        Err(error) => {
            eprintln!("iroh_node_authority_error stage=start error={error:?}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "iroh_node_authority_ready listen={} namespace={:?} owner={:?} admitted_signers={}",
        authority.local_addr(),
        process_config.namespace,
        process_config.owner,
        process_config.authorized_signers.len(),
    );

    let signal = tokio::select! {
        signal = shutdown_signal() => match signal {
            Ok(signal) => signal,
            Err(error) => {
                eprintln!("iroh_node_authority_error stage=signal error={error:?}");
                return ExitCode::FAILURE;
            }
        },
        error = authority.wait_for_failure() => {
            eprintln!("iroh_node_authority_error stage=serve error={error:?}");
            return ExitCode::FAILURE;
        }
    };
    let requests = authority.request_count();
    if let Err(error) = authority.shutdown().await {
        eprintln!("iroh_node_authority_error stage=shutdown error={error:?}");
        return ExitCode::FAILURE;
    }
    println!("iroh_node_authority_stopped signal={signal} requests={requests}");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_singleton_argument_fails_closed() {
        let mut value = Some("first".to_string());
        assert!(set_once(&mut value, "second".to_string(), "--owner").is_err());
        assert_eq!(value.as_deref(), Some("second"));
    }

    #[test]
    fn required_argument_reports_its_flag() {
        assert!(
            required::<String>(None, "--namespace")
                .unwrap_err()
                .contains("--namespace")
        );
    }

    #[test]
    fn node_id_conversion_uses_irohs_canonical_signer_codec() {
        let key = iroh::SecretKey::generate();
        let node_id = NodeId::from_bytes(*key.public().as_bytes());
        assert_eq!(
            signer_from_node_id(&node_id.to_hex()).unwrap(),
            key.public().to_z32()
        );
        assert!(signer_from_node_id("not-a-node-id").is_err());
    }
}
