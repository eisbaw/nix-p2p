//! Diagnostic for one explicitly supplied NodeId and one pinned local authority.
//!
//! `--attempts 2` repeats that same identity in one runtime so replay/high-water
//! evidence can rotate two responses. No second NodeId or enumeration input
//! exists.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use daemon::{
    AddressLookupCapability, EndpointProfile, EndpointScope, IdentitySource, IrohNodeBuilder,
    NODE_LOOKUP_SCHEMA, NodeId, NodeLocation, NodeLookupAuthorityAuthorization, NodeLookupConfig,
    NodeLookupUnavailable, RelayCapability, ShutdownOutcome,
};
use serde_json::json;

#[derive(Debug)]
struct Config {
    node_id: NodeId,
    attempts: u8,
    state_dir: PathBuf,
    iroh_port: u16,
    namespace: String,
    recipient: String,
    authority_socket: SocketAddr,
    authority_host: String,
    owner: String,
    external_authorization: Option<String>,
}

impl Config {
    fn parse() -> Result<Self, NodeLookupUnavailable> {
        let mut node_id = None;
        let mut attempts = 1u8;
        let mut attempts_set = false;
        let mut state_dir = None;
        let mut iroh_port = None;
        let mut namespace = None;
        let mut recipient = None;
        let mut authority_socket = None;
        let mut authority_host = None;
        let mut owner = None;
        let mut external_authorization = None;
        let mut arguments = env::args().skip(1);
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or_else(|| {
                NodeLookupUnavailable::new(
                    daemon::NodeLookupUnavailableKind::UntrustedConfiguration,
                    format!("missing value after {flag:?}; {}", usage()),
                )
            })?;
            match flag.as_str() {
                "--node-id" => {
                    let parsed = value
                        .parse()
                        .map_err(NodeLookupUnavailable::invalid_node_id)?;
                    set_once(&mut node_id, parsed, &flag)?;
                }
                "--attempts" => {
                    if attempts_set {
                        return Err(config_error("duplicate --attempts"));
                    }
                    attempts = value.parse().map_err(|error| {
                        config_error(format!("invalid --attempts {value:?}: {error}"))
                    })?;
                    if !(1..=2).contains(&attempts) {
                        return Err(config_error("--attempts must be 1 or 2"));
                    }
                    attempts_set = true;
                }
                "--state-dir" => set_once(&mut state_dir, PathBuf::from(value), &flag)?,
                "--iroh-port" => {
                    let port = value.parse::<u16>().map_err(|error| {
                        config_error(format!("invalid --iroh-port {value:?}: {error}"))
                    })?;
                    if port == 0 {
                        return Err(config_error("--iroh-port must be nonzero"));
                    }
                    set_once(&mut iroh_port, port, &flag)?;
                }
                "--namespace" => set_once(&mut namespace, value, &flag)?,
                "--recipient" => set_once(&mut recipient, value, &flag)?,
                "--authority-socket" => {
                    let socket = value.parse().map_err(|error| {
                        config_error(format!("invalid --authority-socket {value:?}: {error}"))
                    })?;
                    set_once(&mut authority_socket, socket, &flag)?;
                }
                "--authority-host" => set_once(&mut authority_host, value, &flag)?,
                "--owner" => set_once(&mut owner, value, &flag)?,
                "--external-authorization" => {
                    set_once(&mut external_authorization, value, &flag)?;
                }
                _ => {
                    return Err(config_error(format!(
                        "unknown argument {flag:?}; {}",
                        usage()
                    )));
                }
            }
        }
        Ok(Self {
            node_id: required(node_id, "--node-id")?,
            attempts,
            state_dir: required(state_dir, "--state-dir")?,
            iroh_port: required(iroh_port, "--iroh-port")?,
            namespace: required(namespace, "--namespace")?,
            recipient: required(recipient, "--recipient")?,
            authority_socket: required(authority_socket, "--authority-socket")?,
            authority_host: required(authority_host, "--authority-host")?,
            owner: required(owner, "--owner")?,
            external_authorization,
        })
    }
}

fn config_error(message: impl Into<String>) -> NodeLookupUnavailable {
    NodeLookupUnavailable::new(
        daemon::NodeLookupUnavailableKind::UntrustedConfiguration,
        message,
    )
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), NodeLookupUnavailable> {
    if slot.replace(value).is_some() {
        return Err(config_error(format!("duplicate {flag}")));
    }
    Ok(())
}

fn required<T>(slot: Option<T>, flag: &str) -> Result<T, NodeLookupUnavailable> {
    slot.ok_or_else(|| config_error(format!("required argument {flag} is missing; {}", usage())))
}

fn usage() -> &'static str {
    "usage: iroh-node-lookup --node-id <canonical-hex> [--attempts 1|2] --state-dir <dir> --iroh-port <nonzero> --namespace <name> --recipient <label> --authority-socket <private-ip:port> --authority-host <host> --owner <name>"
}

fn failure_json(error: &NodeLookupUnavailable, elapsed_micros: u128) -> serde_json::Value {
    let mut value = json!({
        "verdict": "unavailable",
        "reason": error.kind().as_str(),
        "detail": error.message(),
        "elapsed_micros": elapsed_micros,
    });
    if let (Some(sequence), Some(packet_hash)) = (
        error.validated_sequence(),
        error.validated_signed_packet_blake3_hex(),
    ) {
        value["source"] = json!(daemon::NODE_LOOKUP_SOURCE);
        value["provenance"] = json!("network_validated");
        value["sequence"] = json!(sequence);
        value["signed_packet_blake3_hex"] = json!(packet_hash);
    }
    value
}

fn shutdown_policy(shutdown: &Result<ShutdownOutcome, daemon::IrohError>) -> (&'static str, bool) {
    match shutdown {
        Ok(ShutdownOutcome::Graceful) => ("graceful", true),
        Ok(ShutdownOutcome::Forced) => ("forced", false),
        Err(_) => ("failed", false),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::parse() {
        Ok(config) => config,
        Err(error) => {
            println!(
                "{}",
                json!({
                    "schema": NODE_LOOKUP_SCHEMA,
                    "verdict": "unavailable",
                    "reason": error.kind().as_str(),
                    "detail": error.message(),
                    "attempts": [],
                })
            );
            return ExitCode::from(2);
        }
    };
    let authorization = match &config.external_authorization {
        Some(reference) => NodeLookupAuthorityAuthorization::ExternalAuthorized {
            owner: config.owner.clone(),
            authorization_reference: reference.clone(),
        },
        None => NodeLookupAuthorityAuthorization::LocalProductionShaped {
            owner: config.owner.clone(),
        },
    };
    let lookup = match NodeLookupConfig::new(
        config.namespace.clone(),
        config.recipient.clone(),
        config.authority_socket,
        config.authority_host.clone(),
        authorization,
    ) {
        Ok(lookup) => lookup,
        Err(error) => {
            println!(
                "{}",
                json!({
                    "schema": NODE_LOOKUP_SCHEMA,
                    "verdict": "unavailable",
                    "node_id": config.node_id,
                    "reason": error.kind().as_str(),
                    "detail": error.message(),
                    "attempts": [],
                })
            );
            return ExitCode::from(2);
        }
    };
    let node = match IrohNodeBuilder::new(
        EndpointProfile {
            scope: EndpointScope::Global {
                port: config.iroh_port,
            },
        },
        IdentitySource::Persistent {
            state_dir: config.state_dir.clone(),
        },
        RelayCapability::Disabled,
        AddressLookupCapability::PinnedPkarr(lookup),
    ) {
        Ok(builder) => match builder.spawn().await {
            Ok(node) => node,
            Err(error) => {
                let unavailable = config_error(format!("starting lookup runtime: {error}"));
                println!(
                    "{}",
                    json!({
                        "schema": NODE_LOOKUP_SCHEMA,
                        "verdict": "unavailable",
                        "node_id": config.node_id,
                        "reason": unavailable.kind().as_str(),
                        "detail": unavailable.message(),
                        "attempts": [],
                    })
                );
                return ExitCode::FAILURE;
            }
        },
        Err(error) => {
            eprintln!("iroh_node_lookup_error stage=config error={error}");
            return ExitCode::from(2);
        }
    };
    let handle = node
        .node_lookup_handle()
        .expect("enabled lookup builder must retain its narrow handle");
    let mut attempts = Vec::with_capacity(config.attempts.into());
    let mut all_passed = true;
    for attempt in 1..=config.attempts {
        let started = Instant::now();
        let value = match handle.resolve(config.node_id).await {
            Ok(result) => {
                let candidates = result
                    .candidates()
                    .iter()
                    .map(|candidate| match candidate {
                        NodeLocation::Direct(address) => {
                            json!({"kind": "direct", "value": address.to_string()})
                        }
                        NodeLocation::Relay(url) => {
                            json!({"kind": "relay", "value": url})
                        }
                    })
                    .collect::<Vec<_>>();
                json!({
                    "attempt": attempt,
                    "verdict": "pass",
                    "elapsed_micros": started.elapsed().as_micros(),
                    "lookup_schema": result.lookup_schema(),
                    "record_schema": result.record_schema(),
                    "source": result.source(),
                    "provenance": result.provenance().as_str(),
                    "node_id": result.node_id(),
                    "namespace": result.namespace(),
                    "recipient": result.recipient(),
                    "ttl_seconds": result.ttl_seconds(),
                    "sequence": result.sequence(),
                    "expires_unix_micros": result.expires_unix_micros(),
                    "signed_packet_blake3_hex": result.signed_packet_blake3_hex(),
                    "candidates": candidates,
                })
            }
            Err(error) => {
                all_passed = false;
                let mut value = failure_json(&error, started.elapsed().as_micros());
                value["attempt"] = json!(attempt);
                value
            }
        };
        attempts.push(value);
    }
    let shutdown = node.shutdown().await;
    let (shutdown_label, shutdown_passed) = shutdown_policy(&shutdown);
    if !shutdown_passed {
        all_passed = false;
        match &shutdown {
            Ok(ShutdownOutcome::Forced) => {
                eprintln!("iroh_node_lookup_error stage=shutdown error=forced-deadline")
            }
            Err(error) => eprintln!("iroh_node_lookup_error stage=shutdown error={error}"),
            Ok(ShutdownOutcome::Graceful) => unreachable!(),
        }
    }
    println!(
        "{}",
        json!({
            "schema": NODE_LOOKUP_SCHEMA,
            "verdict": if all_passed { "pass" } else { "unavailable" },
            "node_id": config.node_id,
            "attempt_count": config.attempts,
            "attempts": attempts,
            "shutdown": shutdown_label,
        })
    );
    if all_passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_are_bounded_to_repeating_one_identity() {
        assert!(usage().contains("--node-id"));
        assert!(!usage().contains("node-ids"));
        assert!(!usage().contains("peer-list"));
    }

    #[test]
    fn only_graceful_shutdown_can_preserve_a_pass_verdict() {
        assert_eq!(
            shutdown_policy(&Ok(ShutdownOutcome::Graceful)),
            ("graceful", true)
        );
        assert_eq!(
            shutdown_policy(&Ok(ShutdownOutcome::Forced)),
            ("forced", false)
        );
    }
}
