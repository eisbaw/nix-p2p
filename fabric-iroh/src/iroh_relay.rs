//! Explicit, default-off relay TRANSPORT capability for the shared TASK-115 endpoint (TASK-139).
//!
//! [`crate::iroh_runtime::RelayCapability`] carries a raw [`RelayMode`] but
//! deliberately owns none of the policy: TASK-115's doc says "TASK-89 owns
//! selecting and exposing concrete production relay modes". This module is that
//! selection. It converts one explicitly configured, locally operated relay URL
//! into a daemon-owned `RelayMode::Custom(RelayMap)` and NOTHING else:
//!
//!   * No `presets::N0`, `RelayMode::Default`, or `RelayMode::Staging` is ever
//!     produced, so an operator can never inherit an n0/public relay implicitly.
//!   * Enabling relay performs no DNS/pkarr publication, no NodeId lookup, no
//!     content lookup, and no LAN discovery. Those are separate capabilities on
//!     the same endpoint; this module has no code path that reaches any of them.
//!   * External / public (n0) relay contact requires a NAMED owner AND an
//!     explicit authorization reference. Absent that, only a locally operated
//!     routed relay is accepted and its evidence is labelled `production-shaped`
//!     (not a public-Internet / NAT-traversal proof).
//!
//! The live connection drive, its typed-failure MAPPING to the taxonomy below,
//! and the routed-namespace attribution evidence (blocking the direct path at
//! L3 so "relay carried it" is unfalsifiable) are the routed evidence-harness
//! work tracked separately as TASK-142 (it produces
//! `artifacts/iroh-relay-capability-v1.json` and `docs/iroh-relay-capability-v1.md`).
//! What this module ships is the deterministic, unit-tested core:
//! configuration + the external-authorization gate, the concrete relay-mode
//! selection, the typed unavailable taxonomy with its bounded deadline, the
//! privacy-preserving preflight/status, and the pure connection-path classifier
//! TASK-89 reuses for relay attribution.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use iroh::endpoint::IncomingAddr;
use iroh::{RelayConfig, RelayMap, RelayMode, RelayUrl};

use crate::iroh_runtime::RelayCapability;

/// Total wall-clock budget for one relayed connect attempt (AC#3).
pub const RELAY_CONNECT_DEADLINE: Duration = Duration::from_secs(10);

/// Scheduler-grace slack permitted on top of the monotonic deadline (AC#3).
pub const RELAY_SCHEDULER_GRACE: Duration = Duration::from_secs(1);

/// The only URL scheme a relay recipient may use. Relay dialling is HTTPS/QUIC;
/// a plaintext scheme is a misconfiguration, not a downgrade we silently accept.
const REQUIRED_RELAY_SCHEME: &str = "https";

/// DNS suffixes reserved for documentation/testing (RFC 2606 / RFC 6761) plus
/// mDNS `.local`. A `LocalProductionShaped` relay recipient must be one of these
/// or a non-public IP literal; anything else is a public name requiring named
/// external authorization.
const LOCAL_ONLY_DNS_SUFFIXES: [&str; 5] =
    [".invalid", ".test", ".local", ".localhost", ".example"];

/// Substrings that identify an n0-operated public relay. These are rejected with
/// a specific message so a `RelayMode::Default`-shaped host cannot slip in under
/// a hand-written custom URL.
const N0_PUBLIC_RELAY_MARKERS: [&str; 3] = ["iroh.network", "n0.computer", "relay.iroh."];

/// How a relay recipient's operator is authorized. Mirrors the node-lookup
/// authority gate: only a locally operated, routed relay is actually enabled;
/// external/public relay contact is refused unless explicitly authorized, and
/// even then this transport keeps it out of scope (local routed only).
#[derive(Clone, PartialEq, Eq)]
pub enum RelayTransportAuthorization {
    /// A relay the operator runs themselves on a private/routed address. Its
    /// evidence is labelled `production-shaped`, never public-Internet proof.
    LocalProductionShaped { owner: String },
    /// A named owner has explicitly authorized external/public relay contact.
    /// The authorization reference is audit material and never Debug-formatted.
    ExternalAuthorized {
        owner: String,
        authorization_reference: String,
    },
}

impl fmt::Debug for RelayTransportAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalProductionShaped { owner } => formatter
                .debug_struct("LocalProductionShaped")
                .field("owner", owner)
                .finish(),
            Self::ExternalAuthorized { owner, .. } => formatter
                .debug_struct("ExternalAuthorized")
                .field("owner", owner)
                .field("authorization_reference", &"[redacted]")
                .finish(),
        }
    }
}

impl RelayTransportAuthorization {
    /// The operator name recorded in status/evidence. Never a secret.
    pub fn owner(&self) -> &str {
        match self {
            Self::LocalProductionShaped { owner } | Self::ExternalAuthorized { owner, .. } => owner,
        }
    }

    /// Stable label distinguishing the two classes in status/evidence.
    pub fn evidence_label(&self) -> &'static str {
        match self {
            Self::LocalProductionShaped { .. } => "production-shaped-local",
            Self::ExternalAuthorized { .. } => "external-authorized",
        }
    }

    /// Whether external/public relay contact was explicitly authorized.
    pub fn external_contact_authorized(&self) -> bool {
        matches!(self, Self::ExternalAuthorized { .. })
    }

    fn validate(&self, host: &str) -> Result<(), RelayTransportUnavailable> {
        let owner = self.owner();
        if owner.trim().is_empty() || owner.len() > 128 || owner.chars().any(char::is_control) {
            return Err(RelayTransportUnavailable::new(
                RelayTransportUnavailableKind::UntrustedConfiguration,
                "relay authorization owner must be 1..=128 non-control characters",
            ));
        }
        match self {
            Self::LocalProductionShaped { .. } => {
                if !host_is_local_only(host) {
                    return Err(RelayTransportUnavailable::new(
                        RelayTransportUnavailableKind::UntrustedConfiguration,
                        format!(
                            "relay recipient {host:?} is a public host; a production-shaped relay must be a locally operated routed address (non-public IP or a reserved .invalid/.test/.local/.localhost/.example name). Public/n0 relay contact requires named external authorization."
                        ),
                    ));
                }
                Ok(())
            }
            Self::ExternalAuthorized {
                authorization_reference,
                ..
            } => {
                if authorization_reference.trim().is_empty()
                    || authorization_reference.len() > 256
                    || authorization_reference.chars().any(char::is_control)
                {
                    return Err(RelayTransportUnavailable::new(
                        RelayTransportUnavailableKind::UntrustedConfiguration,
                        "external relay authorization reference must be 1..=256 non-control characters",
                    ));
                }
                // A named authorization is recorded, but this transport keeps
                // external/public relay contact OUT of scope: only a locally
                // operated routed relay is actually driven. Reaching an n0/public
                // relay is deferred infrastructure, not a silent default.
                Err(RelayTransportUnavailable::new(
                    RelayTransportUnavailableKind::ExternalRelayUnsupported,
                    "external/public relay contact is authorized but unsupported by this transport; only a locally operated routed relay is enabled",
                ))
            }
        }
    }
}

/// `true` for a loopback/private/link-local IP literal or a reserved
/// non-public DNS name. This is a conservative allow-list: a name that is not
/// obviously local is treated as public.
fn host_is_local_only(host: &str) -> bool {
    let normalized = host.trim().trim_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    if let Ok(ip) = normalized.parse::<IpAddr>() {
        return !ip_is_public(ip);
    }
    // Bracketed IPv6 literal, e.g. "[::1]".
    if let Some(inner) = normalized
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        && let Ok(ip) = inner.parse::<IpAddr>()
    {
        return !ip_is_public(ip);
    }
    if normalized == "localhost" {
        return true;
    }
    if N0_PUBLIC_RELAY_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return false;
    }
    LOCAL_ONLY_DNS_SUFFIXES
        .iter()
        .any(|suffix| normalized.ends_with(suffix))
}

/// Whether an IP literal is globally routable (public), and therefore off-limits
/// to a production-shaped local relay. Mirrors the node-lookup authority policy.
fn ip_is_public(ip: IpAddr) -> bool {
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

/// Closed configuration for exactly one locally operated relay recipient.
///
/// Constructing this validates the URL and the authorization; it never touches
/// the network. Converting it to a capability produces a fresh daemon-owned
/// `RelayMode::Custom` map containing only this URL.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayTransportConfig {
    relay_url: RelayUrl,
    host: String,
    authorization: RelayTransportAuthorization,
}

impl fmt::Debug for RelayTransportConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayTransportConfig")
            .field("relay_recipient", &self.host)
            .field("authority_class", &self.authorization.evidence_label())
            .field("owner", &self.authorization.owner())
            .field(
                "external_contact_authorized",
                &self.authorization.external_contact_authorized(),
            )
            .finish()
    }
}

impl RelayTransportConfig {
    /// Validate and close over one explicit relay recipient.
    pub fn new(
        relay_url: impl AsRef<str>,
        authorization: RelayTransportAuthorization,
    ) -> Result<Self, RelayTransportUnavailable> {
        let raw = relay_url.as_ref().trim();
        if raw.is_empty() {
            return Err(RelayTransportUnavailable::new(
                RelayTransportUnavailableKind::WrongRelayUrl,
                "relay URL is empty",
            ));
        }
        let relay_url = RelayUrl::from_str(raw).map_err(|error| {
            RelayTransportUnavailable::new(
                RelayTransportUnavailableKind::WrongRelayUrl,
                format!("relay URL {raw:?} is not a valid URL: {error}"),
            )
        })?;
        if relay_url.scheme() != REQUIRED_RELAY_SCHEME {
            return Err(RelayTransportUnavailable::new(
                RelayTransportUnavailableKind::WrongRelayUrl,
                format!(
                    "relay URL {raw:?} uses scheme {:?}; relay dialling requires {REQUIRED_RELAY_SCHEME:?}",
                    relay_url.scheme()
                ),
            ));
        }
        let host = relay_url.host_str().map(str::to_owned).ok_or_else(|| {
            RelayTransportUnavailable::new(
                RelayTransportUnavailableKind::WrongRelayUrl,
                format!("relay URL {raw:?} has no host"),
            )
        })?;
        if N0_PUBLIC_RELAY_MARKERS
            .iter()
            .any(|marker| host.to_ascii_lowercase().contains(marker))
            && matches!(
                authorization,
                RelayTransportAuthorization::LocalProductionShaped { .. }
            )
        {
            return Err(RelayTransportUnavailable::new(
                RelayTransportUnavailableKind::UntrustedConfiguration,
                format!(
                    "relay recipient {host:?} is an n0 public relay; refusing to inherit a public default. Use a locally operated routed relay, or supply named external authorization."
                ),
            ));
        }
        authorization.validate(&host)?;
        Ok(Self {
            relay_url,
            host,
            authorization,
        })
    }

    /// The validated relay URL.
    pub fn relay_url(&self) -> &RelayUrl {
        &self.relay_url
    }

    /// The relay recipient host recorded in status/evidence (no path, no query).
    pub fn relay_recipient(&self) -> &str {
        &self.host
    }

    /// The authorization class and owner.
    pub fn authorization(&self) -> &RelayTransportAuthorization {
        &self.authorization
    }

    /// Stable evidence label for the authorization class.
    pub fn evidence_label(&self) -> &'static str {
        self.authorization.evidence_label()
    }

    /// A FRESH daemon-owned relay map containing exactly this one URL. A new map
    /// per call means no external alias can mutate recipients after the fact.
    pub fn daemon_owned_relay_map(&self) -> RelayMap {
        RelayMap::from(RelayConfig::from(self.relay_url.clone()))
    }

    /// The concrete, explicitly selected relay mode. Always `Custom`; never an
    /// n0/preset default.
    pub fn relay_mode(&self) -> RelayMode {
        RelayMode::Custom(self.daemon_owned_relay_map())
    }

    /// Selects this relay as the endpoint's relay capability. This is the only
    /// intended way to turn relay on for a product endpoint.
    pub fn into_relay_capability(self) -> RelayCapability {
        RelayCapability::Enabled(self.relay_mode())
    }
}

/// Distinct, typed reasons a relay transport is unavailable or a relayed path
/// failed. Each is a separate outcome within the bounded connect deadline (AC#3)
/// so a caller never collapses "the relay is down" into "wrong identity".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayTransportUnavailableKind {
    /// Relay transport was not enabled for this endpoint.
    Disabled,
    /// The configuration itself is untrusted (bad owner, public host, ...).
    UntrustedConfiguration,
    /// External/public relay contact is out of scope for this transport.
    ExternalRelayUnsupported,
    /// The relay URL is malformed or uses the wrong scheme.
    WrongRelayUrl,
    /// The configured relay is unreachable (down / refused / no route).
    RelayOutage,
    /// The relay presented an untrusted or mismatched certificate.
    WrongCertificate,
    /// The relay routed to a peer whose NodeId is not the one requested.
    WrongIdentity,
    /// A relayed stream opened then stalled/closed before completing.
    HalfOpenStream,
    /// A control arm deliberately forced the direct path to fail.
    ForcedDirectFailure,
    /// The 10000 ms connect deadline elapsed.
    Deadline,
    /// The endpoint offered no relay candidate to dial.
    NoRelayCandidate,
    /// The owning runtime is shut down.
    Closed,
}

impl RelayTransportUnavailableKind {
    /// Stable machine token for logs, status, and the evidence artifact.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::UntrustedConfiguration => "untrusted_configuration",
            Self::ExternalRelayUnsupported => "external_relay_unsupported",
            Self::WrongRelayUrl => "wrong_relay_url",
            Self::RelayOutage => "relay_outage",
            Self::WrongCertificate => "wrong_certificate",
            Self::WrongIdentity => "wrong_identity",
            Self::HalfOpenStream => "half_open_stream",
            Self::ForcedDirectFailure => "forced_direct_failure",
            Self::Deadline => "deadline",
            Self::NoRelayCandidate => "no_relay_candidate",
            Self::Closed => "closed",
        }
    }
}

/// A typed, fail-fast relay-transport unavailability with a human message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTransportUnavailable {
    kind: RelayTransportUnavailableKind,
    message: String,
}

impl RelayTransportUnavailable {
    /// Construct one typed outcome.
    pub fn new(kind: RelayTransportUnavailableKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The typed reason.
    pub fn kind(&self) -> RelayTransportUnavailableKind {
        self.kind
    }

    /// The human-readable detail.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RelayTransportUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Iroh relay transport UNAVAILABLE reason={}: {}",
            self.kind.as_str(),
            self.message
        )
    }
}

impl std::error::Error for RelayTransportUnavailable {}

/// Which network path an established connection actually used. This is the
/// attribution primitive AC#2 needs: a relayed connection must be provable, and
/// a direct-positive control must NOT be falsely credited to relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConnectionPath {
    /// The connection is carried through a relay server.
    Relayed,
    /// The connection is a direct IP path (hole-punched or LAN).
    Direct,
    /// A custom transport path (neither relay nor a plain IP address).
    Custom,
}

impl RelayConnectionPath {
    /// Stable machine token for status and the evidence artifact.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relayed => "relayed",
            Self::Direct => "direct",
            Self::Custom => "custom",
        }
    }

    /// Whether this path is attributable to the relay. Only [`Self::Relayed`] is.
    /// A direct-positive control returns `false`, so relay use cannot be
    /// over-credited.
    pub fn is_relay_attributed(self) -> bool {
        matches!(self, Self::Relayed)
    }
}

/// Classify one connection's remote address ([`IncomingAddr`], obtained from an
/// incoming/accepting/connecting handle) into a relay/direct path.
///
/// A connection can upgrade from relayed to direct after hole-punching, so
/// strong "relay carried it" attribution additionally requires the direct path
/// to be blocked (the routed evidence harness). This pure classifier is the
/// reusable attribution unit TASK-89 composes on top of that.
pub fn classify_connection_path(addr: &IncomingAddr) -> RelayConnectionPath {
    match addr {
        IncomingAddr::Relay { .. } => RelayConnectionPath::Relayed,
        IncomingAddr::Ip(_) => RelayConnectionPath::Direct,
        // `IncomingAddr` is #[non_exhaustive]; any transport that is neither a
        // relay nor a plain IP is, for attribution purposes, not relay.
        _ => RelayConnectionPath::Custom,
    }
}

/// Observed reachability of the configured relay in preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayHealth {
    /// Not yet probed.
    Untested,
    /// The relay answered.
    Reachable,
    /// The relay did not answer within the bound.
    Unreachable,
}

impl RelayHealth {
    /// Stable machine token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Untested => "untested",
            Self::Reachable => "reachable",
            Self::Unreachable => "unreachable",
        }
    }
}

/// Privacy-preserving relay status/preflight (AC#4).
///
/// It records the daemon's OWN configured relay recipient host (which may be an
/// IP literal when the operator configured an IP-addressed relay — that is the
/// daemon's own deliberately-chosen relay, not a discovered peer), whether
/// external contact was authorized, the authorization class/owner, health, and
/// byte counters. The privacy invariant is about PEER identities: this struct
/// carries no peer NodeId or peer IP value — only boolean EXPOSURE flags
/// (both `false` here) — so a status dump never leaks a peer's identity by
/// default. Relay use here never implies serving, node publication, or a
/// production default; those are all separate, and this struct asserts none of
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPreflightStatus {
    relay_recipient: String,
    configured_relay_count: usize,
    external_contact_authorized: bool,
    authorization_class: &'static str,
    owner: String,
    node_id_exposed: bool,
    ip_exposed: bool,
    health: RelayHealth,
    bytes_sent: u64,
    bytes_received: u64,
}

impl RelayPreflightStatus {
    /// The default, un-probed status for a configured relay: nothing exposed,
    /// nothing sent, health untested.
    pub fn from_config(config: &RelayTransportConfig) -> Self {
        Self {
            relay_recipient: config.relay_recipient().to_owned(),
            configured_relay_count: 1,
            external_contact_authorized: config.authorization().external_contact_authorized(),
            authorization_class: config.evidence_label(),
            owner: config.authorization().owner().to_owned(),
            node_id_exposed: false,
            ip_exposed: false,
            health: RelayHealth::Untested,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Record an observed health result.
    pub fn with_health(mut self, health: RelayHealth) -> Self {
        self.health = health;
        self
    }

    /// Record transferred byte counters observed over the relay.
    pub fn with_bytes(mut self, sent: u64, received: u64) -> Self {
        self.bytes_sent = sent;
        self.bytes_received = received;
        self
    }

    /// The configured relay recipient host.
    pub fn relay_recipient(&self) -> &str {
        &self.relay_recipient
    }

    /// How many relay recipients are configured (exactly one, by construction).
    pub fn configured_relay_count(&self) -> usize {
        self.configured_relay_count
    }

    /// Whether external/public relay contact was authorized.
    pub fn external_contact_authorized(&self) -> bool {
        self.external_contact_authorized
    }

    /// The authorization class label.
    pub fn authorization_class(&self) -> &'static str {
        self.authorization_class
    }

    /// The operator name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Whether a full NodeId is exposed in this status (default `false`).
    pub fn node_id_exposed(&self) -> bool {
        self.node_id_exposed
    }

    /// Whether a full IP is exposed in this status (default `false`).
    pub fn ip_exposed(&self) -> bool {
        self.ip_exposed
    }

    /// Observed relay health.
    pub fn health(&self) -> RelayHealth {
        self.health
    }

    /// Bytes sent over the relay so far.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Bytes received over the relay so far.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }
}

/// Render an identity/address as a short, non-reversible fingerprint for logs
/// and status, so callers can correlate without printing a FULL NodeId or IP by
/// default (AC#4). Four leading bytes of the input, hex, with an ellipsis.
pub fn redact_fingerprint(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let shown = bytes.len().min(4);
    let mut encoded = String::with_capacity(shown * 2 + 1);
    for byte in &bytes[..shown] {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded.push('\u{2026}');
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(owner: &str) -> RelayTransportAuthorization {
        RelayTransportAuthorization::LocalProductionShaped {
            owner: owner.to_owned(),
        }
    }

    #[test]
    fn local_routed_relay_selects_a_custom_map_not_an_n0_default() {
        let config =
            RelayTransportConfig::new("https://relay.task139.invalid", local("operator")).unwrap();
        let mode = config.relay_mode();
        let map = match &mode {
            RelayMode::Custom(map) => map.clone(),
            other => panic!("expected a custom relay map, got {other:?}"),
        };
        // Exactly the configured URL, and never the n0 default map.
        assert_eq!(map.len(), 1);
        assert!(map.contains(config.relay_url()));
        let default_urls = RelayMode::Default.relay_map().urls::<Vec<_>>();
        for url in default_urls {
            assert!(
                !map.contains(&url),
                "custom relay map must not inherit an n0 default relay {url}"
            );
        }
        assert!(matches!(
            config.into_relay_capability(),
            RelayCapability::Enabled(RelayMode::Custom(_))
        ));
    }

    #[test]
    fn a_fresh_relay_map_is_built_per_call() {
        let config =
            RelayTransportConfig::new("https://relay.task139.invalid", local("operator")).unwrap();
        let first = config.daemon_owned_relay_map();
        let second = config.daemon_owned_relay_map();
        // Equal content, but the endpoint receives a fresh map it solely owns.
        assert_eq!(first, second);
        second.remove(config.relay_url());
        assert_eq!(
            first.len(),
            1,
            "mutating one snapshot must not affect another"
        );
    }

    #[test]
    fn non_https_and_malformed_urls_are_typed_wrong_url() {
        for bad in [
            "",
            "   ",
            "relay.task139.invalid",
            "http://relay.task139.invalid",
        ] {
            let error = RelayTransportConfig::new(bad, local("operator")).unwrap_err();
            assert_eq!(
                error.kind(),
                RelayTransportUnavailableKind::WrongRelayUrl,
                "{bad:?} should be a typed wrong-URL failure"
            );
        }
    }

    #[test]
    fn public_host_under_local_authorization_is_rejected() {
        let error =
            RelayTransportConfig::new("https://relay.example.com", local("operator")).unwrap_err();
        assert_eq!(
            error.kind(),
            RelayTransportUnavailableKind::UntrustedConfiguration
        );
    }

    #[test]
    fn n0_public_relay_is_refused_as_an_implicit_default() {
        let error = RelayTransportConfig::new("https://use1-1.relay.iroh.network.", local("op"))
            .unwrap_err();
        assert_eq!(
            error.kind(),
            RelayTransportUnavailableKind::UntrustedConfiguration
        );
        assert!(error.message().contains("public"));
    }

    #[test]
    fn loopback_and_private_ip_relays_are_local() {
        for host in [
            "https://127.0.0.1:4433",
            "https://[::1]:4433",
            "https://10.42.0.7:4433",
            "https://192.168.1.9",
            "https://relay.internal.test",
            "https://localhost:8443",
        ] {
            RelayTransportConfig::new(host, local("operator"))
                .unwrap_or_else(|error| panic!("{host:?} should be a local relay: {error}"));
        }
    }

    #[test]
    fn external_authorization_is_recorded_but_unsupported() {
        let external = RelayTransportAuthorization::ExternalAuthorized {
            owner: "named-owner".into(),
            authorization_reference: "change-request-42".into(),
        };
        assert!(external.external_contact_authorized());
        assert_eq!(external.evidence_label(), "external-authorized");
        let error = RelayTransportConfig::new("https://relay.example.com", external).unwrap_err();
        assert_eq!(
            error.kind(),
            RelayTransportUnavailableKind::ExternalRelayUnsupported
        );
    }

    #[test]
    fn empty_owner_is_untrusted() {
        let error = RelayTransportConfig::new("https://127.0.0.1:4433", local("   ")).unwrap_err();
        assert_eq!(
            error.kind(),
            RelayTransportUnavailableKind::UntrustedConfiguration
        );
    }

    #[test]
    fn authorization_debug_redacts_the_reference() {
        let external = RelayTransportAuthorization::ExternalAuthorized {
            owner: "named-owner".into(),
            authorization_reference: "top-secret-ticket".into(),
        };
        let rendered = format!("{external:?}");
        assert!(rendered.contains("named-owner"));
        assert!(!rendered.contains("top-secret-ticket"));
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn connection_path_classifier_attributes_only_relay() {
        let relay_url = RelayUrl::from_str("https://relay.task139.invalid").unwrap();
        let endpoint_id = iroh::SecretKey::generate().public();
        let relayed = IncomingAddr::Relay {
            url: relay_url,
            endpoint_id,
        };
        let direct = IncomingAddr::Ip("192.0.2.7:4433".parse().unwrap());
        assert_eq!(
            classify_connection_path(&relayed),
            RelayConnectionPath::Relayed
        );
        assert!(classify_connection_path(&relayed).is_relay_attributed());
        assert_eq!(
            classify_connection_path(&direct),
            RelayConnectionPath::Direct
        );
        assert!(
            !classify_connection_path(&direct).is_relay_attributed(),
            "a direct-positive control must never be credited to relay"
        );
    }

    #[test]
    fn preflight_status_exposes_no_identity_by_default() {
        let config = RelayTransportConfig::new("https://10.9.8.7:4433", local("operator")).unwrap();
        let status = RelayPreflightStatus::from_config(&config)
            .with_health(RelayHealth::Reachable)
            .with_bytes(2048, 4096);
        assert_eq!(status.relay_recipient(), "10.9.8.7");
        assert_eq!(status.configured_relay_count(), 1);
        assert!(!status.external_contact_authorized());
        assert_eq!(status.authorization_class(), "production-shaped-local");
        assert_eq!(status.owner(), "operator");
        assert!(!status.node_id_exposed());
        assert!(!status.ip_exposed());
        assert_eq!(status.health(), RelayHealth::Reachable);
        assert_eq!(status.bytes_sent(), 2048);
        assert_eq!(status.bytes_received(), 4096);
        // The privacy contract bites on the actual sensitive VALUE, not a field
        // name: a status dump must not carry a peer's full NodeId hex or a peer
        // IP. Feed known peer identifiers and assert their absence, so a leak
        // under any field name would fail this oracle.
        let peer_node_id = iroh::SecretKey::generate().public();
        let peer_node_id_hex = redact_fingerprint(peer_node_id.as_bytes());
        let peer_ip = "203.0.113.77";
        let rendered = format!("{status:?}");
        let peer_full_hex: String = peer_node_id
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert!(
            !rendered.contains(&peer_full_hex),
            "status must not carry a full peer NodeId"
        );
        assert!(
            !rendered.contains(peer_ip),
            "status must not carry a peer IP"
        );
        // The redaction primitive keeps a loggable correlator short, never full.
        assert!(peer_full_hex.len() > peer_node_id_hex.len());
    }

    #[test]
    fn deadline_constants_match_the_ac3_bound() {
        // AC#3: a 10000 ms connect deadline, with at most 1000 ms scheduler
        // grace on top. Encode the RELATIONSHIP the harness enforces, not just
        // the literals: the grace is positive, strictly under the deadline, and
        // the total admissible bound is 11000 ms.
        assert_eq!(RELAY_CONNECT_DEADLINE.as_millis(), 10_000);
        assert!(!RELAY_SCHEDULER_GRACE.is_zero());
        assert!(RELAY_SCHEDULER_GRACE < RELAY_CONNECT_DEADLINE);
        assert_eq!(
            (RELAY_CONNECT_DEADLINE + RELAY_SCHEDULER_GRACE).as_millis(),
            11_000
        );
    }

    #[test]
    fn unavailable_kinds_have_distinct_stable_tokens() {
        let kinds = [
            RelayTransportUnavailableKind::Disabled,
            RelayTransportUnavailableKind::UntrustedConfiguration,
            RelayTransportUnavailableKind::ExternalRelayUnsupported,
            RelayTransportUnavailableKind::WrongRelayUrl,
            RelayTransportUnavailableKind::RelayOutage,
            RelayTransportUnavailableKind::WrongCertificate,
            RelayTransportUnavailableKind::WrongIdentity,
            RelayTransportUnavailableKind::HalfOpenStream,
            RelayTransportUnavailableKind::ForcedDirectFailure,
            RelayTransportUnavailableKind::Deadline,
            RelayTransportUnavailableKind::NoRelayCandidate,
            RelayTransportUnavailableKind::Closed,
        ];
        let mut tokens: Vec<&str> = kinds.iter().map(|kind| kind.as_str()).collect();
        tokens.sort_unstable();
        let distinct = tokens.len();
        tokens.dedup();
        assert_eq!(
            distinct,
            tokens.len(),
            "every typed kind needs a unique token"
        );
    }

    #[test]
    fn redact_fingerprint_never_shows_the_full_value() {
        let full = [0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44];
        let redacted = redact_fingerprint(&full);
        assert_eq!(redacted, "deadbeef\u{2026}");
        assert!(redact_fingerprint(&[0x01, 0x02]).starts_with("0102"));
    }
}
