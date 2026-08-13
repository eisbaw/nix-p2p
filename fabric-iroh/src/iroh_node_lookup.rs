//! Strict, explicitly enabled NodeId-to-address lookup over the Task137 pkarr authority.
//!
//! This capability has one operation: resolve one asker-supplied [`NodeId`]. It
//! cannot enumerate identities, publish this endpoint, discover content, enable
//! a relay transport, or activate LAN discovery. Every call performs one pinned
//! GET and validates the signed lifecycle record; accepted data is retained only
//! as bounded runtime-lifetime replay state and is never served after a network
//! error.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant as MonotonicInstant, SystemTime, UNIX_EPOCH};

use iroh::address_lookup::{AddressLookup, Error as IrohLookupError, Item as IrohLookupItem};
use iroh::{EndpointAddr, EndpointId, PublicKey, TransportAddr};
use iroh_dns::pkarr::{SignedPacket, SignedPacketVerifyError};
use n0_future::boxed::BoxStream;
use tokio::sync::{Mutex, MutexGuard};
use tokio::time::Instant;

use crate::iroh_node_record::{
    MAX_NODE_LOCATIONS, NODE_PUBLICATION_SCHEMA, NodeLocation, NodeRecord, NodeRecordErrorKind,
    PublicationState, decode_node_record, validate_namespace, validate_recipient,
};
use crate::iroh_runtime::{IrohRuntimeError, TaskSupervisorHandle};
use crate::pinned_http::{PinnedHttpEndpoint, PinnedHttpError, PinnedHttpErrorKind};
use peer_fabric::NodeId;

pub const NODE_LOOKUP_SCHEMA: &str = "iroh-node-lookup-v1";
pub const NODE_LOOKUP_SOURCE: &str = "pinned-pkarr-http";
pub const NODE_LOOKUP_PROVENANCE: &str = "nix-p2p-pkarr-node-lookup-v1";
pub const NODE_LOOKUP_DEADLINE: Duration = Duration::from_secs(10);
pub const NODE_LOOKUP_SCHEDULER_GRACE: Duration = Duration::from_secs(1);
pub const MAX_NODE_LOOKUP_TRACKED_IDS: usize = 1024;

/// Authority ownership is explicit and plain HTTP remains local/private only.
#[derive(Clone, PartialEq, Eq)]
pub enum NodeLookupAuthorityAuthorization {
    LocalProductionShaped {
        owner: String,
    },
    ExternalAuthorized {
        owner: String,
        authorization_reference: String,
    },
}

impl fmt::Debug for NodeLookupAuthorityAuthorization {
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

impl NodeLookupAuthorityAuthorization {
    fn validate(&self, recipient: SocketAddr) -> Result<(), NodeLookupUnavailable> {
        let owner = self.owner();
        if owner.trim().is_empty() || owner.len() > 128 || owner.chars().any(char::is_control) {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::UntrustedConfiguration,
                "lookup authority owner must be 1..=128 non-control characters",
            ));
        }
        match self {
            Self::LocalProductionShaped { .. } => {
                if is_public_ip(recipient.ip()) {
                    return Err(NodeLookupUnavailable::new(
                        NodeLookupUnavailableKind::UntrustedConfiguration,
                        format!(
                            "public lookup authority recipient {recipient} requires named external authorization"
                        ),
                    ));
                }
            }
            Self::ExternalAuthorized {
                authorization_reference,
                ..
            } => {
                if authorization_reference.trim().is_empty()
                    || authorization_reference.len() > 256
                    || authorization_reference.chars().any(char::is_control)
                {
                    return Err(NodeLookupUnavailable::new(
                        NodeLookupUnavailableKind::UntrustedConfiguration,
                        "external authorization reference must be 1..=256 non-control characters",
                    ));
                }
                return Err(NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::ExternalAuthorityUnsupported,
                    "external pkarr lookup is unsupported over pinned plaintext HTTP; only a locally operated private routed authority is enabled",
                ));
            }
        }
        Ok(())
    }

    pub fn owner(&self) -> &str {
        match self {
            Self::LocalProductionShaped { owner } | Self::ExternalAuthorized { owner, .. } => owner,
        }
    }

    pub fn evidence_label(&self) -> &'static str {
        match self {
            Self::LocalProductionShaped { .. } => "production-shaped-local",
            Self::ExternalAuthorized { .. } => "external-authorized",
        }
    }
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

/// Closed configuration for exactly one locally operated lookup authority.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeLookupConfig {
    namespace: String,
    signed_recipient: String,
    authority_recipient: SocketAddr,
    authority_host: String,
    authorization: NodeLookupAuthorityAuthorization,
}

impl fmt::Debug for NodeLookupConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeLookupConfig")
            .field("namespace", &self.namespace)
            .field("signed_recipient", &self.signed_recipient)
            .field("authority_private", &true)
            .field("authority_class", &self.authorization.evidence_label())
            .field("owner", &self.authorization.owner())
            .finish()
    }
}

impl NodeLookupConfig {
    pub fn new(
        namespace: impl Into<String>,
        signed_recipient: impl Into<String>,
        authority_recipient: SocketAddr,
        authority_host: impl Into<String>,
        authorization: NodeLookupAuthorityAuthorization,
    ) -> Result<Self, NodeLookupUnavailable> {
        let namespace = namespace.into();
        if namespace.is_empty() {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::UntrustedConfiguration,
                "lookup namespace is empty",
            ));
        }
        validate_namespace(&namespace).map_err(|error| {
            NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::UntrustedConfiguration,
                format!("invalid lookup namespace: {error}"),
            )
        })?;
        let signed_recipient = signed_recipient.into();
        validate_recipient(&signed_recipient).map_err(|error| {
            NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::UntrustedConfiguration,
                format!("invalid signed lookup recipient: {error}"),
            )
        })?;
        let authority_host = authority_host.into();
        let endpoint = PinnedHttpEndpoint::new(authority_recipient, authority_host.clone())
            .map_err(|error| {
                NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::UntrustedConfiguration,
                    format!("invalid pinned lookup authority: {error}"),
                )
            })?;
        authorization.validate(endpoint.recipient())?;
        Ok(Self {
            namespace,
            signed_recipient,
            authority_recipient: endpoint.recipient(),
            authority_host,
            authorization,
        })
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn signed_recipient(&self) -> &str {
        &self.signed_recipient
    }

    pub fn authority_recipient(&self) -> SocketAddr {
        self.authority_recipient
    }

    pub fn authority_host(&self) -> &str {
        &self.authority_host
    }

    pub fn authorization(&self) -> &NodeLookupAuthorityAuthorization {
        &self.authorization
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeLookupUnavailableKind {
    Disabled,
    InvalidNodeId,
    EmptyNamespace,
    UntrustedConfiguration,
    ExternalAuthorityUnsupported,
    AuthorityStatus,
    AuthorityConnectionRefused,
    AuthorityConnect,
    AuthorityWrite,
    AuthorityRead,
    AuthorityProtocol,
    Deadline,
    BadSignature,
    MalformedOrUntrustedRecord,
    NamespaceMismatch,
    RecipientMismatch,
    NodeIdMismatch,
    StaleSequence,
    ConflictingReplay,
    Expired,
    Withdrawn,
    NoDialableCandidate,
    Capacity,
    ClockRollback,
    Closed,
}

impl NodeLookupUnavailableKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::InvalidNodeId => "invalid_node_id",
            Self::EmptyNamespace => "empty_namespace",
            Self::UntrustedConfiguration => "untrusted_configuration",
            Self::ExternalAuthorityUnsupported => "external_authority_unsupported",
            Self::AuthorityStatus => "authority_status",
            Self::AuthorityConnectionRefused => "authority_connection_refused",
            Self::AuthorityConnect => "authority_connect",
            Self::AuthorityWrite => "authority_write",
            Self::AuthorityRead => "authority_read",
            Self::AuthorityProtocol => "authority_protocol",
            Self::Deadline => "deadline",
            Self::BadSignature => "bad_signature",
            Self::MalformedOrUntrustedRecord => "malformed_or_untrusted_record",
            Self::NamespaceMismatch => "namespace_mismatch",
            Self::RecipientMismatch => "recipient_mismatch",
            Self::NodeIdMismatch => "node_id_mismatch",
            Self::StaleSequence => "stale_sequence",
            Self::ConflictingReplay => "conflicting_replay",
            Self::Expired => "expired",
            Self::Withdrawn => "withdrawn",
            Self::NoDialableCandidate => "no_dialable_candidate",
            Self::Capacity => "capacity",
            Self::ClockRollback => "clock_rollback",
            Self::Closed => "closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLookupUnavailable {
    kind: NodeLookupUnavailableKind,
    message: String,
    validated_signed_packet: Option<(u64, String)>,
}

impl NodeLookupUnavailable {
    pub fn new(kind: NodeLookupUnavailableKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            validated_signed_packet: None,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn kind(&self) -> NodeLookupUnavailableKind {
        self.kind
    }

    fn with_validated_signed_packet(mut self, sequence: u64, packet_hash: [u8; 32]) -> Self {
        self.validated_signed_packet = Some((sequence, hex(&packet_hash)));
        self
    }

    pub fn validated_sequence(&self) -> Option<u64> {
        self.validated_signed_packet
            .as_ref()
            .map(|(sequence, _)| *sequence)
    }

    pub fn validated_signed_packet_blake3_hex(&self) -> Option<&str> {
        self.validated_signed_packet
            .as_ref()
            .map(|(_, packet_hash)| packet_hash.as_str())
    }

    pub fn invalid_node_id(error: impl fmt::Display) -> Self {
        Self::new(
            NodeLookupUnavailableKind::InvalidNodeId,
            format!("invalid asker-supplied NodeId: {error}"),
        )
    }
}

impl fmt::Display for NodeLookupUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Iroh node lookup UNAVAILABLE reason={}: {}",
            self.kind.as_str(),
            self.message
        )
    }
}

impl std::error::Error for NodeLookupUnavailable {}

/// Validated result for exactly one requested NodeId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLookupResult {
    lookup_schema: &'static str,
    record_schema: &'static str,
    source: &'static str,
    provenance: NodeLookupProvenance,
    node_id: NodeId,
    namespace: String,
    recipient: String,
    ttl_seconds: u32,
    sequence: u64,
    expires_unix_micros: u64,
    candidates: Vec<NodeLocation>,
    signed_packet_blake3_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeLookupProvenance {
    /// This invocation completed a new pinned GET and verified its exact bytes.
    NetworkValidated,
}

impl NodeLookupProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NetworkValidated => "network_validated",
        }
    }
}

impl NodeLookupResult {
    fn from_record(record: NodeRecord, packet_hash: [u8; 32]) -> Self {
        Self {
            lookup_schema: NODE_LOOKUP_SCHEMA,
            record_schema: NODE_PUBLICATION_SCHEMA,
            source: NODE_LOOKUP_SOURCE,
            provenance: NodeLookupProvenance::NetworkValidated,
            node_id: record.node_id,
            namespace: record.namespace,
            recipient: record.recipient,
            ttl_seconds: record.ttl_seconds,
            sequence: record.sequence,
            expires_unix_micros: record.expires_unix_micros,
            candidates: record.locations,
            signed_packet_blake3_hex: hex(&packet_hash),
        }
    }

    pub fn lookup_schema(&self) -> &'static str {
        self.lookup_schema
    }

    pub fn record_schema(&self) -> &'static str {
        self.record_schema
    }

    pub fn source(&self) -> &'static str {
        self.source
    }

    pub fn provenance(&self) -> NodeLookupProvenance {
        self.provenance
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    pub fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn expires_unix_micros(&self) -> u64 {
        self.expires_unix_micros
    }

    pub fn candidates(&self) -> &[NodeLocation] {
        &self.candidates
    }

    pub fn signed_packet_blake3_hex(&self) -> &str {
        &self.signed_packet_blake3_hex
    }

    pub fn endpoint_addr(&self) -> Result<EndpointAddr, NodeLookupUnavailable> {
        let public_key = PublicKey::from_bytes(self.node_id.as_bytes()).map_err(|error| {
            NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::InvalidNodeId,
                format!("resolved NodeId is not an Ed25519 public key: {error}"),
            )
        })?;
        let mut addresses = Vec::with_capacity(self.candidates.len());
        for candidate in &self.candidates {
            match candidate {
                NodeLocation::Direct(address) => addresses.push(TransportAddr::Ip(*address)),
                NodeLocation::Relay(url) => {
                    let relay = url.parse().map_err(|error| {
                        NodeLookupUnavailable::new(
                            NodeLookupUnavailableKind::MalformedOrUntrustedRecord,
                            format!("validated relay URL cannot enter Iroh: {error}"),
                        )
                    })?;
                    addresses.push(TransportAddr::Relay(relay));
                }
            }
        }
        Ok(EndpointAddr::from_parts(public_key, addresses))
    }
}

trait LookupClock: Send + Sync + 'static {
    fn read(&self) -> Result<ClockReading, NodeLookupUnavailable>;
}

#[derive(Debug)]
struct SystemLookupClock;

impl LookupClock for SystemLookupClock {
    fn read(&self) -> Result<ClockReading, NodeLookupUnavailable> {
        let wall_unix_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::ClockRollback,
                    format!("system clock is before Unix epoch: {error}"),
                )
            })?
            .as_micros()
            .try_into()
            .map_err(|_| {
                NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::ClockRollback,
                    "system clock exceeds u64 microseconds",
                )
            })?;
        Ok(ClockReading {
            wall_unix_micros,
            monotonic: MonotonicInstant::now(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct ClockReading {
    wall_unix_micros: u64,
    monotonic: MonotonicInstant,
}

#[derive(Debug, Clone)]
struct HighWater {
    sequence: u64,
    packet_hash: [u8; 32],
    observed_monotonic: MonotonicInstant,
    valid_for_at_observation: Duration,
    cached: Option<NodeLookupResult>,
}

#[derive(Debug, Default)]
struct LookupState {
    high_water: HashMap<NodeId, HighWater>,
    last_wall_unix_micros: Option<u64>,
}

struct NodeLookupCore {
    config: NodeLookupConfig,
    endpoint: PinnedHttpEndpoint,
    state: Mutex<LookupState>,
    clock: Arc<dyn LookupClock>,
    closed: AtomicBool,
    capacity: usize,
}

impl fmt::Debug for NodeLookupCore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeLookupCore")
            .field("config", &self.config)
            .field("closed", &self.closed.load(Ordering::Acquire))
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl NodeLookupCore {
    fn new(config: NodeLookupConfig) -> Result<Self, NodeLookupUnavailable> {
        Self::new_with_clock_and_capacity(
            config,
            Arc::new(SystemLookupClock),
            MAX_NODE_LOOKUP_TRACKED_IDS,
        )
    }

    fn new_with_clock_and_capacity(
        config: NodeLookupConfig,
        clock: Arc<dyn LookupClock>,
        capacity: usize,
    ) -> Result<Self, NodeLookupUnavailable> {
        if capacity == 0 {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::UntrustedConfiguration,
                "node lookup replay capacity must be positive",
            ));
        }
        let endpoint =
            PinnedHttpEndpoint::new(config.authority_recipient, config.authority_host.clone())
                .map_err(|error| {
                    NodeLookupUnavailable::new(
                        NodeLookupUnavailableKind::UntrustedConfiguration,
                        format!("invalid pinned lookup endpoint: {error}"),
                    )
                })?;
        Ok(Self {
            config,
            endpoint,
            state: Mutex::new(LookupState::default()),
            clock,
            closed: AtomicBool::new(false),
            capacity,
        })
    }

    async fn preflight(
        &self,
        node_id: NodeId,
        absolute_deadline: Instant,
    ) -> Result<(), NodeLookupUnavailable> {
        if self.closed.load(Ordering::Acquire) {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::Closed,
                "node lookup runtime is closed",
            ));
        }
        let mut state = self
            .lock_state_until(absolute_deadline, "before network admission")
            .await?;
        if self.closed.load(Ordering::Acquire) {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::Closed,
                "node lookup runtime closed while waiting for replay state",
            ));
        }
        self.read_and_observe_clock(&mut state)?;
        if !state.high_water.contains_key(&node_id) && state.high_water.len() >= self.capacity {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::Capacity,
                format!(
                    "node lookup replay table is full at {} identities",
                    self.capacity
                ),
            ));
        }
        drop(state);
        Ok(())
    }

    /// Read and observe the wall clock while the caller owns replay state.
    ///
    /// Serializing those two operations is essential: reading before locking
    /// lets a delayed older observation arrive after a newer concurrent one
    /// and falsely report a system-clock rollback.
    fn read_and_observe_clock(
        &self,
        state: &mut LookupState,
    ) -> Result<ClockReading, NodeLookupUnavailable> {
        let reading = self.clock.read()?;
        observe_wall_clock(state, reading.wall_unix_micros)?;
        Ok(reading)
    }

    async fn lock_state_until(
        &self,
        absolute_deadline: Instant,
        phase: &'static str,
    ) -> Result<MutexGuard<'_, LookupState>, NodeLookupUnavailable> {
        let state = tokio::time::timeout_at(absolute_deadline, self.state.lock())
            .await
            .map_err(|_| {
                NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::Deadline,
                    format!(
                        "node lookup exhausted its absolute 10000 ms deadline waiting for replay state {phase}"
                    ),
                )
            })?;
        if Instant::now() >= absolute_deadline {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::Deadline,
                format!(
                    "node lookup exhausted its absolute 10000 ms deadline waiting for replay state {phase}"
                ),
            ));
        }
        Ok(state)
    }

    async fn resolve(
        &self,
        node_id: NodeId,
        public_key: PublicKey,
        absolute_deadline: Instant,
    ) -> Result<NodeLookupResult, NodeLookupUnavailable> {
        self.preflight(node_id, absolute_deadline).await?;
        if Instant::now() >= absolute_deadline {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::Deadline,
                "node lookup exhausted its absolute 10000 ms deadline before network admission",
            ));
        }
        let response = self
            .endpoint
            .get_record_raw_until(&public_key, absolute_deadline)
            .await
            .map_err(map_http_error)?;
        if Instant::now() >= absolute_deadline {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::Deadline,
                "node lookup exhausted its absolute 10000 ms deadline",
            ));
        }
        match response.status {
            200 => {}
            404 => {
                return Err(NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::EmptyNamespace,
                    format!("authority namespace has no record for NodeId {node_id}"),
                ));
            }
            status => {
                return Err(NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::AuthorityStatus,
                    format!("lookup authority returned HTTP status {status}"),
                ));
            }
        }

        let signed = SignedPacket::from_relay_payload(&public_key, &response.body)
            .map_err(map_signed_packet_error)?;
        if signed.public_key() != public_key {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::BadSignature,
                "verified packet signer differs from asker-supplied NodeId",
            ));
        }
        let packet_hash = *blake3::hash(signed.as_bytes()).as_bytes();
        let record = decode_node_record(signed.as_bytes()).map_err(|error| {
            let kind = match error.kind() {
                NodeRecordErrorKind::NoDialableCandidate => {
                    NodeLookupUnavailableKind::NoDialableCandidate
                }
                NodeRecordErrorKind::MalformedOrUntrusted => {
                    NodeLookupUnavailableKind::MalformedOrUntrustedRecord
                }
            };
            NodeLookupUnavailable::new(kind, format!("signed node record rejected: {error}"))
        })?;
        if record.node_id != node_id {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::NodeIdMismatch,
                format!(
                    "signed record NodeId {} differs from requested {node_id}",
                    record.node_id
                ),
            ));
        }
        if record.namespace != self.config.namespace {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::NamespaceMismatch,
                format!(
                    "signed namespace {:?} differs from configured {:?}",
                    record.namespace, self.config.namespace
                ),
            ));
        }
        if record.recipient != self.config.signed_recipient {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::RecipientMismatch,
                format!(
                    "signed recipient {:?} differs from configured {:?}",
                    record.recipient, self.config.signed_recipient
                ),
            ));
        }
        if record.locations.len() > MAX_NODE_LOCATIONS {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::MalformedOrUntrustedRecord,
                format!(
                    "record has {} candidates, maximum is {MAX_NODE_LOCATIONS}",
                    record.locations.len()
                ),
            ));
        }
        let sequence = record.sequence;
        if Instant::now() >= absolute_deadline {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::Deadline,
                "node lookup exhausted its absolute 10000 ms deadline during signed-record validation",
            )
            .with_validated_signed_packet(sequence, packet_hash));
        }
        let mut state = self
            .lock_state_until(absolute_deadline, "after signed-record validation")
            .await
            .map_err(|error| error.with_validated_signed_packet(sequence, packet_hash))?;
        let reading = self
            .read_and_observe_clock(&mut state)
            .map_err(|error| error.with_validated_signed_packet(sequence, packet_hash))?;
        let outcome = validate_and_advance(
            &mut state,
            self.capacity,
            node_id,
            record,
            packet_hash,
            reading,
        );
        drop(state);
        if Instant::now() >= absolute_deadline {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::Deadline,
                "node lookup exhausted its absolute 10000 ms deadline during replay/freshness validation",
            )
            .with_validated_signed_packet(sequence, packet_hash));
        }
        outcome.map_err(|error| error.with_validated_signed_packet(sequence, packet_hash))
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

fn observe_wall_clock(
    state: &mut LookupState,
    wall_unix_micros: u64,
) -> Result<(), NodeLookupUnavailable> {
    if let Some(previous) = state.last_wall_unix_micros
        && wall_unix_micros < previous
    {
        return Err(NodeLookupUnavailable::new(
            NodeLookupUnavailableKind::ClockRollback,
            format!("wall clock moved backward from {previous} to {wall_unix_micros} microseconds"),
        ));
    }
    state.last_wall_unix_micros = Some(wall_unix_micros);
    Ok(())
}

fn validate_and_advance(
    state: &mut LookupState,
    capacity: usize,
    node_id: NodeId,
    record: NodeRecord,
    packet_hash: [u8; 32],
    reading: ClockReading,
) -> Result<NodeLookupResult, NodeLookupUnavailable> {
    if record.sequence
        > reading
            .wall_unix_micros
            .saturating_add(NODE_LOOKUP_SCHEDULER_GRACE.as_micros() as u64)
    {
        return Err(NodeLookupUnavailable::new(
            NodeLookupUnavailableKind::MalformedOrUntrustedRecord,
            format!(
                "record sequence {} is more than {:?} in the future",
                record.sequence, NODE_LOOKUP_SCHEDULER_GRACE
            ),
        ));
    }

    if let Some(existing) = state.high_water.get(&node_id) {
        if record.sequence < existing.sequence {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::StaleSequence,
                format!(
                    "record sequence {} is below runtime high-water {}",
                    record.sequence, existing.sequence
                ),
            ));
        }
        if record.sequence == existing.sequence && packet_hash != existing.packet_hash {
            return Err(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::ConflictingReplay,
                format!(
                    "record sequence {} conflicts with a different signed packet",
                    record.sequence
                ),
            ));
        }
        if record.sequence == existing.sequence {
            let monotonic_expired = reading
                .monotonic
                .saturating_duration_since(existing.observed_monotonic)
                >= existing.valid_for_at_observation;
            if reading.wall_unix_micros >= record.expires_unix_micros || monotonic_expired {
                return Err(NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::Expired,
                    format!("record sequence {} is expired", record.sequence),
                ));
            }
            if let Some(cached) = &existing.cached {
                return Ok(cached.clone());
            }
            return record_state_error(&record);
        }
    } else if state.high_water.len() >= capacity {
        return Err(NodeLookupUnavailable::new(
            NodeLookupUnavailableKind::Capacity,
            format!("node lookup replay table is full at {capacity} identities"),
        ));
    }

    let valid_micros = record
        .expires_unix_micros
        .saturating_sub(reading.wall_unix_micros);
    let valid_for = Duration::from_micros(valid_micros);
    let expired = valid_micros == 0;
    let state_error = if expired {
        Some(NodeLookupUnavailable::new(
            NodeLookupUnavailableKind::Expired,
            format!("record sequence {} is expired", record.sequence),
        ))
    } else {
        match record.state {
            PublicationState::Withdrawn => Some(NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::Withdrawn,
                format!("record sequence {} is a withdrawal", record.sequence),
            )),
            PublicationState::Live if record.locations.is_empty() => {
                Some(NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::NoDialableCandidate,
                    format!(
                        "record sequence {} has no dialable candidate",
                        record.sequence
                    ),
                ))
            }
            PublicationState::Live => None,
        }
    };
    let result = state_error
        .is_none()
        .then(|| NodeLookupResult::from_record(record.clone(), packet_hash));
    state.high_water.insert(
        node_id,
        HighWater {
            sequence: record.sequence,
            packet_hash,
            observed_monotonic: reading.monotonic,
            valid_for_at_observation: valid_for,
            cached: result.clone(),
        },
    );
    match (result, state_error) {
        (Some(result), None) => Ok(result),
        (None, Some(error)) => Err(error),
        _ => unreachable!("lookup outcome is either a result or one state error"),
    }
}

fn record_state_error(record: &NodeRecord) -> Result<NodeLookupResult, NodeLookupUnavailable> {
    match record.state {
        PublicationState::Withdrawn => Err(NodeLookupUnavailable::new(
            NodeLookupUnavailableKind::Withdrawn,
            format!("record sequence {} is a withdrawal", record.sequence),
        )),
        PublicationState::Live => Err(NodeLookupUnavailable::new(
            NodeLookupUnavailableKind::NoDialableCandidate,
            format!(
                "record sequence {} has no cached live result",
                record.sequence
            ),
        )),
    }
}

fn map_http_error(error: PinnedHttpError) -> NodeLookupUnavailable {
    let kind = match error.kind() {
        PinnedHttpErrorKind::Configuration => NodeLookupUnavailableKind::UntrustedConfiguration,
        PinnedHttpErrorKind::ConnectionRefused => {
            NodeLookupUnavailableKind::AuthorityConnectionRefused
        }
        PinnedHttpErrorKind::Connect => NodeLookupUnavailableKind::AuthorityConnect,
        PinnedHttpErrorKind::Write => NodeLookupUnavailableKind::AuthorityWrite,
        PinnedHttpErrorKind::Read => NodeLookupUnavailableKind::AuthorityRead,
        PinnedHttpErrorKind::Protocol => NodeLookupUnavailableKind::AuthorityProtocol,
        PinnedHttpErrorKind::Deadline => NodeLookupUnavailableKind::Deadline,
    };
    NodeLookupUnavailable::new(kind, error.to_string())
}

fn map_signed_packet_error(error: SignedPacketVerifyError) -> NodeLookupUnavailable {
    let kind = match error {
        SignedPacketVerifyError::SignatureError { .. } => NodeLookupUnavailableKind::BadSignature,
        SignedPacketVerifyError::TooShort { .. }
        | SignedPacketVerifyError::TooLarge { .. }
        | SignedPacketVerifyError::DnsError { .. }
        | SignedPacketVerifyError::InvalidKey { .. } => {
            NodeLookupUnavailableKind::MalformedOrUntrustedRecord
        }
        _ => NodeLookupUnavailableKind::MalformedOrUntrustedRecord,
    };
    NodeLookupUnavailable::new(kind, format!("pkarr response rejected: {error}"))
}

fn map_runtime_error(error: IrohRuntimeError) -> NodeLookupUnavailable {
    match error {
        IrohRuntimeError::Capacity { active, limit } => NodeLookupUnavailable::new(
            NodeLookupUnavailableKind::Capacity,
            format!("runtime task capacity exhausted at {active}/{limit}"),
        ),
        IrohRuntimeError::Closed => NodeLookupUnavailable::new(
            NodeLookupUnavailableKind::Closed,
            "node lookup runtime is closed",
        ),
        other => NodeLookupUnavailable::new(
            NodeLookupUnavailableKind::Closed,
            format!("node lookup owner rejected operation: {other}"),
        ),
    }
}

/// Narrow query capability. It exposes no endpoint, publisher, peer list, or
/// content-discovery operation.
#[derive(Clone)]
pub struct NodeLookupHandle {
    core: Option<Weak<NodeLookupCore>>,
    supervisor: Option<TaskSupervisorHandle>,
}

impl fmt::Debug for NodeLookupHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeLookupHandle")
            .field("enabled", &self.core.is_some())
            .finish()
    }
}

impl NodeLookupHandle {
    pub fn disabled() -> Self {
        Self {
            core: None,
            supervisor: None,
        }
    }

    pub async fn resolve(
        &self,
        node_id: NodeId,
    ) -> Result<NodeLookupResult, NodeLookupUnavailable> {
        let absolute_deadline = Instant::now()
            .checked_add(NODE_LOOKUP_DEADLINE)
            .ok_or_else(|| {
                NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::Deadline,
                    "node lookup deadline overflows monotonic clock",
                )
            })?;
        let core = self
            .core
            .as_ref()
            .ok_or_else(|| {
                NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::Disabled,
                    "node lookup capability is disabled",
                )
            })?
            .upgrade()
            .ok_or_else(|| {
                NodeLookupUnavailable::new(
                    NodeLookupUnavailableKind::Closed,
                    "node lookup runtime is closed",
                )
            })?;
        let public_key = PublicKey::from_bytes(node_id.as_bytes())
            .map_err(NodeLookupUnavailable::invalid_node_id)?;
        let supervisor = self.supervisor.clone().ok_or_else(|| {
            NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::Closed,
                "node lookup has no runtime task owner",
            )
        })?;
        tokio::time::timeout_at(
            absolute_deadline,
            supervisor.execute("node-lookup", async move {
                core.resolve(node_id, public_key, absolute_deadline).await
            }),
        )
        .await
        .map_err(|_| {
            NodeLookupUnavailable::new(
                NodeLookupUnavailableKind::Deadline,
                "node lookup exceeded its absolute 10000 ms deadline",
            )
        })?
        .map_err(|error| map_runtime_error(error.into()))?
    }

    pub(crate) fn adapter(&self) -> NodeLookupAddressAdapter {
        NodeLookupAddressAdapter {
            lookup: self.clone(),
        }
    }
}

pub(crate) struct NodeLookupRuntime {
    core: Arc<NodeLookupCore>,
    handle: NodeLookupHandle,
}

impl NodeLookupRuntime {
    pub(crate) fn start(
        config: NodeLookupConfig,
        supervisor: TaskSupervisorHandle,
    ) -> Result<Self, NodeLookupUnavailable> {
        let core = Arc::new(NodeLookupCore::new(config)?);
        Ok(Self {
            handle: NodeLookupHandle {
                core: Some(Arc::downgrade(&core)),
                supervisor: Some(supervisor),
            },
            core,
        })
    }

    pub(crate) fn handle(&self) -> NodeLookupHandle {
        self.handle.clone()
    }

    pub(crate) fn close(&self) {
        self.core.close();
    }
}

impl Drop for NodeLookupRuntime {
    fn drop(&mut self) {
        self.core.close();
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NodeLookupAddressAdapter {
    lookup: NodeLookupHandle,
}

impl AddressLookup for NodeLookupAddressAdapter {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<IrohLookupItem, IrohLookupError>>> {
        let lookup = self.lookup.clone();
        let node_id = NodeId::from_bytes(*endpoint_id.as_bytes());
        let future = async move {
            let result = lookup
                .resolve(node_id)
                .await
                .map_err(|error| IrohLookupError::from_err(NODE_LOOKUP_PROVENANCE, error))?;
            let address = result
                .endpoint_addr()
                .map_err(|error| IrohLookupError::from_err(NODE_LOOKUP_PROVENANCE, error))?;
            let endpoint_info = address.into();
            Ok(IrohLookupItem::new(
                endpoint_info,
                NODE_LOOKUP_PROVENANCE,
                Some(result.sequence()),
            ))
        };
        Some(Box::pin(n0_future::stream::once_future(future)))
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BlockingFirstClock {
        calls: std::sync::atomic::AtomicUsize,
        first_started: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<()>>>,
        first_release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        monotonic: MonotonicInstant,
    }

    /// A clock whose SECOND read blocks for `post_validation_sleep`. In
    /// `resolve` the first read happens in preflight and the second is the
    /// post-validation observation (`read_and_observe_clock`, after the signed
    /// record has been fetched, decoded and validated and its sequence
    /// recorded). Sleeping strictly longer than the absolute deadline on that
    /// second read drives the deadline breach to the post-validation
    /// checkpoint deterministically - never to a pre-validation network check,
    /// which would report no validated sequence.
    #[derive(Debug)]
    struct SlowSecondClock {
        reads: std::sync::atomic::AtomicUsize,
        post_validation_sleep: Duration,
    }

    impl LookupClock for SlowSecondClock {
        fn read(&self) -> Result<ClockReading, NodeLookupUnavailable> {
            if self.reads.fetch_add(1, Ordering::SeqCst) == 1 {
                std::thread::sleep(self.post_validation_sleep);
            }
            SystemLookupClock.read()
        }
    }

    impl LookupClock for BlockingFirstClock {
        fn read(&self) -> Result<ClockReading, NodeLookupUnavailable> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let wall_unix_micros = if call == 0 {
                self.first_started
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                self.first_release.lock().unwrap().recv().unwrap();
                100
            } else {
                200
            };
            Ok(ClockReading {
                wall_unix_micros,
                monotonic: self.monotonic,
            })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_preflight_waits_for_replay_state_without_false_capacity_or_rollback() {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let clock = Arc::new(BlockingFirstClock {
            calls: std::sync::atomic::AtomicUsize::new(0),
            first_started: std::sync::Mutex::new(Some(started_tx)),
            first_release: std::sync::Mutex::new(release_rx),
            monotonic: MonotonicInstant::now(),
        });
        let config = NodeLookupConfig::new(
            "run-1",
            "authority.test:v1",
            "127.0.0.1:8080".parse().unwrap(),
            "authority.test",
            NodeLookupAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
        )
        .unwrap();
        let core = Arc::new(
            NodeLookupCore::new_with_clock_and_capacity(config, clock.clone(), 2).unwrap(),
        );
        let older_node = NodeId::from_bytes(*iroh::SecretKey::generate().public().as_bytes());
        let newer_node = NodeId::from_bytes(*iroh::SecretKey::generate().public().as_bytes());

        let absolute_deadline = Instant::now() + Duration::from_secs(2);
        let older = {
            let core = core.clone();
            tokio::spawn(async move { core.preflight(older_node, absolute_deadline).await })
        };
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first clock read must start");
        let newer = {
            let core = core.clone();
            tokio::spawn(async move { core.preflight(newer_node, absolute_deadline).await })
        };
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            !newer.is_finished(),
            "a concurrent caller must await the replay-state guard"
        );
        assert_eq!(clock.calls.load(Ordering::SeqCst), 1);
        release_tx.send(()).unwrap();
        let (older_result, newer_result) =
            tokio::time::timeout(Duration::from_secs(1), async { tokio::join!(older, newer) })
                .await
                .expect("serialized preflights must complete before their shared deadline");

        older_result
            .unwrap()
            .expect("the serialized older observation cannot look like rollback");
        newer_result
            .unwrap()
            .expect("harmless replay-state contention cannot look like capacity");
        assert_eq!(clock.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn held_replay_state_expires_at_the_shared_deadline_without_sending_a_get() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let config = NodeLookupConfig::new(
            "run-1",
            "authority.test:v1",
            listener.local_addr().unwrap(),
            "authority.test",
            NodeLookupAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
        )
        .unwrap();
        let core = Arc::new(NodeLookupCore::new(config).unwrap());
        let key = iroh::SecretKey::generate();
        let node_id = NodeId::from_bytes(*key.public().as_bytes());
        let absolute_deadline = Instant::now() + NODE_LOOKUP_DEADLINE;
        let state_guard = core.state.lock().await;
        let lookup = {
            let core = core.clone();
            let public_key = key.public();
            tokio::spawn(async move { core.resolve(node_id, public_key, absolute_deadline).await })
        };

        tokio::task::yield_now().await;
        assert!(
            !lookup.is_finished(),
            "lookup must wait for harmless replay-state contention"
        );
        tokio::time::advance(NODE_LOOKUP_DEADLINE + Duration::from_millis(1)).await;
        let error = lookup
            .await
            .unwrap()
            .expect_err("the shared absolute deadline must bound lock acquisition");
        assert_eq!(error.kind(), NodeLookupUnavailableKind::Deadline);
        assert!(
            error.to_string().contains("waiting for replay state"),
            "deadline must identify the blocked preflight phase: {error}"
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "a lookup that cannot pass replay preflight must send no GET"
        );
        drop(state_guard);
    }

    #[tokio::test]
    async fn synchronous_replay_validation_cannot_return_success_after_absolute_deadline() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let authority = listener.local_addr().unwrap();
        let key = iroh::SecretKey::generate();
        let node_id = NodeId::from_bytes(*key.public().as_bytes());
        let sequence = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
            - 100_000;
        let packet = crate::iroh_node_record::encode_node_record(
            &key,
            "run-1",
            "authority.test:v1",
            30,
            sequence,
            sequence + 30_000_000,
            PublicationState::Live,
            &[NodeLocation::direct("192.0.2.1:4433".parse().unwrap()).unwrap()],
        )
        .unwrap();
        let body = packet.to_relay_payload();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0u8; 512];
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0);
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let config = NodeLookupConfig::new(
            "run-1",
            "authority.test:v1",
            authority,
            "authority.test",
            NodeLookupAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
        )
        .unwrap();
        // This test deliberately drives resolve() against a REAL loopback TCP
        // authority, so tokio's paused clock is unusable here: with time paused
        // the runtime would auto-advance to the deadline timer and fire the
        // fetch's `timeout_at` mid-read, aborting the transfer before validation
        // ever runs. The absolute deadline is therefore real wall time, and
        // determinism comes from the relationship between two real durations
        // rather than from a tight race against I/O:
        //
        //   * DEADLINE is generous relative to a loopback round-trip, so the
        //     pre-validation network checks (which run before the record's
        //     sequence is recorded) never trip under CPU contention. That early
        //     trip was the original ~1/5 -> 2/3 flake: a 10ms deadline racing a
        //     real TCP round-trip, so validated_sequence() saw None under load.
        //   * POST_VALIDATION_SLEEP > DEADLINE, and it is consumed only on the
        //     SECOND clock read, which resolve() performs AFTER the record is
        //     fetched and validated. So the deadline is always breached at the
        //     post-validation checkpoint, with the validated sequence recorded,
        //     regardless of how long the fetch actually took.
        //
        // The oracle still bites: remove resolve()'s post-validation deadline
        // guard and it returns success -> unwrap_err() panics; stop recording
        // the validated sequence and validated_sequence() != Some(sequence).
        const DEADLINE: Duration = Duration::from_millis(300);
        const POST_VALIDATION_SLEEP: Duration = Duration::from_millis(400);
        let core = NodeLookupCore::new_with_clock_and_capacity(
            config,
            Arc::new(SlowSecondClock {
                reads: std::sync::atomic::AtomicUsize::new(0),
                post_validation_sleep: POST_VALIDATION_SLEEP,
            }),
            1,
        )
        .unwrap();
        let error = core
            .resolve(node_id, key.public(), Instant::now() + DEADLINE)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), NodeLookupUnavailableKind::Deadline);
        assert_eq!(error.validated_sequence(), Some(sequence));
        server.await.unwrap();
    }

    #[test]
    fn config_is_default_closed_and_external_plaintext_is_rejected() {
        let local = NodeLookupConfig::new(
            "run-1",
            "authority.test:v1",
            "127.0.0.1:8080".parse().unwrap(),
            "authority.test",
            NodeLookupAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
        )
        .unwrap();
        assert_eq!(local.namespace(), "run-1");
        let empty = NodeLookupConfig::new(
            "",
            "authority.test:v1",
            "127.0.0.1:8080".parse().unwrap(),
            "authority.test",
            NodeLookupAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
        )
        .unwrap_err();
        assert_eq!(
            empty.kind(),
            NodeLookupUnavailableKind::UntrustedConfiguration
        );
        let external = NodeLookupConfig::new(
            "run-1",
            "authority.test:v1",
            "192.0.2.10:8080".parse().unwrap(),
            "authority.test",
            NodeLookupAuthorityAuthorization::ExternalAuthorized {
                owner: "operator".into(),
                authorization_reference: "ticket-1".into(),
            },
        )
        .unwrap_err();
        assert_eq!(
            external.kind(),
            NodeLookupUnavailableKind::ExternalAuthorityUnsupported
        );
    }

    #[tokio::test]
    async fn disabled_handle_is_typed_and_network_inert() {
        let error = NodeLookupHandle::disabled()
            .resolve(NodeId::from_bytes([7; 32]))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), NodeLookupUnavailableKind::Disabled);
    }

    #[tokio::test]
    async fn dropping_the_iroh_lookup_stream_cancels_its_owned_tcp_request() {
        use n0_future::StreamExt as _;
        use tokio::io::AsyncReadExt as _;

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let authority = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0u8; 512];
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "request ended before headers");
                request.extend_from_slice(&chunk[..read]);
                assert!(request.len() < 8192, "request headers exceeded test bound");
            }
            accepted_tx.send(()).unwrap();
            let mut proof = [0u8; 1];
            closed_tx
                .send(stream.read(&mut proof).await.unwrap())
                .unwrap();
        });

        let config = NodeLookupConfig::new(
            "run-1",
            "authority.test:v1",
            authority,
            "authority.test",
            NodeLookupAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
        )
        .unwrap();
        let supervisor = crate::iroh_runtime::TaskSupervisor::new();
        let runtime = NodeLookupRuntime::start(config, supervisor.handle()).unwrap();
        let key = iroh::SecretKey::generate();
        let mut stream = runtime.handle().adapter().resolve(key.public()).unwrap();
        let asker = tokio::spawn(async move { stream.next().await });

        accepted_rx.await.unwrap();
        asker.abort();
        let _ = asker.await;
        let read = tokio::time::timeout(Duration::from_secs(1), closed_rx)
            .await
            .expect("dropping Iroh's lookup stream must close the authority request")
            .unwrap();
        assert_eq!(read, 0);
        server.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while supervisor.active_task_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled Iroh lookup must leave zero owned tasks");
        drop(runtime);
        supervisor.cancel_now();
    }

    #[test]
    fn result_converts_direct_and_relay_candidates_for_iroh() {
        let key = iroh::SecretKey::generate();
        let node_id = NodeId::from_bytes(*key.public().as_bytes());
        let result = NodeLookupResult {
            lookup_schema: NODE_LOOKUP_SCHEMA,
            record_schema: NODE_PUBLICATION_SCHEMA,
            source: NODE_LOOKUP_SOURCE,
            provenance: NodeLookupProvenance::NetworkValidated,
            node_id,
            namespace: "run-1".into(),
            recipient: "authority.test:v1".into(),
            ttl_seconds: 30,
            sequence: 1,
            expires_unix_micros: 31_000_000,
            candidates: vec![
                NodeLocation::direct("192.0.2.1:4433".parse().unwrap()).unwrap(),
                NodeLocation::relay("https://relay.example".to_string()).unwrap(),
            ],
            signed_packet_blake3_hex: "00".repeat(32),
        };
        let address = result.endpoint_addr().unwrap();
        assert_eq!(address.id, key.public());
        assert_eq!(address.ip_addrs().count(), 1);
        assert_eq!(address.relay_urls().count(), 1);
    }

    #[test]
    fn source_has_no_enumeration_content_lan_or_publish_operation() {
        let production = include_str!("iroh_node_lookup.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "fn enumerate",
            "fn list_peers",
            "ContentDiscovery",
            "LocalSwarmDiscovery",
            "fn publish(&self",
            "put_record(",
            "SecretKey",
            "encode_node_record",
            "content MISS",
        ] {
            assert!(
                !production.contains(forbidden),
                "lookup boundary gained forbidden operation/dependency {forbidden}"
            );
        }
    }

    fn record(
        node_id: NodeId,
        sequence: u64,
        expiry: u64,
        state: PublicationState,
        locations: Vec<NodeLocation>,
    ) -> NodeRecord {
        NodeRecord {
            node_id,
            namespace: "run-1".into(),
            recipient: "authority.test:v1".into(),
            ttl_seconds: 30,
            sequence,
            expires_unix_micros: expiry,
            state,
            locations,
        }
    }

    #[test]
    fn no_dialable_clock_capacity_and_monotonic_expiry_are_typed() {
        let key = iroh::SecretKey::generate();
        let node_id = NodeId::from_bytes(*key.public().as_bytes());
        let monotonic = MonotonicInstant::now();
        let reading = ClockReading {
            wall_unix_micros: 1_000_000,
            monotonic,
        };
        let mut state = LookupState::default();
        let error = validate_and_advance(
            &mut state,
            1,
            node_id,
            record(
                node_id,
                900_000,
                2_000_000,
                PublicationState::Live,
                Vec::new(),
            ),
            [1; 32],
            reading,
        )
        .unwrap_err();
        assert_eq!(error.kind(), NodeLookupUnavailableKind::NoDialableCandidate);
        assert_eq!(state.high_water[&node_id].sequence, 900_000);

        let other = NodeId::from_bytes(*iroh::SecretKey::generate().public().as_bytes());
        let capacity = validate_and_advance(
            &mut state,
            1,
            other,
            record(
                other,
                900_001,
                2_000_001,
                PublicationState::Live,
                vec![NodeLocation::direct("192.0.2.1:4433".parse().unwrap()).unwrap()],
            ),
            [2; 32],
            reading,
        )
        .unwrap_err();
        assert_eq!(capacity.kind(), NodeLookupUnavailableKind::Capacity);

        let mut rollback_state = LookupState::default();
        observe_wall_clock(&mut rollback_state, 10).unwrap();
        assert_eq!(
            observe_wall_clock(&mut rollback_state, 9)
                .unwrap_err()
                .kind(),
            NodeLookupUnavailableKind::ClockRollback
        );

        let mut freshness = LookupState::default();
        let live = record(
            node_id,
            900_000,
            2_000_000,
            PublicationState::Live,
            vec![NodeLocation::direct("192.0.2.2:4433".parse().unwrap()).unwrap()],
        );
        validate_and_advance(&mut freshness, 1, node_id, live.clone(), [3; 32], reading).unwrap();
        let monotonic_expired = validate_and_advance(
            &mut freshness,
            1,
            node_id,
            live,
            [3; 32],
            ClockReading {
                wall_unix_micros: 1_000_000,
                monotonic: monotonic + Duration::from_secs(2),
            },
        )
        .unwrap_err();
        assert_eq!(monotonic_expired.kind(), NodeLookupUnavailableKind::Expired);
    }

    #[test]
    fn future_sequence_is_untrusted_and_does_not_advance_high_water() {
        let key = iroh::SecretKey::generate();
        let node_id = NodeId::from_bytes(*key.public().as_bytes());
        let reading = ClockReading {
            wall_unix_micros: 1_000_000,
            monotonic: MonotonicInstant::now(),
        };
        let mut state = LookupState::default();
        let future = 1_000_000 + NODE_LOOKUP_SCHEDULER_GRACE.as_micros() as u64 + 1;
        let error = validate_and_advance(
            &mut state,
            1,
            node_id,
            record(
                node_id,
                future,
                future + 30_000_000,
                PublicationState::Live,
                vec![NodeLocation::direct("192.0.2.3:4433".parse().unwrap()).unwrap()],
            ),
            [4; 32],
            reading,
        )
        .unwrap_err();
        assert_eq!(
            error.kind(),
            NodeLookupUnavailableKind::MalformedOrUntrustedRecord
        );
        assert!(state.high_water.is_empty());
    }
}
