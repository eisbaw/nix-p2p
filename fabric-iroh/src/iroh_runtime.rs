//! One deployment-shaped Iroh endpoint lifetime (TASK-115).
//!
//! The runtime owns the only strong endpoint reference exposed to product code
//! and the only [`Router`]. Provider/fetch handles receive a weak
//! [`IrohEndpointHandle`]: they can use the socket while the runtime is alive,
//! but cannot keep it bound, create a replacement, or close it independently.
//!
//! Endpoint configuration is closed and explicit. [`EndpointScope`] selects
//! only local socket binds. Relay and address-lookup participation are separate
//! capability inputs, so choosing a LAN/global bind cannot silently publish to
//! or query a public service. The test selector is genuinely offline: both Iroh
//! default IP transports are cleared, only IPv4/IPv6 loopback are re-added,
//! relay/address lookup/port mapping are disabled, and all optional net-report
//! probes are disabled. `presets::N0` is intentionally absent.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use iroh::endpoint::{Connection, NetReportConfig, PortmapperConfig, RelayMode, presets};
use iroh::protocol::{DynProtocolHandler, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, SecretKey, Watcher};
use n0_future::StreamExt;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::iroh_node_lookup::{NodeLookupConfig, NodeLookupHandle, NodeLookupRuntime};
use crate::iroh_node_record::{NodeLocation, normalize_socket_addr};
use crate::iroh_publication::{
    NodePublicationCapability, NodePublicationHandle, NodePublicationRuntime,
    PUBLICATION_STARTUP_DEADLINE, PUBLICATION_TRANSITION_DEADLINE,
};
use peer_fabric::NodeId;
use proc_supervisor::process_group::ProcessJobRegistry;
// The generic task/subprocess supervisor moved to the stack-neutral `proc-supervisor`
// crate (TASK-146) so `daemon-core` and this backend both build on it without a cycle.
// Re-exported here so the daemon's existing `iroh_runtime::TaskSupervisor{,Handle}` /
// `daemon::TaskSupervisor` paths keep resolving unchanged during the split.
use proc_supervisor::SupervisorError;
pub use proc_supervisor::{
    MAX_OWNED_TASKS, SupervisedProcessOutput, TaskSupervisor, TaskSupervisorHandle, TrackedTask,
};

/// Stable on-disk name. The schema version lives inside the record so an
/// upgrade cannot accidentally interpret new bytes using old rules.
pub const IROH_IDENTITY_FILENAME: &str = "iroh-identity.json";

const IDENTITY_SCHEMA_VERSION: u32 = 1;
const IDENTITY_CHECKSUM_DOMAIN: &[u8] = b"nix-p2p/iroh-identity/v1\0";
const MAX_IDENTITY_BYTES: u64 = 4096;
const STATE_DIRECTORY_MODE: u32 = 0o700;
const IDENTITY_FILE_MODE: u32 = 0o600;

/// The total graceful-shutdown budget before the runtime aborts the router and
/// drops its last strong endpoint owner. This is a named product value rather
/// than an unbounded await hidden in process teardown.
pub const IROH_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

/// Which local IP sockets an endpoint may bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointScope {
    /// Hermetic test scope: explicit IPv4 and IPv6 loopback only.
    OfflineTest { port: u16 },
    /// Explicit LAN interface addresses. Nothing is discovered or published by
    /// selecting this scope; callers must separately provide capabilities.
    Lan {
        ipv4: Ipv4Addr,
        ipv6: Option<Ipv6Addr>,
        port: u16,
    },
    /// All local interfaces. This only binds sockets; no relay, lookup or
    /// application protocol is enabled by the scope itself.
    Global { port: u16 },
}

/// The daemon-owned endpoint selector shared with the throughput benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointProfile {
    pub scope: EndpointScope,
}

impl EndpointProfile {
    /// Exhaustive const comparison used by the TASK-69/TASK-115 compile-time
    /// daemon/benchmark selector guard.
    pub const fn same_configuration(self, other: Self) -> bool {
        match (self.scope, other.scope) {
            (
                EndpointScope::OfflineTest { port: left },
                EndpointScope::OfflineTest { port: right },
            )
            | (EndpointScope::Global { port: left }, EndpointScope::Global { port: right }) => {
                left == right
            }
            (
                EndpointScope::Lan {
                    ipv4: left_v4,
                    ipv6: left_v6,
                    port: left_port,
                },
                EndpointScope::Lan {
                    ipv4: right_v4,
                    ipv6: right_v6,
                    port: right_port,
                },
            ) => {
                left_v4.to_bits() == right_v4.to_bits()
                    && ipv6_option_eq(left_v6, right_v6)
                    && left_port == right_port
            }
            _ => false,
        }
    }
}

const fn ipv6_option_eq(left: Option<Ipv6Addr>, right: Option<Ipv6Addr>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left.to_bits() == right.to_bits(),
        _ => false,
    }
}

/// The selector used by daemon tests and every raw benchmark arm.
pub const DAEMON_TEST_ENDPOINT_PROFILE: EndpointProfile = EndpointProfile {
    scope: EndpointScope::OfflineTest { port: 0 },
};

/// Identity must be an explicit choice at every construction site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentitySource {
    /// Generate a process-lifetime key. Intended for benchmarks and isolated
    /// tests only; the daemon uses [`Self::Persistent`].
    Ephemeral,
    /// Load or atomically initialize the identity in this state directory.
    Persistent { state_dir: PathBuf },
}

/// Relay is a separate capability, never inferred from bind scope.
pub enum RelayCapability {
    Disabled,
    /// Explicitly authorized relay configuration. TASK-89 owns selecting and
    /// exposing concrete production relay modes; TASK-115 only carries it.
    Enabled(RelayMode),
}

impl fmt::Debug for RelayCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("Disabled"),
            Self::Enabled(mode) => {
                let mode_name = match mode {
                    RelayMode::Disabled => "Disabled",
                    RelayMode::Default => "Default",
                    RelayMode::Staging => "Staging",
                    RelayMode::Custom(_) => "Custom",
                };
                // RelayConfig's derived Debug includes auth_token. Report only
                // non-secret configuration truth here.
                formatter
                    .debug_struct("Enabled")
                    .field("mode", &mode_name)
                    .field("relay_count", &mode.relay_map().len())
                    .finish()
            }
        }
    }
}

/// Address lookup is separately authorized from bind scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressLookupCapability {
    Disabled,
    /// Daemon-owned in-memory resolver used by non-network capability tests.
    /// Networked resolvers use named variants here; arbitrary builders never
    /// receive `&Endpoint` and therefore cannot clone/export the runtime socket.
    Memory,
    /// Resolve only asker-supplied NodeIds through one pinned, locally operated
    /// Task137 pkarr authority. This variant does not publish endpoint data.
    PinnedPkarr(NodeLookupConfig),
}

/// Observable network capabilities selected explicitly for one endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointCapabilityState {
    pub relay_enabled: bool,
    pub address_lookup_services: usize,
    pub node_lookup_enabled: bool,
    pub node_publication_enabled: bool,
}

/// Fail-fast runtime construction and shutdown errors.
#[derive(Debug)]
pub enum IrohRuntimeError {
    Configuration(String),
    Identity(String),
    Bind(String),
    DuplicateAlpn(String),
    Capacity { active: usize, limit: usize },
    Closed,
    Operation(String),
    Shutdown(String),
}

impl fmt::Display for IrohRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(why) => write!(f, "invalid Iroh endpoint configuration: {why}"),
            Self::Identity(why) => write!(f, "Iroh identity state rejected: {why}"),
            Self::Bind(why) => write!(f, "Iroh endpoint bind failed: {why}"),
            Self::DuplicateAlpn(alpn) => {
                write!(f, "duplicate Iroh ALPN registration rejected: {alpn}")
            }
            Self::Capacity { active, limit } => write!(
                f,
                "Iroh runtime is busy: {active}/{limit} owned tasks are queued or running"
            ),
            Self::Closed => f.write_str("Iroh node runtime is shut down"),
            Self::Operation(why) => write!(f, "Iroh endpoint operation failed: {why}"),
            Self::Shutdown(why) => write!(f, "Iroh runtime shutdown failed: {why}"),
        }
    }
}

impl std::error::Error for IrohRuntimeError {}

impl IrohRuntimeError {
    pub fn is_capacity_exhausted(&self) -> bool {
        matches!(self, Self::Capacity { .. })
    }
}

/// The endpoint runtime drives the stack-neutral [`TaskSupervisor`] and propagates its
/// failures as its own richer error (TASK-146): `?` on a supervisor call inside an
/// endpoint fn that returns [`IrohRuntimeError`] maps through here. `Poisoned` (a broken
/// shutdown-path invariant) folds into `Shutdown`; the other two are 1:1.
impl From<SupervisorError> for IrohRuntimeError {
    fn from(error: SupervisorError) -> Self {
        match error {
            SupervisorError::Closed => IrohRuntimeError::Closed,
            SupervisorError::Capacity { active, limit } => {
                IrohRuntimeError::Capacity { active, limit }
            }
            SupervisorError::Poisoned(why) => IrohRuntimeError::Shutdown(why),
        }
    }
}

/// Builds exactly one endpoint and one router.
pub struct IrohRuntimeBuilder {
    profile: EndpointProfile,
    identity: IdentitySource,
    relay: RelayCapability,
    address_lookup: AddressLookupCapability,
    node_publication: NodePublicationCapability,
    protocols: BTreeMap<Vec<u8>, Box<dyn DynProtocolHandler>>,
    shutdown_deadline: Duration,
    publication_startup_deadline: Option<tokio::time::Instant>,
    supervisor: TaskSupervisor,
}

impl fmt::Debug for IrohRuntimeBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("IrohRuntimeBuilder");
        debug
            .field("profile", &self.profile)
            .field("identity", &self.identity)
            .field("relay", &self.relay)
            .field("address_lookup", &self.address_lookup)
            .field(
                "lookup_count",
                &self.capability_state().address_lookup_services,
            )
            .field("alpns", &self.protocols.keys().collect::<Vec<_>>())
            .field("shutdown_deadline", &self.shutdown_deadline)
            .field(
                "publication_startup_deadline_set",
                &self.publication_startup_deadline.is_some(),
            )
            .field("supervisor", &self.supervisor);
        match &self.node_publication {
            NodePublicationCapability::Disabled => {
                debug.field("node_publication", &"disabled");
            }
            NodePublicationCapability::Enabled(config) => {
                // The external authorization reference is deliberately not
                // formatted.  It is operator-supplied audit material and may
                // contain identifiers unsuitable for generic Debug sinks.
                debug
                    .field("node_publication", &"enabled")
                    .field("publication_namespace", &config.namespace())
                    .field("publication_recipient", &config.authority_recipient())
                    .field("publication_owner", &config.authorization().owner());
            }
        }
        debug.finish()
    }
}

impl IrohRuntimeBuilder {
    pub fn new(
        profile: EndpointProfile,
        identity: IdentitySource,
        relay: RelayCapability,
        address_lookup: AddressLookupCapability,
    ) -> Result<Self, IrohRuntimeError> {
        if let EndpointScope::Lan { ipv4, ipv6, .. } = profile.scope {
            if ipv4.is_unspecified() || ipv4.is_multicast() || ipv4.is_broadcast() {
                return Err(IrohRuntimeError::Configuration(format!(
                    "LAN IPv4 {ipv4} is not a concrete unicast interface address"
                )));
            }
            if let Some(ipv6) = ipv6 {
                if ipv6.is_unspecified() || ipv6.is_multicast() {
                    return Err(IrohRuntimeError::Configuration(format!(
                        "LAN IPv6 {ipv6} is not a concrete unicast interface address"
                    )));
                }
                if ipv6.is_unicast_link_local() {
                    return Err(IrohRuntimeError::Configuration(format!(
                        "LAN IPv6 {ipv6} requires an interface scope id, which this profile does not guess; use a scoped address capability"
                    )));
                }
            }
        }
        if matches!(profile.scope, EndpointScope::OfflineTest { .. }) {
            if !matches!(relay, RelayCapability::Disabled) {
                return Err(IrohRuntimeError::Configuration(
                    "offline-test rejects relay capability injection".to_string(),
                ));
            }
            if !matches!(&address_lookup, AddressLookupCapability::Disabled) {
                return Err(IrohRuntimeError::Configuration(
                    "offline-test rejects address-lookup capability injection".to_string(),
                ));
            }
        }
        validate_relay_capability(&relay)?;
        Ok(Self {
            profile,
            identity,
            relay,
            address_lookup,
            node_publication: NodePublicationCapability::Disabled,
            protocols: BTreeMap::new(),
            shutdown_deadline: IROH_SHUTDOWN_DEADLINE,
            publication_startup_deadline: None,
            supervisor: TaskSupervisor::new(),
        })
    }

    /// Registration capability shared by provider/application work assembled
    /// before the endpoint is bound.
    pub fn task_supervisor_handle(&self) -> TaskSupervisorHandle {
        self.supervisor.handle()
    }

    pub fn capability_state(&self) -> EndpointCapabilityState {
        EndpointCapabilityState {
            relay_enabled: matches!(self.relay, RelayCapability::Enabled(_)),
            address_lookup_services: usize::from(matches!(
                &self.address_lookup,
                AddressLookupCapability::Memory | AddressLookupCapability::PinnedPkarr(_)
            )),
            node_lookup_enabled: matches!(
                &self.address_lookup,
                AddressLookupCapability::PinnedPkarr(_)
            ),
            node_publication_enabled: matches!(
                self.node_publication,
                NodePublicationCapability::Enabled(_)
            ),
        }
    }

    /// Attach only the separately authorized node-address publisher.  This
    /// does not add an address lookup, relay, LAN, or content capability.
    pub fn node_publication(
        mut self,
        capability: NodePublicationCapability,
    ) -> Result<Self, IrohRuntimeError> {
        let mut capability = capability;
        if matches!(capability, NodePublicationCapability::Enabled(_)) {
            if matches!(self.profile.scope, EndpointScope::OfflineTest { .. }) {
                return Err(IrohRuntimeError::Configuration(
                    "offline-test rejects node-publication capability injection".into(),
                ));
            }
            if !matches!(self.identity, IdentitySource::Persistent { .. }) {
                return Err(IrohRuntimeError::Configuration(
                    "node publication requires a persistent identity/state directory".into(),
                ));
            }
            if let NodePublicationCapability::Enabled(config) = &capability
                && config.initial_locations().iter().any(|location| {
                    matches!(location, crate::iroh_node_record::NodeLocation::Relay(_))
                })
                && !matches!(self.relay, RelayCapability::Enabled(_))
            {
                return Err(IrohRuntimeError::Configuration(
                    "a published relay location requires the endpoint relay capability to be enabled explicitly"
                        .into(),
                ));
            }
            if matches!(self.relay, RelayCapability::Enabled(_))
                && let NodePublicationCapability::Enabled(config) = &mut capability
            {
                config.authorize_relay_locations();
            }
        }
        self.node_publication = capability;
        Ok(self)
    }

    /// Register an application protocol, rejecting the silent replacement that
    /// pinned Iroh's `RouterBuilder::accept` otherwise performs.
    pub fn accept(
        mut self,
        alpn: impl AsRef<[u8]>,
        handler: impl ProtocolHandler,
    ) -> Result<Self, IrohRuntimeError> {
        let alpn = alpn.as_ref().to_vec();
        if alpn.is_empty() {
            return Err(IrohRuntimeError::Configuration(
                "ALPN identifiers must not be empty".to_string(),
            ));
        }
        if self.protocols.contains_key(&alpn) {
            return Err(IrohRuntimeError::DuplicateAlpn(format_alpn(&alpn)));
        }
        self.protocols.insert(alpn, Box::new(handler));
        Ok(self)
    }

    /// Override only for focused timeout tests. Product construction uses the
    /// named [`IROH_SHUTDOWN_DEADLINE`].
    #[doc(hidden)]
    pub fn shutdown_deadline(mut self, deadline: Duration) -> Result<Self, IrohRuntimeError> {
        if deadline.is_zero() {
            return Err(IrohRuntimeError::Configuration(
                "shutdown deadline must be positive".to_string(),
            ));
        }
        self.shutdown_deadline = deadline;
        Ok(self)
    }

    /// Propagate a process-level publication deadline captured before product
    /// configuration and provider preparation. Without this explicit input,
    /// library callers receive the standard budget starting at `spawn`.
    pub fn publication_startup_deadline(
        mut self,
        deadline: tokio::time::Instant,
    ) -> Result<Self, IrohRuntimeError> {
        if deadline <= tokio::time::Instant::now() {
            return Err(IrohRuntimeError::Configuration(
                "publication startup deadline has already elapsed".into(),
            ));
        }
        self.publication_startup_deadline = Some(deadline);
        Ok(self)
    }

    pub async fn spawn(self) -> Result<IrohNodeRuntime, IrohRuntimeError> {
        let startup_deadline = self
            .publication_startup_deadline
            .unwrap_or_else(|| tokio::time::Instant::now() + PUBLICATION_STARTUP_DEADLINE);
        let capabilities = self.capability_state();
        let publication_state_dir = match (&self.node_publication, &self.identity) {
            (NodePublicationCapability::Enabled(_), IdentitySource::Persistent { state_dir }) => {
                Some(state_dir.clone())
            }
            (NodePublicationCapability::Enabled(_), IdentitySource::Ephemeral) => {
                return Err(IrohRuntimeError::Configuration(
                    "node publication requires persistent identity state".into(),
                ));
            }
            (NodePublicationCapability::Disabled, _) => None,
        };
        let secret_key = load_identity(self.identity)?;
        let publication_key =
            matches!(self.node_publication, NodePublicationCapability::Enabled(_))
                .then(|| secret_key.clone());
        let publication_plan = match (
            self.node_publication,
            publication_key,
            publication_state_dir,
        ) {
            (NodePublicationCapability::Disabled, None, None) => None,
            (NodePublicationCapability::Enabled(config), Some(key), Some(state_dir)) => {
                Some((config, key, state_dir))
            }
            _ => {
                return Err(IrohRuntimeError::Configuration(
                    "node-publication capability state was internally inconsistent".into(),
                ));
            }
        };
        let (installed_lookup, node_lookup) = match self.address_lookup {
            AddressLookupCapability::Disabled => (InstalledAddressLookup::Disabled, None),
            AddressLookupCapability::Memory => (InstalledAddressLookup::Memory, None),
            AddressLookupCapability::PinnedPkarr(config) => {
                let lookup = NodeLookupRuntime::start(config, self.supervisor.handle()).map_err(
                    |error| {
                        IrohRuntimeError::Configuration(format!(
                            "initializing pinned node lookup: {error}"
                        ))
                    },
                )?;
                (
                    InstalledAddressLookup::PinnedPkarr(lookup.handle()),
                    Some(lookup),
                )
            }
        };
        let endpoint =
            bind_endpoint_with_secret(self.profile, secret_key, self.relay, installed_lookup)
                .await?;
        let supervisor_handle = self.supervisor.handle();
        let owner = Arc::new(EndpointOwner {
            endpoint,
            supervisor: supervisor_handle,
            capabilities,
        });
        let handle = IrohEndpointHandle {
            owner: Arc::downgrade(&owner),
        };

        let mut router_builder = Router::builder(owner.endpoint.clone());
        for (alpn, handler) in self.protocols {
            router_builder = router_builder.accept(alpn, handler);
        }
        let router = router_builder.spawn();
        let (publication, publication_address_watch) =
            if let Some((config, key, state_dir)) = publication_plan {
                let allowed_locations = config.initial_locations().to_vec();
                let publication_start = async {
                    let effective_locations = wait_for_initial_publication_locations(
                        &owner.endpoint,
                        &allowed_locations,
                        startup_deadline,
                    )
                    .await?;
                    NodePublicationRuntime::start_with_effective_locations(
                        &state_dir,
                        key,
                        config,
                        effective_locations,
                        startup_deadline,
                    )
                    .await
                };
                match publication_start.await {
                    Ok((publication, receipt)) => {
                        let watcher = spawn_publication_address_watch(
                            &owner.endpoint,
                            publication.handle(),
                            allowed_locations,
                            receipt.record.locations.clone(),
                        );
                        (Some(publication), Some(watcher))
                    }
                    Err(error) => {
                        self.supervisor.cancel_now();
                        let endpoint = owner.endpoint.clone();
                        let cleanup_deadline = tokio::time::Instant::now() + self.shutdown_deadline;
                        let cleanup = tokio::time::timeout_at(cleanup_deadline, async {
                            endpoint.close().await;
                            router
                                .shutdown()
                                .await
                                .map_err(|cleanup| cleanup.to_string())
                        })
                        .await;
                        drop(owner);
                        let cleanup = match cleanup {
                            Ok(Ok(())) => "cleanup completed".to_string(),
                            Ok(Err(cleanup)) => format!("router cleanup failed: {cleanup}"),
                            Err(_) => format!("cleanup exceeded {:?}", self.shutdown_deadline),
                        };
                        return Err(IrohRuntimeError::Operation(format!(
                            "starting node-address publication: {error}; {cleanup}"
                        )));
                    }
                }
            } else {
                (None, None)
            };
        Ok(IrohNodeRuntime {
            owner: Some(owner),
            router: Some(router),
            handle,
            shutdown_deadline: self.shutdown_deadline,
            supervisor: Some(self.supervisor),
            publication,
            publication_address_watch,
            node_lookup,
        })
    }
}

async fn wait_for_initial_publication_locations(
    endpoint: &Endpoint,
    allowed: &[NodeLocation],
    absolute_deadline: tokio::time::Instant,
) -> Result<Vec<NodeLocation>, crate::iroh_publication::PublicationError> {
    let current = effective_publication_locations(allowed, &endpoint.addr());
    if !current.is_empty() {
        return Ok(current);
    }
    let mut updates = endpoint.watch_addr().stream();
    loop {
        let observed = tokio::time::timeout_at(absolute_deadline, updates.next())
            .await
            .map_err(|_| {
                crate::iroh_publication::PublicationError::configuration(
                    "startup deadline elapsed before any declared publication address was observed; refusing withdrawal-as-readiness",
                )
            })?
            .ok_or_else(|| {
                crate::iroh_publication::PublicationError::configuration(
                    "endpoint address watch ended before any declared publication address was observed",
                )
            })?;
        let effective = effective_publication_locations(allowed, &observed);
        if !effective.is_empty() {
            return Ok(effective);
        }
    }
}

fn effective_publication_locations(
    allowed: &[NodeLocation],
    observed: &EndpointAddr,
) -> Vec<NodeLocation> {
    let observed_ips = observed
        .ip_addrs()
        .copied()
        .map(normalize_socket_addr)
        .collect::<Vec<_>>();
    let observed_relays = observed
        .relay_urls()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    allowed
        .iter()
        .filter(|location| match location {
            NodeLocation::Direct(address) => observed_ips.contains(address),
            NodeLocation::Relay(url) => observed_relays.contains(url),
        })
        .cloned()
        .collect()
}

fn publication_location_update_needed(
    last_effective: &[NodeLocation],
    next_effective: &[NodeLocation],
) -> bool {
    last_effective != next_effective
}

pub(crate) fn spawn_publication_address_watch(
    endpoint: &Endpoint,
    publication: NodePublicationHandle,
    allowed: Vec<NodeLocation>,
    initial_effective: Vec<NodeLocation>,
) -> JoinHandle<()> {
    let mut updates = endpoint.watch_addr().stream();
    let closed = endpoint.closed();
    tokio::spawn(async move {
        tokio::pin!(closed);
        let mut last_effective = initial_effective;
        loop {
            tokio::select! {
                biased;
                _ = &mut closed => {
                    let error = crate::iroh_publication::PublicationError::new(
                        crate::iroh_publication::PublicationErrorKind::Closed,
                        "Iroh endpoint closed while node publication was still enabled",
                    );
                    eprintln!("IROH-NODE-PUBLICATION-FATAL source=endpoint-closed error={error}");
                    publication.mark_fatal(error);
                    break;
                },
                observed = updates.next() => {
                    let Some(observed) = observed else {
                        publication.mark_fatal(crate::iroh_publication::PublicationError::new(
                            crate::iroh_publication::PublicationErrorKind::State,
                            "endpoint address watch ended unexpectedly while publication was enabled",
                        ));
                        break;
                    };
                    let effective = effective_publication_locations(&allowed, &observed);
                    if !publication_location_update_needed(&last_effective, &effective) {
                        continue;
                    }
                    match publication.update_locations(effective).await {
                        Err(error) => {
                            eprintln!("IROH-NODE-PUBLICATION-FATAL source=address-watch error={error}");
                            publication.mark_fatal(error);
                            break;
                        }
                        Ok(receipt) => {
                            last_effective = receipt.record.locations.clone();
                            eprintln!(
                                "IROH-NODE-PUBLICATION-ADDRESS-CHANGE state={:?} sequence={} locations={}",
                                receipt.record.state,
                                receipt.record.sequence,
                                receipt.record.locations.len(),
                            );
                        }
                    }
                }
            }
        }
    })
}

fn format_alpn(alpn: &[u8]) -> String {
    match std::str::from_utf8(alpn) {
        Ok(text) => format!("{text:?}"),
        Err(_) => format!("0x{}", encode_hex(alpn)),
    }
}

struct EndpointOwner {
    endpoint: Endpoint,
    supervisor: TaskSupervisorHandle,
    capabilities: EndpointCapabilityState,
}

/// A non-owning capability to use the runtime endpoint.
#[derive(Clone)]
pub struct IrohEndpointHandle {
    owner: Weak<EndpointOwner>,
}

impl fmt::Debug for IrohEndpointHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohEndpointHandle")
            .field("alive", &self.owner.strong_count().gt(&0))
            .finish()
    }
}

impl IrohEndpointHandle {
    fn owner(&self) -> Result<Arc<EndpointOwner>, IrohRuntimeError> {
        self.owner.upgrade().ok_or(IrohRuntimeError::Closed)
    }

    /// Connect under runtime ownership, then give the continuation only the
    /// resulting connection. The owning endpoint clone is dropped before any
    /// protocol work starts and can never escape through a generic callback.
    pub async fn run_connected<T, F, Fut>(
        &self,
        name: impl Into<String>,
        addr: EndpointAddr,
        alpn: Vec<u8>,
        dial_timeout: Duration,
        continuation: F,
    ) -> Result<T, IrohRuntimeError>
    where
        T: Send + 'static,
        F: FnOnce(Connection) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        let owner = self.owner()?;
        let endpoint = owner.endpoint.clone();
        let supervisor = owner.supervisor.clone();
        // A constructed-but-unpolled operation future must not retain the
        // runtime's EndpointOwner. Only the operation's narrow endpoint clone
        // and weak supervisor capability cross the await boundary.
        drop(owner);
        supervisor
            .execute(name, async move {
                let connection =
                    match tokio::time::timeout(dial_timeout, endpoint.connect(addr, &alpn)).await {
                        Ok(Ok(connection)) => connection,
                        Ok(Err(error)) => {
                            return Err(IrohRuntimeError::Operation(format!(
                                "dial failed: {error}"
                            )));
                        }
                        Err(_) => {
                            return Err(IrohRuntimeError::Operation(format!(
                                "dial exceeded {dial_timeout:?}"
                            )));
                        }
                    };
                drop(endpoint);
                Ok(continuation(connection).await)
            })
            .await?
    }

    pub fn node_id(&self) -> Result<NodeId, IrohRuntimeError> {
        let owner = self.owner()?;
        Ok(NodeId::from_bytes(*owner.endpoint.id().as_bytes()))
    }

    /// Local sockets as bound. These are observability, not necessarily
    /// publishable addresses: global wildcard binds are deliberately retained.
    pub fn bound_socket_addrs(&self) -> Result<Vec<SocketAddr>, IrohRuntimeError> {
        Ok(self.owner()?.endpoint.bound_sockets())
    }

    /// Concrete addresses safe to hand to a direct dialer.
    pub fn reachable_socket_addrs(&self) -> Result<Vec<SocketAddr>, IrohRuntimeError> {
        let sockets = self.bound_socket_addrs()?;
        Ok(sockets
            .into_iter()
            .filter(|socket| !socket.ip().is_unspecified())
            .collect())
    }

    pub fn endpoint_addr(&self) -> Result<EndpointAddr, IrohRuntimeError> {
        let owner = self.owner()?;
        endpoint_addr(&owner.endpoint)
    }

    pub fn address_lookup_count(&self) -> Result<usize, IrohRuntimeError> {
        let owner = self.owner()?;
        owner
            .endpoint
            .address_lookup()
            .map(|lookups| lookups.len())
            .map_err(|_error| IrohRuntimeError::Closed)
    }

    pub fn capability_state(&self) -> Result<EndpointCapabilityState, IrohRuntimeError> {
        Ok(self.owner()?.capabilities)
    }
}

/// Result of the bounded shutdown path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownOutcome {
    Graceful,
    /// The deadline expired; the router task was aborted and all strong endpoint
    /// owners held by this runtime were dropped.
    Forced,
}

/// Owns the only endpoint/router lifetime for one node.
pub struct IrohNodeRuntime {
    // Explicit shutdown joins these values under one deadline. The Drop
    // implementation first cancels supervised work, then normal field drop
    // releases the router and final endpoint owner as an RAII fallback.
    router: Option<Router>,
    owner: Option<Arc<EndpointOwner>>,
    handle: IrohEndpointHandle,
    shutdown_deadline: Duration,
    supervisor: Option<TaskSupervisor>,
    publication: Option<NodePublicationRuntime>,
    publication_address_watch: Option<JoinHandle<()>>,
    node_lookup: Option<NodeLookupRuntime>,
}

impl Drop for IrohNodeRuntime {
    fn drop(&mut self) {
        // A hard drop cannot promise a network withdrawal, but it does stop the
        // refresh owner before endpoint/task cancellation. The signed TTL is the
        // fail-safe for crashes; explicit `shutdown` performs the tombstone.
        if let Some(watcher) = self.publication_address_watch.take() {
            watcher.abort();
        }
        if let Some(lookup) = &self.node_lookup {
            lookup.close();
        }
        self.publication.take();
        if let Some(supervisor) = &self.supervisor {
            supervisor.cancel_now();
        }
    }
}

impl fmt::Debug for IrohNodeRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohNodeRuntime")
            .field("alive", &self.owner.is_some())
            .field("shutdown_deadline", &self.shutdown_deadline)
            .field("publication_enabled", &self.publication.is_some())
            .field("node_lookup_enabled", &self.node_lookup.is_some())
            .finish()
    }
}

impl IrohNodeRuntime {
    pub fn endpoint_handle(&self) -> IrohEndpointHandle {
        self.handle.clone()
    }

    pub fn task_supervisor_handle(&self) -> TaskSupervisorHandle {
        self.supervisor
            .as_ref()
            .map(TaskSupervisor::handle)
            .unwrap_or_else(TaskSupervisorHandle::disconnected)
    }

    pub fn node_id(&self) -> Result<NodeId, IrohRuntimeError> {
        self.handle.node_id()
    }

    pub fn bound_socket_addrs(&self) -> Result<Vec<SocketAddr>, IrohRuntimeError> {
        self.handle.bound_socket_addrs()
    }

    pub fn capability_state(&self) -> Result<EndpointCapabilityState, IrohRuntimeError> {
        self.handle.capability_state()
    }

    pub fn node_publication_handle(&self) -> Option<NodePublicationHandle> {
        self.publication
            .as_ref()
            .map(NodePublicationRuntime::handle)
    }

    pub fn node_lookup_handle(&self) -> Option<NodeLookupHandle> {
        self.node_lookup.as_ref().map(NodeLookupRuntime::handle)
    }

    /// Resolve one typed identity through the exact lookup registry installed
    /// on this endpoint. This diagnostic seam proves the adapter returns a real
    /// Iroh `Item`; it adds no peer-list or inventory operation.
    #[doc(hidden)]
    pub async fn resolve_registered_node_lookup(
        &self,
        node_id: NodeId,
    ) -> Result<iroh::address_lookup::Item, IrohRuntimeError> {
        let owner = self.owner.as_ref().ok_or(IrohRuntimeError::Closed)?.clone();
        let endpoint_id = iroh::PublicKey::from_bytes(node_id.as_bytes()).map_err(|error| {
            IrohRuntimeError::Operation(format!("invalid typed lookup NodeId: {error}"))
        })?;
        let lookups = owner
            .endpoint
            .address_lookup()
            .map_err(|_| IrohRuntimeError::Closed)?;
        let mut results = lookups.resolve(endpoint_id);
        match results.next().await {
            Some(Ok(Ok(item))) => Ok(item),
            Some(Ok(Err(error))) => Err(IrohRuntimeError::Operation(format!(
                "registered node lookup failed: {error}"
            ))),
            Some(Err(error)) => Err(IrohRuntimeError::Operation(format!(
                "registered node lookup produced no result: {error}"
            ))),
            None => Err(IrohRuntimeError::Operation(
                "registered node lookup stream ended without a result".into(),
            )),
        }
    }

    pub async fn shutdown(mut self) -> Result<ShutdownOutcome, IrohRuntimeError> {
        let started_at = tokio::time::Instant::now();
        let absolute_deadline = started_at + self.shutdown_deadline;
        let force_reserve = std::cmp::min(self.shutdown_deadline / 2, Duration::from_millis(100));
        let graceful_deadline = absolute_deadline - force_reserve;
        let mut task_errors = Vec::new();
        if let Some(lookup) = &self.node_lookup {
            lookup.close();
        }
        if let Some(watcher) = self.publication_address_watch.take() {
            if watcher.is_finished() {
                if let Err(error) = watcher.await {
                    task_errors.push(format!(
                        "node-publication address watch terminated unexpectedly: {error}"
                    ));
                }
            } else {
                watcher.abort();
                let _ = watcher.await;
            }
        }
        if let Some(publication) = self.publication.take() {
            if let Some(error) = publication.fatal_error() {
                task_errors.push(format!("node-publication fatal health failure: {error}"));
            }
            let withdrawal_deadline = std::cmp::min(
                graceful_deadline,
                tokio::time::Instant::now() + PUBLICATION_TRANSITION_DEADLINE,
            );
            match publication.shutdown(withdrawal_deadline).await {
                Ok(receipt) => eprintln!(
                    "IROH-NODE-PUBLICATION-WITHDRAWN sequence={} locations={} visibility_ms={}",
                    receipt.record.sequence,
                    receipt.record.locations.len(),
                    receipt.visibility_elapsed.as_millis(),
                ),
                Err(error) => task_errors.push(format!("node-publication withdrawal: {error}")),
            }
        }
        let router = self.router.take().ok_or_else(|| {
            IrohRuntimeError::Shutdown("runtime router was already taken".to_string())
        })?;
        let endpoint = self
            .owner
            .as_ref()
            .ok_or_else(|| IrohRuntimeError::Shutdown("runtime endpoint owner is missing".into()))?
            .endpoint
            .clone();
        let supervisor = self.supervisor.take().ok_or_else(|| {
            IrohRuntimeError::Shutdown("runtime task supervisor is missing".into())
        })?;
        let process_jobs = supervisor.process_jobs();

        // Poll Endpoint::close once before cancelling any application work. The
        // handshake is sent only after that first poll, making "endpoint first"
        // an observed ordering rather than scheduler luck.
        let (close_started_tx, close_started_rx) = oneshot::channel();
        let close_join = tokio::spawn(async move {
            let mut close = Box::pin(endpoint.close());
            let mut close_started_tx = Some(close_started_tx);
            let completed_on_first_poll = poll_fn(|cx| {
                let poll = close.as_mut().poll(cx);
                if let Some(started) = close_started_tx.take() {
                    let _ = started.send(());
                }
                std::task::Poll::Ready(poll.is_ready())
            })
            .await;
            if !completed_on_first_poll {
                close.await;
            }
        });
        let mut forced = tokio::time::timeout_at(graceful_deadline, close_started_rx)
            .await
            .is_err();

        let mut tasks = supervisor.begin_shutdown()?;
        tasks.push(TrackedTask {
            name: "endpoint-close".to_string(),
            join: close_join,
        });
        let router_failures = Arc::new(Mutex::new(Vec::new()));
        let router_failures_for_task = router_failures.clone();
        tasks.push(TrackedTask {
            name: "router-shutdown".to_string(),
            join: tokio::spawn(async move {
                if let Err(error) = router.shutdown().await {
                    eprintln!("IROH-ROUTER-SHUTDOWN-FAILED error={error}");
                    if let Ok(mut failures) = router_failures_for_task.lock() {
                        failures.push(format!("router shutdown: {error}"));
                    }
                }
            }),
        });

        if !forced {
            match tokio::time::timeout_at(
                graceful_deadline,
                wait_for_owned_work(&mut tasks, &process_jobs, &supervisor),
            )
            .await
            {
                Ok(errors) => task_errors.extend(errors),
                Err(_) => forced = true,
            }
        }
        if forced {
            supervisor.abort_active()?;
            for task in &tasks {
                // Keep the registry manager alive so it can join and account
                // for the active tasks whose abort was just requested.
                if task.name != "owned-task-registry" {
                    task.join.abort();
                }
            }
            match tokio::time::timeout_at(
                absolute_deadline,
                wait_for_owned_work(&mut tasks, &process_jobs, &supervisor),
            )
            .await
            {
                Ok(errors) => task_errors.extend(errors),
                Err(_) => {
                    let active_tasks = supervisor.active_task_count();
                    let process_labels = process_jobs.active_labels();
                    let task_names = tasks
                        .iter()
                        .map(|task| task.name.clone())
                        .collect::<Vec<_>>();
                    eprintln!(
                        "IROH-FORCED-TASKS-UNACKNOWLEDGED tasks={task_names:?} active_tasks={active_tasks} process_jobs={process_labels:?} detail=work-did-not-prove-completion-before-absolute-deadline"
                    );
                    task_errors.push(format!(
                        "absolute shutdown deadline expired with tasks={task_names:?}, active_tasks={active_tasks}, process_jobs={process_labels:?}"
                    ));
                    for task in &tasks {
                        task.join.abort();
                    }
                }
            }
            eprintln!(
                "IROH-SHUTDOWN-FORCED deadline_ms={} reason=graceful-deadline-expired",
                self.shutdown_deadline.as_millis()
            );
        }
        for error in &task_errors {
            eprintln!("IROH-OWNED-TASK-SHUTDOWN-FAILED {error}");
        }
        // The router has closed (or been aborted). Dropping the runtime's final
        // strong owner makes surviving provider/fetch weak handles inert and
        // releases the UDP sockets even if application objects outlive us.
        self.owner.take();
        tokio::task::yield_now().await;
        let mut failures = router_failures
            .lock()
            .map_err(|_| IrohRuntimeError::Shutdown("router-failure mutex poisoned".into()))?
            .clone();
        failures.extend(supervisor.recorded_failures()?);
        failures.extend(process_jobs.recorded_failures());
        failures.extend(task_errors);
        drop(supervisor);
        if !failures.is_empty() {
            return Err(IrohRuntimeError::Shutdown(failures.join("; ")));
        }
        Ok(if forced {
            ShutdownOutcome::Forced
        } else {
            ShutdownOutcome::Graceful
        })
    }
}

async fn wait_for_owned_work(
    tasks: &mut Vec<TrackedTask>,
    process_jobs: &ProcessJobRegistry,
    supervisor: &TaskSupervisor,
) -> Vec<String> {
    let mut errors = Vec::new();
    loop {
        let mut index = 0;
        while index < tasks.len() {
            if tasks[index].join.is_finished() {
                let task = tasks.swap_remove(index);
                if let Err(error) = task.join.await
                    && !error.is_cancelled()
                {
                    errors.push(format!("task={} join_error={error}", task.name));
                }
            } else {
                index += 1;
            }
        }
        if tasks.is_empty() && process_jobs.active_len() == 0 && supervisor.active_task_count() == 0
        {
            return errors;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// The single endpoint constructor used by runtime and benchmark.
#[doc(hidden)]
pub async fn bind_endpoint(
    profile: EndpointProfile,
    identity: IdentitySource,
    relay: RelayCapability,
    address_lookup: AddressLookupCapability,
) -> Result<Endpoint, IrohRuntimeError> {
    if matches!(profile.scope, EndpointScope::OfflineTest { .. })
        && (!matches!(&relay, RelayCapability::Disabled)
            || !matches!(&address_lookup, AddressLookupCapability::Disabled))
    {
        return Err(IrohRuntimeError::Configuration(
            "offline-test rejects relay/address-lookup capability injection".to_string(),
        ));
    }
    bind_endpoint_with_lookups(profile, identity, relay, address_lookup).await
}

async fn bind_endpoint_with_lookups(
    profile: EndpointProfile,
    identity: IdentitySource,
    relay: RelayCapability,
    address_lookup: AddressLookupCapability,
) -> Result<Endpoint, IrohRuntimeError> {
    let secret_key = load_identity(identity)?;
    let installed = match address_lookup {
        AddressLookupCapability::Disabled => InstalledAddressLookup::Disabled,
        AddressLookupCapability::Memory => InstalledAddressLookup::Memory,
        AddressLookupCapability::PinnedPkarr(_) => {
            return Err(IrohRuntimeError::Configuration(
                "pinned node lookup requires IrohRuntimeBuilder ownership and a narrow lookup handle"
                    .into(),
            ));
        }
    };
    bind_endpoint_with_secret(profile, secret_key, relay, installed).await
}

enum InstalledAddressLookup {
    Disabled,
    Memory,
    PinnedPkarr(NodeLookupHandle),
}

async fn bind_endpoint_with_secret(
    profile: EndpointProfile,
    secret_key: SecretKey,
    relay: RelayCapability,
    address_lookup: InstalledAddressLookup,
) -> Result<Endpoint, IrohRuntimeError> {
    // Snapshot at the last point before materialising Iroh configuration. A
    // Custom RelayMap has shared interior upstream; passing it through would let
    // an external alias silently change recipients after capability_state was
    // frozen. The endpoint receives only this fresh daemon-owned map.
    let relay = snapshot_relay_capability(relay)?;
    // Minimal supplies the pinned crypto provider only. Every network-affecting
    // default is cleared/disabled here before the closed scope is applied.
    let mut builder = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .clear_relay_transports()
        .clear_address_lookup()
        .portmapper_config(PortmapperConfig::Disabled)
        .net_report_config(NetReportConfig::minimal())
        .secret_key(secret_key);

    builder = match profile.scope {
        EndpointScope::OfflineTest { port } => builder
            .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .map_err(|error| IrohRuntimeError::Bind(format!("adding IPv4 loopback: {error}")))?
            .bind_addr(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0))
            .map_err(|error| IrohRuntimeError::Bind(format!("adding IPv6 loopback: {error}")))?,
        EndpointScope::Lan { ipv4, ipv6, port } => {
            let builder = builder
                .bind_addr(SocketAddrV4::new(ipv4, port))
                .map_err(|error| IrohRuntimeError::Bind(format!("adding LAN IPv4: {error}")))?;
            match ipv6 {
                Some(ipv6) => builder
                    .bind_addr(SocketAddrV6::new(ipv6, port, 0, 0))
                    .map_err(|error| IrohRuntimeError::Bind(format!("adding LAN IPv6: {error}")))?,
                None => builder,
            }
        }
        EndpointScope::Global { port } => builder
            .bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
            .map_err(|error| IrohRuntimeError::Bind(format!("adding global IPv4: {error}")))?
            .bind_addr(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))
            .map_err(|error| IrohRuntimeError::Bind(format!("adding global IPv6: {error}")))?,
    };

    if let RelayCapability::Enabled(mode) = relay {
        builder = builder.relay_mode(mode);
    }
    match address_lookup {
        InstalledAddressLookup::Disabled => {}
        InstalledAddressLookup::Memory => {
            builder = builder.address_lookup(iroh::address_lookup::memory::MemoryLookup::new());
        }
        InstalledAddressLookup::PinnedPkarr(lookup) => {
            builder = builder.address_lookup(lookup.adapter());
        }
    }
    builder
        .bind()
        .await
        .map_err(|error| IrohRuntimeError::Bind(format!("profile {profile:?}: {error}")))
}

fn validate_relay_capability(relay: &RelayCapability) -> Result<(), IrohRuntimeError> {
    let RelayCapability::Enabled(mode) = relay else {
        return Ok(());
    };
    if matches!(mode, RelayMode::Disabled) || mode.relay_map().is_empty() {
        return Err(IrohRuntimeError::Configuration(
            "RelayCapability::Enabled requires a non-disabled, non-empty relay map".into(),
        ));
    }
    Ok(())
}

fn snapshot_relay_capability(relay: RelayCapability) -> Result<RelayCapability, IrohRuntimeError> {
    let RelayCapability::Enabled(mode) = relay else {
        return Ok(RelayCapability::Disabled);
    };
    if matches!(mode, RelayMode::Disabled) {
        return Err(IrohRuntimeError::Configuration(
            "RelayCapability::Enabled requires a non-disabled, non-empty relay map".into(),
        ));
    }
    let source = mode.relay_map();
    let configs = source.relays::<Vec<_>>();
    if configs.is_empty() {
        return Err(IrohRuntimeError::Configuration(
            "RelayCapability::Enabled requires a non-disabled, non-empty relay map".into(),
        ));
    }
    Ok(RelayCapability::Enabled(RelayMode::Custom(
        iroh::RelayMap::from_iter(configs),
    )))
}

pub fn endpoint_addr(endpoint: &Endpoint) -> Result<EndpointAddr, IrohRuntimeError> {
    let sockets = endpoint
        .bound_sockets()
        .into_iter()
        .filter(|socket| !socket.ip().is_unspecified())
        .collect::<Vec<_>>();
    if sockets.is_empty() {
        return Err(IrohRuntimeError::Bind(
            "bound endpoint reported no concrete reachable socket addresses; wildcard bind addresses are never publishable"
                .to_string(),
        ));
    }
    let mut addr = EndpointAddr::new(endpoint.id());
    for socket in sockets {
        addr = addr.with_ip_addr(socket);
    }
    Ok(addr)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRecord {
    schema_version: u32,
    secret_key_hex: String,
    node_id_hex: String,
    checksum_blake3_hex: String,
}

fn load_identity(source: IdentitySource) -> Result<SecretKey, IrohRuntimeError> {
    match source {
        IdentitySource::Ephemeral => Ok(SecretKey::generate()),
        IdentitySource::Persistent { state_dir } => load_or_create_identity(&state_dir),
    }
}

/// Exposed for focused persistence tests without binding a network socket.
#[doc(hidden)]
pub fn load_or_create_identity(state_dir: &Path) -> Result<SecretKey, IrohRuntimeError> {
    load_or_create_identity_with_hooks(state_dir, &IdentityInitializationHooks::default())
}

/// Deterministic synchronization/failpoint hooks for identity durability tests.
/// Product code always uses the empty default.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct IdentityInitializationHooks {
    after_absent: Option<Arc<dyn Fn() + Send + Sync>>,
    after_publish_before_sync: Option<Arc<dyn Fn() + Send + Sync>>,
    before_first_return_validation: Option<Arc<dyn Fn() + Send + Sync>>,
    after_open_before_read: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl IdentityInitializationHooks {
    pub fn after_absent(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.after_absent = Some(Arc::new(hook));
        self
    }

    pub fn after_publish_before_sync(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.after_publish_before_sync = Some(Arc::new(hook));
        self
    }

    pub fn before_first_return_validation(
        mut self,
        hook: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        self.before_first_return_validation = Some(Arc::new(hook));
        self
    }

    pub fn after_open_before_read(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
        self.after_open_before_read = Some(Arc::new(hook));
        self
    }
}

/// Test seam for synchronized collision and crash-after-publication oracles.
#[doc(hidden)]
pub fn load_or_create_identity_with_hooks(
    state_dir: &Path,
    hooks: &IdentityInitializationHooks,
) -> Result<SecretKey, IrohRuntimeError> {
    let (dirfd, created) = open_state_directory(state_dir)?;
    if created {
        fs::fchmod(&dirfd, Mode::from_raw_mode(STATE_DIRECTORY_MODE))
            .map_err(|error| identity_io(state_dir, "setting new state-directory mode", error))?;
        fs::fsync(&dirfd)
            .map_err(|error| identity_io(state_dir, "syncing new state directory", error))?;
    }
    validate_directory(&dirfd, state_dir)?;

    let key = match open_identity_file(&dirfd) {
        Ok(file) => read_identity(file, &dirfd, state_dir, hooks),
        Err(Errno::NOENT) => {
            if let Some(hook) = &hooks.after_absent {
                hook();
            }
            initialize_identity(&dirfd, state_dir, hooks)
        }
        Err(error) => Err(identity_io(
            state_dir,
            "opening existing identity without following symlinks",
            error,
        )),
    }?;
    // Every successful observer establishes directory-entry durability for
    // itself. This covers an existing-file reader racing a publisher that dies
    // after linkat but before its own fsync.
    fs::fsync(&dirfd).map_err(|error| {
        identity_io(
            state_dir,
            "syncing identity directory before success",
            error,
        )
    })?;
    Ok(key)
}

pub(crate) fn open_state_directory(state_dir: &Path) -> Result<(OwnedFd, bool), IrohRuntimeError> {
    let name = state_dir.file_name().ok_or_else(|| {
        IrohRuntimeError::Identity(format!(
            "{} has no final directory component",
            state_dir.display()
        ))
    })?;
    let parent = state_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parentfd = fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| identity_io(state_dir, "opening state-directory parent", error))?;
    let created = match fs::mkdirat(&parentfd, name, Mode::from_raw_mode(STATE_DIRECTORY_MODE)) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(error) => {
            return Err(identity_io(
                state_dir,
                "creating state directory (its parent must already exist)",
                error,
            ));
        }
    };
    let dirfd = fs::openat(
        &parentfd,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        identity_io(
            state_dir,
            "opening state directory as a real directory without following symlinks",
            error,
        )
    })?;
    if created {
        // Syncing the new directory itself does not make its parent entry
        // durable. Persist the mkdir before returning a key whose record will be
        // fsynced inside it.
        fs::fsync(&parentfd)
            .map_err(|error| identity_io(state_dir, "syncing state-directory parent", error))?;
    }
    Ok((dirfd, created))
}

pub(crate) fn validate_directory(
    dirfd: &OwnedFd,
    state_dir: &Path,
) -> Result<(), IrohRuntimeError> {
    let stat = fs::fstat(dirfd)
        .map_err(|error| identity_io(state_dir, "inspecting state directory", error))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(IrohRuntimeError::Identity(format!(
            "{} is not a directory",
            state_dir.display()
        )));
    }
    validate_expected_owner(
        &state_dir.display().to_string(),
        stat.st_uid,
        rustix::process::geteuid().as_raw(),
    )?;
    let mode = stat.st_mode & 0o777;
    if mode != STATE_DIRECTORY_MODE {
        return Err(IrohRuntimeError::Identity(format!(
            "{} mode is {mode:#05o}, required {STATE_DIRECTORY_MODE:#05o}",
            state_dir.display()
        )));
    }
    Ok(())
}

fn open_identity_file(dirfd: &OwnedFd) -> Result<OwnedFd, Errno> {
    fs::openat(
        dirfd,
        IROH_IDENTITY_FILENAME,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

fn read_identity(
    file: OwnedFd,
    dirfd: &OwnedFd,
    state_dir: &Path,
    hooks: &IdentityInitializationHooks,
) -> Result<SecretKey, IrohRuntimeError> {
    let stat_before = fs::fstat(&file)
        .map_err(|error| identity_io(state_dir, "inspecting identity file", error))?;
    validate_identity_stat(&stat_before, state_dir)?;
    if let Some(hook) = &hooks.after_open_before_read {
        hook();
    }

    let mut file = File::from(file);
    let mut bytes = Vec::with_capacity(stat_before.st_size as usize);
    (&mut file)
        .take(MAX_IDENTITY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            IrohRuntimeError::Identity(format!(
                "reading {}: {error}",
                state_dir.join(IROH_IDENTITY_FILENAME).display()
            ))
        })?;
    if bytes.len() as u64 > MAX_IDENTITY_BYTES {
        return Err(IrohRuntimeError::Identity(format!(
            "{} grew beyond {MAX_IDENTITY_BYTES} bytes while reading",
            state_dir.join(IROH_IDENTITY_FILENAME).display()
        )));
    }
    let stat_after = fs::fstat(&file)
        .map_err(|error| identity_io(state_dir, "re-inspecting identity after read", error))?;
    validate_identity_stat(&stat_after, state_dir)?;
    let directory_stat = fs::statat(dirfd, IROH_IDENTITY_FILENAME, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| {
            identity_io(
                state_dir,
                "checking identity directory entry after read",
                error,
            )
        })?;
    if stat_before.st_dev != stat_after.st_dev
        || stat_before.st_ino != stat_after.st_ino
        || stat_before.st_size != stat_after.st_size
        || stat_before.st_mtime != stat_after.st_mtime
        || stat_before.st_mtime_nsec != stat_after.st_mtime_nsec
        || stat_before.st_ctime != stat_after.st_ctime
        || stat_before.st_ctime_nsec != stat_after.st_ctime_nsec
        || stat_after.st_dev != directory_stat.st_dev
        || stat_after.st_ino != directory_stat.st_ino
    {
        return Err(IrohRuntimeError::Identity(format!(
            "{} changed while it was being read; refusing an unstable identity",
            state_dir.join(IROH_IDENTITY_FILENAME).display()
        )));
    }
    decode_identity_record(&bytes).map_err(|why| {
        IrohRuntimeError::Identity(format!(
            "{}: {why}",
            state_dir.join(IROH_IDENTITY_FILENAME).display()
        ))
    })
}

fn validate_identity_stat(
    stat: &rustix::fs::Stat,
    state_dir: &Path,
) -> Result<(), IrohRuntimeError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(IrohRuntimeError::Identity(format!(
            "{} is not a regular file",
            state_dir.join(IROH_IDENTITY_FILENAME).display()
        )));
    }
    validate_expected_owner(
        &state_dir.join(IROH_IDENTITY_FILENAME).display().to_string(),
        stat.st_uid,
        rustix::process::geteuid().as_raw(),
    )?;
    let mode = stat.st_mode & 0o777;
    if mode != IDENTITY_FILE_MODE {
        return Err(IrohRuntimeError::Identity(format!(
            "{} mode is {mode:#05o}, required {IDENTITY_FILE_MODE:#05o}",
            state_dir.join(IROH_IDENTITY_FILENAME).display()
        )));
    }
    if stat.st_nlink != 1 {
        return Err(IrohRuntimeError::Identity(format!(
            "{} has {} hard links; required exactly one",
            state_dir.join(IROH_IDENTITY_FILENAME).display(),
            stat.st_nlink
        )));
    }
    if stat.st_size < 0 || stat.st_size as u64 > MAX_IDENTITY_BYTES {
        return Err(IrohRuntimeError::Identity(format!(
            "{} size is outside 0..={MAX_IDENTITY_BYTES} bytes",
            state_dir.join(IROH_IDENTITY_FILENAME).display()
        )));
    }

    Ok(())
}

/// Pure ownership-policy seam used by both identity metadata checks.
/// Filesystem integration tests can only manufacture a foreign UID as root;
/// this function makes the reject/accept decision executable on every run.
#[doc(hidden)]
pub fn validate_expected_owner(
    label: &str,
    actual_uid: u32,
    expected_uid: u32,
) -> Result<(), IrohRuntimeError> {
    if actual_uid == expected_uid {
        Ok(())
    } else {
        Err(IrohRuntimeError::Identity(format!(
            "{label} is not owned by the current effective user (uid {actual_uid}, required {expected_uid})"
        )))
    }
}

fn initialize_identity(
    dirfd: &OwnedFd,
    state_dir: &Path,
    hooks: &IdentityInitializationHooks,
) -> Result<SecretKey, IrohRuntimeError> {
    let key = SecretKey::generate();
    let bytes = encode_identity_record(&key)?;
    // O_TMPFILE has no directory name to leak after a crash. Publication is a
    // single no-replace linkat; concurrent initializers either win or read the
    // same winner, with no stale secret-bearing temp files to reap.
    let temp_fd = fs::openat(
        dirfd,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(IDENTITY_FILE_MODE),
    )
    .map_err(|error| identity_io(state_dir, "creating unnamed identity temporary file", error))?;
    fs::fchmod(&temp_fd, Mode::from_raw_mode(IDENTITY_FILE_MODE))
        .map_err(|error| identity_io(state_dir, "setting identity temporary-file mode", error))?;
    let mut temp_file = File::from(temp_fd);
    let write_result = (|| -> std::io::Result<()> {
        temp_file.write_all(&bytes)?;
        temp_file.sync_all()
    })();
    if let Err(error) = write_result {
        return Err(IrohRuntimeError::Identity(format!(
            "writing and syncing identity temporary file in {}: {error}",
            state_dir.display()
        )));
    }
    match fs::linkat(
        &temp_file,
        "",
        dirfd,
        IROH_IDENTITY_FILENAME,
        AtFlags::EMPTY_PATH,
    ) {
        Ok(()) => {
            if let Some(hook) = &hooks.after_publish_before_sync {
                hook();
            }
            fs::fsync(dirfd).map_err(|error| {
                identity_io(
                    state_dir,
                    "syncing state directory after identity publish",
                    error,
                )
            })?;
            if let Some(hook) = &hooks.before_first_return_validation {
                hook();
            }
            let temp_stat = fs::fstat(&temp_file).map_err(|error| {
                identity_io(
                    state_dir,
                    "inspecting published identity source inode",
                    error,
                )
            })?;
            validate_identity_stat(&temp_stat, state_dir)?;
            let published_file = open_identity_file(dirfd).map_err(|error| {
                identity_io(
                    state_dir,
                    "opening newly published identity for first-return validation",
                    error,
                )
            })?;
            let published_stat = fs::fstat(&published_file).map_err(|error| {
                identity_io(
                    state_dir,
                    "inspecting newly published identity directory entry",
                    error,
                )
            })?;
            if temp_stat.st_dev != published_stat.st_dev
                || temp_stat.st_ino != published_stat.st_ino
            {
                return Err(IrohRuntimeError::Identity(format!(
                    "{} no longer names the inode published by this initializer",
                    state_dir.join(IROH_IDENTITY_FILENAME).display()
                )));
            }
            let validated = read_identity(published_file, dirfd, state_dir, hooks)?;
            if validated.to_bytes() != key.to_bytes() {
                return Err(IrohRuntimeError::Identity(format!(
                    "{} decoded a different key than this initializer published",
                    state_dir.join(IROH_IDENTITY_FILENAME).display()
                )));
            }
            Ok(validated)
        }
        Err(Errno::EXIST) => {
            // Sync the winning link before returning it, even if the
            // winning process dies before reaching its own fsync.
            fs::fsync(dirfd).map_err(|error| {
                identity_io(
                    state_dir,
                    "syncing concurrently initialized identity",
                    error,
                )
            })?;
            let file = open_identity_file(dirfd).map_err(|error| {
                identity_io(
                    state_dir,
                    "opening identity won by concurrent initializer",
                    error,
                )
            })?;
            read_identity(file, dirfd, state_dir, hooks)
        }
        Err(error) => Err(identity_io(
            state_dir,
            "publishing identity atomically with no-replace linkat",
            error,
        )),
    }
}

fn encode_identity_record(key: &SecretKey) -> Result<Vec<u8>, IrohRuntimeError> {
    let secret = key.to_bytes();
    let node = *key.public().as_bytes();
    let record = IdentityRecord {
        schema_version: IDENTITY_SCHEMA_VERSION,
        secret_key_hex: encode_hex(&secret),
        node_id_hex: encode_hex(&node),
        checksum_blake3_hex: encode_hex(checksum(&secret, &node).as_bytes()),
    };
    serde_json::to_vec_pretty(&record).map_err(|error| {
        IrohRuntimeError::Identity(format!("encoding new identity record: {error}"))
    })
}

fn decode_identity_record(bytes: &[u8]) -> Result<SecretKey, String> {
    let record: IdentityRecord =
        serde_json::from_slice(bytes).map_err(|error| format!("malformed JSON record: {error}"))?;
    if record.schema_version != IDENTITY_SCHEMA_VERSION {
        return Err(format!(
            "unknown schema_version {}; supported version is {IDENTITY_SCHEMA_VERSION}",
            record.schema_version
        ));
    }
    let secret = decode_hex_32("secret_key_hex", &record.secret_key_hex)?;
    let stored_node = decode_hex_32("node_id_hex", &record.node_id_hex)?;
    let stored_checksum = decode_hex_32("checksum_blake3_hex", &record.checksum_blake3_hex)?;
    let key = SecretKey::from_bytes(&secret);
    let derived_node = *key.public().as_bytes();
    if stored_node != derived_node {
        return Err("node_id_hex does not match the secret key".to_string());
    }
    if stored_checksum != *checksum(&secret, &derived_node).as_bytes() {
        return Err("checksum_blake3_hex does not match the identity record".to_string());
    }
    Ok(key)
}

fn checksum(secret: &[u8; 32], node: &[u8; 32]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(IDENTITY_CHECKSUM_DOMAIN);
    hasher.update(&IDENTITY_SCHEMA_VERSION.to_be_bytes());
    hasher.update(secret);
    hasher.update(node);
    hasher.finalize()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_32(field: &str, text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err(format!(
            "{field} must contain exactly 64 lowercase hex digits"
        ));
    }
    let mut out = [0u8; 32];
    let bytes = text.as_bytes();
    for index in 0..32 {
        let high = decode_nibble(bytes[index * 2])
            .ok_or_else(|| format!("{field} contains non-lowercase-hex data"))?;
        let low = decode_nibble(bytes[index * 2 + 1])
            .ok_or_else(|| format!("{field} contains non-lowercase-hex data"))?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn identity_io(state_dir: &Path, operation: &str, error: Errno) -> IrohRuntimeError {
    IrohRuntimeError::Identity(format!("{operation} at {}: {error}", state_dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    // These were top-level imports until TASK-146 moved the task supervisor out; the
    // remaining endpoint-runtime tests still build supervised-process specs and poke the
    // active-task counter directly, so they are scoped to the test module now.
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::iroh_publication::{NodePublicationConfig, PublicationAuthorityAuthorization};
    use iroh::TransportAddr;
    use iroh::endpoint::Connection;
    use iroh::protocol::AcceptError;

    #[derive(Debug, Clone)]
    struct Noop;

    impl ProtocolHandler for Noop {
        async fn accept(&self, _connection: Connection) -> Result<(), AcceptError> {
            Ok(())
        }
    }

    #[test]
    fn duplicate_alpn_is_rejected_before_router_construction() {
        let builder = IrohRuntimeBuilder::new(
            DAEMON_TEST_ENDPOINT_PROFILE,
            IdentitySource::Ephemeral,
            RelayCapability::Disabled,
            AddressLookupCapability::Disabled,
        )
        .expect("offline builder");
        let builder = builder.accept(b"/duplicate/1", Noop).expect("first ALPN");
        let error = builder
            .accept(b"/duplicate/1", Noop)
            .expect_err("duplicate must fail instead of silently replacing");
        assert!(matches!(error, IrohRuntimeError::DuplicateAlpn(_)));
    }

    #[test]
    fn offline_scope_rejects_network_capabilities() {
        assert!(
            IrohRuntimeBuilder::new(
                DAEMON_TEST_ENDPOINT_PROFILE,
                IdentitySource::Ephemeral,
                RelayCapability::Enabled(RelayMode::Default),
                AddressLookupCapability::Disabled,
            )
            .is_err()
        );
        assert!(
            IrohRuntimeBuilder::new(
                DAEMON_TEST_ENDPOINT_PROFILE,
                IdentitySource::Ephemeral,
                RelayCapability::Disabled,
                AddressLookupCapability::Memory,
            )
            .is_err()
        );

        let publication = NodePublicationConfig::new(
            "run-1",
            "authority.test:v1",
            "127.0.0.1:8080".parse().unwrap(),
            "authority.test",
            PublicationAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
            Duration::from_secs(30),
            Duration::from_secs(10),
            Duration::from_secs(2),
            [NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap()],
        )
        .unwrap();
        let builder = IrohRuntimeBuilder::new(
            DAEMON_TEST_ENDPOINT_PROFILE,
            IdentitySource::Ephemeral,
            RelayCapability::Disabled,
            AddressLookupCapability::Disabled,
        )
        .unwrap();
        assert!(
            builder
                .node_publication(NodePublicationCapability::Enabled(publication))
                .is_err()
        );
    }

    #[test]
    fn publication_candidates_follow_observed_endpoint_addresses() {
        let key = SecretKey::generate();
        let matching = NodeLocation::direct("192.0.2.10:4433".parse().unwrap()).unwrap();
        let removed = NodeLocation::direct("192.0.2.11:4433".parse().unwrap()).unwrap();
        let relay = NodeLocation::relay("https://relay.example.test").unwrap();
        let observed = EndpointAddr::from_parts(
            key.public(),
            [TransportAddr::Ip("192.0.2.10:4433".parse().unwrap())],
        );
        assert_eq!(
            effective_publication_locations(
                &[matching.clone(), removed.clone(), relay.clone()],
                &observed,
            ),
            vec![matching.clone()]
        );
        assert!(
            effective_publication_locations(
                &[matching.clone(), removed, relay],
                &EndpointAddr::from(key.public()),
            )
            .is_empty(),
            "empty intersection drives a signed withdrawal"
        );

        let mapped = EndpointAddr::from_parts(
            key.public(),
            [TransportAddr::Ip(
                "[::ffff:192.0.2.10]:4433".parse().unwrap(),
            )],
        );
        assert_eq!(
            effective_publication_locations(std::slice::from_ref(&matching), &mapped),
            vec![matching]
        );
    }

    #[test]
    fn identical_publication_watch_observation_is_a_no_op() {
        let location = NodeLocation::direct("192.0.2.10:4433".parse().unwrap()).unwrap();
        assert!(!publication_location_update_needed(
            std::slice::from_ref(&location),
            std::slice::from_ref(&location),
        ));
        assert!(publication_location_update_needed(
            std::slice::from_ref(&location),
            &[],
        ));
        assert!(!publication_location_update_needed(&[], &[]));
    }

    #[tokio::test]
    async fn publication_startup_deadline_requires_an_actually_observed_location() {
        let endpoint = bind_endpoint(
            DAEMON_TEST_ENDPOINT_PROFILE,
            IdentitySource::Ephemeral,
            RelayCapability::Disabled,
            AddressLookupCapability::Disabled,
        )
        .await
        .unwrap();
        let declared_but_unobserved =
            NodeLocation::direct("192.0.2.10:4433".parse().unwrap()).unwrap();
        let error = wait_for_initial_publication_locations(
            &endpoint,
            &[declared_but_unobserved],
            tokio::time::Instant::now() + Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.kind,
            crate::iroh_publication::PublicationErrorKind::Configuration
        );
        assert!(error.to_string().contains("withdrawal-as-readiness"));
        endpoint.close().await;
    }

    #[test]
    fn relay_candidate_requires_runtime_relay_capability() {
        let publication = NodePublicationConfig::new(
            "run-1",
            "authority.test:v1",
            "127.0.0.1:8080".parse().unwrap(),
            "authority.test",
            PublicationAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
            Duration::from_secs(30),
            Duration::from_secs(10),
            Duration::from_secs(2),
            [NodeLocation::relay("https://relay.example.test").unwrap()],
        )
        .unwrap();
        let builder = IrohRuntimeBuilder::new(
            EndpointProfile {
                scope: EndpointScope::Lan {
                    ipv4: Ipv4Addr::LOCALHOST,
                    ipv6: None,
                    port: 4433,
                },
            },
            IdentitySource::Persistent {
                state_dir: PathBuf::from("unused-test-state"),
            },
            RelayCapability::Disabled,
            AddressLookupCapability::Disabled,
        )
        .unwrap();
        assert!(
            builder
                .node_publication(NodePublicationCapability::Enabled(publication))
                .is_err()
        );
    }

    #[test]
    fn daemon_test_profile_is_const_self_equal() {
        const _: () =
            assert!(DAEMON_TEST_ENDPOINT_PROFILE.same_configuration(DAEMON_TEST_ENDPOINT_PROFILE));
    }

    #[tokio::test]
    async fn abandoned_execute_is_observed_before_the_operation_is_first_polled() {
        let supervisor = TaskSupervisor::new();
        let handle = supervisor.handle();
        let polls = Arc::new(AtomicUsize::new(0));
        {
            let operation_polls = polls.clone();
            let never = poll_fn(move |_context| {
                operation_polls.fetch_add(1, Ordering::SeqCst);
                std::task::Poll::<()>::Pending
            });
            let mut execution = Box::pin(handle.execute("pre-cancelled-execute", never));
            poll_fn(|context| {
                assert!(execution.as_mut().poll(context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            // Registration happened during the manual poll above. Dropping the
            // caller now closes result_rx before the manager can first poll the
            // registered operation on this current-thread executor.
            drop(execution);
        }
        tokio::task::yield_now().await;
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        let mut tasks = supervisor.begin_shutdown().expect("begin shutdown");
        let errors = wait_for_owned_work(&mut tasks, &supervisor.process_jobs(), &supervisor).await;
        assert!(errors.is_empty(), "tracked task errors: {errors:?}");
    }

    #[tokio::test]
    async fn supervised_process_kills_and_reaps_pipe_holding_grandchild() {
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let pid_file = std::env::temp_dir().join(format!("nix-p2p-process-pids-{suffix}"));
        let activity_file = std::env::temp_dir().join(format!("nix-p2p-process-activity-{suffix}"));
        let supervisor = TaskSupervisor::new();
        let handle = supervisor.handle();
        let operation = tokio::spawn({
            let pid_file = pid_file.clone();
            let activity_file = activity_file.clone();
            async move {
                handle
                    .execute_process(
                        "grandchild-pipe-regression",
                        PathBuf::from("sh"),
                        vec![
                            OsString::from("-c"),
                            OsString::from(
                                "(while :; do printf x >> \"$2\"; sleep 0.01; done) & grand=$!; printf '%s %s' \"$$\" \"$grand\" > \"$1\"; wait",
                            ),
                            OsString::from("nix-p2p-supervised-helper"),
                            pid_file.as_os_str().to_owned(),
                            activity_file.as_os_str().to_owned(),
                        ],
                        Vec::new(),
                        1,
                    )
                    .await
            }
        });

        let pids = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(raw) = std::fs::read_to_string(&pid_file)
                    && raw.split_whitespace().count() == 2
                {
                    break raw;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("helper and grandchild published their pids");
        let pids = pids
            .split_whitespace()
            .map(|raw| raw.parse::<u32>().expect("decimal pid"))
            .collect::<Vec<_>>();

        let process_jobs = supervisor.process_jobs();
        let mut tasks = supervisor.begin_shutdown().expect("begin shutdown");
        let errors = tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_owned_work(&mut tasks, &process_jobs, &supervisor),
        )
        .await
        .expect("process group kill and reap are bounded");
        assert!(errors.is_empty(), "tracked task errors: {errors:?}");
        assert!(operation.await.unwrap().is_err());

        for pid in pids {
            assert!(
                !PathBuf::from(format!("/proc/{pid}")).exists(),
                "supervised pid {pid} still exists after shutdown returned"
            );
        }
        let activity_after_shutdown = std::fs::metadata(&activity_file)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            std::fs::metadata(&activity_file)
                .map(|metadata| metadata.len())
                .unwrap_or(0),
            activity_after_shutdown,
            "grandchild activity continued after shutdown returned"
        );
        let _ = std::fs::remove_file(pid_file);
        let _ = std::fs::remove_file(activity_file);
    }
}
