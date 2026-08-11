//! Explicit, durable Iroh node-address publication.
//!
//! This capability owns publication only.  It cannot resolve a NodeId, discover
//! content, join a relay, enumerate peers, or perform LAN discovery.  A publish
//! transition is an acknowledged state machine:
//!
//! 1. persist the exact signed packet as `pending`;
//! 2. PUT those exact bytes to one pinned authority recipient;
//! 3. GET and verify byte-identical visibility;
//! 4. atomically move `pending` to `committed`.
//!
//! A restart retries an unexpired pending packet byte-for-byte.  Expired
//! pending work advances to a new sequence; it is never resurrected.

use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::SecretKey;
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::iroh_node_record::{
    MAX_NODE_LOCATIONS, NodeLocation, NodeRecord, PublicationState, decode_node_record,
    encode_node_record, validate_namespace, validate_recipient,
};
use crate::iroh_runtime::{open_state_directory, validate_directory};
use crate::pinned_http::PinnedHttpEndpoint;
use crate::transport::NodeId;

pub const PUBLICATION_STATE_FILENAME: &str = "iroh-node-publication-state.json";
const PUBLICATION_LOCK_FILENAME: &str = "iroh-node-publication.lock";
const PUBLICATION_TEMP_FILENAME: &str = ".iroh-node-publication-state.tmp";
const PUBLICATION_ANCHOR_FILENAME: &str = "iroh-node-publication-anchor.json";
const PUBLICATION_ANCHOR_TEMP_FILENAME: &str = ".iroh-node-publication-anchor.tmp";
const PUBLICATION_STATE_SCHEMA: u32 = 1;
const STATE_FILE_MODE: u32 = 0o600;
const MAX_STATE_BYTES: u64 = 16 * 1024;
const STATE_CHECKSUM_DOMAIN: &[u8] = b"nix-p2p/iroh-node-publication-state/v1\0";
const ANCHOR_CHECKSUM_DOMAIN: &[u8] = b"nix-p2p/iroh-node-publication-anchor/v1\0";
const DESIRED_ANCHOR_HASH_DOMAIN: &[u8] =
    b"nix-p2p/iroh-node-publication-anchor/desired-locations/v1\0";
pub const PUBLICATION_STARTUP_DEADLINE: Duration = Duration::from_secs(10);
pub const PUBLICATION_TRANSITION_DEADLINE: Duration = Duration::from_secs(5);
pub const PUBLICATION_COMPLETION_MARGIN: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationAuthorityAuthorization {
    /// Named operator of a locally controlled, production-shaped authority.
    LocalProductionShaped { owner: String },
    /// Explicit authorization for a public/external recipient.  The opaque
    /// authorization reference is configuration evidence, never an HTTP token.
    ExternalAuthorized {
        owner: String,
        authorization_reference: String,
    },
}

impl PublicationAuthorityAuthorization {
    fn validate(&self, recipient: SocketAddr) -> Result<(), PublicationError> {
        match self {
            Self::LocalProductionShaped { owner } => {
                validate_owner(owner)?;
                if is_public_ip(recipient.ip()) {
                    return Err(PublicationError::configuration(format!(
                        "public authority recipient {recipient} requires ExternalAuthorized with a named authorization reference"
                    )));
                }
            }
            Self::ExternalAuthorized {
                owner,
                authorization_reference,
            } => {
                validate_owner(owner)?;
                if authorization_reference.trim().is_empty()
                    || authorization_reference.len() > 256
                    || authorization_reference.chars().any(char::is_control)
                {
                    return Err(PublicationError::configuration(
                        "external authorization reference must be 1..=256 non-control characters",
                    ));
                }
                return Err(PublicationError::configuration(
                    "external pkarr authorities are not enabled: the current transport is pinned plain HTTP for a locally operated routed authority and must not be presented as HTTPS-compatible",
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

fn validate_owner(owner: &str) -> Result<(), PublicationError> {
    if owner.trim().is_empty() || owner.len() > 128 || owner.chars().any(char::is_control) {
        return Err(PublicationError::configuration(
            "publication authority owner must be 1..=128 non-control characters",
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
            let segment = ip.segments()[0];
            let unique_local = segment & 0xfe00 == 0xfc00;
            !(ip.is_loopback()
                || ip.is_unicast_link_local()
                || unique_local
                || ip == Ipv6Addr::UNSPECIFIED)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePublicationConfig {
    namespace: String,
    signed_recipient: String,
    authority_recipient: SocketAddr,
    authority_host: String,
    authorization: PublicationAuthorityAuthorization,
    ttl: Duration,
    refresh_interval: Duration,
    request_deadline: Duration,
    initial_locations: Vec<NodeLocation>,
    relay_locations_allowed: bool,
}

impl NodePublicationConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace: impl Into<String>,
        signed_recipient: impl Into<String>,
        authority_recipient: SocketAddr,
        authority_host: impl Into<String>,
        authorization: PublicationAuthorityAuthorization,
        ttl: Duration,
        refresh_interval: Duration,
        request_deadline: Duration,
        initial_locations: impl IntoIterator<Item = NodeLocation>,
    ) -> Result<Self, PublicationError> {
        let namespace = namespace.into();
        let signed_recipient = signed_recipient.into();
        let authority_host = authority_host.into();
        validate_namespace(&namespace).map_err(PublicationError::record)?;
        validate_recipient(&signed_recipient).map_err(PublicationError::record)?;
        let endpoint = PinnedHttpEndpoint::new(authority_recipient, authority_host.clone())
            .map_err(PublicationError::transport)?;
        authorization.validate(endpoint.recipient())?;
        if ttl.as_secs() == 0 || ttl.subsec_nanos() != 0 || ttl.as_secs() > u32::MAX as u64 {
            return Err(PublicationError::configuration(
                "publication TTL must be a whole number of seconds in 1..=u32::MAX",
            ));
        }
        if refresh_interval.is_zero() || refresh_interval >= ttl {
            return Err(PublicationError::configuration(
                "publication refresh interval must be positive and below TTL",
            ));
        }
        if request_deadline.is_zero() || request_deadline > PUBLICATION_TRANSITION_DEADLINE / 2 {
            return Err(PublicationError::configuration(format!(
                "one publication request deadline must be positive and at most {:?}, leaving room for PUT plus visibility GET",
                PUBLICATION_TRANSITION_DEADLINE / 2
            )));
        }
        let retry_reserve = publication_retry_reserve(request_deadline);
        let minimum_safe_ttl = std::cmp::max(
            retry_reserve
                .saturating_mul(2)
                .saturating_add(PUBLICATION_COMPLETION_MARGIN),
            refresh_interval
                .saturating_add(retry_reserve)
                .saturating_add(PUBLICATION_COMPLETION_MARGIN),
        );
        if ttl <= minimum_safe_ttl {
            return Err(PublicationError::configuration(format!(
                "publication TTL {ttl:?} must exceed {minimum_safe_ttl:?}, the greater of twice the bounded retry reserve and refresh interval plus reserve, with {:?} completion margin for request deadline {request_deadline:?}; this prevents a visibility gap after delayed publication",
                PUBLICATION_COMPLETION_MARGIN,
            )));
        }
        let initial_locations = canonical_locations(initial_locations)?;
        if initial_locations.is_empty() {
            return Err(PublicationError::configuration(
                "enabled publication requires at least one declared reachable location",
            ));
        }
        Ok(Self {
            namespace,
            signed_recipient,
            authority_recipient: endpoint.recipient(),
            authority_host,
            authorization,
            ttl,
            refresh_interval,
            request_deadline,
            initial_locations,
            relay_locations_allowed: false,
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

    pub fn authorization(&self) -> &PublicationAuthorityAuthorization {
        &self.authorization
    }

    pub fn initial_locations(&self) -> &[NodeLocation] {
        &self.initial_locations
    }

    pub(crate) fn authorize_relay_locations(&mut self) {
        self.relay_locations_allowed = true;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
// This capability is configured once during startup. Boxing the enabled value
// would add allocation and public API friction without reducing runtime state.
#[allow(clippy::large_enum_variant)]
pub enum NodePublicationCapability {
    #[default]
    Disabled,
    Enabled(NodePublicationConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub(crate) enum PublicationFailpoint {
    None,
    AfterPendingPersist,
    AfterPutBeforeCommit,
}

#[derive(Debug, Clone)]
pub struct PublicationReceipt {
    pub record: NodeRecord,
    pub reused_committed_packet: bool,
    pub put_elapsed: Option<Duration>,
    pub visibility_elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationErrorKind {
    Configuration,
    State,
    Transport,
    Authority,
    Visibility,
    InjectedCrash,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationError {
    pub kind: PublicationErrorKind,
    message: String,
}

impl PublicationError {
    pub(crate) fn new(kind: PublicationErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn configuration(message: impl Into<String>) -> Self {
        Self::new(PublicationErrorKind::Configuration, message)
    }

    fn state(message: impl Into<String>) -> Self {
        Self::new(PublicationErrorKind::State, message)
    }

    fn record(error: impl fmt::Display) -> Self {
        Self::configuration(format!(
            "invalid node-publication record configuration: {error}"
        ))
    }

    fn transport(error: impl fmt::Display) -> Self {
        Self::new(PublicationErrorKind::Transport, error.to_string())
    }
}

impl fmt::Display for PublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Iroh node publication {:?}: {}",
            self.kind, self.message
        )
    }
}

impl std::error::Error for PublicationError {}

fn transition_deadline_error() -> PublicationError {
    PublicationError::new(
        PublicationErrorKind::Transport,
        format!(
            "publication transition exceeded {:?}",
            PUBLICATION_TRANSITION_DEADLINE
        ),
    )
}

fn publication_retry_reserve(request_deadline: Duration) -> Duration {
    std::cmp::min(
        PUBLICATION_TRANSITION_DEADLINE,
        request_deadline.saturating_mul(4),
    )
}

fn single_submission_bound(request_deadline: Duration) -> Duration {
    std::cmp::min(
        PUBLICATION_TRANSITION_DEADLINE,
        request_deadline.saturating_mul(2),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum StoredRecordKind {
    Live,
    Withdrawn,
}

impl From<PublicationState> for StoredRecordKind {
    fn from(value: PublicationState) -> Self {
        match value {
            PublicationState::Live => Self::Live,
            PublicationState::Withdrawn => Self::Withdrawn,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredPacket {
    sequence: u64,
    desired_revision: u64,
    expires_unix_micros: u64,
    kind: StoredRecordKind,
    packet_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum StoredDesiredLocation {
    Direct(SocketAddr),
    Relay(String),
}

impl From<&NodeLocation> for StoredDesiredLocation {
    fn from(location: &NodeLocation) -> Self {
        match location {
            NodeLocation::Direct(address) => Self::Direct(*address),
            NodeLocation::Relay(url) => Self::Relay(url.clone()),
        }
    }
}

impl StoredDesiredLocation {
    fn to_location(&self) -> Result<NodeLocation, PublicationError> {
        match self {
            Self::Direct(address) => {
                NodeLocation::direct(*address).map_err(PublicationError::record)
            }
            Self::Relay(url) => NodeLocation::relay(url.clone()).map_err(PublicationError::record),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublicationStateBody {
    schema_version: u32,
    node_id_hex: String,
    namespace: String,
    signed_recipient: String,
    desired_revision: u64,
    desired_locations: Vec<StoredDesiredLocation>,
    high_water_sequence: u64,
    committed: Option<StoredPacket>,
    pending: Option<StoredPacket>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublicationAnchorBody {
    schema_version: u32,
    node_id_hex: String,
    namespace: String,
    signed_recipient: String,
    desired_revision: u64,
    desired_locations_blake3_hex: String,
    high_water_sequence: u64,
    latest_packet_sequence: Option<u64>,
    latest_packet_blake3_hex: Option<String>,
    latest_packet_committed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationAnchorEnvelope {
    body: PublicationAnchorBody,
    checksum_blake3_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationStateEnvelope {
    body: PublicationStateBody,
    checksum_blake3_hex: String,
}

impl PublicationStateBody {
    fn fresh(node_id: NodeId, config: &NodePublicationConfig) -> Self {
        Self {
            schema_version: PUBLICATION_STATE_SCHEMA,
            node_id_hex: node_id.to_hex(),
            namespace: config.namespace.clone(),
            signed_recipient: config.signed_recipient.clone(),
            desired_revision: 1,
            desired_locations: config
                .initial_locations
                .iter()
                .map(StoredDesiredLocation::from)
                .collect(),
            high_water_sequence: 0,
            committed: None,
            pending: None,
        }
    }

    fn last_sequence(&self) -> Option<u64> {
        (self.high_water_sequence != 0).then_some(self.high_water_sequence)
    }

    fn desired_locations(&self) -> Result<Vec<NodeLocation>, PublicationError> {
        canonical_locations(
            self.desired_locations
                .iter()
                .map(StoredDesiredLocation::to_location)
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
}

struct PublicationStateStore {
    state_dir: PathBuf,
    dirfd: rustix::fd::OwnedFd,
    _lock: rustix::fd::OwnedFd,
    #[cfg(test)]
    fail_writes_remaining: AtomicU64,
    #[cfg(test)]
    fail_next_post_rename: std::sync::atomic::AtomicBool,
    poisoned: AtomicBool,
}

impl fmt::Debug for PublicationStateStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicationStateStore")
            .field("state_dir", &self.state_dir)
            .finish_non_exhaustive()
    }
}

impl PublicationStateStore {
    fn open(
        state_dir: &Path,
        node_id: NodeId,
        config: &NodePublicationConfig,
    ) -> Result<(Self, PublicationStateBody), PublicationError> {
        let (dirfd, _) = open_state_directory(state_dir)
            .map_err(|error| PublicationError::state(error.to_string()))?;
        validate_directory(&dirfd, state_dir)
            .map_err(|error| PublicationError::state(error.to_string()))?;
        let (lock, lock_created) = match fs::openat(
            &dirfd,
            PUBLICATION_LOCK_FILENAME,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(STATE_FILE_MODE),
        ) {
            Ok(lock) => (lock, true),
            Err(Errno::EXIST) => (
                fs::openat(
                    &dirfd,
                    PUBLICATION_LOCK_FILENAME,
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| state_io(state_dir, "opening existing publication lock", error))?,
                false,
            ),
            Err(error) => return Err(state_io(state_dir, "creating publication lock", error)),
        };
        if lock_created {
            fs::fchmod(&lock, Mode::from_raw_mode(STATE_FILE_MODE))
                .map_err(|error| state_io(state_dir, "setting publication lock mode", error))?;
            fs::fsync(&dirfd)
                .map_err(|error| state_io(state_dir, "syncing new publication lock", error))?;
        }
        validate_secure_file(&lock, state_dir, PUBLICATION_LOCK_FILENAME, MAX_STATE_BYTES)?;
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            PublicationError::state(format!(
                "{} is already owned by another publisher: {error}",
                state_dir.join(PUBLICATION_LOCK_FILENAME).display()
            ))
        })?;
        let store = Self {
            state_dir: state_dir.to_path_buf(),
            dirfd,
            _lock: lock,
            #[cfg(test)]
            fail_writes_remaining: AtomicU64::new(0),
            #[cfg(test)]
            fail_next_post_rename: std::sync::atomic::AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
        };
        let loaded = store.read()?;
        let had_state = loaded.is_some();
        let body = match loaded {
            Some(body) => {
                validate_loaded_state(&body, node_id, config)?;
                body
            }
            None => PublicationStateBody::fresh(node_id, config),
        };
        store.validate_or_initialize_anchor(&body, had_state)?;
        if !had_state {
            // Persist the initial desired intent before packet construction or
            // any authority request. The independent anchor is initialized
            // first, then advanced by this state write.
            store.write(&body)?;
        }
        Ok((store, body))
    }

    fn read(&self) -> Result<Option<PublicationStateBody>, PublicationError> {
        self.ensure_healthy()?;
        let file = match fs::openat(
            &self.dirfd,
            PUBLICATION_STATE_FILENAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => {
                return Err(state_io(
                    &self.state_dir,
                    "opening publication state",
                    error,
                ));
            }
        };
        let before = validate_secure_file(
            &file,
            &self.state_dir,
            PUBLICATION_STATE_FILENAME,
            MAX_STATE_BYTES,
        )?;
        let mut file = File::from(file);
        let mut bytes = Vec::with_capacity(before.st_size.max(0) as usize);
        (&mut file)
            .take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                PublicationError::state(format!(
                    "reading {}: {error}",
                    self.state_dir.join(PUBLICATION_STATE_FILENAME).display()
                ))
            })?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(PublicationError::state(format!(
                "{} exceeds {MAX_STATE_BYTES} bytes",
                self.state_dir.join(PUBLICATION_STATE_FILENAME).display()
            )));
        }
        let after = validate_secure_file(
            &file,
            &self.state_dir,
            PUBLICATION_STATE_FILENAME,
            MAX_STATE_BYTES,
        )?;
        let entry = fs::statat(
            &self.dirfd,
            PUBLICATION_STATE_FILENAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| state_io(&self.state_dir, "rechecking publication state", error))?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_size != after.st_size
            || before.st_mtime != after.st_mtime
            || before.st_mtime_nsec != after.st_mtime_nsec
            || after.st_dev != entry.st_dev
            || after.st_ino != entry.st_ino
        {
            return Err(PublicationError::state(format!(
                "{} changed during read",
                self.state_dir.join(PUBLICATION_STATE_FILENAME).display()
            )));
        }
        decode_state(&bytes).map(Some)
    }

    fn write(&self, body: &PublicationStateBody) -> Result<(), PublicationError> {
        self.ensure_healthy()?;
        #[cfg(test)]
        if self
            .fail_writes_remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(PublicationError::state(
                "injected publication state write failure",
            ));
        }
        let bytes = encode_state(body)?;
        let temp_fd = fs::openat(
            &self.dirfd,
            ".",
            OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(STATE_FILE_MODE),
        )
        .map_err(|error| {
            state_io(
                &self.state_dir,
                "creating publication state temporary file",
                error,
            )
        })?;
        fs::fchmod(&temp_fd, Mode::from_raw_mode(STATE_FILE_MODE)).map_err(|error| {
            state_io(
                &self.state_dir,
                "setting publication state temporary mode",
                error,
            )
        })?;
        let mut temp = File::from(temp_fd);
        temp.write_all(&bytes)
            .and_then(|_| temp.sync_all())
            .map_err(|error| {
                PublicationError::state(format!(
                    "writing publication state temporary file: {error}"
                ))
            })?;
        match fs::unlinkat(&self.dirfd, PUBLICATION_TEMP_FILENAME, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(error) => {
                return Err(state_io(
                    &self.state_dir,
                    "removing stale publication temporary link",
                    error,
                ));
            }
        }
        fs::linkat(
            &temp,
            "",
            &self.dirfd,
            PUBLICATION_TEMP_FILENAME,
            AtFlags::EMPTY_PATH,
        )
        .map_err(|error| {
            state_io(
                &self.state_dir,
                "linking publication state temporary file",
                error,
            )
        })?;
        if let Err(error) = fs::renameat(
            &self.dirfd,
            PUBLICATION_TEMP_FILENAME,
            &self.dirfd,
            PUBLICATION_STATE_FILENAME,
        ) {
            let _ = fs::unlinkat(&self.dirfd, PUBLICATION_TEMP_FILENAME, AtFlags::empty());
            return Err(state_io(
                &self.state_dir,
                "atomically replacing publication state",
                error,
            ));
        }
        let post_rename: Result<(), PublicationError> = (|| {
            #[cfg(test)]
            if self
                .fail_next_post_rename
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                return Err(PublicationError::state(
                    "injected post-rename publication persistence failure",
                ));
            }
            fs::fsync(&self.dirfd).map_err(|error| {
                state_io(
                    &self.state_dir,
                    "syncing publication state directory",
                    error,
                )
            })?;
            let published = fs::openat(
                &self.dirfd,
                PUBLICATION_STATE_FILENAME,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                state_io(
                    &self.state_dir,
                    "reopening committed publication state",
                    error,
                )
            })?;
            validate_secure_file(
                &published,
                &self.state_dir,
                PUBLICATION_STATE_FILENAME,
                MAX_STATE_BYTES,
            )?;
            self.write_anchor(&PublicationAnchorBody::from_state(body)?)?;
            Ok(())
        })();
        if let Err(error) = post_rename {
            self.poisoned.store(true, Ordering::Release);
            return Err(PublicationError::state(format!(
                "{error}; publisher state store is poisoned until restart"
            )));
        }
        Ok(())
    }

    fn validate_or_initialize_anchor(
        &self,
        state: &PublicationStateBody,
        had_state: bool,
    ) -> Result<(), PublicationError> {
        let current = PublicationAnchorBody::from_state(state)?;
        let Some(anchor) = self.read_anchor()? else {
            if had_state {
                return Err(PublicationError::state(format!(
                    "{} is missing while publisher state exists; refusing a rollback-ambiguous state",
                    self.state_dir.join(PUBLICATION_ANCHOR_FILENAME).display()
                )));
            }
            return self.write_anchor(&current);
        };
        if anchor.schema_version != current.schema_version
            || anchor.node_id_hex != current.node_id_hex
            || anchor.namespace != current.namespace
            || anchor.signed_recipient != current.signed_recipient
        {
            return Err(PublicationError::state(
                "publisher rollback anchor identity does not match state/configuration",
            ));
        }
        if current.high_water_sequence < anchor.high_water_sequence
            || current.desired_revision < anchor.desired_revision
        {
            return Err(PublicationError::state(
                "publisher state regressed below rollback anchor high-water",
            ));
        }
        if current.desired_revision == anchor.desired_revision
            && current.desired_locations_blake3_hex != anchor.desired_locations_blake3_hex
        {
            return Err(PublicationError::state(
                "publisher desired locations changed at the rollback-anchor revision",
            ));
        }
        if current.high_water_sequence == anchor.high_water_sequence {
            let packet_changed = current.latest_packet_sequence != anchor.latest_packet_sequence
                || current.latest_packet_blake3_hex != anchor.latest_packet_blake3_hex;
            let legitimately_retired_pending = !anchor.latest_packet_committed
                && anchor.latest_packet_sequence == Some(anchor.high_water_sequence)
                && current.latest_packet_sequence != Some(current.high_water_sequence);
            if packet_changed && !legitimately_retired_pending {
                return Err(PublicationError::state(
                    "publisher state packet at rollback-anchor high-water changed or disappeared",
                ));
            }
            if anchor.latest_packet_committed
                && !current.latest_packet_committed
                && current.latest_packet_sequence == anchor.latest_packet_sequence
            {
                return Err(PublicationError::state(
                    "publisher state regressed from committed to pending at rollback-anchor high-water",
                ));
            }
        }
        if current != anchor {
            // State is synced before the independent anchor. A crash may leave
            // state ahead; repair only in that direction. Anchor-ahead was
            // rejected above. Restoring both files together remains outside
            // this local consistency witness's threat model.
            self.write_anchor(&current)?;
        }
        Ok(())
    }

    fn read_anchor(&self) -> Result<Option<PublicationAnchorBody>, PublicationError> {
        let file = match fs::openat(
            &self.dirfd,
            PUBLICATION_ANCHOR_FILENAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => {
                return Err(state_io(
                    &self.state_dir,
                    "opening publisher rollback anchor",
                    error,
                ));
            }
        };
        let stat = validate_secure_file(
            &file,
            &self.state_dir,
            PUBLICATION_ANCHOR_FILENAME,
            MAX_STATE_BYTES,
        )?;
        let mut file = File::from(file);
        let mut bytes = Vec::with_capacity(stat.st_size.max(0) as usize);
        (&mut file)
            .take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                PublicationError::state(format!("reading publisher rollback anchor: {error}"))
            })?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(PublicationError::state(
                "publisher rollback anchor exceeds size bound",
            ));
        }
        decode_anchor(&bytes).map(Some)
    }

    fn write_anchor(&self, anchor: &PublicationAnchorBody) -> Result<(), PublicationError> {
        let bytes = encode_anchor(anchor)?;
        let temp_fd = fs::openat(
            &self.dirfd,
            ".",
            OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(STATE_FILE_MODE),
        )
        .map_err(|error| {
            state_io(
                &self.state_dir,
                "creating publisher rollback anchor temporary file",
                error,
            )
        })?;
        fs::fchmod(&temp_fd, Mode::from_raw_mode(STATE_FILE_MODE)).map_err(|error| {
            state_io(
                &self.state_dir,
                "setting publisher rollback anchor temporary mode",
                error,
            )
        })?;
        let mut temp = File::from(temp_fd);
        temp.write_all(&bytes)
            .and_then(|_| temp.sync_all())
            .map_err(|error| {
                PublicationError::state(format!("writing publisher rollback anchor: {error}"))
            })?;
        match fs::unlinkat(
            &self.dirfd,
            PUBLICATION_ANCHOR_TEMP_FILENAME,
            AtFlags::empty(),
        ) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(error) => {
                return Err(state_io(
                    &self.state_dir,
                    "removing stale publisher rollback anchor link",
                    error,
                ));
            }
        }
        fs::linkat(
            &temp,
            "",
            &self.dirfd,
            PUBLICATION_ANCHOR_TEMP_FILENAME,
            AtFlags::EMPTY_PATH,
        )
        .map_err(|error| state_io(&self.state_dir, "linking publisher rollback anchor", error))?;
        if let Err(error) = fs::renameat(
            &self.dirfd,
            PUBLICATION_ANCHOR_TEMP_FILENAME,
            &self.dirfd,
            PUBLICATION_ANCHOR_FILENAME,
        ) {
            let _ = fs::unlinkat(
                &self.dirfd,
                PUBLICATION_ANCHOR_TEMP_FILENAME,
                AtFlags::empty(),
            );
            return Err(state_io(
                &self.state_dir,
                "atomically replacing publisher rollback anchor",
                error,
            ));
        }
        fs::fsync(&self.dirfd)
            .map_err(|error| state_io(&self.state_dir, "syncing publisher rollback anchor", error))
    }

    fn ensure_healthy(&self) -> Result<(), PublicationError> {
        if self.poisoned.load(Ordering::Acquire) {
            Err(PublicationError::state(
                "publisher state store is poisoned after an ambiguous post-rename persistence failure; restart is required",
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) fn seed_pending_state_for_test(
    state_dir: &Path,
    key: &SecretKey,
    config: &NodePublicationConfig,
    packet: &[u8],
    high_water_sequence: u64,
) -> Result<(), PublicationError> {
    let node_id = NodeId::from_bytes(*key.public().as_bytes());
    let record = decode_node_record(packet).map_err(|error| {
        PublicationError::state(format!("test pending packet invalid: {error}"))
    })?;
    if record.node_id != node_id
        || record.namespace != config.namespace
        || record.recipient != config.signed_recipient
        || record.sequence > high_water_sequence
    {
        return Err(PublicationError::state(
            "test pending packet does not match publisher state identity or high-water",
        ));
    }
    let (store, mut state) = PublicationStateStore::open(state_dir, node_id, config)?;
    let pending_desired_revision = state.desired_revision;
    state.desired_revision = state
        .desired_revision
        .checked_add(1)
        .ok_or_else(|| PublicationError::state("test desired revision overflow"))?;
    state.high_water_sequence = high_water_sequence;
    state.pending = Some(StoredPacket {
        sequence: record.sequence,
        desired_revision: pending_desired_revision,
        expires_unix_micros: record.expires_unix_micros,
        kind: record.state.into(),
        packet_hex: encode_hex(packet),
    });
    store.write(&state)
}

fn validate_secure_file<Fd: std::os::fd::AsFd>(
    file: &Fd,
    state_dir: &Path,
    name: &str,
    max_bytes: u64,
) -> Result<rustix::fs::Stat, PublicationError> {
    let stat = fs::fstat(file)
        .map_err(|error| state_io(state_dir, "inspecting secure state file", error))?;
    let path = state_dir.join(name);
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(PublicationError::state(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let expected_uid = rustix::process::geteuid().as_raw();
    if stat.st_uid != expected_uid {
        return Err(PublicationError::state(format!(
            "{} uid is {}, required {expected_uid}",
            path.display(),
            stat.st_uid
        )));
    }
    let mode = stat.st_mode & 0o777;
    if mode != STATE_FILE_MODE {
        return Err(PublicationError::state(format!(
            "{} mode is {mode:#05o}, required {STATE_FILE_MODE:#05o}",
            path.display()
        )));
    }
    if stat.st_nlink != 1 {
        return Err(PublicationError::state(format!(
            "{} has {} hard links, required exactly one",
            path.display(),
            stat.st_nlink
        )));
    }
    if stat.st_size < 0 || stat.st_size as u64 > max_bytes {
        return Err(PublicationError::state(format!(
            "{} size is outside 0..={max_bytes}",
            path.display()
        )));
    }
    Ok(stat)
}

fn encode_state(body: &PublicationStateBody) -> Result<Vec<u8>, PublicationError> {
    let body_bytes = serde_json::to_vec(body).map_err(|error| {
        PublicationError::state(format!("encoding publication state body: {error}"))
    })?;
    let envelope = PublicationStateEnvelope {
        body: body.clone(),
        checksum_blake3_hex: state_checksum(&body_bytes).to_hex().to_string(),
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| PublicationError::state(format!("encoding publication state: {error}")))?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(PublicationError::state(format!(
            "encoded publication state is {} bytes, maximum is {MAX_STATE_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn decode_state(bytes: &[u8]) -> Result<PublicationStateBody, PublicationError> {
    let envelope: PublicationStateEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| PublicationError::state(format!("decoding publication state: {error}")))?;
    let body_bytes = serde_json::to_vec(&envelope.body).map_err(|error| {
        PublicationError::state(format!("canonicalizing publication state: {error}"))
    })?;
    if envelope.checksum_blake3_hex != state_checksum(&body_bytes).to_hex().as_str() {
        return Err(PublicationError::state(
            "publication state checksum does not match",
        ));
    }
    Ok(envelope.body)
}

fn state_checksum(body: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STATE_CHECKSUM_DOMAIN);
    hasher.update(body);
    hasher.finalize()
}

impl PublicationAnchorBody {
    fn from_state(state: &PublicationStateBody) -> Result<Self, PublicationError> {
        let desired_bytes = serde_json::to_vec(&state.desired_locations).map_err(|error| {
            PublicationError::state(format!(
                "encoding desired locations for publisher rollback anchor: {error}"
            ))
        })?;
        let mut desired_hasher = blake3::Hasher::new();
        desired_hasher.update(DESIRED_ANCHOR_HASH_DOMAIN);
        desired_hasher.update(&desired_bytes);
        let latest = state
            .pending
            .as_ref()
            .map(|packet| (packet, false))
            .or_else(|| state.committed.as_ref().map(|packet| (packet, true)));
        let (latest_packet_sequence, latest_packet_blake3_hex, latest_packet_committed) =
            match latest {
                Some((packet, committed)) => (
                    Some(packet.sequence),
                    Some(
                        blake3::hash(&decode_hex(&packet.packet_hex)?)
                            .to_hex()
                            .to_string(),
                    ),
                    committed,
                ),
                None => (None, None, false),
            };
        Ok(Self {
            schema_version: state.schema_version,
            node_id_hex: state.node_id_hex.clone(),
            namespace: state.namespace.clone(),
            signed_recipient: state.signed_recipient.clone(),
            desired_revision: state.desired_revision,
            desired_locations_blake3_hex: desired_hasher.finalize().to_hex().to_string(),
            high_water_sequence: state.high_water_sequence,
            latest_packet_sequence,
            latest_packet_blake3_hex,
            latest_packet_committed,
        })
    }
}

fn encode_anchor(body: &PublicationAnchorBody) -> Result<Vec<u8>, PublicationError> {
    let body_bytes = serde_json::to_vec(body).map_err(|error| {
        PublicationError::state(format!("encoding publisher rollback anchor body: {error}"))
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(ANCHOR_CHECKSUM_DOMAIN);
    hasher.update(&body_bytes);
    let envelope = PublicationAnchorEnvelope {
        body: body.clone(),
        checksum_blake3_hex: hasher.finalize().to_hex().to_string(),
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|error| {
        PublicationError::state(format!("encoding publisher rollback anchor: {error}"))
    })?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(PublicationError::state(
            "encoded publisher rollback anchor exceeds size bound",
        ));
    }
    Ok(bytes)
}

fn decode_anchor(bytes: &[u8]) -> Result<PublicationAnchorBody, PublicationError> {
    let envelope: PublicationAnchorEnvelope = serde_json::from_slice(bytes).map_err(|error| {
        PublicationError::state(format!("decoding publisher rollback anchor: {error}"))
    })?;
    let body_bytes = serde_json::to_vec(&envelope.body).map_err(|error| {
        PublicationError::state(format!("canonicalizing publisher rollback anchor: {error}"))
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(ANCHOR_CHECKSUM_DOMAIN);
    hasher.update(&body_bytes);
    if envelope.checksum_blake3_hex != hasher.finalize().to_hex().as_str() {
        return Err(PublicationError::state(
            "publisher rollback anchor checksum does not match",
        ));
    }
    Ok(envelope.body)
}

fn validate_loaded_state(
    body: &PublicationStateBody,
    node_id: NodeId,
    config: &NodePublicationConfig,
) -> Result<(), PublicationError> {
    if body.schema_version != PUBLICATION_STATE_SCHEMA
        || body.node_id_hex != node_id.to_hex()
        || body.namespace != config.namespace
        || body.signed_recipient != config.signed_recipient
    {
        return Err(PublicationError::state(
            "publication state identity/namespace/recipient/schema does not match configuration",
        ));
    }
    let desired_locations = body.desired_locations()?;
    if body.desired_revision == 0 {
        return Err(PublicationError::state(
            "stored desired publication revision must be positive",
        ));
    }
    let desired_state = if desired_locations.is_empty() {
        PublicationState::Withdrawn
    } else {
        PublicationState::Live
    };
    if !config.relay_locations_allowed
        && desired_locations
            .iter()
            .any(|location| matches!(location, NodeLocation::Relay(_)))
    {
        return Err(PublicationError::state(
            "stored desired publication intent contains a relay without relay authorization",
        ));
    }
    for stored in body.committed.iter().chain(body.pending.iter()) {
        let bytes = decode_hex(&stored.packet_hex)?;
        let record = decode_node_record(&bytes).map_err(|error| {
            PublicationError::state(format!("stored packet is invalid: {error}"))
        })?;
        if record.node_id != node_id
            || record.namespace != config.namespace
            || record.recipient != config.signed_recipient
            || record.sequence != stored.sequence
            || stored.desired_revision > body.desired_revision
            || record.expires_unix_micros != stored.expires_unix_micros
            || StoredRecordKind::from(record.state) != stored.kind
            || (stored.desired_revision == body.desired_revision
                && (record.state != desired_state || record.locations != desired_locations))
            || (!config.relay_locations_allowed
                && record
                    .locations
                    .iter()
                    .any(|location| matches!(location, NodeLocation::Relay(_))))
        {
            return Err(PublicationError::state(
                "stored publication packet metadata does not match state envelope",
            ));
        }
    }
    if let (Some(committed), Some(pending)) = (&body.committed, &body.pending)
        && pending.sequence <= committed.sequence
    {
        return Err(PublicationError::state(
            "pending publication sequence does not advance committed state",
        ));
    }
    if body
        .committed
        .iter()
        .chain(body.pending.iter())
        .any(|packet| packet.sequence > body.high_water_sequence)
    {
        return Err(PublicationError::state(
            "publication high-water sequence is below a stored packet sequence",
        ));
    }
    Ok(())
}

fn state_io(state_dir: &Path, operation: &str, error: Errno) -> PublicationError {
    PublicationError::state(format!("{operation} in {}: {error}", state_dir.display()))
}

fn canonical_locations(
    locations: impl IntoIterator<Item = NodeLocation>,
) -> Result<Vec<NodeLocation>, PublicationError> {
    let mut locations = locations.into_iter().collect::<Vec<_>>();
    for location in &locations {
        location.validate().map_err(PublicationError::record)?;
    }
    locations.sort();
    locations.dedup();
    if locations.len() > MAX_NODE_LOCATIONS {
        return Err(PublicationError::configuration(format!(
            "node publication has {} locations, maximum is {MAX_NODE_LOCATIONS}; refusing to truncate",
            locations.len()
        )));
    }
    Ok(locations)
}

struct PublisherInner {
    key: SecretKey,
    node_id: NodeId,
    config: NodePublicationConfig,
    client: PinnedHttpEndpoint,
    store: Arc<PublicationStateStore>,
    state: Mutex<PublicationStateBody>,
    transition_gate: Mutex<()>,
    desired_intent: std::sync::Mutex<(u64, Vec<NodeLocation>)>,
    fatal: watch::Sender<Option<PublicationError>>,
    closing: AtomicBool,
    close: watch::Sender<bool>,
}

impl fmt::Debug for PublisherInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublisherInner")
            .field("node_id", &self.node_id)
            .field("namespace", &self.config.namespace)
            .field("recipient", &self.config.signed_recipient)
            .finish_non_exhaustive()
    }
}

impl PublisherInner {
    fn open(
        state_dir: &Path,
        key: SecretKey,
        config: NodePublicationConfig,
    ) -> Result<Arc<Self>, PublicationError> {
        let node_id = NodeId::from_bytes(*key.public().as_bytes());
        let client =
            PinnedHttpEndpoint::new(config.authority_recipient, config.authority_host.clone())
                .map_err(PublicationError::transport)?;
        let (store, state) = PublicationStateStore::open(state_dir, node_id, &config)?;
        let desired_locations = state.desired_locations()?;
        let desired_revision = state.desired_revision;
        let (close, _close_rx) = watch::channel(false);
        let (fatal, _fatal_rx) = watch::channel(None);
        Ok(Arc::new(Self {
            key,
            node_id,
            config,
            client,
            store: Arc::new(store),
            state: Mutex::new(state),
            transition_gate: Mutex::new(()),
            desired_intent: std::sync::Mutex::new((desired_revision, desired_locations)),
            fatal,
            closing: AtomicBool::new(false),
            close,
        }))
    }

    async fn transition(
        &self,
        locations: Vec<NodeLocation>,
        failpoint: PublicationFailpoint,
    ) -> Result<PublicationReceipt, PublicationError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(PublicationError::new(
                PublicationErrorKind::Closed,
                "publisher is closing",
            ));
        }
        let locations = self.validate_desired_locations(locations)?;
        self.record_desired_intent(locations)?;
        self.transition_recorded(failpoint).await
    }

    fn validate_desired_locations(
        &self,
        locations: Vec<NodeLocation>,
    ) -> Result<Vec<NodeLocation>, PublicationError> {
        let locations = canonical_locations(locations)?;
        if !self.config.relay_locations_allowed
            && locations
                .iter()
                .any(|location| matches!(location, NodeLocation::Relay(_)))
        {
            return Err(PublicationError::configuration(
                "relay location publication requires an explicitly enabled runtime relay capability",
            ));
        }
        Ok(locations)
    }

    async fn transition_recorded(
        &self,
        failpoint: PublicationFailpoint,
    ) -> Result<PublicationReceipt, PublicationError> {
        let _gate = self.transition_gate.lock().await;
        if self.closing.load(Ordering::Acquire) {
            return Err(PublicationError::new(
                PublicationErrorKind::Closed,
                "publisher is closing",
            ));
        }
        let locations = self.persist_latest_desired().await?;
        self.transition_locked(locations, failpoint, true).await
    }

    async fn refresh_current(&self) -> Result<PublicationReceipt, PublicationError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(PublicationError::new(
                PublicationErrorKind::Closed,
                "publisher is closing",
            ));
        }
        let _gate = self.transition_gate.lock().await;
        if self.closing.load(Ordering::Acquire) {
            return Err(PublicationError::new(
                PublicationErrorKind::Closed,
                "publisher is closing",
            ));
        }
        let locations = self.persist_latest_desired().await?;
        self.transition_locked(locations, PublicationFailpoint::None, true)
            .await
    }

    fn record_desired_intent(&self, locations: Vec<NodeLocation>) -> Result<u64, PublicationError> {
        let mut desired = self
            .desired_intent
            .lock()
            .map_err(|_| PublicationError::state("desired-location intent mutex poisoned"))?;
        if self.closing.load(Ordering::Acquire) {
            return Err(PublicationError::new(
                PublicationErrorKind::Closed,
                "publisher is closing",
            ));
        }
        update_desired_intent(&mut desired, locations)
    }

    fn record_shutdown_intent(&self) -> Result<u64, PublicationError> {
        let mut desired = self
            .desired_intent
            .lock()
            .map_err(|_| PublicationError::state("desired-location intent mutex poisoned"))?;
        // Serialize the close latch with desired-intent mutation. An update
        // that acquired this mutex first is superseded by this withdrawal; an
        // update arriving later observes `closing` while holding the same
        // mutex and cannot overwrite it.
        self.closing.store(true, Ordering::Release);
        update_desired_intent(&mut desired, Vec::new())
    }

    async fn persist_latest_desired(&self) -> Result<Vec<NodeLocation>, PublicationError> {
        let (revision, locations) = self
            .desired_intent
            .lock()
            .map_err(|_| PublicationError::state("desired-location intent mutex poisoned"))?
            .clone();
        let mut state = self.state.lock().await;
        if revision > state.desired_revision {
            let mut candidate = state.clone();
            candidate.desired_revision = revision;
            candidate.desired_locations =
                locations.iter().map(StoredDesiredLocation::from).collect();
            self.store.write(&candidate)?;
            *state = candidate;
        }
        state.desired_locations()
    }

    async fn refresh_with_retry(&self) -> Result<PublicationReceipt, PublicationError> {
        let deadline = Instant::now() + PUBLICATION_TRANSITION_DEADLINE;
        let first = tokio::time::timeout_at(deadline, self.refresh_current())
            .await
            .map_err(|_| transition_deadline_error())?;
        match first {
            Ok(receipt) => Ok(receipt),
            Err(first_error) => {
                tokio::task::yield_now().await;
                tokio::time::timeout_at(deadline, self.refresh_current())
                    .await
                    .map_err(|_| transition_deadline_error())?
                    .map_err(|second_error| {
                        PublicationError::new(
                            second_error.kind.clone(),
                            format!(
                                "latest desired publication failed twice inside {:?}: first={first_error}; second={second_error}",
                                PUBLICATION_TRANSITION_DEADLINE
                            ),
                        )
                    })
            }
        }
    }

    fn mark_fatal(&self, error: PublicationError) {
        self.fatal.send_if_modified(|current| {
            if current.is_none() {
                *current = Some(error);
                true
            } else {
                false
            }
        });
    }

    fn fatal_error(&self) -> Option<PublicationError> {
        self.fatal.borrow().clone()
    }

    async fn withdraw_for_shutdown(&self) -> Result<PublicationReceipt, PublicationError> {
        self.record_shutdown_intent()?;
        let _gate = self.transition_gate.lock().await;
        let locations = self.persist_latest_desired().await?;
        if !locations.is_empty() {
            return Err(PublicationError::state(
                "shutdown withdrawal intent was superseded after the close latch",
            ));
        }
        self.transition_locked(locations, PublicationFailpoint::None, false)
            .await
    }

    async fn transition_locked(
        &self,
        locations: Vec<NodeLocation>,
        failpoint: PublicationFailpoint,
        recover_pending: bool,
    ) -> Result<PublicationReceipt, PublicationError> {
        self.store.ensure_healthy()?;
        let desired_state = if locations.is_empty() {
            PublicationState::Withdrawn
        } else {
            PublicationState::Live
        };
        let mut state = self.state.lock().await;
        let recovered = if recover_pending {
            self.recover_pending(&mut state, failpoint).await?
        } else if state.pending.is_some() {
            // Shutdown never replays an interrupted live transition.  The
            // durable high-water remains, and the tombstone below advances it.
            let mut candidate = state.clone();
            candidate.pending = None;
            self.store.write(&candidate)?;
            *state = candidate;
            None
        } else {
            None
        };
        let now = unix_micros()?;
        let retry_reserve = publication_retry_reserve(self.config.request_deadline);
        let completion_reserve = retry_reserve.saturating_add(PUBLICATION_COMPLETION_MARGIN);
        let completion_reserve_micros = duration_micros(completion_reserve)?;
        let reusable_start_margin = single_submission_bound(self.config.request_deadline)
            .saturating_add(completion_reserve);
        let reusable_start_margin_micros = duration_micros(reusable_start_margin)?;

        // `recover_pending` already performed the exact PUT + visibility GET
        // and committed those bytes. If that recovered transition is exactly
        // what this caller wants and is not near refresh, return its receipt.
        // Falling into committed reuse here would issue a redundant second
        // idempotent PUT+GET pair (four requests during restart).
        if let Some(receipt) = recovered
            && receipt.record.state == desired_state
            && receipt.record.locations == locations
            && receipt.record.ttl_seconds == self.config.ttl.as_secs() as u32
            && receipt.record.expires_unix_micros.saturating_sub(now) > completion_reserve_micros
        {
            return Ok(receipt);
        }

        if let Some(committed) = &state.committed {
            let bytes = decode_hex(&committed.packet_hex)?;
            let record = decode_node_record(&bytes).map_err(|error| {
                PublicationError::state(format!("committed packet invalid: {error}"))
            })?;
            if record.state == desired_state
                && record.locations == locations
                && record.ttl_seconds == self.config.ttl.as_secs() as u32
                && record.expires_unix_micros.saturating_sub(now) > reusable_start_margin_micros
            {
                // Re-submit before verifying even when the local committed
                // packet is still fresh. A GET-first fast path strands the
                // publisher after an authority loses/reinitializes its state:
                // the authority returns 404 and the publisher keeps waiting
                // for the local refresh margin. Exact PUT is idempotent at a
                // healthy authority and heals an empty one. A conflicting
                // equal sequence remains a 409, so this does not weaken the
                // authority's monotonicity rule. This path is exactly two
                // bounded requests (PUT + GET), the same as a new transition.
                let put_elapsed = self.put_exact(&bytes).await?;
                let visible_started = Instant::now();
                self.verify_visible(&bytes).await?;
                return Ok(PublicationReceipt {
                    record,
                    reused_committed_packet: true,
                    put_elapsed: Some(put_elapsed),
                    visibility_elapsed: visible_started.elapsed(),
                });
            }
        }

        let sequence = next_sequence(now, state.last_sequence())?;
        let ttl_micros = duration_micros(self.config.ttl)?;
        let expires = sequence.checked_add(ttl_micros).ok_or_else(|| {
            PublicationError::state("publication expiry overflows u64 microseconds")
        })?;
        let packet = encode_node_record(
            &self.key,
            &self.config.namespace,
            &self.config.signed_recipient,
            self.config.ttl.as_secs() as u32,
            sequence,
            expires,
            desired_state,
            &locations,
        )
        .map_err(|error| {
            PublicationError::state(format!("encoding signed publication: {error}"))
        })?;
        let packet_bytes = packet.as_bytes().to_vec();
        let mut candidate = state.clone();
        candidate.pending = Some(StoredPacket {
            sequence,
            desired_revision: state.desired_revision,
            expires_unix_micros: expires,
            kind: desired_state.into(),
            packet_hex: encode_hex(&packet_bytes),
        });
        candidate.high_water_sequence = sequence;
        self.store.write(&candidate)?;
        *state = candidate;
        if failpoint == PublicationFailpoint::AfterPendingPersist {
            return Err(PublicationError::new(
                PublicationErrorKind::InjectedCrash,
                "injected crash after pending packet persistence",
            ));
        }
        self.submit_pending(&mut state, failpoint).await
    }

    async fn recover_pending(
        &self,
        state: &mut PublicationStateBody,
        failpoint: PublicationFailpoint,
    ) -> Result<Option<PublicationReceipt>, PublicationError> {
        let Some(pending) = &state.pending else {
            return Ok(None);
        };
        if pending.desired_revision < state.desired_revision {
            // A newer target was durably accepted after this packet was
            // prepared. Retire it locally without PUT so retry cannot briefly
            // resurrect an older live record (especially before withdrawal).
            let mut candidate = state.clone();
            candidate.pending = None;
            self.store.write(&candidate)?;
            *state = candidate;
            return Ok(None);
        }
        let now = unix_micros()?;
        let minimum_remaining = single_submission_bound(self.config.request_deadline)
            .saturating_add(publication_retry_reserve(self.config.request_deadline))
            .saturating_add(PUBLICATION_COMPLETION_MARGIN);
        if pending.expires_unix_micros.saturating_sub(now) <= duration_micros(minimum_remaining)? {
            let mut candidate = state.clone();
            candidate.pending = None;
            self.store.write(&candidate)?;
            *state = candidate;
            return Ok(None);
        }
        self.submit_pending(state, failpoint).await.map(Some)
    }

    async fn submit_pending(
        &self,
        state: &mut PublicationStateBody,
        failpoint: PublicationFailpoint,
    ) -> Result<PublicationReceipt, PublicationError> {
        let pending = state.pending.clone().ok_or_else(|| {
            PublicationError::state("submit_pending called without pending packet")
        })?;
        let bytes = decode_hex(&pending.packet_hex)?;
        let put_elapsed = self.put_exact(&bytes).await?;
        if failpoint == PublicationFailpoint::AfterPutBeforeCommit {
            return Err(PublicationError::new(
                PublicationErrorKind::InjectedCrash,
                "injected crash after authority PUT before local commit",
            ));
        }
        let visible_started = Instant::now();
        self.verify_visible(&bytes).await?;
        let visibility_elapsed = visible_started.elapsed();
        let record = decode_node_record(&bytes)
            .map_err(|error| PublicationError::state(format!("pending packet invalid: {error}")))?;
        let mut candidate = state.clone();
        candidate.committed = Some(pending);
        candidate.pending = None;
        self.store.write(&candidate)?;
        *state = candidate;
        Ok(PublicationReceipt {
            record,
            reused_committed_packet: false,
            put_elapsed: Some(put_elapsed),
            visibility_elapsed,
        })
    }

    async fn put_exact(&self, bytes: &[u8]) -> Result<Duration, PublicationError> {
        let signer = self.key.public().to_z32();
        let put_started = Instant::now();
        let response = self
            .client
            .put_record(&signer, bytes, self.config.request_deadline)
            .await
            .map_err(PublicationError::transport)?;
        let put_elapsed = put_started.elapsed();
        if !(200..300).contains(&response.status) {
            return Err(PublicationError::new(
                PublicationErrorKind::Authority,
                format!(
                    "authority PUT returned status {} with {} body bytes",
                    response.status,
                    response.body.len()
                ),
            ));
        }
        Ok(put_elapsed)
    }

    async fn verify_visible(&self, expected: &[u8]) -> Result<(), PublicationError> {
        let signer = self.key.public().to_z32();
        let response = self
            .client
            .get_record(&signer, self.config.request_deadline)
            .await
            .map_err(PublicationError::transport)?;
        if response.status != 200 {
            return Err(PublicationError::new(
                PublicationErrorKind::Visibility,
                format!(
                    "authority visibility GET returned status {}",
                    response.status
                ),
            ));
        }
        if response.body != expected {
            return Err(PublicationError::new(
                PublicationErrorKind::Visibility,
                "authority visibility GET did not return the exact signed packet",
            ));
        }
        let record = decode_node_record(&response.body).map_err(|error| {
            PublicationError::new(
                PublicationErrorKind::Visibility,
                format!("visible signed record failed strict validation: {error}"),
            )
        })?;
        if record.node_id != self.node_id
            || record.namespace != self.config.namespace
            || record.recipient != self.config.signed_recipient
        {
            return Err(PublicationError::new(
                PublicationErrorKind::Visibility,
                "visible record does not match configured signer/namespace/recipient",
            ));
        }
        Ok(())
    }
}

fn update_desired_intent(
    desired: &mut (u64, Vec<NodeLocation>),
    locations: Vec<NodeLocation>,
) -> Result<u64, PublicationError> {
    if desired.1 == locations {
        return Ok(desired.0);
    }
    let revision = desired
        .0
        .checked_add(1)
        .ok_or_else(|| PublicationError::state("desired-location revision overflow"))?;
    *desired = (revision, locations);
    Ok(revision)
}

/// Weak mutation/status capability.  It cannot keep a publisher or endpoint
/// alive and exposes no signer material.
#[derive(Clone)]
pub struct NodePublicationHandle {
    inner: Weak<PublisherInner>,
}

impl fmt::Debug for NodePublicationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodePublicationHandle")
            .field("alive", &self.inner.strong_count().gt(&0))
            .finish()
    }
}

impl NodePublicationHandle {
    pub async fn current_record(&self) -> Result<Option<NodeRecord>, PublicationError> {
        let inner = self.inner.upgrade().ok_or_else(|| {
            PublicationError::new(PublicationErrorKind::Closed, "publisher is closed")
        })?;
        if inner.closing.load(Ordering::Acquire) {
            return Err(PublicationError::new(
                PublicationErrorKind::Closed,
                "publisher is closing",
            ));
        }
        if let Some(error) = inner.fatal_error() {
            return Err(error);
        }
        inner.store.ensure_healthy()?;
        let state = inner.state.lock().await;
        let record = state
            .committed
            .as_ref()
            .map(|stored| {
                let bytes = decode_hex(&stored.packet_hex)?;
                decode_node_record(&bytes).map_err(|error| {
                    PublicationError::state(format!("committed packet is invalid: {error}"))
                })
            })
            .transpose()?;
        if let Some(error) = inner.fatal_error() {
            return Err(error);
        }
        if let Some(record) = &record
            && !record.is_visible_at(unix_micros()?)
        {
            return Err(PublicationError::state(format!(
                "last committed node-publication record expired at {} and is not current",
                record.expires_unix_micros
            )));
        }
        Ok(record)
    }

    pub(crate) async fn update_locations(
        &self,
        locations: impl IntoIterator<Item = NodeLocation>,
    ) -> Result<PublicationReceipt, PublicationError> {
        let inner = self.inner.upgrade().ok_or_else(|| {
            PublicationError::new(PublicationErrorKind::Closed, "publisher is closed")
        })?;
        if inner.closing.load(Ordering::Acquire) {
            return Err(PublicationError::new(
                PublicationErrorKind::Closed,
                "publisher is closing",
            ));
        }
        let mut closing = inner.close.subscribe();
        let deadline = Instant::now() + PUBLICATION_TRANSITION_DEADLINE;
        let requested = inner.validate_desired_locations(locations.into_iter().collect())?;
        // Validation and revision allocation happen before the retry boundary.
        // Therefore an invalid/unauthorized request or revision overflow can
        // never be disguised as success by refreshing the previous target.
        inner.record_desired_intent(requested)?;
        let transition = tokio::time::timeout_at(deadline, async {
            match inner.transition_recorded(PublicationFailpoint::None).await {
                Ok(receipt) => Ok(receipt),
                Err(first_error) => {
                    tokio::task::yield_now().await;
                    inner.refresh_current().await.map_err(|second_error| {
                        PublicationError::new(
                            second_error.kind.clone(),
                            format!(
                                "latest desired address update failed twice inside {:?}: first={first_error}; second={second_error}",
                                PUBLICATION_TRANSITION_DEADLINE
                            ),
                        )
                    })
                }
            }
        });
        tokio::pin!(transition);
        tokio::select! {
            biased;
            changed = closing.changed() => {
                let _ = changed;
                Err(PublicationError::new(PublicationErrorKind::Closed, "publisher closed during transition"))
            }
            result = &mut transition => {
                result.map_err(|_| transition_deadline_error())?
            }
        }
    }

    pub async fn wait_for_fatal(&self) -> PublicationError {
        let inner = match self.inner.upgrade() {
            Some(inner) => inner,
            None => {
                return PublicationError::new(
                    PublicationErrorKind::Closed,
                    "publisher closed before health could be observed",
                );
            }
        };
        let mut fatal = inner.fatal.subscribe();
        if let Some(error) = fatal.borrow().clone() {
            return error;
        }
        match fatal.wait_for(Option::is_some).await {
            Ok(error) => error
                .clone()
                .expect("watch predicate guarantees a fatal publication error"),
            Err(_) => PublicationError::new(
                PublicationErrorKind::Closed,
                "publisher health channel closed without a fatal error",
            ),
        }
    }

    pub(crate) fn mark_fatal(&self, error: PublicationError) {
        if let Some(inner) = self.inner.upgrade() {
            inner.mark_fatal(error);
        }
    }

    #[cfg(test)]
    #[doc(hidden)]
    pub(crate) async fn update_locations_with_failpoint(
        &self,
        locations: impl IntoIterator<Item = NodeLocation>,
        failpoint: PublicationFailpoint,
    ) -> Result<PublicationReceipt, PublicationError> {
        let inner = self.inner.upgrade().ok_or_else(|| {
            PublicationError::new(PublicationErrorKind::Closed, "publisher is closed")
        })?;
        inner
            .transition(locations.into_iter().collect(), failpoint)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn refresh_current_for_test(
        &self,
    ) -> Result<PublicationReceipt, PublicationError> {
        let inner = self.inner.upgrade().ok_or_else(|| {
            PublicationError::new(PublicationErrorKind::Closed, "publisher is closed")
        })?;
        inner.refresh_with_retry().await
    }

    #[cfg(test)]
    pub(crate) fn desired_locations_for_test(&self) -> Result<Vec<NodeLocation>, PublicationError> {
        let inner = self.inner.upgrade().ok_or_else(|| {
            PublicationError::new(PublicationErrorKind::Closed, "publisher is closed")
        })?;
        let locations = inner
            .desired_intent
            .lock()
            .map_err(|_| PublicationError::state("desired-location intent mutex poisoned"))?
            .1
            .clone();
        Ok(locations)
    }

    #[cfg(test)]
    pub(crate) async fn pending_packet_for_test(&self) -> Option<Vec<u8>> {
        let inner = self.inner.upgrade()?;
        let state = inner.state.lock().await;
        state.pending.as_ref().map(|pending| {
            decode_hex(&pending.packet_hex).expect("test pending packet must decode")
        })
    }

    #[cfg(test)]
    pub(crate) async fn committed_packet_for_test(&self) -> Option<Vec<u8>> {
        let inner = self.inner.upgrade()?;
        let state = inner.state.lock().await;
        state.committed.as_ref().map(|packet| {
            decode_hex(&packet.packet_hex).expect("test committed packet must decode")
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_state_writes_for_test(&self, count: u64) {
        if let Some(inner) = self.inner.upgrade() {
            inner
                .store
                .fail_writes_remaining
                .store(count, Ordering::Release);
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_post_rename_for_test(&self) {
        if let Some(inner) = self.inner.upgrade() {
            inner
                .store
                .fail_next_post_rename
                .store(true, Ordering::Release);
        }
    }
}

pub(crate) struct NodePublicationRuntime {
    inner: Arc<PublisherInner>,
    refresh: Option<JoinHandle<()>>,
}

impl fmt::Debug for NodePublicationRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodePublicationRuntime")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl NodePublicationRuntime {
    #[cfg(test)]
    pub(crate) async fn start(
        state_dir: &Path,
        key: SecretKey,
        config: NodePublicationConfig,
        absolute_startup_deadline: Instant,
    ) -> Result<(Self, PublicationReceipt), PublicationError> {
        let initial_locations = config.initial_locations.clone();
        Self::start_with_effective_locations(
            state_dir,
            key,
            config,
            initial_locations,
            absolute_startup_deadline,
        )
        .await
    }

    pub(crate) async fn start_with_effective_locations(
        state_dir: &Path,
        key: SecretKey,
        config: NodePublicationConfig,
        initial_locations: Vec<NodeLocation>,
        absolute_startup_deadline: Instant,
    ) -> Result<(Self, PublicationReceipt), PublicationError> {
        let initial_locations = canonical_locations(initial_locations)?;
        if initial_locations.is_empty() {
            return Err(PublicationError::configuration(
                "publication startup requires at least one currently observed reachable location; a withdrawal is not readiness",
            ));
        }
        let refresh_interval = config.refresh_interval;
        let refresh_reserve = publication_retry_reserve(config.request_deadline);
        if Instant::now() >= absolute_startup_deadline {
            return Err(PublicationError::new(
                PublicationErrorKind::State,
                "identity/state validation and endpoint bind consumed the startup-to-visible deadline",
            ));
        }
        // Local durable-state syscalls are deliberately ordered in this task.
        // They are assumed to run on a responsive local filesystem; detaching
        // them behind `spawn_blocking` would allow a canceled write to rename
        // state after the publication transition had returned.
        let inner = PublisherInner::open(state_dir, key, config)?;
        let receipt = tokio::time::timeout_at(
            absolute_startup_deadline,
            inner.transition(initial_locations.clone(), PublicationFailpoint::None),
        )
        .await
        .map_err(|_| {
            PublicationError::new(
                PublicationErrorKind::Transport,
                format!(
                    "startup-to-visible exceeded {:?}",
                    PUBLICATION_STARTUP_DEADLINE
                ),
            )
        })
        .and_then(|result| result);
        let receipt = match receipt {
            Ok(receipt) => receipt,
            Err(startup_error) => {
                // A successful PUT can precede a visibility or local-commit
                // failure.  Never return ownership to the caller while that
                // escaped live record is left unopposed: advance the durable
                // high-water and attempt a bounded tombstone first.
                inner.closing.store(true, Ordering::Release);
                let cleanup = tokio::time::timeout(
                    PUBLICATION_TRANSITION_DEADLINE,
                    inner.withdraw_for_shutdown(),
                )
                .await;
                let cleanup = match cleanup {
                    Ok(Ok(receipt)) => format!(
                        "higher-sequence withdrawal {} became visible",
                        receipt.record.sequence
                    ),
                    Ok(Err(error)) => format!("withdrawal failed: {error}"),
                    Err(_) => format!("withdrawal exceeded {:?}", PUBLICATION_TRANSITION_DEADLINE),
                };
                return Err(PublicationError::new(
                    startup_error.kind,
                    format!("{}; startup cleanup: {cleanup}", startup_error.message),
                ));
            }
        };
        let mut stop_rx = inner.close.subscribe();
        let refresh_inner = inner.clone();
        let mut refresh_record = receipt.record.clone();
        let refresh = tokio::spawn(async move {
            loop {
                let delay = match refresh_delay(&refresh_record, refresh_interval, refresh_reserve)
                {
                    Ok(delay) => delay,
                    Err(error) => {
                        eprintln!(
                            "IROH-NODE-PUBLICATION-FATAL source=refresh-schedule error={error}"
                        );
                        refresh_inner.mark_fatal(error);
                        break;
                    }
                };
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {
                        match refresh_inner.refresh_with_retry().await {
                            Err(error) => {
                                eprintln!("IROH-NODE-PUBLICATION-FATAL source=refresh error={error}");
                                refresh_inner.mark_fatal(error);
                                break;
                            }
                            Ok(receipt) => {
                                refresh_record = receipt.record.clone();
                                eprintln!(
                                    "IROH-NODE-PUBLICATION-REFRESH state={:?} sequence={} reused={} locations={} visibility_ms={}",
                                    receipt.record.state,
                                    receipt.record.sequence,
                                    receipt.reused_committed_packet,
                                    receipt.record.locations.len(),
                                    receipt.visibility_elapsed.as_millis(),
                                );
                            }
                        }
                    }
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        Ok((
            Self {
                inner,
                refresh: Some(refresh),
            },
            receipt,
        ))
    }

    pub(crate) fn handle(&self) -> NodePublicationHandle {
        NodePublicationHandle {
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub(crate) fn fatal_error(&self) -> Option<PublicationError> {
        self.inner.fatal_error()
    }

    /// Simulate abrupt process loss without publishing a withdrawal while
    /// still waiting for the in-process refresh task to release the state
    /// lock.  Real process exit releases the flock synchronously; tests need
    /// this explicit join because Tokio cancellation is cooperative.
    #[cfg(test)]
    pub(crate) async fn crash_for_test(mut self) {
        self.inner.closing.store(true, Ordering::Release);
        let _ = self.inner.close.send(true);
        if let Some(refresh) = self.refresh.take() {
            refresh.abort();
            let _ = refresh.await;
        }
    }

    pub(crate) async fn shutdown(
        mut self,
        absolute_deadline: Instant,
    ) -> Result<PublicationReceipt, PublicationError> {
        tokio::time::timeout_at(absolute_deadline, async {
            self.inner.closing.store(true, Ordering::Release);
            let _ = self.inner.close.send(true);
            if let Some(refresh) = self.refresh.take() {
                refresh.abort();
                let _ = refresh.await;
            }
            self.inner.withdraw_for_shutdown().await
        })
        .await
        .map_err(|_| {
            PublicationError::new(
                PublicationErrorKind::Transport,
                "graceful withdrawal exceeded the runtime absolute deadline",
            )
        })?
    }
}

fn refresh_delay(
    record: &NodeRecord,
    configured_interval: Duration,
    transition_reserve: Duration,
) -> Result<Duration, PublicationError> {
    let remaining_micros = record.expires_unix_micros.saturating_sub(unix_micros()?);
    let reserve_micros =
        duration_micros(transition_reserve.saturating_add(PUBLICATION_COMPLETION_MARGIN))?;
    Ok(configured_interval.min(Duration::from_micros(
        remaining_micros.saturating_sub(reserve_micros),
    )))
}

impl Drop for NodePublicationRuntime {
    fn drop(&mut self) {
        self.inner.closing.store(true, Ordering::Release);
        let _ = self.inner.close.send(true);
        if let Some(refresh) = self.refresh.take() {
            refresh.abort();
        }
    }
}

fn unix_micros() -> Result<u64, PublicationError> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            PublicationError::state(format!("system clock precedes UNIX epoch: {error}"))
        })?
        .as_micros();
    micros
        .try_into()
        .map_err(|_| PublicationError::state("system clock microseconds exceed u64"))
}

fn duration_micros(duration: Duration) -> Result<u64, PublicationError> {
    duration
        .as_micros()
        .try_into()
        .map_err(|_| PublicationError::configuration("duration microseconds exceed u64"))
}

fn next_sequence(now: u64, high_water: Option<u64>) -> Result<u64, PublicationError> {
    match high_water {
        Some(u64::MAX) => Err(PublicationError::state(
            "publication sequence reached u64::MAX and cannot advance",
        )),
        Some(high_water) => Ok(now.max(high_water + 1)),
        None => Ok(now),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, PublicationError> {
    if !raw.len().is_multiple_of(2) || raw.len() > iroh_dns::pkarr::SignedPacket::MAX_BYTES * 2 {
        return Err(PublicationError::state(
            "stored packet hex has an invalid length",
        ));
    }
    raw.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, PublicationError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(PublicationError::state(
            "stored packet hex is not canonical lowercase hex",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_is_closed_and_external_contact_requires_authorization() {
        let location = NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap();
        let result = NodePublicationConfig::new(
            "run-1",
            "authority.test:v1",
            "203.0.113.1:8080".parse().unwrap(),
            "authority.test",
            PublicationAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
            Duration::from_secs(30),
            Duration::from_secs(10),
            Duration::from_secs(2),
            [location],
        );
        assert!(result.is_err());

        let external = NodePublicationConfig::new(
            "run-1",
            "authority.test:v1",
            "203.0.113.1:8080".parse().unwrap(),
            "authority.test",
            PublicationAuthorityAuthorization::ExternalAuthorized {
                owner: "operator".into(),
                authorization_reference: "change-ticket-123".into(),
            },
            Duration::from_secs(30),
            Duration::from_secs(10),
            Duration::from_secs(2),
            [NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap()],
        )
        .unwrap_err();
        assert!(external.to_string().contains("pinned plain HTTP"));

        let unsafe_timing = NodePublicationConfig::new(
            "run-1",
            "authority.test:v1",
            "127.0.0.1:8080".parse().unwrap(),
            "authority.test",
            PublicationAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
            Duration::from_secs(6),
            Duration::from_secs(4),
            Duration::from_secs(2),
            [NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap()],
        )
        .unwrap_err();
        assert!(unsafe_timing.to_string().contains("completion margin"));

        let boundary_ttl = NodePublicationConfig::new(
            "run-1",
            "authority.test:v1",
            "127.0.0.1:8080".parse().unwrap(),
            "authority.test",
            PublicationAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
            Duration::from_secs(11),
            Duration::from_secs(4),
            Duration::from_secs(2),
            [NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap()],
        )
        .unwrap_err();
        assert!(boundary_ttl.to_string().contains("must exceed 11s"));

        NodePublicationConfig::new(
            "run-1",
            "authority.test:v1",
            "127.0.0.1:8080".parse().unwrap(),
            "authority.test",
            PublicationAuthorityAuthorization::LocalProductionShaped {
                owner: "operator".into(),
            },
            Duration::from_secs(12),
            Duration::from_secs(4),
            Duration::from_secs(2),
            [NodeLocation::direct("127.0.0.1:4433".parse().unwrap()).unwrap()],
        )
        .expect("TTL 12s is the first safe whole-second evidence boundary");
    }

    #[test]
    fn state_checksum_and_unknown_fields_fail_closed() {
        let key = SecretKey::generate();
        let node = NodeId::from_bytes(*key.public().as_bytes());
        let config = NodePublicationConfig::new(
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
        let body = PublicationStateBody::fresh(node, &config);
        let bytes = encode_state(&body).unwrap();
        assert_eq!(decode_state(&bytes).unwrap(), body);
        let mut corrupt = bytes.clone();
        let index = corrupt.len() / 2;
        corrupt[index] ^= 1;
        assert!(decode_state(&corrupt).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(decode_state(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn durable_high_water_defeats_clock_rollback_and_max_fails_closed() {
        assert_eq!(next_sequence(10, Some(50)).unwrap(), 51);
        assert_eq!(next_sequence(100, Some(50)).unwrap(), 100);
        assert!(next_sequence(1, Some(u64::MAX)).is_err());
    }

    #[test]
    fn refresh_delay_keeps_retry_window_and_completion_margin_before_expiry() {
        let record = NodeRecord {
            node_id: NodeId::from_bytes([0; 32]),
            namespace: "run-1".into(),
            recipient: "authority.test:v1".into(),
            ttl_seconds: 12,
            sequence: 1,
            expires_unix_micros: unix_micros().unwrap() + 6_050_000,
            state: PublicationState::Withdrawn,
            locations: Vec::new(),
        };
        let delay = refresh_delay(
            &record,
            Duration::from_secs(4),
            PUBLICATION_TRANSITION_DEADLINE,
        )
        .unwrap();
        assert!(
            delay <= Duration::from_millis(50),
            "only the 50ms beyond retry reserve plus completion margin may be slept: {delay:?}"
        );

        let at_boundary = NodeRecord {
            expires_unix_micros: unix_micros().unwrap() + 6_000_000,
            ..record
        };
        assert_eq!(
            refresh_delay(
                &at_boundary,
                Duration::from_secs(4),
                PUBLICATION_TRANSITION_DEADLINE,
            )
            .unwrap(),
            Duration::ZERO,
            "the strict expiry boundary leaves no safe sleep"
        );
    }

    #[test]
    fn anchor_rejects_same_revision_desired_location_mutation() {
        let state_dir = std::env::temp_dir().join(format!(
            "nix-p2p-publisher-anchor-desired-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&state_dir).unwrap();
        std::fs::set_permissions(
            &state_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let key = SecretKey::generate();
        let node = NodeId::from_bytes(*key.public().as_bytes());
        let config = NodePublicationConfig::new(
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
        let (store, mut state) = PublicationStateStore::open(&state_dir, node, &config).unwrap();
        drop(store);
        state.desired_locations = vec![StoredDesiredLocation::from(
            &NodeLocation::direct("127.0.0.1:4434".parse().unwrap()).unwrap(),
        )];
        std::fs::write(
            state_dir.join(PUBLICATION_STATE_FILENAME),
            encode_state(&state).unwrap(),
        )
        .unwrap();
        let error = match PublicationStateStore::open(&state_dir, node, &config) {
            Err(error) => error,
            Ok(_) => panic!("same-revision desired-location mutation passed its anchor"),
        };
        assert!(error.to_string().contains("desired locations changed"));
        std::fs::remove_dir_all(state_dir).unwrap();
    }
}
