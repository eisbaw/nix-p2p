//! Persistent, monotonic authority for routed Iroh node-publication records.
//!
//! This is intentionally small enough to operate as a separately routed local
//! service.  It is not a discovery client: PUT accepts one signer-scoped pkarr
//! packet and GET returns that exact packet.  The durable high-water sequence is
//! retained after expiry and withdrawal so replay can never resurrect a node.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh_dns::pkarr::SignedPacket;
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
#[cfg(test)]
use tokio::sync::Notify;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::iroh_node_record::{
    PublicationState, decode_node_record, normalize_socket_addr, validate_namespace,
    validate_recipient,
};
use crate::iroh_runtime::{open_state_directory, validate_directory};
use crate::pinned_http::{MAX_RELAY_PAYLOAD_BYTES, RECORD_PATH_PREFIX, validate_host};

pub const AUTHORITY_STATE_FILENAME: &str = "iroh-node-publication-authority.json";
const AUTHORITY_LOCK_FILENAME: &str = "iroh-node-publication-authority.lock";
const AUTHORITY_TEMP_FILENAME: &str = ".iroh-node-publication-authority.tmp";
const AUTHORITY_ANCHOR_FILENAME: &str = "iroh-node-publication-authority-anchor.json";
const AUTHORITY_ANCHOR_TEMP_FILENAME: &str = ".iroh-node-publication-authority-anchor.tmp";
const AUTHORITY_STATE_SCHEMA: u32 = 1;
const AUTHORITY_STATE_MODE: u32 = 0o600;
const MAX_AUTHORITY_STATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REQUEST_HEADER_BYTES: usize = 8192;
const MAX_ACTIVE_CONNECTIONS: usize = 64;
const AUTHORITY_CHECKSUM_DOMAIN: &[u8] = b"nix-p2p/iroh-node-publication-authority/v1\0";
const AUTHORITY_ANCHOR_CHECKSUM_DOMAIN: &[u8] =
    b"nix-p2p/iroh-node-publication-authority/anchor/v1\0";
const AUTHORITY_ADMISSION_DOMAIN: &[u8] = b"nix-p2p/iroh-node-publication-authority/admission/v1\0";
const EXPIRY_CLOCK_GRACE: Duration = Duration::from_secs(1);
const CLOCK_HIGH_WATER_GRANULARITY_MICROS: u64 = 1_000_000;
const AUTHORITY_REQUEST_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct PublicationAuthorityConfig {
    pub listen: SocketAddr,
    pub state_dir: PathBuf,
    pub namespace: String,
    pub signed_recipient: String,
    pub expected_host: String,
    pub owner: String,
    pub signer_admission: AuthoritySignerAdmission,
}

#[derive(Debug, Clone)]
pub enum AuthoritySignerAdmission {
    /// Exact canonical z-base-32 signer IDs admitted by this authority.
    Explicit(BTreeSet<String>),
    /// Unit tests exercise protocol/state behavior without coupling every
    /// fixture's generated key into config construction. Never built into a
    /// production library artifact.
    #[cfg(test)]
    TestOnlyUnrestricted,
}

impl AuthoritySignerAdmission {
    pub fn explicit(signers: impl IntoIterator<Item = String>) -> Result<Self, AuthorityError> {
        let signers = signers.into_iter().collect::<BTreeSet<_>>();
        let admission = Self::Explicit(signers);
        admission.validate()?;
        Ok(admission)
    }

    fn validate(&self) -> Result<(), AuthorityError> {
        match self {
            Self::Explicit(signers) => {
                if signers.is_empty() || signers.len() > 256 {
                    return Err(AuthorityError::configuration(
                        "authorized signer set must contain 1..=256 keys",
                    ));
                }
                for signer in signers {
                    let key = iroh::PublicKey::from_z32(signer).map_err(|error| {
                        AuthorityError::configuration(format!(
                            "authorized signer {signer:?} is invalid: {error}"
                        ))
                    })?;
                    if key.to_z32() != *signer {
                        return Err(AuthorityError::configuration(format!(
                            "authorized signer {signer:?} is not canonical"
                        )));
                    }
                }
                Ok(())
            }
            #[cfg(test)]
            Self::TestOnlyUnrestricted => Ok(()),
        }
    }

    fn admits(&self, signer: &str) -> bool {
        match self {
            Self::Explicit(signers) => signers.contains(signer),
            #[cfg(test)]
            Self::TestOnlyUnrestricted => true,
        }
    }

    fn fingerprint(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(AUTHORITY_ADMISSION_DOMAIN);
        match self {
            Self::Explicit(signers) => {
                hasher.update(b"explicit\0");
                for signer in signers {
                    hasher.update(&(signer.len() as u64).to_be_bytes());
                    hasher.update(signer.as_bytes());
                }
            }
            #[cfg(test)]
            Self::TestOnlyUnrestricted => {
                hasher.update(b"test-only-unrestricted\0");
            }
        }
        hasher.finalize().to_hex().to_string()
    }
}

impl PublicationAuthorityConfig {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        let listen = normalize_socket_addr(self.listen);
        if listen.port() == 0
            || listen.ip().is_unspecified()
            || listen.ip().is_multicast()
            || matches!(listen.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::BROADCAST)
            || !is_local_authority_ip(listen.ip())
            || matches!(listen, SocketAddr::V6(address) if address.ip().is_unicast_link_local() && address.scope_id() == 0)
        {
            return Err(AuthorityError::configuration(format!(
                "authority listen {} must be loopback/private/local unicast with a nonzero port; public plain-HTTP binds are forbidden",
                self.listen
            )));
        }
        validate_namespace(&self.namespace)
            .map_err(|error| AuthorityError::configuration(error.to_string()))?;
        validate_recipient(&self.signed_recipient)
            .map_err(|error| AuthorityError::configuration(error.to_string()))?;
        validate_host(&self.expected_host)
            .map_err(|error| AuthorityError::configuration(error.to_string()))?;
        self.signer_admission.validate()?;
        if self.owner.trim().is_empty()
            || self.owner.len() > 128
            || self.owner.chars().any(char::is_control)
        {
            return Err(AuthorityError::configuration(
                "authority owner must be 1..=128 non-control characters",
            ));
        }
        Ok(())
    }
}

fn is_local_authority_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            ip.is_loopback() || ip.is_unicast_link_local() || first & 0xfe00 == 0xfc00
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityError(String);

impl AuthorityError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    fn configuration(message: impl Into<String>) -> Self {
        Self::new(format!(
            "authority configuration rejected: {}",
            message.into()
        ))
    }
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AuthorityError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthorityRecordState {
    Live,
    Withdrawn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityEntry {
    high_water_sequence: u64,
    expires_unix_micros: u64,
    state: AuthorityRecordState,
    /// One-way durable latch. Once expiry is observed, wall-clock rollback
    /// cannot make the entry visible again.
    expired: bool,
    packet_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityStateBody {
    schema_version: u32,
    namespace: String,
    signed_recipient: String,
    signer_admission_blake3_hex: String,
    wall_clock_high_water_unix_micros: u64,
    records: BTreeMap<String, AuthorityEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityStateEnvelope {
    body: AuthorityStateBody,
    checksum_blake3_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthorityAnchorEntry {
    high_water_sequence: u64,
    expired: bool,
    packet_blake3_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthorityAnchorBody {
    schema_version: u32,
    namespace: String,
    signed_recipient: String,
    signer_admission_blake3_hex: String,
    wall_clock_high_water_unix_micros: u64,
    records: BTreeMap<String, AuthorityAnchorEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityAnchorEnvelope {
    body: AuthorityAnchorBody,
    checksum_blake3_hex: String,
}

struct AuthorityStateStore {
    state_dir: PathBuf,
    dirfd: rustix::fd::OwnedFd,
    _lock: rustix::fd::OwnedFd,
    #[cfg(test)]
    fail_next_write: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_next_post_rename: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    successful_writes: AtomicU64,
    poisoned: std::sync::atomic::AtomicBool,
}

impl AuthorityStateStore {
    fn open(
        config: &PublicationAuthorityConfig,
    ) -> Result<(Self, AuthorityStateBody), AuthorityError> {
        let (dirfd, _) = open_state_directory(&config.state_dir)
            .map_err(|error| AuthorityError::new(error.to_string()))?;
        validate_directory(&dirfd, &config.state_dir)
            .map_err(|error| AuthorityError::new(error.to_string()))?;
        let (lock, created) = match fs::openat(
            &dirfd,
            AUTHORITY_LOCK_FILENAME,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(AUTHORITY_STATE_MODE),
        ) {
            Ok(lock) => (lock, true),
            Err(Errno::EXIST) => (
                fs::openat(
                    &dirfd,
                    AUTHORITY_LOCK_FILENAME,
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| {
                    authority_io(&config.state_dir, "opening authority lock", error)
                })?,
                false,
            ),
            Err(error) => {
                return Err(authority_io(
                    &config.state_dir,
                    "creating authority lock",
                    error,
                ));
            }
        };
        if created {
            fs::fchmod(&lock, Mode::from_raw_mode(AUTHORITY_STATE_MODE)).map_err(|error| {
                authority_io(&config.state_dir, "setting authority lock mode", error)
            })?;
            fs::fsync(&dirfd).map_err(|error| {
                authority_io(&config.state_dir, "syncing authority lock", error)
            })?;
        }
        validate_secure_file(&lock, &config.state_dir, AUTHORITY_LOCK_FILENAME)?;
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            AuthorityError::new(format!(
                "{} is already owned by another authority: {error}",
                config.state_dir.join(AUTHORITY_LOCK_FILENAME).display()
            ))
        })?;
        let store = Self {
            state_dir: config.state_dir.clone(),
            dirfd,
            _lock: lock,
            #[cfg(test)]
            fail_next_write: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_next_post_rename: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            successful_writes: AtomicU64::new(0),
            poisoned: std::sync::atomic::AtomicBool::new(false),
        };
        let loaded = store.read()?;
        let had_state = loaded.is_some();
        let body = loaded.unwrap_or_else(|| AuthorityStateBody {
            schema_version: AUTHORITY_STATE_SCHEMA,
            namespace: config.namespace.clone(),
            signed_recipient: config.signed_recipient.clone(),
            signer_admission_blake3_hex: config.signer_admission.fingerprint(),
            wall_clock_high_water_unix_micros: 0,
            records: BTreeMap::new(),
        });
        validate_authority_state(&body, config)?;
        store.validate_or_initialize_anchor(&body, had_state)?;
        let now = unix_micros()?;
        if body.wall_clock_high_water_unix_micros != 0
            && now.saturating_add(CLOCK_HIGH_WATER_GRANULARITY_MICROS)
                < body.wall_clock_high_water_unix_micros
        {
            return Err(AuthorityError::new(format!(
                "authority wall clock regressed from durable high-water {} to {now}; refusing to serve until clock recovery",
                body.wall_clock_high_water_unix_micros
            )));
        }
        Ok((store, body))
    }

    fn read(&self) -> Result<Option<AuthorityStateBody>, AuthorityError> {
        self.ensure_healthy()?;
        let file = match fs::openat(
            &self.dirfd,
            AUTHORITY_STATE_FILENAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => {
                return Err(authority_io(
                    &self.state_dir,
                    "opening authority state",
                    error,
                ));
            }
        };
        let before = validate_secure_file(&file, &self.state_dir, AUTHORITY_STATE_FILENAME)?;
        let mut file = File::from(file);
        let mut bytes = Vec::with_capacity(before.st_size.max(0) as usize);
        (&mut file)
            .take(MAX_AUTHORITY_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| AuthorityError::new(format!("reading authority state: {error}")))?;
        if bytes.len() as u64 > MAX_AUTHORITY_STATE_BYTES {
            return Err(AuthorityError::new(format!(
                "authority state exceeds {MAX_AUTHORITY_STATE_BYTES} bytes"
            )));
        }
        let after = validate_secure_file(&file, &self.state_dir, AUTHORITY_STATE_FILENAME)?;
        let entry = fs::statat(
            &self.dirfd,
            AUTHORITY_STATE_FILENAME,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| authority_io(&self.state_dir, "rechecking authority state", error))?;
        if before.st_dev != after.st_dev
            || before.st_ino != after.st_ino
            || before.st_size != after.st_size
            || before.st_mtime != after.st_mtime
            || before.st_mtime_nsec != after.st_mtime_nsec
            || after.st_dev != entry.st_dev
            || after.st_ino != entry.st_ino
        {
            return Err(AuthorityError::new("authority state changed during read"));
        }
        decode_authority_state(&bytes).map(Some)
    }

    fn write(&self, body: &AuthorityStateBody) -> Result<(), AuthorityError> {
        self.ensure_healthy()?;
        #[cfg(test)]
        if self.fail_next_write.swap(false, Ordering::AcqRel) {
            return Err(AuthorityError::new(
                "injected authority state write failure",
            ));
        }
        let bytes = encode_authority_state(body)?;
        let temp_fd = fs::openat(
            &self.dirfd,
            ".",
            OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(AUTHORITY_STATE_MODE),
        )
        .map_err(|error| {
            authority_io(
                &self.state_dir,
                "creating authority state temporary file",
                error,
            )
        })?;
        fs::fchmod(&temp_fd, Mode::from_raw_mode(AUTHORITY_STATE_MODE)).map_err(|error| {
            authority_io(&self.state_dir, "setting authority temporary mode", error)
        })?;
        let mut temp = File::from(temp_fd);
        temp.write_all(&bytes)
            .and_then(|_| temp.sync_all())
            .map_err(|error| AuthorityError::new(format!("writing authority state: {error}")))?;
        match fs::unlinkat(&self.dirfd, AUTHORITY_TEMP_FILENAME, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(error) => {
                return Err(authority_io(
                    &self.state_dir,
                    "removing stale authority temporary link",
                    error,
                ));
            }
        }
        fs::linkat(
            &temp,
            "",
            &self.dirfd,
            AUTHORITY_TEMP_FILENAME,
            AtFlags::EMPTY_PATH,
        )
        .map_err(|error| {
            authority_io(&self.state_dir, "linking authority temporary file", error)
        })?;
        if let Err(error) = fs::renameat(
            &self.dirfd,
            AUTHORITY_TEMP_FILENAME,
            &self.dirfd,
            AUTHORITY_STATE_FILENAME,
        ) {
            let _ = fs::unlinkat(&self.dirfd, AUTHORITY_TEMP_FILENAME, AtFlags::empty());
            return Err(authority_io(
                &self.state_dir,
                "atomically replacing authority state",
                error,
            ));
        }
        let post_rename: Result<(), AuthorityError> = (|| {
            #[cfg(test)]
            if self.fail_next_post_rename.swap(false, Ordering::AcqRel) {
                return Err(AuthorityError::new(
                    "injected post-rename authority persistence failure",
                ));
            }
            fs::fsync(&self.dirfd).map_err(|error| {
                authority_io(&self.state_dir, "syncing authority state directory", error)
            })?;
            let published = fs::openat(
                &self.dirfd,
                AUTHORITY_STATE_FILENAME,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                authority_io(
                    &self.state_dir,
                    "reopening committed authority state",
                    error,
                )
            })?;
            validate_secure_file(&published, &self.state_dir, AUTHORITY_STATE_FILENAME)?;
            self.write_anchor(&AuthorityAnchorBody::from_state(body)?)?;
            Ok(())
        })();
        if let Err(error) = post_rename {
            self.poisoned.store(true, Ordering::Release);
            return Err(AuthorityError::new(format!(
                "{error}; authority state store is poisoned until restart"
            )));
        }
        #[cfg(test)]
        self.successful_writes.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<(), AuthorityError> {
        if self.poisoned.load(Ordering::Acquire) {
            Err(AuthorityError::new(
                "authority state store is poisoned after an ambiguous post-rename persistence failure; restart is required",
            ))
        } else {
            Ok(())
        }
    }

    fn validate_or_initialize_anchor(
        &self,
        state: &AuthorityStateBody,
        had_state: bool,
    ) -> Result<(), AuthorityError> {
        let current = AuthorityAnchorBody::from_state(state)?;
        let Some(anchor) = self.read_anchor()? else {
            if had_state {
                return Err(AuthorityError::new(format!(
                    "{} is missing while authority state exists; refusing a rollback-ambiguous state",
                    self.state_dir.join(AUTHORITY_ANCHOR_FILENAME).display()
                )));
            }
            return self.write_anchor(&current);
        };
        if anchor.schema_version != current.schema_version
            || anchor.namespace != current.namespace
            || anchor.signed_recipient != current.signed_recipient
            || anchor.signer_admission_blake3_hex != current.signer_admission_blake3_hex
        {
            return Err(AuthorityError::new(
                "authority rollback anchor identity does not match configuration/state",
            ));
        }
        if current.wall_clock_high_water_unix_micros < anchor.wall_clock_high_water_unix_micros {
            return Err(AuthorityError::new(
                "authority state wall-clock high-water is below rollback anchor",
            ));
        }
        for (signer, anchored) in &anchor.records {
            let Some(candidate) = current.records.get(signer) else {
                return Err(AuthorityError::new(format!(
                    "authority state omitted signer {signer} retained by rollback anchor"
                )));
            };
            if candidate.high_water_sequence < anchored.high_water_sequence
                || (candidate.high_water_sequence == anchored.high_water_sequence
                    && (candidate.packet_blake3_hex != anchored.packet_blake3_hex
                        || (anchored.expired && !candidate.expired)))
            {
                return Err(AuthorityError::new(format!(
                    "authority state for signer {signer} regressed below rollback anchor"
                )));
            }
        }
        if current != anchor {
            // State is written and directory-synced before its anchor. A crash
            // between those operations legitimately leaves the state ahead;
            // repair only in that direction. An anchor ahead was rejected.
            self.write_anchor(&current)?;
        }
        Ok(())
    }

    fn read_anchor(&self) -> Result<Option<AuthorityAnchorBody>, AuthorityError> {
        let file = match fs::openat(
            &self.dirfd,
            AUTHORITY_ANCHOR_FILENAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => file,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => {
                return Err(authority_io(
                    &self.state_dir,
                    "opening authority rollback anchor",
                    error,
                ));
            }
        };
        let stat = validate_secure_file(&file, &self.state_dir, AUTHORITY_ANCHOR_FILENAME)?;
        let mut file = File::from(file);
        let mut bytes = Vec::with_capacity(stat.st_size.max(0) as usize);
        (&mut file)
            .take(MAX_AUTHORITY_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                AuthorityError::new(format!("reading authority rollback anchor: {error}"))
            })?;
        if bytes.len() as u64 > MAX_AUTHORITY_STATE_BYTES {
            return Err(AuthorityError::new(
                "authority rollback anchor exceeds size bound",
            ));
        }
        decode_authority_anchor(&bytes).map(Some)
    }

    fn write_anchor(&self, anchor: &AuthorityAnchorBody) -> Result<(), AuthorityError> {
        let bytes = encode_authority_anchor(anchor)?;
        let temp_fd = fs::openat(
            &self.dirfd,
            ".",
            OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::from_raw_mode(AUTHORITY_STATE_MODE),
        )
        .map_err(|error| {
            authority_io(
                &self.state_dir,
                "creating rollback anchor temporary file",
                error,
            )
        })?;
        fs::fchmod(&temp_fd, Mode::from_raw_mode(AUTHORITY_STATE_MODE)).map_err(|error| {
            authority_io(
                &self.state_dir,
                "setting rollback anchor temporary mode",
                error,
            )
        })?;
        let mut temp = File::from(temp_fd);
        temp.write_all(&bytes)
            .and_then(|_| temp.sync_all())
            .map_err(|error| AuthorityError::new(format!("writing rollback anchor: {error}")))?;
        match fs::unlinkat(
            &self.dirfd,
            AUTHORITY_ANCHOR_TEMP_FILENAME,
            AtFlags::empty(),
        ) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(error) => {
                return Err(authority_io(
                    &self.state_dir,
                    "removing stale rollback anchor link",
                    error,
                ));
            }
        }
        fs::linkat(
            &temp,
            "",
            &self.dirfd,
            AUTHORITY_ANCHOR_TEMP_FILENAME,
            AtFlags::EMPTY_PATH,
        )
        .map_err(|error| authority_io(&self.state_dir, "linking rollback anchor", error))?;
        if let Err(error) = fs::renameat(
            &self.dirfd,
            AUTHORITY_ANCHOR_TEMP_FILENAME,
            &self.dirfd,
            AUTHORITY_ANCHOR_FILENAME,
        ) {
            let _ = fs::unlinkat(
                &self.dirfd,
                AUTHORITY_ANCHOR_TEMP_FILENAME,
                AtFlags::empty(),
            );
            return Err(authority_io(
                &self.state_dir,
                "atomically replacing rollback anchor",
                error,
            ));
        }
        fs::fsync(&self.dirfd)
            .map_err(|error| authority_io(&self.state_dir, "syncing rollback anchor", error))
    }
}

impl AuthorityAnchorBody {
    fn from_state(state: &AuthorityStateBody) -> Result<Self, AuthorityError> {
        Ok(Self {
            schema_version: state.schema_version,
            namespace: state.namespace.clone(),
            signed_recipient: state.signed_recipient.clone(),
            signer_admission_blake3_hex: state.signer_admission_blake3_hex.clone(),
            wall_clock_high_water_unix_micros: state.wall_clock_high_water_unix_micros,
            records: state
                .records
                .iter()
                .map(|(signer, entry)| {
                    Ok((
                        signer.clone(),
                        AuthorityAnchorEntry {
                            high_water_sequence: entry.high_water_sequence,
                            expired: entry.expired,
                            packet_blake3_hex: blake3::hash(&decode_hex(&entry.packet_hex)?)
                                .to_hex()
                                .to_string(),
                        },
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, AuthorityError>>()?,
        })
    }
}

fn validate_secure_file<Fd: std::os::fd::AsFd>(
    file: &Fd,
    state_dir: &Path,
    name: &str,
) -> Result<rustix::fs::Stat, AuthorityError> {
    let stat = fs::fstat(file)
        .map_err(|error| authority_io(state_dir, "inspecting authority file", error))?;
    let path = state_dir.join(name);
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o777 != AUTHORITY_STATE_MODE
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size as u64 > MAX_AUTHORITY_STATE_BYTES
    {
        return Err(AuthorityError::new(format!(
            "{} must be a current-user-owned regular 0600 single-link file no larger than {MAX_AUTHORITY_STATE_BYTES} bytes",
            path.display()
        )));
    }
    Ok(stat)
}

fn validate_authority_state(
    state: &AuthorityStateBody,
    config: &PublicationAuthorityConfig,
) -> Result<(), AuthorityError> {
    if state.schema_version != AUTHORITY_STATE_SCHEMA
        || state.namespace != config.namespace
        || state.signed_recipient != config.signed_recipient
        || state.signer_admission_blake3_hex != config.signer_admission.fingerprint()
    {
        return Err(AuthorityError::new(
            "authority state schema/namespace/recipient does not match configuration",
        ));
    }
    for (signer, entry) in &state.records {
        let packet = decode_hex(&entry.packet_hex)?;
        let signed = SignedPacket::from_bytes(&packet).map_err(|error| {
            AuthorityError::new(format!("stored authority packet invalid: {error}"))
        })?;
        if signed.public_key().to_z32() != *signer {
            return Err(AuthorityError::new(
                "stored authority signer key does not match map key",
            ));
        }
        let record = decode_node_record(&packet)
            .map_err(|error| AuthorityError::new(format!("stored node record invalid: {error}")))?;
        if record.sequence != entry.high_water_sequence
            || record.expires_unix_micros != entry.expires_unix_micros
            || record.namespace != config.namespace
            || record.recipient != config.signed_recipient
            || matches!(record.state, PublicationState::Live)
                != matches!(entry.state, AuthorityRecordState::Live)
        {
            return Err(AuthorityError::new(
                "stored authority entry metadata does not match signed packet",
            ));
        }
    }
    Ok(())
}

fn encode_authority_state(body: &AuthorityStateBody) -> Result<Vec<u8>, AuthorityError> {
    let body_bytes = serde_json::to_vec(body)
        .map_err(|error| AuthorityError::new(format!("encoding authority state body: {error}")))?;
    let envelope = AuthorityStateEnvelope {
        body: body.clone(),
        checksum_blake3_hex: authority_checksum(&body_bytes).to_hex().to_string(),
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| AuthorityError::new(format!("encoding authority state: {error}")))?;
    if bytes.len() as u64 > MAX_AUTHORITY_STATE_BYTES {
        return Err(AuthorityError::new(format!(
            "encoded authority state is {} bytes, maximum is {MAX_AUTHORITY_STATE_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn decode_authority_state(bytes: &[u8]) -> Result<AuthorityStateBody, AuthorityError> {
    let envelope: AuthorityStateEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| AuthorityError::new(format!("decoding authority state: {error}")))?;
    let body_bytes = serde_json::to_vec(&envelope.body)
        .map_err(|error| AuthorityError::new(format!("canonicalizing authority state: {error}")))?;
    if envelope.checksum_blake3_hex != authority_checksum(&body_bytes).to_hex().as_str() {
        return Err(AuthorityError::new(
            "authority state checksum does not match",
        ));
    }
    Ok(envelope.body)
}

fn authority_checksum(bytes: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUTHORITY_CHECKSUM_DOMAIN);
    hasher.update(bytes);
    hasher.finalize()
}

fn encode_authority_anchor(body: &AuthorityAnchorBody) -> Result<Vec<u8>, AuthorityError> {
    let body_bytes = serde_json::to_vec(body)
        .map_err(|error| AuthorityError::new(format!("encoding rollback anchor body: {error}")))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUTHORITY_ANCHOR_CHECKSUM_DOMAIN);
    hasher.update(&body_bytes);
    let envelope = AuthorityAnchorEnvelope {
        body: body.clone(),
        checksum_blake3_hex: hasher.finalize().to_hex().to_string(),
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| AuthorityError::new(format!("encoding rollback anchor: {error}")))?;
    if bytes.len() as u64 > MAX_AUTHORITY_STATE_BYTES {
        return Err(AuthorityError::new(
            "encoded rollback anchor exceeds size bound",
        ));
    }
    Ok(bytes)
}

fn decode_authority_anchor(bytes: &[u8]) -> Result<AuthorityAnchorBody, AuthorityError> {
    let envelope: AuthorityAnchorEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| AuthorityError::new(format!("decoding rollback anchor: {error}")))?;
    let body_bytes = serde_json::to_vec(&envelope.body)
        .map_err(|error| AuthorityError::new(format!("canonicalizing rollback anchor: {error}")))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(AUTHORITY_ANCHOR_CHECKSUM_DOMAIN);
    hasher.update(&body_bytes);
    if envelope.checksum_blake3_hex != hasher.finalize().to_hex().as_str() {
        return Err(AuthorityError::new(
            "rollback anchor checksum does not match",
        ));
    }
    Ok(envelope.body)
}

struct AuthorityInner {
    config: PublicationAuthorityConfig,
    state: Mutex<(AuthorityStateStore, AuthorityStateBody)>,
    monotonic_expiry: Mutex<BTreeMap<String, std::time::Instant>>,
    request_count: AtomicU64,
    #[cfg(test)]
    block_next_put: AtomicU64,
    #[cfg(test)]
    put_started: Notify,
    #[cfg(test)]
    release_put: Notify,
    #[cfg(test)]
    idempotent_puts: AtomicU64,
    #[cfg(test)]
    fail_next_get: AtomicU64,
}

pub struct PublicationAuthority {
    local_addr: SocketAddr,
    inner: Arc<AuthorityInner>,
    stop: watch::Sender<bool>,
    health: watch::Receiver<AuthorityHealth>,
    join: Option<JoinHandle<Result<(), AuthorityError>>>,
}

#[derive(Debug, Clone)]
enum AuthorityHealth {
    Running,
    Stopped,
    Failed(AuthorityError),
}

impl fmt::Debug for PublicationAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicationAuthority")
            .field("local_addr", &self.local_addr)
            .field("namespace", &self.inner.config.namespace)
            .field("owner", &self.inner.config.owner)
            .finish_non_exhaustive()
    }
}

impl PublicationAuthority {
    pub async fn bind(config: PublicationAuthorityConfig) -> Result<Self, AuthorityError> {
        let mut config = config;
        config.listen = normalize_socket_addr(config.listen);
        config.validate()?;
        let (store, state) = AuthorityStateStore::open(&config)?;
        let listener = TcpListener::bind(config.listen).await.map_err(|error| {
            AuthorityError::new(format!("binding authority {}: {error}", config.listen))
        })?;
        Self::from_listener(config, store, state, listener)
    }

    fn from_listener(
        config: PublicationAuthorityConfig,
        store: AuthorityStateStore,
        state: AuthorityStateBody,
        listener: TcpListener,
    ) -> Result<Self, AuthorityError> {
        let local_addr = listener
            .local_addr()
            .map_err(|error| AuthorityError::new(format!("reading authority socket: {error}")))?;
        let inner = Arc::new(AuthorityInner {
            config,
            monotonic_expiry: Mutex::new(monotonic_expiry_deadlines(&state, unix_micros()?)),
            state: Mutex::new((store, state)),
            request_count: AtomicU64::new(0),
            #[cfg(test)]
            block_next_put: AtomicU64::new(0),
            #[cfg(test)]
            put_started: Notify::new(),
            #[cfg(test)]
            release_put: Notify::new(),
            #[cfg(test)]
            idempotent_puts: AtomicU64::new(0),
            #[cfg(test)]
            fail_next_get: AtomicU64::new(0),
        });
        let (stop, stop_rx) = watch::channel(false);
        let (health_tx, health) = watch::channel(AuthorityHealth::Running);
        let serving_inner = inner.clone();
        let join = tokio::spawn(async move {
            let result = run_authority(listener, serving_inner, stop_rx).await;
            health_tx.send_replace(match &result {
                Ok(()) => AuthorityHealth::Stopped,
                Err(error) => AuthorityHealth::Failed(error.clone()),
            });
            result
        });
        Ok(Self {
            local_addr,
            inner,
            stop,
            health,
            join: Some(join),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn request_count(&self) -> u64 {
        self.inner.request_count.load(Ordering::Acquire)
    }

    /// Wait until the serving task exits and always report that as unhealthy.
    /// A standalone authority selects this alongside process signals so an
    /// accept-loop or durable-state failure cannot leave a nominally live but
    /// non-serving process behind.
    pub async fn wait_for_failure(&self) -> AuthorityError {
        let mut health = self.health.clone();
        loop {
            let status = health.borrow_and_update().clone();
            match status {
                AuthorityHealth::Running => {}
                AuthorityHealth::Stopped => {
                    return AuthorityError::new("authority serving task stopped unexpectedly");
                }
                AuthorityHealth::Failed(error) => return error,
            }
            if health.changed().await.is_err() {
                return AuthorityError::new(
                    "authority serving-task health channel closed unexpectedly",
                );
            }
        }
    }

    #[cfg(test)]
    fn block_next_put(&self) {
        self.inner.block_next_put.store(1, Ordering::Release);
    }

    #[cfg(test)]
    async fn wait_until_put_blocked(&self) {
        self.inner.put_started.notified().await;
    }

    #[cfg(test)]
    fn release_blocked_put(&self) {
        self.inner.release_put.notify_one();
    }

    #[cfg(test)]
    fn idempotent_put_count(&self) -> u64 {
        self.inner.idempotent_puts.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn fail_next_visibility_get(&self) {
        self.inner.fail_next_get.store(1, Ordering::Release);
    }

    #[cfg(test)]
    fn packet_for_test(&self, signer: &str) -> Option<Vec<u8>> {
        let guarded = self.inner.state.lock().ok()?;
        let (_, state) = &*guarded;
        state
            .records
            .get(signer)
            .map(|entry| decode_hex(&entry.packet_hex).expect("test authority packet must decode"))
    }

    pub async fn shutdown(mut self) -> Result<(), AuthorityError> {
        let _ = self.stop.send(true);
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        join.await
            .map_err(|error| AuthorityError::new(format!("authority task join failed: {error}")))?
    }
}

impl Drop for PublicationAuthority {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

async fn run_authority(
    listener: TcpListener,
    inner: Arc<AuthorityInner>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), AuthorityError> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                match joined {
                    Some(Ok(Err(error))) => {
                        return Err(AuthorityError::new(format!(
                            "authority fatal request-state failure: {error}"
                        )));
                    }
                    Some(Err(error)) if !error.is_cancelled() => {
                        return Err(AuthorityError::new(format!("authority connection task failed: {error}")));
                    }
                    _ => {}
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|error| AuthorityError::new(format!("accepting authority connection: {error}")))?;
                if connections.len() >= MAX_ACTIVE_CONNECTIONS {
                    drop(stream);
                    continue;
                }
                let inner = inner.clone();
                connections.spawn(async move {
                    match tokio::time::timeout(
                        AUTHORITY_REQUEST_DEADLINE,
                        handle_connection(stream, inner),
                    ).await {
                        Err(_) => eprintln!("IROH-NODE-AUTHORITY-REQUEST-FAILED error=request deadline exceeded"),
                        Ok(Err(ConnectionError::Client(error))) => {
                            eprintln!("IROH-NODE-AUTHORITY-REQUEST-FAILED error={error}");
                        }
                        Ok(Err(ConnectionError::Fatal(error))) => return Err(error),
                        Ok(Ok(())) => {}
                    }
                    Ok(())
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn handle_connection(
    mut stream: TcpStream,
    inner: Arc<AuthorityInner>,
) -> Result<(), ConnectionError> {
    inner.request_count.fetch_add(1, Ordering::AcqRel);
    let request = read_request(&mut stream, &inner.config.expected_host)
        .await
        .map_err(ConnectionError::Client)?;
    #[cfg(test)]
    if request.method == "PUT" && inner.block_next_put.swap(0, Ordering::AcqRel) == 1 {
        inner.put_started.notify_one();
        inner.release_put.notified().await;
    }
    #[cfg(test)]
    if request.method == "GET" && inner.fail_next_get.swap(0, Ordering::AcqRel) == 1 {
        return write_response(
            &mut stream,
            response(503, "Service Unavailable", Vec::new()),
        )
        .await
        .map_err(ConnectionError::Client);
    }
    // Keep persistence ordered with the response. Detaching it would allow a
    // timed-out task to commit a live record after the caller returned.
    let response = apply_request(&inner, request).map_err(ConnectionError::Fatal)?;
    write_response(&mut stream, response)
        .await
        .map_err(ConnectionError::Client)
}

struct AuthorityRequest {
    method: String,
    signer: String,
    body: Vec<u8>,
}

#[derive(Debug)]
enum ConnectionError {
    /// Malformed input, timeout, or a peer disconnect. The listener is healthy.
    Client(AuthorityError),
    /// Clock/state/persistence failure. Continuing would claim false health.
    Fatal(AuthorityError),
}

#[derive(Debug)]
struct AuthorityResponse {
    status: u16,
    reason: &'static str,
    body: Vec<u8>,
}

async fn read_request(
    stream: &mut TcpStream,
    expected_host: &str,
) -> Result<AuthorityRequest, AuthorityError> {
    let mut received = Vec::with_capacity(2048);
    let header_end = loop {
        if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            if position + 4 > MAX_REQUEST_HEADER_BYTES {
                return Err(AuthorityError::new("request headers exceed 8192 bytes"));
            }
            break position;
        }
        if received.len() >= MAX_REQUEST_HEADER_BYTES {
            return Err(AuthorityError::new("request headers exceed 8192 bytes"));
        }
        let mut chunk = [0u8; 1024];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| AuthorityError::new(format!("reading request: {error}")))?;
        if read == 0 {
            return Err(AuthorityError::new("request ended before headers"));
        }
        received.extend_from_slice(&chunk[..read]);
    };
    let headers = std::str::from_utf8(&received[..header_end])
        .map_err(|_| AuthorityError::new("request headers are not UTF-8/ASCII"))?;
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| AuthorityError::new("request line is missing"))?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default();
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(AuthorityError::new(
            "request line is not canonical HTTP/1.1",
        ));
    }
    if !matches!(method.as_str(), "GET" | "PUT") {
        return Err(AuthorityError::new("authority supports only GET and PUT"));
    }
    let signer = path
        .strip_prefix(RECORD_PATH_PREFIX)
        .ok_or_else(|| AuthorityError::new("request path is outside node-record route"))?;
    let key = iroh::PublicKey::from_z32(signer)
        .map_err(|error| AuthorityError::new(format!("request path signer invalid: {error}")))?;
    if key.to_z32() != signer {
        return Err(AuthorityError::new("request path signer is not canonical"));
    }

    let mut host = None;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(AuthorityError::new("malformed request header"));
        };
        if name.eq_ignore_ascii_case("host") {
            if host.replace(value.trim().to_string()).is_some() {
                return Err(AuthorityError::new("duplicate Host header"));
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length
                .replace(value.trim().parse::<usize>().map_err(|error| {
                    AuthorityError::new(format!("invalid Content-Length: {error}"))
                })?)
                .is_some()
            {
                return Err(AuthorityError::new("duplicate Content-Length"));
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(AuthorityError::new("Transfer-Encoding is rejected"));
        }
    }
    let content_length = match (method.as_str(), content_length) {
        ("GET", None) => 0,
        (_, Some(length)) => length,
        ("PUT", None) => return Err(AuthorityError::new("PUT Content-Length missing")),
        _ => unreachable!("method validated above"),
    };
    if host.as_deref() != Some(expected_host) {
        return Err(AuthorityError::new(
            "Host header does not match configured authority",
        ));
    }
    if content_length > MAX_RELAY_PAYLOAD_BYTES {
        return Err(AuthorityError::new(
            "request body exceeds signed-packet bound",
        ));
    }
    let expected_body = if method == "GET" { 0 } else { content_length };
    if content_length != expected_body {
        return Err(AuthorityError::new("GET must have zero Content-Length"));
    }
    let mut body = received[(header_end + 4)..].to_vec();
    if body.len() > content_length {
        return Err(AuthorityError::new("request bytes exceed Content-Length"));
    }
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let mut chunk = [0u8; 1024];
        let length = remaining.min(chunk.len());
        let read = stream
            .read(&mut chunk[..length])
            .await
            .map_err(|error| AuthorityError::new(format!("reading request body: {error}")))?;
        if read == 0 {
            return Err(AuthorityError::new(
                "request body ended before Content-Length",
            ));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(AuthorityRequest {
        method,
        signer: signer.to_string(),
        body,
    })
}

fn apply_request(
    inner: &AuthorityInner,
    request: AuthorityRequest,
) -> Result<AuthorityResponse, AuthorityError> {
    apply_request_at(inner, request, unix_micros()?)
}

fn apply_request_at(
    inner: &AuthorityInner,
    request: AuthorityRequest,
    now: u64,
) -> Result<AuthorityResponse, AuthorityError> {
    if !inner.config.signer_admission.admits(&request.signer) {
        return Ok(if request.method == "GET" {
            response(404, "Not Found", Vec::new())
        } else {
            response(403, "Forbidden", Vec::new())
        });
    }
    let mut guarded = inner
        .state
        .lock()
        .map_err(|_| AuthorityError::new("authority state mutex poisoned"))?;
    let (store, state) = &mut *guarded;
    store.ensure_healthy()?;
    if state.wall_clock_high_water_unix_micros != 0
        && now.saturating_add(CLOCK_HIGH_WATER_GRANULARITY_MICROS)
            < state.wall_clock_high_water_unix_micros
    {
        return Err(AuthorityError::new(format!(
            "authority wall clock regressed from durable high-water {} to {now}; request failed closed",
            state.wall_clock_high_water_unix_micros
        )));
    }
    let clock_advance_due = now.saturating_sub(state.wall_clock_high_water_unix_micros)
        >= CLOCK_HIGH_WATER_GRANULARITY_MICROS;
    if request.method == "GET" {
        let Some(entry) = state.records.get(&request.signer) else {
            return Ok(response(404, "Not Found", Vec::new()));
        };
        let entry_expired = entry.expired;
        let entry_expiry = entry.expires_unix_micros;
        let packet_hex = entry.packet_hex.clone();
        let monotonic_expired = inner
            .monotonic_expiry
            .lock()
            .map_err(|_| AuthorityError::new("authority monotonic-expiry mutex poisoned"))?
            .get(&request.signer)
            .is_some_and(|deadline| *deadline <= std::time::Instant::now());
        if entry_expired {
            return Ok(response(404, "Not Found", Vec::new()));
        }
        if entry_expiry <= now || monotonic_expired {
            let mut candidate = state.clone();
            candidate.wall_clock_high_water_unix_micros =
                candidate.wall_clock_high_water_unix_micros.max(now);
            candidate
                .records
                .get_mut(&request.signer)
                .expect("entry was checked")
                .expired = true;
            store.write(&candidate)?;
            *state = candidate;
            inner
                .monotonic_expiry
                .lock()
                .map_err(|_| AuthorityError::new("authority monotonic-expiry mutex poisoned"))?
                .remove(&request.signer);
            return Ok(response(404, "Not Found", Vec::new()));
        }
        if clock_advance_due {
            let mut candidate = state.clone();
            candidate.wall_clock_high_water_unix_micros = now;
            store.write(&candidate)?;
            *state = candidate;
        }
        let packet = SignedPacket::from_bytes(&decode_hex(&packet_hex)?).map_err(|error| {
            AuthorityError::new(format!("stored response packet invalid: {error}"))
        })?;
        return Ok(response(200, "OK", packet.to_relay_payload()));
    }

    let signer_key = match iroh::PublicKey::from_z32(&request.signer) {
        Ok(key) => key,
        Err(_) => return Ok(response(422, "Unprocessable Entity", Vec::new())),
    };
    let signed = match SignedPacket::from_relay_payload(&signer_key, &request.body) {
        Ok(packet) => packet,
        Err(_) => return Ok(response(422, "Unprocessable Entity", Vec::new())),
    };
    if signed.public_key().to_z32() != request.signer {
        return Ok(response(422, "Unprocessable Entity", Vec::new()));
    }
    let record = match decode_node_record(signed.as_bytes()) {
        Ok(record) => record,
        Err(_) => return Ok(response(422, "Unprocessable Entity", Vec::new())),
    };
    if record.namespace != inner.config.namespace
        || record.recipient != inner.config.signed_recipient
    {
        return Ok(response(422, "Unprocessable Entity", Vec::new()));
    }
    let max_expiry = now
        .checked_add(record.ttl_seconds as u64 * 1_000_000)
        .and_then(|value| value.checked_add(EXPIRY_CLOCK_GRACE.as_micros() as u64))
        .ok_or_else(|| AuthorityError::new("record expiry bound overflow"))?;
    if record.expires_unix_micros <= now || record.expires_unix_micros > max_expiry {
        return Ok(response(422, "Unprocessable Entity", Vec::new()));
    }
    if let Some(existing) = state.records.get(&request.signer) {
        if existing.expired && record.sequence <= existing.high_water_sequence {
            return Ok(response(409, "Conflict", Vec::new()));
        }
        if record.sequence < existing.high_water_sequence {
            return Ok(response(409, "Conflict", Vec::new()));
        }
        if record.sequence == existing.high_water_sequence {
            if existing.packet_hex == encode_hex(signed.as_bytes()) {
                #[cfg(test)]
                inner.idempotent_puts.fetch_add(1, Ordering::AcqRel);
                return Ok(response(200, "OK", Vec::new()));
            }
            return Ok(response(409, "Conflict", Vec::new()));
        }
    }
    let mut candidate = state.clone();
    candidate.wall_clock_high_water_unix_micros =
        candidate.wall_clock_high_water_unix_micros.max(now);
    candidate.records.insert(
        request.signer,
        AuthorityEntry {
            high_water_sequence: record.sequence,
            expires_unix_micros: record.expires_unix_micros,
            state: match record.state {
                PublicationState::Live => AuthorityRecordState::Live,
                PublicationState::Withdrawn => AuthorityRecordState::Withdrawn,
            },
            expired: false,
            packet_hex: encode_hex(signed.as_bytes()),
        },
    );
    store.write(&candidate)?;
    *state = candidate;
    let remaining = record.expires_unix_micros.saturating_sub(now);
    let deadline = std::time::Instant::now()
        .checked_add(Duration::from_micros(remaining))
        .ok_or_else(|| AuthorityError::new("authority monotonic expiry deadline overflow"))?;
    inner
        .monotonic_expiry
        .lock()
        .map_err(|_| AuthorityError::new("authority monotonic-expiry mutex poisoned"))?
        .insert(signed.public_key().to_z32(), deadline);
    Ok(response(201, "Created", Vec::new()))
}

fn monotonic_expiry_deadlines(
    state: &AuthorityStateBody,
    now_unix_micros: u64,
) -> BTreeMap<String, std::time::Instant> {
    let now = std::time::Instant::now();
    state
        .records
        .iter()
        .filter(|(_, entry)| !entry.expired)
        .filter_map(|(signer, entry)| {
            now.checked_add(Duration::from_micros(
                entry.expires_unix_micros.saturating_sub(now_unix_micros),
            ))
            .map(|deadline| (signer.clone(), deadline))
        })
        .collect()
}

fn response(status: u16, reason: &'static str, body: Vec<u8>) -> AuthorityResponse {
    AuthorityResponse {
        status,
        reason,
        body,
    }
}

async fn write_response(
    stream: &mut TcpStream,
    response: AuthorityResponse,
) -> Result<(), AuthorityError> {
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/x-pkarr-signed-packet\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.reason,
        response.body.len()
    );
    stream
        .write_all(headers.as_bytes())
        .await
        .map_err(|error| AuthorityError::new(format!("writing authority response: {error}")))?;
    stream
        .write_all(&response.body)
        .await
        .map_err(|error| AuthorityError::new(format!("writing authority body: {error}")))?;
    stream
        .shutdown()
        .await
        .map_err(|error| AuthorityError::new(format!("closing authority response: {error}")))
}

fn unix_micros() -> Result<u64, AuthorityError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AuthorityError::new(format!("system clock precedes epoch: {error}")))?
        .as_micros()
        .try_into()
        .map_err(|_| AuthorityError::new("system clock microseconds exceed u64"))
}

fn authority_io(state_dir: &Path, operation: &str, error: Errno) -> AuthorityError {
    AuthorityError::new(format!("{operation} in {}: {error}", state_dir.display()))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, AuthorityError> {
    if !raw.len().is_multiple_of(2) || raw.len() > SignedPacket::MAX_BYTES * 2 {
        return Err(AuthorityError::new("authority packet hex length invalid"));
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

fn hex_nibble(byte: u8) -> Result<u8, AuthorityError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(AuthorityError::new(
            "authority packet hex is not lowercase hex",
        )),
    }
}

#[cfg(test)]
#[path = "iroh_publication_authority_tests.rs"]
mod tests;
