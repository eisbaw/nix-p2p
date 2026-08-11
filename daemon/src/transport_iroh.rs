//! The REAL iroh whole-NAR [`Transport`] (task-39): the FIRST peer-to-peer byte
//! transfer in the project. It fills the task-38 [`Transport`] trait for the
//! [`TransportTag::Iroh`] tag, replacing the in-memory `FakeTransport` with two
//! genuine iroh endpoints exchanging bytes over a real QUIC connection.
//!
//! ## Provider + client
//!
//!   * [`IrohProvider`] (node B) runs an iroh-blobs PROVIDER: it adds a node's raw
//!     NARs to an in-memory iroh-blobs store addressed by `BLAKE3(RawNarV1)` and
//!     serves them under the stock iroh-blobs ALPN via an [`iroh::protocol::Router`].
//!     ([`IrohProvider::seed`] models the content-addressed "put"; the real
//!     seeding index that enumerates a node's held NARs is task-50.)
//!   * [`IrohTransport`] (node A) is the [`Transport`] impl: given a
//!     [`Blake3Digest`] and a peer [`NodeId`] (from a claim's `Iroh` offer), it
//!     dials the peer and fetches the blob by that exact digest. iroh-blobs' `bao`
//!     streaming decode verifies BLAKE3 incrementally against the requested hash
//!     (gate 1) as bytes arrive, so a holder that cannot honestly serve the digest
//!     yields an error, never wrong bytes.
//!
//! ## Why our [`Blake3Digest`] IS the iroh blob hash
//!
//! The task-48 freeze pinned the addressed unit to PLAIN, UNKEYED `BLAKE3(RawNarV1)`
//! with no domain separation precisely because that equals the iroh-blobs blob
//! hash of the same bytes (`content_id.rs`). So we convert a [`Blake3Digest`] to an
//! [`iroh_blobs::Hash`] by its raw 32 bytes and fetch by it directly - no
//! re-hashing, no second identity.
//!
//! ## The TWO gates (kept distinct)
//!
//! Gate 1 (transport BLAKE3/bao) is owned here and re-asserted with the daemon's
//! own [`verify_blake3`] single-source-of-truth recipe before any bytes are
//! returned. Gate 2 (`sha256 == NarHash`, Nix's signed trust anchor) is downstream
//! and NOT re-implemented here - the daemon is outside the TCB (see
//! `transport_fetch` module docs).
//!
//! ## Relay / discovery (honest scope)
//!
//! [`IrohNodeBuilder`] owns the single endpoint/router lifecycle for provider and
//! fetch capabilities. Tests use its closed `offline-test` scope: explicit IPv4
//! and IPv6 loopback binds, no relay, no address lookup, no port mapper, and
//! minimal network reporting. The daemon requires an explicit persistent identity
//! directory and endpoint scope instead of inheriting preset defaults. A discovery
//! layer resolves a `NodeId` to an address; until that layer is wired,
//! [`IrohTransport::add_peer`] is the explicit in-memory address book used by the
//! harness. Relay policy remains an injected capability, never an implicit n0
//! service dependency. A coarse dial/fetch timeout ([`FETCH_TIMEOUT`]) guards
//! against an unbounded hang; the signed NarSize streaming bound lives in the
//! safety envelope.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bao_tree::io::BaoContentItem;
use iroh::endpoint::{Accepting, Connection};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{EndpointAddr, PublicKey};
use iroh_blobs::api::TempTag;
use iroh_blobs::api::blobs::BlobStatus;
use iroh_blobs::get::request::{GetBlobItem, get_blob};
use iroh_blobs::provider::events::{
    AbortReason, EventMask, EventSender, ProviderMessage, RequestMode, RequestUpdate,
};
use iroh_blobs::store::mem::{MemStore, Options as MemStoreOptions};
use iroh_blobs::store::{GcConfig, ProtectCb, ProtectOutcome};
use iroh_blobs::{BlobsProtocol, Hash};
use n0_future::StreamExt;
use tokio::sync::watch;

use crate::claim::KnownTransport;
use crate::content_id::Blake3Digest;
use crate::iroh_publication::{NodePublicationCapability, NodePublicationHandle};
use crate::iroh_runtime::{
    AddressLookupCapability, DAEMON_TEST_ENDPOINT_PROFILE, EndpointCapabilityState,
    EndpointProfile, IdentitySource, IrohEndpointHandle, IrohNodeRuntime, IrohRuntimeBuilder,
    IrohRuntimeError, RelayCapability, ShutdownOutcome, TaskSupervisorHandle,
};
use crate::supply_catalog::{NarProductionSource, SupplyCatalogHandle};
use crate::transport::{IROH_BLOBS_ALPN, NodeId};
use crate::transport_fetch::{Transport, TransportError, TransportTag, verify_blake3};

// -------------------------------------------------------------------------
// AC#4: the ALPN cross-check, as a COMPILE-TIME assertion.
// -------------------------------------------------------------------------

/// Const byte-slice equality (the stdlib `==` on `&[u8]` is not const), so the
/// assertion below fails at COMPILE time rather than only in a test.
const fn alpn_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The task-48 freeze pinned [`IROH_BLOBS_ALPN`] WITHOUT an iroh dependency in
/// tree and explicitly deferred the cross-check to task-39. Now that iroh IS a
/// dependency, a divergence between our frozen constant and the real
/// `iroh_blobs::ALPN` must fail LOUD - and the loudest possible failure is the
/// build itself. (codex confirmed `/iroh-bytes/4` is current; this ASSERTS it.)
const _: () = assert!(
    alpn_bytes_eq(IROH_BLOBS_ALPN, iroh_blobs::ALPN),
    "frozen IROH_BLOBS_ALPN diverged from iroh_blobs::ALPN - realign the constant \
     in transport.rs to the pinned iroh version",
);

/// The real iroh-blobs ALPN, exposed so a test can cross-check the frozen constant
/// without depending on the `iroh_blobs` crate itself.
pub fn iroh_blobs_alpn() -> &'static [u8] {
    iroh_blobs::ALPN
}

// -------------------------------------------------------------------------
// The conservative safety envelope (task-51). PROVISIONAL DEFAULTS.
// -------------------------------------------------------------------------
//
// These three time bounds plus the streaming NarSize cap are the FLOOR task-43
// asserts (never unbounded-hang, never OOM), NOT a tuned policy. task-44 MODELS
// the real slow-HIT policy (hedge / delayed-race / adaptive) and a later task
// implements the winner; do NOT read these numbers as the answer. The slow-HIT
// DEFAULT here is the simplest safe thing: a bounded abort -> fall back to
// upstream. The values are deliberately generous (a healthy LAN peer finishes far
// inside them) and conservative (a dead/stalled/lying peer is cut off well before
// it can hang a build or exhaust memory).

/// DIAL bound: how long `endpoint.connect()` may take before a holder is declared
/// dead/unreachable. A `NodeId` that never answers the QUIC handshake is cut off
/// here -> bounded failure -> the driver tries the next offer or falls back to
/// upstream, never a hang. (task-40's `PROBE_TIMEOUT` bounded DISCOVERY; this
/// bounds the FETCH dial.) PROVISIONAL.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// BODY-IDLE bound: the maximum gap between successive bytes once the transfer has
/// started. A peer that connects then STALLS mid-stream (no progress for this long)
/// is aborted. This is the real slow-peer guard - distinct from a total-time cap: a
/// slow-but-PROGRESSING peer keeps resetting this idle clock and is tolerated,
/// while a STALLED one trips it fast. PROVISIONAL.
pub const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// TOTAL bound: a coarse backstop over the whole dial+transfer, so a peer that
/// stays just under the idle bound forever (dribbling one chunk per idle-epsilon)
/// still cannot run unbounded. The idle bound is the precise guard; this is the
/// belt-and-suspenders ceiling. PROVISIONAL. (Kept as `FETCH_TIMEOUT`, the name
/// task-39 exported, now widened to sit above dial+idle.)
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(60);

/// The three time bounds of the safety envelope, injectable so a test can pin
/// SHORT bounds and prove a dead/stalled peer yields a bounded abort (mirrors
/// [`crate::discovery::DirectDiscovery::with_timeout`]). [`Default`] is the
/// PROVISIONAL production envelope above.
#[derive(Debug, Clone, Copy)]
pub struct SafetyEnvelope {
    /// Bound on `connect()` (the dead-holder guard).
    pub dial_timeout: Duration,
    /// Bound on the gap between successive body chunks (the stall guard).
    pub body_idle_timeout: Duration,
    /// Coarse backstop over the whole dial+transfer.
    pub total_timeout: Duration,
}

impl Default for SafetyEnvelope {
    fn default() -> Self {
        Self {
            dial_timeout: DIAL_TIMEOUT,
            body_idle_timeout: BODY_IDLE_TIMEOUT,
            total_timeout: FETCH_TIMEOUT,
        }
    }
}

// -------------------------------------------------------------------------
// Errors.
// -------------------------------------------------------------------------

/// Why an iroh provider/transport operation failed. Kept separate from
/// [`TransportError`] (the trait's per-offer failure) so setup failures
/// (bind/seed) are distinguishable from a fetch that should just try the next
/// offer; [`IrohTransport::fetch`] maps the fetch-path ones into [`TransportError`].
#[derive(Debug)]
pub enum IrohError {
    /// Binding the iroh endpoint failed (socket/config).
    Bind(String),
    /// Adding bytes to the provider's blob store failed.
    Seed(String),
    /// A `NodeId`'s 32 bytes are not a valid ed25519 curve point (AC#4's
    /// deferred-from-task-48 validity check).
    InvalidNodeId(String),
    /// No socket address is bound yet, so no dialable address can be published.
    NoBoundAddress,
    /// The blob store could not be asked what it currently holds. RAISED, never
    /// reported as "holds nothing": a residency oracle that answers 0 when it
    /// could not look would pass every future eviction change (task-65).
    StoreQuery(String),
    /// The shared node runtime rejected configuration, identity state, endpoint
    /// access or shutdown.
    Runtime(String),
}

impl fmt::Display for IrohError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrohError::Bind(why) => write!(f, "iroh endpoint bind failed: {why}"),
            IrohError::Seed(why) => write!(f, "iroh-blobs seed failed: {why}"),
            IrohError::InvalidNodeId(why) => write!(f, "invalid iroh node id: {why}"),
            IrohError::NoBoundAddress => f.write_str("iroh endpoint has no bound address yet"),
            IrohError::StoreQuery(why) => write!(f, "iroh-blobs store query failed: {why}"),
            IrohError::Runtime(why) => write!(f, "Iroh node runtime failed: {why}"),
        }
    }
}

impl std::error::Error for IrohError {}

impl From<IrohRuntimeError> for IrohError {
    fn from(error: IrohRuntimeError) -> Self {
        Self::Runtime(error.to_string())
    }
}

// -------------------------------------------------------------------------
// A peer's dialable address (opaque wrapper so callers/tests never touch iroh).
// -------------------------------------------------------------------------

/// A peer's dialable iroh address: its [`NodeId`] plus concrete direct socket
/// addresses. Opaque on purpose - it wraps an [`EndpointAddr`] so tests and future
/// discovery code hand it around without depending on the `iroh` crate. In wave-2
/// this is what a discovery layer (task-40) resolves a `NodeId` to.
#[derive(Clone)]
pub struct IrohPeerAddr(EndpointAddr);

impl IrohPeerAddr {
    /// Build a dialable address from a peer's [`NodeId`] and its direct socket
    /// addresses. This is the resolution a discovery layer (task-40/47) produces -
    /// "here is the node and where to reach it" - made constructible without the
    /// `iroh` crate. (task-51's dead-holder bite also uses it to point a valid
    /// `NodeId` at a black-hole socket.)
    pub fn new(node: NodeId, sockets: impl IntoIterator<Item = SocketAddr>) -> Self {
        // A NodeId is 32 bytes; PublicKey::from_bytes only fails off-curve, which
        // Transport::fetch rejects via validate_node_id before dialing. Build the
        // EndpointAddr from whatever key bytes we were given; an off-curve id simply
        // never gets past validation to a dial.
        let key = PublicKey::from_bytes(node.as_bytes())
            .unwrap_or_else(|_| PublicKey::from_bytes(&[0u8; 32]).expect("zero key is on-curve"));
        let mut addr = EndpointAddr::new(key);
        for socket in sockets {
            addr = addr.with_ip_addr(socket);
        }
        IrohPeerAddr(addr)
    }

    /// The peer's node identity (our canonical [`NodeId`] type).
    pub fn node_id(&self) -> NodeId {
        NodeId::from_bytes(*self.0.id.as_bytes())
    }
}

// -------------------------------------------------------------------------
// The SUPPLY seam (task-61's decision) and the SERVE BUDGET (task-72).
// -------------------------------------------------------------------------
//
// TASK-61 decided the supply model: REGENERATE ON DEMAND, hold nothing at rest.
// The numbers that forced it are in PRD.md ("Supply model"): the owner's real
// store is 108,401 paths / 155,621 MiB of NAR, which at task-65's measured
// holder cost of 2.0033 bytes of RSS per byte of NAR would be ~304 GiB of RAM to
// hold, and whose p100 path is 3186 MiB - about 6.2 GiB of RAM for ONE serve
// (model output, extrapolated past the fitted 8..128 MiB grid).
//
// Two consequences, and they are the whole of this section:
//
//   1. ANNOUNCING MUST NOT COST HOLDING. A node names what it can serve by
//      digest; the digest is derived from the bytes with
//      `Blake3Digest::stream_raw_nar` in 64 KiB slices and the bytes are then
//      dropped. What survives is a [`NarSupplier`] binding: "this digest, that
//      source".
//   2. IN-FLIGHT MEMORY IS NOW THE ENTIRE MEMORY COST, so it is the thing that
//      must be BOUNDED. The daemon is outside the trust base: any peer may ask
//      for the largest NAR we announce, so "serve whatever is asked" is a
//      remote-triggerable OOM (an AVAILABILITY defect - Nix still re-verifies
//      sig + NarHash, so never wrong bytes). [`ServeBudget`] is the bound and
//      [`IrohProvider`] enforces it BEFORE allocating anything.

/// Why an on-demand supply of a raw NAR failed. A string, not an enum: the
/// failure is whatever the underlying source said (a missing file, a
/// `nix-store --dump` that exited nonzero), and flattening those into categories
/// would lose the only useful part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupplyError(pub String);

impl fmt::Display for SupplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "on-demand NAR supply failed: {}", self.0)
    }
}

impl std::error::Error for SupplyError {}

/// Where a node REGENERATES a raw NAR from when a peer asks for it (the task-61
/// supply model). The implementation for a real node dumps the store path; the
/// one here reads back the exact raw NAR file the node announced.
///
/// The closed plan separates admission metadata from production. Planning must
/// answer "how big is this, and do we even have it?" without producing bytes;
/// its process or memory source is consumed only after admission agrees to pay.
///
/// NO ENUMERATION (PRD privacy invariant, owner constraint from phase 1). Both
/// methods are per-digest probes. There is deliberately no `list`, no `iter` and
/// no `len`: a peer may learn yes/no about a digest it can already name, never
/// what a node holds.
mod nar_supplier_sealed {
    use super::{Blake3Digest, SupplyError, SupplyPlan};

    pub trait Sealed {
        fn plan(&self, content: &Blake3Digest) -> Result<Option<SupplyPlan>, SupplyError>;
    }
}

/// Closed, cancellation-aware NAR supply boundary.
///
/// Downstream code can hold this trait but cannot implement it. That is a
/// shutdown property, not API taste: accepting an arbitrary synchronous
/// implementation would admit an unkillable `spawn_blocking` worker that an
/// absolute async shutdown deadline cannot stop.
pub trait NarSupplier: nar_supplier_sealed::Sealed + Send + Sync {}

/// A closed, inert supply description. It is produced synchronously without IO
/// and consumed only after the serve budget reserves `declared_size`.
#[doc(hidden)]
#[derive(Clone)]
pub struct SupplyPlan {
    declared_size: u64,
    source: SupplySource,
}

#[derive(Clone)]
enum SupplySource {
    Process {
        program: PathBuf,
        args: Vec<OsString>,
        environment: Vec<(OsString, OsString)>,
    },
    Memory {
        bytes: Arc<Vec<u8>>,
        released: Option<Arc<AtomicBool>>,
        metrics: Arc<MemorySupplierMetrics>,
    },
}

#[derive(Default)]
struct MemorySupplierMetrics {
    supplied: AtomicUsize,
    active_operations: AtomicUsize,
    activity_ticks: AtomicUsize,
    cancelled_operations: AtomicUsize,
}

/// Closed in-memory supplier used by behavioral tests.
///
/// Its delay seam is cancellation-aware and its copy proceeds in chunks, so it
/// can model a never-released materialisation without creating an arbitrary or
/// detached worker implementation.
pub struct MemoryNarSupplier {
    nars: HashMap<Blake3Digest, Arc<Vec<u8>>>,
    declared_size_overrides: HashMap<Blake3Digest, u64>,
    blocked: HashMap<Blake3Digest, Arc<AtomicBool>>,
    metrics: Arc<MemorySupplierMetrics>,
}

impl MemoryNarSupplier {
    pub fn new(nars: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            nars: nars
                .into_iter()
                .map(|nar| (Blake3Digest::from_raw_nar(&nar), Arc::new(nar)))
                .collect(),
            declared_size_overrides: HashMap::new(),
            blocked: HashMap::new(),
            metrics: Arc::new(MemorySupplierMetrics::default()),
        }
    }

    pub fn set_declared_size(&mut self, content: Blake3Digest, bytes: u64) {
        self.declared_size_overrides.insert(content, bytes);
    }

    pub fn block_until(&mut self, content: Blake3Digest, released: Arc<AtomicBool>) {
        self.blocked.insert(content, released);
    }

    pub fn supplied(&self) -> usize {
        self.metrics.supplied.load(Ordering::Acquire)
    }

    pub fn active_operations(&self) -> usize {
        self.metrics.active_operations.load(Ordering::Acquire)
    }

    pub fn activity_ticks(&self) -> usize {
        self.metrics.activity_ticks.load(Ordering::Acquire)
    }

    pub fn cancelled_operations(&self) -> usize {
        self.metrics.cancelled_operations.load(Ordering::Acquire)
    }
}

impl nar_supplier_sealed::Sealed for MemoryNarSupplier {
    fn plan(&self, content: &Blake3Digest) -> Result<Option<SupplyPlan>, SupplyError> {
        let Some(bytes) = self.nars.get(content) else {
            return Ok(None);
        };
        Ok(Some(SupplyPlan {
            declared_size: self
                .declared_size_overrides
                .get(content)
                .copied()
                .unwrap_or(bytes.len() as u64),
            source: SupplySource::Memory {
                bytes: Arc::clone(bytes),
                released: self.blocked.get(content).cloned(),
                metrics: Arc::clone(&self.metrics),
            },
        }))
    }
}

impl NarSupplier for MemoryNarSupplier {}

/// A [`NarSupplier`] backed by raw-NAR FILES on disk: the shape the wave-2a
/// harness and the `--iroh-seed-nar` flag speak. A real node's supplier dumps
/// `/nix/store` instead (task-50's `CommandNarDumper` is that producer); the seam
/// is the same either way, which is the point of having it.
///
/// [`Self::announce`] is what replaced the eager startup seed: it stream-hashes
/// the file in bounded memory and records the binding. Peak allocation is one
/// 64 KiB chunk, whatever the NAR's size - so a node can announce a 3 GiB path
/// without ever holding 3 GiB.
pub struct FileNarSupplier {
    /// `BLAKE3(RawNarV1) -> the file holding exactly those bytes`. Behind a
    /// `Mutex` because announcing happens on the startup path while serving reads
    /// it from the provider's tasks.
    by_digest: Mutex<HashMap<Blake3Digest, FileNarRecord>>,
    helper_program: PathBuf,
}

#[derive(Clone)]
struct FileNarRecord {
    path: PathBuf,
    size: u64,
}

fn open_regular_raw_nar(path: &Path) -> Result<(File, u64), SupplyError> {
    use rustix::fs::{FileType, Mode, OFlags};

    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| SupplyError(format!("opening raw NAR {}: {error}", path.display())))?;
    let stat = rustix::fs::fstat(&fd)
        .map_err(|error| SupplyError(format!("inspecting raw NAR {}: {error}", path.display())))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(SupplyError(format!(
            "raw NAR {} is not a regular file",
            path.display()
        )));
    }
    let size = u64::try_from(stat.st_size).map_err(|_| {
        SupplyError(format!(
            "raw NAR {} reported a negative size",
            path.display()
        ))
    })?;
    Ok((File::from(fd), size))
}

impl FileNarSupplier {
    /// An empty supplier: it can supply nothing until something is announced.
    pub fn new(helper_program: impl Into<PathBuf>) -> Self {
        FileNarSupplier {
            by_digest: Mutex::new(HashMap::new()),
            helper_program: helper_program.into(),
        }
    }

    /// Read `path` ONCE in bounded memory to learn what it is, record the
    /// binding, and return `(digest, nar_size)` so the caller can publish a
    /// claim. The file is NOT retained in memory and NOT copied.
    ///
    /// Fails fast and loudly: an unreadable seed file is a configuration error
    /// that must stop startup, not a node that silently announces nothing.
    pub fn announce(&self, path: impl Into<PathBuf>) -> Result<(Blake3Digest, u64), SupplyError> {
        let path = path.into();
        let (file, _) = open_regular_raw_nar(&path)?;
        let (digest, nar_size) = Blake3Digest::stream_raw_nar(std::io::BufReader::new(file))
            .map_err(|e| SupplyError(format!("hashing raw NAR {}: {e}", path.display())))?;
        self.by_digest.lock().expect("supplier mutex").insert(
            digest,
            FileNarRecord {
                path,
                size: nar_size,
            },
        );
        Ok((digest, nar_size))
    }
}

impl nar_supplier_sealed::Sealed for FileNarSupplier {
    fn plan(&self, content: &Blake3Digest) -> Result<Option<SupplyPlan>, SupplyError> {
        let Some(record) = self
            .by_digest
            .lock()
            .expect("supplier mutex")
            .get(content)
            .cloned()
        else {
            return Ok(None);
        };
        Ok(Some(SupplyPlan {
            declared_size: record.size,
            source: SupplySource::Process {
                program: self.helper_program.clone(),
                args: vec![
                    OsString::from("__dump-raw-nar"),
                    record.path.as_os_str().to_owned(),
                ],
                environment: raw_nar_helper_environment(),
            },
        }))
    }
}

impl NarSupplier for FileNarSupplier {}

const RAW_NAR_HELPER_ENV: &str = "DAEMON_INTERNAL_RAW_NAR_HELPER";
const RAW_NAR_HELPER_VALUE: &str = "v1";

fn raw_nar_helper_environment() -> Vec<(OsString, OsString)> {
    vec![(
        OsString::from(RAW_NAR_HELPER_ENV),
        OsString::from(RAW_NAR_HELPER_VALUE),
    )]
}

#[doc(hidden)]
pub fn raw_nar_helper_authorized() -> bool {
    std::env::var_os(RAW_NAR_HELPER_ENV).as_deref()
        == Some(std::ffi::OsStr::new(RAW_NAR_HELPER_VALUE))
}

/// Copy one raw-NAR regular file to a writer for the hidden helper process.
///
/// Linux can leave a task uninterruptible in kernel IO (D-state) on a broken
/// FUSE/NFS mount; no userspace shutdown contract can defeat that. Running this
/// operation in an owned process group still closes every ordinary userspace
/// callback/thread escape: shutdown kills and reaps the helper and descendants.
#[doc(hidden)]
pub fn copy_regular_raw_nar(
    path: impl AsRef<Path>,
    mut output: impl Write,
) -> Result<u64, SupplyError> {
    let path = path.as_ref();
    let (mut file, expected_size) = open_regular_raw_nar(path)?;
    let mut copied = 0u64;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|error| SupplyError(format!("reading raw NAR {}: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        output.write_all(&chunk[..read]).map_err(|error| {
            SupplyError(format!(
                "writing raw NAR {} to stdout: {error}",
                path.display()
            ))
        })?;
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| SupplyError(format!("raw NAR {} exceeded u64 bytes", path.display())))?;
    }
    if copied != expected_size {
        return Err(SupplyError(format!(
            "raw NAR {} changed while reading: stat said {expected_size} B, read {copied} B",
            path.display()
        )));
    }
    Ok(copied)
}

/// The [`NarSupplier`] a real node uses: an inert read-only supply catalog.
///
/// THIS IS THE FIX FOR TASK-72 GAP 2, and the direction of the dependency is the
/// point. The transport consumes the index; the index knows nothing about
/// transports (its module docs are explicit that seeding is external), so adding a
/// supply path did not turn the index into a transport-aware module. What it did
/// was make one set out of two: the index answers "yes, I hold NarHash k" only for
/// registrations it can also produce bytes for, and this adapter is how the
/// provider reaches those bytes.
pub struct IndexNarSupplier {
    catalog: SupplyCatalogHandle,
    helper_program: PathBuf,
}

impl IndexNarSupplier {
    /// Serve only records already published by the availability writer. The
    /// provider cannot derive, persist, announce, or lock the index itself.
    pub fn new(catalog: SupplyCatalogHandle, helper_program: impl Into<PathBuf>) -> Self {
        IndexNarSupplier {
            catalog,
            helper_program: helper_program.into(),
        }
    }
}

impl nar_supplier_sealed::Sealed for IndexNarSupplier {
    fn plan(&self, content: &Blake3Digest) -> Result<Option<SupplyPlan>, SupplyError> {
        let Some(record) = self.catalog.probe(content) else {
            return Ok(None);
        };
        let source = match record.source {
            NarProductionSource::Process { program, args } => SupplySource::Process {
                program,
                args,
                environment: Vec::new(),
            },
            NarProductionSource::RegularFile(path) => SupplySource::Process {
                program: self.helper_program.clone(),
                args: vec![OsString::from("__dump-raw-nar"), path.into_os_string()],
                environment: raw_nar_helper_environment(),
            },
            NarProductionSource::Memory(bytes) => SupplySource::Memory {
                bytes,
                released: None,
                metrics: Arc::new(MemorySupplierMetrics::default()),
            },
        };
        Ok(Some(SupplyPlan {
            declared_size: record.declared_size,
            source,
        }))
    }
}

impl NarSupplier for IndexNarSupplier {}

/// Largest single NAR the node agrees to serve, in NarSize bytes. PROVISIONAL,
/// like the [`SafetyEnvelope`] time bounds, and chosen against the owner's
/// measured store rather than by feel: p99 there is 10.92 MiB and p100 is
/// 3186.03 MiB, so 256 MiB serves essentially every real path while declining the
/// handful whose serve would cost gigabytes of RAM.
pub const DEFAULT_MAX_SERVE_NAR_BYTES: u64 = 256 * 1024 * 1024;

/// Largest TOTAL of concurrently-admitted NARs, in NarSize bytes. PROVISIONAL.
/// Four maximum-size serves at once; beyond that a peer is declined rather than
/// queued, because queueing a request whose memory we cannot afford only moves
/// the OOM later.
pub const DEFAULT_MAX_INFLIGHT_NAR_BYTES: u64 = 1024 * 1024 * 1024;

/// How long one admitted serve may hold its slice of the budget. PROVISIONAL, and
/// the least satisfying number in this module - the reasoning is written out
/// because the trade-off is real and unresolved.
///
/// This is a BUDGET bound, not a transfer bound. The in-flight total is a shared
/// resource, and the [`SafetyEnvelope`] bounds a stalled HOLDER on the FETCH side
/// while nothing bounded a stalled READER on the SERVE side.
///
/// MEASURED, not assumed: when a peer simply vanishes mid-serve, the provider's
/// update stream does NOT end promptly. The connection stays live from our side
/// until QUIC's own idle timeout, so an abandoned request holds its reservation
/// until either that timeout or this deadline - whichever comes first - and there
/// is no signal at our layer that distinguishes an abandoned peer from a slow one.
/// (Reproduced in `a_peer_that_disconnects_mid_admission_gives_its_reservation_back`:
/// with the deadline effectively disabled the reservation was still held after
/// 20 s.)
///
/// So the deadline is what bounds the damage, and its length is a straight trade:
/// too long and a few abandoned requests can hold the budget; too short and a
/// genuinely slow peer loses a legitimate transfer. 120 s serves the default
/// 256 MiB per-NAR bound at ~2.1 MiB/s, which is slower than any link this project
/// has measured (task-63's WAN shape is 20 MiB/s; task-64's loopback peer path is
/// ~204 MB/s). Deriving it from a minimum-throughput policy instead of a flat
/// constant belongs with task-44, which owns the slow-HIT policy.
pub const DEFAULT_MAX_SERVE_DURATION: Duration = Duration::from_secs(120);

/// The numeric bound on what serving may cost (task-72 AC#1). The two byte fields
/// are in NarSize units - UNCOMPRESSED NAR bytes, the addressed unit - never the
/// compressed FileSize a narinfo carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeBudget {
    /// Above this, a single blob is DECLINED rather than allocated.
    pub max_nar_bytes_uncompressed_nar: u64,
    /// Above this total across concurrently-admitted serves, a further request is
    /// DECLINED rather than admitted.
    pub max_inflight_bytes_uncompressed_nar: u64,
    /// How long one serve may hold its reservation before it is reclaimed.
    pub max_serve_duration: Duration,
}

impl Default for ServeBudget {
    fn default() -> Self {
        ServeBudget {
            max_nar_bytes_uncompressed_nar: DEFAULT_MAX_SERVE_NAR_BYTES,
            max_inflight_bytes_uncompressed_nar: DEFAULT_MAX_INFLIGHT_NAR_BYTES,
            max_serve_duration: DEFAULT_MAX_SERVE_DURATION,
        }
    }
}

impl ServeBudget {
    /// The PRE-task-72 behaviour: serve whatever is asked, allocate whatever that
    /// costs. It exists so the bound can be proven by MUTATION - a test removes
    /// the bound with this and shows the allocation come back - and for no other
    /// reason. It is deliberately not reachable from the CLI: an operator who
    /// wants no bound can raise the number, and will then have written the number
    /// they chose.
    pub fn unbounded() -> Self {
        ServeBudget {
            max_nar_bytes_uncompressed_nar: u64::MAX,
            max_inflight_bytes_uncompressed_nar: u64::MAX,
            max_serve_duration: DEFAULT_MAX_SERVE_DURATION,
        }
    }
}

/// Why a get-request was refused before any memory was committed to it. Each
/// variant is counted separately in [`ServeCounters`]: "we declined 12 requests"
/// is not actionable, "we declined 12 as over the per-NAR bound" is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeDecline {
    /// The blob is larger than [`ServeBudget::max_nar_bytes_uncompressed_nar`].
    TooLarge,
    /// Admitting it would push concurrently-held bytes past
    /// [`ServeBudget::max_inflight_bytes_uncompressed_nar`].
    Busy,
    /// Neither the store nor the supplier knows this digest. (iroh-blobs would
    /// fail the transfer anyway; declining here makes it a NAMED, counted answer
    /// instead of an opaque stream error.)
    Unknown,
    /// The supplier knew the digest but could not produce the bytes (a GC'd store
    /// path, an unreadable file, content that no longer hashes to the digest).
    SupplyFailed,
    /// The blob store could not be ASKED what it holds. Distinct from `Unknown` on
    /// purpose, and the distinction is this module's own stated rule: a query that
    /// FAILED must never be reported as "holds nothing" (see [`IrohError::StoreQuery`]).
    /// Folding it into `Unknown` would tell a peer we do not have content we may
    /// well have, and would hide a broken store behind a routine-looking counter.
    StoreUnreadable,
}

/// A decline together with the CAUSE that produced it.
///
/// The category drives the counter and the abort code a peer sees; the cause is
/// the sentence an operator needs. Keeping only the category is what made
/// `declined_supply_failed=12` unactionable - it cannot distinguish a permissions
/// problem from a garbage-collected path from a digest mismatch, and
/// [`SupplyError`] goes to the trouble of building exactly that string.
#[derive(Debug)]
struct Declined {
    reason: ServeDecline,
    why: String,
}

impl Declined {
    fn new(reason: ServeDecline, why: impl Into<String>) -> Self {
        Declined {
            reason,
            why: why.into(),
        }
    }
}

impl ServeDecline {
    /// The stable, greppable name used in counters and logs.
    pub const fn reason(self) -> &'static str {
        match self {
            ServeDecline::TooLarge => "too_large",
            ServeDecline::Busy => "busy",
            ServeDecline::Unknown => "unknown",
            ServeDecline::SupplyFailed => "supply_failed",
            ServeDecline::StoreUnreadable => "store_unreadable",
        }
    }

    /// How the refusal is reported to the peer. `RateLimited` says "try later"
    /// (a busy node genuinely will be free later); `Permission` says "not from
    /// me" for the three that will not change on their own.
    const fn abort_reason(self) -> AbortReason {
        match self {
            ServeDecline::Busy => AbortReason::RateLimited,
            _ => AbortReason::Permission,
        }
    }
}

/// What the admission gate has done since startup. Counters, not a log, because
/// the interesting question ("is this node refusing work, and why") is a rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServeCounters {
    /// Get-requests admitted (the budget agreed to pay for them).
    pub admitted: u64,
    /// Admissions that had to REGENERATE the content first (a supplier call).
    /// The difference between this and `admitted` is the store-hit rate.
    pub regenerated: u64,
    /// Declined: over the per-NAR bound.
    pub declined_too_large: u64,
    /// Declined: over the in-flight total.
    pub declined_busy: u64,
    /// Declined: digest unknown to both the store and the supplier.
    pub declined_unknown: u64,
    /// Declined: the supplier could not produce the bytes.
    pub declined_supply_failed: u64,
    /// Declined: the blob store could not be queried at all.
    pub declined_store_unreadable: u64,
    /// Admitted serves whose reservation was RECLAIMED because they exceeded
    /// [`ServeBudget::max_serve_duration`]. Not a decline - the peer was let in and
    /// then took too long - so it is counted separately.
    pub reservations_timed_out: u64,
}

impl ServeCounters {
    /// Total declines, whatever the reason.
    pub fn declined(&self) -> u64 {
        self.declined_too_large
            + self.declined_busy
            + self.declined_unknown
            + self.declined_supply_failed
            + self.declined_store_unreadable
    }
}

/// One admitted, not-yet-finished serve. `refs` because two peers can ask for the
/// same digest at once: the content is materialised ONCE and both are served from
/// it, so the budget charges for it once and releases it when the LAST of them is
/// done.
struct Inflight {
    refs: usize,
    bytes_uncompressed_nar: u64,
    /// Holds the blob against the garbage collector for the life of the serve.
    /// `None` for a blob that was already resident (nothing to pin that this
    /// admission created).
    tag: Option<TempTag>,
    /// SINGLE FLIGHT. `None` while the first admitter is regenerating the content;
    /// `Some(true)` once the blob is in the store; `Some(false)` if regeneration
    /// failed. Followers WAIT on this rather than returning "allowed" against a
    /// blob that does not exist yet - which would hand the peer an empty transfer
    /// under exactly the herd condition that makes on-demand supply interesting.
    ///
    /// A `watch` and not a `Notify`: `watch` carries the STATE as well as the
    /// edge, so a follower that arrives after the leader already published cannot
    /// miss the wakeup and hang. That lost-wakeup window is the whole reason this
    /// is not a bare notification.
    state: watch::Sender<Option<bool>>,
}

/// What [`ServeGate::reserve`] decided this caller must do next.
enum Reservation {
    /// This caller is the first: it must produce the bytes and publish the result.
    Materialise,
    /// The content is already in the store; nothing to do.
    Ready,
    /// Another caller is materialising it; wait for their verdict.
    Follow(watch::Receiver<Option<bool>>),
}

/// How a releasing provider decides that a collector sweep may run.
struct SweepPolicy {
    /// Set by whatever asks for a release; consumed by the next sweep.
    armed: AtomicBool,
    /// TRUE under [`StoreRetention::ReleaseAfterServe`]: the collector runs on its
    /// own interval and PROTECTS what is in flight, so a node under sustained load
    /// still reclaims. FALSE under [`StoreRetention::ReleaseOnRequest`], whose
    /// contract is "hold everything until `release_all` is called" - there, only an
    /// explicit request arms a sweep, and a completed serve must not.
    free_running: bool,
}

/// The admission gate: the budget, what can be regenerated, and what is in flight.
struct ServeGate {
    budget: ServeBudget,
    supplier: Option<Arc<dyn NarSupplier>>,
    supervisor: TaskSupervisorHandle,
    /// The SINGLE SOURCE OF TRUTH for "what is this node currently on the hook
    /// for". In-flight BYTES are summed from it rather than tracked in a parallel
    /// counter: two representations of one fact is how they drift.
    inflight: Mutex<HashMap<Hash, Inflight>>,
    /// How this provider reclaims, or `None` under [`StoreRetention::RetainAll`]
    /// where nothing sweeps. ONE field, not two booleans projected from one enum:
    /// a third retention variant would otherwise have to remember to update both,
    /// which is the drift this module polices everywhere else.
    sweep: Option<SweepPolicy>,
    admitted: AtomicU64,
    regenerated: AtomicU64,
    declined_too_large: AtomicU64,
    declined_busy: AtomicU64,
    declined_unknown: AtomicU64,
    declined_supply_failed: AtomicU64,
    declined_store_unreadable: AtomicU64,
    timed_out: AtomicU64,
}

impl ServeGate {
    fn counters(&self) -> ServeCounters {
        ServeCounters {
            admitted: self.admitted.load(Ordering::Relaxed),
            regenerated: self.regenerated.load(Ordering::Relaxed),
            declined_too_large: self.declined_too_large.load(Ordering::Relaxed),
            declined_busy: self.declined_busy.load(Ordering::Relaxed),
            declined_unknown: self.declined_unknown.load(Ordering::Relaxed),
            declined_supply_failed: self.declined_supply_failed.load(Ordering::Relaxed),
            declined_store_unreadable: self.declined_store_unreadable.load(Ordering::Relaxed),
            reservations_timed_out: self.timed_out.load(Ordering::Relaxed),
        }
    }

    /// Whether the collector runs on its own interval (protecting what is in
    /// flight) rather than only when something explicitly asks for a release.
    fn sweeps_freely(&self) -> bool {
        self.sweep.as_ref().is_some_and(|sweep| sweep.free_running)
    }

    /// Ask for one sweep. A no-op on a store that never sweeps.
    fn arm_sweep(&self) {
        if let Some(sweep) = &self.sweep {
            sweep.armed.store(true, Ordering::SeqCst);
        }
    }

    /// The hashes a sweep must not collect: everything currently being served.
    fn inflight_hashes(&self) -> Vec<Hash> {
        self.inflight
            .lock()
            .expect("inflight mutex")
            .keys()
            .copied()
            .collect()
    }

    fn count_decline(&self, why: ServeDecline) {
        let counter = match why {
            ServeDecline::TooLarge => &self.declined_too_large,
            ServeDecline::Busy => &self.declined_busy,
            ServeDecline::Unknown => &self.declined_unknown,
            ServeDecline::SupplyFailed => &self.declined_supply_failed,
            ServeDecline::StoreUnreadable => &self.declined_store_unreadable,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Reserve `size` bytes for `hash`, or say why not, and say what this caller
    /// must do next.
    ///
    /// THE BUDGET IS CHECKED BEFORE ANYTHING IS PRODUCED. That ordering is the
    /// whole of task-72 AC#1: `size` came from metadata or from the store's own
    /// accounting, so a 3 GiB request is refused having allocated nothing.
    ///
    /// The insert also happens HERE, before any `add_bytes`, and THAT ordering is
    /// load-bearing for the collector race - see the `ProtectCb` installed while
    /// preparing [`IrohProviderConfig`].
    fn reserve(
        &self,
        hash: Hash,
        size: u64,
        must_regenerate: bool,
    ) -> Result<Reservation, ServeDecline> {
        if size > self.budget.max_nar_bytes_uncompressed_nar {
            return Err(ServeDecline::TooLarge);
        }
        let mut inflight = self.inflight.lock().expect("inflight mutex");
        if let Some(entry) = inflight.get_mut(&hash) {
            entry.refs += 1;
            return Ok(match *entry.state.borrow() {
                Some(true) => Reservation::Ready,
                _ => Reservation::Follow(entry.state.subscribe()),
            });
        }
        let held: u64 = inflight
            .values()
            .map(|e| e.bytes_uncompressed_nar)
            .sum::<u64>();
        if held.saturating_add(size) > self.budget.max_inflight_bytes_uncompressed_nar {
            return Err(ServeDecline::Busy);
        }
        // A resident blob is published READY at insert time: there is nothing to
        // wait for, and leaving it `None` would strand a concurrent follower.
        let (state, _) = watch::channel(if must_regenerate { None } else { Some(true) });
        inflight.insert(
            hash,
            Inflight {
                refs: 1,
                bytes_uncompressed_nar: size,
                tag: None,
                state,
            },
        );
        Ok(if must_regenerate {
            Reservation::Materialise
        } else {
            Reservation::Ready
        })
    }

    /// Publish the outcome of a materialisation to this caller and to any
    /// followers: the pinning tag on success, the verdict either way.
    fn publish(&self, hash: Hash, tag: Option<TempTag>) {
        let ok = tag.is_some();
        if let Some(entry) = self.inflight.lock().expect("inflight mutex").get_mut(&hash) {
            entry.tag = tag;
            // `send_replace`, not `send`: with no followers subscribed `send`
            // reports an error, and a materialisation that succeeded must not be
            // recorded as failed just because nobody happened to be waiting.
            entry.state.send_replace(Some(ok));
        }
    }

    /// Give back one reference. When the last one goes the entry is removed - which
    /// DROPS its [`TempTag`], making the blob collectible.
    ///
    /// PRIVATE, and called from exactly one place: [`Admission`]'s `Drop`. Every
    /// hand-written release site is a chance to miss one, and missing one leaks the
    /// budget permanently - see [`Admission`].
    fn release(&self, hash: Hash) {
        let mut inflight = self.inflight.lock().expect("inflight mutex");
        if let Some(entry) = inflight.get_mut(&hash) {
            entry.refs -= 1;
            if entry.refs == 0 {
                inflight.remove(&hash);
            }
        }
    }
}

/// A live reservation against the serve budget. Dropping it gives the budget back.
///
/// WHY THIS IS A GUARD AND NOT A PAIR OF CALLS. The first cut released the
/// reservation where the transfer's update stream ended, and returned early
/// without releasing when the verdict could not be delivered - which is exactly
/// what happens when the peer DISCONNECTS. That window spans the whole
/// regeneration, so a peer could request a large announced NAR, hang up after
/// 100 ms, repeat four times, and leave the node permanently `busy` for everyone
/// while pinning a gigabyte it would never release. No timeout, no reaper, and no
/// counter would have shown it.
///
/// As a guard, every early return, every `?`, a panic and a cancelled task all
/// release. The failure mode is not fixed so much as made unrepresentable.
struct Admission {
    gate: Arc<ServeGate>,
    hash: Hash,
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.gate.release(self.hash);
    }
}

/// THE ADMISSION GATE. Runs before iroh-blobs is allowed to serve a get-request,
/// and is where task-72's two gaps are closed:
///
///   * GAP 1 (peer-triggerable OOM): the size is established from metadata or from
///     the store's own accounting, and compared against the budget, BEFORE anything
///     is produced. A 3 GiB request costs a `stat`, not 3 GiB.
///   * GAP 2 (announced but unservable): a digest the supplier can produce is
///     materialised HERE, so "we announced it" and "we can serve it" are the same
///     statement. A digest neither the store nor the supplier knows is declined as
///     `Unknown` - a named, counted answer instead of a dial that hangs up mid-stream.
///
/// On success it returns the [`Admission`] guard. HOLDING IT is what keeps the
/// reservation alive; dropping it - by any path, including a panic or a cancelled
/// task - gives the budget back.
async fn admit(gate: &Arc<ServeGate>, store: &MemStore, hash: Hash) -> Result<Admission, Declined> {
    let content = Blake3Digest::from_bytes(*hash.as_bytes());

    // 1. HOW BIG IS IT - answered WITHOUT producing anything.
    //
    // A store that could not ANSWER is not a store that says "no". Erasing that
    // difference is the failure this module names at `IrohError::StoreQuery`, so a
    // query error is only tolerable when the supplier can produce the content
    // anyway; otherwise it is declined as itself.
    let (resident, store_readable) = match store.blobs().status(hash).await {
        Ok(BlobStatus::Complete { size }) => (Some(size), true),
        // Partial is a real answer and a real "not servable whole": fall through
        // to the supplier, which can produce it complete.
        Ok(_) => (None, true),
        Err(_) => (None, false),
    };
    // The supplier returns inert data only. This call performs no filesystem IO,
    // process spawn, lazy digest derivation, or arbitrary callback dispatch.
    let supplied_plan = gate
        .supplier
        .as_ref()
        .map(|supplier| nar_supplier_sealed::Sealed::plan(supplier.as_ref(), &content))
        .transpose()
        .map_err(|error| Declined::new(ServeDecline::SupplyFailed, error.to_string()))?
        .flatten();
    let (size, must_regenerate) = match resident {
        Some(size) => (size, false),
        None => match supplied_plan.as_ref() {
            Some(plan) => (plan.declared_size, true),
            None if store_readable => {
                return Err(Declined::new(
                    ServeDecline::Unknown,
                    format!("neither the store nor the supplier knows {content}"),
                ));
            }
            None => {
                return Err(Declined::new(
                    ServeDecline::StoreUnreadable,
                    format!("the blob store could not be asked about {content}"),
                ));
            }
        },
    };

    // 2. THE BOUND, and the reservation, before the allocation.
    let reservation = gate
        .reserve(hash, size, must_regenerate)
        .map_err(|reason| {
            Declined::new(
                reason,
                format!("{size} B (uncompressed NAR) does not fit the serve budget"),
            )
        })?;
    // FROM HERE ON THE RESERVATION IS HELD BY A GUARD. Every `?` below releases it.
    let admission = Admission {
        gate: gate.clone(),
        hash,
    };

    match reservation {
        Reservation::Follow(mut state) => loop {
            if let Some(ok) = *state.borrow_and_update() {
                if ok {
                    break;
                }
                return Err(Declined::new(
                    ServeDecline::SupplyFailed,
                    format!("the admission that is regenerating {content} failed"),
                ));
            }
            // `Err` means the entry (and its sender) went away - which only
            // happens on the failure path, so it reads the same as `Some(false)`.
            if state.changed().await.is_err() {
                return Err(Declined::new(
                    ServeDecline::SupplyFailed,
                    format!("the admission regenerating {content} vanished"),
                ));
            }
        },
        // READY and MATERIALISE end in the same requirement - the blob must be in
        // the store when we answer yes - so they share one path.
        //
        // The `has` re-check is NOT conditioned on this caller's own `status()`
        // read. `reserve` can return `Ready` because ANOTHER admission published
        // the blob, and that other admission may have observed it resident just
        // before a sweep took it. Gating the re-check on our own read would skip it
        // for precisely the caller holding the freshest evidence of absence.
        Reservation::Ready | Reservation::Materialise => {
            let present = matches!(reservation, Reservation::Ready)
                && !gate.sweeps_freely()
                // A store error here reads as "regenerate anyway": the fallback is
                // to do MORE work, never to tell a peer we hold nothing.
                || store.blobs().has(hash).await.unwrap_or(false);
            if !present {
                if let Err(declined) =
                    materialise(gate, store, &content, hash, size, supplied_plan.as_ref()).await
                {
                    // Tell the followers BEFORE the guard drops the entry.
                    gate.publish(hash, None);
                    return Err(declined);
                }
                gate.regenerated.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    gate.admitted.fetch_add(1, Ordering::Relaxed);
    Ok(admission)
}

/// Produce the content for `hash` and put it in the store, pinned for the serve.
///
/// Called ONLY after [`ServeGate::reserve`] has agreed to pay `reserved` bytes for
/// it, and only by the single caller that won the single-flight race.
async fn materialise(
    gate: &Arc<ServeGate>,
    store: &MemStore,
    content: &Blake3Digest,
    hash: Hash,
    reserved: u64,
    plan: Option<&SupplyPlan>,
) -> Result<(), Declined> {
    let plan = plan.ok_or_else(|| {
        Declined::new(
            ServeDecline::Unknown,
            format!("no closed supply plan can regenerate {content}"),
        )
    })?;
    for _attempt in 0..MATERIALISE_ATTEMPTS {
        let raw = execute_supply_plan(gate, plan, content, reserved).await?;
        // RECONCILE AGAINST WHAT WAS RESERVED, not merely against the per-NAR cap.
        // Comparing to the cap would let a source that declared 1 MiB and produced
        // 200 MiB through (200 < the 256 MiB default) while the in-flight ledger
        // still said 1 MiB - and the in-flight total exists precisely to stop a
        // swarm of individually-acceptable serves. The two must be EQUAL: they
        // describe the same NAR.
        if raw.len() as u64 != reserved {
            return Err(Declined::new(
                ServeDecline::TooLarge,
                format!(
                    "{content} was admitted as {reserved} B but its source produced \
                     {} B - the budget charged for a different NAR than it got",
                    raw.len()
                ),
            ));
        }
        // BY VALUE. `add_bytes` takes `impl Into<bytes::Bytes>`, so a `Vec<u8>` is
        // MOVED into the store, not copied. That is why this path costs ~1x the NAR
        // rather than the ~2x `IrohProvider::seed` costs, and it is NOT task-46's
        // fix arriving early: task-46 owns removing the `to_vec()` from `seed`,
        // whose `&[u8]` signature forces the copy. This is a different call site
        // that never had a borrowed slice to begin with. See task-46's notes.
        let tag = store
            .blobs()
            .add_bytes(raw)
            .temp_tag()
            .await
            .map_err(|add| {
                Declined::new(
                    ServeDecline::SupplyFailed,
                    format!("the blob store rejected {content}: {add}"),
                )
            })?;
        if tag.hash() != hash {
            // The supplier produced content that is not what was asked for (a store
            // path rebuilt, a file replaced). Serving it would be serving the wrong
            // blob under the right name; refuse, loudly and counted.
            return Err(Declined::new(
                ServeDecline::SupplyFailed,
                format!("the source for {content} now hashes to {}", tag.hash()),
            ));
        }
        // THE ONE COLLECTOR RETRY. See `StoreRetention::ReleaseAfterServe`: a sweep
        // already past its protect callback can delete a blob added under it. That
        // can happen at most once, because this hash is in the in-flight table from
        // before the add, so every LATER callback protects it - and `run_gc` is one
        // sequential loop, so only one sweep can be in that window at a time.
        if store.blobs().has(hash).await.unwrap_or(false) {
            gate.publish(hash, Some(tag));
            return Ok(());
        }
    }
    Err(Declined::new(
        ServeDecline::SupplyFailed,
        format!("{content} was collected from under {MATERIALISE_ATTEMPTS} materialisations"),
    ))
}

struct ActiveMemoryOperation {
    metrics: Arc<MemorySupplierMetrics>,
    completed: bool,
}

impl Drop for ActiveMemoryOperation {
    fn drop(&mut self) {
        self.metrics
            .active_operations
            .fetch_sub(1, Ordering::AcqRel);
        if !self.completed {
            self.metrics
                .cancelled_operations
                .fetch_add(1, Ordering::AcqRel);
        }
    }
}

async fn execute_supply_plan(
    gate: &Arc<ServeGate>,
    plan: &SupplyPlan,
    content: &Blake3Digest,
    reserved: u64,
) -> Result<Vec<u8>, Declined> {
    let retained_limit = usize::try_from(reserved).map_err(|_| {
        Declined::new(
            ServeDecline::TooLarge,
            format!(
                "{content} reservation {reserved} B exceeds this process's addressable output cap"
            ),
        )
    })?;

    match &plan.source {
        SupplySource::Process {
            program,
            args,
            environment,
        } => {
            let output = gate
                .supervisor
                .execute_process(
                    "iroh-supplier-process",
                    program.clone(),
                    args.clone(),
                    environment.clone(),
                    retained_limit,
                )
                .await
                .map_err(|error| {
                    Declined::new(
                        ServeDecline::SupplyFailed,
                        format!("supervising source process for {content}: {error}"),
                    )
                })?;
            if output.stdout_exceeded_limit {
                return Err(Declined::new(
                    ServeDecline::TooLarge,
                    format!("{content} source exceeded its reserved output cap of {reserved} B"),
                ));
            }
            if !output.status.success() {
                return Err(Declined::new(
                    ServeDecline::SupplyFailed,
                    format!(
                        "source process for {content} exited {}: {}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim()
                    ),
                ));
            }
            Ok(output.stdout)
        }
        SupplySource::Memory {
            bytes,
            released,
            metrics,
        } => {
            metrics.supplied.fetch_add(1, Ordering::AcqRel);
            metrics.active_operations.fetch_add(1, Ordering::AcqRel);
            let mut active = ActiveMemoryOperation {
                metrics: Arc::clone(metrics),
                completed: false,
            };
            if let Some(released) = released {
                while !released.load(Ordering::Acquire) {
                    metrics.activity_ticks.fetch_add(1, Ordering::AcqRel);
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
            if bytes.len() > retained_limit {
                return Err(Declined::new(
                    ServeDecline::TooLarge,
                    format!(
                        "{content} memory source exceeded its reserved output cap of {reserved} B"
                    ),
                ));
            }
            let retained = bytes.len().min(retained_limit);
            let mut raw = Vec::with_capacity(retained);
            for chunk in bytes[..retained].chunks(64 * 1024) {
                raw.extend_from_slice(chunk);
                tokio::task::yield_now().await;
            }
            active.completed = true;
            Ok(raw)
        }
    }
}

// -------------------------------------------------------------------------
// Provider (node B): serve this node's NARs by BLAKE3 over iroh-blobs.
// -------------------------------------------------------------------------

/// What the provider's blob store does with content after it is seeded (task-65)
/// or regenerated (task-72).
///
/// TASK-61 HAS NOW MADE THE POLICY DECISION that task-65 deliberately left open:
/// regenerate on demand, hold only the in-flight serve. That decision is expressed
/// by [`StoreRetention::ReleaseAfterServe`], which the daemon uses whenever a
/// [`NarSupplier`] is configured. [`StoreRetention::RetainAll`] remains the default
/// of the bare [`IrohProviderNode::spawn`] constructor, because the in-process
/// tests that seed a blob and fetch it are not modelling a node's supply policy.
#[derive(Debug, Clone)]
pub enum StoreRetention {
    /// Hold every seeded blob for the life of the process. No collector runs at
    /// all, so nothing can be released.
    RetainAll,
    /// Hold everything until [`IrohProvider::release_all`] is called, then let
    /// iroh-blobs' own garbage collector sweep ONCE, within `sweep_interval`.
    ///
    /// ARMED BY THE RELEASE, NOT BY THE CLOCK, and that is not a stylistic choice.
    /// iroh-blobs' gc calls `clear_protected()` before it marks, so a sweep landing
    /// while blobs are being ADDED can delete a blob whose named tag is not written
    /// yet (upstream says as much where it keeps `Blobs::delete` private: "it does
    /// not work as expected when called manually, because blobs are protected from
    /// deletion"). MEASURED here, not theorised: a free-running 50 ms gc alongside
    /// 512 seeds kept 501 of them. A background evictor for this store therefore
    /// needs that race solved before it is a policy option at all - a lesson
    /// forward-carried to TASK-61.
    ReleaseOnRequest { sweep_interval: Duration },
    /// THE TASK-61 SUPPLY MODEL: hold a blob only while a serve of it is in
    /// flight, then let it go. A node under this retention holds nothing at rest -
    /// its store residency returns to zero after an idle period, whatever it
    /// announces.
    ///
    /// HOW THE TASK-65 COLLECTOR RACE IS SOLVED, since that warning said a
    /// background evictor was not a policy option until it was. Two rules, and
    /// together they make a lost blob impossible rather than merely unlikely:
    ///
    ///   1. A sweep is ARMED only when the last in-flight serve finishes, and the
    ///      `ProtectCb` REFUSES (`Abort`, re-arming for the next tick) if anything
    ///      is in flight when it runs. So a sweep only ever begins from quiescence.
    ///   2. An admission inserts its hash into the in-flight table BEFORE it calls
    ///      `add_bytes`. `iroh_blobs::store::gc::run_gc` is ONE SEQUENTIAL LOOP
    ///      (`cb().await` then `gc_run_once().await`), so at most ONE sweep can be
    ///      between "callback returned" and "sweep finished" at any instant. A blob
    ///      added in that window can be collected exactly once; the retry cannot
    ///      lose, because by then the table is non-empty and every subsequent
    ///      callback aborts. That is why [`MATERIALISE_ATTEMPTS`] is 2 and not "a
    ///      few" - the bound is a proof, not a hope.
    ReleaseAfterServe { sweep_interval: Duration },
}

/// How many times a materialisation may re-add a blob the collector took from
/// under it. TWO, and the reason it is exactly two is the sequential-`run_gc`
/// argument on [`StoreRetention::ReleaseAfterServe`]. A third attempt would be
/// unreachable; making it configurable would invite someone to "fix" a race by
/// raising it.
const MATERIALISE_ATTEMPTS: usize = 2;

/// What the blob store currently HOLDS, asked of the store itself (task-65).
///
/// This is the residency oracle. It is NOT peak RSS: `VmHWM` is monotone by kernel
/// definition, so it cannot observe a release at all, and `VmRSS` cannot either when
/// glibc keeps a freed arena instead of returning it to the OS. An RSS-only oracle
/// therefore fails on a correct fix and passes on a wrong one. This asks iroh-blobs
/// which blobs it still has and how big they are.
///
/// STATED LIMIT: it answers "does the STORE still hold this content". With
/// [`MemStore`] that IS resident memory by construction. Under a future on-disk store
/// it would not be, and the mapping from store residency to RAM would have to be
/// re-derived (TASK-61).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoreResidency {
    /// Blobs the store still holds.
    pub blobs: u64,
    /// Their total size in UNCOMPRESSED NAR bytes (NarSize units - the addressed unit
    /// is the raw NAR, so a blob's size IS its NarSize). Never FileSize.
    pub bytes_uncompressed_nar: u64,
}

/// One COMPLETED get-transfer this provider served, as a half-open time window
/// measured on the HOLDER's own clock (task-65).
///
/// Why the holder's clock and not the fetching client's: the concurrency dimension
/// asks whether k serves actually OVERLAPPED, and a k-way overlap measured at the
/// HTTP client would be satisfied even if the daemon serialised the peer fetches
/// internally - the client windows would still overlap while the serves took turns.
/// A precondition that cannot fail is not a precondition (the task-18 rule).
#[derive(Debug, Clone, Copy)]
pub struct ServeWindow {
    /// Milliseconds from provider spawn to the transfer's `Started` event.
    pub start_ms: f64,
    /// Milliseconds from provider spawn to its `Completed` event.
    pub end_ms: f64,
    /// Declared blob size served, in UNCOMPRESSED NAR bytes.
    pub bytes_uncompressed_nar: u64,
}

/// An iroh-blobs provider handle attached to a shared [`IrohNodeRuntime`].
///
/// This handle does not own a router or a strong endpoint reference. It can
/// seed/query the store and inspect the live runtime endpoint, but it cannot
/// bind or close network resources independently.
pub struct IrohProvider {
    endpoint: IrohEndpointHandle,
    lifecycle: Arc<AtomicU8>,
    store: MemStore,
    /// Per-transfer serve windows on this provider's own clock (see [`ServeWindow`]).
    serve_windows: Arc<Mutex<Vec<ServeWindow>>>,
    /// The task-72 admission gate: the serve budget, the on-demand supplier, and
    /// what is in flight right now. Shared with the request-intercept task and with
    /// the collector's protect callback.
    gate: Arc<ServeGate>,
    /// Total DECLARED size of the whole-blob transfers this provider has COMPLETED,
    /// observed from iroh-blobs' own provider events (never a client self-report).
    /// This is the S6 ground-truth oracle: node A's daemon claiming it "fetched from
    /// a peer" is untrusted narration; node B counting the bytes it SERVED is the
    /// ground truth. It is a LOWER BOUND on wire bytes: it credits the blob size on
    /// `Completed` (for a fresh whole-blob serve, size == bytes sent), never credits
    /// `Aborted`, and would under-count only if the bounded event channel lagged
    /// (harmless for S6's small blobs; exact byte-on-wire accounting for large
    /// payloads is a task-42/43 concern).
    bytes_served: Arc<AtomicU64>,
    /// Count of COMPLETED get-transfers served (each a whole blob handed to a
    /// client). Paired with [`Self::bytes_served`] so a nonzero byte count is
    /// attributable to real transfers, not a spurious event.
    transfers_completed: Arc<AtomicU64>,
}

/// Provider-side store, admission and retention inputs. Endpoint identity and
/// network scope belong to the node runtime, not to this configuration.
pub struct IrohProviderConfig {
    retention: StoreRetention,
    budget: ServeBudget,
    supplier: Option<Arc<dyn NarSupplier>>,
}

impl fmt::Debug for IrohProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrohProviderConfig")
            .field("retention", &self.retention)
            .field("budget", &self.budget)
            .field("has_supplier", &self.supplier.is_some())
            .finish()
    }
}

impl IrohProviderConfig {
    pub fn retaining(retention: StoreRetention) -> Self {
        Self {
            retention,
            budget: ServeBudget::default(),
            supplier: None,
        }
    }

    pub fn supplying(
        supplier: Arc<dyn NarSupplier>,
        budget: ServeBudget,
        sweep_interval: Duration,
    ) -> Self {
        Self {
            retention: StoreRetention::ReleaseAfterServe { sweep_interval },
            budget,
            supplier: Some(supplier),
        }
    }

    pub fn new(
        retention: StoreRetention,
        budget: ServeBudget,
        supplier: Option<Arc<dyn NarSupplier>>,
    ) -> Self {
        Self {
            retention,
            budget,
            supplier,
        }
    }
}

struct PreparedProvider {
    store: MemStore,
    serve_windows: Arc<Mutex<Vec<ServeWindow>>>,
    gate: Arc<ServeGate>,
    bytes_served: Arc<AtomicU64>,
    transfers_completed: Arc<AtomicU64>,
    protocol: ManagedBlobsProtocol,
}

impl PreparedProvider {
    fn prepare(
        config: IrohProviderConfig,
        supervisor: TaskSupervisorHandle,
    ) -> Result<Self, IrohError> {
        let retention = config.retention;
        let gate = Arc::new(ServeGate {
            budget: config.budget,
            supplier: config.supplier,
            supervisor: supervisor.clone(),
            inflight: Mutex::new(HashMap::new()),
            sweep: match retention {
                StoreRetention::RetainAll => None,
                StoreRetention::ReleaseOnRequest { .. } => Some(SweepPolicy {
                    armed: AtomicBool::new(false),
                    free_running: false,
                }),
                StoreRetention::ReleaseAfterServe { .. } => Some(SweepPolicy {
                    armed: AtomicBool::new(true),
                    free_running: true,
                }),
            },
            admitted: AtomicU64::new(0),
            regenerated: AtomicU64::new(0),
            declined_too_large: AtomicU64::new(0),
            declined_busy: AtomicU64::new(0),
            declined_unknown: AtomicU64::new(0),
            declined_supply_failed: AtomicU64::new(0),
            declined_store_unreadable: AtomicU64::new(0),
            timed_out: AtomicU64::new(0),
        });

        let store = match retention {
            StoreRetention::RetainAll => MemStore::new(),
            StoreRetention::ReleaseOnRequest { sweep_interval }
            | StoreRetention::ReleaseAfterServe { sweep_interval } => {
                let gate_for_cb = gate.clone();
                let add_protected: ProtectCb = Arc::new(move |live| {
                    let gate = gate_for_cb.clone();
                    Box::pin(async move {
                        let Some(sweep) = &gate.sweep else {
                            return ProtectOutcome::Abort;
                        };
                        if !sweep.free_running && !sweep.armed.swap(false, Ordering::SeqCst) {
                            return ProtectOutcome::Abort;
                        }
                        for hash in gate.inflight_hashes() {
                            live.insert(hash);
                        }
                        ProtectOutcome::Continue
                    })
                });
                MemStore::new_with_opts(MemStoreOptions {
                    gc_config: Some(GcConfig {
                        interval: sweep_interval,
                        add_protected: Some(add_protected),
                    }),
                })
            }
        };

        let mask = EventMask {
            get: RequestMode::InterceptLog,
            ..EventMask::DEFAULT
        };
        let (events, rx) = EventSender::channel(64, mask);
        let bytes_served = Arc::new(AtomicU64::new(0));
        let transfers_completed = Arc::new(AtomicU64::new(0));
        let serve_origin = Instant::now();
        let serve_windows = Arc::new(Mutex::new(Vec::<ServeWindow>::new()));
        let tasks = ProviderEventTasks::new(
            rx,
            bytes_served.clone(),
            transfers_completed.clone(),
            serve_windows.clone(),
            gate.clone(),
            store.clone(),
            serve_origin,
        );
        let blobs = BlobsProtocol::new(&store, Some(events));
        Ok(Self {
            store,
            serve_windows,
            gate,
            bytes_served,
            transfers_completed,
            protocol: ManagedBlobsProtocol { blobs, tasks },
        })
    }

    fn attach(self, endpoint: IrohEndpointHandle) -> IrohProvider {
        IrohProvider {
            endpoint,
            lifecycle: Arc::clone(&self.protocol.tasks.lifecycle),
            store: self.store,
            serve_windows: self.serve_windows,
            gate: self.gate,
            bytes_served: self.bytes_served,
            transfers_completed: self.transfers_completed,
        }
    }
}

struct ProviderEventTasks {
    driver: Mutex<Option<ProviderEventDriver>>,
    lifecycle: Arc<AtomicU8>,
}

const PROVIDER_CREATED: u8 = 0;
const PROVIDER_READY: u8 = 1;
const PROVIDER_STOPPED: u8 = 2;

struct ProviderEventDriver {
    rx: tokio::sync::mpsc::Receiver<ProviderMessage>,
    bytes_served: Arc<AtomicU64>,
    transfers_completed: Arc<AtomicU64>,
    serve_windows: Arc<Mutex<Vec<ServeWindow>>>,
    gate: Arc<ServeGate>,
    store: MemStore,
    serve_origin: Instant,
}

impl fmt::Debug for ProviderEventTasks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderEventTasks").finish_non_exhaustive()
    }
}

impl ProviderEventTasks {
    fn new(
        rx: tokio::sync::mpsc::Receiver<ProviderMessage>,
        bytes_served: Arc<AtomicU64>,
        transfers_completed: Arc<AtomicU64>,
        serve_windows: Arc<Mutex<Vec<ServeWindow>>>,
        gate: Arc<ServeGate>,
        store: MemStore,
        serve_origin: Instant,
    ) -> Arc<Self> {
        Arc::new(Self {
            driver: Mutex::new(Some(ProviderEventDriver {
                rx,
                bytes_served,
                transfers_completed,
                serve_windows,
                gate,
                store,
                serve_origin,
            })),
            lifecycle: Arc::new(AtomicU8::new(PROVIDER_CREATED)),
        })
    }

    fn is_ready(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) == PROVIDER_READY
    }

    fn require_ready(&self) -> Result<(), AcceptError> {
        if self.is_ready() {
            Ok(())
        } else {
            Err(AcceptError::from(std::io::Error::other(
                "Iroh blobs provider event driver is not ready",
            )))
        }
    }

    async fn start(&self, supervisor: TaskSupervisorHandle) -> Result<(), IrohError> {
        let Some(mut driver) = self
            .driver
            .lock()
            .map_err(|_| IrohError::Runtime("provider event-driver mutex poisoned".into()))?
            .take()
        else {
            return Err(IrohError::Runtime(
                "provider event driver was already started".into(),
            ));
        };
        let request_supervisor = supervisor.clone();
        let lifecycle = Arc::clone(&self.lifecycle);
        let lifecycle_for_task = Arc::clone(&lifecycle);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        if let Err(error) = supervisor.spawn("iroh-provider-events", async move {
            struct MarkStopped(Arc<AtomicU8>);
            impl Drop for MarkStopped {
                fn drop(&mut self) {
                    self.0.store(PROVIDER_STOPPED, Ordering::Release);
                }
            }
            let _stopped = MarkStopped(Arc::clone(&lifecycle_for_task));
            // This statement runs on the driver's first poll. The builder awaits
            // its acknowledgement before returning a usable node.
            lifecycle_for_task.store(PROVIDER_READY, Ordering::Release);
            let _ = ready_tx.send(());
            while let Some(message) = driver.rx.recv().await {
                let ProviderMessage::GetRequestReceived(message) = message else {
                    continue;
                };
                let request_hash = message.request.hash;
                let bytes_served = driver.bytes_served.clone();
                let transfers_completed = driver.transfers_completed.clone();
                let serve_windows = driver.serve_windows.clone();
                let gate = driver.gate.clone();
                let gate_for_registration = driver.gate.clone();
                let store = driver.store.clone();
                let serve_origin = driver.serve_origin;
                if let Err(error) = request_supervisor.spawn("iroh-provider-request", async move {
                    let hash = request_hash;
                    let serve_deadline = gate.budget.max_serve_duration;
                    let request = async {
                        let mut updates = message.rx;
                        let verdict = admit(&gate, &store, hash).await;
                        let (admission, answer) = match verdict {
                            Ok(admission) => (Some(admission), Ok(())),
                            Err(declined) => {
                                gate.count_decline(declined.reason);
                                eprintln!(
                                    "IROH-SERVE-DECLINED reason={} hash={hash} why={}",
                                    declined.reason.reason(),
                                    declined.why
                                );
                                (None, Err(declined.reason.abort_reason()))
                            }
                        };
                        let answered = message.tx.send(answer).await;
                        let Some(_admission) = admission else {
                            return;
                        };
                        if answered.is_err() {
                            return;
                        }

                        let mut blob_size: u64 = 0;
                        let mut started_ms: Option<f64> = None;
                        while let Ok(Some(update)) = updates.recv().await {
                            match update {
                                RequestUpdate::Started(started) => {
                                    blob_size = started.size;
                                    started_ms =
                                        Some(serve_origin.elapsed().as_secs_f64() * 1000.0);
                                }
                                RequestUpdate::Completed(_) => {
                                    bytes_served.fetch_add(blob_size, Ordering::Relaxed);
                                    transfers_completed.fetch_add(1, Ordering::Relaxed);
                                    if let Some(start_ms) = started_ms.take() {
                                        serve_windows
                                            .lock()
                                            .expect("serve windows mutex")
                                            .push(ServeWindow {
                                                start_ms,
                                                end_ms: serve_origin.elapsed().as_secs_f64()
                                                    * 1000.0,
                                                bytes_uncompressed_nar: blob_size,
                                            });
                                    }
                                }
                                _ => {}
                            }
                        }
                    };
                    if tokio::time::timeout(serve_deadline, request).await.is_err() {
                        gate.timed_out.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "IROH-SERVE-TIMEOUT hash={hash} after={serve_deadline:?} - the reservation is reclaimed and the transfer will fail"
                        );
                    }
                }) {
                    if error.is_capacity_exhausted() {
                        // `spawn` owns and drops the rejected future, including
                        // the response channel in `message`. The requesting
                        // peer therefore observes an immediate failed request
                        // rather than waiting for a provider reply that can no
                        // longer be supervised. Capacity is transient: keep
                        // the event driver alive so later requests can recover.
                        gate_for_registration
                            .declined_busy
                            .fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "IROH-SERVE-DECLINED reason=busy hash={request_hash} why={error}"
                        );
                        continue;
                    }
                    eprintln!("IROH-SERVE-TASK-REGISTRATION-FAILED error={error}");
                    break;
                }
            }
        }) {
            lifecycle.store(PROVIDER_STOPPED, Ordering::Release);
            return Err(error.into());
        }
        ready_rx.await.map_err(|_| {
            lifecycle.store(PROVIDER_STOPPED, Ordering::Release);
            IrohError::Runtime(
                "provider event driver stopped before acknowledging its first poll".into(),
            )
        })?;
        if !self.is_ready() {
            return Err(IrohError::Runtime(
                "provider event driver acknowledged startup without entering ready state".into(),
            ));
        }
        Ok(())
    }

    fn stop(&self) {
        self.lifecycle.store(PROVIDER_STOPPED, Ordering::Release);
    }
}

#[derive(Clone)]
struct ManagedBlobsProtocol {
    blobs: BlobsProtocol,
    tasks: Arc<ProviderEventTasks>,
}

impl fmt::Debug for ManagedBlobsProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedBlobsProtocol")
            .finish_non_exhaustive()
    }
}

impl ManagedBlobsProtocol {
    async fn start(&self, supervisor: TaskSupervisorHandle) -> Result<(), IrohError> {
        self.tasks.start(supervisor).await
    }
}

impl ProtocolHandler for ManagedBlobsProtocol {
    async fn on_accepting(&self, accepting: Accepting) -> Result<Connection, AcceptError> {
        self.tasks.require_ready()?;
        let connection = accepting.await?;
        self.tasks.require_ready()?;
        Ok(connection)
    }

    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        self.tasks.require_ready()?;
        ProtocolHandler::accept(&self.blobs, connection).await
    }

    async fn shutdown(&self) {
        self.tasks.stop();
        ProtocolHandler::shutdown(&self.blobs).await;
    }
}

impl IrohProvider {
    #[doc(hidden)]
    pub fn event_driver_ready(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) == PROVIDER_READY
    }

    /// What the admission gate has admitted, regenerated and declined so far.
    pub fn serve_counters(&self) -> ServeCounters {
        self.gate.counters()
    }

    /// Total raw-NAR bytes this provider has SERVED to clients over completed
    /// get-transfers (the ground-truth peer-served counter). Observed from
    /// iroh-blobs provider events, so it cannot be forged by a client.
    pub fn bytes_served(&self) -> u64 {
        self.bytes_served.load(Ordering::Relaxed)
    }

    /// Count of completed get-transfers served (see [`Self::bytes_served`]).
    pub fn transfers_completed(&self) -> u64 {
        self.transfers_completed.load(Ordering::Relaxed)
    }

    /// Every completed serve's [`ServeWindow`], in completion order.
    pub fn serve_windows(&self) -> Vec<ServeWindow> {
        self.serve_windows
            .lock()
            .expect("serve windows mutex")
            .clone()
    }

    /// THE RESIDENCY ORACLE (task-65): what the blob store holds RIGHT NOW, asked of
    /// the store itself rather than inferred from the process's resident memory.
    ///
    /// See [`StoreResidency`] for why peak RSS cannot answer this and what this does
    /// and does not claim. Partial blobs count their stored prefix: a half-received
    /// blob is half-resident, and rounding it to zero would understate what a node
    /// is holding mid-transfer - precisely the case a streaming change (TASK-62)
    /// makes interesting.
    pub async fn store_residency(&self) -> Result<StoreResidency, IrohError> {
        let hashes = self
            .store
            .blobs()
            .list()
            .hashes()
            .await
            .map_err(|e| IrohError::StoreQuery(format!("listing blobs: {e}")))?;
        let mut residency = StoreResidency::default();
        for hash in hashes {
            let status = self
                .store
                .blobs()
                .status(hash)
                .await
                .map_err(|e| IrohError::StoreQuery(format!("status of {hash}: {e}")))?;
            let size = match status {
                BlobStatus::Complete { size } => size,
                BlobStatus::Partial { size } => size.unwrap_or(0),
                // Listed a moment ago, gone now: a concurrent release. Not an error,
                // and NOT counted - the store is telling us it no longer holds it.
                BlobStatus::NotFound => continue,
            };
            residency.blobs += 1;
            residency.bytes_uncompressed_nar += size;
        }
        Ok(residency)
    }

    /// Drop every tag protecting this provider's blobs and arm ONE garbage-collector
    /// sweep, so a store built with [`StoreRetention::ReleaseOnRequest`] genuinely
    /// REMOVES them. Returns the number of tags removed.
    ///
    /// Untagging without a sweep on a [`StoreRetention::RetainAll`] store leaves the
    /// content held (nothing sweeps) - which is itself an assertion the task-65
    /// residency test makes, because an oracle that reported the CALLER'S INTENT
    /// instead of the store's state would answer "released" here and would have
    /// proven nothing.
    ///
    /// This is the OPERATOR-DRIVEN release. The task-61 supply model's automatic
    /// one is [`StoreRetention::ReleaseAfterServe`], which arms the same sweep when
    /// the last in-flight serve finishes; this remains for a caller that wants to
    /// drop everything now.
    pub async fn release_all(&self) -> Result<u64, IrohError> {
        let removed = self
            .store
            .tags()
            .delete_all()
            .await
            .map_err(|e| IrohError::StoreQuery(format!("deleting tags: {e}")))?;
        // Arm AFTER untagging, so the armed sweep cannot run against a store whose
        // tags are still in place and conclude there is nothing to collect.
        self.gate.arm_sweep();
        Ok(removed)
    }

    /// Content-addressed "put": add the raw NAR bytes to the served store and
    /// return their [`Blake3Digest`] (the iroh-blobs blob hash, which equals our
    /// frozen addressed unit).
    ///
    /// THIS IS NOT THE SUPPLY MODEL. Task-61 decided a node regenerates on demand
    /// and holds nothing at rest ([`IrohProviderNode::spawn_supplying`] +
    /// [`NarSupplier`]);
    /// `seed` is the eager PUT that in-process tests use to put a known blob in
    /// front of a fetch. Under [`StoreRetention::ReleaseAfterServe`] a blob seeded
    /// this way is collectible once anything has been served, because it holds no
    /// tag - which is correct for that retention and wrong for what a test usually
    /// means, so pair `seed` with [`StoreRetention::RetainAll`].
    ///
    /// The `to_vec` here is the copy TASK-46 owns: the `&[u8]` signature forces it.
    /// The supply path (`materialise`) takes its `Vec<u8>` by value and does not
    /// pay it.
    pub async fn seed(&self, raw_nar: &[u8]) -> Result<Blake3Digest, IrohError> {
        let tag = self
            .store
            .add_bytes(raw_nar.to_vec())
            .await
            .map_err(|e| IrohError::Seed(e.to_string()))?;
        let digest = Blake3Digest::from_bytes(*tag.hash.as_bytes());
        // The iroh-blobs blob hash MUST equal our plain-unkeyed BLAKE3 recipe, or
        // the task-48 "content identity == blob hash" freeze is broken.
        debug_assert_eq!(
            digest,
            Blake3Digest::from_raw_nar(raw_nar),
            "iroh-blobs blob hash must equal BLAKE3(RawNarV1) (task-48 freeze)"
        );
        Ok(digest)
    }

    /// This provider's node identity (the locator a claim's `Iroh` offer carries).
    pub fn node_id(&self) -> Result<NodeId, IrohError> {
        self.endpoint.node_id().map_err(Into::into)
    }

    /// Every concrete socket reported by iroh for this provider. The addresses
    /// are exactly those selected by the node's explicit [`EndpointProfile`]. The
    /// harness selects IPv4 loopback from the closed offline-test profile; a real
    /// discovery mechanism must publish only addresses reachable in its network
    /// scope.
    pub fn bound_socket_addrs(&self) -> Result<Vec<SocketAddr>, IrohError> {
        self.endpoint.bound_socket_addrs().map_err(Into::into)
    }

    /// Concrete non-wildcard sockets suitable for direct discovery records.
    pub fn reachable_socket_addrs(&self) -> Result<Vec<SocketAddr>, IrohError> {
        self.endpoint.reachable_socket_addrs().map_err(Into::into)
    }

    /// This provider's endpoint address, assembled from its node id and every
    /// socket iroh reports as bound. This in-process stand-in carries the complete
    /// endpoint address selected by the explicit profile. A publisher crossing a
    /// process/network boundary must discard unspecified sockets and
    /// publish only reachable addresses, as the e2e harness does; task-40 owns the
    /// discovery result for a real `NodeId`.
    pub async fn addr(&self) -> Result<IrohPeerAddr, IrohError> {
        self.endpoint
            .endpoint_addr()
            .map(IrohPeerAddr)
            .map_err(Into::into)
    }
}

// -------------------------------------------------------------------------
// One node: shared runtime + optional provider + fetch handle.
// -------------------------------------------------------------------------

/// Composes provider/fetch/application protocols onto one runtime endpoint.
pub struct IrohNodeBuilder {
    runtime: IrohRuntimeBuilder,
    provider: Option<IrohProviderConfig>,
    envelope: SafetyEnvelope,
}

impl IrohNodeBuilder {
    pub fn new(
        profile: EndpointProfile,
        identity: IdentitySource,
        relay: RelayCapability,
        address_lookup: AddressLookupCapability,
    ) -> Result<Self, IrohError> {
        Ok(Self {
            runtime: IrohRuntimeBuilder::new(profile, identity, relay, address_lookup)?,
            provider: None,
            envelope: SafetyEnvelope::default(),
        })
    }

    /// The hermetic default for unit/integration tests and the benchmark.
    pub fn offline_ephemeral() -> Result<Self, IrohError> {
        Self::new(
            DAEMON_TEST_ENDPOINT_PROFILE,
            IdentitySource::Ephemeral,
            RelayCapability::Disabled,
            AddressLookupCapability::Disabled,
        )
    }

    pub fn provider(mut self, provider: IrohProviderConfig) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn safety_envelope(mut self, envelope: SafetyEnvelope) -> Self {
        self.envelope = envelope;
        self
    }

    pub fn node_publication(
        mut self,
        capability: NodePublicationCapability,
    ) -> Result<Self, IrohError> {
        self.runtime = self.runtime.node_publication(capability)?;
        Ok(self)
    }

    pub fn publication_startup_deadline(
        mut self,
        deadline: tokio::time::Instant,
    ) -> Result<Self, IrohError> {
        self.runtime = self.runtime.publication_startup_deadline(deadline)?;
        Ok(self)
    }

    /// Add an application handler to the same duplicate-checked router as
    /// iroh-blobs.
    pub fn accept(
        mut self,
        alpn: impl AsRef<[u8]>,
        handler: impl ProtocolHandler,
    ) -> Result<Self, IrohError> {
        self.runtime = self.runtime.accept(alpn, handler)?;
        Ok(self)
    }

    #[doc(hidden)]
    pub fn shutdown_deadline(mut self, deadline: Duration) -> Result<Self, IrohError> {
        self.runtime = self.runtime.shutdown_deadline(deadline)?;
        Ok(self)
    }

    pub async fn spawn(mut self) -> Result<IrohNode, IrohError> {
        let supervisor = self.runtime.task_supervisor_handle();
        let prepared = self
            .provider
            .take()
            .map(|provider| PreparedProvider::prepare(provider, supervisor))
            .transpose()?;
        if let Some(provider) = &prepared {
            self.runtime = self
                .runtime
                .accept(iroh_blobs::ALPN, provider.protocol.clone())?;
        }
        let runtime = self.runtime.spawn().await?;
        if let Some(provider) = &prepared
            && let Err(error) = provider
                .protocol
                .start(runtime.task_supervisor_handle())
                .await
        {
            let shutdown = runtime.shutdown().await;
            return Err(IrohError::Runtime(format!(
                "starting provider event driver after successful bind: {error}; cleanup={shutdown:?}"
            )));
        }
        let endpoint = runtime.endpoint_handle();
        let provider = prepared.map(|provider| Arc::new(provider.attach(endpoint.clone())));
        let transport = IrohTransport::attached(endpoint, self.envelope);
        Ok(IrohNode {
            provider,
            transport,
            runtime,
        })
    }
}

/// One long-lived Iroh node. All protocol handles share its identity and socket
/// set; only this owner can shut the runtime down.
pub struct IrohNode {
    provider: Option<Arc<IrohProvider>>,
    transport: IrohTransport,
    runtime: IrohNodeRuntime,
}

impl IrohNode {
    pub fn provider(&self) -> Option<&IrohProvider> {
        self.provider.as_deref()
    }

    pub fn provider_handle(&self) -> Option<Arc<IrohProvider>> {
        self.provider.clone()
    }

    pub fn transport(&self) -> &IrohTransport {
        &self.transport
    }

    pub fn transport_handle(&self) -> IrohTransport {
        self.transport.clone()
    }

    pub fn node_id(&self) -> Result<NodeId, IrohError> {
        self.runtime.node_id().map_err(Into::into)
    }

    pub fn bound_socket_addrs(&self) -> Result<Vec<SocketAddr>, IrohError> {
        self.runtime.bound_socket_addrs().map_err(Into::into)
    }

    pub fn task_supervisor_handle(&self) -> TaskSupervisorHandle {
        self.runtime.task_supervisor_handle()
    }

    pub fn node_publication_handle(&self) -> Option<NodePublicationHandle> {
        self.runtime.node_publication_handle()
    }

    /// Attach daemon-side work whose lifetime must not exceed the node.
    pub fn spawn_task(
        &self,
        name: impl Into<String>,
        future: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), IrohError> {
        self.task_supervisor_handle()
            .spawn(name, future)
            .map_err(Into::into)
    }

    pub async fn shutdown(self) -> Result<ShutdownOutcome, IrohError> {
        let Self {
            provider,
            transport,
            runtime,
        } = self;
        drop(provider);
        drop(transport);
        runtime.shutdown().await.map_err(Into::into)
    }
}

/// Explicit test/benchmark owner for a node with the blobs provider installed.
/// Deref preserves the provider-focused test API while endpoint ownership stays
/// visibly on this node wrapper, never on [`IrohProvider`].
pub struct IrohProviderNode(IrohNode);

impl IrohProviderNode {
    pub async fn spawn() -> Result<Self, IrohError> {
        Self::spawn_with_retention(StoreRetention::RetainAll).await
    }

    pub async fn spawn_with_retention(retention: StoreRetention) -> Result<Self, IrohError> {
        let node = IrohNodeBuilder::offline_ephemeral()?
            .provider(IrohProviderConfig::retaining(retention))
            .spawn()
            .await?;
        Ok(Self(node))
    }

    pub async fn spawn_supplying(
        supplier: Arc<dyn NarSupplier>,
        budget: ServeBudget,
        sweep_interval: Duration,
    ) -> Result<Self, IrohError> {
        let node = IrohNodeBuilder::offline_ephemeral()?
            .provider(IrohProviderConfig::supplying(
                supplier,
                budget,
                sweep_interval,
            ))
            .spawn()
            .await?;
        Ok(Self(node))
    }

    pub async fn spawn_with(
        retention: StoreRetention,
        budget: ServeBudget,
        supplier: Option<Arc<dyn NarSupplier>>,
    ) -> Result<Self, IrohError> {
        let node = IrohNodeBuilder::offline_ephemeral()?
            .provider(IrohProviderConfig::new(retention, budget, supplier))
            .spawn()
            .await?;
        Ok(Self(node))
    }

    pub fn transport(&self) -> &IrohTransport {
        self.0.transport()
    }

    pub async fn shutdown(self) -> Result<ShutdownOutcome, IrohError> {
        self.0.shutdown().await
    }
}

impl std::ops::Deref for IrohProviderNode {
    type Target = IrohProvider;

    fn deref(&self) -> &Self::Target {
        self.0
            .provider()
            .expect("provider-node construction always installs a provider")
    }
}

/// Explicit test owner for a fetch-only node.
pub struct IrohClientNode(IrohNode);

impl IrohClientNode {
    pub async fn spawn() -> Result<Self, IrohError> {
        Ok(Self(IrohNodeBuilder::offline_ephemeral()?.spawn().await?))
    }

    pub fn with_envelope(mut self, envelope: SafetyEnvelope) -> Self {
        self.0.transport.envelope = envelope;
        self
    }

    pub fn transport_handle(&self) -> IrohTransport {
        self.0.transport_handle()
    }

    pub async fn shutdown(self) -> Result<ShutdownOutcome, IrohError> {
        self.0.shutdown().await
    }
}

impl std::ops::Deref for IrohClientNode {
    type Target = IrohTransport;

    fn deref(&self) -> &Self::Target {
        self.0.transport()
    }
}

// -------------------------------------------------------------------------
// Client (node A): the Transport impl that fetches by BLAKE3 from a peer.
// -------------------------------------------------------------------------

/// The real iroh [`Transport`]: fetches through a shared node runtime endpoint.
/// It holds only a weak endpoint capability and cannot bind, retain or close the
/// node's socket independently.
#[derive(Clone)]
pub struct IrohTransport {
    endpoint: IrohEndpointHandle,
    /// `NodeId` -> dialable address. In production a discovery lookup fills this;
    /// here a test wires it via [`Self::add_peer`]. Behind a `Mutex` because
    /// [`Transport::fetch`] takes `&self`.
    peers: Arc<Mutex<HashMap<NodeId, EndpointAddr>>>,
    /// The task-51 safety envelope (dial / body-idle / total bounds). Default is
    /// the PROVISIONAL production envelope; a test pins short bounds via
    /// [`Self::with_envelope`].
    envelope: SafetyEnvelope,
}

impl IrohTransport {
    fn attached(endpoint: IrohEndpointHandle, envelope: SafetyEnvelope) -> Self {
        Self {
            endpoint,
            peers: Arc::new(Mutex::new(HashMap::new())),
            envelope,
        }
    }

    /// Replace the safety envelope (dial / body-idle / total time bounds). A test
    /// pins SHORT bounds to prove a dead/stalled peer yields a bounded abort without
    /// waiting the production seconds.
    pub fn with_envelope(mut self, envelope: SafetyEnvelope) -> Self {
        self.envelope = envelope;
        self
    }

    /// Observability only: the identity is owned by the runtime and disappears
    /// when that runtime shuts down.
    pub fn node_id(&self) -> Result<NodeId, IrohError> {
        self.endpoint.node_id().map_err(Into::into)
    }

    pub fn bound_socket_addrs(&self) -> Result<Vec<SocketAddr>, IrohError> {
        self.endpoint.bound_socket_addrs().map_err(Into::into)
    }

    pub fn reachable_socket_addrs(&self) -> Result<Vec<SocketAddr>, IrohError> {
        self.endpoint.reachable_socket_addrs().map_err(Into::into)
    }

    #[doc(hidden)]
    pub fn address_lookup_count(&self) -> Result<usize, IrohError> {
        self.endpoint.address_lookup_count().map_err(Into::into)
    }

    #[doc(hidden)]
    pub fn endpoint_capabilities(&self) -> Result<EndpointCapabilityState, IrohError> {
        self.endpoint.capability_state().map_err(Into::into)
    }

    /// Register a peer's dialable address (the discovery stand-in): a subsequent
    /// [`Transport::fetch`] for an `Iroh` offer naming this peer's `NodeId` can
    /// then dial it directly.
    pub fn add_peer(&self, addr: &IrohPeerAddr) {
        self.peers
            .lock()
            .expect("peers mutex")
            .insert(addr.node_id(), addr.0.clone());
    }

    /// AC#4 (deferred from the task-48 freeze): validate that a [`NodeId`]'s 32
    /// bytes are a real ed25519 curve point, using the pinned iroh key
    /// constructor. A non-point id is undiallable and must be rejected loudly, not
    /// silently dialled.
    pub fn validate_node_id(node: &NodeId) -> Result<(), IrohError> {
        PublicKey::from_bytes(node.as_bytes())
            .map(|_| ())
            .map_err(|e| IrohError::InvalidNodeId(e.to_string()))
    }

    /// The dial+stream, with the full task-51 envelope:
    ///   1. DIAL bounded by `envelope.dial_timeout` (dead-holder guard).
    ///   2. The body is STREAMED leaf-by-leaf (never buffered whole first), with:
    ///      - each stream step bounded by `envelope.body_idle_timeout` (stall guard);
    ///      - a running NarSize CAP: the moment cumulative bytes exceed
    ///        `expected_size` the stream is dropped and [`TransportError::TooLarge`]
    ///        returned, so a lying holder claiming a small NarSize but serving a huge
    ///        blob is cut off at ~NarSize, memory bounded (risk 6). The bound is the
    ///        SIGNED NarSize (uncompressed raw NAR) - the exact unit of the streamed
    ///        `RawNarV1` - NEVER the compressed FileSize.
    ///
    /// The whole thing is additionally wrapped in `envelope.total_timeout` by the
    /// caller as a coarse backstop.
    async fn dial_and_stream(
        envelope: SafetyEnvelope,
        content: Blake3Digest,
        connection: Connection,
        node: NodeId,
        expected_size: Option<u64>,
    ) -> Result<Vec<u8>, TransportError> {
        // STREAM by the exact BLAKE3 addressed unit. The runtime has already
        // bounded the dial and dropped its endpoint clone; this continuation can
        // own only the connection.
        //    verifies each leaf against `hash` as it arrives (gate 1, incremental).
        //    We drive it as a STREAM (not `.bytes()`, which buffers everything) so
        //    the NarSize cap can abort mid-transfer.
        let hash = Hash::from_bytes(*content.as_bytes());
        let mut stream = get_blob(connection, hash);
        let mut raw: Vec<u8> = Vec::new();
        loop {
            // Body-idle guard: no forward progress within the bound => stalled peer.
            let item = match tokio::time::timeout(envelope.body_idle_timeout, stream.next()).await {
                Ok(Some(item)) => item,
                Ok(None) => {
                    return Err(TransportError::Unavailable(format!(
                        "iroh stream from {node} ended before the blob completed"
                    )));
                }
                Err(_elapsed) => {
                    // Dropping `stream` (and its connection) here aborts the transfer.
                    return Err(TransportError::Unavailable(format!(
                        "iroh transfer from {node} stalled: no bytes for {:?}",
                        envelope.body_idle_timeout
                    )));
                }
            };

            match item {
                GetBlobItem::Item(BaoContentItem::Leaf(leaf)) => {
                    raw.extend_from_slice(&leaf.data);
                    // Running NarSize cap: abort the instant we exceed the signed
                    // bound. Memory is held to <= bound + one bao chunk, regardless
                    // of how large the lying blob actually is. Dropping `stream` at
                    // the return aborts the transfer; we never drain the rest.
                    if let Some(limit) = expected_size
                        && raw.len() as u64 > limit
                    {
                        return Err(TransportError::TooLarge {
                            limit,
                            streamed: raw.len() as u64,
                        });
                    }
                }
                // Parent (tree) nodes carry no leaf data - bao uses them to verify.
                GetBlobItem::Item(BaoContentItem::Parent(_)) => {}
                GetBlobItem::Done(_stats) => break,
                GetBlobItem::Error(cause) => {
                    return Err(TransportError::Unavailable(format!(
                        "iroh get_blob failed (holder cannot honestly serve {content}): {cause}"
                    )));
                }
            }
        }

        // Re-assert gate 1 with the daemon's single-source-of-truth recipe. bao
        // already enforced it on the wire; this makes the trait contract explicit
        // and non-vacuous (never return unverified bytes).
        verify_blake3(&content, &raw)?;
        Ok(raw)
    }
}

#[async_trait]
impl Transport for IrohTransport {
    fn tag(&self) -> TransportTag {
        TransportTag::Iroh
    }

    async fn fetch(
        &self,
        content: &Blake3Digest,
        offer: &KnownTransport,
        expected_size: Option<u64>,
    ) -> Result<Vec<u8>, TransportError> {
        // Defensive: the registry dispatches by tag, but a wrong variant is a bug
        // worth surfacing rather than silently mis-serving.
        let node = match offer {
            KnownTransport::Iroh { node } => node,
            other => {
                return Err(TransportError::WrongOffer {
                    expected: TransportTag::Iroh,
                    got: TransportTag::of(other),
                });
            }
        };

        // AC#4: reject a NodeId that is not a valid ed25519 curve point (it is
        // structurally 32 bytes, so only the curve check catches it) before dialing.
        Self::validate_node_id(node).map_err(|e| TransportError::Unavailable(e.to_string()))?;

        // Resolve the locator to a dialable address (discovery stand-in). No entry
        // means "no address known for this NodeId" - task-40 supplies it.
        let addr = self
            .peers
            .lock()
            .expect("peers mutex")
            .get(node)
            .cloned()
            .ok_or_else(|| {
                TransportError::Unavailable(format!(
                    "no known address for {node}; discovery (task-40) resolves NodeId->addr"
                ))
            })?;

        // Coarse total backstop over dial+transfer, on top of the finer-grained
        // dial and body-idle bounds inside `dial_and_stream`. A TooLarge abort from
        // the streaming cap propagates through unchanged (it is a deliberate abort,
        // not a hang the backstop should mask).
        let node = *node;
        let content = *content;
        let envelope = self.envelope;
        let operation = self.endpoint.run_connected(
            "iroh-outbound-fetch",
            addr,
            iroh_blobs::ALPN.to_vec(),
            envelope.dial_timeout,
            move |connection| async move {
                Self::dial_and_stream(envelope, content, connection, node, expected_size).await
            },
        );
        match tokio::time::timeout(envelope.total_timeout, operation).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(TransportError::Unavailable(format!(
                "shared Iroh runtime is unavailable: {error}"
            ))),
            Err(_elapsed) => Err(TransportError::Unavailable(format!(
                "iroh fetch from {node} exceeded total bound {:?}",
                envelope.total_timeout
            ))),
        }
    }
}

// -------------------------------------------------------------------------
// Shared endpoint construction and address conversion.
// -------------------------------------------------------------------------

/// The narrow integration seam shared with the raw-QUIC throughput example.
///
/// # Deliberate boundary exception
///
/// Product callers normally use [`IrohPeerAddr`], [`IrohProvider`] and
/// [`IrohTransport`] so iroh types remain opaque. Cargo examples are separate
/// crates, however, and the TASK-64 raw-QUIC arm must install a private ALPN on
/// the exact [`Endpoint`] construction path used by the daemon. This hidden
/// module therefore exposes [`Endpoint`] and [`EndpointAddr`] deliberately and
/// only for that measurement integration. Keeping the exception here makes the
/// endpoint builder and address conversion single sources of truth; it is not a
/// general transport API.
#[doc(hidden)]
pub mod endpoint_support {
    use iroh::{Endpoint, EndpointAddr};

    use super::{IrohError, IrohProvider};
    use crate::iroh_runtime::{self, AddressLookupCapability, IdentitySource, RelayCapability};

    pub use crate::iroh_runtime::{
        DAEMON_TEST_ENDPOINT_PROFILE as DAEMON_ENDPOINT_PROFILE, EndpointProfile, EndpointScope,
    };

    /// Bind through the same fully-explicit constructor as the node runtime,
    /// using an explicit ephemeral identity for the measurement process.
    pub async fn bind_endpoint(profile: EndpointProfile) -> Result<Endpoint, IrohError> {
        iroh_runtime::bind_endpoint(
            profile,
            IdentitySource::Ephemeral,
            RelayCapability::Disabled,
            AddressLookupCapability::Disabled,
        )
        .await
        .map_err(Into::into)
    }

    pub fn endpoint_addr(endpoint: &Endpoint) -> Result<EndpointAddr, IrohError> {
        iroh_runtime::endpoint_addr(endpoint).map_err(Into::into)
    }

    pub fn provider_addr(provider: &IrohProvider) -> Result<EndpointAddr, IrohError> {
        provider.endpoint.endpoint_addr().map_err(Into::into)
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::iroh_runtime::TaskSupervisor;

    #[tokio::test]
    async fn provider_is_fail_closed_until_driver_first_poll_acknowledges_ready() {
        let supervisor = TaskSupervisor::new();
        let prepared = PreparedProvider::prepare(
            IrohProviderConfig::retaining(StoreRetention::RetainAll),
            supervisor.handle(),
        )
        .expect("prepare provider");
        assert!(!prepared.protocol.tasks.is_ready());
        assert!(prepared.protocol.tasks.require_ready().is_err());
        assert_eq!(prepared.gate.counters().admitted, 0);
        assert_eq!(prepared.gate.counters().declined(), 0);

        prepared
            .protocol
            .start(supervisor.handle())
            .await
            .expect("first poll acknowledged");
        assert!(prepared.protocol.tasks.require_ready().is_ok());

        supervisor.cancel_now();
        tokio::task::yield_now().await;
        assert!(!prepared.protocol.tasks.is_ready());
    }
}
