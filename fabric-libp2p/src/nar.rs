//! The libp2p NAR byte-transfer protocol `/nix-p2p/<scope>/nar/1`: a libp2p
//! `request-response` protocol carried over the SAME [`Swarm`](crate::swarm) as the
//! kad+identify discovery behaviour (TASK-151). This module owns the WIRE codec, the
//! substrate-internal supply seam the server produces bytes through, and the task-72
//! admission gate that bounds what serving may cost.
//!
//! ## Two halves, one protocol
//!
//!   * FETCH ([`crate::transport::Libp2pTransport`]): send a 32-byte
//!     [`Blake3Digest`] request to a provider peer, receive the raw NAR bytes, and
//!     gate-1 BLAKE3-verify them against the requested digest before handing them up.
//!   * SERVE ([`crate::server::Libp2pServer`]): answer an inbound digest request from
//!     a substrate-internal [`Libp2pNarSupplier`], admitting it against a
//!     [`ServeBudget`] BEFORE producing any bytes (the peer-triggerable-OOM defense).
//!
//! ## Wire form (deliberately trivial, self-describing, length-capped)
//!
//! Request  = 32 raw digest bytes.
//! Response = 1 status byte, then:
//!   * `0` NotHeld — nothing follows.
//!   * `1` Nar — u64-LE length `n`, then `n` raw NAR bytes. `n` is rejected on the reader
//!     BEFORE allocation if it exceeds [`MAX_NAR_RESPONSE_BYTES`], so a lying length can
//!     never drive an unbounded allocation.
//!   * `2` Declined — 1 reason byte (for the caller's log; the fetch still fails).
//!
//! ## Honest scope (filed as follow-ups, not faked)
//!
//!   * BUFFERED, NOT STREAMED — and the buffer is bounded at the 256 MiB
//!     [`MAX_NAR_RESPONSE_BYTES`] hard cap, NOT at the per-call signed size. `fetch`
//!     reads the whole response (up to the cap) and then compares its length to
//!     `expected_size`, so a lying provider CAN force up to ~256 MiB of allocation and
//!     transfer regardless of the signed NarSize. The guarantee here is "never
//!     UNBOUNDED" (bounded at the cap), NOT "never buffers more than the signed size".
//!     A TRUE mid-stream abort at exactly `expected_size` needs the raw-stream transport
//!     — TASK-157.
//!   * INLINE PRODUCTION blocks the swarm poll loop. `ServeGate::respond` runs on the
//!     single worker and `produce()` is synchronous, so a serve does a full-NAR
//!     allocation/copy ON the poll thread — up to the per-NAR budget (256 MiB by
//!     default) — stalling kad/identify/every connection for its duration. Fine while
//!     the daemon wiring is absent and NARs are small; off-worker streamed production is
//!     TASK-157. Consequently the in-flight ceiling is vestigial this cycle (see
//!     [`ServeGate::respond`]) and `max_serve_duration` is not yet enforced.
//!   * A REAL node's store-dump / regular-file supplier ([`CatalogNarSupplier`] over the
//!     [`CatalogProbe`] digest->store-path seam, regenerating on demand via a supervised
//!     process group, mirroring `fabric-iroh`'s producer) LANDED in TASK-158 and is
//!     exercised directly by this module's tests. It is NOT yet wired into the shipped
//!     `daemon-libp2p` provider - that provider still stands up on the in-memory
//!     [`MemoryNarSupplier`] from `--libp2p-seed-nar` files (TASK-178). Replacing that
//!     with the store-dump supplier so a peer serves a `/nix/store` path it never held
//!     as a `.nar`, plus the container e2e, is TASK-191 (the daemon consumer of this
//!     capability; iroh analogue TASK-83). Note also that supervised Process production
//!     is async and does NOT run on the synchronous inline [`ServeGate::respond`] worker
//!     path this cycle; moving production off the poll loop is TASK-157.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use proc_supervisor::TaskSupervisorHandle;

use peer_fabric::{Blake3Digest, ServeBudget};

/// The absolute ceiling on a single NAR response the FETCH side will read off the
/// wire, whatever the per-call `expected_size`. It is the peer-triggerable-OOM floor: a
/// lying provider that declares a length over this is aborted BEFORE allocation.
///
/// It is pinned to the `peer_fabric` serve default single-NAR ceiling
/// ([`ServeBudget::default().max_nar_bytes_uncompressed_nar`] = 256 MiB), asserted by
/// `max_response_cap_tracks_the_serve_default` so the two cannot silently drift when
/// TASK-120 moves the authoritative ceiling. CAVEAT: because it is a FIXED const, it is
/// also a hard FUNCTIONAL ceiling on the fetch side - a node configured (via a larger
/// [`ServeBudget`]) to serve NARs bigger than this cannot be fetched over libp2p, and a
/// cold-start fetch (`expected_size == None`) of a > 256 MiB NAR hard-fails the codec.
/// Deriving the fetch cap from the negotiated per-call bound is part of TASK-157.
pub const MAX_NAR_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;

// Response status bytes.
const STATUS_NOT_HELD: u8 = 0;
const STATUS_NAR: u8 = 1;
const STATUS_DECLINED: u8 = 2;

/// Why a serve request was DECLINED before (or instead of) producing bytes. Carried on
/// the wire as a single reason byte purely for the caller's log; a decline always fails
/// the fetch (a corrupt/over-budget provider is skipped, never trusted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclineReason {
    /// The declared NAR size is over [`ServeBudget::max_nar_bytes_uncompressed_nar`].
    TooLarge,
    /// Admitting it would push in-flight bytes over the budget's in-flight ceiling.
    Busy,
    /// The supplier could not produce the bytes (a source error).
    SupplyFailed,
}

impl DeclineReason {
    fn wire(self) -> u8 {
        match self {
            DeclineReason::TooLarge => 0,
            DeclineReason::Busy => 1,
            DeclineReason::SupplyFailed => 2,
        }
    }

    fn from_wire(byte: u8) -> DeclineReason {
        // An unknown reason byte from an untrusted peer is coerced to SupplyFailed: the
        // decline fails the fetch either way, so the exact category is only advisory.
        match byte {
            0 => DeclineReason::TooLarge,
            1 => DeclineReason::Busy,
            _ => DeclineReason::SupplyFailed,
        }
    }
}

impl std::fmt::Display for DeclineReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DeclineReason::TooLarge => "declared NAR exceeds the serve per-NAR budget",
            DeclineReason::Busy => "serve in-flight budget is full",
            DeclineReason::SupplyFailed => "supplier could not produce the NAR",
        })
    }
}

/// A fetch request: the exact content identity the requester wants.
#[derive(Debug, Clone)]
pub struct NarRequest(pub Blake3Digest);

/// A fetch response. `Nar` carries the raw (uncompressed) NAR bytes; the requester
/// gate-1 BLAKE3-verifies them before use.
#[derive(Debug, Clone)]
pub enum NarResponse {
    /// The provider does not hold this content identity.
    NotHeld,
    /// The provider declined to serve it (over budget / supply error).
    Declined(DeclineReason),
    /// The raw NAR bytes.
    Nar(Vec<u8>),
}

/// The `request-response` codec for the NAR protocol. A unit struct: the protocol is
/// stateless per request, and the size cap is a const, so there is nothing to carry.
#[derive(Debug, Clone, Default)]
pub struct NarCodec;

async fn read_u64<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    io.read_exact(&mut buf).await?;
    Ok(u64::from_le_bytes(buf))
}

#[async_trait]
impl request_response::Codec for NarCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = NarRequest;
    type Response = NarResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut digest = [0u8; 32];
        io.read_exact(&mut digest).await?;
        Ok(NarRequest(Blake3Digest::from_bytes(digest)))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut status = [0u8; 1];
        io.read_exact(&mut status).await?;
        match status[0] {
            STATUS_NOT_HELD => Ok(NarResponse::NotHeld),
            STATUS_DECLINED => {
                let mut reason = [0u8; 1];
                io.read_exact(&mut reason).await?;
                Ok(NarResponse::Declined(DeclineReason::from_wire(reason[0])))
            }
            STATUS_NAR => {
                let len = read_u64(io).await?;
                // Reject a lying/oversized length BEFORE allocating: this is the
                // unbounded-OOM floor on the fetch side. The precise per-call
                // `expected_size` abort is enforced by the transport on top of this.
                if len > MAX_NAR_RESPONSE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "NAR response declares {len} bytes, over the {MAX_NAR_RESPONSE_BYTES} \
                             byte hard cap"
                        ),
                    ));
                }
                let mut bytes = vec![0u8; len as usize];
                io.read_exact(&mut bytes).await?;
                Ok(NarResponse::Nar(bytes))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown NAR response status byte {other}"),
            )),
        }
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        NarRequest(digest): Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(digest.as_bytes()).await?;
        io.flush().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match response {
            NarResponse::NotHeld => io.write_all(&[STATUS_NOT_HELD]).await?,
            NarResponse::Declined(reason) => {
                io.write_all(&[STATUS_DECLINED, reason.wire()]).await?
            }
            NarResponse::Nar(bytes) => {
                io.write_all(&[STATUS_NAR]).await?;
                io.write_all(&(bytes.len() as u64).to_le_bytes()).await?;
                io.write_all(&bytes).await?;
            }
        }
        io.flush().await
    }
}

// -------------------------------------------------------------------------
// The substrate-internal supply seam (below the peer_fabric seam, mirroring the
// fabric-iroh SEALED supplier decision from TASK-150).
// -------------------------------------------------------------------------

/// Where the server REGENERATES a raw NAR from (the task-61 "hold nothing at rest"
/// supply model, mirroring `fabric-iroh`'s `SupplySource`). Kept private so the source
/// shape stays a backend-internal detail, never crossing the `peer_fabric` seam.
///
/// A raw-NAR REGULAR FILE is deliberately NOT its own variant: it collapses into
/// [`NarSource::Process`] running a daemon-supplied helper (see [`CatalogNarSupplier`]),
/// exactly as `fabric-iroh`'s `IndexNarSupplier` folds `ProbedSource::RegularFile` into
/// a helper process. The reason is cancellation-safety, not taste: a plain in-process
/// file read can wedge uninterruptibly (D-state) on a broken FUSE/NFS mount, which no
/// userspace shutdown deadline can defeat, whereas an owned process group is killed and
/// reaped on shutdown.
enum NarSource {
    /// The raw NAR is already resident (test/inline supply).
    Memory(Arc<Vec<u8>>),
    /// Regenerate the raw NAR by running `program args` in an OWNED process group and
    /// taking its stdout (`nix-store --dump <path>`, or the raw-NAR helper for a
    /// regular file). Produced ONLY via [`NarSupplyPlan::produce_supervised`], so the
    /// child rides in a killable, reaped-on-shutdown job (AC#2).
    Process {
        program: PathBuf,
        args: Vec<OsString>,
        environment: Vec<(OsString, OsString)>,
    },
}

/// An inert supply plan: the admission `declared_size` learned WITHOUT producing bytes,
/// plus the source production is deferred to. Mirrors `fabric-iroh`'s `SupplyPlan`: the
/// declared size answers "how big, and do we have it?" so the budget can decline a huge
/// request having allocated nothing (task-72 GAP-1).
pub struct NarSupplyPlan {
    declared_size: u64,
    source: NarSource,
}

impl NarSupplyPlan {
    /// The uncompressed NAR size, for admission BEFORE any bytes are produced.
    ///
    /// DECLARED-SIZE-BEFORE-PRODUCE (AC#1): for a real node this value comes from the
    /// [`CatalogProbe`] - the daemon's persisted `NarSize` (TASK-82's verified
    /// `NarHashKey -> (StorePath, Blake3Digest, NarSize)` binding), an UNCOMPRESSED NAR
    /// byte count, NOT a compressed FileSize (the recurring unit trap). It is learned
    /// without running the dumper, so a peer that names a huge NAR is declined at
    /// admission having produced nothing.
    pub fn declared_size(&self) -> u64 {
        self.declared_size
    }

    /// Produce the raw NAR bytes on the SYNCHRONOUS inline swarm-worker path
    /// ([`ServeGate::respond`]). This cycle that path is Memory-only, matching the
    /// module's honest scope note: a real store-dump / regular-file source needs
    /// off-worker supervised async production ([`Self::produce_supervised`]), and wiring
    /// that into the worker's serve loop is the daemon end-to-end path (TASK-157 /
    /// TASK-169). A [`NarSource::Process`] reaching this path is therefore a wiring
    /// error, reported loudly rather than run un-supervised on the poll thread.
    fn produce(self) -> Result<Vec<u8>, String> {
        match self.source {
            NarSource::Memory(bytes) => Ok((*bytes).clone()),
            NarSource::Process { program, .. } => Err(format!(
                "a Process/RegularFile NAR source ({}) cannot be produced on the synchronous \
                 swarm-worker path; it requires supervised async production via \
                 NarSupplyPlan::produce_supervised (worker wiring is TASK-157 / the daemon \
                 store-dump serve path)",
                program.display()
            )),
        }
    }

    /// Produce the raw NAR bytes CANCELLATION-SAFELY (AC#2), regenerating on demand and
    /// holding nothing at rest (task-61). Consumes the plan: production happens exactly
    /// once, only after admission agreed to pay for `declared_size`.
    ///
    /// A [`NarSource::Process`] runs under `supervisor` in an OWNED process group
    /// (`proc_supervisor::TaskSupervisorHandle::execute_process`): on node shutdown or
    /// caller-abandonment the whole group is SIGKILLed and the child reaped, so a slow
    /// or wedged `nix-store --dump` can never survive as an unkillable worker. Its
    /// stdout is capped at `declared_size`, so a source that GREW past what admission
    /// reserved is rejected before it can allocate past the budget.
    ///
    /// SERVE-TIME INTEGRITY RECHECK (byte-integrity anchor, forward-carried from
    /// TASK-56/82): the produced bytes are checked `len == declared_size` AND
    /// `BLAKE3(RawNarV1) == content` before they are returned. A store path that was
    /// rebuilt, or a raw-NAR file that was replaced, since it was announced makes this
    /// fail LOUD - the node never ships the wrong bytes under the right name.
    pub async fn produce_supervised(
        self,
        supervisor: &TaskSupervisorHandle,
        content: &Blake3Digest,
    ) -> Result<Vec<u8>, String> {
        let declared = self.declared_size;
        let bytes = match self.source {
            NarSource::Memory(bytes) => (*bytes).clone(),
            NarSource::Process {
                program,
                args,
                environment,
            } => {
                let stdout_cap = usize::try_from(declared).map_err(|_| {
                    format!(
                        "declared size {declared} B for {content} exceeds this process's \
                         addressable output cap"
                    )
                })?;
                let output = supervisor
                    .execute_process(
                        "libp2p-nar-supplier-process",
                        program.clone(),
                        args,
                        environment,
                        stdout_cap,
                    )
                    .await
                    .map_err(|error| {
                        format!(
                            "supervising source process {} for {content}: {error}",
                            program.display()
                        )
                    })?;
                if output.stdout_exceeded_limit {
                    return Err(format!(
                        "source {} for {content} exceeded its reserved output cap of {declared} B",
                        program.display()
                    ));
                }
                if !output.status.success() {
                    return Err(format!(
                        "source process {} for {content} exited {}: {}",
                        program.display(),
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim()
                    ));
                }
                output.stdout
            }
        };
        // RECONCILE AGAINST WHAT ADMISSION RESERVED, not merely the per-NAR cap: a
        // source that declared 1 MiB and produced 200 MiB (still under the 256 MiB cap)
        // would otherwise slip through while the in-flight ledger still said 1 MiB.
        if bytes.len() as u64 != declared {
            return Err(format!(
                "{content} was admitted as {declared} B but its source produced {} B - the \
                 budget charged for a different NAR than it got",
                bytes.len()
            ));
        }
        // The byte-integrity anchor: never serve bytes that do not hash to the announced
        // content identity, whatever the source claimed.
        let produced = Blake3Digest::from_raw_nar(&bytes);
        if &produced != content {
            return Err(format!(
                "the source for {content} now hashes to {produced} - refusing to serve the \
                 wrong bytes under the right name"
            ));
        }
        Ok(bytes)
    }
}

/// The server's supply seam: "of this named digest, how big is it and how do I make
/// it?". NO ENUMERATION (PRD privacy invariant): a single per-digest probe, no `list` /
/// `iter` / `len`. Implemented by a real node over its availability catalog (TASK-158);
/// [`MemoryNarSupplier`] is the in-memory test double.
pub trait Libp2pNarSupplier: Send + Sync {
    /// Plan the supply of `content`; `None` iff this node cannot produce it.
    fn plan(&self, content: &Blake3Digest) -> Option<NarSupplyPlan>;
}

/// An in-memory [`Libp2pNarSupplier`] for tests and inline serving: a map of content
/// digest -> raw NAR bytes, with optional declared-size overrides so a test can model a
/// provider that LIES about its NAR size (to bite the task-72 admission gate).
pub struct MemoryNarSupplier {
    nars: std::collections::HashMap<Blake3Digest, Arc<Vec<u8>>>,
    declared_size_overrides: std::collections::HashMap<Blake3Digest, u64>,
}

impl MemoryNarSupplier {
    /// A supplier holding each NAR under its OWN honest content digest
    /// (`BLAKE3(RawNarV1)`), the normal case.
    pub fn new(nars: impl IntoIterator<Item = Vec<u8>>) -> Self {
        MemoryNarSupplier {
            nars: nars
                .into_iter()
                .map(|nar| (Blake3Digest::from_raw_nar(&nar), Arc::new(nar)))
                .collect(),
            declared_size_overrides: std::collections::HashMap::new(),
        }
    }

    /// Bind `bytes` under an ARBITRARY `content` digest, even one they do NOT hash to -
    /// a CORRUPT/LYING provider, so a test can prove the fetch side's gate-1 BLAKE3
    /// verify rejects the mismatch rather than trusting the bytes.
    pub fn insert_raw(&mut self, content: Blake3Digest, bytes: Vec<u8>) {
        self.nars.insert(content, Arc::new(bytes));
    }

    /// Make `content` DECLARE `bytes` at admission while its real bytes are a different
    /// size - to bite the task-72 declared-size-before-produce gate.
    pub fn set_declared_size(&mut self, content: Blake3Digest, bytes: u64) {
        self.declared_size_overrides.insert(content, bytes);
    }
}

impl Libp2pNarSupplier for MemoryNarSupplier {
    fn plan(&self, content: &Blake3Digest) -> Option<NarSupplyPlan> {
        let bytes = self.nars.get(content)?;
        let declared_size = self
            .declared_size_overrides
            .get(content)
            .copied()
            .unwrap_or(bytes.len() as u64);
        Some(NarSupplyPlan {
            declared_size,
            source: NarSource::Memory(Arc::clone(bytes)),
        })
    }
}

// -------------------------------------------------------------------------
// The digest -> store-path REVERSE-MAP seam (TASK-158): how a real node's
// availability catalog answers "of this content digest, how big is it and where do I
// regenerate it from?" WITHOUT the daemon leaking into `fabric-libp2p`.
// -------------------------------------------------------------------------

/// The daemon-internal argument that marks the raw-NAR helper invocation, and the env
/// guard that authorizes it. A [`ProbedSource::RegularFile`] is served by running the
/// daemon's own helper program (supplied to [`CatalogNarSupplier::new`]) as
/// `helper __dump-raw-nar <path>`, mirroring `fabric-iroh`'s convention so the two
/// backends drive the same daemon helper. The helper BINARY itself lives with the
/// daemon (this crate never dumps a file in-process - see [`NarSource`]); the daemon
/// end-to-end wiring is the follow-up that consumes this seam.
pub const RAW_NAR_HELPER_ARG: &str = "__dump-raw-nar";
const RAW_NAR_HELPER_ENV: &str = "DAEMON_INTERNAL_RAW_NAR_HELPER";
const RAW_NAR_HELPER_VALUE: &str = "v1";

fn raw_nar_helper_environment() -> Vec<(OsString, OsString)> {
    vec![(
        OsString::from(RAW_NAR_HELPER_ENV),
        OsString::from(RAW_NAR_HELPER_VALUE),
    )]
}

/// An inert supply record a [`CatalogProbe`] answers for ONE named digest: the
/// admission `declared_size` (learned WITHOUT producing bytes) and a source the node can
/// regenerate from on demand. The PUBLIC, substrate-neutral shape the daemon's catalog
/// fills; it deliberately mirrors the private [`NarSupplyPlan`]/[`NarSource`] without
/// exposing them (the same sealed decision `fabric-iroh` took with `ProbedSupply`).
pub struct ProbedSupply {
    /// Uncompressed NAR size for admission (task-72 GAP-1: size before production). For
    /// a store path this is the daemon's persisted `NarSize` (TASK-82); NOT a compressed
    /// FileSize (unit trap).
    pub declared_size: u64,
    /// How to regenerate the bytes on demand.
    pub source: ProbedSource,
}

/// Where a probed digest is regenerated from. DATA ONLY - no callback, lock guard, or
/// index handle - so the provider consumes it without reaching back into the daemon
/// catalog (the edge stays `daemon -> fabric-libp2p`, never the reverse).
pub enum ProbedSource {
    /// Run this program with these args in an owned process group; its stdout is the raw
    /// NAR. For a store path the daemon fills this with its `nix-store --dump <path>`
    /// invocation.
    Process {
        program: PathBuf,
        args: Vec<OsString>,
    },
    /// Dump this raw-NAR regular file verbatim (via the daemon's raw-NAR helper).
    RegularFile(PathBuf),
    /// The raw NAR is already in memory (test/inline supply).
    Memory(Arc<Vec<u8>>),
}

/// A read-only, CALLER-NAMED-digest probe of a supply catalog. The provider holds
/// `Arc<dyn CatalogProbe>` and NEVER names the daemon's concrete catalog types, so
/// `fabric-libp2p` carries no edge back to `daemon-core`; the daemon availability index
/// implements it over its inert catalog handle (TASK-82/146).
///
/// NO ENUMERATION (PRD privacy invariant): one caller-supplied digest -> optional
/// record. There is deliberately no `list` / `iter` / `len` - a peer may learn yes/no
/// about a digest it can already name, never what a node holds.
pub trait CatalogProbe: Send + Sync {
    /// Probe `content`; `Some` iff this node can currently regenerate it.
    fn probe(&self, content: &Blake3Digest) -> Option<ProbedSupply>;
}

/// The [`Libp2pNarSupplier`] a REAL node uses: an inert read-only supply catalog reached
/// through the [`CatalogProbe`] seam. Mirrors `fabric-iroh`'s `IndexNarSupplier`. The
/// provider can only serve what the availability writer already published; it cannot
/// derive, persist, announce, or enumerate the index.
///
/// The daemon end-to-end wiring that builds this over its `AvailabilityIndex` and serves
/// a real `/nix/store` (replacing the `--libp2p-seed-nar` `MemoryNarSupplier`) is
/// TASK-191; production through it is cancellation-safe via
/// [`NarSupplyPlan::produce_supervised`].
pub struct CatalogNarSupplier {
    catalog: Arc<dyn CatalogProbe>,
    /// The daemon's raw-NAR helper program, run for a [`ProbedSource::RegularFile`].
    helper_program: PathBuf,
}

impl CatalogNarSupplier {
    /// A supplier that regenerates through `catalog`, running `helper_program` for
    /// regular-file sources.
    pub fn new(catalog: impl CatalogProbe + 'static, helper_program: impl Into<PathBuf>) -> Self {
        CatalogNarSupplier {
            catalog: Arc::new(catalog),
            helper_program: helper_program.into(),
        }
    }
}

impl Libp2pNarSupplier for CatalogNarSupplier {
    fn plan(&self, content: &Blake3Digest) -> Option<NarSupplyPlan> {
        let record = self.catalog.probe(content)?;
        let source = match record.source {
            ProbedSource::Process { program, args } => NarSource::Process {
                program,
                args,
                environment: Vec::new(),
            },
            ProbedSource::RegularFile(path) => NarSource::Process {
                program: self.helper_program.clone(),
                args: vec![OsString::from(RAW_NAR_HELPER_ARG), path.into_os_string()],
                environment: raw_nar_helper_environment(),
            },
            ProbedSource::Memory(bytes) => NarSource::Memory(bytes),
        };
        Some(NarSupplyPlan {
            declared_size: record.declared_size,
            source,
        })
    }
}

// -------------------------------------------------------------------------
// The task-72 admission gate, driven on the swarm worker for each inbound request.
// -------------------------------------------------------------------------

/// What the admission gate has done since it started serving. Counters, not a log,
/// because the useful question ("is this node refusing work, and why") is a rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServeCounters {
    /// Requests admitted and served.
    pub admitted: u64,
    /// Declined: the declared NAR size is over the per-NAR budget.
    pub declined_too_large: u64,
    /// Declined: admitting it would exceed the in-flight budget.
    pub declined_busy: u64,
    /// Declined: neither held nor producible (the supplier said `None`).
    pub declined_unknown: u64,
    /// Declined: the supplier knew the digest but could not produce the bytes.
    pub declined_supply_failed: u64,
    /// Requests answered NotHeld because the session had stopped admitting (the
    /// [`ServeHandle`](peer_fabric::ServeHandle) was dropped).
    pub refused_stopped: u64,
}

/// The admission gate: the budget, the supplier, and what is in flight. Shared (via
/// [`Arc`]) between the swarm worker (which calls [`respond`](ServeGate::respond) on
/// each inbound request) and the serve teardown guard (which flips
/// [`stop`](ServeGate::stop)).
pub struct ServeGate {
    budget: ServeBudget,
    supplier: Arc<dyn Libp2pNarSupplier>,
    /// Cleared by the serve teardown guard's `Drop`: the SYNCHRONOUS stop-admitting
    /// signal. Once `false`, [`respond`](ServeGate::respond) answers `NotHeld` without
    /// consulting the supplier, so dropping the handle stops admission the instant it
    /// runs, independent of the (best-effort, async) worker uninstall command.
    active: AtomicBool,
    /// The single source of truth for in-flight bytes. Reserved BEFORE production and
    /// released after, so the in-flight ceiling is checked against real reservations.
    inflight_bytes: AtomicU64,
    admitted: AtomicU64,
    declined_too_large: AtomicU64,
    declined_busy: AtomicU64,
    declined_unknown: AtomicU64,
    declined_supply_failed: AtomicU64,
    refused_stopped: AtomicU64,
}

impl ServeGate {
    /// A gate serving `supplier` under `budget`, admitting until [`stop`](Self::stop).
    pub fn new(budget: ServeBudget, supplier: Arc<dyn Libp2pNarSupplier>) -> Self {
        // Destructure the seam budget EXHAUSTIVELY (mirroring fabric-iroh's
        // ServeBudget::from_seam) so a new `peer_fabric::ServeBudget` field fails THIS
        // build rather than being silently unenforced by the gate. NOTE (honest scope):
        // `max_serve_duration` is NOT yet enforced here - inline production is
        // instantaneous, so there is no long-lived reservation to time out; it comes
        // alive with off-worker streamed production (TASK-157).
        let ServeBudget {
            max_nar_bytes_uncompressed_nar: _,
            max_inflight_bytes_uncompressed_nar: _,
            max_serve_duration: _,
        } = budget;
        ServeGate {
            budget,
            supplier,
            active: AtomicBool::new(true),
            inflight_bytes: AtomicU64::new(0),
            admitted: AtomicU64::new(0),
            declined_too_large: AtomicU64::new(0),
            declined_busy: AtomicU64::new(0),
            declined_unknown: AtomicU64::new(0),
            declined_supply_failed: AtomicU64::new(0),
            refused_stopped: AtomicU64::new(0),
        }
    }

    /// Stop admitting new requests (the synchronous teardown signal). Idempotent.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
    }

    /// A snapshot of the admission counters.
    pub fn counters(&self) -> ServeCounters {
        ServeCounters {
            admitted: self.admitted.load(Ordering::Relaxed),
            declined_too_large: self.declined_too_large.load(Ordering::Relaxed),
            declined_busy: self.declined_busy.load(Ordering::Relaxed),
            declined_unknown: self.declined_unknown.load(Ordering::Relaxed),
            declined_supply_failed: self.declined_supply_failed.load(Ordering::Relaxed),
            refused_stopped: self.refused_stopped.load(Ordering::Relaxed),
        }
    }

    /// Admit and answer one inbound request. THE DECLARED SIZE IS CHECKED BEFORE ANY
    /// BYTES ARE PRODUCED (task-72 GAP-1): a request over budget costs a plan lookup,
    /// not an allocation. Runs on the swarm worker, so production is inline this cycle
    /// (bounded by the per-NAR budget); off-worker streamed production is TASK-157.
    pub fn respond(&self, content: &Blake3Digest) -> NarResponse {
        if !self.active.load(Ordering::Acquire) {
            self.refused_stopped.fetch_add(1, Ordering::Relaxed);
            return NarResponse::NotHeld;
        }
        let Some(plan) = self.supplier.plan(content) else {
            self.declined_unknown.fetch_add(1, Ordering::Relaxed);
            return NarResponse::NotHeld;
        };
        let declared = plan.declared_size();
        if declared > self.budget.max_nar_bytes_uncompressed_nar {
            self.declined_too_large.fetch_add(1, Ordering::Relaxed);
            return NarResponse::Declined(DeclineReason::TooLarge);
        }
        // The in-flight ceiling. HONEST LIMIT: this cycle `respond` runs only on the
        // single swarm worker and `produce()` is synchronous, so requests are strictly
        // serialized and `held` is always 0 here - the in-flight decline is effectively
        // vestigial (it reduces to a weaker restatement of the per-NAR check). It is
        // written as a real reservation so it BINDS the moment TASK-157 moves production
        // off the worker.
        // TASK-157: this load-then-add is NOT an atomic reserve; it is a TOCTOU that is
        // safe ONLY because respond() is serialized on the worker. When production moves
        // off-worker, replace it with a CAS loop or a mutex-guarded reserve (the iroh
        // model) or two concurrent admits will both pass and blow past the ceiling.
        let held = self.inflight_bytes.load(Ordering::Acquire);
        if held.saturating_add(declared) > self.budget.max_inflight_bytes_uncompressed_nar {
            self.declined_busy.fetch_add(1, Ordering::Relaxed);
            return NarResponse::Declined(DeclineReason::Busy);
        }
        // Reserve before producing; release after. The reservation is what the
        // in-flight ceiling is measured against.
        self.inflight_bytes.fetch_add(declared, Ordering::AcqRel);
        let response = match plan.produce() {
            Ok(bytes) => {
                self.admitted.fetch_add(1, Ordering::Relaxed);
                NarResponse::Nar(bytes)
            }
            Err(why) => {
                tracing::warn!(%content, %why, "libp2p serve: supplier failed to produce NAR");
                self.declined_supply_failed.fetch_add(1, Ordering::Relaxed);
                NarResponse::Declined(DeclineReason::SupplyFailed)
            }
        };
        self.inflight_bytes.fetch_sub(declared, Ordering::AcqRel);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn budget(max_nar: u64, max_inflight: u64) -> ServeBudget {
        ServeBudget {
            max_nar_bytes_uncompressed_nar: max_nar,
            max_inflight_bytes_uncompressed_nar: max_inflight,
            max_serve_duration: Duration::from_secs(120),
        }
    }

    #[test]
    fn max_response_cap_tracks_the_serve_default() {
        // SSOT tripwire: the fetch-side hard cap must equal the authoritative serve
        // per-NAR default, or an honest node could serve a NAR a peer cannot fetch.
        // If TASK-120 moves the default, this fails until MAX_NAR_RESPONSE_BYTES follows.
        assert_eq!(
            MAX_NAR_RESPONSE_BYTES,
            ServeBudget::default().max_nar_bytes_uncompressed_nar
        );
    }

    #[test]
    fn respond_serves_a_held_nar() {
        let nar = b"a small raw nar".to_vec();
        let content = Blake3Digest::from_raw_nar(&nar);
        let supplier = Arc::new(MemoryNarSupplier::new([nar.clone()]));
        let gate = ServeGate::new(budget(1 << 20, 1 << 30), supplier);
        match gate.respond(&content) {
            NarResponse::Nar(bytes) => assert_eq!(bytes, nar),
            other => panic!("expected Nar, got {other:?}"),
        }
        assert_eq!(gate.counters().admitted, 1);
    }

    #[test]
    fn respond_notheld_for_unknown_digest() {
        let supplier = Arc::new(MemoryNarSupplier::new([b"held".to_vec()]));
        let gate = ServeGate::new(budget(1 << 20, 1 << 30), supplier);
        let unknown = Blake3Digest::from_bytes([0x11; 32]);
        assert!(matches!(gate.respond(&unknown), NarResponse::NotHeld));
        assert_eq!(gate.counters().declined_unknown, 1);
    }

    #[test]
    fn admission_declines_over_per_nar_budget_before_producing() {
        // THE task-72 GAP-1 BITE: a NAR whose DECLARED size is over the per-NAR budget
        // is declined WITHOUT producing. The supplier declares a huge size while holding
        // tiny bytes; the decline must fire on the declared size, not on production.
        let nar = b"tiny".to_vec();
        let content = Blake3Digest::from_raw_nar(&nar);
        let mut supplier = MemoryNarSupplier::new([nar]);
        supplier.set_declared_size(content, 10 * 1024 * 1024); // declares 10 MiB
        let gate = ServeGate::new(budget(1 << 20, 1 << 30), Arc::new(supplier)); // 1 MiB cap
        assert!(matches!(
            gate.respond(&content),
            NarResponse::Declined(DeclineReason::TooLarge)
        ));
        let c = gate.counters();
        assert_eq!(c.declined_too_large, 1);
        assert_eq!(c.admitted, 0, "nothing was produced");
    }

    #[test]
    fn stopped_gate_refuses_admission() {
        let nar = b"held after stop".to_vec();
        let content = Blake3Digest::from_raw_nar(&nar);
        let gate = ServeGate::new(
            budget(1 << 20, 1 << 30),
            Arc::new(MemoryNarSupplier::new([nar])),
        );
        gate.stop();
        assert!(matches!(gate.respond(&content), NarResponse::NotHeld));
        assert_eq!(gate.counters().refused_stopped, 1);
        assert_eq!(gate.counters().admitted, 0);
    }

    // -------------------------------------------------------------------------
    // TASK-158: the real-node store-dump / regular-file supplier, cancellation-safe.
    // -------------------------------------------------------------------------

    use proc_supervisor::TaskSupervisor;

    /// A unique-per-run temp path (no external tempdir dep; mirrors the iroh tests).
    fn unique_temp(stem: &str) -> PathBuf {
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(format!("nix-p2p-task158-{stem}-{suffix}"))
    }

    /// A one-content [`CatalogProbe`] that hands back a fixed [`ProbedSupply`], so a test
    /// can drive `plan` / `produce_supervised` without the daemon catalog.
    struct OneProbe {
        content: Blake3Digest,
        declared_size: u64,
        make: Box<dyn Fn() -> ProbedSource + Send + Sync>,
    }

    impl CatalogProbe for OneProbe {
        fn probe(&self, content: &Blake3Digest) -> Option<ProbedSupply> {
            (content == &self.content).then(|| ProbedSupply {
                declared_size: self.declared_size,
                source: (self.make)(),
            })
        }
    }

    /// AC#1 (declared-size-before-produce + no dump at plan time). The dumper program
    /// TOUCHES a marker when it runs; `plan()` must learn the declared size WITHOUT
    /// running it (marker absent), and only `produce_supervised()` regenerates the exact
    /// bytes (marker present). BITE: make `plan()` run the dumper to learn the size and
    /// the "marker absent after plan" assertion fails.
    #[tokio::test]
    async fn process_plan_learns_declared_size_without_running_the_dumper() {
        let marker = unique_temp("dump-marker");
        let _ = std::fs::remove_file(&marker);
        let body = b"hello raw nar body produced on demand".to_vec();
        let content = Blake3Digest::from_raw_nar(&body);
        let body_str = String::from_utf8(body.clone()).unwrap();
        let script = format!("touch \"$1\"; printf %s '{body_str}'");
        let program = PathBuf::from("sh");
        let args = vec![
            OsString::from("-c"),
            OsString::from(script),
            OsString::from("sh"),
            marker.clone().into_os_string(),
        ];
        let probe = OneProbe {
            content,
            declared_size: body.len() as u64,
            make: Box::new(move || ProbedSource::Process {
                program: program.clone(),
                args: args.clone(),
            }),
        };
        let supplier = CatalogNarSupplier::new(probe, "unused-helper");

        let plan = supplier.plan(&content).expect("probe supplies the content");
        assert_eq!(
            plan.declared_size(),
            body.len() as u64,
            "declared size comes from the probe, not a dump"
        );
        assert!(
            !marker.exists(),
            "plan() must NOT run the dumper to learn the size (declared-size-before-produce)"
        );

        let supervisor = TaskSupervisor::new();
        let produced = plan
            .produce_supervised(&supervisor.handle(), &content)
            .await
            .expect("produce regenerates the bytes");
        assert_eq!(
            produced, body,
            "produce_supervised regenerates the exact NAR"
        );
        assert!(
            marker.exists(),
            "produce_supervised actually ran the dumper"
        );
        let _ = std::fs::remove_file(&marker);
    }

    /// AC#1 (RegularFile source round-trips a raw NAR without holding it at rest). The
    /// file is dumped by a helper PROCESS (never an in-process read - see `NarSource`),
    /// and the produced bytes hash back to the announced content.
    #[tokio::test]
    async fn regular_file_source_round_trips_via_helper_process() {
        use std::os::unix::fs::PermissionsExt;

        let body = b"a raw nar regular file, streamed on demand and not held".to_vec();
        let content = Blake3Digest::from_raw_nar(&body);
        let nar_path = unique_temp("file.nar");
        std::fs::write(&nar_path, &body).unwrap();
        // The daemon's raw-NAR helper is `helper __dump-raw-nar <path>`; here a tiny
        // script that ignores $1 (the marker arg) and cats $2 (the path) stands in.
        let helper = unique_temp("dump-helper.sh");
        std::fs::write(&helper, "#!/bin/sh\nexec cat \"$2\"\n").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();

        let file_path = nar_path.clone();
        let probe = OneProbe {
            content,
            declared_size: body.len() as u64,
            make: Box::new(move || ProbedSource::RegularFile(file_path.clone())),
        };
        let supplier = CatalogNarSupplier::new(probe, helper.clone());

        let plan = supplier.plan(&content).expect("probe supplies the file");
        assert_eq!(plan.declared_size(), body.len() as u64);
        let supervisor = TaskSupervisor::new();
        let produced = plan
            .produce_supervised(&supervisor.handle(), &content)
            .await
            .expect("regular-file round-trip");
        assert_eq!(produced, body);
        let _ = std::fs::remove_file(&nar_path);
        let _ = std::fs::remove_file(&helper);
    }

    /// AC#1 (serve-time integrity anchor). A source that produces bytes NOT hashing to
    /// the announced content must fail LOUD, never ship the wrong bytes under a right
    /// name (a store path rebuilt / a raw-NAR file replaced since announce).
    #[tokio::test]
    async fn produce_rejects_bytes_that_do_not_hash_to_the_announced_content() {
        let announced = b"the bytes that were announced".to_vec();
        let content = Blake3Digest::from_raw_nar(&announced);
        // The dumper prints DIFFERENT bytes of the SAME length (so the size guard passes
        // and only the BLAKE3 recheck can catch it).
        let changed = b"the bytes that got changed!!!".to_vec();
        assert_eq!(announced.len(), changed.len());
        let changed_str = String::from_utf8(changed.clone()).unwrap();
        let program = PathBuf::from("sh");
        let args = vec![
            OsString::from("-c"),
            OsString::from(format!("printf %s '{changed_str}'")),
        ];
        let probe = OneProbe {
            content,
            declared_size: announced.len() as u64,
            make: Box::new(move || ProbedSource::Process {
                program: program.clone(),
                args: args.clone(),
            }),
        };
        let supplier = CatalogNarSupplier::new(probe, "unused-helper");
        let plan = supplier.plan(&content).unwrap();
        let supervisor = TaskSupervisor::new();
        let error = plan
            .produce_supervised(&supervisor.handle(), &content)
            .await
            .expect_err("bytes that do not hash to the announced content are rejected");
        assert!(
            error.contains("now hashes to"),
            "expected a byte-integrity rejection, got: {error}"
        );
    }

    /// AC#2 (cancellation-safety: the process GROUP is reaped on shutdown, no unkillable
    /// worker). A supervised producer starts a blocking `sh` that spawns a grandchild;
    /// once the job is live, node cancel must SIGKILL and reap the whole group. The reap
    /// oracle is the registry: a job is removed only after its worker proves the group is
    /// child-free. BITE: run the producer UN-supervised (a raw detached spawn instead of
    /// `execute_process`) and the grandchild survives cancel - the `/proc/<pid>` and
    /// `active_len()==0` assertions fail. BOUNDED: one spawn + one reap.
    #[tokio::test]
    async fn supervised_process_source_is_reaped_on_cancel() {
        let pid_file = unique_temp("reap-pids");
        let _ = std::fs::remove_file(&pid_file);
        let content = Blake3Digest::from_bytes([0x5a; 32]);
        let program = PathBuf::from("sh");
        let script = "(while :; do sleep 0.05; done) & grand=$!; printf '%s %s' \"$$\" \"$grand\" > \"$1\"; wait";
        let pid_file_arg = pid_file.clone();
        let probe = OneProbe {
            content,
            declared_size: 1 << 20, // never reached; the process is cancelled first
            make: Box::new(move || ProbedSource::Process {
                program: PathBuf::from("sh"),
                args: vec![
                    OsString::from("-c"),
                    OsString::from(script),
                    OsString::from("reaper-helper"),
                    pid_file_arg.clone().into_os_string(),
                ],
            }),
        };
        let _ = program; // documents the source program; the probe rebuilds it per call
        let supplier = CatalogNarSupplier::new(probe, "unused-helper");
        let plan = supplier.plan(&content).unwrap();

        let supervisor = TaskSupervisor::new();
        let handle = supervisor.handle();
        let probe_content = content;
        let op =
            tokio::spawn(async move { plan.produce_supervised(&handle, &probe_content).await });

        // Wait until the helper AND grandchild published their pids and the job is live.
        let pids = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(raw) = std::fs::read_to_string(&pid_file)
                    && raw.split_whitespace().count() == 2
                    && supervisor.process_jobs().active_len() == 1
                {
                    break raw;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the supervised process group started and published its pids");
        let pids = pids
            .split_whitespace()
            .map(|raw| raw.parse::<u32>().expect("decimal pid"))
            .collect::<Vec<_>>();

        // Node shutdown: SIGKILL the group and reap.
        supervisor.cancel_now();

        // The reap oracle: the job leaves the registry only after it proved the group is
        // child-free.
        tokio::time::timeout(Duration::from_secs(3), async {
            while supervisor.process_jobs().active_len() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the process job was reaped and left the registry");

        let produced = op.await.expect("producer task joined");
        assert!(
            produced.is_err(),
            "a cancelled supervised produce fails rather than returning bytes"
        );

        for pid in pids {
            assert!(
                !PathBuf::from(format!("/proc/{pid}")).exists(),
                "supervised pid {pid} (or its grandchild) survived node cancel - an orphan"
            );
        }
        let _ = std::fs::remove_file(&pid_file);
    }
}
