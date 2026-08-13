//! The libp2p NAR byte-transfer protocol `/nix-p2p/<scope>/nar/2`: a RAW libp2p-stream
//! protocol (`AsyncRead`/`AsyncWrite` per call, TASK-157) carried over the SAME
//! [`Swarm`](crate::swarm) as the kad+identify discovery behaviour. It REPLACES the
//! original request-response carrier (TASK-151, protocol `/nar/1`), which buffered the
//! whole NAR: bytes now FLOW as a stream, so the fetcher aborts mid-transfer at exactly
//! the signed size and the server streams produced bytes OFF the poll loop. This module
//! owns the WIRE framing ([`write_request`] / [`read_response_streamed`] / [`serve_stream`]),
//! the substrate-internal supply seam the server produces bytes through, and the task-72
//! admission gate that bounds what serving may cost.
//!
//! ## Two halves, one protocol
//!
//!   * FETCH ([`crate::transport::Libp2pTransport`]): open a stream to a provider peer,
//!     send a 32-byte [`Blake3Digest`] request, then STREAM the raw NAR bytes back with a
//!     mid-stream size abort ([`read_response_streamed`], AC#1) and an inter-chunk idle
//!     bound (AC#2), gate-1 BLAKE3-verifying them against the requested digest.
//!   * SERVE ([`crate::server::Libp2pServer`]): answer an inbound digest request from a
//!     substrate-internal [`Libp2pNarSupplier`] on a task OFF the poll loop
//!     ([`serve_stream`], AC#3), admitting it against a [`ServeBudget`] BEFORE producing
//!     any bytes (the peer-triggerable-OOM defense).
//!
//! The concrete wire form is documented on the raw-stream wire functions below.
//!
//! ## Honest scope (filed as follow-ups, not faked)
//!
//!   * GATE-1 GRANULARITY. The SIZE abort is truly mid-stream (AC#1), but per-CHUNK
//!     byte-corruption detection (a flipped byte caught before EOF, as iroh-blobs' bao
//!     does) needs a bao outboard tree interleaved on the wire; this transport carries the
//!     raw NAR alone, so BYTE corruption is caught at stream completion via the frozen
//!     [`Blake3Digest::from_raw_nar`] recipe (single pass, memory bounded to the size cap +
//!     one chunk), never after a second full buffer-and-rehash. The trust property holds -
//!     a corrupt peer fails the fetch - only the detection is at EOF, not per chunk. TASK-197.
//!   * SERVE PRODUCTION still BUFFERS the produced NAR before streaming it out, because the
//!     serve-time integrity recheck (`len == declared_size` AND `BLAKE3(RawNarV1) == content`,
//!     "never ship the wrong bytes under the right name") must complete BEFORE any byte is
//!     shipped. The bytes reach the fetcher as a true stream; producing them by piping a
//!     `nix-store --dump` stdout STRAIGHT to the socket (no serve-side buffer) would need
//!     the same bao outboard so the recheck can be incremental. TASK-197 (same follow-up).
//!   * PRODUCTION PLACEMENT (TASK-193, now extended). A [`NarSource::Process`] (store-dump /
//!     raw-NAR helper) is produced OFF the poll loop; with libp2p-stream the ENTIRE inbound
//!     serve - including the Memory inline case - runs on a spawned per-stream task
//!     ([`serve_stream`]), so nothing but connection muxing touches the poll loop. A Process
//!     reservation is held across the off-loop await (the in-flight ceiling BINDS via a CAS
//!     reserve), production is RACED against the consumer hanging up (a dropped stream reaps
//!     the supervised group), and `max_serve_duration` is now ENFORCED as a real serve
//!     deadline around production ([`ServeGate::produce_admitted`]).
//!   * A REAL node's store-dump / regular-file supplier ([`CatalogNarSupplier`] over the
//!     [`CatalogProbe`] digest->store-path seam, regenerating on demand via a supervised
//!     process group, mirroring `fabric-iroh`'s producer) LANDED in TASK-158 and is
//!     exercised directly by this module's tests. It is NOT yet wired into the shipped
//!     `daemon-libp2p` provider - that provider still stands up on the in-memory
//!     [`MemoryNarSupplier`] from `--libp2p-seed-nar` files (TASK-178). Replacing that
//!     with the store-dump supplier so a peer serves a `/nix/store` path it never held
//!     as a `.nar`, plus the container e2e, is TASK-191 (the daemon consumer of this
//!     capability; iroh analogue TASK-83). Supervised Process production is reachable from
//!     the shipped serve loop OFF the poll thread (TASK-193) and now streams to the fetcher
//!     over the raw-stream transport (TASK-157).

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use proc_supervisor::TaskSupervisorHandle;

use peer_fabric::{Blake3Digest, ServeBudget, TransferError};

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
/// cold-start fetch (`expected_size == None`) of a > 256 MiB NAR hard-fails. Since TASK-157
/// the fetch is a true stream: when the caller SIGNED an `expected_size` the running abort
/// caps at exactly that (this const is only the floor for the cold-start `None` case), so a
/// lying provider is cut off at the signed size, never at this 256 MiB const.
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

/// A fetch response the [`ServeGate`] produces for one inbound request. `Nar` carries the
/// raw (uncompressed) NAR bytes; the requester gate-1 BLAKE3-verifies them before use.
/// This is the SERVER-SIDE outcome type; on the wire it is framed by [`write_response`].
#[derive(Debug, Clone)]
pub enum NarResponse {
    /// The provider does not hold this content identity.
    NotHeld,
    /// The provider declined to serve it (over budget / supply error).
    Declined(DeclineReason),
    /// The raw NAR bytes.
    Nar(Vec<u8>),
}

// -------------------------------------------------------------------------
// The RAW-STREAM NAR wire (TASK-157): replaces the request-response codec so bytes flow
// as a stream, not a buffered request/response. The ADDRESSED UNIT on the wire is
// unchanged - the exact `RawNarV1` bytes keyed by BLAKE3 - only the framing that MOVES
// them peer to peer changed (the churnable transport layer, not a frozen surface).
//
// Wire form (over one raw substream of `/nix-p2p/<scope>/nar/2`):
//   Request  = 32 raw digest bytes; the requester then KEEPS its write half OPEN for the
//              whole transfer (it is the "still interested" signal the server races
//              production against - see `serve_stream`), closing only when done reading.
//   Response = 1 status byte, then:
//     * `0` NotHeld  - nothing follows; the server closes its write half.
//     * `1` Nar      - the raw NAR bytes STREAMED to EOF (NO length prefix, mirroring
//                      fabric-iroh's bao stream): the reader counts bytes as they arrive
//                      and aborts the INSTANT cumulative bytes exceed the per-call bound,
//                      so a lying provider is cut off at ~expected_size, never after
//                      buffering the whole thing. The server closes its write half at the
//                      end; that EOF is how the reader knows the NAR is complete.
//     * `2` Declined - 1 reason byte (for the caller's log; the fetch still fails).
// -------------------------------------------------------------------------

/// The chunk the fetch read loop pulls per step. The running size cap is enforced AFTER
/// each chunk, so peak fetch memory is bounded by `expected_size + NAR_STREAM_CHUNK` (the
/// "bound + one chunk" property fabric-iroh states for its bao leaf).
const NAR_STREAM_CHUNK: usize = 64 * 1024;

/// The serve-side exchange deadline used when this node is NOT serving (no [`ServeGate`] to
/// source `max_serve_duration` from): a slowloris guard so a peer that opens a `/nar/2`
/// stream and then never sends its request digest - or never reads the `NotHeld` reply -
/// cannot park a serve task forever. A serving node uses its
/// [`ServeBudget::max_serve_duration`] instead (see [`serve_stream`]).
const UNSERVED_STREAM_DEADLINE: Duration = Duration::from_secs(30);

/// Send a fetch REQUEST on an opened outbound stream: the 32-byte content digest, flushed.
/// Deliberately does NOT close the write half - the open write half is the requester's
/// "still interested" signal the server watches, so closing it early would look like an
/// abandoned request (see [`serve_stream`]).
pub(crate) async fn write_request<W>(writer: &mut W, content: &Blake3Digest) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(content.as_bytes()).await?;
    writer.flush().await
}

/// Read a fetch RESPONSE off an inbound stream with the full task-51 envelope, mirroring
/// fabric-iroh's `dial_and_stream` (the gate-1 streaming-decode contract):
///
///   * INTER-CHUNK IDLE BOUND (AC#2): every read - the status byte and each body chunk -
///     is bounded by `body_idle_timeout`; no forward progress within it is a stalled peer,
///     aborted distinctly from the transport-level `total_timeout`.
///   * MID-STREAM SIZE ABORT (AC#1): the body is streamed chunk by chunk and the moment
///     cumulative bytes exceed the running cap - `expected_size` when the caller signed one,
///     else the [`MAX_NAR_RESPONSE_BYTES`] unbounded-OOM floor - the stream is DROPPED and
///     [`TransferError::TooLarge`] returned. A provider that streams MORE than declared is
///     cut off at ~cap, never after 256 MiB and never after the whole (possibly huge) blob.
///   * GATE-1 BLAKE3 VERIFY: the accumulated bytes are BLAKE3-verified against the requested
///     identity with the frozen [`Blake3Digest::from_raw_nar`] recipe at completion, so a
///     corrupt/lying provider yields [`TransferError::IntegrityMismatch`], never trusted
///     bytes. HONEST LIMIT (TASK-197): the SIZE abort is truly mid-stream, but
///     per-CHUNK byte-corruption detection (catching a flipped byte before EOF, as bao does)
///     needs a bao outboard interleaved on the wire; this transport carries the raw NAR
///     alone, so byte corruption is caught at stream completion (single pass, memory bounded
///     to cap + one chunk), never after a second full buffer-and-rehash.
pub(crate) async fn read_response_streamed<R>(
    reader: &mut R,
    expected_size: Option<u64>,
    body_idle_timeout: Duration,
    content: &Blake3Digest,
) -> Result<Vec<u8>, TransferError>
where
    R: AsyncRead + Unpin,
{
    let mut status = [0u8; 1];
    match tokio::time::timeout(body_idle_timeout, reader.read_exact(&mut status)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return Err(TransferError::Unavailable(format!(
                "NAR stream for {content} closed before its status byte: {error}"
            )));
        }
        Err(_elapsed) => {
            return Err(TransferError::Unavailable(format!(
                "NAR stream for {content} stalled before its status byte for {body_idle_timeout:?}"
            )));
        }
    }
    match status[0] {
        STATUS_NOT_HELD => Err(TransferError::NotHeld(*content)),
        STATUS_DECLINED => {
            let mut reason = [0u8; 1];
            // A declined response fails the fetch whatever the reason byte; an unreadable
            // reason is coerced to the generic supply-failure category, never trusted.
            let reason =
                match tokio::time::timeout(body_idle_timeout, reader.read_exact(&mut reason)).await
                {
                    Ok(Ok(())) => DeclineReason::from_wire(reason[0]),
                    _ => DeclineReason::SupplyFailed,
                };
            Err(TransferError::Unavailable(format!(
                "provider declined to serve {content}: {reason}"
            )))
        }
        STATUS_NAR => {
            // The running cap: the signed per-call bound when present, else the fixed
            // unbounded-OOM floor (a cold-start fetch of a > 256 MiB NAR hard-fails here).
            let cap = expected_size.unwrap_or(MAX_NAR_RESPONSE_BYTES);
            let mut raw: Vec<u8> = Vec::new();
            let mut buf = vec![0u8; NAR_STREAM_CHUNK];
            loop {
                let read = tokio::time::timeout(body_idle_timeout, reader.read(&mut buf)).await;
                let n = match read {
                    Ok(Ok(0)) => break, // EOF: the server closed its write half - NAR complete.
                    Ok(Ok(n)) => n,
                    Ok(Err(error)) => {
                        return Err(TransferError::Unavailable(format!(
                            "NAR stream for {content} failed mid-transfer: {error}"
                        )));
                    }
                    Err(_elapsed) => {
                        // Dropping `reader` (its stream) at this return ABORTS the transfer.
                        return Err(TransferError::Unavailable(format!(
                            "NAR transfer for {content} stalled: no bytes for {body_idle_timeout:?}"
                        )));
                    }
                };
                raw.extend_from_slice(&buf[..n]);
                // Abort the INSTANT the running total crosses the cap - before reading more.
                if raw.len() as u64 > cap {
                    return Err(TransferError::TooLarge {
                        limit: cap,
                        streamed: raw.len() as u64,
                    });
                }
            }
            // Gate 1: BLAKE3-verify against the requested identity with the frozen SSOT
            // recipe. A corrupt/lying provider errors here, never wrong bytes handed upward.
            let actual = Blake3Digest::from_raw_nar(&raw);
            if &actual != content {
                return Err(TransferError::IntegrityMismatch {
                    expected: *content,
                    actual,
                });
            }
            Ok(raw)
        }
        other => Err(TransferError::Unavailable(format!(
            "unknown NAR response status byte {other} from the provider for {content}"
        ))),
    }
}

/// Frame a [`NarResponse`] onto a serve stream's write half and CLOSE it. The close is the
/// EOF the fetcher's read loop terminates on (there is no length prefix on the NAR body).
async fn write_response<W>(writer: &mut W, response: NarResponse) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match response {
        NarResponse::NotHeld => writer.write_all(&[STATUS_NOT_HELD]).await?,
        NarResponse::Declined(reason) => {
            writer.write_all(&[STATUS_DECLINED, reason.wire()]).await?
        }
        NarResponse::Nar(bytes) => {
            writer.write_all(&[STATUS_NAR]).await?;
            writer.write_all(&bytes).await?;
        }
    }
    writer.flush().await?;
    // Half-close: the FIN is how the fetcher knows the (length-prefix-free) NAR is complete.
    writer.close().await
}

/// Resolve once the CONSUMER hung up: after sending its 32-byte request the requester keeps
/// its write half OPEN for the whole transfer, so a read on the server's read half PENDS
/// while the consumer is still there and yields EOF/error the moment it drops or resets the
/// stream. The server races this against off-loop production so an abandoned request REAPS
/// the supervised producer instead of running a `nix-store --dump` to completion for nobody.
async fn consumer_hung_up<R>(reader: &mut R)
where
    R: AsyncRead + Unpin,
{
    let mut scratch = [0u8; 1];
    loop {
        match reader.read(&mut scratch).await {
            Ok(0) => return,   // EOF: the consumer closed/reset the stream - gone.
            Ok(_) => continue, // The protocol sends nothing after the request; ignore + watch.
            Err(_) => return,  // A read error is also "gone".
        }
    }
}

/// Serve ONE inbound NAR stream, entirely OFF the swarm poll loop (AC#3): this runs on a
/// task the accept loop spawned, never touching the swarm, so a large or slow serve never
/// stalls kad / identify / other transfers. It reads the 32-byte request digest, admits it
/// through the installed [`ServeGate`] (or answers `NotHeld` when this node is not serving),
/// and streams the response:
///
///   * a non-admit ([`Serve::Now`]) or an inline Memory NAR is written straight back;
///   * an admitted process source ([`Serve::OffLoop`]) is produced under the gate's
///     supervisor, RACED against the consumer hanging up so a dropped stream reaps the
///     `nix-store --dump` group (cancellation-safety), with the in-flight [`InflightReservation`]
///     guard held for the whole future so even a drop before the first poll releases the
///     reserve.
///
/// EVERY phase is DEADLINE-BOUND so a stalled or non-reading consumer cannot park this task
/// (nor, for a Process serve, pin its in-flight reservation) indefinitely - the raw-stream
/// rewrite re-establishes the whole-exchange bound the replaced request-response carrier had
/// as its single request timeout. The bound is the serving node's
/// [`ServeBudget::max_serve_duration`], or [`UNSERVED_STREAM_DEADLINE`] when not serving.
///
/// Generic over the stream type purely so it is unit-testable over an in-memory mock; the
/// swarm passes a `libp2p::Stream`.
pub(crate) async fn serve_stream<S>(stream: S, gate: Option<Arc<ServeGate>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut read_half, mut write_half) = stream.split();

    // The per-phase deadline: a serving node bounds by its ServeBudget; a non-serving node
    // (which only reads a digest and writes one NotHeld byte) uses the slowloris guard.
    let deadline = gate
        .as_ref()
        .map(|gate| gate.max_serve_duration())
        .unwrap_or(UNSERVED_STREAM_DEADLINE);

    // The request digest, bounded: a peer that opens a stream and then stalls (sends a
    // partial digest, or nothing) cannot park this task forever.
    let mut digest = [0u8; 32];
    match tokio::time::timeout(deadline, read_half.read_exact(&mut digest)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::debug!(%error, "libp2p serve: inbound NAR stream closed before its request digest");
            return;
        }
        Err(_elapsed) => {
            tracing::debug!(
                ?deadline,
                "libp2p serve: inbound NAR request digest did not arrive within the serve deadline"
            );
            return;
        }
    }
    let content = Blake3Digest::from_bytes(digest);

    // The in-flight reservation (Process serve only) is held HERE, at serve_stream scope, so
    // it lives through production AND the response write - the in-flight ceiling accounts for
    // the produced NAR's memory while it is resident being written, not merely while
    // producing. It was created synchronously at admit, so dropping this task at ANY point
    // after admit - including a drop before the first poll - releases the reserve exactly once.
    let mut _reservation: Option<InflightReservation> = None;

    let response = match gate {
        None => NarResponse::NotHeld,
        Some(gate) => match gate.admit(&content) {
            Serve::Now(response) => response,
            Serve::OffLoop {
                plan,
                content,
                reservation,
            } => {
                _reservation = Some(reservation);
                tokio::select! {
                    biased;
                    // The consumer abandoned the transfer: drop the produce future, which
                    // SIGKILL-reaps the supervised group. Nothing to deliver on a dead stream.
                    () = consumer_hung_up(&mut read_half) => {
                        tracing::debug!(
                            %content,
                            "libp2p serve: consumer hung up before off-loop NAR production finished; reaping"
                        );
                        return;
                    }
                    response = gate.produce_admitted(plan, content) => response,
                }
            }
        },
    };

    // The response write, bounded: a consumer that never READS its response (but keeps the
    // stream open, so `consumer_hung_up` above never fired) would otherwise block `write_all`
    // on yamux backpressure forever, holding the reservation and parking this task. The
    // deadline caps that; dropping `write_half` on return resets the substream, and
    // `_reservation` releases as this function returns.
    match tokio::time::timeout(deadline, write_response(&mut write_half, response)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::debug!(%error, %content, "libp2p serve: failed to write NAR response (consumer gone?)");
        }
        Err(_elapsed) => {
            tracing::debug!(?deadline, %content, "libp2p serve: response write exceeded the serve deadline (consumer not reading); dropping");
        }
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

    /// Whether producing this plan REQUIRES the off-poll-loop supervised path
    /// ([`Self::produce_supervised`]) rather than the inline [`Self::produce`]: true for a
    /// [`NarSource::Process`] (a `nix-store --dump` / raw-NAR helper that must ride in a
    /// killable, reaped-on-shutdown process group), false for an already-resident
    /// [`NarSource::Memory`]. The swarm serve loop routes Process sources OFF the poll
    /// thread on this (TASK-193).
    pub(crate) fn requires_supervised_production(&self) -> bool {
        matches!(self.source, NarSource::Process { .. })
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

/// Whether THIS process was spawned as the daemon's raw-NAR helper (`helper __dump-raw-nar
/// <path>`) by a [`CatalogNarSupplier`] serving a [`ProbedSource::RegularFile`] - i.e. the
/// authorizing env guard set by [`raw_nar_helper_environment`] is present. A thin binary's
/// `fn main` calls this to gate its `__dump-raw-nar` subcommand, so the raw-file dumper can
/// only be reached through the supervised supply path, never as a user-invokable mode
/// (mirrors `fabric-iroh`'s `raw_nar_helper_authorized`). Store paths are served by a
/// [`ProbedSource::Process`] (`nix-store --dump`) and never spawn this helper.
pub fn raw_nar_helper_authorized() -> bool {
    std::env::var(RAW_NAR_HELPER_ENV).ok().as_deref() == Some(RAW_NAR_HELPER_VALUE)
}

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
    /// The supervisor OFF-loop Process production runs under (TASK-193): a
    /// [`NarSource::Process`] source rides in a killable, reaped-on-shutdown process group
    /// via [`NarSupplyPlan::produce_supervised`]. A [`TaskSupervisorHandle::disconnected`]
    /// handle disables Process serving (every Process serve is `Declined(SupplyFailed)`),
    /// which is exactly what a Memory-only server wants; a serving fabric threads a live
    /// handle from the supervisor it owns.
    supervisor: TaskSupervisorHandle,
    /// Cleared by the serve teardown guard's `Drop`: the SYNCHRONOUS stop-admitting
    /// signal. Once `false`, [`respond`](ServeGate::respond) answers `NotHeld` without
    /// consulting the supplier, so dropping the handle stops admission the instant it
    /// runs, independent of the (best-effort, async) worker uninstall command.
    active: AtomicBool,
    /// The single source of truth for in-flight bytes. Reserved BEFORE production and
    /// released after, so the in-flight ceiling is checked against real reservations. Held
    /// behind an [`Arc`] so an [`InflightReservation`] guard can own the decrement WITHOUT a
    /// back-reference to the whole gate: the guard is constructed synchronously at admit and
    /// moved into the production future, so dropping that future at ANY point - even before
    /// its first poll - releases the reserve (TASK-193; the DEEP-gate pre-first-poll leak).
    inflight_bytes: Arc<AtomicU64>,
    admitted: AtomicU64,
    declined_too_large: AtomicU64,
    declined_busy: AtomicU64,
    declined_unknown: AtomicU64,
    declined_supply_failed: AtomicU64,
    refused_stopped: AtomicU64,
}

impl ServeGate {
    /// A gate serving `supplier` under `budget`, admitting until [`stop`](Self::stop).
    /// Off-loop [`NarSource::Process`] production runs under `supervisor` (TASK-193); pass
    /// [`TaskSupervisorHandle::disconnected`] for a Memory-only server that never needs it.
    pub fn new(
        budget: ServeBudget,
        supplier: Arc<dyn Libp2pNarSupplier>,
        supervisor: TaskSupervisorHandle,
    ) -> Self {
        // Destructure the seam budget EXHAUSTIVELY (mirroring fabric-iroh's
        // ServeBudget::from_seam) so a new `peer_fabric::ServeBudget` field fails THIS
        // build rather than being silently unenforced by the gate. All three are now
        // enforced: the per-NAR and in-flight ceilings in `admit_plan`, and (TASK-157)
        // `max_serve_duration` as a real serve deadline around off-loop production in
        // `produce_admitted`.
        let ServeBudget {
            max_nar_bytes_uncompressed_nar: _,
            max_inflight_bytes_uncompressed_nar: _,
            max_serve_duration: _,
        } = budget;
        ServeGate {
            budget,
            supplier,
            supervisor,
            active: AtomicBool::new(true),
            inflight_bytes: Arc::new(AtomicU64::new(0)),
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

    /// The SHARED admission policy for one inbound request. THE DECLARED SIZE IS CHECKED
    /// BEFORE ANY BYTES ARE PRODUCED (task-72 GAP-1): a request over budget costs a plan
    /// lookup, not an allocation. Applies the stop / unknown / too-large / in-flight-ceiling
    /// gates and, on admission, RESERVES `declared` bytes against the in-flight ceiling,
    /// returning the plan together with the [`InflightReservation`] guard that OWNS the
    /// release. `Err` carries the immediate non-admit response (nothing reserved). Runs on
    /// the poll loop ([`Self::admit`]) or the synchronous test path ([`Self::respond`]).
    ///
    /// RESERVE-AND-GUARD ARE ATOMIC AT ADMIT (TASK-193, DEEP-gate fix): the guard is built
    /// HERE, synchronously, the instant the CAS reserve succeeds - never later inside an
    /// async body. So whatever the caller does with the returned guard (drop it, or move it
    /// into a production future that is then dropped before its first poll), the reserve is
    /// always paired with exactly one release; an abandoned request can never leak capacity.
    fn admit_plan(
        &self,
        content: &Blake3Digest,
    ) -> Result<(NarSupplyPlan, InflightReservation), NarResponse> {
        if !self.active.load(Ordering::Acquire) {
            self.refused_stopped.fetch_add(1, Ordering::Relaxed);
            return Err(NarResponse::NotHeld);
        }
        let Some(plan) = self.supplier.plan(content) else {
            self.declined_unknown.fetch_add(1, Ordering::Relaxed);
            return Err(NarResponse::NotHeld);
        };
        let declared = plan.declared_size();
        if declared > self.budget.max_nar_bytes_uncompressed_nar {
            self.declined_too_large.fetch_add(1, Ordering::Relaxed);
            return Err(NarResponse::Declined(DeclineReason::TooLarge));
        }
        // Reserve against the in-flight ceiling with a CAS loop (TASK-193). Before this
        // task, production was inline and every admit was serialized on the swarm worker,
        // so a plain load-then-add was safe and the ceiling was effectively vestigial.
        // Now a Process reservation is HELD ACROSS an off-loop await and RELEASED from the
        // producing task, so releases race admits: the compare-exchange makes the reserve
        // correct under a concurrent release (and even a concurrent admit), so two admits
        // can never both pass and blow past the ceiling.
        loop {
            let held = self.inflight_bytes.load(Ordering::Acquire);
            let want = held.saturating_add(declared);
            if want > self.budget.max_inflight_bytes_uncompressed_nar {
                self.declined_busy.fetch_add(1, Ordering::Relaxed);
                return Err(NarResponse::Declined(DeclineReason::Busy));
            }
            if self
                .inflight_bytes
                .compare_exchange_weak(held, want, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        // The reserve is now taken; bind its release to a guard in the SAME synchronous
        // step, so there is no window in which the increment exists without an owning guard.
        let reservation = InflightReservation {
            inflight: Arc::clone(&self.inflight_bytes),
            declared,
        };
        Ok((plan, reservation))
    }

    /// Produce an admitted plan INLINE (the Memory fast path / the synchronous test path)
    /// and update the counters. Does NOT touch the reservation (the caller releases it). A
    /// [`NarSource::Process`] reaching here is `Declined(SupplyFailed)` - the sync
    /// [`NarSupplyPlan::produce`] refuses to run a supervised process on the poll thread.
    fn finish_inline(&self, plan: NarSupplyPlan, content: &Blake3Digest) -> NarResponse {
        match plan.produce() {
            Ok(bytes) => {
                self.admitted.fetch_add(1, Ordering::Relaxed);
                NarResponse::Nar(bytes)
            }
            Err(why) => {
                tracing::warn!(%content, %why, "libp2p serve: supplier failed to produce NAR inline");
                self.declined_supply_failed.fetch_add(1, Ordering::Relaxed);
                NarResponse::Declined(DeclineReason::SupplyFailed)
            }
        }
    }

    /// Admit and answer one inbound request on the SYNCHRONOUS path. Kept for the
    /// in-memory/inline case and the unit tests; a [`NarSource::Process`] reaching here is
    /// `Declined(SupplyFailed)` (the RED path) because [`NarSupplyPlan::produce`] cannot run
    /// a supervised process - the swarm worker routes Process sources through
    /// [`Self::admit`] + [`Self::produce_admitted`] off the poll loop instead (TASK-193).
    pub fn respond(&self, content: &Blake3Digest) -> NarResponse {
        let (plan, _reservation) = match self.admit_plan(content) {
            Ok(admitted) => admitted,
            Err(immediate) => return immediate,
        };
        // `_reservation` releases when it drops at the end of this call, after the inline
        // production - the reserve/release pairing the async path gets from the guard too.
        self.finish_inline(plan, content)
    }

    /// Admit one inbound request on the swarm poll loop, deciding WHERE its bytes are
    /// produced (TASK-193). A [`NarSource::Memory`] is produced inline on the spot
    /// ([`Serve::Now`]); a [`NarSource::Process`] (store-dump / raw-NAR helper) is admitted
    /// and its reservation HELD for OFF-loop supervised production ([`Serve::OffLoop`]), so
    /// the poll loop is never blocked on a `nix-store --dump`. A non-admit (stopped /
    /// unknown / over-budget) is an immediate [`Serve::Now`].
    pub(crate) fn admit(&self, content: &Blake3Digest) -> Serve {
        let (plan, reservation) = match self.admit_plan(content) {
            Ok(admitted) => admitted,
            Err(immediate) => return Serve::Now(immediate),
        };
        if plan.requires_supervised_production() {
            // Hand the guard to the caller INSIDE the outcome: the swarm worker moves it
            // into the production future, so the reserve is released whenever that future is
            // dropped - including before its first poll (the DEEP-gate pre-first-poll leak).
            Serve::OffLoop {
                plan,
                content: *content,
                reservation,
            }
        } else {
            // Memory produced inline on the poll loop; `reservation` releases as it drops
            // at the end of this call.
            Serve::Now(self.finish_inline(plan, content))
        }
    }

    /// Produce an admitted [`Serve::OffLoop`] plan OFF the poll loop (TASK-193): run the
    /// supervised process source under this gate's [`TaskSupervisorHandle`], keeping the
    /// serve-time `len == declared_size` AND `BLAKE3(RawNarV1) == content` recheck
    /// ([`NarSupplyPlan::produce_supervised`]).
    ///
    /// The in-flight reservation is NOT managed here: its [`InflightReservation`] guard was
    /// constructed at admit and is owned by the caller's future (the swarm worker moves it
    /// in alongside this call). That deliberately keeps the reserve released even when this
    /// future is dropped BEFORE its first poll - the DEEP-gate leak an in-body guard missed.
    /// Dropping the returned future still SIGKILL-reaps the `nix-store --dump` group, because
    /// dropping the inner `produce_supervised` future signals caller-abandonment.
    ///
    /// SERVE DEADLINE (TASK-157): production is bounded by `budget.max_serve_duration`. A
    /// source that has not produced its bytes within the deadline is `Declined(SupplyFailed)`
    /// and, because the timeout DROPS the inner `produce_supervised` future, its supervised
    /// process group is SIGKILL-reaped - a wedged / pathologically slow dump can never pin a
    /// serve slot open forever now that production is a long-lived off-loop await.
    /// The serve exchange deadline (`ServeBudget::max_serve_duration`): bounds off-loop
    /// production ([`Self::produce_admitted`]) AND the serve-side request read / response
    /// write ([`serve_stream`]), so no phase of an inbound serve can hang unbounded.
    pub(crate) fn max_serve_duration(&self) -> Duration {
        self.budget.max_serve_duration
    }

    pub(crate) async fn produce_admitted(
        &self,
        plan: NarSupplyPlan,
        content: Blake3Digest,
    ) -> NarResponse {
        let production = plan.produce_supervised(&self.supervisor, &content);
        match tokio::time::timeout(self.budget.max_serve_duration, production).await {
            Ok(Ok(bytes)) => {
                self.admitted.fetch_add(1, Ordering::Relaxed);
                NarResponse::Nar(bytes)
            }
            Ok(Err(why)) => {
                tracing::warn!(
                    %content, %why,
                    "libp2p serve: off-loop supplier failed to produce NAR"
                );
                self.declined_supply_failed.fetch_add(1, Ordering::Relaxed);
                NarResponse::Declined(DeclineReason::SupplyFailed)
            }
            Err(_elapsed) => {
                let deadline = self.budget.max_serve_duration;
                tracing::warn!(
                    %content, ?deadline,
                    "libp2p serve: off-loop production exceeded the serve deadline; reaping"
                );
                self.declined_supply_failed.fetch_add(1, Ordering::Relaxed);
                NarResponse::Declined(DeclineReason::SupplyFailed)
            }
        }
    }
}

/// Where an admitted inbound serve request's bytes are produced (TASK-193): the poll-loop
/// decision returned by [`ServeGate::admit`].
pub(crate) enum Serve {
    /// Answer NOW from the poll loop: a non-admit (NotHeld / Declined) or an inline Memory
    /// NAR produced on the spot.
    Now(NarResponse),
    /// An admitted process source to produce OFF the poll loop via
    /// [`ServeGate::produce_admitted`]. Carries the [`InflightReservation`] guard that OWNS
    /// the reserve's release: the swarm worker moves it into the production future, so
    /// dropping that future - at any point, including before its first poll - releases it.
    OffLoop {
        plan: NarSupplyPlan,
        content: Blake3Digest,
        reservation: InflightReservation,
    },
}

/// A RAII reservation against a [`ServeGate`]'s in-flight ceiling. Constructed synchronously
/// by [`ServeGate::admit`] the instant the CAS reserve succeeds, holding a direct handle to
/// the shared counter (NOT a back-reference to the gate), and released when this guard drops.
///
/// It is deliberately handed to the caller AT ADMIT and moved into the production future, so
/// the reserve is released on the guard's drop whatever happens to that future - normal
/// completion, a mid-await cancellation, OR a drop BEFORE the future's first poll (a peer
/// that abandons the request instantly). A guard built inside the async body would miss that
/// last case and permanently leak the reserve, wedging the serve gate (TASK-193 DEEP gate).
pub(crate) struct InflightReservation {
    inflight: Arc<AtomicU64>,
    declared: u64,
}

impl Drop for InflightReservation {
    fn drop(&mut self) {
        self.inflight.fetch_sub(self.declared, Ordering::AcqRel);
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

    /// A serve gate over `supplier` (1 MiB per-NAR / 1 GiB in-flight) with a DISCONNECTED
    /// supervisor: the Memory-only cases below never reach the supervised Process path.
    fn memory_gate(supplier: Arc<dyn Libp2pNarSupplier>) -> ServeGate {
        ServeGate::new(
            budget(1 << 20, 1 << 30),
            supplier,
            TaskSupervisorHandle::disconnected(),
        )
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
        let gate = memory_gate(supplier);
        match gate.respond(&content) {
            NarResponse::Nar(bytes) => assert_eq!(bytes, nar),
            other => panic!("expected Nar, got {other:?}"),
        }
        assert_eq!(gate.counters().admitted, 1);
    }

    #[test]
    fn respond_notheld_for_unknown_digest() {
        let supplier = Arc::new(MemoryNarSupplier::new([b"held".to_vec()]));
        let gate = memory_gate(supplier);
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
        let gate = memory_gate(Arc::new(supplier)); // 1 MiB cap
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
        let gate = memory_gate(Arc::new(MemoryNarSupplier::new([nar])));
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

    // -------------------------------------------------------------------------
    // TASK-193: the off-loop serve seam - a Process source is served through
    // admit()+produce_admitted(), where the synchronous respond() path declines it.
    // -------------------------------------------------------------------------

    /// A serve gate over a one-content Process source producing `body` via `sh -c 'printf'`,
    /// with a LIVE supervisor. `body` must contain no single quote.
    fn process_gate(body: &[u8], supervisor: &TaskSupervisor) -> (ServeGate, Blake3Digest) {
        let content = Blake3Digest::from_raw_nar(body);
        let body_str = String::from_utf8(body.to_vec()).expect("ascii test body");
        let probe = OneProbe {
            content,
            declared_size: body.len() as u64,
            make: Box::new(move || ProbedSource::Process {
                program: PathBuf::from("sh"),
                args: vec![
                    OsString::from("-c"),
                    OsString::from(format!("printf %s '{body_str}'")),
                ],
            }),
        };
        let supplier = Arc::new(CatalogNarSupplier::new(probe, "unused-helper"));
        let gate = ServeGate::new(budget(1 << 20, 1 << 30), supplier, supervisor.handle());
        (gate, content)
    }

    /// RED vs GREEN, the core unblock: the SYNC `respond()` path DECLINES a Process source
    /// (it cannot run a supervised process on the poll thread), while the async
    /// `admit()` + `produce_admitted()` path SERVES the exact bytes and the BLAKE3 of the
    /// served bytes matches the announced content. BITE: route the Process source through
    /// `respond()` (the old sync path) and it is `Declined(SupplyFailed)`.
    #[tokio::test]
    async fn process_source_is_declined_inline_but_served_off_loop() {
        let body = b"raw nar produced by a process source, off the poll loop".to_vec();
        let supervisor = TaskSupervisor::new();
        let (gate, content) = process_gate(&body, &supervisor);
        let gate = Arc::new(gate);

        // RED: the synchronous inline path declines a Process source.
        assert!(
            matches!(
                gate.respond(&content),
                NarResponse::Declined(DeclineReason::SupplyFailed)
            ),
            "the sync respond() path must decline a Process source (the pre-193 behaviour)"
        );

        // GREEN: admit -> off-loop supervised production serves the exact bytes. The
        // reservation guard is created at admit; hold it across production (as the worker
        // does by moving it into the future) and let it release on completion.
        let (plan, admitted_content, reservation) = match gate.admit(&content) {
            Serve::OffLoop {
                plan,
                content,
                reservation,
            } => (plan, content, reservation),
            Serve::Now(other) => panic!("expected OffLoop for a Process source, got {other:?}"),
        };
        assert_eq!(admitted_content, content);
        assert_eq!(
            gate.inflight_bytes.load(Ordering::Acquire),
            body.len() as u64,
            "admit reserved the declared bytes"
        );
        let response = {
            let _reservation = reservation;
            gate.produce_admitted(plan, admitted_content).await
        };
        match response {
            NarResponse::Nar(bytes) => {
                assert_eq!(bytes, body, "off-loop production serves the exact bytes");
                assert_eq!(Blake3Digest::from_raw_nar(&bytes), content);
            }
            other => panic!("expected Nar from the off-loop path, got {other:?}"),
        }
        assert_eq!(gate.counters().admitted, 1);
        assert_eq!(
            gate.inflight_bytes.load(Ordering::Acquire),
            0,
            "the reservation is released after off-loop production completes"
        );
    }

    /// TASK-193 cancellation-safety THROUGH the gate: a slow Process serve admitted and
    /// producing off-loop is REAPED (the process group is SIGKILLed and its job leaves the
    /// registry) when the node's supervisor is cancelled, AND the in-flight reservation is
    /// released - no orphan `nix-store --dump`, no leaked reservation. BITE: skip the reap
    /// (an un-supervised spawn) and the grandchild survives in `/proc`; drop the RAII
    /// reservation guard and the in-flight ledger stays non-zero. BOUNDED: one spawn + reap.
    #[tokio::test]
    async fn off_loop_serve_is_reaped_and_reservation_released_on_cancel() {
        let pid_file = unique_temp("task193-reap-pids");
        let _ = std::fs::remove_file(&pid_file);
        let content = Blake3Digest::from_bytes([0x5b; 32]);
        let declared: u64 = 1 << 20; // never produced; the serve is cancelled first
        let script = "(while :; do sleep 0.05; done) & grand=$!; printf '%s %s' \"$$\" \"$grand\" > \"$1\"; wait";
        let pid_file_arg = pid_file.clone();
        let probe = OneProbe {
            content,
            declared_size: declared,
            make: Box::new(move || ProbedSource::Process {
                program: PathBuf::from("sh"),
                args: vec![
                    OsString::from("-c"),
                    OsString::from(script),
                    OsString::from("task193-reaper"),
                    pid_file_arg.clone().into_os_string(),
                ],
            }),
        };
        let supervisor = TaskSupervisor::new();
        let supplier = Arc::new(CatalogNarSupplier::new(probe, "unused-helper"));
        let gate = Arc::new(ServeGate::new(
            budget(1 << 30, 1 << 30),
            supplier,
            supervisor.handle(),
        ));

        // Admit on the "poll loop": this RESERVES `declared` and hands back the guard.
        let (plan, admitted_content, reservation) = match gate.admit(&content) {
            Serve::OffLoop {
                plan,
                content,
                reservation,
            } => (plan, content, reservation),
            Serve::Now(other) => panic!("expected OffLoop, got {other:?}"),
        };
        assert_eq!(
            gate.inflight_bytes.load(Ordering::Acquire),
            declared,
            "admit reserved the declared bytes"
        );
        // Move the guard into the production future, exactly as the swarm worker does.
        let gate_task = Arc::clone(&gate);
        let op = tokio::spawn(async move {
            let _reservation = reservation;
            gate_task.produce_admitted(plan, admitted_content).await
        });

        // Wait until the supervised group is live (pids published + one active job).
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
        .expect("the off-loop supervised group started and published its pids");
        let pids = pids
            .split_whitespace()
            .map(|raw| raw.parse::<u32>().expect("decimal pid"))
            .collect::<Vec<_>>();

        // Node shutdown: SIGKILL + reap the group.
        supervisor.cancel_now();
        tokio::time::timeout(Duration::from_secs(3), async {
            while supervisor.process_jobs().active_len() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the off-loop process job was reaped and left the registry");

        let response = op.await.expect("producer task joined");
        assert!(
            matches!(response, NarResponse::Declined(DeclineReason::SupplyFailed)),
            "a cancelled off-loop serve declines rather than shipping bytes"
        );
        assert_eq!(
            gate.inflight_bytes.load(Ordering::Acquire),
            0,
            "the in-flight reservation must be released on the cancelled path (no leak)"
        );
        for pid in pids {
            assert!(
                !PathBuf::from(format!("/proc/{pid}")).exists(),
                "supervised pid {pid} (or its grandchild) survived cancel - an orphan"
            );
        }
        let _ = std::fs::remove_file(&pid_file);
    }

    /// TASK-193 DEEP-gate bite (the decisive one): admitting an `OffLoop` reserves against
    /// the in-flight ceiling, and DROPPING the production future WITHOUT EVER POLLING IT (a
    /// peer that abandons the request before the task is scheduled) must still release the
    /// reserve. No ResponseChannel is needed - this is the pure reservation-lifetime oracle.
    ///
    /// BITE: with the reservation guard constructed INSIDE `produce_admitted`'s async body
    /// (the pre-fix code), the guard is never built for an unpolled future, so the reserve
    /// LEAKS and the final `inflight == 0` assertion fails (RED). With the guard owned from
    /// admit and moved into the future (the fix), the unpolled drop releases it (GREEN).
    /// Repeated leaks would retire serve capacity - an availability/DoS hole.
    #[tokio::test]
    async fn dropping_an_unpolled_off_loop_future_releases_the_reservation() {
        let body = b"an abandoned request must not leak the in-flight reserve".to_vec();
        let supervisor = TaskSupervisor::new();
        let (gate, content) = process_gate(&body, &supervisor);
        let gate = Arc::new(gate);

        let (plan, reservation) = match gate.admit(&content) {
            Serve::OffLoop {
                plan, reservation, ..
            } => (plan, reservation),
            Serve::Now(other) => panic!("expected OffLoop for a Process source, got {other:?}"),
        };
        assert_eq!(
            gate.inflight_bytes.load(Ordering::Acquire),
            body.len() as u64,
            "admit reserved the declared bytes"
        );

        // Build the EXACT future the swarm worker builds (the guard moved in alongside the
        // plan), then DROP it without ever polling it.
        let gate_fut = Arc::clone(&gate);
        let fut = async move {
            let _reservation = reservation;
            gate_fut.produce_admitted(plan, content).await
        };
        drop(fut);

        assert_eq!(
            gate.inflight_bytes.load(Ordering::Acquire),
            0,
            "dropping the unpolled production future must release the reserve (no leak)"
        );
        // Nothing was ever produced, so no supervised process was spawned.
        assert_eq!(supervisor.process_jobs().active_len(), 0);
    }

    /// TASK-193 DEEP-gate bite (the declared-size / exact-length arm, distinct from the hash
    /// arm): a Process source whose dump produces a DIFFERENT LENGTH than its declared size
    /// must be `Declined(SupplyFailed)`, never served/mislabeled. Here the probe DECLARES
    /// more bytes than the dump emits; the produced bytes DO hash to the announced content,
    /// so ONLY the `len == declared_size` recheck can catch the lie.
    ///
    /// BITE: remove that exact-length check in `produce_supervised` and the short dump is
    /// served under the wrong (larger) declared size - the `Declined` assertion goes RED.
    #[tokio::test]
    async fn process_source_with_wrong_declared_length_is_declined() {
        let actual = b"short dump body".to_vec();
        // The announced content is the honest hash of the ACTUAL bytes, so the BLAKE3 arm
        // passes; the lie is purely in the declared size.
        let content = Blake3Digest::from_raw_nar(&actual);
        let declared = actual.len() as u64 + 100; // claim 100 more bytes than produced
        let actual_str = String::from_utf8(actual.clone()).expect("ascii body");
        let probe = OneProbe {
            content,
            declared_size: declared,
            make: Box::new(move || ProbedSource::Process {
                program: PathBuf::from("sh"),
                args: vec![
                    OsString::from("-c"),
                    OsString::from(format!("printf %s '{actual_str}'")),
                ],
            }),
        };
        let supervisor = TaskSupervisor::new();
        let supplier = Arc::new(CatalogNarSupplier::new(probe, "unused-helper"));
        let gate = Arc::new(ServeGate::new(
            budget(1 << 20, 1 << 30),
            supplier,
            supervisor.handle(),
        ));

        let (plan, admitted_content, reservation) = match gate.admit(&content) {
            Serve::OffLoop {
                plan,
                content,
                reservation,
            } => (plan, content, reservation),
            Serve::Now(other) => panic!("expected OffLoop, got {other:?}"),
        };
        let response = {
            let _reservation = reservation;
            gate.produce_admitted(plan, admitted_content).await
        };
        assert!(
            matches!(response, NarResponse::Declined(DeclineReason::SupplyFailed)),
            "a dump whose length != declared_size must be Declined, got {response:?}"
        );
        assert_eq!(
            gate.inflight_bytes.load(Ordering::Acquire),
            0,
            "the reservation is released after the declined serve"
        );
    }

    // -------------------------------------------------------------------------
    // TASK-157: the FETCH-side streaming read core (`read_response_streamed`), unit-bitten
    // over in-memory readers. These are the crisp, load-tolerant bites for AC#1 (mid-stream
    // size abort) and AC#2 (inter-chunk idle bound) - no wall-clock races, no live swarm.
    // -------------------------------------------------------------------------

    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A short body-idle bound for the unit bites: long enough not to flake on a scheduler
    /// hiccup, short enough that the test finishes fast.
    const IDLE: Duration = Duration::from_millis(150);

    /// Frame a wire response as raw bytes: a status byte then (for Nar) the body verbatim,
    /// exactly what a well-behaved server writes (no length prefix - EOF terminates the NAR).
    fn wire_nar(body: &[u8]) -> Vec<u8> {
        let mut v = vec![STATUS_NAR];
        v.extend_from_slice(body);
        v
    }

    /// A reader that yields the status byte once, then STALLS FOREVER (never another byte,
    /// never EOF) - a provider that sent a status and then hung mid-body. The body-idle bound
    /// must fire on it (AC#2), distinct from any total bound.
    struct StatusThenStall {
        sent_status: bool,
    }

    impl AsyncRead for StatusThenStall {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if !self.sent_status && !buf.is_empty() {
                self.sent_status = true;
                buf[0] = STATUS_NAR;
                Poll::Ready(Ok(1))
            } else {
                // No forward progress, ever: the inter-chunk idle guard must abort.
                Poll::Pending
            }
        }
    }

    /// AC#1 the DECISIVE mid-stream bite: a provider streams a body far LARGER than the
    /// signed `expected_size`. The read must abort the INSTANT the running total crosses the
    /// cap - after ONE chunk - not after buffering the whole (here 512 KiB) blob, and not at
    /// the 256 MiB floor. BITE: move the size check to AFTER the read loop (a post-receive
    /// buffer check, the pre-157 behaviour) and `streamed` becomes the full 512 KiB.
    #[tokio::test]
    async fn read_aborts_mid_stream_when_body_exceeds_expected_size() {
        let big = vec![0x5au8; 512 * 1024];
        let content = Blake3Digest::from_raw_nar(&big); // honest hash; only SIZE is over
        let cap: u64 = 4 * 1024; // the consumer signed 4 KiB
        let wire = wire_nar(&big);
        let mut reader = futures::io::Cursor::new(wire);

        let err = read_response_streamed(&mut reader, Some(cap), IDLE, &content)
            .await
            .expect_err("an over-signed-size stream must abort");
        match err {
            TransferError::TooLarge { limit, streamed } => {
                assert_eq!(limit, cap, "the abort limit is the signed expected_size");
                assert!(
                    streamed > cap,
                    "streamed ({streamed}) must have crossed the cap ({cap})"
                );
                // The decisive mid-stream property: aborted after ONE chunk, NOT after the
                // whole 512 KiB, and bounded by cap + one chunk.
                assert!(
                    streamed <= cap + NAR_STREAM_CHUNK as u64,
                    "streamed ({streamed}) must be bounded by cap + one chunk, not the whole body"
                );
                assert!(
                    (streamed as usize) < big.len(),
                    "streamed ({streamed}) must be far less than the full body ({}) - proof the \
                     read did NOT buffer the whole thing",
                    big.len()
                );
            }
            other => panic!("expected TooLarge, got {other}"),
        }
    }

    /// AC#1 the cold-start floor: with NO signed size the running cap is the 256 MiB floor,
    /// so a modest honest body still round-trips (the floor does not falsely abort it).
    #[tokio::test]
    async fn read_without_expected_size_uses_the_floor_and_accepts_a_modest_body() {
        let body = b"a cold-start fetch with no signed size still streams fine".to_vec();
        let content = Blake3Digest::from_raw_nar(&body);
        let mut reader = futures::io::Cursor::new(wire_nar(&body));
        let got = read_response_streamed(&mut reader, None, IDLE, &content)
            .await
            .expect("a modest body under the floor round-trips with no signed size");
        assert_eq!(got, body);
    }

    /// AC#2 the DECISIVE inter-chunk idle bite: a provider sends the status byte then stalls
    /// with no body forever. The read must fail on the BODY-IDLE bound (within it), not hang
    /// - proving the idle guard is enforced per chunk, distinct from `total_timeout`. BITE:
    /// drop the `timeout(body_idle_timeout, ...)` around the body read and this hangs forever.
    #[tokio::test]
    async fn read_aborts_on_inter_chunk_stall_within_the_idle_bound() {
        let content = Blake3Digest::from_bytes([0x11; 32]);
        let mut reader = StatusThenStall { sent_status: false };
        let started = std::time::Instant::now();
        let err = read_response_streamed(&mut reader, Some(1 << 20), IDLE, &content)
            .await
            .expect_err("a mid-body stall must abort on the idle bound");
        let elapsed = started.elapsed();
        match err {
            TransferError::Unavailable(why) => assert!(
                why.contains("stalled"),
                "expected a body-idle stall abort, got: {why}"
            ),
            other => panic!("expected Unavailable(stalled), got {other}"),
        }
        // It fired on the idle bound, not after some far larger wall-clock wait.
        assert!(
            elapsed < IDLE * 20,
            "the idle abort took {elapsed:?}, far past the {IDLE:?} bound - it did not fire on idle"
        );
    }

    /// GATE-1 preserved: a provider whose streamed bytes do NOT hash to the requested
    /// identity (same length, different bytes) fails the BLAKE3 verify at completion -
    /// `IntegrityMismatch`, never trusted bytes. BITE: drop the final `from_raw_nar` check
    /// and corrupt bytes are returned as if valid.
    #[tokio::test]
    async fn read_rejects_bytes_that_do_not_hash_to_the_requested_identity() {
        let wanted = b"the honest bytes the consumer asked for".to_vec();
        let requested = Blake3Digest::from_raw_nar(&wanted);
        let corrupt = b"different bytes of the same length !!!!".to_vec();
        assert_eq!(wanted.len(), corrupt.len());
        let mut reader = futures::io::Cursor::new(wire_nar(&corrupt));
        let err = read_response_streamed(&mut reader, Some(wanted.len() as u64), IDLE, &requested)
            .await
            .expect_err("corrupt bytes must fail gate-1");
        match err {
            TransferError::IntegrityMismatch { expected, actual } => {
                assert_eq!(expected, requested);
                assert_ne!(actual, requested);
            }
            other => panic!("expected IntegrityMismatch, got {other}"),
        }
    }

    /// The status arms: NotHeld and Declined map to the right typed fetch failures.
    #[tokio::test]
    async fn read_maps_notheld_and_declined_status_bytes() {
        let content = Blake3Digest::from_bytes([0x22; 32]);

        let mut not_held = futures::io::Cursor::new(vec![STATUS_NOT_HELD]);
        match read_response_streamed(&mut not_held, None, IDLE, &content).await {
            Err(TransferError::NotHeld(got)) => assert_eq!(got, content),
            other => panic!("expected NotHeld, got {other:?}"),
        }

        let mut declined =
            futures::io::Cursor::new(vec![STATUS_DECLINED, DeclineReason::Busy.wire()]);
        match read_response_streamed(&mut declined, None, IDLE, &content).await {
            Err(TransferError::Unavailable(why)) => {
                assert!(why.contains("declined"), "expected a decline, got: {why}")
            }
            other => panic!("expected Unavailable(declined), got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // TASK-157 serve-side deadline (the mped-architect finding): a consumer that opens a
    // stream, sends its request, then never READS the response must not park the serve task
    // or pin its in-flight reservation - every serve phase is deadline-bound.
    // -------------------------------------------------------------------------

    /// A stream that delivers a fixed 32-byte request digest on read, then STALLS its read
    /// side (the consumer stays connected but sends nothing more - deliberately NOT EOF, so
    /// the consumer-hung-up reap does not fire), and BLACK-HOLES its write side (the consumer
    /// never reads, so writes never drain). Models the serve-side slowloris.
    struct DigestThenUnreadable {
        digest: [u8; 32],
        read_pos: usize,
    }

    impl AsyncRead for DigestThenUnreadable {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.read_pos < self.digest.len() && !buf.is_empty() {
                let start = self.read_pos;
                let n = (self.digest.len() - start).min(buf.len());
                buf[..n].copy_from_slice(&self.digest[start..start + n]);
                self.read_pos += n;
                Poll::Ready(Ok(n))
            } else {
                // Connected but idle: NOT EOF (which would trip `consumer_hung_up`).
                Poll::Pending
            }
        }
    }

    impl AsyncWrite for DigestThenUnreadable {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending // the consumer never reads, so a real write would block on backpressure
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    /// FINDING-1 bite: a Process serve whose consumer sends the request then never reads the
    /// response must NOT hang the serve task or pin its in-flight reservation - the serve
    /// deadline caps the write, the reservation is released, and the task terminates. BITE:
    /// drop the `timeout(deadline, write_response(..))` and the write blocks forever, so
    /// `serve_stream` never returns (the 5 s guard trips) and the reservation stays charged.
    #[tokio::test]
    async fn serve_releases_the_reservation_when_the_consumer_never_reads_the_response() {
        let body = b"a NAR whose consumer opens the stream then refuses to read".to_vec();
        let content = Blake3Digest::from_raw_nar(&body);
        let body_str = String::from_utf8(body.clone()).unwrap();
        let probe = OneProbe {
            content,
            declared_size: body.len() as u64,
            make: Box::new(move || ProbedSource::Process {
                program: PathBuf::from("sh"),
                args: vec![
                    OsString::from("-c"),
                    OsString::from(format!("printf %s '{body_str}'")),
                ],
            }),
        };
        let supervisor = TaskSupervisor::new();
        let supplier = Arc::new(CatalogNarSupplier::new(probe, "unused-helper"));
        // A SHORT serve deadline so the bounded write fires fast; the test passes whether
        // production completes first (write then times out) or not (produce times out).
        let short = ServeBudget {
            max_nar_bytes_uncompressed_nar: 1 << 20,
            max_inflight_bytes_uncompressed_nar: 1 << 30,
            max_serve_duration: Duration::from_millis(500),
        };
        let gate = Arc::new(ServeGate::new(short, supplier, supervisor.handle()));

        let mock = DigestThenUnreadable {
            digest: *content.as_bytes(),
            read_pos: 0,
        };
        let serve = tokio::spawn(serve_stream(mock, Some(Arc::clone(&gate))));

        // Must TERMINATE within a small multiple of the deadline (not hang), and the in-flight
        // reservation must be released - proof the non-reading consumer did not pin it.
        tokio::time::timeout(Duration::from_secs(5), serve)
            .await
            .expect("serve_stream must terminate within the serve deadline, not hang forever")
            .expect("serve task joins");
        assert_eq!(
            gate.inflight_bytes.load(Ordering::Acquire),
            0,
            "the in-flight reservation must be released after the bounded serve write"
        );
    }
}
