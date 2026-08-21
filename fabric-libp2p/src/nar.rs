//! Bao-authenticated NAR transfer over the wholesale
//! `/nix-p2p/<scope>/nar/4` libp2p-stream protocol.
//!
//! The response declares exact RawNarV1 size and one response-global codec, then carries a
//! full-range Bao preorder traversal over fixed 64-KiB raw leaves. Parent pairs stay raw;
//! zstd uses one independently bounded frame per leaf. A fetch exposes each non-final leaf
//! only after Bao authenticates it against the requested [`Blake3Digest`], and withholds final
//! completion until `N4OK` plus clean FIN. Only v4 is registered; falling back to v3 would drop
//! this security property.
//!
//! Process-backed serving is bounded two-pass regeneration, not literal one-pass passthrough:
//! pass 1 creates a declared-size-derived ephemeral outboard and verifies exact EOF, exit zero,
//! and the requested root; pass 2 regenerates and authenticates every leaf against that outboard
//! before socket write. Neither pass retains the whole NAR. This preserves roughly the prior
//! proof-preparation delay and performs a second dump, so it is not an absolute-TTFB improvement.
//! One absolute serve deadline covers request parsing, both passes, socket backpressure,
//! COMPLETE, and FIN; cancellation kills and reaps owned process groups under a separately
//! bounded measured tail.
//!
//! The transport pipeline is bounded to codec/process chunks, one encoded leaf, one
//! transport-owned verified raw leaf, and O(tree depth), plus the provider's ephemeral outboard.
//! The raw-leaf bound assumes pull discipline: the verifier advances only when the caller asks
//! for the next leaf, but returned [`bytes::Bytes`] can of course be cloned and retained by that
//! caller. [`VerifiedNarStream`] is a crate-internal bounded handoff; TASK-62 still must expose it
//! through `peer-fabric::NarStream`, connect that public stream to HTTP, and measure the real
//! consumer high-water mark. The current [`crate::transport::Libp2pTransport`] compatibility path
//! collects verified leaves into one `Vec`, so socket-to-HTTP memory remains O(N) until TASK-62.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use tokio::sync::Semaphore;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use proc_supervisor::{
    ProcessCleanupTicket, SupervisedProcessCompletion, SupervisedProcessStream,
    TaskSupervisorHandle,
};

use peer_fabric::{
    Blake3Digest, CodecChoiceReason, ServeBudget, ServeCodecPolicy, TransferError, WireCodec,
    negotiate_serve_codec,
};
// The fetch-side in-flight meter and the substrate-neutral streaming contract
// ([`NarChunkSource`]) are consumed by the SHIPPED streaming reader
// (`open_nar_response_stream` -> [`MeteredNarStream`]), promoted from the inc1
// `#[cfg(test)]` design validation to the shipped serve path in TASK-62 inc3.
use peer_fabric::{InflightMeter, NarChunkSource};

use crate::nar_v4;

/// The fallback ceiling on a NAR response when FETCH has no signed/caller-provided
/// `expected_size`. It is the cold-start peer-triggerable-OOM guard: an untrusted provider
/// that declares a length over this is aborted before allocation.
///
/// The fallback is pinned to the `peer_fabric` serve default single-NAR ceiling
/// ([`ServeBudget::default().max_nar_bytes_uncompressed_nar`] = 256 MiB), asserted by
/// `max_response_cap_tracks_the_serve_default` so the two cannot silently drift when
/// TASK-120 moves the authoritative default. It is not an absolute ceiling when a caller
/// supplies `Some(expected_size)`: that exact size is the cap, even above 256 MiB, so an
/// explicitly configured larger serve remains fetchable when its signed size is known.
/// Only a cold-start `expected_size == None` fetch above this fallback hard-fails.
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
    /// The fetcher's `accept` bitmask named no codec this server can honour (TASK-99): a
    /// protocol error, so the server DECLINES rather than shipping a codec the client never
    /// offered (a compliant fetcher always offers raw, so only a broken/hostile peer sees this).
    NoCommonCodec,
}

impl DeclineReason {
    fn wire(self) -> u8 {
        match self {
            DeclineReason::TooLarge => 0,
            DeclineReason::Busy => 1,
            DeclineReason::SupplyFailed => 2,
            DeclineReason::NoCommonCodec => 3,
        }
    }

    fn from_wire(byte: u8) -> DeclineReason {
        // An unknown reason byte from an untrusted peer is coerced to SupplyFailed: the
        // decline fails the fetch either way, so the exact category is only advisory.
        match byte {
            0 => DeclineReason::TooLarge,
            1 => DeclineReason::Busy,
            3 => DeclineReason::NoCommonCodec,
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
            DeclineReason::NoCommonCodec => "no common NAR codec in the fetcher's accept set",
        })
    }
}

/// A fetch response the [`ServeGate`] produces for one inbound request. `Nar` carries the
/// raw (uncompressed) NAR bytes; `/nar/4` Bao-authenticates each leaf against the requested
/// BLAKE3 before use and requires terminal COMPLETE + clean FIN.
/// This is the SERVER-SIDE outcome type; on the wire it is framed by [`write_response`].
#[derive(Debug, Clone)]
pub enum NarResponse {
    /// The provider does not hold this content identity.
    NotHeld,
    /// The provider declined to serve it (over budget / supply error).
    Declined(DeclineReason),
    /// The raw NAR bytes.
    Nar(Arc<Vec<u8>>),
}

// -------------------------------------------------------------------------
// `/nar/4` changes only the churnable transport framing. The addressed unit remains exact
// RawNarV1 keyed by BLAKE3; response-global compression never changes the content identity.
//
// Wire form (over one raw substream of `/nix-p2p/<scope>/nar/4`):
//   Request  = 32 raw digest bytes + 1 `accept` byte (the codec bitmask the FETCHER can
//              decode: bit0=raw mandatory, bit1=zstd). It keeps the write half open as the
//              "still interested" signal raced by `serve_stream`.
//   Response = 1 status byte, then:
//     * `0` NotHeld  - nothing follows; clean FIN.
//     * `1` Nar      - 1 codec byte + raw_size u64 LE, canonical full-range Bao preorder:
//                      raw 64-byte parent pairs; each raw leaf verbatim, or for zstd a bounded
//                      u32 LE length plus one independent frame. `N4OK`, then clean FIN.
//     * `2` Declined - 1 reason byte (for the caller's log; the fetch still fails).
// -------------------------------------------------------------------------

/// Socket-pump chunk size. Channels are capacity one and the decoder additionally bounds one
/// encoded leaf and one raw leaf; this is not the compatibility collector's O(N) allocation.
const NAR_STREAM_CHUNK: usize = 64 * 1024;

/// Bao hashing/verification is synchronous and intentionally runs off the async
/// runtime. Independent fixed pools bound serve/proof workers and fetch verifiers.
/// They must remain independent: a serve encoder can wait on socket backpressure,
/// while its reciprocal fetch must be able to start a verifier and drain that
/// socket. One shared pool creates a circular-wait deadlock under saturation.
// Preserve the prior 64-worker capacity independently in each direction. A
// 32/32 split would avoid the deadlock but silently halve pure-serve and
// pure-fetch capacity without measurement; TASK-247 owns higher-concurrency
// tuning/evidence. The combined ceiling is still explicit and finite (128).
const BAO_SERVE_WORKER_MAX_CONCURRENT: usize = 64;
const BAO_FETCH_WORKER_MAX_CONCURRENT: usize = 64;

struct BaoWorkerPools {
    serve: Arc<Semaphore>,
    fetch: Arc<Semaphore>,
}

impl BaoWorkerPools {
    fn new(serve: usize, fetch: usize) -> Self {
        assert!(serve > 0, "Bao serve worker pool must not be empty");
        assert!(fetch > 0, "Bao fetch worker pool must not be empty");
        Self {
            serve: Arc::new(Semaphore::new(serve)),
            fetch: Arc::new(Semaphore::new(fetch)),
        }
    }

    async fn acquire_serve(&self) -> tokio::sync::OwnedSemaphorePermit {
        Arc::clone(&self.serve)
            .acquire_owned()
            .await
            .expect("Bao serve worker semaphore is never closed")
    }

    async fn acquire_fetch(&self) -> tokio::sync::OwnedSemaphorePermit {
        Arc::clone(&self.fetch)
            .acquire_owned()
            .await
            .expect("Bao fetch worker semaphore is never closed")
    }
}

static BAO_WORKER_POOLS: LazyLock<BaoWorkerPools> = LazyLock::new(|| {
    BaoWorkerPools::new(
        BAO_SERVE_WORKER_MAX_CONCURRENT,
        BAO_FETCH_WORKER_MAX_CONCURRENT,
    )
});

const REAP_TAIL_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
enum ProcessServeError {
    /// Source start/replay, exactness, exit, root, or Bao authentication failed.
    Supply(String),
    /// The peer/socket failed after supply had been admitted.
    Transport(String),
}

#[derive(Debug)]
enum ResponseWriteError {
    /// Resident bytes, root, or Bao framing did not match the admitted supply.
    Supply(String),
    /// Writing, flushing, or closing the peer stream failed.
    Transport(io::Error),
}

impl std::fmt::Display for ResponseWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Supply(why) => write!(formatter, "supply failed: {why}"),
            Self::Transport(error) => write!(formatter, "transport failed: {error}"),
        }
    }
}

#[derive(Clone, Default)]
struct ServeProcessCleanup {
    tickets: Arc<std::sync::Mutex<Vec<ProcessCleanupTicket>>>,
}

impl ServeProcessCleanup {
    fn track(&self, ticket: ProcessCleanupTicket) {
        match self.tickets.lock() {
            Ok(mut tickets) => tickets.push(ticket),
            Err(poisoned) => poisoned.into_inner().push(ticket),
        }
    }

    async fn cancel_and_wait(&self) -> (usize, u128, bool) {
        let tickets = match self.tickets.lock() {
            Ok(tickets) => tickets.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        for ticket in &tickets {
            ticket.cancel();
        }
        let started = std::time::Instant::now();
        let waits = futures::future::join_all(tickets.iter().map(|ticket| ticket.wait_reaped()));
        let completed = tokio::time::timeout(REAP_TAIL_TIMEOUT, waits)
            .await
            .is_ok_and(|results| results.into_iter().all(|result| result.is_ok()));
        (tickets.len(), started.elapsed().as_nanos(), completed)
    }
}

struct BlockingChunkReader {
    receiver: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    current: io::Cursor<Vec<u8>>,
    terminal_error: Option<io::Error>,
}

impl BlockingChunkReader {
    fn new(receiver: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>) -> Self {
        Self {
            receiver,
            current: io::Cursor::new(Vec::new()),
            terminal_error: None,
        }
    }
}

impl io::Read for BlockingChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.current.position() as usize != self.current.get_ref().len() {
                return self.current.read(buf);
            }
            if let Some(error) = self.terminal_error.take() {
                return Err(error);
            }
            match self.receiver.blocking_recv() {
                Some(Ok(chunk)) if chunk.is_empty() => continue,
                Some(Ok(chunk)) => self.current = io::Cursor::new(chunk),
                Some(Err(error)) => self.terminal_error = Some(error),
                None => return Ok(0),
            }
        }
    }
}

struct BlockingChunkWriter {
    sender: tokio::sync::mpsc::Sender<OwnedWireChunk>,
}

/// One ownership-preserving encoder-to-socket handoff. The encoder waits for
/// `recycle` before it can produce another item, so removing an item from the
/// capacity-one channel is not mistaken for completing its socket write.
struct OwnedWireChunk {
    bytes: Vec<u8>,
    recycle: std::sync::mpsc::Sender<Vec<u8>>,
}

/// Explicit terminal framing between the async socket pump and the blocking
/// Bao verifier. The verifier stream also retains a cancellation sender, so
/// relying on "all senders dropped" for EOF would deadlock successful fetches:
/// the collector cannot call `finish` (and drop that sender) until the
/// verifier has itself observed EOF. Keep transport termination in the data
/// model instead of inferring it from channel ownership.
enum BaoWireItem {
    Data(Vec<u8>),
    Error(io::Error),
    End,
}

struct BlockingBaoWireReader {
    receiver: tokio::sync::mpsc::Receiver<BaoWireItem>,
    current: io::Cursor<Vec<u8>>,
    terminal_error: Option<io::Error>,
    ended: bool,
}

impl BlockingBaoWireReader {
    fn new(receiver: tokio::sync::mpsc::Receiver<BaoWireItem>) -> Self {
        Self {
            receiver,
            current: io::Cursor::new(Vec::new()),
            terminal_error: None,
            ended: false,
        }
    }
}

impl io::Read for BlockingBaoWireReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.current.position() as usize != self.current.get_ref().len() {
                return self.current.read(buf);
            }
            if let Some(error) = self.terminal_error.take() {
                return Err(error);
            }
            if self.ended {
                return Ok(0);
            }
            match self.receiver.blocking_recv() {
                Some(BaoWireItem::Data(chunk)) if chunk.is_empty() => continue,
                Some(BaoWireItem::Data(chunk)) => self.current = io::Cursor::new(chunk),
                Some(BaoWireItem::Error(error)) => {
                    self.terminal_error = Some(error);
                    self.ended = true;
                }
                Some(BaoWireItem::End) => self.ended = true,
                None => {
                    self.terminal_error = Some(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Bao wire sender disappeared without explicit transport End",
                    ));
                    self.ended = true;
                }
            }
        }
    }
}

impl BlockingChunkWriter {
    fn new(sender: tokio::sync::mpsc::Sender<OwnedWireChunk>) -> Self {
        Self { sender }
    }
}

impl nar_v4::OwnedWireSink for BlockingChunkWriter {
    fn write_owned(&mut self, bytes: Vec<u8>) -> io::Result<Vec<u8>> {
        let (recycle, recycled) = std::sync::mpsc::channel();
        self.sender
            .blocking_send(OwnedWireChunk { bytes, recycle })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "wire consumer closed"))?;
        recycled.recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wire consumer closed before completing the socket write",
            )
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Receiver of independently Bao-authenticated RawNarV1 leaves. The final leaf
/// appears only after the decoder has consumed COMPLETE and clean EOF. This is
/// the crate-internal bounded primitive TASK-62 will expose through
/// `peer-fabric::NarStream` and connect to the HTTP body; it is not a daemon API
/// yet. The current `NarTransfer::fetch -> Vec` path is only a collector wrapper
/// around it. Its one-raw-leaf invariant covers transport-owned buffers under
/// pull-based use: a caller can retain clones of returned `Bytes`, and TASK-62
/// must include the real HTTP consumer in its end-to-end memory oracle.
pub(crate) struct VerifiedNarStream {
    leaves: tokio::sync::mpsc::Receiver<VerifiedLeaf>,
    verifier: tokio::task::JoinHandle<io::Result<u64>>,
    expected: Blake3Digest,
    cancel: tokio::sync::mpsc::Sender<BaoWireItem>,
    transport_failure: Arc<std::sync::Mutex<Option<String>>>,
    previous_leaf_release: Option<std::sync::mpsc::Sender<()>>,
    leaves_finished: bool,
}

struct VerifiedLeaf {
    bytes: bytes::Bytes,
    release_on_next_pull: std::sync::mpsc::Sender<()>,
}

impl VerifiedNarStream {
    pub(crate) async fn next_leaf(&mut self) -> Option<bytes::Bytes> {
        // Do not let the verifier allocate the next raw leaf until the caller
        // asks for it. `mpsc` capacity alone is insufficient because a send
        // completes when queued. This is pull discipline, not a Bytes-drop
        // oracle: callers may retain or clone earlier leaves.
        if let Some(release) = self.previous_leaf_release.take() {
            let _ = release.send(());
        }
        match self.leaves.recv().await {
            Some(leaf) => {
                self.previous_leaf_release = Some(leaf.release_on_next_pull);
                Some(leaf.bytes)
            }
            None => {
                self.leaves_finished = true;
                None
            }
        }
    }

    pub(crate) async fn finish(mut self) -> Result<u64, TransferError> {
        if !self.leaves_finished {
            self.leaves.close();
            // Dropping this acknowledgement releases a verifier blocked after
            // handing out the previous leaf. It then fails closed rather than
            // leaking a blocking worker while cancellation is delivered.
            self.previous_leaf_release.take();
            let _ = self
                .cancel
                .send(BaoWireItem::Error(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "verified stream finish called before leaf EOF",
                )))
                .await;
            let _ = self.verifier.await;
            return Err(TransferError::Unavailable(format!(
                "verified stream for {} was finished before all authenticated leaves were pulled",
                self.expected
            )));
        }
        let result = self.verifier.await.map_err(|error| {
            TransferError::Unavailable(format!(
                "Bao verifier worker failed for {}: {error}",
                self.expected
            ))
        })?;
        match result {
            Ok(bytes) => Ok(bytes),
            Err(error) => {
                let transport_failure = match self.transport_failure.lock() {
                    Ok(mut failure) => failure.take(),
                    Err(poisoned) => poisoned.into_inner().take(),
                };
                if let Some(why) = transport_failure {
                    Err(TransferError::Unavailable(why))
                } else {
                    Err(TransferError::AuthenticationFailed {
                        expected: self.expected,
                        reason: error.to_string(),
                    })
                }
            }
        }
    }
}

pub(crate) struct VerifiedNarWireSink {
    sender: tokio::sync::mpsc::Sender<BaoWireItem>,
    transport_failure: Arc<std::sync::Mutex<Option<String>>>,
}

impl VerifiedNarWireSink {
    async fn send(&self, chunk: Vec<u8>) -> Result<(), ()> {
        self.sender
            .send(BaoWireItem::Data(chunk))
            .await
            .map_err(|_| ())
    }

    async fn fail(&self, error: io::Error) {
        let why = error.to_string();
        match self.transport_failure.lock() {
            Ok(mut failure) => *failure = Some(why),
            Err(poisoned) => *poisoned.into_inner() = Some(why),
        }
        let _ = self.sender.send(BaoWireItem::Error(error)).await;
    }

    async fn finish(&self) -> Result<(), ()> {
        self.sender.send(BaoWireItem::End).await.map_err(|_| ())
    }

    async fn closed(&self) {
        self.sender.closed().await;
    }
}

pub(crate) async fn verified_nar_stream(
    content: Blake3Digest,
    raw_size: u64,
    codec: WireCodec,
) -> (VerifiedNarWireSink, VerifiedNarStream) {
    verified_nar_stream_with_pools(content, raw_size, codec, &BAO_WORKER_POOLS).await
}

async fn verified_nar_stream_with_pools(
    content: Blake3Digest,
    raw_size: u64,
    codec: WireCodec,
    pools: &BaoWorkerPools,
) -> (VerifiedNarWireSink, VerifiedNarStream) {
    let permit = pools.acquire_fetch().await;
    let (wire_tx, wire_rx) = tokio::sync::mpsc::channel::<BaoWireItem>(1);
    let (leaf_tx, leaf_rx) = tokio::sync::mpsc::channel::<VerifiedLeaf>(1);
    let transport_failure = Arc::new(std::sync::Mutex::new(None));
    let root = bao_tree::blake3::Hash::from(*content.as_bytes());
    let verifier = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut blocking_reader = BlockingBaoWireReader::new(wire_rx);
        nar_v4::decode_verified(&mut blocking_reader, root, raw_size, codec, |leaf| {
            let (release_on_next_pull, wait_for_next_pull) = std::sync::mpsc::channel();
            leaf_tx
                .blocking_send(VerifiedLeaf {
                    bytes: leaf,
                    release_on_next_pull,
                })
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "verified-leaf consumer closed")
                })?;
            wait_for_next_pull.recv().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "verified-leaf caller stopped before requesting the next leaf",
                )
            })
        })
    });
    (
        VerifiedNarWireSink {
            sender: wire_tx.clone(),
            transport_failure: Arc::clone(&transport_failure),
        },
        VerifiedNarStream {
            leaves: leaf_rx,
            verifier,
            expected: content,
            cancel: wire_tx,
            transport_failure,
            previous_leaf_release: None,
            leaves_finished: false,
        },
    )
}

/// The serve-side exchange deadline used when this node is NOT serving (no [`ServeGate`] to
/// source `max_serve_duration` from): a slowloris guard so a peer that opens a `/nar/4`
/// stream and then never sends its request digest - or never reads the `NotHeld` reply -
/// cannot park a serve task forever. A serving node uses its
/// [`ServeBudget::max_serve_duration`] instead (see [`serve_stream`]).
const UNSERVED_STREAM_DEADLINE: Duration = Duration::from_secs(30);

/// Send a fetch REQUEST on an opened outbound stream: the 32-byte content digest followed by
/// the 1-byte `accept` codec bitmask (which codecs the fetcher can DECODE - raw is mandatory,
/// TASK-99), flushed. Deliberately does NOT close the write half - the open write half is the
/// requester's "still interested" signal the server watches, so closing it early would look
/// like an abandoned request (see [`serve_stream`]).
pub(crate) async fn write_request<W>(
    writer: &mut W,
    content: &Blake3Digest,
    accept: u8,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(content.as_bytes()).await?;
    writer.write_all(&[accept]).await?;
    writer.flush().await
}

/// Read and authenticate one `/nar/4` response. The untrusted header declares
/// exact raw geometry before any tree allocation; every full-range Bao leaf is
/// verified against `content` in a bounded worker before it reaches the
/// collector. The final leaf is retained until COMPLETE and clean FIN.
///
/// `NarTransfer` still returns a `Vec` for seam compatibility; TASK-62 removes
/// that final collector. The wire pump, encoded-leaf decoder, verifier, and
/// verified-leaf handoff are each one-item bounded and independent of NAR size.
#[cfg(test)]
pub(crate) async fn read_response_streamed<R>(
    reader: &mut R,
    expected_size: Option<u64>,
    body_idle_timeout: Duration,
    content: &Blake3Digest,
) -> Result<Vec<u8>, TransferError>
where
    R: AsyncRead + Unpin,
{
    read_response_streamed_since(
        reader,
        expected_size,
        body_idle_timeout,
        content,
        std::time::Instant::now(),
        peer_fabric::ACCEPT_RAW_AND_ZSTD,
    )
    .await
    .map(|response| response.bytes)
}

pub(crate) struct AuthenticatedNar {
    pub(crate) bytes: Vec<u8>,
    pub(crate) authenticated_first_leaf_ns: u128,
    pub(crate) total_fetch_ns: u128,
    pub(crate) selected_codec: WireCodec,
}

/// The decoded `/nar/4` response header for a NAR body that follows: the chosen codec and
/// the provider-declared uncompressed RawNarV1 size.
pub(crate) struct NarHeader {
    pub(crate) codec: WireCodec,
    pub(crate) raw_size: u64,
}

/// Read and validate the `/nar/4` response status + codec/size header, returning the body
/// geometry when a NAR body follows.
///
/// This is the SINGLE source of truth for every terminal outcome decided BEFORE a body byte
/// is downloaded - `NotHeld`, `Declined`, the risk-6 `TooLarge` abort, a declared size that
/// disagrees with the signed bound, and an unknown status byte - so the collecting reader
/// ([`read_response_streamed_since`]) and the streaming reader (`open_nar_response_stream`)
/// enforce them IDENTICALLY, and a stream is opened only for a genuine, size-agreed NAR body.
/// Bounding the risk-6 abort here (before `verified_nar_stream` spawns a verifier or
/// `pump_bao_wire` pulls one body byte) caps a lying claim's wasted-download DoS to a
/// ~10-byte header read.
///
/// TRUST PRECONDITION (TASK-46, do not weaken silently): the size bound is sound only because
/// `expected_size` is the SIGNED NarSize from a TRUSTED narinfo; the p2p claim/offer schema
/// carries no size of its own, so a peer cannot move the ceiling. Units are uncompressed
/// RawNarV1 bytes, NEVER a compressed FileSize.
async fn read_nar_header<R>(
    reader: &mut R,
    expected_size: Option<u64>,
    body_idle_timeout: Duration,
    content: &Blake3Digest,
    accept: u8,
) -> Result<NarHeader, TransferError>
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
            let mut header = [0u8; 9];
            match tokio::time::timeout(body_idle_timeout, reader.read_exact(&mut header)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(TransferError::Unavailable(format!(
                        "NAR stream for {content} closed before its codec/size header: {error}"
                    )));
                }
                Err(_elapsed) => {
                    return Err(TransferError::Unavailable(format!(
                        "NAR stream for {content} stalled before its codec/size header for {body_idle_timeout:?}"
                    )));
                }
            }
            let codec = WireCodec::from_wire(header[0]).ok_or_else(|| {
                TransferError::Unavailable(format!(
                    "provider chose unknown NAR codec byte {} for {content}",
                    header[0]
                ))
            })?;
            let codec_bit = match codec {
                WireCodec::Raw => peer_fabric::ACCEPT_RAW,
                WireCodec::Zstd => peer_fabric::ACCEPT_ZSTD,
            };
            if accept & codec_bit == 0 {
                return Err(TransferError::Unavailable(format!(
                    "provider selected {codec:?} for {content}, but request accept mask {accept:#04x} did not offer it"
                )));
            }
            let raw_size = u64::from_le_bytes(header[1..].try_into().expect("8-byte size"));
            let cap = expected_size.unwrap_or(MAX_NAR_RESPONSE_BYTES);
            if raw_size > cap {
                return Err(TransferError::TooLarge {
                    limit: cap,
                    streamed: raw_size,
                });
            }
            if let Some(expected) = expected_size
                && raw_size != expected
            {
                return Err(TransferError::Unavailable(format!(
                    "provider declared raw_size {raw_size} for {content}, signed NarSize is {expected}"
                )));
            }
            Ok(NarHeader { codec, raw_size })
        }
        other => Err(TransferError::Unavailable(format!(
            "unknown NAR response status byte {other} from the provider for {content}"
        ))),
    }
}

/// The out-channel depth for the streaming fetch->HTTP handoff. With 64-KiB Bao leaves the
/// resident in-flight bytes peak at (this depth + the one leaf being sent) leaves, so a depth
/// of 3 bounds the fetcher-side in-flight window to `4 * STREAM_CHUNK_BYTES` =
/// [`peer_fabric::MAX_INFLIGHT_FETCH_BYTES_RAM`] (AC#2/AC#7), NarSize-INDEPENDENT.
const FETCH_OUT_CHANNEL_DEPTH: usize = 3;

/// A bounded, verifier-authenticated, metered stream of raw NAR leaves for the store-and-
/// forward HTTP path (TASK-62 AC#6).
///
/// TASK-62 inc3: promoted from the inc1 `#[cfg(test)]` design validation to the SHIPPED
/// serve path. It backs the libp2p [`peer_fabric::NarTransfer::fetch_stream`] override via
/// [`peer_fabric::NarChunkSource`], so `PeerFabricNarSource` builds the HTTP body from it
/// incrementally (AC#6/AC#4). It is still exercised by the AC#1/#3/#7 mechanism oracles
/// below over synthetic `/nar/4` wire, now against the SAME code the shipped path runs.
///
/// The header phase (status/codec/size + the risk-6 abort) is enforced by [`read_nar_header`]
/// BEFORE this value exists, so its construction implies a genuine, size-agreed NAR body
/// follows. Each [`next_chunk`](Self::next_chunk) yields the NEXT Bao-authenticated leaf; a
/// mid-stream failure (transport reset, stall, or a final Bao authentication failure at EOF)
/// surfaces as a TERMINAL `Err` chunk AFTER the earlier verified leaves - never as wrong bytes
/// (gate 1 holds per leaf; gate 2 sha256==NarHash is Nix's, downstream). Clean completion
/// yields `None`.
pub(crate) struct MeteredNarStream {
    /// The provider-declared uncompressed RawNarV1 size (the Content-Length source on the
    /// correlated path in inc2; the daemon frames chunked on the cold-start `None` path).
    pub(crate) declared_size: u64,
    out: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, io::Error>>,
    driver: Option<tokio::task::JoinHandle<()>>,
    meter: Arc<InflightMeter>,
    finished: bool,
}

impl MeteredNarStream {
    /// Pull the next Bao-authenticated raw NAR leaf. `Some(Ok(bytes))` is a verified chunk;
    /// `Some(Err(_))` is the TERMINAL mid-stream failure (the client sees a truncated NAR and
    /// Nix retries the next substituter - the PRD additive invariant, AC#3); `None` is clean
    /// EOF. Releasing the consumed chunk from the in-flight meter here is the AC#7 permit
    /// release for a delivered byte.
    pub(crate) async fn next_chunk(&mut self) -> Option<Result<bytes::Bytes, io::Error>> {
        if self.finished {
            return None;
        }
        match self.out.recv().await {
            Some(Ok(bytes)) => {
                self.meter.release(bytes.len() as u64);
                Some(Ok(bytes))
            }
            Some(Err(error)) => {
                self.finished = true;
                Some(Err(error))
            }
            None => {
                self.finished = true;
                None
            }
        }
    }
}

/// The [`peer_fabric::NarChunkSource`] view the shipped serve path consumes: it forwards
/// to the inherent [`MeteredNarStream::next_chunk`] (which releases the delivered chunk from
/// the in-flight meter). The trait is what lets `peer_source` build one HTTP body regardless
/// of which backend produced the stream.
#[async_trait::async_trait]
impl NarChunkSource for MeteredNarStream {
    async fn next_chunk(&mut self) -> Option<Result<bytes::Bytes, io::Error>> {
        MeteredNarStream::next_chunk(self).await
    }
}

impl Drop for MeteredNarStream {
    fn drop(&mut self) {
        // AC#7 teardown: dropping the consumer aborts the producer task, so a client
        // disconnect / HEAD / cancellation stops the peer transfer promptly (task-cancellation
        // latency) rather than waiting for the next leaf boundary. Dropping the receiver would
        // also break the producer's `send`, but the explicit abort is the tighter bound.
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

/// Open a bounded, metered streaming read of the `/nar/4` response for the store-and-forward
/// HTTP path (TASK-62 AC#6). Enforces the header/size gates synchronously via
/// [`read_nar_header`] - so `NotHeld` / `Declined` / the risk-6 `TooLarge` abort / a size
/// mismatch are returned as `Err` BEFORE any body byte, hence before a 200 could be committed
/// to the client - then spawns a producer that pumps the wire, verifies each leaf against
/// `content` (gate 1), COPIES it into an independently-owned `Bytes`, charges the shared
/// `meter`, and forwards it into a depth-bounded channel. The channel depth bounds resident
/// fetch-side bytes to [`peer_fabric::MAX_INFLIGHT_FETCH_BYTES_RAM`] independent of NAR size.
///
/// The per-leaf copy is deliberate and NOT extra O(N) work versus the collector: the old
/// collector already copied every leaf via `extend_from_slice`. Copying decouples the
/// consumer-held `Bytes` from the verifier's pull-discipline buffer, so retaining a delivered
/// chunk past the next pull is memory-safe.
///
/// `reader` is taken BY VALUE (`Send + 'static`) because the producer owns it for the transfer;
/// the libp2p substream is exactly such an owned handle.
pub(crate) async fn open_nar_response_stream<R>(
    mut reader: R,
    expected_size: Option<u64>,
    body_idle_timeout: Duration,
    content: Blake3Digest,
    accept: u8,
    meter: Arc<InflightMeter>,
) -> Result<MeteredNarStream, TransferError>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let NarHeader { codec, raw_size } = read_nar_header(
        &mut reader,
        expected_size,
        body_idle_timeout,
        &content,
        accept,
    )
    .await?;

    let (wire_sink, mut verified) = verified_nar_stream(content, raw_size, codec).await;
    let (out_tx, out_rx) =
        tokio::sync::mpsc::channel::<Result<bytes::Bytes, io::Error>>(FETCH_OUT_CHANNEL_DEPTH);
    let producer_meter = Arc::clone(&meter);
    let driver = tokio::spawn(async move {
        // Pump the wire into the verifier and forward verified leaves concurrently (the same
        // join the collector uses). The forward loop charges the meter as each verified leaf
        // enters the bounded handoff and stops the instant the consumer is gone (send error) -
        // that is the AC#7 teardown that releases in-flight bytes and halts the peer transfer.
        let pump = pump_bao_wire(&mut reader, wire_sink, body_idle_timeout, &content);
        let forward = async {
            while let Some(leaf) = verified.next_leaf().await {
                let owned = bytes::Bytes::copy_from_slice(&leaf);
                let n = owned.len() as u64;
                producer_meter.charge(n);
                if out_tx.send(Ok(owned)).await.is_err() {
                    // Consumer dropped: release what we charged and stop. Dropping `verified`
                    // and the pump future aborts the peer transfer.
                    producer_meter.release(n);
                    return false; // did not complete cleanly
                }
            }
            true
        };
        let (pump_result, forwarded_all) = tokio::join!(pump, forward);
        if !forwarded_all {
            return; // consumer went away mid-stream; nothing more to deliver
        }
        // All leaves forwarded. Confirm the verifier's terminal contract (COMPLETE + clean FIN
        // + full authentication). A failure HERE - after leaves were delivered - becomes a
        // TERMINAL error chunk so the HTTP body errors out and Nix refetches (AC#3), never a
        // clean EOF that would present a truncated NAR as complete.
        let terminal = match (verified.finish().await, pump_result) {
            (Ok(verified_bytes), Ok(())) if verified_bytes == raw_size => None,
            (Ok(verified_bytes), Ok(())) => Some(format!(
                "Bao verifier completed {verified_bytes} B, header declared {raw_size} B for {content}"
            )),
            (Err(error), _) => Some(error.to_string()),
            (_, Err(error)) => Some(error.to_string()),
        };
        if let Some(why) = terminal {
            let _ = out_tx
                .send(Err(io::Error::new(io::ErrorKind::InvalidData, why)))
                .await;
        }
        // Dropping out_tx closes the channel: the consumer sees clean EOF (None) on success or
        // the terminal Err above on failure.
    });

    Ok(MeteredNarStream {
        declared_size: raw_size,
        out: out_rx,
        driver: Some(driver),
        meter,
        finished: false,
    })
}

pub(crate) async fn read_response_streamed_since<R>(
    reader: &mut R,
    expected_size: Option<u64>,
    body_idle_timeout: Duration,
    content: &Blake3Digest,
    request_started: std::time::Instant,
    accept: u8,
) -> Result<AuthenticatedNar, TransferError>
where
    R: AsyncRead + Unpin,
{
    let NarHeader { codec, raw_size } =
        match read_nar_header(reader, expected_size, body_idle_timeout, content, accept).await {
            Ok(header) => header,
            Err(error) => return Err(error),
        };

    let (wire_sink, mut verified) = verified_nar_stream(*content, raw_size, codec).await;

    let pump = pump_bao_wire(reader, wire_sink, body_idle_timeout, content);
    let collect = async {
        let mut raw = Vec::new();
        let mut first_leaf = None;
        while let Some(leaf) = verified.next_leaf().await {
            first_leaf.get_or_insert_with(std::time::Instant::now);
            raw.extend_from_slice(&leaf);
        }
        (raw, first_leaf)
    };
    let (pump_result, (raw, first_leaf)) = tokio::join!(pump, collect);
    let verified_bytes = verified.finish().await?;
    pump_result?;
    if verified_bytes != raw_size || raw.len() as u64 != raw_size {
        return Err(TransferError::Unavailable(format!(
            "Bao verifier completed {verified_bytes} B and collector got {} B, header declared {raw_size} B",
            raw.len()
        )));
    }
    let authenticated_first_leaf_ns = first_leaf
        .map(|first_leaf| first_leaf.duration_since(request_started).as_nanos())
        .ok_or_else(|| {
            TransferError::Unavailable(format!(
                "successful Bao verification for {content} emitted no authenticated leaf"
            ))
        })?;
    tracing::debug!(
        %content,
        authenticated_first_leaf_ns,
        raw_size,
        "libp2p fetch: first Bao-authenticated leaf exposed"
    );
    Ok(AuthenticatedNar {
        bytes: raw,
        authenticated_first_leaf_ns,
        total_fetch_ns: request_started.elapsed().as_nanos(),
        selected_codec: codec,
    })
}

pub(crate) async fn pump_bao_wire<R>(
    reader: &mut R,
    sender: VerifiedNarWireSink,
    body_idle_timeout: Duration,
    content: &Blake3Digest,
) -> Result<(), TransferError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; NAR_STREAM_CHUNK];
    loop {
        let read = tokio::select! {
            () = sender.closed() => {
                return Err(TransferError::Unavailable(format!(
                    "Bao verifier stopped before the wire ended for {content}"
                )));
            }
            read = tokio::time::timeout(body_idle_timeout, reader.read(&mut buf)) => read,
        };
        let n = match read {
            Ok(Ok(0)) => {
                sender.finish().await.map_err(|()| {
                    TransferError::Unavailable(format!(
                        "Bao verifier stopped before transport EOF for {content}"
                    ))
                })?;
                break;
            }
            Ok(Ok(n)) => n,
            Ok(Err(error)) => {
                sender
                    .fail(io::Error::new(error.kind(), error.to_string()))
                    .await;
                return Err(TransferError::Unavailable(format!(
                    "NAR stream for {content} failed mid-transfer: {error}"
                )));
            }
            Err(_elapsed) => {
                let why = format!(
                    "NAR transfer for {content} stalled: no bytes for {body_idle_timeout:?}"
                );
                sender
                    .fail(io::Error::new(io::ErrorKind::TimedOut, why.clone()))
                    .await;
                return Err(TransferError::Unavailable(format!(
                    "NAR transfer for {content} stalled: no bytes for {body_idle_timeout:?}"
                )));
            }
        };
        if sender.send(buf[..n].to_vec()).await.is_err() {
            return Err(TransferError::Unavailable(format!(
                "Bao verifier stopped before the wire ended for {content}"
            )));
        }
    }
    Ok(())
}

/// Frame a response and close its write half. A NAR uses the wholesale v4
/// header (`status`, response-global codec, exact raw size), canonical Bao
/// preorder body, COMPLETE marker, then FIN.
async fn write_response<W>(
    writer: &mut W,
    response: NarResponse,
    codec: WireCodec,
    level: i32,
    content: &Blake3Digest,
) -> Result<(), ResponseWriteError>
where
    W: AsyncWrite + Unpin,
{
    match response {
        NarResponse::NotHeld => writer
            .write_all(&[STATUS_NOT_HELD])
            .await
            .map_err(ResponseWriteError::Transport)?,
        NarResponse::Declined(reason) => writer
            .write_all(&[STATUS_DECLINED, reason.wire()])
            .await
            .map_err(ResponseWriteError::Transport)?,
        NarResponse::Nar(bytes) => {
            write_memory_nar_v4(writer, bytes, codec, level, content).await?;
        }
    }
    writer
        .flush()
        .await
        .map_err(ResponseWriteError::Transport)?;
    // Half-close: the FIN is how the fetcher knows the (length-prefix-free) NAR is complete.
    writer.close().await.map_err(ResponseWriteError::Transport)
}

async fn write_memory_nar_v4<W>(
    writer: &mut W,
    bytes: Arc<Vec<u8>>,
    codec: WireCodec,
    level: i32,
    content: &Blake3Digest,
) -> Result<(), ResponseWriteError>
where
    W: AsyncWrite + Unpin,
{
    let proof_started = std::time::Instant::now();
    let permit = BAO_WORKER_POOLS.acquire_serve().await;
    let prepared = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let raw_size = bytes.len() as u64;
        let mut cursor = io::Cursor::new(bytes.as_slice());
        let outboard = nar_v4::create_outboard(&mut cursor, raw_size)?;
        Ok::<_, io::Error>((bytes, outboard))
    })
    .await
    .map_err(|error| ResponseWriteError::Supply(format!("Bao proof worker failed: {error}")))?
    .map_err(|error| ResponseWriteError::Supply(format!("Bao proof creation failed: {error}")))?;
    let (bytes, outboard) = prepared;
    let requested_root = bao_tree::blake3::Hash::from(*content.as_bytes());
    if outboard.root != requested_root {
        return Err(ResponseWriteError::Supply(format!(
            "memory source root {} does not match requested {content}",
            outboard.root.to_hex()
        )));
    }
    let proof_preparation_ns = proof_started.elapsed().as_nanos();
    let raw_size = bytes.len() as u64;
    writer
        .write_all(&[&[STATUS_NAR, codec.wire()][..], &raw_size.to_le_bytes()].concat())
        .await
        .map_err(ResponseWriteError::Transport)?;

    let (wire_tx, mut wire_rx) = tokio::sync::mpsc::channel::<OwnedWireChunk>(1);
    let permit = BAO_WORKER_POOLS.acquire_serve().await;
    let encoder = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let (sink, raw_bytes, framed_bao_bytes) = nar_v4::encode_validated(
            bytes.as_slice(),
            &outboard,
            BlockingChunkWriter::new(wire_tx),
            codec,
            level,
        )?;
        drop(sink);
        Ok::<_, io::Error>((raw_bytes, framed_bao_bytes))
    });
    let mut write_error = None;
    while let Some(item) = wire_rx.recv().await {
        let OwnedWireChunk { mut bytes, recycle } = item;
        if let Err(error) = writer.write_all(&bytes).await {
            write_error = Some(error);
            wire_rx.close();
            drop(recycle);
            break;
        }
        bytes.clear();
        let _ = recycle.send(bytes);
    }
    let encoded = encoder.await.map_err(|error| {
        ResponseWriteError::Supply(format!("Bao encode worker failed: {error}"))
    })?;
    if let Some(error) = write_error {
        return Err(ResponseWriteError::Transport(error));
    }
    let (pass2_bytes, framed_bao_bytes) = encoded.map_err(|error| {
        ResponseWriteError::Supply(format!("Bao authentication/framing failed: {error}"))
    })?;
    if pass2_bytes != raw_size {
        return Err(ResponseWriteError::Supply(format!(
            "Bao pass encoded {pass2_bytes} B, expected {raw_size} B"
        )));
    }
    writer
        .write_all(nar_v4::COMPLETE_MARKER)
        .await
        .map_err(ResponseWriteError::Transport)?;
    let wire =
        nar_v4::NarV4WireAccounting::from_framed_bao_bytes(raw_size, codec, framed_bao_bytes)
            .map_err(|error| {
                ResponseWriteError::Supply(format!("/nar/4 byte accounting failed: {error}"))
            })?;
    tracing::debug!(
        %content,
        proof_preparation_ns,
        pass1_bytes = raw_size,
        pass2_bytes,
        proof_bytes = wire.proof_bytes,
        leaf_count = wire.leaf_count,
        leaf_length_prefix_bytes = wire.leaf_length_prefix_bytes,
        encoded_leaf_bytes = wire.encoded_leaf_bytes,
        response_protocol_bytes = wire.response_protocol_bytes,
        exchange_protocol_bytes = wire.exchange_protocol_bytes,
        memory_proof_and_encode_ns = proof_started.elapsed().as_nanos(),
        "libp2p serve: memory Bao response completed"
    );
    Ok(())
}

fn validate_replay_completion(
    source: &ReplayableProcessSource,
    pass: &'static str,
    completion: SupervisedProcessCompletion,
) -> Result<u64, String> {
    if completion.stdout_exceeded_limit {
        return Err(format!(
            "{pass} source {} exceeded declared raw_size {} B",
            source.program.display(),
            source.declared_size
        ));
    }
    if completion.stdout_bytes_read as u64 != source.declared_size {
        return Err(format!(
            "{pass} source {} produced {} B, declared raw_size is {} B",
            source.program.display(),
            completion.stdout_bytes_read,
            source.declared_size
        ));
    }
    if !completion.status.success() {
        return Err(format!(
            "{pass} source process {} exited {} after {} B: {}",
            source.program.display(),
            completion.status,
            completion.stdout_bytes_read,
            String::from_utf8_lossy(&completion.stderr).trim()
        ));
    }
    Ok(completion.stdout_bytes_read as u64)
}

async fn pump_process_stdout(
    mut process: SupervisedProcessStream,
    sender: tokio::sync::mpsc::Sender<io::Result<Vec<u8>>>,
    source: &ReplayableProcessSource,
    pass: &'static str,
) -> Result<u64, String> {
    while let Some(chunk) = process.next_chunk().await {
        if sender.send(Ok(chunk)).await.is_err() {
            let _ = process.cancel_and_wait().await;
            return Err(format!(
                "{pass} Bao worker stopped before source {} completed",
                source.program.display()
            ));
        }
    }
    drop(sender);
    let completion = process.finish().await.map_err(|error| {
        format!(
            "waiting for {pass} source process {}: {error}",
            source.program.display()
        )
    })?;
    validate_replay_completion(source, pass, completion)
}

#[derive(Clone, Copy)]
struct ProcessServeContext<'a> {
    source: &'a ReplayableProcessSource,
    supervisor: &'a TaskSupervisorHandle,
    cleanup: &'a ServeProcessCleanup,
    pools: &'a BaoWorkerPools,
}

async fn prepare_process_outboard(
    context: ProcessServeContext<'_>,
    content: &Blake3Digest,
) -> Result<(bao_tree::io::outboard::PreOrderOutboard<Vec<u8>>, u64, u128), String> {
    let started = std::time::Instant::now();
    // Admission owns the reservation already, but no producer may exist while
    // this request is merely queued for bounded Bao capacity.
    let permit = context.pools.acquire_serve().await;
    let process = context
        .source
        .start(context.supervisor, context.cleanup, "pass1")?;
    let (data_tx, data_rx) = tokio::sync::mpsc::channel::<io::Result<Vec<u8>>>(1);
    let raw_size = context.source.declared_size;
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut reader = BlockingChunkReader::new(data_rx);
        nar_v4::create_outboard(&mut reader, raw_size)
    });
    let (process_result, outboard_result) = tokio::join!(
        pump_process_stdout(process, data_tx, context.source, "pass1"),
        worker
    );
    let pass1_bytes = process_result?;
    let outboard = outboard_result
        .map_err(|error| format!("pass1 Bao proof worker failed: {error}"))?
        .map_err(|error| format!("pass1 Bao proof creation failed: {error}"))?;
    let requested = bao_tree::blake3::Hash::from(*content.as_bytes());
    if outboard.root != requested {
        return Err(format!(
            "pass1 source {} for {content} has root {}, refusing before STATUS_NAR",
            context.source.program.display(),
            outboard.root.to_hex()
        ));
    }
    Ok((outboard, pass1_bytes, started.elapsed().as_nanos()))
}

async fn write_process_nar_v4<W>(
    writer: &mut W,
    context: ProcessServeContext<'_>,
    outboard: bao_tree::io::outboard::PreOrderOutboard<Vec<u8>>,
    codec: WireCodec,
    level: i32,
) -> Result<(u64, nar_v4::NarV4WireAccounting), ProcessServeError>
where
    W: AsyncWrite + Unpin,
{
    // As in pass 1, capacity precedes process creation. Otherwise a saturated
    // Bao pool admits up to the supervisor ceiling of idle producer groups.
    let permit = context.pools.acquire_serve().await;
    let process = context
        .source
        .start(context.supervisor, context.cleanup, "pass2")
        .map_err(ProcessServeError::Supply)?;
    let (data_tx, data_rx) = tokio::sync::mpsc::channel::<io::Result<Vec<u8>>>(1);
    let (wire_tx, mut wire_rx) = tokio::sync::mpsc::channel::<OwnedWireChunk>(1);
    let encoder = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut reader = BlockingChunkReader::new(data_rx);
        let (sink, raw_bytes, framed_bao_bytes) = nar_v4::encode_validated_reader(
            &mut reader,
            &outboard,
            BlockingChunkWriter::new(wire_tx),
            codec,
            level,
        )?;
        drop(sink);
        Ok::<_, io::Error>((raw_bytes, framed_bao_bytes))
    });
    let drain_wire = async {
        while let Some(item) = wire_rx.recv().await {
            let OwnedWireChunk { mut bytes, recycle } = item;
            if let Err(error) = writer.write_all(&bytes).await {
                // This future borrows `wire_rx`; simply returning would leave
                // the receiver open until the surrounding join completed.
                // Closing it and dropping this ownership acknowledgement
                // makes both the encoder and its process-input pump unwind.
                wire_rx.close();
                drop(recycle);
                return Err(ProcessServeError::Transport(format!(
                    "writing authenticated pass2 bytes: {error}"
                )));
            }
            bytes.clear();
            let _ = recycle.send(bytes);
        }
        Ok::<(), ProcessServeError>(())
    };
    let (process_result, wire_result, encode_result) = tokio::join!(
        pump_process_stdout(process, data_tx, context.source, "pass2"),
        drain_wire,
        encoder
    );
    // Prefer the actual socket error over the secondary broken-pipe errors it
    // induces in the encoder/process pipeline.
    wire_result?;
    let pass2_bytes = process_result.map_err(ProcessServeError::Supply)?;
    let (encoded_raw_bytes, framed_bao_bytes) = encode_result
        .map_err(|error| {
            ProcessServeError::Supply(format!("pass2 Bao encoder worker failed: {error}"))
        })?
        .map_err(|error| {
            ProcessServeError::Supply(format!("pass2 Bao authentication/framing failed: {error}"))
        })?;
    if encoded_raw_bytes != context.source.declared_size
        || pass2_bytes != context.source.declared_size
    {
        return Err(ProcessServeError::Supply(format!(
            "pass2 byte-accounting mismatch: process {pass2_bytes} B, Bao {encoded_raw_bytes} B, declared {} B",
            context.source.declared_size
        )));
    }
    let wire = nar_v4::NarV4WireAccounting::from_framed_bao_bytes(
        context.source.declared_size,
        codec,
        framed_bao_bytes,
    )
    .map_err(|error| {
        ProcessServeError::Supply(format!("pass2 /nar/4 byte accounting failed: {error}"))
    })?;
    Ok((pass2_bytes, wire))
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

enum AdmittedServe {
    Immediate {
        response: NarResponse,
        reservation: Option<InflightReservation>,
        gate: Option<Arc<ServeGate>>,
    },
    Process {
        gate: Arc<ServeGate>,
        source: ReplayableProcessSource,
        reservation: InflightReservation,
    },
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
    serve_stream_with_process_pools(stream, gate, &BAO_WORKER_POOLS).await;
}

/// Test seam for overriding the Bao pools consulted by process-backed pass 1/pass 2 serving.
/// Memory-backed serving does not acquire from the injected process pool.
async fn serve_stream_with_process_pools<S>(
    stream: S,
    gate: Option<Arc<ServeGate>>,
    pools: &BaoWorkerPools,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let serve_started = tokio::time::Instant::now();
    let (mut read_half, mut write_half) = stream.split();

    // One absolute deadline covers request parsing, both regeneration passes,
    // socket backpressure, COMPLETE, and FIN. It is never renewed per phase.
    let serve_duration = gate
        .as_ref()
        .map(|gate| gate.max_serve_duration())
        .unwrap_or(UNSERVED_STREAM_DEADLINE);
    let deadline_at = serve_started + serve_duration;

    // The serve-side compression policy (TASK-99): what this node is WILLING to do. A
    // non-serving node never ships a body, so the default (unused) is fine.
    let codec_policy = gate
        .as_ref()
        .map(|gate| gate.codec_policy())
        .unwrap_or_default();

    // The request: 32 digest bytes + 1 `accept` codec bitmask byte (TASK-99), bounded - a
    // peer that opens a stream then stalls (sends a partial request, or nothing) cannot park
    // this task forever.
    let mut request = [0u8; 33];
    match tokio::time::timeout_at(deadline_at, read_half.read_exact(&mut request)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::debug!(%error, "libp2p serve: inbound NAR stream closed before its request");
            return;
        }
        Err(_elapsed) => {
            tracing::debug!(
                ?serve_duration,
                "libp2p serve: inbound NAR request did not arrive within the serve deadline"
            );
            return;
        }
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&request[..32]);
    let accept = request[32];
    let content = Blake3Digest::from_bytes(digest);

    // The in-flight reservation - for a Memory serve OR a Process serve - is held HERE, at
    // serve_stream scope, so it lives through production AND the response write. The ceiling
    // then accounts for the produced NAR's memory while it is resident being written, for
    // BOTH source kinds: a consumer that never reads cannot park a reservation-free blocked
    // write and so slip past the ceiling (codex DEEP-gate finding). It was created
    // synchronously at admit, so dropping this task at ANY point after admit - including a
    // drop before the first poll - releases the reserve exactly once (`None` for a non-admit,
    // which reserved nothing).
    let admitted = match gate {
        None => AdmittedServe::Immediate {
            response: NarResponse::NotHeld,
            reservation: None,
            gate: None,
        },
        Some(gate) => match gate.admit(&content) {
            Serve::Now {
                response,
                reservation,
            } => AdmittedServe::Immediate {
                response,
                reservation,
                gate: Some(Arc::clone(&gate)),
            },
            Serve::OffLoop {
                plan, reservation, ..
            } => match plan.into_replayable_process() {
                Ok(source) => AdmittedServe::Process {
                    gate,
                    source,
                    reservation,
                },
                Err(why) => {
                    tracing::error!(%content, %why, "libp2p serve: admitted process plan was not replayable");
                    return;
                }
            },
        },
    };

    if let AdmittedServe::Process {
        gate,
        source,
        reservation: _reservation,
    } = &admitted
    {
        let (codec, reason) = match negotiate_serve_codec(
            accept,
            &codec_policy,
            source.declared_size,
        ) {
            Ok(selected) => selected,
            Err(no_codec) => {
                tracing::debug!(%content, %no_codec, "libp2p serve: declining - no common NAR codec offered");
                let result = tokio::time::timeout_at(
                    deadline_at,
                    write_response(
                        &mut write_half,
                        NarResponse::Declined(DeclineReason::NoCommonCodec),
                        WireCodec::Raw,
                        codec_policy.level,
                        &content,
                    ),
                )
                .await;
                // This is a protocol decline after byte admission, not a completed NAR serve and
                // not a supplier failure. It therefore owns no existing ServeGate counter; the
                // reservation is released when this branch returns. Classify every write outcome
                // explicitly so a failed/expired decline cannot disappear as apparent success.
                match result {
                    Ok(Ok(())) => tracing::debug!(
                        %content,
                        %no_codec,
                        ?serve_duration,
                        total_serve_ns = serve_started.elapsed().as_nanos(),
                        "libp2p serve: no-common-codec decline response completed"
                    ),
                    Ok(Err(ResponseWriteError::Supply(why))) => tracing::error!(
                        %content,
                        %no_codec,
                        %why,
                        ?serve_duration,
                        total_serve_ns = serve_started.elapsed().as_nanos(),
                        "libp2p serve: body-free no-common-codec decline hit an impossible supply failure"
                    ),
                    Ok(Err(ResponseWriteError::Transport(error))) => tracing::debug!(
                        %content,
                        %no_codec,
                        %error,
                        ?serve_duration,
                        total_serve_ns = serve_started.elapsed().as_nanos(),
                        "libp2p serve: failed to write no-common-codec decline response"
                    ),
                    Err(_elapsed) => tracing::debug!(
                        %content,
                        %no_codec,
                        ?serve_duration,
                        total_serve_ns = serve_started.elapsed().as_nanos(),
                        "libp2p serve: absolute deadline expired while writing no-common-codec decline response"
                    ),
                }
                return;
            }
        };
        if reason != CodecChoiceReason::ZstdNegotiated {
            tracing::trace!(%content, %reason, "libp2p serve: raw NAR codec (named fallback)");
        }
        let cleanup = ServeProcessCleanup::default();
        let exchange_cleanup = cleanup.clone();
        let terminal_close_started = AtomicBool::new(false);
        let exchange = async {
            let process_context = ProcessServeContext {
                source,
                supervisor: &gate.supervisor,
                cleanup: &exchange_cleanup,
                pools,
            };
            let (outboard, pass1_bytes, proof_preparation_ns) =
                prepare_process_outboard(process_context, &content)
                    .await
                    .map_err(ProcessServeError::Supply)?;
            write_half
                .write_all(
                    &[
                        &[STATUS_NAR, codec.wire()][..],
                        &source.declared_size.to_le_bytes(),
                    ]
                    .concat(),
                )
                .await
                .map_err(|error| {
                    ProcessServeError::Transport(format!("writing /nar/4 response header: {error}"))
                })?;
            let (pass2_bytes, wire) = write_process_nar_v4(
                &mut write_half,
                process_context,
                outboard,
                codec,
                codec_policy.level,
            )
            .await?;
            write_half
                .write_all(nar_v4::COMPLETE_MARKER)
                .await
                .map_err(|error| {
                    ProcessServeError::Transport(format!("writing /nar/4 COMPLETE: {error}"))
                })?;
            write_half.flush().await.map_err(|error| {
                ProcessServeError::Transport(format!("flushing /nar/4 COMPLETE: {error}"))
            })?;
            terminal_close_started.store(true, Ordering::Release);
            write_half.close().await.map_err(|error| {
                ProcessServeError::Transport(format!("closing /nar/4 response: {error}"))
            })?;
            Ok::<_, ProcessServeError>((pass1_bytes, pass2_bytes, wire, proof_preparation_ns))
        };
        let exchange = tokio::time::timeout_at(deadline_at, exchange);
        tokio::pin!(exchange);
        let result = tokio::select! {
            biased;
            result = &mut exchange => Some(result),
            () = consumer_hung_up(&mut read_half) => {
                if terminal_close_started.load(Ordering::Acquire) {
                    // COMPLETE is flushed and no producer remains. A requester
                    // may now close its request half as soon as it observes
                    // response FIN. Let the already-deadline-bounded close
                    // resolve so simultaneous readiness cannot erase success.
                    Some((&mut exchange).await)
                } else {
                    None
                }
            }
        };
        match result {
            Some(result) => match result {
                Ok(Ok((pass1_bytes, pass2_bytes, wire, proof_preparation_ns))) => {
                    gate.admitted.fetch_add(1, Ordering::Relaxed);
                    let total_serve_ns = serve_started.elapsed().as_nanos();
                    tracing::info!(
                        %content,
                        pass1_bytes,
                        pass2_bytes,
                        proof_bytes = wire.proof_bytes,
                        leaf_count = wire.leaf_count,
                        leaf_length_prefix_bytes = wire.leaf_length_prefix_bytes,
                        encoded_leaf_bytes = wire.encoded_leaf_bytes,
                        response_protocol_bytes = wire.response_protocol_bytes,
                        exchange_protocol_bytes = wire.exchange_protocol_bytes,
                        proof_preparation_ns,
                        total_serve_ns,
                        "libp2p serve: two-pass bounded Bao regeneration completed"
                    );
                    if let Some(observations) = &gate.observations
                        && let Err(error) = observations.try_send(ServeObservation {
                            content,
                            selected_codec: codec,
                            pass1_bytes,
                            pass2_bytes,
                            proof_preparation_ns,
                            total_serve_ns,
                            wire,
                        })
                    {
                        tracing::debug!(
                            %content,
                            %error,
                            "libp2p serve: bounded process observation was not accepted"
                        );
                    }
                }
                Ok(Err(ProcessServeError::Supply(why))) => {
                    gate.declined_supply_failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%content, %why, "libp2p serve: two-pass regeneration failed closed");
                }
                Ok(Err(ProcessServeError::Transport(why))) => {
                    tracing::debug!(%content, %why, "libp2p serve: transport failed after process admission");
                }
                Err(_elapsed) => {
                    let (reap_jobs, reap_tail_ns, reap_complete) = cleanup.cancel_and_wait().await;
                    tracing::warn!(
                        %content,
                        ?serve_duration,
                        total_serve_ns = serve_started.elapsed().as_nanos(),
                        reap_jobs,
                        reap_tail_ns,
                        reap_complete,
                        "libp2p serve: absolute serve deadline expired; cancelling producers"
                    );
                }
            },
            None => {
                tracing::debug!(%content, "libp2p serve: consumer hung up; cancelling two-pass regeneration");
                let (reap_jobs, reap_tail_ns, reap_complete) = cleanup.cancel_and_wait().await;
                tracing::info!(%content, reap_jobs, reap_tail_ns, reap_complete, "libp2p serve: consumer-hangup reap tail measured");
            }
        }
        return;
    }

    let AdmittedServe::Immediate {
        response,
        reservation: _reservation,
        gate: immediate_gate,
    } = admitted
    else {
        unreachable!("process serve returned above")
    };

    // Negotiate the wire codec for a NAR body (TASK-99): intersect what the fetcher offered
    // (`accept`) with this node's policy, for a nar of the produced size. The chosen codec is
    // ALWAYS one the fetcher offered; the reason is logged so a raw fallback is never silent
    // (AC#5). If the fetcher offered NO honourable codec (a broken/hostile `accept`; a
    // compliant fetcher always offers raw), that is a protocol error - DECLINE the request
    // rather than ship a codec it never offered. NotHeld/Declined carry no body, so the codec
    // is irrelevant there.
    //
    // Codec capability mixing is within wholesale `/nar/4`; no prior protocol
    // is registered or opened because doing so would silently drop Bao guarantees.
    let (response, codec, level) = match response {
        NarResponse::Nar(bytes) => {
            match negotiate_serve_codec(accept, &codec_policy, bytes.len() as u64) {
                Ok((codec, reason)) => {
                    if reason != CodecChoiceReason::ZstdNegotiated {
                        tracing::trace!(%content, %reason, "libp2p serve: raw NAR codec (named fallback)");
                    }
                    (NarResponse::Nar(bytes), codec, codec_policy.level)
                }
                Err(no_codec) => {
                    tracing::debug!(%content, %no_codec, "libp2p serve: declining - no common NAR codec offered");
                    (
                        NarResponse::Declined(DeclineReason::NoCommonCodec),
                        WireCodec::Raw,
                        codec_policy.level,
                    )
                }
            }
        }
        other => (other, WireCodec::Raw, codec_policy.level),
    };

    // The response write, bounded: a consumer that never READS its response (but keeps the
    // stream open, so `consumer_hung_up` above never fired) would otherwise block `write_all`
    // on yamux backpressure forever, holding the reservation and parking this task. The
    // deadline caps that; dropping `write_half` on return resets the substream, and
    // `_reservation` releases as this function returns.
    let served_nar = matches!(&response, NarResponse::Nar(_));
    match tokio::time::timeout_at(
        deadline_at,
        write_response(&mut write_half, response, codec, level, &content),
    )
    .await
    {
        Ok(Ok(())) => {
            if served_nar && let Some(gate) = &immediate_gate {
                gate.admitted.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(Err(ResponseWriteError::Supply(why))) => {
            if served_nar && let Some(gate) = &immediate_gate {
                gate.declined_supply_failed.fetch_add(1, Ordering::Relaxed);
            }
            tracing::warn!(%why, %content, "libp2p serve: admitted memory supply failed before clean response");
        }
        Ok(Err(ResponseWriteError::Transport(error))) => {
            tracing::debug!(%error, %content, "libp2p serve: failed to write NAR response (consumer gone?)");
        }
        Err(_elapsed) => {
            tracing::debug!(?serve_duration, %content, "libp2p serve: absolute response deadline expired (consumer not reading); dropping");
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
#[derive(Clone)]
enum NarSource {
    /// The raw NAR is already resident (test/inline supply).
    Memory(Arc<Vec<u8>>),
    /// Regenerate the raw NAR by running `program args` in an OWNED process group and
    /// taking its stdout (`nix-store --dump <path>`, or the raw-NAR helper for a
    /// regular file). Served only by the bounded two-pass v4 regeneration path,
    /// so the child rides in a killable, reaped-on-shutdown job (AC#2).
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
#[derive(Clone)]
pub struct NarSupplyPlan {
    declared_size: u64,
    source: NarSource,
}

#[derive(Clone)]
struct ReplayableProcessSource {
    declared_size: u64,
    program: PathBuf,
    args: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
}

impl ReplayableProcessSource {
    fn stdout_limit(&self) -> Result<usize, String> {
        usize::try_from(self.declared_size).map_err(|_| {
            format!(
                "declared process output {} B does not fit this platform's address space",
                self.declared_size
            )
        })
    }

    fn start(
        &self,
        supervisor: &TaskSupervisorHandle,
        cleanup: &ServeProcessCleanup,
        pass: &'static str,
    ) -> Result<SupervisedProcessStream, String> {
        let stream = supervisor
            .stream_process(
                format!("libp2p-nar-supplier-{pass}"),
                self.program.clone(),
                self.args.clone(),
                self.environment.clone(),
                self.stdout_limit()?,
            )
            .map_err(|error| {
                format!(
                    "starting {pass} source process {}: {error}",
                    self.program.display()
                )
            })?;
        cleanup.track(stream.cleanup_ticket());
        Ok(stream)
    }
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
    /// rather than the inline [`Self::produce`]: true for a
    /// [`NarSource::Process`] (a `nix-store --dump` / raw-NAR helper that must ride in a
    /// killable, reaped-on-shutdown process group), false for an already-resident
    /// [`NarSource::Memory`]. The swarm serve loop routes Process sources OFF the poll
    /// thread on this (TASK-193).
    pub(crate) fn requires_supervised_production(&self) -> bool {
        matches!(self.source, NarSource::Process { .. })
    }

    fn into_replayable_process(self) -> Result<ReplayableProcessSource, String> {
        match self.source {
            NarSource::Process {
                program,
                args,
                environment,
            } => Ok(ReplayableProcessSource {
                declared_size: self.declared_size,
                program,
                args,
                environment,
            }),
            NarSource::Memory(_) => {
                Err("memory NAR cannot enter the two-pass process regeneration path".to_owned())
            }
        }
    }

    /// Produce the raw NAR bytes on the SYNCHRONOUS inline swarm-worker path
    /// ([`ServeGate::respond`]). This cycle that path is Memory-only, matching the
    /// module's honest scope note: a real store-dump / regular-file source uses
    /// v4's off-worker two-pass path. A [`NarSource::Process`] reaching this path
    /// is therefore a wiring error, reported loudly rather than buffered or run
    /// un-supervised on the poll thread.
    fn produce(self) -> Result<Arc<Vec<u8>>, String> {
        match self.source {
            NarSource::Memory(bytes) => {
                let actual = bytes.len() as u64;
                if actual != self.declared_size {
                    return Err(format!(
                        "memory NAR produced {actual} B, declared_size is {} B",
                        self.declared_size
                    ));
                }
                Ok(bytes)
            }
            NarSource::Process { program, .. } => Err(format!(
                "a Process/RegularFile NAR source ({}) cannot be produced on the synchronous \
                 swarm-worker path; it requires bounded two-pass /nar/4 regeneration",
                program.display()
            )),
        }
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
    /// a CORRUPT/LYING provider, so a test can prove Bao root authentication rejects
    /// the mismatch rather than trusting the bytes.
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
/// TASK-191; production through it is cancellation-safe via v4's two
/// supervised regeneration passes.
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

/// An ADDITIVE supply seam (TASK-278): a provider that serves from SEVERAL suppliers at once
/// (e.g. the in-memory `--libp2p-seed-nar` [`MemoryNarSupplier`] AND the on-demand
/// `--libp2p-provide-store` / announce-after-fetch [`CatalogNarSupplier`]). The two are NOT
/// mutually exclusive - each answers [`plan`](Libp2pNarSupplier::plan) with `Option`, so the
/// union simply asks each leg in order and takes the FIRST that can produce the digest. Seeds and
/// store provisions are DISTINCT content digests, so at most one leg answers any given probe;
/// order only decides an (identical-bytes, content-addressed) tie.
///
/// NO ENUMERATION is preserved: the union exposes only the same single-digest `plan` probe, never
/// a `list`/`iter`/`len` - it cannot reveal what any leg holds beyond a caller-named digest.
pub struct UnionNarSupplier(Vec<Arc<dyn Libp2pNarSupplier>>);

impl UnionNarSupplier {
    /// Union the given legs; each is asked in order and the FIRST that can produce the digest wins.
    /// The leg vector is PRIVATE (this constructor is the only way in), so no caller can reach past
    /// the single-digest `plan` probe into a `list`/`iter`/`len` over the union - the NO-ENUMERATION
    /// invariant is type-enforced, not just documented.
    pub fn new(legs: Vec<Arc<dyn Libp2pNarSupplier>>) -> Self {
        Self(legs)
    }
}

impl Libp2pNarSupplier for UnionNarSupplier {
    fn plan(&self, content: &Blake3Digest) -> Option<NarSupplyPlan> {
        self.0.iter().find_map(|supplier| supplier.plan(content))
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

/// One successfully completed process-backed `/nar/4` serve, observed after COMPLETE, flush,
/// and clean FIN. This is an event stream for evidence/telemetry, not mutable serve state.
#[derive(Debug, Clone)]
pub struct ServeObservation {
    pub content: Blake3Digest,
    pub selected_codec: WireCodec,
    pub pass1_bytes: u64,
    pub pass2_bytes: u64,
    pub proof_preparation_ns: u128,
    pub total_serve_ns: u128,
    pub wire: nar_v4::NarV4WireAccounting,
}

/// The admission gate: the budget, the supplier, and what is in flight. Shared (via
/// [`Arc`]) between the swarm worker (which calls [`respond`](ServeGate::respond) on
/// each inbound request) and the serve teardown guard (which flips
/// [`stop`](ServeGate::stop)).
pub struct ServeGate {
    budget: ServeBudget,
    /// The serve-side link-compression policy (TASK-99): whether/at what level this node
    /// compresses a served nar, intersected per request with the fetcher's `accept` bitmask.
    /// Raw is always available; this only decides when zstd is offered.
    codec_policy: ServeCodecPolicy,
    supplier: Arc<dyn Libp2pNarSupplier>,
    /// The supervisor OFF-loop Process production runs under (TASK-193): a
    /// [`NarSource::Process`] source rides in killable, reaped-on-shutdown process groups
    /// for both v4 passes. A [`TaskSupervisorHandle::disconnected`]
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
    observations: Option<tokio::sync::mpsc::Sender<ServeObservation>>,
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
        // `max_serve_duration` as one absolute deadline around the complete exchange.
        let ServeBudget {
            max_nar_bytes_uncompressed_nar: _,
            max_inflight_bytes_uncompressed_nar: _,
            max_serve_duration: _,
        } = budget;
        ServeGate {
            budget,
            codec_policy: ServeCodecPolicy::default(),
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
            observations: None,
        }
    }

    /// Subscribe to successful process-backed serve observations. Emission is a non-blocking
    /// `try_send` after `write_half.close()` succeeds; a full or closed receiver is logged and
    /// dropped, so telemetry cannot backpressure a completed transfer or grow without bound.
    pub fn with_observations(
        mut self,
        sender: tokio::sync::mpsc::Sender<ServeObservation>,
    ) -> Self {
        self.observations = Some(sender);
        self
    }

    /// Set the serve-side link-compression policy (TASK-99). Builder-style so a fabric can
    /// configure the level / disable zstd without churning the `new` signature; the default
    /// ([`ServeCodecPolicy::default`]) offers zstd at [`peer_fabric::DEFAULT_ZSTD_LEVEL`].
    pub fn with_codec_policy(mut self, policy: ServeCodecPolicy) -> Self {
        self.codec_policy = policy;
        self
    }

    /// The serve-side link-compression policy, read by [`serve_stream`] to negotiate the
    /// per-request codec against the fetcher's `accept` bitmask.
    pub(crate) fn codec_policy(&self) -> ServeCodecPolicy {
        self.codec_policy
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
            let Some(want) = held.checked_add(declared) else {
                self.declined_busy.fetch_add(1, Ordering::Relaxed);
                return Err(NarResponse::Declined(DeclineReason::Busy));
            };
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

    /// Produce an admitted plan INLINE (the Memory fast path / the synchronous test path).
    /// Does NOT count it as served: the async path records success only after clean response
    /// close, while [`respond`](Self::respond) records delivery to its synchronous caller.
    /// Does NOT touch the reservation (the caller releases it). A
    /// [`NarSource::Process`] reaching here is `Declined(SupplyFailed)` - the sync
    /// [`NarSupplyPlan::produce`] refuses to run a supervised process on the poll thread.
    fn finish_inline(&self, plan: NarSupplyPlan, content: &Blake3Digest) -> NarResponse {
        match plan.produce() {
            Ok(bytes) => NarResponse::Nar(bytes),
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
    /// [`Self::admit`] and the v4 two-pass serve path instead (TASK-193).
    pub fn respond(&self, content: &Blake3Digest) -> NarResponse {
        let (plan, _reservation) = match self.admit_plan(content) {
            Ok(admitted) => admitted,
            Err(immediate) => return immediate,
        };
        // `_reservation` releases when it drops at the end of this call, after the inline
        // production - the reserve/release pairing the async path gets from the guard too.
        let response = self.finish_inline(plan, content);
        if matches!(&response, NarResponse::Nar(_)) {
            self.admitted.fetch_add(1, Ordering::Relaxed);
        }
        response
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
            // A non-admit reserved NOTHING (stopped / unknown / too-large / busy), so it
            // carries no reservation to release.
            Err(immediate) => {
                return Serve::Now {
                    response: immediate,
                    reservation: None,
                };
            }
        };
        if plan.requires_supervised_production() {
            // Hand the guard to the caller INSIDE the outcome: the per-stream serve task moves
            // it into the production future, so the reserve is released whenever that future is
            // dropped - including before its first poll (the DEEP-gate pre-first-poll leak).
            Serve::OffLoop { plan, reservation }
        } else {
            // Memory produced inline; the reserve is HANDED BACK (not dropped here) so
            // `serve_stream` holds it THROUGH the response write, exactly as the Process path
            // does. The in-flight ceiling must bound concurrent Memory serve writes too - a
            // consumer that never reads must not park a reservation-free blocked write and so
            // bypass the ceiling (codex DEEP-gate finding).
            let response = self.finish_inline(plan, content);
            Serve::Now {
                response,
                reservation: Some(reservation),
            }
        }
    }

    /// The serve exchange deadline (`ServeBudget::max_serve_duration`): bounds both process
    /// passes AND the serve-side request read / response
    /// write ([`serve_stream`]), so no phase of an inbound serve can hang unbounded.
    pub(crate) fn max_serve_duration(&self) -> Duration {
        self.budget.max_serve_duration
    }
}

/// Where an admitted inbound serve request's bytes are produced (TASK-193): the poll-loop
/// decision returned by [`ServeGate::admit`].
pub(crate) enum Serve {
    /// Answer NOW (on the per-stream serve task): either a non-admit (NotHeld / Declined,
    /// `reservation: None` - nothing was reserved) or an inline Memory NAR produced on the
    /// spot (`reservation: Some`, the in-flight reserve that [`serve_stream`] must hold
    /// THROUGH the response write so the ceiling bounds concurrent Memory serve writes exactly
    /// as it bounds Process ones - a never-reading consumer must not park a reservation-free
    /// blocked write).
    Now {
        response: NarResponse,
        reservation: Option<InflightReservation>,
    },
    /// An admitted process source to produce OFF the poll loop through v4's
    /// two-pass path. Carries the [`InflightReservation`] guard that OWNS
    /// the reserve's release: the swarm worker moves it into the production future, so
    /// dropping that future - at any point, including before its first poll - releases it.
    OffLoop {
        plan: NarSupplyPlan,
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
    use peer_fabric::{ACCEPT_RAW_AND_ZSTD, DEFAULT_ZSTD_LEVEL};
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
        // SSOT tripwire: the unknown-size fetch fallback must equal the authoritative
        // serve per-NAR default, or a default-serving node could advertise a NAR that a
        // cold-start peer refuses before it learns the signed size.
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
            NarResponse::Nar(bytes) => assert_eq!(bytes.as_slice(), nar),
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
    fn inflight_reservation_overflow_declines_busy_without_wrapping() {
        let nar = vec![0x7a];
        let content = Blake3Digest::from_raw_nar(&nar);
        let gate = ServeGate::new(
            ServeBudget {
                max_nar_bytes_uncompressed_nar: u64::MAX,
                max_inflight_bytes_uncompressed_nar: u64::MAX,
                max_serve_duration: Duration::from_secs(1),
            },
            Arc::new(MemoryNarSupplier::new([nar])),
            TaskSupervisorHandle::disconnected(),
        );
        gate.inflight_bytes.store(u64::MAX, Ordering::Release);

        assert!(matches!(
            gate.respond(&content),
            NarResponse::Declined(DeclineReason::Busy)
        ));
        assert_eq!(gate.inflight_bytes.load(Ordering::Acquire), u64::MAX);
        assert_eq!(gate.counters().declined_busy, 1);
        assert_eq!(gate.counters().admitted, 0);
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
    /// can drive supply planning and the two-pass serve without the daemon catalog.
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

    fn no_codec_process_gate(
        body: &[u8],
        max_serve_duration: Duration,
    ) -> (TaskSupervisor, Arc<ServeGate>, Blake3Digest) {
        let content = Blake3Digest::from_raw_nar(body);
        let probe = OneProbe {
            content,
            declared_size: body.len() as u64,
            make: Box::new(|| ProbedSource::Process {
                program: PathBuf::from("process-must-not-start-for-no-common-codec"),
                args: Vec::new(),
            }),
        };
        let supervisor = TaskSupervisor::new();
        let gate = Arc::new(ServeGate::new(
            ServeBudget {
                max_nar_bytes_uncompressed_nar: 1 << 20,
                max_inflight_bytes_uncompressed_nar: 1 << 30,
                max_serve_duration,
            },
            Arc::new(CatalogNarSupplier::new(probe, "unused-helper")),
            supervisor.handle(),
        ));
        (supervisor, gate, content)
    }
    // -------------------------------------------------------------------------
    // TASK-157: the FETCH-side streaming read core (`read_response_streamed`), unit-bitten
    // over in-memory readers. These are the crisp, load-tolerant bites for AC#1 (mid-stream
    // size abort) and AC#2 (inter-chunk idle bound) - no wall-clock races, no live swarm.
    // -------------------------------------------------------------------------

    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Poll};

    /// A short body-idle bound for the unit bites: long enough not to flake on a scheduler
    /// hiccup, short enough that the test finishes fast.
    const IDLE: Duration = Duration::from_millis(150);

    /// Frame a complete v4 response using the production Bao codec.
    fn wire_nar(body: &[u8]) -> Vec<u8> {
        wire_nar_codec(body, WireCodec::Raw, DEFAULT_ZSTD_LEVEL)
    }

    /// Frame a ZSTD v4 response with one independently compressed frame per Bao leaf.
    fn wire_nar_zstd(body: &[u8], level: i32) -> Vec<u8> {
        wire_nar_codec(body, WireCodec::Zstd, level)
    }

    fn wire_nar_codec(body: &[u8], codec: WireCodec, level: i32) -> Vec<u8> {
        let mut cursor = io::Cursor::new(body);
        let outboard = nar_v4::create_outboard(&mut cursor, body.len() as u64).unwrap();
        let mut wire = vec![STATUS_NAR, codec.wire()];
        wire.extend_from_slice(&(body.len() as u64).to_le_bytes());
        nar_v4::encode_validated(body, &outboard, &mut wire, codec, level).unwrap();
        wire.extend_from_slice(nar_v4::COMPLETE_MARKER);
        wire
    }

    /// The async socket pump and blocking verifier have independent lifetimes.
    /// A retained cancellation sender must not prevent normal EOF, and a leaf
    /// that has already been authenticated must be observable before the peer
    /// sends FIN. The final leaf remains withheld until the explicit End item.
    #[tokio::test]
    async fn verified_stream_exposes_early_leaf_and_explicit_end_completes() {
        let raw = (0..((64 * 1024) + 17))
            .map(|index| index as u8)
            .collect::<Vec<_>>();
        let content = Blake3Digest::from_raw_nar(&raw);
        let wire = wire_nar(&raw);
        let (sink, mut verified) =
            verified_nar_stream(content, raw.len() as u64, WireCodec::Raw).await;

        // Exclude the status/codec/raw-size header: this seam carries only the
        // canonical Bao body, COMPLETE marker, and explicit transport End.
        // For this two-leaf tree the body starts with one 64-byte parent
        // pair, then the first 64-KiB leaf. Stop exactly there: receiving the
        // first leaf must not depend on any byte from leaf two.
        let through_first_leaf = 64 + (64 * 1024);
        sink.send(wire[10..10 + through_first_leaf].to_vec())
            .await
            .unwrap();
        let first = tokio::time::timeout(IDLE, verified.next_leaf())
            .await
            .expect("the first authenticated leaf is exposed before any later-leaf byte")
            .expect("the stream has a first leaf");
        assert_eq!(&first[..], &raw[..64 * 1024]);

        sink.send(wire[10 + through_first_leaf..].to_vec())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(25), verified.next_leaf())
                .await
                .is_err(),
            "the final leaf must remain withheld before clean transport EOF"
        );
        sink.finish().await.unwrap();
        let final_leaf = tokio::time::timeout(IDLE, verified.next_leaf())
            .await
            .expect("clean EOF releases the final authenticated leaf")
            .expect("the stream has a final leaf");
        assert_eq!(&final_leaf[..], &raw[64 * 1024..]);
        assert!(verified.next_leaf().await.is_none());
        assert_eq!(verified.finish().await.unwrap(), raw.len() as u64);
    }

    #[test]
    fn disappearing_wire_sender_is_not_clean_fin_and_never_releases_final_leaf() {
        let raw = vec![0x31; 4096];
        let content = Blake3Digest::from_raw_nar(&raw);
        let wire = wire_nar(&raw);
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .try_send(BaoWireItem::Data(wire[10..].to_vec()))
            .unwrap();
        drop(sender);

        let mut reader = BlockingBaoWireReader::new(receiver);
        let mut exposed = Vec::new();
        let error = nar_v4::decode_verified(
            &mut reader,
            bao_tree::blake3::Hash::from(*content.as_bytes()),
            raw.len() as u64,
            WireCodec::Raw,
            |leaf| {
                exposed.push(leaf);
                Ok(())
            },
        )
        .expect_err("sender disappearance without explicit End is not a clean FIN");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(
            error.to_string().contains("without explicit transport End"),
            "unexpected sender-drop error: {error}"
        );
        assert!(
            exposed.is_empty(),
            "the final authenticated leaf must remain withheld without clean FIN"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_socket_handoff_cannot_queue_a_second_owned_leaf() {
        const LEAF: usize = 64 * 1024;
        for codec in [WireCodec::Raw, WireCodec::Zstd] {
            let raw = vec![0x4d; (3 * LEAF) + 17];
            let mut source = io::Cursor::new(&raw);
            let outboard = nar_v4::create_outboard(&mut source, raw.len() as u64).unwrap();
            let (wire_tx, mut wire_rx) = tokio::sync::mpsc::channel(1);
            let encoder = tokio::task::spawn_blocking(move || {
                let result = nar_v4::encode_validated(
                    &raw[..],
                    &outboard,
                    BlockingChunkWriter::new(wire_tx),
                    codec,
                    DEFAULT_ZSTD_LEVEL,
                );
                result.map(|(_sink, raw_bytes, wire_bytes)| (raw_bytes, wire_bytes))
            });

            let first_leaf = loop {
                let item = tokio::time::timeout(IDLE, wire_rx.recv())
                    .await
                    .expect("encoder hands off its next wire item")
                    .expect("encoder remains connected before its first leaf");
                let is_leaf = match codec {
                    WireCodec::Raw => item.bytes.len() == LEAF,
                    WireCodec::Zstd => item.bytes.len() != 64,
                };
                if is_leaf {
                    break item;
                }
                let OwnedWireChunk { mut bytes, recycle } = item;
                bytes.clear();
                recycle.send(bytes).unwrap();
            };

            tokio::time::sleep(Duration::from_millis(25)).await;
            assert!(
                !encoder.is_finished(),
                "{codec:?} encoder must wait for the socket-write acknowledgement"
            );
            assert!(
                matches!(
                    wire_rx.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ),
                "{codec:?} handoff must not queue another item behind the owned leaf"
            );

            let OwnedWireChunk { mut bytes, recycle } = first_leaf;
            bytes.clear();
            recycle.send(bytes).unwrap();
            while let Some(item) = wire_rx.recv().await {
                let OwnedWireChunk { mut bytes, recycle } = item;
                bytes.clear();
                let _ = recycle.send(bytes);
            }
            let (raw_bytes, _wire_bytes) = encoder.await.unwrap().unwrap();
            assert_eq!(raw_bytes, ((3 * LEAF) + 17) as u64);
        }
    }

    #[tokio::test]
    async fn verified_stream_waits_for_next_pull_before_allocating_the_next_leaf() {
        const LEAF: usize = 64 * 1024;
        let raw = vec![0x52; (3 * LEAF) + 17];
        let content = Blake3Digest::from_raw_nar(&raw);
        let wire = wire_nar(&raw);
        let (sink, mut verified) =
            verified_nar_stream(content, raw.len() as u64, WireCodec::Raw).await;
        let producer = tokio::spawn(async move {
            for chunk in wire[10..].chunks(16 * 1024) {
                sink.send(chunk.to_vec()).await.unwrap();
            }
            sink.finish().await.unwrap();
        });

        let first = verified.next_leaf().await.expect("first verified leaf");
        assert_eq!(first.len(), LEAF);
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            matches!(
                verified.leaves.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "the verifier must wait until the caller pulls the next leaf"
        );

        let second = verified.next_leaf().await.expect("second verified leaf");
        assert_eq!(second.len(), LEAF);
        assert_eq!(
            first.len(),
            LEAF,
            "callers may retain an earlier Bytes leaf"
        );
        drop(first);
        drop(second);
        let third = verified.next_leaf().await.expect("third verified leaf");
        assert_eq!(third.len(), LEAF);
        drop(third);
        let final_leaf = verified.next_leaf().await.expect("terminal verified leaf");
        assert_eq!(final_leaf.len(), 17);
        drop(final_leaf);
        assert!(verified.next_leaf().await.is_none());
        assert_eq!(verified.finish().await.unwrap(), raw.len() as u64);
        producer.await.unwrap();
    }

    /// Reciprocal-fetch deadlock regression: every serve worker may be blocked
    /// on peer socket backpressure, yet a fetch verifier must still start and
    /// drain a response. Sharing one permit pool makes the constructor below
    /// wait forever when the serve side is saturated.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetch_verifier_starts_while_all_serve_worker_permits_are_occupied() {
        let pools = BaoWorkerPools::new(2, 1);
        let _all_serve_permits = Arc::clone(&pools.serve)
            .acquire_many_owned(2)
            .await
            .unwrap();
        assert_eq!(pools.serve.available_permits(), 0);
        assert_eq!(pools.fetch.available_permits(), 1);

        let raw = vec![0x53; 4096];
        let content = Blake3Digest::from_raw_nar(&raw);
        let wire = wire_nar(&raw);
        let (sink, mut verified) = tokio::time::timeout(
            IDLE,
            verified_nar_stream_with_pools(content, raw.len() as u64, WireCodec::Raw, &pools),
        )
        .await
        .expect("fetch verifier pool remains available when serve pool is saturated");

        sink.send(wire[10..].to_vec()).await.unwrap();
        sink.finish().await.unwrap();
        let leaf = tokio::time::timeout(IDLE, verified.next_leaf())
            .await
            .expect("independent fetch verifier authenticates the response")
            .expect("one authenticated leaf");
        assert_eq!(leaf.as_ref(), raw.as_slice());
        assert!(verified.next_leaf().await.is_none());
        assert_eq!(verified.finish().await.unwrap(), raw.len() as u64);
    }

    /// A process-backed admission may reserve bytes while waiting for Bao
    /// capacity, but it must not create a producer process until that capacity
    /// is owned. Cancelling the queued serve releases the reservation without
    /// leaving a process or supervisor entry behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saturated_serve_pool_queues_before_process_start_and_cancels_cleanly() {
        let pools = Arc::new(BaoWorkerPools::new(1, 1));
        let _occupied_serve_permit = Arc::clone(&pools.serve).acquire_owned().await.unwrap();
        let body_path = unique_temp("nar4-permit-before-process-body");
        let started_path = unique_temp("nar4-permit-before-process-started");
        let _files = RemoveTestFiles(vec![body_path.clone(), started_path.clone()]);
        let body = vec![0x54; 4096];
        std::fs::write(&body_path, &body).unwrap();
        let content = Blake3Digest::from_raw_nar(&body);
        let marker_arg = started_path.clone();
        let body_arg = body_path.clone();
        let probe = OneProbe {
            content,
            declared_size: body.len() as u64,
            make: Box::new(move || ProbedSource::Process {
                program: PathBuf::from("sh"),
                args: vec![
                    OsString::from("-c"),
                    OsString::from("printf started > \"$1\"; cat \"$2\""),
                    OsString::from("nar4-permit-before-process"),
                    marker_arg.clone().into_os_string(),
                    body_arg.clone().into_os_string(),
                ],
            }),
        };
        let supervisor = TaskSupervisor::new();
        let gate = Arc::new(ServeGate::new(
            ServeBudget {
                max_nar_bytes_uncompressed_nar: 1 << 20,
                max_inflight_bytes_uncompressed_nar: 1 << 20,
                max_serve_duration: Duration::from_secs(5),
            },
            Arc::new(CatalogNarSupplier::new(probe, "unused-helper")),
            supervisor.handle(),
        ));
        let mock = RequestThenCapture::new(&content, peer_fabric::ACCEPT_RAW);
        let task_gate = Arc::clone(&gate);
        let task_pools = Arc::clone(&pools);
        let serve = tokio::spawn(async move {
            serve_stream_with_process_pools(mock, Some(task_gate), task_pools.as_ref()).await;
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while gate.inflight_bytes.load(Ordering::Acquire) != body.len() as u64 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("process serve reaches admission while Bao capacity is occupied");
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !serve.is_finished(),
            "serve remains queued for Bao capacity"
        );
        assert_eq!(
            supervisor.process_jobs().active_len(),
            0,
            "queued Bao work must not create a supervised producer"
        );
        assert!(
            !started_path.exists(),
            "producer command must not execute before a serve permit is owned"
        );

        serve.abort();
        let _ = serve.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while gate.inflight_bytes.load(Ordering::Acquire) != 0
                || supervisor.process_jobs().active_len() != 0
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("cancelling queued serve releases reservation and process state");
    }

    #[tokio::test]
    async fn prematurely_finished_verified_stream_cancels_without_deadlock() {
        let content = Blake3Digest::from_bytes([0x5a; 32]);
        let (_sink, verified) = verified_nar_stream(content, 1, WireCodec::Raw).await;
        let error = tokio::time::timeout(IDLE, verified.finish())
            .await
            .expect("premature finish must cancel and reap the verifier")
            .expect_err("premature finish must not claim success");
        assert!(
            matches!(error, TransferError::Unavailable(ref why) if why.contains("before all authenticated leaves")),
            "unexpected premature-finish error: {error}"
        );
    }

    #[tokio::test]
    async fn authenticated_first_leaf_timing_uses_request_origin() {
        let raw = vec![0x42; (64 * 1024) + 1];
        let content = Blake3Digest::from_raw_nar(&raw);
        let mut reader = futures::io::Cursor::new(wire_nar(&raw));
        let request_started = std::time::Instant::now()
            .checked_sub(Duration::from_millis(20))
            .unwrap();
        let response = read_response_streamed_since(
            &mut reader,
            Some(raw.len() as u64),
            IDLE,
            &content,
            request_started,
            peer_fabric::ACCEPT_RAW_AND_ZSTD,
        )
        .await
        .unwrap();
        assert_eq!(response.bytes, raw);
        assert!(
            response.authenticated_first_leaf_ns >= 20_000_000,
            "timing must include request/header time, not restart at verifier creation"
        );
    }

    /// A reader that yields the status byte, the RAW codec byte, THEN one real body chunk,
    /// THEN STALLS FOREVER (never another byte, never EOF). The successful body chunk is the
    /// point: it proves the body-idle guard is re-armed PER read (the stall it must catch
    /// happens AFTER a chunk was already delivered), not merely on the first body read.
    /// Phases: 0=status, 1=codec byte, 2=one body chunk, 3=stall.
    struct StatusChunkThenStall {
        prefix: io::Cursor<Vec<u8>>,
        sent_partial_proof: bool,
    }

    impl AsyncRead for StatusChunkThenStall {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.prefix.position() as usize != self.prefix.get_ref().len() {
                return Poll::Ready(std::io::Read::read(&mut self.prefix, buf));
            }
            if !self.sent_partial_proof {
                self.sent_partial_proof = true;
                let n = buf.len().min(32);
                buf[..n].fill(0x5a);
                Poll::Ready(Ok(n))
            } else {
                Poll::Pending
            }
        }
    }

    /// AC#1 declared-size bite: v4 carries exact raw geometry in its fixed header. A value above
    /// signed `expected_size` is rejected before reading or allocating the Bao body, rather than
    /// after buffering the whole (here 512 KiB) NAR. `TooLarge::streamed` retains its historical
    /// field name but reports the rejected declared raw size on v4.
    #[tokio::test]
    async fn read_rejects_declared_raw_size_above_signed_limit_before_body() {
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
                    "declared raw size ({streamed}) must exceed the signed cap ({cap})"
                );
                assert_eq!(
                    streamed,
                    big.len() as u64,
                    "v4 rejects the exact raw_size header before reading its body"
                );
            }
            other => panic!("expected TooLarge, got {other}"),
        }
    }

    /// A hostile provider that DECLARES a raw geometry far above the signed cap and stands
    /// ready to stream an attacker-chosen huge body. This reader hands over ONLY the 10-byte
    /// v4 prelude (status + codec + declared `raw_size`); every byte past it is an EXPLODING
    /// tail that RECORDS the read (`body_reads`). It is the physical embodiment of the risk-6
    /// wasted-download DoS: if the fetch pulls the body, that pull is observable.
    ///
    /// Phases: header bytes drain from `prelude`; any read past it is a body read.
    struct HeaderThenExplodingBody {
        prelude: io::Cursor<Vec<u8>>,
        body_reads: Arc<AtomicUsize>,
    }

    impl AsyncRead for HeaderThenExplodingBody {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let served = self.prelude.position();
            let total = self.prelude.get_ref().len() as u64;
            if served < total {
                // Still inside the 10-byte prelude: serve header bytes verbatim.
                return Poll::Ready(io::Read::read(&mut self.prelude, buf));
            }
            // The body was requested. In a real fetch this is where the attacker's
            // over-declared blob would start streaming. Record it and end the stream so
            // the failure surfaces as a missed abort, not a hang.
            self.body_reads.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(0))
        }
    }

    /// Drive a `read_response_streamed` against a provider that declares `declared` raw bytes
    /// and then EXPLODES on the body, returning the abort error and how many times the body was
    /// pulled. `body_pulls == 0` is the risk-6 DoS property: the over-declared blob never began
    /// downloading. No `declared`-sized buffer is ever allocated - the body is refused first.
    async fn abort_pulls_for(declared: u64, signed: Option<u64>) -> (TransferError, usize) {
        let content = Blake3Digest::from_bytes([0x33; 32]);
        // The 10-byte v4 prelude ONLY: status, RAW codec, 8-byte LE declared size.
        let mut prelude = vec![STATUS_NAR, WireCodec::Raw.wire()];
        prelude.extend_from_slice(&declared.to_le_bytes());
        let body_reads = Arc::new(AtomicUsize::new(0));
        let mut reader = HeaderThenExplodingBody {
            prelude: io::Cursor::new(prelude),
            body_reads: body_reads.clone(),
        };
        let err = read_response_streamed(&mut reader, signed, IDLE, &content)
            .await
            .expect_err("an over-declared body must abort, never stream");
        (err, body_reads.load(Ordering::SeqCst))
    }

    /// AC#2 (TASK-46) the DECISIVE DoS bite: the over-declared abort fires BEFORE a single
    /// body byte is downloaded, so a lying claim pointing at an attacker-chosen huge blob costs
    /// a 10-byte header read, not a full transfer. Strictly stronger than
    /// `read_rejects_declared_raw_size_above_signed_limit_before_body` (a `Cursor` over a
    /// fully-buffered body cannot witness "the body was never read"): here the body is an
    /// exploding tail whose first pull is counted, so the oracle observes the exact
    /// wasted-download boundary the defense must hold.
    ///
    /// Two cases, because two guards jointly protect the SIGNED path but only ONE protects the
    /// cold-start path - so the cases ATTRIBUTE the body-not-read property to the right guard:
    ///   * COLD START (`signed == None`): the running cap is the 256 MiB floor and the
    ///     `raw_size != expected` sibling check is SKIPPED, so `raw_size > cap` is the ONLY
    ///     guard on the body. Disabling it lets the exploding body stream (`body_pulls > 0`) -
    ///     the clean, attributable mutation bite for THIS guard.
    ///   * SIGNED NarSize (the headline): a declared 8 GiB over a signed 4 KiB. `body_pulls`
    ///     is still 0; here `raw_size > cap` and `raw_size != expected` REDUNDANTLY protect the
    ///     body, which is the belt-and-braces the shipped path actually has.
    ///
    /// All sizes are UNCOMPRESSED signed-NarSize units, never a compressed FileSize (the
    /// recurring unit trap).
    ///
    /// BITE (mutation-proven): delete the `if raw_size > cap { TooLarge }` guard in
    /// `read_response_streamed_since`; the COLD-START case then proceeds into
    /// `verified_nar_stream` + `pump_bao_wire`, which pull the exploding body - `body_pulls`
    /// becomes non-zero and this fails at the body-read boundary.
    #[tokio::test]
    async fn over_declared_body_aborts_before_any_body_byte_is_downloaded() {
        const FLOOR_OVER: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB, over the 256 MiB cold floor
        const SIGNED: u64 = 4 * 1024; // a 4 KiB signed NarSize
        const SIGNED_OVER: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB claimed against 4 KiB signed

        // COLD START: only `raw_size > cap` (vs the floor) stands between us and the body.
        let (err, body_pulls) = abort_pulls_for(FLOOR_OVER, None).await;
        // THE DoS ORACLE FIRST, so the failure ATTRIBUTES to the wasted-download boundary (not
        // to an incidental error-type mismatch): with the guard deleted, the code enters the
        // verifier and pulls the exploding body, so `body_pulls > 0` and THIS line bites.
        assert_eq!(
            body_pulls, 0,
            "cold-start: the abort must fire before the body is read; a non-zero pull is a \
             downloaded blob (this is the guard-attributable DoS bite)"
        );
        match err {
            TransferError::TooLarge { limit, streamed } => {
                assert_eq!(limit, MAX_NAR_RESPONSE_BYTES, "cold-start cap is the floor");
                assert_eq!(
                    streamed, FLOOR_OVER,
                    "reported over-size is the declared raw_size"
                );
            }
            other => panic!("cold-start over-floor must be TooLarge before body, got {other}"),
        }

        // SIGNED NarSize headline: an 8 GiB claim against a 4 KiB signed size, refused early.
        let (err, body_pulls) = abort_pulls_for(SIGNED_OVER, Some(SIGNED)).await;
        assert_eq!(
            body_pulls, 0,
            "signed: no body byte pulled for an over-signed claim"
        );
        match err {
            TransferError::TooLarge { limit, streamed } => {
                assert_eq!(limit, SIGNED, "the abort limit is the signed NarSize");
                assert_eq!(
                    streamed, SIGNED_OVER,
                    "reported over-size is the declared raw_size"
                );
            }
            other => panic!("signed over-size must be TooLarge before body, got {other}"),
        }

        // CONTRAST: a within-bound claim (declared == signed) proceeds normally and streams its
        // whole body - the abort does not falsely fire on an honest transfer.
        let honest = b"an honest NAR whose declared size equals the signed NarSize".to_vec();
        let honest_content = Blake3Digest::from_raw_nar(&honest);
        let mut honest_reader = futures::io::Cursor::new(wire_nar(&honest));
        let got = read_response_streamed(
            &mut honest_reader,
            Some(honest.len() as u64),
            IDLE,
            &honest_content,
        )
        .await
        .expect("a within-bound transfer streams normally");
        assert_eq!(
            got, honest,
            "the honest within-bound NAR round-trips in full"
        );
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

    /// AC#2 the DECISIVE inter-chunk idle bite: a provider sends the status byte AND one real
    /// body chunk, THEN stalls forever. The read must fail on the BODY-IDLE bound (within it),
    /// not hang - proving the idle guard is re-armed PER chunk and fires on a stall that
    /// happens AFTER a chunk already streamed, distinct from `total_timeout`. BITE: guard only
    /// the FIRST body read (or drop the per-read `timeout(body_idle_timeout, ..)`) and this
    /// hangs forever on the post-chunk stall.
    #[tokio::test]
    async fn read_aborts_on_inter_chunk_stall_within_the_idle_bound() {
        let content = Blake3Digest::from_bytes([0x11; 32]);
        let raw_size = 1u64 << 20;
        let mut prefix = vec![STATUS_NAR, WireCodec::Raw.wire()];
        prefix.extend_from_slice(&raw_size.to_le_bytes());
        let mut reader = StatusChunkThenStall {
            prefix: io::Cursor::new(prefix),
            sent_partial_proof: false,
        };
        let started = std::time::Instant::now();
        // A cap far above the 1 KiB chunk, so ONLY the post-chunk idle stall can abort here.
        let err = read_response_streamed(&mut reader, Some(1 << 20), IDLE, &content)
            .await
            .expect_err("a post-chunk stall must abort on the re-armed idle bound");
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

    /// A provider whose bytes do NOT match the requested root (same length, different bytes)
    /// fails at the first inconsistent Bao leaf and never exposes untrusted bytes.
    #[tokio::test]
    async fn read_rejects_bytes_that_do_not_hash_to_the_requested_identity() {
        let wanted = b"the honest bytes the consumer asked for".to_vec();
        let requested = Blake3Digest::from_raw_nar(&wanted);
        let corrupt = b"different bytes of the same length !!!!".to_vec();
        assert_eq!(wanted.len(), corrupt.len());
        let mut reader = futures::io::Cursor::new(wire_nar(&corrupt));
        let err = read_response_streamed(&mut reader, Some(wanted.len() as u64), IDLE, &requested)
            .await
            .expect_err("corrupt bytes must fail Bao authentication");
        match err {
            TransferError::AuthenticationFailed { expected, reason } => {
                assert_eq!(expected, requested);
                assert!(
                    reason.to_ascii_lowercase().contains("leaf hash mismatch"),
                    "{reason}"
                );
            }
            other => panic!("expected AuthenticationFailed, got {other}"),
        }
    }

    // -------------------------------------------------------------------------
    // TASK-99: the negotiated-codec wire, bitten over in-memory readers. The zstd body is
    // decoded by the SAME `read_response_streamed` path, so these prove the compressed link
    // round-trips, keeps the frozen blob id, and fails closed on bomb/corruption/truncation.
    // -------------------------------------------------------------------------

    /// AC#1/#3 the compressed round-trip: a server that ships a zstd body and a fetcher that
    /// decodes it yield the EXACT raw nar, hashing to the SAME BLAKE3(RawNarV1) id as the
    /// uncompressed path. Proven by writing a real serve response (`write_response` with the
    /// negotiated codec) and reading it back through the fetch path.
    #[tokio::test]
    async fn zstd_body_round_trips_and_keeps_the_frozen_blob_id() {
        let raw = b"a real-ish nar body that compresses well because it repeats".repeat(500);
        let content = Blake3Digest::from_raw_nar(&raw);

        // Serve side: frame a Nar response with the negotiated zstd codec.
        let mut wire = futures::io::Cursor::new(Vec::new());
        write_response(
            &mut wire,
            NarResponse::Nar(Arc::new(raw.clone())),
            WireCodec::Zstd,
            DEFAULT_ZSTD_LEVEL,
            &content,
        )
        .await
        .expect("serve writes the compressed response");
        let wire = wire.into_inner();
        assert!(
            (wire.len() as u64) < raw.len() as u64,
            "the compressed wire ({}) must be smaller than the raw nar ({})",
            wire.len(),
            raw.len()
        );

        // Fetch side: decode it, bounded by the signed uncompressed size.
        let mut reader = futures::io::Cursor::new(wire);
        let got = read_response_streamed(&mut reader, Some(raw.len() as u64), IDLE, &content)
            .await
            .expect("fetch decodes the compressed body");
        assert_eq!(got, raw, "the decoded nar is byte-identical to the raw nar");
        assert_eq!(
            Blake3Digest::from_raw_nar(&got),
            content,
            "the frozen blob id is unchanged by compression (AC#1)"
        );
    }

    /// AC#1 the multi-holder property: two servers compressing the SAME nar at DIFFERENT
    /// levels produce DIFFERENT wire bytes, but a fetcher decodes either to the same nar and
    /// the same blob id - so both can serve one fetch keyed by that id.
    #[tokio::test]
    async fn two_levels_serve_one_blob_id() {
        let raw = b"different compressor settings must not fork the content id".repeat(300);
        let content = Blake3Digest::from_raw_nar(&raw);

        let mut got = Vec::new();
        let mut wires = Vec::new();
        for level in [1, 19] {
            let mut wire = futures::io::Cursor::new(Vec::new());
            write_response(
                &mut wire,
                NarResponse::Nar(Arc::new(raw.clone())),
                WireCodec::Zstd,
                level,
                &content,
            )
            .await
            .unwrap();
            let wire = wire.into_inner();
            let mut reader = futures::io::Cursor::new(wire.clone());
            let decoded =
                read_response_streamed(&mut reader, Some(raw.len() as u64), IDLE, &content)
                    .await
                    .expect("either level decodes to the same nar");
            assert_eq!(Blake3Digest::from_raw_nar(&decoded), content);
            got.push(decoded);
            wires.push(wire);
        }
        assert_ne!(
            wires[0], wires[1],
            "different levels give different wire bytes"
        );
        assert_eq!(got[0], got[1], "but the same decoded nar");
    }

    /// AC#6 size-bound bite: even a highly compressible response whose v4 header declares FAR
    /// more raw data than the signed size is rejected before decoding any leaf.
    #[tokio::test]
    async fn zstd_response_above_signed_raw_size_rejects_before_decode() {
        let bomb = vec![0u8; 8 * 1024 * 1024]; // 8 MiB of zeros -> tiny zstd frame
        let content = Blake3Digest::from_raw_nar(&bomb);
        let wire = wire_nar_zstd(&bomb, DEFAULT_ZSTD_LEVEL);
        assert!(wire.len() < 64 * 1024, "the bomb is tiny on the wire");
        let cap: u64 = 64 * 1024; // the fetcher signed only 64 KiB
        let mut reader = futures::io::Cursor::new(wire);
        let err = read_response_streamed(&mut reader, Some(cap), IDLE, &content)
            .await
            .expect_err("a decompression bomb must abort");
        match err {
            TransferError::TooLarge { limit, streamed } => {
                assert_eq!(limit, cap);
                assert_eq!(
                    streamed,
                    bomb.len() as u64,
                    "v4 rejects the declared raw_size before decoding any leaf"
                );
            }
            other => panic!("expected TooLarge, got {other}"),
        }
    }

    /// AC#3 corruption ON THE WIRE: a flipped byte inside a leaf's zstd frame fails the fetch
    /// (either a frame error or a Bao mismatch), never a silent short/wrong nar.
    #[tokio::test]
    async fn corrupt_zstd_frame_fails_the_fetch() {
        let raw = b"honest compressed nar bytes to be corrupted mid-frame".repeat(100);
        let content = Blake3Digest::from_raw_nar(&raw);
        let mut wire = wire_nar_zstd(&raw, DEFAULT_ZSTD_LEVEL);
        // Flip a byte inside the frame (past the status+codec+magic bytes).
        let mid = wire.len() / 2;
        wire[mid] ^= 0xff;
        let mut reader = futures::io::Cursor::new(wire);
        let result =
            read_response_streamed(&mut reader, Some(raw.len() as u64), IDLE, &content).await;
        assert!(
            result.is_err(),
            "a corrupt zstd frame must fail the fetch, got {result:?}"
        );
    }

    /// AC#3 truncation ON THE WIRE: cutting the v4 response before its final leaf/COMPLETE is
    /// rejected by leaf framing or Bao authentication; a correct-but-short NAR is never released.
    #[tokio::test]
    async fn truncated_zstd_frame_fails_at_the_codec() {
        let raw = b"a nar whose compressed frame is cut short before EOF".repeat(120);
        let content = Blake3Digest::from_raw_nar(&raw);
        let full = wire_nar_zstd(&raw, DEFAULT_ZSTD_LEVEL);
        let truncated = full[..full.len() - 6].to_vec(); // drop the frame tail
        let mut reader = futures::io::Cursor::new(truncated);
        let err = read_response_streamed(&mut reader, Some(raw.len() as u64), IDLE, &content)
            .await
            .expect_err("a truncated frame must fail rather than yield a short nar");
        match err {
            TransferError::AuthenticationFailed { reason, .. } => assert!(
                reason.contains("failed to fill")
                    || reason.contains("truncated")
                    || reason.contains("early eof")
                    || reason.contains("LeafNotFound"),
                "a truncated v4 body must fail authentication/framing, got {reason}"
            ),
            other => panic!("expected v4 authentication/framing failure, got {other}"),
        }
    }

    /// AC#5 an unknown codec byte from an untrusted server fails the fetch (never guesses a
    /// framing).
    #[tokio::test]
    async fn unknown_codec_byte_fails_the_fetch() {
        let content = Blake3Digest::from_bytes([0x33; 32]);
        let mut wire = vec![STATUS_NAR, 0x7f]; // 0x7f is not a known codec
        wire.extend_from_slice(&1024u64.to_le_bytes());
        let mut reader = futures::io::Cursor::new(wire);
        let err = read_response_streamed(&mut reader, Some(1024), IDLE, &content)
            .await
            .expect_err("an unknown codec must fail");
        match err {
            TransferError::Unavailable(why) => {
                assert!(why.contains("unknown NAR codec"), "got: {why}")
            }
            other => panic!("expected Unavailable(unknown codec), got {other}"),
        }
    }

    /// A serve-side mock: yields a fixed 33-byte request (digest + accept) on read, then
    /// PENDS (a Memory serve never reads again after admit), and CAPTURES everything the
    /// server writes into a shared buffer for inspection. Lets a test drive `serve_stream`
    /// end to end (the accept -> negotiate -> codec path) without a full duplex.
    struct RequestThenCapture {
        request: [u8; 33],
        read_pos: usize,
        written: Arc<std::sync::Mutex<Vec<u8>>>,
        close_pending_once: bool,
        close_started: bool,
        fail_after_response_bytes: Option<usize>,
    }

    impl RequestThenCapture {
        fn new(content: &Blake3Digest, accept: u8) -> Self {
            let mut request = [0u8; 33];
            request[..32].copy_from_slice(content.as_bytes());
            request[32] = accept;
            RequestThenCapture {
                request,
                read_pos: 0,
                written: Arc::new(std::sync::Mutex::new(Vec::new())),
                close_pending_once: false,
                close_started: false,
                fail_after_response_bytes: None,
            }
        }

        /// Model a requester that closes its request half as soon as response
        /// FIN is observable. The provider's first `poll_close` deliberately
        /// returns Pending so, on the next poll, both exchange completion and
        /// `consumer_hung_up` are ready and select ordering is exercised.
        fn with_close_completion_race(mut self) -> Self {
            self.close_pending_once = true;
            self
        }

        fn with_write_failure(mut self) -> Self {
            self.fail_after_response_bytes = Some(0);
            self
        }

        fn with_write_failure_after(mut self, response_bytes: usize) -> Self {
            self.fail_after_response_bytes = Some(response_bytes);
            self
        }
    }

    impl AsyncRead for RequestThenCapture {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.read_pos < self.request.len() && !buf.is_empty() {
                let start = self.read_pos;
                let n = (self.request.len() - start).min(buf.len());
                buf[..n].copy_from_slice(&self.request[start..start + n]);
                self.read_pos += n;
                Poll::Ready(Ok(n))
            } else if self.close_pending_once && self.close_started {
                Poll::Ready(Ok(0))
            } else {
                Poll::Pending // connected but idle (a Memory serve does not read again)
            }
        }
    }

    impl AsyncWrite for RequestThenCapture {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(limit) = self.fail_after_response_bytes {
                let already_written = self.written.lock().unwrap().len();
                if already_written >= limit {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "synthetic response write failure",
                    )));
                }
                let accepted = (limit - already_written).min(buf.len());
                self.written
                    .lock()
                    .unwrap()
                    .extend_from_slice(&buf[..accepted]);
                return Poll::Ready(Ok(accepted));
            }
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.close_pending_once && !self.close_started {
                self.close_started = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    /// A process-backed request with an empty accept mask is declined before either regeneration
    /// pass. A completed decline and a socket failure are distinct outcomes, but neither is a
    /// completed NAR serve or a supplier failure, so both release the reservation without changing
    /// the existing admission counters.
    #[tokio::test]
    async fn process_no_common_codec_classifies_completed_and_failed_decline_writes() {
        let body = b"process source that codec negotiation must reject before start";
        let (supervisor, gate, content) = no_codec_process_gate(body, Duration::from_secs(1));

        let success = RequestThenCapture::new(&content, 0);
        let success_wire = Arc::clone(&success.written);
        serve_stream(success, Some(Arc::clone(&gate))).await;
        assert_eq!(
            success_wire.lock().unwrap().as_slice(),
            [STATUS_DECLINED, DeclineReason::NoCommonCodec.wire()],
            "successful branch writes the exact no-common-codec decline"
        );
        assert_eq!(gate.counters(), ServeCounters::default());
        assert_eq!(gate.inflight_bytes.load(Ordering::Acquire), 0);
        assert_eq!(supervisor.process_jobs().active_len(), 0);

        let failed = RequestThenCapture::new(&content, 0).with_write_failure();
        serve_stream(failed, Some(Arc::clone(&gate))).await;
        assert_eq!(
            gate.counters(),
            ServeCounters::default(),
            "transport failure is neither a completed serve nor a supply failure"
        );
        assert_eq!(gate.inflight_bytes.load(Ordering::Acquire), 0);
        assert_eq!(supervisor.process_jobs().active_len(), 0);
    }

    /// Accept exactly `write_budget` response bytes, then model a live consumer whose socket
    /// window never advances. The shared flag makes the test observe real pass-2 socket
    /// backpressure rather than merely assuming a Pending write was reached.
    struct RequestThenBudgetedWrite {
        request: [u8; 33],
        read_pos: usize,
        write_budget: usize,
        written: Arc<std::sync::Mutex<Vec<u8>>>,
        write_blocked: Arc<AtomicBool>,
    }

    impl RequestThenBudgetedWrite {
        fn new(content: &Blake3Digest, write_budget: usize) -> Self {
            let mut request = [0u8; 33];
            request[..32].copy_from_slice(content.as_bytes());
            request[32] = peer_fabric::ACCEPT_RAW;
            Self {
                request,
                read_pos: 0,
                write_budget,
                written: Arc::new(std::sync::Mutex::new(Vec::new())),
                write_blocked: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl AsyncRead for RequestThenBudgetedWrite {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.read_pos < self.request.len() && !buf.is_empty() {
                let start = self.read_pos;
                let count = (self.request.len() - start).min(buf.len());
                buf[..count].copy_from_slice(&self.request[start..start + count]);
                self.read_pos += count;
                Poll::Ready(Ok(count))
            } else {
                Poll::Pending
            }
        }
    }

    impl AsyncWrite for RequestThenBudgetedWrite {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.write_budget == 0 {
                self.write_blocked.store(true, Ordering::Release);
                return Poll::Pending;
            }
            let count = self.write_budget.min(buf.len());
            self.written
                .lock()
                .unwrap()
                .extend_from_slice(&buf[..count]);
            self.write_budget -= count;
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.write_budget == 0 {
                self.write_blocked.store(true, Ordering::Release);
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.write_budget == 0 {
                self.write_blocked.store(true, Ordering::Release);
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    struct ProcessServeProbe {
        wire: Vec<u8>,
        invocations: u64,
        inflight_after: u64,
        active_jobs_after: usize,
        observations: Vec<ServeObservation>,
        counters: ServeCounters,
        serve_elapsed: Duration,
    }

    async fn run_two_pass_process_serve(
        announced: &[u8],
        pass1: &[u8],
        pass2: &[u8],
        nonzero_pass: Option<u64>,
    ) -> ProcessServeProbe {
        run_two_pass_process_serve_with_close_race(
            announced,
            pass1,
            pass2,
            nonzero_pass,
            false,
            None,
        )
        .await
    }

    async fn run_two_pass_process_serve_with_close_race(
        announced: &[u8],
        pass1: &[u8],
        pass2: &[u8],
        nonzero_pass: Option<u64>,
        close_completion_race: bool,
        fail_after_response_bytes: Option<usize>,
    ) -> ProcessServeProbe {
        let counter = unique_temp("nar4-pass-counter");
        let pass1_path = unique_temp("nar4-pass1");
        let pass2_path = unique_temp("nar4-pass2");
        let _ = std::fs::remove_file(&counter);
        std::fs::write(&pass1_path, pass1).unwrap();
        std::fs::write(&pass2_path, pass2).unwrap();
        let content = Blake3Digest::from_raw_nar(announced);
        let fail_pass = nonzero_pass.unwrap_or(0);
        let script = format!(
            "n=$(cat \"$1\" 2>/dev/null || printf 0); n=$((n + 1)); \
             printf %s \"$n\" > \"$1\"; \
             if [ \"$n\" -eq 1 ]; then cat \"$2\"; else cat \"$3\"; fi; \
             if [ \"$n\" -eq {fail_pass} ]; then exit 7; fi"
        );
        let counter_arg = counter.clone();
        let pass1_arg = pass1_path.clone();
        let pass2_arg = pass2_path.clone();
        let probe = OneProbe {
            content,
            declared_size: announced.len() as u64,
            make: Box::new(move || ProbedSource::Process {
                program: PathBuf::from("sh"),
                args: vec![
                    OsString::from("-c"),
                    OsString::from(script.clone()),
                    OsString::from("nar4-two-pass-test"),
                    counter_arg.clone().into_os_string(),
                    pass1_arg.clone().into_os_string(),
                    pass2_arg.clone().into_os_string(),
                ],
            }),
        };
        let supervisor = TaskSupervisor::new();
        let (observation_tx, mut observation_rx) = tokio::sync::mpsc::channel(2);
        let gate = Arc::new(
            ServeGate::new(
                ServeBudget {
                    max_nar_bytes_uncompressed_nar: 1 << 20,
                    max_inflight_bytes_uncompressed_nar: 1 << 30,
                    max_serve_duration: Duration::from_secs(2),
                },
                Arc::new(CatalogNarSupplier::new(probe, "unused-helper")),
                supervisor.handle(),
            )
            .with_observations(observation_tx),
        );
        let mut mock = RequestThenCapture::new(&content, peer_fabric::ACCEPT_RAW);
        if close_completion_race {
            mock = mock.with_close_completion_race();
        }
        if let Some(limit) = fail_after_response_bytes {
            mock = mock.with_write_failure_after(limit);
        }
        let captured = Arc::clone(&mock.written);
        let serve_started = std::time::Instant::now();
        tokio::time::timeout(
            Duration::from_secs(3),
            serve_stream(mock, Some(Arc::clone(&gate))),
        )
        .await
        .expect("two-pass serve stays within its absolute deadline");
        let serve_elapsed = serve_started.elapsed();
        tokio::time::timeout(Duration::from_secs(1), async {
            while supervisor.process_jobs().active_len() != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("every started pass is child-free after serve completion");
        let invocations = std::fs::read_to_string(&counter)
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(0);
        let mut observations = Vec::new();
        while let Ok(observation) = observation_rx.try_recv() {
            observations.push(observation);
        }
        let result = ProcessServeProbe {
            wire: captured.lock().unwrap().clone(),
            invocations,
            inflight_after: gate.inflight_bytes.load(Ordering::Acquire),
            active_jobs_after: supervisor.process_jobs().active_len(),
            observations,
            counters: gate.counters(),
            serve_elapsed,
        };
        let _ = std::fs::remove_file(counter);
        let _ = std::fs::remove_file(pass1_path);
        let _ = std::fs::remove_file(pass2_path);
        result
    }

    fn assert_process_serve_cleaned(result: &ProcessServeProbe) {
        assert_eq!(result.inflight_after, 0, "reservation released");
        assert_eq!(result.active_jobs_after, 0, "all process groups reaped");
    }

    struct RemoveTestFiles(Vec<PathBuf>);

    impl Drop for RemoveTestFiles {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    fn process_exists(pid: u32) -> bool {
        PathBuf::from(format!("/proc/{pid}")).exists()
    }

    async fn wait_for_process_cleanup(supervisor: &TaskSupervisor, gate: &ServeGate, pids: &[u32]) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if supervisor.process_jobs().active_len() == 0
                    && gate.inflight_bytes.load(Ordering::Acquire) == 0
                    && pids.iter().all(|pid| !process_exists(*pid))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("process groups, registry entry, and reservation clean up");
    }

    struct BackpressuredProcessFixture {
        _files: RemoveTestFiles,
        content: Blake3Digest,
        raw_size: usize,
        counter: PathBuf,
        pass2_pid: PathBuf,
        pass2_grandchild: PathBuf,
        gate: Arc<ServeGate>,
        supervisor: TaskSupervisor,
    }

    fn backpressured_process_fixture(
        max_serve_duration: Duration,
        pass_delay: &str,
    ) -> BackpressuredProcessFixture {
        let body_path = unique_temp("nar4-backpressure-body");
        let counter = unique_temp("nar4-backpressure-counter");
        let pass2_pid = unique_temp("nar4-backpressure-pass2-pid");
        let pass2_grandchild = unique_temp("nar4-backpressure-pass2-grandchild");
        let body = (0..(4 * 1024 * 1024))
            .map(|index| (index as u8).wrapping_mul(17))
            .collect::<Vec<_>>();
        std::fs::write(&body_path, &body).unwrap();
        let content = Blake3Digest::from_raw_nar(&body);
        let script = format!(
            "n=$(cat \"$1\" 2>/dev/null || printf 0); n=$((n + 1)); printf %s \"$n\" > \"$1\"; \
             sleep {pass_delay}; \
             if [ \"$n\" -eq 1 ]; then cat \"$2\"; exit $?; fi; \
             printf %s $$ > \"$3\"; sleep 1000 & child=$!; printf %s \"$child\" > \"$4\"; \
             cat \"$2\"; wait"
        );
        let counter_arg = counter.clone();
        let body_arg = body_path.clone();
        let pid_arg = pass2_pid.clone();
        let grandchild_arg = pass2_grandchild.clone();
        let probe = OneProbe {
            content,
            declared_size: body.len() as u64,
            make: Box::new(move || ProbedSource::Process {
                program: PathBuf::from("sh"),
                args: vec![
                    OsString::from("-c"),
                    OsString::from(script.clone()),
                    OsString::from("nar4-backpressure"),
                    counter_arg.clone().into_os_string(),
                    body_arg.clone().into_os_string(),
                    pid_arg.clone().into_os_string(),
                    grandchild_arg.clone().into_os_string(),
                ],
            }),
        };
        let supervisor = TaskSupervisor::new();
        let gate = Arc::new(ServeGate::new(
            ServeBudget {
                max_nar_bytes_uncompressed_nar: 8 * 1024 * 1024,
                max_inflight_bytes_uncompressed_nar: 8 * 1024 * 1024,
                max_serve_duration,
            },
            Arc::new(CatalogNarSupplier::new(probe, "unused-helper")),
            supervisor.handle(),
        ));
        BackpressuredProcessFixture {
            _files: RemoveTestFiles(vec![
                body_path,
                counter.clone(),
                pass2_pid.clone(),
                pass2_grandchild.clone(),
            ]),
            content,
            raw_size: body.len(),
            counter,
            pass2_pid,
            pass2_grandchild,
            gate,
            supervisor,
        }
    }

    async fn observe_backpressured_pass2(
        fixture: &BackpressuredProcessFixture,
        blocked: &AtomicBool,
    ) -> (u32, u32) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let pid = std::fs::read_to_string(&fixture.pass2_pid)
                    .ok()
                    .and_then(|value| value.trim().parse::<u32>().ok());
                let grandchild = std::fs::read_to_string(&fixture.pass2_grandchild)
                    .ok()
                    .and_then(|value| value.trim().parse::<u32>().ok());
                if let (Some(pid), Some(grandchild)) = (pid, grandchild)
                    && blocked.load(Ordering::Acquire)
                    && fixture.supervisor.process_jobs().active_len() != 0
                {
                    break (pid, grandchild);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("pass 2 reaches measured socket backpressure with live descendants")
    }

    #[tokio::test]
    async fn process_v4_success_invokes_exactly_two_equal_replays() {
        let body = vec![0x31; (64 * 1024) + 17];
        let result = run_two_pass_process_serve(&body, &body, &body, None).await;
        assert_eq!(result.invocations, 2);
        let content = Blake3Digest::from_raw_nar(&body);
        let mut wire = futures::io::Cursor::new(result.wire.clone());
        assert_eq!(
            read_response_streamed(&mut wire, Some(body.len() as u64), IDLE, &content)
                .await
                .unwrap(),
            body
        );
        assert_process_serve_cleaned(&result);
    }

    #[tokio::test]
    async fn process_observation_emits_once_after_success_and_never_on_failure() {
        let body = vec![0x29; (64 * 1024) + 9];
        let success = run_two_pass_process_serve(&body, &body, &body, None).await;
        let [observation] = success.observations.as_slice() else {
            panic!(
                "one successful COMPLETE+FIN must emit exactly one observation, got {}",
                success.observations.len()
            );
        };
        assert_eq!(observation.content, Blake3Digest::from_raw_nar(&body));
        assert_eq!(observation.pass1_bytes, body.len() as u64);
        assert_eq!(observation.pass2_bytes, body.len() as u64);
        assert!(observation.proof_preparation_ns > 0);
        assert!(observation.total_serve_ns >= observation.proof_preparation_ns);
        observation.wire.validate().unwrap();

        let failed = run_two_pass_process_serve(&body, &body[..body.len() - 1], &body, None).await;
        assert!(
            failed.observations.is_empty(),
            "pass-1 failure before STATUS_NAR must not emit a successful observation"
        );
    }

    #[tokio::test]
    async fn clean_fin_wins_simultaneous_request_half_close_and_records_success() {
        let body = vec![0x2a; (64 * 1024) + 11];
        let result =
            run_two_pass_process_serve_with_close_race(&body, &body, &body, None, true, None).await;
        assert_eq!(result.invocations, 2);
        assert!(
            result.wire.ends_with(nar_v4::COMPLETE_MARKER),
            "the response completed before the requester closed its request half"
        );
        assert_eq!(
            result.observations.len(),
            1,
            "a clean response FIN must not be reclassified as consumer hangup"
        );
        assert_process_serve_cleaned(&result);
    }

    #[tokio::test]
    async fn process_transport_failure_is_not_counted_as_served_or_supply_failed() {
        let body = vec![0x2b; 4096];
        let result =
            run_two_pass_process_serve_with_close_race(&body, &body, &body, None, false, Some(0))
                .await;
        assert_eq!(
            result.invocations, 1,
            "header write fails before pass 2 starts"
        );
        assert_eq!(result.counters.admitted, 0);
        assert_eq!(
            result.counters.declined_supply_failed, 0,
            "a peer/socket failure is not a supplier failure"
        );
        assert!(result.observations.is_empty());
        assert_process_serve_cleaned(&result);
    }

    #[tokio::test]
    async fn process_mid_body_transport_failure_unwinds_before_the_serve_deadline() {
        let body = vec![0x2c; (3 * 64 * 1024) + 17];
        let failure_after = nar_v4::NarV4WireAccounting::RESPONSE_HEADER_BYTES as usize + 1024;
        let result = run_two_pass_process_serve_with_close_race(
            &body,
            &body,
            &body,
            None,
            false,
            Some(failure_after),
        )
        .await;

        assert_eq!(result.invocations, 2, "the socket fails during pass 2");
        assert_eq!(result.wire.len(), failure_after);
        assert!(
            !result.wire.ends_with(nar_v4::COMPLETE_MARKER),
            "a failed socket must never receive COMPLETE"
        );
        assert!(
            result.serve_elapsed < Duration::from_secs(1),
            "socket failure took {:?}, suggesting the encoder channel stayed open until the 2 s serve deadline",
            result.serve_elapsed
        );
        assert_eq!(result.counters.admitted, 0);
        assert_eq!(result.counters.declined_supply_failed, 0);
        assert!(result.observations.is_empty());
        assert_process_serve_cleaned(&result);
    }

    #[tokio::test]
    async fn process_v4_pass1_short_emits_no_status() {
        let body = vec![0x32; 4096];
        let result = run_two_pass_process_serve(&body, &body[..body.len() - 1], &body, None).await;
        assert_eq!(result.invocations, 1);
        assert!(result.wire.is_empty(), "pass1 failure must precede status");
        assert_process_serve_cleaned(&result);
    }

    #[tokio::test]
    async fn process_v4_pass1_long_emits_no_status() {
        let body = vec![0x33; 4096];
        let mut long = body.clone();
        long.push(1);
        let result = run_two_pass_process_serve(&body, &long, &body, None).await;
        assert_eq!(result.invocations, 1);
        assert!(result.wire.is_empty(), "pass1 overrun must precede status");
        assert_process_serve_cleaned(&result);
    }

    #[tokio::test]
    async fn process_v4_pass1_nonzero_after_exact_emits_no_status() {
        let body = vec![0x34; 4096];
        let result = run_two_pass_process_serve(&body, &body, &body, Some(1)).await;
        assert_eq!(result.invocations, 1);
        assert!(
            result.wire.is_empty(),
            "pass1 exit status is checked before status"
        );
        assert_process_serve_cleaned(&result);
    }

    async fn assert_pass2_terminal_failure(pass2: Vec<u8>, nonzero_pass: Option<u64>) {
        let body = vec![0x35; (64 * 1024) + 17];
        let result = run_two_pass_process_serve(&body, &body, &pass2, nonzero_pass).await;
        assert_eq!(result.invocations, 2);
        assert_eq!(result.wire.first(), Some(&STATUS_NAR));
        assert!(
            !result.wire.ends_with(nar_v4::COMPLETE_MARKER),
            "a failed pass2 must never emit COMPLETE"
        );
        let content = Blake3Digest::from_raw_nar(&body);
        let mut wire = futures::io::Cursor::new(result.wire.clone());
        assert!(
            read_response_streamed(&mut wire, Some(body.len() as u64), IDLE, &content)
                .await
                .is_err(),
            "terminally failed pass2 must not complete the fetch"
        );
        assert_process_serve_cleaned(&result);
    }

    #[tokio::test]
    async fn process_v4_pass2_short_has_no_complete() {
        let body = vec![0x35; (64 * 1024) + 17];
        assert_pass2_terminal_failure(body[..body.len() - 1].to_vec(), None).await;
    }

    #[tokio::test]
    async fn process_v4_pass2_long_has_no_complete() {
        let mut body = vec![0x35; (64 * 1024) + 17];
        body.push(1);
        assert_pass2_terminal_failure(body, None).await;
    }

    #[tokio::test]
    async fn process_v4_pass2_nonzero_after_exact_has_no_complete() {
        let body = vec![0x35; (64 * 1024) + 17];
        assert_pass2_terminal_failure(body, Some(2)).await;
    }

    #[tokio::test]
    async fn process_v4_same_size_nondeterminism_fails_pass2_authentication() {
        let body = vec![0x36; (64 * 1024) + 17];
        let mut changed = body.clone();
        changed[64 * 1024] ^= 1;
        let result = run_two_pass_process_serve(&body, &body, &changed, None).await;
        assert_eq!(result.invocations, 2);
        assert_eq!(result.wire.first(), Some(&STATUS_NAR));
        assert!(!result.wire.ends_with(nar_v4::COMPLETE_MARKER));
        assert_eq!(
            result.wire.len(),
            10 + 64 + (64 * 1024),
            "socket contains only header + root proof + authenticated leaf1; changed final leaf never crosses"
        );
        assert_eq!(
            &result.wire[10 + 64..],
            &body[..64 * 1024],
            "the only raw content on the socket is the authenticated prefix"
        );
        assert_process_serve_cleaned(&result);
    }

    #[tokio::test]
    async fn absolute_deadline_reaps_a_backpressured_pass2_and_releases_its_reservation() {
        let serve_limit = Duration::from_millis(500);
        let fixture = backpressured_process_fixture(serve_limit, "0.05");
        let proof_bytes = bao_tree::BaoTree::new(fixture.raw_size as u64, nar_v4::BAO_BLOCK_SIZE)
            .outboard_size() as usize;
        let accepted_before_block = 10 + proof_bytes + (64 * 1024);
        let mock = RequestThenBudgetedWrite::new(&fixture.content, accepted_before_block);
        let blocked = Arc::clone(&mock.write_blocked);
        let written = Arc::clone(&mock.written);
        let started = std::time::Instant::now();
        let serve = tokio::spawn(serve_stream(mock, Some(Arc::clone(&fixture.gate))));
        let (pass2_pid, pass2_grandchild) = observe_backpressured_pass2(&fixture, &blocked).await;
        assert_eq!(
            written.lock().unwrap().len(),
            accepted_before_block,
            "header, exact proof, and one authenticated leaf cross before backpressure"
        );
        serve.await.expect("deadline-bounded serve task joins");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(400),
            "serve returned before its configured absolute deadline: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(900),
            "pass delays plus blocked write must share one 500-ms absolute deadline: {elapsed:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&fixture.counter).unwrap().trim(),
            "2",
            "deadline reaches pass 2 after exact pass 1"
        );
        wait_for_process_cleanup(
            &fixture.supervisor,
            &fixture.gate,
            &[pass2_pid, pass2_grandchild],
        )
        .await;
    }

    #[tokio::test]
    async fn dropping_a_backpressured_pass2_reaps_descendants_and_releases_reservation() {
        let fixture = backpressured_process_fixture(Duration::from_secs(30), "0");
        let proof_bytes = bao_tree::BaoTree::new(fixture.raw_size as u64, nar_v4::BAO_BLOCK_SIZE)
            .outboard_size() as usize;
        let mock = RequestThenBudgetedWrite::new(&fixture.content, 10 + proof_bytes + (64 * 1024));
        let blocked = Arc::clone(&mock.write_blocked);
        let serve = tokio::spawn(serve_stream(mock, Some(Arc::clone(&fixture.gate))));
        let (pass2_pid, pass2_grandchild) = observe_backpressured_pass2(&fixture, &blocked).await;
        serve.abort();
        let _ = serve.await;
        wait_for_process_cleanup(
            &fixture.supervisor,
            &fixture.gate,
            &[pass2_pid, pass2_grandchild],
        )
        .await;
    }

    #[tokio::test]
    async fn dropping_pass1_reaps_descendants_and_releases_reservation() {
        let body = vec![0x71; 4096];
        let content = Blake3Digest::from_raw_nar(&body);
        let pass1_pid = unique_temp("nar4-drop-pass1-pid");
        let pass1_grandchild = unique_temp("nar4-drop-pass1-grandchild");
        let _files = RemoveTestFiles(vec![pass1_pid.clone(), pass1_grandchild.clone()]);
        let pid_arg = pass1_pid.clone();
        let grandchild_arg = pass1_grandchild.clone();
        let probe = OneProbe {
            content,
            declared_size: body.len() as u64,
            make: Box::new(move || ProbedSource::Process {
                program: PathBuf::from("sh"),
                args: vec![
                    OsString::from("-c"),
                    OsString::from(
                        "printf %s $$ > \"$1\"; sleep 1000 & child=$!; \
                         printf %s \"$child\" > \"$2\"; wait",
                    ),
                    OsString::from("nar4-drop-pass1"),
                    pid_arg.clone().into_os_string(),
                    grandchild_arg.clone().into_os_string(),
                ],
            }),
        };
        let supervisor = TaskSupervisor::new();
        let gate = Arc::new(ServeGate::new(
            budget(1 << 20, 1 << 20),
            Arc::new(CatalogNarSupplier::new(probe, "unused-helper")),
            supervisor.handle(),
        ));
        let serve = tokio::spawn(serve_stream(
            RequestThenCapture::new(&content, peer_fabric::ACCEPT_RAW),
            Some(Arc::clone(&gate)),
        ));
        let (pid, grandchild) = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let pid = std::fs::read_to_string(&pass1_pid)
                    .ok()
                    .and_then(|value| value.trim().parse::<u32>().ok());
                let grandchild = std::fs::read_to_string(&pass1_grandchild)
                    .ok()
                    .and_then(|value| value.trim().parse::<u32>().ok());
                if let (Some(pid), Some(grandchild)) = (pid, grandchild)
                    && supervisor.process_jobs().active_len() != 0
                    && gate.inflight_bytes.load(Ordering::Acquire) == body.len() as u64
                {
                    break (pid, grandchild);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("pass 1 and its descendant are live under an owned reservation");
        serve.abort();
        let _ = serve.await;
        wait_for_process_cleanup(&supervisor, &gate, &[pid, grandchild]).await;
    }

    #[tokio::test]
    async fn memory_serve_counts_only_authenticated_cleanly_closed_delivery() {
        let announced = vec![0x41; 4096];
        let wrong = Arc::new(vec![0x42; announced.len()]);
        let content = Blake3Digest::from_raw_nar(&announced);
        let wrong_for_probe = Arc::clone(&wrong);
        let probe = OneProbe {
            content,
            declared_size: announced.len() as u64,
            make: Box::new(move || ProbedSource::Memory(Arc::clone(&wrong_for_probe))),
        };
        let wrong_root_gate = Arc::new(ServeGate::new(
            budget(1 << 20, 1 << 30),
            Arc::new(CatalogNarSupplier::new(probe, "unused-helper")),
            TaskSupervisorHandle::disconnected(),
        ));
        let mock = RequestThenCapture::new(&content, peer_fabric::ACCEPT_RAW);
        let wire = Arc::clone(&mock.written);
        serve_stream(mock, Some(Arc::clone(&wrong_root_gate))).await;
        assert!(
            wire.lock().unwrap().is_empty(),
            "memory root mismatch must fail before STATUS_NAR"
        );
        assert_eq!(
            wrong_root_gate.counters().admitted,
            0,
            "root-invalid memory supply was not served"
        );
        assert_eq!(
            wrong_root_gate.counters().declined_supply_failed,
            1,
            "root-invalid resident bytes are a supplier failure"
        );

        let honest = vec![0x43; 4096];
        let honest_content = Blake3Digest::from_raw_nar(&honest);
        let write_failure_gate = Arc::new(memory_gate(Arc::new(MemoryNarSupplier::new([honest]))));
        let mock =
            RequestThenCapture::new(&honest_content, peer_fabric::ACCEPT_RAW).with_write_failure();
        serve_stream(mock, Some(Arc::clone(&write_failure_gate))).await;
        let counters = write_failure_gate.counters();
        assert_eq!(
            counters.admitted, 0,
            "socket failure before clean close was not a completed serve"
        );
        assert_eq!(
            counters.declined_supply_failed, 0,
            "transport failure must not be mislabeled as supplier failure"
        );
    }

    #[tokio::test]
    async fn memory_supply_must_match_declared_size_before_any_response() {
        let raw = vec![0x44; 4096];
        let content = Blake3Digest::from_raw_nar(&raw);
        for declared_size in [0, (raw.len() as u64) + 1] {
            let mut supplier = MemoryNarSupplier::new([raw.clone()]);
            supplier.set_declared_size(content, declared_size);
            let gate = Arc::new(memory_gate(Arc::new(supplier)));
            let mock = RequestThenCapture::new(&content, peer_fabric::ACCEPT_RAW);
            let wire = Arc::clone(&mock.written);

            serve_stream(mock, Some(Arc::clone(&gate))).await;

            assert_eq!(
                wire.lock().unwrap().as_slice(),
                [STATUS_DECLINED, DeclineReason::SupplyFailed.wire()],
                "declared={declared_size}: mismatch may decline but must not emit STATUS_NAR/body"
            );
            let counters = gate.counters();
            assert_eq!(counters.admitted, 0);
            assert_eq!(counters.declined_supply_failed, 1);
            assert_eq!(
                gate.inflight_bytes.load(Ordering::Acquire),
                0,
                "declared={declared_size}: reservation releases after fail-closed mismatch"
            );
        }
    }

    /// AC#5 negotiation END TO END through serve_stream: a Memory server with the DEFAULT
    /// policy (zstd on) actually ships a ZSTD body when the fetcher offers zstd - the captured
    /// wire's codec byte is zstd and its frame decodes to the exact nar (same blob id).
    #[tokio::test]
    async fn serve_stream_negotiates_zstd_when_offered() {
        let raw = b"end-to-end negotiated compression through serve_stream".repeat(400);
        let content = Blake3Digest::from_raw_nar(&raw);
        let supplier = Arc::new(MemoryNarSupplier::new([raw.clone()]));
        let gate = Arc::new(memory_gate(supplier)); // default policy: zstd enabled

        let mock = RequestThenCapture::new(&content, ACCEPT_RAW_AND_ZSTD);
        let wire = Arc::clone(&mock.written);
        tokio::time::timeout(
            Duration::from_secs(5),
            serve_stream(mock, Some(Arc::clone(&gate))),
        )
        .await
        .expect("serve completes");

        let wire = wire.lock().unwrap().clone();
        assert_eq!(wire[0], STATUS_NAR, "status byte");
        assert_eq!(
            wire[1],
            WireCodec::Zstd.wire(),
            "server chose zstd when offered"
        );
        // The frame decodes back to the exact nar and the frozen id.
        let mut reader = futures::io::Cursor::new(wire);
        let got = read_response_streamed(&mut reader, Some(raw.len() as u64), IDLE, &content)
            .await
            .expect("the captured zstd wire decodes");
        assert_eq!(got, raw);
        assert_eq!(Blake3Digest::from_raw_nar(&got), content);
        assert_eq!(gate.counters().admitted, 1);
    }

    /// AC#5 raw fallback (server opt-out): a server whose policy DISABLES zstd serves a RAW
    /// body even though the fetcher offered zstd - the codec byte is raw and the fetch still
    /// succeeds (raw is the mandatory floor, over the SAME protocol).
    #[tokio::test]
    async fn serve_stream_falls_back_to_raw_when_server_disables_zstd() {
        let raw =
            b"a server that opts out of compression serves raw on the same protocol".repeat(50);
        let content = Blake3Digest::from_raw_nar(&raw);
        let supplier = Arc::new(MemoryNarSupplier::new([raw.clone()]));
        let gate = Arc::new(memory_gate(supplier).with_codec_policy(ServeCodecPolicy {
            zstd_enabled: false,
            ..ServeCodecPolicy::default()
        }));

        let mock = RequestThenCapture::new(&content, ACCEPT_RAW_AND_ZSTD);
        let wire = Arc::clone(&mock.written);
        tokio::time::timeout(
            Duration::from_secs(5),
            serve_stream(mock, Some(Arc::clone(&gate))),
        )
        .await
        .expect("serve completes");

        let wire = wire.lock().unwrap().clone();
        assert_eq!(
            wire[1],
            WireCodec::Raw.wire(),
            "zstd-disabled server serves raw"
        );
        let mut reader = futures::io::Cursor::new(wire);
        let got = read_response_streamed(&mut reader, Some(raw.len() as u64), IDLE, &content)
            .await
            .expect("raw fallback decodes");
        assert_eq!(got, raw);
    }

    /// AC#5 raw fallback (client opt-out): a fetcher that offers ONLY raw gets a raw body even
    /// from a zstd-enabled server - mixed codec-capability peers interoperate.
    #[tokio::test]
    async fn serve_stream_serves_raw_when_client_offers_only_raw() {
        let raw =
            b"a fetcher that cannot decode zstd still fetches over the same protocol".repeat(50);
        let content = Blake3Digest::from_raw_nar(&raw);
        let supplier = Arc::new(MemoryNarSupplier::new([raw.clone()]));
        let gate = Arc::new(memory_gate(supplier)); // zstd enabled server

        let mock = RequestThenCapture::new(&content, peer_fabric::ACCEPT_RAW); // raw only
        let wire = Arc::clone(&mock.written);
        tokio::time::timeout(
            Duration::from_secs(5),
            serve_stream(mock, Some(Arc::clone(&gate))),
        )
        .await
        .expect("serve completes");

        let wire = wire.lock().unwrap().clone();
        assert_eq!(
            wire[1],
            WireCodec::Raw.wire(),
            "server must honour a raw-only fetcher (mandatory fallback)"
        );
        let mut reader = futures::io::Cursor::new(wire);
        let got = read_response_streamed(&mut reader, Some(raw.len() as u64), IDLE, &content)
            .await
            .expect("raw fallback decodes");
        assert_eq!(got, raw);
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
        accept: u8,
        read_pos: usize,
    }

    impl AsyncRead for DigestThenUnreadable {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            // The request is 33 bytes: 32 digest + the configured accept byte.
            let mut request = [0u8; 33];
            request[..32].copy_from_slice(&self.digest);
            request[32] = self.accept;
            if self.read_pos < request.len() && !buf.is_empty() {
                let start = self.read_pos;
                let n = (request.len() - start).min(buf.len());
                buf[..n].copy_from_slice(&request[start..start + n]);
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
            accept: ACCEPT_RAW_AND_ZSTD,
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

    /// The body-free process/no-codec decline uses the same absolute deadline as every other
    /// response. Since this mock's write side stays Pending and its read side never reaches EOF,
    /// returning from `serve_stream` logically pins the deadline classification without log capture.
    #[tokio::test]
    async fn process_no_common_codec_decline_write_expires_at_the_absolute_deadline() {
        let body = b"process source whose no-codec decline peer never reads";
        let (supervisor, gate, content) = no_codec_process_gate(body, Duration::from_millis(100));
        let mock = DigestThenUnreadable {
            digest: *content.as_bytes(),
            accept: 0,
            read_pos: 0,
        };

        tokio::time::timeout(
            Duration::from_secs(2),
            serve_stream(mock, Some(Arc::clone(&gate))),
        )
        .await
        .expect("no-common-codec decline returns at its absolute response deadline");
        assert_eq!(gate.counters(), ServeCounters::default());
        assert_eq!(gate.inflight_bytes.load(Ordering::Acquire), 0);
        assert_eq!(supervisor.process_jobs().active_len(), 0);
    }

    /// THE DECISIVE ceiling oracle (codex DEEP-gate finding): the in-flight byte ceiling must
    /// bound MEMORY-backed serves too, not only Process ones. A never-reading consumer opens a
    /// Memory serve, which produces inline and then BLOCKS on the write while HOLDING its
    /// reservation; with the ceiling sized for exactly one such NAR, a SECOND serve must be
    /// `Declined(Busy)`. It directly OBSERVES the reservation is NONZERO while the first write
    /// is blocked, then that it releases to zero after the blocked serve is dropped.
    ///
    /// BITE: this is the oracle for the fix. With the pre-fix Memory path (the reservation
    /// dropped inside `admit` BEFORE the write), `inflight` stays 0 while the first consumer
    /// blocks, so (a) the "charged the ceiling" wait times out RED, and (b) the second serve
    /// would be wrongly ADMITTED - the ceiling defeated for memory-backed content.
    #[tokio::test]
    async fn a_never_reading_memory_consumer_holds_the_inflight_ceiling_against_a_second_serve() {
        let nar = vec![0x5au8; 4096];
        let content = Blake3Digest::from_raw_nar(&nar);
        let supplier = Arc::new(MemoryNarSupplier::new([nar.clone()]));
        // The ceiling holds EXACTLY one such NAR, and a LONG serve deadline so the first write
        // stays blocked (the deadline does not race the assertions).
        let tight = ServeBudget {
            max_nar_bytes_uncompressed_nar: 1 << 20,
            max_inflight_bytes_uncompressed_nar: nar.len() as u64,
            max_serve_duration: Duration::from_secs(30),
        };
        let gate = Arc::new(ServeGate::new(
            tight,
            supplier,
            TaskSupervisorHandle::disconnected(),
        ));

        // Never-reader #1: sends the digest, never reads. The Memory serve produces inline then
        // BLOCKS on the write, holding its reservation THROUGH the write (the fix).
        let mock = DigestThenUnreadable {
            digest: *content.as_bytes(),
            accept: ACCEPT_RAW_AND_ZSTD,
            read_pos: 0,
        };
        let serve1 = tokio::spawn(serve_stream(mock, Some(Arc::clone(&gate))));

        // OBSERVE the reservation charged while #1 is blocked on its write.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if gate.inflight_bytes.load(Ordering::Acquire) == nar.len() as u64 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "never-reader #1 never charged the in-flight ceiling - the Memory reservation \
                 was dropped before the blocked write (the ceiling is bypassable)"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // DECISIVE: with #1's reservation held through its blocked write, the ceiling is full,
        // so a second serve is Declined(Busy). Pre-fix, inflight would be 0 here and this would
        // be admitted - the ceiling defeated.
        match gate.admit(&content) {
            Serve::Now {
                response: NarResponse::Declined(DeclineReason::Busy),
                ..
            } => {}
            other => match other {
                Serve::Now { response, .. } => {
                    panic!(
                        "expected the second serve Declined(Busy) while #1 holds the ceiling, got {response:?}"
                    )
                }
                Serve::OffLoop { .. } => panic!("expected Serve::Now for a Memory source"),
            },
        }

        // Drop #1 (abort its blocked write) and confirm the reserve releases back to zero.
        serve1.abort();
        let _ = serve1.await;
        let released = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if gate.inflight_bytes.load(Ordering::Acquire) == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < released,
                "the in-flight reserve must release to zero once the blocked serve is dropped"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // -------------------------------------------------------------------------
    // TASK-203/TASK-197: serve-side streaming zstd, now one frame per authenticated v4 leaf.
    // End-to-end through serve_stream, plus deadline-bound + write-error paths that prove the
    // off-worker pipeline stays preemptible and leak-free.
    // -------------------------------------------------------------------------

    /// A ~512 KiB low-entropy raw NAR: large enough for several 64-KiB Bao leaves and
    /// compressible enough that their independent zstd frames remain small.
    fn multi_leaf_nar(len: usize, seed: u32) -> Vec<u8> {
        let mut raw = Vec::with_capacity(len);
        let mut x = seed;
        while raw.len() < len {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            raw.push(((x >> 24) & 0x0f) as u8);
        }
        raw
    }

    /// AC#1 end-to-end: a large multi-leaf nar served through `serve_stream` uses independently
    /// framed zstd leaves that the fetch path decodes to the exact nar and frozen blob id.
    #[tokio::test]
    async fn serve_stream_authenticates_a_large_multi_leaf_nar() {
        let raw = multi_leaf_nar(512 * 1024, 0x0f0f_0f0f);
        let content = Blake3Digest::from_raw_nar(&raw);
        let supplier = Arc::new(MemoryNarSupplier::new([raw.clone()]));
        let gate = Arc::new(memory_gate(supplier));

        let mock = RequestThenCapture::new(&content, ACCEPT_RAW_AND_ZSTD);
        let wire = Arc::clone(&mock.written);
        tokio::time::timeout(
            Duration::from_secs(10),
            serve_stream(mock, Some(Arc::clone(&gate))),
        )
        .await
        .expect("serve completes");

        let wire = wire.lock().unwrap().clone();
        assert_eq!(wire[0], STATUS_NAR, "status byte");
        assert_eq!(
            wire[1],
            WireCodec::Zstd.wire(),
            "server selected per-leaf zstd for a large NAR"
        );
        let accounting = nar_v4::NarV4WireAccounting::from_response_protocol_bytes(
            raw.len() as u64,
            WireCodec::Zstd,
            wire.len() as u64,
        )
        .expect("captured response has exact v4 accounting");
        // A real compression happened despite proof/prefix/header/COMPLETE overhead.
        assert!(
            accounting.response_protocol_bytes < raw.len() as u64,
            "the exact v4 response ({} B) must be smaller than the raw NAR ({} B)",
            accounting.response_protocol_bytes,
            raw.len()
        );
        let mut reader = futures::io::Cursor::new(wire);
        let got = read_response_streamed(&mut reader, Some(raw.len() as u64), IDLE, &content)
            .await
            .expect("the captured streamed zstd wire decodes");
        assert_eq!(got, raw, "the v4 response decodes to the exact NAR");
        assert_eq!(Blake3Digest::from_raw_nar(&got), content, "same blob id");
        assert_eq!(gate.counters().admitted, 1);
    }

    /// AC#1 preemption + no-leak: a large NAR whose consumer NEVER reads must have its streaming
    /// zstd write PREEMPTED by the serve deadline (each owned handoff reaches an await), the serve task
    /// terminate, and the in-flight reservation RELEASE - the streaming path stays deadline-bound
    /// and leak-free. BITE: an un-preemptible whole-nar compress + a never-released reservation
    /// would trip the 5 s guard / leave inflight non-zero.
    #[tokio::test]
    async fn serve_streaming_zstd_stays_deadline_bounded_for_a_non_reading_consumer() {
        let raw = multi_leaf_nar(400 * 1024, 0xbeef_1234);
        let content = Blake3Digest::from_raw_nar(&raw);
        let supplier = Arc::new(MemoryNarSupplier::new([raw.clone()]));
        let short = ServeBudget {
            max_nar_bytes_uncompressed_nar: 1 << 20,
            max_inflight_bytes_uncompressed_nar: 1 << 30,
            max_serve_duration: Duration::from_millis(300),
        };
        let gate = Arc::new(ServeGate::new(
            short,
            supplier,
            TaskSupervisorHandle::disconnected(),
        ));

        let mock = DigestThenUnreadable {
            digest: *content.as_bytes(),
            accept: ACCEPT_RAW_AND_ZSTD,
            read_pos: 0,
        };
        let serve = tokio::spawn(serve_stream(mock, Some(Arc::clone(&gate))));
        tokio::time::timeout(Duration::from_secs(5), serve)
            .await
            .expect("serve_stream must terminate within the serve deadline, not hang")
            .expect("serve task joins");
        assert_eq!(
            gate.inflight_bytes.load(Ordering::Acquire),
            0,
            "the reservation must release after the deadline-bounded streamed write"
        );
    }

    // -------------------------------------------------------------------------
    // TASK-62 store-and-forward streaming oracles (AC#1 / AC#3 / AC#7 MECHANISMS),
    // driven through the REAL `open_nar_response_stream` over synthetic /nar/4 wire.
    // Each names its BITE. These are the reader/handoff-level proofs; the end-to-end
    // HTTP-client TTFB (AC#1) and the peer-kill build-survives (AC#3) are the e2e gate,
    // reported separately.
    // -------------------------------------------------------------------------

    /// A `futures::io::Cursor` for the owned-reader (`Send + 'static`) streaming API.
    fn cursor(wire: Vec<u8>) -> futures::io::Cursor<Vec<u8>> {
        futures::io::Cursor::new(wire)
    }

    /// AC#1 (reader level): the streaming reader delivers the FIRST verified chunk as a
    /// PREFIX SLICE of the NAR, before the whole NAR is collected - the property a `Vec<u8>`
    /// collector at the seam cannot have. Over a multi-leaf NAR the first chunk is strictly
    /// shorter than the whole, and consuming chunk-by-chunk reassembles the exact bytes.
    ///
    /// BITE: revert the seam to buffer-then-`Full` (collect every leaf into one `Vec`): the
    /// consumer then receives ONE chunk equal to the whole NAR - `first.len() == raw.len()` -
    /// and this fails. (The end-to-end TTFB-at-the-client bite lives in the AC#1 HTTP oracle.)
    #[tokio::test]
    async fn streaming_reader_exposes_first_chunk_before_the_whole_nar() {
        // 3 leaves (> 2 so "first < whole" is unambiguous).
        let raw: Vec<u8> = (0..((2 * 64 * 1024) + 123)).map(|i| i as u8).collect();
        let content = Blake3Digest::from_raw_nar(&raw);
        let meter = Arc::new(InflightMeter::new());
        let mut stream = open_nar_response_stream(
            cursor(wire_nar(&raw)),
            Some(raw.len() as u64),
            IDLE,
            content,
            ACCEPT_RAW_AND_ZSTD,
            Arc::clone(&meter),
        )
        .await
        .expect("a valid /nar/4 response opens a stream");
        assert_eq!(
            stream.declared_size,
            raw.len() as u64,
            "declared size == signed NarSize (AC#4 Content-Length source)"
        );

        let first = stream
            .next_chunk()
            .await
            .expect("a first chunk")
            .expect("the first chunk is a verified leaf, not an error");
        assert!(
            (first.len() as u64) < raw.len() as u64,
            "the first chunk must be a strict PREFIX slice, not the whole buffered NAR \
             (a seam collector would hand the whole {} B here)",
            raw.len()
        );
        assert_eq!(
            &first[..],
            &raw[..first.len()],
            "the first chunk is the honest NAR prefix"
        );

        let mut got = first.to_vec();
        while let Some(chunk) = stream.next_chunk().await {
            got.extend_from_slice(&chunk.expect("no mid-stream error on a clean transfer"));
        }
        assert_eq!(
            got, raw,
            "chunk-by-chunk delivery reassembles the exact NAR"
        );
    }

    /// AC#7/#2 (mechanism): under a DELIBERATELY SLOW reader the fetch-side in-flight
    /// high-water mark stays within the frozen `MAX_INFLIGHT_FETCH_BYTES_RAM` and is
    /// INDEPENDENT of NAR size; every permit is released (`current() == 0`) at clean EOF.
    ///
    /// BITE: an unbounded / O(NarSize) handoff (an unbounded channel, or forwarding without
    /// the depth-bounded `send` backpressure) drives `hwm` past the bound and makes
    /// `hwm(large) >> hwm(small)` - this asserts the opposite, by integer cross-multiplication.
    #[tokio::test]
    async fn inflight_hwm_is_bounded_and_size_independent_under_a_slow_reader() {
        async fn drain_slowly(bytes: usize) -> u64 {
            let raw: Vec<u8> = (0..bytes).map(|i| i as u8).collect();
            let content = Blake3Digest::from_raw_nar(&raw);
            let meter = Arc::new(InflightMeter::new());
            let mut stream = open_nar_response_stream(
                cursor(wire_nar(&raw)),
                Some(raw.len() as u64),
                IDLE,
                content,
                ACCEPT_RAW_AND_ZSTD,
                Arc::clone(&meter),
            )
            .await
            .expect("stream opens");
            let mut total: u64 = 0;
            while let Some(chunk) = stream.next_chunk().await {
                let chunk = chunk.expect("clean transfer");
                total += chunk.len() as u64;
                // Yield + brief sleep so the producer races ahead and FILLS the bounded
                // channel - a fast reader never fills it, so the hwm would be meaningless.
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_micros(50)).await;
            }
            assert_eq!(total, raw.len() as u64, "delivered the whole NAR");
            assert_eq!(
                meter.current(),
                0,
                "AC#7: every in-flight permit is released at clean EOF"
            );
            meter.hwm()
        }

        let hwm_small = drain_slowly(1024 * 1024).await; // 1 MiB, 16 leaves
        let hwm_large = drain_slowly(8 * 1024 * 1024).await; // 8 MiB, 128 leaves
        let bound = peer_fabric::MAX_INFLIGHT_FETCH_BYTES_RAM;
        assert!(
            hwm_small <= bound && hwm_large <= bound,
            "in-flight hwm within the frozen bound {bound}: small={hwm_small} large={hwm_large}"
        );
        // Size INDEPENDENCE (manifest 5/4 rule, integer cross-multiplication):
        // hwm_large / hwm_small <= 5/4  <=>  hwm_large*4 <= hwm_small*5.
        assert!(
            hwm_large * 4 <= hwm_small * 5,
            "in-flight hwm must NOT scale with NAR size: small={hwm_small} large={hwm_large}"
        );
    }

    /// AC#3 (mechanism): a TRUNCATED mid-body transfer surfaces as a TERMINAL `Err` chunk
    /// AFTER the honest verified prefix - NEVER a clean `None` that would present a partial
    /// NAR as complete, and never a wrong byte. This is the reader-level shape of the PRD
    /// additive invariant: once bytes are committed to the client, a mid-body peer failure is
    /// visible, so Nix refetches; the daemon never launders truncation into apparent success.
    ///
    /// BITE: drop the `verified.finish()` terminal check (close the channel cleanly on EOF
    /// regardless of the verifier result): the consumer then sees `None` after a partial NAR -
    /// silent truncation - and `saw_terminal_error` is false.
    #[tokio::test]
    async fn a_truncated_transfer_ends_in_a_terminal_error_never_a_clean_partial() {
        let raw: Vec<u8> = (0..(8 * 64 * 1024)).map(|i| i as u8).collect(); // 8 leaves
        let content = Blake3Digest::from_raw_nar(&raw);
        let full = wire_nar(&raw);
        // Cut the transfer at ~55%: several leaves authenticate + deliver, COMPLETE never
        // arrives, transport EOF is seen WITHOUT the completion marker.
        let truncated = full[..(full.len() * 55 / 100)].to_vec();
        let meter = Arc::new(InflightMeter::new());
        let mut stream = open_nar_response_stream(
            cursor(truncated),
            Some(raw.len() as u64),
            IDLE,
            content,
            ACCEPT_RAW_AND_ZSTD,
            Arc::clone(&meter),
        )
        .await
        .expect("the header is intact, so the stream opens; the body is where it dies");

        let mut got: Vec<u8> = Vec::new();
        let mut saw_terminal_error = false;
        while let Some(chunk) = stream.next_chunk().await {
            match chunk {
                Ok(bytes) => got.extend_from_slice(&bytes),
                Err(_) => {
                    saw_terminal_error = true;
                    break;
                }
            }
        }
        assert!(
            saw_terminal_error,
            "a truncated transfer MUST end in a terminal error, not a clean partial EOF \
             (silent truncation would let Nix accept a short NAR)"
        );
        assert_eq!(
            got,
            raw[..got.len()],
            "every delivered chunk is the HONEST prefix - a mid-body failure never yields wrong bytes"
        );
    }

    /// AC#3 (mechanism, strongest "never wrong bytes"): a holder serving bytes that do NOT
    /// authenticate against the requested BLAKE3 (gate 1) yields ZERO honest `Ok` chunks and a
    /// terminal `Err` - Bao rejects at the root before any wrong byte is exposed.
    ///
    /// BITE: expose leaves before Bao authenticates them (drop the per-leaf gate): a wrong
    /// `Ok` chunk would appear and `wrong_ok_chunks` would be non-zero.
    #[tokio::test]
    async fn wrong_content_never_yields_an_ok_chunk_only_a_terminal_error() {
        let served: Vec<u8> = (0..(3 * 64 * 1024)).map(|i| i as u8).collect();
        let requested_other: Vec<u8> = (0..(3 * 64 * 1024)).map(|i| (i as u8) ^ 0xff).collect();
        let requested = Blake3Digest::from_raw_nar(&requested_other);
        // The wire carries `served`'s honest bao tree, but we ASK for a different digest.
        let meter = Arc::new(InflightMeter::new());
        let mut stream = open_nar_response_stream(
            cursor(wire_nar(&served)),
            Some(served.len() as u64),
            IDLE,
            requested,
            ACCEPT_RAW_AND_ZSTD,
            Arc::clone(&meter),
        )
        .await
        .expect("header (status/size) is well-formed; the digest mismatch dies in the body");

        let mut wrong_ok_chunks = 0usize;
        let mut saw_terminal_error = false;
        while let Some(chunk) = stream.next_chunk().await {
            match chunk {
                Ok(_) => wrong_ok_chunks += 1,
                Err(_) => {
                    saw_terminal_error = true;
                    break;
                }
            }
        }
        assert_eq!(
            wrong_ok_chunks, 0,
            "gate 1 (Bao) must reject wrong content at the root - NO Ok chunk may carry \
             bytes that do not authenticate to the requested digest"
        );
        assert!(
            saw_terminal_error,
            "wrong content must surface as a terminal error, so the fetch fails closed"
        );
    }
}
