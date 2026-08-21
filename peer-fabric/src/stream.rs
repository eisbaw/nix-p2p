//! Fetcher-side in-flight accounting for the store-and-forward streaming peer-fetch
//! path (TASK-62 AC#2 / AC#7).
//!
//! ## Why this lives at the seam, not inside a backend
//!
//! When the daemon STREAMS a peer NAR straight into the HTTP body (rather than
//! buffering the whole `Vec<u8>` at the transport boundary), the only bytes that may
//! be resident on the fetcher side are those that have been verifier-authenticated
//! but not yet consumed by the HTTP client. [`InflightMeter`] is the SINGLE place that
//! quantity and its high-water mark are recorded, so the AC#2/AC#7 oracle observes ONE
//! number regardless of which backend (libp2p `/nar/4`, iroh-blobs bao) produced the
//! stream.
//!
//! ## The placement obligation (frozen manifest `ac2_ac7_backpressure_inflight`)
//!
//! The meter MUST sit at the LOWEST point that holds bytes pending client consumption -
//! i.e. it charges a chunk the instant the backend hands a verified leaf toward the
//! HTTP body, and releases it the instant the HTTP body consumes it. A meter placed
//! ABOVE a backend that internally buffers the whole NAR would read ~one chunk and pass
//! trivially while real RSS blows up (a green-for-the-wrong-reason gate). The backend's
//! verifier handoff is bounded to O(1 leaf) by construction (pull discipline; see
//! `fabric_libp2p::nar::VerifiedNarStream`), so charging at the handoff is honest: the
//! only NarSize-scaling accumulation this could have is the buffer this meter watches.
//!
//! ## What the oracle asserts (integers only - owner no-float rule)
//!
//! [`InflightMeter::hwm`] is compared, as an integer count of bytes, against the frozen
//! `max_inflight_fetch_bytes_ram` (4 * `STREAM_CHUNK_BYTES` = 262144). A producer that
//! accumulates O(NarSize) drives the hwm past that bound and FAILS; a size-independent
//! bounded window stays under it at every NAR size.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;

use crate::capabilities::TransferError;
use crate::ids::STREAM_CHUNK_BYTES;

/// The frozen fetch-side in-flight ceiling: `4 * STREAM_CHUNK_BYTES` (= 262144), the small
/// NarSize-INDEPENDENT window the streaming handoff is allowed to hold. Derived from the
/// SAME `STREAM_CHUNK_BYTES` single source of truth so the two cannot drift; it equals
/// `artifacts/task62-streaming-manifest-v1.json`
/// `thresholds.ac2_ac7_backpressure_inflight.max_inflight_fetch_bytes_ram` (262144). A
/// producer whose in-flight bytes exceed this at any NAR size fails the AC#2/AC#7 oracle.
pub const MAX_INFLIGHT_FETCH_BYTES_RAM: u64 = 4 * STREAM_CHUNK_BYTES as u64;

/// Live count + high-water mark of raw NAR bytes held in the fetch->HTTP handoff.
///
/// `charge` when a verified leaf enters the bounded handoff (before it is queued toward
/// the HTTP body); `release` when the HTTP body consumes it. `hwm` is monotone and is
/// the AC#2/AC#7 decision input; `current` returning to 0 after teardown is the AC#7
/// permit-release signal.
///
/// All counters are integers (bytes). No float ever participates (owner rule).
#[derive(Debug, Default)]
pub struct InflightMeter {
    current: AtomicU64,
    hwm: AtomicU64,
}

impl InflightMeter {
    /// A fresh meter with zero bytes in flight and a zero high-water mark.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `n` raw bytes ENTERED the in-flight window (a verified leaf was handed
    /// toward the HTTP body). Bumps `current` and raises `hwm` if the new level is a peak.
    pub fn charge(&self, n: u64) {
        // AcqRel so the hwm update observes this add and vice versa across threads.
        let now = self.current.fetch_add(n, Ordering::AcqRel) + n;
        self.hwm.fetch_max(now, Ordering::AcqRel);
    }

    /// Record that `n` raw bytes LEFT the in-flight window (the HTTP body consumed the
    /// chunk, or teardown released it). `current` drops; `hwm` never drops (it is the
    /// peak the oracle bounds).
    pub fn release(&self, n: u64) {
        self.current.fetch_sub(n, Ordering::AcqRel);
    }

    /// Bytes CURRENTLY in flight (charged minus released). AC#7: must return to 0 after a
    /// cancellation/disconnect/HEAD/timeout teardown once every permit is released.
    pub fn current(&self) -> u64 {
        self.current.load(Ordering::Acquire)
    }

    /// The peak in-flight byte count over this meter's life. AC#2/AC#7: must stay
    /// `<= MAX_INFLIGHT_FETCH_BYTES_RAM` and be NarSize-independent.
    pub fn hwm(&self) -> u64 {
        self.hwm.load(Ordering::Acquire)
    }
}

// -------------------------------------------------------------------------
// TASK-62 AC#6: the substrate-neutral streaming NAR contract.
// -------------------------------------------------------------------------

/// A pull-based source of gate-1-verified raw NAR leaves for the store-and-forward
/// streaming HTTP path (TASK-62 AC#6). It is substrate-neutral: the libp2p backend's
/// verifier handoff, the iroh backend's leaf loop, and the in-memory fake all present
/// the SAME shape, so `peer_source` builds one HTTP body regardless of which backend
/// produced the stream.
///
/// [`next_chunk`](NarChunkSource::next_chunk) contract:
///   * `Some(Ok(bytes))` - the NEXT BLAKE3-verified raw leaf (gate 1 held on it).
///   * `Some(Err(_))` - a TERMINAL mid-stream failure surfaced AFTER the earlier
///     verified leaves (transport reset, stall, or a final Bao authentication failure
///     at EOF). Never wrong bytes: gate 1 holds per leaf, and gate 2 (sha256==NarHash)
///     is Nix's, downstream - so a truncated body makes Nix retry the next substituter
///     (the PRD additive invariant, empirically confirmed), never accept a partial.
///   * `None` - clean EOF: every leaf was delivered and the terminal contract passed.
#[async_trait]
pub trait NarChunkSource: Send {
    /// Pull the next verified raw NAR leaf; see the trait doc for the three outcomes.
    async fn next_chunk(&mut self) -> Option<Result<Bytes, io::Error>>;
}

/// The streaming NAR a [`NarTransfer::fetch_stream`](crate::NarTransfer::fetch_stream)
/// yields once the header phase has passed: the provider-declared uncompressed
/// RawNarV1 size plus the verified-leaf source.
///
/// ## Why the header phase is already over when a `NarStream` exists
///
/// Every terminal outcome decided BEFORE a body byte - `NotHeld`, `Declined`, the
/// risk-6 `TooLarge` abort, a declared size that disagrees with the signed bound - is
/// returned as `Err(TransferError)` by `fetch_stream` BEFORE this value is constructed.
/// So the mere existence of a `NarStream` implies a genuine, size-agreed NAR body
/// follows, and the daemon may commit the HTTP `200` head. This is what preserves the
/// pre-head clean fallback (S2): a peer that does not hold the content, or lies about
/// its size, fails BEFORE any head is written, exactly as under the old buffering path.
/// Only a failure DURING the body (after the head is committed) is client-visible, and
/// that is the case the empirically-confirmed Nix cross-substituter retry covers.
///
/// ## `declared_size` and framing (AC#4)
///
/// `declared_size` is the header's RawNarV1 size, already checked to equal the signed
/// NarSize on the correlated path. `peer_source` uses it as the `Content-Length` when a
/// signed size is known (`expected_size.is_some()`), and frames chunked on the cold-start
/// `None` path. It is UNCOMPRESSED RawNarV1 bytes, NEVER a compressed FileSize.
pub struct NarStream {
    declared_size: u64,
    source: Box<dyn NarChunkSource>,
}

impl NarStream {
    /// A stream of `declared_size` RawNarV1 bytes served by `source`. The caller has
    /// already validated the header (size agreement, codec, risk-6 abort) before
    /// constructing this - see the type doc.
    pub fn new(declared_size: u64, source: Box<dyn NarChunkSource>) -> Self {
        Self {
            declared_size,
            source,
        }
    }

    /// Wrap already-collected raw NAR bytes as a streaming NAR (the buffering
    /// interface-adapter used by the iroh backend, the in-memory fake, and the default
    /// [`fetch_stream`](crate::NarTransfer::fetch_stream)).
    ///
    /// HONEST: this is NOT incremental streaming - the whole NAR is already resident, so
    /// it neither decouples fetcher RSS (AC#5) nor bounds in-flight bytes (AC#2). It only
    /// presents the streaming INTERFACE so a backend that has not been converted to true
    /// streaming still satisfies the `NarStream` contract. The bytes are emitted in
    /// `STREAM_CHUNK_BYTES` slices so a consumer sees the same leaf granularity as a true
    /// stream (a HEAD/disconnect can stop between slices), but the memory is already spent.
    pub fn from_collected(raw: Vec<u8>) -> Self {
        let declared_size = raw.len() as u64;
        Self {
            declared_size,
            source: Box::new(CollectedChunks {
                buf: Bytes::from(raw),
            }),
        }
    }

    /// The provider-declared uncompressed RawNarV1 size (the `Content-Length` source on
    /// the correlated path; the daemon frames chunked on the cold-start `None` path).
    pub fn declared_size(&self) -> u64 {
        self.declared_size
    }

    /// Pull the next verified raw leaf (see [`NarChunkSource::next_chunk`]).
    pub async fn next_chunk(&mut self) -> Option<Result<Bytes, io::Error>> {
        self.source.next_chunk().await
    }

    /// Drain the whole stream into one `Vec` (the mechanical collector for the legacy
    /// `Vec<u8>` consumers and unit tests). A terminal mid-stream `Err` becomes a
    /// [`TransferError::Unavailable`] - the same fold a buffering fetch produced. This
    /// REINTRODUCES the O(NarSize) buffer, so the shipped streaming serve path
    /// (`peer_source`) must NOT use it - it consumes `next_chunk` directly.
    pub async fn collect(mut self) -> Result<Vec<u8>, TransferError> {
        let mut raw =
            Vec::with_capacity(self.declared_size.min(STREAM_CHUNK_BYTES as u64) as usize);
        while let Some(chunk) = self.source.next_chunk().await {
            match chunk {
                Ok(bytes) => raw.extend_from_slice(&bytes),
                Err(error) => {
                    return Err(TransferError::Unavailable(format!(
                        "streaming NAR failed mid-body after {} B: {error}",
                        raw.len()
                    )));
                }
            }
        }
        Ok(raw)
    }
}

impl std::fmt::Debug for NarStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The chunk source is a trait object and not `Debug`; render only the geometry.
        f.debug_struct("NarStream")
            .field("declared_size", &self.declared_size)
            .finish_non_exhaustive()
    }
}

/// An in-memory [`NarChunkSource`] over already-resident bytes, emitting
/// `STREAM_CHUNK_BYTES` slices. Backs [`NarStream::from_collected`].
struct CollectedChunks {
    buf: Bytes,
}

#[async_trait]
impl NarChunkSource for CollectedChunks {
    async fn next_chunk(&mut self) -> Option<Result<Bytes, io::Error>> {
        if self.buf.is_empty() {
            return None;
        }
        let take = STREAM_CHUNK_BYTES.min(self.buf.len());
        // `split_to` is O(1) refcount slicing on `Bytes`, no re-copy.
        Some(Ok(self.buf.split_to(take)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn charge_release_tracks_current_and_peaks_hwm() {
        let m = InflightMeter::new();
        assert_eq!((m.current(), m.hwm()), (0, 0));
        m.charge(65536);
        m.charge(65536);
        assert_eq!((m.current(), m.hwm()), (131072, 131072));
        m.release(65536);
        // current drops, hwm holds the peak (it is monotone - the oracle bounds the PEAK).
        assert_eq!((m.current(), m.hwm()), (65536, 131072));
        m.release(65536);
        assert_eq!((m.current(), m.hwm()), (0, 131072));
    }

    #[test]
    fn hwm_is_the_bound_decision_input_as_an_integer() {
        // A bounded window (charge one, release before charging the next) never exceeds one
        // chunk regardless of how many total chunks pass - the size-INDEPENDENCE property.
        let m = InflightMeter::new();
        for _ in 0..10_000 {
            m.charge(65536);
            m.release(65536);
        }
        assert_eq!(m.current(), 0);
        assert_eq!(m.hwm(), 65536);
        assert!(m.hwm() <= MAX_INFLIGHT_FETCH_BYTES_RAM);

        // BITE: an accumulating producer (charge without releasing) drives the hwm PAST the
        // bound - exactly the O(NarSize) buffer the AC#2 oracle must reject.
        let bad = InflightMeter::new();
        for _ in 0..8 {
            bad.charge(65536); // 8 * 64KiB = 524288 > 262144
        }
        assert!(
            bad.hwm() > MAX_INFLIGHT_FETCH_BYTES_RAM,
            "an O(NarSize) accumulator must exceed the frozen in-flight bound"
        );
    }

    #[test]
    fn meter_is_shareable_across_producer_and_consumer() {
        // The producer (backend) and consumer (HTTP body) hold the SAME Arc<InflightMeter>,
        // so charge/release net to the true resident count.
        let m = Arc::new(InflightMeter::new());
        let producer = Arc::clone(&m);
        producer.charge(65536);
        assert_eq!(m.current(), 65536);
        m.release(65536);
        assert_eq!(m.current(), 0);
    }

    #[tokio::test]
    async fn from_collected_round_trips_and_reports_declared_size() {
        let raw: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let stream = NarStream::from_collected(raw.clone());
        assert_eq!(stream.declared_size(), raw.len() as u64);
        let back = stream
            .collect()
            .await
            .expect("collect a from_collected stream");
        assert_eq!(
            back, raw,
            "from_collected -> collect must be byte-identical"
        );
    }

    #[tokio::test]
    async fn from_collected_emits_stream_chunk_sized_slices() {
        // A consumer sees the same leaf granularity as a true stream: STREAM_CHUNK_BYTES
        // slices, with a short final slice. This is what lets a HEAD/disconnect stop
        // between slices even on the buffering interface-adapter.
        let n = STREAM_CHUNK_BYTES * 2 + 7;
        let stream = NarStream::from_collected(vec![0u8; n]);
        let mut sizes = Vec::new();
        let mut src = stream.source;
        while let Some(chunk) = src.next_chunk().await {
            sizes.push(chunk.expect("no error from an in-memory source").len());
        }
        assert_eq!(
            sizes,
            vec![STREAM_CHUNK_BYTES, STREAM_CHUNK_BYTES, 7],
            "chunks are STREAM_CHUNK_BYTES with a short tail"
        );
    }

    #[tokio::test]
    async fn empty_collected_stream_is_immediately_eof() {
        let stream = NarStream::from_collected(Vec::new());
        assert_eq!(stream.declared_size(), 0);
        assert_eq!(
            stream.collect().await.expect("empty collect"),
            Vec::<u8>::new()
        );
    }

    /// A source whose leaves are fine until a TERMINAL error - proves `collect` folds a
    /// mid-body failure to `TransferError::Unavailable` (the buffering-parity fold) AND
    /// that the earlier verified leaves are what preceded the failure.
    struct FailAfter {
        good: Vec<Bytes>,
        idx: usize,
    }

    #[async_trait]
    impl NarChunkSource for FailAfter {
        async fn next_chunk(&mut self) -> Option<Result<Bytes, io::Error>> {
            if self.idx < self.good.len() {
                let out = self.good[self.idx].clone();
                self.idx += 1;
                return Some(Ok(out));
            }
            if self.idx == self.good.len() {
                self.idx += 1;
                return Some(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer aborted",
                )));
            }
            None
        }
    }

    #[tokio::test]
    async fn collect_folds_a_terminal_error_to_unavailable() {
        let stream = NarStream::new(
            10,
            Box::new(FailAfter {
                good: vec![Bytes::from_static(b"abc"), Bytes::from_static(b"de")],
                idx: 0,
            }),
        );
        match stream.collect().await {
            Err(TransferError::Unavailable(why)) => {
                assert!(
                    why.contains("mid-body after 5 B"),
                    "fold reports bytes seen: {why}"
                );
            }
            other => panic!("a terminal mid-stream error must fold to Unavailable, got {other:?}"),
        }
    }
}
