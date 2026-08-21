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

use std::sync::atomic::{AtomicU64, Ordering};

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
}
