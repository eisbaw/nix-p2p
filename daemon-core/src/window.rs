//! The shared TUMBLING-WINDOW accounting primitive: the integer monotonic clock seam, the
//! fail-closed window clamp, and the window-expiry test used by BOTH the responder derivation
//! ledger ([`crate::derive_ledger::PeerDeriveLedger`], TASK-229/297) and the serve-side egress
//! shaper ([`crate::upload_ledger::UploadRateLedger`], TASK-299).
//!
//! Extracting it keeps ONE source of truth for "how a tumbling window reads time and rolls":
//! both ledgers are the same primitive (an integer-millisecond clock + a window that resets
//! WHOLLY at its boundary) differing only in the integer ACCUMULATORS they carry (the derive
//! ledger tracks bytes+dumps per peer plus a global window; the upload shaper tracks a single
//! global octet total). The accumulators stay in each ledger; the clock/clamp/expiry live here.
//!
//! Integers only (owner no-floats rule): time is milliseconds as `u64`, the window is a
//! `Duration` of integer milliseconds, and expiry is a saturating integer comparison — never a
//! float, never a wall-clock read.

use std::time::{Duration, Instant};

/// A monotonic millisecond clock. A seam so a test advances time deterministically (window
/// roll-over is the whole point and must be testable without sleeping).
pub trait MonotonicClock: Send + Sync {
    /// Milliseconds since some fixed, process-local epoch. MONOTONIC and integer: it never goes
    /// backwards and carries no fractional part, so a window delta is an exact integer and no
    /// clock adjustment can widen the gate.
    fn now_millis(&self) -> u64;
}

/// The production clock: integer milliseconds since the clock was constructed.
#[derive(Debug)]
pub struct SystemClock {
    epoch: Instant,
}

impl SystemClock {
    /// A clock whose zero is now.
    pub fn new() -> Self {
        SystemClock {
            epoch: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemClock {
    fn now_millis(&self) -> u64 {
        // `Instant` is monotonic; the elapsed-millis truncation is integer by construction
        // (`as u64` on `u128` millis). Saturating so a pathological very long uptime cannot panic.
        self.epoch.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}

/// The floor a configured accounting window is clamped UP to. A zero (or sub-millisecond) window
/// would make [`window_expired`] fire on EVERY admission — silently disabling all aggregation and
/// collapsing a per-window bound into a per-call one.
///
/// DIRECTION NOTE: clamping a sub-floor window UP is CONSERVATIVE (safe) for both a WORK bound and a
/// RATE bound. For a work bound (the derive ledger) a longer window is the conservative direction for
/// "resets disable aggregation". For a RATE bound the enforced rate is `cap / window`, so raising the
/// window (the DENOMINATOR) LOWERS the enforced rate — i.e. clamping up makes the enforced rate
/// TIGHTER than the declared sub-floor intent, never looser. Both current callers' frozen windows are
/// at/above this floor (derive 60 s, upload 1 s) so the clamp never fires in production; it is only a
/// degenerate-input fail-safe. It is reflected in each ledger's reported window, so the surfaced value
/// is always the one actually enforced (never a value that looks tighter than reality).
pub const MIN_WINDOW_MS: u64 = 1000;

/// Clamp a configured window UP to [`MIN_WINDOW_MS`] (fail-closed against a degenerate window that
/// would reset aggregation on every call). Clamping UP is conservative for both a work and a rate
/// bound — see [`MIN_WINDOW_MS`] for the direction note (a larger window lowers the enforced rate).
pub fn clamp_window(window: Duration) -> Duration {
    let ms = window.as_millis().min(u64::MAX as u128) as u64;
    Duration::from_millis(ms.max(MIN_WINDOW_MS))
}

/// Whether a window opened at `start_millis` has aged past `window_millis` as of `now` (integer
/// milliseconds). Saturating subtraction so a monotonic clock can never underflow. When `true`
/// the caller resets its window (start := now, accumulators := 0) — the TUMBLING reset.
///
/// TUMBLING (not sliding), stated once for both callers: the caller resets the WHOLE window at the
/// boundary, so the effective bound is `cap` per window in steady state with a transient at the
/// boundary (see each ledger's doc for its exact worst-case). A true sliding window is a
/// deliberate non-goal of this primitive.
pub fn window_expired(start_millis: u64, now: u64, window_millis: u64) -> bool {
    now.saturating_sub(start_millis) >= window_millis
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_raises_a_sub_floor_window_and_leaves_a_large_one() {
        assert_eq!(
            clamp_window(Duration::ZERO),
            Duration::from_millis(MIN_WINDOW_MS)
        );
        assert_eq!(
            clamp_window(Duration::from_millis(1)),
            Duration::from_millis(MIN_WINDOW_MS)
        );
        assert_eq!(
            clamp_window(Duration::from_secs(60)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn expiry_is_saturating_and_boundary_inclusive() {
        // Exactly at the boundary counts as expired (>=), so a window of length W tumbles at W.
        assert!(window_expired(0, 1000, 1000));
        assert!(!window_expired(0, 999, 1000));
        // A `now` before `start` (should not happen with a monotonic clock) saturates to 0, not
        // an underflow, and reads as not-yet-expired.
        assert!(!window_expired(5000, 100, 1000));
    }
}
