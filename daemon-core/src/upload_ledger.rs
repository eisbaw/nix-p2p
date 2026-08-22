//! The SERVE-side EGRESS (upload-rate) SHAPER (TASK-299): the stateful enforcer of
//! [`peer_fabric::UploadBudget`], the compressed-wire analog of TASK-72's serve gate and
//! TASK-229's derive ledger.
//!
//! ## What it defends
//!
//! The shipped libp2p `/nar` serve path writes NAR bytes to a requesting peer with NO
//! rate/volume bound: [`peer_fabric::ServeBudget`] caps the UNCOMPRESSED-NAR size of ONE
//! serve and the aggregate IN-FLIGHT bytes, but nothing bounds how many COMPRESSED-WIRE
//! OCTETS this node emits over TIME. A node serving popular content can thus be driven to
//! saturate its uplink by a stream of serve requests. This ledger is that bound: a
//! node-wide, integer, tumbling-window ceiling on compressed-wire octets emitted per window.
//!
//! ## Model: node-wide single window (NOT per-peer)
//!
//! Unlike [`crate::derive_ledger::PeerDeriveLedger`] (whose per-peer split defends a shared
//! CPU/IO resource a Sybil flood could monopolise), upload-rate bounds THIS node's finite
//! uplink — one aggregate resource with no per-peer subdivision. So there is ONE global
//! window: every admitted serve's real egress advances it, and once it is spent the node
//! DECLINES further serves until the window rolls. There is no Sybil bypass to close —
//! minting PeerIds cannot widen a fixed uplink budget.
//!
//! ## Enforcement: charge ACTUAL octets, decline the NEXT serve
//!
//! We do NOT charge an estimate up front: the compressed-wire size of a serve is not known
//! before it is written (codec negotiation + compression happen during the write), and
//! charging the UNCOMPRESSED declared size against a COMPRESSED-wire budget is exactly the
//! NarSize-vs-FileSize unit trap. Instead:
//!
//!   * [`admit_upload`](UploadRateLedger::admit_upload) is consulted at serve ADMISSION
//!     (`fabric_libp2p::ServeGate::admit_plan`): it rolls an expired window and ADMITS iff the
//!     window's emitted octets are still below the cap. Once a window is spent, it DECLINES.
//!   * [`charge_wire_octets`](UploadRateLedger::charge_wire_octets) is called as the serve
//!     writes, charging the ACTUAL octets handed to the transport (the correct unit;
//!     partially-written aborted serves are charged for what they emitted).
//!
//! WHAT IS AND ISN'T BOUNDED (stated honestly — the amplifying egress only). This bounds the
//! NAR-BODY serve egress — the large, amplifying output a peer induces with a one-request probe. It
//! does NOT bound the tiny protocol-CONTROL responses: once the window is spent, a further request
//! for known content is DECLINED, but that `Declined(Busy)` frame (a few bytes) is still written.
//! Those frames are each GATED BY AN INBOUND REQUEST (the peer must send ~33 request bytes to elicit
//! a ~2-byte decline), so they are NON-AMPLIFYING and are deliberately outside the shaped envelope;
//! the ledger records them (the writer charges every octet) but recording a spent window enforces
//! nothing on them. The security claim is therefore "bounded NAR-BODY egress per window", never "all
//! egress bounded".
//!
//! THE TRANSIENT BOUND (unit-honest). [`admit_upload`](UploadRateLedger::admit_upload) is
//! LEVEL-TRIGGERED and NON-RESERVING — it returns `used < cap` and reserves nothing. So at an instant
//! when a window reads empty, EVERY concurrently-arriving serve passes admission and then streams and
//! charges. The window can thus overshoot `cap` by the compressed-WIRE volume of the serves admitted
//! in that empty-window instant. That volume is BOUNDED (concurrency is not unlimited): the concurrent
//! in-flight UNCOMPRESSED-NAR total is capped by
//! [`peer_fabric::ServeBudget::max_inflight_bytes_uncompressed_nar`] (1 GiB default), and each serve's
//! compressed wire is roughly its NarSize plus Bao proof + a 14-byte header/marker. This is a COARSE
//! CROSS-UNIT magnitude bound (compressed-wire octets vs the uncompressed-NAR inflight cap plus proof
//! overhead) — NOT a clean same-unit `cap + max_inflight` inequality, and NOT `cap + one NAR`. Because
//! the window is TUMBLING and non-reserving, this overshoot volume (call it `T_wire`) can recur EACH
//! window, so the enforced long-run rate is AT MOST `(cap + T_wire) / window` — a hair above the
//! nominal `cap / window`, never below it (units: a byte VOLUME `cap + T_wire` over a window). It is
//! a coarse egress rate-limit that bounds SUSTAINED NAR-body egress (a burst drains the window, then
//! body serves decline until it rolls); a true reserving/sliding bound is a deliberate non-goal. It is
//! a SAFETY/amplification cap, not a fairness mechanism: a single greedy peer can spend the whole node
//! window and starve others — per-peer upload fairness is out of scope here.
//!
//! ## Data design (integers only, no floats — owner rule)
//!
//! State is one [`Window`] `{start_millis, bytes}` — all integers. Time is read through the
//! shared [`crate::derive_ledger::MonotonicClock`] seam (a test drives the roll-over
//! deterministically; production uses [`crate::derive_ledger::SystemClock`]). Never
//! wall-clock — only a monotonic delta, so a clock step cannot open the gate. Every
//! accumulation is [`u64::saturating_add`]: a saturated total is at/over `u64::MAX`, which is
//! `>= cap`, so the shaper fail-CLOSES (declines) rather than wrapping to a small total.

use std::sync::Mutex;

use peer_fabric::UploadBudget;

use crate::window::{MonotonicClock, SystemClock, clamp_window, window_expired};

/// One TUMBLING accounting window: the compressed-wire octets emitted since `start_millis`
/// (resets wholly at the boundary — see [`crate::window`] for the shared clock/clamp/expiry
/// primitive this composes with its own integer octet accumulator). Integers only.
#[derive(Debug, Clone, Copy)]
struct Window {
    /// The millisecond timestamp this window opened.
    start_millis: u64,
    /// Compressed-wire octets emitted in this window so far.
    bytes: u64,
}

impl Window {
    fn opened_at(now: u64) -> Self {
        Window {
            start_millis: now,
            bytes: 0,
        }
    }

    /// Reset to an empty window opened at `now` if the current one has aged past `window_millis`.
    fn roll_if_expired(&mut self, now: u64, window_millis: u64) {
        if window_expired(self.start_millis, now, window_millis) {
            *self = Window::opened_at(now);
        }
    }
}

/// The stateful node-wide egress shaper (TASK-299). Constructed once per serving node from an
/// [`UploadBudget`] (the ACTIVE PROFILE's frozen `upload_rate_bytes_compressed_wire_per_window`
/// + `upload_rate_window_ns`), then SHARED (behind its own interior mutex) across every serve.
///
/// [`unlimited`](Self::unlimited) builds a shaper that admits everything and charges nothing —
/// for a gate the composition root did not wire a budget onto (tests, non-serving paths).
pub struct UploadRateLedger {
    budget: UploadBudget,
    /// `false` for the unlimited shaper (admits everything, charges nothing).
    enforced: bool,
    clock: Box<dyn MonotonicClock>,
    state: Mutex<Option<Window>>,
}

impl std::fmt::Debug for UploadRateLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadRateLedger")
            .field("budget", &self.budget)
            .field("enforced", &self.enforced)
            .finish_non_exhaustive()
    }
}

impl UploadRateLedger {
    /// An ENFORCING shaper over `budget`, reading time from the production [`SystemClock`].
    pub fn new(budget: UploadBudget) -> Self {
        Self::with_clock(budget, Box::new(SystemClock::new()))
    }

    /// An enforcing shaper over `budget` reading time from `clock` (tests inject a manual clock
    /// to drive window roll-over deterministically).
    ///
    /// FAIL-CLOSED window clamp: a zero or sub-[`MIN_WINDOW_MS`] window is clamped UP to the
    /// floor (a sub-millisecond window rolls on every admission and disables the rate bound).
    /// The clamp is reflected in the stored [`budget`](Self::budget), so the reported window is
    /// the one actually enforced — never a value that looks tighter than it is.
    pub fn with_clock(mut budget: UploadBudget, clock: Box<dyn MonotonicClock>) -> Self {
        budget.window = clamp_window(budget.window);
        UploadRateLedger {
            budget,
            enforced: true,
            clock,
            state: Mutex::new(None),
        }
    }

    /// A shaper that admits everything and charges nothing: a gate with no wired budget.
    pub fn unlimited() -> Self {
        UploadRateLedger {
            budget: UploadBudget::default(),
            enforced: false,
            clock: Box::new(SystemClock::new()),
            state: Mutex::new(None),
        }
    }

    /// The integer policy numbers this shaper enforces (window reflects the fail-closed clamp).
    pub fn budget(&self) -> UploadBudget {
        self.budget
    }

    fn window_millis(&self) -> u64 {
        self.budget.window.as_millis().min(u64::MAX as u128) as u64
    }

    /// Ask permission to begin one serve's egress. Rolls an expired window, then ADMITS
    /// (`true`) iff the window's emitted octets are still BELOW the cap; once the window is
    /// spent (emitted `>=` cap) it DECLINES (`false`) until the window rolls. A non-enforcing
    /// ([`unlimited`](Self::unlimited)) shaper always admits.
    ///
    /// This is the coarse gate: a serve admitted while the window still has budget may itself
    /// push the window over (bounded — see the module docs), but a serve begun AFTER the window
    /// is spent is declined, which is what bounds sustained egress.
    pub fn admit_upload(&self) -> bool {
        if !self.enforced {
            return true;
        }
        let now = self.clock.now_millis();
        let window_millis = self.window_millis();
        let mut state = self.state.lock().expect("upload-ledger mutex");
        let window = state.get_or_insert_with(|| Window::opened_at(now));
        window.roll_if_expired(now, window_millis);
        window.bytes < self.budget.max_bytes_per_window
    }

    /// Charge `octets` of ACTUAL compressed-wire egress to the current window (rolling an
    /// expired one first). `saturating_add` fail-CLOSES: a total driven to `u64::MAX` is over
    /// any real cap, so the next [`admit_upload`](Self::admit_upload) declines rather than
    /// wrapping to a small total. A non-enforcing shaper charges nothing.
    pub fn charge_wire_octets(&self, octets: u64) {
        if !self.enforced {
            return;
        }
        let now = self.clock.now_millis();
        let window_millis = self.window_millis();
        let mut state = self.state.lock().expect("upload-ledger mutex");
        let window = state.get_or_insert_with(|| Window::opened_at(now));
        window.roll_if_expired(now, window_millis);
        window.bytes = window.bytes.saturating_add(octets);
    }

    /// The current window's emitted octets for the operator surface (used/CAP), rolling an
    /// expired window to zero first so a stale figure is never reported. An AGGREGATE integer
    /// with no per-peer identifier — safe to expose without a peer-behaviour channel.
    pub fn window_bytes_used(&self) -> u64 {
        if !self.enforced {
            return 0;
        }
        let now = self.clock.now_millis();
        let window_millis = self.window_millis();
        let mut state = self.state.lock().expect("upload-ledger mutex");
        let window = state.get_or_insert_with(|| Window::opened_at(now));
        window.roll_if_expired(now, window_millis);
        window.bytes
    }

    /// The window octet ceiling (the reported CAP).
    pub fn window_bytes_cap(&self) -> u64 {
        self.budget.max_bytes_per_window
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::MIN_WINDOW_MS;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// A manually-advanced clock so window roll-over is deterministic.
    #[derive(Clone, Default)]
    struct ManualClock(Arc<AtomicU64>);

    impl ManualClock {
        fn advance(&self, ms: u64) {
            self.0.fetch_add(ms, Ordering::SeqCst);
        }
    }

    impl MonotonicClock for ManualClock {
        fn now_millis(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn budget(cap: u64) -> UploadBudget {
        UploadBudget {
            max_bytes_per_window: cap,
            window: Duration::from_secs(60),
        }
    }

    #[test]
    fn admits_until_the_window_is_spent_then_declines() {
        let clock = ManualClock::default();
        let ledger = UploadRateLedger::with_clock(budget(1000), Box::new(clock.clone()));
        // Empty window: admitted.
        assert!(ledger.admit_upload());
        // A serve emits 1500 octets (an overshoot beyond the 1000 cap is possible for the
        // in-flight serve; that is the documented bounded boundary overshoot).
        ledger.charge_wire_octets(1500);
        // The window is now spent (1500 >= 1000): the NEXT serve is declined.
        assert!(!ledger.admit_upload());
        assert_eq!(ledger.window_bytes_used(), 1500);
        assert_eq!(ledger.window_bytes_cap(), 1000);
    }

    #[test]
    fn partial_charge_below_cap_still_admits() {
        let clock = ManualClock::default();
        let ledger = UploadRateLedger::with_clock(budget(1000), Box::new(clock.clone()));
        assert!(ledger.admit_upload());
        ledger.charge_wire_octets(400);
        // 400 < 1000: still admits.
        assert!(ledger.admit_upload());
        ledger.charge_wire_octets(600);
        // 1000 >= 1000: spent, declines.
        assert!(!ledger.admit_upload());
    }

    #[test]
    fn window_rolls_over_and_resets_usage() {
        let clock = ManualClock::default();
        let ledger = UploadRateLedger::with_clock(budget(1000), Box::new(clock.clone()));
        ledger.charge_wire_octets(1000);
        assert!(!ledger.admit_upload(), "spent within the window");
        // Advance past the 60s window: usage resets, admits again.
        clock.advance(60_000);
        assert!(ledger.admit_upload());
        assert_eq!(ledger.window_bytes_used(), 0);
    }

    #[test]
    fn charge_saturates_fail_closed_never_wraps() {
        let clock = ManualClock::default();
        let ledger = UploadRateLedger::with_clock(budget(1000), Box::new(clock.clone()));
        ledger.charge_wire_octets(u64::MAX);
        // A second charge would overflow a wrapping add back to a small total (wrongly
        // admitting); saturating_add keeps it at u64::MAX, which is >= cap -> declines.
        ledger.charge_wire_octets(100);
        assert_eq!(ledger.window_bytes_used(), u64::MAX, "no wrap");
        assert!(!ledger.admit_upload());
    }

    #[test]
    fn zero_window_is_clamped_not_silently_disabling_the_bound() {
        let clock = ManualClock::default();
        let ledger = UploadRateLedger::with_clock(
            UploadBudget {
                max_bytes_per_window: 1000,
                window: Duration::ZERO, // degenerate: would reset every admission
            },
            Box::new(clock.clone()),
        );
        assert_eq!(
            ledger.budget().window,
            Duration::from_millis(MIN_WINDOW_MS),
            "a zero window must be clamped UP to the floor, not stored as 0"
        );
        ledger.charge_wire_octets(1000);
        // Advance within the clamped window: the bound MUST still hold (no per-call reset).
        clock.advance(10);
        assert!(
            !ledger.admit_upload(),
            "a clamped window must still aggregate across calls, not reset each time"
        );
        clock.advance(MIN_WINDOW_MS);
        assert!(
            ledger.admit_upload(),
            "only after the clamped window elapses"
        );
    }

    #[test]
    fn unlimited_admits_everything_and_charges_nothing() {
        let ledger = UploadRateLedger::unlimited();
        for _ in 0..10_000 {
            assert!(ledger.admit_upload());
            ledger.charge_wire_octets(u64::MAX / 2);
        }
        assert_eq!(ledger.window_bytes_used(), 0);
    }
}
