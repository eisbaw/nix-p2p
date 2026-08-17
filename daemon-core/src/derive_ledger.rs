//! The RESPONDER DERIVATION LEDGER (TASK-229): the stateful enforcer of
//! [`peer_fabric::DeriveBudget`], the hashing analog of TASK-72's serve gate.
//!
//! ## What it defends
//!
//! Answering a peer's hold-query for a COLD path costs this node one
//! `nix-store --dump` + a whole-NAR BLAKE3 (see [`crate::availability`]). TASK-104
//! added a per-MESSAGE dump-COUNT cap (`MAX_BATCH_DERIVE_WORK`), but that is not a DoS
//! defence: a hostile peer picks the message boundaries (many small batches, or a
//! stream of single-key probes), so the real bound must be
//!
//!   1. in BYTES hashed, not dump COUNT (16 multi-GB dumps is still unbounded I/O), and
//!   2. per authenticated PEER AGGREGATE across messages, not per message, plus a
//!      GLOBAL ceiling as the Sybil floor (per-peer alone is bypassable by minting
//!      PeerIds).
//!
//! This ledger is that bound. It is consulted by [`crate::availability::AvailabilityIndex`]'s
//! RESPONDER answer path (`answer_batch_for_peer` / `answer_for_peer`) BEFORE any cold
//! dump, seeded by the path's NarSize queried WITHOUT dumping ([`crate::availability::NarDumper::nar_size`]).
//! An over-budget probe is REFUSED (answered `Absent`, the safe direction TASK-104
//! already takes - the asker falls back upstream, never a wrong byte), with NO dump.
//!
//! ## Data design (integers only, no floats - owner rule)
//!
//! State is a per-peer window plus one global window. A [`Window`] is `{start_millis,
//! bytes, dumps}` - all integers. Admission (a) rolls a window that has aged past
//! [`peer_fabric::DeriveBudget::window`] back to zero, (b) checks the GLOBAL byte
//! ceiling first (the backstop), (c) checks the per-peer byte AND dump ceilings, and
//! (d) only on success COMMITS the charge to both windows. A refusal commits nothing,
//! so a refused probe costs no budget (and no dump).
//!
//! Time is read through a [`MonotonicClock`] seam so a test drives the window
//! deterministically; production uses [`SystemClock`] (an `Instant` rendered as
//! integer milliseconds since ledger creation). Never wall-clock - only a monotonic
//! delta, so a clock step cannot open the gate.
//!
//! ## What it is NOT
//!
//! It is not a full Sybil defence (TASK-205 owns per-subnet/rate-of-new-identity
//! accounting); the global ceiling is only the responder's own last line. It does not
//! bound WARM answers - a key already derived costs no dump, so it draws no budget,
//! exactly as the serve gate only charges bytes actually served.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use peer_fabric::DeriveBudget;

use crate::transport::NodeId;

/// Clamp a configured window UP to [`MIN_WINDOW_MS`] (fail-closed): a zero or
/// sub-millisecond window would reset the accounting on every admission and silently
/// disable aggregation.
fn clamp_window(window: Duration) -> Duration {
    let ms = window.as_millis().min(u64::MAX as u128) as u64;
    Duration::from_millis(ms.max(MIN_WINDOW_MS))
}

/// A monotonic millisecond clock. A seam so a test advances time deterministically
/// (the window roll-over is the whole point and must be testable without sleeping).
pub trait MonotonicClock: Send + Sync {
    /// Milliseconds since some fixed, process-local epoch. MONOTONIC and integer: it
    /// never goes backwards and carries no fractional part, so a window delta is an
    /// exact integer and no clock adjustment can widen the gate.
    fn now_millis(&self) -> u64;
}

/// The production clock: integer milliseconds since the ledger was constructed.
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
        // `Instant` is monotonic; the elapsed-millis truncation is integer by
        // construction (`as u64` on `u128` millis). Saturating so a pathological very
        // long uptime cannot panic.
        self.epoch.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}

/// One TUMBLING accounting window: the bytes hashed and dumps taken since
/// `start_millis` (resets wholly at the boundary — up to 2x cap across it). Integers only.
#[derive(Debug, Clone, Copy)]
struct Window {
    /// The millisecond timestamp this window opened.
    start_millis: u64,
    /// NarSize bytes charged in this window so far.
    bytes: u64,
    /// Fresh dumps charged in this window so far.
    dumps: u32,
}

/// The floor a [`DeriveBudget::window`] is clamped UP to at ledger construction. A
/// zero (or sub-millisecond) window would make [`Window::roll_if_expired`] reset on
/// EVERY admission - silently disabling all aggregation and turning the per-peer bound
/// into a per-message one. Clamping fail-CLOSED (never below this floor) keeps the
/// aggregation the type promises; see [`PeerDeriveLedger::with_clock`].
pub const MIN_WINDOW_MS: u64 = 1000;

impl Window {
    fn opened_at(now: u64) -> Self {
        Window {
            start_millis: now,
            bytes: 0,
            dumps: 0,
        }
    }

    /// Reset to an empty window opened at `now` if the current one has aged past
    /// `window_millis`. Uses saturating subtraction so a monotonic clock can never
    /// underflow.
    ///
    /// TUMBLING (not sliding), stated honestly: this resets the WHOLE window to zero at
    /// the boundary, so the EFFECTIVE bound a peer can spend across a boundary is up to
    /// 2x the per-window cap (full cap just before the reset, full cap just after). The
    /// per-window ceilings are therefore a rate bound of `cap` per `window` in steady
    /// state with a `2*cap` transient at each boundary - NOT a hard `cap` over every
    /// sliding `window`. A true sliding window (bounding any window-length interval to
    /// `cap`) is a follow-up (TASK-243); the tumbling bound is sufficient as a
    /// coarse DoS rate-limit and is documented here so no caller assumes the tighter one.
    fn roll_if_expired(&mut self, now: u64, window_millis: u64) {
        if now.saturating_sub(self.start_millis) >= window_millis {
            *self = Window::opened_at(now);
        }
    }
}

/// The verdict of [`PeerDeriveLedger::try_admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveAdmission {
    /// The dump is admitted; the charge has been COMMITTED to both the per-peer and
    /// the global window.
    Admitted,
    /// Refused because this peer's per-peer byte OR dump ceiling would be exceeded.
    /// Nothing was charged.
    RefusedPerPeer,
    /// Refused because the GLOBAL byte ceiling (the Sybil floor) would be exceeded.
    /// Nothing was charged.
    RefusedGlobal,
}

impl DeriveAdmission {
    /// Whether the dump may proceed.
    pub fn is_admitted(self) -> bool {
        matches!(self, DeriveAdmission::Admitted)
    }
}

/// Mutable state behind the ledger mutex: the global window plus one window per peer.
#[derive(Debug, Default)]
struct LedgerState {
    global: Option<Window>,
    per_peer: HashMap<NodeId, Window>,
}

/// The stateful per-peer + global derivation enforcer (TASK-229). Constructed once per
/// responder from a [`DeriveBudget`] (its integer policy numbers, sourced from the
/// TASK-120 `ResourceCaps`), then SHARED (behind its own interior mutex) across every
/// hold-query answer, so a peer's usage accrues ACROSS the messages it sends.
///
/// [`unlimited`](Self::unlimited) builds a ledger that admits everything - the LOCAL
/// self-probe path ([`crate::availability::AvailabilityIndex::hold`] used by
/// `claim`/`publish`/post-fetch learning) is node-initiated, not peer-driven, and must
/// always answer truthfully, so it is never bounded.
pub struct PeerDeriveLedger {
    budget: DeriveBudget,
    /// `false` for the local/self-probe ledger (admits everything, charges nothing).
    enforced: bool,
    clock: Box<dyn MonotonicClock>,
    state: Mutex<LedgerState>,
}

impl std::fmt::Debug for PeerDeriveLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerDeriveLedger")
            .field("budget", &self.budget)
            .field("enforced", &self.enforced)
            .finish_non_exhaustive()
    }
}

impl PeerDeriveLedger {
    /// An ENFORCING ledger over `budget`, reading time from the production
    /// [`SystemClock`].
    pub fn new(budget: DeriveBudget) -> Self {
        Self::with_clock(budget, Box::new(SystemClock::new()))
    }

    /// An enforcing ledger over `budget` reading time from `clock` (tests inject a
    /// manual clock to drive window roll-over deterministically).
    ///
    /// FAIL-CLOSED window clamp: a zero or sub-[`MIN_WINDOW_MS`] window is clamped UP to
    /// the floor, because a sub-millisecond window rolls on every admission and silently
    /// disables aggregation (the per-peer bound would collapse to per-message). The
    /// clamp is reflected in the stored [`budget`](Self::budget), so the reported window
    /// is the one actually enforced - never a value that looks tighter than it is.
    pub fn with_clock(mut budget: DeriveBudget, clock: Box<dyn MonotonicClock>) -> Self {
        budget.window = clamp_window(budget.window);
        PeerDeriveLedger {
            budget,
            enforced: true,
            clock,
            state: Mutex::new(LedgerState::default()),
        }
    }

    /// A ledger that admits everything and charges nothing: the LOCAL self-probe path,
    /// which is never peer-attributed and must always answer truthfully.
    pub fn unlimited() -> Self {
        PeerDeriveLedger {
            budget: DeriveBudget::default(),
            enforced: false,
            clock: Box::new(SystemClock::new()),
            state: Mutex::new(LedgerState::default()),
        }
    }

    /// The integer policy numbers this ledger enforces.
    pub fn budget(&self) -> DeriveBudget {
        self.budget
    }

    /// Ask permission to spend one fresh dump of `nar_size` UNCOMPRESSED NAR bytes on
    /// behalf of the authenticated `peer`. On [`DeriveAdmission::Admitted`] the charge
    /// is COMMITTED to both the per-peer and global windows; a refusal charges nothing.
    ///
    /// Order matters and is deliberate: the GLOBAL ceiling is checked (and would refuse)
    /// FIRST, because it is the backstop that must hold even when a single peer is still
    /// under its own cap; then the per-peer byte and dump ceilings. A single call to a
    /// non-enforcing ([`unlimited`](Self::unlimited)) ledger is always `Admitted`.
    ///
    /// Overflow is fail-CLOSED: an accumulation that would overflow the `u64` byte or
    /// `u32` dump accumulator is treated as OVER-cap and REFUSED (via `checked_add`),
    /// never wrapped and never saturated-equal-to a `MAX` cap (which a `>` test would
    /// then wrongly admit). A cap set to `u64::MAX`/`u32::MAX` therefore still refuses
    /// mathematically-over-cap work rather than admitting it.
    pub fn try_admit(&self, peer: &NodeId, nar_size: u64) -> DeriveAdmission {
        if !self.enforced {
            return DeriveAdmission::Admitted;
        }
        let now = self.clock.now_millis();
        let window_millis = self.budget.window.as_millis().min(u64::MAX as u128) as u64;

        let mut state = self.state.lock().expect("derive-ledger mutex");

        // Roll the global window first, then evaluate the global ceiling. A refusal
        // here is the Sybil floor biting: return WITHOUT touching the per-peer window,
        // so nothing is charged. An accumulator overflow is over-cap (fail-closed).
        let global = state.global.get_or_insert_with(|| Window::opened_at(now));
        global.roll_if_expired(now, window_millis);
        // `global_after` is a plain integer copy, so the per-peer borrow below cannot
        // disturb it; it is committed only if the per-peer check ALSO passes (a two-phase
        // check-then-commit; nothing is charged on a per-peer refusal).
        let global_after = match global.bytes.checked_add(nar_size) {
            Some(sum) if sum <= self.budget.max_bytes_global_uncompressed_nar => sum,
            _ => return DeriveAdmission::RefusedGlobal,
        };

        let peer_window = state
            .per_peer
            .entry(*peer)
            .or_insert_with(|| Window::opened_at(now));
        peer_window.roll_if_expired(now, window_millis);
        // Both per-peer ceilings, overflow-as-over-cap. `checked_add` returning `None`
        // (or a sum over the cap) refuses; nothing is charged on a refusal.
        let peer_bytes_after = match peer_window.bytes.checked_add(nar_size) {
            Some(sum) if sum <= self.budget.max_bytes_per_peer_uncompressed_nar => sum,
            _ => return DeriveAdmission::RefusedPerPeer,
        };
        let peer_dumps_after = match peer_window.dumps.checked_add(1) {
            Some(sum) if sum <= self.budget.max_dumps_per_peer => sum,
            _ => return DeriveAdmission::RefusedPerPeer,
        };

        // COMMIT: both ceilings pass. Charge the peer window and the global window.
        peer_window.bytes = peer_bytes_after;
        peer_window.dumps = peer_dumps_after;
        let global = state.global.as_mut().expect("global window present");
        // The global window could not have rolled since `global_after` was computed
        // (single lock held throughout), so committing it is exact.
        global.bytes = global_after;

        DeriveAdmission::Admitted
    }

    /// The GLOBAL window's `(bytes_used, cap)` for the operator surface (used/CAP),
    /// resetting an expired window to zero first so a stale figure is never reported. An
    /// AGGREGATE integer with no per-peer identifier - safe to expose without leaking a
    /// peer-behaviour channel (mirrors how `announce_budget` reports a single figure).
    pub fn global_bytes_used(&self) -> u64 {
        if !self.enforced {
            return 0;
        }
        let now = self.clock.now_millis();
        let window_millis = self.budget.window.as_millis().min(u64::MAX as u128) as u64;
        let mut state = self.state.lock().expect("derive-ledger mutex");
        let global = state.global.get_or_insert_with(|| Window::opened_at(now));
        global.roll_if_expired(now, window_millis);
        global.bytes
    }

    /// The global byte ceiling (the reported CAP).
    pub fn global_bytes_cap(&self) -> u64 {
        self.budget.max_bytes_global_uncompressed_nar
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// A manually-advanced clock so window roll-over is deterministic.
    #[derive(Clone, Default)]
    pub struct ManualClock(Arc<AtomicU64>);

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

    fn peer(tag: u8) -> NodeId {
        NodeId::from_bytes([tag; 32])
    }

    fn budget(per_peer_bytes: u64, per_peer_dumps: u32, global_bytes: u64) -> DeriveBudget {
        DeriveBudget {
            max_bytes_per_peer_uncompressed_nar: per_peer_bytes,
            max_dumps_per_peer: per_peer_dumps,
            max_bytes_global_uncompressed_nar: global_bytes,
            window: Duration::from_secs(60),
        }
    }

    #[test]
    fn per_peer_byte_ceiling_refuses_and_charges_nothing() {
        let clock = ManualClock::default();
        let ledger =
            PeerDeriveLedger::with_clock(budget(100, 1000, 1_000_000), Box::new(clock.clone()));
        let p = peer(1);
        assert_eq!(ledger.try_admit(&p, 60), DeriveAdmission::Admitted);
        // 60 + 60 = 120 > 100: refused, nothing charged.
        assert_eq!(ledger.try_admit(&p, 60), DeriveAdmission::RefusedPerPeer);
        // A smaller probe that fits the remaining 40 is still admitted (the refusal
        // charged nothing, so 40 bytes remain).
        assert_eq!(ledger.try_admit(&p, 40), DeriveAdmission::Admitted);
        assert_eq!(ledger.try_admit(&p, 1), DeriveAdmission::RefusedPerPeer);
    }

    #[test]
    fn per_peer_dump_count_ceiling_bounds_many_small_nars() {
        let ledger = PeerDeriveLedger::with_clock(
            budget(1_000_000, 3, 1_000_000),
            Box::new(ManualClock::default()),
        );
        let p = peer(2);
        for _ in 0..3 {
            assert_eq!(ledger.try_admit(&p, 1), DeriveAdmission::Admitted);
        }
        // 4th small dump exceeds the count cap even though bytes are tiny.
        assert_eq!(ledger.try_admit(&p, 1), DeriveAdmission::RefusedPerPeer);
    }

    #[test]
    fn per_peer_windows_are_independent_across_peers() {
        let ledger = PeerDeriveLedger::with_clock(
            budget(100, 1000, 1_000_000),
            Box::new(ManualClock::default()),
        );
        // Peer 1 exhausts its byte window; peer 2 is unaffected.
        assert_eq!(ledger.try_admit(&peer(1), 100), DeriveAdmission::Admitted);
        assert_eq!(
            ledger.try_admit(&peer(1), 1),
            DeriveAdmission::RefusedPerPeer
        );
        assert_eq!(ledger.try_admit(&peer(2), 100), DeriveAdmission::Admitted);
    }

    #[test]
    fn window_rolls_over_and_resets_usage() {
        let clock = ManualClock::default();
        let ledger =
            PeerDeriveLedger::with_clock(budget(100, 1000, 1_000_000), Box::new(clock.clone()));
        let p = peer(3);
        assert_eq!(ledger.try_admit(&p, 100), DeriveAdmission::Admitted);
        assert_eq!(ledger.try_admit(&p, 1), DeriveAdmission::RefusedPerPeer);
        // Advance past the 60s window: usage resets.
        clock.advance(60_000);
        assert_eq!(ledger.try_admit(&p, 100), DeriveAdmission::Admitted);
    }

    #[test]
    fn global_ceiling_bites_across_distinct_peers() {
        // Per-peer generous, global tight: many distinct peers still bounded.
        let ledger = PeerDeriveLedger::with_clock(
            budget(1_000_000, 1000, 250),
            Box::new(ManualClock::default()),
        );
        assert_eq!(ledger.try_admit(&peer(1), 100), DeriveAdmission::Admitted);
        assert_eq!(ledger.try_admit(&peer(2), 100), DeriveAdmission::Admitted);
        // Global is at 200; a third distinct peer's 100 would make 300 > 250.
        assert_eq!(
            ledger.try_admit(&peer(3), 100),
            DeriveAdmission::RefusedGlobal
        );
        // A smaller probe that fits the remaining 50 global bytes is admitted.
        assert_eq!(ledger.try_admit(&peer(4), 50), DeriveAdmission::Admitted);
    }

    #[test]
    fn global_refusal_charges_no_per_peer_budget() {
        let ledger = PeerDeriveLedger::with_clock(
            budget(1_000_000, 1000, 150),
            Box::new(ManualClock::default()),
        );
        assert_eq!(ledger.try_admit(&peer(1), 100), DeriveAdmission::Admitted);
        // Peer 2 refused by GLOBAL (100+100 > 150); its per-peer window must be untouched.
        assert_eq!(
            ledger.try_admit(&peer(2), 100),
            DeriveAdmission::RefusedGlobal
        );
        // After the global frees up (window roll), peer 2 can spend its full per-peer cap
        // with no residual charge from the refused attempt.
        assert_eq!(ledger.global_bytes_used(), 100);
    }

    #[test]
    fn unlimited_ledger_admits_everything() {
        let ledger = PeerDeriveLedger::unlimited();
        for _ in 0..10_000 {
            assert_eq!(
                ledger.try_admit(&peer(9), u64::MAX / 2),
                DeriveAdmission::Admitted
            );
        }
        assert_eq!(ledger.global_bytes_used(), 0);
    }

    /// codex fix B (MAX-cap boundary, fail-closed): with a `u64::MAX` global cap, work
    /// that OVERFLOWS the accumulator is REFUSED, not admitted. MUTATION: revert the
    /// `checked_add`/`<=` admission to `saturating_add` + `>` and the second probe
    /// saturates to `u64::MAX`, which is NOT `> u64::MAX`, so it is wrongly admitted -
    /// reddening the `RefusedGlobal` assertion below.
    #[test]
    fn overflow_of_the_accumulator_is_refused_not_admitted_at_max_cap() {
        // GLOBAL cap at the u64 ceiling: only an accumulator OVERFLOW can refuse - and it
        // must, or a MAX cap would silently mean "unlimited".
        let ledger = PeerDeriveLedger::with_clock(
            budget(u64::MAX, 1000, u64::MAX),
            Box::new(ManualClock::default()),
        );
        // First near-MAX probe fits exactly under the MAX cap (no overflow).
        assert_eq!(
            ledger.try_admit(&peer(1), u64::MAX - 1),
            DeriveAdmission::Admitted
        );
        // The next probe would overflow the u64 accumulator: fail-CLOSED -> refused,
        // never wrapped, never saturated-equal-to the MAX cap and then admitted.
        assert_eq!(
            ledger.try_admit(&peer(2), 100),
            DeriveAdmission::RefusedGlobal
        );
        assert_eq!(
            ledger.global_bytes_used(),
            u64::MAX - 1,
            "no wrap on refusal"
        );
    }

    /// codex fix A (window fail-closed): a zero (or sub-`MIN_WINDOW_MS`) window is clamped
    /// UP at construction, so aggregation still happens - it does NOT silently reset on
    /// every admission. MUTATION: drop the `clamp_window` call in `with_clock` and, with a
    /// clock that advances 1 ms between calls, the window (0 ms) rolls on the SECOND
    /// admission, so the per-peer cap never bites and the second probe is (wrongly)
    /// Admitted - reddening the `RefusedPerPeer` assertion.
    #[test]
    fn zero_window_is_clamped_not_silently_disabling_aggregation() {
        let clock = ManualClock::default();
        let ledger = PeerDeriveLedger::with_clock(
            DeriveBudget {
                max_bytes_per_peer_uncompressed_nar: 100,
                max_dumps_per_peer: 1000,
                max_bytes_global_uncompressed_nar: 1_000_000,
                window: Duration::ZERO, // hostile/degenerate: would disable aggregation
            },
            Box::new(clock.clone()),
        );
        // The stored window reflects the clamp (honest reporting), never 0.
        assert_eq!(
            ledger.budget().window,
            Duration::from_millis(MIN_WINDOW_MS),
            "a zero window must be clamped UP to the floor, not stored as 0"
        );
        let p = peer(7);
        assert_eq!(ledger.try_admit(&p, 60), DeriveAdmission::Admitted);
        // Advance well within the clamped window; aggregation MUST still hold.
        clock.advance(10);
        assert_eq!(
            ledger.try_admit(&p, 60),
            DeriveAdmission::RefusedPerPeer,
            "a clamped window must still aggregate across admissions, not reset each call"
        );
        // Only after the CLAMPED window elapses does usage reset.
        clock.advance(MIN_WINDOW_MS);
        assert_eq!(ledger.try_admit(&p, 60), DeriveAdmission::Admitted);
    }
}
