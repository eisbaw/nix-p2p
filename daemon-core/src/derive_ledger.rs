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
//! so a refused probe costs no budget (and no dump) - and (MED-7b) inserts no per-peer
//! entry, since the per-peer window is read on a COPY and only written back on commit.
//!
//! Two admission shapes share that core ([`charge_locked`](PeerDeriveLedger::charge_locked)):
//! [`try_admit`](PeerDeriveLedger::try_admit) is the SYNCHRONOUS commit the responder hold-query
//! path uses (the dump follows immediately, no abort window). The libp2p SERVE path instead
//! [`reserve_work`](PeerDeriveLedger::reserve_work)s (commit-on-admission for correct concurrent
//! accounting) and later either [`commit`](PeerDeriveLedger::commit_reservation)s (real regenerate
//! work began) or [`release`](PeerDeriveLedger::release_reservation)s (REFUND - the request aborted
//! before any producer started), so a serve that does zero work leaves the budget unconsumed
//! (TASK-297 HIGH-2).
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

/// A RESERVED regenerate charge (TASK-297 HIGH-2): the receipt of a [`PeerDeriveLedger::reserve_work`]
/// admission. The charge is ALREADY committed to both windows when this exists (so a concurrent
/// over-cap request is still declined up front - prevention is preserved), but the reservation is
/// PROVISIONAL: the caller [`commit`](PeerDeriveLedger::commit_reservation)s it once real regenerate
/// work begins (a producer is spawned under a held permit while the client is still connected), or
/// [`release`](PeerDeriveLedger::release_reservation)s it (refund) on any early abort - client
/// disconnected before the producer starts, process-start failure, or a pre-work decline. Net
/// invariant: a request that performs ZERO regenerate work leaves BOTH the per-peer and the global
/// window UNCONSUMED once it settles.
///
/// It records the exact amounts AND the window `start_millis` they were charged against, so a
/// refund subtracts from the SAME window it charged - if the window rolled between reserve and
/// release, the charge was already reset to zero and the refund is a no-op (never underflows a
/// fresh window). Not `Clone`/`Copy`: a ticket is spent exactly once (commit XOR release).
#[derive(Debug)]
pub struct ReservationTicket {
    peer: NodeId,
    bytes: u64,
    dumps: u32,
    /// The `start_millis` of the GLOBAL window the charge landed in; a refund only applies if the
    /// current global window still has this start (else it rolled and the charge is already gone).
    global_window_start: u64,
    /// The `start_millis` of the per-peer window the charge landed in (same roll-guard as global).
    peer_window_start: u64,
}

/// The per-peer map size at/above which [`LedgerState::evict_expired`] reclaims entries whose
/// window has fully elapsed. A flood of freshly-minted PeerIds is already bounded WITHIN a window
/// by the GLOBAL ceilings (a peer refused by the global backstop is never inserted), but across
/// window ROLLS the stale entries would otherwise accumulate unbounded; this bounds the resident
/// identity set to roughly (threshold + one window's admitted peers). An expired entry's bytes and
/// dumps are already zero, so removing it changes no admission decision (TASK-297 MED-7b).
const EVICT_SWEEP_THRESHOLD: usize = 1024;

/// Mutable state behind the ledger mutex: the global window plus one window per peer.
#[derive(Debug, Default)]
struct LedgerState {
    global: Option<Window>,
    per_peer: HashMap<NodeId, Window>,
}

impl LedgerState {
    /// Reclaim per-peer entries whose window has fully elapsed (MED-7b). Only sweeps once the map
    /// crosses [`EVICT_SWEEP_THRESHOLD`], so the common case pays nothing; under a rotating-PeerId
    /// flood it amortizes an O(n) `retain` to keep the resident identity set bounded across window
    /// rolls. Removing an expired entry is decision-neutral: a fresh window would reset it to zero
    /// anyway.
    fn evict_expired(&mut self, now: u64, window_millis: u64) {
        if self.per_peer.len() < EVICT_SWEEP_THRESHOLD {
            return;
        }
        self.per_peer
            .retain(|_, window| now.saturating_sub(window.start_millis) < window_millis);
    }
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
        self.try_admit_work(peer, nar_size, 1)
    }

    /// The generalised charge (TASK-297): ask permission to spend `dumps` fresh dump EXECUTIONS
    /// totalling `bytes` UNCOMPRESSED NAR bytes on behalf of `peer`, and commit atomically on
    /// admission. `try_admit` is the `dumps == 1` case the responder hold-query path uses (one
    /// dump per answer); the libp2p SERVE path charges `dumps == 2` because a `/nar/4` serve
    /// regenerates the source TWICE (bao pass-1 outboard + pass-2 authenticate), so the honest
    /// work bound is two executions and twice the bytes - see `fabric_libp2p`'s `SERVE_DUMP_PASSES`.
    ///
    /// FOUR ceilings, GLOBAL first (the Sybil floor, checked before any per-peer state is touched so
    /// a global refusal inserts no per-peer entry): global BYTES, global DUMPS (the dump-count Sybil
    /// floor - without it, rotating PeerIds serving tiny NARs defeat the per-peer dump cap), then
    /// per-peer BYTES and per-peer DUMPS. Every accumulation is `checked_add` fail-CLOSED (an
    /// overflow is treated as over-cap and REFUSED, never wrapped/saturated-then-admitted). A refusal
    /// at ANY ceiling commits NOTHING. A non-enforcing ([`unlimited`](Self::unlimited)) ledger always
    /// admits.
    pub fn try_admit_work(&self, peer: &NodeId, bytes: u64, dumps: u32) -> DeriveAdmission {
        if !self.enforced {
            return DeriveAdmission::Admitted;
        }
        let now = self.clock.now_millis();
        let window_millis = self.budget.window.as_millis().min(u64::MAX as u128) as u64;
        let mut state = self.state.lock().expect("derive-ledger mutex");
        state.evict_expired(now, window_millis);
        match self.charge_locked(&mut state, now, window_millis, peer, bytes, dumps) {
            Ok(_committed_windows) => DeriveAdmission::Admitted,
            Err(reason) => reason,
        }
    }

    /// RESERVE (TASK-297 HIGH-2) `dumps` executions totalling `bytes` for `peer`: run the SAME
    /// four-ceiling admission as [`try_admit_work`] and, on success, COMMIT the charge to both
    /// windows (so a concurrent over-cap request is declined up front - prevention holds) and return
    /// a [`ReservationTicket`]. A refusal charges nothing and returns `None`.
    ///
    /// Unlike `try_admit_work` (which the responder hold-query path uses because the dump follows
    /// synchronously with no abort window), the serve path may ABORT after admission but BEFORE any
    /// producer starts (client half-close under Bao backpressure, or a process-start failure). The
    /// caller therefore holds the ticket and either [`commit_reservation`](Self::commit_reservation)s
    /// it (real work began - the charge stays) or [`release_reservation`](Self::release_reservation)s
    /// it (refund - the request did no work). See [`ReservationTicket`] for the settle-once contract.
    pub fn reserve_work(&self, peer: &NodeId, bytes: u64, dumps: u32) -> Option<ReservationTicket> {
        if !self.enforced {
            // A non-enforcing ledger charges nothing; hand back a ticket whose refund/commit are
            // both no-ops (the ledger's own `refund` early-returns on `!enforced`).
            return Some(ReservationTicket {
                peer: *peer,
                bytes: 0,
                dumps: 0,
                global_window_start: 0,
                peer_window_start: 0,
            });
        }
        let now = self.clock.now_millis();
        let window_millis = self.budget.window.as_millis().min(u64::MAX as u128) as u64;
        let mut state = self.state.lock().expect("derive-ledger mutex");
        state.evict_expired(now, window_millis);
        match self.charge_locked(&mut state, now, window_millis, peer, bytes, dumps) {
            Ok((global_window_start, peer_window_start)) => Some(ReservationTicket {
                peer: *peer,
                bytes,
                dumps,
                global_window_start,
                peer_window_start,
            }),
            Err(_refused) => None,
        }
    }

    /// COMMIT a reservation: the real regenerate work began, so the charge STAYS. A no-op on the
    /// windows (the charge was already committed at reserve time); consuming the ticket so it cannot
    /// also be released. Kept as an explicit method (not just "drop the ticket") so the two terminal
    /// transitions read symmetrically at the call site and a future ticket-state assertion has a hook.
    pub fn commit_reservation(&self, _ticket: ReservationTicket) {}

    /// RELEASE a reservation: the request aborted before any producer started, so REFUND the charge.
    /// Subtracts from the SAME window it landed in (roll-guarded: if the window rolled since reserve,
    /// the charge is already gone and this is a no-op - never underflows a fresh window).
    pub fn release_reservation(&self, ticket: ReservationTicket) {
        self.refund(
            &ticket.peer,
            ticket.bytes,
            ticket.dumps,
            ticket.global_window_start,
            ticket.peer_window_start,
        );
    }

    /// The shared four-ceiling admission-and-commit, holding `state`'s lock. On success COMMITS the
    /// charge to both windows and returns their post-roll `start_millis` (`(global, per_peer)`) so a
    /// reservation can later refund the exact windows. On refusal returns the reason and charges
    /// NOTHING - and, MED-7b, inserts NO per-peer entry (the per-peer window is read/rolled on a COPY
    /// and only written back on commit), so a refused-per-peer flood cannot grow the identity map.
    ///
    /// Order is deliberate: the GLOBAL ceilings (the Sybil floor) are checked FIRST, so a global
    /// refusal touches no per-peer state. Every accumulation is `checked_add` fail-CLOSED (an
    /// overflow is over-cap and REFUSED, never wrapped/saturated-then-admitted).
    fn charge_locked(
        &self,
        state: &mut LedgerState,
        now: u64,
        window_millis: u64,
        peer: &NodeId,
        bytes: u64,
        dumps: u32,
    ) -> Result<(u64, u64), DeriveAdmission> {
        // Roll the global window first, then evaluate the global ceilings. `*_after`/`global_start`
        // are plain integer copies, so the per-peer read below cannot disturb them; they are
        // committed only if the per-peer checks ALSO pass.
        let global = state.global.get_or_insert_with(|| Window::opened_at(now));
        global.roll_if_expired(now, window_millis);
        let global_start = global.start_millis;
        let global_bytes_after = match global.bytes.checked_add(bytes) {
            Some(sum) if sum <= self.budget.max_bytes_global_uncompressed_nar => sum,
            _ => return Err(DeriveAdmission::RefusedGlobal),
        };
        let global_dumps_after = match global.dumps.checked_add(dumps) {
            Some(sum) if sum <= self.budget.max_dumps_global => sum,
            _ => return Err(DeriveAdmission::RefusedGlobal),
        };

        // Per-peer: read a COPY (roll if expired) so a REFUSAL inserts nothing (MED-7b). Only a
        // committed charge writes the entry back.
        let mut peer_window = state
            .per_peer
            .get(peer)
            .copied()
            .unwrap_or_else(|| Window::opened_at(now));
        peer_window.roll_if_expired(now, window_millis);
        let peer_start = peer_window.start_millis;
        let peer_bytes_after = match peer_window.bytes.checked_add(bytes) {
            Some(sum) if sum <= self.budget.max_bytes_per_peer_uncompressed_nar => sum,
            _ => return Err(DeriveAdmission::RefusedPerPeer),
        };
        let peer_dumps_after = match peer_window.dumps.checked_add(dumps) {
            Some(sum) if sum <= self.budget.max_dumps_per_peer => sum,
            _ => return Err(DeriveAdmission::RefusedPerPeer),
        };

        // COMMIT: all four ceilings pass. Write the peer window back (insert-on-admit only) and
        // charge the global window.
        peer_window.bytes = peer_bytes_after;
        peer_window.dumps = peer_dumps_after;
        state.per_peer.insert(*peer, peer_window);
        let global = state.global.as_mut().expect("global window present");
        // The global window could not have rolled since the `*_after` copies were computed
        // (single lock held throughout), so committing them is exact.
        global.bytes = global_bytes_after;
        global.dumps = global_dumps_after;

        Ok((global_start, peer_start))
    }

    /// Refund a reserved charge (TASK-297 HIGH-2), subtracting from the SAME window it landed in.
    /// The `start_millis` guards ensure a refund after a window ROLL is a no-op (the charge was
    /// already reset to zero); `saturating_sub` is belt-and-braces so no path can underflow.
    fn refund(
        &self,
        peer: &NodeId,
        bytes: u64,
        dumps: u32,
        global_window_start: u64,
        peer_window_start: u64,
    ) {
        if !self.enforced {
            return;
        }
        let mut state = self.state.lock().expect("derive-ledger mutex");
        if let Some(global) = state.global.as_mut()
            && global.start_millis == global_window_start
        {
            global.bytes = global.bytes.saturating_sub(bytes);
            global.dumps = global.dumps.saturating_sub(dumps);
        }
        if let Some(peer_window) = state.per_peer.get_mut(peer)
            && peer_window.start_millis == peer_window_start
        {
            peer_window.bytes = peer_window.bytes.saturating_sub(bytes);
            peer_window.dumps = peer_window.dumps.saturating_sub(dumps);
        }
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

    /// The number of per-peer identities currently resident (test-only observability for the
    /// eviction bound; not an operator surface - a per-peer count is not disclosed).
    #[cfg(test)]
    fn per_peer_len(&self) -> usize {
        self.state
            .lock()
            .expect("derive-ledger mutex")
            .per_peer
            .len()
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
            // Global dump ceiling generous by default so these cases isolate the OTHER bound they
            // exercise; the dedicated global-dump test below sets it tight.
            max_dumps_global: u32::MAX,
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
    fn try_admit_work_charges_all_dumps_and_bytes_atomically() {
        // The serve path charges dumps==2 (two-pass regeneration). A single work charge of 2 dumps
        // and 2*L bytes must consume BOTH the dump-count and the byte budget as one unit.
        let ledger = PeerDeriveLedger::with_clock(
            budget(200, 4, 1_000_000),
            Box::new(ManualClock::default()),
        );
        let p = peer(1);
        // 2 dumps of 60 bytes each = 120 bytes, 2 dumps. Under 200 bytes / 4 dumps: admitted.
        assert_eq!(ledger.try_admit_work(&p, 120, 2), DeriveAdmission::Admitted);
        // A second 2-dump/120-byte charge: bytes 240 > 200 -> RefusedPerPeer, nothing charged.
        assert_eq!(
            ledger.try_admit_work(&p, 120, 2),
            DeriveAdmission::RefusedPerPeer
        );
        // The refusal charged nothing: a small 1-dump/40-byte charge still fits the remaining 80.
        assert_eq!(ledger.try_admit_work(&p, 40, 1), DeriveAdmission::Admitted);
        // global reflects only the two admitted charges: 120 + 40 = 160.
        assert_eq!(ledger.global_bytes_used(), 160);
    }

    #[test]
    fn per_peer_dump_count_counts_multi_dump_work() {
        // dumps==2 per call against a per-peer dump cap of 3: the first 2-dump charge is admitted
        // (2 <= 3), the second would be 4 > 3 -> refused on the DUMP count even though bytes are tiny.
        let ledger = PeerDeriveLedger::with_clock(
            budget(1_000_000, 3, 1_000_000),
            Box::new(ManualClock::default()),
        );
        let p = peer(2);
        assert_eq!(ledger.try_admit_work(&p, 1, 2), DeriveAdmission::Admitted);
        assert_eq!(
            ledger.try_admit_work(&p, 1, 2),
            DeriveAdmission::RefusedPerPeer
        );
    }

    #[test]
    fn global_dump_ceiling_bounds_a_rotating_peerid_flood_of_tiny_nars() {
        // MED-7a: many DISTINCT peers each serving a TINY NAR stay under the global BYTE ceiling but
        // must be bounded by the global DUMP ceiling. Per-peer generous; global bytes generous;
        // global dumps tight at 2.
        let mut b = budget(1_000_000, 1000, 1_000_000);
        b.max_dumps_global = 2;
        let ledger = PeerDeriveLedger::with_clock(b, Box::new(ManualClock::default()));
        // Two distinct peers each spend one tiny dump: global dumps -> 2.
        assert_eq!(
            ledger.try_admit_work(&peer(1), 1, 1),
            DeriveAdmission::Admitted
        );
        assert_eq!(
            ledger.try_admit_work(&peer(2), 1, 1),
            DeriveAdmission::Admitted
        );
        // A third freshly-minted identity, still tiny bytes, is refused by the GLOBAL dump ceiling -
        // rotating PeerIds no longer defeats the per-peer dump cap.
        assert_eq!(
            ledger.try_admit_work(&peer(3), 1, 1),
            DeriveAdmission::RefusedGlobal
        );
    }

    #[test]
    fn stale_identities_are_evicted_across_window_rolls() {
        // MED-7b: fill the map past the sweep threshold with peers from window 0, advance a full
        // window, then a fresh admit triggers the sweep and reclaims the now-expired entries.
        let clock = ManualClock::default();
        // Generous ceilings so insertion is never globally refused while we fill the map.
        let ledger = PeerDeriveLedger::with_clock(
            budget(u64::MAX, u32::MAX, u64::MAX),
            Box::new(clock.clone()),
        );
        for i in 0..(EVICT_SWEEP_THRESHOLD as u64 + 8) {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_le_bytes());
            assert!(
                ledger
                    .try_admit_work(&NodeId::from_bytes(id), 1, 1)
                    .is_admitted()
            );
        }
        assert!(
            ledger.per_peer_len() > EVICT_SWEEP_THRESHOLD,
            "the map filled past the sweep threshold before any window elapsed"
        );
        // Advance a full window so every existing entry is now expired, then admit ONE fresh peer.
        clock.advance(60_000);
        let mut fresh = [0u8; 32];
        fresh[0] = 0xEE;
        assert!(
            ledger
                .try_admit_work(&NodeId::from_bytes(fresh), 1, 1)
                .is_admitted()
        );
        // The sweep reclaimed the expired identities: the map is now small, not unbounded.
        assert!(
            ledger.per_peer_len() <= 1,
            "expired identities must be evicted across a window roll; map still has {}",
            ledger.per_peer_len()
        );
    }

    #[test]
    fn reserve_then_release_refunds_both_windows() {
        // TASK-297 HIGH-2: a reservation that is RELEASED (the request aborted before any producer
        // started) leaves BOTH the per-peer and the global window unconsumed.
        let ledger = PeerDeriveLedger::with_clock(
            budget(1000, 100, 10_000),
            Box::new(ManualClock::default()),
        );
        let p = peer(1);
        let ticket = ledger.reserve_work(&p, 120, 2).expect("reserved under cap");
        assert_eq!(
            ledger.global_bytes_used(),
            120,
            "reserve commits the charge to the window immediately (so a concurrent over-cap \
             request is still declined up front)"
        );
        ledger.release_reservation(ticket);
        assert_eq!(
            ledger.global_bytes_used(),
            0,
            "release refunds the GLOBAL window"
        );
        // The PER-PEER window is refunded too: a full per-peer-cap charge now fits (it would be
        // RefusedPerPeer at 120 + 1000 > 1000 if the reservation had not been refunded).
        assert_eq!(
            ledger.try_admit_work(&p, 1000, 1),
            DeriveAdmission::Admitted,
            "release must refund the per-peer window, not only the global one"
        );
    }

    #[test]
    fn reserve_then_commit_keeps_the_charge() {
        // The COMMIT branch: real regenerate work began, so the reserved charge STAYS.
        let ledger = PeerDeriveLedger::with_clock(
            budget(1000, 100, 10_000),
            Box::new(ManualClock::default()),
        );
        let p = peer(1);
        let ticket = ledger.reserve_work(&p, 120, 2).expect("reserved");
        ledger.commit_reservation(ticket);
        assert_eq!(
            ledger.global_bytes_used(),
            120,
            "commit keeps the charge (the two-pass work ran)"
        );
        // The per-peer window kept its charge too: 120 already spent of 1000.
        assert_eq!(
            ledger.try_admit_work(&p, 881, 1),
            DeriveAdmission::RefusedPerPeer
        );
        assert_eq!(ledger.try_admit_work(&p, 880, 1), DeriveAdmission::Admitted);
    }

    #[test]
    fn reserve_declines_a_concurrent_over_cap_request_then_frees_on_abort() {
        // Prevention is preserved: WHILE a reservation is in flight, a concurrent same-peer request
        // that would exceed the cap is declined up front. After the first aborts (release), the
        // budget is available again - the exploit shape (queue no-work reservations to deny others)
        // is closed because an aborted reservation refunds.
        let ledger = PeerDeriveLedger::with_clock(
            budget(200, 100, 1_000_000),
            Box::new(ManualClock::default()),
        );
        let p = peer(1);
        let first = ledger.reserve_work(&p, 120, 2).expect("first reserve fits");
        assert!(
            ledger.reserve_work(&p, 120, 2).is_none(),
            "an over-cap concurrent request (240 > 200) is declined WHILE the first is reserved"
        );
        ledger.release_reservation(first);
        assert!(
            ledger.reserve_work(&p, 120, 2).is_some(),
            "after the aborted reservation refunds, the budget is available again"
        );
    }

    #[test]
    fn refund_after_window_roll_is_a_noop() {
        // The roll-guard: if the window rolled between reserve and release, the charge was already
        // reset to zero; refunding must NOT subtract from the fresh window (no underflow, no
        // stealing budget from the new window).
        let clock = ManualClock::default();
        let ledger =
            PeerDeriveLedger::with_clock(budget(1000, 100, 10_000), Box::new(clock.clone()));
        let p = peer(1);
        let stale = ledger
            .reserve_work(&p, 120, 2)
            .expect("reserved in window 0");
        clock.advance(60_000); // roll the window: the reserved charge is reset to zero
        assert_eq!(ledger.try_admit_work(&p, 500, 1), DeriveAdmission::Admitted);
        assert_eq!(ledger.global_bytes_used(), 500, "fresh window charged 500");
        ledger.release_reservation(stale);
        assert_eq!(
            ledger.global_bytes_used(),
            500,
            "a refund after a window roll is a no-op (never underflows/steals from the fresh window)"
        );
    }

    #[test]
    fn refused_per_peer_on_first_request_inserts_no_map_entry() {
        // MED-7b (unconditional map bound): a FRESH identity whose single request exceeds the
        // per-peer byte cap is refused and inserts NO per-peer entry, so a rotating refused-per-peer
        // flood cannot grow the identity map.
        let ledger = PeerDeriveLedger::with_clock(
            budget(100, 1000, 1_000_000),
            Box::new(ManualClock::default()),
        );
        assert_eq!(
            ledger.try_admit_work(&peer(1), 200, 1),
            DeriveAdmission::RefusedPerPeer
        );
        assert_eq!(
            ledger.per_peer_len(),
            0,
            "a per-peer refusal on a fresh identity must insert no map entry (MED-7b)"
        );
        // Contrast: an ADMITTED request DOES insert its window.
        assert_eq!(
            ledger.try_admit_work(&peer(2), 50, 1),
            DeriveAdmission::Admitted
        );
        assert_eq!(ledger.per_peer_len(), 1);
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
                max_dumps_global: u32::MAX,
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
