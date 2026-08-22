//! TASK-297: the composition-root adapter that charges the shipped libp2p `/nar` serve
//! regenerate path against TASK-229's enforced per-authenticated-PeerId [`PeerDeriveLedger`].
//!
//! These are the FAST unit bites on `Libp2pServeDeriveAdmission` - the REAL adapter the shipped
//! provider wires over the REAL ledger. They call the seam directly (`charge_regenerate`), so they
//! pass the already-two-pass-multiplied work the gate hands it. TASK-297 charge-at-spawn: a charge is
//! a single atomic decision, never refunded. The end-to-end production-wiring + byte-ceiling +
//! cancel-stays-charged bites over a real serve live in `serve_derive_wiring.rs`.

use std::sync::Arc;
use std::time::Duration;

use daemon_core::{DeriveBudget, OperatorContract, PeerDeriveLedger, SharingProfile};
use daemon_libp2p::Libp2pServeDeriveAdmission;
use fabric_libp2p::{PeerId, SERVE_DUMP_PASSES, ServeDeriveAdmission};

fn budget(per_peer_bytes: u64, per_peer_dumps: u32, global_bytes: u64) -> DeriveBudget {
    DeriveBudget {
        max_bytes_per_peer_uncompressed_nar: per_peer_bytes,
        max_dumps_per_peer: per_peer_dumps,
        max_bytes_global_uncompressed_nar: global_bytes,
        // Generous global dump ceiling so these cases isolate the per-peer bound they exercise.
        max_dumps_global: u32::MAX,
        window: Duration::from_secs(60),
    }
}

/// One `/nar` serve as the gate charges it at the SPAWN: two passes, so `2 * declared_size` bytes and
/// 2 dumps, in ONE atomic charge (`true` admits the spawn, `false` declines over-cap). Never refunded.
fn serve(admission: &Libp2pServeDeriveAdmission, peer: &PeerId, declared_size: u64) -> bool {
    admission.charge_regenerate(
        peer,
        declared_size * SERVE_DUMP_PASSES as u64,
        SERVE_DUMP_PASSES,
    )
}

/// The adapter refuses a single authenticated peer's serve flood once it exceeds its per-peer budget
/// (here a DUMP-EXECUTION cap of 4 = two serves, bytes/global generous), and a DISTINCT peer is
/// unaffected - so a hostile PeerId can exhaust neither another peer's per-peer window nor (here)
/// the global.
///
/// MUTATION (the load-bearing control `unbounded_budget_admits_the_same_flood`): widen the budget
/// and the same peer's third serve is admitted -> this refusal assertion reddens.
#[test]
fn adapter_refuses_a_per_peer_flood_and_isolates_distinct_peers() {
    let declared = 4096;
    // Per-peer dump cap of 4 = exactly TWO serves (2 passes each); bytes/global generous.
    let ledger = Arc::new(PeerDeriveLedger::new(budget(1 << 40, 4, 1 << 40)));
    let admission = Libp2pServeDeriveAdmission::new(Arc::clone(&ledger));

    let hostile = PeerId::random();
    assert!(
        serve(&admission, &hostile, declared),
        "serve #1 is within budget"
    );
    assert!(
        serve(&admission, &hostile, declared),
        "serve #2 is within budget"
    );
    assert!(
        !serve(&admission, &hostile, declared),
        "serve #3 from the SAME peer must be REFUSED (its per-peer dump budget of 4 executions = 2 \
         serves is spent)"
    );

    // A DISTINCT authenticated peer has its OWN per-peer window: the hostile peer's exhaustion did
    // not spend it.
    let other = PeerId::random();
    assert!(
        serve(&admission, &other, declared),
        "a distinct authenticated peer's first serve is admitted (independent per-peer window)"
    );
}

/// The per-peer BYTE ceiling (not only the dump count) is the BINDING constraint for FEW LARGE
/// serves: with a per-peer byte budget of `3 * declared`, one serve charges `2 * declared` (fits),
/// but a second would reach `4 * declared` > `3 * declared` and is refused ON BYTES. Proves the
/// charge is seeded by the declared uncompressed-NAR size, doubled for the two passes (HIGH-3/5).
#[test]
fn adapter_byte_ceiling_binds_for_large_serves() {
    let declared = 64 * 1024 * 1024; // 64 MiB
    // Byte budget for ONE serve (2*declared) plus slack, but less than TWO serves (4*declared).
    let ledger = Arc::new(PeerDeriveLedger::new(budget(
        3 * declared,
        1000,
        100 * declared,
    )));
    let admission = Libp2pServeDeriveAdmission::new(Arc::clone(&ledger));
    let p = PeerId::random();
    assert!(
        serve(&admission, &p, declared),
        "the first large serve fits the byte budget"
    );
    assert!(
        !serve(&admission, &p, declared),
        "the second large serve exceeds the per-peer BYTE ceiling (4*declared > 3*declared) and is \
         refused ON BYTES - the byte cap is load-bearing"
    );
    // Exactly ONE serve was admitted: the ledger charged 2*declared (both passes), not declared.
    assert_eq!(
        ledger.global_bytes_used(),
        2 * declared,
        "a serve charges BOTH passes: 2*declared bytes, not one"
    );
}

/// TASK-297 charge-at-spawn at the adapter seam: a charge STAYS - there is no refund path. One charge
/// commits `2 * declared` to the window; the peer cannot get it back, so a second serve (which would
/// reach `4 * declared` > `3 * declared`) is declined ON BYTES. Contrast the old reserve/commit/release
/// model: there is no `commit`/`release` to call, and no way for a cancelled serve to un-charge.
#[test]
fn adapter_charge_stays_there_is_no_refund() {
    let declared: u64 = 4096;
    // A per-peer byte budget for exactly ONE serve (2*declared) plus slack, but less than TWO.
    let ledger = Arc::new(PeerDeriveLedger::new(budget(3 * declared, 1000, 1 << 40)));
    let admission = Libp2pServeDeriveAdmission::new(Arc::clone(&ledger));
    let p = PeerId::random();

    assert!(
        serve(&admission, &p, declared),
        "the first serve charges at the spawn"
    );
    assert_eq!(
        ledger.global_bytes_used(),
        2 * declared,
        "one charge commits 2*declared (both passes) to the window"
    );
    // The charge STAYS (no refund): a second serve reaches 4*declared > 3*declared and is declined.
    assert!(
        !serve(&admission, &p, declared),
        "the charge is never refunded, so a second serve exceeds the per-peer byte ceiling"
    );
    assert_eq!(
        ledger.global_bytes_used(),
        2 * declared,
        "a declined serve charges nothing more; the first charge is still present (never refunded)"
    );
}

/// LOAD-BEARING control (the mutation): with an effectively unbounded budget the adapter admits the
/// SAME peer's flood without limit - so the refusals above are attributable to the BUDGET.
#[test]
fn unbounded_budget_admits_the_same_flood() {
    let ledger = Arc::new(PeerDeriveLedger::new(budget(u64::MAX, u32::MAX, u64::MAX)));
    let admission = Libp2pServeDeriveAdmission::new(ledger);
    let p = PeerId::random();
    for i in 0..64 {
        assert!(
            serve(&admission, &p, 4096),
            "an unbounded budget admits serve #{i} (the reverted-charge control)"
        );
    }
}

/// The adapter over the SHIPPED default budget (`ResourceCaps::derive_budget()` for a public-share
/// provider - exactly what `wire_provider_derive_budget` wires) does NOT wrongly decline a
/// legitimate peer's normal use: a handful of modest serves well under the 1 GiB / 64-dump per-peer
/// window are all admitted. Guards against a mis-set cap that reddens honest traffic. (16 serves =
/// 32 dump executions < 64, and 16*2*16 MiB = 512 MiB < 1 GiB.)
#[test]
fn shipped_default_budget_admits_legitimate_use() {
    let contract = OperatorContract::for_profile(SharingProfile::PublicShare);
    let ledger = Arc::new(PeerDeriveLedger::new(contract.caps.derive_budget()));
    let admission = Libp2pServeDeriveAdmission::new(ledger);
    let legit = PeerId::random();
    for i in 0..16 {
        assert!(
            serve(&admission, &legit, 16 * 1024 * 1024),
            "the shipped default budget must not decline a legitimate peer's normal use (#{i})"
        );
    }
}
