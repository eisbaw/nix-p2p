//! TASK-297: the composition-root adapter that charges the shipped libp2p `/nar` serve
//! regenerate path against TASK-229's enforced per-authenticated-PeerId [`PeerDeriveLedger`].
//!
//! `fabric-libp2p`'s two-node fetch flood (`tests/nar_transport.rs`) proves the SERVE GATE
//! declines a per-peer regenerate flood and that the bound is load-bearing, using a faithful
//! stand-in admission. This suite closes the other half: that `Libp2pServeDeriveAdmission` - the
//! REAL adapter the shipped provider wires (`install_provider`) over the REAL ledger built from
//! `ResourceCaps::derive_budget()` - actually REFUSES a per-authenticated-PeerId flood, ISOLATES
//! distinct peers, and that the refusal is attributable to the budget (mutation: an unbounded
//! budget serves the SAME flood).

use std::sync::Arc;
use std::time::Duration;

use daemon_core::{DeriveBudget, OperatorContract, PeerDeriveLedger, SharingProfile};
use daemon_libp2p::Libp2pServeDeriveAdmission;
use fabric_libp2p::{PeerId, ServeDeriveAdmission};

fn budget(per_peer_bytes: u64, per_peer_dumps: u32, global_bytes: u64) -> DeriveBudget {
    DeriveBudget {
        max_bytes_per_peer_uncompressed_nar: per_peer_bytes,
        max_dumps_per_peer: per_peer_dumps,
        max_bytes_global_uncompressed_nar: global_bytes,
        window: Duration::from_secs(60),
    }
}

/// The adapter refuses a single authenticated peer's regenerate flood once it exceeds its per-peer
/// budget (here a DUMP-COUNT cap of 2, bytes/global generous), and a DISTINCT peer is unaffected -
/// so a hostile PeerId can exhaust neither another peer's nor the global allowance.
///
/// MUTATION (the load-bearing control `unbounded_budget_admits_the_same_flood` below): widen the
/// budget and the same peer's fourth regenerate is admitted -> this refusal assertion reddens.
#[test]
fn adapter_refuses_a_per_peer_flood_and_isolates_distinct_peers() {
    let nar_size = 4096;
    // Cap: 2 regenerates per peer; bytes/global generous so the COUNT is the bound that bites.
    let ledger = Arc::new(PeerDeriveLedger::new(budget(1 << 40, 2, 1 << 40)));
    let admission = Libp2pServeDeriveAdmission::new(Arc::clone(&ledger));

    let hostile = PeerId::random();
    assert!(
        admission.admit_regenerate(&hostile, nar_size),
        "regenerate #1 is within the per-peer budget"
    );
    assert!(
        admission.admit_regenerate(&hostile, nar_size),
        "regenerate #2 is within the per-peer budget"
    );
    assert!(
        !admission.admit_regenerate(&hostile, nar_size),
        "regenerate #3 from the SAME authenticated peer must be REFUSED (over its per-peer budget)"
    );
    assert!(
        !admission.admit_regenerate(&hostile, nar_size),
        "still refused while over budget; a refusal charges nothing but does not reopen the gate"
    );

    // A DISTINCT authenticated peer has its OWN budget: the hostile peer's exhaustion did not spend
    // it. This is the per-peer isolation the DoS bound depends on.
    let other = PeerId::random();
    assert!(
        admission.admit_regenerate(&other, nar_size),
        "a distinct authenticated peer's first regenerate is admitted (independent per-peer budget)"
    );
    assert!(
        admission.admit_regenerate(&other, nar_size),
        "and its second, still within its OWN per-peer budget"
    );
    assert!(
        !admission.admit_regenerate(&other, nar_size),
        "its third exceeds its OWN budget - each peer is bounded independently"
    );
}

/// The per-peer BYTE ceiling (not only the dump count) bounds the aggregate a single peer can drive
/// across requests: two `nar_size`-byte regenerates fit a `2*nar_size` byte budget; the third does
/// not. Proves the charge is seeded by the DECLARED uncompressed-NAR size, the ledger's unit.
#[test]
fn adapter_charges_declared_bytes_per_peer() {
    let nar_size = 4096;
    // Byte budget for exactly two NARs; dump-count generous so BYTES are the bound.
    let ledger = Arc::new(PeerDeriveLedger::new(budget(2 * nar_size, 1000, 1 << 40)));
    let admission = Libp2pServeDeriveAdmission::new(ledger);
    let p = PeerId::random();
    assert!(admission.admit_regenerate(&p, nar_size));
    assert!(admission.admit_regenerate(&p, nar_size));
    assert!(
        !admission.admit_regenerate(&p, nar_size),
        "the per-peer BYTE ceiling bounds the aggregate NAR bytes a peer can regenerate per window"
    );
}

/// LOAD-BEARING control (the mutation): with an effectively unbounded budget the adapter admits the
/// SAME peer's flood without limit - so the refusals above are attributable to the BUDGET, not to
/// the adapter refusing everything.
#[test]
fn unbounded_budget_admits_the_same_flood() {
    let ledger = Arc::new(PeerDeriveLedger::new(budget(u64::MAX, u32::MAX, u64::MAX)));
    let admission = Libp2pServeDeriveAdmission::new(ledger);
    let p = PeerId::random();
    for i in 0..64 {
        assert!(
            admission.admit_regenerate(&p, 4096),
            "an unbounded budget admits regenerate #{i} (the reverted-charge control)"
        );
    }
}

/// The adapter over the SHIPPED default budget (`ResourceCaps::derive_budget()` for a public-share
/// provider - exactly what `install_provider` wires) does NOT wrongly decline a legitimate peer's
/// normal use: a handful of modest regenerates well under the 1 GiB / 64-dump per-peer window are
/// all admitted. Guards against a mis-set cap that reddens honest traffic.
#[test]
fn shipped_default_budget_admits_legitimate_use() {
    let contract = OperatorContract::for_profile(SharingProfile::PublicShare);
    let ledger = Arc::new(PeerDeriveLedger::new(contract.caps.derive_budget()));
    let admission = Libp2pServeDeriveAdmission::new(ledger);
    let legit = PeerId::random();
    // 16 modest (16 MiB) regenerates: 256 MiB total, well under 1 GiB/peer and 16 < 64 dumps.
    for i in 0..16 {
        assert!(
            admission.admit_regenerate(&legit, 16 * 1024 * 1024),
            "the shipped default budget must not decline a legitimate peer's normal use (#{i})"
        );
    }
}
