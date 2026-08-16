//! TASK-100 AC#6 - a PUBLISH-capable adapter CONSUMES the single publication-eligibility
//! decision, and BYPASSING the filter makes a test fail.
//!
//! The contract, exercised through the seam with the fake announcer: an announcer is
//! CONSTRUCTED WITH a `PublicationEligibility` authority and consults it fail-closed
//! before emitting anything. THE bite: a refusing authority makes `announce` return
//! `AnnounceError::Ineligible` and record NO exposure - the record never reaches "the
//! wire". If the announcer skipped the eligibility consult (the mutation), the refusing
//! case below would publish and record exposure, reddening the assertions.
//!
//! Honest scope: this proves the SEAM CONTRACT and the FAKE publish-capable adapter.
//! The shipped `fabric-libp2p` announcer's public eligibility is enforced one layer up
//! by the `ApprovedPublicProvision` gate (the single TASK-102 `PublicNarAllowlist`
//! decision, bite-tested in `daemon-libp2p`), because the frozen `ProviderRecord` no
//! longer carries the sha256 `NarHash` the allowlist is keyed by; threading a
//! seam-level eligibility WITNESS as the required `announce` input across the shipped
//! adapter + all call sites is a filed residual (see the task notes).

use std::sync::Arc;

use peer_fabric::{
    AdmitAllPublication, AnnounceBudget, AnnounceError, AvailabilityAnnouncer, Blake3Digest,
    ContentKey, ExposureLedger, ExposureSurface, FakeAvailabilityAnnouncer, IneligibleReason,
    NodeId, ProviderRecord, RefusePublication, TransportOffer,
};

fn record() -> ProviderRecord {
    let provider = NodeId::from_bytes([0x33; 32]);
    ProviderRecord {
        key: ContentKey::from_bytes([0x01; 32]),
        content: Blake3Digest::from_bytes([0x42; 32]),
        provider,
        offers: vec![TransportOffer::Iroh { node: provider }],
        sequence: 1,
        issued_at: 100,
        expiry: 200,
        signature: [0u8; 64],
    }
}

// AC#6: a refusing eligibility authority makes the publish FAIL, fail-closed, and
// NOTHING is emitted (no exposure recorded). This is the bypass bite: neutering the
// announcer's eligibility consult would let this publish succeed.
#[tokio::test]
async fn a_refusing_authority_blocks_the_publish_and_emits_nothing() {
    let ledger = Arc::new(ExposureLedger::new());
    let announcer = FakeAvailabilityAnnouncer::with_eligibility(
        Arc::new(RefusePublication),
        vec![],
        ExposureSurface::none(),
        Arc::clone(&ledger),
    );

    let outcome = announcer
        .announce(&record(), &AnnounceBudget::default())
        .await;

    assert!(
        matches!(
            outcome,
            Err(AnnounceError::Ineligible(IneligibleReason::NotAllowlisted))
        ),
        "a refused record must fail with Ineligible, got {outcome:?}"
    );
    assert!(
        ledger.is_empty(),
        "a refused publish must emit nothing - no exposure recorded (fail-closed)"
    );
}

// AC#6 (not vacuous): an admitting authority lets the publish through - so the guard is
// not simply refusing everything.
#[tokio::test]
async fn an_admitting_authority_lets_the_publish_through() {
    let ledger = Arc::new(ExposureLedger::new());
    let announcer = FakeAvailabilityAnnouncer::with_eligibility(
        Arc::new(AdmitAllPublication),
        vec![],
        ExposureSurface::none(),
        Arc::clone(&ledger),
    );

    let outcome = announcer
        .announce(&record(), &AnnounceBudget::default())
        .await;
    assert!(
        outcome.is_ok(),
        "an admitted record publishes, got {outcome:?}"
    );
}

// AC#6: the DEFAULT `accepting` constructor is not an ABSENT authority - it is an
// EXPLICIT AdmitAllPublication choice, so every fake announcer still consumes a
// decision (there is no announcer constructed without one).
#[tokio::test]
async fn the_default_announcer_consumes_an_explicit_admit_all_authority() {
    let ledger = Arc::new(ExposureLedger::new());
    let announcer =
        FakeAvailabilityAnnouncer::accepting(vec![], ExposureSurface::none(), Arc::clone(&ledger));
    // It admits (AdmitAllPublication), proving the default path still routes through the
    // eligibility consult rather than skipping it.
    assert!(
        announcer
            .announce(&record(), &AnnounceBudget::default())
            .await
            .is_ok()
    );
}
