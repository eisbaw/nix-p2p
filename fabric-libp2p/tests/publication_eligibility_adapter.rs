//! TASK-231 (DEEP security gate): the SHIPPED `fabric-libp2p` announcer STRUCTURALLY consumes
//! its per-fabric publication-eligibility authority before publishing, so an
//! UNALLOWLISTED-but-validly-signed record cannot reach the kad DHT through the adapter - the
//! precise hole codex confirmed (a freely-mintable LAN-path witness reaching `announce`).
//!
//! THE bite (`announce_refuses_an_unallowlisted_record_before_reaching_the_dht`): the announcer
//! is built with an authority that admits ONLY a specific allowlisted ContentKey. A validly
//! signed record for a DIFFERENT key - wrapped in a PERMISSIVE `AdmitAll` witness, exactly the
//! LAN-door bypass vector - is REFUSED with `Ineligible` and records NO exposure (nothing
//! reached `start_providing`/`put_record`, which run only after the ledger write). MUTATION that
//! reddens it: remove the `self.eligibility.admit(record)?` consult at the top of `announce` and
//! the unallowlisted record proceeds to publish. The allowlisted record, by contrast, passes the
//! eligibility gate (it is never `Ineligible`), so the guard is not vacuously refusing.
//!
//! `withdraw_refuses_a_key_this_node_never_announced`: a withdrawal ALSO emits a signed record to
//! the DHT, so the announcer refuses a tombstone for a key it never announced (the self-serve
//! invariant), closing that emit-to-DHT path too.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use fabric_libp2p::{Libp2pFabric, NodeConfig};
use peer_fabric::{
    AdmitAllPublication, AnnounceBudget, AnnounceError, Blake3Digest, ContentKey, IneligibleReason,
    NodeId, PeerFabric, ProviderRecord, PublicationEligibility, PublicationWitness, TransportOffer,
    sign_provider_record,
};

/// An authority that admits ONLY `allowed` - a minimal stand-in for the shipped
/// allowlist-backed authority (which admits exactly the derived keys of proven-public NARs).
struct AllowOnly {
    allowed: ContentKey,
}

impl PublicationEligibility for AllowOnly {
    fn admit(&self, record: &ProviderRecord) -> Result<(), IneligibleReason> {
        if record.key == self.allowed {
            Ok(())
        } else {
            Err(IneligibleReason::NotAllowlisted)
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A validly SIGNED record for `nar_hash` from identity `seed` (so `record.provider ==
/// node_id`, passing the self-serve check), i.e. it fails ONLY the eligibility gate, never the
/// signature/self-serve checks - the "validly-signed but unallowlisted" vector.
fn signed_record(seed_byte: u8, nar_hash: [u8; 32]) -> (ContentKey, ProviderRecord) {
    let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
    let provider = NodeId::from_bytes(signing_key.verifying_key().to_bytes());
    let key = ContentKey::derive_from_signed_nar_hash(&nar_hash);
    let now = now_secs();
    let record = ProviderRecord {
        key,
        content: Blake3Digest::from_bytes([0x5a; 32]),
        provider,
        offers: vec![TransportOffer::Iroh { node: provider }],
        sequence: 1,
        issued_at: now,
        expiry: now + 3600,
        signature: [0u8; 64],
    };
    (key, sign_provider_record(&signing_key, &record))
}

/// A PERMISSIVE `AdmitAll` witness for `record` - the LAN-door bypass vector (a witness minted
/// by a permissive authority and handed to a stricter announcer).
fn admit_all_witness(record: &ProviderRecord) -> PublicationWitness {
    AdmitAllPublication
        .authorize(record.clone())
        .expect("admit-all mints a witness")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn announce_refuses_an_unallowlisted_record_before_reaching_the_dht() {
    let _ = tracing_subscriber::fmt::try_init();

    // The one allowlisted identity this node may publish.
    let (allowed_key, allowed_record) = signed_record(7, [0x11u8; 32]);
    // A DIFFERENT, validly-signed record the authority does NOT admit.
    let (unallowed_key, unallowed_record) = signed_record(7, [0x22u8; 32]);
    assert_ne!(allowed_key, unallowed_key);

    // The shipped announcer, built with an authority that admits ONLY `allowed_key`.
    let fabric = Libp2pFabric::start(
        NodeConfig::new([7u8; 32])
            .with_network_scope("task231-adapter")
            .with_publication_eligibility(Arc::new(AllowOnly {
                allowed: allowed_key,
            })),
    )
    .expect("swarm builds");
    let announcer = fabric.announcer().expect("announcer axis present").clone();

    // THE BITE: an unallowlisted-but-validly-signed record, handed in via a PERMISSIVE AdmitAll
    // witness, is REFUSED by the announcer's OWN authority - Ineligible, before any DHT op.
    let refused = announcer
        .announce(
            &admit_all_witness(&unallowed_record),
            &AnnounceBudget::new(Duration::from_millis(500), 20),
        )
        .await;
    assert!(
        matches!(
            refused,
            Err(AnnounceError::Ineligible(IneligibleReason::NotAllowlisted))
        ),
        "an unallowlisted record must be refused by the announcer's authority, got: {refused:?}"
    );
    // Nothing reached the wire: the eligibility consult is BEFORE the exposure ledger write (and
    // before start_providing/put_record), so a refused announce discloses NOTHING.
    assert!(
        fabric.exposure_ledger().is_empty(),
        "a refused announce must emit nothing - no DHT exposure recorded"
    );

    // NOT VACUOUS: the ALLOWLISTED record passes the eligibility gate. It is never Ineligible
    // (it may not fully publish on this peerless node within the short budget - that is a
    // network outcome, not an eligibility refusal).
    let admitted = announcer
        .announce(
            &admit_all_witness(&allowed_record),
            &AnnounceBudget::new(Duration::from_millis(500), 20),
        )
        .await;
    assert!(
        !matches!(admitted, Err(AnnounceError::Ineligible(_))),
        "the allowlisted record must PASS the eligibility gate, got: {admitted:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withdraw_refuses_a_key_this_node_never_announced() {
    let _ = tracing_subscriber::fmt::try_init();
    // An isolated node (AdmitAll authority) so the check under test is the withdraw self-serve
    // gate, not the eligibility gate.
    let fabric = Libp2pFabric::start(
        NodeConfig::new([9u8; 32])
            .with_network_scope("task231-withdraw")
            .with_admit_all_publication(),
    )
    .expect("swarm builds");
    let announcer = fabric.announcer().expect("announcer axis present").clone();

    // A key this node NEVER announced: withdrawing it would emit a signed tombstone naming the
    // key + this node to the DHT. Refused (self-serve v1 retracts only its own records).
    let never = ContentKey::derive_from_signed_nar_hash(&[0x44u8; 32]);
    let refused = announcer.withdraw(&never).await;
    match refused {
        Err(AnnounceError::Rejected(why)) => assert!(
            why.contains("never announced"),
            "the refusal must name the never-announced invariant, got: {why}"
        ),
        other => panic!("withdrawing a never-announced key must be Rejected, got: {other:?}"),
    }
}
