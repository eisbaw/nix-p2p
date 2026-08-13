//! TASK-191 daemon-side wiring: the STORE-supply provider builds a `CatalogNarSupplier` over a
//! `Libp2pCatalogProbe` backed by the availability index (AC#1), and its announce is
//! VERIFICATION-GATED by the index's TASK-56 `sha256(--dump) == NarHash` check (AC#2).
//!
//! These are NO-NIX, no-network unit-level bites of the two properties the shipped binary depends
//! on. They use a `RegularFileNarDumper` over a temp raw-NAR file (a Process/file source, the
//! store-dump analogue) so `verify_store_provisions` runs a real dump + verify without needing a
//! `/nix/store`; the byte-identical two-swarm SERVE with a Process source is proven separately in
//! `fabric-libp2p/tests/nar_transport.rs`.

use std::path::PathBuf;
use std::sync::Arc;

use daemon_core::content_id::Blake3Digest;
use daemon_core::{
    AvailabilityIndex, NarDumper, NarHashKey, NodeId, NullAnnounce, NullStore,
    RegularFileNarDumper, StorePath,
};
use daemon_libp2p::{Libp2pCatalogProbe, verify_store_provisions};
use fabric_libp2p::{CatalogNarSupplier, Libp2pNarSupplier};

/// A unique-per-run temp path (no external tempdir dep; mirrors the fabric-libp2p tests).
fn unique_temp(stem: &str) -> PathBuf {
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    std::env::temp_dir().join(format!("nix-p2p-task191-{stem}-{suffix}"))
}

/// AC#2 (verification-gated announce): a store path registered under its TRUE NarHash is VERIFIED,
/// yielding a provision whose announced `content` is the index's verified BLAKE3 and whose
/// declared size is the real NAR length - and the reverse-map is now published so the supplier can
/// serve it. BITE: register it under a WRONG NarHash and `verify_store_provisions` REFUSES the
/// whole batch (the index quarantines the mismatch), so no unverified store path is ever announced.
#[test]
fn verify_store_provisions_accepts_verified_and_refuses_quarantined() {
    let body = b"a raw NAR regenerated on demand from a real store path".to_vec();
    let true_key = NarHashKey::from_raw_nar(&body);
    let expected_content = Blake3Digest::from_raw_nar(&body);

    // --- VERIFIED: registered under its true NarHash ---
    let nar_path = unique_temp("verified.nar");
    std::fs::write(&nar_path, &body).unwrap();
    let index = AvailabilityIndex::open(
        NodeId::from_bytes([0u8; 32]),
        Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("index opens");
    index
        .register(true_key, StorePath::new(&nar_path))
        .expect("register");

    let provisions = verify_store_provisions(&index, &[true_key])
        .expect("a store path under its true NarHash verifies");
    assert_eq!(provisions.len(), 1);
    assert_eq!(
        *provisions[0].nar_hash(),
        true_key,
        "the provision announces the registered NarHash"
    );
    assert_eq!(
        provisions[0].content(),
        expected_content,
        "the announced content is the index's VERIFIED digest, not the operator's word"
    );
    assert_eq!(
        provisions[0].declared_size(),
        body.len() as u64,
        "the declared size is the real uncompressed NAR length"
    );

    // --- QUARANTINE BITE: registered under a WRONG NarHash ---
    let wrong_key = NarHashKey::from_raw_nar(b"totally different bytes -> a different NarHash");
    assert_ne!(wrong_key, true_key);
    let mismatch_path = unique_temp("mismatch.nar");
    std::fs::write(&mismatch_path, &body).unwrap();
    let mismatch_index = AvailabilityIndex::open(
        NodeId::from_bytes([0u8; 32]),
        Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("index opens");
    mismatch_index
        .register(wrong_key, StorePath::new(&mismatch_path))
        .expect("register (the mis-binding is caught at verify, not register)");
    let refused = verify_store_provisions(&mismatch_index, &[wrong_key]);
    assert!(
        refused.is_err(),
        "a store path whose dump does not hash to its registered NarHash must be REFUSED \
         (quarantined), never announced: {refused:?}"
    );

    let _ = std::fs::remove_file(&nar_path);
    let _ = std::fs::remove_file(&mismatch_path);
}

/// AC#1 (store path served BY the supplier, nothing at rest): once a store path is registered +
/// verified, a `CatalogNarSupplier` over the `Libp2pCatalogProbe` bridge can PLAN its supply from
/// the index's reverse-map (verified digest -> store path). BITE: a digest that was never
/// registered/verified is NOT planned (the supplier has nothing to serve), and reverting to a
/// seed/MemoryNarSupplier would not reach the store path at all.
#[test]
fn catalog_supplier_serves_a_verified_store_path_and_only_that() {
    let body = b"raw NAR served on demand through the CatalogNarSupplier bridge".to_vec();
    let key = NarHashKey::from_raw_nar(&body);
    let content = Blake3Digest::from_raw_nar(&body);

    let nar_path = unique_temp("supplied.nar");
    std::fs::write(&nar_path, &body).unwrap();
    let index = AvailabilityIndex::open(
        NodeId::from_bytes([0u8; 32]),
        Arc::new(RegularFileNarDumper) as Arc<dyn NarDumper>,
        Arc::new(NullStore),
        Arc::new(NullAnnounce),
    )
    .expect("index opens");
    index
        .register(key, StorePath::new(&nar_path))
        .expect("register");

    // The supplier the shipped provider builds: an inert probe over the index's supply catalog.
    let supplier = CatalogNarSupplier::new(
        Libp2pCatalogProbe::new(index.supply_catalog()),
        "unused-helper",
    );

    // BEFORE verification the reverse-map is empty, so the supplier cannot plan the content.
    assert!(
        supplier.plan(&content).is_none(),
        "an unverified store path is NOT servable (the reverse-map is empty until first verify)"
    );

    // Verification publishes the reverse-map (the store analogue of seeding), gating the announce.
    let provisions = verify_store_provisions(&index, &[key]).expect("verifies");
    assert_eq!(provisions[0].content(), content);

    // NOW the supplier plans the store path's supply from the index - served on demand, no .nar
    // held at rest by the provider.
    let plan = supplier
        .plan(&content)
        .expect("the verified store path is now servable via the supplier");
    assert_eq!(
        plan.declared_size(),
        body.len() as u64,
        "the plan's admission size is the index's declared NarSize"
    );

    // A digest never registered here is still not servable (the bite: no register+verify -> None).
    let unknown = Blake3Digest::from_raw_nar(b"a NAR this node was never asked to provide");
    assert!(
        supplier.plan(&unknown).is_none(),
        "the supplier serves ONLY what the index verified, never an arbitrary digest"
    );

    let _ = std::fs::remove_file(&nar_path);
}
