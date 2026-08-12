//! REAL two-endpoint iroh whole-NAR transfer (task-39) - the FIRST peer-to-peer
//! byte transfer in the project.
//!
//! Two genuine iroh endpoints run in THIS process. A PROVIDER (node B) seeds a
//! raw NAR into an iroh-blobs store addressed by `BLAKE3(RawNarV1)` and serves it
//! under the stock iroh-blobs ALPN. A CLIENT (node A) dials B over REAL iroh on
//! loopback and fetches the blob by that exact [`Blake3Digest`]. No mock, no
//! stub: the bytes cross a real QUIC connection and iroh/bao BLAKE3-verifies them
//! incrementally (gate 1) as they arrive.
//!
//! Relay/discovery: these tests use iroh's DIRECT-ADDRESSING path (the client is
//! handed B's loopback socket via [`IrohProvider::addr`], exactly the address a
//! wave-2 discovery layer would resolve a `NodeId` to - task-40), with the n0
//! relay DISABLED, so the test needs NO external relay server. n0 relay
//! dependence for WAN holepunch is a known soft-centralization limit (PRD); it is
//! out of scope here.
//!
//! The TWO gates, kept distinct (the corruption-bite SPLIT, codex #6):
//!   * gate 1 - transport BLAKE3 (bao): the bytes MUST hash to the requested
//!     [`Blake3Digest`]. iroh gives this intrinsically; we re-assert it with the
//!     daemon's own [`verify_blake3`] so the assertion is not vacuous.
//!   * gate 2 - trust: `sha256(nar) == NarHash`, Nix's signed gate, modelled here
//!     with the `sha2` crate exactly as the Nix client would compute it. The
//!     daemon is OUTSIDE the TCB and never re-implements it.
//!
//! Nothing here names the generated fixture tree (the source guard forbids it):
//! each test synthesises its own valid `nix-archive-1` NAR in memory.

use daemon::{
    Blake3Digest, IROH_BLOBS_ALPN, IrohClientNode, IrohProvider, IrohProviderNode, IrohTransport,
    KnownTransport, NodeId, Transport, TransportError, TransportTag, iroh_blobs_alpn,
    verify_blake3,
};
use sha2::{Digest, Sha256};

// ---- a real (uncompressed) nix-archive-1 NAR, synthesised in memory ----------

/// Serialise one NAR token: a u64-LE length prefix, the bytes, then zero-padding
/// to the next 8-byte boundary. This is the exact `nix-archive-1` framing Nix
/// uses, so the result begins with the length-prefixed magic and is a genuine
/// raw NAR (what `nix-store --dump` of a single regular file emits).
fn nar_str(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    let pad = (8 - (bytes.len() % 8)) % 8;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// A valid raw NAR for a single regular file whose contents are `contents`.
/// The addressed unit is `BLAKE3` of exactly these bytes (uncompressed).
fn synth_raw_nar(contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    nar_str(&mut out, b"nix-archive-1");
    nar_str(&mut out, b"(");
    nar_str(&mut out, b"type");
    nar_str(&mut out, b"regular");
    nar_str(&mut out, b"contents");
    nar_str(&mut out, contents);
    nar_str(&mut out, b")");
    out
}

/// Model Nix's trust anchor: the sha256 over the raw NAR bytes (gate 2's input).
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Build a client transport already wired to `provider`'s loopback address, as a
/// discovery layer (task-40) would resolve the provider's `NodeId` to an address.
async fn client_wired_to(provider: &IrohProvider) -> IrohClientNode {
    let client = IrohClientNode::spawn()
        .await
        .expect("client endpoint binds");
    client.add_peer(&provider.addr().await.expect("provider addr"));
    client
}

fn iroh_offer(provider: &IrohProvider) -> KnownTransport {
    KnownTransport::Iroh {
        node: provider.node_id().unwrap(),
    }
}

// ---- AC#1: honest fetch passes BOTH gates, byte-identical -------------------

#[tokio::test]
async fn honest_iroh_fetch_passes_both_gates() {
    let nar = synth_raw_nar(b"AC#1: the honest whole-NAR payload node B holds");

    // PROVIDER (node B): content-addressed put -> the digest is BLAKE3(RawNarV1).
    let provider = IrohProviderNode::spawn()
        .await
        .expect("provider endpoint binds");
    let content = provider.seed(&nar).await.expect("seed the raw NAR");
    assert_eq!(
        content,
        Blake3Digest::from_raw_nar(&nar),
        "the iroh-blobs blob hash IS our frozen Blake3Digest (content_id freeze)"
    );

    // CLIENT (node A): fetch by content id over REAL iroh (loopback, no relay).
    let client = client_wired_to(&provider).await;
    assert_eq!(client.tag(), TransportTag::Iroh);
    let got = client
        .fetch(&content, &iroh_offer(&provider), Some(nar.len() as u64))
        .await
        .expect("a real two-endpoint iroh fetch of the seeded blob");

    // gate 1 (transport BLAKE3 / bao): re-assert with the daemon's own recipe so
    // the assertion is not vacuous - bao already enforced it on the wire.
    assert!(
        verify_blake3(&content, &got).is_ok(),
        "gate 1 holds on the fetched bytes"
    );
    // byte-identical to what B seeded.
    assert_eq!(got, nar, "the fetched NAR is byte-identical to the fixture");
    // gate 2 (trust, Nix's): sha256(nar) == the signed NarHash. A DIFFERENT gate.
    assert_eq!(
        sha256_hex(&got),
        sha256_hex(&nar),
        "gate 2 (sha256==NarHash) holds on the fetched bytes"
    );

    provider.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}

// ---- S6 oracle: the PROVIDER-side byte counter grounds "peer-served" --------
// The whole S6 offload claim rests on node B genuinely SENDING the NAR bytes.
// node A's daemon self-reporting "I fetched from a peer" is untrusted narration
// (wave-1 lesson); the ground truth is node B's provider counting the bytes it
// served. This proves that counter observes exactly the NAR size, from iroh's
// own provider events, after a real fetch - and stays zero when nothing is sent.

#[tokio::test]
async fn provider_byte_counter_grounds_the_peer_served_bytes() {
    let nar = synth_raw_nar(b"S6: the whole-NAR node B actually serves node A");
    let provider = IrohProviderNode::spawn().await.expect("provider binds");
    let content = provider.seed(&nar).await.expect("seed the raw NAR");

    // Before any fetch: nothing served (the absent-before analogue for the counter).
    assert_eq!(
        provider.bytes_served(),
        0,
        "no bytes served before any fetch"
    );
    assert_eq!(provider.transfers_completed(), 0);

    let client = client_wired_to(&provider).await;
    let got = client
        .fetch(&content, &iroh_offer(&provider), Some(nar.len() as u64))
        .await
        .expect("a real two-endpoint iroh fetch");
    assert_eq!(got, nar, "byte-identical peer-served NAR");

    // The provider event task is async: poll the counter up to a bound rather
    // than assume it has drained by the time the client's fetch future resolved.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while provider.bytes_served() != nar.len() as u64 {
        if std::time::Instant::now() > deadline {
            panic!(
                "provider byte counter never reached {} (saw {})",
                nar.len(),
                provider.bytes_served()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        provider.bytes_served(),
        nar.len() as u64,
        "the ground-truth counter equals exactly the served NAR size"
    );
    assert_eq!(
        provider.transfers_completed(),
        1,
        "exactly one completed transfer served"
    );

    provider.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}

// ---- AC#2 bite (a): a holder that cannot honestly serve the requested id ----
// yields NO bytes over real iroh (bao/get fails closed). Wrong bytes for a valid
// hash are impossible against a stock iroh-blobs provider (content-addressed +
// bao), so the gate-1 failure manifests as a fail-closed error, never a corrupt
// success. The daemon-side verify_blake3 recipe biting on tampered bytes is
// proven as a unit in transport_fetch.rs; here we prove the REAL network path
// fails closed.

#[tokio::test]
async fn wrong_content_id_fails_closed_over_real_iroh() {
    let held = synth_raw_nar(b"bite(a): the only NAR node B actually holds");
    let provider = IrohProviderNode::spawn().await.expect("provider binds");
    let held_id = provider.seed(&held).await.expect("seed");

    // The client asks for a DIFFERENT identity the provider does NOT hold.
    let bogus = Blake3Digest::from_raw_nar(b"bite(a): a NAR the holder lacks");
    assert_ne!(bogus, held_id);

    let client = client_wired_to(&provider).await;
    match client.fetch(&bogus, &iroh_offer(&provider), None).await {
        // fail-closed: no bytes for an id the holder cannot honestly serve.
        Err(TransportError::NotHeld(_)) | Err(TransportError::Unavailable(_)) => {}
        Ok(_) => panic!("a holder lacking the id must not yield bytes"),
        Err(other) => panic!("expected a fail-closed transport error, got {other:?}"),
    }

    provider.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}

// ---- AC#2 bite (b): a DIFFERENT valid NAR passes gate 1 but fails gate 2 -----
// The substituted-blob attack. A liar advertises a valid blob whose own BLAKE3
// is valid (so the transport gate PASSES), but it is not the NAR the client
// wanted, so its sha256 != the signed NarHash -> Nix's gate 2 REJECTS it. This
// is the split's whole point: transport integrity != trust.

#[tokio::test]
async fn a_different_valid_nar_passes_gate1_but_fails_gate2() {
    let wanted = synth_raw_nar(b"bite(b): the NAR the client actually wanted");
    let substituted = synth_raw_nar(b"bite(b): a DIFFERENT valid NAR a liar advertised");
    // The signed trust anchor is the sha256 of the WANTED NAR.
    let wanted_nar_hash = sha256_hex(&wanted);
    let sub_content = Blake3Digest::from_raw_nar(&substituted);

    // The lying holder serves the substituted (but internally valid) blob.
    let provider = IrohProviderNode::spawn().await.expect("provider binds");
    let seeded = provider.seed(&substituted).await.expect("seed substituted");
    assert_eq!(seeded, sub_content);

    let client = client_wired_to(&provider).await;
    // The (lying) claim pointed the wanted key at sub_content; fetch by it.
    let got = client
        .fetch(&sub_content, &iroh_offer(&provider), None)
        .await
        .expect("the substituted blob is internally valid, so the transport succeeds");

    // gate 1 PASSES: the bytes hash to the advertised blake3 (bao verified it).
    assert!(
        verify_blake3(&sub_content, &got).is_ok(),
        "gate 1 passes for a valid-but-wrong NAR"
    );
    // gate 2 FAILS: sha256(bytes) != the signed NarHash of what was wanted.
    assert_ne!(
        sha256_hex(&got),
        wanted_nar_hash,
        "the substituted NAR must fail Nix's sha256==NarHash trust gate"
    );
    // and it is not the wanted bytes.
    assert_ne!(got, wanted);

    provider.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}

// ---- AC#4: ALPN cross-check + NodeId ed25519 curve-point validation ---------

#[test]
fn frozen_alpn_equals_the_real_iroh_blobs_constant() {
    // The task-48 freeze pinned IROH_BLOBS_ALPN WITHOUT an iroh dependency in
    // tree; now that iroh is a dependency we cross-check the frozen bytes against
    // the real crate constant. (A compile-time `const _` assertion in
    // transport_iroh.rs makes a divergence fail the BUILD; this test documents
    // it too.) codex confirmed /iroh-bytes/4 is current - but we ASSERT it.
    assert_eq!(
        IROH_BLOBS_ALPN,
        iroh_blobs_alpn(),
        "the frozen ALPN must equal iroh_blobs::ALPN or peers never connect"
    );
    assert_eq!(IROH_BLOBS_ALPN, b"/iroh-bytes/4");
}

#[tokio::test]
async fn a_real_provider_node_id_is_a_valid_ed25519_point() {
    // The task-48 freeze deferred ed25519 curve-point validation to here (it
    // needs the iroh key constructor). A real provider's NodeId must validate...
    let provider = IrohProviderNode::spawn().await.expect("provider binds");
    let id = provider.node_id().unwrap();
    assert!(
        IrohTransport::validate_node_id(&id).is_ok(),
        "a live iroh endpoint id must be a valid curve point"
    );
    provider.shutdown().await.unwrap();

    // ...and a NodeId whose 32 bytes are NOT a valid ed25519 curve point is
    // rejected. Roughly half of all 32-byte strings fail point decompression, so
    // we scan a deterministic family for one that does; finding it proves the
    // check actually decompresses the point (not a length-only check) and that a
    // structurally-valid-but-off-curve id is refused, not silently dialled.
    let off_curve = (0u8..=255)
        .map(|b| NodeId::from_bytes([b; 32]))
        .find(|id| IrohTransport::validate_node_id(id).is_err())
        .expect("some 32-byte string must fail ed25519 point decompression");
    assert!(
        IrohTransport::validate_node_id(&off_curve).is_err(),
        "a non-canonical (off-curve) NodeId must be rejected, not silently dialled"
    );
}

// ---- TASK-148 AC#1: the SAME iroh fetch is reachable through the seam ---------
// The transfer axis is de-welded onto `peer_fabric::NarTransfer`: `IrohTransport`
// is the NATIVE impl and the daemon `Transport` is a thin bridge over it. This
// exercises the SEAM trait directly (a `TransportOffer`, a seam `SafetyEnvelope`,
// UFCS to avoid the two `fetch` methods colliding), proving the de-welded impl is
// real and behaviourally identical - not vacuous scaffolding. It also asserts the
// signed-NarSize abort fires through the seam path.

#[tokio::test]
async fn iroh_transfer_is_reachable_through_the_seam_nartransfer() {
    use peer_fabric::{NarTransfer, SafetyEnvelope as SeamEnvelope, TransferError, TransportOffer};

    let nar = synth_raw_nar(b"TASK-148: the seam NarTransfer fetches the same NAR");
    let provider = IrohProviderNode::spawn().await.expect("provider binds");
    let content = provider.seed(&nar).await.expect("seed the raw NAR");

    let client = client_wired_to(&provider).await;
    let transport = client.transport_handle();
    let offer = TransportOffer::Iroh {
        node: provider.node_id().unwrap(),
    };
    let envelope = SeamEnvelope::default();

    // gate 1 verified bytes, byte-identical to the fixture - through the seam trait.
    let got = NarTransfer::fetch(
        &transport,
        &content,
        &offer,
        Some(nar.len() as u64),
        &envelope,
    )
    .await
    .expect("a real two-endpoint iroh fetch through peer_fabric::NarTransfer");
    assert_eq!(
        got, nar,
        "the seam-fetched NAR is byte-identical to the fixture"
    );
    assert_eq!(NarTransfer::tag(&transport), TransportTag::Iroh);

    // The signed-NarSize bound is WIRED through the seam: a limit below the served
    // size aborts with TooLarge (the real mid-stream cap), never oversized bytes.
    let aborted = NarTransfer::fetch(
        &transport,
        &content,
        &offer,
        Some((nar.len() as u64).saturating_sub(1)),
        &envelope,
    )
    .await;
    assert!(
        matches!(aborted, Err(TransferError::TooLarge { .. })),
        "expected a TooLarge abort through the seam, got {aborted:?}"
    );

    provider.shutdown().await.unwrap();
    client.shutdown().await.unwrap();
}
