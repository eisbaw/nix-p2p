//! BYTE-LEVEL conformance for the FROZEN ProviderRecord codec + ContentKey
//! derivation (TASK-126). The peer-fabric twin of `daemon/tests/claim_wire_golden.rs`.
//!
//! ## Why this test exists (and why round-trip tests are not enough)
//!
//! `peer-fabric/src/record_codec.rs` and the [`ContentKey`] derivation are on the
//! irreversibility map: two daemons that disagree about the discovery-key recipe or
//! the opaque-value bytes do not interoperate, they SPLIT the network. A round-trip
//! (`encode` then `decode` agree) is blind to exactly that: rename a field, reorder
//! the layout, add a byte to the domain context, and encode+decode still agree with
//! each other - just not with the other node, whose signature then fails to verify.
//!
//! So this pins the actual BYTES. For each committed vector it asserts, byte-for-byte,
//! that our encoder EMITS the committed wire, our decoder ACCEPTS it, and every
//! must-reject wire is REFUSED. It also pins the ContentKey derivation and proves the
//! domain separation BITES (a one-byte context change lands on a different key).
//!
//! `include_str!` compiles the committed JSON in, so this runs in the Nix build
//! sandbox with no generated fixture tree - exactly like `golden_vectors.rs`. The
//! INDEPENDENT second-implementation half (recompute the key with python blake3
//! derive_key; verify the record signature with python cryptography) lives in
//! `scripts/check-content-key-derivation.py`; both read this one JSON, so they cannot
//! disagree about what the golden value IS.
//!
//! CHANGING A VECTOR IS A RE-FREEZE: bump `PROVIDER_RECORD_SCHEMA_VERSION` /
//! `CONTENT_KEY_CONTEXT` (and move the vectors to a new file), or revert.

use ed25519_dalek::SigningKey;
use peer_fabric::{
    Blake3Digest, ContentKey, InfoHash, NodeId, ProviderAssertion, ProviderRecord,
    ProviderWithdrawal, TransportOffer, decode_provider_assertion, encode_provider_record,
    encode_provider_withdrawal, sign_provider_record, sign_provider_withdrawal,
};

const GOLDEN: &str = include_str!("golden/provider_record_v1.json");

fn golden() -> serde_json::Value {
    serde_json::from_str(GOLDEN).expect("golden/provider_record_v1.json is valid JSON")
}

fn hexd(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex must be even length: {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hexe(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn wire_hex(name: &str) -> String {
    for v in golden()["vectors"].as_array().expect("vectors is an array") {
        if v["name"] == name {
            return v["wire_hex"]
                .as_str()
                .expect("wire_hex is a string")
                .to_string();
        }
    }
    panic!("no golden vector named {name:?}");
}

fn nar_hash() -> [u8; 32] {
    hexd(golden()["content_key"]["nar_hash_hex"].as_str().unwrap())
        .try_into()
        .unwrap()
}

fn key() -> ContentKey {
    ContentKey::derive_from_signed_nar_hash(&nar_hash())
}

fn signer() -> SigningKey {
    let seed: [u8; 32] = hexd(golden()["identities"]["signer_seed_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    SigningKey::from_bytes(&seed)
}

fn content() -> Blake3Digest {
    Blake3Digest::from_bytes(
        hexd(
            golden()["identities"]["content_blake3_hex"]
                .as_str()
                .unwrap(),
        )
        .try_into()
        .unwrap(),
    )
}

// ---- the ContentKey derivation, byte-pinned + the mutation controls -----------

#[test]
fn content_key_derivation_is_byte_for_byte_pinned() {
    let ck = &golden()["content_key"];
    let expected = ck["content_key_hex"].as_str().unwrap();
    assert_eq!(
        hexe(key().as_bytes()),
        expected,
        "the frozen ContentKey derivation drifted - this SPLITS the discovery \
         network unless CONTENT_KEY_CONTEXT is version-bumped"
    );
    // The context in the file must be the one the code froze.
    assert_eq!(
        ck["context"].as_str().unwrap(),
        peer_fabric::CONTENT_KEY_CONTEXT,
    );
}

#[test]
fn a_one_byte_namespace_change_lands_on_a_different_key() {
    // The mutation vector: the SAME NarHash under a context with one extra byte must
    // land on the pinned-but-DIFFERENT key. Recomputed here from blake3 directly (a
    // peer-fabric dep), so this proves the domain separation BITES, not just that two
    // committed strings differ.
    let ck = &golden()["content_key"];
    let base = ck["content_key_hex"].as_str().unwrap();
    let mutated_ctx = ck["namespace_mutation"]["context"].as_str().unwrap();
    let mutated_expected = ck["namespace_mutation"]["content_key_hex"]
        .as_str()
        .unwrap();
    let got = hexe(&blake3::derive_key(mutated_ctx, &nar_hash()));
    assert_eq!(got, mutated_expected, "the mutation vector drifted");
    assert_ne!(
        got, base,
        "a one-byte domain change MUST move the key, or the domain separation is vacuous"
    );

    // ...and a version bump (v1 -> v2) likewise.
    let v2_ctx = ck["cross_version"]["context"].as_str().unwrap();
    let v2_expected = ck["cross_version"]["content_key_hex"].as_str().unwrap();
    let v2 = hexe(&blake3::derive_key(v2_ctx, &nar_hash()));
    assert_eq!(v2, v2_expected, "the cross-version vector drifted");
    assert_ne!(v2, base, "a version bump must not collide with v1");
}

// ---- the accept vectors: encoder EMITS, decoder ACCEPTS -----------------------

fn full_record() -> ProviderRecord {
    let sk = signer();
    sign_provider_record(
        &sk,
        &ProviderRecord {
            key: key(),
            content: content(),
            provider: NodeId::from_bytes([0; 32]), // overwritten by sign_*
            offers: vec![
                TransportOffer::Iroh {
                    node: NodeId::from_bytes(sk.verifying_key().to_bytes()),
                },
                TransportOffer::BitTorrent {
                    infohash: InfoHash::V2([0xbb; 32]),
                },
            ],
            sequence: 7,
            issued_at: 100,
            expiry: 1_000,
            signature: [0; 64],
        },
    )
}

fn no_offers_record() -> ProviderRecord {
    sign_provider_record(
        &signer(),
        &ProviderRecord {
            key: key(),
            content: content(),
            provider: NodeId::from_bytes([0; 32]),
            offers: vec![],
            sequence: 1,
            issued_at: 0,
            expiry: 1_000,
            signature: [0; 64],
        },
    )
}

fn bittorrent_v1_record() -> ProviderRecord {
    sign_provider_record(
        &signer(),
        &ProviderRecord {
            key: key(),
            content: content(),
            provider: NodeId::from_bytes([0; 32]),
            offers: vec![TransportOffer::BitTorrent {
                infohash: InfoHash::V1([0xcc; 20]),
            }],
            sequence: 3,
            issued_at: 0,
            expiry: 1_000,
            signature: [0; 64],
        },
    )
}

fn withdrawal() -> ProviderWithdrawal {
    sign_provider_withdrawal(
        &signer(),
        &ProviderWithdrawal {
            key: key(),
            provider: NodeId::from_bytes([0; 32]),
            sequence: 9,
            issued_at: 200,
            expiry: 2_000,
            signature: [0; 64],
        },
    )
}

#[test]
fn provider_record_full_is_byte_for_byte_pinned() {
    let record = full_record();
    let expected = wire_hex("provider_record_full");
    assert_eq!(
        hexe(&encode_provider_record(&record).expect("encode")),
        expected,
        "the frozen ProviderRecord encoding changed"
    );
    assert_eq!(
        decode_provider_assertion(&hexd(&expected), &key(), 500).expect("decode"),
        ProviderAssertion::Provide(record)
    );
}

#[test]
fn provider_record_no_offers_is_byte_for_byte_pinned() {
    let record = no_offers_record();
    let expected = wire_hex("provider_record_no_offers");
    assert_eq!(
        hexe(&encode_provider_record(&record).expect("encode")),
        expected
    );
    assert_eq!(
        decode_provider_assertion(&hexd(&expected), &key(), 500).expect("decode"),
        ProviderAssertion::Provide(record)
    );
}

#[test]
fn provider_record_bittorrent_v1_is_byte_for_byte_pinned() {
    let record = bittorrent_v1_record();
    let expected = wire_hex("provider_record_bittorrent_v1");
    assert_eq!(
        hexe(&encode_provider_record(&record).expect("encode")),
        expected
    );
    assert_eq!(
        decode_provider_assertion(&hexd(&expected), &key(), 500).expect("decode"),
        ProviderAssertion::Provide(record)
    );
}

#[test]
fn provider_withdrawal_is_byte_for_byte_pinned() {
    let w = withdrawal();
    let expected = wire_hex("provider_withdrawal");
    assert_eq!(
        hexe(&encode_provider_withdrawal(&w).expect("encode")),
        expected
    );
    assert_eq!(
        decode_provider_assertion(&hexd(&expected), &key(), 500).expect("decode"),
        ProviderAssertion::Withdraw(w)
    );
}

// ---- the reject vectors: every must-reject wire is REFUSED --------------------

#[test]
fn every_reject_vector_is_refused_with_its_exact_typed_error() {
    let mut rejects = 0;
    for v in golden()["vectors"].as_array().expect("array") {
        if v["direction"] != "reject" {
            continue;
        }
        rejects += 1;
        let name = v["name"].as_str().unwrap();
        let expected_debug = v["reject_debug"]
            .as_str()
            .unwrap_or_else(|| panic!("reject vector `{name}` has no reject_debug"));
        let bytes = hexd(v["wire_hex"].as_str().unwrap());
        // Each vector is crafted so its ONLY fault is the guard under test (re-signed
        // after the mutation where needed). Compare the FULL typed error - variant AND
        // fields (round-3 #3) - so a BadInfoHash{version:4} cannot satisfy a vector that
        // pins version 3, and the specific rejection reason is truly frozen.
        let err = decode_provider_assertion(&bytes, &key(), 500)
            .expect_err(&format!("golden reject vector `{name}` was ACCEPTED"));
        assert_eq!(
            format!("{err:?}"),
            expected_debug,
            "reject vector `{name}` failed with the wrong typed error"
        );
    }
    assert!(rejects >= 8, "the must-reject class must not be emptied");
}

// ---- the file and the tests that consume it cannot drift apart ----------------

const EXERCISED: &[&str] = &[
    "provider_record_full",
    "provider_record_no_offers",
    "provider_record_bittorrent_v1",
    "provider_withdrawal",
    "reject_wrong_version",
    "reject_bad_signature",
    "reject_trailing_bytes",
    "reject_bad_infohash",
    "reject_malleable_signature",
    "reject_offers_not_canonical",
    "reject_iroh_node_not_provider",
    "reject_identity_forgery",
];

#[test]
fn every_golden_vector_is_exercised() {
    let present: Vec<String> = golden()["vectors"]
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v["name"].as_str().expect("a name").to_string())
        .collect();
    let listed: Vec<String> = EXERCISED.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        present, listed,
        "the golden file and the tests that consume it have drifted - a vector \
         nobody asserts pins nothing"
    );
    for v in golden()["vectors"].as_array().expect("array") {
        let d = v["direction"].as_str().expect("a direction");
        assert!(
            d == "both" || d == "reject",
            "vector {} declares an unknown direction {d:?}",
            v["name"]
        );
    }
}
