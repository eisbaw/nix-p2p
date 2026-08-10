//! BYTE-LEVEL conformance for the FROZEN claim/hold-query wire (task-91).
//!
//! ## Why this test exists (and why it did not before)
//!
//! `daemon/src/claim.rs` declares the claim wire schema FROZEN - it is on the
//! irreversibility map, because two daemons that disagree about it do not
//! interoperate, they split the network. Until task-91 that freeze was enforced
//! only by ROUND-TRIP tests (`encode` then `decode` equals the input). A
//! round-trip test is blind to exactly the change that splits a network: rename a
//! field, reorder a variant tag, change `Absent` from `"absent"` to `"none"`, and
//! encode+decode still agree with each other - just not with the other node.
//!
//! So before ADDING the batched query alongside the frozen types, task-91 pinned
//! the frozen types' actual BYTES here. The committed vectors live in
//! `golden/claim_wire_v1.json`; this test asserts, for each one:
//!
//!   * our encoder EMITS exactly those bytes (byte-for-byte, not "parses to the
//!     same value"), and
//!   * our decoder ACCEPTS exactly those bytes and reconstructs the typed value.
//!
//! Both directions are needed: the first catches a change in what we send, the
//! second catches a change in what we tolerate receiving.
//!
//! It follows `golden_vectors.rs`: `include_str!` so it runs in the Nix build
//! sandbox with no generated fixture tree.
//!
//! CHANGING A VECTOR IS A RE-FREEZE. If a change to `claim.rs` makes a vector
//! fail, the correct response is almost never to update the vector - it is to
//! bump `schema_version` (that is what the field is for) or to revert. The one
//! legitimate re-pin is the planned move off the JSON draft codec to the binary
//! codec, which re-pins every vector at once under a new file.

use daemon::{
    BatchHoldAnswer, BatchHoldQuery, BatchHoldResponse, Blake3Digest, Claim, HoldAnswer, HoldQuery,
    HoldResponse, KnownPayload, KnownTransport, NarHashKey, NodeId, decode_batch_hold_query,
    decode_batch_hold_response, decode_claim, decode_hold_query, decode_hold_response,
    encode_batch_hold_query, encode_batch_hold_response, encode_claim, encode_hold_query,
    encode_hold_response,
};
use daemon::{BitTorrentInfoHash, CLAIM_SCHEMA_VERSION, QUERY_SCHEMA_VERSION};

const GOLDEN: &str = include_str!("golden/claim_wire_v1.json");

fn golden() -> serde_json::Value {
    serde_json::from_str(GOLDEN).expect("golden/claim_wire_v1.json is valid JSON")
}

/// The committed wire string for `name`, or a panic naming the missing vector.
fn wire(name: &str) -> String {
    let doc = golden();
    let vectors = doc["vectors"].as_array().expect("vectors is an array");
    for vector in vectors {
        if vector["name"] == name {
            return vector["wire"]
                .as_str()
                .expect("wire is a string")
                .to_string();
        }
    }
    panic!("no golden vector named {name:?}");
}

/// The committed canonical string for identity `name`.
fn identity(name: &str) -> String {
    golden()["identities"][name]
        .as_str()
        .unwrap_or_else(|| panic!("no golden identity named {name:?}"))
        .to_string()
}

// ---- the typed values the vectors are built from ---------------------------

fn key() -> NarHashKey {
    identity("key").parse().expect("golden key is canonical")
}
fn key_2() -> NarHashKey {
    NarHashKey::from_sha256_bytes([0x22; 32])
}
fn node_a() -> NodeId {
    NodeId::from_bytes([0x11; 32])
}
fn node_b() -> NodeId {
    NodeId::from_bytes([0x22; 32])
}
fn blake3_id() -> Blake3Digest {
    Blake3Digest::from_bytes([0xaa; 32])
}
fn blake3_2() -> Blake3Digest {
    Blake3Digest::from_bytes([0xcc; 32])
}
fn infohash() -> BitTorrentInfoHash {
    BitTorrentInfoHash::v2([0xbb; 32])
}

#[test]
fn golden_identities_match_our_typed_encodings() {
    // The vectors embed these strings inline. If an identity ENCODING drifted,
    // every vector would fail with an opaque byte diff; this check names the
    // drifted identity instead.
    assert_eq!(key().to_string(), identity("key"));
    assert_eq!(key_2().to_string(), identity("key_2"));
    assert_eq!(node_a().to_string(), identity("node_a"));
    assert_eq!(node_b().to_string(), identity("node_b"));
    assert_eq!(blake3_id().to_string(), identity("blake3"));
    assert_eq!(blake3_2().to_string(), identity("blake3_2"));
    assert_eq!(infohash().to_string(), identity("infohash"));
}

#[test]
fn frozen_claim_encoding_is_byte_for_byte_pinned() {
    let claim = Claim {
        schema_version: CLAIM_SCHEMA_VERSION,
        key: key(),
        payload: Some(KnownPayload::WholeNar {
            blake3: blake3_id(),
        }),
        holders: vec![node_a(), node_b()],
        transports: vec![
            KnownTransport::Iroh { node: node_a() },
            KnownTransport::BitTorrent {
                infohash: infohash(),
            },
        ],
        relay: None,
        signatures: vec![],
    };
    let expected = wire("claim_full");
    assert_eq!(
        String::from_utf8(encode_claim(&claim).expect("encode")).expect("utf8"),
        expected,
        "the frozen claim encoding changed - this splits the network unless \
         schema_version is bumped"
    );
    assert_eq!(
        decode_claim(expected.as_bytes()).expect("the golden wire must still decode"),
        claim
    );
}

#[test]
fn frozen_hold_query_encoding_is_byte_for_byte_pinned() {
    let query = HoldQuery {
        schema_version: QUERY_SCHEMA_VERSION,
        key: key(),
    };
    let expected = wire("hold_query");
    assert_eq!(
        String::from_utf8(encode_hold_query(&query).expect("encode")).expect("utf8"),
        expected,
        "the SINGLE-KEY hold query must be unchanged by the task-91 batch addition"
    );
    assert_eq!(
        decode_hold_query(expected.as_bytes()).expect("the golden wire must still decode"),
        query
    );
}

#[test]
fn frozen_hold_response_encodings_are_byte_for_byte_pinned() {
    let have = HoldResponse {
        schema_version: QUERY_SCHEMA_VERSION,
        answer: HoldAnswer::Have {
            blake3: blake3_id(),
            offers: vec![KnownTransport::Iroh { node: node_a() }],
        },
    };
    let absent = HoldResponse {
        schema_version: QUERY_SCHEMA_VERSION,
        answer: HoldAnswer::Absent,
    };
    for (response, name) in [
        (have, "hold_response_have"),
        (absent, "hold_response_absent"),
    ] {
        let expected = wire(name);
        assert_eq!(
            String::from_utf8(encode_hold_response(&response).expect("encode")).expect("utf8"),
            expected,
            "the frozen {name} encoding changed"
        );
        assert_eq!(
            decode_hold_response(expected.as_bytes()).expect("the golden wire must still decode"),
            response
        );
    }
}

// ---- the task-91 ADDITIONS, pinned from the day they land ------------------
//
// These are new in this change, so pinning them costs nothing now and is what
// makes the NEXT change to them visible. They are deliberately in the same file
// as the frozen four: a reader comparing them can see that the batch form ADDS
// message kinds and does not touch the existing ones.

#[test]
fn batch_hold_query_encoding_is_pinned() {
    let query = BatchHoldQuery {
        schema_version: QUERY_SCHEMA_VERSION,
        keys: vec![key(), key_2()],
    };
    let expected = wire("batch_hold_query");
    assert_eq!(
        String::from_utf8(encode_batch_hold_query(&query).expect("encode")).expect("utf8"),
        expected
    );
    assert_eq!(
        decode_batch_hold_query(expected.as_bytes()).expect("decode"),
        query
    );
}

#[test]
fn batch_hold_response_encoding_is_pinned() {
    let response = BatchHoldResponse {
        schema_version: QUERY_SCHEMA_VERSION,
        offers: vec![KnownTransport::Iroh { node: node_b() }],
        answers: vec![
            BatchHoldAnswer::Have {
                blake3: blake3_id(),
            },
            BatchHoldAnswer::Absent,
            BatchHoldAnswer::Have { blake3: blake3_2() },
        ],
    };
    let expected = wire("batch_hold_response");
    assert_eq!(
        String::from_utf8(encode_batch_hold_response(&response).expect("encode")).expect("utf8"),
        expected
    );
    assert_eq!(
        decode_batch_hold_response(expected.as_bytes(), response.answers.len()).expect("decode"),
        response
    );
}

#[test]
fn batch_hold_response_carries_no_keys_of_its_own() {
    // THE no-enumeration property, asserted on the actual BYTES: a batch answer
    // is positional over the keys the ASKER named, so there is no field on the
    // wire in which a peer could name a hash the asker did not ask about. If a
    // future change adds a `key` (or `keys`) field to the response, this fails.
    let on_wire: serde_json::Value =
        serde_json::from_str(&wire("batch_hold_response")).expect("valid JSON");
    let object = on_wire.as_object().expect("a JSON object");
    // (`serde_json::Value` sorts object keys, so this is a SET check; the field
    // ORDER on the wire is what the byte-for-byte vector above pins.)
    assert_eq!(
        object.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["answers", "offers", "schema_version"],
        "a batch response has exactly these three fields - none of them names a hash"
    );
    for answer in on_wire["answers"].as_array().expect("answers is an array") {
        let fields: Vec<&str> = answer
            .as_object()
            .expect("an answer object")
            .keys()
            .map(String::as_str)
            .collect();
        assert!(
            !fields.contains(&"key"),
            "an answer entry must not name a NarHash: {answer}"
        );
    }
    // And the whole wire contains no `sha256:` string at all: the NarHash keys
    // exist ONLY in the asker's own query.
    assert!(
        !wire("batch_hold_response").contains("sha256:"),
        "a batch response must not echo any NarHash key back"
    );
}
