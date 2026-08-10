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
//! ## The hole this file shipped with, and what closed it
//!
//! The first version pinned only vectors whose optional fields were POPULATED, so
//! it was blind to a whole class of change: adding
//! `skip_serializing_if = "Vec::is_empty"` to `HoldAnswer::Have::offers` alters
//! the legal legacy bytes of an empty-offers Have, and removing `serde(default)`
//! alters which wires we still accept. BOTH mutations left all seven tests green.
//! So the file now carries two extra kinds of vector:
//!
//!   * an EMPTY/DEFAULTED encoding vector wherever an optional field exists, and
//!   * `decode-only` vectors: legal inputs we must keep ACCEPTING but never emit
//!     (an omitted defaulted field, a dropped unknown transport kind).
//!
//! It also pins the RESERVED v2 fields populated (`relay.blob`,
//! `signatures[].key_id`, `signatures[].sig`). Those fields exist so that v2 needs
//! no wire break; leaving them `None`/empty in every vector meant their names were
//! free to be renamed with the freeze audit still green.
//!
//! `every_golden_vector_is_exercised` asserts the file and this test cannot drift
//! apart: a vector added to the JSON and not asserted here fails the suite.
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
    BatchHoldAnswer, BatchHoldQuery, BatchHoldResponse, Blake3Digest, Claim, ClaimSignature,
    HoldAnswer, HoldQuery, HoldResponse, KnownPayload, KnownTransport, NarHashKey, NodeId,
    SignedNarinfoRelay, decode_batch_hold_query, decode_batch_hold_response, decode_claim,
    decode_hold_query, decode_hold_response, encode_batch_hold_query, encode_batch_hold_response,
    encode_claim, encode_hold_query, encode_hold_response,
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
fn infohash_2() -> BitTorrentInfoHash {
    BitTorrentInfoHash::v2([0xdd; 32])
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
    assert_eq!(infohash_2().to_string(), identity("infohash_2"));
}

/// EVERY vector name in the committed file, in file order. The file is data and
/// this list is the code that consumes it; keeping them equal is what stops a
/// vector from being added (or silently dropped) without an assertion behind it.
const EXERCISED: &[&str] = &[
    "claim_full",
    "claim_v2_reserved_fields",
    "claim_transports_omitted",
    "claim_unknown_transport_dropped",
    "hold_query",
    "hold_response_have",
    "hold_response_have_empty_offers",
    "hold_response_have_offers_omitted",
    "hold_response_absent",
    "batch_hold_query",
    "batch_hold_response",
    "batch_hold_response_all_absent",
    "batch_hold_response_distinct_locators",
    "batch_hold_response_unknown_transport_slot",
    "batch_hold_response_have_empty_offer_indices",
    "reject_claim_known_transport_with_stray_blake3",
    "reject_claim_known_payload_with_unknown_field",
    "reject_batch_hold_query_unknown_field",
    "reject_batch_response_offer_bound_to_no_answer",
    "reject_batch_response_two_locators_of_one_kind",
    "reject_batch_answer_absent_with_a_field",
];

#[test]
fn every_golden_vector_is_exercised() {
    let doc = golden();
    let present: Vec<String> = doc["vectors"]
        .as_array()
        .expect("vectors is an array")
        .iter()
        .map(|v| v["name"].as_str().expect("a name").to_string())
        .collect();
    let listed: Vec<String> = EXERCISED.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        present, listed,
        "the golden file and the tests that consume it have drifted - a vector \
         nobody asserts is a vector that pins nothing"
    );
    // ...and each vector must declare which direction(s) it claims.
    for vector in doc["vectors"].as_array().expect("array") {
        let direction = vector["direction"].as_str().expect("a direction");
        assert!(
            direction == "both" || direction == "decode-only" || direction == "reject",
            "vector {} declares an unknown direction {direction:?}",
            vector["name"]
        );
    }
    // The reject class must be NON-EMPTY. Without it this file could only pin what
    // we emit, so every acceptance-widening change - dropping a
    // `deny_unknown_fields`, loosening a binding rule - passed by construction.
    assert!(
        doc["vectors"]
            .as_array()
            .expect("array")
            .iter()
            .filter(|v| v["direction"] == "reject")
            .count()
            >= 6,
        "the must-REJECT vector class must not be emptied"
    );
}

/// Every `reject` vector, decoded by the codec entry point its shape names. A
/// wire we must refuse is as much part of the freeze as one we must accept, and
/// nothing in this file could express it before.
#[test]
fn every_reject_vector_is_refused() {
    for vector in golden()["vectors"].as_array().expect("array") {
        if vector["direction"] != "reject" {
            continue;
        }
        let name = vector["name"].as_str().expect("a name");
        let bytes = vector["wire"].as_str().expect("a wire").as_bytes().to_vec();
        let outcome: Result<(), String> = if name.starts_with("reject_claim") {
            decode_claim(&bytes)
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        } else if name.starts_with("reject_batch_hold_query") {
            decode_batch_hold_query(&bytes)
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        } else {
            // Every remaining reject vector is a batch RESPONSE with one answer.
            decode_batch_hold_response(&bytes, 1)
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        };
        assert!(
            outcome.is_err(),
            "golden vector `{name}` must be REFUSED and was accepted: {}",
            vector["note"].as_str().unwrap_or("")
        );
    }
}

#[test]
fn batch_hold_response_have_empty_offer_indices_is_pinned() {
    // An empty `offer_indices` is legal and reachable, and no other vector has
    // one - so `skip_serializing_if` on that field changed only THESE bytes.
    let response = BatchHoldResponse {
        schema_version: QUERY_SCHEMA_VERSION,
        offers: vec![],
        answers: vec![BatchHoldAnswer::Have {
            blake3: blake3_id(),
            offer_indices: vec![],
        }],
    };
    let expected = wire("batch_hold_response_have_empty_offer_indices");
    assert_eq!(
        String::from_utf8(encode_batch_hold_response(&response).expect("encode")).unwrap(),
        expected,
        "the empty-offer_indices encoding drifted"
    );
    let decoded = decode_batch_hold_response(expected.as_bytes(), 1).expect("decode");
    assert_eq!(decoded, response);
}

// ---- the FROZEN four, pinned in both directions ----------------------------

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
fn the_reserved_v2_claim_fields_are_pinned_populated() {
    // `claim_full` leaves relay=None and signatures=[], so BOTH are omitted from
    // its wire and their field NAMES are pinned by nothing: renaming
    // `SignedNarinfoRelay::blob` passed the entire golden suite. These fields
    // exist so that v2 needs no wire break, which makes their names part of the
    // freeze, not a v2 decision.
    let claim = Claim {
        schema_version: CLAIM_SCHEMA_VERSION,
        key: key(),
        payload: Some(KnownPayload::WholeNar {
            blake3: blake3_id(),
        }),
        holders: vec![node_a()],
        transports: vec![KnownTransport::Iroh { node: node_a() }],
        relay: Some(SignedNarinfoRelay {
            blob: "opaque-v2-narinfo-blob".to_string(),
        }),
        signatures: vec![ClaimSignature {
            key_id: "opaque-v2-key-id".to_string(),
            sig: "opaque-v2-signature".to_string(),
        }],
    };
    let expected = wire("claim_v2_reserved_fields");
    assert_eq!(
        String::from_utf8(encode_claim(&claim).expect("encode")).expect("utf8"),
        expected,
        "a RESERVED v2 field name changed - v2 would need a wire break after all"
    );
    assert_eq!(
        decode_claim(expected.as_bytes()).expect("the golden wire must still decode"),
        claim
    );
}

#[test]
fn accepted_legacy_claim_inputs_still_decode() {
    // DECODE-ONLY. These are wires we must keep accepting and do not emit, so no
    // encoding vector can see them change. Removing `serde(default)` from
    // `transports`, or making an unknown transport kind a hard error, leaves every
    // emitted byte in this file identical.
    let omitted = decode_claim(wire("claim_transports_omitted").as_bytes())
        .expect("a claim with no transports field must still decode");
    assert_eq!(
        omitted.transports,
        vec![],
        "an omitted transports field defaults to an empty offer set"
    );

    let dropped = decode_claim(wire("claim_unknown_transport_dropped").as_bytes())
        .expect("an unknown transport KIND is tolerated, not fatal");
    assert_eq!(
        dropped.transports,
        vec![
            KnownTransport::Iroh { node: node_a() },
            KnownTransport::BitTorrent {
                infohash: infohash()
            },
        ],
        "the unknown kind is dropped and the known ones keep their order"
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
    // The EMPTY-offers Have is a separate vector on purpose: it is the only one
    // that can see `skip_serializing_if = "Vec::is_empty"` being added, which
    // changes these legal legacy bytes while leaving the non-empty vector alone.
    let have_empty = HoldResponse {
        schema_version: QUERY_SCHEMA_VERSION,
        answer: HoldAnswer::Have {
            blake3: blake3_id(),
            offers: vec![],
        },
    };
    let absent = HoldResponse {
        schema_version: QUERY_SCHEMA_VERSION,
        answer: HoldAnswer::Absent,
    };
    for (response, name) in [
        (have, "hold_response_have"),
        (have_empty, "hold_response_have_empty_offers"),
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

#[test]
fn an_accepted_hold_response_with_offers_omitted_still_decodes() {
    // DECODE-ONLY: `offers` absent entirely. Nothing we emit looks like this, so
    // only an acceptance vector can pin it.
    let decoded = decode_hold_response(wire("hold_response_have_offers_omitted").as_bytes())
        .expect("a Have with no offers field must still decode");
    assert_eq!(
        decoded,
        HoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            answer: HoldAnswer::Have {
                blake3: blake3_id(),
                offers: vec![],
            },
        }
    );
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
                offer_indices: vec![0],
            },
            BatchHoldAnswer::Absent {},
            BatchHoldAnswer::Have {
                blake3: blake3_2(),
                offer_indices: vec![0],
            },
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
fn an_all_absent_batch_response_encoding_is_pinned_with_an_empty_dictionary() {
    // The empty-dictionary encoding, for the same reason `hold_response_have_
    // empty_offers` exists: it is the only vector that can see `offers` gaining a
    // `skip_serializing_if`, and it is also where the "an all-absent response
    // cannot carry a locator" rule shows up on the wire.
    let response = BatchHoldResponse {
        schema_version: QUERY_SCHEMA_VERSION,
        offers: vec![],
        answers: vec![BatchHoldAnswer::Absent {}, BatchHoldAnswer::Absent {}],
    };
    let expected = wire("batch_hold_response_all_absent");
    assert_eq!(
        String::from_utf8(encode_batch_hold_response(&response).expect("encode")).expect("utf8"),
        expected
    );
    assert_eq!(
        decode_batch_hold_response(expected.as_bytes(), 2).expect("decode"),
        response
    );
}

#[test]
fn each_have_keeps_its_own_content_specific_locator() {
    // THE regression vector. Two keys, two DIFFERENT BitTorrent infohashes (a
    // per-CONTENT coordinate), one shared iroh locator (a per-PEER coordinate).
    // Under the earlier response-wide offer list this was inexpressible: every
    // Have shared one list, so key 2's claim silently carried key 1's infohash.
    let response = BatchHoldResponse {
        schema_version: QUERY_SCHEMA_VERSION,
        offers: vec![
            KnownTransport::Iroh { node: node_b() },
            KnownTransport::BitTorrent {
                infohash: infohash(),
            },
            KnownTransport::BitTorrent {
                infohash: infohash_2(),
            },
        ],
        answers: vec![
            BatchHoldAnswer::Have {
                blake3: blake3_id(),
                offer_indices: vec![0, 1],
            },
            BatchHoldAnswer::Have {
                blake3: blake3_2(),
                offer_indices: vec![0, 2],
            },
        ],
    };
    let expected = wire("batch_hold_response_distinct_locators");
    assert_eq!(
        String::from_utf8(encode_batch_hold_response(&response).expect("encode")).expect("utf8"),
        expected
    );
    let decoded = decode_batch_hold_response(expected.as_bytes(), 2).expect("decode");
    assert_eq!(decoded, response);

    // ...and stated as the property, not just as bytes: each answer resolves to
    // its own infohash and neither sees the other's.
    let locators = |at: usize| -> Vec<KnownTransport> {
        let BatchHoldAnswer::Have { offer_indices, .. } = &decoded.answers[at] else {
            panic!("answer {at} must be a Have");
        };
        offer_indices
            .iter()
            .map(|i| decoded.offers[usize::from(*i)].clone())
            .collect()
    };
    assert!(locators(0).contains(&KnownTransport::BitTorrent {
        infohash: infohash()
    }));
    assert!(!locators(0).contains(&KnownTransport::BitTorrent {
        infohash: infohash_2()
    }));
    assert!(locators(1).contains(&KnownTransport::BitTorrent {
        infohash: infohash_2()
    }));
    assert!(!locators(1).contains(&KnownTransport::BitTorrent {
        infohash: infohash()
    }));
}

#[test]
fn an_unknown_transport_slot_is_dropped_and_the_indices_are_rewritten() {
    // DECODE-ONLY, and the rule most likely to be broken by a well-meaning
    // simplification: tolerate-but-drop on an INDEXED dictionary must compact and
    // re-index together, or the second Have's index 2 lands on nothing (or, worse,
    // on a different locator after a later element shifts down).
    let decoded = decode_batch_hold_response(
        wire("batch_hold_response_unknown_transport_slot").as_bytes(),
        2,
    )
    .expect("an unknown transport kind is tolerated, not fatal");
    assert_eq!(
        decoded,
        BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            offers: vec![
                KnownTransport::Iroh { node: node_b() },
                KnownTransport::BitTorrent {
                    infohash: infohash()
                },
            ],
            answers: vec![
                BatchHoldAnswer::Have {
                    blake3: blake3_id(),
                    // was [0, 1]; the carrier_pigeon slot at 1 was dropped, so this
                    // Have keeps only the locator this build can actually speak.
                    offer_indices: vec![0],
                },
                BatchHoldAnswer::Have {
                    blake3: blake3_2(),
                    // was 2 on the wire; index 2 slid down to 1 with its locator.
                    offer_indices: vec![1],
                },
            ],
        }
    );
}

#[test]
fn batch_hold_response_carries_no_keys_of_its_own() {
    // THE no-enumeration property, asserted on the actual BYTES: a batch answer
    // is positional over the keys the ASKER named, so there is no field on the
    // wire in which a peer could name a hash the asker did not ask about. If a
    // future change adds a `key` (or `keys`) field to the response, this fails.
    for name in [
        "batch_hold_response",
        "batch_hold_response_all_absent",
        "batch_hold_response_distinct_locators",
    ] {
        let on_wire: serde_json::Value = serde_json::from_str(&wire(name)).expect("valid JSON");
        let object = on_wire.as_object().expect("a JSON object");
        // (`serde_json::Value` sorts object keys, so this is a SET check; the field
        // ORDER on the wire is what the byte-for-byte vectors above pin.)
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["answers", "offers", "schema_version"],
            "{name}: a batch response has exactly these three fields - none of them \
             names a hash"
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
                "{name}: an answer entry must not name a NarHash: {answer}"
            );
        }
        // And the whole wire contains no `sha256:` string at all: the NarHash keys
        // exist ONLY in the asker's own query.
        assert!(
            !wire(name).contains("sha256:"),
            "{name}: a batch response must not echo any NarHash key back"
        );
    }
}
