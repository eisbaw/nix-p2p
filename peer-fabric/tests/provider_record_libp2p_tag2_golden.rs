//! Byte-level compatibility contract for TASK-156's additive ProviderRecord tag 2.
//!
//! The original `provider_record_v1.json` remains the immutable TASK-126 anchor.
//! This separate schema-v1 fixture pins only the additive libp2p offer layout and
//! proves both sides of the rolling-upgrade rule: an upgraded reader accepts tag 2,
//! while a historical v1 reader that knows only tags 0 and 1 fails closed with
//! `UnknownOffer { tag: 2 }`.

use ed25519_dalek::SigningKey;
use peer_fabric::{
    Blake3Digest, ContentKey, InfoHash, NodeId, PROVIDER_RECORD_SCHEMA_VERSION, ProviderAssertion,
    ProviderRecord, RecordDecodeError, RelayHints, TransportOffer, TransportTag,
    decode_provider_assertion, encode_provider_record, sign_provider_record,
};

const GOLDEN: &str = include_str!("golden/provider_record_libp2p_tag2.json");
const SIGNATURE_LEN: usize = 64;

fn golden() -> serde_json::Value {
    serde_json::from_str(GOLDEN).expect("golden/provider_record_libp2p_tag2.json is valid JSON")
}

fn hexd(value: &str) -> Vec<u8> {
    assert!(
        value.len().is_multiple_of(2),
        "hex must have even length: {value:?}"
    );
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("valid hex"))
        .collect()
}

fn bytes32(value: &str) -> [u8; 32] {
    hexd(value).try_into().expect("32-byte golden field")
}

fn hexe(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key(document: &serde_json::Value) -> ContentKey {
    ContentKey::from_bytes(bytes32(document["identity"]["key_hex"].as_str().unwrap()))
}

fn signer(document: &serde_json::Value) -> SigningKey {
    SigningKey::from_bytes(&bytes32(
        document["identity"]["signer_seed_hex"].as_str().unwrap(),
    ))
}

fn positive_record(document: &serde_json::Value, vector: &serde_json::Value) -> ProviderRecord {
    let signer = signer(document);
    let provider = NodeId::from_bytes(signer.verifying_key().to_bytes());
    let relay_nodes: Vec<NodeId> = vector["relay_hints_hex"]
        .as_array()
        .expect("relay_hints_hex is an array")
        .iter()
        .map(|relay| NodeId::from_bytes(bytes32(relay.as_str().unwrap())))
        .collect();
    let relay_hints = RelayHints::try_from(relay_nodes.as_slice())
        .expect("positive golden relay hints are valid and canonical");

    let libp2p = TransportOffer::Libp2p {
        node: provider,
        relay_hints,
    };
    let offers = if vector["name"] == "mixed_iroh_bittorrent_libp2p" {
        // Deliberately construct in reverse tag order. sign_provider_record is the
        // integration site that canonicalises the set to wire tags 0, 1, 2.
        vec![
            libp2p,
            TransportOffer::BitTorrent {
                infohash: InfoHash::V1(
                    hexd(vector["bittorrent_v1_hex"].as_str().unwrap())
                        .try_into()
                        .expect("20-byte v1 infohash"),
                ),
            },
            TransportOffer::Iroh { node: provider },
        ]
    } else {
        vec![libp2p]
    };

    sign_provider_record(
        &signer,
        &ProviderRecord {
            key: key(document),
            content: Blake3Digest::from_bytes(bytes32(
                document["identity"]["content_hex"].as_str().unwrap(),
            )),
            provider,
            offers,
            sequence: vector["sequence"].as_u64().expect("sequence is a u64"),
            issued_at: 100,
            expiry: 1_000,
            signature: [0; SIGNATURE_LEN],
        },
    )
}

#[test]
fn upgraded_codec_emits_and_accepts_every_tag2_positive_vector() {
    let document = golden();
    assert_eq!(
        PROVIDER_RECORD_SCHEMA_VERSION, 1,
        "tag 2 is additive inside schema v1, not a schema-version bump"
    );
    assert_eq!(document["layout"]["schema_version"], 1);
    assert_eq!(document["layout"]["offer_libp2p_tag"], 2);

    let mut positives = 0;
    for vector in document["vectors"].as_array().expect("vectors is an array") {
        if vector["direction"] != "both" {
            continue;
        }
        positives += 1;
        let name = vector["name"].as_str().expect("vector name");
        let expected_wire = hexd(vector["wire_hex"].as_str().expect("wire_hex"));
        let record = positive_record(&document, vector);

        if name == "mixed_iroh_bittorrent_libp2p" {
            let tags: Vec<TransportTag> = record.offers.iter().map(TransportTag::of).collect();
            assert_eq!(
                tags,
                [
                    TransportTag::Iroh,
                    TransportTag::BitTorrent,
                    TransportTag::Libp2p,
                ],
                "the mixed tournament offer set was not canonicalised to tags 0/1/2"
            );
        }

        assert_eq!(
            encode_provider_record(&record).expect("encode positive tag-2 record"),
            expected_wire,
            "tag-2 encoder drifted for `{name}`"
        );
        assert_eq!(
            decode_provider_assertion(&expected_wire, &key(&document), 500)
                .expect("upgraded reader accepts positive tag-2 record"),
            ProviderAssertion::Provide(record),
            "tag-2 decoder drifted for `{name}`"
        );
    }
    assert_eq!(
        positives, 4,
        "the 0/1/2-hint plus mixed-tournament positive matrix drifted"
    );
}

fn decode_error_name(error: &RecordDecodeError) -> &'static str {
    match error {
        RecordDecodeError::Oversized { .. } => "Oversized",
        RecordDecodeError::Truncated { .. } => "Truncated",
        RecordDecodeError::TrailingBytes { .. } => "TrailingBytes",
        RecordDecodeError::UnknownVersion { .. } => "UnknownVersion",
        RecordDecodeError::UnknownKind { .. } => "UnknownKind",
        RecordDecodeError::UnknownOffer { .. } => "UnknownOffer",
        RecordDecodeError::BadInfoHash { .. } => "BadInfoHash",
        RecordDecodeError::TooManyOffers { .. } => "TooManyOffers",
        RecordDecodeError::OffersNotCanonical => "OffersNotCanonical",
        RecordDecodeError::IrohNodeNotProvider { .. } => "IrohNodeNotProvider",
        RecordDecodeError::Libp2pNodeNotProvider { .. } => "Libp2pNodeNotProvider",
        RecordDecodeError::TooManyRelayHints { .. } => "TooManyRelayHints",
        RecordDecodeError::RelayHintsNotCanonical => "RelayHintsNotCanonical",
        RecordDecodeError::BadRelayIdentity { .. } => "BadRelayIdentity",
        RecordDecodeError::Libp2pRelayIsProvider { .. } => "Libp2pRelayIsProvider",
        RecordDecodeError::MultipleLibp2pOffers { .. } => "MultipleLibp2pOffers",
        RecordDecodeError::BadProviderKey => "BadProviderKey",
        RecordDecodeError::NonCanonicalSignature => "NonCanonicalSignature",
        RecordDecodeError::BadSignature => "BadSignature",
        RecordDecodeError::WrongKey { .. } => "WrongKey",
        RecordDecodeError::Stale { .. } => "Stale",
    }
}

fn decode_error_fields(error: &RecordDecodeError) -> serde_json::Value {
    match error {
        RecordDecodeError::Oversized { len, cap } => {
            serde_json::json!({ "len": len, "cap": cap })
        }
        RecordDecodeError::Truncated { need, have } => {
            serde_json::json!({ "need": need, "have": have })
        }
        RecordDecodeError::TrailingBytes { extra } => serde_json::json!({ "extra": extra }),
        RecordDecodeError::UnknownVersion { found, expected } => {
            serde_json::json!({ "found": found, "expected": expected })
        }
        RecordDecodeError::UnknownKind { found } => serde_json::json!({ "found": found }),
        RecordDecodeError::UnknownOffer { tag } => serde_json::json!({ "tag": tag }),
        RecordDecodeError::BadInfoHash { version } => {
            serde_json::json!({ "version": version })
        }
        RecordDecodeError::TooManyOffers { found, cap }
        | RecordDecodeError::TooManyRelayHints { found, cap } => {
            serde_json::json!({ "found": found, "cap": cap })
        }
        RecordDecodeError::OffersNotCanonical
        | RecordDecodeError::RelayHintsNotCanonical
        | RecordDecodeError::BadProviderKey
        | RecordDecodeError::NonCanonicalSignature
        | RecordDecodeError::BadSignature => serde_json::json!({}),
        RecordDecodeError::IrohNodeNotProvider {
            offer_node,
            provider,
        }
        | RecordDecodeError::Libp2pNodeNotProvider {
            offer_node,
            provider,
        } => serde_json::json!({
            "offer_node_hex": offer_node.to_hex(),
            "provider_hex": provider.to_hex(),
        }),
        RecordDecodeError::BadRelayIdentity { relay } => {
            serde_json::json!({ "relay_hex": relay.to_hex() })
        }
        RecordDecodeError::Libp2pRelayIsProvider { relay, provider } => serde_json::json!({
            "relay_hex": relay.to_hex(),
            "provider_hex": provider.to_hex(),
        }),
        RecordDecodeError::MultipleLibp2pOffers { found } => {
            serde_json::json!({ "found": found })
        }
        RecordDecodeError::WrongKey { expected, found } => serde_json::json!({
            "expected_hex": hexe(expected.as_bytes()),
            "found_hex": hexe(found.as_bytes()),
        }),
        RecordDecodeError::Stale { expiry, now } => {
            serde_json::json!({ "expiry": expiry, "now": now })
        }
    }
}

#[test]
fn upgraded_codec_refuses_every_tag2_reject_vector_for_the_pinned_reason() {
    let document = golden();
    let mut rejects = 0;
    for vector in document["vectors"].as_array().expect("vectors is an array") {
        if vector["direction"] != "reject" {
            continue;
        }
        rejects += 1;
        let name = vector["name"].as_str().expect("vector name");
        let expected = vector["reject_reason"].as_str().expect("reject_reason");
        let expected_fields = &vector["reject_fields"];
        let wire = hexd(vector["wire_hex"].as_str().expect("wire_hex"));
        let error = match decode_provider_assertion(&wire, &key(&document), 500) {
            Ok(assertion) => panic!("reject vector `{name}` was accepted as {assertion:?}"),
            Err(error) => error,
        };
        assert_eq!(
            decode_error_name(&error),
            expected,
            "reject vector `{name}` failed at the wrong guard: {error:?}"
        );
        assert_eq!(
            &decode_error_fields(&error),
            expected_fields,
            "reject vector `{name}` had the right variant but wrong typed payload: {error:?}"
        );
    }
    assert!(rejects >= 11, "the tag-2 reject matrix was weakened");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoricalV1Error {
    UnknownOffer { tag: u8 },
    Malformed,
}

/// Minimal historical schema-v1 reader: it deliberately knows only the tag-0 Iroh
/// and tag-1 BitTorrent layouts that existed before TASK-156. It is test-local so it
/// cannot accidentally share the upgraded Rust decoder's tag table.
fn historical_v1_read(wire: &[u8]) -> Result<(), HistoricalV1Error> {
    let body = wire
        .get(
            ..wire
                .len()
                .checked_sub(SIGNATURE_LEN)
                .ok_or(HistoricalV1Error::Malformed)?,
        )
        .ok_or(HistoricalV1Error::Malformed)?;
    let mut cursor = 0usize;
    let mut take = |count: usize| {
        let bytes = body.get(cursor..cursor.saturating_add(count));
        cursor = cursor.saturating_add(count);
        bytes.ok_or(HistoricalV1Error::Malformed)
    };

    if take(2)? != [0, 1] || take(1)? != [0] {
        return Err(HistoricalV1Error::Malformed);
    }
    take(32 + 32 + 8 + 8 + 8 + 32)?;
    let offer_count = take(1)?[0] as usize;
    for _ in 0..offer_count {
        match take(1)?[0] {
            0 => {
                take(32)?;
            }
            1 => match take(1)?[0] {
                1 => {
                    take(20)?;
                }
                2 => {
                    take(32)?;
                }
                _ => return Err(HistoricalV1Error::Malformed),
            },
            tag => return Err(HistoricalV1Error::UnknownOffer { tag }),
        }
    }
    if cursor != body.len() {
        return Err(HistoricalV1Error::Malformed);
    }
    Ok(())
}

#[test]
fn historical_v1_reader_fails_closed_on_every_tag2_positive() {
    let document = golden();
    for vector in document["vectors"].as_array().expect("vectors is an array") {
        if vector["direction"] != "both" {
            continue;
        }
        let name = vector["name"].as_str().expect("vector name");
        let wire = hexd(vector["wire_hex"].as_str().expect("wire_hex"));
        assert_eq!(
            historical_v1_read(&wire),
            Err(HistoricalV1Error::UnknownOffer { tag: 2 }),
            "historical reader did not fail closed on `{name}`"
        );
    }
}

#[test]
fn historical_unknown_offer_guard_bites_on_the_tag_discriminant() {
    let document = golden();
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == "libp2p_zero_hints")
        .expect("zero-hint vector");
    let mut wire = hexd(vector["wire_hex"].as_str().unwrap());

    let tag_offset = 2 + 1 + 32 + 32 + 8 + 8 + 8 + 32 + 1;
    assert_eq!(wire[tag_offset], 2, "fixture tag offset drifted");
    wire[tag_offset] = 0;
    assert_ne!(
        historical_v1_read(&wire),
        Err(HistoricalV1Error::UnknownOffer { tag: 2 }),
        "changing the discriminant must disarm the historical UnknownOffer bite"
    );
}

#[test]
fn every_tag2_golden_vector_is_named_once_and_consumed() {
    const EXPECTED: &[&str] = &[
        "libp2p_zero_hints",
        "libp2p_one_hint",
        "libp2p_two_hints",
        "mixed_iroh_bittorrent_libp2p",
        "reject_tampered_signed_body",
        "reject_relay_hint_signed_body_tamper",
        "reject_truncated_hint",
        "reject_over_cap_hints",
        "reject_duplicate_hints",
        "reject_descending_hints",
        "reject_invalid_relay_identity",
        "reject_small_order_relay_identity",
        "reject_self_relay",
        "reject_node_not_provider",
        "reject_multiple_libp2p_offers",
    ];
    let document = golden();
    let actual: Vec<&str> = document["vectors"]
        .as_array()
        .expect("vectors is an array")
        .iter()
        .map(|vector| vector["name"].as_str().expect("vector name"))
        .collect();
    assert_eq!(actual, EXPECTED, "golden vectors and consumers drifted");

    // A compact extra byte pin: this independently checks the formatter used by the
    // encoder assertions rather than trusting JSON-to-byte conversion in one direction.
    assert_eq!(
        hexe(&hexd(
            document["identity"]["provider_hex"].as_str().unwrap()
        )),
        document["identity"]["provider_hex"].as_str().unwrap()
    );
}
