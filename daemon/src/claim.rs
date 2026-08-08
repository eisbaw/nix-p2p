//! The p2p CLAIM wire format: the network's shared language (wave-2, task-37).
//!
//! Two versioned wire surfaces live here, and ONLY these types - no transport,
//! no DHT, no discovery logic (those consume this module: task-38 the transport
//! trait, task-40 discovery, task-50 the availability index that PRODUCES
//! claims):
//!
//!   * [`Claim`] - a peer's assertion "this content identity is held, here is
//!     how to fetch it". Exchanged PEER-TO-PEER (see the DHT note below), and
//!     potentially RELAYED through intermediary peers, so it must survive being
//!     parsed by a peer that does not understand every variant it carries
//!     (forward-compat).
//!   * [`HoldQuery`] / [`HoldResponse`] - the versioned yes/no probe envelope
//!     ("do you hold NarHash X?"). A request names ONE concrete NarHash; the
//!     response is have-with-offer or absent. There is deliberately NO "list
//!     your holdings" message - enumeration would leak the secret store-path
//!     names a node holds (PRD privacy invariant).
//!
//! ## DHT-is-rendezvous model (why the claim is NOT a DHT record)
//!
//! The wave-2b DHT (task-47 spike) maps a `NarHash`-derived key -> a set of
//! candidate `NodeId`s and NOTHING MORE: mainline `get_peers` cannot carry a
//! structured claim record. So a claim is NEVER stored in the DHT. The flow is:
//! DHT (or gossip) gives you candidate NodeIds; you send each a [`HoldQuery`];
//! a holder answers with a [`HoldResponse`] carrying a [`Claim`]/offer. This
//! module is therefore the PEER-TO-PEER wire format, deliberately designed so it
//! does NOT assume any DHT transports it. DHT key derivation is out of scope here
//! (task-47).
//!
//! ## Forward-compat model (two DIFFERENT axes, do not conflate)
//!
//!   * Unknown VARIANT, same schema_version: a newer peer sends a payload or
//!     transport this build does not know (a future `CastoreRoot` payload, a
//!     third transport). We parse the claim, keep the unknown variant VERBATIM
//!     (so relaying it does not destroy a future peer's data), and IGNORE it in
//!     logic - never an error. See [`ClaimPayload::Unknown`] /
//!     [`TransportOffer::Unknown`].
//!   * Wrong schema_version: a hard network-split boundary. [`decode_claim`] /
//!     [`decode_hold_query`] / [`decode_hold_response`] REJECT it cleanly
//!     (`Err`, never a panic, never a silent accept). The `schema_version` field
//!     being present is not enough - it is CHECKED. The tests prove raw serde
//!     accepts a v999 record while `decode_*` rejects it, so the check, not the
//!     parser, is what draws the line.
//!
//! The claim (relayed) needs the in-band variant-forward-compat above; the query
//! ENVELOPE is point-to-point request/response, so it evolves by version bump
//! only and carries no variant catch-all of its own - its embedded transport
//! OFFERS still get the offer-level forward-compat, which is where it matters.
//!
//! ## Codec (draft; the binary wire codec is a velocity surface, not frozen)
//!
//! The types derive serde; the concrete codec used here for tests and the
//! current `encode_*`/`decode_*` helpers is JSON (deterministic field order,
//! sorted maps - golden-vector friendly). The FINAL on-wire codec (a compact
//! binary form: CBOR/postcard) is a wave-2 velocity surface and is chosen later;
//! the serde derives keep the record codec-agnostic. One honest coupling: the
//! [`ClaimPayload::Unknown`] / [`TransportOffer::Unknown`] catch-all holds a
//! `serde_json::Value`, which is JSON-shaped; when the binary codec is frozen the
//! catch-all's value type is revisited (follow-up filed to task-48).
//!
//! ## What is NOT frozen here (honest deferral to task-48)
//!
//! The exact BYTE encoding of the addressed unit and of node identity - the
//! raw-NAR-v1 BLAKE3 bytes, the iroh `NodeId`, a BitTorrent infohash - is the
//! task-48 `RawNarV1`/`NodeId` freeze. Here they are `String` newtypes
//! ([`RawNarBlake3`], [`NodeId`], [`BitTorrentInfoHash`]): they round-trip
//! deterministically, but their canonical encoding is TODO(task-48) and is NOT
//! settled by this module.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::source::NarHash;

/// Wire schema version of [`Claim`]. Bumped only on a breaking change; a decoder
/// rejects any other version cleanly (network-split boundary).
pub const CLAIM_SCHEMA_VERSION: u16 = 1;

/// Wire schema version of the [`HoldQuery`]/[`HoldResponse`] envelope. Evolves
/// independently of the claim version.
pub const QUERY_SCHEMA_VERSION: u16 = 1;

// -------------------------------------------------------------------------
// Identity newtypes. Encoding-deferred to task-48 (see module docs). String
// today: deterministic + round-trips, but NOT the frozen canonical byte form.
// -------------------------------------------------------------------------

/// The BLAKE3 of the addressed unit (the raw, uncompressed NAR - Candidate B).
/// This is what a consumer actually fetches by, on any transport; a holder
/// `NodeId` alone is insufficient. TODO(task-48): the exact 32-byte encoding and
/// its string form freeze in the `RawNarV1` freeze, not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawNarBlake3(pub String);

/// A holder's network identity (the iroh `NodeId` / ed25519 public key).
/// TODO(task-48): the canonical 32-byte encoding freezes there; `String` here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeId(pub String);

/// A BitTorrent infohash. Present so the BitTorrent transport is REPRESENTABLE
/// (proves a 2nd transport is not a network fork); no BitTorrent backend exists
/// here (task-38). TODO(task-48): infohash byte form (v1 20-byte / v2 32-byte).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitTorrentInfoHash(pub String);

/// The content identity a claim/query is ABOUT: the signed `NarHash` (the
/// wave-1 [`crate::source::NarKey::SignedNarHash`] seam key, keyed on by the
/// correlation catalog).
///
/// This is the wire-serializable TWIN of the seam's [`NarHash`], kept as its own
/// newtype rather than adding serde to the frozen wave-1 `source.rs`: wire
/// encoding is a claim-layer concern, and the frozen seam type stays untouched.
/// [`From`]/[`NarHashKey::to_nar_hash`] bridge the two so `NarHash` remains the
/// single semantic source of truth. Follow-up (task-48): consider unifying by
/// adding serde to the seam type once its encoding is frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NarHashKey(pub String);

impl NarHashKey {
    pub fn new(value: impl Into<String>) -> Self {
        NarHashKey(value.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Bridge back to the frozen seam identity type.
    pub fn to_nar_hash(&self) -> NarHash {
        NarHash::new(self.0.clone())
    }
}

impl From<&NarHash> for NarHashKey {
    fn from(hash: &NarHash) -> Self {
        NarHashKey(hash.as_str().to_string())
    }
}

// -------------------------------------------------------------------------
// Payload: WHAT content identity the claim is about.
// -------------------------------------------------------------------------

/// What content a claim describes. Forward-compatible: a payload kind this build
/// does not know parses into [`ClaimPayload::Unknown`] VERBATIM and is ignored,
/// never an error (see module forward-compat docs).
///
/// `#[serde(untagged)]` makes the wrapper invisible on the wire: a `Known`
/// serializes as its inner tagged object, an `Unknown` as its raw value. On
/// decode, `Known` is tried first; if the tag is unrecognised the inner
/// (internally-tagged) enum fails and the input is captured as `Unknown`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimPayload {
    Known(KnownPayload),
    /// A payload kind newer than this build (e.g. a future `CastoreRoot`). Kept
    /// verbatim so relaying does not destroy it; ignored by logic.
    Unknown(Value),
}

/// The payload kinds THIS build understands. `WholeNar` (Candidate B) is the
/// only wave-2 kind; `CastoreRoot` (Candidate C chunked) is the reserved future
/// kind and lands here as a new variant later - until then a peer sending it is
/// handled by [`ClaimPayload::Unknown`], which is exactly the evolution path
/// this schema promises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnownPayload {
    /// A whole raw-NAR blob, addressed by its BLAKE3.
    WholeNar { blake3: RawNarBlake3 },
    // future: CastoreRoot { root: CastoreRootDigest, .. }  // task: Candidate C
}

// -------------------------------------------------------------------------
// Transport offer: HOW to fetch the content.
// -------------------------------------------------------------------------

/// One way to fetch the claimed content. Forward-compatible like
/// [`ClaimPayload`]: an unknown transport is kept verbatim and ignored.
///
/// The offer carries what the transport needs to ACTUALLY fetch - for iroh, the
/// holder `NodeId` AND the raw-NAR `RawNarBlake3` (a consumer fetches by BLAKE3;
/// a bare holder identity is insufficient). BitTorrent is a representable
/// variant (a 2nd transport is not a fork) though no backend exists here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransportOffer {
    Known(KnownTransport),
    /// A transport neither side of THIS version knows. Kept verbatim; ignored.
    Unknown(Value),
}

/// The transports THIS build can represent. Only `Iroh` has a fetch backend
/// (task-38); `BitTorrent` is representable to prove the schema admits a 2nd
/// transport without a network fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum KnownTransport {
    /// iroh whole-blob (Candidate B, FIRST priority). Needs the holder `NodeId`
    /// AND the raw-NAR `blake3` to fetch by - both carried here.
    Iroh { node: NodeId, blake3: RawNarBlake3 },
    /// BitTorrent - REPRESENTABLE only, NOT implemented (no backend; task-38).
    /// Present so a 2nd transport is not a network fork. Carries the infohash
    /// AND the raw-NAR `blake3`, because a consumer still verifies/fetches by
    /// BLAKE3 regardless of the swarm addressing. The wire tag is pinned
    /// explicitly (`snake_case` would give the odd `bit_torrent`).
    #[serde(rename = "bittorrent")]
    BitTorrent {
        infohash: BitTorrentInfoHash,
        blake3: RawNarBlake3,
    },
}

// -------------------------------------------------------------------------
// Reserved v2 fields (present, documented, NOT implemented - proven to survive
// a round-trip so v2 needs no wire break).
// -------------------------------------------------------------------------

/// RESERVED for v2: a relayed signed narinfo, letting a peer serve narinfo
/// metadata p2p without cache.nixos.org. NOT implemented in v1 (`None` on every
/// v1 claim). Opaque `blob` now; its structure is a v2 concern. TODO(task-48):
/// define the relayed-narinfo encoding. Present so v2 needs no wire break; the
/// round-trip test proves a populated value survives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedNarinfoRelay {
    /// Opaque relayed-narinfo bytes; unvalidated in v1.
    pub blob: String,
}

/// RESERVED for v2: a signature over the claim, so a consumer can attribute a
/// claim to a key (claim-spam mitigation, PRD risk 6). NOT implemented in v1
/// (empty on every v1 claim). Opaque fields now. TODO(task-48): signature and
/// key-id encoding. Present so v2 needs no wire break; the round-trip test
/// proves populated values survive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSignature {
    /// Which key signed (opaque; an ed25519 public-key id in v2).
    pub key_id: String,
    /// The signature bytes (opaque in v1).
    pub sig: String,
}

// -------------------------------------------------------------------------
// The claim record.
// -------------------------------------------------------------------------

/// A peer's assertion about one content identity: WHAT it is, WHO holds it, HOW
/// to fetch it, with room reserved for v2.
///
/// `holders` and `transports` are distinct on purpose and NOT redundant:
///   * `holders` are the identities ASSERTED to hold the content (the
///     rendezvous-level "who" - the shape a DHT lookup returns, and what a
///     relayed/aggregated claim carries). A claim may list a holder for which no
///     inlined transport offer is present; you would then probe it directly.
///   * `transports` are concrete FETCH coordinates. They cannot be derived from
///     `holders`: a BitTorrent offer's coordinate is an infohash, not a
///     `NodeId`. This is why both fields exist.
///
/// `extra` is a struct-level forward-compat catch-all: unknown TOP-LEVEL fields
/// a future peer adds are captured here and re-emitted on encode, so an old
/// relaying node does not silently drop them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// Wire schema version. CHECKED by [`decode_claim`]; a mismatch is rejected.
    pub schema_version: u16,
    /// The content identity: the signed `NarHash` (wave-1 seam key).
    pub key: NarHashKey,
    /// WHAT content (whole NAR now; future `CastoreRoot`).
    pub payload: ClaimPayload,
    /// WHO is asserted to hold it (rendezvous-level identities).
    pub holders: Vec<NodeId>,
    /// HOW to fetch it (concrete per-transport coordinates).
    pub transports: Vec<TransportOffer>,
    /// RESERVED v2: signed-narinfo relay. `None` in v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<SignedNarinfoRelay>,
    /// RESERVED v2: claim signatures. Empty in v1.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<ClaimSignature>,
    /// Forward-compat: unknown top-level fields from a future peer, kept verbatim.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

// -------------------------------------------------------------------------
// Query envelope: the yes/no "do you hold X?" probe. NO enumeration.
// -------------------------------------------------------------------------

/// A probe: "do you hold this ONE NarHash?". Names a single concrete
/// [`NarHashKey`]. There is deliberately no request that asks a peer to LIST its
/// holdings - enumeration would leak the secret store-path names a node holds
/// (PRD privacy invariant). Versioned; a wrong version is rejected by
/// [`decode_hold_query`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldQuery {
    pub schema_version: u16,
    /// The single content identity being probed.
    pub key: NarHashKey,
}

/// The answer to a [`HoldQuery`]: have-with-offers, or absent. Yes/no ONLY - it
/// never carries a listing of other holdings, and it concerns only the queried
/// hash. The embedded [`TransportOffer`]s still get offer-level forward-compat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
pub enum HoldAnswer {
    /// "Yes, I hold it" + how to fetch it (offers for the queried hash only).
    Have { offers: Vec<TransportOffer> },
    /// "No, I do not hold it."
    Absent,
}

/// The versioned response envelope for a [`HoldQuery`]. The answer is FLATTENED
/// so the wire is `{schema_version, answer, [offers]}` - `answer` is the yes/no
/// tag (`have`/`absent`), not a nested object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldResponse {
    pub schema_version: u16,
    #[serde(flatten)]
    pub answer: HoldAnswer,
}

// -------------------------------------------------------------------------
// Codec + version checking. JSON today (draft); binary later (velocity).
// -------------------------------------------------------------------------

/// Why a wire record/envelope could not be turned into a usable value.
///
/// Fail fast + verbosely: distinct variants so a caller (and a log line) can
/// tell a malformed byte string from a version the network has split on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimCodecError {
    /// Bytes were not a valid wire form for the target type.
    Malformed(String),
    /// The record/envelope declared a schema version this build does not speak.
    /// The field is PRESENT but its value is unsupported - a clean rejection,
    /// not a silent accept.
    UnsupportedVersion { found: u16, expected: u16 },
}

impl std::fmt::Display for ClaimCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimCodecError::Malformed(why) => write!(f, "malformed claim wire form: {why}"),
            ClaimCodecError::UnsupportedVersion { found, expected } => write!(
                f,
                "unsupported schema_version {found} (this build speaks {expected})"
            ),
        }
    }
}

impl std::error::Error for ClaimCodecError {}

/// Encode a claim to its wire bytes (JSON draft codec).
pub fn encode_claim(claim: &Claim) -> Result<Vec<u8>, ClaimCodecError> {
    serde_json::to_vec(claim).map_err(|e| ClaimCodecError::Malformed(e.to_string()))
}

/// Decode + VALIDATE a claim. Parsing alone is not acceptance: the
/// `schema_version` is checked, so a v-other record is rejected cleanly. Unknown
/// payload/transport VARIANTS at the supported version are NOT rejected - they
/// survive as `Unknown` and are ignored by the caller (forward-compat).
pub fn decode_claim(bytes: &[u8]) -> Result<Claim, ClaimCodecError> {
    let claim: Claim =
        serde_json::from_slice(bytes).map_err(|e| ClaimCodecError::Malformed(e.to_string()))?;
    check_version(claim.schema_version, CLAIM_SCHEMA_VERSION)?;
    Ok(claim)
}

/// Encode a hold query to its wire bytes.
pub fn encode_hold_query(query: &HoldQuery) -> Result<Vec<u8>, ClaimCodecError> {
    serde_json::to_vec(query).map_err(|e| ClaimCodecError::Malformed(e.to_string()))
}

/// Decode + validate a hold query (version checked).
pub fn decode_hold_query(bytes: &[u8]) -> Result<HoldQuery, ClaimCodecError> {
    let query: HoldQuery =
        serde_json::from_slice(bytes).map_err(|e| ClaimCodecError::Malformed(e.to_string()))?;
    check_version(query.schema_version, QUERY_SCHEMA_VERSION)?;
    Ok(query)
}

/// Encode a hold response to its wire bytes.
pub fn encode_hold_response(response: &HoldResponse) -> Result<Vec<u8>, ClaimCodecError> {
    serde_json::to_vec(response).map_err(|e| ClaimCodecError::Malformed(e.to_string()))
}

/// Decode + validate a hold response (version checked).
pub fn decode_hold_response(bytes: &[u8]) -> Result<HoldResponse, ClaimCodecError> {
    let response: HoldResponse =
        serde_json::from_slice(bytes).map_err(|e| ClaimCodecError::Malformed(e.to_string()))?;
    check_version(response.schema_version, QUERY_SCHEMA_VERSION)?;
    Ok(response)
}

/// The one place the version gate lives, so claim and envelope share exactly one
/// rule. Fail fast on a mismatch with both numbers in the error.
fn check_version(found: u16, expected: u16) -> Result<(), ClaimCodecError> {
    if found == expected {
        Ok(())
    } else {
        Err(ClaimCodecError::UnsupportedVersion { found, expected })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fully-populated v1 claim (known payload + both transports + reserved
    /// fields set) so round-trip tests exercise every field.
    fn sample_claim() -> Claim {
        Claim {
            schema_version: CLAIM_SCHEMA_VERSION,
            key: NarHashKey::new("sha256:1b2c3d"),
            payload: ClaimPayload::Known(KnownPayload::WholeNar {
                blake3: RawNarBlake3("blake3:aaaa".into()),
            }),
            holders: vec![NodeId("node-a".into()), NodeId("node-b".into())],
            transports: vec![
                TransportOffer::Known(KnownTransport::Iroh {
                    node: NodeId("node-a".into()),
                    blake3: RawNarBlake3("blake3:aaaa".into()),
                }),
                TransportOffer::Known(KnownTransport::BitTorrent {
                    infohash: BitTorrentInfoHash("ih:bbbb".into()),
                    blake3: RawNarBlake3("blake3:aaaa".into()),
                }),
            ],
            relay: None,
            signatures: vec![],
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn claim_round_trips_through_the_codec() {
        let claim = sample_claim();
        let bytes = encode_claim(&claim).expect("encode");
        let back = decode_claim(&bytes).expect("decode");
        assert_eq!(claim, back);
    }

    #[test]
    fn nar_hash_key_bridges_the_frozen_seam_type() {
        let seam = NarHash::new("sha256:deadbeef");
        let key = NarHashKey::from(&seam);
        assert_eq!(key.as_str(), "sha256:deadbeef");
        assert_eq!(key.to_nar_hash(), seam);
    }

    // --- Forward-compat: unknown VARIANT survives, is not an error ---------

    /// A strict payload enum WITHOUT the `Unknown` catch-all. It exists only to
    /// PROVE the catch-all is load-bearing: on the same future-variant bytes,
    /// this one ERRORS (fails-before) while [`ClaimPayload`] succeeds
    /// (passes-after). Without this control the forward-compat test could pass
    /// vacuously.
    #[derive(Debug, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    #[allow(dead_code)]
    enum StrictPayload {
        WholeNar { blake3: RawNarBlake3 },
    }

    /// Bytes a NEWER peer would send: a `castore_root` payload this build does
    /// not know, and a `webseed` transport it does not know, both carrying data.
    fn future_variant_claim_bytes() -> Vec<u8> {
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": "sha256:1b2c3d",
            "payload": { "kind": "castore_root", "digest": "castore:xyz", "chunks": 7 },
            "holders": ["node-a"],
            "transports": [
                { "transport": "iroh", "node": "node-a", "blake3": "blake3:aaaa" },
                { "transport": "webseed", "url": "https://example.invalid/x", "blake3": "blake3:aaaa" }
            ]
        });
        serde_json::to_vec(&wire).unwrap()
    }

    #[test]
    fn unknown_payload_variant_is_rejected_by_a_strict_enum() {
        // fails-before: the naive enum without a catch-all cannot parse a future
        // payload kind.
        let bytes = serde_json::to_vec(
            &serde_json::json!({ "kind": "castore_root", "digest": "castore:xyz" }),
        )
        .unwrap();
        let strict: Result<StrictPayload, _> = serde_json::from_slice(&bytes);
        assert!(
            strict.is_err(),
            "strict enum must reject an unknown payload kind (proves the catch-all matters)"
        );
    }

    #[test]
    fn unknown_variants_parse_and_are_ignored_not_errored() {
        // passes-after: the real types parse a future claim, keeping the unknown
        // payload and transport as `Unknown`, never erroring.
        let claim = decode_claim(&future_variant_claim_bytes())
            .expect("a future-variant claim must decode, not error");

        assert!(
            matches!(claim.payload, ClaimPayload::Unknown(_)),
            "unknown payload kind must land in ClaimPayload::Unknown"
        );

        // The known iroh transport is still usable; the unknown one is ignored
        // (kept as Unknown), never an error.
        let known: Vec<_> = claim
            .transports
            .iter()
            .filter(|t| matches!(t, TransportOffer::Known(_)))
            .collect();
        let unknown: Vec<_> = claim
            .transports
            .iter()
            .filter(|t| matches!(t, TransportOffer::Unknown(_)))
            .collect();
        assert_eq!(known.len(), 1, "the iroh offer must still be understood");
        assert_eq!(
            unknown.len(),
            1,
            "the future transport must be kept as Unknown"
        );
    }

    #[test]
    fn unknown_variant_value_survives_an_unknown_to_known_round_trip() {
        // An old node relaying a future claim must not DESTROY the future
        // variant's data. Decode (we see it as Unknown) -> re-encode -> a peer
        // that DOES know the variant recovers the original bytes.
        let original = future_variant_claim_bytes();
        let as_value: Value = serde_json::from_slice(&original).unwrap();

        let decoded = decode_claim(&original).expect("decode future claim");
        let reencoded = encode_claim(&decoded).expect("re-encode");
        let reencoded_value: Value = serde_json::from_slice(&reencoded).unwrap();

        assert_eq!(
            as_value, reencoded_value,
            "the unknown payload/transport data must survive an old node relaying it"
        );
    }

    #[test]
    fn unknown_top_level_fields_survive_round_trip() {
        // A future peer adds a top-level field we do not know; the `extra`
        // flatten catch-all must keep it across a round-trip.
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": "sha256:1b2c3d",
            "payload": { "kind": "whole_nar", "blake3": "blake3:aaaa" },
            "holders": ["node-a"],
            "transports": [],
            "future_field": { "some": "v2 thing" }
        });
        let bytes = serde_json::to_vec(&wire).unwrap();
        let claim = decode_claim(&bytes).expect("decode");
        assert_eq!(
            claim.extra.get("future_field"),
            Some(&serde_json::json!({ "some": "v2 thing" })),
            "unknown top-level field must be captured in extra"
        );
        let reencoded: Value = serde_json::from_slice(&encode_claim(&claim).unwrap()).unwrap();
        assert_eq!(
            reencoded, wire,
            "unknown top-level field must survive the round-trip verbatim"
        );
    }

    // --- Reserved v2 fields: real serde survival, not verify-by-trust ------

    #[test]
    fn reserved_v2_fields_survive_round_trip() {
        let mut claim = sample_claim();
        claim.relay = Some(SignedNarinfoRelay {
            blob: "relayed-narinfo-bytes".into(),
        });
        claim.signatures = vec![ClaimSignature {
            key_id: "cache.example-1".into(),
            sig: "sig:abcd".into(),
        }];

        let bytes = encode_claim(&claim).expect("encode");

        // The reserved data is actually ON THE WIRE (not silently skipped).
        let on_wire: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(on_wire["relay"]["blob"], "relayed-narinfo-bytes");
        assert_eq!(on_wire["signatures"][0]["key_id"], "cache.example-1");

        // And it decodes back byte-for-byte identical.
        let back = decode_claim(&bytes).expect("decode");
        assert_eq!(claim, back);
    }

    // --- BitTorrent representable, iroh implemented-shape ------------------

    #[test]
    fn bittorrent_transport_is_representable_without_a_fork() {
        let offer = TransportOffer::Known(KnownTransport::BitTorrent {
            infohash: BitTorrentInfoHash("ih:1234".into()),
            blake3: RawNarBlake3("blake3:aaaa".into()),
        });
        let bytes = serde_json::to_vec(&offer).unwrap();
        let on_wire: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(on_wire["transport"], "bittorrent");
        // Round-trips as a first-class known variant (a 2nd transport is not a
        // fork), while carrying the BLAKE3 a consumer fetches by.
        let back: TransportOffer = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(offer, back);
    }

    #[test]
    fn iroh_offer_carries_node_and_blake3() {
        let offer = TransportOffer::Known(KnownTransport::Iroh {
            node: NodeId("node-a".into()),
            blake3: RawNarBlake3("blake3:aaaa".into()),
        });
        let on_wire: Value = serde_json::from_slice(&serde_json::to_vec(&offer).unwrap()).unwrap();
        assert_eq!(on_wire["transport"], "iroh");
        assert_eq!(on_wire["node"], "node-a");
        assert_eq!(
            on_wire["blake3"], "blake3:aaaa",
            "the iroh offer MUST carry the BLAKE3 a consumer fetches by"
        );
    }

    // --- Version present AND checked --------------------------------------

    fn wrong_version_claim_bytes() -> Vec<u8> {
        let wire = serde_json::json!({
            "schema_version": 999,
            "key": "sha256:1b2c3d",
            "payload": { "kind": "whole_nar", "blake3": "blake3:aaaa" },
            "holders": [],
            "transports": []
        });
        serde_json::to_vec(&wire).unwrap()
    }

    #[test]
    fn wrong_schema_version_is_rejected_cleanly() {
        let bytes = wrong_version_claim_bytes();

        // fails-before intuition made permanent: raw serde ACCEPTS the v999 bytes
        // (the field is well-formed), so a decoder that only parsed would let it
        // through.
        assert!(
            serde_json::from_slice::<Claim>(&bytes).is_ok(),
            "raw serde parses a v999 record - the field alone does not reject"
        );

        // passes-after: decode_claim CHECKS the version and rejects cleanly (an
        // Err with both numbers, never a panic, never a silent accept).
        match decode_claim(&bytes) {
            Err(ClaimCodecError::UnsupportedVersion { found, expected }) => {
                assert_eq!(found, 999);
                assert_eq!(expected, CLAIM_SCHEMA_VERSION);
            }
            other => panic!("expected clean version rejection, got {other:?}"),
        }
    }

    #[test]
    fn malformed_bytes_are_a_clean_error_not_a_panic() {
        let err = decode_claim(b"not json at all").unwrap_err();
        assert!(matches!(err, ClaimCodecError::Malformed(_)));
    }

    // --- Query envelope: versioned, yes/no only, no enumeration -----------

    #[test]
    fn hold_query_round_trips_and_names_one_hash() {
        let query = HoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            key: NarHashKey::new("sha256:1b2c3d"),
        };
        let bytes = encode_hold_query(&query).expect("encode");
        assert_eq!(decode_hold_query(&bytes).expect("decode"), query);
    }

    #[test]
    fn hold_response_have_and_absent_round_trip() {
        let have = HoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            answer: HoldAnswer::Have {
                offers: vec![TransportOffer::Known(KnownTransport::Iroh {
                    node: NodeId("node-a".into()),
                    blake3: RawNarBlake3("blake3:aaaa".into()),
                })],
            },
        };
        let absent = HoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            answer: HoldAnswer::Absent,
        };
        for response in [have, absent] {
            let bytes = encode_hold_response(&response).expect("encode");
            assert_eq!(decode_hold_response(&bytes).expect("decode"), response);
        }
    }

    #[test]
    fn hold_response_is_yes_no_only_and_scoped_to_the_query() {
        // The response answers HAVE/ABSENT and nothing else - there is no
        // variant that enumerates other holdings. An "absent" answer carries no
        // offers at all; a "have" carries offers ONLY for the queried hash
        // (there is structurally no field naming any OTHER hash).
        let absent = HoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            answer: HoldAnswer::Absent,
        };
        let on_wire: Value =
            serde_json::from_slice(&encode_hold_response(&absent).unwrap()).unwrap();
        assert_eq!(on_wire["answer"], "absent");
        assert!(
            on_wire.get("offers").is_none(),
            "an absent answer must not leak a holdings listing"
        );
    }

    #[test]
    fn hold_query_wrong_version_is_rejected_cleanly() {
        let wire = serde_json::json!({ "schema_version": 999, "key": "sha256:1b2c3d" });
        let bytes = serde_json::to_vec(&wire).unwrap();
        assert!(matches!(
            decode_hold_query(&bytes),
            Err(ClaimCodecError::UnsupportedVersion {
                found: 999,
                expected: QUERY_SCHEMA_VERSION
            })
        ));
    }
}
