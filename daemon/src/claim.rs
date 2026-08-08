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
//! ## The frozen identity encodings (task-48)
//!
//! The exact BYTE encoding of the addressed unit and of the transport locators is
//! FROZEN by task-48, in two deliberately separated modules this one composes:
//!   * [`crate::content_id::Blake3Digest`] - the UNIVERSAL, transport-independent
//!     content identity (`BLAKE3(RawNarV1)`, canonical string `blake3:<hex>`). A
//!     claim's payload and every offer carry it; it is the byte a peer is asked
//!     for on any transport.
//!   * [`crate::transport::NodeId`] / [`crate::transport::BitTorrentInfoHash`] -
//!     the per-TRANSPORT locators (an iroh ed25519 key; a BitTorrent infohash).
//!     Not derivable from the content identity, and different per transport, which
//!     is exactly why a claim carries both a universal identity and a
//!     transport-specific locator.
//!
//! Earlier drafts held these as `String` placeholders; task-48 replaced them with
//! the canonical typed encodings (their tests were updated for the new form).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::content_id::Blake3Digest;
use crate::source::NarHash;
use crate::transport::{BitTorrentInfoHash, NodeId};

/// Wire schema version of [`Claim`]. Bumped only on a breaking change; a decoder
/// rejects any other version cleanly (network-split boundary).
pub const CLAIM_SCHEMA_VERSION: u16 = 1;

/// Wire schema version of the [`HoldQuery`]/[`HoldResponse`] envelope. Evolves
/// independently of the claim version.
pub const QUERY_SCHEMA_VERSION: u16 = 1;

// -------------------------------------------------------------------------
// Identity types. The addressed-unit BLAKE3 and the transport locators are the
// task-48 freeze; they live in `content_id` (universal) and `transport`
// (per-transport) and are composed here. See the module docs.
// -------------------------------------------------------------------------

/// Length in bytes of the SHA-256 `NarHash` a claim/query is keyed on.
pub const NAR_HASH_LEN: usize = 32;

/// The algorithm prefix of the canonical `NarHash` string. Frozen: only sha256 is
/// admitted (Nix signs sha256 NarHashes; a claim carries exactly that).
pub const NAR_HASH_PREFIX: &str = "sha256:";

/// The content identity a claim/query is ABOUT: the signed `NarHash` - the value
/// Nix SIGNS and the wave-2 discovery layer keys on. FROZEN (codex finding 2): a
/// STRICT type holding the 32 raw SHA-256 bytes, canonical wire form
/// `sha256:<52 lowercase nix-base32>` (Nix's own encoding, see
/// [`crate::nixbase32`]), VALIDATED on parse/decode/Display.
///
/// Why strict, not a free `String`: this key routes discovery and indexing, so a
/// permissive key (`"not-a-nar-hash"`, wrong length, wrong alphabet) would let two
/// nodes disagree about what key a path has and silently split the network. The
/// value is the interop identity; it must have exactly one canonical form.
///
/// Relationship to the wave-1 seam type [`crate::source::NarHash`]: that type is an
/// intentionally-opaque `String` correlation key internal to the daemon (never on
/// the p2p wire); this is the STRICT wire twin. They agree by construction for
/// real values - [`NarHashKey::to_nar_hash`] emits the canonical string, and
/// [`TryFrom`]`<&NarHash>` validates the seam value into this type (fallible,
/// because the seam is loose by wave-1 design). A real narinfo `NarHash` is always
/// `sha256:<52 nix-base32>`, so the bridge never rejects a genuine value; a
/// non-canonical seam value fails fast rather than reaching the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NarHashKey([u8; NAR_HASH_LEN]);

/// Why a string was not a canonical [`NarHashKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NarHashKeyParseError {
    /// The `sha256:` prefix was missing (only sha256 NarHashes are admitted).
    MissingPrefix,
    /// The base-32 body was not a canonical 52-char lowercase nix-base32 digest.
    BadBase32(String),
}

impl std::fmt::Display for NarHashKeyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NarHashKeyParseError::MissingPrefix => {
                write!(f, "missing '{NAR_HASH_PREFIX}' prefix on a NarHash key")
            }
            NarHashKeyParseError::BadBase32(why) => write!(f, "malformed NarHash base-32: {why}"),
        }
    }
}

impl std::error::Error for NarHashKeyParseError {}

impl NarHashKey {
    /// Wrap the 32 raw SHA-256 bytes of a NarHash.
    pub const fn from_sha256_bytes(bytes: [u8; NAR_HASH_LEN]) -> Self {
        NarHashKey(bytes)
    }

    /// The raw 32 SHA-256 bytes.
    pub const fn as_bytes(&self) -> &[u8; NAR_HASH_LEN] {
        &self.0
    }

    /// The 52-char nix-base32 body (WITHOUT the `sha256:` prefix).
    pub fn to_nix_base32(&self) -> String {
        crate::nixbase32::encode(&self.0)
    }

    /// Bridge to the wave-1 seam identity type, as its canonical string.
    pub fn to_nar_hash(&self) -> NarHash {
        NarHash::new(self.to_string())
    }
}

impl std::str::FromStr for NarHashKey {
    type Err = NarHashKeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = s
            .strip_prefix(NAR_HASH_PREFIX)
            .ok_or(NarHashKeyParseError::MissingPrefix)?;
        let bytes = crate::nixbase32::decode_fixed::<NAR_HASH_LEN>(body)
            .map_err(|e| NarHashKeyParseError::BadBase32(e.to_string()))?;
        Ok(NarHashKey(bytes))
    }
}

impl std::fmt::Display for NarHashKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{NAR_HASH_PREFIX}{}", self.to_nix_base32())
    }
}

impl Serialize for NarHashKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NarHashKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&NarHash> for NarHashKey {
    type Error = NarHashKeyParseError;

    fn try_from(hash: &NarHash) -> Result<Self, Self::Error> {
        hash.as_str().parse()
    }
}

// -------------------------------------------------------------------------
// Payload: WHAT content identity the claim is about.
// -------------------------------------------------------------------------

/// What content a claim describes. Forward-compatible, but STRICTLY so (codex
/// finding 3): a payload whose `kind` this build does NOT recognise is kept
/// verbatim as [`ClaimPayload::Unknown`] and ignored; a payload with a KNOWN
/// `kind` but malformed fields is a hard ERROR, never silently swallowed as
/// Unknown. The two axes are distinct - unknown TAG (forward-compat, preserve)
/// vs malformed KNOWN (a real defect, reject) - and conflating them is exactly
/// the task-13 defect species this discriminator-aware decode avoids.
///
/// Serialize is untagged (a `Known` emits its inner tagged object, an `Unknown`
/// its raw value); Deserialize is hand-written to peek the discriminator - see
/// the `Deserialize` impl below.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ClaimPayload {
    Known(KnownPayload),
    /// A payload kind newer than this build (e.g. a future `CastoreRoot`). Kept
    /// verbatim so relaying does not destroy it; ignored by logic.
    Unknown(Value),
}

/// The payload `kind` tags THIS build claims to understand. EXTEND THIS when
/// adding a [`KnownPayload`] variant, so a malformed instance of the NEW kind is
/// rejected (not swallowed) while a still-unknown kind stays `Unknown`.
const KNOWN_PAYLOAD_KINDS: &[&str] = &["whole_nar"];

/// The payload kinds THIS build understands. `WholeNar` (Candidate B) is the
/// only wave-2 kind; `CastoreRoot` (Candidate C chunked) is the reserved future
/// kind and lands here as a new variant later - until then a peer sending it is
/// handled by [`ClaimPayload::Unknown`], which is exactly the evolution path
/// this schema promises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnownPayload {
    /// A whole raw-NAR blob, addressed by the claim's single BLAKE3 (the
    /// universal content identity, `blake3:<hex>` on the wire).
    WholeNar { blake3: Blake3Digest },
    // future: CastoreRoot { root: CastoreRootDigest, .. }  // task: Candidate C
}

impl<'de> Deserialize<'de> for ClaimPayload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Peek the discriminator on the raw value, then dispatch: a KNOWN kind is
        // strict-parsed (errors propagate); anything else is preserved as Unknown.
        let value = Value::deserialize(deserializer)?;
        let is_known = value
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|tag| KNOWN_PAYLOAD_KINDS.contains(&tag));
        if is_known {
            let known =
                serde_json::from_value::<KnownPayload>(value).map_err(serde::de::Error::custom)?;
            Ok(ClaimPayload::Known(known))
        } else {
            Ok(ClaimPayload::Unknown(value))
        }
    }
}

// -------------------------------------------------------------------------
// Transport offer: HOW to fetch the content.
// -------------------------------------------------------------------------

/// One way to fetch the claimed content: a PURE LOCATOR (the content identity is
/// the claim/Have's single `blake3`, never repeated here - codex finding 1).
/// Forward-compatible like [`ClaimPayload`] and STRICTLY so (codex finding 3): an
/// unknown `transport` tag is preserved as `Unknown`; a KNOWN transport with a
/// malformed locator is a hard ERROR, not silently downgraded to `Unknown`.
///
/// Serialize is untagged; Deserialize is hand-written to peek the discriminator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum TransportOffer {
    Known(KnownTransport),
    /// A transport neither side of THIS version knows. Kept verbatim; ignored.
    Unknown(Value),
}

/// The `transport` tags THIS build claims to understand. EXTEND when adding a
/// [`KnownTransport`] variant (same rule as [`KNOWN_PAYLOAD_KINDS`]).
const KNOWN_TRANSPORT_TAGS: &[&str] = &["iroh", "bittorrent"];

impl<'de> Deserialize<'de> for TransportOffer {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let is_known = value
            .get("transport")
            .and_then(Value::as_str)
            .is_some_and(|tag| KNOWN_TRANSPORT_TAGS.contains(&tag));
        if is_known {
            let known = serde_json::from_value::<KnownTransport>(value)
                .map_err(serde::de::Error::custom)?;
            Ok(TransportOffer::Known(known))
        } else {
            Ok(TransportOffer::Unknown(value))
        }
    }
}

/// The transports THIS build can represent. Only `Iroh` has a fetch backend
/// (task-38); `BitTorrent` is representable to prove the schema admits a 2nd
/// transport without a network fork.
///
/// A transport offer is a PURE LOCATOR: it carries ONLY the transport-specific
/// coordinate, NOT the content identity (codex finding 1). The universal
/// `blake3` a consumer fetches/verifies by lives EXACTLY ONCE per claim - in the
/// payload ([`KnownPayload::WholeNar`]) - or once per [`HoldAnswer::Have`]. This
/// is the (a) fix: there is no second copy of the content address to disagree
/// with the first, so a claim can never name two different blobs. The separation
/// of universal-identity from per-transport-locator is thereby structural, not a
/// runtime cross-check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum KnownTransport {
    /// iroh whole-blob (Candidate B, FIRST priority). The locator is the holder
    /// `NodeId`; the blob to fetch is the claim/Have's single `blake3`.
    Iroh { node: NodeId },
    /// BitTorrent - REPRESENTABLE only, NOT implemented (no backend; task-38).
    /// Present so a 2nd transport is not a network fork; its locator is an
    /// `infohash` (a coordinate a `NodeId` cannot express), proving the schema
    /// admits a transport whose addressing differs. The content is still the
    /// claim/Have's single `blake3`. The wire tag is pinned explicitly
    /// (`snake_case` would give the odd `bit_torrent`).
    #[serde(rename = "bittorrent")]
    BitTorrent { infohash: BitTorrentInfoHash },
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
    /// "Yes, I hold it": the single content identity (`blake3`) for the queried
    /// key, plus pure-locator offers (codex finding 1). The `blake3` lives here
    /// exactly once - a Have has no payload - so the offers carry no digest to
    /// disagree with it. A consumer fetches the `blake3` via any offer's locator.
    Have {
        blake3: Blake3Digest,
        offers: Vec<TransportOffer>,
    },
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

    // Canonical fixed identities, in BOTH typed and wire-string form, so the
    // typed constructors and the raw-JSON literals below cannot drift. The
    // `wire_strings_match_typed` test asserts they agree.
    const KEY_HEX: &str = "sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb";
    const NODE_A_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const NODE_B_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const BLAKE3_HEX: &str =
        "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const INFOHASH_HEX: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; // 64 = v2

    fn key() -> NarHashKey {
        KEY_HEX.parse().expect("KEY_HEX is a canonical NarHash")
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
    fn infohash() -> BitTorrentInfoHash {
        BitTorrentInfoHash::v2([0xbb; 32])
    }

    #[test]
    fn wire_strings_match_typed() {
        // The raw-JSON literals used across these tests must equal the canonical
        // string form of the typed identities, or a "future variant" fixture
        // would fail to decode for the wrong reason.
        assert_eq!(key().to_string(), KEY_HEX);
        assert_eq!(node_a().to_string(), NODE_A_HEX);
        assert_eq!(node_b().to_string(), NODE_B_HEX);
        assert_eq!(blake3_id().to_string(), BLAKE3_HEX);
        assert_eq!(infohash().to_string(), INFOHASH_HEX);
    }

    /// A fully-populated v1 claim (known payload + both transports + reserved
    /// fields set) so round-trip tests exercise every field. Note the single
    /// content identity lives ONLY in the payload; the offers are pure locators.
    fn sample_claim() -> Claim {
        Claim {
            schema_version: CLAIM_SCHEMA_VERSION,
            key: key(),
            payload: ClaimPayload::Known(KnownPayload::WholeNar {
                blake3: blake3_id(),
            }),
            holders: vec![node_a(), node_b()],
            transports: vec![
                TransportOffer::Known(KnownTransport::Iroh { node: node_a() }),
                TransportOffer::Known(KnownTransport::BitTorrent {
                    infohash: infohash(),
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

    // --- CODEX FINDING 2: NarHashKey is a STRICT, validated identity --------

    #[test]
    fn nar_hash_key_bridges_the_seam_type_by_construction() {
        // to_nar_hash emits the canonical string; TryFrom validates it back. A
        // real seam value round-trips to the same strict key.
        let key = key();
        let seam = key.to_nar_hash();
        assert_eq!(seam.as_str(), KEY_HEX);
        assert_eq!(NarHashKey::try_from(&seam).unwrap(), key);
    }

    #[test]
    fn nar_hash_key_parse_rejects_non_canonical() {
        // Direct parse: missing prefix, wrong alphabet, wrong length all rejected.
        assert_eq!(
            "not-a-nar-hash".parse::<NarHashKey>(),
            Err(NarHashKeyParseError::MissingPrefix)
        );
        assert!(matches!(
            "sha256:not-base32-and-too-short".parse::<NarHashKey>(),
            Err(NarHashKeyParseError::BadBase32(_))
        ));
        // A canonical value uppercased is no longer canonical (nix-base32 is
        // lowercase-only), so it is rejected too.
        assert!(KEY_HEX.to_uppercase().parse::<NarHashKey>().is_err());
    }

    #[test]
    fn claim_with_a_non_canonical_key_is_rejected() {
        // fails-before (String key): `"not-a-nar-hash"` decoded fine, letting two
        // nodes disagree on a path's key. passes-after: decode_claim REJECTS it.
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": "not-a-nar-hash",
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [],
            "transports": []
        });
        let bytes = serde_json::to_vec(&wire).unwrap();
        assert!(
            matches!(decode_claim(&bytes), Err(ClaimCodecError::Malformed(_))),
            "a claim whose key is not a canonical NarHash must be rejected"
        );
    }

    // --- CODEX FINDING 1: exactly ONE content identity per claim ------------

    #[test]
    fn a_claim_names_exactly_one_content_identity() {
        // The content address lives ONLY in the payload; offers are pure
        // locators. There is structurally no second blake3 to disagree with it.
        let on_wire: Value =
            serde_json::from_slice(&encode_claim(&sample_claim()).unwrap()).unwrap();
        assert_eq!(on_wire["payload"]["blake3"], BLAKE3_HEX);
        for offer in on_wire["transports"].as_array().unwrap() {
            assert!(
                offer.get("blake3").is_none(),
                "a transport offer must NOT carry its own blake3 (finding 1): {offer}"
            );
        }
    }

    #[test]
    fn a_stray_offer_blake3_cannot_introduce_a_second_identity() {
        // Even if a peer put a DIFFERENT blake3 on an iroh offer, the typed model
        // has no field for it, so the decoded claim still has exactly one content
        // identity (the payload's). A two-blob claim is not representable.
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [NODE_A_HEX],
            "transports": [
                { "transport": "iroh", "node": NODE_A_HEX,
                  "blake3": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
            ]
        });
        let claim = decode_claim(&serde_json::to_vec(&wire).unwrap()).expect("decode");
        assert_eq!(
            claim.payload,
            ClaimPayload::Known(KnownPayload::WholeNar {
                blake3: blake3_id()
            })
        );
        assert_eq!(
            claim.transports,
            vec![TransportOffer::Known(KnownTransport::Iroh {
                node: node_a()
            })],
            "the stray offer blake3 is not part of the typed offer - no 2nd identity"
        );
    }

    // --- Forward-compat: unknown TAG survives; malformed KNOWN errors -------

    /// Bytes a NEWER peer would send: a `castore_root` payload this build does
    /// not know, and a `webseed` transport it does not know. Offers are pure
    /// locators (no blake3), matching finding 1.
    fn future_variant_claim_bytes() -> Vec<u8> {
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "castore_root", "digest": "castore:xyz", "chunks": 7 },
            "holders": [NODE_A_HEX],
            "transports": [
                { "transport": "iroh", "node": NODE_A_HEX },
                { "transport": "webseed", "url": "https://example.invalid/x" }
            ]
        });
        serde_json::to_vec(&wire).unwrap()
    }

    #[test]
    fn unknown_variants_parse_and_are_ignored_not_errored() {
        // task-37 forward-compat still holds: an unknown TAG is preserved as
        // Unknown, never an error.
        let claim = decode_claim(&future_variant_claim_bytes())
            .expect("a future-variant claim must decode, not error");

        assert!(
            matches!(claim.payload, ClaimPayload::Unknown(_)),
            "unknown payload kind must land in ClaimPayload::Unknown"
        );
        let known = claim
            .transports
            .iter()
            .filter(|t| matches!(t, TransportOffer::Known(_)))
            .count();
        let unknown = claim
            .transports
            .iter()
            .filter(|t| matches!(t, TransportOffer::Unknown(_)))
            .count();
        assert_eq!(known, 1, "the iroh offer must still be understood");
        assert_eq!(unknown, 1, "the future transport must be kept as Unknown");
    }

    // --- CODEX FINDING 3: malformed KNOWN variant ERRORS, not swallowed -----

    /// The OLD untagged behaviour, kept as a fails-before control: it swallows a
    /// malformed KNOWN variant into `Unknown` instead of erroring. The real
    /// [`ClaimPayload`] must instead ERROR - that is the finding-3 fix.
    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    #[allow(dead_code)]
    enum UntaggedPayload {
        Known(KnownPayload),
        Unknown(Value),
    }

    #[test]
    fn malformed_known_payload_errors_instead_of_becoming_unknown() {
        // A KNOWN kind (`whole_nar`) with a malformed blake3.
        let bad = serde_json::json!({ "kind": "whole_nar", "blake3": "blake3:not-hex" });

        // fails-before: the untagged control swallows it as Unknown (the defect).
        let swallowed: UntaggedPayload = serde_json::from_value(bad.clone()).unwrap();
        assert!(
            matches!(swallowed, UntaggedPayload::Unknown(_)),
            "control: untagged decode swallows a malformed known variant (the bug)"
        );

        // passes-after: the real payload decode ERRORS on the malformed known kind.
        let strict: Result<ClaimPayload, _> = serde_json::from_value(bad);
        assert!(
            strict.is_err(),
            "a malformed whole_nar payload must ERROR, not become Unknown"
        );
    }

    #[test]
    fn malformed_known_transport_errors_but_unknown_tag_is_preserved() {
        // A KNOWN transport (`iroh`) with a malformed node must ERROR.
        let bad_iroh = serde_json::json!({ "transport": "iroh", "node": "not-hex" });
        assert!(
            serde_json::from_value::<TransportOffer>(bad_iroh).is_err(),
            "a malformed iroh offer must ERROR (finding 3)"
        );
        // An UNKNOWN transport tag is still preserved as Unknown (forward-compat).
        let future = serde_json::json!({ "transport": "webseed", "url": "x" });
        let offer: TransportOffer = serde_json::from_value(future).unwrap();
        assert!(matches!(offer, TransportOffer::Unknown(_)));
    }

    #[test]
    fn a_malformed_known_offer_inside_a_claim_fails_the_whole_decode() {
        // The finding-3 fix must hold end-to-end, not just on a bare offer.
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [],
            "transports": [ { "transport": "iroh", "node": "not-hex" } ]
        });
        let bytes = serde_json::to_vec(&wire).unwrap();
        assert!(
            matches!(decode_claim(&bytes), Err(ClaimCodecError::Malformed(_))),
            "a claim carrying a malformed known offer must be rejected"
        );
    }

    #[test]
    fn unknown_variant_value_survives_an_unknown_to_known_round_trip() {
        // An old node relaying a future claim must not DESTROY the future
        // variant's data. Decode (Unknown) -> re-encode -> a peer that knows the
        // variant recovers the original bytes.
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
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [NODE_A_HEX],
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

    // --- BitTorrent representable, iroh implemented-shape (pure locators) ---

    #[test]
    fn bittorrent_transport_is_representable_without_a_fork() {
        let offer = TransportOffer::Known(KnownTransport::BitTorrent {
            infohash: infohash(),
        });
        let bytes = serde_json::to_vec(&offer).unwrap();
        let on_wire: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(on_wire["transport"], "bittorrent");
        // The transport-specific locator (infohash) is present; the content
        // identity is NOT duplicated here (it is the claim's single blake3). A
        // BitTorrent locator does not fit in a NodeId, so a 2nd transport is
        // representable without forking the content identity.
        assert_eq!(on_wire["infohash"], INFOHASH_HEX);
        assert!(
            on_wire.get("blake3").is_none(),
            "an offer is a pure locator - no duplicated content identity"
        );
        let back: TransportOffer = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(offer, back);
    }

    #[test]
    fn iroh_offer_is_a_pure_node_locator() {
        let offer = TransportOffer::Known(KnownTransport::Iroh { node: node_a() });
        let on_wire: Value = serde_json::from_slice(&serde_json::to_vec(&offer).unwrap()).unwrap();
        assert_eq!(on_wire["transport"], "iroh");
        assert_eq!(on_wire["node"], NODE_A_HEX);
        assert!(
            on_wire.get("blake3").is_none(),
            "the iroh offer is a pure locator; the blake3 is the claim's single id"
        );
    }

    // --- Version present AND checked --------------------------------------

    fn wrong_version_claim_bytes() -> Vec<u8> {
        let wire = serde_json::json!({
            "schema_version": 999,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
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

        // passes-after: decode_claim CHECKS the version and rejects cleanly.
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
            key: key(),
        };
        let bytes = encode_hold_query(&query).expect("encode");
        assert_eq!(decode_hold_query(&bytes).expect("decode"), query);
    }

    #[test]
    fn hold_response_have_and_absent_round_trip() {
        let have = HoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            answer: HoldAnswer::Have {
                blake3: blake3_id(),
                offers: vec![TransportOffer::Known(KnownTransport::Iroh {
                    node: node_a(),
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
    fn have_response_carries_exactly_one_content_identity() {
        // A Have has no payload, so it carries the single blake3 itself; its
        // offers are pure locators (finding 1 applied to the query path).
        let have = HoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            answer: HoldAnswer::Have {
                blake3: blake3_id(),
                offers: vec![TransportOffer::Known(KnownTransport::Iroh {
                    node: node_a(),
                })],
            },
        };
        let on_wire: Value = serde_json::from_slice(&encode_hold_response(&have).unwrap()).unwrap();
        assert_eq!(on_wire["blake3"], BLAKE3_HEX);
        for offer in on_wire["offers"].as_array().unwrap() {
            assert!(
                offer.get("blake3").is_none(),
                "Have offers are pure locators"
            );
        }
    }

    #[test]
    fn hold_response_is_yes_no_only_and_scoped_to_the_query() {
        // The response answers HAVE/ABSENT and nothing else - there is no
        // variant that enumerates other holdings. An "absent" answer carries no
        // offers and no blake3 at all.
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
        assert!(on_wire.get("blake3").is_none());
    }

    #[test]
    fn hold_query_wrong_version_is_rejected_cleanly() {
        let wire = serde_json::json!({ "schema_version": 999, "key": KEY_HEX });
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
