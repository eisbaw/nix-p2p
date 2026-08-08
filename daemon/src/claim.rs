//! The p2p CLAIM wire format: the network's shared language (wave-2, task-37).
//!
//! Two versioned wire surfaces live here, and ONLY these types - no transport,
//! no DHT, no discovery logic (those consume this module: task-38 the transport
//! trait, task-40 discovery, task-50 the availability index that PRODUCES
//! claims):
//!
//!   * [`Claim`] - a peer's assertion "this content identity is held, here is
//!     how to fetch it". In wave-2a a node announces its OWN claims from its OWN
//!     availability index (task-50); there is NO relay, so a claim is never
//!     re-serialized on behalf of another peer. Relay (and the lossless
//!     preservation it would demand) is wave-2b, task-55.
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
//! ## Forward-compat model (SIMPLIFIED at root - freeze round 3, mark-emulator B)
//!
//! Earlier drafts kept a `serde_json::Value` catch-all (a struct-level
//! `#[serde(flatten)] extra` and `Unknown(Value)` variants) so a relaying node
//! could preserve a future peer's data verbatim. Codex showed that catch-all was
//! a well of edge cases: it re-admitted a SECOND content digest (a two-blob
//! claim) via `extra["payload"]` or an `Unknown` offer, it was not lossless
//! (a u64 overflowed to float), and it had no size bound. Because wave-2a has NO
//! relay (a node announces its OWN claims, task-50), lossless PRESERVATION is not
//! needed here, so the mechanism was REMOVED rather than patched again. Two axes
//! remain, and both fail loud or drop - never carry:
//!
//!   * Unknown KIND/transport, same schema_version: TOLERATED BUT INERT. Decode
//!     succeeds; an unknown payload kind yields a claim with NO usable content id
//!     (`payload == None`), an unknown transport offer is DROPPED from the set.
//!     The unknown is NOT retained and NOT re-serialized (no `Value` kept). A
//!     KNOWN kind with MALFORMED fields is still a hard ERROR (the task-13 fix).
//!   * Wrong schema_version: a hard network-split boundary. [`decode_claim`] /
//!     [`decode_hold_query`] / [`decode_hold_response`] REJECT it cleanly. Real
//!     v2 evolution BUMPS `schema_version` - that is what the version field is
//!     FOR; there is deliberately no silent unknown-top-level-field tolerance
//!     ([`Claim`] is `deny_unknown_fields`).
//!
//! Lossless relay preservation is filed as task-55 (wave-2b, when relay exists).
//!
//! ## Codec (draft; the binary wire codec is a velocity surface, not frozen)
//!
//! The types derive serde; the concrete codec used here for tests and the current
//! `encode_*`/`decode_*` helpers is JSON. The FINAL on-wire codec (a compact
//! binary form: CBOR/postcard) is a wave-2 velocity surface and is chosen later.
//! Decode is SIZE-BOUNDED ([`MAX_CLAIM_WIRE_BYTES`]): a claim is tiny, so an
//! oversize input fails fast rather than allocating an unbounded parse tree.
//!
//! ## The frozen identity encodings (task-48)
//!
//! The exact BYTE encoding of the addressed unit and of the transport locators is
//! FROZEN by task-48, in two deliberately separated modules this one composes:
//!   * [`crate::content_id::Blake3Digest`] - the UNIVERSAL, transport-independent
//!     content identity (`BLAKE3(RawNarV1)`, canonical string `blake3:<hex>`). It
//!     appears AT MOST ONCE per claim - in a known payload
//!     ([`KnownPayload::WholeNar`]) or once per [`HoldAnswer::Have`]; an absent or
//!     unknown-kind payload carries none. It is never duplicated (transport offers
//!     are pure locators), so a claim can never name two different blobs; it is the
//!     byte a peer is asked for on any transport.
//!   * [`crate::transport::NodeId`] / [`crate::transport::BitTorrentInfoHash`] -
//!     the per-TRANSPORT locators (an iroh ed25519 key; a BitTorrent infohash). A
//!     transport offer carries ONLY its locator, never the content digest, so a
//!     claim cannot name two blobs. Not derivable from the content identity, and
//!     different per transport, which is why a claim pairs the single universal
//!     identity with per-transport locators.
//!
//! Earlier drafts held these as `String` placeholders; task-48 replaced them with
//! the canonical typed encodings (their tests were updated for the new form).

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

/// Maximum accepted wire size of a claim or query/response, checked BEFORE parse
/// (freeze round 3). A claim is a handful of small fields - a few hundred bytes;
/// 64 KiB is generous headroom and past it the input is not a well-formed claim.
/// The bound makes a malformed/huge input fail fast with no unbounded allocation.
pub const MAX_CLAIM_WIRE_BYTES: usize = 64 * 1024;

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

/// The payload `kind` tags THIS build understands. EXTEND when adding a
/// [`KnownPayload`] variant, so a malformed instance of the NEW kind is rejected
/// (not tolerated) while a still-unknown kind stays inert.
const KNOWN_PAYLOAD_KINDS: &[&str] = &["whole_nar"];

/// The payload kinds THIS build understands. `WholeNar` (Candidate B) is the only
/// wave-2 kind; `CastoreRoot` (Candidate C chunked) lands here as a new variant
/// later. A claim whose payload kind is NOT known decodes to `payload == None`
/// (inert, no usable content id) - never an error, never carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnownPayload {
    /// A whole raw-NAR blob, addressed by the claim's single BLAKE3 (the
    /// universal content identity, `blake3:<hex>` on the wire).
    WholeNar { blake3: Blake3Digest },
    // future: CastoreRoot { root: CastoreRootDigest, .. }  // task: Candidate C
}

/// Field deserializer for [`Claim::payload`]: TOLERATE-BUT-DROP an unknown kind.
/// Peek `kind`; a KNOWN kind is strict-parsed (a malformed known kind ERRORS); an
/// unknown/absent/null kind yields `None` (inert). The unknown is NOT retained -
/// wave-2a has no relay, so there is nothing to preserve (task-55 revisits this
/// for wave-2b relay).
fn deserialize_optional_known_payload<'de, D>(
    deserializer: D,
) -> Result<Option<KnownPayload>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(None);
    }
    let is_known = value
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|tag| KNOWN_PAYLOAD_KINDS.contains(&tag));
    if is_known {
        serde_json::from_value::<KnownPayload>(value)
            .map(Some)
            .map_err(serde::de::Error::custom)
    } else {
        Ok(None)
    }
}

// -------------------------------------------------------------------------
// Transport offer: HOW to fetch the content. A PURE LOCATOR - it carries ONLY the
// transport-specific coordinate, NEVER the content identity (which lives exactly
// once per claim, in the payload, or once per Have). So a claim can never name
// two different blobs; single-identity is structural, not a runtime cross-check.
// -------------------------------------------------------------------------

/// The `transport` tags THIS build understands. EXTEND when adding a
/// [`KnownTransport`] variant (same rule as [`KNOWN_PAYLOAD_KINDS`]).
const KNOWN_TRANSPORT_TAGS: &[&str] = &["iroh", "bittorrent"];

/// The transports THIS build can represent. Only `Iroh` has a fetch backend
/// (task-38); `BitTorrent` is representable to prove the schema admits a 2nd
/// transport without a network fork. Each is a PURE LOCATOR (no content digest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum KnownTransport {
    /// iroh whole-blob (Candidate B, FIRST priority). The locator is the holder
    /// `NodeId`; the blob to fetch is the claim/Have's single `blake3`.
    Iroh { node: NodeId },
    /// BitTorrent - REPRESENTABLE only, NOT implemented (no backend; task-38).
    /// Present so a 2nd transport is not a network fork; its locator is an
    /// `infohash` (a coordinate a `NodeId` cannot express). The content is still
    /// the claim/Have's single `blake3`. The wire tag is pinned explicitly
    /// (`snake_case` would give the odd `bit_torrent`).
    #[serde(rename = "bittorrent")]
    BitTorrent { infohash: BitTorrentInfoHash },
}

/// Field deserializer for a transport-offer list: TOLERATE-BUT-DROP unknown
/// transports. Each element is peeked; a KNOWN transport is strict-parsed (a
/// malformed known transport ERRORS the whole decode), an unknown transport tag
/// is DROPPED from the set (not retained, not re-serialized). Used by both
/// [`Claim::transports`] and [`HoldAnswer::Have`].
fn deserialize_known_transports<'de, D>(deserializer: D) -> Result<Vec<KnownTransport>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Vec::<Value>::deserialize(deserializer)?;
    let mut offers = Vec::with_capacity(raw.len());
    for value in raw {
        let is_known = value
            .get("transport")
            .and_then(Value::as_str)
            .is_some_and(|tag| KNOWN_TRANSPORT_TAGS.contains(&tag));
        if is_known {
            offers.push(
                serde_json::from_value::<KnownTransport>(value)
                    .map_err(serde::de::Error::custom)?,
            );
        }
        // else: an unknown transport is dropped (inert), never carried.
    }
    Ok(offers)
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
/// to fetch it, with typed room reserved for v2.
///
/// `deny_unknown_fields` (freeze round 3): there is NO struct-level catch-all. An
/// unknown TOP-LEVEL field is REJECTED, not silently captured - a versioned format
/// evolves by bumping `schema_version`, which is what that field is for. This
/// structurally forecloses smuggling a second `payload` (a two-blob claim) through
/// a catch-all. The content digest appears in EXACTLY ONE place: `payload`.
///
/// `holders` and `transports` are distinct on purpose and NOT redundant:
///   * `holders` are the identities ASSERTED to hold the content (the
///     rendezvous-level "who" - the shape a DHT lookup returns). A claim may list
///     a holder for which no inlined transport offer is present; probe it directly.
///   * `transports` are concrete FETCH coordinates (pure locators). They cannot be
///     derived from `holders`: a BitTorrent offer's coordinate is an infohash, not
///     a `NodeId`. This is why both fields exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    /// Wire schema version. CHECKED by [`decode_claim`]; a mismatch is rejected.
    pub schema_version: u16,
    /// The content identity: the signed `NarHash` (wave-1 seam key).
    pub key: NarHashKey,
    /// WHAT content (whole NAR now; future `CastoreRoot`). An UNKNOWN kind decodes
    /// to `None` (inert, no usable content id); it is not carried. A produced
    /// claim always sets `Some(..)`; `None` omits the field on the wire.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_known_payload"
    )]
    pub payload: Option<KnownPayload>,
    /// WHO is asserted to hold it (rendezvous-level identities).
    pub holders: Vec<NodeId>,
    /// HOW to fetch it (pure per-transport locators). Unknown transports are
    /// dropped on decode (tolerated but inert), never carried.
    #[serde(default, deserialize_with = "deserialize_known_transports")]
    pub transports: Vec<KnownTransport>,
    /// RESERVED v2: signed-narinfo relay. `None` in v1. TYPED, not a catch-all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<SignedNarinfoRelay>,
    /// RESERVED v2: claim signatures. Empty in v1. TYPED, not a catch-all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<ClaimSignature>,
}

impl Claim {
    /// The ONE content identity this claim addresses, or `None` if the payload
    /// kind is unknown to this build. Single by construction: there is no other
    /// field on a claim that carries a content digest.
    pub fn content_id(&self) -> Option<&Blake3Digest> {
        match &self.payload {
            Some(KnownPayload::WholeNar { blake3 }) => Some(blake3),
            None => None,
        }
    }
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
#[serde(deny_unknown_fields)]
pub struct HoldQuery {
    pub schema_version: u16,
    /// The single content identity being probed.
    pub key: NarHashKey,
}

/// The answer to a [`HoldQuery`]: have-with-offers, or absent. Yes/no ONLY - it
/// never carries a listing of other holdings, and it concerns only the queried
/// hash. Unknown transport offers are dropped on decode (tolerated but inert).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
pub enum HoldAnswer {
    /// "Yes, I hold it": the single content identity (`blake3`) for the queried
    /// key, plus pure-locator offers. The `blake3` lives here exactly once - a
    /// Have has no payload - so the offers carry no digest to disagree with it. A
    /// consumer fetches the `blake3` via any offer's locator.
    Have {
        blake3: Blake3Digest,
        #[serde(default, deserialize_with = "deserialize_known_transports")]
        offers: Vec<KnownTransport>,
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

/// Reject an oversize wire input BEFORE parsing (freeze round 3). A claim is
/// tiny; past [`MAX_CLAIM_WIRE_BYTES`] the input is not a well-formed claim, and
/// bounding it here means no unbounded parse-tree allocation on hostile input.
fn check_size(len: usize) -> Result<(), ClaimCodecError> {
    if len > MAX_CLAIM_WIRE_BYTES {
        Err(ClaimCodecError::Malformed(format!(
            "wire input is {len} bytes, exceeds the {MAX_CLAIM_WIRE_BYTES}-byte cap"
        )))
    } else {
        Ok(())
    }
}

/// A guard type that walks ANY JSON value purely to REJECT a repeated key at any
/// object level (freeze round 4). It exists because `serde_json` SILENTLY accepts
/// duplicate keys and keeps the LAST one - which on a FROZEN wire format is an
/// ambiguous parse: a wire with two `payload.blake3` values, or a `kind` repeated
/// (`whole_nar` then a future kind), would decode to a last-wins choice, so two
/// independent implementations could disagree on the content identity or on
/// whether a malformed known kind is present. Rejecting ANY repeated key gives
/// EXACTLY ONE canonical parse - fail-closed, not last-wins. This runs BEFORE the
/// real parse, over the WHOLE tree, so the later discriminator peek (which
/// materialises a `Value`, itself last-wins) can never see a duplicate.
struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct GuardVisitor;

        impl<'de> serde::de::Visitor<'de> for GuardVisitor {
            type Value = NoDuplicateKeys;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value with no repeated object keys")
            }

            fn visit_bool<E: serde::de::Error>(self, _v: bool) -> Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_i64<E: serde::de::Error>(self, _v: i64) -> Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_u64<E: serde::de::Error>(self, _v: u64) -> Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_f64<E: serde::de::Error>(self, _v: f64) -> Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_str<E: serde::de::Error>(self, _v: &str) -> Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                NoDuplicateKeys::deserialize(deserializer)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                // Recurse into every element so a duplicate key nested inside an
                // array of objects is caught too.
                while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
                Ok(NoDuplicateKeys)
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut seen = std::collections::HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate key {key:?} (ambiguous wire is rejected)"
                        )));
                    }
                    // Recurse into the value: a duplicate nested key must be caught
                    // wherever it hides.
                    map.next_value::<NoDuplicateKeys>()?;
                }
                Ok(NoDuplicateKeys)
            }
        }

        deserializer.deserialize_any(GuardVisitor)
    }
}

/// Reject a wire input containing a repeated key at ANY object level, so the
/// input has exactly one canonical parse (see [`NoDuplicateKeys`]). Runs after the
/// size gate, before the typed parse.
fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), ClaimCodecError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    NoDuplicateKeys::deserialize(&mut de).map_err(|e| ClaimCodecError::Malformed(e.to_string()))?;
    // No trailing tokens after the single value, matching `from_slice`'s contract.
    de.end()
        .map_err(|e| ClaimCodecError::Malformed(e.to_string()))?;
    Ok(())
}

/// Decode + VALIDATE a claim. Parsing alone is not acceptance: the input is
/// size-bounded, DUPLICATE-KEY-rejected (one canonical parse), the
/// `schema_version` is checked, an unknown payload/transport KIND is
/// tolerated-but-dropped (never carried), and a malformed KNOWN kind is a hard
/// error.
pub fn decode_claim(bytes: &[u8]) -> Result<Claim, ClaimCodecError> {
    check_size(bytes.len())?;
    reject_duplicate_keys(bytes)?;
    let claim: Claim =
        serde_json::from_slice(bytes).map_err(|e| ClaimCodecError::Malformed(e.to_string()))?;
    check_version(claim.schema_version, CLAIM_SCHEMA_VERSION)?;
    Ok(claim)
}

/// Encode a hold query to its wire bytes.
pub fn encode_hold_query(query: &HoldQuery) -> Result<Vec<u8>, ClaimCodecError> {
    serde_json::to_vec(query).map_err(|e| ClaimCodecError::Malformed(e.to_string()))
}

/// Decode + validate a hold query (size-, duplicate-key- and version-checked).
pub fn decode_hold_query(bytes: &[u8]) -> Result<HoldQuery, ClaimCodecError> {
    check_size(bytes.len())?;
    reject_duplicate_keys(bytes)?;
    let query: HoldQuery =
        serde_json::from_slice(bytes).map_err(|e| ClaimCodecError::Malformed(e.to_string()))?;
    check_version(query.schema_version, QUERY_SCHEMA_VERSION)?;
    Ok(query)
}

/// Encode a hold response to its wire bytes.
pub fn encode_hold_response(response: &HoldResponse) -> Result<Vec<u8>, ClaimCodecError> {
    serde_json::to_vec(response).map_err(|e| ClaimCodecError::Malformed(e.to_string()))
}

/// Decode + validate a hold response (size-, duplicate-key- and version-checked).
pub fn decode_hold_response(bytes: &[u8]) -> Result<HoldResponse, ClaimCodecError> {
    check_size(bytes.len())?;
    reject_duplicate_keys(bytes)?;
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

    // --- FINDING 1 (freeze round 3): exactly ONE content identity per claim,
    // and NO catch-all path (extra flatten / Unknown Value) that could smuggle a
    // second digest. The digest lives once, in the payload. ------------------

    /// A digest DIFFERENT from `blake3_id()`, for adversarial "second blob" wires.
    const OTHER_BLAKE3_HEX: &str =
        "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[test]
    fn a_claim_names_exactly_one_content_identity() {
        // The content address lives ONLY in the payload; offers are pure locators.
        let claim = sample_claim();
        assert_eq!(claim.content_id(), Some(&blake3_id()));
        let on_wire: Value = serde_json::from_slice(&encode_claim(&claim).unwrap()).unwrap();
        assert_eq!(on_wire["payload"]["blake3"], BLAKE3_HEX);
        for offer in on_wire["transports"].as_array().unwrap() {
            assert!(
                offer.get("blake3").is_none(),
                "a transport offer must NOT carry its own blake3 (finding 1): {offer}"
            );
        }
    }

    #[test]
    fn a_second_payload_via_a_stray_top_level_field_is_rejected() {
        // fails-before: the #[serde(flatten)] extra catch-all captured stray
        // top-level fields, so a wire could smuggle a SECOND payload (a two-blob
        // claim). passes-after: `deny_unknown_fields` REJECTS any unknown
        // top-level field - evolution bumps schema_version instead.
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [],
            "transports": [],
            "payload_shadow": { "kind": "whole_nar", "blake3": OTHER_BLAKE3_HEX }
        });
        let bytes = serde_json::to_vec(&wire).unwrap();
        assert!(
            matches!(decode_claim(&bytes), Err(ClaimCodecError::Malformed(_))),
            "a stray top-level field (a smuggled 2nd payload) must be rejected"
        );
    }

    #[test]
    fn a_stray_offer_blake3_cannot_introduce_a_second_identity() {
        // A known iroh offer with a DIFFERENT stray blake3: the typed offer has no
        // digest field, so it is ignored and the claim still has ONE identity.
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [NODE_A_HEX],
            "transports": [
                { "transport": "iroh", "node": NODE_A_HEX, "blake3": OTHER_BLAKE3_HEX }
            ]
        });
        let claim = decode_claim(&serde_json::to_vec(&wire).unwrap()).expect("decode");
        assert_eq!(claim.content_id(), Some(&blake3_id()));
        assert_eq!(
            claim.transports,
            vec![KnownTransport::Iroh { node: node_a() }],
            "the stray offer blake3 is not part of the typed offer - no 2nd identity"
        );
    }

    #[test]
    fn an_unknown_offer_carrying_a_digest_is_dropped_not_a_second_identity() {
        // fails-before: an Unknown(Value) offer retained a whole object - including
        // a second blake3 - as a live value. passes-after: an unknown transport is
        // DROPPED entirely, so no digest rides in on it.
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [],
            "transports": [
                { "transport": "webseed", "url": "https://x.invalid", "blake3": OTHER_BLAKE3_HEX }
            ]
        });
        let claim = decode_claim(&serde_json::to_vec(&wire).unwrap()).expect("decode");
        assert_eq!(claim.content_id(), Some(&blake3_id()));
        assert!(
            claim.transports.is_empty(),
            "the unknown transport (and its stray digest) must be dropped, not carried"
        );
    }

    // --- FINDINGS 1 & 4 root cause (freeze round 4): DUPLICATE-KEY rejection.
    // serde_json accepts duplicate keys (last wins), an ambiguous parse on a
    // frozen wire. We reject any repeated key at any level -> one canonical parse.
    // json!() cannot express duplicate keys, so these wires are built as strings.

    #[test]
    fn duplicate_payload_digest_key_is_rejected() {
        // Two `payload.blake3` values: last-wins would smuggle a SECOND blob
        // (finding 1). The ambiguous wire is rejected outright.
        let wire = format!(
            "{{\"schema_version\":{CLAIM_SCHEMA_VERSION},\"key\":\"{KEY_HEX}\",\
             \"payload\":{{\"kind\":\"whole_nar\",\"blake3\":\"{BLAKE3_HEX}\",\
             \"blake3\":\"{OTHER_BLAKE3_HEX}\"}},\"holders\":[],\"transports\":[]}}"
        );
        match decode_claim(wire.as_bytes()) {
            Err(ClaimCodecError::Malformed(why)) => {
                assert!(
                    why.contains("duplicate key"),
                    "should name the duplicate: {why}"
                )
            }
            other => panic!("a duplicate payload.blake3 must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_kind_key_is_rejected() {
        // `kind` repeated - a malformed `whole_nar` followed by a future kind.
        // last-wins would keep `future_kind`, silently DROPPING the malformed
        // known (finding 4). Rejected instead.
        let wire = format!(
            "{{\"schema_version\":{CLAIM_SCHEMA_VERSION},\"key\":\"{KEY_HEX}\",\
             \"payload\":{{\"kind\":\"whole_nar\",\"blake3\":\"blake3:not-hex\",\
             \"kind\":\"future_kind\"}},\"holders\":[],\"transports\":[]}}"
        );
        assert!(matches!(
            decode_claim(wire.as_bytes()),
            Err(ClaimCodecError::Malformed(_))
        ));
    }

    #[test]
    fn duplicate_top_level_and_nested_offer_keys_are_rejected() {
        // A repeated top-level key...
        let dup_top = format!(
            "{{\"schema_version\":{CLAIM_SCHEMA_VERSION},\"key\":\"{KEY_HEX}\",\
             \"payload\":{{\"kind\":\"whole_nar\",\"blake3\":\"{BLAKE3_HEX}\"}},\
             \"holders\":[],\"holders\":[\"{NODE_A_HEX}\"],\"transports\":[]}}"
        );
        assert!(matches!(
            decode_claim(dup_top.as_bytes()),
            Err(ClaimCodecError::Malformed(_))
        ));
        // ...and a repeated key nested inside an offer object (inside an array).
        let dup_nested = format!(
            "{{\"schema_version\":{CLAIM_SCHEMA_VERSION},\"key\":\"{KEY_HEX}\",\
             \"payload\":{{\"kind\":\"whole_nar\",\"blake3\":\"{BLAKE3_HEX}\"}},\
             \"holders\":[],\"transports\":[{{\"transport\":\"iroh\",\
             \"node\":\"{NODE_A_HEX}\",\"node\":\"{NODE_B_HEX}\"}}]}}"
        );
        assert!(matches!(
            decode_claim(dup_nested.as_bytes()),
            Err(ClaimCodecError::Malformed(_))
        ));
    }

    #[test]
    fn a_canonical_dup_free_claim_still_decodes() {
        // The guard must not reject a legitimate, duplicate-free claim.
        let claim = sample_claim();
        let bytes = encode_claim(&claim).unwrap();
        assert_eq!(decode_claim(&bytes).unwrap(), claim);
    }

    // --- Forward-compat (freeze round 3): unknown KIND is TOLERATED-BUT-INERT
    // (decode succeeds, nothing carried); a malformed KNOWN kind is an ERROR.
    // Wave-2a has no relay, so nothing is preserved; lossless relay is task-55.

    /// Bytes a NEWER peer would send: a `castore_root` payload this build does not
    /// know, and a `webseed` transport it does not know.
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
    fn unknown_kind_is_tolerated_inert_and_not_carried() {
        // task-37 AC#1 ("parses and is ignored, not an error") - now WITHOUT the
        // lossless clause. Decode succeeds; the unknown payload is inert (no
        // content id); the known iroh offer survives; the unknown webseed offer
        // is DROPPED. Nothing unknown is retained.
        let claim = decode_claim(&future_variant_claim_bytes())
            .expect("a future-variant claim must decode, not error");
        assert_eq!(
            claim.content_id(),
            None,
            "an unknown payload kind yields no usable content id (inert)"
        );
        assert_eq!(
            claim.transports,
            vec![KnownTransport::Iroh { node: node_a() }],
            "the known offer survives; the unknown one is dropped, not kept"
        );
        // And the drop is real: re-encoding does NOT resurrect the unknown offer
        // or payload (nothing is preserved - task-55 revisits this for relay).
        let reencoded: Value = serde_json::from_slice(&encode_claim(&claim).unwrap()).unwrap();
        assert!(
            reencoded.get("payload").is_none(),
            "inert payload not re-emitted"
        );
        assert_eq!(
            reencoded["transports"].as_array().unwrap().len(),
            1,
            "the dropped unknown offer is not re-emitted"
        );
    }

    // --- Malformed KNOWN kind ERRORS (the task-13 fix, kept) ----------------

    /// A control mimicking the OLD swallow behaviour: an untagged enum turns a
    /// malformed KNOWN variant into `Unknown` instead of erroring. Our field
    /// deserializers must instead ERROR. Kept so the fails-before is permanent.
    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    #[allow(dead_code)]
    enum UntaggedPayload {
        Known(KnownPayload),
        Unknown(Value),
    }

    #[test]
    fn malformed_known_payload_in_a_claim_errors() {
        // fails-before control: untagged decode swallows a malformed known kind.
        let bad = serde_json::json!({ "kind": "whole_nar", "blake3": "blake3:not-hex" });
        let swallowed: UntaggedPayload = serde_json::from_value(bad).unwrap();
        assert!(
            matches!(swallowed, UntaggedPayload::Unknown(_)),
            "control: untagged decode swallows a malformed known variant (the bug)"
        );
        // passes-after: the claim decode ERRORS on the malformed known payload.
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": "blake3:not-hex" },
            "holders": [],
            "transports": []
        });
        assert!(
            matches!(
                decode_claim(&serde_json::to_vec(&wire).unwrap()),
                Err(ClaimCodecError::Malformed(_))
            ),
            "a malformed whole_nar payload must ERROR, not become inert"
        );
    }

    #[test]
    fn malformed_known_transport_in_a_claim_errors() {
        // A KNOWN transport (`iroh`) with a malformed node must ERROR the decode -
        // this is the codex finding that a malformed known must not be dropped.
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [],
            "transports": [ { "transport": "iroh", "node": "not-hex" } ]
        });
        assert!(
            matches!(
                decode_claim(&serde_json::to_vec(&wire).unwrap()),
                Err(ClaimCodecError::Malformed(_))
            ),
            "a malformed known iroh offer must ERROR, not be dropped"
        );
    }

    // --- Decode SIZE BOUND (freeze round 3) --------------------------------

    #[test]
    fn oversize_input_is_rejected_before_parse() {
        // A valid claim padded past the cap via a huge holders list. It is
        // well-formed JSON, so ONLY the size gate rejects it - proving the bound
        // fails fast rather than allocating an unbounded parse tree.
        let mut holders = String::new();
        while holders.len() < MAX_CLAIM_WIRE_BYTES + 1024 {
            holders.push_str(&format!("\"{NODE_A_HEX}\","));
        }
        let huge = format!(
            "{{\"schema_version\":{CLAIM_SCHEMA_VERSION},\"key\":\"{KEY_HEX}\",\
             \"holders\":[{}\"{NODE_A_HEX}\"],\"transports\":[]}}",
            holders
        );
        assert!(huge.len() > MAX_CLAIM_WIRE_BYTES);
        match decode_claim(huge.as_bytes()) {
            Err(ClaimCodecError::Malformed(why)) => {
                assert!(why.contains("cap"), "size error should name the cap: {why}");
            }
            other => panic!("oversize input must be rejected, got {other:?}"),
        }
        // A normal claim is far under the cap and decodes fine.
        assert!(encode_claim(&sample_claim()).unwrap().len() < MAX_CLAIM_WIRE_BYTES);
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
        let offer = KnownTransport::BitTorrent {
            infohash: infohash(),
        };
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
        let back: KnownTransport = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(offer, back);
    }

    #[test]
    fn iroh_offer_is_a_pure_node_locator() {
        let offer = KnownTransport::Iroh { node: node_a() };
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
                offers: vec![KnownTransport::Iroh { node: node_a() }],
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
                offers: vec![KnownTransport::Iroh { node: node_a() }],
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
