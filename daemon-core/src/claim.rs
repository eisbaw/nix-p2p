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
//!   * [`BatchHoldQuery`] / [`BatchHoldResponse`] (task-91) - the SAME question
//!     asked about a whole closure at once: N named NarHashes, one round trip,
//!     one positional yes/no vector back. ADDED ALONGSIDE the single-key form,
//!     which is unchanged; both are pinned byte-for-byte in
//!     `daemon/tests/golden/claim_wire_v1.json`. No KNOWN-offer enumeration: the
//!     answer is positional over keys the asker already named, and its KNOWN
//!     offers are bounded one-per-transport-kind. An unknown-KIND offer can no
//!     longer name a LIST of identities either (task-224): the shared
//!     tolerate-drop decoder rejects an unknown offer whose SHAPE (array, nested
//!     object, or more than one scalar field) could name unqueried identities.
//!     A residual remains, NOT closed: the one tolerated opaque scalar is
//!     unbounded, so identities delimiter-crammed into a single string are still
//!     accepted - a byte-volume channel owned by task-223, strictly more
//!     permissive than a type-validated known-transport locator.
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
use sha2::{Digest, Sha256};

use crate::content_id::Blake3Digest;
use crate::source::NarHash;
use crate::transport::{BitTorrentInfoHash, NodeId};
use peer_fabric::TransportTag;

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

    /// The Nix `NarHash` of a raw NAR: `sha256(RawNarV1)` over the EXACT
    /// `nix-store --dump <path>` byte stream (the uncompressed NAR), wrapped as the
    /// strict key. This is the sha256 TWIN of [`Blake3Digest::from_raw_nar`],
    /// computed from the IDENTICAL bytes, so a holder derives both content
    /// identities from one dump - and the availability index can assert
    /// `from_raw_nar(dump) == key` at the source (task-56), catching a
    /// mis-registration before it becomes a false claim.
    ///
    /// The comparison the index does is in RAW-BYTE space (`NarHashKey ==
    /// NarHashKey`), so there is no base32-vs-hex ambiguity to get wrong: both
    /// sides are the 32 raw sha256 bytes.
    ///
    /// CARRIED UNIT TRAP (bitten the project 3x): the input MUST be the
    /// UNCOMPRESSED dump, never a compressed `.nar.xz`/`.nar.zst`. That this recipe
    /// reproduces Nix's OWN committed NarHash on a real store path is proven by
    /// `scripts/check-golden-vectors.py`, which computes `sha256(real --dump)` over
    /// the `lib` fixture and asserts it equals the golden/manifest `nar_hash`,
    /// cross-checking the same nix-base32 encoding this key's `Display` uses.
    pub fn from_raw_nar(raw_nar: &[u8]) -> Self {
        let digest = Sha256::digest(raw_nar);
        let mut bytes = [0u8; NAR_HASH_LEN];
        bytes.copy_from_slice(&digest);
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
/// STRICT: an unknown FIELD inside a KNOWN kind is rejected. That is a different
/// rule from the tolerate-but-drop applied to an unknown KIND, and both are
/// deliberate - a kind we do not understand is inert, but a kind we DO understand
/// must mean exactly what we think it means. Without this, a payload could carry a
/// second identity-like field beside its `blake3` and be silently accepted, which
/// is the two-blob-claim class the freeze closed for `Claim` itself and left open
/// one type down. Struct variants only, so `deny_unknown_fields` is honoured (it
/// is silently inert on unit variants - see `BatchHoldAnswer`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
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
/// STRICT, for the same reason as [`KnownPayload`] and with more exposure: a
/// `KnownTransport` sits inside the batch offer DICTIONARY, so an accepted junk
/// field there is a padding channel bounded only by the 64 KiB wire gate, and an
/// `also_held: ["sha256:..."]` was accepted on the wire (dropped, but accepted) by
/// the very message type whose docs say no field can name an unasked key.
///
/// THE TRADE-OFF, STATED: this tightens what the FROZEN `Claim.transports` and
/// `HoldAnswer::Have.offers` accept - a v1 wire carrying an extra field inside a
/// KNOWN transport used to decode and now does not. It is not a change to
/// anything we EMIT (the golden encoding vectors are byte-identical), and it is
/// consistent with the existing rule that a MALFORMED known transport is a hard
/// error rather than a dropped one. Unknown transport KINDS are still tolerated
/// and dropped; that is the forward-compatibility seam and it is untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
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

impl KnownTransport {
    /// The `transport` tag this offer serialises as.
    ///
    /// Exists so the batch binding rules can ask "which KIND is this?" without
    /// re-serialising. It must agree with [`KNOWN_TRANSPORT_TAGS`] and with the
    /// serde attributes above; `known_transport_tags_agree_with_the_wire_tags`
    /// asserts all three against each other, because three hand-maintained lists
    /// of the same fact is exactly how a tag drifts.
    pub(crate) fn wire_tag(&self) -> &'static str {
        match self {
            KnownTransport::Iroh { .. } => "iroh",
            KnownTransport::BitTorrent { .. } => "bittorrent",
        }
    }

    /// The seam [`TransportTag`] this daemon-wire offer dispatches on. The daemon's
    /// wire offer enum and the seam's `peer_fabric::TransportOffer` are DIFFERENT
    /// representations of the same intent, so each maps to the shared tag on its
    /// own type (the seam's `TransportTag::of` takes the seam's offer). Both agree
    /// on the frozen `"iroh"`/`"bittorrent"` wire tags: that `TransportTag::as_str`
    /// equals this offer's [`KnownTransport::wire_tag`] is asserted directly in
    /// `known_transport_tags_agree_with_the_wire_tags` (via `offer.tag().as_str()`),
    /// so the seam string cannot silently drift from what the daemon emits.
    pub fn tag(&self) -> TransportTag {
        match self {
            KnownTransport::Iroh { .. } => TransportTag::Iroh,
            KnownTransport::BitTorrent { .. } => TransportTag::BitTorrent,
        }
    }

    /// Convert this daemon-wire offer into the seam's
    /// [`peer_fabric::TransportOffer`] - the pure locator a
    /// [`peer_fabric::NarTransfer`] backend fetches from. This is the ONE place the
    /// daemon's claim-wire offer representation crosses into the stack-neutral seam
    /// representation (TASK-148 de-weld): a backend below the seam never sees
    /// `KnownTransport`, only `TransportOffer`. The value carries over unchanged -
    /// `NodeId` and `BitTorrentInfoHash` ARE the seam's `NodeId`/`InfoHash` (the
    /// daemon re-exports them from `peer_fabric`), so no locator information is lost
    /// or reinterpreted.
    pub fn to_offer(&self) -> peer_fabric::TransportOffer {
        match self {
            KnownTransport::Iroh { node } => peer_fabric::TransportOffer::Iroh { node: *node },
            KnownTransport::BitTorrent { infohash } => peer_fabric::TransportOffer::BitTorrent {
                infohash: *infohash,
            },
        }
    }
}

/// FREEZE AMENDMENT (TASK-224): the maximal SHAPE a tolerated unknown-KIND
/// transport offer may take on the wire. Returns `Err(reason)` for a shape that
/// could NAME content identities the asker never queried; the caller turns that
/// into a hard decode error (NOT a silent drop).
///
/// ## The tension this resolves
/// Forward compatibility (TASK-110 AC#4) requires an unknown FUTURE transport
/// KIND to decode INERTLY, so a build that speaks it ships without a wire fork.
/// The no-enumeration invariant (PRD privacy invariant) requires that an offer
/// the asker did not query cannot NAME content identities on the wire. Before
/// this amendment the two collided: an unknown-kind offer was peeked for its
/// `transport` tag ONLY and the rest of the object was accepted as an opaque
/// [`Value`] and then dropped - so `{"transport":"future","content_ids":
/// ["blake3:..","blake3:.."]}` was ACCEPTED (then dropped). That is exactly the
/// accept-then-drop enumeration defect the KNOWN-transport rule near
/// [`KNOWN_TRANSPORT_TAGS`] (and the `also_held` rule elsewhere in this file)
/// forbids, leaking onto the unknown-KIND path. codex proved it with an
/// executable probe at the TASK-110 re-gate.
///
/// ## The rule (approach A: a whitelisted minimal shape, REJECT on violation)
/// A tolerated unknown-kind offer is an OBJECT carrying the `transport` tag and
/// AT MOST ONE other field, whose value must be a SCALAR STRING (a single opaque
/// locator). Any ARRAY, any NESTED OBJECT, any NON-STRING extra value, a SECOND
/// non-`transport` field, or an array/object in the `transport` slot itself
/// REJECTS the whole decode - it is not silently dropped, because
/// accepting-then-dropping a wire that NAMED identities is itself the defect, so
/// the wire must be un-acceptable, not merely un-used.
///
/// ## Two disclosed costs of this narrowing (it is not free)
/// 1. FORWARD-COMPAT REGRESSION vs TASK-110 AC#4. The old seam tolerated an
///    unknown offer of ANY shape and dropped it, so a future transport shipped
///    without a wire fork. Now a future transport whose locator needs TWO+ scalar
///    fields (host+port, node+relay-url, url+auth - all plausible; iroh itself
///    commonly needs node + relay/direct-addrs) is a HARD decode error on THIS
///    build, not an inert drop. That is the price of foreclosing the
///    `{"a":id,"b":id}` multi-field enumeration vector: the two are the same
///    affordance. A future multi-locator transport therefore DOES need a wire
///    revision (a new envelope/schema bump), which it would have needed anyway to
///    be understood - but it no longer decodes inertly on older builds.
/// 2. A non-OBJECT offer element (a bare array/string/number sitting in the offer
///    list) was previously dropped; it is now a hard error too. No emitted or
///    golden-accepted wire uses that shape, so nothing legitimate breaks, but it
///    is behaviour beyond the strictly-named scope, recorded here deliberately.
///
/// ## What this closes, what it does NOT, and why NOT a byte cap
/// This removes the FORMAT-LEVEL affordance to express a LIST of identities: an
/// array, a nested object, or a second scalar field can no longer appear, so
/// volunteering a list of holdings is INEXPRESSIBLE in the schema. That is the
/// structural half - the exact shape codex's probe used.
///
/// It is NOT literal parity with a known transport, and this doc must not claim
/// it is. A known transport's locator is TYPE-VALIDATED and fixed-length
/// (`iroh`'s `node` is exactly 64 hex chars via `NodeId::from_str`;
/// `bittorrent`'s `infohash` likewise), so a crammed string simply fails to
/// parse - it has NO cramming residual. The single scalar tolerated here is
/// arbitrary-length and arbitrary-content (we cannot validate a format we do not
/// know), so it is STRICTLY MORE PERMISSIVE: a hostile
/// `{"transport":"future","loc":"blake3:a,blake3:b,..."}` is still ACCEPTED and
/// still names identities as raw text. That residual is a BYTE-VOLUME channel
/// (how many delimited identities fit scales with bytes, bounded only by
/// [`MAX_CLAIM_WIRE_BYTES`]); it is deliberately left to TASK-223's per-offer
/// byte cap, NOT closed here. No length cap is added in this task because (a) a
/// cap does not change the KIND of the residual - codex already showed a byte
/// cap still admits several SHORT identities per slot - and (b) a legitimate
/// future locator may itself be large and needs its own forward-compat analysis
/// (the recorded TASK-110/223 rationale). So: structural list-affordance CLOSED;
/// crammable unbounded-scalar residual OPEN and owned by TASK-223.
///
/// Applied at BOTH tolerate-drop decoders via this one helper
/// ([`deserialize_known_transports`] for [`Claim::transports`],
/// [`deserialize_transport_slots`] for the single-key AND batch hold-response
/// offer dictionaries), so the rule lives once (like [`KNOWN_TRANSPORT_TAGS`])
/// and the two cannot drift - asserted by
/// `the_slot_and_drop_transport_decoders_agree`. Pinned by
/// `an_unknown_kind_offer_cannot_name_content_ids_on_the_wire_on_both_paths` and
/// the golden `reject_*_unknown_transport_names_content_ids` vectors.
fn reject_enumeration_shaped_unknown_offer(value: &Value) -> Result<(), String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "an unknown-kind transport offer must be a JSON object".to_string())?;
    let mut extra_fields = 0usize;
    for (field_name, field_value) in obj {
        if field_name == "transport" {
            // The tag slot must be a bare scalar (a string, or absent/non-string
            // which decodes to an empty tag). An array or object THERE would be a
            // smuggling channel of its own.
            if field_value.is_array() || field_value.is_object() {
                return Err(
                    "an unknown-kind transport offer's `transport` tag is an array or object; \
                     that can name content identities the asker never queried"
                        .to_string(),
                );
            }
            continue;
        }
        extra_fields += 1;
        if extra_fields > 1 {
            return Err(format!(
                "an unknown-kind transport offer carries more than one field besides \
                 `transport` (`{field_name}` is a second); at most one bounded scalar string \
                 locator is tolerated, or it could name content identities the asker never \
                 queried"
            ));
        }
        if !field_value.is_string() {
            return Err(format!(
                "an unknown-kind transport offer field `{field_name}` is not a scalar string; \
                 an array or nested object is a LIST affordance for naming several content \
                 identities at once, which the schema must not express (a single string is \
                 tolerated as one opaque locator, though its bytes are still bounded only by \
                 the frame - task-223)"
            ));
        }
    }
    Ok(())
}

/// Field deserializer for a transport-offer list: TOLERATE-BUT-DROP unknown
/// transports. Each element is peeked; a KNOWN transport is strict-parsed (a
/// malformed known transport ERRORS the whole decode), an unknown transport tag
/// is DROPPED from the set (not retained, not re-serialized). Used by
/// [`Claim::transports`]; the hold-response paths (single-key AND batch) decode
/// their offers via [`deserialize_transport_slots`] instead (same tolerate-drop
/// rule, slot-preserving), so the unknown-KIND residual below is shared by both.
///
/// NO-ENUMERATION SHAPE RULE (TASK-224): an unknown-KIND element is peeked for
/// its `transport` tag, then its SHAPE is checked by
/// [`reject_enumeration_shaped_unknown_offer`] before it is dropped. An unknown
/// offer carrying an array, a nested object, or more than one scalar field (e.g.
/// `{"transport":"future","content_ids":[..]}`) is now REJECTED, not accepted
/// then discarded - closing the STRUCTURAL half of the `also_held` enumeration
/// case that [`deny_unknown_fields`] forecloses for a KNOWN transport, on the
/// unknown-KIND path. A well-shaped unknown offer (`transport` tag + at most one
/// scalar string locator) still decodes INERTLY (dropped); a plausible future
/// SINGLE-locator transport is preserved, a future MULTI-field one is now
/// rejected (see the helper doc's disclosed costs). The unbounded single scalar
/// is still delimiter-crammable (byte-volume residual, task-223). The identical
/// rule guards [`deserialize_transport_slots`] (the shared hold-response path);
/// the two are kept in step by `the_slot_and_drop_transport_decoders_agree`.
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
        } else {
            // An unknown transport is dropped (inert), never carried - but only if
            // its SHAPE cannot name content identities (TASK-224); an
            // enumeration-shaped unknown offer is a hard error, not a silent drop.
            reject_enumeration_shaped_unknown_offer(&value).map_err(serde::de::Error::custom)?;
        }
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

/// The answer to a [`HoldQuery`]: have-with-offers, or absent. Yes/no over the
/// queried hash; its KNOWN offers name no other holdings and are bounded
/// one-per-transport-kind. An unknown-KIND offer can no longer name a LIST of
/// content identities either (task-224): the shared tolerate-drop decoder
/// rejects an unknown offer whose SHAPE could name unqueried identities (see
/// [`reject_enumeration_shaped_unknown_offer`]). A well-shaped unknown transport
/// offer is still dropped on decode (tolerated but inert); its one unbounded
/// scalar is still delimiter-crammable (byte-volume residual, task-223).
///
/// ## Bounded to ONE offer per transport KIND (task-110 freeze amendment)
///
/// `offers` answers about EXACTLY ONE key, and the content behind a key has one
/// identity per transport kind, so a legitimate `Have` needs at most one offer
/// per kind. That bound is ENFORCED at both wire boundaries by
/// [`check_single_offer_bindings`] (at most [`MAX_OFFERS_PER_ANSWER`], one per
/// kind), against the RAW pre-drop offer list so unknown kinds are counted before
/// they are dropped - see that function's doc for the freeze-amendment rationale
/// and for what this does and does NOT bound. It is the single-key twin of the
/// batch rule in [`check_batch_offer_bindings`].
///
/// WHAT THIS BOUNDS, PRECISELY: the offer COUNT (at most 4 slots, one per kind)
/// and thus the number of KNOWN-transport content identities a `Have` can name -
/// the KNOWN-offer enumeration, consistent with the batch path's
/// `deny_unknown_fields`. The unknown-KIND enumeration's STRUCTURAL half is
/// closed SEPARATELY (TASK-224, [`reject_enumeration_shaped_unknown_offer`]): an
/// unknown offer whose shape (array / nested object / multiple scalar fields)
/// could name a LIST of identities is REJECTED, so it cannot list-smuggle on the
/// wire (a single crammed scalar residual remains, task-223).
/// This COUNT bound does NOT bound the message BYTES: a well-shaped unknown-kind
/// slot still has a byte-unbounded single scalar, so a hostile peer can still pad
/// a single-key `Have` up to [`MAX_CLAIM_WIRE_BYTES`] (64 KiB) with
/// as few as one dropped unknown offer. That byte ceiling is the pre-existing frame
/// gate, identical before and after this amendment and identical to the batch
/// path; a per-offer byte cap is deliberately deferred (TASK-223) because a
/// future transport's legitimate locator may itself be large.
///
/// NOTE THE MISSING `Deserialize` (same reason as [`BatchHoldResponse`]): the
/// bound is only a bound if the validator is the ONLY path from bytes. Unknown
/// transport kinds are tolerated-but-dropped on decode, so the offers are parsed
/// into position-preserving [`OfferSlot`]s, bound-checked against the raw list,
/// and only then dropped - all inside [`decode_hold_response`]. A derived
/// `Deserialize` would let a caller skip that and re-open the amplification. The
/// non-`Deserialize` fact is enforced by coherence in [`not_deserialize`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
pub enum HoldAnswer {
    /// "Yes, I hold it": the single content identity (`blake3`) for the queried
    /// key, plus pure-locator offers. The `blake3` lives here exactly once - a
    /// Have has no payload - so the offers carry no digest to disagree with it. A
    /// consumer fetches the `blake3` via any offer's locator. Bounded to one
    /// offer per transport kind (see the type doc).
    Have {
        blake3: Blake3Digest,
        offers: Vec<KnownTransport>,
    },
    /// "No, I do not hold it."
    Absent,
}

/// The versioned response envelope for a [`HoldQuery`]. The answer is FLATTENED
/// so the wire is `{schema_version, answer, [offers]}` - `answer` is the yes/no
/// tag (`have`/`absent`), not a nested object.
///
/// NOT `Deserialize`, deliberately (see [`HoldAnswer`] and [`not_deserialize`]):
/// [`decode_hold_response`] is the ONLY way to build one from bytes, because the
/// offer bound has to run against the RAW pre-drop offer list. A derived
/// `Deserialize` compiled cleanly and silently skipped the bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HoldResponse {
    pub schema_version: u16,
    #[serde(flatten)]
    pub answer: HoldAnswer,
}

/// The wire twin of [`HoldResponse`] used ONLY by [`decode_hold_response`]. It
/// differs from [`HoldResponse`] in one way: a `Have`'s offer list keeps a SLOT
/// for every element the peer sent, an unknown transport kind decoding to an
/// [`OfferSlot::Unknown`] rather than vanishing. Keeping the slot is what lets the
/// one-per-kind + count bound COUNT unknown kinds against the same cap as known
/// ones - so the number of OFFERS is bounded even when they would be dropped -
/// while still dropping them from the value a caller sees (forward
/// compatibility). This bounds the offer COUNT; the content IDENTITIES a single
/// unknown offer could name are bounded SEPARATELY by the shape rule (task-224,
/// [`reject_enumeration_shaped_unknown_offer`] - no array/nested/multi-field
/// body). It does NOT bound the message BYTES: a well-shaped unknown offer's
/// single scalar is byte-unbounded and a peer can still pad a one-key answer up
/// to [`MAX_CLAIM_WIRE_BYTES`] (task-223) - see [`HoldAnswer`] and
/// [`check_single_offer_bindings`] for what is and is not closed.
#[derive(Deserialize)]
struct HoldResponseWire {
    schema_version: u16,
    #[serde(flatten)]
    answer: HoldAnswerWire,
}

/// The wire twin of [`HoldAnswer`]: identical acceptance to the frozen type
/// EXCEPT that `Have.offers` decodes into position-preserving [`OfferSlot`]s
/// (unknown kinds preserved for counting, then dropped by
/// [`keep_known_offers`]). No `deny_unknown_fields` is added - that would narrow
/// acceptance beyond this task's scope; only the offer COUNT/kind is bounded.
#[derive(Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
enum HoldAnswerWire {
    Have {
        blake3: Blake3Digest,
        #[serde(default, deserialize_with = "deserialize_transport_slots")]
        offers: Vec<OfferSlot>,
    },
    Absent,
}

// -------------------------------------------------------------------------
// BATCHED query envelope (task-91): one round trip for a whole CLOSURE.
//
// ADDED ALONGSIDE the single-key form above, which is FROZEN and unchanged -
// [`HoldQuery`], [`HoldAnswer`] and [`HoldResponse`] keep their exact bytes
// (pinned in `daemon/tests/golden/claim_wire_v1.json`). A peer that speaks only
// the single-key form is unaffected; the batch is a new message kind on the same
// `QUERY_SCHEMA_VERSION` envelope.
// -------------------------------------------------------------------------

/// Maximum number of keys ONE [`BatchHoldQuery`] may name, and therefore the
/// maximum number of answers one [`BatchHoldResponse`] may carry. A cap, not a
/// suggestion: over-cap is REJECTED, never truncated (a truncated answer would be
/// a silent wrong "no" for the dropped keys).
///
/// Why 256 and not 8, or 4096:
///   * A real Nix closure is ~200 store paths, so 256 resolves the common closure
///     in ONE round trip instead of ~200. Bigger closures chunk (a 1000-path
///     closure is 4 probes per peer, not 1000).
///   * It keeps BOTH directions inside the existing [`MAX_CLAIM_WIRE_BYTES`]
///     pre-parse gate. MEASURED, not estimated (and asserted by
///     `a_full_batch_fits_the_wire_cap_with_headroom`): a full 256-key query is
///     15 901 B; a full 256-`Have` response sharing ONE iroh locator is 31 114 B;
///     the same response with a DISTINCT per-content locator for every key is
///     58 910 B. All three fit the 64 KiB gate, but the last has only ~10% spare -
///     that is the honest limit of this cap, and the reason the offers are indexed
///     rather than inlined (inlining that case costs ~79 KiB, OVER the gate, so a
///     peer holding all 256 keys over two transports could not answer at all).
///     Raising the cap to 1024 puts the response over the gate: the wire size
///     bound and the key cap must be chosen together.
///   * It bounds the WORK one message can demand: at most 256 index probes, each
///     of which may cost one `nix-store --dump`. Note this is not NEW work - it
///     is exactly what the same 256 single-key probes cost today. Batching
///     removes round trips; it does not add per-key cost. A per-batch work/time
///     budget (so one message cannot monopolise a responder) is TASK-104.
pub const MAX_BATCH_HOLD_KEYS: usize = 256;

/// Maximum number of DISTINCT transport offers one [`BatchHoldResponse`]'s offer
/// dictionary may carry.
///
/// Two transports per answered key is the most this build can express (`iroh` +
/// `bittorrent`), so `2 * MAX_BATCH_HOLD_KEYS` is the largest dictionary a legal
/// full batch could ever need. It is an EXPLICIT bound rather than a derived one
/// because the real binding constraint - [`MAX_CLAIM_WIRE_BYTES`] - is a byte
/// count, and a byte count is not a thing a reviewer can check a decoder against.
/// Both are enforced: this cap, and `check_size` on the encoder's OUTPUT.
pub const MAX_BATCH_HOLD_OFFERS: usize = 2 * MAX_BATCH_HOLD_KEYS;

/// Maximum number of offers ONE answer may name, and therefore the number of
/// dictionary entries each ANSWERED key can justify.
///
/// This is the bound that makes the dictionary a function of what was ANSWERED
/// rather than of the mere existence of one `Have`. Without it, "every entry is
/// referenced by at least one `Have`" is satisfied by a SINGLE `Have` naming the
/// whole dictionary: a one-key question could be answered with 512 BitTorrent
/// infohashes - 511 content identities the asker never named - at 613.8x wire
/// amplification. Measured, not hypothesised: see
/// `a_single_have_cannot_legitimise_a_pile_of_content_locators`.
///
/// Why 4 and not 2: a locator is meaningful once per transport KIND (the content
/// has one identity, so a second infohash for the same key names a second blob),
/// and this build knows 2 kinds. The extra headroom is for FORWARD
/// COMPATIBILITY: a future peer offering two transports this build has never
/// heard of must still be able to answer, because unknown kinds occupy
/// dictionary slots until compaction. A peer needing more than 4 locators for
/// one key is refused, which is a pinned, reviewable limit rather than an
/// accident.
pub const MAX_OFFERS_PER_ANSWER: usize = 4;

/// A probe about MANY content identities at once: "of these N NarHashes, which do
/// you hold?". One round trip replaces N.
///
/// ## Answers are NOT enumeration (KNOWN closed; unknown-KIND list-shape closed: task-110/224)
///
/// The asker names every key. The answer ([`BatchHoldResponse`]) is a POSITIONAL
/// vector over exactly those keys and carries no keys of its own in its KNOWN
/// structure. Nor can a Have's unknown-KIND offer name a LIST of unqueried hashes
/// anymore (task-224): the shared decoder rejects an unknown offer whose SHAPE
/// (array/nested/multi-field) could name identities (see
/// [`reject_enumeration_shaped_unknown_offer`]). A byte-volume residual remains -
/// the one tolerated opaque scalar is unbounded and delimiter-crammable
/// (task-223) - so a batch reveals AT MOST what N single [`HoldQuery`] probes
/// would, plus that residual; it removes the round trips. There is still no
/// message in this module that asks a peer "what do you have?", and that remains
/// structural, not a policy. (The
/// privacy invariant being protected is that store-path names are secrets: a node
/// must not be able to harvest a listing it could not already guess.)
///
/// BOUNDED: `keys` is capped at [`MAX_BATCH_HOLD_KEYS`], must be non-empty, and
/// must contain no repeated key. Duplicates are rejected rather than deduplicated
/// so the request has exactly one canonical meaning and the positional answer
/// mapping is unambiguous (the same reasoning as the duplicate-JSON-key guard).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchHoldQuery {
    pub schema_version: u16,
    /// The content identities being probed, in the asker's own order. The answer
    /// vector is aligned to THIS order and has THIS length.
    pub keys: Vec<NarHashKey>,
}

/// Field deserializer for an INDEXED offer dictionary: the same tolerate-but-drop
/// rule as [`deserialize_known_transports`], except an unknown transport leaves a
/// `None` SLOT behind instead of vanishing. The slot matters because the `Have`s
/// index into this list: dropping an element in place would silently rebind every
/// later index. [`compact_offer_slots`] removes the `None`s and rewrites the
/// indices together, which is the only safe order.
///
/// Carries the SAME no-enumeration SHAPE rule as [`deserialize_known_transports`]
/// (TASK-224): the unknown-kind element's SHAPE is checked by
/// [`reject_enumeration_shaped_unknown_offer`] before the slot is dropped, so an
/// unknown offer that would name a LIST of identities (an array, a nested object,
/// more than one scalar field) is REJECTED rather than accepted-then-dropped. A
/// well-shaped unknown offer still leaves an inert `Unknown` slot; its one
/// unbounded scalar remains delimiter-crammable (byte-volume residual, task-223).
/// Proven identical across the batch and single-key paths (and the claim path) by
/// `an_unknown_kind_offer_cannot_name_content_ids_on_the_wire_on_both_paths` and
/// `the_slot_and_drop_transport_decoders_agree`.
///
/// It is a SEPARATE function rather than a refactor of
/// [`deserialize_known_transports`] because the two return DIFFERENT types: the
/// frozen one yields the offers it kept, this one yields a slot per wire element
/// including the dropped ones. Collapsing them would mean the frozen decoder
/// allocating slots it has no use for.
///
/// It previously justified itself by saying the change had to be textually
/// additive so a "freeze audit (`git diff | grep '^-'` returning nothing)" stayed
/// meaningful. That argument was doubly wrong and is retracted: no such gate
/// exists anywhere in the Justfile or scripts, and the property is false - this
/// file has since had lines removed for good reasons. A duplication has to be
/// paid for with a real guarantee, not an imagined one. The real one: the shared
/// rule (which tags are known) lives once, in [`KNOWN_TRANSPORT_TAGS`], and
/// `the_slot_and_drop_transport_decoders_agree` asserts the two do not diverge
/// on the same inputs, including the hard-error case.
fn deserialize_transport_slots<'de, D>(deserializer: D) -> Result<Vec<OfferSlot>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Vec::<Value>::deserialize(deserializer)?;
    let mut slots = Vec::with_capacity(raw.len());
    for value in raw {
        let tag = value.get("transport").and_then(Value::as_str);
        let is_known = tag.is_some_and(|tag| KNOWN_TRANSPORT_TAGS.contains(&tag));
        if is_known {
            // A malformed KNOWN transport is a hard error, exactly as on a claim.
            slots.push(OfferSlot::Known(
                serde_json::from_value::<KnownTransport>(value)
                    .map_err(serde::de::Error::custom)?,
            ));
        } else {
            // An absent or non-string `transport` has no kind at all; it still
            // occupies a slot (indices must not shift) and is still dropped - but
            // only if its SHAPE cannot name content identities (TASK-224); an
            // enumeration-shaped unknown offer is a hard error, not a silent drop.
            reject_enumeration_shaped_unknown_offer(&value).map_err(serde::de::Error::custom)?;
            slots.push(OfferSlot::Unknown(tag.unwrap_or_default().to_string()));
        }
    }
    Ok(slots)
}

/// One position in a decoded offer dictionary, BEFORE compaction.
///
/// A slot exists for every element the peer sent so that `Have` indices mean the
/// same thing on both nodes. An unknown kind is dropped on compaction, but its
/// wire TAG survives validation: the one-locator-per-kind rule has to tell two
/// DIFFERENT future transports apart from the same one repeated, and a slot that
/// forgot its tag makes those two cases indistinguishable - which would either
/// reject a legal forward-compatible response or admit a padded one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OfferSlot {
    Known(KnownTransport),
    Unknown(String),
}

impl OfferSlot {
    /// The transport tag at this position, known or not.
    fn wire_tag(&self) -> &str {
        match self {
            OfferSlot::Known(offer) => offer.wire_tag(),
            OfferSlot::Unknown(tag) => tag.as_str(),
        }
    }
}

/// View an already-decoded dictionary as slots, so the ENCODE side runs the very
/// same [`check_batch_offer_bindings`] as the decode side. Every entry is `Known`
/// by construction: a value we hold in memory has no unknown kinds left in it.
pub(crate) fn as_offer_slots(offers: &[KnownTransport]) -> Vec<OfferSlot> {
    offers.iter().cloned().map(OfferSlot::Known).collect()
}

/// An index into a [`BatchHoldResponse`]'s offer dictionary. `u16` rather than
/// `usize` so the wire representation is bounded by the type as well as by the
/// range check; the value is additionally required to be `< offers.len()`, which
/// is itself `<= MAX_BATCH_HOLD_OFFERS`.
pub type OfferIndex = u16;

/// One positional answer inside a [`BatchHoldResponse`]: the peer's yes/no about
/// the key at the SAME INDEX in the [`BatchHoldQuery`].
///
/// It deliberately does NOT carry the key it answers. That is what keeps a batch
/// answer from being a listing: detached from the asker's query it is a row of
/// bare yes/no, meaningless on its own.
///
/// ## Why the offers are INDICES and not inline transports
///
/// A transport offer is not always peer-scoped. `Iroh`'s locator is the holder's
/// `NodeId`, one value for the whole batch; `BitTorrent`'s is an `infohash`, which
/// is a PER-CONTENT coordinate. An earlier revision of this type hoisted ONE offer
/// list to the response and let every `Have` share it; that silently bound key 2's
/// claim to key 1's infohash, and let an all-`Absent` response carry a
/// content-specific locator bound to nothing at all. So each `Have` names its OWN
/// locators - but by INDEX into a shared dictionary, so the common case (one iroh
/// offer for all 256 keys) costs one copy of the locator plus 256 small integers
/// instead of 256 copies of the locator. That is not a micro-optimisation: a full
/// 256-key answer carrying an iroh locator AND a per-content infohash measures
/// 58 910 B indexed and ~79 912 B inlined, and the pre-parse gate is 65 536 B - so
/// the inline form makes a legal, fully-populated answer UNSENDABLE. It also keeps
/// the resolver from retaining one copy of the whole dictionary per answered key.
///
/// The binding rules are enforced at BOTH boundaries (see
/// [`check_batch_offer_bindings`]): every index in range, no index repeated inside
/// one `Have`, and every dictionary entry referenced by at least one `Have`.
///
/// `Absent` is an EMPTY STRUCT variant, not a unit variant, and that is load
/// bearing: `deny_unknown_fields` on an internally-tagged enum is honoured for
/// struct variants but is SILENTLY INERT for unit variants, so a unit `Absent`
/// would happily decode `{"answer":"absent","blake3":"..."}`. Verified by
/// experiment, and pinned by `an_absent_batch_answer_rejects_any_field_attached_to_it`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum BatchHoldAnswer {
    /// "Yes, I hold the key at this position": its single content identity, plus
    /// the offers - by index into [`BatchHoldResponse::offers`] - that locate
    /// THIS key. May be empty: a peer can assert a holding whose only locator
    /// this build cannot speak (the unknown transport was dropped on decode), in
    /// which case the claim has no usable fetch coordinate and the fetch falls
    /// back upstream. That is a miss, never a wrong byte.
    Have {
        blake3: Blake3Digest,
        offer_indices: Vec<OfferIndex>,
    },
    /// "No, I do not hold the key at this position." Carries nothing - and, being
    /// a struct variant, REJECTS anything a peer tries to attach.
    Absent {},
}

/// The answer to a [`BatchHoldQuery`]: one [`BatchHoldAnswer`] per queried key, in
/// the query's order, plus the offer dictionary those answers index into.
///
/// `answers.len()` MUST equal the number of keys asked. That is not a courtesy -
/// it is the whole safety argument, so it is checked at the decode boundary
/// ([`decode_batch_hold_response`] takes the asked count and rejects a mismatch)
/// rather than left to each caller. A short answer would silently re-index every
/// later key onto the wrong hash.
///
/// NOTE THE MISSING `Deserialize`, which is deliberate. Unknown transport kinds
/// are TOLERATED-BUT-DROPPED, and dropping an element of an INDEXED dictionary
/// would shift every later index onto the wrong locator - the exact defect the
/// index space exists to prevent. So the dictionary is parsed into
/// position-preserving slots, validated against the RAW positions, and only then
/// compacted and re-indexed. That happens in [`decode_batch_hold_response`], and
/// making this type non-`Deserialize` means no caller can bypass it by parsing the
/// struct directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BatchHoldResponse {
    pub schema_version: u16,
    /// The offer DICTIONARY: every pure locator this response uses, each named by
    /// index from the `Have` it belongs to. Always emitted, empty included, so the
    /// encoding has exactly one canonical form.
    ///
    /// The dictionary is bounded by what was ANSWERED. Every entry must be
    /// referenced by at least one `Have`; each `Have` may name at most
    /// [`MAX_OFFERS_PER_ANSWER`] entries, and at most ONE per transport kind. So
    /// an all-`Absent` response must carry an EMPTY dictionary, and - the part
    /// "every entry is referenced" alone did NOT give - a ONE-key response cannot
    /// carry more than [`MAX_OFFERS_PER_ANSWER`] locators either. Referencing
    /// alone let a single `Have` legitimise the whole 512-entry dictionary, i.e.
    /// 511 content identities the asker never named.
    pub offers: Vec<KnownTransport>,
    /// Positionally aligned with the query's `keys`. Carries no keys of its own.
    pub answers: Vec<BatchHoldAnswer>,
}

/// COMPILE-TIME PROOF that the wire response types do not implement
/// `Deserialize`.
///
/// The bound-runs-before-value safety argument rests on the `decode_*` functions
/// being the only way to build these from bytes. For [`BatchHoldResponse`] that
/// protects the index-remap; for [`HoldResponse`]/[`HoldAnswer`] (task-110) it
/// protects the one-offer-per-kind bound, which runs against the RAW pre-drop
/// slots and would be silently skipped by a derived `Deserialize`. Both were
/// enforced by nothing but the absence of a word: re-adding `Deserialize` to a
/// derive list compiled cleanly and left the whole suite GREEN.
///
/// Rust has no negative trait bound, so the proof is by COHERENCE: the blanket
/// impl below covers every `Deserialize` type, and each specific impl covers one
/// of these types. They overlap if and only if that type is `Deserialize`, and an
/// overlap is E0119 - a build error, not a test failure. There is deliberately no
/// accompanying #[test]: a test would document the fact, and this enforces it.
mod not_deserialize {
    use super::{BatchHoldResponse, HoldAnswer, HoldResponse};

    #[allow(dead_code)] // a coherence vehicle, never called: see the module doc
    pub(super) trait NotDeserialize {}
    impl<T> NotDeserialize for T where T: for<'de> serde::Deserialize<'de> {}
    impl NotDeserialize for BatchHoldResponse {}
    impl NotDeserialize for HoldResponse {}
    impl NotDeserialize for HoldAnswer {}
}

/// The wire twin of [`BatchHoldResponse`] used ONLY by
/// [`decode_batch_hold_response`]. It differs in exactly one way: the offer
/// dictionary keeps a SLOT for every element the peer sent, with an unknown
/// transport kind decoding to `None` instead of vanishing. Keeping the slot is
/// what makes the `Have` indices mean the same thing on both nodes; the compaction
/// that removes the `None`s also rewrites the indices.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchHoldResponseWire {
    schema_version: u16,
    #[serde(deserialize_with = "deserialize_transport_slots")]
    offers: Vec<OfferSlot>,
    answers: Vec<BatchHoldAnswer>,
}

/// Reject a batch response whose offer dictionary and `Have` indices do not bind
/// to each other. Applied on BOTH encode and decode, and on decode against the RAW
/// (pre-compaction) dictionary, so an out-of-range index is a hard error rather
/// than something compaction quietly renumbers away.
///
/// The three rules, and why each is a rule and not a nicety:
///   * IN RANGE - an index past the dictionary has no meaning, and the safe
///     reading of it is not "ignore that offer" but "this response is not
///     interpretable".
///   * NO REPEAT inside one `Have` - a repeated index is duplicated state with two
///     possible readings (one offer, or two identical offers); rejecting it leaves
///     exactly one canonical meaning, the same argument as the duplicate-key guard.
///   * EVERY ENTRY REFERENCED - an unreferenced locator is bound to no answered
///     key. Content-specific locators (`BitTorrent`'s infohash) would then be
///     volunteered rather than answered, which is both meaningless and a
///     no-enumeration leak: it lets an all-`Absent` response say something about
///     content the asker never named.
///   * ONE LOCATOR PER KIND inside one `Have`, and at most
///     [`MAX_OFFERS_PER_ANSWER`] of them. "Every entry is referenced" bounds the
///     dictionary against the existence of a `Have`, NOT against what was
///     answered - one `Have` could name all 512 entries, so a one-key question
///     could be answered with 511 content identities the asker never named.
///     These two rules make the dictionary a function of the ANSWERED keys: the
///     content behind a key has ONE identity per transport, so a second
///     `bittorrent` offer on the same answer names a second blob, which the
///     whole single-identity design exists to forbid.
pub(crate) fn check_batch_offer_bindings(
    offers: &[OfferSlot],
    answers: &[BatchHoldAnswer],
) -> Result<(), ClaimCodecError> {
    let offer_count = offers.len();
    if answers.is_empty() {
        return Err(ClaimCodecError::Malformed(
            "a batch hold-response must answer at least one key".to_string(),
        ));
    }
    if answers.len() > MAX_BATCH_HOLD_KEYS {
        return Err(ClaimCodecError::BatchTooLarge {
            found: answers.len(),
            cap: MAX_BATCH_HOLD_KEYS,
        });
    }
    if offer_count > MAX_BATCH_HOLD_OFFERS {
        return Err(ClaimCodecError::BatchTooLarge {
            found: offer_count,
            cap: MAX_BATCH_HOLD_OFFERS,
        });
    }
    // NOTE WHAT IS *NOT* HERE: an explicit `offers.len() <= have_count * N` check.
    // It was written, and it could not be made to fail: with every entry required
    // to be referenced (below) and each answer capped at MAX_OFFERS_PER_ANSWER
    // distinct indices, `offers.len() <= have_count * MAX_OFFERS_PER_ANSWER` is a
    // THEOREM of the two rules, not a third rule. Shipping it would have been an
    // unfalsifiable check that only masked the two real ones - the mutation that
    // deleted each of them came back GREEN because the other caught the same wire.
    // The theorem is asserted where it belongs, in
    // `a_single_have_cannot_legitimise_a_pile_of_content_locators`.
    let mut referenced = vec![false; offer_count];
    for (position, answer) in answers.iter().enumerate() {
        let BatchHoldAnswer::Have { offer_indices, .. } = answer else {
            continue;
        };
        if offer_indices.len() > MAX_OFFERS_PER_ANSWER {
            return Err(ClaimCodecError::Malformed(format!(
                "batch answer {position} names {} offers; at most {MAX_OFFERS_PER_ANSWER} \
                 locators can describe one key",
                offer_indices.len()
            )));
        }
        let mut seen = std::collections::HashSet::with_capacity(offer_indices.len());
        let mut kinds = std::collections::HashSet::with_capacity(offer_indices.len());
        for index in offer_indices {
            let at = usize::from(*index);
            if at >= offer_count {
                return Err(ClaimCodecError::Malformed(format!(
                    "batch answer {position} names offer {at}, but the response carries \
                     {offer_count} offers"
                )));
            }
            if !seen.insert(at) {
                return Err(ClaimCodecError::Malformed(format!(
                    "batch answer {position} names offer {at} twice (ambiguous response \
                     is rejected)"
                )));
            }
            let kind = offers[at].wire_tag();
            if !kinds.insert(kind) {
                return Err(ClaimCodecError::Malformed(format!(
                    "batch answer {position} names two `{kind}` offers; the content behind \
                     one key has ONE identity per transport, so the second names a \
                     different blob"
                )));
            }
            referenced[at] = true;
        }
    }
    if let Some(orphan) = referenced.iter().position(|seen| !seen) {
        return Err(ClaimCodecError::Malformed(format!(
            "batch response offer {orphan} is referenced by no answer - a locator must \
             bind to a key the asker named"
        )));
    }
    Ok(())
}

/// Drop the unknown-transport slots and RE-INDEX every `Have` onto the compacted
/// dictionary, so the value handed to a caller has no holes and its indices still
/// point at the same locators the peer meant.
///
/// A `Have` whose only offers were unknown transports ends up with an empty
/// `offer_indices`: the holding is still asserted, but this build cannot fetch it.
/// That is the tolerate-but-drop rule applied per key instead of per response.
fn compact_offer_slots(
    slots: Vec<OfferSlot>,
    answers: &mut [BatchHoldAnswer],
) -> Vec<KnownTransport> {
    // `remap[old] == Some(new)` for a kept slot, `None` for a dropped one.
    let mut remap: Vec<Option<OfferIndex>> = Vec::with_capacity(slots.len());
    let mut kept: Vec<KnownTransport> = Vec::with_capacity(slots.len());
    for slot in slots {
        match slot {
            OfferSlot::Known(offer) => {
                remap.push(Some(kept.len() as OfferIndex));
                kept.push(offer);
            }
            OfferSlot::Unknown(_) => remap.push(None),
        }
    }
    for answer in answers.iter_mut() {
        if let BatchHoldAnswer::Have { offer_indices, .. } = answer {
            // `get`, not `[]`: an out-of-range index is already rejected by
            // `check_batch_offer_bindings` before this runs, so this arm is
            // unreachable by contract - but this function's input comes off the
            // wire, and a decoder that PANICS on hostile input is a denial of
            // service even when the panic is technically a fail-fast. Dropping is
            // the safe direction here: it can cost a fetch coordinate, never bind
            // one to the wrong key.
            offer_indices.retain_mut(|index| match remap.get(usize::from(*index)) {
                Some(Some(new)) => {
                    *index = *new;
                    true
                }
                Some(None) | None => false,
            });
        }
    }
    kept
}

/// Reject a SINGLE-KEY [`HoldAnswer::Have`] offer list that names more than one
/// locator of the same transport kind, or more than [`MAX_OFFERS_PER_ANSWER`] in
/// total. Applied on BOTH encode and decode (see [`encode_hold_response`] /
/// [`decode_hold_response`]), against the RAW pre-drop [`OfferSlot`] list so that
/// unknown transport kinds count too.
///
/// ## Why this is a DELIBERATE freeze amendment, not a slip (task-110)
///
/// This NARROWS what the FROZEN `HoldAnswer::Have.offers` ACCEPTS: a v1 wire with
/// 622 offers used to decode and now does not. It is APPROVED by the same four
/// arguments the orchestrator ruled on for `deny_unknown_fields` at
/// [`KnownTransport`]/[`KnownPayload`] (TASK-91, 2026-08-10), re-examined here:
///   1. IT ALIGNS THE CODE WITH A RULE THE MODULE ALREADY ENFORCES. The batch
///      path already holds that "the content behind a key has ONE identity per
///      transport kind" ([`check_batch_offer_bindings`], one locator per kind).
///      The single-key `Have` answers about exactly ONE key, so the SAME theorem
///      gives the tighter bound directly. This closes the gap where the frozen
///      single-key path did not implement the module's own stated single-identity
///      rule; it invents no new policy.
///   2. FORWARD COMPATIBILITY IS PRESERVED. Unknown transport KINDS still decode
///      inertly (dropped by [`keep_known_offers`] after being counted), so a
///      future transport still ships without a wire break - proven by
///      `a_single_key_have_still_drops_unknown_transports_inertly`. Only the
///      COUNT is refused here. TASK-224 later narrowed that same forward-compat
///      seam to a whitelisted minimal shape so it can no longer NAME a LIST of
///      identities (array/nested/multi-field), keeping inert decode for a
///      plausible single-locator transport but hard-rejecting a multi-field
///      future one (a disclosed cost); a crammed single scalar is still a
///      byte-volume residual (task-223). See below.
///   3. IT COSTS NOTHING WHILE NO PEERS ARE DEPLOYED. There is no released
///      network to break; the cost of tightening is zero today and rises
///      monotonically. Tightening later is a real break; tightening now is not.
///   4. IT CLOSES THE KNOWN-OFFER ENUMERATION AND COUNT (not enumeration in
///      general). Measured: 622 `bittorrent` offers = 65 440 B against an 88 B
///      query, and a `bittorrent` infohash is a CONTENT identity, so those 622
///      offers named 621 content identities the asker never asked about. After the
///      bound a one-key `Have` carries at most one KNOWN offer per transport kind,
///      i.e. at most one known content identity for the queried key; a legitimate
///      known-only answer is iroh + bittorrent = 330 B (330/88 = 3.75x). Pinned by
///      `a_single_key_have_cannot_amplify_past_one_per_kind`.
///
/// ## Scope of THIS bound, and what a SEPARATE amendment closed (task-110/224)
///
/// This bound is the COUNT/kind half of enumeration. Two further vectors, both
/// PRE-EXISTING and both SHARED with the batch path, were NOT closed HERE:
///
/// A. ENUMERATION via the unknown-KIND slot (TASK-224 closed the STRUCTURAL half;
///    a byte-volume residual remains, see [`reject_enumeration_shaped_unknown_offer`]).
///    An unknown transport used to be retained as an opaque `serde_json::Value`
///    (only its `transport` tag read), so a hostile peer could name content
///    identities inside it (`{"transport":"future","content_ids":[..]}`) and the
///    message was ACCEPTED (then dropped). TASK-224 narrowed the shared
///    tolerate-drop decoder to a whitelisted minimal shape (tag + at most one
///    scalar string locator), so an array/nested/multi-field unknown offer is now
///    REJECTED - the STRUCTURAL `also_held` list vector, closed on the unknown-KIND
///    path. NOT literal parity with a known transport: the one tolerated scalar is
///    unbounded/unvalidated, so a delimiter-crammed single string still names
///    identities as raw text (byte-volume residual, TASK-223). Pinned by
///    `an_unknown_kind_offer_cannot_name_content_ids_on_the_wire_on_both_paths`.
/// B. BYTE amplification (TASK-223, still OPEN). This is a COUNT bound, not a BYTE
///    bound: a well-shaped unknown-kind slot still has a byte-unbounded single
///    scalar, so a hostile `Have` can pad to [`MAX_CLAIM_WIRE_BYTES`] (64 KiB,
///    ~744x) with as few as one dropped offer - the count cap of 4 never even
///    engages. So the "3.75x" figure is the LEGITIMATE (known-only) case, NOT the
///    hostile worst case; do not read it as the latter. Pinned by
///    `a_padded_unknown_kind_have_still_saturates_the_frame_and_decodes_empty`. A
///    per-offer byte cap is deferred (a future transport's legitimate locator may
///    itself be large, needing its own forward-compat analysis); it is orthogonal
///    to A - TASK-224 closes naming a LIST of identities (structure), TASK-223 would
///    bound the BYTE volume of the one opaque locator that remains.
///
/// The COUNT/kind rule is this task's scope, matching the batch path's SEMANTIC
/// bound; that is what this does. The enumeration SHAPE rule (A) is TASK-224's.
///
/// The accept-set narrowed; the emit-set did not (the golden `hold_response_*`
/// encodings are byte-identical). An auditor finds this decision, not a slip.
pub(crate) fn check_single_offer_bindings(offers: &[OfferSlot]) -> Result<(), ClaimCodecError> {
    if offers.len() > MAX_OFFERS_PER_ANSWER {
        return Err(ClaimCodecError::Malformed(format!(
            "hold answer names {} offers; at most {MAX_OFFERS_PER_ANSWER} locators can \
             describe one key",
            offers.len()
        )));
    }
    let mut kinds = std::collections::HashSet::with_capacity(offers.len());
    for offer in offers {
        let kind = offer.wire_tag();
        if !kinds.insert(kind) {
            return Err(ClaimCodecError::Malformed(format!(
                "hold answer names two `{kind}` offers; the content behind one key has ONE \
                 identity per transport, so the second names a different blob"
            )));
        }
    }
    Ok(())
}

/// Drop the unknown-transport slots from a single-key [`HoldAnswer::Have`] offer
/// list, keeping the known ones in order. The single-key twin of
/// [`compact_offer_slots`]: there are no indices to re-map here (the list is
/// flat), so this is a plain filter. Applied AFTER
/// [`check_single_offer_bindings`], so an unknown kind is counted against the
/// bound and only then dropped (tolerate-but-drop, per key).
fn keep_known_offers(slots: Vec<OfferSlot>) -> Vec<KnownTransport> {
    slots
        .into_iter()
        .filter_map(|slot| match slot {
            OfferSlot::Known(offer) => Some(offer),
            OfferSlot::Unknown(_) => None,
        })
        .collect()
}

/// Reject a batch key list that is empty, over the cap, or contains a repeated
/// key. Applied on BOTH encode and decode, so this node can neither send nor
/// accept a batch that violates the bound - a sender-side check alone would let a
/// bug here become a peer's problem.
pub(crate) fn check_batch_keys(keys: &[NarHashKey]) -> Result<(), ClaimCodecError> {
    if keys.is_empty() {
        return Err(ClaimCodecError::Malformed(
            "a batch hold-query must name at least one key".to_string(),
        ));
    }
    if keys.len() > MAX_BATCH_HOLD_KEYS {
        return Err(ClaimCodecError::BatchTooLarge {
            found: keys.len(),
            cap: MAX_BATCH_HOLD_KEYS,
        });
    }
    let mut seen = std::collections::HashSet::with_capacity(keys.len());
    for key in keys {
        if !seen.insert(key) {
            return Err(ClaimCodecError::Malformed(format!(
                "batch hold-query repeats key {key} (ambiguous request is rejected)"
            )));
        }
    }
    Ok(())
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
    /// A batched query named more keys than [`MAX_BATCH_HOLD_KEYS`] allows. Its
    /// own variant (not a [`Malformed`](ClaimCodecError::Malformed)) because it is
    /// the one error a caller may sensibly ACT on: split the closure into chunks
    /// and retry, rather than give up on the peer.
    BatchTooLarge { found: usize, cap: usize },
    /// A batch response did not carry exactly one answer per key asked. A protocol
    /// fault by the responder: the answers are positional, so a different count
    /// means every answer after the gap is about the wrong hash. Distinct from
    /// [`Malformed`](ClaimCodecError::Malformed) so a caller can tell "this peer
    /// is broken" from "these bytes are not a batch response".
    BatchAnswerCount { expected: usize, found: usize },
}

impl std::fmt::Display for ClaimCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimCodecError::Malformed(why) => write!(f, "malformed claim wire form: {why}"),
            ClaimCodecError::UnsupportedVersion { found, expected } => write!(
                f,
                "unsupported schema_version {found} (this build speaks {expected})"
            ),
            ClaimCodecError::BatchTooLarge { found, cap } => write!(
                f,
                "batch hold-query names {found} keys, exceeds the {cap}-key cap"
            ),
            ClaimCodecError::BatchAnswerCount { expected, found } => write!(
                f,
                "batch response carries {found} answers for {expected} keys asked \
                 (answers are positional; a mismatch mis-assigns every later key)"
            ),
        }
    }
}

impl std::error::Error for ClaimCodecError {}

/// Encode a claim to its wire bytes (JSON draft codec).
pub fn encode_claim(claim: &Claim) -> Result<Vec<u8>, ClaimCodecError> {
    encode_checked(claim)
}

/// Serialize a wire value, refusing to EMIT anything the decode side would refuse
/// to ACCEPT.
///
/// Every decoder in this module runs [`check_size`] on its input as its very first
/// act; until now no encoder ran it on its output, so this node could construct
/// and send a message that no node - including itself - would take. That
/// asymmetry is exactly the amplification surface a batched response opens: a
/// 91-byte query could draw a 52 KiB answer, and a caller that hands in a
/// thousand offers could push it past 64 KiB and only find out at the far end.
/// Bounding the sender means the bug fails HERE, loudly, at the point of the
/// mistake - the same fail-fast rationale as the encode-side key cap.
///
/// The gate is on the SERIALIZED length, because that is the quantity the wire
/// cap is about; a field-count check cannot stand in for it.
fn encode_checked<T: Serialize>(value: &T) -> Result<Vec<u8>, ClaimCodecError> {
    let bytes = serde_json::to_vec(value).map_err(|e| ClaimCodecError::Malformed(e.to_string()))?;
    check_size(bytes.len())?;
    Ok(bytes)
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
    encode_checked(query)
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

/// Encode a hold response to its wire bytes, refusing to EMIT an offer list this
/// node's own decoder would refuse: a `Have` may name at most one offer per
/// transport kind ([`check_single_offer_bindings`]). Bounding the sender means a
/// bug that piles up offers fails HERE, loudly, not as a peer's rejection - the
/// same fail-fast rationale as [`encode_batch_hold_response`].
pub fn encode_hold_response(response: &HoldResponse) -> Result<Vec<u8>, ClaimCodecError> {
    if let HoldAnswer::Have { offers, .. } = &response.answer {
        check_single_offer_bindings(&as_offer_slots(offers))?;
    }
    encode_checked(response)
}

/// Decode + validate a hold response.
///
/// Size-, duplicate-key- and version-checked, and - task-110 - the `Have` offer
/// list is BOUND: at most one offer per transport kind, at most
/// [`MAX_OFFERS_PER_ANSWER`] in total ([`check_single_offer_bindings`]). The bound
/// runs against the RAW, pre-drop offer slots (so unknown-kind slots are COUNTED
/// against the cap, not silently dropped under it) and BEFORE the value is handed
/// back, so an over-cap response is REJECTED rather than trusted. It bounds the
/// offer COUNT, not the bytes - see [`check_single_offer_bindings`] for the
/// residual. Unknown transport kinds are then dropped ([`keep_known_offers`]),
/// tolerated-but-inert as before.
pub fn decode_hold_response(bytes: &[u8]) -> Result<HoldResponse, ClaimCodecError> {
    check_size(bytes.len())?;
    reject_duplicate_keys(bytes)?;
    let wire: HoldResponseWire =
        serde_json::from_slice(bytes).map_err(|e| ClaimCodecError::Malformed(e.to_string()))?;
    check_version(wire.schema_version, QUERY_SCHEMA_VERSION)?;
    let answer = match wire.answer {
        HoldAnswerWire::Have { blake3, offers } => {
            check_single_offer_bindings(&offers)?;
            HoldAnswer::Have {
                blake3,
                offers: keep_known_offers(offers),
            }
        }
        HoldAnswerWire::Absent => HoldAnswer::Absent,
    };
    Ok(HoldResponse {
        schema_version: wire.schema_version,
        answer,
    })
}

/// Encode a BATCHED hold query to its wire bytes, refusing to EMIT an over-cap,
/// empty or duplicate-bearing batch. Bounding the sender means a caller bug
/// (a whole 12k-path index handed in as one batch) fails here, loudly, at the
/// point of the mistake - not as a peer's rejection three hops later.
pub fn encode_batch_hold_query(query: &BatchHoldQuery) -> Result<Vec<u8>, ClaimCodecError> {
    check_batch_keys(&query.keys)?;
    encode_checked(query)
}

/// Decode + validate a batched hold query.
///
/// ORDER MATTERS, and it is the AC#2 point: the [`MAX_CLAIM_WIRE_BYTES`] gate runs
/// FIRST, on the raw byte length, so a hostile 100 MiB "batch" is refused with no
/// parse and no allocation at all. Only then is the (now provably <= 64 KiB) input
/// parsed, and only then is the KEY CAP applied - which is a protocol bound, and
/// is applied BEFORE any per-key work (an index probe, a `nix-store --dump`) is
/// done. An over-cap batch is REJECTED, never truncated to the first
/// [`MAX_BATCH_HOLD_KEYS`] keys: truncation would answer "no" for keys the peer
/// actually holds, which is a silent wrong answer rather than a loud refusal.
pub fn decode_batch_hold_query(bytes: &[u8]) -> Result<BatchHoldQuery, ClaimCodecError> {
    check_size(bytes.len())?;
    reject_duplicate_keys(bytes)?;
    let query: BatchHoldQuery =
        serde_json::from_slice(bytes).map_err(|e| ClaimCodecError::Malformed(e.to_string()))?;
    check_version(query.schema_version, QUERY_SCHEMA_VERSION)?;
    check_batch_keys(&query.keys)?;
    Ok(query)
}

/// Encode a batched hold response to its wire bytes.
///
/// Three bounds, all of them the SENDER refusing to create a problem rather than
/// exporting it: the answer count is capped by the same [`MAX_BATCH_HOLD_KEYS`]
/// bound as the query it answers; the offer dictionary must be capped and bound to
/// the answers ([`check_batch_offer_bindings`]); and the SERIALIZED length must
/// fit the wire gate ([`encode_checked`]), because neither of the first two is a
/// byte count and the amplification budget is measured in bytes.
pub fn encode_batch_hold_response(
    response: &BatchHoldResponse,
) -> Result<Vec<u8>, ClaimCodecError> {
    check_batch_offer_bindings(&as_offer_slots(&response.offers), &response.answers)?;
    encode_checked(response)
}

/// Decode + validate a batched hold response against the number of keys THIS node
/// asked about.
///
/// `keys_asked` is a required argument rather than a courtesy check a caller might
/// forget: the answers are positional, so a response of any other length cannot be
/// interpreted at all, and the safe reading of it is not "use the prefix" but
/// "reject". Passing the count in also means the answer vector is bounded by the
/// asker's own query, which is bounded by [`MAX_BATCH_HOLD_KEYS`].
///
/// Allocation is bounded before that check by [`MAX_CLAIM_WIRE_BYTES`]: the
/// smallest legal answer element is ~19 bytes, so a 64 KiB response cannot parse
/// into more than a few thousand answers even before the count is compared.
///
/// `keys_asked` IS NOT TRUSTED. It says what this node asked, and a caller that
/// passes 257 (or 0) is as much a bug as a peer that answers 257 times, so the
/// protocol cap is applied to it FIRST and independently. Otherwise the cap would
/// be a caller precondition rather than a property of the decoder, and a single
/// wrong call site would re-open the amplification the cap exists to close.
///
/// The offer dictionary is validated against the RAW, pre-drop positions and only
/// then compacted, so an unknown transport kind cannot renumber a later index onto
/// a different locator - see [`BatchHoldResponse`] for why this type has no
/// derived `Deserialize` at all.
pub fn decode_batch_hold_response(
    bytes: &[u8],
    keys_asked: usize,
) -> Result<BatchHoldResponse, ClaimCodecError> {
    check_size(bytes.len())?;
    if keys_asked == 0 {
        return Err(ClaimCodecError::Malformed(
            "a batch hold-response was awaited for zero keys; no legal query asks none".to_string(),
        ));
    }
    if keys_asked > MAX_BATCH_HOLD_KEYS {
        return Err(ClaimCodecError::BatchTooLarge {
            found: keys_asked,
            cap: MAX_BATCH_HOLD_KEYS,
        });
    }
    reject_duplicate_keys(bytes)?;
    let wire: BatchHoldResponseWire =
        serde_json::from_slice(bytes).map_err(|e| ClaimCodecError::Malformed(e.to_string()))?;
    check_version(wire.schema_version, QUERY_SCHEMA_VERSION)?;
    if wire.answers.len() != keys_asked {
        return Err(ClaimCodecError::BatchAnswerCount {
            expected: keys_asked,
            found: wire.answers.len(),
        });
    }
    let mut answers = wire.answers;
    check_batch_offer_bindings(&wire.offers, &answers)?;
    let offers = compact_offer_slots(wire.offers, &mut answers);
    Ok(BatchHoldResponse {
        schema_version: wire.schema_version,
        offers,
        answers,
    })
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
        // A KNOWN iroh offer with a DIFFERENT stray blake3.
        //
        // This used to DECODE, on the reasoning that the typed offer has no digest
        // field so the stray was ignored and the claim still had one identity.
        // True of this build, and not a property of the wire: the bytes carried
        // two identity-like values and were accepted, so two implementations could
        // disagree about what they meant. Round 7 made `KnownTransport` strict, so
        // the wire is now REFUSED outright - a stronger guarantee than "ignored",
        // and the same argument `deny_unknown_fields` on `Claim` already made one
        // level up. This is a decoder-acceptance change on a frozen type; it
        // changes nothing we EMIT, and it is pinned in the golden file as a
        // must-REJECT vector.
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [NODE_A_HEX],
            "transports": [
                { "transport": "iroh", "node": NODE_A_HEX, "blake3": OTHER_BLAKE3_HEX }
            ]
        });
        assert!(
            matches!(
                decode_claim(&serde_json::to_vec(&wire).unwrap()),
                Err(ClaimCodecError::Malformed(_))
            ),
            "a known transport carrying a second identity-like field must be refused"
        );
        // The CONTROL: the same claim without the stray field still decodes, so
        // this is strictness and not breakage.
        let clean = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [NODE_A_HEX],
            "transports": [ { "transport": "iroh", "node": NODE_A_HEX } ]
        });
        let claim = decode_claim(&serde_json::to_vec(&clean).unwrap()).expect("decode");
        assert_eq!(claim.content_id(), Some(&blake3_id()));
        assert_eq!(
            claim.transports,
            vec![KnownTransport::Iroh { node: node_a() }]
        );
    }

    #[test]
    fn an_unknown_offer_carrying_a_digest_is_rejected_not_dropped() {
        // TASK-224 tightened this. An unknown-kind offer carrying a SECOND identity
        // (`blake3` alongside its `url` - two fields besides `transport`) is now
        // REJECTED by `reject_enumeration_shaped_unknown_offer`, not accepted then
        // dropped: accepting-then-dropping a wire that named an identity IS the
        // enumeration defect (the `also_held` precedent), so the wire must be
        // un-acceptable. (Before TASK-224 this decoded and the stray digest was
        // merely dropped from the value - accepted on the wire, which was the gap.)
        let wire = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [],
            "transports": [
                { "transport": "webseed", "url": "https://x.invalid", "blake3": OTHER_BLAKE3_HEX }
            ]
        });
        assert!(
            matches!(
                decode_claim(&serde_json::to_vec(&wire).unwrap()),
                Err(ClaimCodecError::Malformed(_))
            ),
            "an unknown offer naming a second content identity must be REJECTED"
        );

        // CONTROL (so the rejection is not vacuous): the SAME unknown transport with
        // just its one scalar locator still decodes inertly, dropped from the value.
        let well_shaped = serde_json::json!({
            "schema_version": CLAIM_SCHEMA_VERSION,
            "key": KEY_HEX,
            "payload": { "kind": "whole_nar", "blake3": BLAKE3_HEX },
            "holders": [],
            "transports": [ { "transport": "webseed", "url": "https://x.invalid" } ]
        });
        let claim = decode_claim(&serde_json::to_vec(&well_shaped).unwrap()).expect("decode");
        assert_eq!(claim.content_id(), Some(&blake3_id()));
        assert!(
            claim.transports.is_empty(),
            "a well-shaped unknown transport is still dropped (forward-compat)"
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

    // --- single-key Have offers are bounded to one per kind (task-110) -------

    /// Build the wire bytes of a single-key `Have` carrying `n` copies of an
    /// offer whose `transport` tag is `tag`, WITHOUT going through
    /// [`encode_hold_response`] - the whole point is to synthesise the hostile
    /// pre-bound message a peer could send, which the encoder now refuses to make.
    fn have_wire_with_repeated_offer(tag: &str, body: &str, n: usize) -> Vec<u8> {
        let offer = format!("{{\"transport\":\"{tag}\",{body}}}");
        let offers = vec![offer; n].join(",");
        format!(
            "{{\"schema_version\":{QUERY_SCHEMA_VERSION},\"answer\":\"have\",\
             \"blake3\":\"{BLAKE3_HEX}\",\"offers\":[{offers}]}}"
        )
        .into_bytes()
    }

    #[test]
    fn a_single_key_have_cannot_amplify_past_one_per_kind() {
        // AC#1 + AC#2. BEFORE (pinned): a `Have` about ONE key could carry 622
        // `bittorrent` offers = 65 440 B against an 88 B query = 743.6x, bounded
        // only by the 64 KiB wire gate - and a bittorrent infohash is a CONTENT
        // identity, so those 622 offers name 621 content identities the asker
        // never asked about (a KNOWN-offer no-enumeration leak, not just
        // amplification - the unknown-KIND leak is separate, TASK-224).
        let query_bytes = encode_hold_query(&HoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            key: key(),
        })
        .expect("encode query");
        assert_eq!(query_bytes.len(), 88, "the pinned before-query is 88 B");

        let before = have_wire_with_repeated_offer(
            "bittorrent",
            &format!("\"infohash\":\"{INFOHASH_HEX}\""),
            622,
        );
        assert_eq!(
            before.len(),
            65_440,
            "the pinned before-response is 65 440 B"
        );
        // 65 440 / 88 = 743.6x (terminal DISPLAY only; the gate below is integer).
        assert!(
            before.len() < MAX_CLAIM_WIRE_BYTES,
            "the before-message passed the ONLY pre-existing gate (the 64 KiB \
             MAX_CLAIM_WIRE_BYTES), which is exactly why the count bound is needed"
        );
        // The bound REJECTS it now (622 `bittorrent` offers is >1 per kind AND
        // > MAX_OFFERS_PER_ANSWER). Proven to reject BEFORE any value is trusted:
        // decode returns Err, so no `HoldAnswer::Have` is ever handed back.
        assert!(matches!(
            decode_hold_response(&before),
            Err(ClaimCodecError::Malformed(_))
        ));

        // AFTER (the LEGITIMATE case, NOT the hostile worst case): the largest
        // SENDABLE known-only answer is one offer per known kind (iroh +
        // bittorrent). Measured through the real encoder. This bound closes the
        // KNOWN-offer count/enumeration. The unknown-KIND content-id smuggling
        // vector is now ALSO closed, separately (TASK-224,
        // `an_unknown_kind_offer_cannot_name_content_ids_on_the_wire_on_both_paths`).
        // One residual remains, pinned separately: hostile byte padding of a single
        // well-shaped opaque locator (~744x, TASK-223,
        // `a_padded_unknown_kind_have_still_saturates_the_frame_and_decodes_empty`).
        let after = HoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            answer: HoldAnswer::Have {
                blake3: blake3_id(),
                offers: vec![
                    KnownTransport::Iroh { node: node_a() },
                    KnownTransport::BitTorrent {
                        infohash: infohash(),
                    },
                ],
            },
        };
        let after_bytes = encode_hold_response(&after).expect("encode after");
        assert_eq!(after_bytes.len(), 330, "the after-response is 330 B");
        // Amplification as an EXACT rational, no float in the assertion: after/query
        // = 330/88 = 15/4 (cross-multiplied). Display is 3.75x.
        assert_eq!(after_bytes.len() * 4, query_bytes.len() * 15);
        // Round-trips through the bound cleanly (it is at the bound, not over it).
        assert_eq!(
            decode_hold_response(&after_bytes).expect("decode after"),
            after
        );
    }

    #[test]
    fn a_padded_unknown_kind_have_still_saturates_the_frame_and_decodes_empty() {
        // HONESTY ORACLE (task-110/223): the one-per-kind + count-4 rule is a COUNT
        // bound, not a BYTE bound. A WELL-SHAPED unknown-kind offer (tag + one
        // scalar string, admitted by task-224) is kept as an opaque slot whose
        // single scalar is byte-unbounded, so a hostile peer can pad a single-key
        // `Have` up to the frame gate with as few as ONE dropped unknown offer -
        // the count cap of 4 never even engages. This pins that BYTE residual so the
        // frozen record matches reality, not the aspirational "3.75x worst case" the
        // amendment must NOT claim. What IS closed is the KNOWN-offer
        // count/enumeration: the DECODED offers are EMPTY (zero content identities
        // in the decoded VALUE), the unknown kind dropped inertly - and, since
        // task-224, the WIRE can no longer NAME A LIST of identities in the slot
        // (only ONE opaque scalar; the LIST form is rejected - see the note below +
        // the sibling parity test). The BYTE volume of that one scalar is TASK-223.
        let query_len = 88usize; // the pinned single-key query size
        let pad_len = 60_000; // one fat unknown offer, comfortably under the 64 KiB frame
        let wire = format!(
            "{{\"schema_version\":{QUERY_SCHEMA_VERSION},\"answer\":\"have\",\
             \"blake3\":\"{BLAKE3_HEX}\",\"offers\":[\
             {{\"transport\":\"future_bulk\",\"loc\":\"{}\"}}]}}",
            "z".repeat(pad_len)
        )
        .into_bytes();
        // It is a large fraction of the frame yet still under it, so ONLY a byte
        // cap (which this task deliberately does not add) could reject it.
        assert!(
            wire.len() > MAX_CLAIM_WIRE_BYTES * 3 / 4 && wire.len() < MAX_CLAIM_WIRE_BYTES,
            "the padded message must reach most of the frame but stay under it (len {})",
            wire.len()
        );
        // The COUNT bound passes (one offer, one kind) and the message DECODES...
        let decoded = decode_hold_response(&wire).expect("one padded unknown offer decodes");
        // ...dropping the unknown kind from the DECODED value, but at a wire cost
        // that is still a large multiple of the query (byte residual OPEN, bounded
        // only by the pre-existing frame gate). Magnitude, no float in the check:
        // wire.len() > 600 * query_len (~680x here). This offer is WELL-SHAPED under
        // TASK-224 (the tag plus ONE scalar string `loc`), so the structural
        // enumeration rule admits it. What remains is BYTE volume - and note that
        // "padding" need not be filler: the same unbounded scalar could hold a
        // delimiter-crammed LIST of identities as raw text (e.g. "blake3:a,blake3:b,
        // ..."), still accepted. TASK-224 forbids the STRUCTURED list form (array /
        // nested / multiple fields), pinned by
        // `an_unknown_kind_offer_cannot_name_content_ids_on_the_wire_on_both_paths`,
        // but NOT the text-crammed single scalar - that is strictly more permissive
        // than a type-validated known-transport locator and is TASK-223's job
        // (bounding the bytes of the one remaining opaque scalar).
        assert_eq!(
            decoded.answer,
            HoldAnswer::Have {
                blake3: blake3_id(),
                offers: vec![],
            },
            "the unknown kind is dropped from the decoded value (it was still accepted)"
        );
        assert!(
            wire.len() > 600 * query_len,
            "the byte amplification residual is still ~hundreds-x (len {} vs query {})",
            wire.len(),
            query_len
        );
    }

    #[test]
    fn an_unknown_kind_offer_cannot_name_content_ids_on_the_wire_on_both_paths() {
        // FROZEN DECODER-ACCEPTANCE NARROWING (task-224, the flip of the task-110
        // re-gate finding): an unknown-KIND offer that names a LIST of content
        // identities - here a `content_ids` ARRAY of two blake3 digests - is now
        // REJECTED, not accepted-then-dropped. That closes the STRUCTURAL half of
        // the `also_held` enumeration case the KNOWN-transport rule near
        // `KNOWN_TRANSPORT_TAGS` forbids, on the unknown-KIND path, via
        // `reject_enumeration_shaped_unknown_offer`. This test proves that closure
        // AND that it is IDENTICAL across the single-key and batch decoders (the
        // shared `deserialize_transport_slots`), so neither path can list-smuggle.
        // SCOPE (honest): it does NOT prove the invariant is LITERALLY closed - a
        // single unbounded scalar can still delimiter-cram identities as text
        // (byte-volume residual, task-223); this test bites the array/list form.
        //
        // BITE (AC): removing the `reject_enumeration_shaped_unknown_offer` call in
        // `deserialize_transport_slots` re-opens the gap and BOTH asserts below go
        // red (the wire is accepted again), which is what makes this a mutation
        // proof rather than a description.
        let smuggled = format!(
            "{{\"transport\":\"future_bulk\",\"content_ids\":[\"{BLAKE3_HEX}\",\"blake3:{}\"]}}",
            "c".repeat(64)
        );

        // SINGLE-KEY path: a `Have` naming one unknown-kind offer that would smuggle
        // two content identities is REFUSED - the whole decode errors.
        let single = format!(
            "{{\"schema_version\":{QUERY_SCHEMA_VERSION},\"answer\":\"have\",\
             \"blake3\":\"{BLAKE3_HEX}\",\"offers\":[{smuggled}]}}"
        );
        assert!(
            matches!(
                decode_hold_response(single.as_bytes()),
                Err(ClaimCodecError::Malformed(_))
            ),
            "single-key: an unknown-kind offer naming content identities must be \
             REJECTED on the wire, not accepted-then-dropped"
        );

        // BATCH path: the SAME unknown-kind offer, referenced by a `Have`, is ALSO
        // refused - proving the closure is identical on both paths (shared codec).
        let batch = format!(
            "{{\"schema_version\":{QUERY_SCHEMA_VERSION},\"offers\":[{smuggled}],\
             \"answers\":[{{\"answer\":\"have\",\"blake3\":\"{BLAKE3_HEX}\",\
             \"offer_indices\":[0]}}]}}"
        );
        assert!(
            matches!(
                decode_batch_hold_response(batch.as_bytes(), 1),
                Err(ClaimCodecError::Malformed(_))
            ),
            "batch parity: the same enumeration-shaped unknown offer must be REJECTED \
             here too"
        );

        // FORWARD-COMPAT CONTROL (same test, so the closure cannot pass by refusing
        // everything): a WELL-SHAPED unknown-kind offer - the tag plus one scalar
        // string locator - still decodes INERTLY on both paths, dropped from the
        // value. This is the plausible future single-locator transport the whitelist
        // preserves; a hostile ARRAY body is what it refuses.
        let well_shaped = "{\"transport\":\"future_bulk\",\"loc\":\"opaque-locator\"}";
        let single_ok = format!(
            "{{\"schema_version\":{QUERY_SCHEMA_VERSION},\"answer\":\"have\",\
             \"blake3\":\"{BLAKE3_HEX}\",\"offers\":[{well_shaped}]}}"
        );
        assert_eq!(
            decode_hold_response(single_ok.as_bytes())
                .expect("a well-shaped unknown offer still decodes")
                .answer,
            HoldAnswer::Have {
                blake3: blake3_id(),
                offers: vec![],
            },
            "single-key: a one-scalar-locator unknown offer stays inert (forward-compat)"
        );
        let batch_ok = format!(
            "{{\"schema_version\":{QUERY_SCHEMA_VERSION},\"offers\":[{well_shaped}],\
             \"answers\":[{{\"answer\":\"have\",\"blake3\":\"{BLAKE3_HEX}\",\
             \"offer_indices\":[0]}}]}}"
        );
        assert!(
            decode_batch_hold_response(batch_ok.as_bytes(), 1)
                .expect("batch: a well-shaped unknown offer still decodes")
                .offers
                .is_empty(),
            "batch parity: a one-scalar-locator unknown offer stays inert (forward-compat)"
        );
    }

    #[test]
    fn a_single_key_have_rejects_two_offers_of_the_same_kind() {
        // The load-bearing semantic rule, at both known kinds. Two `iroh` or two
        // `bittorrent` offers on ONE key name a second blob for a single content
        // identity - forbidden by the same theorem as the batch path.
        let two_iroh =
            have_wire_with_repeated_offer("iroh", &format!("\"node\":\"{NODE_A_HEX}\""), 2);
        assert!(matches!(
            decode_hold_response(&two_iroh),
            Err(ClaimCodecError::Malformed(_))
        ));
        let two_bt = have_wire_with_repeated_offer(
            "bittorrent",
            &format!("\"infohash\":\"{INFOHASH_HEX}\""),
            2,
        );
        assert!(matches!(
            decode_hold_response(&two_bt),
            Err(ClaimCodecError::Malformed(_))
        ));

        // The ENCODER refuses to emit it either (a bug fails at the sender).
        let dup = HoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            answer: HoldAnswer::Have {
                blake3: blake3_id(),
                offers: vec![
                    KnownTransport::Iroh { node: node_a() },
                    KnownTransport::Iroh { node: node_b() },
                ],
            },
        };
        assert!(matches!(
            encode_hold_response(&dup),
            Err(ClaimCodecError::Malformed(_))
        ));
    }

    #[test]
    fn the_bound_counts_raw_offers_before_unknown_kinds_are_dropped() {
        // AC#5 boundary: the bound must run against the RAW pre-drop offer list,
        // or a peer pads a one-key answer to the wire gate with offers this build
        // would silently drop. Five DISTINCT unknown kinds decode to zero kept
        // offers, yet must be REFUSED (5 > MAX_OFFERS_PER_ANSWER) - which is only
        // observable if the count is taken before the drop.
        let offers = (0..5)
            .map(|i| format!("{{\"transport\":\"future{i}\",\"loc\":\"x\"}}"))
            .collect::<Vec<_>>()
            .join(",");
        let wire = format!(
            "{{\"schema_version\":{QUERY_SCHEMA_VERSION},\"answer\":\"have\",\
             \"blake3\":\"{BLAKE3_HEX}\",\"offers\":[{offers}]}}"
        );
        assert!(
            matches!(
                decode_hold_response(wire.as_bytes()),
                Err(ClaimCodecError::Malformed(_))
            ),
            "five unknown-kind offers must be counted (and refused) even though all \
             five drop to nothing"
        );
    }

    #[test]
    fn a_single_key_have_still_drops_unknown_transports_inertly() {
        // AC#4 forward compatibility: a `Have` mixing one known (iroh) and one
        // unknown-kind offer must still DECODE, the unknown kind dropped inertly,
        // the known one kept. The count bound (2 offers, 2 distinct kinds) admits
        // it - the unknown kind is tolerated, not a wire break.
        let wire = format!(
            "{{\"schema_version\":{QUERY_SCHEMA_VERSION},\"answer\":\"have\",\
             \"blake3\":\"{BLAKE3_HEX}\",\"offers\":[\
             {{\"transport\":\"iroh\",\"node\":\"{NODE_A_HEX}\"}},\
             {{\"transport\":\"future_quic\",\"endpoint\":\"somewhere\"}}]}}"
        );
        let decoded = decode_hold_response(wire.as_bytes()).expect("unknown kind is inert");
        assert_eq!(
            decoded.answer,
            HoldAnswer::Have {
                blake3: blake3_id(),
                offers: vec![KnownTransport::Iroh { node: node_a() }],
            },
            "the unknown transport kind is dropped, the known one kept"
        );
    }

    // --- BATCHED query (task-91): bounded, positional; no KNOWN-offer enumeration (unknown-kind residual: task-224) --

    /// `n` DISTINCT canonical keys, derived from a counter so a test can build a
    /// full-cap batch without 256 literals.
    fn distinct_keys(n: usize) -> Vec<NarHashKey> {
        (0..n)
            .map(|i| {
                let mut raw = [0u8; NAR_HASH_LEN];
                raw[..8].copy_from_slice(&(i as u64).to_be_bytes());
                NarHashKey::from_sha256_bytes(raw)
            })
            .collect()
    }

    #[test]
    fn batch_query_round_trips_and_names_every_key() {
        let keys = distinct_keys(3);
        let query = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: keys.clone(),
        };
        let bytes = encode_batch_hold_query(&query).expect("encode");
        let back = decode_batch_hold_query(&bytes).expect("decode");
        assert_eq!(back, query);
        assert_eq!(back.keys, keys, "the asker's ORDER is preserved");
    }

    #[test]
    fn batch_response_round_trips_against_the_asked_count() {
        let response = BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            offers: vec![KnownTransport::Iroh { node: node_a() }],
            answers: vec![
                BatchHoldAnswer::Have {
                    blake3: blake3_id(),
                    offer_indices: vec![0],
                },
                BatchHoldAnswer::Absent {},
            ],
        };
        let bytes = encode_batch_hold_response(&response).expect("encode");
        assert_eq!(
            decode_batch_hold_response(&bytes, 2).expect("decode"),
            response
        );
    }

    #[test]
    fn an_over_cap_batch_is_rejected_not_truncated() {
        // AC#2. The refusal must name the cap AND must not be a silent shortening:
        // a truncated batch answers "no" for keys the peer may well hold.
        let keys = distinct_keys(MAX_BATCH_HOLD_KEYS + 1);
        let query = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: keys.clone(),
        };

        // (a) This node refuses to SEND it.
        match encode_batch_hold_query(&query) {
            Err(ClaimCodecError::BatchTooLarge { found, cap }) => {
                assert_eq!(found, MAX_BATCH_HOLD_KEYS + 1);
                assert_eq!(cap, MAX_BATCH_HOLD_KEYS);
            }
            other => panic!("an over-cap batch must not encode, got {other:?}"),
        }

        // (b) And refuses to ACCEPT it - built with raw serde, bypassing our own
        // encoder, exactly as a hostile peer would. The wire is well-formed JSON
        // and well under MAX_CLAIM_WIRE_BYTES, so ONLY the key cap can reject it:
        // this is the bite that the count bound exists independently of the size
        // bound.
        let hostile = serde_json::to_vec(&query).expect("raw serde has no cap");
        assert!(
            hostile.len() < MAX_CLAIM_WIRE_BYTES,
            "the point of this case is that the SIZE gate would pass it ({} bytes)",
            hostile.len()
        );
        match decode_batch_hold_query(&hostile) {
            Err(ClaimCodecError::BatchTooLarge { found, cap }) => {
                assert_eq!((found, cap), (MAX_BATCH_HOLD_KEYS + 1, MAX_BATCH_HOLD_KEYS));
            }
            Ok(accepted) => panic!(
                "an over-cap batch must be REJECTED, not truncated - got {} keys",
                accepted.keys.len()
            ),
            other => panic!("expected a named cap rejection, got {other:?}"),
        }

        // ...while exactly-at-cap still works (the bound is not off by one).
        let at_cap = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: distinct_keys(MAX_BATCH_HOLD_KEYS),
        };
        let bytes = encode_batch_hold_query(&at_cap).expect("a full batch is legal");
        assert_eq!(
            decode_batch_hold_query(&bytes).expect("decode").keys.len(),
            MAX_BATCH_HOLD_KEYS
        );
    }

    #[test]
    fn an_oversize_batch_wire_is_rejected_before_parse() {
        // The other half of the bound: raw BYTES. A megabyte of well-formed batch
        // JSON is refused by the pre-parse size gate, so nothing is allocated for
        // it. (Padding is inside a string value so the input stays parseable and
        // only the size gate can be what rejects it.)
        let huge = format!(
            "{{\"schema_version\":{QUERY_SCHEMA_VERSION},\"keys\":[\"{}\"]}}",
            "x".repeat(MAX_CLAIM_WIRE_BYTES * 16)
        );
        assert!(huge.len() > MAX_CLAIM_WIRE_BYTES);
        match decode_batch_hold_query(huge.as_bytes()) {
            Err(ClaimCodecError::Malformed(why)) => {
                assert!(why.contains("cap"), "size error should name the cap: {why}");
            }
            other => panic!("an oversize batch wire must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn a_full_batch_fits_the_wire_cap_with_headroom() {
        // The cap is a CHOICE that couples two bounds: the key count and the wire
        // size gate. This is the arithmetic that justifies 256, asserted rather
        // than asserted-in-prose. Raising MAX_BATCH_HOLD_KEYS to 1024 makes the
        // response side fail here - which is the point.
        let keys = distinct_keys(MAX_BATCH_HOLD_KEYS);
        let query = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: keys.clone(),
        };
        let query_bytes = encode_batch_hold_query(&query).expect("encode");

        // The worst case on the answer side: EVERY key answered Have.
        let response = BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            offers: vec![
                KnownTransport::Iroh { node: node_a() },
                KnownTransport::BitTorrent {
                    infohash: infohash(),
                },
            ],
            answers: (0..MAX_BATCH_HOLD_KEYS)
                .map(|_| BatchHoldAnswer::Have {
                    blake3: blake3_id(),
                    offer_indices: vec![0, 1],
                })
                .collect(),
        };
        let response_bytes = encode_batch_hold_response(&response).expect("encode");

        // The WORST REALISTIC case: every key answered Have with its own
        // content-specific locator plus the shared peer-scoped one. This is the
        // shape a BitTorrent-capable peer produces (task-75), and it is the case
        // that decides between an indexed dictionary and inline per-answer offers.
        let mut per_content = vec![KnownTransport::Iroh { node: node_a() }];
        for i in 0..MAX_BATCH_HOLD_KEYS {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&(i as u64).to_be_bytes());
            per_content.push(KnownTransport::BitTorrent {
                infohash: BitTorrentInfoHash::v2(raw),
            });
        }
        let per_content_response = BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            offers: per_content,
            answers: (0..MAX_BATCH_HOLD_KEYS)
                .map(|i| BatchHoldAnswer::Have {
                    blake3: blake3_id(),
                    offer_indices: vec![0, (i + 1) as OfferIndex],
                })
                .collect(),
        };
        let per_content_bytes = encode_batch_hold_response(&per_content_response).expect("encode");
        assert!(
            per_content_bytes.len() < MAX_CLAIM_WIRE_BYTES,
            "a full batch with a per-content locator for every key is {} bytes and              does not fit the {MAX_CLAIM_WIRE_BYTES}-byte gate - a peer that holds              everything could not answer at all",
            per_content_bytes.len()
        );
        // HONEST LIMIT, asserted so it cannot rot into an assumption: that case has
        // only ~10% spare, not the 25% the common cases keep. The same answer with
        // the offers INLINED instead of indexed measures ~79 KiB, i.e. over the
        // gate - which is why they are indexed.
        assert!(
            per_content_bytes.len() > MAX_CLAIM_WIRE_BYTES * 3 / 4,
            "if the per-content worst case now fits in 3/4 of the gate, the size              arithmetic in the MAX_BATCH_HOLD_KEYS doc is stale ({} bytes)",
            per_content_bytes.len()
        );

        // 25% headroom, so adding one field to an answer does not silently push
        // the worst case over the gate.
        let headroom = MAX_CLAIM_WIRE_BYTES * 3 / 4;
        assert!(
            query_bytes.len() < headroom,
            "a full {MAX_BATCH_HOLD_KEYS}-key query is {} bytes; the cap must leave \
             headroom under the {MAX_CLAIM_WIRE_BYTES}-byte wire gate",
            query_bytes.len()
        );
        assert!(
            response_bytes.len() < headroom,
            "a full {MAX_BATCH_HOLD_KEYS}-answer response is {} bytes; the cap must \
             leave headroom under the {MAX_CLAIM_WIRE_BYTES}-byte wire gate",
            response_bytes.len()
        );
        // And both really do decode - the gate is not passed by being malformed.
        decode_batch_hold_query(&query_bytes).expect("a full query decodes");
        decode_batch_hold_response(&response_bytes, MAX_BATCH_HOLD_KEYS)
            .expect("a full response decodes");
    }

    #[test]
    fn an_empty_or_duplicate_bearing_batch_is_rejected() {
        let empty = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: vec![],
        };
        assert!(matches!(
            encode_batch_hold_query(&empty),
            Err(ClaimCodecError::Malformed(_))
        ));
        assert!(matches!(
            decode_batch_hold_query(&serde_json::to_vec(&empty).unwrap()),
            Err(ClaimCodecError::Malformed(_))
        ));

        // A repeated key: the request would have two positions meaning the same
        // hash. Rejected, not deduplicated, so the request has one meaning.
        let dup = BatchHoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            keys: vec![key(), key()],
        };
        match decode_batch_hold_query(&serde_json::to_vec(&dup).unwrap()) {
            Err(ClaimCodecError::Malformed(why)) => {
                assert!(why.contains("repeats key"), "should name the fault: {why}")
            }
            other => panic!("a duplicate-bearing batch must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn a_batch_response_of_the_wrong_length_is_rejected() {
        // The positional contract. A response with FEWER answers than keys asked
        // would silently re-index every later key onto the wrong hash - the worst
        // possible failure mode for this message, because it produces confident
        // wrong answers rather than an error.
        let short = BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            offers: vec![],
            answers: vec![BatchHoldAnswer::Absent {}, BatchHoldAnswer::Absent {}],
        };
        let bytes = encode_batch_hold_response(&short).expect("encode");
        match decode_batch_hold_response(&bytes, 3) {
            Err(ClaimCodecError::BatchAnswerCount { expected, found }) => {
                assert_eq!((expected, found), (3, 2));
            }
            other => panic!("a short batch answer must be rejected, got {other:?}"),
        }
        // A LONGER answer is equally rejected (a peer padding the vector).
        assert!(matches!(
            decode_batch_hold_response(&bytes, 1),
            Err(ClaimCodecError::BatchAnswerCount {
                expected: 1,
                found: 2
            })
        ));
    }

    #[test]
    fn a_batch_answer_can_never_name_a_key_the_asker_did_not() {
        // AC#4 at the WIRE level. The response type has no field that holds a
        // NarHash, so the question "which other hashes do you hold?" is not
        // expressible - not merely unanswered.
        let response = BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            offers: vec![KnownTransport::Iroh { node: node_a() }],
            answers: vec![
                BatchHoldAnswer::Have {
                    blake3: blake3_id(),
                    offer_indices: vec![0],
                },
                BatchHoldAnswer::Absent {},
            ],
        };
        let on_wire: Value =
            serde_json::from_slice(&encode_batch_hold_response(&response).unwrap()).unwrap();
        assert!(
            !serde_json::to_string(&on_wire).unwrap().contains("sha256:"),
            "a batch response must carry no NarHash at all: {on_wire}"
        );
        for answer in on_wire["answers"].as_array().unwrap() {
            assert!(
                answer.get("key").is_none() && answer.get("keys").is_none(),
                "an answer entry names no key - it is positional: {answer}"
            );
        }
        // And a peer that TRIES to smuggle a listing in is rejected outright:
        // `deny_unknown_fields` on both the envelope and the answer entries.
        let smuggled = serde_json::json!({
            "schema_version": QUERY_SCHEMA_VERSION,
            "offers": [],
            "answers": [ { "answer": "absent" } ],
            "also_held": [ KEY_HEX ]
        });
        assert!(
            matches!(
                decode_batch_hold_response(&serde_json::to_vec(&smuggled).unwrap(), 1),
                Err(ClaimCodecError::Malformed(_))
            ),
            "an unknown top-level field (a smuggled holdings listing) must be rejected"
        );
    }

    #[test]
    fn batch_envelope_version_is_checked_on_both_directions() {
        let query = serde_json::json!({ "schema_version": 999, "keys": [KEY_HEX] });
        assert!(matches!(
            decode_batch_hold_query(&serde_json::to_vec(&query).unwrap()),
            Err(ClaimCodecError::UnsupportedVersion {
                found: 999,
                expected: QUERY_SCHEMA_VERSION
            })
        ));
        // Shape-valid but version-wrong: the version gate is what must speak.
        let response = serde_json::json!({
            "schema_version": 999,
            "offers": [],
            "answers": [ { "answer": "absent" } ]
        });
        assert!(matches!(
            decode_batch_hold_response(&serde_json::to_vec(&response).unwrap(), 1),
            Err(ClaimCodecError::UnsupportedVersion {
                found: 999,
                expected: QUERY_SCHEMA_VERSION
            })
        ));
        // HONEST LIMIT, shared with the frozen decoders: the version is read from
        // the PARSED value, so a future version whose SHAPE also differs is
        // reported as Malformed rather than UnsupportedVersion. It is still
        // rejected - which is the safety property - but the diagnostic is the
        // less useful of the two. Peeking the version before the typed parse would
        // fix that for all five decoders at once and is deliberately not done
        // piecemeal here.
        let future_shape = serde_json::json!({
            "schema_version": 999,
            "answers": [ { "answer": "absent" } ]
        });
        assert!(matches!(
            decode_batch_hold_response(&serde_json::to_vec(&future_shape).unwrap(), 1),
            Err(ClaimCodecError::Malformed(_))
        ));
    }

    #[test]
    fn a_batch_response_tolerates_an_unknown_transport_inertly() {
        // Same forward-compat rule as the frozen types: an unknown transport offer
        // is DROPPED (inert), a malformed KNOWN one is a hard error.
        let wire = serde_json::json!({
            "schema_version": QUERY_SCHEMA_VERSION,
            "offers": [
                { "transport": "webseed", "url": "https://x.invalid" },
                { "transport": "iroh", "node": NODE_A_HEX }
            ],
            "answers": [
                { "answer": "have", "blake3": BLAKE3_HEX, "offer_indices": [0, 1] }
            ]
        });
        let decoded =
            decode_batch_hold_response(&serde_json::to_vec(&wire).unwrap(), 1).expect("decode");
        assert_eq!(
            decoded.offers,
            vec![KnownTransport::Iroh { node: node_a() }],
            "the unknown transport is dropped, not carried"
        );
        // ...and the SURVIVING locator is still the one the answer meant. The
        // unknown slot sat at index 0, so a naive drop would leave this Have
        // pointing at [0, 1] over a one-element dictionary. The decoder compacts
        // and re-indexes together, which is the whole reason it parses slots.
        assert_eq!(
            decoded.answers,
            vec![BatchHoldAnswer::Have {
                blake3: blake3_id(),
                offer_indices: vec![0],
            }],
            "dropping an unknown offer must renumber the surviving indices"
        );

        let malformed = serde_json::json!({
            "schema_version": QUERY_SCHEMA_VERSION,
            "offers": [ { "transport": "iroh", "node": "not-hex" } ],
            "answers": [ { "answer": "have", "blake3": BLAKE3_HEX, "offer_indices": [0] } ]
        });
        assert!(
            matches!(
                decode_batch_hold_response(&serde_json::to_vec(&malformed).unwrap(), 1),
                Err(ClaimCodecError::Malformed(_))
            ),
            "a malformed KNOWN transport must ERROR, not be dropped"
        );
    }

    #[test]
    fn the_frozen_single_key_types_are_untouched_by_the_batch_addition() {
        // A guard test in the same module as the change: the single-key probe
        // still encodes to exactly its historical bytes. (The full byte-level
        // freeze lives in daemon/tests/claim_wire_golden.rs; this is the fast
        // in-module signal.)
        let query = HoldQuery {
            schema_version: QUERY_SCHEMA_VERSION,
            key: key(),
        };
        assert_eq!(
            String::from_utf8(encode_hold_query(&query).unwrap()).unwrap(),
            format!("{{\"schema_version\":1,\"key\":\"{KEY_HEX}\"}}")
        );
        let absent = HoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            answer: HoldAnswer::Absent,
        };
        assert_eq!(
            String::from_utf8(encode_hold_response(&absent).unwrap()).unwrap(),
            "{\"schema_version\":1,\"answer\":\"absent\"}"
        );
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

    // ---- the freeze-round-6 rules: strict answers, bound offers, bound caller ----

    #[test]
    fn an_absent_batch_answer_rejects_any_field_attached_to_it() {
        // C2. `deny_unknown_fields` on an internally-tagged enum is honoured for
        // STRUCT variants and is SILENTLY INERT for UNIT variants - established by
        // experiment, not read off the documentation. `Absent` is therefore an
        // EMPTY STRUCT variant (`Absent {}`), which emits the same bytes and is
        // strict. This test is what stops someone "simplifying" it back.
        let smuggled = serde_json::json!({
            "schema_version": QUERY_SCHEMA_VERSION,
            "offers": [],
            "answers": [ { "answer": "absent", "blake3": BLAKE3_HEX } ]
        });
        assert!(
            matches!(
                decode_batch_hold_response(&serde_json::to_vec(&smuggled).unwrap(), 1),
                Err(ClaimCodecError::Malformed(_))
            ),
            "an Absent answer carrying a content identity must be rejected"
        );
        // ...and the encoding really is unchanged by the empty-struct form.
        let absent = BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            offers: vec![],
            answers: vec![BatchHoldAnswer::Absent {}],
        };
        assert_eq!(
            String::from_utf8(encode_batch_hold_response(&absent).unwrap()).unwrap(),
            "{\"schema_version\":1,\"offers\":[],\"answers\":[{\"answer\":\"absent\"}]}"
        );
    }

    #[test]
    fn a_have_answer_rejects_a_second_identity_like_field() {
        // The two-blob-claim class, on the type being frozen now: a Have with a
        // valid blake3 AND a blake3_shadow, or with a smuggled also_held listing,
        // decoded happily before `deny_unknown_fields` reached the answer entries.
        for extra in [
            serde_json::json!({
                "answer": "have", "blake3": BLAKE3_HEX, "offer_indices": [],
                "blake3_shadow": BLAKE3_HEX
            }),
            serde_json::json!({
                "answer": "have", "blake3": BLAKE3_HEX, "offer_indices": [],
                "also_held": [ KEY_HEX ]
            }),
            serde_json::json!({
                "answer": "have", "blake3": BLAKE3_HEX, "offer_indices": [], "key": KEY_HEX
            }),
        ] {
            let wire = serde_json::json!({
                "schema_version": QUERY_SCHEMA_VERSION,
                "offers": [],
                "answers": [ extra ]
            });
            assert!(
                matches!(
                    decode_batch_hold_response(&serde_json::to_vec(&wire).unwrap(), 1),
                    Err(ClaimCodecError::Malformed(_))
                ),
                "an unknown field on a Have answer must be rejected: {wire}"
            );
        }
    }

    /// A one-answer response naming `indices` over a dictionary of `offer_count`
    /// iroh locators, as raw wire bytes - so the test can express wires our own
    /// encoder would refuse to build.
    /// A one-answer batch response whose dictionary has `offer_count` entries of
    /// DISTINCT kinds. Distinct because one answer may name at most one locator
    /// per transport kind (the content behind a key has one identity per
    /// transport), so a dictionary of N same-kind offers is not a legal shape to
    /// test the INDEX rules against - it would be rejected for the wrong reason.
    /// Positions past the two known kinds are distinct UNKNOWN kinds, which is the
    /// forward-compatible shape and keeps the slot path exercised.
    fn batch_wire(offer_count: usize, indices: &[u16]) -> Vec<u8> {
        let offers: Vec<Value> = (0..offer_count)
            .map(|i| {
                let mut raw = [0u8; 32];
                raw[0] = i as u8;
                match i {
                    0 => serde_json::json!({
                        "transport": "iroh",
                        "node": NodeId::from_bytes(raw).to_string()
                    }),
                    1 => serde_json::json!({
                        "transport": "bittorrent",
                        "infohash": INFOHASH_HEX
                    }),
                    other => serde_json::json!({ "transport": format!("future_{other}") }),
                }
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "schema_version": QUERY_SCHEMA_VERSION,
            "offers": offers,
            "answers": [
                { "answer": "have", "blake3": BLAKE3_HEX, "offer_indices": indices }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn an_offer_index_outside_the_dictionary_is_rejected() {
        assert!(matches!(
            decode_batch_hold_response(&batch_wire(1, &[1]), 1),
            Err(ClaimCodecError::Malformed(_))
        ));
        assert!(matches!(
            decode_batch_hold_response(&batch_wire(0, &[0]), 1),
            Err(ClaimCodecError::Malformed(_))
        ));
        // An out-of-range index ALONGSIDE valid ones, so the rejection cannot be
        // credited to the every-offer-referenced rule: here both dictionary
        // entries ARE referenced and the wire must still be refused.
        assert!(matches!(
            decode_batch_hold_response(&batch_wire(2, &[0, 1, 5]), 1),
            Err(ClaimCodecError::Malformed(_))
        ));
        // The in-range case is the control: without it this test could pass by
        // rejecting everything.
        assert!(decode_batch_hold_response(&batch_wire(1, &[0]), 1).is_ok());
        assert!(decode_batch_hold_response(&batch_wire(2, &[0, 1]), 1).is_ok());
    }

    #[test]
    fn a_repeated_offer_index_inside_one_answer_is_rejected() {
        // Duplicated state with two readings (one offer, or two identical ones).
        // Same argument as the duplicate-JSON-key guard: exactly one canonical
        // meaning, fail-closed rather than last-wins.
        //
        // The MESSAGE is asserted, not just the variant. A repeated index is
        // necessarily a repeated KIND, so the one-locator-per-kind rule would
        // refuse this wire too - and with only `matches!(.., Malformed(_))` here,
        // deleting the repeat rule left the suite GREEN. Pinning the message pins
        // WHICH rule spoke, which is the whole point of keeping both: the repeat
        // rule gives the precise diagnostic and runs first.
        match decode_batch_hold_response(&batch_wire(2, &[0, 1, 0]), 1) {
            Err(ClaimCodecError::Malformed(why)) => assert!(
                why.contains("names offer 0 twice"),
                "the repeat rule must be the one that refuses this: {why}"
            ),
            other => panic!("a repeated offer index must be rejected: {other:?}"),
        }
        assert!(decode_batch_hold_response(&batch_wire(2, &[0, 1]), 1).is_ok());
    }

    #[test]
    fn a_single_have_cannot_legitimise_a_pile_of_content_locators() {
        // ROUND 7. "Every entry is referenced by at least one `Have`" bounds the
        // dictionary against the EXISTENCE of a Have, not against what was
        // ANSWERED - so one Have could name the whole dictionary. Three
        // independent reviews measured the same hole: a 91 B one-key query
        // answered with 512 BitTorrent infohashes, 557.6x / 578x / 613.8x wire
        // amplification depending on the locator mix. An infohash IS a content
        // identity, so 511 of those name content the asker never asked about.
        let offers: Vec<Value> = (0..MAX_BATCH_HOLD_OFFERS)
            .map(|i| {
                let mut raw = [0u8; 32];
                raw[..8].copy_from_slice(&(i as u64).to_be_bytes());
                serde_json::json!({
                    "transport": "bittorrent",
                    "infohash": BitTorrentInfoHash::v2(raw).to_string()
                })
            })
            .collect();
        let indices: Vec<OfferIndex> = (0..offers.len() as OfferIndex).collect();
        let wire = serde_json::to_vec(&serde_json::json!({
            "schema_version": QUERY_SCHEMA_VERSION,
            "offers": offers,
            "answers": [
                { "answer": "have", "blake3": BLAKE3_HEX, "offer_indices": indices }
            ]
        }))
        .unwrap();
        match decode_batch_hold_response(&wire, 1) {
            Err(ClaimCodecError::Malformed(why)) => assert!(
                why.contains("locators may bind") || why.contains("locators can describe"),
                "the refusal must name the answered-keys bound, not something else: {why}"
            ),
            other => panic!(
                "a one-key question must not be answerable with a pile of content \
                 identities: {other:?}"
            ),
        }
        // ISOLATING CASE for the one-locator-per-kind rule. Deliberately TINY: two
        // offers, one answer, both referenced, two indices (under the per-answer
        // cap), in range, not repeated. Every other rule is satisfied, so only the
        // kind rule can refuse it - and the MESSAGE is asserted, not just the
        // error variant. An earlier draft of this control used 512 offers and
        // passed because the SIZE gate refused it; deleting the kind rule left the
        // suite green. Asserting the variant alone is how that happened.
        let two_of_a_kind = BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            offers: vec![
                KnownTransport::BitTorrent {
                    infohash: BitTorrentInfoHash::v2([1u8; 32]),
                },
                KnownTransport::BitTorrent {
                    infohash: BitTorrentInfoHash::v2([2u8; 32]),
                },
            ],
            answers: vec![BatchHoldAnswer::Have {
                blake3: blake3_id(),
                offer_indices: vec![0, 1],
            }],
        };
        match encode_batch_hold_response(&two_of_a_kind) {
            Err(ClaimCodecError::Malformed(why)) => assert!(
                why.contains("two `bittorrent` offers"),
                "the refusal must name the one-identity-per-transport rule: {why}"
            ),
            other => panic!("one key must not carry two content identities: {other:?}"),
        }
        // ...and the decoder refuses the same shape, not just the encoder.
        let wire_two = serde_json::to_vec(&serde_json::json!({
            "schema_version": QUERY_SCHEMA_VERSION,
            "offers": [
                { "transport": "bittorrent", "infohash": INFOHASH_HEX },
                { "transport": "bittorrent", "infohash": BitTorrentInfoHash::v2([9u8; 32]).to_string() }
            ],
            "answers": [
                { "answer": "have", "blake3": BLAKE3_HEX, "offer_indices": [0, 1] }
            ]
        }))
        .unwrap();
        match decode_batch_hold_response(&wire_two, 1) {
            Err(ClaimCodecError::Malformed(why)) => assert!(
                why.contains("two `bittorrent` offers"),
                "the decoder must refuse it for the same reason: {why}"
            ),
            other => panic!("the decoder accepted two identities for one key: {other:?}"),
        }
        // The CONTROL: two offers of DIFFERENT kinds on one answer is legal, so
        // this test cannot pass by rejecting every multi-offer answer.
        let two_kinds = BatchHoldResponse {
            schema_version: QUERY_SCHEMA_VERSION,
            offers: vec![
                KnownTransport::Iroh { node: node_a() },
                KnownTransport::BitTorrent {
                    infohash: BitTorrentInfoHash::v2([3u8; 32]),
                },
            ],
            answers: vec![BatchHoldAnswer::Have {
                blake3: blake3_id(),
                offer_indices: vec![0, 1],
            }],
        };
        assert!(encode_batch_hold_response(&two_kinds).is_ok());
    }

    #[test]
    fn known_transport_tags_agree_with_the_wire_tags() {
        // FOUR hand-maintained statements of one fact, asserted against each other
        // so a new transport (or a rename) cannot land in only some of them:
        //   1. KNOWN_TRANSPORT_TAGS
        //   2. the serde attributes (what `to_value` emits)
        //   3. `KnownTransport::wire_tag`
        //   4. the seam's `peer_fabric::TransportTag::as_str`, reached via the
        //      `KnownTransport::tag()` bridge this module owns. Without this last
        //      assertion the seam string was an UNGUARDED 4th copy: renaming
        //      `TransportTag::as_str` to "bt" would compile and pass, yet the
        //      bridge would silently disagree with what the daemon emits on the
        //      wire (mped-architect finding, TASK-141).
        for offer in [
            KnownTransport::Iroh { node: node_a() },
            KnownTransport::BitTorrent {
                infohash: BitTorrentInfoHash::v2([7u8; 32]),
            },
        ] {
            let tag = offer.wire_tag();
            assert!(
                KNOWN_TRANSPORT_TAGS.contains(&tag),
                "`{tag}` is not in KNOWN_TRANSPORT_TAGS"
            );
            let encoded = serde_json::to_value(&offer).unwrap();
            assert_eq!(
                encoded.get("transport").and_then(Value::as_str),
                Some(tag),
                "`wire_tag` disagrees with what serde emits for {offer:?}"
            );
            assert_eq!(
                offer.tag().as_str(),
                tag,
                "the seam TransportTag string disagrees with the daemon wire tag \
                 for {offer:?}"
            );
        }
        assert_eq!(
            KNOWN_TRANSPORT_TAGS.len(),
            2,
            "a new transport kind must update MAX_OFFERS_PER_ANSWER's derivation too"
        );
    }

    #[test]
    fn an_offer_bound_to_no_answered_key_is_rejected() {
        // The no-enumeration half of the offer-hoisting defect: a locator that no
        // Have references is bound to nothing the asker named. For a per-CONTENT
        // locator (a BitTorrent infohash) that is a peer VOLUNTEERING content, in
        // a message whose whole safety argument is that it cannot.
        assert!(matches!(
            decode_batch_hold_response(&batch_wire(2, &[0]), 1),
            Err(ClaimCodecError::Malformed(_))
        ));
        // The sharpest case: an ALL-ABSENT response carrying a content-specific
        // locator. It answered nothing, so it may say nothing.
        let all_absent_with_offer = serde_json::to_vec(&serde_json::json!({
            "schema_version": QUERY_SCHEMA_VERSION,
            "offers": [ { "transport": "bittorrent", "infohash": INFOHASH_HEX } ],
            "answers": [ { "answer": "absent" } ]
        }))
        .unwrap();
        assert!(matches!(
            decode_batch_hold_response(&all_absent_with_offer, 1),
            Err(ClaimCodecError::Malformed(_))
        ));
        // ...and our own encoder refuses to BUILD one, so this node cannot be the
        // peer that does it either.
        assert!(matches!(
            encode_batch_hold_response(&BatchHoldResponse {
                schema_version: QUERY_SCHEMA_VERSION,
                offers: vec![KnownTransport::BitTorrent {
                    infohash: infohash()
                }],
                answers: vec![BatchHoldAnswer::Absent {}],
            }),
            Err(ClaimCodecError::Malformed(_))
        ));
    }

    #[test]
    fn the_decoder_applies_the_key_cap_to_the_caller_too() {
        // C3. `keys_asked` used to be TRUSTED, so a 257-answer response decoded
        // cleanly when a caller passed 257 - the cap was a caller precondition,
        // not a property of the decoder. One wrong call site re-opened the whole
        // amplification budget.
        let over = MAX_BATCH_HOLD_KEYS + 1;
        let answers: Vec<Value> = (0..over)
            .map(|_| serde_json::json!({ "answer": "absent" }))
            .collect();
        let wire = serde_json::to_vec(&serde_json::json!({
            "schema_version": QUERY_SCHEMA_VERSION,
            "offers": [],
            "answers": answers
        }))
        .unwrap();
        assert!(
            matches!(
                decode_batch_hold_response(&wire, over),
                Err(ClaimCodecError::BatchTooLarge { found, cap })
                    if found == over && cap == MAX_BATCH_HOLD_KEYS
            ),
            "an over-cap answer count must be refused however confidently the \
             caller asks for it"
        );
        // Zero is equally impossible: no legal query names no keys, so a caller
        // awaiting zero answers is a bug, not an empty result.
        assert!(matches!(
            decode_batch_hold_response(&batch_wire(1, &[0]), 0),
            Err(ClaimCodecError::Malformed(_))
        ));

        // ...and the check is on the CALLER, applied before the response is
        // parsed at all - not a side effect of validating what came back. Asserted
        // by handing in bytes that are not JSON: if `keys_asked` were still
        // trusted, the parse would fail first and the caller's own illegal count
        // would never be named. A mutation removing the keys_asked cap survived an
        // earlier version of this test, because the ANSWER-count cap downstream
        // caught the same wire and produced an indistinguishable error.
        let garbage = b"this is not JSON";
        assert!(
            matches!(
                decode_batch_hold_response(garbage, over),
                Err(ClaimCodecError::BatchTooLarge { found, cap })
                    if found == over && cap == MAX_BATCH_HOLD_KEYS
            ),
            "an over-cap keys_asked must be refused before the response is parsed"
        );
        match decode_batch_hold_response(garbage, 0) {
            Err(ClaimCodecError::Malformed(why)) => assert!(
                why.contains("zero keys"),
                "a zero keys_asked must be named as such, not reported as a parse                  failure: {why}"
            ),
            other => panic!("awaiting zero answers must be refused: {other:?}"),
        }
    }

    #[test]
    fn an_encoder_refuses_to_emit_what_no_decoder_would_accept() {
        // C3, encode side. Every decoder gates its INPUT at MAX_CLAIM_WIRE_BYTES;
        // until now no encoder gated its OUTPUT, so this node could build a message
        // it would itself reject. Two bounds close it: the offer-dictionary cap and
        // the serialized size.
        let too_many_offers: Vec<KnownTransport> = (0..=MAX_BATCH_HOLD_OFFERS)
            .map(|i| {
                let mut raw = [0u8; 32];
                raw[..8].copy_from_slice(&(i as u64).to_be_bytes());
                KnownTransport::Iroh {
                    node: NodeId::from_bytes(raw),
                }
            })
            .collect();
        let indices: Vec<OfferIndex> = (0..too_many_offers.len() as OfferIndex).collect();
        assert!(
            matches!(
                encode_batch_hold_response(&BatchHoldResponse {
                    schema_version: QUERY_SCHEMA_VERSION,
                    offers: too_many_offers,
                    answers: vec![BatchHoldAnswer::Have {
                        blake3: blake3_id(),
                        offer_indices: indices,
                    }],
                }),
                Err(ClaimCodecError::BatchTooLarge { .. })
            ),
            "one answer must not be able to drag an unbounded offer dictionary \
             along with it"
        );

        // The SIZE gate is a separate bound from the count caps, and it has to be
        // exercised somewhere it is REACHABLE. It no longer is on a batch response:
        // the per-answer bound plus the key cap now hold the worst legal batch at
        // 58 910 B under the 65 536 B gate by construction (asserted in
        // `a_full_batch_fits_the_wire_cap_with_headroom`). A frozen `Claim` has no
        // offer-COUNT cap at all, so that is where an encoder can still build a
        // message its own decoder would refuse.
        let mut oversize = sample_claim();
        oversize.transports = (0..2_000)
            .map(|i| {
                let mut raw = [0u8; 32];
                raw[..8].copy_from_slice(&(i as u64).to_be_bytes());
                KnownTransport::Iroh {
                    node: NodeId::from_bytes(raw),
                }
            })
            .collect();
        match encode_claim(&oversize) {
            Err(ClaimCodecError::Malformed(why)) => assert!(
                why.contains("exceeds"),
                "the size gate must say what it refused: {why}"
            ),
            other => panic!("an over-size claim must not be emitted: {other:?}"),
        }
        // The control: the same claim under the gate still encodes, so this test
        // cannot pass by refusing everything.
        oversize.transports.truncate(1);
        assert!(encode_claim(&oversize).is_ok());
    }

    #[test]
    fn the_slot_and_drop_transport_decoders_agree() {
        // `deserialize_transport_slots` duplicates the tolerate-but-drop rule of
        // `deserialize_known_transports` because the two return different types.
        // Duplicated logic drifts, so the agreement is ASSERTED rather than
        // asserted-in-a-comment - which is the only thing that actually pays for
        // the duplication.
        #[derive(Deserialize)]
        struct Dropped {
            #[serde(deserialize_with = "deserialize_known_transports")]
            offers: Vec<KnownTransport>,
        }
        #[derive(Deserialize)]
        struct Slotted {
            #[serde(deserialize_with = "deserialize_transport_slots")]
            offers: Vec<OfferSlot>,
        }
        let inputs = [
            serde_json::json!({ "offers": [] }),
            serde_json::json!({ "offers": [ { "transport": "iroh", "node": NODE_A_HEX } ] }),
            serde_json::json!({ "offers": [
                { "transport": "webseed", "url": "x" },
                { "transport": "iroh", "node": NODE_A_HEX },
                { "transport": "carrier_pigeon" },
                { "transport": "bittorrent", "infohash": INFOHASH_HEX }
            ] }),
        ];
        for input in inputs {
            let bytes = serde_json::to_vec(&input).unwrap();
            let dropped: Dropped = serde_json::from_slice(&bytes).unwrap();
            let slotted: Slotted = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                dropped.offers,
                slotted
                    .offers
                    .into_iter()
                    .filter_map(|slot| match slot {
                        OfferSlot::Known(offer) => Some(offer),
                        OfferSlot::Unknown(_) => None,
                    })
                    .collect::<Vec<_>>(),
                "the two decoders disagree on {input}"
            );
        }
        // ...including on the hard-error case: a malformed KNOWN transport must
        // fail both, not be quietly slotted as unknown.
        let malformed = serde_json::to_vec(
            &serde_json::json!({ "offers": [ { "transport": "iroh", "node": "nope" } ] }),
        )
        .unwrap();
        assert!(serde_json::from_slice::<Dropped>(&malformed).is_err());
        assert!(serde_json::from_slice::<Slotted>(&malformed).is_err());

        // ...AND on the TASK-224 enumeration-shape rejection: an unknown-kind offer
        // whose body could NAME identities (an array field, or two fields) must fail
        // BOTH decoders, or the claim path and the hold-response path would drift on
        // exactly the vector this task closes. This is the assertion that keeps the
        // shared `reject_enumeration_shaped_unknown_offer` applied on both twins.
        for shaped in [
            serde_json::json!({ "offers": [
                { "transport": "future", "content_ids": [ BLAKE3_HEX, BLAKE3_HEX ] }
            ] }),
            serde_json::json!({ "offers": [
                { "transport": "future", "a": BLAKE3_HEX, "b": BLAKE3_HEX }
            ] }),
            serde_json::json!({ "offers": [
                { "transport": "future", "nested": { "content_id": BLAKE3_HEX } }
            ] }),
        ] {
            let bytes = serde_json::to_vec(&shaped).unwrap();
            assert!(
                serde_json::from_slice::<Dropped>(&bytes).is_err(),
                "the claim decoder must REFUSE the enumeration-shaped offer {shaped}"
            );
            assert!(
                serde_json::from_slice::<Slotted>(&bytes).is_err(),
                "the hold-response decoder must REFUSE the enumeration-shaped offer {shaped}"
            );
        }
    }
}
