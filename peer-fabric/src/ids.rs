//! The primitive value types the seam is built from, and their CANONICAL HOME.
//!
//! [`NodeId`], [`Blake3Digest`], [`TransportTag`], [`TransportOffer`] and
//! [`InfoHash`] live HERE, below the seam, because they are the identities that
//! CROSS the seam: every backend and the frontend must agree on them. TASK-141
//! made this crate their single home and DELETED the daemon's former duplicates
//! (`daemon::transport::NodeId`, `daemon::content_id::Blake3Digest`,
//! `daemon::transport_fetch::TransportTag`, `daemon::transport::BitTorrentInfoHash`);
//! the daemon now re-exports these from their old module paths, so the freeze
//! narratives and conformance tests stayed put while the definitions moved down.
//!
//! Because the daemon's claim codec consumes these types' `serde`/`FromStr`
//! behaviour and the orphan rule forbids the daemon impl'ing foreign traits on a
//! foreign type, the FROZEN wire behaviour (the `serde`/`FromStr` string forms and
//! the `BLAKE3(RawNarV1)` recipe) had to move WITH the types. It is ported here
//! byte-for-byte; the tests below pin the golden vectors so any drift fails loudly.
//!
//! Kept transport-BLIND at the identity layer ([`NodeId`]/[`Blake3Digest`]) and
//! transport-SPECIFIC only at the locator ([`TransportOffer`]/[`InfoHash`]) - the
//! same separation the daemon freeze drew between `content_id` (universal) and
//! `transport` (per-transport).
//!
//! INTENTIONAL ASYMMETRY (do not "fix" it): the types in THIS module derive/impl
//! `serde` because their canonical string codecs are FROZEN and the daemon's claim
//! wire depends on them. The types in [`crate::content`] ([`crate::ContentKey`],
//! [`crate::ProviderRecord`]) deliberately carry NO `serde` - TASK-126 freezes that codec
//! against the adopted backend, inside an opaque value. So `serde` is a hard dep of
//! this crate for the ids only; adding `#[derive(Serialize)]` to a `content.rs`
//! type would pre-empt a freeze that is not this crate's to make.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::hexfmt;

// -------------------------------------------------------------------------
// NodeId: a peer's network identity (ed25519 public key).
// -------------------------------------------------------------------------

/// Length in bytes of a [`NodeId`] (an ed25519 public key).
pub const NODE_ID_LEN: usize = 32;

/// A peer's network identity: the 32 raw ed25519 public-key bytes. Transport-blind
/// on purpose - the SAME `NodeId` is the iroh handle, the libp2p `PeerId` seed, and
/// the holder named in a [`ProviderRecord`](crate::ProviderRecord); a backend
/// converts these raw bytes into its own native handle at the transport boundary.
///
/// Canonical string form: 64 lowercase hex chars, bare (no prefix), matching how a
/// stack prints a node key. This validates length and lowercase hex, but NOT that
/// the 32 bytes are a valid ed25519 curve point: that check needs a backend's
/// pinned constructor (`iroh::PublicKey::from_bytes`) and so DEFERS to the backend.
/// A non-point id is undiallable and fails loudly at connect time; it cannot
/// corrupt content addressing (the same deferral the daemon's `NodeId` documented).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; NODE_ID_LEN]);

impl NodeId {
    /// Wrap the 32 raw ed25519 public-key bytes (e.g. `iroh::NodeId::as_bytes`).
    pub const fn from_bytes(bytes: [u8; NODE_ID_LEN]) -> Self {
        NodeId(bytes)
    }

    /// The raw 32 bytes, for a backend to build its native handle.
    pub const fn as_bytes(&self) -> &[u8; NODE_ID_LEN] {
        &self.0
    }

    /// The 64-char lowercase hex canonical string.
    pub fn to_hex(&self) -> String {
        hexfmt::encode(&self.0)
    }
}

/// Why a string was not a canonical [`NodeId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdParseError(String);

impl fmt::Display for NodeIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed node id: {}", self.0)
    }
}

impl std::error::Error for NodeIdParseError {}

impl FromStr for NodeId {
    type Err = NodeIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes =
            hexfmt::decode_fixed::<NODE_ID_LEN>(s).map_err(|e| NodeIdParseError(e.to_string()))?;
        Ok(NodeId(bytes))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for NodeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// -------------------------------------------------------------------------
// Blake3Digest: the universal, transport-independent content identity, AND the
// frozen BLAKE3(RawNarV1) recipe that produces it (task-48 FREEZE, moved here
// by TASK-141 with the type). The daemon's content_id module keeps the freeze
// narrative and re-exports this.
// -------------------------------------------------------------------------

/// Length in bytes of a [`Blake3Digest`]. Frozen: the addressed-unit length two
/// daemons agree on.
pub const BLAKE3_DIGEST_LEN: usize = 32;

/// The algorithm tag prefixing the canonical string form (`blake3:<hex>`), mirror
/// of Nix's `sha256:` convention. Frozen.
pub const BLAKE3_PREFIX: &str = "blake3:";

/// Domain separation applied before hashing the raw NAR: NONE. Stated as a named
/// constant so the freeze is greppable and a reviewer sees the decision, not its
/// absence. `Some(b"...")` here would be a network-splitting change: it would make
/// our identity diverge from the iroh-blobs blob hash (see [`Blake3Digest`] docs).
/// The conformance test proves plain unkeyed BLAKE3 by pinning the published
/// empty-input vector.
pub const BLAKE3_DOMAIN_SEPARATION: Option<&[u8]> = None;

/// The recipe pin, as a COMPILE-TIME assertion. A `debug_assert` fires only in
/// debug builds and only when a function runs; this fails the BUILD, in every
/// profile, the moment someone adds domain separation without reckoning with what
/// it does (it splits the network and diverges from the iroh-blobs blob hash).
const _: () = assert!(
    BLAKE3_DOMAIN_SEPARATION.is_none(),
    "the frozen recipe is plain unkeyed BLAKE3 (task-48); domain separation would \
     split the network and diverge from the iroh-blobs blob hash"
);

/// Slice size [`Blake3Digest::stream_raw_nar`] consumes its input in, and hence
/// its peak allocation regardless of NAR size. NOT frozen and NOT interop-visible:
/// BLAKE3 is a streaming hash, so any chunking yields the identical digest. 64 KiB
/// is a page-multiple read that keeps syscalls off the hot path without making the
/// buffer itself a memory question.
pub const STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// `BLAKE3(RawNarV1)` - the universal, transport-independent content identity of a
/// raw (uncompressed) NAR: the byte a peer is asked for on ANY transport, and what
/// a [`NarTransfer`](crate::NarTransfer) verifies against (gate 1).
///
/// The recipe is PLAIN, UNKEYED BLAKE3 over the raw NAR bytes - NO domain
/// separation (see [`BLAKE3_DOMAIN_SEPARATION`]). This is forced by the transport
/// goal: iroh-blobs addresses blobs by the plain unkeyed BLAKE3 of their content
/// (via bao), so `BLAKE3(RawNarV1)` with nothing added EQUALS the iroh-blobs blob
/// hash, and a peer can fetch by it directly. The full freeze narrative (NarSize vs
/// FileSize, the RawNarV1 unit, the NarHash relationship) lives in the daemon's
/// `content_id` module, which re-exports this type.
///
/// Canonical string form: `blake3:<64 lowercase hex chars>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Blake3Digest([u8; BLAKE3_DIGEST_LEN]);

impl Blake3Digest {
    /// Compute the addressed unit from the exact `RawNarV1` bytes: plain, unkeyed
    /// BLAKE3, no domain separation. This IS the frozen recipe; the equal digest an
    /// iroh-blobs node computes for the same bytes is what lets a peer fetch by it.
    pub fn from_raw_nar(raw_nar: &[u8]) -> Self {
        Blake3Digest(*blake3::hash(raw_nar).as_bytes())
    }

    /// The SAME frozen recipe, applied to a `RawNarV1` byte STREAM in bounded
    /// memory. Returns the digest and the exact number of bytes consumed (its
    /// NarSize, uncompressed - never a FileSize). The input is consumed in
    /// [`STREAM_CHUNK_BYTES`] slices so peak allocation is that chunk whatever the
    /// NAR's size; BLAKE3 is a streaming hash, so this agrees with
    /// [`Blake3Digest::from_raw_nar`] byte-for-byte (asserted in the tests).
    pub fn stream_raw_nar<R: std::io::Read>(mut raw_nar: R) -> std::io::Result<(Self, u64)> {
        let mut hasher = blake3::Hasher::new();
        let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
        let mut total: u64 = 0;
        loop {
            let read = raw_nar.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            hasher.update(&chunk[..read]);
            total += read as u64;
        }
        Ok((Blake3Digest(*hasher.finalize().as_bytes()), total))
    }

    /// Wrap a known 32-byte digest (e.g. one carried in a [`ProviderRecord`] or a
    /// hold answer, or read from a claim on the wire). Does not hash anything.
    pub const fn from_bytes(bytes: [u8; BLAKE3_DIGEST_LEN]) -> Self {
        Blake3Digest(bytes)
    }

    /// The raw 32 bytes, for a transport to build its native content handle
    /// (e.g. `iroh_blobs::Hash::from_bytes`), so no transport's `Display` is ever
    /// depended on.
    pub const fn as_bytes(&self) -> &[u8; BLAKE3_DIGEST_LEN] {
        &self.0
    }

    /// The 64-char lowercase hex (WITHOUT the `blake3:` prefix). For the canonical
    /// wire string use [`fmt::Display`]/`to_string`.
    pub fn to_hex(&self) -> String {
        hexfmt::encode(&self.0)
    }
}

/// Why a string was not a canonical [`Blake3Digest`]. Distinct variants so a log
/// line names the exact fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestParseError {
    /// The `blake3:` prefix was missing.
    MissingPrefix,
    /// The hex body was not exactly 64 lowercase hex chars.
    BadHex(String),
}

impl fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestParseError::MissingPrefix => {
                write!(f, "missing '{BLAKE3_PREFIX}' prefix on a blake3 digest")
            }
            DigestParseError::BadHex(why) => write!(f, "malformed blake3 hex: {why}"),
        }
    }
}

impl std::error::Error for DigestParseError {}

impl FromStr for Blake3Digest {
    type Err = DigestParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s
            .strip_prefix(BLAKE3_PREFIX)
            .ok_or(DigestParseError::MissingPrefix)?;
        let bytes = hexfmt::decode_fixed::<BLAKE3_DIGEST_LEN>(hex)
            .map_err(|e| DigestParseError::BadHex(e.to_string()))?;
        Ok(Blake3Digest(bytes))
    }
}

impl fmt::Display for Blake3Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{BLAKE3_PREFIX}{}", self.to_hex())
    }
}

impl Serialize for Blake3Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Blake3Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// -------------------------------------------------------------------------
// Transport locators: HOW to reach a holder. Per-transport, not derivable from
// the content identity - the whole reason a claim pairs one universal identity
// with per-transport offers.
// -------------------------------------------------------------------------

/// Which transport an offer selects: the dispatch key a
/// [`TransferRegistry`](crate::TransferRegistry) maps to a
/// [`NarTransfer`](crate::NarTransfer) backend. A KNOWN wire transport with NO
/// registered backend (e.g. `BitTorrent` today) is a MISS the driver SKIPS, never
/// a crash - the same tolerate-and-skip posture as the daemon's `TransportTag`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportTag {
    /// iroh whole-blob. Its locator is a [`NodeId`].
    Iroh,
    /// BitTorrent - representable so a second transport is not a network fork; no
    /// backend yet. Its locator is an [`InfoHash`].
    BitTorrent,
    /// Raw NAR transfer over libp2p streams. Its locator is the provider [`NodeId`]
    /// plus a bounded set of signed relay-identity hints.
    Libp2p,
}

impl TransportTag {
    /// The tag that dispatches a given seam [`TransportOffer`]. (The daemon's own
    /// wire offer enum `claim::KnownTransport` maps to this tag via its own
    /// `KnownTransport::tag()`, since the two offer representations differ.)
    pub fn of(offer: &TransportOffer) -> Self {
        match offer {
            TransportOffer::Iroh { .. } => TransportTag::Iroh,
            TransportOffer::BitTorrent { .. } => TransportTag::BitTorrent,
            TransportOffer::Libp2p { .. } => TransportTag::Libp2p,
        }
    }

    /// Stable seam/log name. `iroh` and `bittorrent` also match the frozen daemon
    /// `KnownTransport` JSON tags; `libp2p` deliberately does NOT extend that legacy
    /// enum or wire. ProviderRecord's separate binary union assigns libp2p tag 2.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportTag::Iroh => "iroh",
            TransportTag::BitTorrent => "bittorrent",
            TransportTag::Libp2p => "libp2p",
        }
    }
}

impl fmt::Display for TransportTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A BitTorrent infohash - the swarm/piece-layout locator. Modelled so a
/// [`ProviderRecord`](crate::ProviderRecord) / claim can carry a second transport
/// without a schema fork; no BitTorrent backend exists yet. Both BEP 3 (20-byte
/// SHA-1) and BEP 52 (32-byte SHA-256) forms are representable, disambiguated by
/// length. The daemon re-exports this as `BitTorrentInfoHash`.
///
/// Canonical wire string: lowercase hex, whose LENGTH (40 vs 64 chars)
/// disambiguates the version - so the wire form is self-describing without a
/// separate tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InfoHash {
    /// BEP 3 SHA-1 infohash (20 bytes).
    V1([u8; 20]),
    /// BEP 52 SHA-256 infohash (32 bytes); piece-layout merkle root.
    V2([u8; 32]),
}

impl InfoHash {
    /// The v1 (20-byte SHA-1) infohash.
    pub const fn v1(bytes: [u8; 20]) -> Self {
        InfoHash::V1(bytes)
    }

    /// The v2 (32-byte SHA-256) infohash.
    pub const fn v2(bytes: [u8; 32]) -> Self {
        InfoHash::V2(bytes)
    }

    /// The raw infohash bytes (20 for v1, 32 for v2).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            InfoHash::V1(b) => b,
            InfoHash::V2(b) => b,
        }
    }

    /// The canonical lowercase-hex string (40 chars for v1, 64 for v2).
    pub fn to_hex(&self) -> String {
        hexfmt::encode(self.as_bytes())
    }
}

/// Why a string was not a canonical [`InfoHash`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfoHashParseError {
    /// The hex decoded to a length that is neither 20 (v1) nor 32 (v2) bytes.
    WrongLength(usize),
    /// The string was not valid hex.
    BadHex(String),
}

impl fmt::Display for InfoHashParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InfoHashParseError::WrongLength(n) => write!(
                f,
                "infohash decoded to {n} bytes, expected 20 (v1) or 32 (v2)"
            ),
            InfoHashParseError::BadHex(why) => write!(f, "malformed infohash hex: {why}"),
        }
    }
}

impl std::error::Error for InfoHashParseError {}

impl FromStr for InfoHash {
    type Err = InfoHashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hexfmt::decode_var(s).map_err(|e| InfoHashParseError::BadHex(e.to_string()))?;
        match bytes.len() {
            20 => Ok(InfoHash::V1(bytes.try_into().unwrap())),
            32 => Ok(InfoHash::V2(bytes.try_into().unwrap())),
            n => Err(InfoHashParseError::WrongLength(n)),
        }
    }
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for InfoHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for InfoHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Maximum signed relay identities carried by one libp2p offer. This is a wire
/// bound, not a policy default: a decoder refuses a larger count and a constructor
/// never truncates it.
pub const MAX_LIBP2P_RELAY_HINTS: usize = 2;

/// Why a [`RelayHints`] value could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayHintsError {
    /// More than [`MAX_LIBP2P_RELAY_HINTS`] identities were supplied.
    TooMany { found: usize, cap: usize },
    /// A relay is not a strict ed25519 identity: its compressed point is invalid or
    /// it is a weak/small-order key that strict verification would reject.
    InvalidIdentity { relay: NodeId },
    /// Relay identities were duplicated or not strictly ascending by their canonical
    /// 32-byte [`NodeId`] encoding.
    NotCanonical { previous: NodeId, found: NodeId },
}

impl fmt::Display for RelayHintsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayHintsError::TooMany { found, cap } => {
                write!(
                    f,
                    "libp2p offer carries {found} relay hints, exceeds the {cap} cap"
                )
            }
            RelayHintsError::InvalidIdentity { relay } => write!(
                f,
                "libp2p relay hint {relay} is not a strict ed25519 identity"
            ),
            RelayHintsError::NotCanonical { previous, found } => write!(
                f,
                "libp2p relay hints are not strictly ascending: {previous} then {found}"
            ),
        }
    }
}

impl std::error::Error for RelayHintsError {}

/// A bounded, canonical set of relay identities carried inside a signed libp2p
/// transport offer.
///
/// The representation is private so callers cannot construct an over-cap,
/// duplicate, descending, malformed-point, or small-order hint set. Use
/// [`RelayHints::try_from_nodes`]; it rejects bad input instead of sorting or
/// truncating it. The fixed two-element backing keeps this value, and therefore
/// [`TransportOffer`], [`Copy`]. A provider/self-relay relationship is contextual
/// to the containing record and is checked by the ProviderRecord codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayHints {
    nodes: [NodeId; MAX_LIBP2P_RELAY_HINTS],
    len: u8,
}

impl RelayHints {
    /// No relay hints. Production writers use this until live reservation truth is
    /// wired by TASK-219.
    pub const fn empty() -> Self {
        RelayHints {
            nodes: [NodeId::from_bytes([0; NODE_ID_LEN]); MAX_LIBP2P_RELAY_HINTS],
            len: 0,
        }
    }

    /// Validate and copy a relay-hint slice. The input must already be strictly
    /// ascending; this function never silently sorts or truncates signed input.
    pub fn try_from_nodes(nodes: &[NodeId]) -> Result<Self, RelayHintsError> {
        if nodes.len() > MAX_LIBP2P_RELAY_HINTS {
            return Err(RelayHintsError::TooMany {
                found: nodes.len(),
                cap: MAX_LIBP2P_RELAY_HINTS,
            });
        }

        let mut hints = RelayHints::empty();
        for (index, relay) in nodes.iter().copied().enumerate() {
            let key = VerifyingKey::from_bytes(relay.as_bytes())
                .map_err(|_| RelayHintsError::InvalidIdentity { relay })?;
            if key.is_weak() {
                return Err(RelayHintsError::InvalidIdentity { relay });
            }
            if index > 0 {
                let previous = hints.nodes[index - 1];
                if previous >= relay {
                    return Err(RelayHintsError::NotCanonical {
                        previous,
                        found: relay,
                    });
                }
            }
            hints.nodes[index] = relay;
        }
        hints.len = nodes.len() as u8;
        Ok(hints)
    }

    /// The canonical relay identities in strict ascending order.
    pub fn as_slice(&self) -> &[NodeId] {
        &self.nodes[..usize::from(self.len)]
    }

    /// Number of relay identities carried on wire.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether no relay identities are carried.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for RelayHints {
    fn default() -> Self {
        Self::empty()
    }
}

impl<const N: usize> TryFrom<[NodeId; N]> for RelayHints {
    type Error = RelayHintsError;

    fn try_from(nodes: [NodeId; N]) -> Result<Self, Self::Error> {
        Self::try_from_nodes(&nodes)
    }
}

impl TryFrom<&[NodeId]> for RelayHints {
    type Error = RelayHintsError;

    fn try_from(nodes: &[NodeId]) -> Result<Self, Self::Error> {
        Self::try_from_nodes(nodes)
    }
}

/// A PURE LOCATOR: the transport-specific coordinate to reach a holder, carrying
/// NEVER the content identity (which appears exactly once, in a
/// [`ProviderRecord`](crate::ProviderRecord)'s content field). So a record can
/// never name two different blobs - single-identity is structural. A claim/record
/// may carry several offers; the transport is chosen at REQUEST time by
/// [`TransportTag`], which is why transfer is a runtime tag-keyed registry axis and
/// not a compile-time selection (docs/peer-fabric-seam.md; AC#5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportOffer {
    /// iroh whole-blob: the locator is the holder [`NodeId`].
    Iroh { node: NodeId },
    /// BitTorrent (representable only): the locator is an [`InfoHash`].
    BitTorrent { infohash: InfoHash },
    /// Raw NAR transfer over libp2p: the provider's own [`NodeId`] plus at most two
    /// canonical, signature-bound relay identities. Relay addresses never appear here.
    Libp2p {
        node: NodeId,
        relay_hints: RelayHints,
    },
}

impl TransportOffer {
    /// A direct libp2p locator with no relay hints. This is the TASK-156 production
    /// writer shape until TASK-219 derives live reservation identities.
    pub const fn libp2p(node: NodeId) -> Self {
        TransportOffer::Libp2p {
            node,
            relay_hints: RelayHints::empty(),
        }
    }

    /// The transport tag this offer dispatches on.
    pub fn tag(&self) -> TransportTag {
        TransportTag::of(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- NodeId ---------------------------------------------------------------

    #[test]
    fn node_id_round_trips_as_64_lowercase_hex() {
        let node = NodeId::from_bytes([0x11; NODE_ID_LEN]);
        let s = node.to_string();
        assert_eq!(s, "11".repeat(32));
        assert_eq!(s.len(), 64);
        assert_eq!(node.as_bytes(), &[0x11; NODE_ID_LEN]);
        assert_eq!(s.parse::<NodeId>().unwrap(), node);
    }

    #[test]
    fn node_id_serde_is_bare_hex() {
        let node = NodeId::from_bytes([0x22; NODE_ID_LEN]);
        let json = serde_json::to_string(&node).unwrap();
        assert_eq!(json, format!("\"{}\"", "22".repeat(32)));
        assert_eq!(serde_json::from_str::<NodeId>(&json).unwrap(), node);
    }

    #[test]
    fn node_id_rejects_wrong_length() {
        assert!("1111".parse::<NodeId>().is_err());
    }

    // --- Blake3Digest: the frozen recipe conformance vectors ------------------
    // These BITE: only plain unkeyed BLAKE3 with lowercase hex reproduces them.

    /// The published BLAKE3 empty-input test vector. A keyed or domain-separated
    /// recipe CANNOT produce this, so matching it pins the frozen recipe.
    const BLAKE3_EMPTY: &str =
        "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    /// A fixed non-empty vector (`b"nix-p2p/RawNarV1"`), cross-checked by
    /// `scripts/check-golden-vectors.py` against a stock `b3sum`.
    const BLAKE3_MARKER_INPUT: &[u8] = b"nix-p2p/RawNarV1";
    const BLAKE3_MARKER: &str =
        "blake3:74f885afdc845a012272e457f600cf78ed1297b47ac1a912047bd7351d32e23b";

    #[test]
    fn recipe_is_plain_unkeyed_blake3_lowercase_hex() {
        assert_eq!(
            Blake3Digest::from_raw_nar(b"").to_string(),
            BLAKE3_EMPTY,
            "empty-input digest must be the published plain-BLAKE3 vector; a keyed \
             or domain-separated recipe would land elsewhere"
        );
        assert_eq!(
            Blake3Digest::from_raw_nar(BLAKE3_MARKER_INPUT).to_string(),
            BLAKE3_MARKER,
        );
        assert!(BLAKE3_DOMAIN_SEPARATION.is_none());
    }

    #[test]
    fn a_domain_separated_recipe_would_be_caught() {
        // Negative control: prove the conformance vector would FAIL under a wrong
        // recipe, so the pin above is not vacuous. Simulate the most plausible
        // wrong recipe - prefixing a domain-separation tag - and show it does not
        // land on the frozen empty vector.
        let wrong = {
            let mut input = b"nix-p2p-domain-sep\0".to_vec();
            input.extend_from_slice(b"");
            Blake3Digest::from_raw_nar(&input)
        };
        assert_ne!(
            wrong.to_string(),
            BLAKE3_EMPTY,
            "a domain-separated recipe must NOT collide with the plain empty vector"
        );
    }

    #[test]
    fn streaming_recipe_equals_the_one_shot_recipe() {
        for len in [
            0,
            1,
            STREAM_CHUNK_BYTES - 1,
            STREAM_CHUNK_BYTES,
            STREAM_CHUNK_BYTES + 1,
            3 * STREAM_CHUNK_BYTES + 7,
        ] {
            let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let (streamed, consumed) =
                Blake3Digest::stream_raw_nar(bytes.as_slice()).expect("a slice reader cannot fail");
            assert_eq!(
                streamed,
                Blake3Digest::from_raw_nar(&bytes),
                "the streaming and one-shot constructors are the SAME frozen recipe; \
                 they diverged at len={len}"
            );
            assert_eq!(
                consumed, len as u64,
                "stream_raw_nar must report the exact NarSize it consumed"
            );
        }
        assert_eq!(
            Blake3Digest::stream_raw_nar(b"".as_slice()).unwrap().0,
            BLAKE3_EMPTY.parse::<Blake3Digest>().unwrap(),
        );
    }

    #[test]
    fn digest_string_round_trips_and_is_canonical() {
        let digest = Blake3Digest::from_bytes([0xab; BLAKE3_DIGEST_LEN]);
        let s = digest.to_string();
        assert_eq!(s, format!("blake3:{}", "ab".repeat(32)));
        assert_eq!(s.parse::<Blake3Digest>().unwrap(), digest);
    }

    #[test]
    fn digest_serde_is_the_canonical_string() {
        let digest = Blake3Digest::from_bytes([0x01; BLAKE3_DIGEST_LEN]);
        let json = serde_json::to_string(&digest).unwrap();
        assert_eq!(json, format!("\"blake3:{}\"", "01".repeat(32)));
        assert_eq!(serde_json::from_str::<Blake3Digest>(&json).unwrap(), digest);
    }

    #[test]
    fn digest_parse_rejects_missing_prefix_and_bad_length() {
        assert_eq!(
            "af1349b9".parse::<Blake3Digest>(),
            Err(DigestParseError::MissingPrefix)
        );
        assert!(matches!(
            "blake3:tooshort".parse::<Blake3Digest>(),
            Err(DigestParseError::BadHex(_))
        ));
    }

    // --- TransportTag / TransportOffer ---------------------------------------

    #[test]
    fn transport_tag_dispatches_each_offer_variant() {
        let iroh = TransportOffer::Iroh {
            node: NodeId::from_bytes([0x22; NODE_ID_LEN]),
        };
        let bt = TransportOffer::BitTorrent {
            infohash: InfoHash::V2([0x33; 32]),
        };
        let libp2p = TransportOffer::Libp2p {
            node: NodeId::from_bytes([0x44; NODE_ID_LEN]),
            relay_hints: RelayHints::empty(),
        };
        assert_eq!(iroh.tag(), TransportTag::Iroh);
        assert_eq!(bt.tag(), TransportTag::BitTorrent);
        assert_eq!(libp2p.tag(), TransportTag::Libp2p);
        assert_eq!(TransportTag::Iroh.as_str(), "iroh");
        assert_eq!(TransportTag::BitTorrent.as_str(), "bittorrent");
        assert_eq!(TransportTag::Libp2p.as_str(), "libp2p");

        fn assert_copy<T: Copy>() {}
        assert_copy::<TransportOffer>();
    }

    fn valid_node(seed: u8) -> NodeId {
        NodeId::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    #[test]
    fn relay_hints_are_bounded_strict_and_canonical() {
        let mut relays = [valid_node(1), valid_node(2)];
        relays.sort();
        let hints = RelayHints::try_from(relays).expect("two sorted strict keys");
        assert_eq!(hints.as_slice(), &relays);
        assert_eq!(hints.len(), 2);
        assert!(!hints.is_empty());

        assert!(RelayHints::empty().is_empty());
        assert!(matches!(
            RelayHints::try_from([relays[0], relays[1], valid_node(3)]),
            Err(RelayHintsError::TooMany { found: 3, cap: 2 })
        ));
        assert!(matches!(
            RelayHints::try_from([relays[0], relays[0]]),
            Err(RelayHintsError::NotCanonical { .. })
        ));
        assert!(matches!(
            RelayHints::try_from([relays[1], relays[0]]),
            Err(RelayHintsError::NotCanonical { .. })
        ));
    }

    #[test]
    fn relay_hints_reject_invalid_and_small_order_ed25519_identities() {
        let invalid_point = NodeId::from_bytes([0xdf; NODE_ID_LEN]);
        assert_eq!(
            RelayHints::try_from([invalid_point]),
            Err(RelayHintsError::InvalidIdentity {
                relay: invalid_point
            })
        );

        let mut identity = [0; NODE_ID_LEN];
        identity[0] = 1;
        let small_order = NodeId::from_bytes(identity);
        assert_eq!(
            RelayHints::try_from([small_order]),
            Err(RelayHintsError::InvalidIdentity { relay: small_order })
        );
    }

    // --- InfoHash -------------------------------------------------------------

    #[test]
    fn infohash_v1_and_v2_disambiguate_by_length() {
        let v1 = InfoHash::v1([0xaa; 20]);
        let v2 = InfoHash::v2([0xbb; 32]);
        assert_eq!(v1.to_string(), "aa".repeat(20));
        assert_eq!(v2.to_string(), "bb".repeat(32));
        assert_eq!(v1.to_hex().len(), 40);
        assert_eq!(v2.to_hex().len(), 64);
        assert_eq!(v1.to_string().parse::<InfoHash>().unwrap(), v1);
        assert_eq!(v2.to_string().parse::<InfoHash>().unwrap(), v2);
    }

    #[test]
    fn infohash_rejects_a_length_that_is_neither_form() {
        let bad = "cc".repeat(24);
        assert_eq!(
            bad.parse::<InfoHash>(),
            Err(InfoHashParseError::WrongLength(24))
        );
    }

    #[test]
    fn infohash_serde_round_trips_both_forms() {
        for hash in [InfoHash::v1([0x01; 20]), InfoHash::v2([0x02; 32])] {
            let json = serde_json::to_string(&hash).unwrap();
            assert_eq!(serde_json::from_str::<InfoHash>(&json).unwrap(), hash);
        }
    }
}
