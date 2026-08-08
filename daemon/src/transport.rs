//! Transport-SPECIFIC locators and protocol constants (task-48 FREEZE).
//!
//! The counterpart to [`crate::content_id`]: where that module freezes the ONE
//! universal content identity every transport shares, this module freezes the
//! per-transport LOCATORS - the coordinates each transport needs to actually
//! reach a holder, which are NOT derivable from the content identity and differ
//! by transport:
//!   * iroh: a holder [`NodeId`] (an ed25519 public key) + the [`IROH_BLOBS_ALPN`]
//!     protocol identifier. iroh dials a NodeId and streams the blob addressed by
//!     the universal [`crate::content_id::Blake3Digest`].
//!   * BitTorrent: a [`BitTorrentInfoHash`] naming a swarm/piece-layout. A future
//!     BitTorrent backend addresses the swarm by infohash, then still verifies the
//!     transferred bytes against the SAME `Blake3Digest`. Representable here
//!     (proving a 2nd transport is not a network fork) though no backend exists
//!     yet (task-38/task-39 wire the real transports).
//!
//! This separation is the whole point of the freeze's design constraint: a
//! transport is added by adding its locator type here and a claim offer variant
//! (see [`crate::claim::KnownTransport`]) - never by touching the content
//! identity. A BitTorrent locator does not fit in a `NodeId`, and forcing it to
//! would fork the supply network the day BitTorrent ships.
//!
//! ## Canonical encodings pinned here
//!
//! [`NodeId`] is the 32 raw ed25519 public-key bytes; its canonical wire string is
//! 64 lowercase hex chars. We canonicalise on the RAW BYTES, not on iroh's own
//! `Display`, on purpose: task-39 reconstructs the iroh handle via the stable
//! `iroh::NodeId::from_bytes(&[u8; 32])` byte constructor, so our wire form never
//! depends on which string encoding a given iroh version happens to print. That is
//! how "content identity separated from transport" is made robust against iroh API
//! churn (PRD risk 10).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::hexfmt;

/// The iroh-blobs application-layer protocol negotiated over QUIC ALPN. Frozen:
/// two nix-p2p daemons MUST present the identical ALPN or they never connect;
/// changing it splits the network at the connection layer.
///
/// This is the stock iroh-blobs protocol identifier (PRD: "Transfer uses stock
/// iroh-blobs ALPN"), so a nix-p2p node speaks the same get-protocol as any
/// iroh-blobs node and gets BLAKE3-verified streaming for free.
///
/// FREEZE-RISK NOTE, stated honestly: this constant is pinned WITHOUT an `iroh`
/// dependency in-tree (iroh lands in task-39; the freeze pins the value now). The
/// exact bytes below are this author's best knowledge of iroh-blobs' default ALPN
/// and are an ASSUMPTION until task-39 can cross-check. task-39 MUST add a
/// compile/test assertion that `IROH_BLOBS_ALPN == iroh_blobs::ALPN` (or the
/// pinned version's equivalent). Unlike the hash recipe, a wrong ALPN fails LOUDLY
/// and early (peers simply fail to connect at S6 interop, no bytes are corrupted
/// and no held blob is invalidated), so it is reconcilable at S6 - which is the
/// design intent: S6 CONFIRMS, and an ALPN mismatch is the one freeze surface S6
/// can still safely realign because no data is addressed by it.
pub const IROH_BLOBS_ALPN: &[u8] = b"/iroh-bytes/4";

/// Length in bytes of a [`NodeId`] (ed25519 public key).
pub const NODE_ID_LEN: usize = 32;

/// A holder's iroh network identity: an ed25519 public key. Transport-specific
/// (an iroh coordinate, not a universal content identity).
///
/// Canonical wire string: 64 LOWERCASE hex chars (no prefix - it is a bare key,
/// matching how iroh treats a `NodeId`; uppercase is rejected on decode, see
/// [`crate::hexfmt`]). Convert to/from the raw 32 bytes for the iroh handle via
/// [`NodeId::from_bytes`]/[`NodeId::as_bytes`].
///
/// STRUCTURAL VALIDATION (codex finding 5): this validates length and lowercase
/// hex, but NOT that the 32 bytes are a valid ed25519 curve point. That check
/// needs the pinned iroh constructor (`iroh::PublicKey::from_bytes`, which
/// rejects a non-canonical point) and so DEFERS to task-39, exactly like the
/// `IROH_BLOBS_ALPN == iroh_blobs::ALPN` assert. Stated so the deferral is a
/// decision, not an oversight: a non-point NodeId is undiallable and fails loudly
/// at connect time, it cannot corrupt content addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; NODE_ID_LEN]);

impl NodeId {
    /// Wrap the 32 raw ed25519 public-key bytes (e.g. `iroh::NodeId::as_bytes`).
    pub const fn from_bytes(bytes: [u8; NODE_ID_LEN]) -> Self {
        NodeId(bytes)
    }

    /// The raw 32 bytes, for `iroh::NodeId::from_bytes` at the transport boundary.
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

/// A BitTorrent infohash: the swarm/piece-layout locator a BitTorrent transport
/// addresses. Representable so the claim schema admits a 2nd transport without a
/// fork; no BitTorrent backend exists yet.
///
/// BitTorrent has two infohash forms and both are modelled so a real backend does
/// not need a schema break:
///   * [`BitTorrentInfoHash::V1`] - the 20-byte SHA-1 infohash (BEP 3).
///   * [`BitTorrentInfoHash::V2`] - the 32-byte SHA-256 infohash (BEP 52),
///     which also anchors the piece-layout merkle tree.
///
/// Canonical wire string: lowercase hex, whose LENGTH (40 vs 64 chars)
/// disambiguates the version - so the wire form is self-describing without a
/// separate tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BitTorrentInfoHash {
    /// BEP 3 SHA-1 infohash (20 bytes).
    V1([u8; 20]),
    /// BEP 52 SHA-256 infohash (32 bytes); piece-layout merkle root.
    V2([u8; 32]),
}

impl BitTorrentInfoHash {
    /// The v1 (20-byte SHA-1) infohash.
    pub const fn v1(bytes: [u8; 20]) -> Self {
        BitTorrentInfoHash::V1(bytes)
    }

    /// The v2 (32-byte SHA-256) infohash.
    pub const fn v2(bytes: [u8; 32]) -> Self {
        BitTorrentInfoHash::V2(bytes)
    }

    /// The raw infohash bytes (20 for v1, 32 for v2).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            BitTorrentInfoHash::V1(b) => b,
            BitTorrentInfoHash::V2(b) => b,
        }
    }

    /// The canonical lowercase-hex string (40 chars for v1, 64 for v2).
    pub fn to_hex(&self) -> String {
        hexfmt::encode(self.as_bytes())
    }
}

/// Why a string was not a canonical [`BitTorrentInfoHash`].
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

impl FromStr for BitTorrentInfoHash {
    type Err = InfoHashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hexfmt::decode_var(s).map_err(|e| InfoHashParseError::BadHex(e.to_string()))?;
        match bytes.len() {
            20 => Ok(BitTorrentInfoHash::V1(bytes.try_into().unwrap())),
            32 => Ok(BitTorrentInfoHash::V2(bytes.try_into().unwrap())),
            n => Err(InfoHashParseError::WrongLength(n)),
        }
    }
}

impl fmt::Display for BitTorrentInfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for BitTorrentInfoHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BitTorrentInfoHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_pinned_and_non_empty() {
        // Conformance: the frozen ALPN value. A change to this literal is a
        // deliberate network-split and must be a reviewed diff. (task-39 adds the
        // `== iroh_blobs::ALPN` cross-check once iroh is a dependency.)
        assert_eq!(IROH_BLOBS_ALPN, b"/iroh-bytes/4");
        assert!(
            !IROH_BLOBS_ALPN.is_empty(),
            "an empty ALPN never negotiates"
        );
    }

    #[test]
    fn node_id_round_trips_as_64_hex() {
        let node = NodeId::from_bytes([0x11; NODE_ID_LEN]);
        let s = node.to_string();
        assert_eq!(s, "11".repeat(32));
        assert_eq!(s.len(), 64);
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

    #[test]
    fn infohash_v1_and_v2_disambiguate_by_length() {
        let v1 = BitTorrentInfoHash::v1([0xaa; 20]);
        let v2 = BitTorrentInfoHash::v2([0xbb; 32]);
        assert_eq!(v1.to_string(), "aa".repeat(20));
        assert_eq!(v2.to_string(), "bb".repeat(32));
        // 40 hex chars -> v1, 64 -> v2, purely from length.
        assert_eq!(v1.to_string().parse::<BitTorrentInfoHash>().unwrap(), v1);
        assert_eq!(v2.to_string().parse::<BitTorrentInfoHash>().unwrap(), v2);
    }

    #[test]
    fn infohash_rejects_a_length_that_is_neither_form() {
        // 24 bytes = 48 hex chars: not a real infohash form.
        let bad = "cc".repeat(24);
        assert_eq!(
            bad.parse::<BitTorrentInfoHash>(),
            Err(InfoHashParseError::WrongLength(24))
        );
    }

    #[test]
    fn infohash_serde_round_trips_both_forms() {
        for hash in [
            BitTorrentInfoHash::v1([0x01; 20]),
            BitTorrentInfoHash::v2([0x02; 32]),
        ] {
            let json = serde_json::to_string(&hash).unwrap();
            assert_eq!(
                serde_json::from_str::<BitTorrentInfoHash>(&json).unwrap(),
                hash
            );
        }
    }
}
