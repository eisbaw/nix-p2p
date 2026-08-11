//! The primitive value types the seam is built from, and their CANONICAL HOME.
//!
//! [`NodeId`], [`Blake3Digest`], [`TransportTag`] and [`TransportOffer`] are
//! deliberately re-declared here rather than shared with the daemon's copies
//! (`daemon::transport::NodeId`, `daemon::content_id::Blake3Digest`,
//! `daemon::transport_fetch::TransportTag`, `daemon::claim::KnownTransport`). This
//! crate is the seam every backend and the frontend agree on, so the identities
//! that cross the seam must live below it, not inside the daemon that will become
//! one consumer. TASK-141 reconciles the daemon to depend on THESE and deletes its
//! duplicates; until then the two sets are byte-compatible by construction (same
//! lengths, same lowercase-hex canonical form) but distinct types.
//!
//! Kept transport-BLIND at the identity layer and transport-SPECIFIC only at the
//! locator ([`TransportOffer`]) - the same separation the daemon freeze draws
//! between `content_id` (universal) and `transport` (per-transport).

use std::fmt;

// -------------------------------------------------------------------------
// Tiny lowercase-hex, dependency-free (mirrors daemon::hexfmt). Encode-only:
// the seam types render a canonical string; parsing/codec is a wire concern
// TASK-126 freezes, not this crate's.
// -------------------------------------------------------------------------

/// Encode bytes as lowercase hex (2 chars per byte, no separators). Lowercase by
/// construction, so the canonical string form of every identity is unambiguous.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("high nibble is 0..16"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("low nibble is 0..16"));
    }
    out
}

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
/// stack prints a node key. This validates NOTHING about curve-point validity - a
/// non-point id is undiallable and fails loudly at connect time, it cannot corrupt
/// content addressing (the same deferral the daemon's `NodeId` documents).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; NODE_ID_LEN]);

impl NodeId {
    /// Wrap the 32 raw ed25519 public-key bytes.
    pub const fn from_bytes(bytes: [u8; NODE_ID_LEN]) -> Self {
        NodeId(bytes)
    }

    /// The raw 32 bytes, for a backend to build its native handle.
    pub const fn as_bytes(&self) -> &[u8; NODE_ID_LEN] {
        &self.0
    }

    /// The 64-char lowercase hex canonical string.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// -------------------------------------------------------------------------
// Blake3Digest: the universal, transport-independent content identity.
// -------------------------------------------------------------------------

/// Length in bytes of a [`Blake3Digest`].
pub const BLAKE3_DIGEST_LEN: usize = 32;

/// The algorithm tag prefixing the canonical string form (`blake3:<hex>`).
pub const BLAKE3_PREFIX: &str = "blake3:";

/// `BLAKE3(RawNarV1)` - the universal, transport-independent content identity of a
/// raw (uncompressed) NAR: the byte a peer is asked for on ANY transport, and what
/// a [`NarTransfer`](crate::NarTransfer) verifies against (gate 1). This crate
/// carries the identity, NOT the recipe: the daemon's `content_id` module owns the
/// frozen `BLAKE3(RawNarV1)` hashing recipe, and TASK-141 re-points it here. So this
/// type only wraps/renders 32 known bytes; it never hashes.
///
/// Canonical string form: `blake3:<64 lowercase hex chars>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Blake3Digest([u8; BLAKE3_DIGEST_LEN]);

impl Blake3Digest {
    /// Wrap a known 32-byte digest (e.g. one carried in a [`ProviderRecord`] or a
    /// hold answer). Does not hash anything - the recipe lives in the daemon's
    /// `content_id` freeze (TASK-141 re-points it here).
    pub const fn from_bytes(bytes: [u8; BLAKE3_DIGEST_LEN]) -> Self {
        Blake3Digest(bytes)
    }

    /// The raw 32 bytes, for a transport to build its native content handle.
    pub const fn as_bytes(&self) -> &[u8; BLAKE3_DIGEST_LEN] {
        &self.0
    }

    /// The 64-char lowercase hex (WITHOUT the `blake3:` prefix).
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

impl fmt::Display for Blake3Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{BLAKE3_PREFIX}{}", self.to_hex())
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
}

impl TransportTag {
    /// The tag that dispatches a given offer.
    pub fn of(offer: &TransportOffer) -> Self {
        match offer {
            TransportOffer::Iroh { .. } => TransportTag::Iroh,
            TransportOffer::BitTorrent { .. } => TransportTag::BitTorrent,
        }
    }

    /// The wire-tag string (matches the daemon's `KnownTransport` serde tags).
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportTag::Iroh => "iroh",
            TransportTag::BitTorrent => "bittorrent",
        }
    }
}

impl fmt::Display for TransportTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A BitTorrent infohash - the swarm/piece-layout locator. Modelled so a
/// [`ProviderRecord`](crate::ProviderRecord) can carry a second transport without a
/// schema fork; no BitTorrent backend exists yet. Both BEP 3 (20-byte SHA-1) and
/// BEP 52 (32-byte SHA-256) forms are representable, disambiguated by length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InfoHash {
    /// BEP 3 SHA-1 infohash (20 bytes).
    V1([u8; 20]),
    /// BEP 52 SHA-256 infohash (32 bytes); piece-layout merkle root.
    V2([u8; 32]),
}

impl InfoHash {
    /// The raw infohash bytes (20 for v1, 32 for v2).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            InfoHash::V1(b) => b,
            InfoHash::V2(b) => b,
        }
    }

    /// The canonical lowercase-hex string (40 chars for v1, 64 for v2).
    pub fn to_hex(&self) -> String {
        to_hex(self.as_bytes())
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
}

impl TransportOffer {
    /// The transport tag this offer dispatches on.
    pub fn tag(&self) -> TransportTag {
        TransportTag::of(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_renders_as_64_lowercase_hex() {
        let node = NodeId::from_bytes([0x11; NODE_ID_LEN]);
        let s = node.to_string();
        assert_eq!(s, "11".repeat(32));
        assert_eq!(s.len(), 64);
        assert_eq!(node.as_bytes(), &[0x11; NODE_ID_LEN]);
    }

    #[test]
    fn blake3_digest_renders_with_prefix() {
        let d = Blake3Digest::from_bytes([0xab; BLAKE3_DIGEST_LEN]);
        assert_eq!(d.to_string(), format!("blake3:{}", "ab".repeat(32)));
    }

    #[test]
    fn transport_tag_dispatches_each_offer_variant() {
        let iroh = TransportOffer::Iroh {
            node: NodeId::from_bytes([0x22; NODE_ID_LEN]),
        };
        let bt = TransportOffer::BitTorrent {
            infohash: InfoHash::V2([0x33; 32]),
        };
        assert_eq!(iroh.tag(), TransportTag::Iroh);
        assert_eq!(bt.tag(), TransportTag::BitTorrent);
        assert_eq!(TransportTag::Iroh.as_str(), "iroh");
        assert_eq!(TransportTag::BitTorrent.as_str(), "bittorrent");
    }

    #[test]
    fn infohash_hex_length_distinguishes_versions() {
        assert_eq!(InfoHash::V1([0xaa; 20]).to_hex().len(), 40);
        assert_eq!(InfoHash::V2([0xbb; 32]).to_hex().len(), 64);
    }
}
