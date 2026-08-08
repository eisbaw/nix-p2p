//! The UNIVERSAL, transport-independent content identity of a NAR (task-48 FREEZE).
//!
//! This module freezes the single hardest interop surface in the whole project:
//! the exact bytes two independent daemons must agree on to fetch the same NAR by
//! content, on ANY transport. It is deliberately transport-BLIND - it names no
//! iroh, no BitTorrent, no ALPN. Those are transport-specific LOCATORS and live in
//! [`crate::transport`]. Keeping the content identity here, with zero transport
//! knowledge, is precisely what lets a second transport (BitTorrent, a future
//! webseed) be added WITHOUT forking the supply network: the content identity
//! appears exactly once per claim (in the payload / `Have`), and each transport
//! offer is a PURE LOCATOR that carries no digest of its own (see
//! [`crate::claim`]).
//!
//! ## The addressed unit: `RawNarV1`
//!
//! `RawNarV1` is the exact `nix-store --dump <path>` byte stream: the
//! UNCOMPRESSED NAR. Nix DEFINES this format (the `nix-archive-1` serialisation);
//! we do not invent it. Every raw NAR begins with the length-prefixed magic
//! `nix-archive-1`. The addressed unit is `BLAKE3(RawNarV1)`.
//!
//! CRITICAL, carried-lesson (the NarSize-vs-FileSize trap): the unit is the RAW
//! NAR, NEVER the compressed `.nar.xz`/`.nar.zst`. The compressed file is a
//! transport detail (the narinfo `FileHash`/`FileSize`, rewritten by task-49); its
//! BLAKE3 would be a different, useless identity. A holder that seeded via
//! `nix-store --dump` and a holder that decompressed a `.nar.xz` back to the raw
//! NAR MUST arrive at the identical [`Blake3Digest`]. That only holds if the unit
//! is unambiguously the uncompressed stream, which is why this is stated as a
//! freeze, not a convention.
//!
//! ## The hashing recipe (frozen, and why it is exactly this)
//!
//! PLAIN, UNKEYED BLAKE3 over the raw NAR bytes. NO domain separation, NO prefix
//! mixed into the hash input, NO keyed mode. See [`BLAKE3_DOMAIN_SEPARATION`]
//! (`None`, on purpose).
//!
//! This is not an aesthetic choice - it is forced by the transport goal. The
//! Candidate-B transport is iroh-blobs, which addresses blobs by the plain,
//! unkeyed BLAKE3 of their content (via bao). If we mixed in a domain-separation
//! prefix, our content identity would NO LONGER equal the iroh-blobs blob hash,
//! and a peer could not fetch by it directly - defeating the entire point of
//! reusing iroh-blobs' verified streaming. So the freeze is: `BLAKE3(RawNarV1)`
//! with nothing added, which equals the iroh-blobs blob hash of the same bytes.
//! The conformance test pins the published BLAKE3 empty-input vector
//! (`af1349b9...`), which any second implementation reproduces ONLY if it too uses
//! plain unkeyed BLAKE3 - a keyed or domain-prefixed recipe cannot land there.
//!
//! ## The canonical string encoding
//!
//! A [`Blake3Digest`] is 32 raw bytes. Its canonical string form - the value that
//! appears in a claim's `blake3` field on the wire - is
//! `blake3:<64 lowercase hex chars>`. Rationale in [`crate::hexfmt`]: hex is
//! reproducible with no shared table (`b3sum` prints it), fixed-width so a length
//! check rejects truncation, and independent of any transport crate's `Display`.
//! The `blake3:` prefix mirrors the `sha256:` convention Nix already uses for
//! `NarHash`, so the value is self-describing and greppable.
//!
//! ## Relationship to `NarHash` (the two identities, kept distinct)
//!
//! There are two content identities for one NAR, and they are NOT interchangeable:
//!   * [`crate::source::NarHash`] - `sha256(RawNarV1)`, the value Nix SIGNS and the
//!     client re-verifies (the trust anchor, the wave-2 discovery key). It is the
//!     universal, transport-independent identity for LOOKUP.
//!   * [`Blake3Digest`] - `BLAKE3(RawNarV1)`, the value a transport FETCHES and
//!     STREAM-VERIFIES by (iroh-blobs speaks BLAKE3, not sha256).
//!
//! Both are functions of the same `RawNarV1` bytes, so a holder computes both from
//! one `--dump`. The claim binds them: it is keyed on the signed `NarHash` and its
//! payload carries the `Blake3Digest` EXACTLY ONCE (transport offers are pure
//! locators - they do not repeat it). The trust chain is unchanged - the Nix
//! client still re-verifies `sha256(nar) == NarHash` after any p2p fetch (wave-1
//! S1); BLAKE3 only addresses and stream-verifies the transfer, it never replaces
//! the signed sha256 gate.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::hexfmt;

/// The BLAKE3 digest is 32 bytes. Frozen: the addressed-unit length two daemons
/// agree on.
pub const BLAKE3_DIGEST_LEN: usize = 32;

/// The algorithm tag prefixing the canonical string form (`blake3:<hex>`), mirror
/// of Nix's `sha256:` convention. Frozen.
pub const BLAKE3_PREFIX: &str = "blake3:";

/// Domain separation applied before hashing the raw NAR: NONE. Stated as a named
/// constant so the freeze is greppable and a reviewer sees the decision, not its
/// absence. `Some(b"...")` here would be a network-splitting change: it would make
/// our identity diverge from the iroh-blobs blob hash (see module docs). The
/// conformance test proves plain unkeyed BLAKE3 by pinning the published
/// empty-input vector.
pub const BLAKE3_DOMAIN_SEPARATION: Option<&[u8]> = None;

/// `BLAKE3(RawNarV1)` - the universal, transport-independent content identity of a
/// raw (uncompressed) NAR. This is the byte a peer is asked for on any transport.
///
/// Construct it from raw NAR bytes with [`Blake3Digest::from_raw_nar`], from a
/// known 32-byte array with [`Blake3Digest::from_bytes`], or parse its canonical
/// `blake3:<hex>` string with [`FromStr`]. Serialises to/from that string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Blake3Digest([u8; BLAKE3_DIGEST_LEN]);

impl Blake3Digest {
    /// Compute the addressed unit from the exact `RawNarV1` bytes: plain, unkeyed
    /// BLAKE3, no domain separation. This IS the frozen recipe; the equal digest
    /// an iroh-blobs node computes for the same bytes is what lets a peer fetch by
    /// it. `debug_assert` on [`BLAKE3_DOMAIN_SEPARATION`] pins the recipe against
    /// a future edit that adds separation without updating this function.
    pub fn from_raw_nar(raw_nar: &[u8]) -> Self {
        debug_assert!(
            BLAKE3_DOMAIN_SEPARATION.is_none(),
            "the frozen recipe is plain unkeyed BLAKE3; adding domain separation \
             splits the network and diverges from the iroh-blobs blob hash"
        );
        Blake3Digest(*blake3::hash(raw_nar).as_bytes())
    }

    /// Wrap a known 32-byte digest (e.g. one read from a claim on the wire, or a
    /// bao outboard). Does not hash anything.
    pub const fn from_bytes(bytes: [u8; BLAKE3_DIGEST_LEN]) -> Self {
        Blake3Digest(bytes)
    }

    /// The raw 32 bytes. A transport converts these into its own native handle
    /// (e.g. `iroh_blobs::Hash::from_bytes`), so no transport's string `Display`
    /// is ever depended on.
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
    /// The hex body was not exactly 64 lowercase/uppercase hex chars.
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- The recipe conformance vectors: fixture-INDEPENDENT, so they run in the
    // Nix build sandbox too. These BITE: only plain unkeyed BLAKE3 with lowercase
    // hex reproduces them. -----------------------------------------------------

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
        // Domain separation is frozen OFF; the recipe above depends on it.
        assert!(BLAKE3_DOMAIN_SEPARATION.is_none());
    }

    #[test]
    fn a_domain_separated_recipe_would_be_caught() {
        // Negative control: prove the conformance vector would FAIL under a wrong
        // recipe, so the test above is not vacuous. Here we simulate the most
        // plausible wrong recipe - prefixing a domain-separation tag - and show it
        // does not match the frozen digest.
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
    fn digest_string_round_trips_and_is_canonical() {
        let digest = Blake3Digest::from_bytes([0xab; BLAKE3_DIGEST_LEN]);
        let s = digest.to_string();
        assert_eq!(s, format!("blake3:{}", "ab".repeat(32)));
        assert_eq!(s.parse::<Blake3Digest>().unwrap(), digest);
    }

    #[test]
    fn serde_is_the_canonical_string() {
        let digest = Blake3Digest::from_bytes([0x01; BLAKE3_DIGEST_LEN]);
        let json = serde_json::to_string(&digest).unwrap();
        assert_eq!(json, format!("\"blake3:{}\"", "01".repeat(32)));
        let back: Blake3Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, digest);
    }

    #[test]
    fn parse_rejects_missing_prefix_and_bad_length() {
        assert_eq!(
            "af1349b9".parse::<Blake3Digest>(),
            Err(DigestParseError::MissingPrefix)
        );
        assert!(matches!(
            "blake3:tooshort".parse::<Blake3Digest>(),
            Err(DigestParseError::BadHex(_))
        ));
    }

    #[test]
    fn from_raw_nar_equals_from_bytes_of_the_same_hash() {
        // The two constructors must agree, since a transport receives raw bytes on
        // one side and a digest on the other.
        let bytes = *blake3::hash(b"some raw nar bytes").as_bytes();
        assert_eq!(
            Blake3Digest::from_raw_nar(b"some raw nar bytes"),
            Blake3Digest::from_bytes(bytes)
        );
    }
}
