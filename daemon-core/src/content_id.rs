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
//! ## Where the type now lives (TASK-141)
//!
//! [`Blake3Digest`] and its frozen `BLAKE3(RawNarV1)` recipe MOVED to the
//! `peer-fabric` seam crate, which is now the canonical home of every value type
//! that crosses the P2P seam (the daemon used to keep a byte-compatible DUPLICATE,
//! deleted by TASK-141). The recipe had to move WITH the type: the daemon's claim
//! codec relies on the type's `serde`/`FromStr` impls, and the orphan rule forbids
//! the daemon adding those to a foreign type. This module keeps the FREEZE
//! NARRATIVE (below) and re-exports the type.
//!
//! Where the freeze is now GUARDED (three layers, no duplicated golden value):
//!   * the RECIPE conformance vectors (`blake3:af1349b9…` empty, the marker
//!     vector, streaming==one-shot, the domain-separation negative control) live
//!     with the type in `peer_fabric::ids` - one home for the recipe;
//!   * the recipe-pinning compile-assert (`BLAKE3_DOMAIN_SEPARATION.is_none()`)
//!     moved with its constant into `peer_fabric::ids`, and it fails the WHOLE
//!     workspace build in every profile, so the daemon inherits it;
//!   * the golden VALUE's single source of truth is the committed golden JSON,
//!     which `daemon/tests/golden_vectors.rs` runs the daemon RE-EXPORT against -
//!     that is the genuine cross-crate anchor (`scripts/check-golden-vectors.py`
//!     cross-checks the same JSON against a stock `b3sum`).
//!
//! The tests below are therefore only a light RE-EXPORT SMOKE TEST: they prove the
//! daemon path resolves to a working type, and deliberately do NOT re-hardcode the
//! golden hex (that would triplicate the frozen value - mped-architect finding,
//! TASK-141).
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
//! `blake3:<64 lowercase hex chars>`. Hex is reproducible with no shared table
//! (`b3sum` prints it), fixed-width so a length check rejects truncation, and
//! independent of any transport crate's `Display`. The `blake3:` prefix mirrors
//! the `sha256:` convention Nix already uses for `NarHash`, so the value is
//! self-describing and greppable.
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
//! one `--dump`. The claim binds them: it is keyed on the signed `NarHash` and a
//! known `WholeNar` payload carries the `Blake3Digest` at most once (transport
//! offers are pure locators - they never repeat it, so a claim can never name two
//! blobs). The trust chain is unchanged - the Nix client still re-verifies
//! `sha256(nar) == NarHash` after any p2p fetch (wave-1 S1); BLAKE3 only addresses
//! and stream-verifies the transfer, it never replaces the signed sha256 gate.

// The type, its frozen recipe, its canonical-string codec and the recipe-pinning
// constant now live in `peer-fabric` (their canonical home; TASK-141). Re-exported
// here so every daemon use-site (`crate::content_id::Blake3Digest`, ...) and the
// freeze narrative above keep their home, with a single definition below the seam.
pub use peer_fabric::{
    BLAKE3_DIGEST_LEN, BLAKE3_DOMAIN_SEPARATION, BLAKE3_PREFIX, Blake3Digest, DigestParseError,
    STREAM_CHUNK_BYTES,
};

#[cfg(test)]
mod tests {
    // RE-EXPORT SMOKE TEST (see module docs): these exercise the daemon path
    // `content_id::Blake3Digest` (= the re-exported `peer_fabric::Blake3Digest`) to
    // prove it resolves to a working type. They deliberately do NOT re-hardcode the
    // golden hex - the recipe vectors live once in `peer_fabric::ids`, and the
    // golden VALUE's SSOT is the committed golden JSON that
    // `daemon/tests/golden_vectors.rs` runs THIS re-export against (the genuine
    // cross-crate anchor).
    use super::*;

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
        let bytes = *blake3::hash(b"some raw nar bytes").as_bytes();
        assert_eq!(
            Blake3Digest::from_raw_nar(b"some raw nar bytes"),
            Blake3Digest::from_bytes(bytes)
        );
    }
}
