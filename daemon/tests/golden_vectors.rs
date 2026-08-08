//! Fixture-INDEPENDENT conformance for the task-48 golden vectors.
//!
//! This test compiles the committed golden file into the binary
//! (`include_str!`), so it runs everywhere - `cargo test`, `nix flake check`'s
//! sandboxed `test` - WITHOUT the generated fixture tree (which is absent in the
//! Nix build sandbox; the source guard forbids a `.rs` from even naming the
//! generated-fixture path).
//!
//! What it proves here:
//!   * the recipe vectors are reproduced by our own `Blake3Digest::from_raw_nar`
//!     (the recipe BITES: only plain unkeyed BLAKE3 lands on `af1349b9...`);
//!   * every committed golden string is in the frozen canonical ENCODING
//!     (`blake3:<64 hex>` for the digest, `sha256:` for the NarHash).
//!
//! What it deliberately does NOT do: re-hash the actual fixture NAR. That
//! re-derivation - the "a second impl matches byte-for-byte" half of AC#1 - needs
//! the fixture bytes and so lives in `scripts/check-golden-vectors.py`, run by
//! `just test`. The two halves share this one JSON as their single source of
//! truth, so they cannot disagree about what the golden value IS.

use daemon::{BLAKE3_PREFIX, Blake3Digest};

const GOLDEN: &str = include_str!("golden/raw_nar_v1.json");

/// Minimal field pluck from the golden JSON via serde_json (a daemon dep), so
/// this test needs no bespoke parser.
fn golden() -> serde_json::Value {
    serde_json::from_str(GOLDEN).expect("golden/raw_nar_v1.json is valid JSON")
}

#[test]
fn recipe_vectors_are_reproduced_by_our_hasher() {
    let doc = golden();
    let vectors = doc["recipe_vectors"]
        .as_array()
        .expect("recipe_vectors is an array");
    assert!(
        !vectors.is_empty(),
        "there must be at least one recipe vector"
    );
    for vector in vectors {
        let input = vector["input_utf8"]
            .as_str()
            .expect("input_utf8 is a string");
        let expected = vector["blake3"].as_str().expect("blake3 is a string");
        let got = Blake3Digest::from_raw_nar(input.as_bytes()).to_string();
        assert_eq!(
            got, expected,
            "recipe vector for input {input:?} did not reproduce; the frozen \
             recipe is plain unkeyed BLAKE3 with no domain separation"
        );
    }
}

#[test]
fn committed_fixture_digest_is_canonical() {
    let doc = golden();
    let fixture = &doc["fixture"];

    let blake3 = fixture["blake3"]
        .as_str()
        .expect("fixture.blake3 is a string");
    // Parses as a canonical Blake3Digest AND re-serialises identically: proves the
    // committed golden is itself in the frozen encoding, not merely a lookalike.
    let parsed: Blake3Digest = blake3.parse().expect("fixture.blake3 is canonical");
    assert_eq!(parsed.to_string(), blake3);
    assert!(blake3.starts_with(BLAKE3_PREFIX));
    assert_eq!(
        blake3.len(),
        BLAKE3_PREFIX.len() + 64,
        "a blake3 digest is 32 bytes = 64 hex chars after the prefix"
    );

    let nar_hash = fixture["nar_hash"]
        .as_str()
        .expect("fixture.nar_hash is a string");
    assert!(
        nar_hash.starts_with("sha256:"),
        "NarHash keeps Nix's sha256: form; it is the signed trust anchor, NOT the \
         BLAKE3 addressed unit"
    );

    let len = fixture["raw_nar_len"]
        .as_u64()
        .expect("raw_nar_len is a number");
    assert!(len > 0, "the raw NAR length must be recorded and positive");
}
