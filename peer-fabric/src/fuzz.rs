//! BROAD-cadence structured fuzz target for the signed provider/value record
//! decode+verify boundary (TASK-282 AC#4; folds/supersedes TASK-113). This is the
//! untrusted-bytes -> verified-record seam: `decode_provider_assertion` decodes AND
//! checks the ed25519 signature in one call. See `fuzz/README.md` for the engine
//! decision (proptest, not cargo-fuzz — the reproducibility pin forbids nightly)
//! and the crash-triage runbook.
//!
//! # Invariant (the highest-value security property)
//!
//! A decoder must NEVER return `Ok` on bytes that fail signature/integrity:
//!  * a correctly-signed record round-trips to itself (positive control);
//!  * ANY single-byte mutation of the signed body or signature must NOT verify to a
//!    DIFFERENT record (ed25519 integrity) — Ok is sound only if it returns the
//!    identical record;
//!  * arbitrary bytes must not verify at all (a valid signature over random bytes
//!    would be an ed25519 forgery, probability ~2^-128).

#![cfg(test)]

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

use crate::content::{ContentKey, NAR_HASH_LEN, ProviderRecord};
use crate::ids::{BLAKE3_DIGEST_LEN, Blake3Digest, NodeId, TransportOffer};
use crate::record_codec::{
    ProviderAssertion, decode_provider_assertion, encode_provider_record, sign_provider_record,
};

/// See `fabric_libp2p::fuzz::fuzz_runner` / daemon-core `prop_support` for the
/// two-mode determinism rationale (fixed seed by default, FREE seed under
/// `PROPTEST_FREE_SEED` for `just fuzz-smoke`).
fn fuzz_runner() -> TestRunner {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .unwrap_or(256);
    let config = Config {
        cases,
        ..Config::default()
    };
    if std::env::var_os("PROPTEST_FREE_SEED").is_some() {
        TestRunner::new(config)
    } else {
        TestRunner::new_with_rng(config, TestRng::deterministic_rng(RngAlgorithm::ChaCha))
    }
}

/// Load the committed seed corpus for `target` from `<repo>/fuzz/corpus/<target>`.
fn corpus(target: &str) -> Vec<Vec<u8>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fuzz/corpus")
        .join(target);
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&path) {
                out.push(bytes);
            }
        }
    }
    out
}

fn apply_mutation(bytes: &[u8], kind: u8, idx: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    match kind % 4 {
        0 => {
            if !out.is_empty() {
                let i = idx % out.len();
                out[i] ^= 0xff;
            }
        }
        1 => {
            if !out.is_empty() {
                let i = idx % out.len();
                out[i] = 0;
            }
        }
        2 => {
            let n = idx % (out.len() + 1);
            out.truncate(n);
        }
        _ => out.push((idx as u8) ^ 0x5a),
    }
    out
}

/// A fully-populated, correctly-signed provide over a fixed key (self-serve Iroh
/// offer where the offered node == the signing provider, as schema-v1 requires).
fn good() -> (ProviderRecord, ContentKey) {
    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let key = ContentKey::derive_from_signed_nar_hash(&[0x11u8; NAR_HASH_LEN]);
    let provider = NodeId::from_bytes(sk.verifying_key().to_bytes());
    let record = ProviderRecord {
        key,
        content: Blake3Digest::from_bytes([0xaau8; BLAKE3_DIGEST_LEN]),
        provider,
        offers: vec![TransportOffer::Iroh { node: provider }],
        sequence: 7,
        issued_at: 100,
        expiry: 1_000,
        signature: [0u8; 64],
    };
    (sign_provider_record(&sk, &record), key)
}

/// Integrity under mutation: given a correctly-signed record and its wire bytes
/// (built ONCE, outside the fuzz loop — the ed25519 signing is the expensive part),
/// a mutated stream never verifies to a DIFFERENT record.
fn check_record_mutation(
    record: &ProviderRecord,
    key: &ContentKey,
    bytes: &[u8],
    mut_kind: u8,
    mut_idx: usize,
) -> Result<(), String> {
    let mutated = apply_mutation(bytes, mut_kind, mut_idx);
    if mutated == bytes {
        return Ok(());
    }
    match decode_provider_assertion(&mutated, key, 500) {
        Ok(ProviderAssertion::Provide(r)) => {
            if &r != record {
                return Err(
                    "decode+verify returned Ok on MUTATED bytes yielding a DIFFERENT record — signature/integrity bypass"
                        .to_string(),
                );
            }
        }
        Ok(ProviderAssertion::Withdraw(_)) => {
            return Err("a mutation turned a signed Provide into a verified Withdraw".to_string());
        }
        Err(_) => {}
    }
    Ok(())
}

/// No-forgery: arbitrary bytes must never decode+verify to Ok.
fn check_no_forge(bytes: &[u8], key: &ContentKey) -> Result<(), String> {
    match decode_provider_assertion(bytes, key, 500) {
        Ok(_) => Err(format!(
            "decode+verify returned Ok on {} arbitrary bytes — apparent ed25519 forgery",
            bytes.len()
        )),
        Err(_) => Ok(()),
    }
}

#[test]
#[ignore = "BROAD fuzz tier (TASK-282 AC#4) — run via `just fuzz-smoke`, never the fast loop"]
fn fuzz_decode_provider_assertion() {
    // Build the signed base record ONCE (ed25519 signing is the expensive step;
    // keeping it out of the per-case loop lets the target run tens of thousands of
    // bounded cases inside the fuzz-smoke wall-clock cap).
    let (record, key) = good();
    let bytes = encode_provider_record(&record).expect("encode base record");

    // Positive control (once): a correctly-signed record decodes+verifies to itself.
    match decode_provider_assertion(&bytes, &key, 500) {
        Ok(ProviderAssertion::Provide(ref r)) if *r == record => {}
        other => panic!("positive control did not round-trip: {other:?}"),
    }

    // Corpus replay: curated adversarial byte blobs must not panic and must not
    // forge a verified record.
    for file in corpus("provider_record_decode") {
        check_no_forge(&file, &key).unwrap_or_else(|msg| panic!("corpus blob: {msg}"));
    }

    // Mutation integrity over the correctly-signed record.
    fuzz_runner()
        .run(&(any::<u8>(), any::<usize>()), |(kind, idx)| {
            check_record_mutation(&record, &key, &bytes, kind, idx).map_err(TestCaseError::fail)?;
            Ok(())
        })
        .unwrap();

    // No-forgery over arbitrary bytes (bounded length so decode work stays cheap).
    fuzz_runner()
        .run(&prop::collection::vec(any::<u8>(), 0..256), |bytes| {
            check_no_forge(&bytes, &key).map_err(TestCaseError::fail)?;
            Ok(())
        })
        .unwrap();
}
