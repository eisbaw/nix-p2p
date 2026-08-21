//! BROAD-cadence structured fuzz target for the narinfo parse surface (TASK-282
//! AC#4; folds/supersedes TASK-113). `rewrite::to_raw` is a hand-rolled line
//! scanner over untrusted upstream/peer narinfo bytes — the exact shape of parser
//! that overflows or panics on adversarial input. See `fuzz/README.md` for the
//! engine decision and crash-triage runbook.
//!
//! # Invariants (beyond "doesn't panic")
//!
//! * `to_raw`, `apply`, and `is_well_formed_narinfo` never panic on arbitrary bytes
//!   (no overflow on a giant/degenerate `NarSize`, no OOM on a pathological line).
//! * `to_raw` is DETERMINISTIC — the same bytes yield the same parse (single source
//!   of truth; a nondeterministic parser would break the narinfo cache key).
//! * On `Ok`, `NarSize` is a `u64` INTEGER (the owner no-floats rule, enforced
//!   structurally: a float `NarSize` would not compile past the `let _: u64`), the
//!   `NarHash`/`url_token` are non-empty, and the signed `NarHash` token survives
//!   verbatim in the rewritten body (the rewrite touches only transport lines).

#![cfg(test)]

use std::path::PathBuf;

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

use crate::narinfo_cache::is_well_formed_narinfo;
use crate::rewrite::{apply, to_raw};

/// See daemon-core `prop_support` for the two-mode determinism rationale. Kept
/// local to the fuzz module (rather than reusing `prop_support::runner`) only so
/// the BROAD fuzz cadence and the fast-loop property cadence stay independently
/// tunable; the policy is identical.
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

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn check_narinfo(body: &[u8]) -> Result<(), String> {
    // None of the three untrusted-byte entrypoints may panic.
    let raw1 = to_raw(body);
    let raw2 = to_raw(body);
    let _ = apply(body);
    let _ = is_well_formed_narinfo(body);

    // Determinism: the parse is a pure function of the bytes.
    if raw1 != raw2 {
        return Err("to_raw is non-deterministic on identical bytes".to_string());
    }

    if let Ok(r) = raw1 {
        // No-floats rule, compile-enforced: NarSize is an integer.
        let _nar_size: u64 = r.nar_size;
        if r.nar_hash.is_empty() {
            return Err("to_raw returned Ok with an empty NarHash".to_string());
        }
        if r.url_token.is_empty() {
            return Err("to_raw returned Ok with an empty url_token".to_string());
        }
        // The signed NarHash must survive the rewrite verbatim (only transport lines
        // are rewritten). If it can vanish, S1 byte-identity is at risk.
        if !find_subsequence(&r.body, r.nar_hash.as_bytes()) {
            return Err("rewritten body dropped the signed NarHash token".to_string());
        }
    }
    Ok(())
}

/// One narinfo line: a key from the real vocabulary (plus a bogus key) paired with
/// an adversarial value (huge/overflowing NarSize, empty digest, non-numeric, ...).
fn narinfo_line() -> impl Strategy<Value = String> {
    let keys = prop::sample::select(vec![
        "StorePath",
        "URL",
        "Compression",
        "FileHash",
        "FileSize",
        "NarHash",
        "NarSize",
        "References",
        "Deriver",
        "Sig",
        "System",
        "CA",
        "Bogus",
    ]);
    let vals = prop::sample::select(vec![
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x",
        "nar/1bc.nar.xz",
        "xz",
        "zstd",
        "none",
        "sha256:1bcs0jd7xj5z4c4v5b2a3q9x8w7e6r5t4y3u2i1o0p9a8s7d6f5g4h3",
        "sha256:",
        "123",
        "0",
        "18446744073709551615",
        "18446744073709551616",
        "999999999999999999999999999999",
        "-1",
        "not a number",
        "",
        "\u{00e9}\u{00e9}\u{00e9}",
    ]);
    (keys, vals).prop_map(|(k, v)| format!("{k}: {v}"))
}

#[test]
#[ignore = "BROAD fuzz tier (TASK-282 AC#4) — run via `just fuzz-smoke`, never the fast loop"]
fn fuzz_narinfo_to_raw() {
    // Corpus replay: valid + adversarial narinfo bodies.
    for file in corpus("narinfo") {
        check_narinfo(&file).unwrap_or_else(|msg| panic!("corpus narinfo: {msg}"));
    }

    let raw_bytes = prop::collection::vec(any::<u8>(), 0..2048);
    let structured = prop::collection::vec(narinfo_line(), 0..12).prop_map(|lines| {
        // Random line endings exercise the CRLF/LF split.
        lines.join("\n").into_bytes()
    });
    let structured_crlf = prop::collection::vec(narinfo_line(), 0..12)
        .prop_map(|lines| lines.join("\r\n").into_bytes());
    let strategy = prop_oneof![raw_bytes, structured, structured_crlf];

    fuzz_runner()
        .run(&strategy, |bytes| {
            check_narinfo(&bytes).map_err(TestCaseError::fail)?;
            Ok(())
        })
        .unwrap();
}
