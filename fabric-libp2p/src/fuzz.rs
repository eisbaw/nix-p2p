//! BROAD-cadence structured fuzz targets for fabric-libp2p's untrusted wire/parse
//! surfaces (TASK-282 AC#4; folds/supersedes TASK-113). See `fuzz/README.md` at the
//! repo root for the engine decision, the crash-triage runbook, and the honest
//! coverage limits.
//!
//! # Engine: proptest, not cargo-fuzz
//!
//! cargo-fuzz/libFuzzer is NOT usable here: it needs a NIGHTLY toolchain plus
//! `-Zsanitizer`, and this project's reproducibility pin (`rust-toolchain.toml`
//! channel = "1.97.1", profile = minimal) deliberately forbids nightly in the
//! devshell and the crane build (TASK-113 AC#9: "No nightly enters the default
//! devshell or crane build"). So these targets use `proptest` (already vendored,
//! dev-dep), which gives structured input generation, automatic SHRINKING (= the
//! crash-minimisation the triage path needs) and a `proptest-regressions/`
//! persistence file that becomes the committed crash corpus. This is bounded
//! RANDOM structured fuzzing, NOT coverage-guided fuzzing — an honest, real limit.
//!
//! # Cadence: BROAD only, never the fast loop
//!
//! Every target is `#[ignore]`, so `cargo test` / `just test` never runs it.
//! `just fuzz-smoke` runs them BOUNDED via
//! `PROPTEST_FREE_SEED=1 PROPTEST_CASES=<n> cargo test -- --ignored fuzz_`.
//!
//! # Invariants asserted (not merely "doesn't panic")
//!
//! * `multiaddr_lan_provenance`: an ACCEPTED multiaddr can carry NO globally-
//!   routable / CGNAT / wildcard IP anywhere, NO `/dns*`, NO `/p2p-circuit`, and
//!   EXACTLY ONE IP hop — re-derived by an INDEPENDENT oracle here (it does not
//!   call the crate's own `ip_is_lan_literal`), so a regression to first-hop-only
//!   scanning that re-admits the compound-address bypass BITES. A fuzzer that finds
//!   an accepted non-LAN address is a real security bug.
//! * `nar_v4::decode_verified`: a Bao-authenticated decode can NEVER return `Ok`
//!   with content that differs from the source — any tampered stream must error.

#![cfg(test)]

use std::io::Cursor;
use std::net::IpAddr;
use std::path::PathBuf;

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use peer_fabric::WireCodec;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

/// Two-mode determinism policy, mirroring daemon-core's `prop_support::runner`
/// (whose module doc carries the full rationale): a FIXED seed by default (so a
/// bare `cargo test -- --ignored` is still deterministic and bounded), and a FREE
/// seed + larger `PROPTEST_CASES` under `PROPTEST_FREE_SEED` for the
/// `just fuzz-smoke` exploration run. Kept crate-local (not shared) because a
/// shared test-support crate for ~15 lines across three consumers would be
/// over-engineering; the policy is identical and documented once in prop_support.
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
/// Resolved from `CARGO_MANIFEST_DIR` so it works regardless of the test CWD.
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

/// Deterministic byte mutation used by the integrity targets: flip / zero a byte,
/// truncate, or append junk. Never panics; may return the input unchanged (a no-op
/// the caller skips).
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

// ---------------------------------------------------------------------------
// Target 1: multiaddr LAN-provenance classifier
// ---------------------------------------------------------------------------

/// INDEPENDENT re-derivation of "this IP must never appear in an accepted address"
/// — deliberately NOT delegating to the crate's `ip_is_lan_literal`, so a shared
/// bug cannot mask the classifier. An IP is DANGEROUS unless it is loopback,
/// RFC1918 / RFC4193-ULA, or link-local. (CGNAT `100.64/10`, the `0.0.0.0`/`::`
/// wildcard, and every global unicast address are therefore dangerous.)
fn ip_is_dangerous(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let lan = v4.is_loopback()
                || o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254); // link-local 169.254/16
            !lan
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let lan = v6.is_loopback()
                || (s[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (s[0] & 0xffc0) == 0xfe80; // link-local fe80::/10
            !lan
        }
    }
}

/// The load-bearing security invariant over the classifier's decision.
fn check_multiaddr(addr: &Multiaddr) -> Result<(), String> {
    // Must not panic on any parseable multiaddr.
    if !fabric_libp2p_classifier(addr) {
        return Ok(());
    }
    let comps: Vec<Protocol> = addr.iter().collect();
    let mut ip_hops = 0usize;
    for comp in &comps {
        match comp {
            Protocol::Ip4(v4) => {
                ip_hops += 1;
                if ip_is_dangerous(&IpAddr::V4(*v4)) {
                    return Err(format!("ACCEPTED a routable/non-LAN IPv4 hop in {addr}"));
                }
            }
            Protocol::Ip6(v6) => {
                ip_hops += 1;
                if ip_is_dangerous(&IpAddr::V6(*v6)) {
                    return Err(format!("ACCEPTED a routable/non-LAN IPv6 hop in {addr}"));
                }
            }
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => {
                return Err(format!("ACCEPTED a DNS hop in {addr}"));
            }
            Protocol::P2pCircuit => {
                return Err(format!("ACCEPTED a /p2p-circuit relay hop in {addr}"));
            }
            _ => {}
        }
    }
    if ip_hops != 1 {
        return Err(format!(
            "ACCEPTED {addr} with {ip_hops} IP hops; the single-hop grammar admits exactly one"
        ));
    }
    Ok(())
}

/// Thin wrapper so the classifier call site is named once.
fn fabric_libp2p_classifier(addr: &Multiaddr) -> bool {
    crate::lan::multiaddr_lan_provenance(addr)
}

/// A fixed, valid libp2p peer id string for building `/p2p/<id>` tails.
fn fixed_peer_id() -> String {
    let kp = libp2p::identity::Keypair::ed25519_from_bytes([7u8; 32]).expect("ed25519 key");
    kp.public().to_peer_id().to_string()
}

#[test]
#[ignore = "BROAD fuzz tier (TASK-282 AC#4) — run via `just fuzz-smoke`, never the fast loop"]
fn fuzz_multiaddr_lan_provenance() {
    let peer = fixed_peer_id();

    // Corpus replay first: curated adversarial + valid multiaddr STRINGS.
    for file in corpus("multiaddr_lan_provenance") {
        if let Ok(text) = std::str::from_utf8(&file) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Ok(addr) = line.parse::<Multiaddr>() {
                    check_multiaddr(&addr).unwrap_or_else(|msg| panic!("corpus {line:?}: {msg}"));
                }
            }
        }
    }

    // Structured multiaddr grammar (probes the compound-address bypass, relay/DNS
    // hops, and draft-quic / udp-without-quic transports) plus raw-byte decoding of
    // the binary multiaddr parser.
    let ips = prop::sample::select(vec![
        "/ip4/10.211.34.5".to_string(),
        "/ip4/172.16.9.9".to_string(),
        "/ip4/192.168.1.9".to_string(),
        "/ip4/127.0.0.1".to_string(),
        "/ip4/169.254.3.3".to_string(),
        "/ip4/8.8.8.8".to_string(),
        "/ip4/203.0.113.7".to_string(),
        "/ip4/100.64.0.1".to_string(),
        "/ip4/0.0.0.0".to_string(),
        "/ip6/fc00::9".to_string(),
        "/ip6/fe80::1".to_string(),
        "/ip6/::1".to_string(),
        "/ip6/2606:4700::1".to_string(),
        "/ip6/::".to_string(),
    ]);
    let transports = prop::sample::select(vec![
        "/tcp/4001".to_string(),
        "/udp/4001/quic-v1".to_string(),
        "/udp/4001".to_string(),
        "/tcp/4001/ws".to_string(),
        "/quic".to_string(),
    ]);
    let seconds = prop::sample::select(vec![
        String::new(),
        "/ip4/203.0.113.9/tcp/4001".to_string(),
        "/ip4/10.9.9.9/tcp/4001".to_string(),
        "/ip6/2606:4700::2/udp/4001/quic-v1".to_string(),
    ]);
    let p2ps = prop::sample::select(vec![String::new(), format!("/p2p/{peer}")]);
    let trailings = prop::sample::select(vec![
        String::new(),
        "/p2p-circuit".to_string(),
        "/tls".to_string(),
    ]);

    let structured = (ips, transports, seconds, p2ps, trailings)
        .prop_map(|(a, b, c, d, e)| format!("{a}{b}{c}{d}{e}").parse::<Multiaddr>().ok());
    let raw_bytes =
        prop::collection::vec(any::<u8>(), 0..48).prop_map(|b| Multiaddr::try_from(b).ok());
    let strategy = prop_oneof![structured, raw_bytes];

    fuzz_runner()
        .run(&strategy, |maybe| {
            if let Some(addr) = maybe {
                check_multiaddr(&addr).map_err(TestCaseError::fail)?;
            }
            Ok(())
        })
        .unwrap();
}

// ---------------------------------------------------------------------------
// Target 2: NAR / bao leaf+proof decode (the `/nar/4` verifier path)
// ---------------------------------------------------------------------------

/// Encode `raw` into a complete `/nar/4` wire body under `codec` (valid, framed,
/// terminated with the completion marker) and return the authenticated root.
fn nar_encode(raw: &[u8], codec: WireCodec) -> (bao_tree::blake3::Hash, Vec<u8>) {
    let mut source = Cursor::new(raw);
    let outboard =
        crate::nar_v4::create_outboard(&mut source, raw.len() as u64).expect("valid outboard");
    let mut body = Vec::new();
    crate::nar_v4::encode_validated(raw, &outboard, &mut body, codec, 3).expect("valid encode");
    body.extend_from_slice(crate::nar_v4::COMPLETE_MARKER);
    (outboard.root, body)
}

/// Decode a `/nar/4` wire body against `root`/`raw_size`, collecting leaf bytes.
fn nar_decode(
    body: &[u8],
    root: bao_tree::blake3::Hash,
    raw_size: u64,
    codec: WireCodec,
) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    crate::nar_v4::decode_verified(&mut Cursor::new(body), root, raw_size, codec, |leaf| {
        out.extend_from_slice(&leaf);
        Ok(())
    })?;
    Ok(out)
}

/// The Bao integrity invariant: a valid stream round-trips, and ANY mutation of the
/// authenticated stream either errors or reproduces the EXACT source — it can never
/// return `Ok` with different content.
fn check_nar_integrity(
    raw: &[u8],
    codec: WireCodec,
    mut_kind: u8,
    mut_idx: usize,
) -> Result<(), String> {
    let (root, body) = nar_encode(raw, codec);

    // Positive control: the clean stream decodes to exactly the source.
    match nar_decode(&body, root, raw.len() as u64, codec) {
        Ok(got) if got == raw => {}
        Ok(got) => {
            return Err(format!(
                "positive control decoded {} bytes, want {}",
                got.len(),
                raw.len()
            ));
        }
        Err(e) => return Err(format!("positive control failed to decode: {e}")),
    }

    // Tamper: a mutated stream must never authenticate to different content.
    let mutated = apply_mutation(&body, mut_kind, mut_idx);
    if mutated == body {
        return Ok(());
    }
    match nar_decode(&mutated, root, raw.len() as u64, codec) {
        Ok(got) if got != raw => Err(format!(
            "decode_verified returned Ok on a TAMPERED bao stream with WRONG content ({} vs {} bytes) — integrity bypass",
            got.len(),
            raw.len()
        )),
        _ => Ok(()),
    }
}

#[test]
#[ignore = "BROAD fuzz tier (TASK-282 AC#4) — run via `just fuzz-smoke`, never the fast loop"]
fn fuzz_nar_v4_decode_verified() {
    // Corpus replay: arbitrary wire bytes against a fixed independent root must not
    // panic and (barring a ~2^-128 collision) must not decode.
    let fixed_root = bao_tree::blake3::hash(b"nix-p2p fuzz corpus root");
    for file in corpus("nar_v4_decode") {
        for codec in [WireCodec::Raw, WireCodec::Zstd] {
            // raw_size is bounded so a lying length header cannot self-inflict a huge
            // allocation on the shared box (see fuzz/README.md honest limits).
            let _ = nar_decode(&file, fixed_root, 4096, codec);
        }
    }

    // A handful of FIXED sizes that cross the 64 KiB leaf boundary, so the
    // multi-leaf proof-pair path is exercised cheaply (once), not per proptest case.
    const LEAF: usize = 64 * 1024;
    for size in [0usize, 1, LEAF - 1, LEAF, LEAF + 1, (2 * LEAF) + 7] {
        let raw: Vec<u8> = (0..size)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
            .collect();
        for codec in [WireCodec::Raw, WireCodec::Zstd] {
            check_nar_integrity(&raw, codec, 0, size / 2)
                .unwrap_or_else(|msg| panic!("multi-leaf size {size}: {msg}"));
        }
    }

    // Bounded random-content single-leaf fuzzing of the framing + integrity path.
    let strategy = (
        prop::collection::vec(any::<u8>(), 0..4096),
        any::<bool>(),
        any::<u8>(),
        any::<usize>(),
    );
    fuzz_runner()
        .run(&strategy, |(raw, zstd, kind, idx)| {
            let codec = if zstd {
                WireCodec::Zstd
            } else {
                WireCodec::Raw
            };
            check_nar_integrity(&raw, codec, kind, idx).map_err(TestCaseError::fail)?;
            Ok(())
        })
        .unwrap();
}
