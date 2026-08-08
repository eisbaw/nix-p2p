//! The seven fault-injection modes (TESTING.md), owned entirely by the fixture.
//!
//! Adversarial-upstream behaviour lives here and nowhere near the product
//! daemon (PRD: "adversarial logic never lives inside the product daemon").
//! Each mode is a field on [`FaultConfig`]; the proxy consults a cheap clone of
//! it per request. The seven modes:
//!
//!   1. added latency, per path-kind
//!   2. HTTP 500/503
//!   3. connection reset (abrupt TCP close, no valid HTTP response)
//!   4. truncated NAR at N%
//!   5. corrupted NAR bytes
//!   6. wrong/stale narinfo
//!   7. upstream unreachable (fast gateway failure, no upstream contacted)
//!
//! Design rule that makes the modes safe to run against a live cache: modes
//! 4-6 mutate only the *client-facing egress*, never the disk cache, so the
//! cache stays byte-correct even mid-fault. See `proxy.rs`.

use crate::kind::Kind;
use std::collections::BTreeMap;
use std::time::Duration;

/// Which requests a fault applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Every request kind.
    All,
    /// Only one kind (e.g. reset just the NAR requests).
    Only(Kind),
}

impl Scope {
    pub fn matches(&self, kind: Kind) -> bool {
        match self {
            Scope::All => true,
            Scope::Only(k) => *k == kind,
        }
    }
}

/// The active fault configuration. `Default` is "no faults" - the honest
/// passthrough the AC#1/#2/#3 scenarios run against.
#[derive(Debug, Clone, Default)]
pub struct FaultConfig {
    /// Mode 1: added latency per path-kind, applied before the response.
    pub latency: BTreeMap<Kind, Duration>,
    /// Mode 2: return this HTTP error status for matching requests.
    pub http_error: Option<(Scope, u16)>,
    /// Mode 3: abruptly reset the connection for matching requests.
    pub connection_reset: Option<Scope>,
    /// Mode 4: send only this percent of a NAR body, then close short.
    pub truncate_nar_pct: Option<u8>,
    /// Mode 5: corrupt NAR bytes on the way to the client (cache stays clean).
    pub corrupt_nar: bool,
    /// Mode 6: serve a mutated (wrong/stale) narinfo.
    pub wrong_narinfo: bool,
    /// Mode 7: model a fully-down upstream - fail fast for every kind.
    pub unreachable: bool,
}

impl FaultConfig {
    /// Latency to add for `kind`, if any.
    pub fn latency_for(&self, kind: Kind) -> Option<Duration> {
        self.latency.get(&kind).copied()
    }

    /// The HTTP error code to emit for `kind`, if the mode is armed and scoped
    /// to it.
    pub fn http_error_for(&self, kind: Kind) -> Option<u16> {
        self.http_error
            .as_ref()
            .filter(|(scope, _)| scope.matches(kind))
            .map(|(_, code)| *code)
    }

    /// Whether to reset the connection for `kind`.
    pub fn resets(&self, kind: Kind) -> bool {
        self.connection_reset
            .as_ref()
            .map(|scope| scope.matches(kind))
            .unwrap_or(false)
    }
}

/// Corrupt a NAR chunk deterministically for the client stream. Inverting every
/// byte keeps the length identical (so `Content-Length` still matches) while
/// guaranteeing the client's NarHash check fails - which is exactly the
/// integrity failure the corrupt-NAR e2e bite needs Nix to catch.
pub fn corrupt_chunk(chunk: &[u8]) -> Vec<u8> {
    chunk.iter().map(|b| !b).collect()
}

/// Produce a wrong/stale narinfo from a correct one by mutating its `NarHash`.
/// The signature (which covers NarHash) is left as-is, so the served narinfo is
/// self-inconsistent: a client rejects it on signature *or* content hash. If no
/// `NarHash:` line is present the whole body is nudged so the fault is still
/// observably emitted rather than silently a no-op.
pub fn wrong_narinfo(body: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let mut out = String::with_capacity(text.len());
    let mut mutated = false;
    for line in text.split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix("NarHash: ") {
            // Flip the last base32 character of the hash so the value is a
            // different, still well-formed-looking hash.
            let trimmed = rest.trim_end();
            let flipped = flip_last_base32(trimmed);
            out.push_str("NarHash: ");
            out.push_str(&flipped);
            if line.ends_with('\n') {
                out.push('\n');
            }
            mutated = true;
        } else {
            out.push_str(line);
        }
    }
    if !mutated {
        out.push_str("\nX-Testproxy-Wrong: 1\n");
    }
    out.into_bytes()
}

fn flip_last_base32(value: &str) -> String {
    // Nix base32 alphabet excludes e, o, u, t. Map any last char to a different
    // in-alphabet char so the result stays a plausible hash but a different one.
    let mut chars: Vec<char> = value.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = if *last == '0' { '1' } else { '0' };
    }
    chars.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_matching() {
        assert!(Scope::All.matches(Kind::Nar));
        assert!(Scope::Only(Kind::Nar).matches(Kind::Nar));
        assert!(!Scope::Only(Kind::Nar).matches(Kind::Narinfo));
    }

    #[test]
    fn corrupt_preserves_length_but_changes_bytes() {
        let original = b"the quick brown fox";
        let corrupted = corrupt_chunk(original);
        assert_eq!(corrupted.len(), original.len());
        assert_ne!(&corrupted[..], &original[..]);
    }

    #[test]
    fn wrong_narinfo_changes_the_hash_line() {
        let good = b"StorePath: /nix/store/x\nNarHash: sha256:0abc0\nNarSize: 10\n";
        let bad = wrong_narinfo(good);
        assert_ne!(&bad[..], &good[..]);
        assert!(bad.windows(9).any(|w| w == b"NarHash: "));
        // The store path line is untouched: only the hash was altered.
        assert!(String::from_utf8_lossy(&bad).contains("StorePath: /nix/store/x"));
    }

    #[test]
    fn wrong_narinfo_still_bites_without_a_hash_line() {
        let bland = b"nothing to mutate here\n";
        assert_ne!(wrong_narinfo(bland), bland.to_vec());
    }
}
