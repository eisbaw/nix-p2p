//! Narinfo transport-field rewrite allowlist - EMPTY in wave 1 (AC#3).
//!
//! TESTING.md "Narinfo byte-fidelity policy": the daemon and its cache treat
//! narinfo as verbatim bytes end to end. The allowlist of transport fields the
//! daemon is permitted to rewrite EXISTS in code and is empty; wave 2 (raw-NAR
//! p2p) populates it with `URL`/`Compression`/`FileHash`/`FileSize` ONLY -
//! never the signed fields (`StorePath`, `NarHash`, `NarSize`, `References`,
//! `Deriver`, `Sig`, `CA`). Rewriting a signed field would break the client's
//! signature verification; that is a security event, not a refactor (PRD
//! irreversibility map, "Trust invariant").
//!
//! Because the allowlist is empty, [`apply`] is the identity in wave 1: every
//! narinfo passes through byte-for-byte. Keeping the function (rather than
//! skipping the call) means the seam where rewriting will live is already wired
//! and tested, and populating the allowlist in wave 2 is a localised, reviewable
//! diff.

use std::borrow::Cow;

/// Transport fields the daemon may rewrite. EMPTY in wave 1 by policy.
///
/// The list is the single source of truth for "what may change"; a wave-2
/// change here is the reviewable diff that flips byte-verbatim passthrough into
/// transport rewriting.
pub const REWRITE_ALLOWLIST: &[&str] = &[];

/// Fields that must NEVER be rewritten because they are covered by `Sig`.
/// Present as an assertion target so a future allowlist entry that collides with
/// a signed field is caught by [`allowlist_never_touches_signed_fields`].
pub const SIGNED_FIELDS: &[&str] = &[
    "StorePath",
    "NarHash",
    "NarSize",
    "References",
    "Deriver",
    "CA",
    "Sig",
];

/// Apply the (wave-1: empty) transport-rewrite allowlist to a narinfo body.
///
/// Returns `Cow::Borrowed` (the original bytes) whenever nothing is rewritten,
/// which in wave 1 is always. The signature is `&[u8] -> Cow<[u8]>` so wave 2
/// can return owned rewritten bytes without changing callers.
pub fn apply(body: &[u8]) -> Cow<'_, [u8]> {
    if REWRITE_ALLOWLIST.is_empty() {
        // Wave-1 fast path AND correctness guarantee: no field is rewritable,
        // so the body is verbatim. Nothing is parsed - odd ordering, unknown
        // fields and multiple `Sig:` lines survive untouched.
        return Cow::Borrowed(body);
    }
    // Wave 2 lands here: parse fields, rewrite only allowlisted transport ones,
    // re-emit. Unreachable in wave 1; left as an explicit marker of where the
    // logic goes rather than a silent gap.
    unreachable!("REWRITE_ALLOWLIST is non-empty but wave-2 rewriting is unimplemented");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_is_empty_in_wave_1() {
        assert!(
            REWRITE_ALLOWLIST.is_empty(),
            "wave-1 policy (TESTING.md): the narinfo rewrite allowlist is empty"
        );
    }

    #[test]
    fn allowlist_never_touches_signed_fields() {
        for field in REWRITE_ALLOWLIST {
            assert!(
                !SIGNED_FIELDS.contains(field),
                "allowlist entry {field:?} is a signed field - rewriting it breaks verification"
            );
        }
    }

    #[test]
    fn apply_is_byte_identical_on_a_gnarly_narinfo() {
        // Unknown field, unusual ordering, and TWO Sig lines: all must survive.
        let narinfo = b"Sig: cache.nixos.org-1:AAAA==\n\
             StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
             X-Unknown-Field: whatever\n\
             NarHash: sha256:1111111111111111111111111111111111111111111111111111\n\
             NarSize: 64\n\
             References: \n\
             Sig: nix-p2p-test-1:BBBB==\n";
        let out = apply(narinfo);
        assert_eq!(
            out.as_ref(),
            &narinfo[..],
            "wave-1 apply must be the identity - narinfo is verbatim"
        );
        assert!(
            matches!(out, Cow::Borrowed(_)),
            "identity passthrough should not allocate"
        );
    }
}
