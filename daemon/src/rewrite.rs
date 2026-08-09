//! Narinfo transport-field rewrite (task-49: populate the wave-1 empty allowlist).
//!
//! ## Why this module exists
//!
//! A Nix client handed a narinfo follows its `URL`, `Compression`, `FileHash`
//! and `FileSize` to download a file, then verifies:
//!   1. `sha256(downloaded bytes) == FileHash` and `len == FileSize` (transport);
//!   2. after decompressing per `Compression`, `sha256(nar) == NarHash` and
//!      `len == NarSize`, and `Sig` verifies over the fingerprint
//!      `1;StorePath;NarHash;NarSize;References` (the TRUST anchor).
//!
//! cache.nixos.org narinfos describe a COMPRESSED file (`Compression: xz`,
//! `URL: nar/<h>.nar.xz`, `FileHash`/`FileSize` = the compressed transfer). But a
//! peer serves the RAW (uncompressed) NAR - the addressed unit
//! `BLAKE3(RawNarV1)` (see [`crate::content_id`]). If the daemon hands the client
//! the upstream narinfo but serves raw bytes, gate 1 fails before gate 2 is even
//! reached: `sha256(raw) != FileHash(compressed)`. So for a peer-served path the
//! daemon MUST rewrite the narinfo's UNSIGNED transport fields to describe the RAW
//! nar it will actually serve, while leaving the SIGNED fields byte-identical.
//!
//! ## Signed vs unsigned (the trust invariant)
//!
//! The ed25519 `Sig` covers ONLY `1;StorePath;NarHash;NarSize;References`. Those,
//! plus `Sig`/`Deriver`/`CA`, are [`SIGNED_FIELDS`] and MUST pass through
//! byte-identical or the client rejects the path. `Compression`, `URL`,
//! `FileHash` and `FileSize` are UNSIGNED - they describe the transport, not the
//! content - and are the [`REWRITE_ALLOWLIST`]: the only fields [`to_raw`] may
//! change. Rewriting anything outside this allowlist is a security event (PRD
//! "Trust invariant"), which is why the allowlist and the signed-field set are
//! separate named constants, cross-checked by a test.
//!
//! ## The rewrite (and why it needs no sha256)
//!
//! For a raw nar served with `Compression: none`, the downloaded file IS the raw
//! nar, so gate-1's `FileHash = sha256(file) = sha256(raw nar) = NarHash` - the
//! SIGNED value already in the narinfo. Likewise `FileSize = NarSize`. So the
//! rewrite is a pure copy, no hashing:
//!   * `Compression: none`
//!   * `URL: nar/<narhash-digest>.nar` - a raw endpoint whose token is derived
//!     from the SIGNED NarHash, so the follow-up `GET /nar/<token>` correlates
//!     back to the NarHash and dispatches by it (see [`RawRewrite::url_token`]).
//!   * `FileHash: <NarHash value>`   (byte-equal to the signed NarHash)
//!   * `FileSize: <NarSize value>`   (the signed raw size)
//!
//! CARRIED LESSON (the NarSize-vs-FileSize unit trap, recurred 3x): the rewritten
//! `FileSize` is `NarSize` (the RAW size), NOT the upstream `FileSize` (the
//! COMPRESSED transfer). For `Compression: none` they coincide; for xz/zstd the
//! upstream `FileSize` is the compressed size and using it here would make the
//! client's gate-1 length check fail against the raw bytes we serve.
//!
//! ## The `none` fixture is already the canonical raw form
//!
//! An upstream narinfo that is already `Compression: none` has
//! `URL: nar/<narhash>.nar`, `FileHash == NarHash`, `FileSize == NarSize`. Running
//! [`to_raw`] on it therefore reproduces it BYTE-FOR-BYTE (a test pins this): the
//! rewrite converges xz/zstd narinfos onto exactly the representation Nix already
//! accepts for an uncompressed path.
//!
//! ## Fail-fast, never half-rewritten
//!
//! [`to_raw`] rewrites only a WELL-FORMED cache narinfo: it requires `NarHash`,
//! `NarSize`, `URL`, `Compression`, `FileHash` and `FileSize` all present and a
//! parseable `NarSize`/`NarHash`, returning a [`RewriteError`] otherwise. A caller
//! that gets an error serves the upstream narinfo VERBATIM (via [`apply`]) - the
//! safe wave-1 path - rather than emit an inconsistent narinfo. It never fabricates
//! a signature-valid narinfo from a malformed one.
//!
//! ## Where the rewrite is triggered (and the peer-miss fallback)
//!
//! [`to_raw`] is a pure function; the SERVING layer decides WHEN to apply it via
//! [`RawServeDecision`]. The rule is: rewrite to raw IFF the daemon will actually
//! serve this NarHash's raw nar (a raw-capable [`crate::source::NarSource`] backs
//! it). Coupling the two is load-bearing - rewriting the URL to a raw endpoint
//! while the NAR path can only fetch the COMPRESSED upstream would hand the client
//! a narinfo the daemon cannot back. So:
//!   * decision = NO (the wave-1 default [`NoRawServe`], and whenever local/p2p
//!     availability is unknown): serve the upstream narinfo verbatim + the
//!     compressed nar from upstream. Pure S2 path, no regression.
//!   * decision = YES: rewrite to raw + serve the raw nar. If the raw source then
//!     FAILS MID-TRANSFER, the [`crate::source::NarSource`] returns a `SourceError`
//!     which the serving layer turns into a fast clean 502, so Nix marks this
//!     substituter's download failed and falls back to the next substituter /
//!     upstream (S2) - the daemon never masks a short or corrupt transfer.
//!
//! The wave-1 daemon binary wires [`NoRawServe`]; task-41 wires the
//! availability-backed decision + the raw NAR source that makes a running node
//! serve node B's raw nar to node A's real nix.

use std::borrow::Cow;
use std::fmt;

/// The UNSIGNED transport fields [`to_raw`] may rewrite. This is the single
/// source of truth for "what may change"; everything else is byte-verbatim.
///
/// Populating this (task-49) is the reviewable diff that flips wave-1's
/// byte-verbatim passthrough into transport rewriting for the peer-served path.
pub const REWRITE_ALLOWLIST: &[&str] = &["Compression", "URL", "FileHash", "FileSize"];

/// Fields that must NEVER be rewritten because they are covered by `Sig` (or are
/// themselves the signature / content-address). [`to_raw`] GATES its pass-2
/// rewrite on [`REWRITE_ALLOWLIST`], and `allowlist_never_touches_signed_fields`
/// proves the two sets are disjoint - so a signed field cannot be rewritten
/// structurally, not merely by test convention. Adding any of these to the
/// allowlist would fail that test before it could ever run against a client.
pub const SIGNED_FIELDS: &[&str] = &[
    "StorePath",
    "NarHash",
    "NarSize",
    "References",
    "Deriver",
    "CA",
    "Sig",
];

/// Serve the narinfo on the NORMAL (non-peer) path: byte-verbatim. Nothing is
/// parsed, so unknown fields, odd ordering and multiple `Sig:` lines survive
/// untouched. Returns `Cow::Borrowed` (the original bytes, unchanged).
///
/// This is the transport-field allowlist applied as the empty set: on the normal
/// path the daemon relays the upstream narinfo exactly, and the client fetches the
/// COMPRESSED nar. The peer-served rewrite is [`to_raw`], gated by
/// [`RawServeDecision`].
///
/// `apply` itself borrows and does not copy; the serving layer currently
/// `.into_owned()`s the result to build the response body, so the passthrough does
/// allocate once at that call site (not here). The `Cow` return keeps the door
/// open for a future zero-copy body path.
pub fn apply(body: &[u8]) -> Cow<'_, [u8]> {
    Cow::Borrowed(body)
}

/// The result of rewriting a narinfo to describe the RAW nar the daemon will
/// serve. Carries both the new bytes and the correlation the serving layer must
/// record so the follow-up `GET /nar/<url_token>` dispatches by the SIGNED
/// NarHash (a [`crate::source::NarKey::SignedNarHash`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRewrite {
    /// The rewritten narinfo body. Every SIGNED line is byte-identical to the
    /// input; only the four transport lines differ.
    pub body: Vec<u8>,
    /// The `nar/`-relative URL token the rewritten narinfo now points at, i.e.
    /// what the client requests next: `<narhash-digest>.nar`. Derived from the
    /// signed NarHash so it correlates straight back to it.
    pub url_token: String,
    /// The signed NarHash value (verbatim, e.g. `sha256:0pgsb...`) - the raw
    /// nar's trust-anchored identity and the wave-2 lookup key.
    pub nar_hash: String,
    /// The signed NarSize (uncompressed raw-nar bytes) - the correlation's abort
    /// bound and the rewritten `FileSize`.
    pub nar_size: u64,
}

/// Why a narinfo could not be rewritten to raw form. On any of these the caller
/// serves the upstream narinfo VERBATIM rather than emit an inconsistent one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteError {
    /// A field required to build a consistent raw narinfo was absent.
    MissingField(&'static str),
    /// `NarSize` was present but not a base-10 `u64`.
    MalformedNarSize(String),
    /// `NarHash` was present but empty / had no usable digest for the URL token.
    MalformedNarHash(String),
}

impl fmt::Display for RewriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RewriteError::MissingField(name) => {
                write!(
                    f,
                    "narinfo lacks required field {name:?}; not rewritable to raw"
                )
            }
            RewriteError::MalformedNarSize(v) => write!(f, "malformed NarSize {v:?}"),
            RewriteError::MalformedNarHash(v) => write!(f, "malformed NarHash {v:?}"),
        }
    }
}

impl std::error::Error for RewriteError {}

/// Rewrite a narinfo's UNSIGNED transport fields to describe the RAW nar, leaving
/// every SIGNED field byte-identical. See the module docs for the full rationale.
///
/// Two passes are required because a narinfo's field ordering is not fixed
/// (cache.nixos.org emits `URL`/`FileHash`/`FileSize` BEFORE `NarHash`), so the
/// signed values that seed the rewrite must be read before any line is emitted.
pub fn to_raw(body: &[u8]) -> Result<RawRewrite, RewriteError> {
    // Pass 1: read the signed values we copy, and confirm every transport field
    // we intend to rewrite is actually present (so the output is well-formed).
    let mut nar_hash: Option<&[u8]> = None;
    let mut nar_size_raw: Option<&[u8]> = None;
    let (mut have_url, mut have_compression, mut have_filehash, mut have_filesize) =
        (false, false, false, false);
    for line in body.split(|&b| b == b'\n') {
        if let Some(v) = field_value(line, b"NarHash") {
            nar_hash = Some(v);
        } else if let Some(v) = field_value(line, b"NarSize") {
            nar_size_raw = Some(v);
        } else if is_field(line, b"URL") {
            have_url = true;
        } else if is_field(line, b"Compression") {
            have_compression = true;
        } else if is_field(line, b"FileHash") {
            have_filehash = true;
        } else if is_field(line, b"FileSize") {
            have_filesize = true;
        }
    }

    let nar_hash = nar_hash.ok_or(RewriteError::MissingField("NarHash"))?;
    let nar_size_raw = nar_size_raw.ok_or(RewriteError::MissingField("NarSize"))?;
    if !have_url {
        return Err(RewriteError::MissingField("URL"));
    }
    if !have_compression {
        return Err(RewriteError::MissingField("Compression"));
    }
    if !have_filehash {
        return Err(RewriteError::MissingField("FileHash"));
    }
    if !have_filesize {
        return Err(RewriteError::MissingField("FileSize"));
    }

    let nar_hash = ascii_trim(nar_hash);
    let nar_hash = std::str::from_utf8(nar_hash)
        .map_err(|_| RewriteError::MalformedNarHash("<non-utf8>".to_string()))?
        .to_string();
    let nar_size: u64 = std::str::from_utf8(ascii_trim(nar_size_raw))
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            RewriteError::MalformedNarSize(String::from_utf8_lossy(nar_size_raw).into_owned())
        })?;

    // The URL token is derived from the SIGNED NarHash: strip an `algo:` prefix
    // (`sha256:<base32>` -> `<base32>`) to get the digest, then `.nar`. This is
    // exactly the token an already-`none` narinfo uses, so the rewrite converges
    // onto Nix's canonical uncompressed form and the token correlates to NarHash.
    let digest = nar_hash
        .split_once(':')
        .map_or(nar_hash.as_str(), |(_, d)| d);
    if digest.is_empty() {
        return Err(RewriteError::MalformedNarHash(nar_hash.clone()));
    }
    let url_token = format!("{digest}.nar");

    // Pass 2: re-emit, substituting only the four transport lines. `split_inclusive`
    // keeps each line's terminator so a non-rewritten line is copied byte-for-byte
    // (any `\r\n`, the final missing newline, all preserved), and a rewritten line
    // reuses its own original terminator.
    let mut out = Vec::with_capacity(body.len());
    for seg in body.split_inclusive(|&b| b == b'\n') {
        let (line, term) = split_terminator(seg);
        // The allowlist GATES the rewrite: a line is replaced ONLY if its field
        // name is in REWRITE_ALLOWLIST. Combined with the test proving
        // REWRITE_ALLOWLIST is disjoint from SIGNED_FIELDS, this makes it
        // structurally impossible for `to_raw` to alter a signed field - the
        // allowlist is the single source of truth for "what may change", not a
        // decorative constant. A line whose name is not allowlisted (StorePath,
        // NarHash, References, Deriver, CA, Sig, unknown X-* fields, blanks) is
        // copied byte-for-byte.
        let replacement = field_key(line)
            .filter(|key| REWRITE_ALLOWLIST.iter().any(|f| f.as_bytes() == *key))
            .and_then(|key| match key {
                b"URL" => Some(format!("URL: nar/{url_token}")),
                b"Compression" => Some("Compression: none".to_string()),
                b"FileHash" => Some(format!("FileHash: {nar_hash}")),
                b"FileSize" => Some(format!("FileSize: {nar_size}")),
                // Allowlisted but with no raw-form rule: leave verbatim rather than
                // drop it. Unreachable while the allowlist is exactly the four above.
                _ => None,
            });
        match replacement {
            Some(new_line) => {
                out.extend_from_slice(new_line.as_bytes());
                out.extend_from_slice(term);
            }
            None => out.extend_from_slice(seg),
        }
    }

    Ok(RawRewrite {
        body: out,
        url_token,
        nar_hash,
        nar_size,
    })
}

/// True if `line` is exactly `Key:...` (the field name followed by a colon).
/// `Key` carries no colon; the colon is checked here so `URLL:` never matches
/// `URL` and `FileSize`/`FileHash` never cross-match.
fn is_field(line: &[u8], key: &[u8]) -> bool {
    line.len() > key.len() && line.starts_with(key) && line[key.len()] == b':'
}

/// The value bytes after `Key:` (still possibly leading-space-padded), or `None`
/// if `line` is not that field.
fn field_value<'a>(line: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    is_field(line, key).then(|| &line[key.len() + 1..])
}

/// The field name (bytes before the first `:`), or `None` for a line with no
/// colon (blank or malformed). Used to gate the pass-2 rewrite by the allowlist.
fn field_key(line: &[u8]) -> Option<&[u8]> {
    line.iter().position(|&b| b == b':').map(|i| &line[..i])
}

/// Split a `split_inclusive('\n')` segment into (line-without-terminator,
/// terminator). The terminator is `\r\n`, `\n`, or empty (final line with no
/// trailing newline). Reusing the exact terminator keeps byte-fidelity.
fn split_terminator(seg: &[u8]) -> (&[u8], &[u8]) {
    if let Some(rest) = seg.strip_suffix(b"\r\n") {
        (rest, &seg[rest.len()..])
    } else if let Some(rest) = seg.strip_suffix(b"\n") {
        (rest, &seg[rest.len()..])
    } else {
        (seg, &seg[seg.len()..])
    }
}

/// Trim leading/trailing ASCII whitespace (space, `\t`, `\r`) from a value slice.
fn ascii_trim(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace());
    let end = bytes.iter().rposition(|b| !b.is_ascii_whitespace());
    match (start, end) {
        (Some(s), Some(e)) => &bytes[s..=e],
        _ => &[],
    }
}

/// The serving-layer policy that decides WHEN [`to_raw`] runs: will the daemon
/// serve this NarHash's RAW nar itself (from a peer or a local dump)?
///
/// MUST be coupled with a raw-capable [`crate::source::NarSource`]: returning
/// `true` while the NAR path can only fetch the COMPRESSED upstream would hand the
/// client a raw narinfo the daemon cannot back. See the module docs' peer-miss
/// section. The wave-1 default is [`NoRawServe`].
pub trait RawServeDecision: Send + Sync {
    /// `true` iff the daemon will serve `nar_hash`'s raw nar, so its narinfo
    /// should be rewritten to raw transport fields.
    fn will_serve_raw(&self, nar_hash: &str) -> bool;
}

/// The wave-1 default: never serve raw, so every narinfo is relayed verbatim and
/// the client fetches the compressed upstream nar (the S2 path). task-41 replaces
/// it with an availability-index-backed decision once a raw NAR source is wired.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoRawServe;

impl RawServeDecision for NoRawServe {
    fn will_serve_raw(&self, _nar_hash: &str) -> bool {
        false
    }
}

/// The wave-2a decision: serve RAW exactly the NarHashes the daemon has a
/// discovery claim for. A CONFIGURED allowlist (not a DHT) - the same known-peer-set
/// discipline as [`crate::discovery::DirectDiscovery`]. The integration site
/// (`main.rs`) builds BOTH this allowlist and the p2p discovery from the ONE
/// peer/claim config, so a `true` here has a CONFIGURED raw source behind it.
///
/// HONESTY (the trait contract, [`RawServeDecision`], demands a raw-capable source):
/// the coupling is a CONFIGURED guarantee, not a runtime one. If the configured
/// holder is DEAD at request time, an ALREADY-RAW path still falls back to the raw
/// upstream NAR, but a path whose narinfo was rewritten from COMPRESSED to raw has
/// no raw NAR upstream under the rewritten token, so it fails FAIL-CLOSED (a clean
/// error, never wrong bytes) rather than failing over. Closing that (decompress-on-
/// fallback, or health-aware rewrite) is task-43/44; see `scenario_s6_fallback`.
///
/// Keyed on the FULL signed `NarHash` string (`sha256:<base32>`), exactly the form
/// [`crate::catalog::parse_correlation`] hands [`RawServeDecision::will_serve_raw`],
/// so a claim's `NarHash` and the narinfo's `NarHash` agree by construction with no
/// prefix juggling at the boundary.
#[derive(Debug, Default, Clone)]
pub struct AllowlistRawServe {
    hashes: std::collections::HashSet<String>,
}

impl AllowlistRawServe {
    /// Serve raw exactly these `sha256:<base32>` NarHashes.
    pub fn new(hashes: impl IntoIterator<Item = String>) -> Self {
        Self {
            hashes: hashes.into_iter().collect(),
        }
    }
}

impl RawServeDecision for AllowlistRawServe {
    fn will_serve_raw(&self, nar_hash: &str) -> bool {
        self.hashes.contains(nar_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real cache.nixos.org-shaped narinfos (mirrors of the signed test fixtures,
    // inline so the source guard's generated-tree ban is respected). xz/zstd carry a
    // COMPRESSED FileHash/FileSize distinct from NarHash/NarSize - what the rewrite fixes.
    const XZ: &[u8] = b"StorePath: /nix/store/l30jg5xg904s62jvw5znmr682xpr993c-nix-p2p-fixture-app\n\
URL: nar/15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7.nar.xz\n\
Compression: xz\n\
FileHash: sha256:15m2z8ar1r1jm5x7fqblq4s7438ghdmam396l5kwvc25jq8rzxb7\n\
FileSize: 260\n\
NarHash: sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm\n\
NarSize: 408\n\
References: 0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib\n\
Deriver: 3135ldqj1kl5wxkrrdnf4dfxiqakjz0z-nix-p2p-fixture-app.drv\n\
Sig: nix-p2p-test-1:Xqf1bjNJ1ReFahm86zY+hv80+7QeJer5V/HjlEAvP39yJEK8w8jHG9WH5lM7mN9WCIbdH/DDx81dmsjVObMqAQ==\n";

    const ZSTD: &[u8] = b"StorePath: /nix/store/n4gcfilnaljqkqsadj7mcwyd6p0rvv0c-nix-p2p-fixture-zstd\n\
URL: nar/1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa.nar.zst\n\
Compression: zstd\n\
FileHash: sha256:1nn8563y6j55y003xjk1bvb1854abmigsas2jgzy4shy0f4vnzpa\n\
FileSize: 524649\n\
NarHash: sha256:176pix3424bx7179g5c2b0x341lb4p5hgc03zizqnfc44fns9q8p\n\
NarSize: 524808\n\
References: \n\
Deriver: mgy4bw14lvwv27iwv74f5ghyvlmjp82j-nix-p2p-fixture-zstd.drv\n\
Sig: nix-p2p-test-1:On4YXNoll3VP1i/qoUvK1sNPKX4SMCyfzESqVh6AE0E3S72ZpGQrKT3f42qb5MSTq+AGCDFybpC4nfyYfHLKDQ==\n";

    // Already-raw: URL is nar/<narhash>.nar, FileHash==NarHash, FileSize==NarSize.
    const NONE: &[u8] = b"StorePath: /nix/store/0a0lslqb6gbqnj6xqjlaljjqg6kgb3wz-nix-p2p-fixture-lib\n\
URL: nar/06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb.nar\n\
Compression: none\n\
FileHash: sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb\n\
FileSize: 66048\n\
NarHash: sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb\n\
NarSize: 66048\n\
References: \n\
Deriver: g7hlrj8ys2w9i9d9zm6v4zxw7hpws0a7-nix-p2p-fixture-lib.drv\n\
Sig: nix-p2p-test-1:kvRtCi6KujoW6x7esqgP8QdiaaVX4OL1beI/xmfobVHzM/tSSqmy7jcnI7QDognLkmkwaSgA6vraWOYN0kiICw==\n";

    /// Collect (key, value) for every `Key: value` line, keyed on the field name.
    fn fields(body: &[u8]) -> Vec<(String, String)> {
        String::from_utf8(body.to_vec())
            .unwrap()
            .lines()
            .filter_map(|l| {
                l.split_once(": ")
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect()
    }

    fn value(body: &[u8], key: &str) -> Option<String> {
        fields(body)
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    #[test]
    fn allowlist_never_touches_signed_fields() {
        // Now BITES: the allowlist is populated. A signed field sneaking in fails.
        for field in REWRITE_ALLOWLIST {
            assert!(
                !SIGNED_FIELDS.contains(field),
                "allowlist entry {field:?} is a signed field - rewriting it breaks verification"
            );
        }
    }

    #[test]
    fn allowlist_is_exactly_the_four_transport_fields() {
        assert_eq!(
            REWRITE_ALLOWLIST,
            &["Compression", "URL", "FileHash", "FileSize"]
        );
    }

    #[test]
    fn xz_rewrite_describes_the_raw_nar() {
        let rw = to_raw(XZ).unwrap();
        // Transport fields now describe the RAW nar.
        assert_eq!(value(&rw.body, "Compression").as_deref(), Some("none"));
        assert_eq!(
            value(&rw.body, "URL").as_deref(),
            Some("nar/0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm.nar")
        );
        // FileHash == NarHash (sha256 of the raw nar) - the unit trap's safe side.
        assert_eq!(
            value(&rw.body, "FileHash"),
            value(&rw.body, "NarHash"),
            "for Compression: none the served file IS the raw nar, so FileHash == NarHash"
        );
        // FileSize == NarSize (RAW size), NOT the upstream compressed 260.
        assert_eq!(value(&rw.body, "FileSize").as_deref(), Some("408"));
        assert_eq!(value(&rw.body, "NarSize").as_deref(), Some("408"));
        assert_ne!(
            value(&rw.body, "FileSize").as_deref(),
            Some("260"),
            "FileSize must be the RAW size, never the compressed transfer size"
        );
        // The carried correlation.
        assert_eq!(rw.nar_size, 408);
        assert_eq!(
            rw.nar_hash,
            "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm"
        );
        assert_eq!(
            rw.url_token,
            "0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm.nar"
        );
    }

    #[test]
    fn zstd_rewrite_uses_raw_size_not_compressed() {
        let rw = to_raw(ZSTD).unwrap();
        assert_eq!(value(&rw.body, "Compression").as_deref(), Some("none"));
        assert_eq!(value(&rw.body, "FileSize").as_deref(), Some("524808")); // NarSize
        assert_ne!(value(&rw.body, "FileSize").as_deref(), Some("524649")); // not compressed
        assert_eq!(value(&rw.body, "FileHash"), value(&rw.body, "NarHash"));
    }

    #[test]
    fn signed_fields_are_byte_identical_and_only_transport_lines_change() {
        for input in [XZ, ZSTD, NONE] {
            let rw = to_raw(input).unwrap();
            let before = fields(input);
            let after = fields(&rw.body);
            // Same set of field names, same order, same count.
            let names_before: Vec<&String> = before.iter().map(|(k, _)| k).collect();
            let names_after: Vec<&String> = after.iter().map(|(k, _)| k).collect();
            assert_eq!(
                names_before, names_after,
                "no field added, removed or reordered"
            );
            for ((k, vb), (_, va)) in before.iter().zip(after.iter()) {
                if SIGNED_FIELDS.contains(&k.as_str()) {
                    assert_eq!(vb, va, "signed field {k} must be byte-identical");
                }
            }
            // The ONLY lines that changed are transport lines.
            for ((k, vb), (_, va)) in before.iter().zip(after.iter()) {
                if vb != va {
                    assert!(
                        REWRITE_ALLOWLIST.contains(&k.as_str()),
                        "field {k} changed but is not in the rewrite allowlist"
                    );
                }
            }
        }
    }

    #[test]
    fn none_narinfo_rewrite_is_byte_for_byte_identity() {
        // The already-raw form is a fixed point of the rewrite: nothing to change.
        let rw = to_raw(NONE).unwrap();
        assert_eq!(
            rw.body, NONE,
            "an already-Compression:none narinfo must rewrite to itself byte-for-byte"
        );
    }

    #[test]
    fn ca_survives_and_the_changed_set_is_exactly_the_allowlist() {
        // A content-addressed (CA) narinfo carries a signed `CA:` field. It must
        // pass through verbatim, and for an xz input the set of CHANGED field names
        // must equal REWRITE_ALLOWLIST exactly - not a subset that happens to spare
        // the fields these fixtures contain. This is what makes the allowlist the
        // real guard (finding: without it, a future arm rewriting CA would slip a
        // signed field past a subset-only check).
        let ca = b"StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
URL: nar/deadbeef.nar.xz\n\
Compression: xz\n\
FileHash: sha256:deadbeef\n\
FileSize: 999\n\
NarHash: sha256:cafef00d\n\
NarSize: 42\n\
References: \n\
CA: fixed:r:sha256:1abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn\n\
Sig: nix-p2p-test-1:BBBB==\n";
        let rw = to_raw(ca).unwrap();
        let before = fields(ca);
        let after = fields(&rw.body);
        // CA (a signed field) is byte-identical.
        assert_eq!(value(&rw.body, "CA"), value(ca, "CA"));
        // The changed field-name SET equals the allowlist exactly.
        let mut changed: Vec<&str> = before
            .iter()
            .zip(after.iter())
            .filter(|((_, vb), (_, va))| vb != va)
            .map(|((k, _), _)| k.as_str())
            .collect();
        changed.sort_unstable();
        let mut allow: Vec<&str> = REWRITE_ALLOWLIST.to_vec();
        allow.sort_unstable();
        assert_eq!(
            changed, allow,
            "an xz rewrite changes EXACTLY the allowlist"
        );
    }

    #[test]
    fn gnarly_narinfo_keeps_unknown_fields_and_multiple_sigs() {
        let gnarly = b"Sig: cache.nixos.org-1:AAAA==\n\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
X-Unknown-Field: whatever: with: colons\n\
URL: nar/deadbeef.nar.xz\n\
Compression: xz\n\
FileHash: sha256:deadbeef\n\
FileSize: 999\n\
NarHash: sha256:cafef00d\n\
NarSize: 42\n\
References: \n\
Sig: nix-p2p-test-1:BBBB==\n";
        let rw = to_raw(gnarly).unwrap();
        let text = String::from_utf8(rw.body.clone()).unwrap();
        // Both Sig lines and the unknown field survive verbatim.
        assert!(text.contains("Sig: cache.nixos.org-1:AAAA=="));
        assert!(text.contains("Sig: nix-p2p-test-1:BBBB=="));
        assert!(text.contains("X-Unknown-Field: whatever: with: colons"));
        // Transport fields rewritten to raw.
        assert_eq!(value(&rw.body, "Compression").as_deref(), Some("none"));
        assert_eq!(value(&rw.body, "URL").as_deref(), Some("nar/cafef00d.nar"));
        assert_eq!(
            value(&rw.body, "FileHash").as_deref(),
            Some("sha256:cafef00d")
        );
        assert_eq!(value(&rw.body, "FileSize").as_deref(), Some("42"));
    }

    #[test]
    fn crlf_line_endings_are_preserved_on_untouched_lines() {
        let crlf = b"StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\r\n\
URL: nar/x.nar.xz\r\n\
Compression: xz\r\n\
FileHash: sha256:x\r\n\
FileSize: 9\r\n\
NarHash: sha256:abc\r\n\
NarSize: 3\r\n\
References: \r\n\
Sig: k:AAAA==\r\n";
        let rw = to_raw(crlf).unwrap();
        let text = String::from_utf8(rw.body).unwrap();
        // Signed lines keep their CRLF exactly.
        assert!(text.contains("StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\r\n"));
        assert!(text.contains("Sig: k:AAAA==\r\n"));
        // Rewritten line keeps CRLF too.
        assert!(text.contains("Compression: none\r\n"));
    }

    #[test]
    fn a_tampered_narhash_flows_through_and_drags_filehash_with_it() {
        // Unit-level complement to the real-nix mutate-signed bite: the rewrite
        // never "repairs" a tampered signed field. A mutated NarHash is emitted
        // verbatim (so its Sig no longer verifies) AND the derived FileHash follows
        // it - the rewrite cannot manufacture a signature-valid narinfo from a
        // tampered one. Real nix rejection is proven in scripts/check-rewrite-realnix.py.
        let mut tampered = XZ.to_vec();
        // Flip one base32 char of the NarHash digest.
        let orig = b"NarHash: sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";
        let bad = b"NarHash: sha256:1pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm";
        let pos = tampered
            .windows(orig.len())
            .position(|w| w == orig)
            .expect("NarHash line present");
        tampered[pos..pos + orig.len()].copy_from_slice(bad);

        let rw = to_raw(&tampered).unwrap();
        assert_eq!(
            value(&rw.body, "NarHash").as_deref(),
            Some("sha256:1pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm"),
            "tampered NarHash is emitted verbatim, not silently corrected"
        );
        assert_eq!(
            value(&rw.body, "FileHash"),
            value(&rw.body, "NarHash"),
            "FileHash still tracks NarHash - no signature-valid narinfo is fabricated"
        );
    }

    #[test]
    fn missing_required_field_is_unrewritable() {
        let no_narhash = b"StorePath: /nix/store/x\nURL: nar/a.nar.xz\nCompression: xz\n\
FileHash: sha256:a\nFileSize: 1\nNarSize: 2\nReferences: \n";
        assert_eq!(
            to_raw(no_narhash),
            Err(RewriteError::MissingField("NarHash"))
        );

        let no_url = b"StorePath: /nix/store/x\nCompression: xz\nFileHash: sha256:a\n\
FileSize: 1\nNarHash: sha256:abc\nNarSize: 2\nReferences: \n";
        assert_eq!(to_raw(no_url), Err(RewriteError::MissingField("URL")));

        let no_compression = b"StorePath: /nix/store/x\nURL: nar/a.nar.xz\nFileHash: sha256:a\n\
FileSize: 1\nNarHash: sha256:abc\nNarSize: 2\nReferences: \n";
        assert_eq!(
            to_raw(no_compression),
            Err(RewriteError::MissingField("Compression"))
        );
    }

    #[test]
    fn malformed_narsize_is_rejected() {
        let bad = b"StorePath: /nix/store/x\nURL: nar/a.nar.xz\nCompression: xz\n\
FileHash: sha256:a\nFileSize: 1\nNarHash: sha256:abc\nNarSize: not-a-number\nReferences: \n";
        assert!(matches!(
            to_raw(bad),
            Err(RewriteError::MalformedNarSize(_))
        ));
    }

    #[test]
    fn no_raw_serve_never_rewrites() {
        assert!(!NoRawServe.will_serve_raw("sha256:anything"));
    }
}
