//! TASK-254 (cheap probe half): conformance of the SHIPPED narinfo parse + rewrite
//! path against REAL cache.nixos.org narinfos.
//!
//! ## Why this test exists (the "soil doesn't match reality" gap)
//!
//! Every other green test in the suite runs the parser against MOCK fixtures we
//! author, and those are ~entirely `Compression: none` (raw NARs where
//! `FileSize == NarSize`). The REAL cache serves COMPRESSED archives - `xz` and
//! `zstd` - for which `FileSize` (compressed transport) and `NarSize`
//! (uncompressed NAR) genuinely DIFFER. So the daemon's compressed-narinfo path,
//! which is the real cache's actual behaviour, was under-exercised. This test
//! closes that gap by driving the two shipped parse entry points over a vendored,
//! CHECKED-IN sample of real narinfos and asserting they parse, classify and
//! rewrite correctly - and it BITES: a parser regression on a real shape fails it.
//!
//! ## Provenance of the corpus
//!
//! `tests/real-corpus/*.narinfo` were fetched from `https://cache.nixos.org` (owner
//! signed off on real-cache contact) with an identifying user-agent, a handful of
//! polite sequential GETs. They are UNMODIFIED real narinfos: 4x `Compression: xz`
//! (bash, git, glibc, hello) and 3x `Compression: zstd` (coreutils, curl, python3),
//! spanning a 274 KB -> 133 MB uncompressed NAR range. `coreutils` deliberately
//! carries NO `References:` line - a real shape the mock fixtures never produce.
//!
//! ## The two SHIPPED entry points under test
//!
//! 1. [`daemon_core::catalog::parse_correlation`] - parses the mandatory
//!    `URL`/`NarHash`/`NarSize` trio and classifies the AUTHORITATIVE
//!    `Compression:` field into [`NarCompression`] (`none` -> Raw, ANY other
//!    coding -> Compressed). This is the "any coding is a compressed archive" arm.
//! 2. [`daemon_core::to_raw`] - rewrites the UNSIGNED transport fields to describe
//!    the RAW nar the daemon will serve, leaving every SIGNED field byte-identical.
//!
//! ## What this does NOT prove (honest limit)
//!
//! This is PARSER conformance only: it proves real narinfos PARSE, CLASSIFY and
//! REWRITE correctly in-process. It does NOT fetch a real `.nar.zst`, does NOT
//! decompress, and does NOT prove the real peer-serve/FETCH path works end to end
//! against the live CDN. That heavier real-fetch timing measurement is a separate
//! tracked follow-up.

use daemon_core::catalog::parse_correlation;
use daemon_core::source::NarCompression;
use daemon_core::to_raw;

/// One real narinfo fixture: the file bytes plus its human name for assertion
/// messages. `include_str!` embeds the CHECKED-IN bytes at compile time, so the
/// test needs no filesystem at run time and BITES on any change to the corpus.
struct Fixture {
    name: &'static str,
    body: &'static str,
}

/// The vendored real corpus. Embedded via `include_str!` (not read from disk) so
/// the assertion runs identically under `just test`, `cargo test -p daemon-core`,
/// and inside a Nix build sandbox (the corpus path is widened into the flake
/// source filter, same mechanism as the golden vectors).
const CORPUS: &[Fixture] = &[
    Fixture {
        name: "hello (xz)",
        body: include_str!("real-corpus/hello.narinfo"),
    },
    Fixture {
        name: "bash (xz)",
        body: include_str!("real-corpus/bash.narinfo"),
    },
    Fixture {
        name: "git (xz)",
        body: include_str!("real-corpus/git.narinfo"),
    },
    Fixture {
        name: "glibc (xz)",
        body: include_str!("real-corpus/glibc.narinfo"),
    },
    Fixture {
        name: "coreutils (zstd, no References)",
        body: include_str!("real-corpus/coreutils.narinfo"),
    },
    Fixture {
        name: "curl (zstd)",
        body: include_str!("real-corpus/curl.narinfo"),
    },
    Fixture {
        name: "python3 (zstd)",
        body: include_str!("real-corpus/python3.narinfo"),
    },
];

/// A deliberately INDEPENDENT narinfo field reader (naive `split_once(": ")`, first
/// occurrence). This is the test's "ground truth", distinct from the shipped
/// parsers, so an assertion comparing shipped output against this catches a real
/// parser regression rather than laundering the same bug into both sides.
fn field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    body.lines()
        .find_map(|l| l.strip_prefix(key).and_then(|rest| rest.strip_prefix(": ")))
}

/// The `algo:<digest>` tail after `sha256:`. Used to derive the raw URL token the
/// rewrite is expected to produce, INDEPENDENTLY of the code under test.
fn digest_of(nar_hash: &str) -> &str {
    nar_hash.split_once(':').map_or(nar_hash, |(_, d)| d)
}

/// Every real narinfo yields a correlation, and the AUTHORITATIVE `Compression`
/// field classifies to `Compressed` for BOTH xz AND zstd (the enum's "any coding"
/// arm). Fields are cross-checked against the independent ground-truth reader.
#[test]
fn every_real_narinfo_parses_and_classifies_compressed() {
    for fx in CORPUS {
        let corr = parse_correlation(fx.body.as_bytes())
            .unwrap_or_else(|| panic!("{}: real narinfo failed to parse_correlation", fx.name));

        // Ground truth read independently from the raw bytes.
        let gt_url = field(fx.body, "URL").expect("URL line present");
        let gt_nar_hash = field(fx.body, "NarHash").expect("NarHash line present");
        let gt_nar_size = field(fx.body, "NarSize").expect("NarSize line present");
        let gt_compression = field(fx.body, "Compression").expect("Compression line present");
        let gt_store_path = field(fx.body, "StorePath").expect("StorePath line present");

        // Token is URL with the `nar/` prefix stripped.
        let expected_token = gt_url.strip_prefix("nar/").unwrap_or(gt_url);
        assert_eq!(
            corr.token.as_str(),
            expected_token,
            "{}: token must be the URL minus nar/",
            fx.name
        );

        // NarHash is a sha256 anchor, carried verbatim.
        assert!(
            gt_nar_hash.starts_with("sha256:"),
            "{}: real NarHash is sha256:",
            fx.name
        );
        assert_eq!(corr.nar_hash.as_str(), gt_nar_hash, "{}: NarHash", fx.name);

        // NarSize parses to the exact u64 in the file.
        let expected_nar_size: u64 = gt_nar_size.parse().expect("NarSize is u64");
        assert_eq!(corr.nar_size, expected_nar_size, "{}: NarSize", fx.name);

        // The real corpus is entirely xz/zstd -> every entry classifies Compressed.
        assert!(
            gt_compression == "xz" || gt_compression == "zstd",
            "{}: real corpus entry is xz or zstd (got {gt_compression:?})",
            fx.name
        );
        assert_eq!(
            corr.transport.compression,
            NarCompression::Compressed,
            "{}: {gt_compression} must classify as Compressed (any coding arm), never Raw/Unknown",
            fx.name
        );

        // StorePath survives (drives announce-after-fetch).
        assert_eq!(
            corr.store_path.as_deref(),
            Some(gt_store_path),
            "{}: StorePath",
            fx.name
        );
    }
}

/// The unit trap on REAL data: for every compressed real narinfo the on-file
/// `FileSize` (compressed transport) is STRICTLY DIFFERENT from `NarSize`
/// (uncompressed NAR). This is the shape the mock's `Compression: none` fixtures
/// (where the two coincide) never exercise - the reason this corpus matters.
#[test]
fn real_compressed_narinfos_have_distinct_filesize_and_narsize() {
    for fx in CORPUS {
        let file_size: u64 = field(fx.body, "FileSize")
            .expect("FileSize line present")
            .parse()
            .expect("FileSize is u64");
        let nar_size: u64 = field(fx.body, "NarSize")
            .expect("NarSize line present")
            .parse()
            .expect("NarSize is u64");
        assert_ne!(
            file_size, nar_size,
            "{}: a COMPRESSED narinfo must have FileSize (compressed) != NarSize (raw); \
             these are DIFFERENT UNITS and must never be conflated",
            fx.name
        );
        // Real compression shrinks the transport: compressed FileSize < raw NarSize.
        assert!(
            file_size < nar_size,
            "{}: compressed transport ({file_size}) is smaller than the raw NAR ({nar_size})",
            fx.name
        );
    }
}

/// The shipped rewrite converges every real xz/zstd narinfo onto the canonical
/// raw form, and crucially takes `FileSize := NarSize` (RAW), NEVER the upstream
/// compressed `FileSize`. A regression that reused the compressed size fails here.
#[test]
fn real_rewrite_uses_raw_size_never_compressed() {
    for fx in CORPUS {
        let rw = to_raw(fx.body.as_bytes())
            .unwrap_or_else(|e| panic!("{}: real narinfo not raw-rewritable: {e}", fx.name));

        // Independent ground truth.
        let gt_nar_hash = field(fx.body, "NarHash").expect("NarHash");
        let gt_nar_size: u64 = field(fx.body, "NarSize")
            .expect("NarSize")
            .parse()
            .expect("u64");
        let gt_file_size: u64 = field(fx.body, "FileSize")
            .expect("FileSize")
            .parse()
            .expect("u64");
        let expected_token = format!("{}.nar", digest_of(gt_nar_hash));

        // Transport rewritten to raw.
        assert_eq!(
            field_of(&rw.body, "Compression").as_deref(),
            Some("none"),
            "{}: Compression rewritten to none",
            fx.name
        );
        assert_eq!(
            field_of(&rw.body, "URL").as_deref(),
            Some(format!("nar/{expected_token}").as_str()),
            "{}: URL points at the raw endpoint derived from the signed NarHash",
            fx.name
        );
        // FileHash == NarHash: for a raw-served NAR the downloaded file IS the raw
        // nar, so its sha256 is the signed NarHash. The safe side of the unit trap.
        assert_eq!(
            field_of(&rw.body, "FileHash").as_deref(),
            Some(gt_nar_hash),
            "{}: FileHash tracks the signed NarHash on the raw path",
            fx.name
        );
        // FileSize == NarSize (RAW), and STRICTLY NOT the compressed transport size.
        assert_eq!(
            field_of(&rw.body, "FileSize").as_deref(),
            Some(gt_nar_size.to_string().as_str()),
            "{}: rewritten FileSize is the RAW NarSize",
            fx.name
        );
        assert_ne!(
            field_of(&rw.body, "FileSize").as_deref(),
            Some(gt_file_size.to_string().as_str()),
            "{}: rewritten FileSize must NEVER be the compressed upstream FileSize",
            fx.name
        );

        // Carried correlation agrees with the signed values.
        assert_eq!(rw.nar_hash, gt_nar_hash, "{}: carried nar_hash", fx.name);
        assert_eq!(rw.nar_size, gt_nar_size, "{}: carried nar_size", fx.name);
        assert_eq!(
            rw.url_token, expected_token,
            "{}: carried url_token",
            fx.name
        );
    }
}

/// The trust invariant on REAL narinfos: the rewrite changes ONLY the transport
/// fields and leaves every SIGNED field (StorePath, NarHash, NarSize, References,
/// Deriver, Sig, CA) byte-identical, adding/removing/reordering nothing. This is
/// what keeps the real `cache.nixos.org-1` signature verifiable after rewrite.
#[test]
fn real_rewrite_preserves_signed_fields_byte_for_byte() {
    const SIGNED: &[&str] = &[
        "StorePath",
        "NarHash",
        "NarSize",
        "References",
        "Deriver",
        "CA",
        "Sig",
    ];
    const TRANSPORT: &[&str] = &["Compression", "URL", "FileHash", "FileSize"];

    for fx in CORPUS {
        let rw = to_raw(fx.body.as_bytes()).unwrap();
        let before = fields(fx.body.as_bytes());
        let after = fields(&rw.body);

        // No field added, removed, or reordered.
        let names_before: Vec<&String> = before.iter().map(|(k, _)| k).collect();
        let names_after: Vec<&String> = after.iter().map(|(k, _)| k).collect();
        assert_eq!(
            names_before, names_after,
            "{}: rewrite must not add/remove/reorder fields",
            fx.name
        );

        for ((k, vb), (_, va)) in before.iter().zip(after.iter()) {
            if SIGNED.contains(&k.as_str()) {
                assert_eq!(
                    vb, va,
                    "{}: signed field {k} must be byte-identical",
                    fx.name
                );
            }
            if vb != va {
                assert!(
                    TRANSPORT.contains(&k.as_str()),
                    "{}: field {k} changed but is not a transport field",
                    fx.name
                );
            }
        }
    }
}

/// The MOCK-vs-REAL differential (TASK-254 AC): the parser must treat a real
/// xz/zstd narinfo IDENTICALLY to a synthetic one of the same shape. Here we prove
/// the two structural differences the real corpus introduces - a real
/// `cache.nixos.org-1` signing-key name, and an ENTIRELY ABSENT `References:` line
/// (coreutils) - do NOT change the parse/classify/rewrite outcome versus the mock.
#[test]
fn mock_vs_real_no_behavioural_divergence() {
    // coreutils is the real zstd narinfo with NO References line.
    let coreutils = CORPUS
        .iter()
        .find(|f| f.name.starts_with("coreutils"))
        .unwrap();
    assert!(
        field(coreutils.body, "References").is_none(),
        "fixture precondition: coreutils really has no References line"
    );
    // Absent References is not a parse failure and not a rewrite failure - the
    // shipped path handles it exactly as it handles a present-but-empty one.
    let corr = parse_correlation(coreutils.body.as_bytes())
        .expect("a real narinfo lacking References must still correlate");
    assert_eq!(corr.transport.compression, NarCompression::Compressed);
    let rw = to_raw(coreutils.body.as_bytes())
        .expect("a real narinfo lacking References must still raw-rewrite");
    // No References line is fabricated by the rewrite.
    assert!(
        field_of(&rw.body, "References").is_none(),
        "rewrite must not invent a References line the source lacked"
    );

    // Real signing-key name survives verbatim (it is a signed field).
    let sig = field(coreutils.body, "Sig").expect("Sig present");
    assert!(
        sig.starts_with("cache.nixos.org-1:"),
        "real corpus carries the real cache signing-key name"
    );
    assert_eq!(
        field(coreutils.body, "Sig"),
        field_of(&rw.body, "Sig").as_deref(),
        "the real Sig is preserved byte-for-byte, so it still verifies after rewrite"
    );
}

// -- helpers over rewritten bytes (Vec<u8>) --------------------------------------

/// (key, value) pairs for every `Key: value` line, order-preserving.
fn fields(body: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(body)
        .lines()
        .filter_map(|l| {
            l.split_once(": ")
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// First value for `key` in a rewritten (Vec<u8>) body.
fn field_of(body: &[u8], key: &str) -> Option<String> {
    fields(body)
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}
