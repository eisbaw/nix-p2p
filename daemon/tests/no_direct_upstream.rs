//! AC#5 (the compile-time seam): all Nix cache-upstream HTTP access goes through
//! the traits, so cache-client calls are confined to `upstream.rs`. The separate
//! `pinned_http.rs` client is an explicit pkarr publication exception: its only
//! recipient is a validated numeric socket and its only path is `/pkarr/<key>`.
//! This test greps the daemon's own source to keep both boundaries honest - a
//! new cache client in the serving layer (or any other module) still fails here.
//!
//! It reads `src/` under `CARGO_MANIFEST_DIR` (present in every build, including
//! the Nix sandbox where `src` is the cleaned cargo source) and references no
//! fixture tree or dev-shell env, so the source guard is satisfied.

use std::fs;
use std::path::{Path, PathBuf};

/// Markers that identify an HTTP client implementation. They are permitted in
/// the cache-upstream owner and in one separately constrained pkarr transport.
const CLIENT_MARKERS: &[&str] = &[
    "client::conn",
    "TcpStream::connect",
    "handshake(",
    "send_request",
];

const PINNED_PKARR_REQUIRED: &[&str] = &[
    "const RECORD_PATH_PREFIX: &str = \"/pkarr/\";",
    "validate_recipient_socket(recipient)?;",
    "validate_signer_path(signer_z32)?;",
    "tokio::time::timeout(total_deadline",
    "TcpStream::connect(self.recipient)",
    "redirect status {} rejected; pinned recipients are never widened",
    "Transfer-Encoding is rejected; exact bounded Content-Length is required",
];

const PINNED_PKARR_FORBIDDEN: &[&str] = &[
    "crate::source",
    "NarinfoSource",
    "NarSource",
    "RawUpstream",
    "UpstreamHttp",
    "nix-cache-info",
    ".narinfo",
    "/nar/",
    "std::env",
    "reqwest",
    "hyper",
    "Location:",
];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn production_prefix(source: &str) -> &str {
    source
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("split always yields the production source prefix")
}

fn assert_pinned_pkarr_exception_is_narrow(src: &Path, files: &[PathBuf], source: &str) {
    let production = production_prefix(source);
    let hits = CLIENT_MARKERS
        .iter()
        .copied()
        .filter(|marker| production.contains(marker))
        .collect::<Vec<_>>();
    assert_eq!(
        hits,
        ["TcpStream::connect"],
        "pinned_http.rs may own only its exact-socket TCP client; a generic HTTP client stack is not part of the exception"
    );
    for required in PINNED_PKARR_REQUIRED {
        assert!(
            production.contains(required),
            "pinned_http.rs lost required pkarr boundary {required:?}"
        );
    }
    for forbidden in PINNED_PKARR_FORBIDDEN {
        assert!(
            !production.contains(forbidden),
            "pinned_http.rs gained cache-upstream or ambient-client token {forbidden:?}"
        );
    }

    let library_root = fs::read_to_string(src.join("lib.rs")).expect("read library root");
    assert!(
        library_root.contains("mod pinned_http;"),
        "pinned pkarr transport must remain crate-private"
    );
    assert!(
        !library_root.contains("pub mod pinned_http;"),
        "pinned pkarr transport must not become a general public HTTP client"
    );

    let endpoint_consumers = files
        .iter()
        .filter(|file| {
            file.file_name()
                .is_some_and(|name| name != "pinned_http.rs")
        })
        .filter_map(|file| {
            if fs::read_to_string(file)
                .expect("read Rust source")
                .contains("PinnedHttpEndpoint")
            {
                Some(file.file_name().unwrap().to_string_lossy().to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        endpoint_consumers,
        ["iroh_publication.rs"],
        "PinnedHttpEndpoint must remain private to node publication, not become a cache HTTP escape"
    );
}

#[test]
fn cache_http_client_calls_are_confined_to_upstream_and_bounded_pkarr_transport() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rs_files(&src, &mut files);
    assert!(!files.is_empty(), "found no source files to scan");

    let mut upstream_had_markers = false;
    for file in &files {
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        let text = fs::read_to_string(file).unwrap();
        let hits: Vec<&str> = CLIENT_MARKERS
            .iter()
            .copied()
            .filter(|m| text.contains(m))
            .collect();
        match name.as_str() {
            "upstream.rs" => upstream_had_markers = !hits.is_empty(),
            "pinned_http.rs" => assert_pinned_pkarr_exception_is_narrow(&src, &files, &text),
            _ => {
                assert!(
                    hits.is_empty(),
                    "{name} contains HTTP-client marker(s) {hits:?} - Nix cache-upstream access must go through upstream.rs; only the separately bounded pinned_http.rs pkarr channel is exempt"
                );
            }
        }
    }

    // The test is only meaningful if the markers are real: upstream.rs must
    // actually contain them, or we would be asserting the absence of nothing.
    assert!(
        upstream_had_markers,
        "upstream.rs contains none of {CLIENT_MARKERS:?} - the markers are stale, \
         so the scan proves nothing"
    );
}
