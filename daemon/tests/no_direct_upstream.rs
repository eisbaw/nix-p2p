//! AC#5 (the compile-time seam): all upstream HTTP-client access goes through
//! the traits, so every HTTP-client call is confined to `upstream.rs`. This test
//! greps the daemon's own source to keep it that way - a new direct hyper-client
//! call in the serving layer (or anywhere but `upstream.rs`) fails here.
//!
//! It reads `src/` under `CARGO_MANIFEST_DIR` (present in every build, including
//! the Nix sandbox where `src` is the cleaned cargo source) and references no
//! fixture tree or dev-shell env, so the source guard is satisfied.

use std::fs;
use std::path::{Path, PathBuf};

/// Markers that only an HTTP *client* uses. If any appears outside `upstream.rs`
/// the seam has leaked.
const CLIENT_MARKERS: &[&str] = &[
    "client::conn",
    "TcpStream::connect",
    "handshake(",
    "send_request",
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

#[test]
fn http_client_calls_are_confined_to_upstream_rs() {
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
        if name == "upstream.rs" {
            upstream_had_markers = !hits.is_empty();
        } else {
            assert!(
                hits.is_empty(),
                "{name} contains HTTP-client marker(s) {hits:?} - upstream access \
                 must go through the traits, not a direct client call"
            );
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
