//! AC#5 (the compile-time seam): all Nix cache-upstream HTTP access goes through
//! the traits, so cache-client calls are confined to `upstream.rs`. This test greps
//! the daemon serving source to keep that boundary honest - a new cache client in the
//! serving layer (or any other module) still fails here.
//!
//! ## Scope after the daemon-core split (TASK-146)
//!
//! The serving core (including `upstream.rs`, the ONLY sanctioned cache-HTTP client)
//! moved to the `daemon-core` crate; this composite `daemon` crate keeps only the iroh
//! backend wiring + the libp2p construction. The scan therefore covers BOTH
//! `../daemon-core/src` (the serving core) AND this crate's own `src` (the composition
//! root + bridges), so a stray cache-HTTP client in EITHER still trips it.
//!
//! The separate `pinned_http.rs` pkarr client moved to the `fabric-iroh` backend crate
//! (TASK-144), where it is a backend-internal (re-exported) module, so its narrowness
//! invariant is out of THIS guard's scope (a follow-up re-homes it to a fabric-iroh test);
//! the `pinned_http` branch below is retained but inert (no such file is scanned here).
//!
//! It reads `src/` trees relative to `CARGO_MANIFEST_DIR` (present in every build,
//! including the Nix sandbox where the workspace source is the cleaned cargo source) and
//! references no fixture tree or dev-shell env, so the source guard is satisfied.

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
    "tokio::time::timeout_at(absolute_deadline",
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

    let mut endpoint_consumers = files
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
    endpoint_consumers.sort();
    assert_eq!(
        endpoint_consumers,
        ["iroh_node_lookup.rs", "iroh_publication.rs"],
        "PinnedHttpEndpoint must remain private to explicit node publication/lookup, not become a cache HTTP escape"
    );
}

#[test]
fn cache_http_client_calls_are_confined_to_upstream_and_bounded_pkarr_transport() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = manifest.join("src");
    // The serving core (with the sanctioned `upstream.rs` client) is in daemon-core after
    // the TASK-146 split; the composition root + bridges stay here. Scan both so the
    // cache-HTTP confinement holds across the crate boundary.
    let daemon_core_src = manifest.join("../daemon-core/src");
    let mut files = Vec::new();
    rs_files(&src, &mut files);
    rs_files(&daemon_core_src, &mut files);
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
