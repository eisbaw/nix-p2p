//! The DEFINITIVE de-weld guard (TASK-146): the `daemon-libp2p` binary's NORMAL dependency
//! closure contains NO iroh crate at all.
//!
//! Where the TASK-144 `serving_core_no_iroh_stack_guard` was a source-token content ratchet
//! ("names no concrete iroh type"), THIS is the real crate-graph guarantee the seam design
//! promised: `daemon-libp2p = daemon-core + fabric-libp2p`, and neither depends on iroh, so
//! the pure single-stack binary's closure is disjoint from the iroh stack. If a future edit
//! reintroduced an iroh dependency (directly, or by making `daemon-core` link a backend), it
//! would appear in `cargo tree` and this test bites.
//!
//! It walks the NORMAL-edge dependency tree via `cargo tree` (built into cargo; present in
//! the dev shell) and asserts no iroh crate appears. Dev-dependencies are excluded on
//! purpose (a test may legitimately reach for iroh to build a hostile peer); the SHIPPED
//! binary's closure is what must be iroh-free.

use std::process::Command;

/// Crate-name substrings that mean "the iroh stack is linked". `iroh` covers `iroh`,
/// `iroh-blobs`, `iroh-dns`, `iroh-relay`, `iroh-base`, etc. `fabric-iroh` is the daemon's
/// iroh backend crate - it must never enter this closure either.
const IROH_MARKERS: &[&str] = &[
    "iroh",
    "fabric-iroh",
    "iroh-blobs",
    "iroh-dns",
    "iroh-relay",
];

#[test]
fn daemon_libp2p_normal_closure_has_no_iroh() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .args([
            "tree",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            "--package",
            "daemon-libp2p",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .output()
        .expect("`cargo tree` runs (it is built into cargo)");

    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8(output.stdout).expect("cargo tree output is utf-8");

    // A guard that scanned NOTHING would prove nothing: the closure MUST be non-trivial and
    // MUST actually contain the libp2p backend (else we are asserting the absence of iroh in
    // an empty or wrong graph).
    assert!(
        tree.lines().count() > 5,
        "cargo tree returned a suspiciously small closure ({} lines) - the scan is not \
         exercising the real dependency graph:\n{tree}",
        tree.lines().count()
    );
    assert!(
        tree.contains("fabric-libp2p") && tree.contains("libp2p"),
        "the daemon-libp2p closure must contain the libp2p backend - otherwise this guard is \
         not scanning the binary's real deps:\n{tree}"
    );

    let offenders: Vec<&str> = tree
        .lines()
        .filter(|line| {
            let name = line.split_whitespace().next().unwrap_or("");
            IROH_MARKERS.iter().any(|marker| {
                name == *marker || name.starts_with(&format!("{marker} ")) || name.contains(marker)
            })
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "daemon-libp2p is the PURE single-stack libp2p binary: its NORMAL dependency closure \
         must contain NO iroh crate (docs/peer-fabric-seam.md 'one backend linked, ever'). \
         Found:\n  {}",
        offenders.join("\n  ")
    );
}
