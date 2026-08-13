//! TASK-144 AC#6 (the de-weld guard): the daemon's stack-neutral SERVING CORE names no
//! concrete iroh-STACK type. This is the source-level proof that the iroh weld is isolated
//! behind the `peer_fabric` seam - the serving core reaches iroh only through seam traits
//! (`NarTransfer`/`NarServer`/`NodeLocator`), never through `iroh::`, `iroh_blobs`,
//! `IrohTransport`/`IrohProvider`/`IrohNode`, an `EndpointAddr`, or the ALPN.
//!
//! ## Scope, and the honest limit (why this is a RATCHET, not the final proof)
//!
//! The daemon is still ONE crate (the `daemon-core` split that would make this a compile
//! boundary is TASK-145). So "serving core" here is a CURATED set of the stack-neutral
//! frontend modules - it deliberately EXCLUDES:
//!   * the composition root (`main.rs`, `bin/`) - the ONE place concrete backends are named
//!     and wired, by design;
//!   * `transport_iroh_bridge.rs` - the deliberate, documented daemon-side `Transport`
//!     bridge onto the seam-native iroh transfer (retired by the TASK-144 follow-up);
//!   * `transport.rs` / `transport_fetch.rs` - the daemon's own `Transport`-trait fetch
//!     registry (the seam boundary that names the frozen `TransportTag::Iroh` wire tag and
//!     registers the bridge), not stack-neutral core;
//!   * `lib.rs` - the re-export hub that `pub use fabric_iroh::{...}`.
//!
//! The DEFINITIVE guard is the `daemon-core` crate's Cargo dependency graph (no iroh dep at
//! all): once the frontend is a separate crate, naming an iroh type there cannot compile.
//! Until then this scan is the regression ratchet: it bites the instant a concrete
//! iroh-stack type is introduced into a stack-neutral serving-core module.
//!
//! ## Two KNOWN stack-neutral residues (NOT concrete iroh types)
//!
//! The scan intentionally does NOT forbid two seam-neutral types that currently LIVE in
//! `fabric-iroh` only because they have not been relocated to a shared util yet:
//!   * `server.rs` uses `crate::iroh_runtime::TaskSupervisorHandle` - a GENERIC process
//!     supervisor handle (not iroh), housed in fabric-iroh to keep the crate cut acyclic;
//!   * `supply_catalog.rs` implements `crate::transport_iroh::CatalogProbe` (returning
//!     `ProbedSupply`) - the STACK-NEUTRAL catalog-probe seam (TASK-150).
//!
//! Neither pulls the iroh STACK into the serving core's type surface. Relocating them to
//! `daemon-core`/a shared util is part of the TASK-145 frontend split.

use std::path::PathBuf;

/// The stack-neutral serving-core modules the de-weld isolates from the iroh stack.
const SERVING_CORE: &[&str] = &[
    "source.rs",
    "source_libp2p.rs",
    "server.rs",
    "rewrite.rs",
    "narinfo_cache.rs",
    "cacheinfo.rs",
    "body.rs",
    "upstream.rs",
    "catalog.rs",
    "supply_catalog.rs",
    "discovery.rs",
    "availability.rs",
    "claim.rs",
    "content_id.rs",
    "nixbase32.rs",
];

/// Concrete iroh-STACK surface tokens. A hit on any (in non-comment source) means a
/// serving-core module reaches the iroh stack directly rather than through a seam trait.
/// Deliberately NOT here: `TaskSupervisorHandle`, `CatalogProbe`, `ProbedSupply` - the
/// stack-neutral residues documented in the module header; and `TransportTag::Iroh` /
/// `TransportOffer::Iroh` - frozen wire ENUM variants, not iroh-stack types.
const FORBIDDEN_STACK_TOKENS: &[&str] = &[
    "iroh::",
    "iroh_blobs",
    "bao_tree",
    "IrohTransport",
    "IrohProvider",
    "IrohNode",
    "IrohPeerAddr",
    "EndpointAddr",
    "IrohError",
    "IrohNodeBuilder",
    "IROH_BLOBS_ALPN",
    "use iroh",
];

/// Drop full-line comments (`//`, `///`, `//!`) so doc-links like
/// `[`crate::transport_iroh::IrohProvider`]` in a doc comment are not read as code. A
/// trailing-comment reference to an iroh type in these files is intentionally out of scope
/// (avoid it, or extend this guard) - the value is catching real CODE coupling.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
}

/// Whether `line` names `token` at a LEFT word boundary - so the crate token `iroh::` is
/// NOT matched inside the stack-neutral path `transport_iroh::` (which ends in `_iroh::`)
/// or `iroh_runtime::`. A match counts only when the character before it is not an
/// identifier character (`[A-Za-z0-9_]`), i.e. `token` starts a fresh path/identifier.
fn names_token(line: &str, token: &str) -> bool {
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(rel) = line[from..].find(token) {
        let start = from + rel;
        let left_ok = start == 0
            || !matches!(bytes[start - 1], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_');
        if left_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

#[test]
fn serving_core_names_no_concrete_iroh_stack_type() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut scanned = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for file in SERVING_CORE {
        let path = src.join(file);
        // A curated file that vanished (renamed/moved) must FAIL, not silently pass - a
        // guard that scans nothing proves nothing.
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "serving-core guard: cannot read curated file {}: {e}. If a module was \
                 renamed/moved, update SERVING_CORE.",
                path.display()
            )
        });
        scanned += 1;

        for (line_no, line) in code_lines(&text) {
            for token in FORBIDDEN_STACK_TOKENS {
                if names_token(line, token) {
                    violations.push(format!(
                        "{}:{}: names concrete iroh-stack token {:?} - the serving core must \
                         reach iroh only through the peer_fabric seam:\n    {}",
                        file,
                        line_no + 1,
                        token,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        scanned == SERVING_CORE.len(),
        "serving-core guard scanned {scanned} of {} curated files",
        SERVING_CORE.len()
    );
    assert!(
        violations.is_empty(),
        "the daemon serving core must hold NO concrete iroh-stack type (the de-weld \
         invariant); found:\n{}",
        violations.join("\n")
    );
}
