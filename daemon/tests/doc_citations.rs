//! Every test this codebase CITES in a comment must exist.
//!
//! WHY THIS IS A GATE AND NOT A HABIT. A safety comment that says "proven by
//! `foo`" is offering evidence, and a reader who goes looking for `foo` and finds
//! nothing has been given a false citation in the one place the code is trying
//! hardest to be trusted. Two such citations shipped in `claim.rs` in a single
//! round - `slot_and_drop_decoders_agree` (really
//! `the_slot_and_drop_transport_decoders_agree`) and
//! `an_absent_answer_rejects_any_field` (really
//! `an_absent_batch_answer_rejects_any_field_attached_to_it`) - both load-bearing,
//! both introduced while FIXING a review finding. Renaming a test is exactly when
//! this breaks, and nothing noticed.
//!
//! HOW IT DECIDES WHAT IS A CITATION. Any backtick-quoted `snake_case` identifier
//! with at least [`MIN_UNDERSCORES`] underscores. That threshold is the whole
//! heuristic: it is high enough that ordinary field and variable names
//! (`offer_indices`, `keys_asked`, `schema_version`) are not citations, and low
//! enough that test names - which in this repo are sentences - always are. Both
//! historical dangling citations clear it comfortably.
//!
//! STATED LIMIT: a citation to something that is neither a `fn` nor a `const` nor
//! a type - a module path, say - would be reported as missing. The fix is to add
//! it to [`NOT_ITEMS`] with the reason, which keeps the exception visible.

use std::collections::BTreeSet;

/// Sources whose comments are checked, and which also supply the definitions a
/// citation may resolve to. EVERY module, not a chosen few: a citation gate that
/// scans a subset would itself be a false assurance.
const SOURCES: &[(&str, &str)] = &[
    ("availability.rs", include_str!("../src/availability.rs")),
    ("body.rs", include_str!("../src/body.rs")),
    ("cacheinfo.rs", include_str!("../src/cacheinfo.rs")),
    ("catalog.rs", include_str!("../src/catalog.rs")),
    ("claim.rs", include_str!("../src/claim.rs")),
    ("content_id.rs", include_str!("../src/content_id.rs")),
    ("discovery.rs", include_str!("../src/discovery.rs")),
    ("hexfmt.rs", include_str!("../src/hexfmt.rs")),
    ("lib.rs", include_str!("../src/lib.rs")),
    ("main.rs", include_str!("../src/main.rs")),
    ("narinfo_cache.rs", include_str!("../src/narinfo_cache.rs")),
    ("nixbase32.rs", include_str!("../src/nixbase32.rs")),
    ("rewrite.rs", include_str!("../src/rewrite.rs")),
    ("server.rs", include_str!("../src/server.rs")),
    ("source.rs", include_str!("../src/source.rs")),
    (
        "supply_catalog.rs",
        include_str!("../src/supply_catalog.rs"),
    ),
    ("transport.rs", include_str!("../src/transport.rs")),
    (
        "transport_fetch.rs",
        include_str!("../src/transport_fetch.rs"),
    ),
    (
        "transport_iroh.rs",
        include_str!("../src/transport_iroh.rs"),
    ),
    ("upstream.rs", include_str!("../src/upstream.rs")),
];

/// Test files, which are where most cited names are actually DEFINED. The first
/// version of this gate listed two of them and immediately reported a real test
/// in a third as dangling - the same class of mistake it exists to catch.
const TEST_SOURCES: &[(&str, &str)] = &[
    (
        "availability_index.rs",
        include_str!("availability_index.rs"),
    ),
    ("claim_wire_golden.rs", include_str!("claim_wire_golden.rs")),
    (
        "discovery_resolve_fetch.rs",
        include_str!("discovery_resolve_fetch.rs"),
    ),
    ("fault_loop.rs", include_str!("fault_loop.rs")),
    ("golden_vectors.rs", include_str!("golden_vectors.rs")),
    ("header_hygiene.rs", include_str!("header_hygiene.rs")),
    (
        "iroh_safety_envelope.rs",
        include_str!("iroh_safety_envelope.rs"),
    ),
    ("iroh_transport.rs", include_str!("iroh_transport.rs")),
    (
        "nar_hash_collision.rs",
        include_str!("nar_hash_collision.rs"),
    ),
    ("nar_source_seam.rs", include_str!("nar_source_seam.rs")),
    (
        "narinfo_disk_cache.rs",
        include_str!("narinfo_disk_cache.rs"),
    ),
    ("narinfo_rewrite.rs", include_str!("narinfo_rewrite.rs")),
    (
        "no_direct_upstream.rs",
        include_str!("no_direct_upstream.rs"),
    ),
    ("no_enumeration.rs", include_str!("no_enumeration.rs")),
    ("ordering_flip.rs", include_str!("ordering_flip.rs")),
    ("passthrough.rs", include_str!("passthrough.rs")),
    (
        "serve_budget_and_supply.rs",
        include_str!("serve_budget_and_supply.rs"),
    ),
    (
        "store_residency_oracle.rs",
        include_str!("store_residency_oracle.rs"),
    ),
];

/// A backticked snake_case word needs at least this many underscores before it is
/// treated as a citation rather than as an ordinary identifier.
const MIN_UNDERSCORES: usize = 3;

/// Backticked snake_case words that are deliberately not item names.
const NOT_ITEMS: &[(&str, &str)] = &[(
    "nix_store_dump",
    "Prose for the `nix-store --dump` command, not an item in this crate.",
)];

/// Every `fn`, `const`, `static` and `type` name defined anywhere we look.
fn defined_items() -> BTreeSet<String> {
    let mut items = BTreeSet::new();
    for (_, src) in SOURCES.iter().chain(TEST_SOURCES.iter()) {
        for line in src.lines() {
            let line = line.trim();
            for keyword in ["fn ", "const ", "static ", "type ", "macro_rules! "] {
                let Some(at) = line.find(keyword) else {
                    continue;
                };
                // Only a DECLARATION: everything before the keyword must be
                // modifiers, not an expression calling something.
                let before = &line[..at];
                if !before
                    .split_whitespace()
                    .all(|token| is_modifier(token) || token.is_empty())
                {
                    continue;
                }
                let rest = &line[at + keyword.len()..];
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    items.insert(name);
                }
            }
        }
    }
    items
}

fn is_modifier(token: &str) -> bool {
    matches!(
        token,
        "pub" | "async" | "const" | "unsafe" | "default" | "extern" | "#[allow(dead_code)]"
    ) || token.starts_with("pub(")
}

/// Every backticked snake_case citation in `src`, with the line it sits on.
fn citations(src: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (number, line) in src.lines().enumerate() {
        let trimmed = line.trim();
        // Comments only: a backticked word in a string literal is data.
        if !trimmed.starts_with("//") {
            continue;
        }
        let mut rest = trimmed;
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('`') else { break };
            let word = &after[..close];
            rest = &after[close + 1..];
            if word.len() < 8 || word.matches('_').count() < MIN_UNDERSCORES {
                continue;
            }
            if !word
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                continue;
            }
            found.push((number + 1, word.to_string()));
        }
    }
    found
}

#[test]
fn every_cited_test_name_exists() {
    let items = defined_items();
    let mut dangling = Vec::new();
    let mut checked = 0usize;

    // Test files are scanned for CITATIONS as well as for definitions: tests cite
    // each other constantly ("the bite for this is `foo`"), and a citation is no
    // more reliable for sitting in a test file.
    for (file, src) in SOURCES.iter().chain(TEST_SOURCES.iter()) {
        for (line, word) in citations(src) {
            checked += 1;
            if items.contains(&word) {
                continue;
            }
            if NOT_ITEMS.iter().any(|(name, _)| *name == word) {
                continue;
            }
            dangling.push(format!(
                "{file}:{line} cites `{word}`, which is not defined anywhere - a \
                 comment offering evidence must point at evidence that exists"
            ));
        }
    }

    assert!(
        dangling.is_empty(),
        "dangling citations:\n  {}",
        dangling.join("\n  ")
    );
    // The scanner must be finding citations at all; a regex that matched nothing
    // would report a clean bill of health forever.
    assert!(
        checked >= 20,
        "only {checked} citations found across {} sources; the scanner is not \
         matching - which is a SILENT pass",
        SOURCES.len() + TEST_SOURCES.len()
    );
}

#[test]
fn the_scanner_catches_a_citation_that_does_not_resolve() {
    // Proves the check is not vacuous, using the two names that really shipped.
    let hostile = "/// proven by `slot_and_drop_decoders_agree` and by\n\
                   /// `an_absent_answer_rejects_any_field`.";
    let found = citations(hostile);
    assert_eq!(found.len(), 2, "both citations must be seen: {found:?}");
    let items = defined_items();
    for (_, word) in &found {
        assert!(
            !items.contains(word),
            "`{word}` was the WRONG name that shipped; if it now exists this test \
             is no longer testing anything"
        );
    }
    // ...and the real names DO resolve, so the check is not simply rejecting all.
    for real in [
        "the_slot_and_drop_transport_decoders_agree",
        "an_absent_batch_answer_rejects_any_field_attached_to_it",
    ] {
        assert!(
            items.contains(real),
            "`{real}` should be a defined test; the item scanner is not reading \
             the test sources"
        );
    }
}

#[test]
fn ordinary_identifiers_are_not_mistaken_for_citations() {
    // The threshold has to leave normal field names alone or the gate becomes
    // noise and gets deleted.
    let benign = "// the `offer_indices` field and `keys_asked` argument, plus\n\
                  // `schema_version` and `wall_clock_ms`.";
    assert!(
        citations(benign).is_empty(),
        "ordinary identifiers must not be treated as citations: {:?}",
        citations(benign)
    );
}
