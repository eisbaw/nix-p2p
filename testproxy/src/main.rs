//! nix-p2p test cache-proxy - scaffold only.
//!
//! Permanent test fixture (PRD round 4): a simple caching proxy fronting
//! cache.nixos.org that shields the real cache from test load and owns ALL
//! fault injection (TESTING.md "Fault-injection modes"). Nothing here may ever
//! be depended on by the daemon - the fixture is an independent witness of
//! wire behaviour, and `just independence` enforces that mechanically.
//!
//! At this point it proxies nothing. Task-2 grows the real fixture from here,
//! task-3 adds the mock-upstream mode and the signed fixture store.
//!
//! The near-identical `banner()` in `daemon` is deliberate duplication, not an
//! oversight: factoring it into a shared crate is exactly the coupling the PRD
//! forbids until a second consumer genuinely earns it.

/// Human- and machine-readable identity of this build.
///
/// A pure function of compile-time constants, so harnesses have one place to
/// read the identity from and it is testable without running the binary.
fn banner() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

fn main() {
    println!("{}", banner());
    println!("scaffold: no proxy endpoint yet (task-2)");
}

#[cfg(test)]
mod tests {
    use super::banner;

    #[test]
    fn banner_names_this_crate_and_a_version() {
        let text = banner();
        assert!(
            text.starts_with("testproxy "),
            "banner must lead with the crate name, got {text:?}"
        );
        // A version with no dots would mean the workspace version stopped
        // propagating - cheap guard against a silently empty CARGO_PKG_VERSION.
        let version = text
            .strip_prefix("testproxy ")
            .expect("prefix checked above");
        assert!(
            version.split('.').count() >= 3,
            "expected a semver-ish version, got {version:?}"
        );
    }
}
