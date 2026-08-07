//! nix-p2p product daemon - scaffold only.
//!
//! At this point the daemon serves no HTTP and has no p2p behaviour. It exists
//! so the workspace, the gates and the flake packages are real and exercised
//! from commit one. Task-4 grows the transparent proxy from here.
//!
//! Assumption baked in here and nowhere else: the binary identifies itself on
//! stdout so container/VM harnesses (task-5, task-10) have something
//! deterministic to assert against before real endpoints exist.
//!
//! The near-identical `banner()` in `testproxy` is deliberate duplication, not
//! an oversight: factoring it into a shared crate is exactly the coupling the
//! PRD forbids until a second consumer genuinely earns it.

/// Human- and machine-readable identity of this build.
///
/// Kept as a pure function of compile-time constants so it can be unit tested
/// without running the binary, and so no caller has to reconstruct it.
fn banner() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

fn main() {
    println!("{}", banner());
    println!("scaffold: no substituter endpoint yet (task-4)");
}

#[cfg(test)]
mod tests {
    use super::banner;

    #[test]
    fn banner_names_this_crate_and_a_version() {
        let text = banner();
        assert!(
            text.starts_with("daemon "),
            "banner must lead with the crate name, got {text:?}"
        );
        // A version with no dots would mean the workspace version stopped
        // propagating - cheap guard against a silently empty CARGO_PKG_VERSION.
        let version = text.strip_prefix("daemon ").expect("prefix checked above");
        assert!(
            version.split('.').count() >= 3,
            "expected a semver-ish version, got {version:?}"
        );
    }
}
