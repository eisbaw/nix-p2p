//! Shared proptest runner for this crate's property tests (TASK-112).
//!
//! WHY A CUSTOM RUNNER AND NOT THE BARE `proptest!` MACRO. TASK-109 brought the
//! verification gate from a ~45% failure rate under load to 0/20 by REMOVING
//! non-determinism, and TESTING.md now forbids certifying "test 0" from a
//! non-deterministic gate. proptest's DEFAULT seeds each run from fresh entropy,
//! which would put a randomized test into the flake-gated fast suite and
//! reintroduce exactly what TASK-109 removed. So determinism is OUR concern, set
//! here explicitly, with two modes selected by environment:
//!
//!   * default (`just test`, and the sandboxed `nix flake check` where no env is
//!     set): a FIXED deterministic seed + a small, env-tunable case count. The
//!     exact cases run every time, so the OUTCOME is reproducible (a green is
//!     repeatable, a red replays the same inputs).
//!   * `PROPTEST_FREE_SEED` set (`just prop`): a FRESH random seed each run + a
//!     larger case count (`PROPTEST_CASES`). The EXPLORATION mode, run
//!     deliberately, never on every cycle.
//!
//! (The knobs use the `PROPTEST_` prefix on purpose: the dev-shell-only project
//! env vars are banned from shipped src by check-source-guard because they are
//! unset inside a Nix build, and these two must work there too.)
//!
//! On a failure proptest SHRINKS to a minimal input and PRINTS it (the reproducer,
//! AC#4). It also tries to persist the seed to a `.proptest-regressions` file next
//! to the source; that file write is best-effort and is skipped when proptest
//! cannot locate the source dir (e.g. inside the build sandbox), but the printed
//! counterexample is always emitted, and each shrunk case is additionally
//! committed as a named `example_*` test.

use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

/// The fixed-seed case count when `PROPTEST_CASES` is unset. Small so the property
/// tests stay inside the fast `just test` budget while still sampling enough of
/// the space to bite; `just prop` overrides it upward for exploration.
const DEFAULT_CASES: u32 = 64;

/// Build a [`TestRunner`] with this crate's two-mode determinism policy. Call it
/// fresh per `#[test]` so each property runs an independent, order-insensitive
/// runner.
pub(crate) fn runner() -> TestRunner {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .unwrap_or(DEFAULT_CASES);
    let config = Config {
        cases,
        ..Config::default()
    };
    if std::env::var_os("PROPTEST_FREE_SEED").is_some() {
        // Free/random seed: fresh entropy each run (exploration).
        TestRunner::new(config)
    } else {
        // Fixed seed: byte-reproducible cases (the flake-safe default). The
        // ChaCha algorithm with proptest's canonical fixed seed.
        TestRunner::new_with_rng(config, TestRng::deterministic_rng(RngAlgorithm::ChaCha))
    }
}
