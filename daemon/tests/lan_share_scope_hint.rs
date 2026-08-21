//! TASK-282 (e) — the composite `daemon` binary's lan-share scope hint fires from the REAL startup
//! CALLSITE (codex re-gate: test the callsite, not just the `libp2p_leg_consume_capable` helper). The
//! callsite was moved above the `--preflight` early-return (matching daemon-libp2p), so
//! `daemon --preflight` emits the advisory to stderr and this subprocess test can observe it.
//!
//! THE MIXED-MODE CALLSITE BITE: the composite derives ONE aggregate `contract.profile` from BOTH
//! transports. An iroh give-side inflates the aggregate to a PROVIDER mode, but the libp2p leg is a
//! CONSUMER. The startup callsite computes `consume_capable` via `libp2p_leg_consume_capable` (keying
//! on the libp2p leg), so the hint fires. Reverting the callsite to
//! `matches!(contract.profile, SharingProfile::ConsumeOnly)` -> the aggregate is not ConsumeOnly ->
//! no warning -> RED.

use std::process::Command;

/// A substring of the hint (no em-dash, so byte-matching is robust).
const HINT: &str = "consume-only node is on the public";

fn preflight(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_daemon"))
        .arg("--preflight")
        .args(args)
        .output()
        .expect("run daemon --preflight");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// A minimal offline-test iroh give-side that parses under --preflight (a provider needs an endpoint
// scope, a port, and a seed; the seed path is never stat'd under --preflight).
const IROH_GIVE_SIDE: &[&str] = &[
    "--iroh-provider",
    "--iroh-endpoint-scope",
    "offline-test",
    "--iroh-port",
    "45999",
    "--iroh-seed-nar",
    "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm=/tmp/nonexistent.nar",
];

#[test]
fn mixed_iroh_provider_libp2p_consumer_gets_the_scope_hint() {
    // iroh give-side (aggregate profile = a PROVIDER mode) + a libp2p CONSUMER leg (--libp2p-mdns) on
    // public v1: the libp2p leg silently misses a lan-share.v1 pool, so it MUST warn. MUTATION
    // (callsite bite): revert the callsite to `matches!(contract.profile, ConsumeOnly)` -> the
    // aggregate is a provider mode -> no warning -> RED.
    let mut args = IROH_GIVE_SIDE.to_vec();
    args.push("--libp2p-mdns");
    let (ok, stderr) = preflight(&args);
    assert!(ok, "mixed-mode preflight should exit 0; stderr={stderr}");
    assert!(
        stderr.contains(HINT),
        "a composite node whose libp2p leg is a consumer must get the lan-share scope hint even when \
         an iroh give-side inflates the aggregate profile; stderr={stderr}"
    );
}

#[test]
fn pure_iroh_provider_without_a_libp2p_leg_does_not_warn() {
    // Control: no libp2p consumer leg -> no libp2p scope hint (a pure iroh provider). Confirms the
    // hint is attributable to the libp2p leg, not merely to "aggregate is not ConsumeOnly".
    let (ok, stderr) = preflight(IROH_GIVE_SIDE);
    assert!(ok, "iroh-provider preflight should exit 0; stderr={stderr}");
    assert!(
        !stderr.contains(HINT),
        "a pure iroh provider has no libp2p leg to warn about; stderr={stderr}"
    );
}
