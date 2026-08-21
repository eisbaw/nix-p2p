//! TASK-282 (e) — the lan-share scope hint fires from the REAL startup CALLSITE, not just the pure
//! `libp2p_leg_consume_capable` helper (codex re-gate: a helper test does not catch a callsite that
//! swaps the helper for the aggregate-profile check). This drives the shipped `daemon-libp2p` binary
//! with `--preflight`, which emits the advisory to stderr BEFORE the early return, so the assertion
//! observes the actual startup warning.
//!
//! THE CALLSITE BITE: the startup callsite computes `consume_capable` via `libp2p_leg_consume_capable`.
//! Reverting it to `matches!(cfg.profile, SharingProfile::ConsumeOnly)` makes the ROUTER case below
//! STOP warning (RED), because a router's derived profile is `Router`, not `ConsumeOnly`.

use std::process::Command;

/// A substring of the hint (no em-dash, so byte-matching is robust).
const HINT: &str = "consume-only node is on the public";

fn preflight_stderr(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_daemon-libp2p"))
        .arg("--preflight")
        .args(args)
        .output()
        .expect("run daemon-libp2p --preflight");
    assert!(
        out.status.success(),
        "--preflight should exit 0 for {args:?}; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn router_on_public_v1_gets_the_lan_share_scope_hint() {
    // A bootstrapped ROUTER retains the consume axes (it is wrapped in LeechFabric and
    // daemon_core::run builds a PeerFabricNarSource for it), so on the public v1 scope it CAN consume
    // and silently miss a lan-share.v1 pool -> it must be warned. This is the FIX vs the old
    // `matches!(cfg.profile, ConsumeOnly)`, which warned no router. MUTATION (callsite bite): revert
    // the startup callsite to the aggregate-profile check -> this router stops warning -> RED.
    let stderr = preflight_stderr(&[
        "--libp2p-router",
        "--libp2p-listen",
        "/ip4/127.0.0.1/tcp/0",
        "--libp2p-bootstrap",
        "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN@/ip4/127.0.0.1/tcp/4001",
    ]);
    assert!(
        stderr.contains(HINT),
        "a bootstrapped router on public v1 must get the lan-share scope hint; stderr={stderr}"
    );
}

#[test]
fn provider_does_not_get_the_consumer_scope_hint() {
    // Control: a libp2p give-side provider is not a leech -> excluded (`!is_libp2p_provider`), so it
    // must NOT get the consumer-specific hint (holds for both the old and new callsite logic).
    let stderr = preflight_stderr(&[
        "--libp2p-provider",
        "--libp2p-listen",
        "/ip4/192.168.1.7/tcp/4001",
        "--libp2p-seed-nar",
        "sha256:0pgsb9mjmfj57w1ddmqn9z9667nwbqbnn699j1s1s99jhy6cppsm=/tmp/nonexistent.nar",
    ]);
    assert!(
        !stderr.contains(HINT),
        "a libp2p provider must NOT get the consumer scope hint; stderr={stderr}"
    );
}
