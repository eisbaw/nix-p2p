//! TASK-272 AC#1 bite: the shared `daemon_libp2p::init_tracing` — the ONE wiring both the thin
//! `daemon-libp2p` binary and the composite `/bin/daemon` call — surfaces `fabric-libp2p`
//! `tracing::info!` diagnostics on stderr IFF `RUST_LOG` is set, and installs nothing (stays
//! quiet) when `RUST_LOG` is unset.
//!
//! Why a self-forking SUBPROCESS test and not an in-process one: `tracing_subscriber`'s global
//! default subscriber is process-global and set once (`try_init`). Two in-process cases would
//! contaminate each other (whichever runs first wins the global slot), so the oracle could not
//! bite. Each case therefore runs in a fresh child process (re-exec of this test binary, gated on
//! `INIT_TRACING_BITE_CHILD`), giving a clean global for each. The child writes through the SAME
//! `init_tracing` the shipped binaries use, so the test observes the production wiring, not a
//! reimplementation.
//!
//! Mutation proof this oracle is load-bearing (run by hand, not in CI): delete the
//! `daemon_libp2p::init_tracing()` body's subscriber install (or the RUST_LOG guard) and the
//! `set` case goes RED — the marker never reaches the parent's captured stderr.

use std::process::Command;

/// A distinctive token emitted by the child at INFO, shaped like a real `fabric-libp2p`
/// diagnostic (autonat reachability is one of the NAT verdicts TASK-272 exists to surface). The
/// parent greps for exactly this so an unrelated log line cannot spoof a pass.
const MARKER: &str = "fabric-libp2p: BITE autonat reachability changed";

/// Env var that flips this test binary into its CHILD role. Present -> the child emits one
/// diagnostic through `init_tracing` and exits; absent -> the parent that forks the two children.
const CHILD_FLAG: &str = "INIT_TRACING_BITE_CHILD";

/// Run this test binary as a child, filtered to this one test so no other test runs, with
/// `--nocapture` so libtest does not swallow the child's stderr before it reaches our pipe. The
/// child's `tracing_subscriber` writes to the raw stderr fd, which is the piped fd we read here.
fn run_child(rust_log: Option<&str>) -> String {
    let exe = std::env::current_exe().expect("locate this test binary");
    let mut cmd = Command::new(exe);
    cmd.args([
        "init_tracing_surfaces_only_with_rust_log",
        "--exact",
        "--nocapture",
    ])
    .env(CHILD_FLAG, "1")
    .env_remove("RUST_LOG");
    if let Some(v) = rust_log {
        cmd.env("RUST_LOG", v);
    }
    let out = cmd.output().expect("spawn child test process");
    assert!(
        out.status.success(),
        "child exited non-zero: {:?}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn init_tracing_surfaces_only_with_rust_log() {
    // CHILD role: install the shared subscriber, emit ONE fabric-libp2p-shaped INFO diagnostic,
    // exit before libtest can run anything else. This is the exact call the shipped composite
    // /bin/daemon makes (TASK-272); if the subscriber is absent this event is swallowed.
    if std::env::var_os(CHILD_FLAG).is_some() {
        daemon_libp2p::init_tracing();
        tracing::info!("{MARKER}");
        // Bypass any residual buffering and terminate promptly in the child role.
        use std::io::Write;
        let _ = std::io::stderr().flush();
        std::process::exit(0);
    }

    // PARENT role: fork both cases in fresh processes and diff the observable.
    let with_log = run_child(Some("info"));
    assert!(
        with_log.contains(MARKER),
        "RUST_LOG=info: expected fabric-libp2p diagnostic on stderr, got:\n{with_log}"
    );

    let no_log = run_child(None);
    assert!(
        !no_log.contains(MARKER),
        "RUST_LOG unset: expected NO diagnostic (quiet default), but stderr had it:\n{no_log}"
    );
}
