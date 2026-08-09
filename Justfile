# Canonical gates for nix-p2p (TESTING.md "Negative feedback").
# Run these inside `nix develop`; `_toolchain` below enforces it.
# `nix flake check` runs build/lint/fmt/test/independence again inside the
# sandbox - use it for CI and to catch anything that only passes against a
# warm ./target.

# Show the available gates.
default:
    @just --list

# Refuse to run gates against anything but the pinned toolchain derivation.
_toolchain:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${NIX_P2P_TOOLCHAIN:?not set - run gates inside: nix develop -c just ...}"
    # Checking every tool, not just cargo: a stray rustfmt or clippy from
    # another derivation is exactly the phantom-failure source the pinning
    # exists to prevent.
    for tool in cargo rustc cargo-clippy rustfmt; do
        resolved=$(command -v "${tool}" || true)
        case "${resolved}" in
            "${NIX_P2P_TOOLCHAIN}"/*) ;;
            *)
                echo "${tool} resolves to '${resolved:-<not found>}', not the pinned toolchain ${NIX_P2P_TOOLCHAIN}" >&2
                exit 1
                ;;
        esac
    done
    # The env var above says where the toolchain is; rust-toolchain.toml says
    # which one it must be. Checking against the file keeps the single source
    # of truth authoritative - otherwise exporting NIX_P2P_TOOLCHAIN=/nix/store
    # reinstates the weak "any cargo in the store" check this replaced.
    channel=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' rust-toolchain.toml)
    case "${channel}" in
        [0-9]*)
            reported=$(rustc --version)
            case "${reported}" in
                "rustc ${channel} "*) ;;
                *)
                    echo "rustc reports '${reported}' but rust-toolchain.toml pins ${channel}" >&2
                    exit 1
                    ;;
            esac
            ;;
    esac

# Refuse to run the fixture gates against anything but the pinned Python.
# Without this, `${NIX_P2P_PYTHON}/bin/python3` expands to `/bin/python3`
# outside `nix develop` - which EXISTS on Debian and Ubuntu, so the run would
# reach a system Python and die with an opaque missing-cryptography traceback
# instead of saying what is actually wrong.
_python:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${NIX_P2P_PYTHON:?not set - run gates inside: nix develop -c just ...}"
    : "${NIX_P2P_NIX:?not set - run gates inside: nix develop -c just ...}"
    for tool in "${NIX_P2P_PYTHON}/bin/python3" "${NIX_P2P_NIX}/bin/nix"; do
        test -x "${tool}" || { echo "${tool} is not executable" >&2; exit 1; }
    done

# Compile the whole workspace, tests and benches included.
build: _toolchain
    cargo build --locked --workspace --all-targets

# scripts/ is linted too: the gate scripts are safety-critical and would
# otherwise be the only unchecked files in a repo gated at -D warnings. The
# fixture source guard runs here rather than only in `test` because it is a
# source-policy check like `independence`, and it needs no generated fixture.
# Clippy (warnings are errors), rustfmt drift, and the source-policy guards.
lint: _toolchain _python independence
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo fmt --all --check
    ruff check scripts
    ruff format --check scripts
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-source-guard.py
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-lock-sources.py

# Assert daemon and testproxy stay strictly separated (PRD round 5/6).
independence: _toolchain
    python3 scripts/check-independence.py

# Depends on the fast fixture tier because the signing and tamper assertions
# live in scripts/, not in cargo (rationale: scripts/check-fixtures.py).
# Unit and integration tests plus the fixture gate (in-process, no containers).
# measure.py --self-test unit-tests the egress validator (classify_run) and the
# provenance fail-closed path with synthetic inputs - no containers, so it runs in
# the fast tier alongside the fixture gate.
test: build _python fixtures
    cargo test --locked --workspace
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-fixtures.py
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-golden-vectors.py
    "${NIX_P2P_PYTHON}/bin/python3" scripts/measure.py --self-test
    # task-18: the S5 fitter and the sweep's honesty logic are container-free by
    # design, so the machinery that decides "is this growth superlinear" and
    # "is this number labelled as a model output" is covered on EVERY cycle -
    # not only when someone runs the slow sweep. Both prove their oracles by
    # mutation (a report stripped of its labels must be REJECTED).
    "${NIX_P2P_PYTHON}/bin/python3" scripts/scalefit.py --self-test
    "${NIX_P2P_PYTHON}/bin/python3" scripts/scale_sweep.py --self-test
    # task-42: the profiler's unit gate (NarSize vs FileSize can never share an
    # unlabelled `_bytes` key), its S9 class-recovery bite (a known-O(n^2) law is
    # NEVER fitted linear), the disk walk and the arm scoring are all
    # container-free, so the honesty machinery is covered on EVERY cycle. Every
    # rule is proven by mutation.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/profile_p2p.py --self-test
    # task-49: real nix accepts the daemon's rewritten narinfo + raw nar
    # (none/xz/zstd) and rejects a signed-field mutation. Needs the `daemon`
    # binary (hence the `build` dep) and the fast-tier fixtures.
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-rewrite-realnix.py

# Regenerate the signed fixture cache - fast tier (none/xz/zstd, <1 MiB).
fixtures: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/gen-fixtures.py

# The slow-tier counterpart of `just test`: deliberately not a `just test`
# dependency and not a flake check, because the payload must stay out of the
# fast loop and out of the devshell closure - but the 110 MiB path still has
# to be verified by something, so this recipe gates it rather than only
# building it.
# Regenerate and verify the fixture cache including the 110 MiB payload.
fixtures-large: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/gen-fixtures.py --large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-fixtures.py --require-tier full

# Rebuilds every payload derivation and compares against the realised output.
# Slow by construction, so it is not in `just test` - but it is REQUIRED before
# the J2 baseline is recorded: `just test` only proves export is repeatable,
# which a nondeterministic payload would pass forever once realised.
# Prove the fixture payloads BUILD deterministically, not just export so.
fixtures-verify-rebuild: _python
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-rebuild.py

# A Nix binary cache is static files, so any file server does; the containers
# in task-5 serve the same tree their own way. Served through `current`, the
# published-generation symlink every consumer resolves - never a generation
# directly, which would go stale the moment the fixture is regenerated.
# Serve the fixture cache as a mock upstream on 127.0.0.1.
fixtures-serve port="8080": _python
    "${NIX_P2P_PYTHON}/bin/python3" -m http.server --bind 127.0.0.1 --directory fixtures/out/current/cache {{ port }}

# Apply rustfmt in place; `just lint` is what enforces it.
fmt: _toolchain
    cargo fmt --all

# Build the flake packages that container images and the NixOS module consume.
package:
    nix build --no-link --print-out-paths .#daemon .#testproxy

# The canonical e2e gate (task-5): rootless-podman-pod scenario runner driving
# client(real nix) -> daemon -> testproxy -> mock-origin, asserting the
# TESTING.md oracles. Depends on the full-tier fixtures (the 110 MiB payload is
# part of S1's byte/egress oracles) and on the fail-closed check-fixtures gate,
# which the harness itself invokes before serving anything. SLOW tier: container
# runs are minutes, deliberately out of the fast `build lint test` loop.
# Run the containerized e2e scenario suite (rootless podman pods).
e2e: _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/e2e_harness.py

# Tear down every pod/container the e2e harness created (its label only - never
# the fixture tree). Also the Ctrl-C leak trap's manual counterpart.
e2e-clean:
    "${NIX_P2P_PYTHON}/bin/python3" scripts/e2e_harness.py --clean

# The NixOS VM truth layer (task-10): real nix-daemon + systemd + the NixOS
# module. Builds ONE dedicated flake package (packages.x86_64-linux.vm-test),
# NOT a flake check - a VM test under `checks` would make `nix flake check` and
# the devshell boot QEMU (task-1 codex finding 4), so it is invoked directly
# here and only here. Proves S1 byte-identity through the daemon, S2 fallback
# with the daemon stopped, and the module's daemon-off additive invariant.
# SLOW tier: boots three QEMU VMs, needs /dev/kvm; minutes, not seconds.
# Run the NixOS VM test (real nix-daemon + systemd).
e2e-vm:
    nix build -L --no-link .#vm-test

# The S3/S4 measurement instrument (task-9): runs an identical scripted workload
# with-daemon vs without-daemon over the task-5 Pod seam and emits a
# machine-readable egress + p95 + gap-histogram report, with each oracle proven
# to bite by mutation. The counting rule it freezes lives next to the code in
# scripts/MEASUREMENT_COUNTING_RULE.md. Full-tier fixtures + the fail-closed
# check-fixtures gate (via the harness). SLOW tier: container runs are minutes.
# WAVE-1 SCOPE: this measures the INSTRUMENT (offload is ~0 with no p2p yet).
# Run the egress/latency/gap measurement and emit the report (S3/S4).
measure *ARGS: _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/measure.py {{ ARGS }}

# The S5 scale-sweep instrument (task-18): runs the real system at N over the
# axes that exist - concurrent clients, proxy-chain depth, and the client
# concurrency knobs {1,16,128} - samples per-node peak RSS (VmHWM), fds and
# latency, fits O(1)/O(log n)/O(n)/O(n log n)/O(n^2) via scripts/scalefit.py and
# extrapolates to 10/100/1000 with confidence intervals. Every extrapolated
# number is structurally labelled a model output and a superlinear fit is a RED
# FLAG printed first; the honesty rules are asserted, and a violating report
# fails the run. Each point is run 3x (--repeats) and the replicates are fitted
# as separate observations: single-draw sweeps picked a DIFFERENT growth class
# for the same metric on consecutive runs. SLOW tier: ~12 minutes of container
# runs at the default grid (the fast-tier half is the --self-test wired into
# `just test`). Cleans up label-scoped, like `e2e-clean`, on exit and SIGTERM.
# Run the S5 scale sweep and emit the fitted/extrapolated report.
scale-sweep *ARGS: _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/scale_sweep.py {{ ARGS }}

# The owner-goal profiling instrument (task-42): RAM / disk / latency /
# throughput / speedup over the p2p testbed. Two arms. (1) A real SWARM of n
# holder peers (n+1 daemon processes in one pod, each an iroh provider) swept
# over 1,2,4,8,16 - the peer axis with REAL points, since two nodes cannot
# discriminate O(n) from O(n log n) - fitted by scripts/scalefit.py and
# extrapolated to 10/100/1000 as labelled MODEL OUTPUT. (2) A peers-ON vs
# peers-OFF speedup arm scored by the FROZEN counting rule (net-upstream-egress-v2,
# via measure.classify_run), over the 110 MiB payload so throughput is a real
# number. Every `*_bytes` key carries its unit - NarSize and FileSize are
# different units and the report refuses to name either one plain `_bytes`.
# Full-tier fixtures + the fail-closed check-fixtures gate. SLOW tier: ~20
# minutes of container runs at the default grid (the fast-tier half is the
# --self-test wired into `just test`). Label-scoped cleanup on exit and SIGTERM.
# Do NOT run this concurrently with `e2e`/`measure`/`scale-sweep`: they share one
# podman label and would tear down each other's pods mid-run (TASK-58).
# Run the p2p profile (RAM/disk/latency/throughput/speedup) and emit the report.
profile *ARGS: _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/profile_p2p.py {{ ARGS }}

# The task-64 transport decomposition: a layered loopback throughput bench
# (memcpy / TCP / raw UDP / raw QUIC / iroh-blobs / the product's own fetch)
# that attributes the peer-path per-byte cost to a LAYER, so "iroh is slow" is
# replaced by a number per layer. RELEASE on purpose: a debug build measures
# rustc, not iroh. No containers and no fixtures - it synthesises its payload -
# so it runs in ~3 minutes anywhere. NOT a gate: it prints numbers and asserts
# only that each arm really moved the bytes. A throughput THRESHOLD on a shared
# host would be a flake, not an oracle.
# Decompose the iroh peer-path throughput by layer (task-64).
iroh-bench: _toolchain
    cargo run --locked --release --example iroh_throughput

# Reuses the e2e Pod seam (scripts/e2e_harness.py) as its driver and asserts the
# two operator oracles - the daemon's per-substitution log story (AC#1) and the
# fallback-served-by-request-counts proof (AC#2) - then emits its FRICTION
# manifest. Full-tier fixtures + the e2e image, so it shares e2e's SLOW tier and
# fail-closed preflight gate.
# J1 operator journey (task-6): substitute through the daemon, then lose it.
journey: _python fixtures-large
    "${NIX_P2P_PYTHON}/bin/python3" scripts/journey.py
