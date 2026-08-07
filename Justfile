# Canonical gates for nix-p2p (TESTING.md "Negative feedback").
# Run these inside `nix develop`; `_toolchain` below enforces it.
# `nix flake check` runs build/lint/fmt/test again inside the sandbox - use it
# for CI and to catch anything that only passes against a warm ./target.

# Honesty marker for gates whose harness does not exist yet. A stub that looks
# like a pass is forbidden - tasks 5/9/10/6 replace these with real gates.
stub_marker := "0 scenarios registered - NOT a pass"

# Show the available gates.
default:
    @just --list

# Refuse to run gates against an unpinned host toolchain (house rule).
_toolchain:
    @command -v cargo | grep -q '^/nix/store/' || { echo "cargo is not the pinned toolchain - run gates inside: nix develop -c just ..." >&2; exit 1; }

# Compile the whole workspace, tests and benches included.
build: _toolchain
    cargo build --locked --workspace --all-targets

# Clippy (warnings are errors), rustfmt drift, and the crate-independence guard.
lint: _toolchain independence
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo fmt --all --check

# Assert daemon and testproxy stay strictly separated (PRD round 5/6).
independence: _toolchain
    #!/usr/bin/env bash
    set -euo pipefail
    # Sharing is limited to low-level pure-data crates, and only once a second
    # consumer actually exists. This allowlist starts EMPTY on purpose: adding
    # a shared crate must be a reviewable diff, not a silent green.
    allowlist=()
    # Workspace-local crates in $1's tree. cargo renders path crates with a
    # parenthesised path and registry crates without one, which is what the
    # awk filter keys on. The tree is materialised into a variable before any
    # grep: a `cargo tree | grep -q` pipeline SIGPIPEs cargo and, under
    # pipefail, reports a real violation as a clean exit.
    local_crates() {
        cargo tree --locked --package "$1" --prefix none --format '{p}' \
            | awk '/\(\//{print $1}' | sort -u | { grep -vxF "$1" || true; }
    }
    daemon_local=$(local_crates daemon)
    testproxy_local=$(local_crates testproxy)
    violations=0
    if grep -qxF testproxy <<<"${daemon_local}"; then
        echo "crate independence violated: daemon depends on testproxy" >&2
        violations=1
    fi
    if grep -qxF daemon <<<"${testproxy_local}"; then
        echo "crate independence violated: testproxy depends on daemon" >&2
        violations=1
    fi
    # The realistic violation is not a direct edge, it is someone factoring
    # "just the HTTP bit" into a crate both sides pull in.
    shared=$(comm -12 <(grep -v '^$' <<<"${daemon_local}" || true) \
                      <(grep -v '^$' <<<"${testproxy_local}" || true))
    for crate in ${shared}; do
        if ! printf '%s\n' "${allowlist[@]:-}" | grep -qxF "${crate}"; then
            echo "crate independence violated: daemon and testproxy share workspace crate ${crate}" >&2
            violations=1
        fi
    done
    if [ "${violations}" -eq 0 ]; then
        echo "crate independence: no daemon<->testproxy edge, no shared workspace crate outside the (empty) allowlist"
    fi
    exit "${violations}"

# Unit and integration tests (in-process, no containers).
test: _toolchain
    cargo test --locked --workspace

# Apply rustfmt in place; `just lint` is what enforces it.
fmt: _toolchain
    cargo fmt --all

# Build the flake packages that container images and the NixOS module consume.
package:
    nix build --no-link --print-out-paths .#daemon .#testproxy

# E2E container harness - stub until task-5 lands the podman scenario runner.
e2e:
    @echo "{{ stub_marker }}"

# NixOS VM tests (real nix-daemon + systemd) - stub until task-10.
e2e-vm:
    @echo "{{ stub_marker }}"

# Egress/latency measurement runs (S3/S4) - stub until task-9.
measure:
    @echo "{{ stub_marker }}"

# End-to-end user journey walkthrough - stub until task-6.
journey:
    @echo "{{ stub_marker }}"
