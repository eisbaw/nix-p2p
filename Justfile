# Canonical gates for nix-p2p (TESTING.md "Negative feedback").
# Run these inside `nix develop`; `_toolchain` below enforces it.
# `nix flake check` runs build/lint/fmt/test/independence again inside the
# sandbox - use it for CI and to catch anything that only passes against a
# warm ./target.

# Honesty marker for gates whose harness does not exist yet. A stub that looks
# like a pass is forbidden - tasks 5/9/10/6 replace these with real gates.
stub_marker := "0 scenarios registered - NOT a pass"

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

# Compile the whole workspace, tests and benches included.
build: _toolchain
    cargo build --locked --workspace --all-targets

# Clippy (warnings are errors), rustfmt drift, and the crate-independence guard.
# scripts/ is linted too: the independence guard is safety-critical and would
# otherwise be the only unchecked file in a repo gated at -D warnings.
lint: _toolchain independence
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo fmt --all --check
    ruff check scripts
    ruff format --check scripts

# Assert daemon and testproxy stay strictly separated (PRD round 5/6).
independence: _toolchain
    python3 scripts/check-independence.py

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
