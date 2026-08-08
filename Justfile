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

# Assert daemon and testproxy stay strictly separated (PRD round 5/6).
independence: _toolchain
    python3 scripts/check-independence.py

# Depends on the fast fixture tier because the signing and tamper assertions
# live in scripts/, not in cargo (rationale: scripts/check-fixtures.py).
# Unit and integration tests plus the fixture gate (in-process, no containers).
test: _toolchain _python fixtures
    cargo test --locked --workspace
    "${NIX_P2P_PYTHON}/bin/python3" scripts/check-fixtures.py

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
# in task-5 serve the same tree their own way.
# Serve the fixture cache as a mock upstream on 127.0.0.1.
fixtures-serve port="8080": _python
    "${NIX_P2P_PYTHON}/bin/python3" -m http.server --bind 127.0.0.1 --directory fixtures/out/cache {{ port }}

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
