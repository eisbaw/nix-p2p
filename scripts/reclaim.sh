#!/usr/bin/env bash
# `just reclaim` — reclaim this project's REBUILDABLE disk footprint, SAFELY (TASK-54).
#
# Why this exists: the shared box has repeatedly gone toward 0 MB free, which kills
# shell output-capture mid-command and manufactures false gate results. The biggest
# consumers are (a) per-agent cargo target dirs (each reviewer/implementer builds the
# same tree into its OWN target dir), (b) podman images/volumes/build-cache, and
# (c) orphaned build artifacts left by completed reviews.
#
# SAFETY CONTRACT — this script touches ONLY:
#   * THIS rootless user's podman objects (system prune is per-user by construction),
#   * THIS project's cargo target dir(s) (rebuildable by `cargo build`),
#   * unreferenced fixture generations (rebuildable by `just fixtures`),
#   * stale git worktree registrations (`git worktree prune`).
# It NEVER removes another session's files and NEVER touches /tmp/claude-* scratch of
# other sessions. Every rm is guarded (a path must actually look like what we claim it
# is before it is removed).
#
# Not `set -e`: a single failing prune must NOT abort the rest of the reclaim — the
# whole point is to free as much as possible in one shot. Failures are printed.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

# Available bytes on the filesystem holding PATH. Integer only (owner no-float rule).
avail_bytes() {
    local v
    v=$(df -B1 --output=avail "$1" | tail -n1 | tr -d ' ')
    echo "${v:-0}"
}

before=$(avail_bytes "${repo_root}")
echo "reclaim: $(( before / 1024 / 1024 )) MiB free before"

# 1. Podman: stopped containers, unused networks, dangling images, build cache, and
#    unused named volumes. Rootless podman -> only THIS user's objects are in scope.
if command -v podman >/dev/null 2>&1; then
    echo "reclaim: podman system prune -f --volumes"
    podman system prune -f --volumes || echo "reclaim: podman prune failed (continuing)" >&2
else
    echo "reclaim: podman not on PATH, skipping container prune"
fi

# 2. Stale git worktree registrations. A /tmp review worktree deleted without
#    `git worktree remove` leaves a dead registration (and blocks re-use of its path).
echo "reclaim: git worktree prune"
git worktree prune -v || echo "reclaim: git worktree prune failed (continuing)" >&2

# 3. Unreferenced fixture generations. Use the generator's one collector so
#    publication and reclaim share the same lock, descriptor anchoring, ownership
#    markers, current+previous retention, and deletion primitive. Direct execution
#    outside `nix develop` skips this stage clearly and still reaches cargo cleanup.
collect_fixture_root() {
    local label="$1"
    shift
    local python_root="${NIX_P2P_PYTHON:-}"
    if [[ -z "${python_root}" ]]; then
        echo "reclaim: ${label} fixture collection skipped: NIX_P2P_PYTHON is unset; run via 'nix develop -c just reclaim' (continuing)" >&2
        return 1
    fi
    local python_bin="${python_root}/bin/python3"
    if [[ ! -x "${python_bin}" ]]; then
        echo "reclaim: ${label} fixture collection skipped: pinned Python is not executable at ${python_bin}; run via 'nix develop -c just reclaim' (continuing)" >&2
        return 1
    fi
    if ! "${python_bin}" scripts/gen-fixtures.py --collect-only "$@"; then
        echo "reclaim: ${label} fixture collection failed (continuing)" >&2
        return 1
    fi
}
collect_fixture_root "canonical" || :
collect_fixture_root "wide" --wide || :

# 4. Cargo target dir(s) — the biggest consumer. A dir is cleared ONLY if it actually
#    looks like a cargo target dir (CACHEDIR.TAG or a debug/release tree), so a mistyped
#    or empty CARGO_TARGET_DIR can never turn this into a catastrophic rm. Removing the
#    warm cache is the intended reclaim tradeoff: the next build is COLD.
clean_cargo_dir() {
    local dir="$1"
    [[ -n "${dir}" && -d "${dir}" ]] || return 0
    if [[ -f "${dir}/CACHEDIR.TAG" || -d "${dir}/debug" || -d "${dir}/release" ]]; then
        local sz
        sz=$(du -sh "${dir}" 2>/dev/null | cut -f1)
        echo "reclaim: clearing cargo target dir ${dir} (${sz:-?})"
        rm -rf "${dir}"
    else
        echo "reclaim: ${dir} does not look like a cargo target dir, skipping" >&2
    fi
}
# Resolve to real paths so the repo-local ./target and a shared CARGO_TARGET_DIR that
# happen to be the same place are not cleared twice.
# The $HOME/.cache/nix-p2p-target default mirrors the devShell shellHook (flake.nix,
# TASK-238): CARGO_TARGET_DIR is normally inherited from `nix develop`, but list the
# HOME-based default too so a reclaim run WITHOUT that env still clears the shared dir.
declare -A seen_target=()
for candidate in "${repo_root}/target" "${CARGO_TARGET_DIR:-$HOME/.cache/nix-p2p-target}"; do
    [[ -n "${candidate}" ]] || continue
    real=$(readlink -f "${candidate}" 2>/dev/null || echo "${candidate}")
    [[ -n "${seen_target[${real}]:-}" ]] && continue
    seen_target[${real}]=1
    clean_cargo_dir "${real}"
done

after=$(avail_bytes "${repo_root}")
reclaimed=$(( after - before ))
echo "reclaim: $(( after / 1024 / 1024 )) MiB free after"
if (( reclaimed >= 0 )); then
    echo "reclaim: freed $(( reclaimed / 1024 / 1024 )) MiB"
else
    # Concurrent writers on a shared box can outpace us; report honestly rather than
    # print a negative "freed".
    echo "reclaim: net free space fell by $(( -reclaimed / 1024 / 1024 )) MiB during the run (other writers active)"
fi
