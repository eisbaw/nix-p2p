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
#   * STALE cargo artifacts inside this project's target dir (pruned by cargo-sweep, which
#     keeps the current dep cache; the old full `rm -rf <target>` wipe is gone),
#   * unreferenced fixture generations (rebuildable by `just fixtures`),
#   * stale git worktree registrations (`git worktree prune`).
# It NEVER removes another session's files and NEVER touches /tmp/claude-* scratch of
# other sessions. The cargo stage runs NO `rm` — cargo-sweep deletes only cargo artifacts
# inside a target dir it resolves via `cargo metadata`; the podman/worktree/fixture stages
# use their own tools' prune primitives, never an unqualified path rm.
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

# 4. Cargo target — the biggest consumer. We PRUNE STALE artifacts (old dependency versions
#    from dependency churn, other branches) while KEEPING the current dep cache, via
#    `cargo-sweep`. This replaces the old `rm -rf <target>` full wipe: a reclaim no longer
#    forces a cold rebuild of every dependency from source. NO `rm` runs here at all —
#    cargo-sweep only ever deletes cargo artifacts inside a target dir it identifies via
#    `cargo metadata` (run from the repo root, honouring CARGO_TARGET_DIR), so there is no
#    unqualified path to delete. If cargo-sweep is unavailable (run outside `nix develop`),
#    we skip rather than fall back to a wipe.
sweep_cargo_target() {
    if ! command -v cargo-sweep >/dev/null 2>&1; then
        echo "reclaim: cargo-sweep not on PATH — run via 'nix develop -c just reclaim'; skipping cargo cleanup (NO full wipe)" >&2
        return 0
    fi
    local tgt="${CARGO_TARGET_DIR:-$HOME/.cache/nix-p2p-target}"
    if [[ ! -d "${tgt}" ]] || [[ ! -f "${tgt}/CACHEDIR.TAG" && ! -d "${tgt}/debug" && ! -d "${tgt}/release" ]]; then
        echo "reclaim: ${tgt} is not a cargo target dir, skipping cargo cleanup" >&2
        return 0
    fi
    local sz
    sz=$(du -sh "${tgt}" 2>/dev/null | cut -f1)
    echo "reclaim: sweeping cargo target ${tgt} (${sz:-?}) — keep current deps, prune stale (cargo-sweep, no cold rebuild)"
    # SAFE default: drop artifacts not touched in > N days (stale versions / old branches);
    # everything from recent builds (the current dep cache) is kept, so no cold rebuild.
    cargo sweep --time "${NIX_P2P_RECLAIM_DAYS:-2}" \
        || echo "reclaim: cargo sweep --time failed (continuing)" >&2
    # Optional AGGRESSIVE cap: set NIX_P2P_RECLAIM_MAXSIZE (e.g. 40GB) to evict the OLDEST
    # artifacts until the target is under that size — under real disk pressure. This MAY evict
    # some current deps (a partial, not full, rebuild). Off by default.
    if [[ -n "${NIX_P2P_RECLAIM_MAXSIZE:-}" ]]; then
        echo "reclaim: aggressive cap NIX_P2P_RECLAIM_MAXSIZE=${NIX_P2P_RECLAIM_MAXSIZE}"
        cargo sweep --maxsize "${NIX_P2P_RECLAIM_MAXSIZE}" \
            || echo "reclaim: cargo sweep --maxsize failed (continuing)" >&2
    fi
}
sweep_cargo_target

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
