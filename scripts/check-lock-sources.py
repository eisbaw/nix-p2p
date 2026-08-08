#!/usr/bin/env python3
"""Enforce the single runtime source of truth for the fixture lock (task-3 B).

The round-8 redesign moved the AUTHORITATIVE lock inside each generation
(`gen-<sha>/lock.json`) and DEMOTED the git-tracked
`fixtures/workload.lock.json` to a review artifact. This check makes acceptance
condition 1 a permanent, auditable gate rather than a one-off grep:

  1. Runtime/gate/consistency code - check-fixtures.py and check-rebuild.py -
     never reads the git baseline. It resolves the lock only through
     `current -> gen-<sha>/lock.json` (fx.load_generation_lock).

  2. gen-fixtures.publish() reads NO lock at all. Publication is a single
     symlink flip; there is nothing to reconcile, roll back, or read back.

  3. The git baseline (fx.load_baseline / fx.lock_path) is read in gen-fixtures
     ONLY by the freeze/--write-lock functions, never anywhere else.

Uses the AST, not a text grep, so a remediation MESSAGE that names
`fixtures/workload.lock.json` is not mistaken for code that opens it.

Exit 0 clean, 1 a boundary was crossed, 2 the source could not be parsed.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# The scripts/ directory to audit. Defaults to this file's own directory (the
# `just lint` case); a Nix check copies this script to the store alone, so it
# passes the source scripts/ tree explicitly as argv[1].
SCRIPTS = (
    Path(sys.argv[1]).resolve()
    if len(sys.argv) > 1
    else Path(__file__).resolve().parent
)

# Names that mean "reading the git-tracked baseline".
BASELINE_CALLS = {"load_baseline", "lock_path", "load_lock"}
# Any name that means "reading a lock" (baseline OR generation) - forbidden
# inside publish(), which must touch no lock.
ANY_LOCK_CALLS = BASELINE_CALLS | {"load_generation_lock", "read_at"}

# The only functions in gen-fixtures.py permitted to read the git baseline.
BASELINE_READERS_ALLOWED = {"assert_matches_baseline", "prepare_baseline"}


def called_names(node: ast.AST) -> set[str]:
    """Every function/attribute name invoked anywhere under `node`."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Attribute):
                names.add(func.attr)
            elif isinstance(func, ast.Name):
                names.add(func.id)
    return names


def module_functions(path: Path) -> dict[str, ast.FunctionDef]:
    try:
        tree = ast.parse(path.read_text())
    except (OSError, SyntaxError) as error:
        print(f"check-lock-sources: cannot parse {path}: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    return {
        node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
    }


def main() -> int:
    violations: list[str] = []

    # (1) The runtime/gate/consistency scripts must never call a baseline reader.
    for name in ("check-fixtures.py", "check-rebuild.py"):
        path = SCRIPTS / name
        try:
            tree = ast.parse(path.read_text())
        except (OSError, SyntaxError) as error:
            print(f"check-lock-sources: cannot parse {path}: {error}", file=sys.stderr)
            return 2
        used = called_names(tree)
        crossed = used & BASELINE_CALLS
        if crossed:
            violations.append(
                f"{name} calls {sorted(crossed)} - runtime/gate code must resolve the "
                "lock only via current -> gen-<sha>/lock.json (load_generation_lock)"
            )

    gen = module_functions(SCRIPTS / "gen-fixtures.py")

    # (2) publish() must read no lock at all.
    if "publish" not in gen:
        violations.append("gen-fixtures.py has no publish() - cannot verify it")
    else:
        crossed = called_names(gen["publish"]) & ANY_LOCK_CALLS
        if crossed:
            violations.append(
                f"gen-fixtures.publish() calls {sorted(crossed)} - publication is one "
                "symlink flip and must read no lock (no reconciliation, no read-back)"
            )

    # (3) In gen-fixtures, only the freeze/--write-lock functions read the baseline.
    for fname, node in gen.items():
        if fname in BASELINE_READERS_ALLOWED:
            continue
        crossed = called_names(node) & {"load_baseline"}
        if crossed:
            violations.append(
                f"gen-fixtures.{fname}() reads the git baseline (load_baseline); only "
                f"{sorted(BASELINE_READERS_ALLOWED)} may"
            )

    if violations:
        print("check-lock-sources: FAIL", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1
    print(
        "check-lock-sources: ok - the authoritative lock is resolved through "
        "current -> gen-<sha>/lock.json; the git baseline is read only by the "
        f"generator's freeze path {sorted(BASELINE_READERS_ALLOWED)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
