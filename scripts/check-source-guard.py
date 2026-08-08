#!/usr/bin/env python3
"""Assert no Rust source depends on the dev shell or the generated fixtures.

Two things are unavailable inside a Nix build sandbox: the fixture cache
(generated and gitignored, so it is never in the flake source) and the dev
shell's NIX_P2P_* environment. `nix build .#testproxy` runs cargo test in its
checkPhase, so a Rust test needing either would have to skip when they are
absent - and a skip that reports success is a vacuous green, while the same
test stays honest under `nix develop`. That asymmetry is the whole hazard.

This is a POLICY choice, not a forced consequence, and worth stating as one: a
Rust test could read the tree and `panic!` when it is missing, which fails
loudly rather than vacuously. The cost is a carve-out - a feature gate, or
`doCheck = false` for one crate - and wave 1 does not need the machinery. So:
fixture-dependent assertions live in scripts/. Lifting that needs a
deliberate, reviewable diff here, same discipline as the empty ALLOWLIST in
check-independence.py.

Limits, stated plainly. This is a substring scan, so `env!()`, a const, or
string concatenation all evade it; it catches the accident, not the
determined. It has no dependencies beyond the standard library precisely so it
can run BOTH in `just lint` and as a flake check - the guard is about source,
needs no fixture, and would be worth little if the only thing running it were
a developer's local loop.

Usage: check-source-guard.py [ROOT ...]   (default: the repository root)
Exit codes: 0 clean, 1 a violation, 2 nothing was scanned so nothing was proven.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Directories that never contain reviewable first-party source.
SKIP_DIRS = {".git", "target", "result", "fixtures", "backlog", ".direnv"}

# Substrings a Rust source must not contain, with the reason reported on a hit.
FORBIDDEN = {
    "fixtures/": "the generated fixture tree is absent inside a Nix build sandbox",
    "NIX_P2P_": "NIX_P2P_* are dev-shell-only variables, unset inside a Nix build",
}


def scan(roots: list[Path]) -> tuple[list[str], int]:
    violations: list[str] = []
    scanned = 0
    for root in roots:
        for source in sorted(root.rglob("*.rs")):
            if SKIP_DIRS & set(source.relative_to(root).parts):
                continue
            scanned += 1
            try:
                text = source.read_text()
            except (UnicodeDecodeError, OSError) as exc:
                violations.append(f"{source}: cannot be scanned ({exc})")
                continue
            for needle, reason in FORBIDDEN.items():
                if needle in text:
                    violations.append(f"{source}: contains {needle!r} - {reason}")
    return violations, scanned


def main(argv: list[str]) -> int:
    roots = [Path(a).resolve() for a in argv] or [
        Path(__file__).resolve().parent.parent
    ]
    for root in roots:
        if not root.is_dir():
            print(f"check-source-guard: {root} is not a directory", file=sys.stderr)
            return 2

    violations, scanned = scan(roots)
    if violations:
        print("check-source-guard: FAIL", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        print(
            "\nFixture- and dev-shell-dependent assertions belong in scripts/, "
            "which runs under `just test` where both actually exist.",
            file=sys.stderr,
        )
        return 1
    if scanned == 0:
        # A guard that scanned nothing and reported success is the exact shape
        # of the vacuous pass it exists to prevent.
        print(
            f"check-source-guard: scanned ZERO .rs files under {roots} - the guard "
            "is not looking where the code is, so nothing was proven",
            file=sys.stderr,
        )
        return 2
    print(
        f"check-source-guard: ok - {scanned} .rs file(s) scanned, none depend on "
        "the fixture tree or the dev shell"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
