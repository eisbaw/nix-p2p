#!/usr/bin/env python3
"""Enforce the single runtime source of truth for the fixture lock (task-3 B).

The round-8 redesign moved the AUTHORITATIVE lock inside each generation
(`gen-<sha>/lock.json`) and DEMOTED the canonical and wide git-tracked locks to
review artifacts. This check makes acceptance
condition 1 a permanent gate: no runtime/gate code reads the git baseline;
everything resolves through `current -> gen-<sha>/lock.json`
(fx.load_generation_lock).

The governed set is DENY-BY-DEFAULT: every scripts/*.py is runtime/gate code
UNLESS it is the one module that legitimately owns the baseline
(gen-fixtures.py). A brand-new runtime script is therefore covered the moment
it lands, with no allowlist edit - which is the shape of a regression guard
that keeps working after this task closes.

Two independent checks, because the call-name AST check alone was evadable:

  1. Name-reference scan. No governed module REFERENCES a baseline reader -
     `load_baseline` / `lock_path` / `load_lock` - as a call OR as an alias
     (`x = fx.load_baseline; x(repo)` still references the attribute).
     gen-fixtures.publish() references no lock reader at all. Inside
     gen-fixtures, only the designated baseline-owning functions reference
     load_baseline.

  2. Literal-string scan on the GOVERNED modules. Any runtime/gate module that
     names either baseline filename literal fails - this is what catches codex's
     raw-read evasion `(repo / "fixtures" / "workload.lock.json").read_text()`
     and `open(...)` on the path, which reference no known name at all.
     Docstrings are excluded (prose, never a file access). The baseline OWNER
     (gen-fixtures.py) and the library that defines the readers (fixturelib.py)
     are exempt from the literal scan: they legitimately name the file in help
     text, freeze-failure messages, and the reader definitions. For the owner,
     the reference scan of check 1 - not a literal scan - is what keeps a
     smuggled alias out of the non-owner functions.

HONEST RESIDUAL - irreducible, stated rather than papered over. A static guard
cannot prove a negative against arbitrary code. A path assembled at runtime from
pieces (`"workload" + ".lock.json"`, `os.path.join(a, b, c)` over computed
fragments, a name read from elsewhere) names the baseline without any literal a
scanner can see, and evades BOTH checks. So this guard rejects every ORDINARY
and LITERAL reintroduction - the accidental `read_text`, the copy-paste, the
rename - which is what a regression guard is for. It does NOT, and cannot,
defeat a deliberately obfuscated dynamic read. That is the true content of
acceptance condition 1's word "proves": mechanically enforced against ordinary
code, not a proof against an adversary editing this repository.

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

# The ONE module that legitimately reads and writes the git baseline. Everything
# else under scripts/ is governed as runtime/gate code by default - a new script
# needs no allowlist entry to be covered.
BASELINE_OWNER = "gen-fixtures.py"

# fixturelib.py DEFINES the baseline readers (load_baseline, lock_path); it is
# the library, not a runtime entry point, so the literal necessarily lives in it.
# It is exempt from the module-level literal scan but still bound by the rule
# that governed modules must not CALL those readers.
LIBRARY = "fixturelib.py"

# This guard names the baseline in its own prose; exempt itself.
SELF = "check-lock-sources.py"

# Names that mean "reading the git-tracked baseline".
BASELINE_CALLS = {"load_baseline", "lock_path", "load_lock"}
# Any name that means "reading a lock" (baseline OR generation) - forbidden
# inside publish(), which must touch no lock.
ANY_LOCK_CALLS = BASELINE_CALLS | {"load_generation_lock", "read_at"}

# The only functions in gen-fixtures.py permitted to touch the git baseline -
# by call OR by literal. The --write-lock write path (write_baseline) and the
# freeze/reconcile reads live here.
BASELINE_OWNERS = {
    "assert_matches_baseline",
    "prepare_baseline",
    "write_baseline",
    "lock_dict_from_manifest",
}

# Both baseline filenames. Any governed module mentioning either literal
# (outside a designated owner) is reaching for a git review artifact that the
# redesign forbids at runtime.
BASELINE_LITERALS = frozenset({"workload.lock.json", "wide_closure.lock.json"})


def referenced_names(node: ast.AST) -> set[str]:
    """Every name REFERENCED under `node` - as a call, an attribute, or a bare
    name. Broader than "called" on purpose: `alias = fx.load_baseline` followed
    by `alias(repo)` never CALLS `load_baseline`, but it does REFERENCE the
    attribute `load_baseline`, and that is how an alias reaches the reader. A
    reference by name is the last thing an ordinary alias cannot avoid.
    """
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute):
            names.add(child.attr)
        elif isinstance(child, ast.Name):
            names.add(child.id)
    return names


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """id()s of the Constant nodes that are docstrings (prose, not code).

    A literal that actually REACHES the baseline file appears in an executable
    expression - a Path join, an open(), a read_text() argument - never as a
    module/class/function docstring. Excluding docstrings keeps a legitimate
    prose mention of the filename from being mistaken for a file access.
    """
    out: set[int] = set()
    for scope in ast.walk(tree):
        if isinstance(
            scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            body = getattr(scope, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                out.add(id(body[0].value))
    return out


def string_constants(node: ast.AST) -> list[str]:
    """Every non-docstring string literal under `node` (f-string parts included)."""
    skip = _docstring_nodes(node)
    return [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and id(child) not in skip
    ]


def parse(path: Path) -> ast.Module:
    try:
        return ast.parse(path.read_text())
    except (OSError, SyntaxError) as error:
        print(f"check-lock-sources: cannot parse {path}: {error}", file=sys.stderr)
        raise SystemExit(2) from error


def governed_modules() -> list[Path]:
    """Every scripts/*.py that is runtime/gate code: all but the baseline owner,
    the library that defines the readers, and this guard itself."""
    return sorted(
        p for p in SCRIPTS.glob("*.py") if p.name not in {BASELINE_OWNER, LIBRARY, SELF}
    )


def main() -> int:
    violations: list[str] = []

    # (1) Governed runtime/gate modules (deny-by-default): no reference to a
    #     baseline reader - call OR alias - and no baseline-filename literal.
    #     The literal scan is what catches codex's raw-read evasion
    #     `(repo / "fixtures" / "workload.lock.json").read_text()`; the
    #     reference scan catches an aliased reader.
    for path in governed_modules():
        tree = parse(path)
        crossed = referenced_names(tree) & BASELINE_CALLS
        if crossed:
            violations.append(
                f"{path.name} references {sorted(crossed)} - runtime/gate code must "
                "resolve the lock only via current -> gen-<sha>/lock.json "
                "(fx.load_generation_lock)"
            )
        for literal in sorted(BASELINE_LITERALS):
            if any(literal in s for s in string_constants(tree)):
                violations.append(
                    f"{path.name} contains the literal {literal!r} - runtime/gate "
                    "code must not name a demoted git baseline, even via a raw "
                    "read_text/open"
                )

    gen = {
        node.name: node
        for node in ast.walk(parse(SCRIPTS / BASELINE_OWNER))
        if isinstance(node, ast.FunctionDef)
    }

    # (2) publish() references no lock reader at all (call or alias).
    if "publish" not in gen:
        violations.append(f"{BASELINE_OWNER} has no publish() - cannot verify it")
    else:
        crossed = referenced_names(gen["publish"]) & ANY_LOCK_CALLS
        if crossed:
            violations.append(
                f"{BASELINE_OWNER} publish() references {sorted(crossed)} - publication "
                "is one symlink flip and must read no lock (no reconciliation, no "
                "read-back)"
            )

    # (3) In the baseline OWNER module, only the designated functions may
    #     reference load_baseline (catches an alias smuggled into any other
    #     function). The owner is exempt from the LITERAL scan - it legitimately
    #     names the file in argparse help and in freeze-failure messages - which
    #     is why the reference scan, not a literal scan, is the lever here.
    for fname, node in gen.items():
        if fname in BASELINE_OWNERS:
            continue
        if referenced_names(node) & {"load_baseline"}:
            violations.append(
                f"{BASELINE_OWNER} {fname}() references load_baseline; only "
                f"{sorted(BASELINE_OWNERS)} may read the baseline"
            )

    if violations:
        print("check-lock-sources: FAIL", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1
    print(
        "check-lock-sources: ok - governed "
        f"{[p.name for p in governed_modules()]} resolve the lock through "
        "current -> gen-<sha>/lock.json (no baseline call, no baseline literal); "
        f"both git baselines are touched only by {sorted(BASELINE_OWNERS)} in "
        f"{BASELINE_OWNER}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
