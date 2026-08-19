#!/usr/bin/env python3
"""Keep floats out of gate/decision paths in the measurement/evidence scripts.

OWNER STANDING RULE (memory `no-floats-integers-or-rationals`). No float/NaN may
appear in any GATE, BOUND, ADMISSION, DECISION, or SERIALIZED-INTEGRITY field.
Ratios are carried as an EXACT rational num/denom and compared by
cross-multiplication (a*d vs b*c); bandwidth is a whole integer bytes/sec;
latency/durations are whole integer nanoseconds. Floats are permitted only as a
TERMINAL display value (a print, an f-string, a `*_display`/`*_ms`/`*_mbit`
report field). The Rust trust path (daemon/fabric) is already integer-by-type;
the remaining risk lives in the Python measurement/evidence/gate scripts, and
nothing prevented a float from creeping back into a gate. This guard is that
prevention, in the shape of `check-independence.py`/`check_shaping_out_of_daemon.py`:
a CI check wired into `just lint`, proven non-vacuous by a self-test that BITES.

WHAT IT FLAGS (AST, not regex):

  Rule A - a float in a DECISION comparison. Inside a function whose NAME signals
  a gate/verdict/oracle (GATE_FUNC_TOKENS), OR wherever a comparison result is
  assigned to a target whose NAME signals a verdict (VERDICT_VAR_TOKENS), a
  comparison (`<`,`>`,`<=`,`>=`,`==`,`!=`) whose operand subtree contains a float
  literal is a violation. The float is caught anywhere in the operand tree, so a
  coefficient hidden in a BinOp (`x < 0.7 * cap`) is caught, not just a bare
  `x < 0.5`.

  Rule B - a float written into a SERIALIZED-INTEGRITY field. A dict entry whose
  KEY promises an exact integer/rational quantity (`*_ns`, `*_num`, `*_denom`)
  but whose VALUE is a float (a float literal, a `float(...)` call, or a `/`
  division) is a violation. These field names have NO legitimate float use: a
  nanosecond count or a rational numerator is exact by construction.

WHAT IT ALLOWS (ALLOW, each with a reason - the check-independence discipline):

  * Terminal display floats: a `print`, an f-string, a `*_display`/`*_ms`/`*_s`/
    `*_mbit`/`*_frac` report field. These never gate; Rule A only looks at
    comparisons and Rule B only at exact-integer field names, so display sites
    are outside both rules by construction.
  * Genuine statistical fits (scalefit regression, student-t, incomplete-beta)
    that produce confidence intervals for a REPORT and never gate a verdict.
  * Physical-measurement oracles that compare an IRREDUCIBLE physical float (a
    median/percentile/mean of wall-clock seconds or a ping RTT) against a
    tolerance. Fully de-floating these means re-plumbing wall-time to integer ns
    end-to-end, which is a separate change; they are allowlisted BY NAME with a
    stated reason so the exception stays a reviewable diff.

COVERAGE BOUNDARY, stated plainly so the gate is not read as broader than it is:
  * It scans the SCANNED list below (the safety-critical measurement/evidence/
    gate scripts), NOT the whole tree, and NOT the Rust trust path (already
    integer-by-type).
  * Rule A is NAME-driven: a verdict computed in a function whose name carries no
    gate token AND assigned to a target whose name carries no verdict token is
    not seen. This is a deliberate precision-over-recall choice - a name-based
    guard that catches the obvious fail-open cases without drowning the real
    statistical code in false positives, not a general float-taint analyzer.
  * Rule B watches only `*_ns`/`*_num`/`*_denom` keys - the field names that can
    NEVER legitimately hold a float. `*_bytes`/`*_per_s` fields carry measurement
    means and are left to review; watching them would flag every reported mean.
  * `assert` statements inside `*_self_test`/`run_self_test` harnesses are not a
    signal: a self-test asserting a computed value verifies the finalizer it
    guards, and the finalizer's own gates are what this checks.

Run from the workspace root. Exit codes mirror check-independence:
  0  clean (self-test green, real scan green)
  1  a real violation - a float in a gate/decision or an integrity field
  2  the check could not be performed (self-test not trustworthy, or a parse
     error); nothing was proven either way
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_CANNOT_CHECK = 2

# The safety-critical measurement / evidence / gate scripts. Scan what exists:
# the list is a superset so adding a script here is a reviewable one-line diff,
# and a not-yet-present name is skipped rather than erroring.
SCANNED = [
    "peer_wire_baseline.py",
    "task99_link_compression_measure.py",
    "task203_pipelined_measure.py",
    "decentralized_discovery_evidence.py",
    "shaped_link.py",
    "shaped_libp2p.py",
    "shaped_compress.py",
    "shaped_kad.py",
    "measure.py",
    "profile_p2p.py",
    "scalefit.py",
    "scale_sweep.py",
    "measure_real_gap.py",
    "task256_closure_overlap.py",
    "task269_compression_sweep.py",
    "task269_crossover.py",
]

# A function NAME carrying one of these (lowercased substring) marks its body a
# gate/verdict/oracle: a float in a comparison there drives a decision.
GATE_FUNC_TOKENS = (
    "gate",
    "verdict",
    "admit",
    "admission",
    "decide",
    "decision",
    "oracle",
    "judge",
    "bite",
    "earn",
)
# A function whose name starts with one of these is a gate/verdict too.
GATE_FUNC_PREFIXES = ("assert_",)

# Functions that ARE verdicts but whose NAME carries no gate token, so the
# name heuristic alone is blind to them. Listed explicitly (script, function) so
# the guard is not silently blind to a file's real gating floats - the vacuity
# trap. `break_even` is the archetype: its decision-float is a COMPUTED variable
# (`denom = ratio/up - 1.0/peer`) compared against an int `0`, so no float
# literal sits in the comparison itself - only the intra-function taint pass (see
# below) can see it. Extend this list, do not weaken the taint pass.
VERDICT_FUNCS: frozenset[tuple[str, str]] = frozenset(
    {
        ("peer_wire_baseline.py", "break_even"),
    }
)

# A comparison assigned to a target NAME carrying one of these (lowercased
# substring) is a verdict regardless of the enclosing function's name.
VERDICT_VAR_TOKENS = (
    "faster",
    "slower",
    "trips",
    "passes",
    "bites",
    "holds",
    "usable",
    "earned",
    "refused",
    "flipped",
    "_ok",
    "is_ok",
    "_flag",
    "flag_",
)

# Serialized-integrity field-name suffixes that can NEVER hold a float.
INTEGRITY_KEY_SUFFIXES = ("_ns", "_num", "_denom")

# Deliberate, reasoned exceptions. Each is (script, function-name, reason).
# Every entry must correspond to a REAL Rule-A hit (a vacuous allowlist entry is
# the rubber-stamp smell): the guard self-test proves ALLOW suppresses, and each
# name below is a gate/verdict-named function the empty-allowlist scan flags.
#
# scalefit.py's statistical internals (`_fit_basis`, `student_t_ppf`,
# `regularized_incomplete_beta`, ...) are NOT listed: their names carry no gate
# token, so Rule A never fires on them - the sanctioned statistical float is
# outside this guard's name-driven scope by construction, not by allowlisting.
# Keep this list SHORT and every entry justified - it is the reviewable diff.
#
# Each entry states (i) the exact threshold, (ii) the irreducible-or-deferred
# observand, (iii) WHY converting exceeds this task - a *plumbing* or *coupling*
# reason, never bare "it's a float". Two honest sub-classes:
#   PERMANENT  - the observand is an irreducible physical/statistical float (a
#     median/percentile/mean of wall-clock or Monte-Carlo samples); converting
#     needs wall-time re-plumbed to integer ns end-to-end, a measurement-plumbing
#     change, not a representation change.
#   DEFERRED (TASK-211) - the observand IS integer/rational (byte counts, a
#     ratio of integer byte-sums, ping-derived ns) and the site IS convertible,
#     but it is coupled to the proven peer_wire_baseline trust spine / measure.py
#     finalizer + committed evidence schema and (for break_even) needs a boundary
#     self-test-vector audit. Batched into TASK-211 rather than half-converted
#     here (per the mped ruling: the half-measure is the worst option).
ALLOW_FUNCS: list[tuple[str, str, str]] = [
    # --- DEFERRED to TASK-211: peer_wire_baseline verdict spine ---------------
    (
        "peer_wire_baseline.py",
        "break_even",
        "DEFERRED TASK-211. (i) sign tests denom>0 / ==0 / <0 and numer>0/<0. "
        "(ii) denom=ratio/up - 1/peer is exact-rational over integer byte rates, "
        "convertible to Fraction cross-multiplied sign tests. (iii) it is the "
        "trust-spine verdict AND its own self-test builds denom==0 boundary "
        "vectors on float semantics that exact arithmetic could move - needs a "
        "re-bless audit; convert the whole spine coherently, not piecemeal",
    ),
    (
        "peer_wire_baseline.py",
        "assert_link_label",
        "DEFERRED TASK-211. (i) rtt_ms<0.7*want, throughput_mbit>1.3*cap - the "
        "same exact design ratios as shaped_link (already converted). (ii) rtt "
        "ping-decimal->exact ns, throughput decimal->exact bytes/sec. (iii) reads "
        "shaped_link's float rtt_ms/mbit and feeds the committed evidence schema "
        "(rtt_ms, throughput_mbit_per_s); convert with the spine so the serialized "
        "fields stay byte-identical via one terminal float() projection",
    ),
    # --- DEFERRED to TASK-211: measure.py integer-byte-ratio bites ------------
    (
        "measure.py",
        "bite_product_narinfo_cache",
        "DEFERRED TASK-211. (i) on[1]<0.5*on[0] and off[1]>=0.8*off[0]. (ii) on/off "
        "are per-run narinfo egress BYTE counts (integers) - convertible to "
        "2*on[1]<on[0] / 5*off[1]>=4*off[0]. (iii) coupled to the proven measure.py "
        "AC#5 finalizer + its serialized egress fields; batched with the spine",
    ),
    (
        "measure.py",
        "bite_magnitude_and_self_counter",
        "DEFERRED TASK-211. (i) delta<=SELF_COUNTER_TOL (=0.01). (ii) delta=|a-b|/b "
        "over integer byte counters - convertible to |a-b|*100<=b with a Fraction "
        "tolerance. (iii) coupled to the proven finalizer + serialized "
        "self_counter_rel_delta field; batched with the spine",
    ),
    # --- PERMANENT: irreducible physical / statistical measurement floats -----
    (
        "measure.py",
        "bite_gap_oracle",
        "PERMANENT. (i) med_base<x1*0.5, (med2-med1)>=0.5*(x2-x1). (ii) med* are "
        "statistics.median() of injected narinfo->nar gap samples in wall-clock "
        "ms floats - an irreducible physical measurement. (iii) de-floating needs "
        "monotonic-ns capture threaded through _measure_gap_median + the median "
        "end-to-end - a measurement-plumbing change, not a representation change",
    ),
    (
        "measure.py",
        "bite_latency_p95",
        "PERMANENT. (i) ratio>1.0+S4_THRESHOLD (=1.10). (ii) ratio=p95(injected)/"
        "p95(baseline) over wall-clock SECONDS floats (percentile) - the wall "
        "times are the physical observation. (iii) needs wall-time re-plumbed to "
        "integer ns through measure_one_run + percentile end-to-end (plumbing)",
    ),
    (
        "profile_p2p.py",
        "bite_applicability",
        "PERMANENT. (i) rate>=threshold and 1.0-rate>=threshold. (ii) rate is a "
        "Monte-Carlo superlinear-discrimination rate; threshold is the floor plus "
        "a float standard-error margin - a statistical estimate, never a "
        "serialized-integrity field. (iii) no exact form exists for a MC estimate",
    ),
    (
        "profile_p2p.py",
        "cross_condition_block",
        "PERMANENT. (i) peers_faster = mean_speedup > 1.0. (ii) the speedup is a "
        "MEAN of per-run latency ratios (irreducible physical statistic) "
        "summarised for the report. (iii) de-floating needs the whole realise-time "
        "measurement re-plumbed to integer ns end-to-end (plumbing)",
    ),
]


def _is_float_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, float)


def _subtree_has_float(node: ast.AST) -> bool:
    """True if a float literal appears anywhere under `node`."""
    return any(_is_float_constant(n) for n in ast.walk(node))


def _compare_has_float(node: ast.Compare) -> bool:
    return any(
        _subtree_has_float(operand) for operand in (node.left, *node.comparators)
    )


def _name_is_gate(name: str) -> bool:
    low = name.lower()
    if any(low.startswith(prefix) for prefix in GATE_FUNC_PREFIXES):
        return True
    return any(token in low for token in GATE_FUNC_TOKENS)


def _target_names(target: ast.AST) -> list[str]:
    """Assignment-target identifier(s): plain names and simple tuple unpacks."""
    names: list[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            names.extend(_target_names(element))
    return names


def _name_is_verdict(name: str) -> bool:
    low = name.lower()
    return any(token in low for token in VERDICT_VAR_TOKENS)


def _yields_float(node: ast.AST) -> bool:
    """True if `node` is a value expression that yields a float: a float literal
    anywhere in it, a `float(...)` call, or a `/` true-division (which yields a
    float in py3 - `//` or Fraction is the integer-honest form)."""
    for inner in ast.walk(node):
        if _is_float_constant(inner):
            return True
        if isinstance(inner, ast.BinOp) and isinstance(inner.op, ast.Div):
            return True
        if (
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Name)
            and inner.func.id == "float"
        ):
            return True
    return False


def _tainted_names(func_node: ast.AST) -> set[str]:
    """Local names assigned a float-yielding expression in `func_node`'s body.

    This is the intra-function taint that lets the guard see a decision-float
    carried in a VARIABLE, not just a literal - the `break_even` case, where
    `denom = ratio/up - 1.0/peer` is float and the gate is `denom > 0`. Nested
    function/lambda scopes are NOT descended into: each has its own frame."""
    tainted: set[str] = set()

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue  # a nested scope; its own frame handles it
            value: ast.AST | None = None
            targets: list[ast.AST] = []
            if isinstance(child, ast.Assign):
                value, targets = child.value, list(child.targets)
            elif isinstance(child, (ast.AnnAssign, ast.AugAssign)):
                value, targets = child.value, [child.target]
            elif isinstance(child, ast.NamedExpr):
                value, targets = child.value, [child.target]
            if value is not None and _yields_float(value):
                for target in targets:
                    tainted.update(_target_names(target))
            walk(child)

    walk(func_node)
    return tainted


def _compare_is_floaty(node: ast.Compare, tainted: set[str]) -> bool:
    """A comparison drives a float decision if a float literal is in it OR one of
    its operands references a float-tainted local name."""
    if _compare_has_float(node):
        return True
    for operand in (node.left, *node.comparators):
        for inner in ast.walk(operand):
            if isinstance(inner, ast.Name) and inner.id in tainted:
                return True
    return False


class _Frame:
    """One function's analysis context on the stack."""

    __slots__ = ("name", "is_gate", "allowed", "tainted")

    def __init__(self, name: str, is_gate: bool, allowed: bool, tainted: set[str]):
        self.name = name
        self.is_gate = is_gate
        self.allowed = allowed
        self.tainted = tainted


class _Scanner(ast.NodeVisitor):
    """Walk one module, tracking the enclosing function, collecting violations."""

    def __init__(
        self,
        script: str,
        allow_funcs: frozenset[tuple[str, str]],
        verdict_funcs: frozenset[tuple[str, str]],
    ) -> None:
        self.script = script
        self.allow_funcs = allow_funcs
        self.verdict_funcs = verdict_funcs
        self.stack: list[_Frame] = []
        self.violations: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        is_gate = _name_is_gate(node.name) or (
            (self.script, node.name) in self.verdict_funcs
        )
        frame = _Frame(
            name=node.name,
            is_gate=is_gate,
            allowed=(self.script, node.name) in self.allow_funcs,
            tainted=_tainted_names(node) if is_gate else set(),
        )
        self.stack.append(frame)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _top(self) -> _Frame | None:
        return self.stack[-1] if self.stack else None

    # -- Rule A, function-level: gate/verdict function bodies ---------------
    def visit_Compare(self, node: ast.Compare) -> None:  # noqa: N802
        frame = self._top()
        if (
            frame is not None
            and frame.is_gate
            and not frame.allowed
            and _compare_is_floaty(node, frame.tainted)
        ):
            self.violations.append(
                f"{self.script}:{node.lineno} float in a comparison inside "
                f"gate/verdict function '{frame.name}': {ast.unparse(node)[:80]}"
            )
        self.generic_visit(node)

    # -- Rule A, assignment-level: verdict-named targets --------------------
    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        frame = self._top()
        allowed = frame.allowed if frame is not None else False
        if isinstance(node.value, ast.Compare) and _compare_has_float(node.value):
            names = [n for t in node.targets for n in _target_names(t)]
            if any(_name_is_verdict(n) for n in names) and not allowed:
                verdict = next(n for n in names if _name_is_verdict(n))
                self.violations.append(
                    f"{self.script}:{node.lineno} float in a comparison assigned "
                    f"to verdict '{verdict}': {ast.unparse(node.value)[:80]}"
                )
        # -- Rule B: float into a serialized-integrity field ----------------
        self._check_dict_values(node.value, allowed)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
        frame = self._top()
        allowed = frame.allowed if frame is not None else False
        if node.value is not None:
            self._check_dict_values(node.value, allowed)
        self.generic_visit(node)

    def _check_dict_values(self, node: ast.AST, allowed: bool) -> None:
        for dict_node in ast.walk(node):
            if not isinstance(dict_node, ast.Dict):
                continue
            for key, value in zip(dict_node.keys, dict_node.values):
                if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                    continue
                # Rule B: an exact-integer/rational field holding a float.
                if key.value.endswith(INTEGRITY_KEY_SUFFIXES) and _yields_float(value):
                    self.violations.append(
                        f"{self.script}:{value.lineno} float written to "
                        f"serialized-integrity field '{key.value}': "
                        f"{ast.unparse(value)[:60]}"
                    )
                # Rule A (dict form): a verdict-named field whose value is a float
                # comparison - e.g. `"peers_faster": value > 1.0`, which is a
                # verdict computed inline into the serialized dict, not a variable
                # a name-based scan would see.
                if (
                    not allowed
                    and _name_is_verdict(key.value)
                    and any(
                        isinstance(sub, ast.Compare) and _compare_has_float(sub)
                        for sub in ast.walk(value)
                    )
                ):
                    self.violations.append(
                        f"{self.script}:{value.lineno} float comparison computed "
                        f"into verdict field '{key.value}': "
                        f"{ast.unparse(value)[:60]}"
                    )


def scan_source(
    script: str,
    source: str,
    allow_funcs: frozenset[tuple[str, str]],
    verdict_funcs: frozenset[tuple[str, str]] = VERDICT_FUNCS,
) -> list[str]:
    """Return violation lines for one module's source text."""
    tree = ast.parse(source, filename=script)
    scanner = _Scanner(script, allow_funcs, verdict_funcs)
    scanner.visit(tree)
    return scanner.violations


def _allow_index() -> frozenset[tuple[str, str]]:
    return frozenset((script, func) for script, func, _reason in ALLOW_FUNCS)


def scan_repo() -> list[str]:
    """Scan every present SCANNED script; returns violation lines."""
    allow = _allow_index()
    violations: list[str] = []
    for name in SCANNED:
        path = ROOT / "scripts" / name
        if not path.is_file():
            continue
        violations.extend(scan_source(name, path.read_text(), allow))
    return violations


# --- self-test: prove the guard bites (no repo files needed) -------------------

# (label, source, must_flag). Synthetic modules so the guard is proven to bite
# without depending on the real scripts - the check-independence discipline.
SELF_TEST_CASES: list[tuple[str, str, bool]] = [
    (
        "gate-named function comparing a bare float literal",
        "def admission_gate(x):\n    return x < 0.5\n",
        True,
    ),
    (
        "gate-named function with the float hidden in a coefficient BinOp",
        "def assert_shaped(rtt, cap):\n    if rtt < 0.7 * cap:\n        raise ValueError\n",
        True,
    ),
    (
        "verdict-named target outside any gate function",
        "def summarise(value):\n    peers_faster = value > 1.0\n    return peers_faster\n",
        True,
    ),
    (
        "float written to a serialized-integrity _ns field",
        "def finalize():\n    return {'latency_ns': 1.5}\n",
        True,
    ),
    (
        "float division written to a _num field",
        "def finalize(a, b):\n    return {'ratio_num': a / b}\n",
        True,
    ),
    (
        "display-only float: print + _ms/_display report fields, no comparison",
        "def show(rtt_ns):\n"
        "    ms = rtt_ns / 1_000_000\n"
        "    print(f'{ms:.2f}ms')\n"
        "    return {'rtt_ms': ms, 'rate_display': ms * 8.0}\n",
        False,
    ),
    (
        "integer/rational gate: cross-multiplied, no float anywhere",
        "def admission_gate(a, b, c, d):\n    return a * d < b * c\n",
        False,
    ),
    (
        "float compared in a NON-gate, non-verdict function (out of scope by design)",
        "def helper(x):\n    y = x < 0.5\n    return y\n",
        False,
    ),
    (
        "break_even-shaped: float VARIABLE (no literal in the compare) in an "
        "include-listed verdict function - the taint pass must see it",
        "def break_even(ratio, up, peer):\n"
        "    denom = ratio / up - 1.0 / peer\n"
        "    if denom > 0:\n"
        "        return 'peer'\n"
        "    return 'upstream'\n",
        True,
    ),
    (
        "exact break_even: cross-multiplied integers in the same verdict function "
        "- no float, no taint, must pass",
        "def break_even(ratio_num, ratio_den, up, peer):\n"
        "    lhs = ratio_num * peer\n"
        "    rhs = ratio_den * up\n"
        "    if lhs > rhs:\n"
        "        return 'peer'\n"
        "    return 'upstream'\n",
        False,
    ),
]

# The include-list the self-test uses so `break_even` is treated as a verdict
# function even though its name carries no gate token (mirrors VERDICT_FUNCS).
SELF_TEST_VERDICT_FUNCS = frozenset({("synthetic.py", "break_even")})

# Prove the ALLOW mechanism actually suppresses: the same biting source, allowed.
ALLOW_SELF_TEST = (
    "def bite_oracle(x):\n    return x < 0.5\n",
    "bite_oracle",
)


def self_test() -> list[str]:
    """Run the detector against synthetic modules; returns failure lines."""
    failures: list[str] = []
    empty: frozenset[tuple[str, str]] = frozenset()
    for label, source, must_flag in SELF_TEST_CASES:
        found = scan_source("synthetic.py", source, empty, SELF_TEST_VERDICT_FUNCS)
        if must_flag and not found:
            failures.append(f"'{label}' should have been FLAGGED but passed clean")
        elif not must_flag and found:
            failures.append(f"'{label}' should be clean but was flagged: {found}")

    # ALLOW must suppress a genuine hit - and only the named one.
    src, func = ALLOW_SELF_TEST
    if not scan_source("synthetic.py", src, empty):
        failures.append("ALLOW self-test source did not flag without the allowlist")
    if scan_source("synthetic.py", src, frozenset({("synthetic.py", func)})):
        failures.append("ALLOW did not suppress the flagged function")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run only the self-test (prove the guard bites), then exit",
    )
    args = parser.parse_args()

    failures = self_test()
    if failures:
        for failure in failures:
            print(f"no-floats guard self-test FAILED: {failure}", file=sys.stderr)
        print(
            "the guard is not trustworthy; the real scan was not run",
            file=sys.stderr,
        )
        return EXIT_CANNOT_CHECK

    flagged = sum(1 for _, _, must in SELF_TEST_CASES if must)
    if args.self_test:
        print(
            f"no-floats guard: self-test green ({flagged} bite cases caught, "
            f"{len(SELF_TEST_CASES) - flagged} clean cases passed, ALLOW suppresses)"
        )
        return EXIT_OK

    try:
        violations = scan_repo()
    except SyntaxError as error:
        print(f"no-floats check could not run: {error}", file=sys.stderr)
        return EXIT_CANNOT_CHECK

    if violations:
        for violation in violations:
            print(f"no-floats violation: {violation}", file=sys.stderr)
        return EXIT_VIOLATION

    present = sum(1 for n in SCANNED if (ROOT / "scripts" / n).is_file())
    print(
        f"no-floats: self-test green ({flagged} bite cases caught); real scan "
        f"clean across {present} measurement/evidence/gate scripts "
        f"({len(ALLOW_FUNCS)} sanctioned statistical/physical-measurement "
        "floats allowlisted with reasons). No float in a gate/decision "
        "comparison or a serialized-integrity (_ns/_num/_denom) field"
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
