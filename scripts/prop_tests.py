#!/usr/bin/env python3
"""Property-based tests (hypothesis) for shipped PURE Python surfaces (TASK-112).

The gate scripts are example-based: every test names the inputs it tries, so it
finds the cases someone thought of. These properties STATE the invariant instead
of sampling it - the same discipline the Rust `prop_*` tests bring to the claim
wire.

TWO MODES, ONE SET OF PROPERTIES (the whole reason this is its own recipe, per
TASK-109's determinism constraint):

    --check    FIXED seed (derandomize) + a bounded example count. Deterministic
               and fast, wired into `just test` alongside the other --self-test
               gates - it does NOT reintroduce the non-determinism TASK-109
               removed. Also the default with no flag.
    --explore  FREE seed + many examples. The exploration mode: `just prop`, run
               deliberately, not on every cycle.

NO PYTEST. hypothesis's `@given` wraps a plain function; this script calls each
one directly, exactly as the other gate scripts drive their `--self-test`
convention. A falsifying run prints hypothesis's "Falsifying example" - the
committed reproducer (AC#4).

Each property is proven to BITE by mutation (break the invariant in the target
function, watch the property fail) - see the TASK-112 report.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from hypothesis import example, given, settings
from hypothesis import strategies as st

# The shipped surfaces under test live next to this script.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixturelib  # noqa: E402  (path set above so the sibling import resolves)
import flake_rate  # noqa: E402

# FIXED-seed profile: deterministic (derandomize) so `just test` runs the exact
# same examples every time; no deadline so a busy shared host cannot turn a green
# property into a timing flake (the TASK-109 hazard); database=None so no
# `.hypothesis/` example DB is written or replayed (a stale replayed failure would
# be its own non-determinism, the same class as a proptest regressions file).
settings.register_profile(
    "check", max_examples=200, derandomize=True, deadline=None, database=None
)
# FREE-seed profile: fresh entropy + many examples for deliberate exploration.
settings.register_profile(
    "explore", max_examples=2000, derandomize=False, deadline=None, database=None
)

# Printable-ASCII characters exclude every line boundary splitlines() honours
# (\n \r \v \f \x1c-\x1e and the unicode Zl/Zp) and every other control char, so
# a value drawn from here survives a format -> parse round trip through the
# newline-delimited narinfo grammar.
_ASCII_TEXT = st.characters(codec="ascii", exclude_categories=("Cc",))
# narinfo keys are alphanumeric here: no ": " (so the parser's first-separator
# split is unambiguous) and non-empty (so the line is never blank-skipped).
_NARINFO_KEY = st.text(
    alphabet=st.characters(codec="ascii", categories=("Lu", "Ll", "Nd")),
    min_size=1,
    max_size=12,
)
_NARINFO_VALUE = st.text(alphabet=_ASCII_TEXT, max_size=40)


# --- Property 1: flake_rate.classify is FAIL-CLOSED (the 127-as-green trap) ---


@given(exit_code=st.integers(min_value=-8, max_value=300), output=st.text())
@example(exit_code=0, output="test result: ok")  # the only PASS shape
@example(exit_code=127, output="bash: cargo: command not found")  # the trap
@example(exit_code=101, output="test result: FAILED. 1 failed;")
def prop_classify_pass_iff_exit_zero(exit_code: int, output: str) -> None:
    """The SAFETY direction: classify may NEVER return PASS unless exit == 0.

    An independent claim, not a restatement: the impl's first line maps exit 0 ->
    PASS, but the property that matters is the CONVERSE (a non-zero exit - 127 for
    a missing binary, 101 for a real failure - must never be laundered into a
    green), which is the invariant the whole flake gate rests on.
    """
    verdict = flake_rate.classify(exit_code, output)
    if exit_code == 0:
        assert verdict == flake_rate.PASS, (exit_code, verdict)
    else:
        assert verdict != flake_rate.PASS, (exit_code, output, verdict)


# --- Property 2: narinfo parse . format is a ROUND TRIP ----------------------


@given(pairs=st.lists(st.tuples(_NARINFO_KEY, _NARINFO_VALUE), max_size=8))
@example(pairs=[("StorePath", "/nix/store/x"), ("NarSize", "4096")])
def prop_narinfo_parse_after_format_is_identity(
    pairs: list[tuple[str, str]],
) -> None:
    """parse_narinfo(format_narinfo(pairs)) == pairs, order and all.

    A genuine round trip, not a restatement of either function: it constrains the
    two to agree at the byte level, and order preservation is load-bearing (the
    gate rewrites narinfos, and a reordered file is an uncontrolled second diff
    from the pristine fixture, breaking the signature fingerprint).
    """
    text = fixturelib.format_narinfo(pairs)
    assert fixturelib.parse_narinfo(text) == pairs


# --- Property 3: narinfo parse is FAIL-CLOSED on a malformed line ------------


@given(
    line=st.text(
        alphabet=st.characters(codec="ascii", categories=("Lu", "Ll", "Nd")),
        min_size=1,
        max_size=20,
    )
)
@example(line="NoSeparatorHere")
def prop_narinfo_rejects_a_line_without_a_separator(line: str) -> None:
    """A non-blank line with no ": " separator must RAISE, never silently parse.

    The alphanumeric alphabet guarantees the line is non-empty and carries no
    ": ", so a compliant parser cannot make sense of it. Silently dropping such a
    line (the tempting "be liberal" mistake) would let a corrupt narinfo through;
    the parser must fail closed.
    """
    try:
        fixturelib.parse_narinfo(line)
    except ValueError:
        return
    raise AssertionError(f"parse_narinfo accepted a separator-less line {line!r}")


PROPERTIES = (
    prop_classify_pass_iff_exit_zero,
    prop_narinfo_parse_after_format_is_identity,
    prop_narinfo_rejects_a_line_without_a_separator,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="fixed seed + bounded examples (deterministic; the default)",
    )
    mode.add_argument(
        "--explore",
        action="store_true",
        help="free seed + many examples (exploration mode, `just prop`)",
    )
    args = parser.parse_args()

    profile = "explore" if args.explore else "check"
    settings.load_profile(profile)

    for prop in PROPERTIES:
        # A falsification raises here (hypothesis prints the shrunk reproducer),
        # so an uncaught raise is exactly the non-zero exit the gate needs.
        prop()

    print(
        f"prop_tests: ok ({len(PROPERTIES)} properties, {profile} profile) - "
        "classify fail-closed, narinfo round-trip, narinfo fail-closed"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
