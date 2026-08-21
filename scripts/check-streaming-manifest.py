#!/usr/bin/env python3
"""Freeze-and-validate the TASK-62 streaming acceptance manifest (AC#8).

WHAT THIS GUARDS. `artifacts/task62-streaming-manifest-v1.json` PRE-REGISTERS the
integer/rational acceptance thresholds for the store-and-forward streaming change
(TASK-62 AC#1-#7) BEFORE any streaming code is written or measured. The whole point
of pre-registration is anti-p-hacking: a threshold that can be added, deleted, or
loosened AFTER the measurement is not a threshold, it is a rationalisation. This
guard makes that tampering a loud, reviewable failure instead of a silent edit.

It is the ENFORCEMENT half of AC#8. The manifest DATA was frozen in commit
`ae68554` (2026-08-19), strictly before the streaming refactor exists; this script
is what mechanically holds it frozen. Without it the "freeze" is only prose.

THREE INDEPENDENT ORACLES, any of which FAILS the gate (mirrors the JCS-artifact
pattern in daemon-core/src/profile_budget.rs, TASK-120 AC#10):

  1. CONTENT-HASH FREEZE (the anti-post-hoc bite). We recompute
     BLAKE3(JCS(manifest)) and compare it to the checked-in EXPECTED_MANIFEST_HASH.
     ANY content drift -- a threshold numerator nudged from 1 to 3, a whole gate
     added or deleted after seeing a red measurement -- changes the canonical form
     and fails closed. Loosening a frozen number post-result is then a deliberate,
     reviewable one-line re-freeze diff (bump this constant) that a reviewer sees,
     NOT an invisible tweak. The hash proves IDENTITY/immutability; it does NOT
     attest that a human approved the numbers (a content hash cannot do that) and
     it does NOT by itself prove the freeze predated measurement -- that half rests
     on git provenance (the freeze commit's timestamp), stated here honestly.

  2. STRUCTURAL COMPLETENESS (the anti-MISSING bite). Every required threshold and
     sample-size field must be PRESENT and correctly typed. A manifest that simply
     omits `thresholds.ac1_ttfb` (so no TTFB bite can ever fire) is rejected. The
     required schema is REQUIRED_SCHEMA below.

  3. NO FLOAT AS DECISION AUTHORITY (owner standing rule; memory
     `no-floats-integers-or-rationals`). Every NUMBER anywhere in the manifest must
     be an integer (ns, bytes, counts). Ratios are carried as an exact rational
     {"num": int, "den": int} with den > 0 and compared by cross-multiplication.
     A bare JSON float ANYWHERE in the document is a violation. Floats are permitted
     only INSIDE STRING values (the `*_display` / prose fields) where they are
     terminal, human-facing renderings that never gate. This is the JSON-data
     analogue of scripts/check-no-floats.py (which scans Python gate SOURCE, not a
     data artifact) and of profile_budget.rs's `every_field_is_an_integer_no_floats`.

SCOPE / HONEST LIMITS. This validates the FROZEN CONTRACT. It does NOT run any
streaming measurement and cannot: the streaming refactor (AC#1-#7) does not exist
yet. The thresholds here are numbers-to-meet, not measured results. The
KNOWN TENSION the manifest itself flags -- sizeaxis.py/scalefit.py compute the RSS
slope CI in Python float -- is an IMPLEMENTATION OBLIGATION carried on the future
measurement gate (reduce the float CI-high to an outward-rounded rational and decide
by cross-multiplication); it is not something this contract-level guard can enforce
before that code exists. See freeze.no_float_decision_authority in the manifest.

Run from the workspace root. Exit codes mirror scripts/check-no-floats.py:
  0  clean   -- self-test green (guard bites) AND the frozen manifest verifies
  1  violation -- the manifest drifted, is missing a field, or carries a float
                  in a decision position
  2  cannot-check -- the self-test is not trustworthy (the guard cannot be proven
                  to bite), or the manifest file is unreadable; nothing was proven
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

import blake3

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "artifacts" / "task62-streaming-manifest-v1.json"

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_CANNOT_CHECK = 2

# The frozen content hash: BLAKE3(JCS(manifest)), lowercase hex. Pins the CANONICAL
# JCS content of artifacts/task62-streaming-manifest-v1.json as frozen in commit
# ae68554 (2026-08-19), before the streaming refactor exists. A deliberate re-freeze
# (a threshold genuinely revised for a stated reason, before measurement) recomputes
# this via `check-streaming-manifest.py --print-hash` and updates the constant -- a
# reviewable one-line diff. Any UNdeclared drift fails closed (HashDrift). It proves
# the content is unchanged since the freeze; it does NOT attest human authorization
# and does NOT by itself prove the freeze predated measurement (git provenance does).
EXPECTED_MANIFEST_HASH = (
    "b98c41d7b91c6d130e0230df669c8a4753d25251c7696acbd24dbab7fa7af17b"
)


# --- canonicalization + content hash -----------------------------------------


def canonicalize(value: Any) -> bytes:
    """The JCS-subset canonical byte form: compact JSON, object keys sorted
    lexicographically, UTF-8. Exact for the integer/ASCII-string/object/array subset
    this manifest lives in (RFC 8785's float-formatting clause is vacuous here by
    construction -- there are no float numbers; the no-float walk re-asserts that).
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def content_hash(value: Any) -> str:
    """BLAKE3(JCS(value)), lowercase hex -- the freeze identity."""
    return blake3.blake3(canonicalize(value)).hexdigest()


# --- the required schema (anti-MISSING) --------------------------------------
#
# Each leaf names the KIND a required field must have. Presence + type only: the
# EXACT values are pinned by the content hash, so hardcoding them here would
# duplicate the manifest's single source of truth (the manifest IS the SSOT for the
# numbers). "rational" => {"num": int, "den": int > 0}. "list>=N" => a list of at
# least N integers. This is the anti-MISSING bite: drop a required gate and its path
# is reported absent.
REQUIRED_SCHEMA: dict[str, Any] = {
    "schema_version": "int",
    "task": "str",
    "artifact": "str",
    "freeze": {
        "frozen_before_measurement": "true",
        "frozen_at_commit": "str",
        "rule": "str",
        "no_float_decision_authority": "str",
    },
    "units": {
        "time": "str",
        "ram": "str",
        "nar": "str",
        "ratios": "str",
    },
    "stream_chunk_bytes": "int",
    "sample_sizes": {
        "rss_slope_grid_mib": "intlist>=5",
        "rss_size_repeats_min": "int",
        "ttfb_repeats_per_arm_min": "int",
        "ttfb_size_independence_contrast_mib": "int",
        "inflight_sizes_mib": "intlist>=2",
    },
    "wall_clock_prediction": {
        "recorded_up_front": "true",
        "claim": "str",
        "so": "str",
    },
    "thresholds": {
        # AC#1 TTFB-to-total: streaming passes iff ttfb*den <= total*num (<= 1/4);
        # the buffering counterfactual must FAIL (>= 3/4). Both rationals required.
        "ac1_ttfb": {
            "measured_at": "str",
            "pass_rule": "str",
            "pass_ratio": "rational",
            "bite_rule": "str",
            "buffering_bite_ratio": "rational",
            "unbounded_channel_trap": "str",
        },
        # AC#2/#7 backpressure: integer in-flight byte ceiling, size-independent.
        "ac2_ac7_backpressure_inflight": {
            "counter": "str",
            "counter_placement_obligation": "str",
            "max_inflight_fetch_bytes_ram": "int",
            "pass_rule": "str",
            "size_independence_ratio": "rational",
            "bite_rule": "str",
        },
        # AC#7 cancellation/disconnect/HEAD/timeout: integer-ns teardown deadline.
        "ac7_cancellation": {
            "triggers": "strlist>=1",
            "cancellation_deadline_ns": "int",
            "pass_rule": "str",
            "bite_rule": "str",
        },
        # AC#5 RSS slope: the fitted-slope CI gate (rational), grounded in TASK-65.
        "ac5_rss_slope": {
            "model_key": "str",
            "pass_rule": "str",
            "gate_ci_high_decouple": "rational",
            "sanity_note_ci_high_excludes_one": "rational",
            "decision_representation": "str",
            "bite_rule": "str",
        },
        # AC#4 framing: both Content-Length and chunked paths declared.
        "ac4_framing": {
            "correlated_path_expected_size_some": "str",
            "cold_start_path_expected_size_none": "str",
            "teardown": "str",
            "pass_rule": "str",
        },
        # A/A + noise: the noise floor so "wall clock unchanged" reads as confirmed.
        "a_a_noise": {
            "a_a_band_ratio": "rational",
            "a_a_rule": "str",
            "separation_rule": "str",
            "repeats_min_per_arm": "int",
        },
    },
    "oracles_must_bite": "str",
}


def _is_int(value: Any) -> bool:
    """A JSON integer: a Python int that is NOT a bool (bool subclasses int)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _check_kind(value: Any, kind: str, path: str, out: list[str]) -> None:
    """Append a violation to `out` if `value` at `path` is absent-shaped or the
    wrong KIND. Called only when the key is present; absence is handled by caller."""
    if kind == "int":
        if not _is_int(value):
            out.append(f"{path}: expected an integer, got {type(value).__name__}")
    elif kind == "str":
        if not (isinstance(value, str) and value.strip()):
            out.append(f"{path}: expected a non-empty string")
    elif kind == "true":
        if value is not True:
            out.append(f"{path}: expected boolean true, got {value!r}")
    elif kind == "rational":
        _check_rational(value, path, out)
    elif kind.startswith("intlist>="):
        minimum = int(kind.split(">=", 1)[1])
        if not isinstance(value, list) or len(value) < minimum:
            out.append(f"{path}: expected a list of >= {minimum} integers")
        elif not all(_is_int(x) for x in value):
            out.append(f"{path}: every list element must be an integer")
    elif kind.startswith("strlist>="):
        minimum = int(kind.split(">=", 1)[1])
        if not isinstance(value, list) or len(value) < minimum:
            out.append(f"{path}: expected a list of >= {minimum} strings")
        elif not all(isinstance(x, str) and x.strip() for x in value):
            out.append(f"{path}: every list element must be a non-empty string")
    else:  # pragma: no cover - a typo in REQUIRED_SCHEMA, fail loudly
        out.append(f"{path}: INTERNAL - unknown schema kind {kind!r}")


def _check_rational(value: Any, path: str, out: list[str]) -> None:
    """A decision rational is EXACTLY {"num": int, "den": int} with den > 0. This is
    the no-float-as-decision-authority guarantee for a ratio: it can never be a bare
    float, and it is compared by cross-multiplication, never by dividing to a float.
    """
    if not isinstance(value, dict):
        out.append(f"{path}: expected an exact rational {{num, den}}, got a non-object")
        return
    if set(value.keys()) != {"num", "den"}:
        out.append(
            f"{path}: a rational must have exactly keys num, den; got {sorted(value.keys())}"
        )
        return
    if not _is_int(value["num"]):
        out.append(f"{path}.num: rational numerator must be an integer")
    if not _is_int(value["den"]):
        out.append(f"{path}.den: rational denominator must be an integer")
    elif value["den"] <= 0:
        out.append(f"{path}.den: rational denominator must be > 0 (got {value['den']})")


def _walk_schema(node: Any, spec: Any, path: str, out: list[str]) -> None:
    """Recursively assert every required path in `spec` is present + correctly typed
    in `node`. Extra keys are NOT rejected here -- the content hash pins the exact
    content (additions included), so an added post-hoc gate is caught by HashDrift,
    while THIS pass guarantees nothing required is missing."""
    if isinstance(spec, dict):
        if not isinstance(node, dict):
            out.append(f"{path or '<root>'}: expected an object")
            return
        for key, subspec in spec.items():
            child_path = f"{path}.{key}" if path else key
            if key not in node:
                out.append(f"{child_path}: REQUIRED field is missing")
                continue
            _walk_schema(node[key], subspec, child_path, out)
    else:
        _check_kind(node, spec, path, out)


# --- no float anywhere as a number (owner rule) ------------------------------


def _no_float_violations(node: Any, path: str, out: list[str]) -> None:
    """Every NUMBER in the document must be an integer. A bare float as a JSON number
    ANYWHERE is a decision-authority violation (it could silently become a gate
    input). Floats living inside STRING values are display/prose and are not numbers,
    so they are never visited here -- exactly the owner rule's terminal-display
    carve-out."""
    if isinstance(node, float):
        out.append(
            f"{path or '<root>'}: float number {node!r} (no float may be a decision authority)"
        )
    elif isinstance(node, dict):
        for key, child in node.items():
            _no_float_violations(child, f"{path}.{key}" if path else str(key), out)
    elif isinstance(node, list):
        for i, child in enumerate(node):
            _no_float_violations(child, f"{path}[{i}]", out)
    # int/bool/str/None carry no float number.


# --- the composed validation -------------------------------------------------


def validate(manifest: Any) -> list[str]:
    """All CONTENT checks (schema completeness + typing + no-float + rational
    discipline). Does NOT check the freeze hash -- that is verify_frozen, which needs
    the raw canonical form and the expected constant. Returns violation lines."""
    out: list[str] = []
    _walk_schema(manifest, REQUIRED_SCHEMA, "", out)
    _no_float_violations(manifest, "", out)
    return out


def verify_frozen(manifest: Any, expected_hash: str) -> list[str]:
    """The freeze bite: recompute BLAKE3(JCS(manifest)) and compare to the frozen
    constant. A mismatch means the pre-registered content drifted (a threshold edited
    or a gate added/deleted after freeze) -- fail closed."""
    actual = content_hash(manifest)
    if actual != expected_hash:
        return [
            f"content-hash drift: frozen {expected_hash}, got {actual} "
            "(a pre-registered threshold was added, deleted, or edited; if this is a "
            "deliberate PRE-MEASUREMENT re-freeze, update EXPECTED_MANIFEST_HASH in a "
            "reviewable diff -- never after seeing a measurement result)"
        ]
    return []


# --- self-test: prove every oracle bites (no external files needed) ----------


def _load_reference() -> Any:
    """The real frozen manifest, as the base the self-test mutates. If it does not
    load, the self-test cannot construct its bite cases -- that is a cannot-check."""
    return json.loads(MANIFEST_PATH.read_text())


def self_test() -> list[str]:
    """Prove each oracle FAILS on a plausible tamper and PASSES clean, using in-memory
    mutations of the real manifest (the check-no-floats synthetic-source discipline).
    Returns failure lines; an empty list means the guard is trustworthy."""
    failures: list[str] = []
    try:
        base = _load_reference()
    except (OSError, json.JSONDecodeError) as error:
        return [f"could not load the reference manifest to build bite cases: {error}"]

    def expect_flagged(label: str, violations: list[str]) -> None:
        if not violations:
            failures.append(
                f"BITE MISSING: '{label}' should have been flagged but passed clean"
            )

    def expect_clean(label: str, violations: list[str]) -> None:
        if violations:
            failures.append(
                f"FALSE POSITIVE: '{label}' should be clean, got {violations}"
            )

    # 0. The real manifest is clean AND its hash matches the freeze.
    expect_clean("frozen manifest content", validate(base))
    expect_clean("frozen manifest hash", verify_frozen(base, EXPECTED_MANIFEST_HASH))

    # 1. anti-MISSING: delete a whole gate -> its bite can never fire -> rejected.
    m = copy.deepcopy(base)
    del m["thresholds"]["ac1_ttfb"]
    expect_flagged("a deleted required gate (thresholds.ac1_ttfb)", validate(m))

    # 2. no-float: a bare float in a decision position (pass_ratio as 0.25).
    m = copy.deepcopy(base)
    m["thresholds"]["ac1_ttfb"]["pass_ratio"] = 0.25
    expect_flagged("a float where a decision rational belongs", validate(m))

    # 3. no-float, buried: a float inside an otherwise-valid integer field.
    m = copy.deepcopy(base)
    m["thresholds"]["ac7_cancellation"]["cancellation_deadline_ns"] = 2000000000.0
    expect_flagged("a float in an integer-ns deadline field", validate(m))

    # 4. rational discipline: a zero denominator (undefined comparison).
    m = copy.deepcopy(base)
    m["thresholds"]["a_a_noise"]["a_a_band_ratio"]["den"] = 0
    expect_flagged("a rational with a zero denominator", validate(m))

    # 5. the freeze flag itself flipped off.
    m = copy.deepcopy(base)
    m["freeze"]["frozen_before_measurement"] = False
    expect_flagged("frozen_before_measurement flipped to false", validate(m))

    # 6. THE ANTI-P-HACKING BITE: a threshold LOOSENED post-hoc while staying
    #    structurally valid (num 1 -> 3). validate() alone stays clean -- only the
    #    content-hash freeze catches it, which is the whole reason the hash exists.
    m = copy.deepcopy(base)
    m["thresholds"]["ac1_ttfb"]["pass_ratio"]["num"] = 3
    expect_clean("a post-hoc-loosened ratio is STRUCTURALLY valid", validate(m))
    expect_flagged(
        "a post-hoc-loosened ratio drifts the freeze hash",
        verify_frozen(m, EXPECTED_MANIFEST_HASH),
    )

    # 7. an ADDED post-hoc gate is structurally fine but drifts the hash.
    m = copy.deepcopy(base)
    m["thresholds"]["ac99_after_the_fact"] = {"pass_ratio": {"num": 9, "den": 10}}
    expect_flagged(
        "an added post-hoc gate drifts the freeze hash",
        verify_frozen(m, EXPECTED_MANIFEST_HASH),
    )

    # 8. the >=5 RSS-sample-size floor is load-bearing (TASK-65: a slope fit on <5
    #    points is unfalsifiable). Shrinking the grid below 5 is rejected.
    m = copy.deepcopy(base)
    m["sample_sizes"]["rss_slope_grid_mib"] = [8, 16, 32]
    expect_flagged("an under-5 RSS slope grid (unfalsifiable fit)", validate(m))

    return failures


# --- entry point -------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run only the self-test (prove the guard bites), then exit",
    )
    parser.add_argument(
        "--print-hash",
        action="store_true",
        help="print BLAKE3(JCS(manifest)) for a deliberate pre-measurement re-freeze",
    )
    args = parser.parse_args()

    if args.print_hash:
        try:
            manifest = json.loads(MANIFEST_PATH.read_text())
        except (OSError, json.JSONDecodeError) as error:
            print(f"cannot read manifest: {error}", file=sys.stderr)
            return EXIT_CANNOT_CHECK
        print(content_hash(manifest))
        return EXIT_OK

    # The self-test gates everything: an untrustworthy guard proves nothing.
    failures = self_test()
    if failures:
        for failure in failures:
            print(
                f"streaming-manifest guard self-test FAILED: {failure}", file=sys.stderr
            )
        print(
            "the guard is not trustworthy; the real manifest was not judged",
            file=sys.stderr,
        )
        return EXIT_CANNOT_CHECK

    if args.self_test:
        print(
            "streaming-manifest guard: self-test green (9 bite cases + clean controls)"
        )
        return EXIT_OK

    try:
        manifest = json.loads(MANIFEST_PATH.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(
            f"streaming-manifest: cannot read {MANIFEST_PATH}: {error}", file=sys.stderr
        )
        return EXIT_CANNOT_CHECK

    violations = validate(manifest) + verify_frozen(manifest, EXPECTED_MANIFEST_HASH)
    if violations:
        for violation in violations:
            print(f"streaming-manifest violation: {violation}", file=sys.stderr)
        return EXIT_VIOLATION

    print(
        "streaming-manifest: self-test green (guard bites); frozen manifest verifies "
        f"-- schema complete, no float in any decision field, BLAKE3(JCS)={EXPECTED_MANIFEST_HASH} "
        "matches the freeze (TASK-62 AC#8 pre-registration intact)"
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
