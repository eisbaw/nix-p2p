#!/usr/bin/env python3
"""Re-derive the task-48 golden vectors from the fixture and prove they match.

The task-48 freeze pins the addressed unit: RawNarV1 = the exact
`nix-store --dump <path>` byte stream (the uncompressed NAR), and the addressed
unit is BLAKE3(RawNarV1) with NO domain separation, encoded `blake3:<hex>`. The
committed golden file (daemon/tests/golden/raw_nar_v1.json) records that digest
for a fixed fixture path. This script is the "a second implementation matches
byte-for-byte" half of AC#1: it INDEPENDENTLY recomputes BLAKE3 over the actual
fixture bytes with the stock `blake3` module and asserts equality with the
committed golden. A wrong hashing recipe (keyed, domain-separated) or a wrong
encoding fails here.

Why this is a script and not a cargo test: it needs the generated fixture NAR
bytes, which are absent in the Nix build sandbox and which a `.rs` may not even
name (scripts/check-source-guard.py). The sandbox-safe half - that our own
hasher reproduces the recipe vectors, and that the committed strings are
canonical - lives in daemon/tests/golden_vectors.rs. Both halves read the SAME
golden JSON, so they cannot disagree about what the golden value is.

The recipe vectors are checked too (empty input -> the published af1349b9...
vector), which pins plain unkeyed BLAKE3 with no dependence on the fixture: if
the installed `blake3` were somehow a keyed variant, this catches it before the
fixture comparison and the whole run is meaningless.

Fixtures-absent polarity (task-53). The generated fixture NAR bytes are NOT
committed; they exist only after `just fixtures`. The `just test` gate depends
on `fixtures`, so at the gate they are always present. If they are absent the
addressed-unit byte cannot be value-checked - and a silent "nothing proven"
skip is a fail-OPEN gate. So the DEFAULT is fail-CLOSED: absent fixtures exit 1
(a real failure), never a soft skip. Exit 2 (the "nothing proven" soft-skip) is
OPT-IN via `--allow-missing-fixtures`, for a context where the tree is
intentionally absent (a Nix build sandbox or a bare manual run). The recipe
vectors and the committed golden JSON are fixture-FREE and always fail-closed
regardless of the flag - the flag only excuses the generated fixture tree.

Exit codes: 0 all vectors matched; 1 a vector mismatched, a fixture is present
but wrong, OR fixtures are absent in the default (required) context - all real
failures; 2 fixtures are intentionally absent AND --allow-missing-fixtures was
given, so nothing was proven (opt-in soft-skip only).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import blake3

import fixturelib as fx

GOLDEN_PATH = Path("daemon") / "tests" / "golden" / "raw_nar_v1.json"


def fail(message: str, code: int = 1) -> None:
    sys.stdout.flush()
    print(f"check-golden-vectors: FAIL - {message}", file=sys.stderr)
    raise SystemExit(code)


def ok(message: str) -> None:
    print(f"check-golden-vectors: ok - {message}", flush=True)


def missing_fixtures(message: str, *, allow_missing: bool) -> None:
    """The generated fixture tree/bytes are absent.

    Fail-CLOSED by default (exit 1): in the gate the fixtures are a dependency,
    so absence means the addressed-unit byte went un-checked and the gate must
    NOT pass. Only when the caller explicitly opts in with
    `--allow-missing-fixtures` - a Nix build sandbox or a bare manual run where
    the tree is intentionally absent - do we soft-skip (exit 2, nothing proven).
    """
    if allow_missing:
        print(
            f"check-golden-vectors: SKIP (nothing proven) - {message}\n"
            "  --allow-missing-fixtures given: the generated fixture tree is "
            "intentionally absent here (Nix sandbox / bare manual run).",
            file=sys.stderr,
        )
        raise SystemExit(2)
    fail(
        f"{message}\n"
        "The fixture tree is REQUIRED here but absent, so the addressed-unit "
        "golden byte was NOT value-checked. This gate is fail-CLOSED: run "
        "`just fixtures` first. Pass --allow-missing-fixtures ONLY for a context "
        "where the tree is intentionally absent (a soft-skip, exit 2).",
        code=1,
    )


def blake3_string(data: bytes) -> str:
    """The canonical `blake3:<64 hex>` form of plain unkeyed BLAKE3 over `data`."""
    return "blake3:" + blake3.blake3(data).hexdigest()


def check_recipe_vectors(golden: dict) -> None:
    """Fixture-free recipe pin: the installed blake3 must reproduce the vectors."""
    vectors = golden["recipe_vectors"]
    if not vectors:
        fail("golden file has no recipe_vectors to pin the recipe")
    for vector in vectors:
        got = blake3_string(vector["input_utf8"].encode())
        if got != vector["blake3"]:
            fail(
                f"recipe vector for input {vector['input_utf8']!r} mismatched:\n"
                f"  committed: {vector['blake3']}\n  recomputed: {got}\n"
                "The frozen recipe is PLAIN UNKEYED BLAKE3 with no domain "
                "separation; a mismatch means the recipe or the tool is wrong."
            )
    ok(f"{len(vectors)} recipe vector(s) reproduced (plain unkeyed BLAKE3)")


def fixture_entry(manifest: dict, attr: str) -> dict:
    for entry in manifest["paths"]:
        if entry["attr"] == attr:
            return entry
    fail(
        f"fixture manifest has no path with attr={attr!r}; the golden vector "
        "names a path the current workload does not contain. If the workload was "
        "bumped, re-derive and re-freeze the golden file deliberately."
    )
    raise AssertionError("unreachable")  # fail() raises; keeps type-checkers happy


def check_fixture_vector(
    golden: dict, generation: Path, manifest: dict, *, allow_missing: bool
) -> None:
    """Recompute the addressed unit from the real fixture NAR and match the golden.

    The path is deliberately an UNCOMPRESSED one: its served `.nar` IS the raw
    NAR (== `nix-store --dump`), so BLAKE3 of the file is BLAKE3(RawNarV1) with no
    decompression step that could silently change the unit. That is the whole
    NarSize-vs-FileSize trap the freeze guards against.
    """
    fixture = golden["fixture"]
    if manifest["workload_version"] != fixture["workload_version"]:
        fail(
            "workload version drift: golden was frozen against "
            f"{fixture['workload_version']!r} but the fixture is "
            f"{manifest['workload_version']!r}. Re-derive and re-freeze the golden "
            "vectors deliberately before comparing."
        )

    entry = fixture_entry(manifest, fixture["attr"])
    if entry["compression"] != "none":
        fail(
            f"golden fixture path {fixture['attr']!r} is compressed "
            f"({entry['compression']}); its .nar would NOT be the raw NAR. The "
            "addressed unit is the UNCOMPRESSED dump - pick an uncompressed path."
        )
    if entry["nar_hash"] != fixture["nar_hash"]:
        fail(
            "NarHash drift: manifest says "
            f"{entry['nar_hash']!r}, golden says {fixture['nar_hash']!r}. The "
            "signed trust anchor moved; the golden is stale."
        )

    nar_path = generation / "cache" / entry["url"]
    if not nar_path.is_file():
        missing_fixtures(
            f"fixture NAR {nar_path} is absent; regenerate with `just fixtures`.",
            allow_missing=allow_missing,
        )
    raw = nar_path.read_bytes()

    if len(raw) != fixture["raw_nar_len"]:
        fail(
            f"raw NAR length mismatch: file is {len(raw)} bytes, golden pins "
            f"{fixture['raw_nar_len']}. The addressed unit's bytes changed."
        )
    # NAR magic sanity: a genuine `nix-store --dump` stream begins with the
    # length-prefixed "nix-archive-1". Cheap guard that we hashed a NAR, not some
    # other blob that happens to have the right length.
    if b"nix-archive-1" not in raw[:32]:
        fail(
            f"{nar_path} does not begin with the NAR magic 'nix-archive-1'; it is "
            "not a raw NAR dump, so hashing it would freeze the wrong unit."
        )

    got = blake3_string(raw)
    if got != fixture["blake3"]:
        fail(
            "ADDRESSED-UNIT MISMATCH (the freeze bite):\n"
            f"  committed golden: {fixture['blake3']}\n"
            f"  recomputed:       {got}\n"
            "A second derivation did NOT match byte-for-byte. Either the fixture "
            "bytes changed or the golden is wrong; both are freeze violations."
        )

    # INDEPENDENTLY compute the NarHash from the raw NAR bytes rather than trusting
    # the manifest (codex finding 4): sha256(raw) in Nix base-32. This catches a
    # wrong manifest NarHash instead of comparing the manifest to itself, and it
    # cross-checks the Rust nixbase32 encoder against Python's on the same digest.
    computed_narhash = "sha256:" + fx.nix_base32(hashlib.sha256(raw).digest())
    for label, expected in (
        ("golden", fixture["nar_hash"]),
        ("manifest", entry["nar_hash"]),
    ):
        if computed_narhash != expected:
            fail(
                f"NarHash MISMATCH vs {label} (finding 4):\n"
                f"  {label} says: {expected}\n"
                f"  sha256(raw NAR) is: {computed_narhash}\n"
                "The NarHash is derived independently from the bytes here, so a "
                "wrong recorded value is caught, not trusted."
            )

    ok(
        f"addressed unit re-derived from {entry['url']} "
        f"({len(raw)} raw NAR bytes): BLAKE3 matches the committed golden "
        f"{fixture['blake3']}; independently-computed NarHash {computed_narhash} "
        "matches golden and manifest"
    )


def run(repo: Path, *, allow_missing: bool) -> int:
    golden_file = repo / GOLDEN_PATH
    if not golden_file.is_file():
        # The golden JSON is COMMITTED - present in the repo, the Nix sandbox src,
        # and the gate alike. Its absence is a broken checkout, not the
        # intentionally-absent generated tree, so it fail-closes regardless.
        fail(f"golden file not found at {golden_file}")
    golden = json.loads(golden_file.read_text())

    # Fixture-free half first: if the recipe pin fails, the fixture comparison is
    # meaningless, so say so before touching the tree. This half is committed-data
    # only and ALWAYS fail-closed - --allow-missing-fixtures never excuses it.
    check_recipe_vectors(golden)

    out_root = repo / "fixtures" / "out"
    if not out_root.is_dir():
        missing_fixtures(
            f"no fixture publication root at {out_root} - generate it first:\n"
            "  nix develop -c just fixtures",
            allow_missing=allow_missing,
        )
    generation = fx.resolve_current(out_root)
    if generation is None or not (generation / "manifest.json").is_file():
        missing_fixtures(
            f"{out_root}/current does not resolve to a generation with a "
            "manifest.json; regenerate with `just fixtures`.",
            allow_missing=allow_missing,
        )
    manifest = json.loads((generation / "manifest.json").read_text())

    check_fixture_vector(golden, generation, manifest, allow_missing=allow_missing)
    return 0


def _self_test() -> int:
    """Prove the fixtures-absent polarity by construction (task-53 bites 2 & 3).

    Builds a throwaway repo whose committed golden JSON is valid but whose
    generated fixture tree is ABSENT, then asserts:
      - default (required) context   -> exit 1 (fail-CLOSED, NOT the exit-2 skip)
      - --allow-missing-fixtures      -> exit 2 (opt-in soft-skip preserved)
      - a wrong recipe vector         -> exit 1 EVEN with --allow-missing-fixtures
        (the fixture-free recipe half always fail-closes).
    Reverting missing_fixtures() to a soft exit-2 default reddens the first case.
    """
    import tempfile

    def golden_with(recipe_ok: bool) -> dict:
        # A real, verifiable empty-input vector pins plain unkeyed BLAKE3.
        empty = blake3_string(b"")
        return {
            "recipe_vectors": [
                {
                    "input_utf8": "",
                    "blake3": empty if recipe_ok else "blake3:" + "0" * 64,
                }
            ],
            # Never reached when the tree is absent, but must be well-formed.
            "fixture": {
                "workload_version": "x",
                "attr": "x",
                "nar_hash": "sha256:x",
                "raw_nar_len": 0,
                "blake3": "blake3:" + "0" * 64,
            },
        }

    def attempt(golden: dict, *, allow_missing: bool) -> int:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            gp = repo / GOLDEN_PATH
            gp.parent.mkdir(parents=True, exist_ok=True)
            gp.write_text(json.dumps(golden))
            # Deliberately DO NOT create fixtures/out: the tree is absent.
            try:
                run(repo, allow_missing=allow_missing)
            except SystemExit as exc:
                return int(exc.code or 0)
            return 0

    checks = [
        ("absent + required -> fail-closed exit 1", golden_with(True), False, 1),
        ("absent + --allow-missing -> soft-skip exit 2", golden_with(True), True, 2),
        ("bad recipe always fail-closed exit 1", golden_with(False), True, 1),
    ]
    failures = []
    for label, golden, allow_missing, want in checks:
        got = attempt(golden, allow_missing=allow_missing)
        status = "ok" if got == want else "FAIL"
        print(f"self-test: {status} - {label} (want {want}, got {got})")
        if got != want:
            failures.append(label)
    if failures:
        print(f"check-golden-vectors: self-test FAILED: {failures}", file=sys.stderr)
        return 1
    print("check-golden-vectors: self-test ok - fixtures-absent polarity holds")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-missing-fixtures",
        action="store_true",
        help=(
            "opt into a soft-skip (exit 2, nothing proven) when the generated "
            "fixture tree is absent, for a context where it is intentionally "
            "absent (Nix sandbox / bare manual run). DEFAULT is fail-closed."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the in-script fixtures-absent polarity bites and exit.",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    return run(fx.repo_root(), allow_missing=args.allow_missing_fixtures)


if __name__ == "__main__":
    sys.exit(main())
