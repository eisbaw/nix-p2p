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

Exit codes: 0 all vectors matched, 1 a vector mismatched (a real freeze
violation), 2 the fixture tree or environment is missing so nothing was proven.
"""

from __future__ import annotations

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
        "bumped, re-derive and re-freeze the golden file deliberately.",
        code=2,
    )
    raise AssertionError("unreachable")  # fail() raises; keeps type-checkers happy


def check_fixture_vector(golden: dict, generation: Path, manifest: dict) -> None:
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
            "vectors deliberately before comparing.",
            code=2,
        )

    entry = fixture_entry(manifest, fixture["attr"])
    if entry["compression"] != "none":
        fail(
            f"golden fixture path {fixture['attr']!r} is compressed "
            f"({entry['compression']}); its .nar would NOT be the raw NAR. The "
            "addressed unit is the UNCOMPRESSED dump - pick an uncompressed path.",
            code=2,
        )
    if entry["nar_hash"] != fixture["nar_hash"]:
        fail(
            "NarHash drift: manifest says "
            f"{entry['nar_hash']!r}, golden says {fixture['nar_hash']!r}. The "
            "signed trust anchor moved; the golden is stale."
        )

    nar_path = generation / "cache" / entry["url"]
    if not nar_path.is_file():
        fail(
            f"fixture NAR {nar_path} is absent; regenerate with `just fixtures`.",
            code=2,
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
            "not a raw NAR dump, so hashing it would freeze the wrong unit.",
            code=2,
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
    ok(
        f"addressed unit re-derived from {entry['url']} "
        f"({len(raw)} raw NAR bytes): BLAKE3 matches the committed golden "
        f"{fixture['blake3']}, NarHash {fixture['nar_hash']}"
    )


def main() -> int:
    repo = fx.repo_root()
    golden_file = repo / GOLDEN_PATH
    if not golden_file.is_file():
        fail(f"golden file not found at {golden_file}", code=2)
    golden = json.loads(golden_file.read_text())

    # Fixture-free half first: if the recipe pin fails, the fixture comparison is
    # meaningless, so say so before touching the tree.
    check_recipe_vectors(golden)

    out_root = repo / "fixtures" / "out"
    if not out_root.is_dir():
        fail(
            f"no fixture publication root at {out_root} - generate it first:\n"
            "  nix develop -c just fixtures",
            code=2,
        )
    generation = fx.resolve_current(out_root)
    if generation is None or not (generation / "manifest.json").is_file():
        fail(
            f"{out_root}/current does not resolve to a generation with a "
            "manifest.json; regenerate with `just fixtures`.",
            code=2,
        )
    manifest = json.loads((generation / "manifest.json").read_text())

    check_fixture_vector(golden, generation, manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
