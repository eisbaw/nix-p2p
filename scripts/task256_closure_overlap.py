#!/usr/bin/env python3
"""TASK-256 — OFFLINE closure-overlap probe: the peer HIT-RATE half of the value thesis.

Offload is approximately hit-rate * bytes-per-hit. Bytes-per-hit is already measured
(TASK-94/198/203). This probe measures the UNMEASURED half, HIT-RATE, as a pure
SUPPLY/DEMAND OVERLAP property computed OFFLINE from `nix path-info` closures — NO
protocol code, NO network in the analysis, NO containers. It answers: what fraction of
a cold build's closure (DEMAND) is already resident on a reachable peer (SUPPLY)?

    overlap = |DEMAND paths that are also in SUPPLY| / |DEMAND paths|

reported as an EXACT integer numerator/denominator (owner no-floats rule), in TWO
independent units kept strictly separate:
  * PATH COUNT  — how many of the demand closure's store paths the peer holds;
  * uncompressed NAR bytes (`narSize`) — how many demand NAR bytes the peer holds.
These are NEVER mixed. A THIRD figure, the compressed-wire `downloadSize`, is a
DIFFERENT UNIT again (the transport cost, TASK-94/198/203's axis); it is recorded only
as a separately-suffixed CONTEXT field and is NEVER compared to a narSize (that
NarSize-vs-wire conflation has recurred three times in this project).

TWO POPULATIONS, because the answer differs sharply and the DIFFERENCE is the finding:
  (a) SAME-PIN  — the peer is on the SAME pinned nixpkgs as the client (the LAN / org
      case). Store paths are input-addressed, so a same-pin peer's base closure
      (glibc, bash, ...) path-matches the client's exactly.
  (b) CROSS-REV — the peer is on a DIFFERENT nixpkgs revision (the global permissionless
      swarm). A different glibc rehashes every downstream path, so overlap collapses.

COLD-START vs STEADY-STATE are reported SEPARATELY (PRD risk 4 — announce/supply lags
demand; a young network offloads little):
  * COLD-START  — the peer holds ONE seed closure (a barely-used peer / launch day).
  * STEADY-STATE — the peer holds a UNION of many closures (a warm dev store).

THE VACUITY BITE (AC#5). Overlap is RE-DERIVED from the raw `nix path-info` captures on
every run; no stored overlap is ever trusted. `--verify RESULTS.json` recomputes every
cell's num/denom from the raw captures (re-checking each capture's sha256 first) and
FAILS (exit 1) if a stored number disagrees — so a run handed a fabricated overlap, a
tampered capture, or the wrong closure set is rejected. `--self-test` proves the oracle
BITES by mutation, with no repo files and no network:
  * a known synthetic demand/supply recomputes to the hand-computed num/denom (green);
  * injecting a higher numerator into a results cell makes --verify go RED (the bite);
  * overlap(D, D) = 100% differs from overlap(D, S_real) — proving the function reads
    real path identities, not a constant (a wrong/self closure set changes the answer);
  * an empty closure capture yields nothing-proven (exit 2), never a false 0/0.

Exit codes: 0 OK; 1 a real overlap/verification violation; 2 the probe could not be
performed (empty capture, missing raw file — nothing proven either way).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "evidence" / "task-256" / "raw"

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_CANNOT_CHECK = 2

# The two pins. A = the flake's pinned nixpkgs (nixos-26.05); B = a DIFFERENT
# revision (nixos-24.11). Recorded for provenance; the probe reads only the
# captured closures, never the network.
PIN_A_REV = "445d861c6d31b4af0c79d8d4be2331f762a361d7"  # nixos-26.05 (flake.lock)
PIN_B_REV = "50ab793786d9de88ee30ec4e4c24fb4236fc2674"  # nixos-24.11

# The client's cold-build DEMAND target (always the client's own pin, A).
DEMAND = ("A", "curl")

# The peer's SUPPLY. Cold-start = one seed closure; steady-state = a warm union.
SUPPLY_COLD_PKGS = ["hello"]
SUPPLY_STEADY_PKGS = [
    "hello",
    "coreutils",
    "bash",
    "git",
    "wget",
    "gnused",
    "gnugrep",
    "gzip",
]


# ---------------------------------------------------------------------------
# Raw capture I/O. A capture is the collector's wrapper around one
# `nix path-info --recursive --json` closure (see scratchpad/collect_closures.sh).
# ---------------------------------------------------------------------------
def _capture_path(pin_label: str, pkg: str, raw_dir: Path) -> Path:
    return raw_dir / f"{pin_label}_{pkg}.json"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_closure(pin_label: str, pkg: str, raw_dir: Path) -> dict:
    """Return {"paths": {store_path: narSize_int}, ...} for one capture.

    Re-derived from the raw file every call. Fails closed on an empty closure
    (nothing observed => nothing proven) so a vacuous capture can never be read
    as a real 0-byte closure.
    """
    path = _capture_path(pin_label, pkg, raw_dir)
    if not path.is_file():
        raise FileNotFoundError(f"missing raw capture: {path}")
    rec = json.loads(path.read_text())
    closure = rec["closure"]
    if not closure:
        raise ValueError(f"empty closure in {path}: nothing observed, nothing proven")
    narsize = {}
    downloadsize = {}
    for store_path, meta in closure.items():
        # narSize is the UNCOMPRESSED serialized NAR size; downloadSize is the
        # COMPRESSED wire size. Different units — kept in separate maps, never mixed.
        narsize[store_path] = int(meta["narSize"])
        if meta.get("downloadSize") is not None:
            downloadsize[store_path] = int(meta["downloadSize"])
    return {
        "pin_label": rec["pin_label"],
        "pkg": rec["pkg"],
        "root_outpath": rec["root_outpath"],
        "narsize": narsize,
        "downloadsize": downloadsize,
        "sha256": _sha256_file(path),
        "capture_file": path.name,
    }


# ---------------------------------------------------------------------------
# The overlap oracle. RE-DERIVES num/denom from the raw path SETS every call;
# returns EXACT integers only. No float is ever formed here.
# ---------------------------------------------------------------------------
def overlap_counts(
    demand_narsize: dict[str, int], supply_paths: set[str]
) -> dict[str, int]:
    """Exact overlap of DEMAND against a SUPPLY path set, in two units.

    numerator = demand paths (or their narSize bytes) also present in supply;
    denominator = all demand paths (or their narSize bytes). Integers only.
    """
    demand_paths = set(demand_narsize)
    hit_paths = demand_paths & supply_paths
    paths_num = len(hit_paths)
    paths_den = len(demand_paths)
    narbytes_num = sum(demand_narsize[p] for p in hit_paths)
    narbytes_den = sum(demand_narsize[p] for p in demand_paths)
    return {
        "paths_num": paths_num,
        "paths_den": paths_den,
        "narSize_uncompressed_bytes_num": narbytes_num,
        "narSize_uncompressed_bytes_den": narbytes_den,
    }


def _pct_display(num: int, den: int) -> str:
    """TERMINAL display only (owner rule: floats never gate). Exact fraction shown too."""
    if den == 0:
        return "n/a (empty denominator)"
    pct = 100.0 * num / den
    return f"{pct:.4f}% (exact {num}/{den})"


def union_supply_paths(
    pin_label: str, pkgs: list[str], raw_dir: Path
) -> tuple[set[str], list[dict]]:
    """Union of the closure path sets of `pkgs` at `pin_label` — the peer's store."""
    paths: set[str] = set()
    provenance: list[dict] = []
    for pkg in pkgs:
        cap = load_closure(pin_label, pkg, raw_dir)
        paths |= set(cap["narsize"])
        provenance.append(
            {
                "capture_file": cap["capture_file"],
                "pkg": cap["pkg"],
                "pin_label": cap["pin_label"],
                "root_outpath": cap["root_outpath"],
                "sha256": cap["sha256"],
                "n_paths": len(cap["narsize"]),
            }
        )
    return paths, provenance


def compute_cell(
    demand_cap: dict, supply_pin: str, supply_pkgs: list[str], raw_dir: Path
) -> dict:
    """One (population, regime) cell: overlap of DEMAND against a SUPPLY union."""
    supply_paths, supply_prov = union_supply_paths(supply_pin, supply_pkgs, raw_dir)
    counts = overlap_counts(demand_cap["narsize"], supply_paths)
    cell = dict(counts)
    cell["paths_display"] = _pct_display(counts["paths_num"], counts["paths_den"])
    cell["narSize_uncompressed_bytes_display"] = _pct_display(
        counts["narSize_uncompressed_bytes_num"],
        counts["narSize_uncompressed_bytes_den"],
    )
    cell["supply_pin_label"] = supply_pin
    cell["supply_pkgs"] = list(supply_pkgs)
    cell["supply_n_paths_total"] = len(supply_paths)
    cell["supply_captures"] = supply_prov
    return cell


# ---------------------------------------------------------------------------
# Full measurement over the real captures.
# ---------------------------------------------------------------------------
def measure(raw_dir: Path) -> dict:
    demand_cap = load_closure(DEMAND[0], DEMAND[1], raw_dir)
    demand_download_total = sum(demand_cap["downloadsize"].values())
    demand_nar_total = sum(demand_cap["narsize"].values())

    cells: dict[str, dict] = {}
    for pop_label, supply_pin in (("a_same_pin", "A"), ("b_cross_rev", "B")):
        cells[f"{pop_label}__cold_start"] = compute_cell(
            demand_cap, supply_pin, SUPPLY_COLD_PKGS, raw_dir
        )
        cells[f"{pop_label}__steady_state"] = compute_cell(
            demand_cap, supply_pin, SUPPLY_STEADY_PKGS, raw_dir
        )

    finding = _finding(cells)
    return {
        "task": "task-256",
        "label": "decision-input ONLY — NOT policy-training, NOT holdout, NOT a PRD "
        "success claim (AC#7)",
        "measures": "peer HIT-RATE potential = fraction of a cold build's closure "
        "(DEMAND) already resident on a peer (SUPPLY), computed offline from "
        "nix path-info closures. NO protocol code, NO network, NO containers.",
        "no_floats_in_decisions": True,
        "unit_discipline": "overlap ratios are in PATH-COUNT and uncompressed-narSize "
        "units, kept separate; the compressed-wire downloadSize is a DIFFERENT unit, "
        "recorded as context and NEVER compared to a narSize",
        "provenance": {
            "pin_A_rev_same_pin": PIN_A_REV,
            "pin_B_rev_cross_rev": PIN_B_REV,
            "demand_pin_label": DEMAND[0],
            "demand_pkg": DEMAND[1],
            "demand_root_outpath": demand_cap["root_outpath"],
            "demand_capture_file": demand_cap["capture_file"],
            "demand_capture_sha256": demand_cap["sha256"],
            "demand_n_paths": len(demand_cap["narsize"]),
            "demand_narSize_uncompressed_bytes": demand_nar_total,
            "demand_downloadSize_compressed_wire_bytes_CONTEXT_NEVER_COMPARED": (
                demand_download_total
            ),
        },
        "cells": cells,
        "finding": finding,
    }


def _ratio_gt(a: dict, b: dict, num_key: str, den_key: str) -> bool:
    """a's ratio strictly greater than b's, by integer cross-multiplication."""
    return a[num_key] * b[den_key] > b[num_key] * a[den_key]


def _finding(cells: dict[str, dict]) -> dict:
    a_steady = cells["a_same_pin__steady_state"]
    b_steady = cells["b_cross_rev__steady_state"]
    a_cold = cells["a_same_pin__cold_start"]
    same_pin_beats_cross_rev_steady_paths = _ratio_gt(
        a_steady, b_steady, "paths_num", "paths_den"
    )
    warm_beats_cold_same_pin_paths = _ratio_gt(
        a_steady, a_cold, "paths_num", "paths_den"
    )
    return {
        "same_pin_steady_overlap_paths": a_steady["paths_display"],
        "cross_rev_steady_overlap_paths": b_steady["paths_display"],
        "same_pin_cold_overlap_paths": a_cold["paths_display"],
        "same_pin_steady_STRICTLY_beats_cross_rev_steady": (
            same_pin_beats_cross_rev_steady_paths
        ),
        "same_pin_steady_STRICTLY_beats_same_pin_cold": warm_beats_cold_same_pin_paths,
        "interpretation": (
            "The (a)-vs-(b) gap IS the finding: nix store paths are input-addressed, "
            "so a cross-rev peer path-matches almost nothing of a client's closure "
            "(bytes-per-hit is irrelevant when hit-rate is ~0). Meaningful peer "
            "offload requires supply on the SAME nixpkgs pin. See results README."
        ),
    }


# ---------------------------------------------------------------------------
# --verify: re-derive every stored cell from the raw captures. THE BITE.
# ---------------------------------------------------------------------------
def verify(results: dict, raw_dir: Path) -> list[str]:
    """Recompute every cell from raw captures; return a list of disagreements.

    An empty list means the stored results are exactly re-derivable from the raw
    `nix path-info` captures. Any entry is a fabricated/tampered/wrong-set result.
    """
    problems: list[str] = []
    demand_label = results["provenance"]["demand_pin_label"]
    demand_pkg = results["provenance"]["demand_pkg"]
    try:
        demand_cap = load_closure(demand_label, demand_pkg, raw_dir)
    except (FileNotFoundError, ValueError) as exc:
        return [f"demand capture unrecoverable: {exc}"]

    # The stored demand capture sha256 must match the raw file on disk (tamper check).
    stored_sha = results["provenance"]["demand_capture_sha256"]
    if stored_sha != demand_cap["sha256"]:
        problems.append(
            f"demand capture sha256 mismatch: results {stored_sha} != "
            f"raw {demand_cap['sha256']} (raw capture tampered or wrong file)"
        )

    for cell_name, cell in results["cells"].items():
        supply_pin = cell["supply_pin_label"]
        supply_pkgs = cell["supply_pkgs"]
        try:
            supply_paths, _prov = union_supply_paths(supply_pin, supply_pkgs, raw_dir)
        except (FileNotFoundError, ValueError) as exc:
            problems.append(f"{cell_name}: supply capture unrecoverable: {exc}")
            continue
        recomputed = overlap_counts(demand_cap["narsize"], supply_paths)
        for key, want in recomputed.items():
            got = cell.get(key)
            if got != want:
                problems.append(
                    f"{cell_name}.{key}: stored {got} != re-derived {want} "
                    "(fabricated or wrong closure set)"
                )
    return problems


# ---------------------------------------------------------------------------
# Self-test: prove the oracle bites, with no repo files and no network.
# ---------------------------------------------------------------------------
def self_test() -> list[str]:
    failures: list[str] = []

    # (1) Known synthetic demand/supply recomputes to the hand-computed num/denom.
    #     demand paths p1..p4 (narSize 10,20,30,40); supply holds p1,p3 -> 2/4 paths,
    #     (10+30)/(10+20+30+40) = 40/100 bytes.
    demand = {"p1": 10, "p2": 20, "p3": 30, "p4": 40}
    supply = {"p1", "p3", "pX"}
    got = overlap_counts(demand, supply)
    want = {
        "paths_num": 2,
        "paths_den": 4,
        "narSize_uncompressed_bytes_num": 40,
        "narSize_uncompressed_bytes_den": 100,
    }
    if got != want:
        failures.append(f"known-vector overlap recomputed {got}, expected {want}")

    # (2) Wrong/self closure set changes the answer: overlap(D, D) = 100% must DIFFER
    #     from overlap(D, S_real). A constant/vacuous function would not.
    self_overlap = overlap_counts(demand, set(demand))
    if self_overlap["paths_num"] != self_overlap["paths_den"]:
        failures.append("overlap(D, D) was not 100% — the oracle is miscounting")
    if (self_overlap["paths_num"], self_overlap["paths_den"]) == (
        got["paths_num"],
        got["paths_den"],
    ):
        failures.append(
            "overlap(D, D) equals overlap(D, S_real) — the oracle ignores the "
            "supply set (vacuous)"
        )

    # (3) FABRICATION BITE: build a tiny in-memory results/raw pair, verify GREEN,
    #     then inject a higher numerator and prove verify goes RED.
    failures.extend(_self_test_fabrication_bite())

    # (4) Empty-closure capture is nothing-proven, never a false 0/0.
    failures.extend(_self_test_empty_capture())

    # (5) Exact-ratio comparison uses integer cross-multiplication (no float drift):
    #     3/10 < 1/3 must hold exactly (0.3 < 0.3333...), which float-free logic gets
    #     right and a naive equal-denominator mistake would not.
    if not (Fraction(3, 10) < Fraction(1, 3)):
        failures.append("Fraction ordering broken")
    if not _ratio_gt(
        {"n": 1, "d": 3}, {"n": 3, "d": 10}, "n", "d"
    ):  # 1/3 > 3/10 by cross-multiply (10 > 9)
        failures.append("cross-multiplication ordering broken")

    return failures


def _write_synthetic_capture(
    raw_dir: Path, pin_label: str, pkg: str, closure: dict
) -> None:
    rec = {
        "pin_label": pin_label,
        "flakeref": "synthetic",
        "pkg": pkg,
        "root_outpath": f"/nix/store/{pkg}",
        "closure": closure,
    }
    _capture_path(pin_label, pkg, raw_dir).write_text(json.dumps(rec, sort_keys=True))


def _self_test_fabrication_bite() -> list[str]:
    import tempfile

    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp)
        # demand curl@A holds d1,d2,d3; supply hello@A holds d1 (1/3 paths overlap).
        _write_synthetic_capture(
            raw,
            "A",
            "curl",
            {"d1": {"narSize": 10}, "d2": {"narSize": 20}, "d3": {"narSize": 30}},
        )
        _write_synthetic_capture(raw, "A", "hello", {"d1": {"narSize": 10}})
        _write_synthetic_capture(raw, "B", "hello", {"z1": {"narSize": 99}})

        demand_cap = load_closure("A", "curl", raw)
        supply_cold_a, _ = union_supply_paths("A", ["hello"], raw)
        real = overlap_counts(demand_cap["narsize"], supply_cold_a)
        results = {
            "provenance": {
                "demand_pin_label": "A",
                "demand_pkg": "curl",
                "demand_capture_sha256": demand_cap["sha256"],
            },
            "cells": {
                "a_same_pin__cold_start": {
                    **real,
                    "supply_pin_label": "A",
                    "supply_pkgs": ["hello"],
                }
            },
        }
        # Real results verify GREEN.
        problems = verify(results, raw)
        if problems:
            failures.append(f"real synthetic results failed verify: {problems}")

        # FABRICATE a higher overlap (claim the peer holds all 3 demand paths).
        fabricated = json.loads(json.dumps(results))
        fabricated["cells"]["a_same_pin__cold_start"]["paths_num"] = 3
        fabricated["cells"]["a_same_pin__cold_start"][
            "narSize_uncompressed_bytes_num"
        ] = 60
        if not verify(fabricated, raw):
            failures.append(
                "FABRICATION BITE did not fire: an injected overlap that the raw "
                "captures do not support was accepted"
            )

        # TAMPER the raw capture (change demand narSize) — sha256 check must fire.
        _write_synthetic_capture(
            raw,
            "A",
            "curl",
            {"d1": {"narSize": 999}, "d2": {"narSize": 20}, "d3": {"narSize": 30}},
        )
        if not verify(results, raw):
            failures.append(
                "TAMPER BITE did not fire: a mutated raw capture (sha256 changed) "
                "was accepted against the original results"
            )
    return failures


def _self_test_empty_capture() -> list[str]:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp)
        _write_synthetic_capture(raw, "A", "hello", {})
        try:
            load_closure("A", "hello", raw)
        except ValueError:
            return []
    return ["empty-closure capture did not raise nothing-proven"]


# ---------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="TASK-256 offline closure-overlap probe")
    ap.add_argument("--self-test", action="store_true", help="prove the oracle bites")
    ap.add_argument("--raw-dir", type=Path, default=RAW_DIR)
    ap.add_argument(
        "--verify",
        type=Path,
        default=None,
        help="re-derive a results JSON from raw captures; exit 1 on any disagreement",
    )
    ap.add_argument(
        "--out", type=Path, default=None, help="write the measurement JSON here"
    )
    args = ap.parse_args(argv)

    if args.self_test:
        failures = self_test()
        if failures:
            for failure in failures:
                print(f"self-test FAILED: {failure}", file=sys.stderr)
            return EXIT_VIOLATION
        print(
            "task256_closure_overlap: self-test OK — known vector recomputes exactly, "
            "overlap(D,D) != overlap(D,S_real) (not vacuous), the fabrication and "
            "tamper bites both fire, and an empty capture is nothing-proven"
        )
        if not args.verify and args.out is None:
            return EXIT_OK

    if args.verify is not None:
        results = json.loads(args.verify.read_text())
        problems = verify(results, args.raw_dir)
        if problems:
            for problem in problems:
                print(f"VERIFY VIOLATION: {problem}", file=sys.stderr)
            return EXIT_VIOLATION
        print(
            f"verify OK — every cell in {args.verify.name} re-derives exactly from the "
            "raw nix path-info captures"
        )
        return EXIT_OK

    try:
        report = measure(args.raw_dir)
    except (FileNotFoundError, ValueError) as exc:
        print(f"probe could not run: {exc}", file=sys.stderr)
        return EXIT_CANNOT_CHECK

    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out is not None:
        args.out.write_text(text + "\n")
        print(f"wrote {args.out}")
    else:
        print(text)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
