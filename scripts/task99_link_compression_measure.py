#!/usr/bin/env python3
"""TASK-99 AC#2 finalizer: derive the peer-link-compression thesis answer from the harness's
INTEGER-EXACT measurement, honestly and without a single float in any decision.

The harness (`peer-fabric/examples/measure_link_compression.rs`) measures, on REAL nar data,
the SHIPPED /nar/3 codec: for each file and level, the exact `(compressed_bytes, raw_bytes)`
pair and integer compress/decompress nanoseconds. This finalizer re-reads that raw artifact
and derives every conclusion by INTEGER / EXACT-RATIONAL arithmetic (`fractions.Fraction`,
cross-multiplication), mirroring the TASK-94 finalizer discipline (a float tolerance + NaN is
fail-open): it REJECTS a non-finite or non-integer field rather than deriving a decision from
it.

The two thesis questions it answers:

  Q1 (break-even vs the CDN wire): a peer serving a zstd-compressed nar moves
     `compressed_bytes`; the CDN moves `raw_bytes * (CDN FileSize/NarSize)`. The peer breaks
     even iff `compressed_bytes/raw_bytes <= CDN_ratio`, i.e. iff zstd's ratio reaches xz's.
     Decided by cross-multiply against the COMMITTED TASK-94 baseline
     (sum_file_size, sum_nar_size), an exact integer pair - never the printed 0.3256.

  Q2 (net throughput, PRD risk 11): compression CPU competes with the transport's own
     CPU-bound path. On a slow home uplink the link dominates so the ratio wins; on a fast
     LAN the compressor can BECOME the bottleneck. Reported as integer bytes/sec (compress
     throughput = raw_bytes * 1e9 / compress_ns) and an end-to-end model comparing raw vs
     zstd delivery time by the exact `(bytes, ns)` pairs, at the home-uplink and LAN
     bandwidths, never a rounded rate.

Usage:
  task99_link_compression_measure.py --raw <harness.json> [--out <evidence.json>]
                                     [--baseline <task-94 sample.json>]

Exit codes: 0 conclusion derived; 1 a measurement was rejected (non-finite / non-integer /
inconsistent); 2 the finalizer could not run (bad inputs).
"""

from __future__ import annotations

import argparse
import json
import sys
from fractions import Fraction
from pathlib import Path

# The committed TASK-94 baseline (evidence/task-94/59e7d3b/sample.json): the CDN's aggregate
# FileSize/NarSize as an EXACT integer pair. Cross-multiply against this, never the float.
DEFAULT_BASELINE = Path("evidence/task-94/59e7d3b/sample.json")

# Home-uplink and LAN bandwidths as INTEGER bytes/sec (never a float MB/s). The home range is
# the PRD's 1.25-5 MB/s; the LAN point is the transport's own CPU-bound ceiling (~204 MB/s,
# TASK-64 / PRD risk 11), the regime where compression CPU can dominate.
HOME_UPLINK_BYTES_PER_SEC = 2_500_000  # 2.5 MB/s, mid home uplink
LAN_BYTES_PER_SEC = 204_000_000  # ~204 MB/s, the transport CPU-bound ceiling
NS_PER_SEC = 1_000_000_000

# The shipped default level, echoed for the report; the codec crate is the source of truth.
# FAIL-CLOSED: the raw artifact's `default_level` MUST equal this, or the artifact was produced
# by a harness on a different policy default than this finalizer claims (a re-derivability drift
# codex flagged). See `validate_raw`.
SHIPPED_LEVEL = 3

# The two decision-point levels the harness MUST sweep (frozen literals in the Rust harness,
# `measure_link_compression.rs`): a fast level and a high-ratio level. The finalizer REQUIRES both
# for every file, so a harness that collapsed the sweep (e.g. `[3, DEFAULT]` -> `[3, 3]` when the
# default flipped) is rejected rather than silently producing a one-level artifact.
EXPECTED_LEVELS = frozenset({3, 19})

# The minimum same-path (xz-vs-zstd) join required for an HONEST verdict: the same-path compare is
# the ONLY non-confounded ratio verdict (the committed baseline is a different nar set), so the
# finalizer fails closed if it cannot form it.
MIN_SAME_PATH_ROWS = 3


class Reject(Exception):
    """A measurement field could not be trusted - fail closed, never derive from it."""


def require_int(value, where: str) -> int:
    """A field that MUST be a non-negative integer; reject a float/NaN/negative/other."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise Reject(f"{where}: expected an integer, got {value!r} ({type(value).__name__})")
    if value < 0:
        raise Reject(f"{where}: expected a non-negative integer, got {value}")
    return value


def require_pos_int(value, where: str) -> int:
    v = require_int(value, where)
    if v == 0:
        raise Reject(f"{where}: expected a positive integer, got 0")
    return v


def require_unique_joined(hashes: list[str]) -> None:
    """The same-path joined rows must be UNIQUE by store hash, or `n_paths` is inflatable.

    Mirrors TASK-94's `_require_unique_admitted`: a store hash identifies a store path, so a
    repeated hash in the joined set double-counts that path - a replay of one joined row 3x
    would publish `n_paths == 3` and pass a `>= MIN_SAME_PATH_ROWS` gate it does not actually
    meet. A real measurement joins each path once, so a duplicate is a corrupted/forged/replayed
    artifact; reject it fail-closed on the one path shared by producer and verifier.
    """
    seen: set = set()
    dups: list = []
    for h in hashes:
        if h in seen:
            dups.append(h)
        seen.add(h)
    if dups:
        raise Reject(
            f"duplicate joined store hash(es) {sorted(set(dups))!r}: a replayed same-path row "
            "inflates n_paths and the aggregate verdict - rejected fail-closed"
        )


def validate_raw(raw: dict) -> None:
    """FAIL-CLOSED structural checks on the harness artifact BEFORE any conclusion is derived
    (mirroring the TASK-94 re-derivability discipline). Raises `Reject` on:
      * a `default_level` that is missing or != the shipped level this finalizer claims;
      * fewer than two measured files (a one-file input is too thin to conclude from);
      * any file whose swept levels are not EXACTLY {3, 19} (a collapsed/duplicated/extra sweep -
        the exact drift that made the committed [3,19] evidence un-reproducible from a [3,3] run).
    """
    default_level = raw.get("default_level")
    if isinstance(default_level, bool) or not isinstance(default_level, int):
        raise Reject(
            f"raw.default_level: expected an integer, got {default_level!r}"
        )
    if default_level != SHIPPED_LEVEL:
        raise Reject(
            f"raw.default_level {default_level} != the finalizer's shipped level {SHIPPED_LEVEL}: "
            "the artifact was produced against a different policy default than this finalizer "
            "reports - regenerate the evidence from the committed harness"
        )

    files = raw.get("files")
    if not isinstance(files, list) or len(files) < 2:
        raise Reject(
            f"raw.files: expected at least 2 measured files, got "
            f"{0 if not isinstance(files, list) else len(files)}"
        )

    for f in files:
        path = f.get("path", "<unknown>")
        levels = f.get("levels")
        if not isinstance(levels, list):
            raise Reject(f"{path}: missing levels array")
        level_values = [lv.get("level") for lv in levels]
        if any(isinstance(v, bool) or not isinstance(v, int) for v in level_values):
            raise Reject(f"{path}: non-integer level in {level_values!r}")
        if len(level_values) != len(set(level_values)):
            raise Reject(f"{path}: duplicate level in {level_values!r} (a collapsed sweep)")
        if set(level_values) != set(EXPECTED_LEVELS):
            raise Reject(
                f"{path}: swept levels {sorted(level_values)} != the required "
                f"{sorted(EXPECTED_LEVELS)} - the harness must sweep both decision points"
            )


def baseline_ratio(baseline_path: Path) -> tuple[int, int]:
    """The CDN FileSize/NarSize baseline as an exact (num, den) integer pair from the
    committed TASK-94 sample - the sums, not the derived float."""
    data = json.loads(baseline_path.read_text())
    agg = data["cdn_wire_vs_peer_raw_sample"]["aggregate"]
    num = require_pos_int(agg["sum_file_size_bytes_compressed_wire"], "baseline.sum_file_size")
    den = require_pos_int(agg["sum_nar_size_bytes_uncompressed_nar"], "baseline.sum_nar_size")
    return num, den


def frac_str(fr: Fraction) -> str:
    """A terminal decimal for DISPLAY ONLY (never re-read/compared). Six places, integer ppm
    alongside so the exact-ness is visible."""
    dec = fr.numerator / fr.denominator  # display-only float, never gated
    ppm = (fr.numerator * 1_000_000) // fr.denominator
    return f"{dec:.6f} (~{ppm} ppm; exact {fr.numerator}/{fr.denominator})"


def derive(
    raw: dict,
    base_num: int,
    base_den: int,
    cdn_narinfo_text: str | None,
) -> dict:
    """Derive the full evidence dict from the harness `raw`, the CDN baseline integer pair, and
    the SAME-path CDN narinfo text. The ONE computation path shared by the producer and any
    verifier (a re-run must reproduce `measurement.json` byte-for-byte). Raises `Reject` on any
    untrusted/inconsistent field, so every conclusion is fail-closed. No float enters a decision.
    """
    baseline = Fraction(base_num, base_den)

    # FAIL-CLOSED structural validation FIRST (default_level, file count, both levels).
    validate_raw(raw)
    files = raw["files"]

    # Aggregate compressed/raw sums PER LEVEL, as exact integers.
    level_sums: dict[int, dict[str, int]] = {}
    per_file_report = []

    for f in files:
        path = f["path"]
        raw_bytes = require_pos_int(f["raw_bytes"], f"{path}.raw_bytes")
        file_levels = []
        for lv in f["levels"]:
            level = require_int(lv["level"], f"{path}.level")
            # compressed_bytes is a byte COUNT of a real zstd frame: POSITIVE. Zero is
            # impossible (a frame has a header+content) and would silently corrupt the ratio,
            # so reject it fail-closed (codex 3rd re-gate fix #3b), not merely non-negative.
            cb = require_pos_int(lv["compressed_bytes"], f"{path}.compressed_bytes")
            rb = require_pos_int(lv["raw_bytes"], f"{path}.raw_bytes(level)")
            if rb != raw_bytes:
                raise Reject(f"{path}: level raw_bytes {rb} != file raw_bytes {raw_bytes}")
            comp_ns = require_pos_int(lv["compress_ns"], f"{path}.compress_ns")
            deco_ns = require_pos_int(lv["decompress_ns"], f"{path}.decompress_ns")

            ratio = Fraction(cb, rb)
            # Q1: break-even iff compressed/raw <= baseline (cross-multiply).
            breaks_even = cb * base_den <= base_num * rb
            # Q2 components: integer bytes/sec (display) but keep (bytes, ns) for compares.
            compress_bps = (rb * NS_PER_SEC) // comp_ns
            decompress_bps = (rb * NS_PER_SEC) // deco_ns

            sums = level_sums.setdefault(
                level,
                {"compressed": 0, "raw": 0, "compress_ns": 0, "decompress_ns": 0, "n": 0},
            )
            sums["compressed"] += cb
            sums["raw"] += rb
            sums["compress_ns"] += comp_ns
            sums["decompress_ns"] += deco_ns
            sums["n"] += 1

            file_levels.append(
                {
                    "level": level,
                    "compressed_bytes": cb,
                    "raw_bytes": rb,
                    "ratio_pair": [cb, rb],
                    "ratio_display": frac_str(ratio),
                    # INFORMATIONAL ONLY, CROSS-NAR-SET: this compares THIS nar's zstd ratio
                    # against TASK-94's DIFFERENT 220-nar aggregate baseline, so it is
                    # confounded by the nar-set difference and is NOT a verdict. The honest
                    # verdict is `same_path_xz_vs_zstd` (identical paths). See fix #3.
                    "beats_task94_crossset_baseline_INFORMONLY": breaks_even,
                    "compress_bytes_per_sec": compress_bps,
                    "decompress_bytes_per_sec": decompress_bps,
                    "compress_ns": comp_ns,
                    "decompress_ns": deco_ns,
                }
            )
        per_file_report.append(
            {"path": path, "raw_bytes": raw_bytes, "levels": file_levels}
        )

    # Aggregate conclusions per level.
    level_report = []
    for level in sorted(level_sums):
        s = level_sums[level]
        agg_ratio = Fraction(s["compressed"], s["raw"])
        agg_breaks_even = s["compressed"] * base_den <= base_num * s["raw"]
        agg_compress_bps = (s["raw"] * NS_PER_SEC) // s["compress_ns"]
        agg_decompress_bps = (s["raw"] * NS_PER_SEC) // s["decompress_ns"]

        # Net end-to-end delivery TIME (ns) for the aggregate raw payload, raw vs zstd, at
        # each bandwidth. Same delivered payload (raw bytes), so lower time == higher net
        # throughput; compared by exact integers.
        def net_ns(bw: int, s=s) -> dict:
            raw_link_ns = (s["raw"] * NS_PER_SEC) // bw
            zstd_link_ns = (s["compressed"] * NS_PER_SEC) // bw
            # Serial worst case: compress, send, decompress (a conservative upper bound on
            # the zstd path; pipelining only helps it).
            zstd_total_ns = s["compress_ns"] + zstd_link_ns + s["decompress_ns"]
            zstd_wins = zstd_total_ns < raw_link_ns
            # Net throughput of the raw payload over the whole op, integer bytes/sec.
            raw_net_bps = (s["raw"] * NS_PER_SEC) // raw_link_ns if raw_link_ns else 0
            zstd_net_bps = (s["raw"] * NS_PER_SEC) // zstd_total_ns if zstd_total_ns else 0
            return {
                "bandwidth_bytes_per_sec": bw,
                "raw_delivery_ns": raw_link_ns,
                "zstd_compress_ns": s["compress_ns"],
                "zstd_link_ns": zstd_link_ns,
                "zstd_decompress_ns": s["decompress_ns"],
                "zstd_total_ns": zstd_total_ns,
                "zstd_beats_raw_end_to_end": zstd_wins,
                "raw_net_bytes_per_sec": raw_net_bps,
                "zstd_net_bytes_per_sec": zstd_net_bps,
            }

        level_report.append(
            {
                "level": level,
                "n_files": s["n"],
                "sum_compressed_bytes": s["compressed"],
                "sum_raw_bytes": s["raw"],
                "aggregate_ratio_pair": [s["compressed"], s["raw"]],
                "aggregate_ratio_display": frac_str(agg_ratio),
                # INFORMATIONAL ONLY, CROSS-NAR-SET (see per-file note): this aggregate is
                # compared against TASK-94's DIFFERENT 220-nar baseline and is confounded by
                # the nar-set difference, so it is NOT the verdict. It used to be persisted as
                # `aggregate_beats_cdn_wire: true` and asserted on stderr, which over-read a
                # cross-set number as a headline (codex DEEP-gate fix #3). The ONLY honest
                # ratio verdict is `same_path_xz_vs_zstd`.
                "beats_task94_crossset_baseline_INFORMONLY": agg_breaks_even,
                "aggregate_compress_bytes_per_sec": agg_compress_bps,
                "aggregate_decompress_bytes_per_sec": agg_decompress_bps,
                "net_home_uplink": net_ns(HOME_UPLINK_BYTES_PER_SEC),
                "net_lan": net_ns(LAN_BYTES_PER_SEC),
            }
        )
    # The RIGOROUS same-path comparison: xz (CDN) vs our zstd on the IDENTICAL store
    # paths, so the ratio verdict is not confounded by different nar sets (the committed
    # baseline is a DIFFERENT 220-path aggregate). Integer cross-multiply; xz.ns must
    # equal our raw_bytes (same canonical nar), else the join is rejected.
    same_path = None
    if cdn_narinfo_text is not None:
        cdn = {}
        for line in cdn_narinfo_text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith("Compression=xz"):
                fields = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
                cdn[parts[0]] = (
                    require_pos_int(int(fields["FileSize"]), "cdn.FileSize"),
                    require_pos_int(int(fields["NarSize"]), "cdn.NarSize"),
                )
        rows = []
        joined_hashes: list[str] = []
        sums = {"nar": 0, "xz": 0}
        zstd_sums: dict[int, int] = {}
        for f in per_file_report:
            base = Path(f["path"]).name  # NN-<hash>-name.nar
            bits = base.split("-")
            h = bits[1] if len(bits) > 1 else ""
            if h not in cdn:
                continue
            joined_hashes.append(h)
            xz, ns = cdn[h]
            if ns != f["raw_bytes"]:
                raise Reject(
                    f"same-path join: CDN NarSize {ns} != measured raw {f['raw_bytes']} for {h}"
                )
            sums["nar"] += ns
            sums["xz"] += xz
            per_level = {}
            for lv in f["levels"]:
                cb = lv["compressed_bytes"]
                # Same denom (ns) for xz and zstd, so the ratio compare is a byte compare.
                per_level[lv["level"]] = {
                    "compressed_bytes": cb,
                    "beats_xz_same_path": cb < xz,
                }
                zstd_sums[lv["level"]] = zstd_sums.get(lv["level"], 0) + cb
            rows.append(
                {
                    "hash": h,
                    "nar_size": ns,
                    "xz_filesize": xz,
                    "xz_ratio_pair": [xz, ns],
                    "xz_ratio_display": frac_str(Fraction(xz, ns)),
                    "zstd_by_level": per_level,
                }
            )
        # A replayed same-path row (a duplicate joined store hash) must not inflate n_paths
        # (codex 3rd re-gate fix #3a): the join keys must be UNIQUE, mirroring TASK-94.
        require_unique_joined(joined_hashes)
        if rows:
            agg_levels = {}
            for level, zsum in sorted(zstd_sums.items()):
                agg_levels[level] = {
                    "sum_zstd_bytes": zsum,
                    "aggregate_ratio_pair": [zsum, sums["nar"]],
                    "aggregate_ratio_display": frac_str(Fraction(zsum, sums["nar"])),
                    # xz wins iff its bytes are fewer (same nar denom): zstd beats xz iff
                    # zsum < xz_sum.
                    "zstd_beats_xz_aggregate": zsum < sums["xz"],
                }
            same_path = {
                "note": "rigorous: xz (CDN) vs our zstd on the IDENTICAL paths; the ONLY "
                "honest ratio verdict (the cross-set fields above use a DIFFERENT nar set)",
                "n_paths": len(rows),
                "sum_nar_bytes": sums["nar"],
                "sum_xz_bytes": sums["xz"],
                "xz_aggregate_ratio_pair": [sums["xz"], sums["nar"]],
                "xz_aggregate_ratio_display": frac_str(Fraction(sums["xz"], sums["nar"])),
                "zstd_aggregate_by_level": agg_levels,
                "per_path": rows,
            }

    # FAIL-CLOSED: the same-path xz-vs-zstd comparison is the ONLY honest ratio verdict, so it
    # is REQUIRED - an input without a CDN narinfo join (no `--cdn-narinfo`, or too few joined
    # paths) cannot produce a trustworthy conclusion and is rejected rather than shipping only
    # the confounded cross-set numbers (codex DEEP-gate fix #3/#4).
    if same_path is None:
        raise Reject(
            "the same-path xz-vs-zstd comparison is REQUIRED (pass --cdn-narinfo with the "
            "CDN xz FileSize/NarSize for the SAME paths); the cross-set baseline compare "
            "alone is confounded and not an honest verdict"
        )
    if same_path["n_paths"] < MIN_SAME_PATH_ROWS:
        raise Reject(
            f"same-path join has only {same_path['n_paths']} path(s); need "
            f">= {MIN_SAME_PATH_ROWS} for an honest aggregate verdict"
        )

    return {
        "task": "task-99",
        "measures": "peer-LINK zstd compression on real nar data (the shipped /nar/3 codec)",
        "integer_exact": True,
        "no_floats_in_decisions": True,
        "cdn_baseline_pair_file_over_nar": [base_num, base_den],
        "cdn_baseline_display": frac_str(baseline),
        "home_uplink_bytes_per_sec": HOME_UPLINK_BYTES_PER_SEC,
        "lan_bytes_per_sec": LAN_BYTES_PER_SEC,
        "shipped_default_level": SHIPPED_LEVEL,
        "per_level_aggregate": level_report,
        "same_path_xz_vs_zstd": same_path,
        "per_file": per_file_report,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", type=Path, help="harness JSON")
    ap.add_argument("--out", type=Path, default=None, help="write the derived evidence JSON")
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument(
        "--cdn-narinfo",
        type=Path,
        default=None,
        help="text file of `<hash> Compression=xz FileSize=N NarSize=M` lines for the SAME "
        "paths, for the rigorous same-path xz-vs-zstd comparison (the honest verdict)",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove the fail-closed guards (replay + zero) bite by mutation; no inputs needed",
    )
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if args.raw is None:
        print("--raw is required (or pass --self-test)", file=sys.stderr)
        return 2

    try:
        raw = json.loads(args.raw.read_text())
    except Exception as exc:  # noqa: BLE001
        print(f"cannot read harness JSON: {exc}", file=sys.stderr)
        return 2

    try:
        base_num, base_den = baseline_ratio(args.baseline)
    except Exception as exc:  # noqa: BLE001
        print(f"cannot read baseline: {exc}", file=sys.stderr)
        return 2
    baseline = Fraction(base_num, base_den)

    cdn_text = args.cdn_narinfo.read_text() if args.cdn_narinfo else None

    try:
        result = derive(raw, base_num, base_den, cdn_text)
    except Reject as exc:
        print(f"REJECTED (fail closed): {exc}", file=sys.stderr)
        return 1

    text = json.dumps(result, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n")

    # A terse human summary to stderr (display only).
    print("TASK-99 link-compression measurement (integer-exact):", file=sys.stderr)
    print(f"  CDN baseline FileSize/NarSize = {frac_str(baseline)}", file=sys.stderr)
    for lr in result["per_level_aggregate"]:
        # NOTE: the cross-set `beats_task94_crossset_baseline_INFORMONLY` field is deliberately
        # NOT printed as a headline - it is confounded (different nar set). The honest ratio
        # verdict is the SAME-PATH block below.
        print(
            f"  zstd -{lr['level']:>2}: ratio {lr['aggregate_ratio_display']}"
            f"  compress={lr['aggregate_compress_bytes_per_sec']:,} B/s"
            f"  decompress={lr['aggregate_decompress_bytes_per_sec']:,} B/s",
            file=sys.stderr,
        )
        h = lr["net_home_uplink"]
        lan = lr["net_lan"]
        print(
            f"          home-uplink({HOME_UPLINK_BYTES_PER_SEC:,} B/s): zstd_beats_raw={h['zstd_beats_raw_end_to_end']}"
            f"  raw_net={h['raw_net_bytes_per_sec']:,} zstd_net={h['zstd_net_bytes_per_sec']:,} B/s",
            file=sys.stderr,
        )
        print(
            f"          LAN({LAN_BYTES_PER_SEC:,} B/s): zstd_beats_raw={lan['zstd_beats_raw_end_to_end']}"
            f"  raw_net={lan['raw_net_bytes_per_sec']:,} zstd_net={lan['zstd_net_bytes_per_sec']:,} B/s",
            file=sys.stderr,
        )
    if result["same_path_xz_vs_zstd"]:
        sp = result["same_path_xz_vs_zstd"]
        print(
            f"  SAME-PATH xz-vs-zstd ({sp['n_paths']} paths, the honest verdict):",
            file=sys.stderr,
        )
        print(f"    xz (CDN): {sp['xz_aggregate_ratio_display']}", file=sys.stderr)
        for level, lr in sp["zstd_aggregate_by_level"].items():
            print(
                f"    zstd -{level:>2}: {lr['aggregate_ratio_display']}"
                f"  zstd_beats_xz={lr['zstd_beats_xz_aggregate']}",
                file=sys.stderr,
            )
    if args.out:
        print(f"  wrote {args.out}", file=sys.stderr)
    return 0


# ----------------------------------------------------------------------------------------------
# Self-test: prove the fail-closed guards BITE by mutation (codex 3rd re-gate fix #3), mirroring
# TASK-94's `--self-test` discipline. Each guard is shown (a) to reject the bad input AND (b) to
# be non-vacuous - disabling only that guard lets the bad input through - so a green control is
# not a blanket pass.
# ----------------------------------------------------------------------------------------------


def _sample_raw() -> dict:
    """A minimal VALID harness dict (3 files, both levels, positive bytes) whose filenames join
    to `_sample_cdn` by store hash. The base for the self-test mutations."""

    def one(idx: int, h: str, raw_bytes: int, c3: int, c19: int) -> dict:
        return {
            "path": f"/nars/{idx:02d}-{h}-pkg.nar",
            "raw_bytes": raw_bytes,
            "blake3": f"blake3:{h}",
            "levels": [
                {
                    "level": 3,
                    "compressed_bytes": c3,
                    "raw_bytes": raw_bytes,
                    "compress_ns": 1000,
                    "decompress_ns": 500,
                },
                {
                    "level": 19,
                    "compressed_bytes": c19,
                    "raw_bytes": raw_bytes,
                    "compress_ns": 9000,
                    "decompress_ns": 500,
                },
            ],
        }

    return {
        "harness": "self-test",
        "default_level": SHIPPED_LEVEL,
        "files": [
            one(0, "aaa", 1000, 400, 350),
            one(1, "bbb", 2000, 800, 700),
            one(2, "ccc", 3000, 1200, 1050),
        ],
    }


def _sample_cdn() -> str:
    """CDN xz narinfo for the SAME hashes; each NarSize equals its file's raw_bytes (join key)."""
    return (
        "aaa  Compression=xz FileSize=200 NarSize=1000\n"
        "bbb  Compression=xz FileSize=400 NarSize=2000\n"
        "ccc  Compression=xz FileSize=600 NarSize=3000\n"
    )


def self_test() -> int:
    base_num, base_den = 383_084_972, 1_176_685_088  # a positive pair; not the guard under test
    cdn = _sample_cdn()
    failures: list[str] = []

    # CONTROL: a clean input derives and joins EXACTLY 3 unique paths.
    try:
        res = derive(_sample_raw(), base_num, base_den, cdn)
        n = res["same_path_xz_vs_zstd"]["n_paths"]
        if n != 3:
            failures.append(f"control: expected 3 joined paths, got {n}")
    except Reject as exc:
        failures.append(f"control: a clean input was rejected: {exc}")

    # (a) REPLAY: a duplicate joined store hash (same path measured twice) must be REJECTED, not
    # silently inflate n_paths.
    replay = _sample_raw()
    dup = json.loads(json.dumps(replay["files"][0]))  # deep copy of file `aaa`
    dup["path"] = "/nars/03-aaa-dup.nar"  # SAME hash `aaa`, different filename
    replay["files"].append(dup)
    try:
        derive(replay, base_num, base_den, cdn)
        failures.append("(a) replay: a duplicate joined store hash was NOT rejected")
    except Reject:
        pass
    # non-vacuity: with ONLY the uniqueness guard disabled the duplicate INFLATES n_paths to 4,
    # proving that guard is exactly what bites (not some unrelated check).
    orig_uniq = globals()["require_unique_joined"]
    globals()["require_unique_joined"] = lambda hashes: None
    try:
        res = derive(replay, base_num, base_den, cdn)
        n = res["same_path_xz_vs_zstd"]["n_paths"]
        if n != 4:
            failures.append(
                f"(a) replay non-vacuity: with the guard disabled the duplicate did not inflate "
                f"n_paths (got {n}, expected 4) - the mutation is not meaningful"
            )
    except Reject as exc:
        failures.append(f"(a) replay non-vacuity: unexpected reject with guard disabled: {exc}")
    finally:
        globals()["require_unique_joined"] = orig_uniq

    # (b) ZERO: a `compressed_bytes == 0` is an impossible measurement (a zstd frame is never
    # empty) and must be REJECTED, not accepted as merely non-negative.
    zero = _sample_raw()
    zero["files"][0]["levels"][0]["compressed_bytes"] = 0
    try:
        derive(zero, base_num, base_den, cdn)
        failures.append("(b) zero: a compressed_bytes==0 was NOT rejected")
    except Reject:
        pass
    # non-vacuity: with positivity relaxed to a bare non-negative int check the zero SAILS
    # through and would be published - proving positivity is the biting guard.
    orig_pos = globals()["require_pos_int"]
    globals()["require_pos_int"] = require_int  # accepts 0
    try:
        derive(zero, base_num, base_den, cdn)
    except Reject as exc:
        failures.append(
            f"(b) zero non-vacuity: with positivity relaxed the zero was still rejected, so "
            f"positivity is not the biting guard: {exc}"
        )
    finally:
        globals()["require_pos_int"] = orig_pos

    if failures:
        print("SELF-TEST FAILED:", file=sys.stderr)
        for msg in failures:
            print(f"  - {msg}", file=sys.stderr)
        return 1
    print(
        "SELF-TEST OK: control publishes 3 unique paths; the replay (duplicate join) and the "
        "compressed_bytes==0 mutation are each REJECTED fail-closed, and each is non-vacuous "
        "(disabling only its guard lets the bad input through).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
