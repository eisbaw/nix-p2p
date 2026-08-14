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
SHIPPED_LEVEL = 3


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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True, type=Path, help="harness JSON")
    ap.add_argument("--out", type=Path, default=None, help="write the derived evidence JSON")
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument(
        "--cdn-narinfo",
        type=Path,
        default=None,
        help="text file of `<hash> Compression=xz FileSize=N NarSize=M` lines for the SAME "
        "paths, for the rigorous same-path xz-vs-zstd comparison (the honest verdict)",
    )
    args = ap.parse_args()

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

    files = raw.get("files")
    if not files:
        print("harness JSON has no files", file=sys.stderr)
        return 2

    try:
        # Aggregate compressed/raw sums PER LEVEL, as exact integers.
        level_sums: dict[int, dict[str, int]] = {}
        per_file_report = []

        for f in files:
            path = f["path"]
            raw_bytes = require_pos_int(f["raw_bytes"], f"{path}.raw_bytes")
            file_levels = []
            for lv in f["levels"]:
                level = require_int(lv["level"], f"{path}.level")
                cb = require_int(lv["compressed_bytes"], f"{path}.compressed_bytes")
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
                        "beats_cdn_wire": breaks_even,
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
            def net_ns(bw: int) -> dict:
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
                    "aggregate_beats_cdn_wire": agg_breaks_even,
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
        if args.cdn_narinfo:
            cdn = {}
            for line in args.cdn_narinfo.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith("Compression=xz"):
                    fields = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
                    cdn[parts[0]] = (
                        require_pos_int(int(fields["FileSize"]), "cdn.FileSize"),
                        require_pos_int(int(fields["NarSize"]), "cdn.NarSize"),
                    )
            rows = []
            sums = {"nar": 0, "xz": 0}
            zstd_sums: dict[int, int] = {}
            for f in per_file_report:
                base = Path(f["path"]).name  # NN-<hash>-name.nar
                bits = base.split("-")
                h = bits[1] if len(bits) > 1 else ""
                if h not in cdn:
                    continue
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
                    "note": "rigorous: xz (CDN) vs our zstd on the IDENTICAL paths; the honest "
                    "ratio verdict (the committed-baseline compare above uses a DIFFERENT nar set)",
                    "n_paths": len(rows),
                    "sum_nar_bytes": sums["nar"],
                    "sum_xz_bytes": sums["xz"],
                    "xz_aggregate_ratio_pair": [sums["xz"], sums["nar"]],
                    "xz_aggregate_ratio_display": frac_str(Fraction(sums["xz"], sums["nar"])),
                    "zstd_aggregate_by_level": agg_levels,
                    "per_path": rows,
                }
    except Reject as exc:
        print(f"REJECTED (fail closed): {exc}", file=sys.stderr)
        return 1

    result = {
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

    text = json.dumps(result, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n")

    # A terse human summary to stderr (display only).
    print("TASK-99 link-compression measurement (integer-exact):", file=sys.stderr)
    print(f"  CDN baseline FileSize/NarSize = {frac_str(baseline)}", file=sys.stderr)
    for lr in level_report:
        print(
            f"  zstd -{lr['level']:>2}: ratio {lr['aggregate_ratio_display']}"
            f"  beats-CDN={lr['aggregate_beats_cdn_wire']}"
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


if __name__ == "__main__":
    sys.exit(main())
