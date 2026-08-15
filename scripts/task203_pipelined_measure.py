#!/usr/bin/env python3
"""TASK-203 AC#3 finalizer: re-evaluate the TASK-99 net-LAN verdict under a PIPELINED
(compress-and-send-in-blocks) serve model instead of the serial whole-nar-compress model, and
do it with INTEGER / EXACT-RATIONAL arithmetic ONLY - no float in any decision.

WHY THIS IS A LEGITIMATE RE-DERIVATION (not a re-measurement). TASK-203 changed the SCHEDULING
of the serve-side compressor (it now streams the zstd frame in blocks off the worker), NOT the
codec's bytes or its CPU cost: a streamed frame is the SAME single zstd frame as the bulk frame
(the codec test `streamed_frame_size_matches_bulk_within_tolerance` proves the streamed size is
within ~1/64 of bulk, and `streamed_frame_decodes_like_bulk` proves identical decode), and the
compress/decompress CPU-ns are the same work regardless of when it is scheduled. So the honest
re-evaluation reuses TASK-99's committed INTEGER-EXACT harness measurement (`compressed_bytes`,
`raw_bytes`, `compress_ns`, `decompress_ns` for the shipped /nar/3 codec on real nar data) and
applies the PIPELINED makespan model to the same numbers. It does NOT need a fresh shaped-link
run; it needs the same measured costs scheduled differently.

THE TWO MODELS (aggregate over the measured nar set, at a given link bandwidth):

  SERIAL (TASK-99): the whole nar is compressed, THEN sent, THEN decompressed - three costs in
     series. This reproduces TASK-99's `net_lan.zstd_total_ns` exactly (a re-derivability tie
     the finalizer asserts against the committed measurement.json when given `--task99`):
         serial_total_ns = compress_ns + link_ns + decompress_ns

  PIPELINED (TASK-203): compress, link and decompress run CONCURRENTLY on blocks in order. Under
     CONSTANT AGGREGATE per-stage rates and in-order blocks, the makespan of a 3-stage pipeline is
     the BOTTLENECK stage's total time plus the fill+drain of the two NON-bottleneck stages (each a
     single block, since at their AGGREGATE rate they are faster than the bottleneck and never make
     it wait):
         pipelined_total_ns = bottleneck_total_ns + one_block(other stage A) + one_block(other stage B)

     THIS IS AN IDEALIZED / BEST-CASE ESTIMATE, NOT A PROVEN BOUND. It holds EXACTLY only under the
     stated assumptions, and it is explicitly NOT an upper bound on the real pipeline. Two reasons,
     stated honestly so the reader is not misled:
       (1) PER-BLOCK RATE VARIATION can BEAT it. Aggregate constant rates do not bound a pipeline
           whose per-block rates vary: a downstream stage that is slow on an EARLY block stalls the
           whole line even though its AGGREGATE rate is fast. Counterexample (3 blocks, per-block
           service times) compress[5,5] / link[8,1] / decode[1,8]: this model predicts 19, but the
           real in-order schedule takes 22. So the real pipeline can be SLOWER than this estimate,
           not only faster.
       (2) STREAMING / CHANNEL / ALLOCATION OVERHEAD is NOT charged. The model reuses TASK-99's
           BULK single-call compress/decompress CPU-ns. The TASK-203 serve path is different code:
           raw-stream `compress_block` calls, a per-block output allocation, an mpsc channel + a
           `spawn_blocking` hop, and scheduling. That overhead is real and unmodeled here, so the
           TASK-99 bulk CPU is a LOWER BOUND on the new path's CPU, not an equality. See the
           evidence README's MEASURED cross-check of the bulk-vs-streamed encoder CPU, and the
           SENSITIVITY THRESHOLD below (`overhead_to_erase_flip`) for how much such overhead would
           erase the level-3 flip.

  raw_delivery_ns = sum_raw_bytes sent uncompressed over the link.
  zstd_beats_raw  = (zstd model total_ns) < raw_delivery_ns   [integer compare]

  SENSITIVITY (integer-exact, reported per band as `overhead_to_erase_flip` num/denom): when the
     model shows a flip, we also report how much EXTRA per-block streaming overhead - expressed as
     a fraction of the bottleneck (compress) budget - would push the pipelined estimate back up to
     `raw_delivery_ns` and ERASE the flip: (raw_delivery_ns - pipelined_total_ns) / bottleneck_ns.
     This is the honest margin: the flip survives only if the unmodeled overhead stays below it.

THE HEADLINE the model yields (it is NOT a rubber stamp - it still says zstd LOSES where the
compressor is the true bottleneck, e.g. level 19 on a LAN, whose ~2.7 MB/s compress cannot outrun
a 204 MB/s link even pipelined): on the ~204 MB/s LAN the serial model had zstd-3 marginally
LOSING (compress+decompress added in series with the link), while under this IDEALIZED pipelined
model zstd-3 BEATS raw - because the level-3 compressor's AGGREGATE ~316 MB/s outruns the LAN
(~204 MB/s), so compressing-and-overlapping the ~4.5x-smaller compressed volume delivers it faster
than shipping the raw volume, IF the per-block rates are near their aggregate and the streaming
overhead stays under the reported sensitivity margin. The serial penalty was the in-series
compress/decompress latency; pipelining hides it behind the bottleneck. Where the model shows zstd
still losing (a CPU-bound operator, or level 19), that is the honest 'raw on a fast LAN' fallback
(the shipped codec keeps raw as the mandatory floor, so such an operator lowers the level or
disables zstd).

Usage:
  task203_pipelined_measure.py --raw <task-99 harness.json> [--out <evidence.json>]
                               [--task99 <task-99 measurement.json>]

Exit codes: 0 conclusion derived; 1 a measurement was rejected (fail closed); 2 bad inputs.
"""

from __future__ import annotations

import argparse
import json
import sys
from fractions import Fraction
from pathlib import Path

# Bandwidths as INTEGER bytes/sec (never a float MB/s), IDENTICAL to the TASK-99 finalizer so the
# serial control reproduces its net figures byte-for-byte.
HOME_UPLINK_BYTES_PER_SEC = 2_500_000  # 2.5 MB/s, mid home uplink
LAN_BYTES_PER_SEC = 204_000_000  # ~204 MB/s, the transport CPU-bound ceiling (PRD risk 11)
NS_PER_SEC = 1_000_000_000

# The serve-side streaming compressor's raw-input block (fabric-libp2p SERVE_COMPRESS_INPUT_BLOCK
# and peer_fabric ENCODE_BLOCK / DECODE_BLOCK): the pipeline granularity. The fill/drain term is
# one such block through each non-bottleneck stage. Integer bytes.
SERVE_COMPRESS_INPUT_BLOCK = 131_072  # 128 KiB

# The shipped default level and the frozen swept levels - the artifact MUST match, or it was
# produced against a different policy/harness than this finalizer reports (a re-derivability drift).
SHIPPED_LEVEL = 3
EXPECTED_LEVELS = frozenset({3, 19})


class Reject(Exception):
    """A measurement field could not be trusted - fail closed, never derive from it."""


def require_int(value, where: str) -> int:
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


def validate_raw(raw: dict) -> None:
    """FAIL-CLOSED structural checks on the TASK-99 harness artifact before any conclusion."""
    default_level = raw.get("default_level")
    if isinstance(default_level, bool) or not isinstance(default_level, int):
        raise Reject(f"raw.default_level: expected an integer, got {default_level!r}")
    if default_level != SHIPPED_LEVEL:
        raise Reject(
            f"raw.default_level {default_level} != the finalizer's shipped level {SHIPPED_LEVEL}"
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
                f"{sorted(EXPECTED_LEVELS)}"
            )


def frac_str(fr: Fraction) -> str:
    """A terminal decimal for DISPLAY ONLY (never re-read/compared)."""
    dec = fr.numerator / fr.denominator  # display-only float, never gated
    ppm = (fr.numerator * 1_000_000) // fr.denominator
    return f"{dec:.6f} (~{ppm} ppm; exact {fr.numerator}/{fr.denominator})"


def aggregate_level(files: list, level: int) -> dict:
    """Sum the exact integer measurements for one level across all files (fail closed)."""
    s = {"compressed": 0, "raw": 0, "compress_ns": 0, "decompress_ns": 0, "n": 0}
    for f in files:
        path = f["path"]
        raw_bytes = require_pos_int(f["raw_bytes"], f"{path}.raw_bytes")
        for lv in f["levels"]:
            if require_int(lv["level"], f"{path}.level") != level:
                continue
            cb = require_pos_int(lv["compressed_bytes"], f"{path}.compressed_bytes")
            rb = require_pos_int(lv["raw_bytes"], f"{path}.raw_bytes(level)")
            if rb != raw_bytes:
                raise Reject(f"{path}: level raw_bytes {rb} != file raw_bytes {raw_bytes}")
            s["compressed"] += cb
            s["raw"] += rb
            s["compress_ns"] += require_pos_int(lv["compress_ns"], f"{path}.compress_ns")
            s["decompress_ns"] += require_pos_int(lv["decompress_ns"], f"{path}.decompress_ns")
            s["n"] += 1
    if s["n"] == 0:
        raise Reject(f"no rows for level {level}")
    return s


def net_at_bandwidth(s: dict, bw: int) -> dict:
    """Both delivery models for the aggregate nar at link bandwidth `bw` (integer ns)."""
    raw_delivery_ns = (s["raw"] * NS_PER_SEC) // bw
    link_ns = (s["compressed"] * NS_PER_SEC) // bw
    compress_ns = s["compress_ns"]
    decompress_ns = s["decompress_ns"]

    # --- SERIAL (reproduces TASK-99 net_lan) ---
    serial_total = compress_ns + link_ns + decompress_ns
    serial = {
        "compress_ns": compress_ns,
        "link_ns": link_ns,
        "decompress_ns": decompress_ns,
        "total_ns": serial_total,
        "zstd_beats_raw": serial_total < raw_delivery_ns,
    }

    # --- PIPELINED (TASK-203): bottleneck stage total + one block of each other stage ---
    # One-block times from the aggregate average rates (integer; SERVE_COMPRESS_INPUT_BLOCK raw
    # bytes per block, and its proportional compressed bytes over the link).
    blk = SERVE_COMPRESS_INPUT_BLOCK
    compress_block_ns = (blk * compress_ns) // s["raw"]
    decompress_block_ns = (blk * decompress_ns) // s["raw"]
    compressed_per_block = (blk * s["compressed"]) // s["raw"]
    link_block_ns = (compressed_per_block * NS_PER_SEC) // bw

    stages = {
        "compress": (compress_ns, compress_block_ns),
        "link": (link_ns, link_block_ns),
        "decompress": (decompress_ns, decompress_block_ns),
    }
    bottleneck_stage = max(stages, key=lambda k: stages[k][0])
    bottleneck_total = stages[bottleneck_stage][0]
    fill_drain_ns = sum(
        block_ns for name, (_total, block_ns) in stages.items() if name != bottleneck_stage
    )
    pipelined_total = bottleneck_total + fill_drain_ns
    pipelined_beats_raw = pipelined_total < raw_delivery_ns

    # SENSITIVITY (integer-exact rational): how much EXTRA per-block streaming overhead, as a
    # fraction of the bottleneck (compress) budget, would push the IDEALIZED pipelined estimate
    # back up to raw_delivery_ns and ERASE the flip. Only meaningful when the model shows a flip
    # (pipelined currently beats raw); null otherwise. This is the honest margin the unmodeled
    # streaming/channel/alloc overhead must stay under - it is NOT a claim the flip is proven.
    if pipelined_beats_raw and bottleneck_total > 0:
        margin_ns = raw_delivery_ns - pipelined_total  # > 0 here
        overhead_to_erase_flip = {
            "margin_ns": margin_ns,
            "bottleneck_ns": bottleneck_total,
            "fraction_pair": [margin_ns, bottleneck_total],
            "fraction_display": frac_str(Fraction(margin_ns, bottleneck_total)),
        }
    else:
        overhead_to_erase_flip = None

    pipelined = {
        "bottleneck_stage": bottleneck_stage,
        "bottleneck_total_ns": bottleneck_total,
        "compress_block_ns": compress_block_ns,
        "link_block_ns": link_block_ns,
        "decompress_block_ns": decompress_block_ns,
        "fill_drain_ns": fill_drain_ns,
        "total_ns": pipelined_total,
        "zstd_beats_raw": pipelined_beats_raw,
        # An IDEALIZED best-case estimate under constant aggregate rates - NOT an upper bound (see
        # the module docstring: per-block variation can beat it; streaming overhead is uncharged).
        "model": "idealized-best-case-constant-aggregate-rates",
        "is_proven_bound": False,
        "overhead_to_erase_flip": overhead_to_erase_flip,
    }

    return {
        "bandwidth_bytes_per_sec": bw,
        "raw_delivery_ns": raw_delivery_ns,
        "serial_model": serial,
        "pipelined_model": pipelined,
        "verdict_flips_serial_to_pipelined": (
            (not serial["zstd_beats_raw"]) and pipelined["zstd_beats_raw"]
        ),
    }


def derive(raw: dict, task99: dict | None) -> dict:
    validate_raw(raw)
    files = raw["files"]

    per_level = []
    lan_level3 = None
    for level in sorted(EXPECTED_LEVELS):
        s = aggregate_level(files, level)
        ratio = Fraction(s["compressed"], s["raw"])
        home = net_at_bandwidth(s, HOME_UPLINK_BYTES_PER_SEC)
        lan = net_at_bandwidth(s, LAN_BYTES_PER_SEC)
        if level == SHIPPED_LEVEL:
            lan_level3 = lan
        per_level.append(
            {
                "level": level,
                "n_files": s["n"],
                "sum_compressed_bytes": s["compressed"],
                "sum_raw_bytes": s["raw"],
                "aggregate_ratio_pair": [s["compressed"], s["raw"]],
                "aggregate_ratio_display": frac_str(ratio),
                "net_home_uplink": home,
                "net_lan": lan,
            }
        )

    # RE-DERIVABILITY TIE: when given the committed TASK-99 measurement.json, the SERIAL LAN
    # figures MUST reproduce it exactly (same harness numbers, same serial model) - or one of the
    # two artifacts drifted. Fail closed on any mismatch.
    if task99 is not None:
        t99_lan3 = None
        for lr in task99.get("per_level_aggregate", []):
            if lr.get("level") == SHIPPED_LEVEL:
                t99_lan3 = lr.get("net_lan")
        if t99_lan3 is None:
            raise Reject("task99 measurement.json has no level-3 net_lan to tie against")
        got = lan_level3["serial_model"]
        checks = {
            "compress_ns": ("zstd_compress_ns", got["compress_ns"]),
            "link_ns": ("zstd_link_ns", got["link_ns"]),
            "decompress_ns": ("zstd_decompress_ns", got["decompress_ns"]),
            "total_ns": ("zstd_total_ns", got["total_ns"]),
            "raw_delivery_ns": ("raw_delivery_ns", lan_level3["raw_delivery_ns"]),
        }
        for name, (t99_key, mine) in checks.items():
            theirs = t99_lan3.get(t99_key)
            if theirs != mine:
                raise Reject(
                    f"serial re-derivability tie failed on {name}: this finalizer computed "
                    f"{mine} but TASK-99 measurement.json {t99_key}={theirs}"
                )
        if t99_lan3.get("zstd_beats_raw_end_to_end") is not False:
            raise Reject(
                "TASK-99 net_lan zstd_beats_raw_end_to_end was expected False (the serial "
                f"penalty this task removes), got {t99_lan3.get('zstd_beats_raw_end_to_end')!r}"
            )

    return {
        "task": "task-203",
        "measures": "the TASK-99 net-LAN verdict re-evaluated under an IDEALIZED (best-case, "
        "constant-aggregate-rate) PIPELINED serve model",
        "reuses": "the committed TASK-99 harness_raw.json (same shipped /nar/3 codec, same "
        "integer-exact compress/decompress ns and byte counts); pipelining changes the "
        "SCHEDULING of that same work. The bulk CPU is reused as a LOWER BOUND on the streamed "
        "path's CPU (the new raw-stream/channel/alloc overhead is not charged) - see the evidence "
        "README's measured bulk-vs-streamed encoder cross-check",
        "model_kind": "idealized-best-case-constant-aggregate-rates",
        "model_is_proven_bound": False,
        "model_caveats": [
            "per-block rate variation can make the real pipeline SLOWER than this estimate "
            "(aggregate constant rates are not an upper bound; counterexample compress[5,5]/"
            "link[8,1]/decode[1,8] -> model 19, real 22)",
            "streaming/channel/allocation overhead of the TASK-203 serve path is not modeled; "
            "TASK-99 bulk compress CPU is a lower bound on the streamed path's CPU",
            "a live two-ends-shaped serve trace (TASK-198) is out of scope; the flip is a "
            "conditional estimate, not a measured wall-clock result",
        ],
        "integer_exact": True,
        "no_floats_in_decisions": True,
        "home_uplink_bytes_per_sec": HOME_UPLINK_BYTES_PER_SEC,
        "lan_bytes_per_sec": LAN_BYTES_PER_SEC,
        "serve_compress_input_block_bytes": SERVE_COMPRESS_INPUT_BLOCK,
        "shipped_default_level": SHIPPED_LEVEL,
        "headline_net_lan_level3": {
            "serial_zstd_beats_raw": lan_level3["serial_model"]["zstd_beats_raw"],
            "pipelined_zstd_beats_raw": lan_level3["pipelined_model"]["zstd_beats_raw"],
            "verdict_flips_serial_to_pipelined": lan_level3[
                "verdict_flips_serial_to_pipelined"
            ],
            "pipelined_bottleneck_stage": lan_level3["pipelined_model"]["bottleneck_stage"],
            "pipelined_model_is_proven_bound": False,
            "overhead_to_erase_flip": lan_level3["pipelined_model"]["overhead_to_erase_flip"],
        },
        "per_level_aggregate": per_level,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", type=Path, help="TASK-99 harness JSON (harness_raw.json)")
    ap.add_argument("--out", type=Path, default=None, help="write the derived evidence JSON")
    ap.add_argument(
        "--task99",
        type=Path,
        default=None,
        help="committed TASK-99 measurement.json to tie the serial re-derivation against",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove the fail-closed guards + the model's teeth bite by mutation; no inputs",
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
    task99 = json.loads(args.task99.read_text()) if args.task99 else None

    try:
        result = derive(raw, task99)
    except Reject as exc:
        print(f"REJECTED (fail closed): {exc}", file=sys.stderr)
        return 1

    text = json.dumps(result, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n")

    h = result["headline_net_lan_level3"]
    print(
        "TASK-203 net-LAN re-evaluation under an IDEALIZED (best-case, constant-aggregate-rate) "
        "pipelined model - integer-exact, NOT a proven bound:",
        file=sys.stderr,
    )
    print(
        f"  level {SHIPPED_LEVEL} LAN({LAN_BYTES_PER_SEC:,} B/s): "
        f"serial zstd_beats_raw={h['serial_zstd_beats_raw']} -> "
        f"pipelined(idealized) zstd_beats_raw={h['pipelined_zstd_beats_raw']} "
        f"(bottleneck={h['pipelined_bottleneck_stage']}; flips={h['verdict_flips_serial_to_pipelined']})",
        file=sys.stderr,
    )
    if h["overhead_to_erase_flip"] is not None:
        print(
            f"    sensitivity: per-block streaming overhead of "
            f"{h['overhead_to_erase_flip']['fraction_display']} of the compress budget would "
            f"ERASE this flip (margin {h['overhead_to_erase_flip']['margin_ns']:,} ns)",
            file=sys.stderr,
        )
    for lr in result["per_level_aggregate"]:
        lan = lr["net_lan"]
        print(
            f"    zstd -{lr['level']:>2}: raw_delivery={lan['raw_delivery_ns']:,} ns  "
            f"serial={lan['serial_model']['total_ns']:,} ns  "
            f"pipelined={lan['pipelined_model']['total_ns']:,} ns "
            f"(bottleneck={lan['pipelined_model']['bottleneck_stage']})",
            file=sys.stderr,
        )
    if args.out:
        print(f"  wrote {args.out}", file=sys.stderr)
    return 0


# ----------------------------------------------------------------------------------------------
# Self-test: prove the fail-closed guards bite AND that the pipelined model has TEETH (it is not
# a rubber stamp - a bottleneck-bound compressor still LOSES). Each mutation is shown to change
# the outcome, so a green control is not a blanket pass.
# ----------------------------------------------------------------------------------------------


def _sample_raw(compress_ns_l3: int) -> dict:
    """A two-file harness whose level-3 compressor is FAST (so pipelining beats raw on a LAN)
    unless `compress_ns_l3` is made large (bottleneck -> loses). Level-19 rows are present only to
    satisfy the frozen sweep and are not asserted on."""

    def one(idx: int, raw_bytes: int, c3: int, c19: int, cns3: int) -> dict:
        return {
            "path": f"/nars/{idx:02d}-h{idx}-pkg.nar",
            "raw_bytes": raw_bytes,
            "levels": [
                {
                    "level": 3,
                    "compressed_bytes": c3,
                    "raw_bytes": raw_bytes,
                    "compress_ns": cns3,
                    "decompress_ns": max(1, cns3 // 4),
                },
                {
                    "level": 19,
                    "compressed_bytes": c19,
                    "raw_bytes": raw_bytes,
                    "compress_ns": cns3 * 100,
                    "decompress_ns": max(1, cns3 // 4),
                },
            ],
        }

    # ~1/4 compression ratio; two files summing to 8 MiB raw.
    return {
        "harness": "self-test",
        "default_level": SHIPPED_LEVEL,
        "files": [
            one(0, 4 * 1024 * 1024, 1 * 1024 * 1024, 700 * 1024, compress_ns_l3 // 2),
            one(1, 4 * 1024 * 1024, 1 * 1024 * 1024, 700 * 1024, compress_ns_l3 // 2),
        ],
    }


def self_test() -> int:
    failures: list[str] = []
    # A moderate level-3 compressor that models the REAL TASK-99 LAN flip: 8 MiB raw takes
    # ~41 ms over a 204 MB/s LAN; compress ~30 ms, link (2 MiB) ~10 ms, decompress ~7.5 ms. Their
    # SERIAL sum (~47 ms) EXCEEDS raw (zstd loses serially), but each stage ALONE is under raw, so
    # the PIPELINED makespan (bottleneck ~30 ms compress + a tiny drain) is UNDER raw (zstd wins)
    # - the serial->pipelined verdict flip.
    fast = _sample_raw(compress_ns_l3=30_000_000)  # ~30 ms compress total for 8 MiB

    # CONTROL: on the LAN, level-3 pipelined beats raw and serial does not (verdict flips).
    try:
        res = derive(fast, None)
        h = res["headline_net_lan_level3"]
        if not h["pipelined_zstd_beats_raw"]:
            failures.append("control: pipelined level-3 should beat raw on the LAN")
        if h["serial_zstd_beats_raw"]:
            failures.append(
                "control: serial level-3 should NOT beat raw on the LAN (the penalty this "
                "task removes) - the self-test fixture does not model the flip"
            )
        if not h["verdict_flips_serial_to_pipelined"]:
            failures.append("control: the serial->pipelined verdict flip did not register")
    except Reject as exc:
        failures.append(f"control: a clean input was rejected: {exc}")

    # (a) FAIL-CLOSED: a compress_ns == 0 (impossible measurement) must be REJECTED.
    zero = _sample_raw(compress_ns_l3=8_400_000)
    zero["files"][0]["levels"][0]["compress_ns"] = 0
    try:
        derive(zero, None)
        failures.append("(a) zero: a compress_ns==0 was NOT rejected")
    except Reject:
        pass

    # (b) TEETH: a SLOW level-3 compressor (the bottleneck) must still LOSE pipelined on the LAN -
    # the model is not a rubber stamp. ~8 MiB at ~2.7 MB/s (level-19-like) => ~3.1 s compress,
    # far above the ~41 ms raw LAN delivery, so even pipelined zstd loses.
    slow = _sample_raw(compress_ns_l3=3_100_000_000)  # ~3.1 s for 8 MiB => ~2.7 MB/s
    try:
        res = derive(slow, None)
        h = res["headline_net_lan_level3"]
        if h["pipelined_zstd_beats_raw"]:
            failures.append(
                "(b) teeth: a bottleneck-slow compressor was wrongly declared to beat raw "
                "pipelined - the model is a rubber stamp"
            )
        if h["pipelined_bottleneck_stage"] != "compress":
            failures.append(
                f"(b) teeth: expected the compressor to be the bottleneck, got "
                f"{h['pipelined_bottleneck_stage']}"
            )
    except Reject as exc:
        failures.append(f"(b) teeth: unexpected reject: {exc}")

    if failures:
        print("SELF-TEST FAILED:", file=sys.stderr)
        for msg in failures:
            print(f"  - {msg}", file=sys.stderr)
        return 1
    print(
        "SELF-TEST OK: control shows the level-3 LAN verdict FLIP (serial loses -> pipelined "
        "wins); a compress_ns==0 is REJECTED fail-closed; and a bottleneck-slow compressor "
        "still LOSES pipelined (the model has teeth, not a rubber stamp).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
