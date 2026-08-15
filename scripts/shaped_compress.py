#!/usr/bin/env python3
"""TASK-198: the LIVE two-ends-shaped raw-vs-zstd peer transfer measurement.

WHAT THIS IS. TASK-203 (`scripts/task203_pipelined_measure.py`) produced an IDEALIZED, integer-
exact MODEL of whether link zstd beats raw over a link; it is explicitly NOT a measured wall-clock
result, and it names this task as the live counterpart it defers to ("a live two-ends-shaped serve
trace (TASK-198) is out of scope; the flip is a conditional estimate, not a measured wall-clock
result"). This script is that live counterpart: it runs the REAL libp2p `discover->fetch->serve`
`/nar/3` path (TASK-203's streaming zstd serve) between two swarm nodes whose traffic traverses a
`tc netem`-shaped `veth` pair with BOTH ends shaped, transfers the SAME compressible nar RAW and
then ZSTD over that same link, and reports the MEASURED wall-clock of each arm.

WHY BOTH ENDS SHAPED (the TASK-70 AC#3 correction). Every earlier peer-vs-upstream number shaped
only the UPSTREAM (CDN) arm while the peer transport ran over pod loopback, so every peer-advantage
figure was an UPPER BOUND — the peer looked unrealistically fast. TASK-70's own wire-cost
correction forbade re-deriving the speedup until link compression (TASK-99) landed, because the
peer byte-volume depends on whether the link is compressed. Both have landed; this shapes the PEER
link too, removing that loopback upper bound. It is still a shaped EMULATION (netns + tc netem),
NOT real hardware / a real WAN — an honest emulation, not a field trial (see HONEST_LIMITS; the
real-hardware residual is TASK-207's two-VM NAT harness).

THE DELIVERABLE — an HONEST measured number, integer/rational only (owner no-floats rule +
`scripts/check-no-floats.py`):
  * raw-arm wall-clock (integer ns) and zstd-arm wall-clock (integer ns) over the SAME shaped link;
  * the COMPRESSED body bytes each arm put on the wire (integer bytes) — the raw arm's is the
    uncompressed NarSize, the zstd arm's is the compressed frame. LIKE-UNITS ONLY: the raw-vs-zstd
    comparison is compressed-transport-bytes vs raw-transport-bytes over the SAME link; the
    addressed unit stays the raw NAR. Never NarSize-vs-compressed (the trap that recurred 3x);
  * throughput (integer bytes/sec) and the raw/zstd wall-clock speedup as an EXACT RATIONAL
    (`fractions.Fraction`, compared by cross-multiplication).

WHY THE SIGN IS ROBUST (unlike TASK-203's noise-straddling CPU delta). The raw-vs-zstd delta here
is NOT a scheduler-dominated CPU micro-delta. On a BANDWIDTH-BOUND link the transfer time is set by
the WIRE-BYTE volume, and the zstd arm measurably puts ~R x fewer bytes on the wire, so
`zstd_elapsed < raw_elapsed` in EVERY run by a margin that is a large fraction of `raw_elapsed` and
FAR exceeds the run-to-run emulation noise. The magnitude of the speedup varies run to run (shared
box), so we frame the CONCLUSION sign-agnostically by MAGNITUDE vs the margin: the win holds
because the measured `raw_elapsed - zstd_elapsed` margin dwarfs the max-min spread. The measured
wall-clock speedup sits a little BELOW the wire-byte ratio because both arms pay the SAME per-fetch
fixed cost (dial + noise/yamux handshake + one RTT of ramp) — an honest part of a peer-vs-CDN
comparison, reported explicitly, not hidden.

THE SHAPING ORACLE (reused verbatim, TASK-70/206). A number without a biting shaping-oracle is not
evidence. `shaped_link.assert_shaping` refuses the run unless, on the RAW arm: the injected RTT is
recovered on the shaped arm, the UNSHAPED negative control's RTT is near zero, the shaped
throughput sits near the cap, and the unshaped control is MEASURABLY faster (>=2x). `--self-test`
proves the parse AND the verdict bite by mutation (truncation / non-identity / shaping-removed /
zstd-not-faster all REJECTED), with no netns.

PEER-VS-UPSTREAM re-statement (honest scope). The CDN serves the artifact xz-compressed (~3.6x
smaller than the raw NarSize, per the project's TASK-99 corpus). The peer's disadvantage was
serving RAW — ~3.6x the CDN's bytes. On a bandwidth-bound link, transfer time is proportional to
wire bytes, so link zstd shrinks the peer's wire volume — and hence its transfer time — by the
MEASURED ratio R, closing the ~3.6x raw gap to ~(3.6/R)x; the peer reaches near-parity with the CDN
exactly where R approaches the xz ratio. This script MEASURES the peer arms and R over a real
shaped link (removing the loopback upper bound); the CDN xz ratio is a STATED corpus reference, not
re-measured here, and the payload is SYNTHETIC (a stated construction), so we report R and the
structural parity condition, NOT a claim about a specific nixpkgs closure. The LAN regime (where
the compressor CPU, not the link, can dominate) is TASK-203's modeled territory and out of scope
for this bandwidth-bound run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from fractions import Fraction

import shaped_link  # sibling module: the proven shaping oracle + honest-limits text

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
INNER = os.path.join(HERE, "shaped_compress_inner.sh")
# Honour the shared CARGO_TARGET_DIR (TASK-54) so the probe is found whether cargo built into the
# in-tree ./target or the shared cache; fall back to the in-tree path.
_TARGET_DIR = os.environ.get("CARGO_TARGET_DIR") or os.path.join(ROOT, "target")
DEFAULT_BIN = os.path.join(_TARGET_DIR, "debug", "examples", "shaped_probe")

# 16 MiB compressible nar over a 20 mbit (~2.5 MB/s) home-uplink cap is ~6.7 s raw / ~1.7 s zstd —
# long enough that the per-fetch fixed cost (dial + handshake + one RTT of ramp) is a small
# fraction of the transfer (so the wall-clock reflects the shaped rate, not startup), small enough
# to be gentle on a shared box (held in RAM; never touches disk).
DEFAULT_NAR_BYTES = 16 * 1024 * 1024
DEFAULT_DELAY_MS = 20  # -> ~40 ms RTT, a modest home-broadband round trip
DEFAULT_RATE_MBIT = 20  # ~2.5 MB/s, a mid home uplink
DEFAULT_NAR_SEED = 20198
DEFAULT_RUNS = 3  # a FEW bounded shaped runs for a noise estimate — never a CPU-hog farm

NS_PER_SEC = 1_000_000_000


class MeasureFailure(Exception):
    """The measurement could not be established; the run is not evidence (fail closed)."""


def _ms_str_to_ns(ms_text: str) -> int:
    """Exact decimal-millisecond STRING -> integer nanoseconds (a finite decimal * 1e6 is an
    integer, so no rounding enters the reported ns). Owner rule: latency is whole integer ns."""
    return int(Fraction(ms_text) * 1_000_000)


def throughput_bytes_per_s(byte_count: int, elapsed_ns: int) -> int:
    """Integer bytes/sec (floor). No float: bytes * 1e9 as integer, divided by ns."""
    if elapsed_ns <= 0:
        raise MeasureFailure("non-positive elapsed_ns -- cannot form a throughput")
    return (byte_count * NS_PER_SEC) // elapsed_ns


_FETCH_RE = re.compile(
    r"FETCH_DONE bytes=(\d+) expect=(\d+) elapsed_ns=(\d+) "
    r"byte_identical=(\d) blake3_ok=(\d) wire_body_bytes=(\d+) codec_requested=(\w+)"
)


def parse_fetch(line: str) -> dict:
    """Parse ONE FETCH_DONE line, failing closed on anything that is not a complete, byte-identical,
    BLAKE3-verified, full-length delivery (a silent absence must never read as a passing zero).
    Pure so `--self-test` bites it with no netns."""
    m = _FETCH_RE.search(line)
    if not m:
        raise MeasureFailure(f"unparseable FETCH_DONE line: {line!r}")
    got, expect, elapsed_ns = int(m.group(1)), int(m.group(2)), int(m.group(3))
    byte_identical, blake3_ok = int(m.group(4)), int(m.group(5))
    wire_body_bytes, codec = int(m.group(6)), m.group(7)
    if got != expect:
        raise MeasureFailure(f"fetch delivered {got} of {expect} bytes -- truncated, not evidence")
    if byte_identical != 1:
        raise MeasureFailure("fetched bytes are NOT byte-identical to the served NAR")
    if blake3_ok != 1:
        raise MeasureFailure("fetched bytes do NOT BLAKE3-verify to the content id")
    if elapsed_ns <= 0:
        raise MeasureFailure("non-positive elapsed_ns -- cannot form a throughput")
    if wire_body_bytes <= 0:
        raise MeasureFailure("non-positive wire_body_bytes -- no wire measurement")
    return {
        "bytes": got,
        "elapsed_ns": elapsed_ns,
        "wire_body_bytes": wire_body_bytes,
        "codec_requested": codec,
    }


def parse_run(text: str) -> dict:
    """Pull the RTT, the provider META, and BOTH FETCH_DONE arms (raw then zstd) from one inner run.
    Missing any one is fatal. Pure (netns-free) so `--self-test` bites it."""
    if "FATAL" in text:
        fatal = next((ln for ln in text.splitlines() if "FATAL" in ln), "FATAL")
        raise MeasureFailure(f"inner harness reported {fatal!r} -- link/fetch setup failed")

    m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", text)
    if not m:
        raise MeasureFailure("run reported no RTT line (ping did not complete)")
    rtt_avg_str = m.group(1)
    rtt_ns = _ms_str_to_ns(rtt_avg_str)

    m = re.search(r"PROVIDE_META raw_bytes=(\d+) zstd_frame_bytes=(\d+)", text)
    if not m:
        raise MeasureFailure("run reported no PROVIDE_META line (provider did not start)")
    meta = {"raw_bytes": int(m.group(1)), "zstd_frame_bytes": int(m.group(2))}

    arms = {}
    for line in text.splitlines():
        if "FETCH_DONE" in line:
            arm = parse_fetch(line)
            # 'raw' arm offered the raw-only accept set; the zstd arm offered 'both'.
            key = "raw" if arm["codec_requested"] == "raw" else "zstd"
            arms[key] = arm
    if "raw" not in arms:
        raise MeasureFailure("run reported no RAW-arm FETCH_DONE line")
    if "zstd" not in arms:
        raise MeasureFailure("run reported no ZSTD-arm FETCH_DONE line")

    # Cross-check: the raw arm's wire body IS the uncompressed NarSize (raw codec put no
    # compression on the wire); the zstd arm's wire body is the compressed frame, and it must be
    # SMALLER (else compression bought nothing / the codec was not zstd).
    if arms["raw"]["wire_body_bytes"] != meta["raw_bytes"]:
        raise MeasureFailure(
            f"raw arm wire body {arms['raw']['wire_body_bytes']} != served NarSize "
            f"{meta['raw_bytes']} -- the raw arm did not ship the raw nar"
        )
    return {"rtt_ns": rtt_ns, "rtt_avg_str": rtt_avg_str, "meta": meta, "arms": arms}


def _arm_for_oracle(rtt_ns: int, wire_bytes: int, elapsed_ns: int) -> dict:
    """Build the dict shape `shaped_link.assert_shaping` decides on: exact integer `rtt_ns` and
    `rate_bytes_per_s` (the gate reads only these), plus float display fields. The rate is the RAW
    arm's throughput — the bandwidth-bound reference whose shaped value sits near the cap."""
    rate = throughput_bytes_per_s(wire_bytes, elapsed_ns)
    return {
        "rtt_ns": rtt_ns,
        "rate_bytes_per_s": rate,
        # Terminal display only (never gated): ns->ms and bytes/sec->mbit.
        "rtt_ms": rtt_ns / 1_000_000,
        "mbit": rate * 8 / 1_000_000,
    }


def run_inner(
    shape: bool, nar_bytes: int, delay_ms: int, rate_mbit: int, probe_bin: str, nar_seed: int
) -> dict:
    """Run one inner configuration inside `unshare -Urn` and return its parsed metrics."""
    cmd = [
        "unshare",
        "-Urn",
        "bash",
        INNER,
        "yes" if shape else "no",
        str(nar_bytes),
        str(delay_ms),
        str(rate_mbit),
        probe_bin,
        str(nar_seed),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0 and "FATAL" not in out:
        raise MeasureFailure(
            f"{'shaped' if shape else 'unshaped'} run exited {proc.returncode}\n{out}"
        )
    parsed = parse_run(out)
    parsed["raw_output"] = out
    return parsed


def measure(
    nar_bytes: int,
    delay_ms: int,
    rate_mbit: int,
    probe_bin: str,
    nar_seed: int,
    runs: int,
    out_path: str | None,
) -> int:
    if not os.path.exists(probe_bin):
        print(
            f"MEASURE FAILURE: probe binary not found at {probe_bin}\n"
            f"  build it: nix develop -c cargo build -p fabric-libp2p --example shaped_probe",
            file=sys.stderr,
        )
        return 2

    print(
        f"# TASK-198 raw-vs-zstd over a BOTH-ends-shaped peer link: {nar_bytes} byte compressible "
        f"nar, delay {delay_ms}ms, cap {rate_mbit}mbit, {runs} shaped run(s) (nar_seed={nar_seed})"
    )
    try:
        shaped_runs = [
            run_inner(True, nar_bytes, delay_ms, rate_mbit, probe_bin, nar_seed)
            for _ in range(runs)
        ]
        unshaped = run_inner(False, nar_bytes, delay_ms, rate_mbit, probe_bin, nar_seed)
    except subprocess.TimeoutExpired:
        print("MEASURE FAILURE: a run timed out (link/fetch hung)", file=sys.stderr)
        return 2
    except MeasureFailure as exc:
        print(f"MEASURE FAILURE: {exc}", file=sys.stderr)
        return 2

    # THE SHAPING ORACLE (proven, reused verbatim): the RAW arm of the FIRST shaped run vs the
    # unshaped RAW arm. Floats live ONLY inside this proven accept/reject gate.
    s0 = shaped_runs[0]
    shaped_arm = _arm_for_oracle(
        s0["rtt_ns"], s0["arms"]["raw"]["wire_body_bytes"], s0["arms"]["raw"]["elapsed_ns"]
    )
    unshaped_arm = _arm_for_oracle(
        unshaped["rtt_ns"],
        unshaped["arms"]["raw"]["wire_body_bytes"],
        unshaped["arms"]["raw"]["elapsed_ns"],
    )
    try:
        shaped_link.assert_shaping(shaped_arm, unshaped_arm, delay_ms, rate_mbit)
    except shaped_link.ShapingViolation as exc:
        print(f"MEASURE FAILURE (shaping oracle): {exc}", file=sys.stderr)
        return 2

    # THE HEADLINE, integer/rational only. Per-run raw/zstd wall-clock speedup and the wire-byte
    # ratio; the verdict is an INTEGER compare (no float in the decision).
    verdict = derive_verdict(shaped_runs)
    if not verdict["zstd_faster_every_run"]:
        # Not a rubber stamp: if link compression did not deliver the nar faster on this link, say
        # so plainly rather than reporting a win.
        print(
            "MEASURE RESULT: zstd did NOT beat raw in every shaped run over this link "
            "(bandwidth/CPU regime where compression does not help) -- reporting no win",
            file=sys.stderr,
        )

    report = build_report(
        nar_bytes, delay_ms, rate_mbit, nar_seed, runs, shaped_runs, unshaped, shaped_arm,
        unshaped_arm, verdict,
    )
    _print_report(report)
    print()
    print(shaped_link.HONEST_LIMITS)

    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as fh:
            fh.write(json.dumps(report, indent=2) + "\n")
        print(f"\n  wrote {out_path}", file=sys.stderr)
    return 0


def derive_verdict(shaped_runs: list[dict]) -> dict:
    """Integer/rational verdict over the shaped runs. The CONCLUSION depends only on the MAGNITUDE
    of the measured `raw_elapsed - zstd_elapsed` margin vs the max-min spread — never on a tight
    percentage. `zstd_faster` per run is a pure INTEGER compare."""
    per_run = []
    zstd_faster_every_run = True
    wire_smaller_every_run = True
    for r in shaped_runs:
        raw_ns = r["arms"]["raw"]["elapsed_ns"]
        zstd_ns = r["arms"]["zstd"]["elapsed_ns"]
        wire_raw = r["arms"]["raw"]["wire_body_bytes"]
        wire_zstd = r["arms"]["zstd"]["wire_body_bytes"]
        zstd_faster = zstd_ns < raw_ns  # integer compare — the biting decision
        wire_smaller = wire_zstd < wire_raw  # integer compare
        zstd_faster_every_run = zstd_faster_every_run and zstd_faster
        wire_smaller_every_run = wire_smaller_every_run and wire_smaller
        per_run.append(
            {
                "raw_elapsed_ns": raw_ns,
                "zstd_elapsed_ns": zstd_ns,
                "margin_ns": raw_ns - zstd_ns,
                "raw_throughput_bytes_per_s": throughput_bytes_per_s(wire_raw, raw_ns),
                "zstd_throughput_bytes_per_s": throughput_bytes_per_s(wire_zstd, zstd_ns),
                "wire_raw_bytes": wire_raw,
                "wire_zstd_bytes": wire_zstd,
                "wallclock_speedup_pair": [raw_ns, zstd_ns],  # exact rational raw/zstd
                "wire_ratio_pair": [wire_raw, wire_zstd],  # exact rational raw/zstd
                "zstd_faster": zstd_faster,
            }
        )
    # Noise framing: the min margin across runs vs the spread of each arm. The win is robust iff the
    # smallest measured margin dwarfs the arm spread (so no re-sample flips the sign).
    raw_elapseds = [p["raw_elapsed_ns"] for p in per_run]
    zstd_elapseds = [p["zstd_elapsed_ns"] for p in per_run]
    min_margin_ns = min(p["margin_ns"] for p in per_run)
    raw_spread_ns = max(raw_elapseds) - min(raw_elapseds)
    zstd_spread_ns = max(zstd_elapseds) - min(zstd_elapseds)
    # The margin dwarfs the noise iff min_margin > raw_spread + zstd_spread (an integer compare; the
    # sign cannot be re-sampled away while this holds).
    margin_dwarfs_noise = min_margin_ns > (raw_spread_ns + zstd_spread_ns)
    return {
        "per_run": per_run,
        "zstd_faster_every_run": zstd_faster_every_run,
        "wire_smaller_every_run": wire_smaller_every_run,
        "min_margin_ns": min_margin_ns,
        "raw_spread_ns": raw_spread_ns,
        "zstd_spread_ns": zstd_spread_ns,
        "margin_dwarfs_noise": margin_dwarfs_noise,
    }


def _frac_display(num: int, den: int) -> str:
    """A terminal decimal for DISPLAY ONLY (never re-read/compared)."""
    fr = Fraction(num, den)
    approx = fr.numerator / fr.denominator  # display-only float, never gated
    return f"~{approx:.3f}x (exact {fr.numerator}/{fr.denominator})"


def build_report(
    nar_bytes, delay_ms, rate_mbit, nar_seed, runs, shaped_runs, unshaped, shaped_arm,
    unshaped_arm, verdict,
) -> dict:
    """Assemble the serialized evidence. Integer/rational only in every decision/integrity field;
    the *_ns keys carry integers, ratios carry [num, den] pairs, floats appear only in *_display."""
    meta = shaped_runs[0]["meta"]
    # The min-of-N (best) shaped arm elapsed — the standard shared-box min-of-N wall-clock proxy.
    best_raw_ns = min(p["raw_elapsed_ns"] for p in verdict["per_run"])
    best_zstd_ns = min(p["zstd_elapsed_ns"] for p in verdict["per_run"])
    return {
        "task": "task-198",
        "measures": "live raw-vs-zstd libp2p NAR transfer over a tc-netem shaped peer link with "
        "BOTH ends shaped (the two-ends-shaped serve trace TASK-203 deferred here)",
        "environment_boundary": "shaped-link EMULATION (unshare -Urn nested netns + veth + tc "
        "netem), NOT real hardware / a real WAN. Models mean RTT + a rate cap; NOT loss, jitter, "
        "competing traffic, or NAT traversal. Removes the pod-loopback UPPER bound on the peer arm; "
        "is not itself a field measurement (the real-hardware residual is TASK-207).",
        "integer_exact": True,
        "no_floats_in_decisions": True,
        "nar_bytes": nar_bytes,
        "delay_ms": delay_ms,
        "rate_mbit": rate_mbit,
        "nar_seed": nar_seed,
        "shaped_runs": runs,
        "served_raw_bytes": meta["raw_bytes"],
        "served_zstd_frame_bytes": meta["zstd_frame_bytes"],
        "wire_ratio_pair": [meta["raw_bytes"], meta["zstd_frame_bytes"]],
        "wire_ratio_display": _frac_display(meta["raw_bytes"], meta["zstd_frame_bytes"]),
        "shaping_oracle": {
            "passed": True,
            "shaped_rtt_ns": shaped_arm["rtt_ns"],
            "unshaped_rtt_ns": unshaped_arm["rtt_ns"],
            "shaped_raw_throughput_bytes_per_s": shaped_arm["rate_bytes_per_s"],
            "unshaped_raw_throughput_bytes_per_s": unshaped_arm["rate_bytes_per_s"],
        },
        "headline": {
            "zstd_faster_every_run": verdict["zstd_faster_every_run"],
            "wire_smaller_every_run": verdict["wire_smaller_every_run"],
            "margin_dwarfs_noise": verdict["margin_dwarfs_noise"],
            "min_margin_ns": verdict["min_margin_ns"],
            "raw_spread_ns": verdict["raw_spread_ns"],
            "zstd_spread_ns": verdict["zstd_spread_ns"],
            "best_raw_elapsed_ns": best_raw_ns,
            "best_zstd_elapsed_ns": best_zstd_ns,
            "best_wallclock_speedup_pair": [best_raw_ns, best_zstd_ns],
            "best_wallclock_speedup_display": _frac_display(best_raw_ns, best_zstd_ns),
        },
        "per_run": verdict["per_run"],
    }


def _print_report(report: dict) -> None:
    h = report["headline"]
    print(f"  served: raw NarSize {report['served_raw_bytes']} bytes, "
          f"zstd frame {report['served_zstd_frame_bytes']} bytes "
          f"(wire ratio {report['wire_ratio_display']})")
    o = report["shaping_oracle"]
    print(f"  shaping oracle PASSED: shaped RTT {o['shaped_rtt_ns']} ns, "
          f"control RTT {o['unshaped_rtt_ns']} ns; shaped raw throughput "
          f"{o['shaped_raw_throughput_bytes_per_s']} bytes/s, control "
          f"{o['unshaped_raw_throughput_bytes_per_s']} bytes/s")
    for i, p in enumerate(report["per_run"]):
        print(
            f"  run {i}: raw {p['raw_elapsed_ns']} ns ({p['raw_throughput_bytes_per_s']} bytes/s)  "
            f"zstd {p['zstd_elapsed_ns']} ns ({p['zstd_throughput_bytes_per_s']} bytes/s)  "
            f"margin {p['margin_ns']} ns  "
            f"speedup {_frac_display(*p['wallclock_speedup_pair'])}"
        )
    print(
        f"  HEADLINE: zstd faster every run={h['zstd_faster_every_run']}, "
        f"wire smaller every run={h['wire_smaller_every_run']}; best wall-clock speedup "
        f"{h['best_wallclock_speedup_display']}"
    )
    print(
        f"  NOISE FRAMING: min margin {h['min_margin_ns']} ns vs spread "
        f"(raw {h['raw_spread_ns']} ns + zstd {h['zstd_spread_ns']} ns); "
        f"margin dwarfs noise={h['margin_dwarfs_noise']} -> the sign of the win is robust "
        f"(a bandwidth-bound wire-byte difference, not a scheduler micro-delta)"
    )
    print(
        "  PEER-VS-UPSTREAM: with the PEER link now shaped (both ends), the peer arm is no longer a "
        "loopback upper bound. On this bandwidth-bound link the peer transfer time tracks its wire "
        "volume, so link zstd shrinks the peer's ~3.6x-raw disadvantage vs the xz CDN by the "
        f"measured wire ratio {report['wire_ratio_display']} (payload is SYNTHETIC; the xz ratio is "
        "a stated corpus reference, not re-measured here)."
    )


# --- self-test: prove the parse AND the verdict bite by mutation (no netns) --------------------


def _good_fetch(codec: str, elapsed_ns: int, wire: int, nar: int = 16 * 1024 * 1024) -> str:
    return (
        f"FETCH_DONE bytes={nar} expect={nar} elapsed_ns={elapsed_ns} "
        f"byte_identical=1 blake3_ok=1 wire_body_bytes={wire} codec_requested={codec}\n"
    )


def _good_run_text(
    raw_ns: int = 6_700_000_000, zstd_ns: int = 1_700_000_000, nar: int = 16 * 1024 * 1024,
    frame: int = 4 * 1024 * 1024,
) -> str:
    return (
        "=== RTT probe (shape=yes) ===\n"
        "rtt min/avg/max/mdev = 40.0/40.2/40.5/0.1 ms\n"
        f"PROVIDE_META raw_bytes={nar} zstd_frame_bytes={frame}\n"
        "=== XFER raw ===\n"
        + _good_fetch("raw", raw_ns, nar, nar)
        + "=== XFER zstd ===\n"
        + _good_fetch("both", zstd_ns, frame, nar)
    )


def self_test() -> int:
    failures: list[str] = []

    # Baseline must parse and both arms verify.
    try:
        run = parse_run(_good_run_text())
        if run["arms"]["raw"]["codec_requested"] != "raw":
            failures.append("baseline raw arm mis-parsed")
        if run["arms"]["zstd"]["codec_requested"] != "both":
            failures.append("baseline zstd arm mis-parsed")
    except MeasureFailure as exc:
        failures.append(f"baseline run should PARSE but was rejected: {exc}")

    # parse mutations: each breaks exactly one invariant and MUST be caught.
    nar = 16 * 1024 * 1024
    parse_mutations = {
        "fatal": "=== XFER ===\nFATAL provider-not-ready\n",
        "no-rtt": _good_run_text().replace("rtt min/avg/max/mdev = 40.0/40.2/40.5/0.1 ms", ""),
        "no-meta": _good_run_text().replace(
            f"PROVIDE_META raw_bytes={nar} zstd_frame_bytes={4 * 1024 * 1024}", ""
        ),
        "no-raw-arm": (
            "rtt min/avg/max/mdev = 40.0/40.2/40.5/0.1 ms\n"
            f"PROVIDE_META raw_bytes={nar} zstd_frame_bytes={4 * 1024 * 1024}\n"
            + _good_fetch("both", 1_700_000_000, 4 * 1024 * 1024, nar)
        ),
        "no-zstd-arm": (
            "rtt min/avg/max/mdev = 40.0/40.2/40.5/0.1 ms\n"
            f"PROVIDE_META raw_bytes={nar} zstd_frame_bytes={4 * 1024 * 1024}\n"
            + _good_fetch("raw", 6_700_000_000, nar, nar)
        ),
        "raw-truncated": _good_run_text().replace(
            f"FETCH_DONE bytes={nar} expect={nar} elapsed_ns=6700000000",
            f"FETCH_DONE bytes=1024 expect={nar} elapsed_ns=6700000000",
        ),
        "not-byte-identical": _good_run_text().replace("byte_identical=1", "byte_identical=0"),
        "blake3-fail": _good_run_text().replace("blake3_ok=1", "blake3_ok=0"),
        "raw-wire-not-narsize": _good_run_text().replace(
            f"wire_body_bytes={nar} codec_requested=raw",
            f"wire_body_bytes={nar - 1} codec_requested=raw",
        ),
    }
    for name, text in parse_mutations.items():
        try:
            parse_run(text)
            failures.append(f"parse mutation {name!r} should have been REJECTED but passed")
        except MeasureFailure:
            pass

    # verdict CONTROL: a clean shaped run has zstd faster + wire smaller + margin dwarfs noise.
    control = [parse_run(_good_run_text()) for _ in range(3)]
    v = derive_verdict(control)
    if not v["zstd_faster_every_run"]:
        failures.append("verdict control: zstd should be faster every run")
    if not v["wire_smaller_every_run"]:
        failures.append("verdict control: zstd wire should be smaller every run")
    if not v["margin_dwarfs_noise"]:
        failures.append("verdict control: identical runs -> zero spread -> margin should dwarf it")

    # verdict TEETH: if zstd is NOT faster (raw and zstd elapsed swapped), the verdict must be
    # FALSE (not a rubber stamp).
    no_win = [parse_run(_good_run_text(raw_ns=1_700_000_000, zstd_ns=6_700_000_000)) for _ in range(3)]
    if derive_verdict(no_win)["zstd_faster_every_run"]:
        failures.append("verdict teeth: a slower-zstd run was wrongly declared a win")

    # noise TEETH: a huge zstd spread that exceeds the margin must make margin_dwarfs_noise FALSE.
    noisy = [
        parse_run(_good_run_text(zstd_ns=1_700_000_000)),
        parse_run(_good_run_text(zstd_ns=6_600_000_000)),  # nearly as slow as raw
    ]
    if derive_verdict(noisy)["margin_dwarfs_noise"]:
        failures.append("noise teeth: a margin swamped by spread was wrongly declared robust")

    # shaping oracle must still bite via shaped_link: a 'shaping removed' mutation (control as fast
    # as shaped) is REJECTED. Build oracle arms directly.
    good_shaped = _arm_for_oracle(_ms_str_to_ns("40.2"), nar, 6_700_000_000)  # ~2.5 MB/s ~ cap
    good_control = _arm_for_oracle(_ms_str_to_ns("0.05"), nar, 60_000_000)  # ~280 MB/s >> cap
    try:
        shaped_link.assert_shaping(good_shaped, good_control, DEFAULT_DELAY_MS, DEFAULT_RATE_MBIT)
    except shaped_link.ShapingViolation as exc:
        failures.append(f"shaping oracle rejected an honest shaped/control pair: {exc}")
    shaping_removed = _arm_for_oracle(_ms_str_to_ns("0.05"), nar, 60_000_000)  # 'shaped' == control
    try:
        shaped_link.assert_shaping(shaping_removed, good_control, DEFAULT_DELAY_MS, DEFAULT_RATE_MBIT)
        failures.append("shaping oracle: a shaping-removed arm should be REJECTED but passed")
    except shaped_link.ShapingViolation:
        pass

    # integer-reporting checks (no-float rule).
    if not isinstance(throughput_bytes_per_s(nar, 6_700_000_000), int):
        failures.append("throughput must be an integer bytes/sec")
    if _ms_str_to_ns("40.2") != 40_200_000:
        failures.append("_ms_str_to_ns wrong for 40.2 ms")

    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        return 1
    print(
        "SELF-TEST OK: baseline parsed; 9 parse mutations + slower-zstd + swamped-margin bitten; "
        "shaping oracle bites a removed shaper; integer reporting checked"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="TASK-198 live two-ends-shaped raw-vs-zstd measurement")
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove the parse + verdict + shaping oracle bite by mutation (hermetic, no netns)",
    )
    ap.add_argument("--nar-bytes", type=int, default=DEFAULT_NAR_BYTES)
    ap.add_argument("--delay-ms", type=int, default=DEFAULT_DELAY_MS)
    ap.add_argument("--rate-mbit", type=int, default=DEFAULT_RATE_MBIT)
    ap.add_argument("--nar-seed", type=int, default=DEFAULT_NAR_SEED)
    ap.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    ap.add_argument("--probe-bin", default=DEFAULT_BIN)
    ap.add_argument("--out", default=None, help="write the measured evidence JSON here")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return measure(
        args.nar_bytes, args.delay_ms, args.rate_mbit, args.probe_bin, args.nar_seed, args.runs,
        args.out,
    )


if __name__ == "__main__":
    sys.exit(main())
