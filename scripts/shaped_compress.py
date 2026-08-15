#!/usr/bin/env python3
"""TASK-198: the LIVE two-ends-shaped raw-vs-zstd peer transfer measurement.

WHAT THIS IS. TASK-203 (`scripts/task203_pipelined_measure.py`) produced an IDEALIZED, integer-
exact MODEL of whether link zstd beats raw over a link; it is explicitly NOT a measured wall-clock
result, and it names this task as the live counterpart it defers to ("a live two-ends-shaped serve
trace (TASK-198) is out of scope; the flip is a conditional estimate, not a measured wall-clock
result"). This script is that live counterpart: it runs the REAL libp2p streamed `/nar/3` fetch
(TASK-203's streaming zstd serve) between two swarm nodes whose traffic traverses a `tc netem`-
shaped `veth` pair with BOTH ends shaped, transfers the SAME compressible nar RAW and then ZSTD
over that same link, and reports the MEASURED wall-clock of each arm.

WHAT IS AND IS NOT IN THE TIMED WINDOW (the TASK-198 F3 honesty correction). The two nodes discover
nothing over the DHT here and the dial + Noise/yamux handshake happen ONCE, out of band, BEFORE the
clock starts: the probe injects the provider multiaddr+PeerId, completes the dial, and only THEN
starts timing. So this measures an ALREADY-CONNECTED open-stream `/nar/3` fetch — not a
discover->fetch->serve round. What both arms pay ONCE inside the timed window, independent of
payload size, is the request round-trip: open the `/nar/3` substream, write the request header, and
wait for the first response byte (~one RTT of first-byte latency), plus the stream's flow-control
ramp (TCP + yamux windows opening from their initial size). That per-fetch fixed cost does NOT
shrink with compression, which is exactly why the measured wall-clock speedup sits a little BELOW
the wire-byte ratio — stated explicitly, not attributed to a dial/handshake that the clock excludes.

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
  * the COUNTED transport body bytes each arm actually shipped (integer bytes, from the fetcher's
    CountingReader) — the raw arm's counted body and the zstd arm's counted body. The HEADLINE wire
    ratio is derived EXCLUSIVELY from these two like-unit COUNTED quantities (counted raw wire /
    counted zstd wire). The provider-side bulk-compressed frame size is kept ONLY as an auxiliary
    cross-check that must AGREE with the counted zstd body within a tiny tolerance — if it
    disagrees, the run is REJECTED; it never silently becomes the headline. Never NarSize-vs-
    compressed (the trap that recurred 3x): both numerator and denominator of the headline ratio are
    COUNTED wire bytes;
  * throughput (integer bytes/sec) and the raw/zstd wall-clock speedup as an EXACT RATIONAL
    (`fractions.Fraction`, compared by cross-multiplication).

WHY THE SIGN IS ROBUST (unlike TASK-203's noise-straddling CPU delta). The raw-vs-zstd delta here
is NOT a scheduler-dominated CPU micro-delta. On a BANDWIDTH-BOUND link the transfer time is set by
the WIRE-BYTE volume, and the zstd arm measurably puts ~R x fewer bytes on the wire, so
`zstd_elapsed < raw_elapsed` in EVERY run by a margin that is a large fraction of `raw_elapsed` and
FAR exceeds the run-to-run emulation noise. The magnitude of the speedup varies run to run (shared
box), so we frame the CONCLUSION by MAGNITUDE vs the margin: the OBSERVED sign holds because the
measured `raw_elapsed - zstd_elapsed` margin dwarfs the max-min spread. Three fixed-order runs
cannot GUARANTEE no future re-sample ever flips it; the claim is that the OBSERVED sign is robust,
its margin many times the observed spread.

FAIL CLOSED (the TASK-198 F2 correction). This is an EVIDENCE GENERATOR: it must never publish its
conclusion when its own guard trips. Every load-bearing check — zstd faster in every shaped run,
the margin dwarfing the spread, EVERY headline run shape-gated against the negative control, the
counted wire bytes consistent across runs, and the counted zstd body agreeing with the bulk frame —
is required. If ANY fails, the report prints `VERDICT: REJECTED` (NOT the win/robustness/parity
conclusions), the affirmative evidence is NOT written, and the process exits NON-ZERO. `--self-test`
asserts on the RENDERED report text AND the exit status (not merely internal booleans): a mutation
(slower zstd, spread-swamped margin, shaping removed, a run not shape-gated, wire/bulk mismatch)
must make the rendered report omit the win/parity conclusion AND exit non-zero.

THE SHAPING ORACLE (reused verbatim, TASK-70/206). A number without a biting shaping-oracle is not
evidence. `shaped_link.assert_shaping` refuses a run unless, on its RAW arm: the injected RTT is
recovered on the shaped arm, the UNSHAPED negative control's RTT is near zero, the shaped throughput
sits near the cap, and the unshaped control is MEASURABLY faster (>=2x). EVERY shaped run that
contributes to the headline is gated (not just the first), so an unshaped run cannot slip into the
minimum. `--self-test` proves the parse AND the verdict/oracle bite by mutation, with no netns.

PEER-VS-UPSTREAM re-statement (honest scope). The CDN serves the artifact xz-compressed (~3.6x
smaller than the raw NarSize, per the project's TASK-99 corpus). The peer's disadvantage was
serving RAW — ~3.6x the CDN's bytes. On a bandwidth-bound link, transfer time is proportional to
wire bytes, so link zstd shrinks the peer's WIRE VOLUME — and hence its transfer time — by the
MEASURED ratio R, closing the ~3.6x raw gap toward parity; the near-parity is a STRUCTURAL result
on WIRE VOLUME (the peer reaches near-parity with the CDN exactly where R approaches the xz ratio).
This script MEASURES the peer arms and R over a real shaped link (removing the loopback upper
bound); the CDN xz ratio is a STATED corpus reference, not re-measured here, and the payload is
SYNTHETIC (a stated construction), so we report R and the structural parity condition, NOT a claim
about a specific nixpkgs closure. The LAN regime (where the compressor CPU, not the link, can
dominate) is TASK-203's modeled territory and out of scope for this bandwidth-bound run.
"""

from __future__ import annotations

import argparse
import contextlib
import io
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
# long enough that the per-fetch fixed cost (the request round-trip + one RTT of ramp; NOT dial or
# handshake, which are out of the timed window) is a small fraction of the transfer (so the
# wall-clock reflects the shaped rate, not startup), small enough to be gentle on a shared box
# (held in RAM; never touches disk).
DEFAULT_NAR_BYTES = 16 * 1024 * 1024
DEFAULT_DELAY_MS = 20  # -> ~40 ms RTT, a modest home-broadband round trip
DEFAULT_RATE_MBIT = 20  # ~2.5 MB/s, a mid home uplink
DEFAULT_NAR_SEED = 20198
DEFAULT_RUNS = 3  # a FEW bounded shaped runs for a noise estimate — never a CPU-hog farm

NS_PER_SEC = 1_000_000_000

# The streamed serve reframes the zstd body in blocks, so the counted zstd body can differ from a
# single bulk `compress_zstd` frame by up to ~1/64 (the streamed-vs-bulk tolerance the codec test
# pins). The cross-check accepts a difference of at most 1/64 of the counted body; anything larger
# means the auxiliary bulk figure and the authoritative counted body disagree, which REJECTS the run
# rather than letting the two silently diverge. Exact integer compare (no float): 64*|d| <= counted.
WIRE_BULK_TOLERANCE_DEN = 64


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

    # Structural cross-check on the RAW arm: it offered the raw-only accept set, so its COUNTED wire
    # body IS the uncompressed NarSize (no compression on the wire). If it differs, the raw arm did
    # not ship the raw nar and the run is not evidence. (The zstd arm's counted body is cross-checked
    # against the bulk frame later, with a tolerance, because the streamed frame reblocks.)
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


def derive_verdict(shaped_runs: list[dict]) -> dict:
    """Integer/rational verdict over the shaped runs. The CONCLUSION depends only on the MAGNITUDE
    of the measured `raw_elapsed - zstd_elapsed` margin vs the max-min spread — never on a tight
    percentage. `zstd_faster` per run is a pure INTEGER compare. The headline wire ratio is derived
    from the COUNTED per-run wire bodies (raw vs zstd, like-units) — never NarSize-vs-compressed."""
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
                "wire_ratio_pair": [wire_raw, wire_zstd],  # exact rational raw/zstd (COUNTED)
                "zstd_faster": zstd_faster,
            }
        )
    # Noise framing: the min margin across runs vs the spread of each arm. The OBSERVED win is robust
    # iff the smallest measured margin dwarfs the arm spread.
    raw_elapseds = [p["raw_elapsed_ns"] for p in per_run]
    zstd_elapseds = [p["zstd_elapsed_ns"] for p in per_run]
    min_margin_ns = min(p["margin_ns"] for p in per_run)
    raw_spread_ns = max(raw_elapseds) - min(raw_elapseds)
    zstd_spread_ns = max(zstd_elapseds) - min(zstd_elapseds)
    # The margin dwarfs the noise iff min_margin > raw_spread + zstd_spread (an integer compare); the
    # OBSERVED sign cannot be re-sampled away within this run set while this holds.
    margin_dwarfs_noise = min_margin_ns > (raw_spread_ns + zstd_spread_ns)

    # The COUNTED wire bodies must be consistent across the headline runs (the payload + codec are
    # deterministic, so every run must ship the same body volumes); if they drift, the headline ratio
    # is not well-defined and the run is rejected. The headline ratio is [counted raw, counted zstd].
    wire_raw_set = {p["wire_raw_bytes"] for p in per_run}
    wire_zstd_set = {p["wire_zstd_bytes"] for p in per_run}
    wire_bytes_consistent = len(wire_raw_set) == 1 and len(wire_zstd_set) == 1
    wire_raw_common = per_run[0]["wire_raw_bytes"]
    wire_zstd_common = per_run[0]["wire_zstd_bytes"]
    return {
        "per_run": per_run,
        "zstd_faster_every_run": zstd_faster_every_run,
        "wire_smaller_every_run": wire_smaller_every_run,
        "min_margin_ns": min_margin_ns,
        "raw_spread_ns": raw_spread_ns,
        "zstd_spread_ns": zstd_spread_ns,
        "margin_dwarfs_noise": margin_dwarfs_noise,
        "wire_bytes_consistent": wire_bytes_consistent,
        "wire_raw_common": wire_raw_common,
        "wire_zstd_common": wire_zstd_common,
    }


def gate_shaping(
    shaped_runs: list[dict], unshaped: dict, delay_ms: int, rate_mbit: int
) -> dict:
    """Apply the proven shaping oracle to the RAW arm of EVERY shaped run that contributes to the
    headline (TASK-198 F5), against the single unshaped negative control. Returns a per-run pass/
    fail plus the aggregate `all_gated`. An unshaped or mis-shaped run cannot slip into the minimum
    because its own gate fails and rejects the whole measurement (fail closed)."""
    unshaped_arm = _arm_for_oracle(
        unshaped["rtt_ns"],
        unshaped["arms"]["raw"]["wire_body_bytes"],
        unshaped["arms"]["raw"]["elapsed_ns"],
    )
    per_run = []
    all_gated = True
    for r in shaped_runs:
        shaped_arm = _arm_for_oracle(
            r["rtt_ns"], r["arms"]["raw"]["wire_body_bytes"], r["arms"]["raw"]["elapsed_ns"]
        )
        entry = {
            "shaped_rtt_ns": shaped_arm["rtt_ns"],
            "shaped_raw_throughput_bytes_per_s": shaped_arm["rate_bytes_per_s"],
        }
        try:
            shaped_link.assert_shaping(shaped_arm, unshaped_arm, delay_ms, rate_mbit)
            entry["passed"] = True
        except shaped_link.ShapingViolation as exc:
            entry["passed"] = False
            entry["reason"] = str(exc)
            all_gated = False
        per_run.append(entry)
    return {
        "all_gated": all_gated,
        "unshaped_rtt_ns": unshaped_arm["rtt_ns"],
        "unshaped_raw_throughput_bytes_per_s": unshaped_arm["rate_bytes_per_s"],
        "per_run": per_run,
    }


def crosscheck_wire_bulk(wire_zstd_counted: int, bulk_zstd_frame: int) -> dict:
    """Auxiliary cross-check (TASK-198 F1): the provider-side bulk `compress_zstd` frame size must
    AGREE with the authoritative COUNTED zstd wire body within the streamed-vs-bulk tolerance. This
    figure is NEVER the headline (the headline is counted-raw / counted-zstd); it is only a
    consistency check, and a disagreement REJECTS the run rather than silently diverging. Exact
    integer compare: WIRE_BULK_TOLERANCE_DEN * |counted - bulk| <= counted."""
    diff = abs(wire_zstd_counted - bulk_zstd_frame)
    ok = (
        wire_zstd_counted > 0
        and bulk_zstd_frame > 0
        and WIRE_BULK_TOLERANCE_DEN * diff <= wire_zstd_counted
    )
    return {
        "ok": ok,
        "counted_zstd_wire_bytes": wire_zstd_counted,
        "bulk_zstd_frame_bytes": bulk_zstd_frame,
        "abs_diff_bytes": diff,
        "tolerance_den": WIRE_BULK_TOLERANCE_DEN,
    }


def _frac_display(num: int, den: int) -> str:
    """A terminal decimal for DISPLAY ONLY (never re-read/compared)."""
    fr = Fraction(num, den)
    approx = fr.numerator / fr.denominator  # display-only float, never gated
    return f"~{approx:.3f}x (exact {fr.numerator}/{fr.denominator})"


def finalize(
    shaped_runs: list[dict],
    unshaped: dict,
    delay_ms: int,
    rate_mbit: int,
    nar_bytes: int,
    nar_seed: int,
    runs: int,
) -> dict:
    """Given the parsed shaped runs + the unshaped control, gate every run, derive the verdict,
    run the auxiliary cross-check, and assemble the serialized report — including the FAIL-CLOSED
    `accepted` decision (TASK-198 F2) over every load-bearing flag. Pure of netns so `--self-test`
    can drive the whole render+exit path by mutation."""
    verdict = derive_verdict(shaped_runs)
    shaping = gate_shaping(shaped_runs, unshaped, delay_ms, rate_mbit)
    crosscheck = crosscheck_wire_bulk(
        verdict["wire_zstd_common"], shaped_runs[0]["meta"]["zstd_frame_bytes"]
    )

    # The load-bearing flags. EVERY one must hold or the run is not evidence of a win (fail closed).
    flags = {
        "zstd_faster_every_run": verdict["zstd_faster_every_run"],
        "wire_smaller_every_run": verdict["wire_smaller_every_run"],
        "margin_dwarfs_noise": verdict["margin_dwarfs_noise"],
        "all_runs_shape_gated": shaping["all_gated"],
        "wire_bytes_consistent": verdict["wire_bytes_consistent"],
        "wire_bulk_crosscheck_ok": crosscheck["ok"],
    }
    accepted = all(flags.values())
    failure_reasons = [name for name, ok in flags.items() if not ok]

    meta = shaped_runs[0]["meta"]
    # The min-of-N (best) shaped arm elapsed — the standard shared-box min-of-N wall-clock proxy.
    best_raw_ns = min(p["raw_elapsed_ns"] for p in verdict["per_run"])
    best_zstd_ns = min(p["zstd_elapsed_ns"] for p in verdict["per_run"])
    # THE HEADLINE wire ratio: COUNTED raw wire body / COUNTED zstd wire body (like-units, exact
    # rational). Never NarSize-vs-compressed.
    wire_raw = verdict["wire_raw_common"]
    wire_zstd = verdict["wire_zstd_common"]
    return {
        "task": "task-198",
        "measures": "live raw-vs-zstd libp2p NAR transfer over a tc-netem shaped peer link with "
        "BOTH ends shaped (the two-ends-shaped serve trace TASK-203 deferred here). The timed "
        "window is an ALREADY-CONNECTED open-stream /nar/3 fetch: discovery, dial, and the "
        "Noise/yamux handshake happen out of band BEFORE the clock starts.",
        "environment_boundary": "shaped-link EMULATION (unshare -Urn nested netns + veth + tc "
        "netem), NOT real hardware / a real WAN. Models mean RTT + a rate cap; NOT loss, jitter, "
        "competing traffic, or NAT traversal. Removes the pod-loopback UPPER bound on the peer arm; "
        "is not itself a field measurement (the real-hardware residual is TASK-207).",
        "integer_exact": True,
        "no_floats_in_decisions": True,
        "accepted": accepted,
        "verdict": "ACCEPTED" if accepted else "REJECTED",
        "failure_reasons": failure_reasons,
        "load_bearing_flags": flags,
        "nar_bytes": nar_bytes,
        "delay_ms": delay_ms,
        "rate_mbit": rate_mbit,
        "nar_seed": nar_seed,
        "shaped_runs": runs,
        "served_raw_bytes": meta["raw_bytes"],
        # AUXILIARY only (never the headline): provider-side bulk zstd frame + its cross-check.
        "aux_bulk_zstd_frame_bytes": meta["zstd_frame_bytes"],
        "wire_bulk_crosscheck": crosscheck,
        # THE HEADLINE wire ratio, from COUNTED wire bodies (like-units).
        "wire_raw_bytes": wire_raw,
        "wire_zstd_bytes": wire_zstd,
        "wire_ratio_pair": [wire_raw, wire_zstd],
        "wire_ratio_display": _frac_display(wire_raw, wire_zstd),
        "shaping_oracle": shaping,
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
    """Render the report. FAIL CLOSED: the win / robustness / parity conclusions and the
    `VERDICT: ACCEPTED` line are printed ONLY when every load-bearing flag passed. When rejected,
    the raw per-run data is still shown (it is factual), but the affirmative conclusions are
    suppressed and a `VERDICT: REJECTED` line names the failed checks."""
    h = report["headline"]
    print(
        f"  served: raw NarSize {report['served_raw_bytes']} bytes; COUNTED wire bodies: raw "
        f"{report['wire_raw_bytes']} bytes, zstd {report['wire_zstd_bytes']} bytes "
        f"(HEADLINE wire ratio raw/zstd {report['wire_ratio_display']}, from COUNTED wire bytes)"
    )
    cc = report["wire_bulk_crosscheck"]
    print(
        f"  aux cross-check: provider bulk zstd frame {report['aux_bulk_zstd_frame_bytes']} bytes "
        f"vs COUNTED zstd wire {cc['counted_zstd_wire_bytes']} bytes -> "
        f"|diff| {cc['abs_diff_bytes']} bytes (<= 1/{cc['tolerance_den']} tolerance), agree={cc['ok']}"
    )
    o = report["shaping_oracle"]
    print(
        f"  shaping oracle: {sum(1 for p in o['per_run'] if p['passed'])}/{len(o['per_run'])} "
        f"shaped runs gated vs control (control RTT {o['unshaped_rtt_ns']} ns, control raw "
        f"throughput {o['unshaped_raw_throughput_bytes_per_s']} bytes/s); all_gated={o['all_gated']}"
    )
    for i, (p, g) in enumerate(zip(report["per_run"], o["per_run"])):
        print(
            f"  run {i}: raw {p['raw_elapsed_ns']} ns ({p['raw_throughput_bytes_per_s']} bytes/s)  "
            f"zstd {p['zstd_elapsed_ns']} ns ({p['zstd_throughput_bytes_per_s']} bytes/s)  "
            f"margin {p['margin_ns']} ns  speedup {_frac_display(*p['wallclock_speedup_pair'])}  "
            f"shape-gated={g['passed']}"
        )

    if not report["accepted"]:
        print(
            "  VERDICT: REJECTED -- this run is NOT evidence of a win. Failed load-bearing checks: "
            + ", ".join(report["failure_reasons"])
        )
        return

    print(
        f"  VERDICT: ACCEPTED -- zstd faster every run={h['zstd_faster_every_run']}, wire smaller "
        f"every run={h['wire_smaller_every_run']}; best wall-clock speedup "
        f"{h['best_wallclock_speedup_display']}"
    )
    print(
        f"  NOISE FRAMING: min margin {h['min_margin_ns']} ns vs spread "
        f"(raw {h['raw_spread_ns']} ns + zstd {h['zstd_spread_ns']} ns); "
        f"margin dwarfs noise={h['margin_dwarfs_noise']} -> the OBSERVED sign of the win is robust "
        f"(its margin many times the observed spread; a bandwidth-bound wire-byte difference, not a "
        f"scheduler micro-delta). Three fixed-order runs cannot guarantee no future re-sample flips "
        f"it; the claim is about the OBSERVED sign."
    )
    print(
        "  PEER-VS-UPSTREAM: with the PEER link now shaped (both ends), the peer arm is no longer a "
        "loopback upper bound. On this bandwidth-bound link the peer transfer time tracks its WIRE "
        "VOLUME, so link zstd shrinks the peer's ~3.6x-raw disadvantage vs the xz CDN by the "
        f"measured COUNTED wire ratio {report['wire_ratio_display']}. The near-parity is STRUCTURAL "
        "on WIRE VOLUME (payload is SYNTHETIC; the xz ratio is a stated corpus reference, not "
        "re-measured here) -- NOT a latency-parity claim; the measured wall-clock speedup "
        f"{h['best_wallclock_speedup_display']} is smaller, by the shared per-fetch request "
        "round-trip both arms pay once."
    )


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

    report = finalize(shaped_runs, unshaped, delay_ms, rate_mbit, nar_bytes, nar_seed, runs)
    _print_report(report)
    print()
    print(shaped_link.HONEST_LIMITS)

    if not report["accepted"]:
        # FAIL CLOSED: never write the affirmative evidence file when a guard tripped, and exit
        # non-zero so a caller/gate cannot mistake a rejected run for a passing measurement.
        print(
            "MEASURE RESULT: REJECTED -- failed load-bearing checks: "
            + ", ".join(report["failure_reasons"])
            + "; affirmative evidence NOT written",
            file=sys.stderr,
        )
        return 1

    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as fh:
            fh.write(json.dumps(report, indent=2) + "\n")
        print(f"\n  wrote {out_path}", file=sys.stderr)
    return 0


# --- self-test: prove the parse AND the render+exit bite by mutation (no netns) ----------------


def _good_fetch(codec: str, elapsed_ns: int, wire: int, nar: int = 16 * 1024 * 1024) -> str:
    return (
        f"FETCH_DONE bytes={nar} expect={nar} elapsed_ns={elapsed_ns} "
        f"byte_identical=1 blake3_ok=1 wire_body_bytes={wire} codec_requested={codec}\n"
    )


def _good_run_text(
    raw_ns: int = 6_700_000_000,
    zstd_ns: int = 1_700_000_000,
    nar: int = 16 * 1024 * 1024,
    frame: int = 4 * 1024 * 1024,
    rtt_avg: str = "40.2",
    bulk_frame: int | None = None,
) -> str:
    """A synthetic shaped-run capture. `frame` is the COUNTED zstd wire body; `bulk_frame` is the
    provider-side PROVIDE_META bulk figure (defaults to == frame so the cross-check agrees)."""
    if bulk_frame is None:
        bulk_frame = frame
    return (
        f"=== RTT probe (shape=yes) ===\n"
        f"rtt min/avg/max/mdev = {rtt_avg}/{rtt_avg}/{rtt_avg}/0.1 ms\n"
        f"PROVIDE_META raw_bytes={nar} zstd_frame_bytes={bulk_frame}\n"
        "=== XFER raw ===\n"
        + _good_fetch("raw", raw_ns, nar, nar)
        + "=== XFER zstd ===\n"
        + _good_fetch("both", zstd_ns, frame, nar)
    )


def _good_unshaped_text(nar: int = 16 * 1024 * 1024, frame: int = 4 * 1024 * 1024) -> str:
    """A synthetic UNSHAPED negative control: near-zero RTT and a throughput far above the cap
    (raw ~56 MB/s), so the shaping oracle can tell the shaped runs apart from it."""
    return _good_run_text(
        raw_ns=300_000_000, zstd_ns=80_000_000, nar=nar, frame=frame, rtt_avg="0.05"
    )


def _render_and_exit(shaped_runs: list[dict], unshaped: dict) -> tuple[str, int]:
    """Drive the full finalize -> render -> exit path and capture BOTH the rendered text and the
    exit status the way `measure` would derive it (0 iff accepted). This is what the F2 self-test
    asserts on — the RENDERED OUTPUT and the EXIT STATUS, not merely internal booleans."""
    report = finalize(
        shaped_runs, unshaped, DEFAULT_DELAY_MS, DEFAULT_RATE_MBIT, DEFAULT_NAR_BYTES,
        DEFAULT_NAR_SEED, len(shaped_runs),
    )
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _print_report(report)
    exit_code = 0 if report["accepted"] else 1
    return buf.getvalue(), exit_code


def self_test() -> int:
    failures: list[str] = []
    nar = 16 * 1024 * 1024
    frame = 4 * 1024 * 1024

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
    parse_mutations = {
        "fatal": "=== XFER ===\nFATAL provider-not-ready\n",
        "no-rtt": _good_run_text().replace("rtt min/avg/max/mdev = 40.2/40.2/40.2/0.1 ms", ""),
        "no-meta": _good_run_text().replace(f"PROVIDE_META raw_bytes={nar} zstd_frame_bytes={frame}", ""),
        "no-raw-arm": (
            "rtt min/avg/max/mdev = 40.2/40.2/40.2/0.1 ms\n"
            f"PROVIDE_META raw_bytes={nar} zstd_frame_bytes={frame}\n"
            + _good_fetch("both", 1_700_000_000, frame, nar)
        ),
        "no-zstd-arm": (
            "rtt min/avg/max/mdev = 40.2/40.2/40.2/0.1 ms\n"
            f"PROVIDE_META raw_bytes={nar} zstd_frame_bytes={frame}\n"
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

    # --- FAIL-CLOSED render+exit teeth (TASK-198 F2): assert on the RENDERED OUTPUT + EXIT STATUS.
    good_unshaped = parse_run(_good_unshaped_text())

    # CONTROL: a clean 3-run set is ACCEPTED, prints the win/parity conclusion, and exits 0.
    good_shaped = [parse_run(_good_run_text()) for _ in range(3)]
    out, code = _render_and_exit(good_shaped, good_unshaped)
    if code != 0:
        failures.append("fail-closed control: a clean run should exit 0")
    if "VERDICT: ACCEPTED" not in out:
        failures.append("fail-closed control: a clean run should render VERDICT: ACCEPTED")
    if "the OBSERVED sign of the win is robust" not in out:
        failures.append("fail-closed control: a clean run should render the robustness conclusion")
    if "PEER-VS-UPSTREAM" not in out:
        failures.append("fail-closed control: a clean run should render the parity conclusion")

    def _bites(name: str, shaped_runs: list[dict], unshaped: dict) -> None:
        out, code = _render_and_exit(shaped_runs, unshaped)
        if code == 0:
            failures.append(f"F2 mutation {name!r}: should exit NON-ZERO but exited 0")
        if "VERDICT: ACCEPTED" in out:
            failures.append(f"F2 mutation {name!r}: rendered VERDICT: ACCEPTED (must be rejected)")
        if "VERDICT: REJECTED" not in out:
            failures.append(f"F2 mutation {name!r}: did not render VERDICT: REJECTED")
        if "the OBSERVED sign of the win is robust" in out:
            failures.append(f"F2 mutation {name!r}: still rendered the robustness conclusion")
        if "PEER-VS-UPSTREAM" in out:
            failures.append(f"F2 mutation {name!r}: still rendered the parity conclusion")

    # (1) slower zstd: raw/zstd elapsed swapped -> not a win.
    _bites(
        "slower-zstd",
        [parse_run(_good_run_text(raw_ns=1_700_000_000, zstd_ns=6_700_000_000)) for _ in range(3)],
        good_unshaped,
    )
    # (2) spread-swamped margin: zstd still faster every run, but its spread exceeds the margin.
    _bites(
        "swamped-margin",
        [
            parse_run(_good_run_text(zstd_ns=1_700_000_000)),
            parse_run(_good_run_text(zstd_ns=6_600_000_000)),
        ],
        good_unshaped,
    )
    # (3) shaping removed: the 'control' is as slow/shaped as the shaped runs -> not distinguishable.
    _bites(
        "shaping-removed",
        [parse_run(_good_run_text()) for _ in range(3)],
        parse_run(_good_run_text()),  # control == shaped: oracle must reject every run's gate
    )
    # (4) a headline run NOT shape-gated: one run's raw arm collapses far below the cap (F5) — it
    #     must not slip into the minimum; its failed gate rejects the whole measurement.
    _bites(
        "run-not-shape-gated",
        [
            parse_run(_good_run_text()),
            parse_run(_good_run_text()),
            parse_run(_good_run_text(raw_ns=60_000_000_000, zstd_ns=1_700_000_000)),
        ],
        good_unshaped,
    )
    # (5) wire/bulk mismatch: the provider bulk frame disagrees with the COUNTED zstd wire body far
    #     beyond tolerance -> the auxiliary figure must not silently diverge from the headline.
    _bites(
        "wire-bulk-mismatch",
        [parse_run(_good_run_text(bulk_frame=1000)) for _ in range(3)],
        good_unshaped,
    )
    # (6) wire bytes inconsistent across runs: the counted bodies drift, so the headline ratio is not
    #     well-defined.
    _bites(
        "wire-bytes-inconsistent",
        [
            parse_run(_good_run_text(frame=frame)),
            parse_run(_good_run_text(frame=frame + 4096)),
            parse_run(_good_run_text(frame=frame)),
        ],
        good_unshaped,
    )

    # shaping oracle unit teeth (via shaped_link, direct arms): an honest pair passes; a
    # shaping-removed arm is rejected.
    good_shaped_arm = _arm_for_oracle(_ms_str_to_ns("40.2"), nar, 6_700_000_000)
    good_control_arm = _arm_for_oracle(_ms_str_to_ns("0.05"), nar, 60_000_000)
    try:
        shaped_link.assert_shaping(
            good_shaped_arm, good_control_arm, DEFAULT_DELAY_MS, DEFAULT_RATE_MBIT
        )
    except shaped_link.ShapingViolation as exc:
        failures.append(f"shaping oracle rejected an honest shaped/control pair: {exc}")
    removed = _arm_for_oracle(_ms_str_to_ns("0.05"), nar, 60_000_000)  # 'shaped' == control
    try:
        shaped_link.assert_shaping(removed, good_control_arm, DEFAULT_DELAY_MS, DEFAULT_RATE_MBIT)
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
        "SELF-TEST OK: baseline parsed; 9 parse mutations bitten; fail-closed render+exit teeth "
        "bite on slower-zstd, swamped-margin, shaping-removed, run-not-shape-gated, "
        "wire-bulk-mismatch, wire-bytes-inconsistent (each: no VERDICT: ACCEPTED, VERDICT: REJECTED "
        "rendered, exit non-zero); shaping oracle bites a removed shaper; integer reporting checked"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="TASK-198 live two-ends-shaped raw-vs-zstd measurement")
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove the parse + fail-closed render/exit + shaping oracle bite by mutation "
        "(hermetic, no netns)",
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
