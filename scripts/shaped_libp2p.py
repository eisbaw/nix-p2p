#!/usr/bin/env python3
"""Shaped-libp2p connectivity proof (TASK-206).

WHAT THIS IS. Every libp2p connectivity proof so far runs on ONE host over
loopback or unshaped netns routing (TASK-103 discovery, TASK-179 routed netns,
TASK-194 store-supply, the two-node `nar_transport.rs`), so the fetch-over-a-
realistic-link half is unproven for the libp2p-primary path the way TASK-94/99's
shaped links proved it for compression. This closes that credibility residual: it
runs the REAL libp2p `discover->fetch->serve` (`/nar/3` raw-stream, BLAKE3-verified)
BETWEEN two swarm nodes whose kad/stream traffic traverses a `tc netem`-shaped
`veth` pair (real RTT + bandwidth cap), and proves the fetched NAR is BYTE-IDENTICAL
over that shaped link -- not secretly loopback.

HOW. Reuses the PROVEN TASK-70 shaped-link substrate verbatim in structure
(`scripts/shaped_libp2p_inner.sh`, itself a clone of `shaped_link_inner.sh`):
`unshare -Urn` map-root caps, a veth pair across TWO netns (child-pid pattern),
`tc netem delay+rate` on both egress directions. The only change is the payload:
the `fabric-libp2p` `shaped_probe` EXAMPLE binary runs a PROVIDER node in ns A and
a CONSUMER node in ns B (via `nsenter`) so a real libp2p fetch crosses the link.

THE ORACLE. Reuses `shaped_link.assert_shaping` -- the SAME proven discipline: a
shaper that never fired must make the run go RED with a NAMED failure. Two arms
over the same channel (shaped + an UNSHAPED negative control); the run is refused
unless the injected RTT is recovered on the shaped arm, the control's RTT is near
zero, the shaped fetch throughput sits near the cap, and the unshaped control is
MEASURABLY faster (>=2x). PLUS the credibility claim proper: BOTH arms must report
a BYTE-IDENTICAL, BLAKE3-verified fetch (a shaped link that corrupted or truncated
the NAR is not a passing connectivity proof).

NO-FLOAT REPORTING (owner rule; TASK-99 convention). RTT is reported as integer
nanoseconds, throughput as integer bytes/sec, and the negative-control speedup as
an EXACT rational (`fractions.Fraction`). Floats appear only inside the proven
`assert_shaping` accept/reject gate, never in a reported quantity.

STATED LIMITS. Inherits `shaped_link.HONEST_LIMITS`: one host emulating a link
over a shared kernel; models mean RTT + a rate cap, NOT loss, jitter, competing
traffic, NAT-traversal cost, or real-NIC/CPU effects. This removes the loopback
UPPER bound on the libp2p fetch; it is not itself a field measurement.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from fractions import Fraction

import shaped_link  # sibling module: the proven oracle + honest-limits text

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
INNER = os.path.join(HERE, "shaped_libp2p_inner.sh")
DEFAULT_BIN = os.path.join(ROOT, "target", "debug", "examples", "shaped_probe")

# 40 MiB incompressible NAR over a 100 mbit cap is ~3.4 s of pure transfer -- long
# enough that the fetch throughput reflects the steady-state shaped rate rather
# than the fixed dial/handshake cost over a 40 ms RTT, small enough to be gentle on
# a shared box (held in RAM; never touches disk).
DEFAULT_NAR_BYTES = 40 * 1024 * 1024
DEFAULT_DELAY_MS = 20
DEFAULT_RATE_MBIT = 100
DEFAULT_NAR_SEED = 20206


class ProofFailure(Exception):
    """The shaped-libp2p proof could not be established; the run is not a proof."""


def parse_arm(text: str) -> dict:
    """Pull the host-side ping RTT and the fetcher's FETCH_DONE fields from one
    arm. Missing any one is fatal (a silent absence must not read as a passing
    zero), and a non-byte-identical / non-BLAKE3-verified / short fetch is NOT a
    connectivity proof. Pure so `--self-test` bites it with no netns."""
    if "FATAL" in text:
        fatal = next((ln for ln in text.splitlines() if "FATAL" in ln), "FATAL")
        raise ProofFailure(f"inner harness reported {fatal!r} -- link setup failed")

    m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", text)
    if not m:
        raise ProofFailure("arm reported no RTT line (ping did not complete)")
    rtt_ms = float(m.group(1))

    m = re.search(
        r"FETCH_DONE bytes=(\d+) expect=(\d+) elapsed_ns=(\d+) "
        r"byte_identical=(\d) blake3_ok=(\d)",
        text,
    )
    if not m:
        raise ProofFailure(
            "arm reported no FETCH_DONE line (the libp2p fetch did not complete)"
        )
    got, expect, elapsed_ns = int(m.group(1)), int(m.group(2)), int(m.group(3))
    byte_identical, blake3_ok = int(m.group(4)), int(m.group(5))

    if got != expect:
        raise ProofFailure(
            f"fetch delivered {got} of {expect} bytes -- truncated, not a proof"
        )
    if byte_identical != 1:
        raise ProofFailure("fetched bytes are NOT byte-identical to the served NAR")
    if blake3_ok != 1:
        raise ProofFailure("fetched bytes do NOT BLAKE3-verify to the content id")
    if elapsed_ns <= 0:
        raise ProofFailure("non-positive elapsed_ns -- cannot form a throughput")

    return {
        "rtt_ms": rtt_ms,
        "bytes": got,
        "elapsed_ns": elapsed_ns,
        "byte_identical": True,
        "blake3_ok": True,
    }


def throughput_bytes_per_s(byte_count: int, elapsed_ns: int) -> int:
    """Integer bytes/sec (floor). No float: bytes * 1e9 / ns as integer division."""
    return (byte_count * 1_000_000_000) // elapsed_ns


def rtt_ns(rtt_ms: float) -> int:
    """Report RTT as integer nanoseconds (ping only gives us float ms)."""
    return round(rtt_ms * 1_000_000)


def run_arm(
    shape: bool,
    nar_bytes: int,
    delay_ms: int,
    rate_mbit: int,
    probe_bin: str,
    nar_seed: int,
) -> dict:
    """Run one arm inside `unshare -Urn` and return its parsed metrics."""
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
        raise ProofFailure(
            f"{'shaped' if shape else 'unshaped'} arm exited {proc.returncode}\n{out}"
        )
    metrics = parse_arm(out)
    metrics["raw"] = out
    return metrics


def measure(
    nar_bytes: int, delay_ms: int, rate_mbit: int, probe_bin: str, nar_seed: int
) -> int:
    if not os.path.exists(probe_bin):
        print(
            f"PROOF FAILURE: probe binary not found at {probe_bin}\n"
            f"  build it: nix develop -c cargo build -p fabric-libp2p "
            f"--example shaped_probe",
            file=sys.stderr,
        )
        return 2

    print(
        f"# shaped-libp2p proof: {nar_bytes} byte NAR, delay {delay_ms}ms, "
        f"cap {rate_mbit}mbit (nar_seed={nar_seed})"
    )
    try:
        shaped = run_arm(True, nar_bytes, delay_ms, rate_mbit, probe_bin, nar_seed)
        unshaped = run_arm(False, nar_bytes, delay_ms, rate_mbit, probe_bin, nar_seed)
    except subprocess.TimeoutExpired:
        print("PROOF FAILURE: an arm timed out (link/fetch hung)", file=sys.stderr)
        return 2
    except ProofFailure as exc:
        print(f"PROOF FAILURE: {exc}", file=sys.stderr)
        return 2

    # Integer/rational reporting (no-float rule).
    s_bps = throughput_bytes_per_s(shaped["bytes"], shaped["elapsed_ns"])
    u_bps = throughput_bytes_per_s(unshaped["bytes"], unshaped["elapsed_ns"])
    # Exact-rational negative-control speedup, from the raw integer ns (NOT the
    # rounded bytes/sec) so the ratio loses nothing.
    speedup = Fraction(shaped["elapsed_ns"], unshaped["elapsed_ns"])

    print(
        "  shaped   : "
        f"RTT {rtt_ns(shaped['rtt_ms'])} ns  "
        f"throughput {s_bps} bytes/s  "
        f"byte_identical={shaped['byte_identical']} "
        f"blake3_ok={shaped['blake3_ok']}"
    )
    print(
        "  unshaped : "
        f"RTT {rtt_ns(unshaped['rtt_ms'])} ns  "
        f"throughput {u_bps} bytes/s  "
        f"byte_identical={unshaped['byte_identical']} "
        f"blake3_ok={unshaped['blake3_ok']}"
    )
    print(
        f"  negative-control speedup (shaped_elapsed/unshaped_elapsed) = "
        f"{speedup.numerator}/{speedup.denominator} "
        f"(~{float(speedup):.1f}x unshaped is faster)"
    )

    # THE ORACLE (proven, reused verbatim): feed the shaped/unshaped RTT + mbit to
    # shaped_link.assert_shaping. mbit here is the LIBP2P FETCH throughput, so the
    # cap/negative-control invariants are asserted on the real fetch, not a side
    # channel. Floats live ONLY inside this proven accept/reject gate.
    shaped_arm = {"rtt_ms": shaped["rtt_ms"], "mbit": s_bps * 8 / 1e6}
    unshaped_arm = {"rtt_ms": unshaped["rtt_ms"], "mbit": u_bps * 8 / 1e6}
    try:
        shaped_link.assert_shaping(shaped_arm, unshaped_arm, delay_ms, rate_mbit)
    except shaped_link.ShapingViolation as exc:
        print(f"PROOF FAILURE (shaping oracle): {exc}", file=sys.stderr)
        return 2

    print(
        "PROOF OK: real libp2p discover->fetch->serve is BYTE-IDENTICAL + "
        "BLAKE3-verified over a shaped link"
    )
    print(
        "  (injected RTT recovered, fetch throughput near the cap, unshaped "
        "control measurably faster)"
    )
    print()
    print(shaped_link.HONEST_LIMITS)
    return 0


# --- self-test: prove the parse/verdict bites by mutation (no netns needed) ----


def _good_arm_text(delay_ms: int = 20, elapsed_ns: int = 3_400_000_000) -> str:
    return (
        f"=== RTT probe (shape=yes) ===\n"
        f"rtt min/avg/max/mdev = {2 * delay_ms}.0/{2 * delay_ms}.2/{2 * delay_ms}.5/0.1 ms\n"
        f"=== XFER libp2p ===\n"
        f"FETCH_DONE bytes=41943040 expect=41943040 elapsed_ns={elapsed_ns} "
        f"byte_identical=1 blake3_ok=1\n"
    )


def self_test() -> int:
    """Every mutation must be REJECTED and the honest baseline ACCEPTED, or the
    parse/verdict is vacuous (TASK-63 'oracle must bite by mutation')."""
    failures: list[str] = []

    # Baseline must parse and be byte-identical.
    try:
        good = parse_arm(_good_arm_text())
        if not (good["byte_identical"] and good["blake3_ok"]):
            failures.append("baseline arm should be byte-identical+blake3-ok")
    except ProofFailure as exc:
        failures.append(f"baseline arm should PARSE but was rejected: {exc}")

    # Each mutation breaks exactly one invariant and MUST be caught.
    mutations = {
        "fatal": "=== XFER ===\nFATAL provider-not-ready\n",
        "no-rtt": (
            "FETCH_DONE bytes=41943040 expect=41943040 elapsed_ns=3400000000 "
            "byte_identical=1 blake3_ok=1\n"
        ),
        "no-fetch": "rtt min/avg/max/mdev = 40.0/40.2/40.5/0.1 ms\n",
        "truncated": _good_arm_text().replace("bytes=41943040", "bytes=1024"),
        "not-byte-identical": _good_arm_text().replace(
            "byte_identical=1", "byte_identical=0"
        ),
        "blake3-fail": _good_arm_text().replace("blake3_ok=1", "blake3_ok=0"),
    }
    for name, text in mutations.items():
        try:
            parse_arm(text)
            failures.append(f"mutation {name!r} should have been REJECTED but passed")
        except ProofFailure:
            pass  # correctly bitten

    # throughput_bytes_per_s / rtt_ns are integer-domain (no-float rule).
    if not isinstance(throughput_bytes_per_s(41943040, 3_400_000_000), int):
        failures.append("throughput must be an integer bytes/sec")
    if throughput_bytes_per_s(100, 1_000_000_000) != 100:
        failures.append("throughput_bytes_per_s wrong for 100 B / 1 s")
    if rtt_ns(40.2) != 40_200_000:
        failures.append("rtt_ns wrong for 40.2 ms")

    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        return 1
    print(
        "SELF-TEST OK: baseline accepted, 6 mutations bitten, integer reporting checked"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Shaped-libp2p connectivity proof (TASK-206)"
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove the parse/verdict bites by mutation (hermetic, no netns)",
    )
    ap.add_argument("--nar-bytes", type=int, default=DEFAULT_NAR_BYTES)
    ap.add_argument("--delay-ms", type=int, default=DEFAULT_DELAY_MS)
    ap.add_argument("--rate-mbit", type=int, default=DEFAULT_RATE_MBIT)
    ap.add_argument("--nar-seed", type=int, default=DEFAULT_NAR_SEED)
    ap.add_argument("--probe-bin", default=DEFAULT_BIN)
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return measure(
        args.nar_bytes, args.delay_ms, args.rate_mbit, args.probe_bin, args.nar_seed
    )


if __name__ == "__main__":
    sys.exit(main())
