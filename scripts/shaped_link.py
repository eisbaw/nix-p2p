#!/usr/bin/env python3
"""Shaped-link measurement primitive (task-70, AC#1/#2/#4).

WHAT THIS IS. The peer-advantage numbers this project publishes were all taken
over POD LOOPBACK (~200 MB/s), a rate no real peer link reaches. This primitive
emulates a REAL link -- an injected RTT and a bandwidth cap -- so a peer transfer
can be measured over something a home uplink or a WAN peer would actually see.
It shapes the LINK, not our transport, and it lives entirely on the
script/measurement surface: nothing here is linked into the product daemon
(AC#2, proved by `scripts/check_shaping_out_of_daemon.py`).

HOW (settled route (c), task-70). `unshare -Urn` gives a user+net namespace whose
map-root grants FULL capabilities WITHOUT real root, so `ip`/`tc` work. Two
namespaces are wired with a veth pair (`scripts/shaped_link_inner.sh`): the peer
end is moved into a SECOND netns addressed by a child pid, because with both ends
in one netns the kernel short-circuits the pair locally and netem never shapes.
`tc netem delay/rate` is applied to BOTH egress directions.

THE ORACLE (AC#1 -- the load-bearing part). A shaper that never fired must make
the run go RED with a NAMED failure, never a quiet green. So the primitive runs
TWO arms over the same channel -- shaped, and an UNSHAPED negative control -- and
`assert_shaping` refuses the run unless ALL of these hold, each measured OUTSIDE
the shaper by an endpoint clock:

  * the injected RTT is recovered on the shaped arm (~= 2*delay), and
  * the unshaped arm's RTT is near zero (the control really is unshaped), and
  * the shaped throughput sits near the cap (the cap bit, and did not collapse
    the link to zero), and
  * the unshaped throughput is MEASURABLY faster than the shaped one -- if the
    shaper cannot be told apart from the control, it did not fire.

This mirrors `scripts/profile_p2p.py`'s `probe_upstream_link` / `shaping_violations`
discipline for the upstream arm, applied here to the peer link. `--self-test`
proves the oracle is not vacuous by feeding it mutated metrics (each breaking one
invariant) and requiring every one to be caught.

STATED LIMIT (AC#4): see HONEST_LIMITS below. This is a single host emulating a
link over a shared kernel; it models mean RTT and a rate cap, NOT loss, jitter,
competing/cross traffic, NAT-traversal cost, or real-NIC offload/CPU effects.

SCOPE. This cycle delivers the primitive and its assertion (AC#1/#2/#4). It does
NOT re-state the wan_shaped speedup with both link ends shaped (AC#3): per
task-70's own WIRE-COST CORRECTION, no peer-vs-upstream speedup may be re-derived
until task-99 (link compression) lands, because the peer byte-volume depends on
it. AC#3 is carried by its own follow-up task, blocked on task-70 + task-99.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
INNER = os.path.join(HERE, "shaped_link_inner.sh")
XFER = os.path.join(HERE, "shaped_link_xfer.py")

# Defaults: 40 MiB over a 100 mbit cap is ~3.4 s -- long enough for TCP to leave
# slow-start and reach the shaped steady state, small enough to be gentle on a
# shared, near-full disk (the transfer never touches disk; this only bounds RAM).
DEFAULT_BYTES = 40 * 1024 * 1024
DEFAULT_DELAY_MS = 20
DEFAULT_RATE_MBIT = 100

HONEST_LIMITS = """\
HONEST LIMITS (task-70 AC#4) -- what this route does NOT model:
  * packet loss and reordering: netem here injects delay + a rate cap only.
  * jitter: the delay is constant; a real link's RTT varies.
  * competing / cross traffic and bufferbloat under contention.
  * NAT / hole-punching / relay traversal cost -- the two ends are directly
    wired; a real peer link often is not.
  * real-NIC effects: offload, interrupt coalescing, driver/CPU cost. This is a
    veth pair over ONE host's shared kernel scheduler, not two machines.
  * the rate cap is netem's token bucket, an approximation of a physical link's
    serialization; achieved TCP throughput sits a little under the nominal cap.
So a number taken here is "over an emulated link with mean RTT R and cap C",
never "over the real internet". It removes the loopback UPPER bound; it is not
itself a field measurement.
"""


class ShapingViolation(Exception):
    """The shaper could not be proven to have fired; the run is not a measurement."""


def parse_inner_output(text: str) -> dict:
    """Pull the RTT and throughput an arm reported. Missing either is fatal:
    a silent absence must not read as a passing zero."""
    rtt = None
    m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", text)
    if m:
        rtt = float(m.group(1))
    mbit = None
    m = re.search(r"SEND_DONE bytes=\d+ elapsed_s=[\d.]+ mbit_per_s=([\d.]+)", text)
    if m:
        mbit = float(m.group(1))
    if rtt is None:
        raise ShapingViolation(
            "arm reported no RTT line (ping did not complete) -- not a measurement"
        )
    if mbit is None:
        raise ShapingViolation(
            "arm reported no SEND_DONE line (transfer did not complete) -- not a measurement"
        )
    return {"rtt_ms": rtt, "mbit": mbit}


def assert_shaping(shaped: dict, unshaped: dict, delay_ms: int, rate_mbit: int) -> None:
    """PURE oracle. Raise ShapingViolation with a NAMED cause unless every
    shaping invariant is observed. Empty return == the shaper provably fired.

    Tolerances are deliberately generous on the "did it work" side and strict on
    the "can I tell it apart from the control" side -- the failure this exists to
    catch is a shaper that silently did nothing, which shows up as the shaped and
    unshaped arms being indistinguishable."""
    want_rtt = 2 * delay_ms
    problems = []

    # (A) The injected RTT is recovered on the shaped arm (~= 2*delay).
    if shaped["rtt_ms"] < 0.7 * want_rtt:
        problems.append(
            f"shaped RTT {shaped['rtt_ms']:.1f}ms is below 70% of the injected "
            f"{want_rtt}ms -- delay not applied"
        )
    if shaped["rtt_ms"] > want_rtt + 60:
        problems.append(
            f"shaped RTT {shaped['rtt_ms']:.1f}ms is far above the injected "
            f"{want_rtt}ms (+60ms) -- link is mis-shaped or contended"
        )

    # (B) The unshaped control really is unshaped (near-zero RTT).
    if unshaped["rtt_ms"] > 5.0:
        problems.append(
            f"unshaped control RTT {unshaped['rtt_ms']:.1f}ms is not near zero -- "
            f"the 'control' is itself shaped, so the comparison is void"
        )

    # (C) The shaped throughput sits near the cap: the cap bit, and did NOT
    # collapse the link to zero (a broken link is not a shaped link).
    if shaped["mbit"] > 1.3 * rate_mbit:
        problems.append(
            f"shaped throughput {shaped['mbit']:.1f}mbit exceeds 130% of the "
            f"{rate_mbit}mbit cap -- rate cap not applied"
        )
    if shaped["mbit"] < 0.4 * rate_mbit:
        problems.append(
            f"shaped throughput {shaped['mbit']:.1f}mbit is below 40% of the "
            f"{rate_mbit}mbit cap -- link broken, not shaped"
        )

    # (D) The negative control is MEASURABLY faster -- the crux. If the shaper
    # cannot be distinguished from no-shaper, it did not fire (task-63 discipline).
    if unshaped["mbit"] < 1.5 * rate_mbit:
        problems.append(
            f"unshaped control {unshaped['mbit']:.1f}mbit is not comfortably above "
            f"the {rate_mbit}mbit cap -- the link itself is the bottleneck, so the "
            f"cap cannot be shown to bite"
        )
    if unshaped["mbit"] < 2.0 * shaped["mbit"]:
        problems.append(
            f"unshaped {unshaped['mbit']:.1f}mbit is not >=2x shaped "
            f"{shaped['mbit']:.1f}mbit -- shaper indistinguishable from control"
        )
    if shaped["rtt_ms"] < unshaped["rtt_ms"] + delay_ms:
        problems.append(
            f"shaped RTT {shaped['rtt_ms']:.1f}ms is not at least {delay_ms}ms above "
            f"control {unshaped['rtt_ms']:.1f}ms -- delay indistinguishable from control"
        )

    if problems:
        raise ShapingViolation("; ".join(problems))


def run_arm(shape: bool, total: int, delay_ms: int, rate_mbit: int) -> dict:
    """Run one arm inside `unshare -Urn` and return its parsed metrics."""
    cmd = [
        "unshare",
        "-Urn",
        "bash",
        INNER,
        "yes" if shape else "no",
        str(total),
        str(delay_ms),
        str(rate_mbit),
        XFER,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    out = proc.stdout + proc.stderr
    if "FATAL" in out or proc.returncode != 0:
        fatal = next(
            (ln for ln in out.splitlines() if "FATAL" in ln),
            f"exit={proc.returncode}",
        )
        raise ShapingViolation(
            f"{'shaped' if shape else 'unshaped'} arm setup failed: {fatal}\n{out}"
        )
    metrics = parse_inner_output(out)
    metrics["raw"] = out
    return metrics


def measure(total: int, delay_ms: int, rate_mbit: int) -> int:
    print(
        f"# shaped-link measurement: {total} bytes, delay {delay_ms}ms, "
        f"cap {rate_mbit}mbit"
    )
    try:
        shaped = run_arm(True, total, delay_ms, rate_mbit)
        unshaped = run_arm(False, total, delay_ms, rate_mbit)
    except subprocess.TimeoutExpired:
        print("SHAPING FAILURE: an arm timed out (link setup hung)", file=sys.stderr)
        return 2
    except ShapingViolation as exc:
        print(f"SHAPING FAILURE: {exc}", file=sys.stderr)
        return 2

    print(
        f"  shaped   : RTT {shaped['rtt_ms']:.1f}ms  throughput {shaped['mbit']:.1f}mbit"
    )
    print(
        f"  unshaped : RTT {unshaped['rtt_ms']:.1f}ms  throughput {unshaped['mbit']:.1f}mbit"
    )

    try:
        assert_shaping(shaped, unshaped, delay_ms, rate_mbit)
    except ShapingViolation as exc:
        print(f"SHAPING FAILURE (oracle): {exc}", file=sys.stderr)
        return 2

    print("SHAPING OK: injected RTT recovered, cap bit, control measurably faster")
    print()
    print(HONEST_LIMITS)
    return 0


# --- self-test: prove the oracle bites by mutation (no netns needed) -----------


def _good() -> tuple[dict, dict, int, int]:
    # A realistic passing observation: 40ms shaped RTT near-zero control RTT,
    # ~95mbit shaped throughput, ~2 Gbit unshaped loopback.
    shaped = {"rtt_ms": 40.2, "mbit": 95.0}
    unshaped = {"rtt_ms": 0.05, "mbit": 2000.0}
    return shaped, unshaped, 20, 100


def self_test() -> int:
    """Every mutation must be REJECTED and the honest baseline ACCEPTED, or the
    oracle is vacuous. This is the task-63 'oracle must bite by mutation' rule."""
    failures = []

    # Baseline must pass.
    try:
        assert_shaping(*_good())
    except ShapingViolation as exc:
        failures.append(f"baseline should PASS but was rejected: {exc}")

    # Each mutation breaks exactly one invariant and MUST be caught.
    mutations = {
        "delay-not-applied": lambda s, u: (s.update(rtt_ms=1.0), u),
        "cap-not-applied": lambda s, u: (s.update(mbit=1900.0), u),  # shaped ~ unshaped
        "link-collapsed": lambda s, u: (s.update(mbit=1.0), u),
        "control-also-shaped": lambda s, u: (u.update(rtt_ms=39.0), None),
        "control-not-faster": lambda s, u: (u.update(mbit=110.0), None),
        "shaper-eq-control": (lambda s, u: (s.update(rtt_ms=0.05, mbit=2000.0), None)),
    }
    for name, mutate in mutations.items():
        shaped, unshaped, d, r = _good()
        mutate(shaped, unshaped)
        try:
            assert_shaping(shaped, unshaped, d, r)
            failures.append(f"mutation '{name}' should have been REJECTED but passed")
        except ShapingViolation:
            pass  # correctly bitten

    # parse_inner_output must reject a truncated arm (no silent zero).
    for missing, text in {
        "no-rtt": "SEND_DONE bytes=1 elapsed_s=1.0 mbit_per_s=95.00 MB_per_s=11.9",
        "no-xfer": "rtt min/avg/max/mdev = 40.0/40.2/40.5/0.1 ms",
    }.items():
        try:
            parse_inner_output(text)
            failures.append(f"parse should reject '{missing}' arm but did not")
        except ShapingViolation:
            pass

    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        return 1
    print("SELF-TEST OK: baseline accepted, all 6 mutations + 2 truncations bitten")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Shaped-link measurement primitive (task-70)"
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove the oracle bites by mutation (hermetic, no netns)",
    )
    ap.add_argument("--bytes", type=int, default=DEFAULT_BYTES)
    ap.add_argument("--delay-ms", type=int, default=DEFAULT_DELAY_MS)
    ap.add_argument("--rate-mbit", type=int, default=DEFAULT_RATE_MBIT)
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return measure(args.bytes, args.delay_ms, args.rate_mbit)


if __name__ == "__main__":
    sys.exit(main())
