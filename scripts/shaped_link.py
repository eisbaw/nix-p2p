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
from fractions import Fraction

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


def _decimal_ms_to_ns(ms_text: str) -> int:
    """Convert a decimal-millisecond STRING (e.g. `ping`'s `40.2`) to EXACT integer
    nanoseconds. Parsing the string (not the already-lossy float) keeps this exact:
    a finite decimal * 1e6 is an integer, so no rounding enters the oracle's clock.
    Owner rule: latency is a whole integer of nanoseconds, never a float."""
    return int(Fraction(ms_text) * 1_000_000)


def _decimal_mbit_to_bytes_per_s(mbit_text: str) -> Fraction:
    """Convert a decimal-megabit/s STRING (the value the sender already reported) to
    EXACT bytes/sec as a rational. `mbit * 1e6 / 8` is carried as a `Fraction` of the
    SAME reported number, not a re-derivation from bytes/elapsed (which would be a
    different, more-precise number and would perturb the serialized evidence)."""
    return Fraction(mbit_text) * 1_000_000 / 8


def parse_inner_output(text: str) -> dict:
    """Pull the RTT, throughput AND the receiver's delivered-byte count an arm
    reported. Missing any one is fatal: a silent absence must not read as a passing
    zero. The receiver count is the provider-side counter that makes the arm
    non-vacuous -- a truncated transfer (RECV_DONE status=short, or bytes < expect)
    is not a measurement.

    Returns BOTH the exact integer/rational forms the oracle decides on (`rtt_ns`,
    `rate_bytes_per_s`) AND the float `rtt_ms`/`mbit` display fields the report and
    downstream (peer_wire_baseline) still read. The exact forms are the gate; the
    floats are terminal display, derived from the SAME reported decimal string."""
    rtt_ns = None
    rtt_ms = None
    m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", text)
    if m:
        rtt_ns = _decimal_ms_to_ns(m.group(1))
        rtt_ms = float(m.group(1))
    rate_bytes_per_s = None
    mbit = None
    m = re.search(r"SEND_DONE bytes=\d+ elapsed_s=[\d.]+ mbit_per_s=([\d.]+)", text)
    if m:
        rate_bytes_per_s = _decimal_mbit_to_bytes_per_s(m.group(1))
        mbit = float(m.group(1))
    recv_bytes = None
    recv_status = None
    m = re.search(r"RECV_DONE bytes=(\d+)(?: expect=\d+ status=(\w+))?", text)
    if m:
        recv_bytes = int(m.group(1))
        recv_status = m.group(2)
    if rtt_ns is None:
        raise ShapingViolation(
            "arm reported no RTT line (ping did not complete) -- not a measurement"
        )
    if rate_bytes_per_s is None:
        raise ShapingViolation(
            "arm reported no SEND_DONE line (transfer did not complete) -- not a measurement"
        )
    if recv_bytes is None:
        raise ShapingViolation(
            "arm reported no RECV_DONE line (receiver did not confirm delivery) -- "
            "not a measurement"
        )
    if recv_status == "short":
        raise ShapingViolation(
            "receiver reported RECV_DONE status=short -- transfer was truncated, "
            "not a measurement"
        )
    return {
        "rtt_ns": rtt_ns,
        "rate_bytes_per_s": rate_bytes_per_s,
        "recv_bytes": recv_bytes,
        # Terminal display, derived from the same reported decimal string.
        "rtt_ms": rtt_ms,
        "mbit": mbit,
    }


def assert_full_delivery(recv_bytes: int, expected: int) -> None:
    """The receiver must have drained EVERY expected byte. Raise otherwise: a
    truncated transfer that still produced a rate is not a valid measurement.
    Pure so `--self-test` can bite it without a namespace."""
    if recv_bytes != expected:
        raise ShapingViolation(
            f"receiver drained {recv_bytes} of {expected} expected bytes -- "
            "truncated transfer, not a measurement"
        )


def assert_shaping(shaped: dict, unshaped: dict, delay_ms: int, rate_mbit: int) -> None:
    """PURE oracle. Raise ShapingViolation with a NAMED cause unless every
    shaping invariant is observed. Empty return == the shaper provably fired.

    Tolerances are deliberately generous on the "did it work" side and strict on
    the "can I tell it apart from the control" side -- the failure this exists to
    catch is a shaper that silently did nothing, which shows up as the shaped and
    unshaped arms being indistinguishable.

    The oracle DECIDES on the exact integer/rational forms only (owner no-floats
    rule): RTT in whole nanoseconds, throughput in exact bytes/sec, and every
    tolerance as an exact rational compared by cross-multiplication (e.g.
    `x < 0.7*want` becomes `10*x < 7*want`). Floats appear ONLY in the human
    message text. Every threshold is numerically identical to the previous float
    form, so no verdict changes -- this is representation, not re-measurement."""
    # want_rtt and the rate cap are exact integers (ns and bytes/sec).
    want_rtt_ns = 2 * delay_ms * 1_000_000
    rate_cap_bytes_per_s = rate_mbit * 1_000_000 // 8  # mbit -> bytes/sec, exact
    s_rtt_ns = shaped["rtt_ns"]
    u_rtt_ns = unshaped["rtt_ns"]
    s_bps = shaped["rate_bytes_per_s"]
    u_bps = unshaped["rate_bytes_per_s"]
    # Display-only projections for the message text (terminal floats).
    s_rtt_disp = s_rtt_ns / 1_000_000
    u_rtt_disp = u_rtt_ns / 1_000_000
    s_mbit_disp = float(s_bps) * 8 / 1_000_000
    u_mbit_disp = float(u_bps) * 8 / 1_000_000
    problems = []

    # (A) The injected RTT is recovered on the shaped arm (~= 2*delay).
    #     s_rtt < 0.7*want  <=>  10*s_rtt < 7*want   (cross-multiplied)
    if 10 * s_rtt_ns < 7 * want_rtt_ns:
        problems.append(
            f"shaped RTT {s_rtt_disp:.1f}ms is below 70% of the injected "
            f"{2 * delay_ms}ms -- delay not applied"
        )
    if s_rtt_ns > want_rtt_ns + 60 * 1_000_000:
        problems.append(
            f"shaped RTT {s_rtt_disp:.1f}ms is far above the injected "
            f"{2 * delay_ms}ms (+60ms) -- link is mis-shaped or contended"
        )

    # (B) The unshaped control really is unshaped (near-zero RTT, <= 5ms).
    if u_rtt_ns > 5 * 1_000_000:
        problems.append(
            f"unshaped control RTT {u_rtt_disp:.1f}ms is not near zero -- "
            f"the 'control' is itself shaped, so the comparison is void"
        )

    # (C) The shaped throughput sits near the cap: the cap bit, and did NOT
    # collapse the link to zero (a broken link is not a shaped link).
    #     s_bps > 1.3*cap  and  s_bps < 0.4*cap  (exact rational thresholds)
    if s_bps > Fraction(13, 10) * rate_cap_bytes_per_s:
        problems.append(
            f"shaped throughput {s_mbit_disp:.1f}mbit exceeds 130% of the "
            f"{rate_mbit}mbit cap -- rate cap not applied"
        )
    if s_bps < Fraction(2, 5) * rate_cap_bytes_per_s:
        problems.append(
            f"shaped throughput {s_mbit_disp:.1f}mbit is below 40% of the "
            f"{rate_mbit}mbit cap -- link broken, not shaped"
        )

    # (D) The negative control is MEASURABLY faster -- the crux. If the shaper
    # cannot be distinguished from no-shaper, it did not fire (task-63 discipline).
    if u_bps < Fraction(3, 2) * rate_cap_bytes_per_s:
        problems.append(
            f"unshaped control {u_mbit_disp:.1f}mbit is not comfortably above "
            f"the {rate_mbit}mbit cap -- the link itself is the bottleneck, so the "
            f"cap cannot be shown to bite"
        )
    if u_bps < 2 * s_bps:
        problems.append(
            f"unshaped {u_mbit_disp:.1f}mbit is not >=2x shaped "
            f"{s_mbit_disp:.1f}mbit -- shaper indistinguishable from control"
        )
    if s_rtt_ns < u_rtt_ns + delay_ms * 1_000_000:
        problems.append(
            f"shaped RTT {s_rtt_disp:.1f}ms is not at least {delay_ms}ms above "
            f"control {u_rtt_disp:.1f}ms -- delay indistinguishable from control"
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
    # The receiver's delivered count must equal the bytes we asked to send: a
    # short delivery that nonetheless produced a rate line is not a measurement.
    assert_full_delivery(metrics["recv_bytes"], total)
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


def _arm(rtt_ms: float, mbit: float) -> dict:
    """A synthetic arm's metrics in the SAME shape parse_inner_output returns:
    the exact `rtt_ns`/`rate_bytes_per_s` the oracle decides on, plus the float
    display fields. Built from the decimal STRING so the exact fields are exact,
    mirroring the real parse path."""
    return {
        "rtt_ns": _decimal_ms_to_ns(str(rtt_ms)),
        "rate_bytes_per_s": _decimal_mbit_to_bytes_per_s(str(mbit)),
        "rtt_ms": rtt_ms,
        "mbit": mbit,
    }


def _good() -> tuple[dict, dict, int, int]:
    # A realistic passing observation: 40ms shaped RTT near-zero control RTT,
    # ~95mbit shaped throughput, ~2 Gbit unshaped loopback.
    return _arm(40.2, 95.0), _arm(0.05, 2000.0), 20, 100


def self_test() -> int:
    """Every mutation must be REJECTED and the honest baseline ACCEPTED, or the
    oracle is vacuous. This is the task-63 'oracle must bite by mutation' rule."""
    failures = []

    # Baseline must pass.
    try:
        assert_shaping(*_good())
    except ShapingViolation as exc:
        failures.append(f"baseline should PASS but was rejected: {exc}")

    # Each mutation breaks exactly one invariant and MUST be caught. Each rebuilds
    # the offending arm through _arm so the exact fields (not just display) move.
    mutations = {
        "delay-not-applied": lambda s, u: (_arm(1.0, s["mbit"]), u),
        "cap-not-applied": lambda s, u: (_arm(s["rtt_ms"], 1900.0), u),  # ~ unshaped
        "link-collapsed": lambda s, u: (_arm(s["rtt_ms"], 1.0), u),
        "control-also-shaped": lambda s, u: (s, _arm(39.0, u["mbit"])),
        "control-not-faster": lambda s, u: (s, _arm(u["rtt_ms"], 110.0)),
        "shaper-eq-control": lambda s, u: (_arm(0.05, 2000.0), u),
    }
    for name, mutate in mutations.items():
        shaped, unshaped, d, r = _good()
        shaped, unshaped = mutate(shaped, unshaped)
        try:
            assert_shaping(shaped, unshaped, d, r)
            failures.append(f"mutation '{name}' should have been REJECTED but passed")
        except ShapingViolation:
            pass  # correctly bitten

    # parse_inner_output must reject a truncated arm (no silent zero). A complete
    # RTT+SEND_DONE+RECV_DONE(status=ok) triple is the only accepted shape.
    _rtt = "rtt min/avg/max/mdev = 40.0/40.2/40.5/0.1 ms"
    _send = "SEND_DONE bytes=100 elapsed_s=1.0 mbit_per_s=95.00 MB_per_s=11.9"
    _recv_ok = "RECV_DONE bytes=100 expect=100 status=ok"
    _recv_short = "RECV_DONE bytes=40 expect=100 status=short"
    for missing, text in {
        "no-rtt": f"{_send}\n{_recv_ok}",
        "no-xfer": f"{_rtt}\n{_recv_ok}",
        "no-recv": f"{_rtt}\n{_send}",
        "recv-short": f"{_rtt}\n{_send}\n{_recv_short}",
    }.items():
        try:
            parse_inner_output(text)
            failures.append(f"parse should reject '{missing}' arm but did not")
        except ShapingViolation:
            pass

    # A complete, consistent triple must PARSE (proves the checks are not blanket).
    try:
        parsed = parse_inner_output(f"{_rtt}\n{_send}\n{_recv_ok}")
        if parsed.get("recv_bytes") != 100:
            failures.append("parse dropped the receiver delivered-byte count")
    except ShapingViolation as exc:
        failures.append(f"complete arm wrongly rejected: {exc}")

    # assert_full_delivery: got==expect passes, a short delivery bites.
    try:
        assert_full_delivery(100, 100)
    except ShapingViolation as exc:
        failures.append(f"assert_full_delivery wrongly rejected got==expect: {exc}")
    try:
        assert_full_delivery(40, 100)
        failures.append("assert_full_delivery accepted a truncated (40/100) transfer")
    except ShapingViolation:
        pass

    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        return 1
    print(
        "SELF-TEST OK: baseline accepted, 6 mutations + 4 truncations + "
        "delivery-counter bitten"
    )
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
