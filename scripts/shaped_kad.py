#!/usr/bin/env python3
"""Shaped-link kad-DHT DISCOVERY proof + RTT sweep (TASK-209).

WHAT THIS IS. TASK-206 proved a real libp2p `/nar/3` fetch is BYTE-IDENTICAL over a
`tc netem`-shaped `veth` pair, but it drove the fetch via a DIRECT-multiaddr dial, so the
DISCOVER half (kad `get_providers` + peer-routing `get_closest_peers`) never crossed the
shaped link -- that half is shown only unshaped (TASK-179 routed netns at ~0 RTT). This
closes it. A 3-node kad topology -- BOOTSTRAP B + PROVIDER P in ns A, CONSUMER C in ns B --
where C, knowing ONLY B, DISCOVERS P purely through the DHT and then fetches, with EVERY C
round-trip (join, get_providers, get_closest_peers, /nar/3 fetch) traversing the shaped veth.

TWO deliverables, one harness:

 1. THE PROOF (default run). A shaped arm + an UNSHAPED negative control. The run is refused
    unless, on the shaped arm: the host-side ping RTT recovered ~2*delay (shaping fired); kad
    DISCOVERY returned Found for BOTH get_providers and get_closest_peers; the DHT-resolved
    dial address carries P's REAL listen address (proving kad resolution, not injection --
    C was told only B); the fetch is BYTE-IDENTICAL + BLAKE3-verified; the fetch throughput
    sits near the cap; and the unshaped control is measurably faster. Reuses TASK-206's proven
    `shaped_link.assert_shaping` oracle verbatim for the RTT/cap/negative-control gate.

 2. THE RTT SWEEP (`--sweep`). TASK-206 flagged the concrete risk that kad's 10s
    `query_timeout` (fabric-libp2p swarm.rs) is too tight under real RTT. This sweeps the
    injected ONE-WAY delay and records, at each point, whether C's DISCOVERY (join +
    get_providers + get_closest_peers) still returns Found within budget or MISSES it
    (JoinFailed / DeadlineExceeded). It reports the measured budget and the breaking-point
    RTT honestly -- either a real timeout finding (residential/satellite peers) or a
    credibility win if it holds to high RTT.

NO-FLOAT REPORTING (owner rule). RTT integer nanoseconds, throughput integer bytes/sec,
negative-control speedup an EXACT rational. Floats appear only inside the proven
`shaped_link.assert_shaping` accept/reject gate.

STATED LIMITS. Inherits `shaped_link.HONEST_LIMITS`: one host emulating a link over a shared
kernel; models mean RTT + a rate cap, NOT loss/jitter/cross-traffic/NAT-traversal cost. It
removes the loopback UPPER bound on kad discovery; it is not itself a field measurement.
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
INNER = os.path.join(HERE, "shaped_kad_inner.sh")
DEFAULT_BIN = os.path.join(ROOT, "target", "debug", "examples", "shaped_kad_probe")

# P's real listen address inside ns A (kept in lock-step with shaped_kad_inner.sh). The
# consumer is told ONLY the bootstrap (PORT_B=9098); if the DHT-resolved dial address carries
# THIS provider address (PORT_P=9099), the resolution came from kad, not from injection.
PROVIDER_LISTEN = "/ip4/10.99.0.1/tcp/9099"

# 40 MiB incompressible NAR over a 100 mbit cap is ~3.4 s of transfer -- long enough that the
# fetch throughput reflects the steady-state shaped rate. Same rationale as TASK-206.
DEFAULT_NAR_BYTES = 40 * 1024 * 1024
DEFAULT_DELAY_MS = 20
DEFAULT_RATE_MBIT = 100
DEFAULT_NAR_SEED = 20209
# The production kad query_timeout is 10s (fabric-libp2p swarm.rs); we drive find_providers
# with that SAME budget so the breaking point we report is the one a shipped consumer hits.
DEFAULT_DISC_BUDGET_SECS = 10
# Outer retry window per consumer run: enough to absorb propagation + a couple of budget
# expiries, bounded so a broken point fails fast (shared-box discipline).
DEFAULT_OUTER_SECS = 25


class ProofFailure(Exception):
    """The shaped-kad proof could not be established; the run is not a proof."""


def parse_rtt_ms(text: str) -> float:
    m = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", text)
    if not m:
        raise ProofFailure("arm reported no RTT line (ping did not complete)")
    return float(m.group(1))


def parse_discovery(text: str) -> dict:
    """Pull the consumer's DISCOVERY_DONE fields. Missing it is fatal (a silent absence must
    not read as a passing zero). Pure so `--self-test` bites it with no netns."""
    if "FATAL" in text:
        fatal = next((ln for ln in text.splitlines() if "FATAL" in ln), "FATAL")
        raise ProofFailure(f"inner harness reported {fatal!r} -- setup failed")
    m = re.search(
        r"DISCOVERY_DONE find_outcome=(\S+) locate_outcome=(\S+) "
        r"provider_matched=(\d) located=(\S*) discovery_elapsed_ns=(\d+) "
        r"find_attempts=(\d+) locate_attempts=(\d+)",
        text,
    )
    if not m:
        raise ProofFailure(
            "arm reported no DISCOVERY_DONE line (consumer did not report)"
        )
    return {
        "find_outcome": m.group(1),
        "locate_outcome": m.group(2),
        "provider_matched": int(m.group(3)),
        "located": m.group(4),
        "discovery_elapsed_ns": int(m.group(5)),
        "find_attempts": int(m.group(6)),
        "locate_attempts": int(m.group(7)),
    }


def parse_fetch(text: str) -> dict:
    """Pull the consumer's FETCH_DONE fields, enforcing byte-identity as in TASK-206."""
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
        "bytes": got,
        "elapsed_ns": elapsed_ns,
        "byte_identical": True,
        "blake3_ok": True,
    }


def assert_kad_discovered(disc: dict) -> None:
    """AC#9 no-shortcut witness at the harness level: the discovery must be genuinely kad --
    both lookups Found, the provider matched, and the DHT-resolved dial address must carry P's
    REAL listen address the consumer was NEVER told (it knew only the bootstrap)."""
    if disc["find_outcome"] != "Found":
        raise ProofFailure(
            f"kad get_providers did not resolve the provider (find_outcome={disc['find_outcome']})"
        )
    if disc["locate_outcome"] != "Found":
        raise ProofFailure(
            f"kad get_closest_peers did not resolve the dial address "
            f"(locate_outcome={disc['locate_outcome']})"
        )
    if disc["provider_matched"] != 1:
        raise ProofFailure("discovered record did not answer the queried key")
    if not any(loc.startswith(PROVIDER_LISTEN) for loc in disc["located"].split(",")):
        raise ProofFailure(
            f"DHT-resolved address {disc['located']!r} does not carry P's real listen "
            f"address {PROVIDER_LISTEN} -- discovery may have been injected, not kad"
        )


def throughput_bytes_per_s(byte_count: int, elapsed_ns: int) -> int:
    return (byte_count * 1_000_000_000) // elapsed_ns


def rtt_ns(rtt_ms: float) -> int:
    return round(rtt_ms * 1_000_000)


def run_arm(
    shape: bool,
    nar_bytes: int,
    delay_ms: int,
    rate_mbit: int,
    probe_bin: str,
    nar_seed: int,
    disc_budget_secs: int,
    outer_secs: int,
    timeout: int,
) -> dict:
    """Run one arm inside `unshare -Urn` and return its raw output + parsed RTT/discovery."""
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
        str(disc_budget_secs),
        str(outer_secs),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0 and "FATAL" not in out:
        raise ProofFailure(
            f"{'shaped' if shape else 'unshaped'} arm exited {proc.returncode}\n{out}"
        )
    return {"raw": out, "rtt_ms": parse_rtt_ms(out), "disc": parse_discovery(out)}


# --------------------------------------------------------------------------------------------
# Deliverable 1: THE PROOF (shaped arm + unshaped negative control).
# --------------------------------------------------------------------------------------------


def measure(
    nar_bytes: int, delay_ms: int, rate_mbit: int, probe_bin: str, nar_seed: int
) -> int:
    if not os.path.exists(probe_bin):
        print(
            f"PROOF FAILURE: probe binary not found at {probe_bin}\n"
            f"  build it: nix develop -c cargo build -p fabric-libp2p "
            f"--example shaped_kad_probe",
            file=sys.stderr,
        )
        return 2

    print(
        f"# shaped-kad-discovery proof: {nar_bytes} byte NAR, delay {delay_ms}ms, "
        f"cap {rate_mbit}mbit (nar_seed={nar_seed}, disc_budget={DEFAULT_DISC_BUDGET_SECS}s)"
    )
    try:
        shaped = run_arm(
            True,
            nar_bytes,
            delay_ms,
            rate_mbit,
            probe_bin,
            nar_seed,
            DEFAULT_DISC_BUDGET_SECS,
            DEFAULT_OUTER_SECS,
            timeout=300,
        )
        unshaped = run_arm(
            False,
            nar_bytes,
            delay_ms,
            rate_mbit,
            probe_bin,
            nar_seed,
            DEFAULT_DISC_BUDGET_SECS,
            DEFAULT_OUTER_SECS,
            timeout=300,
        )
        # Both arms must have genuinely kad-discovered P, and both must fetch byte-identical.
        assert_kad_discovered(shaped["disc"])
        assert_kad_discovered(unshaped["disc"])
        shaped_fetch = parse_fetch(shaped["raw"])
        unshaped_fetch = parse_fetch(unshaped["raw"])
    except subprocess.TimeoutExpired:
        print(
            "PROOF FAILURE: an arm timed out (link/discovery/fetch hung)",
            file=sys.stderr,
        )
        return 2
    except ProofFailure as exc:
        print(f"PROOF FAILURE: {exc}", file=sys.stderr)
        return 2

    s_bps = throughput_bytes_per_s(shaped_fetch["bytes"], shaped_fetch["elapsed_ns"])
    u_bps = throughput_bytes_per_s(
        unshaped_fetch["bytes"], unshaped_fetch["elapsed_ns"]
    )
    speedup = Fraction(shaped_fetch["elapsed_ns"], unshaped_fetch["elapsed_ns"])

    for label, arm, fetch, bps in (
        ("shaped  ", shaped, shaped_fetch, s_bps),
        ("unshaped", unshaped, unshaped_fetch, u_bps),
    ):
        d = arm["disc"]
        print(
            f"  {label} : RTT {rtt_ns(arm['rtt_ms'])} ns  "
            f"discover(find={d['find_outcome']},locate={d['locate_outcome']},"
            f"elapsed={d['discovery_elapsed_ns']}ns)  "
            f"fetch(throughput {bps} bytes/s, byte_identical={fetch['byte_identical']}, "
            f"blake3_ok={fetch['blake3_ok']})"
        )
    print(f"    shaped DHT-resolved dial address: {shaped['disc']['located']}")
    print(
        f"  negative-control speedup (shaped_elapsed/unshaped_elapsed) = "
        f"{speedup.numerator}/{speedup.denominator} (~{float(speedup):.1f}x unshaped is faster)"
    )

    # THE ORACLE (proven, reused verbatim): the fetch throughput is the `mbit`, so the cap +
    # negative-control invariants are asserted on the real transfer, RTT on the real ping.
    shaped_arm = {"rtt_ms": shaped["rtt_ms"], "mbit": s_bps * 8 / 1e6}
    unshaped_arm = {"rtt_ms": unshaped["rtt_ms"], "mbit": u_bps * 8 / 1e6}
    try:
        shaped_link.assert_shaping(shaped_arm, unshaped_arm, delay_ms, rate_mbit)
    except shaped_link.ShapingViolation as exc:
        print(f"PROOF FAILURE (shaping oracle): {exc}", file=sys.stderr)
        return 2

    print(
        "PROOF OK: a consumer that knew ONLY the bootstrap DISCOVERED the provider via kad "
        "(get_providers + get_closest_peers) and fetched BYTE-IDENTICAL over a shaped link"
    )
    print(
        "  (injected RTT recovered, DHT-resolved address is P's real listen addr, fetch "
        "throughput near the cap, unshaped control measurably faster)"
    )
    print()
    print(shaped_link.HONEST_LIMITS)
    return 0


# --------------------------------------------------------------------------------------------
# Deliverable 2: THE RTT SWEEP (find where kad discovery misses its budget).
# --------------------------------------------------------------------------------------------

DEFAULT_SWEEP_DELAYS_MS = [20, 100, 250, 500, 1000, 2000]


def sweep(
    nar_bytes: int, rate_mbit: int, probe_bin: str, nar_seed: int, delays_ms: list[int]
) -> int:
    """Sweep the injected one-way delay; at each point run the shaped consumer and record
    whether kad DISCOVERY still returns Found within budget. Reports the breaking-point RTT."""
    if not os.path.exists(probe_bin):
        print(f"SWEEP FAILURE: probe binary not found at {probe_bin}", file=sys.stderr)
        return 2

    print(
        f"# RTT sweep: kad discovery over a shaped link, {nar_bytes} byte NAR, cap "
        f"{rate_mbit}mbit, kad query_timeout {DEFAULT_DISC_BUDGET_SECS}s, outer window "
        f"{DEFAULT_OUTER_SECS}s (nar_seed={nar_seed})"
    )
    print(
        "# delay_ms  host_rtt_ns  find(outcome/attempts)  locate(outcome/attempts)  "
        "discovery_elapsed_ns  first_try  ok"
    )
    print(
        "#   first_try=YES means the FIRST single kad query (one 10s query_timeout) resolved "
        "-- what a shipped one-shot consumer sees; NO means it needed retries past the budget."
    )

    breaking_point_ms: int | None = None
    first_try_break_ms: int | None = None
    rows: list[dict] = []
    for delay_ms in delays_ms:
        # Outer window must exceed the injected join+query RTTs; scale it up generously for big
        # delays so a HEALTHY-but-slow point is not cut short (only a genuine budget miss should
        # read as broken). Discovery latency grew ~quadratically with RTT in early runs, so we
        # allow a wide retry window and let find_attempts reveal the 10s-budget breaking point.
        outer = max(
            DEFAULT_OUTER_SECS, 20 * delay_ms // 1000 + DEFAULT_DISC_BUDGET_SECS + 15
        )
        # Hard subprocess timeout: 2x outer (join window + discovery window) + generous slack.
        hard = 2 * outer + 150
        try:
            arm = run_arm(
                True,
                nar_bytes,
                delay_ms,
                rate_mbit,
                probe_bin,
                nar_seed,
                DEFAULT_DISC_BUDGET_SECS,
                outer,
                timeout=hard,
            )
        except subprocess.TimeoutExpired:
            print(
                f"  {delay_ms:>7}  (subprocess timed out after {hard}s -- treated as broken)"
            )
            rows.append({"delay_ms": delay_ms, "ok": False, "find": "SubprocTimeout"})
            if breaking_point_ms is None:
                breaking_point_ms = delay_ms
            continue
        except ProofFailure as exc:
            print(f"  {delay_ms:>7}  (arm failed: {exc})")
            rows.append({"delay_ms": delay_ms, "ok": False, "find": "ArmFailed"})
            if breaking_point_ms is None:
                breaking_point_ms = delay_ms
            continue

        d = arm["disc"]
        host_rtt = rtt_ns(arm["rtt_ms"])
        # A point is only meaningful if shaping fired: the host RTT must recover ~2*delay.
        expected_rtt_ns = 2 * delay_ms * 1_000_000
        shaping_fired = host_rtt >= int(expected_rtt_ns * 0.8)
        ok = (
            d["find_outcome"] == "Found"
            and d["locate_outcome"] == "Found"
            and d["provider_matched"] == 1
        )
        # The FIRST-attempt signal: a shipped consumer that issues ONE find_providers + ONE
        # locate (each bounded by the 10s kad query_timeout) succeeds iff attempts == 1 on both.
        first_try = ok and d["find_attempts"] == 1 and d["locate_attempts"] == 1
        shaping_note = (
            "" if shaping_fired else "  [!] shaping did NOT fire (RTT too low)"
        )
        print(
            f"  {delay_ms:>7}  {host_rtt:>11}  "
            f"{d['find_outcome']}/{d['find_attempts']:<3}  "
            f"{d['locate_outcome']}/{d['locate_attempts']:<3}  "
            f"{d['discovery_elapsed_ns']:>20}  {'YES' if first_try else 'NO':>5}  "
            f"{'YES' if ok else 'NO':>3}{shaping_note}"
        )
        rows.append(
            {
                "delay_ms": delay_ms,
                "host_rtt_ns": host_rtt,
                "find": d["find_outcome"],
                "find_attempts": d["find_attempts"],
                "locate": d["locate_outcome"],
                "locate_attempts": d["locate_attempts"],
                "elapsed_ns": d["discovery_elapsed_ns"],
                "ok": ok,
                "first_try": first_try,
                "shaping_fired": shaping_fired,
            }
        )
        if not first_try and first_try_break_ms is None:
            first_try_break_ms = delay_ms
        if not ok and breaking_point_ms is None:
            breaking_point_ms = delay_ms

    print()
    # (a) The SINGLE-QUERY budget: where the FIRST one-shot kad query (10s query_timeout)
    # starts missing. This is the shipped-consumer-facing limit.
    first_ok = [r for r in rows if r.get("first_try")]
    if first_ok:
        max_first = max(r["delay_ms"] for r in first_ok)
        print(
            f"SWEEP RESULT (single 10s query_timeout): a ONE-SHOT kad discovery held up to "
            f"{max_first}ms one-way delay (~{2 * max_first}ms RTT)."
        )
    if first_try_break_ms is not None:
        fb = next(r for r in rows if r["delay_ms"] == first_try_break_ms)
        detail = (
            f"find={fb.get('find')}/{fb.get('find_attempts')} "
            f"locate={fb.get('locate')}/{fb.get('locate_attempts')}"
        )
        print(
            f"SWEEP RESULT (single 10s query_timeout): FIRST-ATTEMPT BREAKING POINT at "
            f"{first_try_break_ms}ms one-way delay (~{2 * first_try_break_ms}ms RTT): {detail} "
            f"-- the first single query exceeded the 10s budget and needed retries."
        )

    # (b) The retry-tolerant budget: whether discovery EVER succeeds within a bounded outer
    # retry window (a patient consumer that re-queries).
    healthy = [r for r in rows if r.get("ok")]
    if healthy:
        max_ok = max(r["delay_ms"] for r in healthy)
        print(
            f"SWEEP RESULT (with retries): kad discovery still eventually resolved up to "
            f"{max_ok}ms one-way delay (~{2 * max_ok}ms RTT)."
        )
    if breaking_point_ms is not None:
        broke = next(r for r in rows if r["delay_ms"] == breaking_point_ms)
        print(
            f"SWEEP RESULT (with retries): BREAKING POINT at {breaking_point_ms}ms one-way "
            f"delay (~{2 * breaking_point_ms}ms RTT): find={broke.get('find')} "
            f"locate={broke.get('locate')} (unresolved within the retry window)."
        )
    else:
        print(
            f"SWEEP RESULT (with retries): kad discovery resolved across the ENTIRE swept range "
            f"up to {max(delays_ms)}ms one-way delay (~{2 * max(delays_ms)}ms RTT)."
        )
    print()
    print(shaped_link.HONEST_LIMITS)
    return 0


# --------------------------------------------------------------------------------------------
# self-test: prove the parse/verdict bites by mutation (no netns needed).
# --------------------------------------------------------------------------------------------


def _good_disc_text() -> str:
    return (
        "=== RTT probe (shape=yes) ===\n"
        "rtt min/avg/max/mdev = 40.0/48.1/80.1/16.0 ms\n"
        "=== KAD DISCOVERY ===\n"
        "DISCOVERY_DONE find_outcome=Found locate_outcome=Found provider_matched=1 "
        f"located={PROVIDER_LISTEN}/p2p/12D3KooWabc discovery_elapsed_ns=812158737 "
        "find_attempts=1 locate_attempts=1\n"
        "FETCH_DONE bytes=41943040 expect=41943040 elapsed_ns=3400000000 "
        "byte_identical=1 blake3_ok=1\n"
    )


def self_test() -> int:
    """Every mutation must be REJECTED and the honest baseline ACCEPTED, or the parse/verdict
    is vacuous (TASK-63 'oracle must bite by mutation')."""
    failures: list[str] = []

    # Baseline must parse, kad-verify, and be byte-identical.
    try:
        good = parse_discovery(_good_disc_text())
        assert_kad_discovered(good)
        parse_fetch(_good_disc_text())
    except ProofFailure as exc:
        failures.append(f"baseline should be a clean proof but was rejected: {exc}")

    # Each mutation breaks exactly one invariant and MUST be caught.
    mutations = {
        "fatal": ("=== KAD ===\nFATAL provider-not-ready\n", parse_discovery),
        "no-discovery": (
            "rtt min/avg/max/mdev = 40.0/48.1/80.1/16.0 ms\n",
            parse_discovery,
        ),
        "find-missed": (
            _good_disc_text().replace(
                "find_outcome=Found", "find_outcome=DeadlineExceeded"
            ),
            lambda t: assert_kad_discovered(parse_discovery(t)),
        ),
        "locate-missed": (
            _good_disc_text().replace("locate_outcome=Found", "locate_outcome=Miss"),
            lambda t: assert_kad_discovered(parse_discovery(t)),
        ),
        "join-failed": (
            _good_disc_text().replace("find_outcome=Found", "find_outcome=JoinFailed"),
            lambda t: assert_kad_discovered(parse_discovery(t)),
        ),
        "provider-unmatched": (
            _good_disc_text().replace("provider_matched=1", "provider_matched=0"),
            lambda t: assert_kad_discovered(parse_discovery(t)),
        ),
        "injected-address": (
            # A resolved address that is NOT P's real listen addr (e.g. the bootstrap, or a
            # guess) must be refused: it would mean discovery was injected, not kad.
            _good_disc_text().replace(PROVIDER_LISTEN, "/ip4/10.99.0.1/tcp/9098"),
            lambda t: assert_kad_discovered(parse_discovery(t)),
        ),
        "truncated-fetch": (
            _good_disc_text().replace("bytes=41943040", "bytes=1024"),
            parse_fetch,
        ),
        "not-byte-identical": (
            _good_disc_text().replace("byte_identical=1", "byte_identical=0"),
            parse_fetch,
        ),
        "blake3-fail": (
            _good_disc_text().replace("blake3_ok=1", "blake3_ok=0"),
            parse_fetch,
        ),
    }
    for name, (text, fn) in mutations.items():
        try:
            fn(text)
            failures.append(f"mutation {name!r} should have been REJECTED but passed")
        except ProofFailure:
            pass  # correctly bitten

    # Integer-domain reporting (no-float rule).
    if not isinstance(throughput_bytes_per_s(41943040, 3_400_000_000), int):
        failures.append("throughput must be an integer bytes/sec")
    if throughput_bytes_per_s(100, 1_000_000_000) != 100:
        failures.append("throughput_bytes_per_s wrong for 100 B / 1 s")
    if rtt_ns(48.1) != 48_100_000:
        failures.append("rtt_ns wrong for 48.1 ms")

    if failures:
        for f in failures:
            print(f"SELF-TEST FAIL: {f}", file=sys.stderr)
        return 1
    print(
        f"SELF-TEST OK: baseline accepted, {len(mutations)} mutations bitten, "
        "integer reporting checked"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Shaped-kad-discovery proof + RTT sweep (TASK-209)"
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove the parse/verdict bites by mutation (hermetic, no netns)",
    )
    ap.add_argument(
        "--sweep",
        action="store_true",
        help="sweep the injected one-way delay to find the kad-discovery breaking point",
    )
    ap.add_argument("--nar-bytes", type=int, default=DEFAULT_NAR_BYTES)
    ap.add_argument("--delay-ms", type=int, default=DEFAULT_DELAY_MS)
    ap.add_argument("--rate-mbit", type=int, default=DEFAULT_RATE_MBIT)
    ap.add_argument("--nar-seed", type=int, default=DEFAULT_NAR_SEED)
    ap.add_argument("--probe-bin", default=DEFAULT_BIN)
    ap.add_argument(
        "--sweep-delays-ms",
        default=",".join(str(d) for d in DEFAULT_SWEEP_DELAYS_MS),
        help="comma-separated one-way delays to sweep (ms)",
    )
    ap.add_argument(
        "--sweep-nar-bytes",
        type=int,
        default=1 * 1024 * 1024,
        help="NAR size for sweep points (small: the sweep measures DISCOVERY, not throughput)",
    )
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.sweep:
        delays = [int(x) for x in args.sweep_delays_ms.split(",") if x.strip()]
        return sweep(
            args.sweep_nar_bytes, args.rate_mbit, args.probe_bin, args.nar_seed, delays
        )
    return measure(
        args.nar_bytes, args.delay_ms, args.rate_mbit, args.probe_bin, args.nar_seed
    )


if __name__ == "__main__":
    sys.exit(main())
