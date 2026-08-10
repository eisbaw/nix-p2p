#!/usr/bin/env python3
"""TASK-91: the CLOSURE-DISCOVERY axis - what finding the holders of a closure costs.

Every other arm of `scripts/profile_p2p.py` measures moving BYTES. This one
measures the step before any byte moves: asking peers who has what. That step had
the wrong granularity - one round trip per NAR per peer, so a 200-path closure
against 8 peers was ~1,600 probes, each with its own dial and timeout exposure -
and TASK-91 replaced it with one batched probe per peer per chunk of 256 keys.

WHAT IS MEASURED, AND IN WHAT UNITS
-----------------------------------
Two arms over the SAME closure, the SAME peer set and the SAME availability
indexes; the only difference is whether a peer is asked once or once per key:

  round_trips                     - peer exchanges. The quantity the task set out
                                    to reduce, and the one that needs no model.
  round_trips_per_substitution    - round trips divided by the paths actually
                                    resolved (a "substitution" is a path a peer
                                    can supply).
  wall_clock_ms_median            - discovery wall clock, milliseconds.

There is deliberately NO byte figure in this arm. It is about latency and message
count; a `_bytes` key here would invite comparison with the transport arms, whose
numbers are in completely different units.

THE NETWORK IS EMULATED, AND THAT IS WHY THERE ARE TWO RUNS
-----------------------------------------------------------
The peer transport is in-process (`InProcessPeerQuery`), so a round trip costs
microseconds. Measuring wall clock there would say batching saves almost nothing -
true of a loopback HashMap, false of every deployment, and it is exactly the wrong
half of the cost. So the instrument injects a per-round-trip delay and this module
runs it TWICE:

  * `unshaped`  (0 ms) - the honest floor: pure codec + index cost.
  * `shaped`    (profile_p2p.WAN_RTT_MS, derived from task-35's real measurements
    against cache.nixos.org) - the regime a real peer lives in.

Both are MEASURED. The injected delay is a stated experimental condition, the same
device the profiler's WAN-shaped upstream arm already uses - not a model output.
And the injection is ASSERTED, not assumed: `arm_violations` recovers the injected
RTT from the shaped wall clock and FAILS the arm if it is not there. A shaped run
that was not actually shaped would otherwise confirm any conclusion, which is the
half-armed-shaper failure this project has already shipped once.

THE ANTI-CHEAT ORACLE (the one that matters)
--------------------------------------------
A batched arm could "win" by asking about FEWER KEYS - which would not be the same
measurement at all. So `keys_asked` is reported per arm and the two must be EQUAL;
a difference is a named failure, not a footnote. Likewise the two arms must resolve
the same paths: a cost comparison between arms that found different things is not
a measurement.

STATED LIMITS
-------------
  * No containers and no nix. Production still wires `InMemoryDiscovery` from
    config (daemon/src/main.rs), so there is no peer-probing container path for
    this to run over; when TASK-100/TASK-101 give the daemon a real content
    discovery seam, this arm should be re-pointed at it. Until then it measures
    the LIBRARY's resolver over the real wire codec, which is where the round
    trips are decided.
  * The topology is deterministic and uniform (key i is held by peer i % peers
    inside the hit fraction). Real holder distributions are skewed; a skew would
    change the SERIAL arm's cost (a hit found at the first peer is cheap) and
    barely move the batched arm, so this uniform case is not the batched arm's
    best case.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import fixturelib as fx

# ---- frozen parameters ------------------------------------------------------

DISCOVERY_RULE_VERSION = "p2p-closure-discovery-v1"

# A real `nix build` closure is ~200 store paths (task-91), and the task's own
# scenario is 8 peers.
DEFAULT_CLOSURE_PATHS = 200
DEFAULT_PEERS = 8

# The fraction of the closure SOME peer holds. 0.6 keeps a substantial miss
# population, and a miss is the expensive case for BOTH arms (it costs every
# peer), so the comparison is not run on an all-hit best case.
DEFAULT_HIT_RATE = 0.6

# Replicates. The unshaped run is milliseconds, so it takes 3; the shaped run
# costs round_trips x RTT (about a minute for the serial arm at 200x8), so it
# takes 1 - the quantity the shaped run exists for is the RTT-dominated wall
# clock, which is not a noisy measurement.
UNSHAPED_REPEATS = 3
SHAPED_REPEATS = 1

# How far the recovered RTT may sit from the injected one before the shaped run
# is declared unshaped. Wide on the top side because the in-process work is real
# and adds to every round trip; the point of the check is "the delay is there at
# all", which a broken injection fails by an order of magnitude.
RTT_RECOVERY_BAND = (0.85, 1.60)

# The unshaped control must be MATERIALLY faster than the shaped run, or the
# shaping could not be distinguished from none.
MIN_SHAPED_SLOWDOWN = 5.0


def run_instrument(
    *,
    rtt_ms: int,
    repeats: int,
    closure: int = DEFAULT_CLOSURE_PATHS,
    peers: int = DEFAULT_PEERS,
    hit_rate: float = DEFAULT_HIT_RATE,
    repo: Path | None = None,
) -> dict:
    """Run the Rust instrument and return its JSON report.

    RELEASE on purpose, like `just iroh-bench`: a debug build measures rustc, not
    the resolver. Failures are LOUD - a missing instrument must not degrade into
    a missing arm nobody notices.
    """
    repo = repo or fx.repo_root()
    command = [
        "cargo",
        "run",
        "--locked",
        "--release",
        "--quiet",
        "--example",
        "closure_discovery",
        "--",
        "--json",
        "--rtt-ms",
        str(rtt_ms),
        "--repeats",
        str(repeats),
        "--closure",
        str(closure),
        "--peers",
        str(peers),
        "--hit-rate",
        str(hit_rate),
    ]
    result = subprocess.run(
        command, cwd=repo, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"closure_discovery exited {result.returncode}: "
            f"{result.stderr.strip()[-2000:]}"
        )
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as error:
        raise RuntimeError(
            f"closure_discovery emitted no parseable JSON: {result.stdout[-2000:]}"
        ) from error


# ---- pure: the oracles ------------------------------------------------------


def _number(node: dict, path: str, problems: list[str]):
    """Fetch a numeric field by dotted path, recording a problem if unusable."""
    cursor = node
    for part in path.split("."):
        if not isinstance(cursor, dict) or part not in cursor:
            problems.append(f"missing `{path}`; an unmeasured arm is an unasserted one")
            return None
        cursor = cursor[part]
    if not isinstance(cursor, (int, float)) or isinstance(cursor, bool):
        problems.append(f"`{path}` is not a number ({cursor!r})")
        return None
    return float(cursor)


def arm_violations(report: dict, *, expect_shaped: bool) -> list[str]:
    """Is this instrument run a VALID measurement? Empty list == valid.

    PURE, so `run_self_test` can prove every rule bites without running anything.
    """
    problems: list[str] = []

    if report.get("rule_version") != DISCOVERY_RULE_VERSION:
        problems.append(
            f"rule_version is {report.get('rule_version')!r}, expected "
            f"{DISCOVERY_RULE_VERSION!r} - the instrument and this reader disagree "
            "about what was measured"
        )

    serial_rt = _number(report, "arms.serial.round_trips", problems)
    batched_rt = _number(report, "arms.batched.round_trips", problems)
    serial_keys = _number(report, "arms.serial.keys_asked", problems)
    batched_keys = _number(report, "arms.batched.keys_asked", problems)
    serial_ms = _number(report, "arms.serial.wall_clock_ms_median", problems)
    batched_ms = _number(report, "arms.batched.wall_clock_ms_median", problems)
    resolved = _number(report, "resolved_paths", problems)
    rtt_ms = _number(report, "config.injected_rtt_ms", problems)
    if problems:
        return problems

    # THE ANTI-CHEAT RULE. A batched arm that asked about fewer keys did less
    # work, not the same work more cheaply, and its round-trip saving would be an
    # artifact of the question rather than of the protocol.
    if serial_keys != batched_keys:
        problems.append(
            f"the arms asked about different numbers of keys (serial "
            f"{serial_keys:.0f}, batched {batched_keys:.0f}); a cheaper arm that "
            "asked less is not the same measurement"
        )

    if resolved <= 0:
        problems.append(
            "the run resolved 0 paths, so round-trips-per-substitution is "
            "undefined and no win can be claimed"
        )

    # The comparison must be non-vacuous in the direction claimed.
    if serial_rt <= batched_rt:
        problems.append(
            f"NO WIN MEASURED: serial {serial_rt:.0f} round trips vs batched "
            f"{batched_rt:.0f}. This is a named failure, not a silent pass"
        )
    if batched_rt < 1:
        problems.append("the batched arm made no round trips at all - it did nothing")

    if expect_shaped:
        if rtt_ms <= 0:
            problems.append(
                "the shaped run injected 0 ms of RTT - it is not shaped, and any "
                "wall-clock conclusion drawn from it would be vacuous"
            )
        else:
            # RECOVER the injection from the measurement rather than trusting the
            # knob: the serial arm's wall clock must be its round trips x the RTT.
            expected_ms = serial_rt * rtt_ms
            low, high = RTT_RECOVERY_BAND
            if not low * expected_ms <= serial_ms <= high * expected_ms:
                problems.append(
                    f"injected RTT NOT recovered: {serial_rt:.0f} round trips at "
                    f"{rtt_ms:.0f} ms should be ~{expected_ms:.0f} ms, measured "
                    f"{serial_ms:.0f} ms (outside [{low * expected_ms:.0f}, "
                    f"{high * expected_ms:.0f}] ms). The shaper is not armed"
                )
            if batched_ms >= serial_ms:
                problems.append(
                    f"the batched arm ({batched_ms:.0f} ms) was not faster than the "
                    f"serial one ({serial_ms:.0f} ms) under injected latency"
                )
    elif rtt_ms != 0:
        problems.append(
            f"the unshaped control injected {rtt_ms:.0f} ms of RTT; it is not a control"
        )

    return problems


def cross_run_violations(unshaped: dict, shaped: dict) -> list[str]:
    """Rules that need BOTH runs. Empty list == valid."""
    problems: list[str] = []
    for name, run in (("unshaped", unshaped), ("shaped", shaped)):
        for field in ("closure_paths", "peers", "hit_rate"):
            if run["config"][field] != unshaped["config"][field]:
                problems.append(
                    f"the {name} run used a different `{field}`; the two runs "
                    "must differ ONLY in the injected RTT"
                )
    if (
        unshaped["arms"]["serial"]["round_trips"]
        != shaped["arms"]["serial"]["round_trips"]
    ):
        problems.append(
            "the two runs made different numbers of round trips; the topology is "
            "supposed to be deterministic, so this means something else changed"
        )
    slowdown = shaped["arms"]["serial"]["wall_clock_ms_median"] / max(
        unshaped["arms"]["serial"]["wall_clock_ms_median"], 1e-9
    )
    if slowdown < MIN_SHAPED_SLOWDOWN:
        problems.append(
            f"the shaped run was only {slowdown:.1f}x slower than the unshaped "
            f"control (floor {MIN_SHAPED_SLOWDOWN}x); shaped and unshaped are not "
            "distinguishable, so the shaped arm confirms nothing"
        )
    return problems


# ---- report assembly --------------------------------------------------------


def build_block(unshaped: dict, shaped: dict) -> tuple[dict, list[str]]:
    """The report block plus every honesty problem found. Never raises."""
    problems = arm_violations(unshaped, expect_shaped=False)
    problems += arm_violations(shaped, expect_shaped=True)
    if not problems:
        problems += cross_run_violations(unshaped, shaped)

    def arms(run: dict) -> dict:
        return {
            "round_trips": run["arms"]["serial"]["round_trips"],
            "round_trips_batched": run["arms"]["batched"]["round_trips"],
            "round_trips_per_substitution": run["arms"]["serial"][
                "round_trips_per_substitution"
            ],
            "round_trips_per_substitution_batched": run["arms"]["batched"][
                "round_trips_per_substitution"
            ],
            "wall_clock_ms_median": run["arms"]["serial"]["wall_clock_ms_median"],
            "wall_clock_ms_median_batched": run["arms"]["batched"][
                "wall_clock_ms_median"
            ],
        }

    return (
        {
            "rule_version": DISCOVERY_RULE_VERSION,
            "what": (
                "closure discovery cost: one-at-a-time vs batched hold-query "
                "(task-91). Round trips are a count; wall clock is measured with "
                "the network EMULATED by an injected per-round-trip delay"
            ),
            # The RTT is per-CONDITION, not per-arm, so it lives on the shaped
            # block rather than in the shared config where it would be a lie for
            # the control.
            "config": {
                key: value
                for key, value in unshaped["config"].items()
                if key != "injected_rtt_ms"
            },
            "resolved_paths": unshaped["resolved_paths"],
            "keys_asked_per_arm_equal": (
                unshaped["arms"]["serial"]["keys_asked"]
                == unshaped["arms"]["batched"]["keys_asked"]
            ),
            "unshaped": arms(unshaped),
            "shaped": arms(shaped)
            | {"injected_rtt_ms": shaped["config"]["injected_rtt_ms"]},
            "round_trip_reduction_factor": unshaped["round_trip_reduction_factor"],
            # DERIVED, NOT A SECOND RESULT. The shaped wall clock is validated
            # against round_trips * injected_rtt_ms and the run is marked INVALID
            # outside the recovery band, so within a valid run this ratio IS the
            # round-trip ratio restated in milliseconds. It is emitted because it
            # shows the emulation behaved, and it is named `..._is_derived` beside
            # it so nothing downstream can quote it as corroboration.
            "wall_clock_reduction_factor_shaped": (
                shaped["arms"]["serial"]["wall_clock_ms_median"]
                / max(shaped["arms"]["batched"]["wall_clock_ms_median"], 1e-9)
            ),
            "wall_clock_reduction_factor_shaped_is_derived": True,
            # The UNSHAPED arm is the one wall-clock number that is not determined
            # by the knob. It is also small in absolute terms (single-digit
            # milliseconds) and therefore noisy run to run, which is exactly why it
            # is reported as the honest FLOOR rather than as the headline.
            "wall_clock_reduction_factor_unshaped": (
                unshaped["arms"]["serial"]["wall_clock_ms_median"]
                / max(unshaped["arms"]["batched"]["wall_clock_ms_median"], 1e-9)
            ),
            "problems": problems,
        },
        problems,
    )


def human_lines(block: dict) -> list[str]:
    """The printed form. Numbers carry their arm and their condition."""
    lines = [
        "",
        "== closure discovery (task-91): one-at-a-time vs batched ==",
        f"  closure {block['config']['closure_paths']} paths, "
        f"{block['config']['peers']} peers, "
        f"{block['resolved_paths']} resolved",
    ]
    for condition in ("unshaped", "shaped"):
        arm = block[condition]
        label = (
            "in-process floor (0 ms RTT)"
            if condition == "unshaped"
            else f"emulated network ({arm['injected_rtt_ms']} ms RTT/round trip)"
        )
        lines += [
            f"  {label}:",
            f"    serial : {arm['round_trips']:>6} round trips "
            f"({arm['round_trips_per_substitution']:.2f}/substitution), "
            f"{arm['wall_clock_ms_median']:.1f} ms",
            f"    batched: {arm['round_trips_batched']:>6} round trips "
            f"({arm['round_trips_per_substitution_batched']:.2f}/substitution), "
            f"{arm['wall_clock_ms_median_batched']:.1f} ms",
        ]
    # ONE result, stated once. The previous wording put the round-trip factor and
    # the shaped wall-clock factor in one sentence joined by a semicolon, which
    # reads as two corroborating measurements. It is one: the shaped wall clock is
    # round_trips x the injected delay by construction of this harness, and a run
    # where it is not is marked INVALID above.
    lines += [
        f"  RESULT: {block['round_trip_reduction_factor']:.1f}x fewer round trips "
        f"(a count, not a timing)",
        f"  the shaped wall clock ({block['wall_clock_reduction_factor_shaped']:.1f}x) "
        f"is that same count times the {block['shaped']['injected_rtt_ms']} ms knob - "
        f"it confirms the emulation, it is NOT a second result",
        f"  honest floor, unshaped and unemulated: "
        f"{block['wall_clock_reduction_factor_unshaped']:.1f}x "
        f"(single-digit ms, noisy; the serial baseline is strictly sequential "
        f"across peers, i.e. the most naive one available)",
    ]
    if block["problems"]:
        lines.append("  PROBLEMS (the arm is INVALID):")
        lines += [f"    - {problem}" for problem in block["problems"]]
    return lines


# ---- self-test: every oracle proven by mutation -----------------------------


def _valid_run(rtt_ms: int, serial_rt: int = 1180, batched_rt: int = 8) -> dict:
    """A synthetic run shaped exactly like the instrument's real output."""
    serial_ms = serial_rt * rtt_ms * 1.05 if rtt_ms else 6.2
    batched_ms = batched_rt * rtt_ms * 1.05 if rtt_ms else 1.0
    return {
        "rule_version": DISCOVERY_RULE_VERSION,
        "config": {
            "closure_paths": 200,
            "peers": 8,
            "hit_rate": 0.6,
            "injected_rtt_ms": rtt_ms,
            "repeats": 1,
            "nar_bytes_uncompressed_nar": 102400,
        },
        "resolved_paths": 120,
        "arms": {
            "serial": {
                "round_trips": serial_rt,
                "keys_asked": 1180,
                "round_trips_per_substitution": serial_rt / 120,
                "wall_clock_ms_median": serial_ms,
            },
            "batched": {
                "round_trips": batched_rt,
                "keys_asked": 1180,
                "round_trips_per_substitution": batched_rt / 120,
                "wall_clock_ms_median": batched_ms,
            },
        },
        "round_trip_reduction_factor": serial_rt / batched_rt,
    }


def run_self_test() -> int:
    """Prove each oracle BITES by breaking a valid report in one place at a time."""
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, passed: bool, detail: str = "") -> None:
        checks.append((name, passed, detail))

    clean_unshaped = _valid_run(0)
    clean_shaped = _valid_run(50)

    check(
        "a valid unshaped run is clean",
        arm_violations(clean_unshaped, expect_shaped=False) == [],
        str(arm_violations(clean_unshaped, expect_shaped=False)),
    )
    check(
        "a valid shaped run is clean",
        arm_violations(clean_shaped, expect_shaped=True) == [],
        str(arm_violations(clean_shaped, expect_shaped=True)),
    )

    # MUTATION 1: the batched arm asked about fewer keys (the "win" is skipped
    # work, not a protocol improvement).
    mutant = _valid_run(0)
    mutant["arms"]["batched"]["keys_asked"] = 200
    problems = arm_violations(mutant, expect_shaped=False)
    check(
        "an arm that asked about fewer keys is REJECTED",
        any("different numbers of keys" in p for p in problems),
        str(problems),
    )

    # MUTATION 2: no win at all.
    mutant = _valid_run(0, serial_rt=8, batched_rt=8)
    problems = arm_violations(mutant, expect_shaped=False)
    check(
        "an equal-cost run is a NAMED failure, not a pass",
        any("NO WIN MEASURED" in p for p in problems),
        str(problems),
    )

    # MUTATION 3: the shaped run was not actually shaped (the half-armed shaper).
    mutant = _valid_run(50)
    mutant["config"]["injected_rtt_ms"] = 0
    problems = arm_violations(mutant, expect_shaped=True)
    check(
        "a shaped run with no injected RTT is REJECTED",
        any("not shaped" in p for p in problems),
        str(problems),
    )

    # MUTATION 4: the knob says 50 ms but the wall clock says otherwise - the
    # injection did not reach the transport.
    mutant = _valid_run(50)
    mutant["arms"]["serial"]["wall_clock_ms_median"] = 12.0
    problems = arm_violations(mutant, expect_shaped=True)
    check(
        "an unrecovered RTT is REJECTED (the shaper is asserted, not trusted)",
        any("NOT recovered" in p for p in problems),
        str(problems),
    )

    # MUTATION 5: a run that resolved nothing cannot support a per-substitution
    # number.
    mutant = _valid_run(0)
    mutant["resolved_paths"] = 0
    problems = arm_violations(mutant, expect_shaped=False)
    check(
        "a run that resolved nothing is REJECTED",
        any("resolved 0 paths" in p for p in problems),
        str(problems),
    )

    # MUTATION 6: a missing field must fail loudly rather than default to zero.
    mutant = _valid_run(0)
    del mutant["arms"]["batched"]["round_trips"]
    problems = arm_violations(mutant, expect_shaped=False)
    check(
        "a missing measurement is REJECTED, never defaulted",
        any("missing `arms.batched.round_trips`" in p for p in problems),
        str(problems),
    )

    # MUTATION 7: the instrument and this reader disagree about the rule version.
    mutant = _valid_run(0)
    mutant["rule_version"] = "something-else-v9"
    check(
        "a foreign rule_version is REJECTED",
        any("rule_version" in p for p in arm_violations(mutant, expect_shaped=False)),
    )

    # MUTATION 8: shaped and unshaped indistinguishable - the cross-run control.
    indistinguishable = _valid_run(50)
    indistinguishable["arms"]["serial"]["wall_clock_ms_median"] = 6.2
    indistinguishable["arms"]["batched"]["wall_clock_ms_median"] = 1.0
    problems = cross_run_violations(clean_unshaped, indistinguishable)
    check(
        "a shaped run indistinguishable from the control is REJECTED",
        any("not distinguishable" in p for p in problems),
        str(problems),
    )

    # MUTATION 9: the two runs measured different topologies.
    mutant = _valid_run(50)
    mutant["config"]["peers"] = 4
    problems = cross_run_violations(clean_unshaped, mutant)
    check(
        "runs that differ in more than the RTT are REJECTED",
        any("different `peers`" in p for p in problems),
        str(problems),
    )

    # And the assembled block carries its problems rather than hiding them.
    block, problems = build_block(clean_unshaped, clean_shaped)
    check("a clean pair assembles with no problems", problems == [], str(problems))
    check(
        "the block reports round trips for BOTH arms",
        block["unshaped"]["round_trips"] == 1180
        and block["unshaped"]["round_trips_batched"] == 8,
    )
    check(
        "the human lines name both arms and the condition",
        any("in-process floor" in line for line in human_lines(block))
        and any("emulated network" in line for line in human_lines(block)),
    )
    check(
        # AC#3 stated ONE measurement twice: the round-trip count and the shaped
        # wall clock were printed in one sentence joined by a semicolon, which
        # reads as two corroborating results. The shaped wall clock is
        # round_trips x the injected knob BY CONSTRUCTION of this harness (a run
        # where it is not is marked INVALID above), so the printer must say so and
        # must print the one wall-clock number that is NOT determined by the knob.
        "the shaped wall clock is printed as DERIVED, not as a second result",
        any("NOT a second result" in line for line in human_lines(block))
        and any("honest floor" in line for line in human_lines(block))
        and block["wall_clock_reduction_factor_shaped_is_derived"] is True,
    )
    check(
        "the unshaped floor is reported as its own factor, not left to a reader",
        # ~1180/8 would be the shaped answer; the unshaped one is far smaller,
        # because without an injected delay the round trips are nearly free.
        block["wall_clock_reduction_factor_unshaped"]
        < block["wall_clock_reduction_factor_shaped"] / 10,
        f"unshaped={block['wall_clock_reduction_factor_unshaped']:.2f} "
        f"shaped={block['wall_clock_reduction_factor_shaped']:.2f}",
    )
    broken_block, _ = build_block(clean_unshaped, _valid_run(0))
    check(
        "an invalid pair is printed as INVALID, not quietly summarised",
        any("INVALID" in line for line in human_lines(broken_block)),
    )

    print("discoveryaxis --self-test")
    failures = 0
    for name, passed, *detail in checks:
        status = "ok  " if passed else "FAIL"
        print(
            f"  {status} {name}" + (f" -- {detail[0]}" if not passed and detail else "")
        )
        failures += 0 if passed else 1
    print(f"discoveryaxis --self-test: {'ALL PASS' if not failures else 'FAILURES'}")
    return 0 if failures == 0 else 1


def main() -> int:
    """Run both instrument passes and print the arm. Non-zero if it is invalid."""
    if "--self-test" in sys.argv[1:]:
        return run_self_test()
    # Imported HERE, not at module scope: `profile_p2p` imports this module, and
    # the RTT constant has exactly one home (there, with its derivation from
    # task-35's real measurements). A deferred import keeps the single source of
    # truth without a cycle.
    from profile_p2p import WAN_RTT_MS

    unshaped = run_instrument(rtt_ms=0, repeats=UNSHAPED_REPEATS)
    shaped = run_instrument(rtt_ms=WAN_RTT_MS, repeats=SHAPED_REPEATS)
    block, problems = build_block(unshaped, shaped)
    print("\n".join(human_lines(block)))
    print(json.dumps(block, indent=2, sort_keys=True))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
