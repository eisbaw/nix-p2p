#!/usr/bin/env python3
"""J1 operator journey (task-6): substitute through the daemon, then lose it.

Runnable as `just journey`. This is NOT a unit test - it is a fresh operator's
narrated walk through the system end to end, reusing the task-5 Pod seam
(scripts/e2e_harness.py) as its driver rather than standing up a second harness.
It asserts the two things an operator actually cares about and files everything
else it trips over:

  AC#1 the daemon's log tells a comprehensible per-substitution story - one line
       per NAR served, carrying path, source, bytes and duration. Grep-asserted:
       a missing line is a nonzero exit, so the oracle BITES if the daemon ever
       goes quiet again. It WAS silent before task-6 added `log_substitution`
       to the daemon - that was this journey's headline finding, fixed inline.

  AC#2 with the daemon killed mid-journey, the next build still succeeds via the
       explicit direct fallback, and the fallback ACTUALLY served the bytes -
       proven by the testproxy's received-NAR counter, never by exit 0 alone.

Friction the operator hits is emitted as a FRICTION manifest at the end, each
line naming the backlog task that carries it (or 'none found'). Friction is
feature work, not a journey failure: the journey exits nonzero only when an
ORACLE fails (or when it registered no oracles at all - a vacuous green).
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

import e2e_harness as e2e
import fixturelib as fx

# The exact line `daemon/src/server.rs::log_substitution` emits per served NAR.
# Anchored on all four operator-facing facts so a regression that drops any one
# of them (path, source, bytes, duration) fails the grep rather than passing on
# a partial line.
SUBST_RE = re.compile(
    r"daemon: substituted path=(?P<path>\S+) source=(?P<source>\S+) "
    r"bytes=(?P<bytes>\d+) duration_ms=(?P<duration>\d+)"
)


@dataclass
class Journey:
    """Accumulates oracle results (which decide the exit code) and friction
    observations (which are filed as backlog tasks, never a failure)."""

    checks: list[tuple[bool, str, str]] = field(default_factory=list)
    # Friction the operator TRIPPED OVER this run (runtime-detected); kept
    # distinct from limitations we already KNOW and declare, so the manifest
    # does not present a standing caveat as a fresh discovery.
    friction: list[tuple[str, str]] = field(default_factory=list)
    declared: list[tuple[str, str]] = field(default_factory=list)

    def oracle(self, ok: bool, name: str, detail: str = "") -> bool:
        ok = bool(ok)
        self.checks.append((ok, name, detail))
        mark = "ok  " if ok else "FAIL"
        extra = f"  [{detail}]" if detail and not ok else ""
        print(f"  {mark} {name}{extra}")
        return ok

    def note_friction(self, task_id: str, description: str) -> None:
        self.friction.append((task_id, description))

    def note_declared_limit(self, task_id: str, description: str) -> None:
        self.declared.append((task_id, description))


def _step1_substitute(ctx, fixtures, journey, pod, targets, payloads) -> None:
    """The operator points nix at the daemon and runs a real substitution, then
    reads the daemon's own log to see whether it tells the story (AC#1)."""
    expected_source = f"http://127.0.0.1:{e2e.PROXY_PORT}"

    pod.proxy_reset()
    result = pod.client_run(targets, ctx.substituter_daemon_only(), fixtures.public_key)
    journey.oracle(
        result.exit_code == 0,
        "step1: nix build substitutes through the daemon",
        result.stderr[-400:],
    )

    daemon_log = pod.logs("daemon")
    subs = [match.groupdict() for match in SUBST_RE.finditer(daemon_log)]
    unique_paths = {sub["path"] for sub in subs}

    # The biting grep: zero substitution lines is a nonzero exit. Before task-6
    # the daemon printed only its startup banner, so this oracle would have
    # failed - which is exactly why the log line was added.
    journey.oracle(
        len(subs) >= 1,
        "AC#1: the daemon log carries substitution events (it is not silent)",
        f"found {len(subs)} lines; daemon tail: {daemon_log[-300:]!r}",
    )
    # Both total AND unique equal the payload count: the run is deterministic
    # (max-substitution-jobs=1, fresh store, no faults), so exactly one line per
    # payload - asserting total too makes double-logging a payload bite, which a
    # unique-only check would silently tolerate.
    journey.oracle(
        len(subs) == len(payloads) == len(unique_paths),
        "AC#1: exactly one substitution line per payload (path, source, bytes, duration)",
        f"lines={len(subs)} unique={len(unique_paths)} want={len(payloads)}",
    )
    journey.oracle(
        bool(subs) and all(int(sub["bytes"]) > 0 for sub in subs),
        "AC#1: every substitution line reports a nonzero byte count",
        f"bytes={[sub['bytes'] for sub in subs]}",
    )
    journey.oracle(
        bool(subs) and all(sub["source"] == expected_source for sub in subs),
        "AC#1: source= names the daemon's real upstream",
        f"sources={sorted({sub['source'] for sub in subs})} want={expected_source}",
    )

    # -- friction the operator meets on the DEFAULT path --
    # Runtime probe: a default daemon wires no persistent narinfo cache, so its
    # log never mentions one. If task-29 later default-wires it, this line
    # appears and the friction auto-clears - a friction detector that bites.
    if "narinfo disk cache at" not in daemon_log:
        journey.note_friction(
            "TASK-29",
            "daemon default config wires no persistent narinfo disk cache "
            "(no 'narinfo disk cache at' line); a restart re-fetches every narinfo",
        )
    # Standing limitation of the log line this journey added (see server.rs) -
    # declared, not tripped over: bytes=Content-Length (unknown when absent),
    # duration=time-to-headers. Full-drain accounting is filed as TASK-31.
    journey.note_declared_limit(
        "TASK-31",
        "substitution log's bytes/duration are Content-Length + time-to-headers, "
        "not a full-drain count (a truncated transfer logs its advertised length)",
    )


def _step2_lose_the_daemon(ctx, fixtures, journey, pod, targets, payloads) -> None:
    """The operator loses the daemon mid-flight; the next build must stay green
    and the direct fallback must be the thing that served the bytes (AC#2)."""
    pod.kill("daemon")
    journey.oracle(not e2e.daemon_reachable(), "step2: the daemon is really gone", "")

    pod.proxy_reset()
    fallback = pod.client_run(
        targets, ctx.substituter_daemon_and_fallback(), fixtures.public_key
    )
    journey.oracle(
        fallback.exit_code == 0,
        "AC#2: the build still succeeds via the direct fallback",
        fallback.stderr[-500:],
    )
    received_nar = pod.proxy_stats()["received"].get("nar", 0)
    journey.oracle(
        received_nar == len(payloads),
        "AC#2: the fallback ACTUALLY served the NAR bytes (request counts, not exit 0)",
        f"received nar={received_nar} want={len(payloads)}",
    )
    for attr in payloads:
        got = fallback.narhash(fixtures.store_path(attr))
        journey.oracle(
            got == fixtures.nar_hash(attr),
            f"AC#2 byte oracle: {attr} NarHash matches upstream via the fallback",
            f"got={got}",
        )


def _act(ctx, fixtures, journey) -> None:
    payloads = e2e.ALL_ATTRS
    targets = [fixtures.store_path(attr) for attr in payloads]

    print("\n== J1 step 1: operator starts the chain and substitutes via the daemon ==")
    with e2e.Pod(
        ctx, "j1", fixtures.cache, with_daemon=True, expect=journey.oracle
    ) as pod:
        _step1_substitute(ctx, fixtures, journey, pod, targets, payloads)
        print("\n== J1 step 2: operator loses the daemon; the build must stay green ==")
        _step2_lose_the_daemon(ctx, fixtures, journey, pod, targets, payloads)


def _report(journey: Journey) -> int:
    print("\n== J1 summary ==")
    passed = sum(1 for ok, _, _ in journey.checks if ok)
    total = len(journey.checks)
    for ok, name, detail in journey.checks:
        if not ok:
            print(f"  FAIL {name}  [{detail}]")
    print(f"  oracles: {passed}/{total} passed")

    print("\n== FRICTION (detected this run) ==")
    if journey.friction:
        for task_id, description in journey.friction:
            print(f"  FRICTION filed: {task_id} - {description}")
    else:
        print("  none found")

    if journey.declared:
        print("\n== KNOWN LIMITATIONS (declared, filed) ==")
        for task_id, description in journey.declared:
            print(f"  LIMITATION filed: {task_id} - {description}")

    # A journey with zero oracles proved nothing - fail closed, same discipline
    # as the e2e harness's empty-scenario guard.
    all_ok = total > 0 and passed == total
    print(f"\njourney: {'ALL ORACLES PASSED' if all_ok else 'ORACLE FAILURES PRESENT'}")
    return 0 if all_ok else 1


def run_journey() -> int:
    out = fx.repo_root() / "fixtures" / "out"
    e2e.preflight_gate()
    fixtures = e2e.resolve_fixtures(out.resolve())
    image = e2e.load_image()
    e2e.cleanup_pods()  # clear any stale pods from a crashed prior run

    scratch = Path(os.environ.get("TMPDIR", "/tmp")) / f"nix-p2p-journey-{os.getpid()}"
    scratch.mkdir(parents=True, exist_ok=True)
    ctx = e2e.Ctx(podman=e2e.podman(), image=image, fixtures=fixtures, scratch=scratch)

    journey = Journey()
    try:
        _act(ctx, fixtures, journey)
    finally:
        e2e.cleanup_pods()  # never leak a pod out of the journey
        shutil.rmtree(scratch, ignore_errors=True)

    return _report(journey)


if __name__ == "__main__":
    try:
        sys.exit(run_journey())
    except e2e.HarnessError as err:
        # TASK-60: die() (via preflight_gate, load_image, podman, Pod, ...) raises
        # HarnessError instead of exiting. Translate it back to the historical
        # `e2e: FATAL` line + exit code here.
        print(f"e2e: FATAL - {err}", file=sys.stderr)
        sys.exit(err.code)
    except KeyboardInterrupt:
        e2e.cleanup_pods("(interrupted)")
        sys.exit(130)
