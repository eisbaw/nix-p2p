#!/usr/bin/env python3
"""Measure the flake RATE of a test command under a DEFINED, reproducible load.

WHY THIS EXISTS (task-109). `just test` was found to fail intermittently under
machine load, which means every "gate green" this project has certified was one
green roll of a non-deterministic gate. A gate whose failure rate is unknown
cannot certify anything, so the rate has to be a measured number with a stated
load and a stated N - not an impression formed from the last run someone saw.

THE LOAD IS PART OF THE MEASUREMENT. A flake rate quoted without the load it was
measured under is meaningless, so `--load-workers` is recorded in the report and
the workers are plain CPU burners (no memory pressure: on a host that is already
swapping, adding memory pressure measures the host's OOM policy, not the suite).

EXIT-CODE DISCIPLINE - the reason this is a script and not a shell loop. cargo
returns 101 BOTH for "a test failed" and for "the crate did not compile", and a
harness that reads 101 as a test result will silently report compile errors as
flakes (and, worse, a reviewer's harness once read 127 as GREEN). So every run is
classified into exactly one of:

    PASS         exit 0
    TEST_FAILED  exit 101 AND the output contains a libtest failure report
    BUILD_FAILED exit 101 AND the output contains a rustc/cargo compile error
    HARNESS      any other exit code, or 101 with neither marker

BUILD_FAILED and HARNESS abort the measurement immediately: they are not data
points about flakiness, and averaging them into a rate would be a lie.

Usage:
    python3 scripts/flake_rate.py --runs 20 --load-workers 14 --out /tmp/before
    python3 scripts/flake_rate.py --self-test
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# A run that neither passed nor produced a recognised failure report is a
# harness defect, never a flake data point.
PASS = "PASS"
TEST_FAILED = "TEST_FAILED"
BUILD_FAILED = "BUILD_FAILED"
HARNESS = "HARNESS"

# `error[E0432]: unresolved import` / `error: could not compile ...`. Both are
# emitted by rustc/cargo on a build failure, and NEITHER is emitted by libtest
# for a failing test - which is what makes them a sound discriminator.
BUILD_MARKERS = (
    re.compile(r"^error\[E\d+\]:", re.MULTILINE),
    re.compile(r"^error: could not compile ", re.MULTILINE),
    re.compile(r"^error: expected ", re.MULTILINE),
)
# libtest's own failure report. `test result: FAILED` is printed by every
# harness binary that had a failing test; the `error: test failed` line is
# cargo's summary of the same event.
TEST_MARKERS = (
    re.compile(r"^test result: FAILED", re.MULTILINE),
    re.compile(r"^error: test failed, to rerun pass ", re.MULTILINE),
)

# "---- some::test_name stdout ----" and the trailing "    some::test_name"
# entries of libtest's `failures:` block. Both name the test; the stdout header
# is the one that also appears when the panic message is captured.
FAILED_TEST_RE = re.compile(r"^---- (\S+) stdout ----", re.MULTILINE)
# `error: test failed, to rerun pass `-p daemon --test fault_loop``
FAILED_TARGET_RE = re.compile(
    r"^error: test failed, to rerun pass `([^`]+)`", re.MULTILINE
)


@dataclass
class RunResult:
    index: int
    verdict: str
    exit_code: int
    seconds: float
    failed_tests: list[str] = field(default_factory=list)
    failed_targets: list[str] = field(default_factory=list)
    log_path: str = ""


def classify(exit_code: int, output: str) -> str:
    """Map (exit code, output) to exactly one verdict.

    A build failure is checked BEFORE a test failure: a run that both failed to
    compile one target and ran another's tests is a build failure, because the
    suite did not actually execute.
    """
    if exit_code == 0:
        return PASS
    if any(marker.search(output) for marker in BUILD_MARKERS):
        return BUILD_FAILED
    if exit_code == 101 and any(marker.search(output) for marker in TEST_MARKERS):
        return TEST_FAILED
    return HARNESS


def failed_names(output: str) -> tuple[list[str], list[str]]:
    """Names of the failing tests and the cargo targets they live in."""
    tests = sorted(set(FAILED_TEST_RE.findall(output)))
    targets = sorted(set(FAILED_TARGET_RE.findall(output)))
    return tests, targets


def _burn(stop_after: float) -> None:
    """A CPU burner. Spins until `stop_after` (a monotonic deadline)."""
    x = 0
    while time.monotonic() < stop_after:
        for _ in range(100_000):
            x = (x * 1103515245 + 12345) & 0xFFFFFFFF


class CpuLoad:
    """`workers` processes saturating a core each, for the life of the context.

    Deliberately crude: the point is a REPRODUCIBLE amount of CPU contention
    that any reader can recreate, not a realistic workload.
    """

    def __init__(self, workers: int, max_seconds: float) -> None:
        self.workers = workers
        self.max_seconds = max_seconds
        self.procs: list[multiprocessing.Process] = []

    def __enter__(self) -> CpuLoad:
        deadline = time.monotonic() + self.max_seconds
        for _ in range(self.workers):
            proc = multiprocessing.Process(target=_burn, args=(deadline,), daemon=True)
            proc.start()
            self.procs.append(proc)
        return self

    def __exit__(self, *_exc: object) -> None:
        for proc in self.procs:
            proc.terminate()
        for proc in self.procs:
            proc.join(timeout=5)


def run_once(index: int, cmd: list[str], out_dir: Path, cwd: Path) -> RunResult:
    log_path = out_dir / f"run-{index:03d}.log"
    started = time.monotonic()
    completed = subprocess.run(  # noqa: S603 - cmd is operator-supplied by design
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    seconds = time.monotonic() - started
    output = completed.stdout.decode("utf-8", errors="replace")
    log_path.write_text(output, encoding="utf-8")
    verdict = classify(completed.returncode, output)
    tests, targets = failed_names(output)
    return RunResult(
        index=index,
        verdict=verdict,
        exit_code=completed.returncode,
        seconds=seconds,
        failed_tests=tests,
        failed_targets=targets,
        log_path=str(log_path),
    )


def measure(runs: int, cmd: list[str], workers: int, out_dir: Path, cwd: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[RunResult] = []
    # Budget the burners generously; they are terminated on exit either way.
    with CpuLoad(workers, max_seconds=runs * 900.0):
        for index in range(1, runs + 1):
            result = run_once(index, cmd, out_dir, cwd)
            results.append(result)
            print(
                f"run {index:3d}/{runs}  {result.verdict:12s} exit={result.exit_code:3d} "
                f"{result.seconds:6.1f}s  {','.join(result.failed_tests) or '-'}",
                flush=True,
            )
            if result.verdict in (BUILD_FAILED, HARNESS):
                print(
                    f"ABORT: run {index} is {result.verdict} (exit {result.exit_code}). "
                    f"That is not a flake data point - see {result.log_path}",
                    file=sys.stderr,
                    flush=True,
                )
                break

    failures = [r for r in results if r.verdict == TEST_FAILED]
    per_test: dict[str, int] = {}
    for result in failures:
        for name in result.failed_tests or result.failed_targets or ["<unnamed>"]:
            per_test[name] = per_test.get(name, 0) + 1
    report = {
        "command": " ".join(shlex.quote(part) for part in cmd),
        "load_workers": workers,
        "runs_requested": runs,
        "runs_completed": len(results),
        "passed": sum(1 for r in results if r.verdict == PASS),
        "test_failed": len(failures),
        "build_failed": sum(1 for r in results if r.verdict == BUILD_FAILED),
        "harness_error": sum(1 for r in results if r.verdict == HARNESS),
        "exit_codes": sorted({r.exit_code for r in results}),
        "failure_rate": (len(failures) / len(results)) if results else None,
        "per_test_failures": per_test,
        "seconds_median": sorted(r.seconds for r in results)[len(results) // 2]
        if results
        else None,
        "runs": [
            {
                "index": r.index,
                "verdict": r.verdict,
                "exit_code": r.exit_code,
                "seconds": round(r.seconds, 1),
                "failed_tests": r.failed_tests,
                "failed_targets": r.failed_targets,
            }
            for r in results
        ],
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def self_test() -> None:
    """Prove the classifier BITES - the whole point of this script is that it
    must never call a compile failure or a missing binary a test result."""
    test_output = "running 3 tests\ntest result: FAILED. 2 passed; 1 failed;\n"
    build_output = (
        "error[E0433]: failed to resolve\nerror: could not compile `daemon`\n"
    )

    assert classify(0, "test result: ok") == PASS
    assert classify(101, test_output) == TEST_FAILED, (
        "a real libtest failure must count"
    )
    assert classify(101, build_output) == BUILD_FAILED, "a compile error is NOT a flake"
    # THE 127 TRAP: a missing command exits 127. It must never be PASS and never
    # be a test result.
    assert classify(127, "bash: cargo: command not found") == HARNESS
    assert classify(1, "some unrelated failure") == HARNESS
    # 101 with no recognisable report is a harness defect, not a silent green.
    assert classify(101, "killed") == HARNESS
    # And a run that both failed to compile and printed a test result is a BUILD
    # failure: the suite did not execute.
    assert classify(101, test_output + build_output) == BUILD_FAILED

    names, targets = failed_names(
        "---- fault_mode_loop stdout ----\npanicked\n"
        "error: test failed, to rerun pass `-p daemon --test fault_loop`\n"
    )
    assert names == ["fault_mode_loop"], names
    assert targets == ["-p daemon --test fault_loop"], targets
    print(
        "flake_rate.py self-test: ok (classifier bites on 127, on 1, and on compile errors)"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument(
        "--load-workers",
        type=int,
        default=os.cpu_count() or 1,
        help="CPU burner processes running for the whole measurement (0 = unloaded)",
    )
    parser.add_argument("--out", type=Path, default=Path("flake-rate-out"))
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="command to run (after --), default: cargo test --locked --workspace",
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    cmd = [part for part in args.cmd if part != "--"] or [
        "cargo",
        "test",
        "--locked",
        "--workspace",
    ]
    report = measure(args.runs, cmd, args.load_workers, args.out, args.cwd)
    print(json.dumps({k: v for k, v in report.items() if k != "runs"}, indent=2))
    # A non-zero exit when anything other than a clean pass happened, so the
    # harness cannot be mistaken for green.
    return (
        0
        if report["test_failed"]
        == report["build_failed"]
        == report["harness_error"]
        == 0
        else 1
    )


if __name__ == "__main__":
    sys.exit(main())
