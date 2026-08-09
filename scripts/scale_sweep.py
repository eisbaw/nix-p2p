#!/usr/bin/env python3
"""`just scale-sweep` (task-18): the S5 scale sweep + regression-fit instrument.

Runs the real system at N over each feasible axis, samples per-node RSS / file
descriptors / request latency, hands the (n, y) series to `scripts/scalefit.py`,
and emits a machine-readable report whose MEASURED and MODELLED numbers are
structurally separate. The honesty rules of TESTING.md S5 are not prose here:
`scalefit.sweep_report_violations()` is called on the assembled report and a
violation FAILS the run.

WHICH COMPONENT ACTUALLY SCALES (the design point the task names). A daemon is
ONE process; it does not fork per client. The heavy, host-bound part is the
CLIENT: each concurrent client is a fresh `podman run` of real nix with its own
store. So:
  * the law worth extrapolating to 1000 peers is the DAEMON's per-node RSS/fd
    growth against concurrent load - that is what a peer would pay;
  * the host ceiling (~1..30 nodes) is imposed by the clients, not the daemon;
  * the sweep therefore drives many clients at ONE daemon and fits the daemon's
    resources, rather than pretending to run 30 daemons.
task-42 will point the SAME fitter at real peer count, where each peer IS a
daemon process; `scalefit` is deliberately free of any harness import so that
reuse costs nothing.

AXES (TESTING.md S5 + the task's implementation notes):
  clients  - N concurrent nix clients against one daemon (the concurrency law)
  chain    - proxy-chain depth 1..5 (`daemon_chain=N`; the topology law)
  knobs    - client `max-substitution-jobs` / `http-connections` in {1,16,128}
             (TESTING.md client-knobs rule). REPORTED PER KNOB VALUE, NOT
             FITTED: three points is below scalefit.MIN_POINTS, and a knob is a
             scenario parameter, not a scale axis. Read the axis's
             `workload_ceiling` note before believing any knob difference.

WHAT IS MEASURED, precisely (the counting rule for this instrument):
  * RSS HIGH-WATER: `VmHWM` from /proc/<host pid>/status - the kernel's peak
    RSS for that process. A point sample taken between peaks understates the
    resource law, so the high-water figure is what gets FITTED; `VmRSS` point
    samples are reported alongside so the two can be compared.
  * FDS: the entry count of /proc/<host pid>/fd, sampled on the same tick; the
    reported figure is the MAXIMUM observed, for the same reason.
  * LATENCY: the in-container `nix-store --realise` duration (REALISE_NS),
    NOT the host-side `podman run` wall clock - the latter includes container
    create/start/teardown, which grows with concurrency and would have the
    fitter recover podman's scaling law instead of the product's. The host-side
    number is reported beside it, never fitted.
  * BYTES, when reported, are COMPRESSED ON-WIRE bytes (file_size). NarSize
    (uncompressed, signed) is a different unit and is never mixed in.

REPLICATES. Each sweep point is run `--repeats` times (default 3) and the
replicates are handed to the fitter as SEPARATE observations at the same n,
never averaged: three consecutive single-draw sweeps selected O(log n),
O(log n) not-identifiable and O(n) for the same metric, and a class that changes
between runs is not a law. Keeping the replicates lets the residual variance -
and therefore every interval - absorb run-to-run noise instead of hiding it.

FAIL-CLOSED. A node whose /proc could not be read, or a client that exited
nonzero, INVALIDATES that sweep point: it is excluded with a logged reason and
never recorded as 0. An axis left with fewer than `scalefit.MIN_POINTS` DISTINCT
valid n is reported as unfitted with the reason, never fitted on what survived.

`--self-test` runs the pure logic (proc parsing, point validity, report
assembly, the red-flag wiring) with NO containers, so `just test` covers the
honesty machinery on every cycle.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import e2e_harness as e2e
import fixturelib as fx
import scalefit

# `percentile` is the S3/S4 instrument's percentile, imported rather than
# re-implemented: two percentile functions in one repo is two definitions of
# p95, and the first divergence would be invisible.
from measure import percentile

# ---- frozen constants (this instrument's counting rule) ---------------------

REPORT_VERSION = 1
SWEEP_RULE_VERSION = "scale-sweep-v1"

# Resource sampling cadence. Fast enough that a short-lived allocation peak is
# likely to be seen in VmRSS, cheap enough (two small /proc reads per node) that
# the sampler is not itself part of the load. VmHWM does not need the cadence -
# the kernel maintains it - but the point samples do.
POLL_INTERVAL_S = 0.2

# Default sweep points. Six distinct N (>= scalefit.MIN_POINTS with one point of
# slack for an invalid run) and a modest top end: the host is at 95% disk and
# every client is a container running real nix. Raise with --clients on a bigger
# host; do NOT silently shrink below 5 valid points, the fitter refuses to fit.
DEFAULT_CLIENT_COUNTS = (1, 2, 4, 6, 8, 12)
# Chain depth: 1..5 is exactly TESTING.md S5's range and exactly MIN_POINTS.
DEFAULT_CHAIN_DEPTHS = (1, 2, 3, 4, 5)
# TESTING.md client-knobs rule: {1, 16 (nix default), 128 (documented power-user)}.
DEFAULT_KNOB_VALUES = (1, 16, 128)
# Concurrent clients used for the knob comparison arm (enough to make the knob
# observable at all, small enough to stay cheap).
KNOB_ARM_CLIENTS = 4

# Small fixture attrs only. `big` is 110 MiB and every concurrent client
# realises its own copy: at 12 clients that is 1.3 GiB of container-layer churn
# per sweep point on a host with 48 GiB free. Bounding the sweep's footprint is
# TASK-54's subject; this constant is where the bound lives.
SWEEP_ATTRS = ("lib", "app", "zstd")

# Refuse to start a container sweep below this much free disk. TASK-54 tracks
# bounding the footprint properly; this is the guard that keeps a sweep from
# being the thing that fills the disk.
MIN_FREE_DISK_BYTES = 8 * 1024**3

# Replicates per sweep point. NOT cosmetic: with one observation per N the
# daemon's peak RSS is a single noisy draw (allocator behaviour, chunking), and
# three consecutive full sweeps selected O(log n), O(log n) NOT-identifiable and
# O(n) for the SAME metric. A class that changes between runs is not a law. The
# replicates are fed to the fitter as SEPARATE observations at the same n rather
# than averaged, so the residual variance - and therefore every interval -
# absorbs run-to-run noise instead of hiding it behind a mean.
DEFAULT_REPEATS = 3

# Concurrency barrier budget: how long to allow for every client container of
# one sweep point to reach the shared realise instant. Container start costs a
# fraction of a second each, so the allowance grows with N. The barrier is
# JITTER insurance only - a mutation run with it disabled still saw full overlap
# at N=6, because the launches are asynchronous - and a missed barrier is not
# silently harmful: the MEASURED overlap invalidates the point rather than
# quietly mislabelling it. The slack is therefore generous on purpose.
BARRIER_BASE_S = 3.0
BARRIER_PER_CLIENT_S = 0.5

# Client wall-clock ceiling. Past this a client is treated as failed rather than
# waited on forever; the daemon's own safety envelope (transport_iroh.rs:
# DIAL 10s / BODY_IDLE 10s / FETCH 60s) is far below it, so hitting this is a
# harness problem, not a product timeout.
CLIENT_TIMEOUT_S = 600.0


# ---- pure: /proc parsing ----------------------------------------------------


class SampleError(RuntimeError):
    """A resource sample that could not be taken. Raised, never returned as 0 -
    'unknown' reading as 'zero' is how a resource law gets understated."""


def parse_status_kb(status_text: str, key: str) -> int:
    """Extract one `VmXxx:  N kB` field from /proc/<pid>/status, in kB.

    FAIL-CLOSED on a missing or unparsable field: a kernel that stopped
    reporting VmHWM must break the sweep loudly, not contribute a silent 0 that
    flattens the fitted law into a reassuring O(1).
    """
    for line in status_text.splitlines():
        if not line.startswith(key + ":"):
            continue
        parts = line.split()
        if len(parts) < 3 or parts[-1] != "kB":
            raise SampleError(f"/proc status line for {key} is not 'N kB': {line!r}")
        try:
            return int(parts[-2])
        except ValueError:
            raise SampleError(
                f"/proc status {key} is not an integer: {line!r}"
            ) from None
    raise SampleError(f"/proc status has no {key} field (unknown is not 0)")


@dataclass
class NodeSample:
    """One tick of one node's resources. `at` is monotonic seconds since start."""

    role: str
    at: float
    rss_hwm_bytes: int
    rss_point_bytes: int
    fd_count: int


def read_node(role: str, pid: int, at: float) -> NodeSample:
    """Read one node's resources HOST-SIDE from /proc/<pid>.

    Host-side on purpose (the earlier in-container `find` oracle that returned
    rc=127 and passed unconditionally is the cautionary tale): rootless podman
    runs the container init as our own uid, so /proc/<pid>/status and
    /proc/<pid>/fd are directly readable with no binary inside the image.

    LIMITATION, stated: this observes the container's PID 1 only. The daemon and
    the testproxy each fork nothing, so PID 1 is the whole process - but a
    future component that spawns children would be under-counted here, and the
    fix is cgroup accounting, not a wider /proc walk.
    """
    try:
        status = Path(f"/proc/{pid}/status").read_text()
    except OSError as error:
        raise SampleError(f"{role}: cannot read /proc/{pid}/status: {error}") from None
    try:
        fd_count = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError as error:
        raise SampleError(f"{role}: cannot list /proc/{pid}/fd: {error}") from None
    return NodeSample(
        role=role,
        at=at,
        rss_hwm_bytes=parse_status_kb(status, "VmHWM") * 1024,
        rss_point_bytes=parse_status_kb(status, "VmRSS") * 1024,
        fd_count=fd_count,
    )


# ---- pure: aggregation + sweep points ---------------------------------------


@dataclass
class SweepPoint:
    """One (n, measurements) point on one axis. `valid` is fail-closed."""

    n: int
    valid: bool
    reason: str = ""
    metrics: dict = field(default_factory=dict)
    detail: dict = field(default_factory=dict)


@dataclass
class Axis:
    """One swept axis: what varied, what came back, and how it must be read."""

    name: str
    variable: str
    description: str
    points: list[SweepPoint] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    fitted: bool = True


def aggregate_samples(samples: list[NodeSample], daemon_roles: list[str]) -> dict:
    """Per-role and cross-daemon aggregates from a sampler's tick stream.

    HIGH-WATER vs POINT is kept explicit everywhere: `*_hwm_*` is the kernel's
    peak (VmHWM, monotone), `*_point_*` is the largest instantaneous VmRSS the
    sampler happened to catch. They are reported side by side precisely because
    the gap between them is the measurement error a point-sampling harness
    would have hidden.
    """
    by_role: dict[str, list[NodeSample]] = {}
    for sample in samples:
        by_role.setdefault(sample.role, []).append(sample)

    per_role = {}
    for role, rows in sorted(by_role.items()):
        per_role[role] = {
            "ticks": len(rows),
            "rss_hwm_bytes": max(r.rss_hwm_bytes for r in rows),
            "rss_point_max_bytes": max(r.rss_point_bytes for r in rows),
            "rss_point_last_bytes": rows[-1].rss_point_bytes,
            "fd_max": max(r.fd_count for r in rows),
            "fd_last": rows[-1].fd_count,
        }

    present = [r for r in daemon_roles if r in per_role]
    if not present:
        raise SampleError(
            f"no samples for any daemon role {daemon_roles} (sampler saw "
            f"{sorted(per_role)}) - nothing was observed, so nothing is proven"
        )
    return {
        "per_role": per_role,
        # Per-NODE peak: the figure a single peer would pay. This is the one the
        # 1000-peer extrapolation is about.
        "daemon_rss_hwm_bytes": max(per_role[r]["rss_hwm_bytes"] for r in present),
        "daemon_rss_point_max_bytes": max(
            per_role[r]["rss_point_max_bytes"] for r in present
        ),
        "daemon_fd_max": max(per_role[r]["fd_max"] for r in present),
        # Whole-topology total: what the HOST pays for the chain, which is a
        # different question and is fitted separately on the chain axis.
        "chain_total_rss_hwm_bytes": sum(per_role[r]["rss_hwm_bytes"] for r in present),
        "daemon_roles_sampled": present,
    }


def latency_block(realise_s: list[float], wall_s: list[float]) -> dict:
    """Latency summary. `realise_*` is the in-container measurement that gets
    FITTED; `container_wall_*` includes podman create/start/teardown and is
    reported for contrast only (see the module docstring)."""
    return {
        "n_clients": len(realise_s),
        "realise_p50_s": percentile(realise_s, 50),
        "realise_p95_s": percentile(realise_s, 95),
        "realise_max_s": max(realise_s) if realise_s else None,
        "realise_mean_s": statistics.fmean(realise_s) if realise_s else None,
        "realise_samples_s": realise_s,
        "container_wall_p95_s": percentile(wall_s, 95),
        "container_wall_samples_s": wall_s,
    }


# ---- pure: fitting + report assembly ----------------------------------------

# (metric key in point.metrics, unit, human description) per axis.
CLIENT_AXIS_METRICS = (
    ("daemon_rss_hwm_bytes", "bytes", "daemon peak RSS (VmHWM) vs concurrent clients"),
    ("daemon_fd_max", "descriptors", "daemon peak open fds vs concurrent clients"),
    ("realise_p95_s", "seconds", "client p95 realise latency vs concurrent clients"),
)
CHAIN_AXIS_METRICS = (
    ("daemon_rss_hwm_bytes", "bytes", "worst per-hop peak RSS (VmHWM) vs chain depth"),
    ("chain_total_rss_hwm_bytes", "bytes", "whole-chain peak RSS total vs chain depth"),
    ("daemon_fd_max", "descriptors", "worst per-hop peak open fds vs chain depth"),
    ("realise_p95_s", "seconds", "client p95 realise latency vs chain depth"),
)


def fit_axis(axis: Axis, metrics, targets) -> tuple[dict, list[str]]:
    """Fit each metric of one axis. Returns (fits, problems).

    A metric that cannot be honestly fitted (too few valid points, a missing
    sample) produces a PROBLEM string and NO fit - never a fit on whatever
    survived, which is how a sweep quietly becomes a sweep of its own failures.
    """
    fits: dict = {}
    problems: list[str] = []
    valid = [p for p in axis.points if p.valid]
    for key, unit, description in metrics:
        xs = [p.n for p in valid if key in p.metrics and p.metrics[key] is not None]
        ys = [
            p.metrics[key]
            for p in valid
            if key in p.metrics and p.metrics[key] is not None
        ]
        fit_id = f"{axis.name}.{key}"
        try:
            fits[fit_id] = scalefit.fit_scaling(
                xs, ys, metric=description, unit=unit, targets=targets
            )
            fits[fit_id]["axis"] = axis.name
            fits[fit_id]["axis_variable"] = axis.variable
        except scalefit.FitError as error:
            problems.append(f"{fit_id}: NOT FITTED - {error}")
    return fits, problems


def build_report(axes: list[Axis], provenance: dict, config: dict, targets) -> dict:
    """Assemble the report. PURE: takes collected measurements, touches nothing.

    The MEASURED / MODELS split is structural, not stylistic. Nothing under
    `measured` carries a model output and nothing under `models` is a
    measurement; `scalefit.sweep_report_violations` enforces exactly that, plus
    the red-flag coverage and the resource-laws-only caveat, and this function's
    own verdict goes red when it returns anything.
    """
    metrics_by_axis = {
        "clients": CLIENT_AXIS_METRICS,
        "chain": CHAIN_AXIS_METRICS,
    }
    models: dict = {}
    problems: list[str] = []
    measured: dict = {}
    axis_status: list[dict] = []

    for axis in axes:
        measured[axis.name] = {
            "variable": axis.variable,
            "description": axis.description,
            "fitted": axis.fitted,
            "notes": axis.notes,
            # Replicates are separate OBSERVATIONS at the same n, never averaged
            # (see DEFAULT_REPEATS): the fitter needs the spread to size its
            # intervals honestly, and a reader needs to see how many draws each
            # n actually got.
            "distinct_n": sorted({p.n for p in axis.points}),
            "valid_observations_per_n": {
                str(n): sum(1 for p in axis.points if p.n == n and p.valid)
                for n in sorted({p.n for p in axis.points})
            },
            "points": [
                {
                    "n": p.n,
                    "valid": p.valid,
                    "reason": p.reason,
                    "metrics": p.metrics,
                    "detail": p.detail,
                }
                for p in axis.points
            ],
            "invalid_points": [
                {"n": p.n, "reason": p.reason} for p in axis.points if not p.valid
            ],
        }
        valid_points = sum(1 for p in axis.points if p.valid)
        if not axis.fitted:
            # An UNFITTED arm (the knobs comparison) has no fit to fail, so its
            # only honest health signal is point validity - which is where the
            # knob-landed precondition lands. Without this, an arm whose knob
            # never took would ride along inside a green sweep.
            axis_status.append(
                {
                    "axis": axis.name,
                    "fitted": False,
                    "valid_observations": valid_points,
                    "total_observations": len(axis.points),
                    "distinct_valid_n": len({p.n for p in axis.points if p.valid}),
                    "usable": valid_points == len(axis.points) and valid_points > 0,
                    "why": "reported per value; usable iff every point is valid",
                }
            )
            continue
        axis_fits, axis_problems = fit_axis(
            axis, metrics_by_axis.get(axis.name, ()), targets
        )
        models.update(axis_fits)
        problems += axis_problems
        axis_status.append(
            {
                "axis": axis.name,
                "fitted": True,
                "valid_observations": valid_points,
                "total_observations": len(axis.points),
                "distinct_valid_n": len({p.n for p in axis.points if p.valid}),
                "usable": axis_problems == [],
                "why": (
                    "usable iff every metric fitted; a point lost to a flaky "
                    "client is tolerated as long as >= scalefit.MIN_POINTS remain"
                ),
            }
        )

    red_flags = scalefit.red_flags_for(models)
    report = {
        "report_version": REPORT_VERSION,
        "sweep_rule_version": SWEEP_RULE_VERSION,
        "fitter_version": scalefit.FITTER_VERSION,
        "counting_rule": {
            "rss": (
                "VmHWM (kernel peak RSS) is FITTED; VmRSS point samples reported "
                "beside it. A point sample between peaks understates the law."
            ),
            "fds": "max entry count of /proc/<pid>/fd over the sampled ticks",
            "latency": (
                "in-container `nix-store --realise` duration (REALISE_NS). The "
                "host-side podman wall clock is reported but NEVER fitted: it "
                "carries container create/start/teardown, which itself scales."
            ),
            "bytes_unit": (
                "compressed on-wire bytes (file_size) wherever bytes appear; "
                "NarSize (uncompressed, signed) is a different unit and is never "
                "mixed in"
            ),
            "observation_point": (
                "host-side /proc of the container init pid (rootless podman runs "
                "it as our uid); container PID 1 only - a component that forked "
                "children would be under-counted"
            ),
            "validity": (
                "a point with a failed client or an unreadable /proc is INVALID: "
                "excluded with a reason, never recorded as 0"
            ),
            "concurrency": (
                "N concurrent clients start at a shared host-clock barrier, and "
                "the point is INVALID unless the MEASURED overlap of their "
                "realise intervals equals N. The measurement, not the barrier, "
                "is the guarantee: a point labelled N=12 whose clients took "
                "turns is mislabelled data, not noisy data"
            ),
        },
        "provenance": provenance,
        "config": config,
        "caveat": scalefit.CAVEAT,
        "measured": measured,
        "models": models,
        "red_flags": red_flags,
    }
    violations = scalefit.sweep_report_violations(report)
    report["honesty"] = {
        "rules": "TESTING.md S5 (a)-(d), asserted by scalefit.sweep_report_violations",
        "violations": violations,
        "compliant": violations == [],
    }
    arms_usable = all(status["usable"] for status in axis_status)
    report["verdict"] = {
        "axes_run": [a.name for a in axes],
        "axis_status": axis_status,
        "fit_problems": problems,
        "all_axes_fitted": problems == [],
        "all_arms_usable": arms_usable,
        "honesty_compliant": violations == [],
        "red_flag_count": len(red_flags),
        "usable": problems == [] and violations == [] and arms_usable,
        "note": (
            "`usable` is about the INSTRUMENT. Red flags are findings about the "
            "PRODUCT and do not make the sweep unusable - they make it useful."
        ),
    }
    return report


# ---- sampler ----------------------------------------------------------------


class NodeSampler:
    """Polls every long-lived node in a pod on a fixed cadence, in a thread.

    Errors are COLLECTED, not swallowed: any error makes the sweep point
    invalid. A sampler that lost its target and kept returning the last good
    value would produce a beautifully flat scaling law from a dead process.
    """

    def __init__(self, pod: e2e.Pod, roles: list[str]):
        self.pod = pod
        self.roles = roles
        self.samples: list[NodeSample] = []
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._pids: dict[str, int] = {}
        self._started = time.monotonic()

    def __enter__(self) -> NodeSampler:
        for role in self.roles:
            try:
                self._pids[role] = self.pod.host_pid(role)
            except RuntimeError as error:
                self.errors.append(str(error))
        self._started = time.monotonic()
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)
        # One final tick AFTER the load finished: VmHWM is monotone, so this is
        # the authoritative peak even if the cadence missed the moment.
        self._tick()

    def _tick(self) -> None:
        at = time.monotonic() - self._started
        for role, pid in self._pids.items():
            try:
                self.samples.append(read_node(role, pid, at))
            except SampleError as error:
                self.errors.append(str(error))

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._tick()
            self._stop.wait(POLL_INTERVAL_S)


# ---- knob confirmation ------------------------------------------------------


def parse_effective_knobs(stdout: str) -> dict:
    """The knob values NIX resolved, from the client's ===KNOBS=== section.

    Returns {} when the section is absent or empty. The caller must treat {} as
    UNCONFIRMED and mark the knob arm unusable - not as "the knob took". A knob
    sweep whose knob silently never landed is the vacuous-oracle shape this
    project has been burned by three times.
    """
    begin = stdout.find("===KNOBS_BEGIN===")
    end = stdout.find("===KNOBS_END===")
    if begin == -1 or end == -1 or end < begin:
        return {}
    block = stdout[begin + len("===KNOBS_BEGIN===") : end]
    knobs: dict = {}
    for line in block.splitlines():
        parts = line.split()
        if (
            len(parts) >= 3
            and parts[1] == "="
            and parts[0]
            in (
                "max-substitution-jobs",
                "http-connections",
            )
        ):
            try:
                knobs[parts[0]] = int(parts[2])
            except ValueError:
                continue
    return knobs


def parse_marker_int(stdout: str, marker: str) -> int | None:
    """One `MARKER=<int>` line from a client's stdout, or None when absent.

    None means UNKNOWN and every caller must treat it that way - substituting a
    host-side number of a different kind, or a 0, is how a timing series turns
    into fiction."""
    for line in stdout.splitlines():
        if line.startswith(marker + "="):
            try:
                return int(line.split("=", 1)[1])
            except ValueError:
                return None
    return None


def parse_realise_seconds(stdout: str) -> float | None:
    """In-container realise duration from `REALISE_NS=`, in seconds."""
    raw = parse_marker_int(stdout, "REALISE_NS")
    return None if raw is None else raw / 1e9


def max_overlap(intervals: list[tuple[int, int]]) -> int:
    """The largest number of intervals covering any single instant.

    This is the CONCURRENCY PRECONDITION for the clients axis. The workload
    finishes in ~150 ms while container start varies by hundreds of ms, so
    "N clients" can easily mean "N clients that took turns" - and a sweep point
    labelled N=12 that only ever ran 3 at a time is mislabelled data, not noisy
    data. The clients therefore report their absolute realise window and the
    overlap is MEASURED, never assumed: a bite whose precondition is not
    asserted is vacuous (wave-1 harness lesson). Proven to bite on real
    containers - serialising the fleet drove the measured overlap to 1 and
    invalidated the point.
    """
    if not intervals:
        return 0
    events: list[tuple[int, int]] = []
    for start, end in intervals:
        # Half-open [start, end): a client that finishes at the exact nanosecond
        # another starts was NOT concurrent with it. A zero-length interval is
        # widened to one nanosecond so it still counts as one client rather than
        # cancelling itself out.
        events.append((start, +1))
        events.append((max(end, start + 1), -1))
    # Ends before starts at the same instant (delta -1 sorts before +1).
    events.sort()
    current = peak = 0
    for _, delta in events:
        current += delta
        peak = max(peak, current)
    return peak


# ---- the sweep arms (containers) --------------------------------------------


def _silent_expect(collector: list):
    def expect(ok: bool, name: str, detail: str = "") -> bool:
        collector.append((bool(ok), name, detail))
        return bool(ok)

    return expect


@dataclass
class ClientArm:
    """What one sweep point's fleet of clients produced."""

    realise_s: list[float] = field(default_factory=list)
    wall_s: list[float] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    effective_knobs: dict = field(default_factory=dict)
    observed_max_overlap: int = 0
    requested_count: int = 0

    @property
    def concurrency_held(self) -> bool:
        """The precondition: as many clients were really in flight at once as
        the axis claims. Equality, not 'at least some overlap' - a sweep point
        labelled N=12 that only ever ran 3 at a time is mislabelled data."""
        return self.observed_max_overlap == self.requested_count


def _drive_clients(
    pod: e2e.Pod,
    substituter: str,
    keys: str,
    targets: list[str],
    count: int,
    jobs: int,
    conns: int,
) -> ClientArm:
    """Launch `count` clients behind a shared start barrier, wait for all, and
    return their timings PLUS the measured concurrency.

    The barrier deadline grows with `count` because each container costs a
    fraction of a second to start; the slack is generous on purpose, since a
    missed barrier does not corrupt the result (the measured overlap catches
    it) but does waste the sweep point.
    """
    arm = ClientArm(requested_count=count)
    deadline_ns = time.time_ns() + int(
        (BARRIER_BASE_S + BARRIER_PER_CLIENT_S * count) * 1e9
    )
    started: list[float] = []
    handles = []
    for _ in range(count):
        started.append(time.perf_counter())
        handles.append(
            pod.client_run_bg(
                targets,
                substituter,
                keys,
                jobs=jobs,
                conns=conns,
                start_at_ns=deadline_ns,
            )
        )
    intervals: list[tuple[int, int]] = []
    for index, handle in enumerate(handles):
        result = handle.wait_result(timeout=CLIENT_TIMEOUT_S)
        arm.wall_s.append(time.perf_counter() - started[index])
        if result.exit_code != 0:
            tail = result.stderr.strip().splitlines()
            arm.failures.append(
                f"client {index} exit {result.exit_code}: {tail[-1] if tail else ''}"
            )
            continue
        seconds = parse_realise_seconds(result.stdout)
        t0 = parse_marker_int(result.stdout, "REALISE_T0_NS")
        t1 = parse_marker_int(result.stdout, "REALISE_T1_NS")
        if seconds is None or t0 is None or t1 is None:
            arm.failures.append(
                f"client {index}: missing REALISE_NS/T0/T1 marker (timing unknown)"
            )
            continue
        arm.realise_s.append(seconds)
        intervals.append((t0, t1))
        arm.effective_knobs = (
            parse_effective_knobs(result.stdout) or arm.effective_knobs
        )
    arm.observed_max_overlap = max_overlap(intervals)
    return arm


def _point_from_arm(
    n: int,
    arm: ClientArm,
    sampler_errors: list[str],
    resources: dict,
    *,
    metric_keys: tuple[str, ...],
    require_concurrency: bool,
) -> SweepPoint:
    """Assemble one sweep point and decide its validity. Shared by all arms so
    the fail-closed rules are written once and cannot drift between axes."""
    reasons = list(arm.failures) + list(sampler_errors)
    if len(arm.realise_s) != arm.requested_count:
        reasons.append(
            f"{len(arm.realise_s)}/{arm.requested_count} clients produced a timing"
        )
    if require_concurrency and not arm.concurrency_held:
        reasons.append(
            f"concurrency precondition failed: measured max overlap "
            f"{arm.observed_max_overlap} != requested {arm.requested_count} "
            "(the clients did not actually run at the same time, so this point "
            "is not the N it is labelled)"
        )
    metrics = {key: resources[key] for key in metric_keys}
    metrics["realise_p95_s"] = percentile(arm.realise_s, 95) if arm.realise_s else None
    return SweepPoint(
        n=n,
        valid=not reasons,
        reason="; ".join(reasons),
        metrics=metrics,
        detail={
            "resources": resources,
            "latency": latency_block(arm.realise_s, arm.wall_s),
            "effective_knobs": arm.effective_knobs,
            "concurrency": {
                "requested_clients": arm.requested_count,
                "observed_max_overlap": arm.observed_max_overlap,
                "held": arm.concurrency_held,
                "enforced": require_concurrency,
            },
        },
    )


def sweep_clients(ctx, fixtures, counts, jobs: int, conns: int, repeats: int) -> Axis:
    """Axis 1: N concurrent clients against ONE daemon."""
    axis = Axis(
        name="clients",
        variable="concurrent nix clients against one daemon",
        description=(
            "The concurrency law. One daemon process serves N simultaneous "
            "clients; the fitted quantity is the DAEMON's peak RSS/fd/latency, "
            "because that is what a peer would pay at scale. The clients are "
            "the host-bound part and are not the subject of the fit."
        ),
    )
    axis.notes.append(
        f"client knobs pinned at max-substitution-jobs={jobs}, "
        f"http-connections={conns} for this axis"
    )
    substituter = ctx.substituter_daemon_only()
    targets = [fixtures.store_path(a) for a in SWEEP_ATTRS]
    for count in counts:
        for rep in range(repeats):
            print(
                f"scale-sweep: clients axis, N={count} (replicate {rep + 1}/{repeats})",
                file=sys.stderr,
            )
            point = SweepPoint(n=count, valid=False)
            try:
                with e2e.Pod(
                    ctx,
                    f"scale-clients-{count}-{rep}",
                    fixtures.cache,
                    with_daemon=True,
                    expect=_silent_expect([]),
                ) as pod:
                    with NodeSampler(pod, pod.roles()) as sampler:
                        arm = _drive_clients(
                            pod,
                            substituter,
                            fixtures.public_key,
                            targets,
                            count,
                            jobs,
                            conns,
                        )
                    resources = aggregate_samples(sampler.samples, pod.daemon_roles())
                point = _point_from_arm(
                    count,
                    arm,
                    sampler.errors,
                    resources,
                    metric_keys=(
                        "daemon_rss_hwm_bytes",
                        "daemon_rss_point_max_bytes",
                        "daemon_fd_max",
                    ),
                    require_concurrency=True,
                )
            except (RuntimeError, SampleError, OSError) as error:
                point.reason = f"sweep point raised: {error!r}"
            axis.points.append(point)
    return axis


def sweep_chain(ctx, fixtures, depths, repeats: int) -> Axis:
    """Axis 2: proxy-chain depth (client -> daemon-1 -> .. -> daemon-N -> proxy)."""
    axis = Axis(
        name="chain",
        variable="proxy-chain depth (daemons in series)",
        description=(
            "The topology law. One client traverses a chain of N daemons; the "
            "fitted quantities are the WORST per-hop peak RSS/fds (what one node "
            "pays), the whole-chain total (what the host pays), and the client's "
            "end-to-end latency (what depth costs a build)."
        ),
    )
    substituter = f"http://127.0.0.1:{e2e.DAEMON_PORT}?priority=10"
    targets = [fixtures.store_path(a) for a in SWEEP_ATTRS]
    for depth in depths:
        for rep in range(repeats):
            print(
                f"scale-sweep: chain axis, depth={depth} (replicate {rep + 1}/{repeats})",
                file=sys.stderr,
            )
            point = SweepPoint(n=depth, valid=False)
            try:
                with e2e.Pod(
                    ctx,
                    f"scale-chain-{depth}-{rep}",
                    fixtures.cache,
                    with_daemon=False,
                    daemon_chain=depth,
                    expect=_silent_expect([]),
                ) as pod:
                    with NodeSampler(pod, pod.roles()) as sampler:
                        arm = _drive_clients(
                            pod, substituter, fixtures.public_key, targets, 1, 1, 1
                        )
                    resources = aggregate_samples(sampler.samples, pod.daemon_roles())
                # One client per depth, so there is no concurrency to enforce; the
                # variable here is the topology, not the load.
                point = _point_from_arm(
                    depth,
                    arm,
                    sampler.errors,
                    resources,
                    metric_keys=(
                        "daemon_rss_hwm_bytes",
                        "chain_total_rss_hwm_bytes",
                        "daemon_fd_max",
                    ),
                    require_concurrency=False,
                )
            except (RuntimeError, SampleError, OSError) as error:
                point.reason = f"sweep point raised: {error!r}"
            axis.points.append(point)
    return axis


def sweep_knobs(ctx, fixtures, values, clients: int, repeats: int) -> Axis:
    """Axis 3: the client concurrency knobs, REPORTED PER VALUE, never fitted.

    TESTING.md's client-knobs rule requires {1, 16, 128} be swept and reported
    per knob value. It is not a scale axis: three points is below
    scalefit.MIN_POINTS, and the knob is a scenario parameter.

    THE CEILING THAT MAKES THIS ARM WEAK, stated up front rather than
    discovered later: max-substitution-jobs cannot exceed the number of
    substitutable paths in the workload. This fixture workload has 3, so 16 and
    128 are indistinguishable from 3 here. The arm still proves the knob LANDS
    (the effective-knob readback) and reports the measured numbers, but a real
    concurrency law needs a wide-fanout fixture - filed as its own task.
    """
    axis = Axis(
        name="knobs",
        variable="client max-substitution-jobs / http-connections",
        description=(
            "TESTING.md client-knobs rule: {1, 16, 128} reported per value at a "
            "fixed client count. NOT a fitted scale axis."
        ),
        fitted=False,
    )
    axis.notes.append(
        f"workload_ceiling: the workload offers {len(SWEEP_ATTRS)} substitutable "
        f"paths, so any max-substitution-jobs above {len(SWEEP_ATTRS)} is "
        "indistinguishable from it. Knob values above the ceiling are reported "
        "but cannot show a concurrency effect (see TASK-57)."
    )
    substituter = ctx.substituter_daemon_only()
    targets = [fixtures.store_path(a) for a in SWEEP_ATTRS]
    for value in values:
        for rep in range(repeats):
            print(
                f"scale-sweep: knobs axis, jobs=conns={value} "
                f"(replicate {rep + 1}/{repeats})",
                file=sys.stderr,
            )
            point = SweepPoint(n=value, valid=False)
            try:
                with e2e.Pod(
                    ctx,
                    f"scale-knobs-{value}-{rep}",
                    fixtures.cache,
                    with_daemon=True,
                    expect=_silent_expect([]),
                ) as pod:
                    with NodeSampler(pod, pod.roles()) as sampler:
                        arm = _drive_clients(
                            pod,
                            substituter,
                            fixtures.public_key,
                            targets,
                            clients,
                            value,
                            value,
                        )
                    resources = aggregate_samples(sampler.samples, pod.daemon_roles())
                point = _point_from_arm(
                    value,
                    arm,
                    sampler.errors,
                    resources,
                    metric_keys=("daemon_rss_hwm_bytes", "daemon_fd_max"),
                    require_concurrency=True,
                )
                # PRECONDITION, asserted: the knob must be confirmed to have LANDED,
                # read back from nix itself. Without this the arm is three identical
                # runs wearing different labels - the vacuous shape this project has
                # been burned by three times.
                confirmed = arm.effective_knobs.get("max-substitution-jobs") == value
                if not confirmed:
                    point.valid = False
                    point.reason = "; ".join(
                        filter(
                            None,
                            [
                                point.reason,
                                f"knob not confirmed by nix: readback "
                                f"{arm.effective_knobs or '{}'} != "
                                f"max-substitution-jobs={value} (arm unusable, not assumed)",
                            ],
                        )
                    )
                point.detail["knob_confirmed"] = confirmed
                point.detail["above_workload_ceiling"] = value > len(SWEEP_ATTRS)
                point.detail["concurrent_clients"] = clients
            except (RuntimeError, SampleError, OSError) as error:
                point.reason = f"sweep point raised: {error!r}"
            axis.points.append(point)
    return axis


# ---- provenance -------------------------------------------------------------


def provenance(fixtures, out_root: Path) -> dict:
    """What makes these numbers re-derivable. A SCALING report's provenance is
    not the same as the egress instrument's: the HOST is part of the result
    here (cpu count, kernel, memory), because a resource law measured on one
    machine is not transferable to another and a reader must be able to tell."""
    generation = fx.resolve_current(out_root)
    lock = json.loads((generation / "lock.json").read_text())
    manifest = fixtures.manifest
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(fx.repo_root()),
        ).stdout.strip()
    except OSError:
        commit = ""
    total_ram = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                total_ram = int(line.split()[1]) * 1024
    except OSError:
        pass
    return {
        "workload_version": manifest["workload_version"],
        "fixture_tier": manifest["tier"],
        "fixture_public_key": lock["public_key"],
        "generation": generation.name,
        "swept_attrs": list(SWEEP_ATTRS),
        "git_commit": commit,
        "host": {
            "kernel": os.uname().release,
            "machine": os.uname().machine,
            "cpu_count": os.cpu_count(),
            "mem_total_bytes": total_ram,
            "note": (
                "a resource scaling law is a property of the system ON THIS HOST; "
                "the constants do not transfer to different hardware, though the "
                "growth CLASS usually does"
            ),
        },
    }


# ---- human summary ----------------------------------------------------------


def print_human_summary(report: dict) -> None:
    out = sys.stderr
    print("\n============== scale-sweep: HUMAN SUMMARY ==============", file=out)
    # RED FLAGS FIRST (TESTING.md S5(c): surfaced, not a footnote).
    flags = report.get("red_flags", [])
    if flags:
        print("\n  *** RED FLAGS - SUPERLINEAR RESOURCE GROWTH ***", file=out)
        for flag in flags:
            worst = flag.get("worst_extrapolation") or {}
            print(
                f"    {flag['id']}: {flag['selected_label']}  R^2="
                f"{flag['r_squared']:.4f}  identifiable={flag['identifiable']}",
                file=out,
            )
            print(f"      {flag['metric']} [{flag['unit']}]", file=out)
            if worst.get("point_estimate") is not None:
                print(
                    f"      MODEL OUTPUT at n={worst.get('n')}: "
                    f"{worst['point_estimate']:.6g} "
                    f"(95% CI {worst.get('ci95_mean_response')})",
                    file=out,
                )
        print("", file=out)
    else:
        print("  red flags        : none (no superlinear RAM/latency fit)", file=out)

    prov = report["provenance"]
    print(
        f"  workload_version : {prov['workload_version']} (tier={prov['fixture_tier']})",
        file=out,
    )
    print(
        f"  host             : {prov['host']['cpu_count']} cpus, "
        f"kernel {prov['host']['kernel']}",
        file=out,
    )
    for name, axis in report["measured"].items():
        valid = sum(1 for p in axis["points"] if p["valid"])
        distinct = len({p["n"] for p in axis["points"] if p["valid"]})
        print(
            f"  axis {name:<8}: {valid}/{len(axis['points'])} valid observations "
            f"over {distinct} distinct n"
            f"{'' if axis['fitted'] else '  (reported per value, NOT fitted)'}",
            file=out,
        )
        for point in axis["points"]:
            if not point["valid"]:
                print(f"      INVALID n={point['n']}: {point['reason']}", file=out)
    print(
        "\n  MODELS (every number below is a MODEL OUTPUT, not a measurement):",
        file=out,
    )
    for fit_id, fit in report["models"].items():
        far = fit["extrapolations"][-1]
        print(
            f"    {fit_id:<38} {fit['selected_label']:<10} "
            f"R^2={fit['r_squared']:.4f} adjR^2={fit['adjusted_r_squared']:.4f}",
            file=out,
        )
        print(
            f"        n={far['n']}: {far['point_estimate']:.6g} {fit['unit']} "
            f"(95% CI {far['ci95_mean_response']})"
            + ("" if fit["identifiable"] else "  [class NOT identifiable]")
            + (
                "  [UNINFORMATIVE: interval crosses zero]"
                if far["interval_extends_below_zero"]
                else ""
            ),
            file=out,
        )
    print(
        "\n  CAVEAT: resource scaling laws only. Emergent network effects (DHT "
        "k-buckets,\n  gossip fan-out, thundering herds) are NOT predictable from "
        "this sweep.",
        file=out,
    )
    verdict = report["verdict"]
    print(
        f"\n  VERDICT: usable={verdict['usable']} "
        f"(honesty_compliant={verdict['honesty_compliant']} "
        f"all_axes_fitted={verdict['all_axes_fitted']} "
        f"red_flags={verdict['red_flag_count']})",
        file=out,
    )
    for problem in verdict["fit_problems"]:
        print(f"    PROBLEM: {problem}", file=out)
    for violation in report["honesty"]["violations"]:
        print(f"    HONESTY VIOLATION: {violation}", file=out)
    print("========================================================\n", file=out)


# ---- self-test (pure; no containers) ----------------------------------------


def _synthetic_axis(name: str, variable: str, model: str, metric: str) -> Axis:
    """An axis whose points follow a KNOWN growth class, for the assembly test."""
    axis = Axis(name=name, variable=variable, description="synthetic")
    basis = scalefit.BASIS_BY_NAME[model]
    for n in (1, 2, 4, 6, 8, 12):
        axis.points.append(
            SweepPoint(
                n=n,
                valid=True,
                metrics={
                    metric: 64.0e6 + 2.0e6 * basis.transform(n),
                    "daemon_fd_max": 12.0 + n,
                    "realise_p95_s": 1.0 + 0.05 * n,
                },
            )
        )
    return axis


def run_self_test() -> int:  # noqa: C901 - a flat list of checks reads better here
    """Pure tests of the sweep's own logic: /proc parsing, knob readback,
    marker parsing, aggregation, report assembly and the red-flag wiring. No
    containers, no nix - runs in the FAST `just test` tier.

    The fitter's own oracles live in `scalefit.py --self-test`; both are wired
    into `just test`, and both prove their rules by MUTATION.
    """
    ok = True

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and bool(cond)
        print(
            f"  {'PASS' if cond else 'FAIL'}  {name}"
            + (f"  [{detail}]" if not cond and detail else "")
        )

    print("scale_sweep --self-test")

    # --- /proc parsing, fail-closed -----------------------------------------
    status = "Name:\tdaemon\nVmHWM:\t  123456 kB\nVmRSS:\t   65432 kB\n"
    check("VmHWM parsed", parse_status_kb(status, "VmHWM") == 123456)
    check("VmRSS parsed", parse_status_kb(status, "VmRSS") == 65432)
    for text, why in [
        ("Name:\tdaemon\nVmRSS:\t 100 kB\n", "missing VmHWM"),
        ("VmHWM:\tnot-a-number kB\n", "non-integer VmHWM"),
        ("VmHWM:\t123456\n", "missing kB unit"),
        ("", "empty status"),
    ]:
        raised = False
        try:
            parse_status_kb(text, "VmHWM")
        except SampleError:
            raised = True
        check(f"fail-closed: {why} -> SampleError (unknown != 0)", raised)

    # --- high-water vs point sample -----------------------------------------
    # The whole reason VmHWM is fitted: a point sampler that missed the peak
    # reports a smaller number, and the aggregate must expose both.
    samples = [
        NodeSample("daemon", 0.0, 200_000_000, 50_000_000, 20),
        NodeSample("daemon", 0.2, 200_000_000, 30_000_000, 14),
    ]
    agg = aggregate_samples(samples, ["daemon"])
    check(
        "high-water is the peak, not the last point",
        agg["daemon_rss_hwm_bytes"] == 200_000_000,
    )
    check(
        "point sample is reported separately and is SMALLER here",
        agg["daemon_rss_point_max_bytes"] == 50_000_000
        and agg["daemon_rss_point_max_bytes"] < agg["daemon_rss_hwm_bytes"],
    )
    check("fd max is the peak, not the last", agg["daemon_fd_max"] == 20)
    chain_agg = aggregate_samples(
        [
            NodeSample("daemon-1", 0.0, 100, 90, 10),
            NodeSample("daemon-2", 0.0, 300, 200, 12),
        ],
        ["daemon-1", "daemon-2"],
    )
    check("per-node peak is the WORST hop", chain_agg["daemon_rss_hwm_bytes"] == 300)
    check("chain total sums the hops", chain_agg["chain_total_rss_hwm_bytes"] == 400)
    raised = False
    try:
        aggregate_samples([NodeSample("proxy", 0.0, 1, 1, 1)], ["daemon"])
    except SampleError:
        raised = True
    check("fail-closed: no daemon samples -> SampleError", raised)

    # --- client markers ------------------------------------------------------
    check(
        "REALISE_NS parsed to seconds",
        parse_realise_seconds("REALISE_RC=0\nREALISE_NS=1500000000\n") == 1.5,
    )
    check(
        "missing REALISE_NS -> None (never a substituted host number)",
        parse_realise_seconds("REALISE_RC=0\n") is None,
    )
    knob_stdout = (
        "===KNOBS_BEGIN===\n"
        "http-connections = 128\n"
        "max-substitution-jobs = 128\n"
        "===KNOBS_END===\n"
    )
    check(
        "effective knobs read back from nix",
        parse_effective_knobs(knob_stdout)
        == {"http-connections": 128, "max-substitution-jobs": 128},
    )
    check(
        "absent knob section -> {} (UNCONFIRMED, not assumed)",
        parse_effective_knobs("REALISE_RC=0\n") == {},
    )
    check(
        "empty knob section -> {} (the vacuous-knob guard)",
        parse_effective_knobs("===KNOBS_BEGIN===\n===KNOBS_END===\n") == {},
    )
    check(
        "a knob query that produced no value -> {} (UNCONFIRMED, not 0)",
        parse_effective_knobs(
            "===KNOBS_BEGIN===\nmax-substitution-jobs = \n===KNOBS_END===\n"
        )
        == {},
    )

    # --- the concurrency precondition ---------------------------------------
    # This is what stops the "concurrent clients" axis from silently measuring
    # podman's container startup serialising the clients.
    check("no clients -> overlap 0", max_overlap([]) == 0)
    check("one client -> overlap 1", max_overlap([(0, 10)]) == 1)
    check(
        "SERIALISED clients (no overlap) -> overlap 1, not 3",
        max_overlap([(0, 10), (20, 30), (40, 50)]) == 1,
    )
    check(
        "fully overlapping clients -> overlap == N",
        max_overlap([(0, 100), (1, 99), (2, 98)]) == 3,
    )
    check(
        "partial overlap counts the true peak",
        max_overlap([(0, 10), (5, 15), (12, 20)]) == 2,
    )
    check(
        "touching-but-not-overlapping intervals do not count as concurrent",
        max_overlap([(0, 10), (10, 20)]) == 1,
    )
    check(
        "a zero-length interval still counts as one client",
        max_overlap([(5, 5)]) == 1,
    )
    serialised = ClientArm(
        realise_s=[1.0, 1.0, 1.0], observed_max_overlap=1, requested_count=3
    )
    check(
        "an arm whose clients were serialised FAILS the precondition",
        not serialised.concurrency_held,
    )
    concurrent = ClientArm(
        realise_s=[1.0, 1.0, 1.0], observed_max_overlap=3, requested_count=3
    )
    check("an arm with full overlap holds it", concurrent.concurrency_held)
    point = _point_from_arm(
        3,
        serialised,
        [],
        {"daemon_rss_hwm_bytes": 1, "daemon_fd_max": 2},
        metric_keys=("daemon_rss_hwm_bytes", "daemon_fd_max"),
        require_concurrency=True,
    )
    check(
        "a serialised point is INVALID with the reason recorded",
        not point.valid and "concurrency precondition failed" in point.reason,
        point.reason,
    )
    chain_point = _point_from_arm(
        3,
        ClientArm(realise_s=[1.0], observed_max_overlap=1, requested_count=1),
        [],
        {"daemon_rss_hwm_bytes": 1, "daemon_fd_max": 2},
        metric_keys=("daemon_rss_hwm_bytes", "daemon_fd_max"),
        require_concurrency=False,
    )
    check(
        "a single-client axis point is unaffected by the precondition",
        chain_point.valid,
        chain_point.reason,
    )
    check(
        "T0/T1 markers parse",
        parse_marker_int("REALISE_T0_NS=17\nREALISE_T1_NS=42\n", "REALISE_T1_NS") == 42,
    )
    check(
        "a missing marker is None, never 0",
        parse_marker_int("REALISE_RC=0\n", "REALISE_T0_NS") is None,
    )

    # --- report assembly + the honesty/red-flag wiring ----------------------
    prov = {"workload_version": "test", "fixture_tier": "fast", "host": {}}
    config = {"self_test": True}
    linear_axis = _synthetic_axis(
        "clients", "concurrent clients", "linear", "daemon_rss_hwm_bytes"
    )
    report = build_report([linear_axis], prov, config, (10, 100, 1000))
    check(
        "assembled report is honesty-COMPLIANT",
        report["honesty"]["compliant"],
        str(report["honesty"]["violations"]),
    )
    check(
        "known O(n) RSS axis recovers linear",
        report["models"]["clients.daemon_rss_hwm_bytes"]["selected_model"] == "linear",
        report["models"]["clients.daemon_rss_hwm_bytes"]["selected_model"],
    )
    check("no red flag for a linear RSS law", report["red_flags"] == [])
    check("verdict usable on a clean synthetic sweep", report["verdict"]["usable"])

    quad_axis = _synthetic_axis(
        "clients", "concurrent clients", "quadratic", "daemon_rss_hwm_bytes"
    )
    quad_report = build_report([quad_axis], prov, config, (10, 100, 1000))
    fit = quad_report["models"]["clients.daemon_rss_hwm_bytes"]
    check(
        "known O(n^2) RSS axis is NOT reported as linear",
        fit["selected_model"] != "linear",
        fit["selected_model"],
    )
    check("known O(n^2) RSS axis is flagged superlinear", fit["superlinear"])
    check(
        "the superlinear fit reaches the red-flag section, by id",
        [f["id"] for f in quad_report["red_flags"]] == ["clients.daemon_rss_hwm_bytes"],
        str([f["id"] for f in quad_report["red_flags"]]),
    )
    check(
        "a report with a red flag is still honesty-compliant and usable",
        quad_report["honesty"]["compliant"] and quad_report["verdict"]["usable"],
        "a product finding must not read as an instrument failure",
    )

    # MUTATION of the assembled report: strip the red-flag section that
    # build_report produced and assert the validator rejects it. This proves the
    # S5(c) rule is enforced on THIS report shape, not just in scalefit's own
    # synthetic one.
    broken = json.loads(json.dumps(quad_report))
    broken["red_flags"] = []
    check(
        "MUTATION: red_flags emptied on a superlinear report -> REJECTED",
        scalefit.sweep_report_violations(broken) != [],
    )
    broken2 = json.loads(json.dumps(quad_report))
    broken2["models"]["clients.daemon_rss_hwm_bytes"]["extrapolations"][0].pop("kind")
    check(
        "MUTATION: extrapolation label stripped -> REJECTED",
        scalefit.sweep_report_violations(broken2) != [],
    )
    broken3 = json.loads(json.dumps(quad_report))
    broken3["measured"]["clients"]["projection"] = {
        "kind": scalefit.MODEL_OUTPUT_KIND,
        "point_estimate": 1,
    }
    check(
        "MUTATION: model output pasted into `measured` -> REJECTED",
        scalefit.sweep_report_violations(broken3) != [],
    )

    # --- invalid points are excluded, and a starved axis is NOT fitted ------
    starved = _synthetic_axis(
        "clients", "concurrent clients", "linear", "daemon_rss_hwm_bytes"
    )
    for point in starved.points[:3]:
        point.valid = False
        point.reason = "synthetic client failure"
    starved_report = build_report([starved], prov, config, (10, 100, 1000))
    check(
        "an axis starved below MIN_POINTS is NOT fitted",
        starved_report["models"] == {},
        str(list(starved_report["models"])),
    )
    check(
        "and the starved sweep reports itself UNUSABLE",
        not starved_report["verdict"]["usable"]
        and starved_report["verdict"]["fit_problems"],
    )
    check(
        "the invalid points keep their reasons in the measured block",
        len(starved_report["measured"]["clients"]["invalid_points"]) == 3,
    )

    # --- replicates are observations, not an average --------------------------
    replicated = _synthetic_axis(
        "clients", "concurrent clients", "linear", "daemon_rss_hwm_bytes"
    )
    jitter = 0.0
    for extra in list(replicated.points):
        jitter += 1.0e5
        clone = SweepPoint(
            n=extra.n, valid=True, metrics=dict(extra.metrics), detail={}
        )
        clone.metrics["daemon_rss_hwm_bytes"] += jitter
        replicated.points.append(clone)
    rep_report = build_report([replicated], prov, config, (10, 100, 1000))
    rep_fit = rep_report["models"]["clients.daemon_rss_hwm_bytes"]
    check(
        "replicates reach the fitter as SEPARATE observations (not averaged)",
        len(rep_fit["n_values"]) == 12,
        f"{len(rep_fit['n_values'])} observations",
    )
    check(
        "duplicate n still counts as ONE distinct n for the MIN_POINTS rule",
        len(set(rep_fit["n_values"])) == 6,
    )
    check(
        "replicate spread shows up in the residual std error (intervals widen)",
        rep_fit["residual_std_error"]
        > report["models"]["clients.daemon_rss_hwm_bytes"]["residual_std_error"],
    )
    check(
        "the report says how many valid observations each n got",
        rep_report["measured"]["clients"]["valid_observations_per_n"]["12"] == 2,
        str(rep_report["measured"]["clients"]["valid_observations_per_n"]),
    )

    # An unfitted axis (the knobs arm) must not silently become fitted.
    knob_axis = Axis(
        name="knobs", variable="knob", description="synthetic", fitted=False
    )
    knob_axis.points.append(SweepPoint(n=1, valid=True, metrics={"realise_p95_s": 1.0}))
    knob_report = build_report([knob_axis], prov, config, (10,))
    check(
        "an axis marked fitted=False produces no model",
        knob_report["models"] == {} and knob_report["verdict"]["usable"],
    )

    print(f"\nscale_sweep --self-test: {'ALL PASS' if ok else 'FAILURES PRESENT'}")
    return 0 if ok else 1


# ---- main -------------------------------------------------------------------


def _int_list(raw: str) -> tuple[int, ...]:
    return tuple(int(x) for x in raw.replace(",", " ").split())


def _install_sigterm_cleanup() -> None:
    """Tear the pods down on SIGTERM too, not only on Ctrl-C.

    Learned the hard way: a `timeout`-killed sweep left a pod running, because
    only KeyboardInterrupt was handled and SIGTERM kills the process outright.
    On a host at 95% disk a leaked pod is not a tidiness issue. `just e2e-clean`
    remains the manual counterpart; this makes the common case automatic."""

    def handler(_signum, _frame):
        e2e.cleanup_pods("(SIGTERM)")
        raise SystemExit(143)

    signal.signal(signal.SIGTERM, handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--clients",
        type=_int_list,
        default=DEFAULT_CLIENT_COUNTS,
        help="concurrent-client counts to sweep (default: %(default)s)",
    )
    parser.add_argument(
        "--chain-depths",
        type=_int_list,
        default=DEFAULT_CHAIN_DEPTHS,
        help="proxy-chain depths to sweep (default: %(default)s)",
    )
    parser.add_argument(
        "--knobs",
        type=_int_list,
        default=DEFAULT_KNOB_VALUES,
        help="max-substitution-jobs / http-connections values (default: %(default)s)",
    )
    parser.add_argument(
        "--axis",
        action="append",
        default=[],
        choices=["clients", "chain", "knobs"],
        help="run only this axis (repeatable); default runs all three",
    )
    parser.add_argument(
        "--extrapolate-to",
        type=_int_list,
        default=scalefit.DEFAULT_EXTRAPOLATION_TARGETS,
        help="n values to extrapolate to (default: %(default)s)",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=DEFAULT_REPEATS,
        help="replicate runs per sweep point, fed to the fitter as separate "
        "observations at the same n (default: %(default)s). 1 is a dev smoke: "
        "a single draw per n let the selected class change between sweeps.",
    )
    parser.add_argument(
        "--report", type=Path, default=None, help="also write the JSON report here"
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=fx.repo_root() / "fixtures" / "out",
        help="fixture publication root",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the pure logic tests (no containers, no nix) and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    _install_sigterm_cleanup()
    free = shutil.disk_usage(fx.repo_root()).free
    if free < MIN_FREE_DISK_BYTES:
        e2e.die(
            f"only {free / 1024**3:.1f} GiB free; a container sweep needs at least "
            f"{MIN_FREE_DISK_BYTES / 1024**3:.0f} GiB. Refusing to start rather "
            "than filling the disk. Bounding the harness footprint is TASK-54."
        )

    out_root = args.out.resolve()
    e2e.preflight_gate(out_root)
    fixtures = e2e.resolve_fixtures(out_root)
    image = e2e.load_image()
    e2e.cleanup_pods()

    scratch = Path(os.environ.get("TMPDIR", "/tmp")) / f"nix-p2p-scale-{os.getpid()}"
    scratch.mkdir(parents=True, exist_ok=True)
    ctx = e2e.Ctx(podman=e2e.podman(), image=image, fixtures=fixtures, scratch=scratch)

    wanted = set(args.axis) or {"clients", "chain", "knobs"}
    config = {
        "client_counts": list(args.clients),
        "chain_depths": list(args.chain_depths),
        "knob_values": list(args.knobs),
        "knob_arm_clients": KNOB_ARM_CLIENTS,
        "repeats_per_point": args.repeats,
        "axes": sorted(wanted),
        "poll_interval_s": POLL_INTERVAL_S,
        "extrapolation_targets": list(args.extrapolate_to),
        "free_disk_bytes_at_start": free,
    }

    axes: list[Axis] = []
    try:
        if "clients" in wanted:
            axes.append(
                sweep_clients(
                    ctx, fixtures, args.clients, jobs=1, conns=1, repeats=args.repeats
                )
            )
        if "chain" in wanted:
            axes.append(
                sweep_chain(ctx, fixtures, args.chain_depths, repeats=args.repeats)
            )
        if "knobs" in wanted:
            axes.append(
                sweep_knobs(
                    ctx,
                    fixtures,
                    args.knobs,
                    clients=KNOB_ARM_CLIENTS,
                    repeats=args.repeats,
                )
            )
    finally:
        # Label-scoped teardown, same contract as `just e2e-clean`: a sweep that
        # leaked pods would keep eating the disk this host does not have.
        e2e.cleanup_pods()
        shutil.rmtree(scratch, ignore_errors=True)

    report = build_report(
        axes, provenance(fixtures, out_root), config, args.extrapolate_to
    )
    print_human_summary(report)
    text = json.dumps(report, indent=2, default=str)
    if args.report:
        args.report.write_text(text + "\n")
        print(f"scale-sweep: report written to {args.report}", file=sys.stderr)
    print(text)
    return 0 if report["verdict"]["usable"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        e2e.cleanup_pods("(interrupted)")
        sys.exit(130)
