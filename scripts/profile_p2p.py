#!/usr/bin/env python3
"""`just profile` (task-42): the owner-goal profiling instrument for the p2p testbed.

Answers, with numbers and with units: what does a peer COST (RAM, disk, fds),
how fast is a peer-served build (latency, throughput), and how much does it save
against the upstream cache (egress, speedup)? Two arms, deliberately different in
kind:

  SWARM axis (FITTED)  - a real swarm of n+1 daemon PROCESSES in one pod: node-a
      plus n independently-seeded iroh providers. n is swept over a grid with
      >= `scalefit.MIN_POINTS` distinct values, so the peer axis has REAL points;
      two nodes cannot discriminate O(n) from O(n log n) and nothing here is
      extrapolated from a pair. `scripts/scalefit.py` fits the family and
      extrapolates to 10/100/1000 with intervals - all MODEL OUTPUT.

  SPEEDUP arm (NOT FITTED) - peers-ON vs peers-OFF over the SAME scripted
      workload, scored by the FROZEN counting rule (`net-upstream-egress-v2`,
      `scripts/MEASUREMENT_COUNTING_RULE.md`, executed by `measure.classify_run`).
      A peer hit is a valid 0-egress crossing there; that is the speedup
      yardstick and this module does not invent a second one.

WHY A SWARM OF PROCESSES. A peer IS one daemon process - it does not fork per
client. The heavy, host-bound component is the CLIENT (a whole `podman run` of
real nix with its own store), which is why task-18 swept clients against ONE
daemon. Here the axis is the thing task-18 could not reach: how much does a HOST
pay for n peers, and does a single peer's cost grow with n?

UNITS ARE MECHANICAL, NOT EDITORIAL (the trap that has recurred three times in
this project). NarSize is the UNCOMPRESSED, SIGNED NAR length; FileSize is the
COMPRESSED transport length; they are different units and a ratio across them is
a lie. Every key in this report ending in `_bytes` MUST end in one of:

    _bytes_ram              resident memory (VmHWM / VmRSS)
    _bytes_ondisk           bytes in files on a filesystem
    _bytes_uncompressed_nar NarSize units - `nix-store --dump` output length
    _bytes_compressed_wire  FileSize units - what crosses the cache boundary

`unit_violations()` walks the assembled report and FAILS the run on any other
`*_bytes` key, and the self-test proves it by mutation. On top of that the
speedup arm uses ONLY `compression: none` fixture attrs and ASSERTS
`file_size == nar_size` from the manifest, so for that arm the two units
coincide BY CHECKED PRECONDITION rather than by hope - which is what makes a
peer-served-bytes vs upstream-egress-bytes comparison legitimate at all.

WHAT IS MEASURED, precisely (this instrument's counting rule):
  * RSS: `VmHWM` (kernel peak) is the FITTED quantity, `VmRSS` point samples
    reported beside it, both read HOST-SIDE from /proc of the container init pid.
  * FDS: max entry count of /proc/<pid>/fd over the sampled ticks.
  * DISK: a host-side walk of the directory bind-mounted as each daemon's
    `--narinfo-cache-dir`. Host-side because `du`/`find`/`grep` are NOT in the
    e2e image - an in-container probe returns rc=127 and passes unconditionally,
    which is the dead-oracle trap this repo has shipped three times.
    FINDING, not an omission: the iroh blob store is `MemStore`
    (`daemon/src/transport_iroh.rs`), so held content costs RAM, not disk. The
    on-disk figure is therefore small and the RAM figure carries the content -
    see `disk_finding` in the report. (TASK-54 owns bounding the footprint.)
  * LATENCY: the IN-CONTAINER `nix-store --realise` duration (REALISE_NS). The
    host-side `podman run` wall clock is reported but NEVER fitted: it carries
    container create/start/teardown, which itself scales with the swarm, so
    fitting it would recover podman's law instead of the product's.
  * THROUGHPUT: transferred bytes / in-container realise seconds, per arm, in
    that arm's own unit.

S9 BITE (AC#2). The fitter's ability to tell a resource law apart from another
one is not asserted, it is MEASURED: `class_recovery_study()` runs a Monte-Carlo
over generators of each KNOWN class on the REAL swept grid and reports the
recovery rate per class. The self-test gates on those RATES (a single seed that
happens to pass is a coin flip, not an oracle) and specifically requires that a
known-SUPERLINEAR generator is never classified linear. `wrong_model_failures()`
defines wrong-model as "selected class outside the generated class's family" and
a non-empty list FAILS the self-test.

HONEST LIMIT OF THAT BITE, measured here rather than discovered later: on the
default grid O(n^2) is separated from linear at every noise level tried, but
O(n log n) is NOT reliably separated once relative noise reaches ~5%. The study
block reports the rate, and the real sweep's OBSERVED replicate spread is
reported next to it, so a reader can see whether the real data sits inside the
regime where the bite is proven.

`--self-test` runs all the pure logic (unit gate, report assembly, the S9
recovery study, disk walking, arm scoring) with NO containers and is wired into
the FAST `just test` tier.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import e2e_harness as e2e
import fixturelib as fx
import scalefit

# Reuse, do not reimplement. `scale_sweep` owns the /proc sampling, the
# high-water aggregation, the measured-concurrency machinery and the sweep-point
# validity rules; a second copy of any of them would be a second definition of
# "peak RSS" whose first divergence would be invisible. `measure` owns the frozen
# egress counting rule. Both are import-clean (no side effects at import).
import scale_sweep as ss
from measure import classify_run, percentile, stat_block

# ---- frozen constants (this instrument's counting rule) ---------------------

REPORT_VERSION = 1
PROFILE_RULE_VERSION = "p2p-profile-v1"

# The peer-count grid. FIVE distinct n, exactly `scalefit.MIN_POINTS`, spanning a
# 16x range so a growth class has room to show itself; TESTING.md S5 names 1..30
# as the target range and `--swarm` raises the top end on a bigger host. Do NOT
# shrink below 5 valid points - the fitter refuses to fit, by design.
DEFAULT_SWARM_SIZES = (1, 2, 4, 8, 16)

# Replicates per swarm point, fed to the fitter as SEPARATE observations at the
# same n (never averaged), for exactly task-18's reason: with one draw per n the
# selected growth class moved between consecutive sweeps. 3 is the default there
# too; keeping them lets the residual variance absorb run-to-run noise instead of
# hiding it behind a mean.
DEFAULT_REPEATS = 3

# Runs per arm in the speedup/throughput arm. 10 is
# `measure.BASELINE_MIN_VALID_RUNS`, the frozen counting rule's floor for an arm
# to be `usable`; below it the arm is reported as a dev smoke, not a baseline.
DEFAULT_SPEEDUP_RUNS = 10

# Swarm-axis workload: SMALL attrs only. Every holder seeds every NAR into its
# in-RAM blob store, so a 110 MiB payload at n=16 would be ~1.8 GiB of held
# content and the axis would measure the host running out of memory. The swarm
# axis is about the BASE per-peer cost as the swarm grows; the cost of HELD
# CONTENT is what the speedup arm's `big` payload exposes.
SWARM_ATTRS = ("lib",)

# Speedup/throughput workload. Both attrs are `compression: none`, which is what
# makes wire bytes and NarSize the same number - ASSERTED against the manifest in
# `assert_unit_coincidence`, not assumed. `big` is 110 MiB: a real transfer, long
# enough for a throughput figure to mean something and bursty enough to finally
# separate VmHWM from point-sampled VmRSS (task-18 left that distinction
# unexercised because its workload grew RSS monotonically).
SPEEDUP_ATTRS = ("lib", "big")

# Refuse to start below this much free disk. The host runs at ~95% used and this
# instrument spins swarms that each hold a blob store plus a per-pod seed copy of
# the 110 MiB payload; a mid-run ENOSPC would corrupt a sweep point into looking
# like a product failure. TASK-54 owns bounding the footprint properly - this is
# the guard that keeps the harness from being the thing that fills the disk.
MIN_FREE_DISK_BYTES = 8 * 1024**3

# The recognised byte units. A `*_bytes` key that ends in none of these is a
# violation: it would let NarSize and FileSize sit in one report under
# indistinguishable names, which is precisely how the three previous unit
# confusions in this project happened.
UNIT_SUFFIXES = (
    "_bytes_ram",
    "_bytes_ondisk",
    "_bytes_uncompressed_nar",
    "_bytes_compressed_wire",
)

# S9 study parameters. 120 replicates per (class, noise) keeps the whole study
# ~1 s (measured: 500 fits in 1.05 s) so it belongs in the FAST tier, and is
# enough resolution for the rate floors below.
STUDY_REPLICATES = 120
STUDY_NOISE_LEVELS = (0.01, 0.02, 0.05)

# Rate floors the self-test GATES on, at STUDY_GATE_NOISE. Chosen from the
# measured rates on the default grid, with margin; they are floors on the
# INSTRUMENT, and a regression in scalefit's selection must trip them.
STUDY_GATE_NOISE = 0.02
GATE_EXACT_RATE = {
    # measured 0.95 / 0.94 / 0.92 at noise 0.02, 200 seeds, grid 1..16
    "linear": 0.90,
    "constant": 0.88,
}
# THE bite: a known-superlinear generator must be classified superlinear, and
# must NEVER be classified linear. `linear_rate` is gated at exactly 0.0.
GATE_SUPERLINEAR_RATE = {"quadratic": 1.0, "linearithmic": 0.95}

# Which selected classes count as "the same family" as a generated class, for the
# wrong-model rule. The split that matters (and that TESTING.md S9 names) is
# linear-vs-SUPERLINEAR; n log n vs n^2 is not reliably identifiable at n <= 30
# and treating that as a wrong model would gate on noise instead of on meaning.
CLASS_FAMILY = {
    "constant": frozenset({"constant"}),
    "logarithmic": frozenset({"logarithmic"}),
    "linear": frozenset({"linear"}),
    "linearithmic": frozenset({"linearithmic", "quadratic"}),
    "quadratic": frozenset({"linearithmic", "quadratic"}),
}


# ---- pure: the unit gate ----------------------------------------------------


def unit_violations(node, path: str = "") -> list[str]:
    """Every `*_bytes` key must carry a recognised unit suffix. Empty == clean.

    This is the mechanical form of the rule the project keeps breaking in prose:
    NarSize (uncompressed, signed) and FileSize (compressed, on-wire) are
    DIFFERENT UNITS, and a report that names both `*_bytes` invites the ratio
    that has already been wrong three times. A reader cannot mix what the schema
    will not let the writer spell.
    """
    problems: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if isinstance(key, str) and key.endswith("_bytes"):
                problems.append(
                    f"{here}: byte-valued key without a unit suffix. Use one of "
                    f"{', '.join(UNIT_SUFFIXES)} - NarSize and FileSize are "
                    "different units and an unlabelled `_bytes` lets them be "
                    "compared"
                )
            problems += unit_violations(value, here)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            problems += unit_violations(value, f"{path}[{index}]")
    return problems


def assert_unit_coincidence(fixtures, attrs) -> dict:
    """PRECONDITION for the speedup arm: for every attr used, the COMPRESSED wire
    size equals the UNCOMPRESSED NarSize (i.e. `compression: none`).

    Only under this condition may peer-served bytes (raw NAR, NarSize units) and
    upstream egress bytes (on-wire, FileSize units) appear in the same offload
    statement. Returns the evidence; RAISES when it does not hold, so a fixture
    regeneration that switched a payload to xz breaks the run LOUDLY here instead
    of silently producing a cross-unit ratio downstream.
    """
    evidence = {}
    bad = []
    for attr in attrs:
        entry = fixtures.entry(attr)
        file_size = int(entry["file_size"])
        nar_size = int(entry["nar_size"])
        evidence[attr] = {
            "compression": entry.get("compression"),
            "wire_bytes_compressed_wire": file_size,
            "nar_bytes_uncompressed_nar": nar_size,
            "coincide": file_size == nar_size,
        }
        if file_size != nar_size:
            bad.append(f"{attr}: file_size={file_size} != nar_size={nar_size}")
    if bad:
        raise ValueError(
            "speedup arm requires `compression: none` payloads so wire bytes and "
            "NarSize coincide; they do not for " + "; ".join(bad) + ". Comparing "
            "peer-served raw-NAR bytes against compressed upstream egress would "
            "mix units."
        )
    return evidence


# ---- pure: disk footprint ---------------------------------------------------


@dataclass
class DiskFootprint:
    """One directory's on-disk footprint, measured two ways.

    `apparent` is the sum of file sizes; `allocated` is the sum of blocks*512,
    which is what the filesystem actually spends. They differ for sparse files
    and for many small files, and reporting only one of them is how a footprint
    number becomes unfalsifiable.
    """

    apparent_bytes_ondisk: int
    allocated_bytes_ondisk: int
    file_count: int


def dir_footprint(path: Path) -> DiskFootprint:
    """Walk `path` HOST-SIDE and total its files.

    Host-side is not an optimisation, it is the only observation point that
    works: the e2e image has no `du` and no `find`, so an in-container probe
    returns rc=127 with empty output and reads as 0 bytes.

    FAIL-CLOSED on a missing directory: `dir_footprint` on a path that was never
    created raises, because "the daemon wrote nothing" and "we measured the wrong
    place" must not produce the same reassuring 0.
    """
    if not path.is_dir():
        raise ss.SampleError(
            f"disk footprint: {path} is not a directory (a missing measurement "
            "point must not read as 0 bytes)"
        )
    apparent = allocated = count = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                info = os.lstat(os.path.join(root, name))
            except OSError:
                # A file that vanished between listing and stat is transient
                # daemon state; skip it rather than fail the whole point, but do
                # not count it as 0 bytes of something that exists.
                continue
            apparent += info.st_size
            allocated += info.st_blocks * 512
            count += 1
    return DiskFootprint(apparent, allocated, count)


# ---- pure: the S9 bite (class recovery, MEASURED not asserted) ---------------


def synthetic_series(model: str, grid, repeats: int, noise: float, seed: int):
    """(xs, ys) drawn from a KNOWN class with reproducible RELATIVE noise.

    Relative (multiplicative) noise on purpose: resource metrics are
    multiplicative-ish, and task-18 measured that scalefit's intervals UNDER-cover
    under exactly this noise shape (0.865 vs 0.95 nominal at n=1000). Generating
    the study under the noise shape the real data has is what makes the recovery
    rate below a statement about this instrument rather than about a tidier one.
    """
    basis = scalefit.BASIS_BY_NAME[model]
    rnd = random.Random(seed)
    xs: list[float] = []
    ys: list[float] = []
    # An intercept much larger than the growth term is the REAL regime for daemon
    # RSS (a ~60 MB base plus a small per-peer increment), so the study is run in
    # the low-SNR regime the sweep actually operates in, not a flattering one.
    base, step = 64.0e6, 2.0e6
    for n in grid:
        for _ in range(repeats):
            xs.append(float(n))
            ys.append(
                (base + step * basis.transform(n)) * (1.0 + rnd.gauss(0.0, noise))
            )
    return xs, ys


def class_recovery_study(grid, *, repeats: int, replicates: int, noise_levels) -> dict:
    """MEASURE how well the fitter recovers a KNOWN class on THIS grid.

    Returns, per (class, noise): the exact-class recovery rate, the rate at which
    the fit was called superlinear, and the rate at which it was called LINEAR -
    the last being the dangerous one for a superlinear generator (TESTING.md S9:
    the confusion that matters is linear-vs-superlinear).

    This is deliberately a RATE over many seeds, not a single fit. A one-seed
    "the fitter got it right" check is a coin flip dressed as an oracle, and this
    project has shipped three oracles that passed for the wrong reason.

    FAIL-CLOSED, not fatal: a grid too short to fit (`< scalefit.MIN_POINTS`
    distinct n) yields a `ran: False` block naming the reason. The same grid also
    makes the real fit impossible, so the report is already unusable - the study
    must say "not measured", never quietly study a DIFFERENT grid than the one
    swept, which would be a bite proven somewhere the data does not live.
    """
    distinct = sorted(set(grid))
    if len(distinct) < scalefit.MIN_POINTS:
        return {
            "ran": False,
            "grid": list(grid),
            "reason": (
                f"{len(distinct)} distinct n {distinct} is below "
                f"scalefit.MIN_POINTS={scalefit.MIN_POINTS}; the S9 bite is NOT "
                "demonstrated for this grid (and neither is any fit on it)"
            ),
            "how_to_read": "no bite was demonstrated - treat every fit as absent",
        }
    study: dict = {}
    for model in scalefit.BASIS_BY_NAME:
        per_noise = {}
        for noise in noise_levels:
            selections: dict[str, int] = {}
            superlinear = 0
            for replicate in range(replicates):
                xs, ys = synthetic_series(
                    model,
                    grid,
                    repeats,
                    noise,
                    seed=hash((model, noise, replicate)) & 0xFFFFFFFF,
                )
                fit = scalefit.fit_scaling(
                    xs, ys, metric=f"synthetic {model}", unit="bytes"
                )
                chosen = fit["selected_model"]
                selections[chosen] = selections.get(chosen, 0) + 1
                superlinear += bool(fit["superlinear"])
            per_noise[str(noise)] = {
                "replicates": replicates,
                "selections": selections,
                "exact_rate": selections.get(model, 0) / replicates,
                "superlinear_rate": superlinear / replicates,
                "linear_rate": selections.get("linear", 0) / replicates,
                "family_rate": sum(
                    count
                    for name, count in selections.items()
                    if name in CLASS_FAMILY[model]
                )
                / replicates,
            }
        study[model] = per_noise
    return {
        "ran": True,
        "grid": list(grid),
        "observations_per_n": repeats,
        "noise_shape": "multiplicative (relative), gaussian",
        "per_class": study,
        "how_to_read": (
            "Rates are properties of the FITTER ON THIS GRID, not of the product. "
            "`linear_rate` for a superlinear generator is the S9 failure mode: a "
            "law that does not survive scale reported as one that does."
        ),
    }


def wrong_model_failures(cases) -> list[str]:
    """The wrong-model rule. `cases` is an iterable of (generated, selected).

    Wrong model == the selected class is outside the generated class's FAMILY
    (`CLASS_FAMILY`). Families collapse only n log n with n^2, which are not
    reliably identifiable below n~30; every other class stands alone, so a
    linear generator reported as superlinear (or vice versa) is a failure.
    """
    failures = []
    for generated, selected in cases:
        family = CLASS_FAMILY.get(generated)
        if family is None:
            failures.append(f"unknown generated class {generated!r}")
        elif selected not in family:
            failures.append(
                f"WRONG MODEL: generated {generated}, selected {selected} "
                f"(outside family {sorted(family)})"
            )
    return failures


# ---- pure: swarm-point assembly ---------------------------------------------

# (metric key in point.metrics, unit, human description). Every one of these is
# fitted against the peer count.
SWARM_METRICS = (
    (
        "peer_rss_hwm_bytes_ram",
        "bytes (RSS)",
        "worst per-peer peak RSS (VmHWM) vs swarm size",
    ),
    (
        "swarm_total_rss_hwm_bytes_ram",
        "bytes (RSS)",
        "whole-swarm peak RSS total (what the HOST pays) vs swarm size",
    ),
    ("peer_fd_max", "descriptors", "worst per-peer peak open fds vs swarm size"),
    (
        "peer_disk_allocated_bytes_ondisk",
        "bytes (on disk)",
        "worst per-peer on-disk daemon state vs swarm size",
    ),
    (
        "realise_p95_s",
        "seconds",
        "client p95 in-container realise latency vs swarm size",
    ),
)


def swarm_metrics_from(resources: dict, disks: dict, realise_s: list[float]) -> dict:
    """Map the reused aggregate + the disk walk onto this report's UNIT-LABELLED
    metric names. The renaming is not cosmetic: `scale_sweep.aggregate_samples`
    returns bare `*_bytes` keys, and this report's unit gate rejects those, so the
    translation happens once, here, where both sides are visible."""
    return {
        "peer_rss_hwm_bytes_ram": resources["daemon_rss_hwm_bytes"],
        "peer_rss_point_max_bytes_ram": resources["daemon_rss_point_max_bytes"],
        "swarm_total_rss_hwm_bytes_ram": resources["chain_total_rss_hwm_bytes"],
        "peer_fd_max": resources["daemon_fd_max"],
        "peer_disk_apparent_bytes_ondisk": max(
            (d.apparent_bytes_ondisk for d in disks.values()), default=0
        ),
        "peer_disk_allocated_bytes_ondisk": max(
            (d.allocated_bytes_ondisk for d in disks.values()), default=0
        ),
        "swarm_total_disk_allocated_bytes_ondisk": sum(
            d.allocated_bytes_ondisk for d in disks.values()
        ),
        "realise_p95_s": percentile(realise_s, 95) if realise_s else None,
    }


def hwm_gap_summary(pairs, *, source: str) -> dict:
    """Did the workload SEPARATE high-water RSS (VmHWM) from the largest point
    sample the 0.2 s sampler caught? `pairs` is an iterable of (hwm, point).

    task-18 left this honest gap open: on its workload VmHWM == max VmRSS at
    every observation, so the distinction the harness reports was never exercised
    by real data. This block answers it with numbers rather than implying it - if
    the gap is 0 everywhere, the report SAYS the distinction is still unexercised
    rather than letting a reader infer it was validated.
    """
    gaps = [
        int(hwm) - int(pnt) for hwm, pnt in pairs if hwm is not None and pnt is not None
    ]
    separated = [g for g in gaps if g > 0]
    return {
        "source": source,
        "observations": len(gaps),
        "observations_where_hwm_exceeds_point_sample": len(separated),
        "max_gap_bytes_ram": max(gaps) if gaps else None,
        "median_gap_bytes_ram": statistics.median(gaps) if gaps else None,
        "exercised": bool(separated),
        "note": (
            "VmHWM is the kernel's peak; the point sample is the largest VmRSS "
            "the 0.2 s sampler happened to catch. A gap of 0 at every "
            "observation means the distinction is UNEXERCISED by this data "
            "(task-18 saw exactly that) - it does NOT mean it was validated."
        ),
    }


def hwm_vs_point(points) -> dict:
    """`hwm_gap_summary` over the swarm axis's per-point worst-peer figures."""
    return hwm_gap_summary(
        (
            (
                point.metrics.get("peer_rss_hwm_bytes_ram"),
                point.metrics.get("peer_rss_point_max_bytes_ram"),
            )
            for point in points
            if point.valid
        ),
        source="swarm axis, worst peer per point",
    )


def hwm_vs_point_roles(per_role: dict, source: str) -> dict:
    """`hwm_gap_summary` over every sampled ROLE of one arm.

    Per-role rather than per-arm-max on purpose: the arm maximum is one number,
    and the separation this is looking for happens on the ONE node that buffers
    the payload. Collapsing to a maximum first would hide which node burst.
    """
    return hwm_gap_summary(
        (
            (row.get("rss_hwm_bytes_ram"), row.get("rss_point_max_bytes_ram"))
            for row in per_role.values()
        ),
        source=source,
    )


def held_content_ram_cost(per_role: dict, held_bytes_uncompressed_nar: int) -> dict:
    """How much RESIDENT MEMORY a node pays per byte of content it holds/moves.

    The units on the two sides are deliberately DIFFERENT and both are named in
    the key: RSS is `_ram`, held content is NarSize. This is a legitimate
    cross-unit RATIO (memory per payload byte) precisely because it is spelled as
    one; what is forbidden is a cross-unit SUM or an offload fraction, which is
    why the offload block draws both of its terms from the wire unit only.

    This is the number that makes the MemStore finding concrete: with the blob
    store in RAM and a whole-NAR transport, BOTH the holder and the fetcher
    resident-size the payload.
    """
    if held_bytes_uncompressed_nar <= 0:
        return {"measured": False, "why": "no held content in this arm"}
    return {
        "measured": True,
        "held_bytes_uncompressed_nar": held_bytes_uncompressed_nar,
        "per_role_rss_bytes_ram_per_held_nar_byte": {
            role: row["rss_hwm_bytes_ram"] / held_bytes_uncompressed_nar
            for role, row in per_role.items()
        },
        "note": (
            "Peak RSS / held NarSize bytes, per node. A ratio near or above 1 "
            "means the node resident-sizes the whole payload - the expected "
            "consequence of an in-RAM blob store (MemStore) plus a whole-NAR "
            "addressed unit. TASK-54 owns bounding this."
        ),
    }


# ---- pure: speedup / throughput arm scoring ---------------------------------


@dataclass
class ProfileRun:
    """One scored workload execution: the frozen counting rule's verdict plus the
    in-container timing the rule does not carry."""

    valid: bool
    reason: str
    realise_s: float | None
    wall_s: float
    egress_nar_bytes_compressed_wire: int
    egress_total_bytes_compressed_wire: int
    peer_served_bytes_uncompressed_nar: int = 0


def summarize_profile_arm(
    name: str,
    runs: list[ProfileRun],
    *,
    workload_bytes_compressed_wire: int,
    workload_bytes_uncompressed_nar: int,
    min_valid: int,
) -> dict:
    """Aggregate one arm. Latency comes from the IN-CONTAINER realise duration;
    the host-side podman wall clock is reported beside it and never used for a
    speedup ratio, because container create/start/teardown is not the product.

    Throughput is stated per UNIT and per arm; the two arms' throughputs are only
    comparable because `assert_unit_coincidence` proved wire == NarSize for this
    workload, which the report records as evidence."""
    valid = [r for r in runs if r.valid]
    realise = [r.realise_s for r in valid if r.realise_s is not None]
    # Per-run throughput, not total/total: a mean of ratios and a ratio of means
    # differ, and the per-run figure is the one with a distribution.
    throughput = [workload_bytes_uncompressed_nar / s for s in realise if s and s > 0]
    return {
        "arm": name,
        "runs": len(runs),
        "valid_runs": len(valid),
        "min_valid_required": min_valid,
        "usable": len(valid) >= min_valid,
        # The frozen counting rule's SECTION 5 threshold. An arm below
        # `measure.BASELINE_MIN_VALID_RUNS` can be `usable` for a dev loop but it
        # is NOT a baseline, and saying so is the difference between a smoke run
        # and a number someone quotes later.
        "dev_smoke_below_n10": len(valid) < 10,
        "invalid_runs": [
            {"run": i, "reason": r.reason} for i, r in enumerate(runs) if not r.valid
        ],
        "workload_bytes_compressed_wire": workload_bytes_compressed_wire,
        "workload_bytes_uncompressed_nar": workload_bytes_uncompressed_nar,
        # THE latency figure: in-container realise.
        "realise_s": stat_block(realise),
        # Context only - carries container create/start/teardown.
        "container_wall_s": stat_block([r.wall_s for r in valid]),
        # THE offload figure, in wire units, per the frozen counting rule.
        "egress_payload_nar_bytes_compressed_wire": stat_block(
            [float(r.egress_nar_bytes_compressed_wire) for r in valid]
        ),
        "egress_total_bytes_compressed_wire": stat_block(
            [float(r.egress_total_bytes_compressed_wire) for r in valid]
        ),
        # Ground truth from the holder's OWN provider counter, in NarSize units.
        "peer_served_bytes_uncompressed_nar": stat_block(
            [float(r.peer_served_bytes_uncompressed_nar) for r in valid]
        ),
        "throughput_bytes_uncompressed_nar_per_s": stat_block(throughput),
    }


def speedup_block(peers_on: dict, peers_off: dict, unit_evidence: dict) -> dict:
    """The S7 speedup/offload statement, assembled so a cross-unit ratio is not
    expressible: every quantity in a ratio here is drawn from ONE unit family.

    `egress_offload_fraction` is computed from `*_compressed_wire` on both sides.
    `latency_speedup` is a ratio of in-container SECONDS. The peer-served figure
    (NarSize units) is reported as corroboration - it is what proves the bytes
    really moved peer-to-peer - and is never a term in either ratio.
    """
    off_nar = peers_off["egress_payload_nar_bytes_compressed_wire"]["mean"]
    on_nar = peers_on["egress_payload_nar_bytes_compressed_wire"]["mean"]
    off_p50 = peers_off["realise_s"]["mean"]
    on_p50 = peers_on["realise_s"]["mean"]
    off_p95 = peers_off["realise_s"]["p95"]
    on_p95 = peers_on["realise_s"]["p95"]

    def ratio(numerator, denominator):
        if numerator is None or denominator in (None, 0):
            return None
        return numerator / denominator

    offload = None
    if off_nar not in (None, 0) and on_nar is not None:
        offload = (off_nar - on_nar) / off_nar
    return {
        "counting_rule": "net-upstream-egress-v2 (scripts/MEASUREMENT_COUNTING_RULE.md)",
        "unit_coincidence_evidence": unit_evidence,
        "egress_payload_peers_off_bytes_compressed_wire": off_nar,
        "egress_payload_peers_on_bytes_compressed_wire": on_nar,
        # Both terms are compressed-wire; the ratio is within one unit family.
        "egress_offload_fraction": offload,
        "peer_served_corroboration_bytes_uncompressed_nar": peers_on[
            "peer_served_bytes_uncompressed_nar"
        ]["mean"],
        "realise_mean_peers_off_s": off_p50,
        "realise_mean_peers_on_s": on_p50,
        "realise_p95_peers_off_s": off_p95,
        "realise_p95_peers_on_s": on_p95,
        # >1 means peers are FASTER. A ratio of seconds; no bytes involved.
        "latency_speedup_mean": ratio(off_p50, on_p50),
        "latency_speedup_p95": ratio(off_p95, on_p95),
        "caveat": (
            "The 'upstream' here is the in-pod testproxy on loopback, NOT "
            "cache.nixos.org. A loopback/container testbed is not residential- "
            "uplink reality: it makes the CACHE side unrealistically fast, so the "
            "latency speedup measured here is a LOWER bound on what a real "
            "upstream would show and the egress offload is the transferable "
            "number. Real-upstream timing (task-35, measured against "
            "cache.nixos.org): median narinfo->nar gap ~300 ms, up to 3.08 s at "
            "closure tails - that gap is absent from every number in this block."
        ),
    }


# ---- container arms ----------------------------------------------------------


def _drive_one_client(pod, substituter: str, keys: str, targets: list[str]):
    """One client container; returns (ClientResult, host wall seconds)."""
    started = time.perf_counter()
    result = pod.client_run(targets, substituter, keys)
    return result, time.perf_counter() - started


def score_run(
    pod, fixtures, attrs, result, wall_s: float, peer_served: int
) -> ProfileRun:
    """Score one run through the FROZEN counting rule (`measure.classify_run`),
    then attach the in-container realise duration.

    The counting rule is imported, not re-expressed: a second definition of "net
    upstream egress" in this repo would silently break every cross-wave
    comparison the rule exists to protect."""
    url_sizes = {
        fixtures.entry(a)["url"]: int(fixtures.entry(a)["file_size"]) for a in attrs
    }
    delivered = {
        fixtures.entry(a)["url"]: (result.narhash(fixtures.store_path(a)) is not None)
        for a in attrs
    }
    verdict = classify_run(
        pod.proxy_log(),
        url_sizes,
        delivered,
        pod.proxy_stats().get("bytes_sent"),
        result.exit_code,
        wall_s,
    )
    realise_s = ss.parse_realise_seconds(result.stdout)
    reasons = [verdict.reason] if verdict.reason else []
    if realise_s is None:
        # Unknown timing is NOT the host wall clock and NOT zero. A run whose
        # in-container duration is unknown cannot contribute to a latency or
        # throughput figure, so it is invalid.
        reasons.append("missing REALISE_NS marker (in-container timing unknown)")
    return ProfileRun(
        valid=not reasons,
        reason="; ".join(reasons),
        realise_s=realise_s,
        wall_s=wall_s,
        egress_nar_bytes_compressed_wire=verdict.egress_nar,
        egress_total_bytes_compressed_wire=verdict.egress_total,
        peer_served_bytes_uncompressed_nar=peer_served,
    )


def sweep_swarm(ctx, fixtures, sizes, repeats: int, state_root: Path) -> ss.Axis:
    """The FITTED axis: n holder peers (n+1 daemon processes) vs resources.

    Each point stands up a fresh pod with node-a plus n independently-seeded iroh
    providers, samples every node's /proc host-side for the duration of one real
    peer-served build, walks each node's on-disk state host-side, and records the
    in-container realise latency.
    """
    axis = ss.Axis(
        name="swarm",
        variable="peer holder count (iroh provider daemon processes)",
        description=(
            "The peer-count law. n holder peers plus one fetching node, all real "
            "daemon PROCESSES on this host. Fitted: what ONE peer pays "
            "(per-peer peak RSS / fds / on-disk state), what the HOST pays "
            "(swarm total), and what a build pays (client realise latency)."
        ),
    )
    axis.notes.append(
        "every holder seeds the SAME NARs, so per-peer figures are comparable "
        f"across the swarm; workload attrs = {list(SWARM_ATTRS)} (small on "
        "purpose - the iroh blob store is in RAM, so a 110 MiB payload at n=16 "
        "would measure the host running out of memory, not a scaling law)"
    )
    axis.notes.append(
        "node A's claims all name holder `node-b`: InMemoryDiscovery::announce "
        "REPLACES on key, so a multi-holder claim is not expressible through "
        "--p2p-claim today. This axis therefore measures the cost of n peer "
        "PROCESSES plus an n-entry peer address book, NOT holder selection or "
        "dial fan-out across n candidates (TASK-43/47)."
    )
    substituter = ctx.substituter_daemon_only()
    targets = [fixtures.store_path(a) for a in SWARM_ATTRS]

    for size in sizes:
        for rep in range(repeats):
            print(
                f"profile: swarm axis, holders={size} (replicate {rep + 1}/{repeats})",
                file=sys.stderr,
            )
            point = ss.SweepPoint(n=size, valid=False)
            scratch = ctx.scratch / f"swarm-{size}-{rep}"
            try:
                seed_dir, seeds = e2e.build_p2p_seed_dir(
                    fixtures, scratch, list(SWARM_ATTRS)
                )
                point_state = state_root / f"swarm-{size}-{rep}"
                with e2e.Pod(
                    ctx,
                    f"prof-swarm-{size}-{rep}",
                    fixtures.cache,
                    with_daemon=False,
                    expect=ss.silent_expect([]),
                    p2p_seed_dir=seed_dir,
                    p2p_seeds=seeds,
                    p2p_holders=size,
                    state_root=point_state,
                ) as pod:
                    pod.proxy_reset()
                    with ss.NodeSampler(pod, pod.roles()) as sampler:
                        result, wall_s = _drive_one_client(
                            pod, substituter, fixtures.public_key, targets
                        )
                    resources = ss.aggregate_samples(
                        sampler.samples, pod.daemon_roles()
                    )
                    disks = {
                        role: dir_footprint(pod.state_dir(role))
                        for role in pod.daemon_roles()
                    }
                    expected_served = sum(s.nar_size for s in seeds)
                    served = pod.node_b_served_bytes(want_at_least=expected_served)
                    realise_s = ss.parse_realise_seconds(result.stdout)

                reasons: list[str] = list(sampler.errors)
                if result.exit_code != 0:
                    tail = result.stderr.strip().splitlines()
                    reasons.append(
                        f"client exit {result.exit_code}: {tail[-1] if tail else ''}"
                    )
                if realise_s is None:
                    reasons.append("missing REALISE_NS marker (timing unknown)")
                # THE precondition that stops this axis from measuring a swarm
                # that quietly fell back to upstream: the claimed holder's OWN
                # provider counter must show it served the whole workload. Without
                # it a point could be a fully-upstream build wearing a peer label.
                if served < expected_served:
                    reasons.append(
                        f"peer-serve precondition failed: node-b served {served} B "
                        f"< expected {expected_served} B (uncompressed NAR) - this "
                        "build was not actually peer-served"
                    )
                metrics = swarm_metrics_from(
                    resources, disks, [realise_s] if realise_s else []
                )
                point = ss.SweepPoint(
                    n=size,
                    valid=not reasons,
                    reason="; ".join(reasons),
                    metrics=metrics,
                    detail={
                        "daemon_processes": size + 1,
                        "peer_served_bytes_uncompressed_nar": served,
                        "expected_served_bytes_uncompressed_nar": expected_served,
                        "container_wall_s": wall_s,
                        "realise_s": realise_s,
                        "per_role_disk": {
                            role: vars(footprint) for role, footprint in disks.items()
                        },
                        "per_role_resources": {
                            role: {
                                "rss_hwm_bytes_ram": row["rss_hwm_bytes"],
                                "rss_point_max_bytes_ram": row["rss_point_max_bytes"],
                                "fd_max": row["fd_max"],
                                "ticks": row["ticks"],
                            }
                            for role, row in resources["per_role"].items()
                        },
                    },
                )
            except (RuntimeError, ss.SampleError, OSError, ValueError) as error:
                point.reason = f"swarm point raised: {error!r}"
            except SystemExit as error:
                # `e2e.die` (exit code 2) is fatal to a SCENARIO but must only
                # invalidate a POINT here: a swarm of 17 containers has 17 chances
                # for one holder to miss its identity announcement, and losing the
                # whole sweep to that would be a harness fault reported as a
                # missing law. Any OTHER exit code - notably the SIGTERM handler's
                # 143 - is a real request to stop and is re-raised.
                if error.code != 2:
                    raise
                point.reason = (
                    f"swarm point aborted by the Pod seam (e2e.die, exit "
                    f"{error.code}); see the harness output above for the reason"
                )
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
            axis.points.append(point)
    return axis


def run_speedup_arms(ctx, fixtures, runs: int, state_root: Path) -> dict:
    """peers-ON vs peers-OFF over the same workload, scored by the frozen rule.

    The two arms are held IDENTICAL in everything the counting rule says must be
    identical: same client script, same knobs, same narinfo-cache configuration
    (both get a state dir), same payloads. The ONLY difference is whether a peer
    holds the NARs.
    """
    unit_evidence = assert_unit_coincidence(fixtures, SPEEDUP_ATTRS)
    targets = [fixtures.store_path(a) for a in SPEEDUP_ATTRS]
    wire_total = sum(int(fixtures.entry(a)["file_size"]) for a in SPEEDUP_ATTRS)
    nar_total = sum(int(fixtures.entry(a)["nar_size"]) for a in SPEEDUP_ATTRS)
    substituter = ctx.substituter_daemon_only()
    min_valid = min(runs, 10)

    # -- peers ON --
    on_runs: list[ProfileRun] = []
    scratch = ctx.scratch / "speedup-seed"
    seed_dir, seeds = e2e.build_p2p_seed_dir(fixtures, scratch, list(SPEEDUP_ATTRS))
    expected_served = sum(s.nar_size for s in seeds)
    try:
        with e2e.Pod(
            ctx,
            "prof-speed-on",
            fixtures.cache,
            with_daemon=False,
            expect=ss.silent_expect([]),
            p2p_seed_dir=seed_dir,
            p2p_seeds=seeds,
            state_root=state_root / "speedup-on",
        ) as pod:
            with ss.NodeSampler(pod, pod.roles()) as sampler:
                for index in range(runs):
                    print(
                        f"profile: speedup arm peers-ON run {index + 1}/{runs}",
                        file=sys.stderr,
                    )
                    pod.proxy_reset()
                    before = pod.node_b_served_bytes(want_at_least=1, timeout_s=0.5)
                    result, wall_s = _drive_one_client(
                        pod, substituter, fixtures.public_key, targets
                    )
                    after = pod.node_b_served_bytes(
                        want_at_least=before + expected_served
                    )
                    on_runs.append(
                        score_run(
                            pod,
                            fixtures,
                            SPEEDUP_ATTRS,
                            result,
                            wall_s,
                            peer_served=after - before,
                        )
                    )
            on_resources = ss.aggregate_samples(sampler.samples, pod.daemon_roles())
            on_disk = {
                role: vars(dir_footprint(pod.state_dir(role)))
                for role in pod.daemon_roles()
            }
            on_sampler_errors = list(sampler.errors)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    # -- peers OFF (the contrast that falsifies a 0-egress claim) --
    off_runs: list[ProfileRun] = []
    with e2e.Pod(
        ctx,
        "prof-speed-off",
        fixtures.cache,
        with_daemon=True,
        expect=ss.silent_expect([]),
        state_root=state_root / "speedup-off",
    ) as pod:
        with ss.NodeSampler(pod, pod.roles()) as sampler:
            for index in range(runs):
                print(
                    f"profile: speedup arm peers-OFF run {index + 1}/{runs}",
                    file=sys.stderr,
                )
                pod.proxy_reset()
                result, wall_s = _drive_one_client(
                    pod, substituter, fixtures.public_key, targets
                )
                off_runs.append(
                    score_run(
                        pod, fixtures, SPEEDUP_ATTRS, result, wall_s, peer_served=0
                    )
                )
        off_resources = ss.aggregate_samples(sampler.samples, pod.daemon_roles())
        off_disk = {
            role: vars(dir_footprint(pod.state_dir(role)))
            for role in pod.daemon_roles()
        }
        off_sampler_errors = list(sampler.errors)

    peers_on = summarize_profile_arm(
        "peers-on",
        on_runs,
        workload_bytes_compressed_wire=wire_total,
        workload_bytes_uncompressed_nar=nar_total,
        min_valid=min_valid,
    )
    peers_off = summarize_profile_arm(
        "peers-off",
        off_runs,
        workload_bytes_compressed_wire=wire_total,
        workload_bytes_uncompressed_nar=nar_total,
        min_valid=min_valid,
    )
    peers_on["resources"] = _labelled_resources(on_resources)
    peers_off["resources"] = _labelled_resources(off_resources)
    peers_on["disk"] = on_disk
    peers_off["disk"] = off_disk
    peers_on["sampler_errors"] = on_sampler_errors
    peers_off["sampler_errors"] = off_sampler_errors
    # The 110 MiB payload is the bursty workload task-18 never had: this is where
    # the high-water/point-sample distinction gets exercised (or does not), and
    # where the in-RAM blob store's cost per held byte becomes a number.
    for arm, held in ((peers_on, nar_total), (peers_off, 0)):
        arm["high_water_vs_point_sample"] = hwm_vs_point_roles(
            arm["resources"]["per_role"], f"speedup arm {arm['arm']}, per role"
        )
        arm["held_content_ram_cost"] = held_content_ram_cost(
            arm["resources"]["per_role"], held
        )
    return {
        "attrs": list(SPEEDUP_ATTRS),
        "runs_requested": runs,
        "peers_on": peers_on,
        "peers_off": peers_off,
        "speedup": speedup_block(peers_on, peers_off, unit_evidence),
    }


def _labelled_resources(resources: dict) -> dict:
    """`scale_sweep.aggregate_samples` output with this report's unit suffixes."""
    return {
        "peer_rss_hwm_bytes_ram": resources["daemon_rss_hwm_bytes"],
        "peer_rss_point_max_bytes_ram": resources["daemon_rss_point_max_bytes"],
        "total_rss_hwm_bytes_ram": resources["chain_total_rss_hwm_bytes"],
        "peer_fd_max": resources["daemon_fd_max"],
        "per_role": {
            role: {
                "rss_hwm_bytes_ram": row["rss_hwm_bytes"],
                "rss_point_max_bytes_ram": row["rss_point_max_bytes"],
                "rss_point_last_bytes_ram": row["rss_point_last_bytes"],
                "fd_max": row["fd_max"],
                "ticks": row["ticks"],
            }
            for role, row in resources["per_role"].items()
        },
    }


# ---- report assembly ---------------------------------------------------------

DISK_FINDING = {
    "measured": (
        "on-disk daemon state = a host-side walk of the directory bind-mounted "
        "as each node's --narinfo-cache-dir (the ONLY on-disk state a daemon "
        "keeps today)"
    ),
    "blob_store_is_in_ram": (
        "FINDING, not an omission: the iroh blob store is `MemStore` "
        "(daemon/src/transport_iroh.rs `IrohProvider::spawn`), so a holder's "
        "content costs RESIDENT MEMORY, not disk. There is no castore/on-disk "
        "blob store to measure in wave-2a. Read the per-peer RSS figure as the "
        "cost of held content, and the on-disk figure as metadata only."
    ),
    "consequence_for_scale": (
        "A peer's held-content budget is therefore bounded by RAM, not by disk. "
        "Any 1000-peer statement about DISK from this report is a statement "
        "about narinfo metadata only. Bounding the footprint is TASK-54."
    ),
}


def build_report(
    axis, speedup: dict | None, study: dict, provenance: dict, config: dict, targets
) -> dict:
    """Assemble the report. PURE: takes collected measurements, touches nothing.

    Two independent honesty gates run on the assembled object and BOTH must come
    back empty: `scalefit.sweep_report_violations` (the S5 measured/model split,
    fit quality, red-flag coverage, the resource-laws-only caveat) and this
    module's `unit_violations` (no unlabelled byte quantity anywhere).
    """
    models: dict = {}
    problems: list[str] = []
    valid_points = sum(1 for p in axis.points if p.valid)
    distinct_valid = len({p.n for p in axis.points if p.valid})

    fits, fit_problems = ss.fit_axis(axis, SWARM_METRICS, targets)
    models.update(fits)
    problems += fit_problems

    measured = {
        "swarm": {
            "variable": axis.variable,
            "description": axis.description,
            "notes": axis.notes,
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
            "high_water_vs_point_sample": hwm_vs_point(axis.points),
            "observed_replicate_spread": replicate_spread(axis.points),
        }
    }
    if speedup is not None:
        measured["speedup"] = speedup

    red_flags = scalefit.red_flags_for(models)
    report = {
        "report_version": REPORT_VERSION,
        "profile_rule_version": PROFILE_RULE_VERSION,
        "fitter_version": scalefit.FITTER_VERSION,
        "counting_rule": {
            "rss": (
                "VmHWM (kernel peak RSS) is FITTED; VmRSS point samples reported "
                "beside it. Both host-side from /proc of the container init pid."
            ),
            "fds": "max entry count of /proc/<pid>/fd over the sampled ticks",
            "disk": DISK_FINDING["measured"],
            "latency": (
                "in-container `nix-store --realise` duration (REALISE_NS). The "
                "host-side podman wall clock is reported but NEVER fitted and "
                "never used in a speedup ratio: it carries container "
                "create/start/teardown, which itself scales with the swarm."
            ),
            "throughput": (
                "workload bytes / in-container realise seconds, per arm, in that "
                "arm's own unit"
            ),
            "egress": (
                "net-upstream-egress-v2, executed by measure.classify_run - the "
                "SAME frozen rule the wave-1 baseline used. A peer hit is a VALID "
                "zero-egress crossing when the client confirms delivery."
            ),
            "units": (
                "every `*_bytes` key carries one of "
                + ", ".join(UNIT_SUFFIXES)
                + ". NarSize (uncompressed, signed) and FileSize (compressed, "
                "on-wire) are DIFFERENT UNITS and are never compared; the speedup "
                "arm additionally ASSERTS file_size == nar_size for its payloads "
                "so the two coincide by checked precondition."
            ),
            "validity": (
                "a point with a failed client, an unreadable /proc, a missing "
                "in-container timing, or a holder that did not actually serve the "
                "workload is INVALID: excluded with a reason, never recorded as 0"
            ),
        },
        "disk_finding": DISK_FINDING,
        "provenance": provenance,
        "config": config,
        "caveat": scalefit.CAVEAT,
        "s9_bite": study,
        "measured": measured,
        "models": models,
        "red_flags": red_flags,
    }
    s5_violations = scalefit.sweep_report_violations(report)
    unit_problems = unit_violations(report)
    report["honesty"] = {
        "rules": (
            "TESTING.md S5 (a)-(d) via scalefit.sweep_report_violations, plus this "
            "module's unit rule via unit_violations"
        ),
        "s5_violations": s5_violations,
        "unit_violations": unit_problems,
        "compliant": not s5_violations and not unit_problems,
    }
    speedup_usable = True
    if speedup is not None:
        speedup_usable = (
            speedup["peers_on"]["usable"] and speedup["peers_off"]["usable"]
        )
    report["verdict"] = {
        "swarm_valid_observations": valid_points,
        "swarm_total_observations": len(axis.points),
        "swarm_distinct_valid_n": distinct_valid,
        "fit_problems": problems,
        "all_metrics_fitted": problems == [],
        "speedup_arms_usable": speedup_usable,
        "honesty_compliant": report["honesty"]["compliant"],
        "red_flag_count": len(red_flags),
        # AC#2 travels WITH the report: a profile whose grid was too short to
        # demonstrate the S9 bite must not read as one that demonstrated it.
        "s9_bite_demonstrated": bool(study.get("ran")),
        "usable": (
            problems == []
            and report["honesty"]["compliant"]
            and speedup_usable
            and bool(study.get("ran"))
        ),
        "note": (
            "`usable` is about the INSTRUMENT. Red flags are findings about the "
            "PRODUCT and do not make the profile unusable - they make it useful."
        ),
    }
    return report


def replicate_spread(points) -> dict:
    """The OBSERVED relative spread between replicates at the same n.

    This is what closes the loop on the S9 study: the study proves the bite at
    synthetic noise levels, and this says which noise level the REAL data sits
    at. A bite proven at 2% noise says nothing about data with 20% spread, and a
    report that does not put the two numbers next to each other is inviting that
    exact mistake.
    """
    out: dict = {}
    for key, _unit, _desc in SWARM_METRICS:
        by_n: dict[int, list[float]] = {}
        for point in points:
            if not point.valid:
                continue
            value = point.metrics.get(key)
            if value is None:
                continue
            by_n.setdefault(point.n, []).append(float(value))
        spreads = []
        for values in by_n.values():
            if len(values) < 2:
                continue
            mean = statistics.fmean(values)
            if mean:
                spreads.append(statistics.pstdev(values) / abs(mean))
        out[key] = {
            "n_groups_with_replicates": len(spreads),
            "median_relative_spread": statistics.median(spreads) if spreads else None,
            "max_relative_spread": max(spreads) if spreads else None,
        }
    return out


def provenance(fixtures, out_root: Path) -> dict:
    """What makes these numbers re-derivable. The HOST is part of a resource
    result, so it is recorded: a law measured on one machine does not transfer."""
    generation = fx.resolve_current(out_root)
    lock = json.loads((generation / "lock.json").read_text())
    total_ram = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                total_ram = int(line.split()[1]) * 1024
    except OSError:
        pass
    commit = ""
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(fx.repo_root()),
        ).stdout.strip()
    except OSError:
        pass
    return {
        "workload_version": fixtures.manifest["workload_version"],
        "fixture_tier": fixtures.manifest["tier"],
        "fixture_public_key": lock["public_key"],
        "generation": generation.name,
        "swarm_attrs": list(SWARM_ATTRS),
        "speedup_attrs": list(SPEEDUP_ATTRS),
        "git_commit": commit,
        "host": {
            "kernel": os.uname().release,
            "machine": os.uname().machine,
            "cpu_count": os.cpu_count(),
            "mem_total_bytes_ram": total_ram,
            "note": (
                "a resource scaling law is a property of the system ON THIS HOST; "
                "the constants do not transfer to different hardware, though the "
                "growth CLASS usually does"
            ),
        },
    }


# ---- human summary -----------------------------------------------------------


def _mib(value) -> str:
    return "n/a" if value is None else f"{value / 1024**2:.1f} MiB"


def print_human_summary(report: dict) -> None:
    out = sys.stderr
    print("\n============== profile: HUMAN SUMMARY ==============", file=out)
    flags = report.get("red_flags", [])
    if flags:
        print("\n  *** RED FLAGS - SUPERLINEAR RESOURCE GROWTH ***", file=out)
        for flag in flags:
            worst = flag.get("worst_extrapolation") or {}
            print(
                f"    {flag['id']}: {flag['selected_label']}  "
                f"R^2={flag['r_squared']:.4f} identifiable={flag['identifiable']}",
                file=out,
            )
            if worst.get("point_estimate") is not None:
                print(
                    f"      MODEL OUTPUT at n={worst.get('n')}: "
                    f"{worst['point_estimate']:.6g} {flag['unit']}",
                    file=out,
                )
    else:
        print("  red flags        : none (no superlinear fit)", file=out)

    swarm = report["measured"]["swarm"]
    valid = sum(1 for p in swarm["points"] if p["valid"])
    print(
        f"  swarm axis       : {valid}/{len(swarm['points'])} valid over "
        f"{len(swarm['distinct_n'])} distinct n {swarm['distinct_n']}",
        file=out,
    )
    for point in swarm["points"]:
        if not point["valid"]:
            print(f"      INVALID n={point['n']}: {point['reason']}", file=out)
    for point in swarm["points"]:
        if point["valid"]:
            m = point["metrics"]
            print(
                f"      n={point['n']:<3} peer_rss_hwm={_mib(m['peer_rss_hwm_bytes_ram'])}"
                f"  swarm_total={_mib(m['swarm_total_rss_hwm_bytes_ram'])}"
                f"  fds={m['peer_fd_max']}"
                f"  disk={m['peer_disk_allocated_bytes_ondisk']} B"
                f"  realise_p95={m['realise_p95_s']}",
                file=out,
            )
    hwm = swarm["high_water_vs_point_sample"]
    print(
        f"  VmHWM vs VmRSS   : separated at "
        f"{hwm['observations_where_hwm_exceeds_point_sample']}/"
        f"{hwm['observations']} swarm points, max gap "
        f"{_mib(hwm['max_gap_bytes_ram'])} (exercised={hwm['exercised']})",
        file=out,
    )

    speed = report["measured"].get("speedup")
    if speed:
        s = speed["speedup"]
        for arm in (speed["peers_on"], speed["peers_off"]):
            gap = arm["high_water_vs_point_sample"]
            smoke = (
                "  [DEV SMOKE, < 10 valid runs]" if arm["dev_smoke_below_n10"] else ""
            )
            print(
                f"  {arm['arm']:<10} : {arm['valid_runs']}/{arm['runs']} valid"
                f"   VmHWM separated at "
                f"{gap['observations_where_hwm_exceeds_point_sample']}/"
                f"{gap['observations']} roles, max gap "
                f"{_mib(gap['max_gap_bytes_ram'])}{smoke}",
                file=out,
            )
            cost = arm["held_content_ram_cost"]
            if cost.get("measured"):
                worst = max(
                    cost["per_role_rss_bytes_ram_per_held_nar_byte"].items(),
                    key=lambda kv: kv[1],
                )
                print(
                    f"               RAM per held NarSize byte: worst node "
                    f"{worst[0]} = {worst[1]:.2f}x (in-RAM blob store)",
                    file=out,
                )
        print("\n  SPEEDUP / OFFLOAD (measured, frozen counting rule):", file=out)
        print(
            f"    egress payload  peers-off "
            f"{s['egress_payload_peers_off_bytes_compressed_wire']} B(wire) -> "
            f"peers-on {s['egress_payload_peers_on_bytes_compressed_wire']} B(wire)"
            f"   offload={s['egress_offload_fraction']}",
            file=out,
        )
        print(
            f"    realise mean    peers-off {s['realise_mean_peers_off_s']} s -> "
            f"peers-on {s['realise_mean_peers_on_s']} s  "
            f"speedup={s['latency_speedup_mean']}",
            file=out,
        )
        print(
            f"    throughput      peers-on "
            f"{speed['peers_on']['throughput_bytes_uncompressed_nar_per_s']['mean']}"
            f" B(NarSize)/s   peers-off "
            f"{speed['peers_off']['throughput_bytes_uncompressed_nar_per_s']['mean']}"
            f" B(NarSize)/s",
            file=out,
        )

    print(
        "\n  MODELS (every number below is a MODEL OUTPUT, not a measurement):",
        file=out,
    )
    for fit_id, fit in report["models"].items():
        far = fit["extrapolations"][-1]
        print(
            f"    {fit_id:<48} {fit['selected_label']:<10} R^2={fit['r_squared']:.4f}",
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
        "this sweep.\n  DISK: the iroh blob store is in RAM (MemStore) - held "
        "content costs RSS, not disk.",
        file=out,
    )
    verdict = report["verdict"]
    print(
        f"\n  VERDICT: usable={verdict['usable']} "
        f"(honesty_compliant={verdict['honesty_compliant']} "
        f"all_metrics_fitted={verdict['all_metrics_fitted']} "
        f"speedup_arms_usable={verdict['speedup_arms_usable']} "
        f"s9_bite_demonstrated={verdict['s9_bite_demonstrated']} "
        f"red_flags={verdict['red_flag_count']})",
        file=out,
    )
    for problem in verdict["fit_problems"]:
        print(f"    PROBLEM: {problem}", file=out)
    for violation in (
        report["honesty"]["s5_violations"] + report["honesty"]["unit_violations"]
    ):
        print(f"    HONESTY VIOLATION: {violation}", file=out)
    print("====================================================\n", file=out)


# ---- self-test (pure; no containers) ----------------------------------------


def _synthetic_swarm_axis(model: str, metric: str = "peer_rss_hwm_bytes_ram"):
    """A swarm axis whose points follow a KNOWN growth class."""
    axis = ss.Axis(name="swarm", variable="holders", description="synthetic")
    basis = scalefit.BASIS_BY_NAME[model]
    for n in DEFAULT_SWARM_SIZES:
        metrics = {
            "peer_rss_hwm_bytes_ram": 64.0e6,
            "peer_rss_point_max_bytes_ram": 64.0e6,
            "swarm_total_rss_hwm_bytes_ram": 64.0e6 * n,
            "peer_fd_max": 12.0 + n,
            "peer_disk_apparent_bytes_ondisk": 4096.0,
            "peer_disk_allocated_bytes_ondisk": 4096.0,
            "swarm_total_disk_allocated_bytes_ondisk": 4096.0 * n,
            "realise_p95_s": 1.0 + 0.05 * n,
        }
        metrics[metric] = 64.0e6 + 2.0e6 * basis.transform(n)
        axis.points.append(ss.SweepPoint(n=n, valid=True, metrics=metrics))
    return axis


def _fake_run(**kwargs) -> ProfileRun:
    base = {
        "valid": True,
        "reason": "",
        "realise_s": 1.0,
        "wall_s": 2.0,
        "egress_nar_bytes_compressed_wire": 0,
        "egress_total_bytes_compressed_wire": 0,
        "peer_served_bytes_uncompressed_nar": 0,
    }
    base.update(kwargs)
    return ProfileRun(**base)


def run_self_test() -> int:  # noqa: C901 - a flat list of checks reads better here
    """Pure tests of this instrument's logic: the unit gate, the S9 class-recovery
    bite, disk walking, arm scoring, report assembly and the honesty wiring. No
    containers, no nix - runs in the FAST `just test` tier.

    Every rule is proven by MUTATION: break it, watch the gate go red.
    """
    ok = True

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and bool(cond)
        print(
            f"  {'PASS' if cond else 'FAIL'}  {name}"
            + (f"  [{detail}]" if not cond and detail else "")
        )

    print("profile_p2p --self-test")

    # --- the unit gate (the NarSize-vs-FileSize trap, made mechanical) -------
    print("\n  -- unit discipline --")
    check(
        "a unit-suffixed byte key passes",
        unit_violations({"peer_rss_hwm_bytes_ram": 1}) == [],
    )
    for suffix in UNIT_SUFFIXES:
        check(
            f"suffix {suffix} is accepted",
            unit_violations({f"x{suffix}": 1}) == [],
        )
    check(
        "MUTATION: a bare `_bytes` key is REJECTED",
        unit_violations({"egress_bytes": 1}) != [],
    )
    check(
        "MUTATION: a bare `_bytes` key nested in a list is REJECTED",
        unit_violations({"arms": [{"served_bytes": 1}]}) != [],
    )
    check(
        "the violation names the offending path",
        "arms[0].served_bytes" in unit_violations({"arms": [{"served_bytes": 1}]})[0],
        str(unit_violations({"arms": [{"served_bytes": 1}]})),
    )
    check(
        "a non-byte key is untouched",
        unit_violations({"realise_p95_s": 1, "fd_max": 3}) == [],
    )

    # unit coincidence precondition, proven both ways with a fake fixture set.
    class _Fixtures:
        def __init__(self, entries):
            self._entries = entries

        def entry(self, attr):
            return self._entries[attr]

    same = _Fixtures(
        {"lib": {"compression": "none", "file_size": 66048, "nar_size": 66048}}
    )
    diff = _Fixtures({"app": {"compression": "xz", "file_size": 260, "nar_size": 408}})
    evidence = assert_unit_coincidence(same, ["lib"])
    check(
        "coincidence holds for a `compression: none` payload",
        evidence["lib"]["coincide"],
    )
    raised = False
    try:
        assert_unit_coincidence(diff, ["app"])
    except ValueError:
        raised = True
    check(
        "MUTATION: a COMPRESSED payload makes the speedup arm REFUSE to run "
        "(wire != NarSize)",
        raised,
    )

    # --- the S9 bite: class recovery, MEASURED ------------------------------
    print("\n  -- S9 bite: known-class recovery on the real grid --")
    study = class_recovery_study(
        DEFAULT_SWARM_SIZES,
        repeats=DEFAULT_REPEATS,
        replicates=STUDY_REPLICATES,
        noise_levels=STUDY_NOISE_LEVELS,
    )
    gate = str(STUDY_GATE_NOISE)
    for model, floor in GATE_EXACT_RATE.items():
        rate = study["per_class"][model][gate]["exact_rate"]
        check(
            f"known-{scalefit.BASIS_BY_NAME[model].label} generator recovers "
            f"{model} at >= {floor} (measured {rate:.3f})",
            rate >= floor,
            f"{rate:.3f} < {floor}",
        )
    for model, floor in GATE_SUPERLINEAR_RATE.items():
        row = study["per_class"][model][gate]
        check(
            f"known-{scalefit.BASIS_BY_NAME[model].label} generator is flagged "
            f"SUPERLINEAR at >= {floor} (measured {row['superlinear_rate']:.3f})",
            row["superlinear_rate"] >= floor,
            f"{row['superlinear_rate']:.3f} < {floor}",
        )
    quad = study["per_class"]["quadratic"][gate]
    check(
        "THE BITE: a known-O(n^2) generator is NEVER fitted as linear "
        f"(linear_rate={quad['linear_rate']:.3f})",
        quad["linear_rate"] == 0.0,
        f"{quad['linear_rate']:.3f} != 0",
    )
    # The honest counterpart, REPORTED not gated: how often a genuinely LINEAR
    # law is falsely flagged superlinear on this grid.
    lin = study["per_class"]["linear"][gate]
    print(
        f"      [reported, not gated] false-superlinear rate for a LINEAR law "
        f"at noise {gate}: {lin['superlinear_rate']:.3f}"
    )
    worst_nlogn = study["per_class"]["linearithmic"][str(max(STUDY_NOISE_LEVELS))]
    print(
        f"      [reported, not gated] O(n log n) mistaken for LINEAR at noise "
        f"{max(STUDY_NOISE_LEVELS)}: {worst_nlogn['linear_rate']:.3f} - the "
        "discrimination limit of this grid"
    )

    # The guard is caught rather than let-crash on purpose: a mutation that
    # removes it makes `fit_scaling` RAISE, and a self-test that dies with a
    # traceback is red but does not NAME what broke. An oracle that cannot say
    # what it caught is half an oracle.
    try:
        short = class_recovery_study(
            (1, 2), repeats=DEFAULT_REPEATS, replicates=5, noise_levels=(0.02,)
        )
    except scalefit.FitError as error:
        short = {"ran": None, "reason": f"raised instead of failing closed: {error}"}
    check(
        "a grid below MIN_POINTS demonstrates NO bite and says so (fail-closed, "
        "not a crash)",
        short.get("ran") is False and "MIN_POINTS" in short.get("reason", ""),
        str(short)[:200],
    )
    short_report = build_report(
        _synthetic_swarm_axis("linear"),
        None,
        short,
        {"workload_version": "t", "fixture_tier": "full", "host": {}},
        {"self_test": True},
        (10,),
    )
    check(
        "MUTATION: a report whose S9 bite did not run is UNUSABLE, and says so "
        "in the verdict",
        not short_report["verdict"]["usable"]
        and short_report["verdict"]["s9_bite_demonstrated"] is False,
        str(short_report["verdict"]),
    )

    # wrong-model rule, both directions.
    check(
        "wrong_model_failures: matching classes produce no failure",
        wrong_model_failures([("linear", "linear"), ("constant", "constant")]) == [],
    )
    check(
        "MUTATION: a superlinear generator reported LINEAR is a WRONG MODEL",
        wrong_model_failures([("quadratic", "linear")]) != [],
    )
    check(
        "MUTATION: a linear generator reported quadratic is a WRONG MODEL",
        wrong_model_failures([("linear", "quadratic")]) != [],
    )
    check(
        "n log n vs n^2 is NOT a wrong model (not identifiable below n~30)",
        wrong_model_failures([("linearithmic", "quadratic")]) == [],
    )
    check(
        "an unknown generated class is itself a failure (fail-closed)",
        wrong_model_failures([("cubic", "linear")]) != [],
    )
    # End-to-end: fit each synthetic axis and run the wrong-model rule on the
    # ACTUAL selections, which is the AC#2 sentence made executable.
    cases = []
    for model in ("constant", "linear", "linearithmic", "quadratic"):
        axis = _synthetic_swarm_axis(model)
        fits, _ = ss.fit_axis(axis, SWARM_METRICS, (10, 100, 1000))
        cases.append((model, fits["swarm.peer_rss_hwm_bytes_ram"]["selected_model"]))
    failures = wrong_model_failures(cases)
    check(
        "end-to-end: every known-class swarm axis selects a class in its own "
        f"family {cases}",
        failures == [],
        str(failures),
    )

    # --- disk footprint ------------------------------------------------------
    print("\n  -- disk footprint (host-side walk) --")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "sub").mkdir()
        (root / "sub" / "a.json").write_bytes(b"x" * 1000)
        (root / "b.json").write_bytes(b"y" * 10)
        footprint = dir_footprint(root)
        check("apparent size sums file sizes", footprint.apparent_bytes_ondisk == 1010)
        check("file count is recursive", footprint.file_count == 2)
        check(
            "allocated size is block-rounded and >= apparent here",
            footprint.allocated_bytes_ondisk >= footprint.apparent_bytes_ondisk,
            f"{footprint.allocated_bytes_ondisk} vs {footprint.apparent_bytes_ondisk}",
        )
        empty = root / "empty"
        empty.mkdir()
        check(
            "an empty dir is 0 bytes, not an error",
            dir_footprint(empty).file_count == 0,
        )
    raised = False
    try:
        dir_footprint(Path("/nonexistent-profile-p2p-path"))
    except ss.SampleError:
        raised = True
    check(
        "MUTATION: a MISSING measurement point raises, never reads as 0 bytes",
        raised,
    )

    # --- arm scoring + the cross-unit trap ----------------------------------
    print("\n  -- speedup arm scoring --")
    on = summarize_profile_arm(
        "peers-on",
        [
            _fake_run(
                realise_s=2.0,
                egress_nar_bytes_compressed_wire=0,
                peer_served_bytes_uncompressed_nar=115_343_872,
            )
            for _ in range(10)
        ],
        workload_bytes_compressed_wire=115_343_872,
        workload_bytes_uncompressed_nar=115_343_872,
        min_valid=10,
    )
    off = summarize_profile_arm(
        "peers-off",
        [
            _fake_run(realise_s=4.0, egress_nar_bytes_compressed_wire=115_343_872)
            for _ in range(10)
        ],
        workload_bytes_compressed_wire=115_343_872,
        workload_bytes_uncompressed_nar=115_343_872,
        min_valid=10,
    )
    check("an arm at the floor is usable", on["usable"] and off["usable"])
    block = speedup_block(on, off, {"lib": {"coincide": True}})
    check(
        "a full peer hit is a 100% egress offload",
        block["egress_offload_fraction"] == 1.0,
        str(block["egress_offload_fraction"]),
    )
    check(
        "latency speedup is a ratio of IN-CONTAINER seconds (4.0/2.0 = 2.0)",
        block["latency_speedup_mean"] == 2.0,
        str(block["latency_speedup_mean"]),
    )
    # THE cross-unit trap, proven: make the peer-served (NarSize) figure absurdly
    # large and assert the offload fraction does NOT move. If NarSize had leaked
    # into the wire-unit ratio it would.
    on_inflated = json.loads(json.dumps(on))
    on_inflated["peer_served_bytes_uncompressed_nar"]["mean"] = 999_999_999_999
    inflated = speedup_block(on_inflated, off, {"lib": {"coincide": True}})
    check(
        "MUTATION: inflating the NarSize-unit peer-served figure does NOT move "
        "the wire-unit offload fraction (no cross-unit leak)",
        inflated["egress_offload_fraction"] == block["egress_offload_fraction"],
        f"{inflated['egress_offload_fraction']} vs {block['egress_offload_fraction']}",
    )
    starved = summarize_profile_arm(
        "peers-on",
        [_fake_run(valid=False, reason="client exit 1") for _ in range(10)],
        workload_bytes_compressed_wire=1,
        workload_bytes_uncompressed_nar=1,
        min_valid=10,
    )
    check("an arm with no valid runs is UNUSABLE", not starved["usable"])
    check(
        "and its reasons are kept, not dropped",
        len(starved["invalid_runs"]) == 10,
    )

    # --- report assembly + both honesty gates -------------------------------
    print("\n  -- report assembly + honesty gates --")
    prov = {"workload_version": "test", "fixture_tier": "full", "host": {}}
    config = {"self_test": True}
    speedup_measured = {
        "attrs": ["lib"],
        "runs_requested": 10,
        "peers_on": on,
        "peers_off": off,
        "speedup": block,
    }
    linear = _synthetic_swarm_axis("linear")
    report = build_report(
        linear, speedup_measured, study, prov, config, (10, 100, 1000)
    )
    check(
        "assembled report is honesty-COMPLIANT (S5 + units)",
        report["honesty"]["compliant"],
        str(report["honesty"]["s5_violations"] + report["honesty"]["unit_violations"]),
    )
    check(
        "known O(n) per-peer RSS recovers linear",
        report["models"]["swarm.peer_rss_hwm_bytes_ram"]["selected_model"] == "linear",
        report["models"]["swarm.peer_rss_hwm_bytes_ram"]["selected_model"],
    )
    check(
        "the whole-swarm RSS total is O(n) (n independent peers)",
        report["models"]["swarm.swarm_total_rss_hwm_bytes_ram"]["selected_model"]
        == "linear",
        report["models"]["swarm.swarm_total_rss_hwm_bytes_ram"]["selected_model"],
    )
    check("no red flag for a linear law", report["red_flags"] == [])
    check("verdict usable on a clean synthetic profile", report["verdict"]["usable"])

    quad_axis = _synthetic_swarm_axis("quadratic")
    quad_report = build_report(
        quad_axis, speedup_measured, study, prov, config, (10, 100, 1000)
    )
    fit = quad_report["models"]["swarm.peer_rss_hwm_bytes_ram"]
    check(
        "known O(n^2) per-peer RSS is NOT reported linear",
        fit["selected_model"] != "linear",
    )
    check("known O(n^2) per-peer RSS is flagged superlinear", fit["superlinear"])
    check(
        "the superlinear fit reaches the red-flag section, by id",
        "swarm.peer_rss_hwm_bytes_ram" in [f["id"] for f in quad_report["red_flags"]],
        str([f["id"] for f in quad_report["red_flags"]]),
    )
    check(
        "a red-flagged report is still compliant and usable (a product finding "
        "is not an instrument failure)",
        quad_report["honesty"]["compliant"] and quad_report["verdict"]["usable"],
    )

    # MUTATIONS of the assembled report - both gates, on THIS report shape.
    broken = json.loads(json.dumps(quad_report))
    broken["red_flags"] = []
    check(
        "MUTATION: red_flags emptied on a superlinear report -> REJECTED",
        scalefit.sweep_report_violations(broken) != [],
    )
    broken = json.loads(json.dumps(quad_report))
    broken["models"]["swarm.peer_rss_hwm_bytes_ram"]["extrapolations"][0].pop("kind")
    check(
        "MUTATION: extrapolation model-output label stripped -> REJECTED",
        scalefit.sweep_report_violations(broken) != [],
    )
    broken = json.loads(json.dumps(quad_report))
    broken["measured"]["swarm"]["projection"] = {
        "kind": scalefit.MODEL_OUTPUT_KIND,
        "point_estimate": 1,
    }
    check(
        "MUTATION: model output pasted into `measured` -> REJECTED",
        scalefit.sweep_report_violations(broken) != [],
    )
    broken = json.loads(json.dumps(quad_report))
    broken["measured"]["swarm"]["points"][0]["metrics"]["peer_rss_hwm_bytes"] = 1
    check(
        "MUTATION: an UNLABELLED byte quantity in the report -> REJECTED by the "
        "unit gate",
        unit_violations(broken) != [],
    )
    check(
        "and the real report has no unlabelled byte quantity anywhere",
        unit_violations(quad_report) == [],
        str(unit_violations(quad_report)[:3]),
    )
    broken = json.loads(json.dumps(quad_report))
    broken.pop("caveat")
    check(
        "MUTATION: the resource-laws-only caveat removed -> REJECTED",
        scalefit.sweep_report_violations(broken) != [],
    )

    # --- starved axis: refuse to fit rather than fit what survived -----------
    starved_axis = _synthetic_swarm_axis("linear")
    for point in starved_axis.points[:2]:
        point.valid = False
        point.reason = "synthetic holder failure"
    starved_report = build_report(
        starved_axis, None, study, prov, config, (10, 100, 1000)
    )
    check(
        "an axis starved below MIN_POINTS is NOT fitted",
        starved_report["models"] == {},
        str(list(starved_report["models"])),
    )
    check(
        "and the starved profile reports itself UNUSABLE with the reason",
        not starved_report["verdict"]["usable"]
        and starved_report["verdict"]["fit_problems"],
    )
    check(
        "invalid points keep their reasons",
        len(starved_report["measured"]["swarm"]["invalid_points"]) == 2,
    )

    # --- high-water vs point sample ------------------------------------------
    print("\n  -- VmHWM vs VmRSS point sample --")
    equal = ss.Axis(name="swarm", variable="holders", description="x")
    equal.points.append(
        ss.SweepPoint(
            n=1,
            valid=True,
            metrics={
                "peer_rss_hwm_bytes_ram": 100,
                "peer_rss_point_max_bytes_ram": 100,
            },
        )
    )
    check(
        "HWM == point sample everywhere -> reported UNEXERCISED, not validated",
        hwm_vs_point(equal.points)["exercised"] is False,
    )
    burst = ss.Axis(name="swarm", variable="holders", description="x")
    burst.points.append(
        ss.SweepPoint(
            n=1,
            valid=True,
            metrics={
                "peer_rss_hwm_bytes_ram": 300,
                "peer_rss_point_max_bytes_ram": 100,
            },
        )
    )
    check(
        "a burst the sampler missed shows as a SEPARATED high-water",
        hwm_vs_point(burst.points)["exercised"]
        and hwm_vs_point(burst.points)["max_gap_bytes_ram"] == 200,
    )
    roles = {
        "node-a": {"rss_hwm_bytes_ram": 100, "rss_point_max_bytes_ram": 100},
        "node-b": {"rss_hwm_bytes_ram": 300, "rss_point_max_bytes_ram": 100},
    }
    role_gap = hwm_vs_point_roles(roles, "test")
    check(
        "per-ROLE separation finds the ONE node that burst, not the arm max",
        role_gap["observations"] == 2
        and role_gap["observations_where_hwm_exceeds_point_sample"] == 1
        and role_gap["max_gap_bytes_ram"] == 200,
        str(role_gap),
    )
    cost = held_content_ram_cost(roles, 100)
    check(
        "RAM cost per held NarSize byte is a NAMED cross-unit ratio",
        cost["measured"]
        and cost["per_role_rss_bytes_ram_per_held_nar_byte"]["node-b"] == 3.0,
        str(cost),
    )
    check(
        "an arm that holds nothing reports NO ratio (not a 0, not a div-by-zero)",
        held_content_ram_cost(roles, 0)["measured"] is False,
    )
    check(
        "an arm below the counting rule's 10-valid-run floor is marked a DEV SMOKE",
        summarize_profile_arm(
            "x",
            [_fake_run() for _ in range(3)],
            workload_bytes_compressed_wire=1,
            workload_bytes_uncompressed_nar=1,
            min_valid=3,
        )["dev_smoke_below_n10"],
    )
    check(
        "an arm at 10 valid runs is NOT a dev smoke",
        not summarize_profile_arm(
            "x",
            [_fake_run() for _ in range(10)],
            workload_bytes_compressed_wire=1,
            workload_bytes_uncompressed_nar=1,
            min_valid=10,
        )["dev_smoke_below_n10"],
    )

    # --- replicate spread ----------------------------------------------------
    spread_axis = ss.Axis(name="swarm", variable="holders", description="x")
    for value in (100.0, 110.0):
        spread_axis.points.append(
            ss.SweepPoint(n=4, valid=True, metrics={"peer_fd_max": value})
        )
    spread = replicate_spread(spread_axis.points)["peer_fd_max"]
    check(
        "replicate spread is measured where replicates exist",
        spread["n_groups_with_replicates"] == 1
        and abs(spread["median_relative_spread"] - (5.0 / 105.0)) < 1e-9,
        str(spread),
    )
    single = ss.Axis(name="swarm", variable="holders", description="x")
    single.points.append(ss.SweepPoint(n=4, valid=True, metrics={"peer_fd_max": 1.0}))
    check(
        "a single draw yields NO spread claim (None, not 0)",
        replicate_spread(single.points)["peer_fd_max"]["median_relative_spread"]
        is None,
    )

    print(f"\nprofile_p2p --self-test: {'ALL PASS' if ok else 'FAILURES PRESENT'}")
    return 0 if ok else 1


# ---- main --------------------------------------------------------------------


def _install_sigterm_cleanup() -> None:
    """Tear the pods down on SIGTERM as well as Ctrl-C. On a host at 95% disk a
    leaked swarm pod is not a tidiness issue."""

    def handler(_signum, _frame):
        e2e.cleanup_pods("(SIGTERM)")
        raise SystemExit(143)

    signal.signal(signal.SIGTERM, handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--swarm",
        type=ss.int_list,
        default=DEFAULT_SWARM_SIZES,
        help="holder-peer counts to sweep (default: %(default)s)",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=DEFAULT_REPEATS,
        help="replicate runs per swarm point, fitted as separate observations "
        "at the same n (default: %(default)s)",
    )
    parser.add_argument(
        "--speedup-runs",
        type=int,
        default=DEFAULT_SPEEDUP_RUNS,
        help="runs per speedup arm (default: %(default)s; below 10 the frozen "
        "counting rule marks the arm a dev smoke, not a baseline)",
    )
    parser.add_argument(
        "--skip-speedup",
        action="store_true",
        help="run only the fitted swarm axis (dev loop)",
    )
    parser.add_argument(
        "--extrapolate-to",
        type=ss.int_list,
        default=scalefit.DEFAULT_EXTRAPOLATION_TARGETS,
        help="n values to extrapolate to (default: %(default)s)",
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
            f"only {free / 1024**3:.1f} GiB free; this profile spins peer swarms "
            f"that each hold a blob store and copies the 110 MiB payload per pod, "
            f"and needs at least {MIN_FREE_DISK_BYTES / 1024**3:.0f} GiB. Refusing "
            "to start rather than dying with ENOSPC mid-run. Bounding the harness "
            "footprint is TASK-54."
        )

    out_root = args.out.resolve()
    e2e.preflight_gate(out_root)
    fixtures = e2e.resolve_fixtures(out_root)
    image = e2e.load_image()
    e2e.cleanup_pods()

    scratch = Path(os.environ.get("TMPDIR", "/tmp")) / f"nix-p2p-profile-{os.getpid()}"
    scratch.mkdir(parents=True, exist_ok=True)
    state_root = scratch / "state"
    state_root.mkdir(parents=True, exist_ok=True)
    ctx = e2e.Ctx(podman=e2e.podman(), image=image, fixtures=fixtures, scratch=scratch)

    config = {
        "swarm_sizes": list(args.swarm),
        "repeats_per_point": args.repeats,
        "speedup_runs": args.speedup_runs,
        "speedup_skipped": bool(args.skip_speedup),
        "swarm_attrs": list(SWARM_ATTRS),
        "speedup_attrs": list(SPEEDUP_ATTRS),
        "poll_interval_s": ss.POLL_INTERVAL_S,
        "extrapolation_targets": list(args.extrapolate_to),
        "free_disk_bytes_ondisk_at_start": free,
    }

    axis = ss.Axis(name="swarm", variable="peer holder count", description="not run")
    speedup = None
    try:
        axis = sweep_swarm(ctx, fixtures, args.swarm, args.repeats, state_root)
        if not args.skip_speedup:
            speedup = run_speedup_arms(ctx, fixtures, args.speedup_runs, state_root)
    finally:
        # Label-scoped teardown, same contract as `just e2e-clean`.
        e2e.cleanup_pods()
        shutil.rmtree(scratch, ignore_errors=True)

    study = class_recovery_study(
        args.swarm,
        repeats=args.repeats,
        replicates=STUDY_REPLICATES,
        noise_levels=STUDY_NOISE_LEVELS,
    )
    report = build_report(
        axis,
        speedup,
        study,
        provenance(fixtures, out_root),
        config,
        args.extrapolate_to,
    )
    print_human_summary(report)
    text = json.dumps(report, indent=2, default=str)
    if args.report:
        args.report.write_text(text + "\n")
        print(f"profile: report written to {args.report}", file=sys.stderr)
    print(text)
    return 0 if report["verdict"]["usable"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        e2e.cleanup_pods("(interrupted)")
        sys.exit(130)
