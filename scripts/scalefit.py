#!/usr/bin/env python3
"""S5 regression fitter: candidate scaling models, fit quality, extrapolation.

STANDALONE BY DESIGN. This module imports nothing but the Python standard
library - no numpy/scipy (the pinned env is `python3.withPackages [cryptography
blake3]`, flake.nix), no containers, no `e2e_harness`. That is what lets it be
(a) unit-tested in the FAST `just test` tier and (b) imported by a different
sweep runner: task-18 points it at concurrent-client count and chain depth,
task-42 will point the SAME fitter at peer count. The sweep runner supplies
(n, y) samples; this module owns the statistics and the honesty rules.

WHAT IT DOES. For samples (n_i, y_i) it fits the family

    y = a + b * f(n)      f in {0, log n, n, n*log n, n^2}

by ordinary least squares on the transformed axis, scores each candidate by
AICc (small-sample-corrected Akaike), selects with a parsimony margin, and
extrapolates with Student-t intervals. R^2 is always computed against the
ORIGINAL y - never against a transformed target - so it is comparable across
candidates (transforming y instead would make R^2 values from different models
non-comparable, a classic way to "prove" the model you wanted).

THE HONESTY RULES (TESTING.md S5) ARE ASSERTED HERE, NOT DOCUMENTED HERE.
`fit_violations()` / `sweep_report_violations()` return a non-empty list for a
report that:
  * carries an extrapolated number that is not structurally labelled
    `{"kind": "model_output"}`;
  * carries a fit without R^2 / residuals travelling alongside;
  * mixes a model output into the `measured` block;
  * has a SUPERLINEAR fit that is not listed in the report's `red_flags`;
  * omits the resource-laws-only caveat.
A runner is expected to call these and fail. The rules are only real if a
malformed report is rejected mechanically - `run_self_test()` proves that by
MUTATION, not by reading.

WHAT THIS CANNOT DO, stated plainly:
  * Extrapolation covers RESOURCE SCALING LAWS ONLY. Emergent network effects
    (mainline-DHT k-bucket dynamics, gossip fan-out, congestion collapse,
    coordinated churn) are NOT recoverable from a 1..30 node sweep and no
    interval here covers them. See CAVEAT below - it is embedded in every
    report this module builds a fit for.
  * The intervals are the intervals of the SELECTED model. They express
    sampling uncertainty around that model's line; they do NOT express
    model-class uncertainty. When two candidates are within the AICc margin
    the report says so (`competitive_models`) - read that before the interval.
  * With few points and a narrow n-range, n*log n and n^2 are strongly
    collinear and the exact class between them is not reliably identifiable.
    The SUPERLINEAR/not-superlinear split is the robust discrimination, which
    is why the red flag keys off that split and not off the exact class.
"""

from __future__ import annotations

import json
import math
import os
import random
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---- frozen constants -------------------------------------------------------

# v1 -> v2 (task-42): `superlinear` changed MEANING - it now requires the fitted
# slope to be positive, not merely a superlinear basis. That changes what
# `red_flags_for` emits for the same input, so two reports stamped `scalefit-v1`
# would have had different red-flag semantics. Bumping is what this field is for.
FITTER_VERSION = "scalefit-v2"

# Fewer points than this and AICc is undefined for the 3-parameter candidates
# (n - k - 1 <= 0), so selection would be a coin flip dressed as statistics.
# Fail closed instead of fitting: a sweep must supply >= 5 distinct n values.
MIN_POINTS = 5

# AICc difference below which two candidates are "indistinguishable". Burnham &
# Anderson's conventional threshold for substantial support. Used two ways:
# (a) the SIMPLEST candidate within the margin of the best is selected
#     (parsimony - otherwise a curvier basis wins on noise alone);
# (b) every candidate within the margin is reported as `competitive_models`,
#     so a reader is never shown a single class as if it were identified.
AICC_MARGIN = 2.0

# Confidence level for every interval this module emits.
CONFIDENCE = 0.95

# Where the report's extrapolations are asked for by default: the "10s / 100s /
# 1000s of peers" the owner requirement names.
DEFAULT_EXTRAPOLATION_TARGETS = (10, 100, 1000)

# The structural label that separates a modelled number from a measured one.
# Any dict carrying an extrapolated value MUST carry this key with this value.
MODEL_OUTPUT_KIND = "model_output"

# The resource-laws-only caveat, mandatory in every report (TESTING.md S5 (d)).
CAVEAT = {
    "scope": (
        "RESOURCE SCALING LAWS ONLY. These fits describe how per-node RSS, file "
        "descriptors and request latency grow with the swept axis on THIS host, "
        "and nothing else."
    ),
    "emergent_network_effects_out_of_scope": (
        "Emergent network behaviour at scale - mainline-DHT k-bucket dynamics, "
        "gossip fan-out, thundering herds, congestion collapse, coordinated "
        "churn - is NOT predictable from a small-N sweep and is NOT covered by "
        "any interval in this report. A green extrapolation here is not a claim "
        "that the network works at 1000 peers."
    ),
    "extrapolation_status": (
        "Every number under `models` is a MODEL OUTPUT, not a measurement. "
        "Measurements live under `measured` and are never mixed in."
    ),
    "interval_meaning": (
        "Intervals are sampling uncertainty around the SELECTED model, not "
        "model-class uncertainty. Read `competitive_models` first."
    ),
}


# ---- shared sweep-instrument report layer (task-59) -------------------------
#
# `scale_sweep.py` and `profile_p2p.py` are two S5 sweep instruments that build
# the SAME kind of report. The mechanically-identical pieces live here so there
# is ONE definition of "what a compliant S5 sweep report looks like" - two
# copies is exactly the shape that lets one drift silently, and one already had
# (`swarm_valid_observations` vs `axis_status[].valid_observations`, and a whole
# UNIT RULE that policed only one of the two reports).
#
# These helpers are duck-typed, never importing the harness's `Axis`/`SweepPoint`
# dataclasses (that would defeat the standalone-by-design property above): an
# `axis` is anything with `.variable`, `.description`, `.notes` and `.points`,
# and a `point` anything with `.n`, `.valid`, `.reason`, `.metrics`, `.detail`.

# Refuse to start a container sweep below this much free disk. Both instruments
# spin swarms/chains that each hold a blob store plus a per-pod payload copy; a
# mid-run ENOSPC would corrupt a sweep point into looking like a product
# failure. TASK-54 owns bounding the footprint properly - this is the guard that
# keeps the harness from being the thing that fills the disk.
MIN_FREE_DISK_BYTES = 8 * 1024**3

# The recognised byte units (the NarSize-vs-FileSize trap, made mechanical). A
# `*_bytes` key that ends in none of these lets NarSize (uncompressed, signed)
# and FileSize (compressed, on-wire) sit in one report under indistinguishable
# names, which is precisely how the three previous unit confusions happened.
UNIT_SUFFIXES = (
    "_bytes_ram",  # resident memory (VmHWM / VmRSS)
    "_bytes_ondisk",  # bytes in files on a filesystem
    "_bytes_uncompressed_nar",  # NarSize units - `nix-store --dump` output length
    "_bytes_compressed_wire",  # FileSize units - what crosses the cache boundary
)

# The host note both instruments stamp on their provenance: a resource law is a
# property of the machine it ran on, and a reader must be able to tell.
HOST_NOTE = (
    "a resource scaling law is a property of the system ON THIS HOST; "
    "the constants do not transfer to different hardware, though the "
    "growth CLASS usually does"
)


def disk_headroom_ok(free_bytes: int) -> bool:
    """Is there at least `MIN_FREE_DISK_BYTES` free? Integer comparison, no
    float in the DECISION (the caller formats the human message, where a float
    is a terminal display and allowed). Defined once so the threshold and the
    comparison cannot drift between the two instruments."""
    return free_bytes >= MIN_FREE_DISK_BYTES


def measured_axis_block(axis) -> dict:
    """The measured-side block for ONE swept axis, in the CANONICAL schema.

    The distinct-n grid, the per-n valid-observation counts, and the
    point/invalid-point lists - the construction that had grown a near-copy in
    each instrument. Replicates are separate OBSERVATIONS at the same n, never
    averaged (the fitter needs the spread to size its intervals honestly), and a
    reader needs to see how many draws each n actually got, so both are exposed.

    Callers `.update()` their per-instrument extras onto the returned dict
    (scale_sweep adds `fitted`; profile_p2p adds the high-water and
    replicate-spread blocks); the SHARED core is defined here exactly once."""
    distinct = sorted({p.n for p in axis.points})
    return {
        "variable": axis.variable,
        "description": axis.description,
        "notes": axis.notes,
        "distinct_n": distinct,
        "valid_observations_per_n": {
            str(n): sum(1 for p in axis.points if p.n == n and p.valid)
            for n in distinct
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


def axis_status_counts(axis) -> dict:
    """The valid/total/distinct-valid observation triple a verdict reports for
    one axis, in the CANONICAL `axis_status[]` schema.

    This is the key that had DIVERGED: profile_p2p spelled it flat
    (`swarm_valid_observations`, ...), scale_sweep nested it
    (`axis_status[].valid_observations`). Both now spell it the same way through
    this helper, so the two reports converge on one schema."""
    return {
        "valid_observations": sum(1 for p in axis.points if p.valid),
        "total_observations": len(axis.points),
        "distinct_valid_n": len({p.n for p in axis.points if p.valid}),
    }


def host_provenance(*, note: str = HOST_NOTE) -> tuple[dict, dict]:
    """Host identity + total RAM (bytes, unit-labelled by NAME), fail-verbose.

    Returns `(host_dict, unavailable)`: a MemTotal that could not be read is
    recorded under `unavailable` with the reason, never left as a silent blank
    (this block's whole job is re-derivability, so "unknown" quietly reading as
    the number's absence is exactly the failure it must not have). The RAM key
    is `mem_total_bytes_ram` - unit-labelled, so it passes the repo unit rule."""
    unavailable: dict[str, str] = {}
    total_ram = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                total_ram = int(line.split()[1]) * 1024
    except OSError as error:
        unavailable["mem_total_bytes_ram"] = str(error)
    host = {
        "kernel": os.uname().release,
        "machine": os.uname().machine,
        "cpu_count": os.cpu_count(),
        "mem_total_bytes_ram": total_ram,
        "note": note,
    }
    return host, unavailable


def _git(repo_root, argv: list[str], unavailable: dict) -> str | None:
    """One git command's stdout, or None with the reason recorded. Shared by the
    commit-hash and working-tree-clean lookups below."""
    try:
        result = subprocess.run(
            ["git", *argv],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(repo_root),
        )
    except OSError as error:
        unavailable[f"git {' '.join(argv)}"] = str(error)
        return None
    if result.returncode != 0:
        unavailable[f"git {' '.join(argv)}"] = (
            f"exit {result.returncode}: {result.stderr.strip()}"
        )
        return None
    return result.stdout


def base_provenance(
    *,
    workload_version,
    fixture_tier,
    public_key,
    generation: str,
    repo_root,
    extra: dict,
) -> dict:
    """The re-derivability block both sweep instruments share.

    Workload + fixture identity, git commit AND working-tree cleanliness (a
    commit hash alone does NOT describe the code when the tree is dirty, and
    these instruments are normally run dirty during development), the host, and
    whatever could not be read named under `unavailable`. `extra` carries the
    per-instrument bits - which attrs were swept - and is spliced in after the
    fixture identity so the schema reads the same order in both reports."""
    host, unavailable = host_provenance()
    commit = _git(repo_root, ["rev-parse", "HEAD"], unavailable)
    dirty = _git(repo_root, ["status", "--porcelain"], unavailable)
    return {
        "workload_version": workload_version,
        "fixture_tier": fixture_tier,
        "fixture_public_key": public_key,
        "generation": generation,
        **extra,
        "git_commit": None if commit is None else commit.strip(),
        "git_clean": None if dirty is None else dirty.strip() == "",
        "unavailable": unavailable,
        "host": host,
    }


# ---- candidate model family -------------------------------------------------


@dataclass(frozen=True)
class Basis:
    """One candidate scaling class: the name, its transform, and its rank.

    `rank` orders the family by growth (and therefore by parsimony
    preference). `superlinear` marks the classes that grow faster than
    linearly - the ones TESTING.md S5(c) says must be a red flag.
    """

    name: str
    label: str
    rank: int
    transform: (
        object  # callable f(n) -> float; `object` keeps the dataclass frozen-hashable
    )
    n_params: int  # regression parameters, excluding the variance term
    superlinear: bool


def _f_const(_n: float) -> float:
    return 0.0


def _f_log(n: float) -> float:
    return math.log(n)


def _f_linear(n: float) -> float:
    return float(n)


def _f_nlogn(n: float) -> float:
    return n * math.log(n)


def _f_quadratic(n: float) -> float:
    return float(n) * float(n)


BASES: tuple[Basis, ...] = (
    Basis("constant", "O(1)", 0, _f_const, 1, False),
    Basis("logarithmic", "O(log n)", 1, _f_log, 2, False),
    Basis("linear", "O(n)", 2, _f_linear, 2, False),
    Basis("linearithmic", "O(n log n)", 3, _f_nlogn, 2, True),
    Basis("quadratic", "O(n^2)", 4, _f_quadratic, 2, True),
)

BASIS_BY_NAME = {b.name: b for b in BASES}
SUPERLINEAR_CLASSES = frozenset(b.name for b in BASES if b.superlinear)


# ---- Student-t quantile (pure stdlib) ---------------------------------------
#
# scipy.stats.t.ppf is not available and will not be added (adding numpy/scipy
# changes the flake closure and the source-guard gates police script imports).
# The regularized incomplete beta below is the textbook Lentz continued
# fraction; `student_t_ppf` inverts the t CDF by bisection. Both are verified
# against published t-table values in run_self_test() - a hand-rolled special
# function that is never checked against known values is exactly the kind of
# plausible-but-unfalsifiable machinery this project treats as the worst
# outcome.


def _betacf(a: float, b: float, x: float, iterations: int = 300) -> float:
    """Continued fraction for the incomplete beta function (Lentz's method)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, iterations + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3.0e-15:
            return h
    # Non-convergence is a real failure, not a number to return silently.
    raise ArithmeticError(f"incomplete beta did not converge for a={a} b={b} x={x}")


def regularized_incomplete_beta(a: float, b: float, x: float) -> float:
    """I_x(a, b), the regularized incomplete beta function."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_front = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    front = math.exp(log_front)
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def student_t_cdf(t: float, df: float) -> float:
    """P(T <= t) for Student's t with `df` degrees of freedom."""
    if df <= 0:
        raise ValueError(f"df must be positive, got {df}")
    x = df / (df + t * t)
    tail = 0.5 * regularized_incomplete_beta(df / 2.0, 0.5, x)
    return 1.0 - tail if t >= 0 else tail


def student_t_ppf(p: float, df: float) -> float:
    """Inverse t CDF by bisection. Verified against a t-table in the self-test."""
    if not 0.0 < p < 1.0:
        raise ValueError(f"p must be in (0,1), got {p}")
    if df <= 0:
        raise ValueError(f"df must be positive, got {df}")
    if p < 0.5:
        return -student_t_ppf(1.0 - p, df)
    lo, hi = 0.0, 1.0
    while student_t_cdf(hi, df) < p:
        hi *= 2.0
        if hi > 1e12:
            raise ArithmeticError(f"t quantile did not bracket for p={p} df={df}")
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if student_t_cdf(mid, df) < p:
            lo = mid
        else:
            hi = mid
        if hi - lo < 1e-12 * max(1.0, hi):
            break
    return 0.5 * (lo + hi)


# ---- one candidate fit ------------------------------------------------------


@dataclass
class CandidateFit:
    """OLS of y on f(n) for one basis, with everything needed to re-derive it."""

    model: str
    label: str
    rank: int
    superlinear: bool
    intercept: float
    slope: float
    n_points: int
    dof: int
    rss: float
    tss: float
    r_squared: float
    adjusted_r_squared: float
    residual_std_error: float
    aicc: float
    residuals: list[float] = field(default_factory=list)
    fitted: list[float] = field(default_factory=list)
    # OLS internals kept so the interval maths is re-derivable by a reader.
    t_mean: float = 0.0
    t_ss: float = 0.0

    def predict(self, n: float) -> float:
        return self.intercept + self.slope * BASIS_BY_NAME[self.model].transform(n)


def _fit_basis(xs: list[float], ys: list[float], basis: Basis) -> CandidateFit:
    """OLS of y on basis.transform(x). The constant basis degenerates to the
    mean (slope pinned at 0), which is what makes O(1) a 1-parameter model and
    therefore genuinely cheaper under AICc than a linear fit with slope ~0."""
    n = len(xs)
    ts = [basis.transform(x) for x in xs]
    y_mean = sum(ys) / n
    t_mean = sum(ts) / n
    t_ss = sum((t - t_mean) ** 2 for t in ts)

    if basis.n_params == 1 or t_ss == 0.0:
        # Constant model, or a transform that is constant over the sampled n
        # (f(n)=n log n at n=1 only, say). Slope is not estimable; say so by
        # pinning it to 0 rather than dividing by zero.
        slope = 0.0
        intercept = y_mean
    else:
        slope = sum((t - t_mean) * (y - y_mean) for t, y in zip(ts, ys)) / t_ss
        intercept = y_mean - slope * t_mean

    fitted = [intercept + slope * t for t in ts]
    residuals = [y - f for y, f in zip(ys, fitted)]
    rss = sum(r * r for r in residuals)
    tss = sum((y - y_mean) ** 2 for y in ys)

    n_params = 1 if (basis.n_params == 1 or t_ss == 0.0) else 2
    dof = n - n_params

    if tss == 0.0:
        # Perfectly flat data: R^2 is undefined in the usual ratio sense. A
        # model that reproduces flat data exactly is a perfect fit; anything
        # else is not. Reporting 1.0/0.0 explicitly beats a NaN nobody reads.
        r_squared = 1.0 if rss <= 1e-24 else 0.0
    else:
        r_squared = 1.0 - rss / tss
    if dof > 0 and tss > 0.0:
        adjusted = 1.0 - (rss / dof) / (tss / (n - 1))
    else:
        adjusted = r_squared
    residual_std_error = math.sqrt(rss / dof) if dof > 0 else float("inf")

    # AICc with k = regression params + 1 (the variance is estimated too).
    # RSS is floored relative to the data scale: an exact fit gives log(0), and
    # a -inf score would make "exact" beat "exact and simpler" arbitrarily.
    k = n_params + 1
    scale = max(abs(y_mean), 1.0)
    rss_floor = max(rss, 1e-18 * scale * scale * n)
    aic = n * math.log(rss_floor / n) + 2 * k
    denominator = n - k - 1
    aicc = aic + (2 * k * (k + 1) / denominator) if denominator > 0 else float("inf")

    return CandidateFit(
        model=basis.name,
        label=basis.label,
        rank=basis.rank,
        # SUPERLINEAR GROWTH, not merely a superlinear BASIS. A quadratic fit
        # with a NEGATIVE slope is a decreasing function; calling it superlinear
        # made task-42's near-constant fd series (11,11,...,10,10,10) a RED FLAG
        # whose own extrapolation was -4015 descriptors at n=1000. S5(c) exists
        # to surface growth that does not survive scale, and a false flag on a
        # metric that went DOWN is the noise that makes a real flag ignorable.
        superlinear=basis.superlinear and slope > 0.0,
        intercept=intercept,
        slope=slope,
        n_points=n,
        dof=dof,
        rss=rss,
        tss=tss,
        r_squared=r_squared,
        adjusted_r_squared=adjusted,
        residual_std_error=residual_std_error,
        aicc=aicc,
        residuals=residuals,
        fitted=fitted,
        t_mean=t_mean,
        t_ss=t_ss,
    )


# ---- selection + extrapolation ----------------------------------------------


class FitError(ValueError):
    """A fit that cannot be honestly attempted. Raised, never returned as a
    number: 'we could not fit this' must not be reportable as a scaling law."""


def _interval(
    fit: CandidateFit, n: float, *, prediction: bool
) -> tuple[float, float] | None:
    """Student-t interval at `n`. `prediction=True` widens it to cover a NEW
    observation (the useful one for "what will a node cost at 1000 peers");
    otherwise it is the interval on the MEAN response. Returns None when dof
    or the design make the interval undefined - never a fake zero-width band."""
    if fit.dof <= 0 or not math.isfinite(fit.residual_std_error):
        return None
    t_at = BASIS_BY_NAME[fit.model].transform(n)
    base = 1.0 if prediction else 0.0
    leverage = 1.0 / fit.n_points
    if fit.t_ss > 0.0:
        leverage += (t_at - fit.t_mean) ** 2 / fit.t_ss
    width = fit.residual_std_error * math.sqrt(base + leverage)
    crit = student_t_ppf(1.0 - (1.0 - CONFIDENCE) / 2.0, fit.dof)
    centre = fit.predict(n)
    return (centre - crit * width, centre + crit * width)


def slope_interval(fit: CandidateFit) -> tuple[float, float, float] | None:
    """`(std_error, low, high)` for the SLOPE of `fit`, at `CONFIDENCE`.

    Why a slope interval is a separate, first-class thing (task-65): the axis
    that actually binds a deployment is peak RSS against the SIZE of what a node
    serves, and the number a reader quotes off that axis is a SLOPE - "bytes of
    RSS per byte of NAR" - not an extrapolated point. A slope stated without an
    interval is a claim tested at one size wearing a fitted-law costume; two
    successive changes can then both "reduce the slope" without either being
    distinguishable from noise. TASK-61's and TASK-62's RSS criteria are written
    against this interval, so it lives in the fitter with the rest of the OLS
    algebra rather than being re-derived by each consumer.

    Textbook OLS: `se(b) = s / sqrt(Sxx)`, `b +/- t_(1-a/2, dof) * se(b)`, where
    `s` is the residual standard error and `Sxx` the transformed design's total
    sum of squares - both already computed for the prediction intervals.

    Returns None when the slope is not ESTIMABLE (a constant model, a design
    with no spread in the transform, or no residual degrees of freedom). None
    means "this fit does not constrain a slope" and every caller must render it
    that way; a zero-width interval would say the opposite.
    """
    if fit.dof <= 0 or fit.t_ss <= 0.0 or not math.isfinite(fit.residual_std_error):
        return None
    if BASIS_BY_NAME[fit.model].n_params == 1:
        return None
    std_error = fit.residual_std_error / math.sqrt(fit.t_ss)
    crit = student_t_ppf(1.0 - (1.0 - CONFIDENCE) / 2.0, fit.dof)
    return (std_error, fit.slope - crit * std_error, fit.slope + crit * std_error)


def extrapolate(fit: CandidateFit, n: float, max_measured_n: float) -> dict:
    """One extrapolated point, STRUCTURALLY labelled as a model output.

    The `kind` key is the label the honesty validator enforces; it is not
    decoration. R^2 and the residual std error travel WITH the number so a
    reader cannot see the estimate without seeing the fit quality."""
    mean_ci = _interval(fit, n, prediction=False)
    pred_pi = _interval(fit, n, prediction=True)
    factor = n / max_measured_n if max_measured_n else float("inf")
    # Every metric this fitter is pointed at (bytes, descriptors, seconds) is
    # non-negative, but a symmetric t interval knows nothing about that domain.
    # An interval reaching below zero is therefore not a mystery to hide or a
    # number to silently clamp - it is the fit telling you it does not constrain
    # this metric at all. Surfaced as its own flag so a reader sees the verdict
    # rather than an absurd bound.
    below_zero = any(
        interval is not None and interval[0] < 0.0 for interval in (mean_ci, pred_pi)
    )
    # And the POINT ESTIMATE itself. Flagging only the interval left the absurd
    # number in the report: task-42's near-constant fd series extrapolated to
    # -29 descriptors at n=100 with `interval_extends_below_zero` set but the
    # estimate stated plainly, and a point estimate is what a reader quotes.
    # Negative bytes/descriptors/seconds are outside the metric's domain, so the
    # fit does not describe the metric there, whatever the interval says.
    estimate = fit.predict(n)
    estimate_below_zero = estimate < 0.0
    return {
        "kind": MODEL_OUTPUT_KIND,
        "n": n,
        "model": fit.model,
        "model_label": fit.label,
        "point_estimate": estimate,
        "ci95_mean_response": list(mean_ci) if mean_ci else None,
        "pi95_new_observation": list(pred_pi) if pred_pi else None,
        "r_squared": fit.r_squared,
        "residual_std_error": fit.residual_std_error,
        "extrapolation_factor_beyond_measured": factor,
        "interval_extends_below_zero": below_zero,
        "point_estimate_below_zero": estimate_below_zero,
        # ONE field a consumer can branch on, instead of every consumer
        # re-deriving "is this number meaningful" from two flags.
        "uninformative": below_zero or estimate_below_zero,
        "caveat": (
            f"MODEL OUTPUT, not a measurement: {factor:.1f}x beyond the largest "
            f"measured n ({max_measured_n:g}). Resource scaling laws only; "
            "emergent network effects are out of scope."
            + (
                " UNINFORMATIVE: "
                + (
                    "the POINT ESTIMATE itself is negative"
                    if estimate_below_zero
                    else "the interval extends below zero"
                )
                + ", which is outside the physical range of this metric - the "
                "fit does not constrain it at this n. Do not read the point "
                "estimate as a prediction."
                if (below_zero or estimate_below_zero)
                else ""
            )
        ),
    }


def fit_scaling(
    xs,
    ys,
    *,
    metric: str,
    unit: str,
    targets=DEFAULT_EXTRAPOLATION_TARGETS,
) -> dict:
    """Fit the candidate family to (xs, ys) and return the model report.

    ASSUMPTIONS, stated because they are load-bearing:
      * xs are positive (log n and n log n are undefined otherwise);
      * xs contain at least MIN_POINTS DISTINCT values (AICc needs the dof);
      * ys are on a ratio scale where "twice as much" is meaningful (bytes,
        descriptors, seconds - all true for what the sweep samples);
      * the residual variance is roughly constant across n. It usually is NOT
        for resource laws (spread grows with the mean), which makes the
        intervals optimistic at the top of the range. Stated, not corrected -
        a variance-stabilising transform would make R^2 non-comparable across
        candidates, which is the worse trade for this report's purpose.

    Everything in the returned dict is a MODEL OUTPUT.
    """
    xs = [float(x) for x in xs]
    ys = [float(y) for y in ys]
    if len(xs) != len(ys):
        raise FitError(f"{metric}: {len(xs)} x values but {len(ys)} y values")
    if any(x <= 0 for x in xs):
        raise FitError(f"{metric}: non-positive n values {xs} (log n undefined)")
    if any(not math.isfinite(y) for y in ys):
        raise FitError(f"{metric}: non-finite sample in {ys}")
    distinct = sorted(set(xs))
    if len(distinct) < MIN_POINTS:
        raise FitError(
            f"{metric}: {len(distinct)} distinct n values {distinct}, need "
            f">= {MIN_POINTS} - fewer makes AICc selection undefined for the "
            "3-parameter candidates. Refusing to fit rather than guess."
        )

    candidates = [_fit_basis(xs, ys, basis) for basis in BASES]
    best_aicc = min(c.aicc for c in candidates)
    within = [c for c in candidates if c.aicc - best_aicc <= AICC_MARGIN]
    # Parsimony: the SIMPLEST candidate that is statistically indistinguishable
    # from the best. Without this, a curvier basis wins on noise at small n.
    selected = min(within, key=lambda c: (c.rank, c.aicc))
    competitive = sorted(within, key=lambda c: c.aicc)

    max_n = max(xs)
    slope_ci = slope_interval(selected)
    return {
        "kind": MODEL_OUTPUT_KIND,
        "fitter_version": FITTER_VERSION,
        "metric": metric,
        "unit": unit,
        "n_values": xs,
        "y_values": ys,
        "selected_model": selected.model,
        "selected_label": selected.label,
        "superlinear": selected.superlinear,
        "intercept": selected.intercept,
        "slope": selected.slope,
        # The slope WITH its uncertainty (task-65). None means the selected model
        # has no estimable slope (O(1)) or the design has no residual dof - which
        # is a statement, not a missing value, and callers must print it as one.
        "slope_std_error": None if slope_ci is None else slope_ci[0],
        "slope_ci95": None if slope_ci is None else [slope_ci[1], slope_ci[2]],
        "slope_unit": f"{unit} per unit of n",
        # DERIVED here so no consumer re-derives it differently: does the interval
        # exclude zero? A slope whose interval spans zero has not been shown to be
        # a slope at all, and a report that quotes such a number as a per-byte cost
        # is quoting noise.
        "slope_distinguishable_from_zero": (
            None if slope_ci is None else (slope_ci[1] > 0.0 or slope_ci[2] < 0.0)
        ),
        "r_squared": selected.r_squared,
        "adjusted_r_squared": selected.adjusted_r_squared,
        "residuals": selected.residuals,
        "fitted_values": selected.fitted,
        "rss": selected.rss,
        "residual_std_error": selected.residual_std_error,
        "dof": selected.dof,
        "aicc": selected.aicc,
        "aicc_margin": AICC_MARGIN,
        "competitive_models": [
            {
                "model": c.model,
                "label": c.label,
                "aicc": c.aicc,
                "delta_aicc": c.aicc - best_aicc,
                "r_squared": c.r_squared,
                "superlinear": c.superlinear,
            }
            for c in competitive
        ],
        "all_candidates": [
            {
                "model": c.model,
                "aicc": c.aicc,
                "delta_aicc": c.aicc - best_aicc,
                "r_squared": c.r_squared,
                "adjusted_r_squared": c.adjusted_r_squared,
                "rss": c.rss,
            }
            for c in sorted(candidates, key=lambda c: c.rank)
        ],
        "identifiable": len(competitive) == 1,
        "confidence_level": CONFIDENCE,
        "max_measured_n": max_n,
        "extrapolations": [extrapolate(selected, t, max_n) for t in targets],
        "caveat": CAVEAT,
    }


# ---- honesty rules, ASSERTED -------------------------------------------------


def _walk(node, path: str = ""):
    """Yield (path, dict) for every dict nested anywhere under `node`."""
    if isinstance(node, dict):
        yield path, node
        for key, value in node.items():
            yield from _walk(value, f"{path}.{key}" if path else str(key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{path}[{index}]")


# Keys whose presence means "this dict states an extrapolated number". A dict
# holding one of these MUST carry the model-output label.
_EXTRAPOLATION_KEYS = frozenset(
    {"point_estimate", "ci95_mean_response", "pi95_new_observation"}
)

# What must travel with any fit, so an estimate is never readable without its
# fit quality (TESTING.md S5 (b)).
_FIT_REQUIRED_KEYS = ("r_squared", "residuals", "selected_model", "extrapolations")


def fit_violations(fit_report: dict) -> list[str]:
    """S5 (a)+(b) for ONE fit block. Empty list == compliant."""
    problems: list[str] = []
    if fit_report.get("kind") != MODEL_OUTPUT_KIND:
        problems.append(
            f"fit block for {fit_report.get('metric')!r} is not labelled "
            f"kind={MODEL_OUTPUT_KIND!r}"
        )
    for key in _FIT_REQUIRED_KEYS:
        if key not in fit_report:
            problems.append(f"fit block for {fit_report.get('metric')!r} lacks {key!r}")
    for path, node in _walk(fit_report):
        if _EXTRAPOLATION_KEYS & node.keys() and node.get("kind") != MODEL_OUTPUT_KIND:
            problems.append(
                f"extrapolated value at {path or '<root>'} is not labelled "
                f"kind={MODEL_OUTPUT_KIND!r} (it would read as a measurement)"
            )
        if _EXTRAPOLATION_KEYS & node.keys() and "r_squared" not in node:
            problems.append(f"extrapolation at {path or '<root>'} lacks r_squared")
    return problems


def sweep_report_violations(report: dict) -> list[str]:
    """S5 (a)-(d) for a WHOLE sweep report. Empty list == compliant.

    A runner must call this and FAIL on a non-empty result. The rules:
      (a) every extrapolated number is structurally labelled model_output;
      (b) R^2 + residuals travel with every fit;
      (c) every superlinear fit appears in `red_flags`;
      (d) the resource-laws-only caveat is present, and no model output has
          leaked into the `measured` block.
    """
    problems: list[str] = []

    measured = report.get("measured")
    if measured is None:
        problems.append(
            "report has no `measured` block (measurements must be separable)"
        )
    else:
        for path, node in _walk(measured, "measured"):
            if node.get("kind") == MODEL_OUTPUT_KIND or (
                _EXTRAPOLATION_KEYS & node.keys()
            ):
                problems.append(
                    f"model output leaked into the measured block at {path}"
                )

    models = report.get("models")
    if models is None:
        problems.append("report has no `models` block")
        models = {}
    flagged = {entry.get("id") for entry in report.get("red_flags", []) or []}
    for fit_id, fit_report in models.items():
        if not isinstance(fit_report, dict):
            problems.append(f"models.{fit_id} is not a fit block")
            continue
        problems += [f"models.{fit_id}: {p}" for p in fit_violations(fit_report)]
        if fit_report.get("superlinear") and fit_id not in flagged:
            problems.append(
                f"models.{fit_id} selected a SUPERLINEAR model "
                f"({fit_report.get('selected_model')}) but it is missing from "
                "`red_flags` - S5(c) requires it surfaced, not footnoted"
            )

    caveat = report.get("caveat")
    if not isinstance(caveat, dict) or not caveat.get(
        "emergent_network_effects_out_of_scope"
    ):
        problems.append(
            "report lacks the resource-laws-only caveat "
            "(`caveat.emergent_network_effects_out_of_scope`)"
        )
    return problems


def unit_labelled(key: str) -> bool:
    """Is `key` a properly unit-labelled byte quantity?

    ANY key mentioning `bytes` anywhere - not just as a suffix - must END in a
    recognised unit, optionally followed by the rate marker `_per_s`. The
    endswith-only version of this rule was itself the vacuous-oracle shape it
    exists to prevent: `bytes_sent` (a real key name in this codebase, see
    `Pod.proxy_stats`), `egress_bytes_total` and `total_bytes_moved` all passed
    it CLEAN. A rule stated as "a reader cannot mix what the schema will not let
    the writer spell" has to cover what the writer can actually spell."""
    body = key[: -len("_per_s")] if key.endswith("_per_s") else key
    return any(body.endswith(suffix) for suffix in UNIT_SUFFIXES)


def unit_violations(node, path: str = "") -> list[str]:
    """Every key naming a byte quantity must carry a recognised unit. Empty == clean.

    THE REPO-WIDE UNIT RULE (task-59). It used to live in profile_p2p and police
    only ITS report, while scale_sweep emitted an unpoliced sibling report
    carrying `daemon_rss_hwm_bytes`, `chain_total_rss_hwm_bytes` and
    `mem_total_bytes` - all of which this gate rejects. It belongs here, in the
    shared honesty module, and both instruments now call it on their reports.

    This is the mechanical form of the rule the project keeps breaking in prose:
    NarSize (uncompressed, signed) and FileSize (compressed, on-wire) are
    DIFFERENT UNITS, and a report that names both `bytes` invites the ratio that
    has already been wrong three times. Pure and structural - strings and
    set/endswith membership only, no float - so it introduces nothing into a
    gated decision that the no-floats rule forbids."""
    problems: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            # `bytes` as a whole TOKEN, so `bytesize`-style words do not trip it
            # while `bytes_sent` and `total_bytes_moved` do.
            names_bytes = isinstance(key, str) and "bytes" in key.split("_")
            if names_bytes and not unit_labelled(key):
                problems.append(
                    f"{here}: byte-valued key without a unit label. It must END "
                    f"in one of {', '.join(UNIT_SUFFIXES)} (optionally + "
                    "'_per_s') - NarSize and FileSize are different units and an "
                    "unlabelled byte key lets them be compared"
                )
            problems += unit_violations(value, here)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            problems += unit_violations(value, f"{path}[{index}]")
    return problems


def red_flags_for(models: dict) -> list[dict]:
    """The red-flag section: one entry per SUPERLINEAR RAM/latency/fd fit.

    Keyed off `superlinear`, not off the exact class, because n log n vs n^2 is
    not reliably identifiable at small N while the superlinear/not split is."""
    flags = []
    for fit_id, fit_report in sorted(models.items()):
        if not fit_report.get("superlinear"):
            continue
        worst = max(
            fit_report.get("extrapolations", []),
            key=lambda e: e.get("n", 0),
            default=None,
        )
        flags.append(
            {
                "id": fit_id,
                "metric": fit_report.get("metric"),
                "unit": fit_report.get("unit"),
                "selected_model": fit_report.get("selected_model"),
                "selected_label": fit_report.get("selected_label"),
                "r_squared": fit_report.get("r_squared"),
                "identifiable": fit_report.get("identifiable"),
                "severity": "RED FLAG: superlinear resource growth",
                "why": (
                    "A superlinear RAM/latency/fd law does not survive scale: "
                    "the cost per node grows with the swept axis, so the "
                    "extrapolated figure below is a floor on the problem, not a "
                    "budget. TESTING.md S5(c)."
                ),
                "worst_extrapolation": worst,
            }
        )
    return flags


# ---- self-test (pure; no containers, wired into `just test`) ----------------


def _synthetic(
    model: str, ns: list[int], *, a: float, b: float, noise: float, seed: int
):
    """Generate y from a KNOWN class with reproducible relative noise. The
    generator is the ground truth the selector must recover."""
    rng = random.Random(seed)
    basis = BASIS_BY_NAME[model]
    ys = []
    for n in ns:
        clean = a + b * basis.transform(n)
        ys.append(clean * (1.0 + rng.uniform(-noise, noise)))
    return ys


def run_self_test() -> int:  # noqa: C901 - a flat list of checks reads better here
    """Unit tests for the fitter and the honesty rules. No containers, no nix.

    Every check is an ORACLE THAT BITES: each "recovers X" check is paired with
    a "and does NOT select Y" assertion, and each honesty rule is proven by
    MUTATING a compliant report and asserting rejection.
    """
    ok = True

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and bool(cond)
        print(
            f"  {'PASS' if cond else 'FAIL'}  {name}"
            + (f"  [{detail}]" if not cond and detail else "")
        )

    print("scalefit --self-test")

    # --- 1. the t quantile, against published t-table values ---------------
    # A hand-rolled special function nobody checked is not evidence.
    table = {(1, 12.706), (2, 4.303), (5, 2.571), (10, 2.228), (30, 2.042)}
    for df, expected in sorted(table):
        got = student_t_ppf(0.975, df)
        check(
            f"t_(0.975,{df}) == {expected}",
            abs(got - expected) < 0.001,
            f"got {got:.4f}",
        )
    check(
        "t_(0.975, 100000) -> normal 1.96",
        abs(student_t_ppf(0.975, 100000) - 1.95996) < 0.001,
        f"got {student_t_ppf(0.975, 100000):.5f}",
    )
    check(
        "t CDF is symmetric",
        abs(student_t_cdf(-1.7, 7) - (1.0 - student_t_cdf(1.7, 7))) < 1e-12,
    )

    # --- 2. model recovery: generated class == selected class --------------
    # WRONG-MODEL SELECTION FAILS THIS TEST (AC#3). The dangerous confusion is
    # linear-vs-SUPERLINEAR, so the quadratic generator is checked twice: exact
    # class AND the superlinear flag, and explicitly NOT linear.
    ns = [1, 2, 4, 6, 8, 12, 16, 24, 30]
    # The expected superlinear flag is written out LITERALLY, not read from
    # BASES: a mutation run showed that comparing against the same constant the
    # code uses makes the check self-referential, so mislabelling O(n^2) as
    # non-superlinear kept it green. The literal is the independent oracle.
    cases = [
        ("constant", 64.0, 0.0, 0.02, 11, False),
        ("logarithmic", 64.0, 12.0, 0.02, 12, False),
        ("linear", 64.0, 8.0, 0.02, 13, False),
        ("linearithmic", 64.0, 4.0, 0.02, 14, True),
        ("quadratic", 64.0, 2.0, 0.02, 15, True),
    ]
    for model, a, b, noise, seed, expect_superlinear in cases:
        ys = _synthetic(model, ns, a=a, b=b, noise=noise, seed=seed)
        report = fit_scaling(ns, ys, metric=f"synthetic-{model}", unit="MiB")
        check(
            f"known {model} generator recovers {model}",
            report["selected_model"] == model,
            f"selected {report['selected_model']} (R^2={report['r_squared']:.4f})",
        )
        check(
            f"known {model}: superlinear flag == {expect_superlinear}",
            report["superlinear"] is expect_superlinear,
            f"got {report['superlinear']}",
        )

    # --- 2b. the SLOPE interval (task-65) ----------------------------------
    # The size axis quotes a SLOPE ("bytes of RSS per byte of NAR"), so the
    # interval on that slope is the number TASK-61 and TASK-62 are gated on. It
    # is checked three ways: it must cover the truth, it must WIDEN with noise
    # (an interval that ignores the data is decoration), and its COVERAGE is
    # measured by Monte Carlo rather than asserted - a wrong critical value or a
    # wrong standard error passes a "contains the truth once" check about 95% of
    # the time, which is exactly how a broken interval survives.
    true_slope = 8.0
    tight = fit_scaling(
        ns,
        _synthetic("linear", ns, a=64.0, b=true_slope, noise=0.01, seed=41),
        metric="slope-tight",
        unit="MiB",
    )
    loose = fit_scaling(
        ns,
        _synthetic("linear", ns, a=64.0, b=true_slope, noise=0.20, seed=41),
        metric="slope-loose",
        unit="MiB",
    )
    check(
        "slope CI covers the generating slope",
        tight["slope_ci95"] is not None
        and tight["slope_ci95"][0] <= true_slope <= tight["slope_ci95"][1],
        f"slope={tight['slope']:.4f} ci={tight['slope_ci95']}",
    )
    tight_width = tight["slope_ci95"][1] - tight["slope_ci95"][0]
    loose_width = loose["slope_ci95"][1] - loose["slope_ci95"][0]
    check(
        "slope CI WIDENS with noise (it reads the data, not the model name)",
        loose_width > tight_width * 2.0,
        f"tight={tight_width:.5f} loose={loose_width:.5f}",
    )
    check(
        "a tight linear slope is distinguishable from zero",
        tight["slope_distinguishable_from_zero"] is True,
    )
    flat = fit_scaling(
        ns,
        _synthetic("constant", ns, a=64.0, b=0.0, noise=0.02, seed=42),
        metric="slope-flat",
        unit="MiB",
    )
    check(
        "an O(1) fit reports NO slope interval rather than a zero-width one",
        flat["selected_model"] == "constant"
        and flat["slope_ci95"] is None
        and flat["slope_distinguishable_from_zero"] is None,
        f"selected={flat['selected_model']} ci={flat['slope_ci95']}",
    )

    # MEASURED coverage. Additive gaussian noise on purpose: the OLS interval
    # assumes constant residual variance, and `_synthetic`'s MULTIPLICATIVE noise
    # violates that (the spread grows with the mean), which is a property of the
    # real resource data and is already stated as a caveat on `fit_scaling`. The
    # question here is whether the ALGEBRA is right, so it is asked under the
    # algebra's own assumptions.
    covered = 0
    coverage_trials = 400
    rng = random.Random(20650)
    for _ in range(coverage_trials):
        ys = [64.0 + true_slope * n + rng.gauss(0.0, 6.0) for n in ns]
        interval = fit_scaling(ns, ys, metric="coverage", unit="MiB")["slope_ci95"]
        if interval is not None and interval[0] <= true_slope <= interval[1]:
            covered += 1
    rate = covered / coverage_trials
    check(
        f"95% slope CI covers the truth ~95% of the time ({coverage_trials} draws)",
        0.88 <= rate <= 0.99,
        f"measured coverage {rate:.3f}",
    )

    # The specific dangerous confusion, asserted on its own so a regression
    # names itself: O(n^2) memory growth must NEVER be reported as linear.
    quad = fit_scaling(
        ns,
        _synthetic("quadratic", ns, a=64.0, b=2.0, noise=0.02, seed=15),
        metric="synthetic-quadratic",
        unit="MiB",
    )
    check(
        "O(n^2) RAM is NOT fitted as linear (the dangerous confusion)",
        quad["selected_model"] != "linear",
        f"selected {quad['selected_model']}",
    )
    check("O(n^2) RAM is flagged superlinear", quad["superlinear"] is True)
    check(
        "O(n^2) fit quality is reported (R^2 present and high)",
        quad["r_squared"] > 0.99,
        f"R^2={quad['r_squared']}",
    )
    linear_report = fit_scaling(
        ns,
        _synthetic("linear", ns, a=64.0, b=8.0, noise=0.02, seed=13),
        metric="synthetic-linear",
        unit="MiB",
    )
    check(
        "known O(n) is NOT flagged superlinear (the flag is not always-on)",
        linear_report["superlinear"] is False,
    )

    # A superlinear BASIS with a NEGATIVE slope is a DECREASING function and must
    # NOT be a red flag. This is a REGRESSION TEST for a real false flag: task-42
    # swept peer file descriptors and got 11,11,...,10,10,10 - near-constant with
    # one step DOWN - which AICc fitted as quadratic with slope < 0 and the
    # basis-only rule flagged as superlinear resource growth, extrapolating to
    # -4015 descriptors at n=1000. `superlinear` now means superlinear GROWTH.
    decreasing = fit_scaling(
        [1, 1, 1, 2, 2, 2, 4, 4, 4, 8, 8, 8, 16, 16, 16],
        [11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 10, 10, 10],
        metric="near-constant-with-a-step-down",
        unit="descriptors",
    )
    check(
        "a DECREASING fit on a superlinear basis is NOT flagged superlinear "
        f"(selected {decreasing['selected_model']}, slope {decreasing['slope']:.4g})",
        decreasing["slope"] < 0 and decreasing["superlinear"] is False,
        f"model={decreasing['selected_model']} slope={decreasing['slope']} "
        f"superlinear={decreasing['superlinear']}",
    )
    check(
        "and it therefore produces NO red flag",
        red_flags_for({"fds": decreasing}) == [],
    )
    # The rule must be DIRECTION-sensitive, not simply disabled. Mirror the same
    # y series about its own mean: the slope on every basis is exactly negated
    # while the residuals - and therefore R^2, AICc and the selected class - are
    # unchanged. So the ONLY thing that differs is the sign, and the flag must
    # flip. A check that merely asserted "superlinear is not None" here would
    # have passed with the rule deleted.
    fd_xs = [1, 1, 1, 2, 2, 2, 4, 4, 4, 8, 8, 8, 16, 16, 16]
    fd_ys = [11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 10, 10, 10]
    fd_mean = sum(fd_ys) / len(fd_ys)
    mirrored = fit_scaling(
        fd_xs,
        [2 * fd_mean - y for y in fd_ys],
        metric="the same series mirrored about its mean",
        unit="descriptors",
    )
    check(
        "MIRROR: the same data with the slope sign flipped selects the SAME "
        "class but IS flagged superlinear (direction-sensitive, not disabled)",
        mirrored["selected_model"] == decreasing["selected_model"]
        and mirrored["slope"] > 0
        and mirrored["superlinear"] is True,
        f"model={mirrored['selected_model']} slope={mirrored['slope']} "
        f"superlinear={mirrored['superlinear']}",
    )
    check(
        "and the mirrored fit DOES reach the red-flag section",
        [f["id"] for f in red_flags_for({"fds": mirrored})] == ["fds"],
    )

    # --- 3. noise robustness: the selector must not chase noise -------------
    noisy = fit_scaling(
        ns,
        _synthetic("linear", ns, a=64.0, b=8.0, noise=0.15, seed=17),
        metric="noisy-linear",
        unit="MiB",
    )
    check(
        "15% noise on O(n) still selects a non-superlinear class",
        not noisy["superlinear"],
        f"selected {noisy['selected_model']}",
    )
    flat_noisy = fit_scaling(
        ns,
        _synthetic("constant", ns, a=64.0, b=0.0, noise=0.10, seed=18),
        metric="noisy-constant",
        unit="MiB",
    )
    check(
        "10% noise on O(1) still selects constant (parsimony holds)",
        flat_noisy["selected_model"] == "constant",
        f"selected {flat_noisy['selected_model']}",
    )

    # --- 4. fail-closed inputs ---------------------------------------------
    for bad_xs, bad_ys, why in [
        ([1, 2, 3, 4], [1, 2, 3, 4], "fewer than MIN_POINTS distinct n"),
        ([1, 1, 1, 1, 1, 2], [1, 2, 3, 4, 5, 6], "duplicate n collapse"),
        ([0, 1, 2, 3, 4, 5], [1, 2, 3, 4, 5, 6], "non-positive n"),
        ([1, 2, 3, 4, 5, 6], [1, 2, 3, 4, 5, float("nan")], "non-finite y"),
    ]:
        raised = False
        try:
            fit_scaling(bad_xs, bad_ys, metric="bad", unit="x")
        except FitError:
            raised = True
        check(f"fail-closed: {why} -> FitError", raised, "no FitError raised")

    # --- 5. intervals: MONTE-CARLO COVERAGE, not one lucky seed -------------
    # A single-seed "the CI covered the truth" check is a coin flip dressed as
    # an oracle: a correct 95% interval misses 5% of the time, so the check
    # would be flaky, and picking the seed that passes is cherry-picking. The
    # honest oracle is the coverage RATE over many replicates.
    def coverage_rate(noise_kind: str, at_n: float, replicates: int = 200) -> float:
        a_true, b_true = 64.0, 8.0
        truth = a_true + b_true * at_n
        covered = 0
        for rep in range(replicates):
            rng = random.Random(90000 + rep)
            if noise_kind == "additive":
                # Homoscedastic: exactly the OLS assumption, so nominal 95%.
                ys_rep = [a_true + b_true * n + rng.gauss(0.0, 6.0) for n in ns]
            else:
                # Multiplicative: variance grows with the mean, violating the
                # OLS assumption. Reported, not asserted - see below.
                ys_rep = [
                    (a_true + b_true * n) * (1.0 + rng.gauss(0.0, 0.02)) for n in ns
                ]
            rep_fit = fit_scaling(ns, ys_rep, metric="mc", unit="MiB", targets=(at_n,))
            lo_rep, hi_rep = rep_fit["extrapolations"][0]["ci95_mean_response"]
            covered += int(lo_rep <= truth <= hi_rep)
        return covered / replicates

    homo_100 = coverage_rate("additive", 100)
    check(
        "95% mean-response CI covers ~95% of the time at n=100 (homoscedastic)",
        0.88 <= homo_100 <= 1.0,
        f"coverage {homo_100:.3f} over 200 replicates",
    )
    homo_1000 = coverage_rate("additive", 1000)
    check(
        "95% mean-response CI still covers ~95% at n=1000 (33x extrapolation)",
        0.88 <= homo_1000 <= 1.0,
        f"coverage {homo_1000:.3f} over 200 replicates",
    )
    hetero_1000 = coverage_rate("multiplicative", 1000)
    # NOT a pass/fail check - a measured statement of a real limitation. Under
    # multiplicative (variance-grows-with-mean) noise, which is what resource
    # metrics actually look like, the nominal 95% interval UNDER-COVERS on a far
    # extrapolation. Printing the number keeps the docstring's caveat honest.
    print(
        f"  INFO  coverage under MULTIPLICATIVE noise at n=1000: "
        f"{hetero_1000:.3f} (nominal 0.95) - the interval is optimistic when "
        "variance grows with the mean; see fit_scaling() assumptions"
    )

    cover = fit_scaling(
        ns,
        [64.0 + 8.0 * n for n in ns],
        metric="coverage-shape",
        unit="MiB",
    )
    at_100 = next(e for e in cover["extrapolations"] if e["n"] == 100)
    at_1000 = next(e for e in cover["extrapolations"] if e["n"] == 1000)
    width_100 = at_100["ci95_mean_response"][1] - at_100["ci95_mean_response"][0]
    width_1000 = at_1000["ci95_mean_response"][1] - at_1000["ci95_mean_response"][0]
    check(
        "CI widens with extrapolation distance",
        width_1000 > width_100,
        f"{width_1000:.6f} vs {width_100:.6f}",
    )
    # A metric whose interval reaches below zero is UNINFORMATIVE, not a bound
    # to quietly clamp. Observed on a real sweep (client p95 latency at n=1000),
    # so the flag is checked both ways: on a noisy near-zero series and on a
    # clean one, so it is not always-on.
    wild = fit_scaling(
        ns,
        _synthetic("constant", ns, a=0.15, b=0.0, noise=0.9, seed=31),
        metric="wild-latency",
        unit="seconds",
    )
    check(
        "an interval reaching below zero is flagged UNINFORMATIVE",
        wild["extrapolations"][-1]["interval_extends_below_zero"],
        f"mean CI {wild['extrapolations'][-1]['ci95_mean_response']} / "
        f"prediction PI {wild['extrapolations'][-1]['pi95_new_observation']}",
    )
    check(
        "and the flag is not always-on (a clean fit is not flagged)",
        not cover["extrapolations"][-1]["interval_extends_below_zero"]
        and not cover["extrapolations"][-1]["uninformative"],
    )
    # The POINT ESTIMATE going negative is its own failure, and it is the one a
    # reader quotes. Regression test with the real series that produced it:
    # task-42's peer fd sweep, 11,11,...,10,10,10, extrapolated to NEGATIVE
    # descriptors while only the interval flag was set.
    fds = fit_scaling(
        [1, 1, 1, 2, 2, 2, 4, 4, 4, 8, 8, 8, 16, 16, 16],
        [11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 10, 10, 10],
        metric="near-constant-fds",
        unit="descriptors",
        targets=(100, 1000),
    )
    far = fds["extrapolations"][-1]
    check(
        f"a NEGATIVE point estimate ({far['point_estimate']:.1f} descriptors at "
        f"n={far['n']}) is flagged UNINFORMATIVE in its own right",
        far["point_estimate"] < 0
        and far["point_estimate_below_zero"]
        and far["uninformative"],
        str(far["point_estimate"]),
    )
    check(
        "and its caveat SAYS the point estimate is the problem",
        "POINT ESTIMATE itself is negative" in far["caveat"],
        far["caveat"],
    )
    check(
        "`uninformative` is not always-on for a physically sensible estimate",
        not any(e["point_estimate_below_zero"] for e in cover["extrapolations"]),
    )

    noisy_shape = fit_scaling(
        ns,
        _synthetic("linear", ns, a=64.0, b=8.0, noise=0.05, seed=23),
        metric="interval-shape",
        unit="MiB",
    )
    inside = next(e for e in noisy_shape["extrapolations"] if e["n"] == 10)
    check(
        "prediction interval is wider than the mean-response CI",
        (inside["pi95_new_observation"][1] - inside["pi95_new_observation"][0])
        > (inside["ci95_mean_response"][1] - inside["ci95_mean_response"][0]),
    )

    # --- 6. honesty rules bite BY MUTATION ---------------------------------
    # Build a COMPLIANT report, assert it is accepted, then break one rule at a
    # time and assert rejection. An accepted-only check would be vacuous.
    models = {
        "clients.daemon_rss_hwm": fit_scaling(
            ns,
            _synthetic("quadratic", ns, a=64.0, b=2.0, noise=0.02, seed=21),
            metric="daemon RSS high-water",
            unit="bytes",
        ),
        "clients.latency_p95": fit_scaling(
            ns,
            _synthetic("linear", ns, a=1.0, b=0.1, noise=0.02, seed=22),
            metric="client wall-clock p95",
            unit="seconds",
        ),
    }
    good = {
        "measured": {"clients": {"points": [{"n": 1, "rss_hwm_bytes_ram": 123}]}},
        "models": models,
        "red_flags": red_flags_for(models),
        "caveat": CAVEAT,
    }
    check(
        "compliant report -> no violations",
        sweep_report_violations(good) == [],
        str(sweep_report_violations(good)),
    )
    check(
        "superlinear fit reached the red-flag section",
        [f["id"] for f in good["red_flags"]] == ["clients.daemon_rss_hwm"],
        str(good["red_flags"]),
    )

    def mutated(fn) -> dict:
        clone = json.loads(json.dumps(good))
        fn(clone)
        return clone

    mutations = [
        (
            "extrapolation stripped of its model_output label -> REJECTED",
            lambda r: r["models"]["clients.latency_p95"]["extrapolations"][0].pop(
                "kind"
            ),
        ),
        (
            "extrapolation stripped of r_squared -> REJECTED",
            lambda r: r["models"]["clients.latency_p95"]["extrapolations"][0].pop(
                "r_squared"
            ),
        ),
        (
            "fit block stripped of residuals -> REJECTED",
            lambda r: r["models"]["clients.latency_p95"].pop("residuals"),
        ),
        (
            "superlinear fit removed from red_flags -> REJECTED",
            lambda r: r.__setitem__("red_flags", []),
        ),
        (
            "resource-laws-only caveat removed -> REJECTED",
            lambda r: r.pop("caveat"),
        ),
        (
            "emergent-network-effects clause blanked -> REJECTED",
            lambda r: r["caveat"].__setitem__(
                "emergent_network_effects_out_of_scope", ""
            ),
        ),
        (
            "model output pasted into the measured block -> REJECTED",
            lambda r: r["measured"]["clients"].__setitem__(
                "projected", {"point_estimate": 999, "kind": MODEL_OUTPUT_KIND}
            ),
        ),
        (
            "measured block removed entirely -> REJECTED",
            lambda r: r.pop("measured"),
        ),
    ]
    for name, mutation in mutations:
        problems = sweep_report_violations(mutated(mutation))
        check(name, problems != [], "validator accepted a broken report")

    # --- 7. the shared sweep-report layer (task-59) ------------------------
    # The unit rule now lives here (it policed only ONE of the two sweep reports
    # before). Proven to BITE by mutation: an unlabelled byte key is rejected,
    # every recognised suffix is accepted, and a word merely CONTAINING "bytes"
    # is untouched.
    print("\n  -- shared report layer (task-59) --")
    check(
        "unit rule: a unit-suffixed byte key passes",
        unit_violations({"peer_rss_hwm_bytes_ram": 1}) == [],
    )
    for suffix in UNIT_SUFFIXES:
        check(
            f"unit rule: suffix {suffix} is accepted",
            unit_violations({f"x{suffix}": 1}) == [],
        )
    check(
        "unit rule MUTATION: a bare `_bytes` key is REJECTED",
        unit_violations({"chain_total_rss_hwm_bytes": 1}) != [],
    )
    check(
        "unit rule MUTATION: `mem_total_bytes` (scale_sweep's old key) is REJECTED",
        unit_violations({"host": {"mem_total_bytes": 1}}) != [],
    )
    check(
        "unit rule: the labelled `mem_total_bytes_ram` passes",
        unit_violations({"host": {"mem_total_bytes_ram": 1}}) == [],
    )
    check(
        "unit rule: a rate key keeps its unit through `_per_s`",
        unit_violations({"throughput_bytes_compressed_wire_per_s": 1}) == [],
    )
    check(
        "unit rule: a word merely CONTAINING 'bytes' is not a byte key",
        unit_violations({"bytesize_note": "x"}) == [],
    )
    check(
        "unit rule names the offending path",
        "arms[0].served_bytes" in unit_violations({"arms": [{"served_bytes": 1}]})[0],
        str(unit_violations({"arms": [{"served_bytes": 1}]})),
    )

    class _P:
        def __init__(self, n, valid):
            self.n, self.valid, self.reason, self.metrics, self.detail = (
                n,
                valid,
                "",
                {},
                {},
            )

    class _A:
        variable, description, notes = "v", "d", []

        def __init__(self, points):
            self.points = points

    axis = _A([_P(1, True), _P(1, True), _P(2, True), _P(2, False), _P(4, True)])
    block = measured_axis_block(axis)
    check(
        "measured_axis_block: distinct_n is the sorted unique n",
        block["distinct_n"] == [1, 2, 4],
    )
    check(
        "measured_axis_block: per-n valid counts (replicates counted, invalids not)",
        block["valid_observations_per_n"] == {"1": 2, "2": 1, "4": 1},
        str(block["valid_observations_per_n"]),
    )
    check(
        "measured_axis_block: invalid points keep their slot",
        len(block["invalid_points"]) == 1 and len(block["points"]) == 5,
    )
    counts = axis_status_counts(axis)
    check(
        "axis_status_counts: valid/total/distinct-valid triple",
        counts
        == {"valid_observations": 4, "total_observations": 5, "distinct_valid_n": 3},
        str(counts),
    )
    check(
        "disk_headroom_ok: at/above the floor passes, below fails (integer decision)",
        disk_headroom_ok(MIN_FREE_DISK_BYTES)
        and not disk_headroom_ok(MIN_FREE_DISK_BYTES - 1),
    )

    print(f"\nscalefit --self-test: {'ALL PASS' if ok else 'FAILURES PRESENT'}")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return run_self_test()
    print(
        "scalefit is a library (import it) plus `--self-test`. The sweep runner "
        "is scripts/scale_sweep.py.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
